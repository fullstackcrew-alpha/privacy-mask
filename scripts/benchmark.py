#!/usr/bin/env python3
"""Benchmark OCR + detection accuracy against ground truth annotations.

Reads test images from a directory, runs the full detection pipeline,
compares results against ground_truth.json, and outputs:
- Per-image OCR text, detections, and TP/FP/FN analysis
- Aggregate recall, precision, and F1
- Visual preview images with color-coded bounding boxes

Usage:
    python3 scripts/benchmark.py [tests/real_screenshots/]
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PIL import Image, ImageDraw, ImageFont
from mask_engine.config import load_config
from mask_engine.ocr import run_ocr
from mask_engine.detector import detect_sensitive, Detection


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class GroundTruthItem:
    label: str
    text: str
    bbox_approx: list[int]  # [x, y, w, h]
    matched: bool = False   # set True when matched by a detection


@dataclass
class MatchedDetection:
    detection: Detection
    kind: str  # "TP" or "FP"
    gt_item: GroundTruthItem | None = None


@dataclass
class ImageResult:
    filename: str
    ocr_raw_text: str
    gt_items: list[GroundTruthItem]
    detections: list[Detection]
    matched: list[MatchedDetection] = field(default_factory=list)
    missed: list[GroundTruthItem] = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    fn: int = 0


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _text_overlap(det_text: str, gt_text: str) -> bool:
    """Check if detection text contains or is contained in ground truth text."""
    dt = det_text.lower().replace(" ", "")
    gtt = gt_text.lower().replace(" ", "")
    return gtt in dt or dt in gtt


def _bbox_iou(a: tuple | list, b: tuple | list) -> float:
    """Compute IoU between two (x, y, w, h) bounding boxes."""
    ax1, ay1 = a[0], a[1]
    ax2, ay2 = a[0] + a[2], a[1] + a[3]
    bx1, by1 = b[0], b[1]
    bx2, by2 = b[0] + b[2], b[1] + b[3]

    ix1 = max(ax1, bx1)
    iy1 = max(ay1, by1)
    ix2 = min(ax2, bx2)
    iy2 = min(ay2, by2)

    if ix2 <= ix1 or iy2 <= iy1:
        return 0.0

    inter = (ix2 - ix1) * (iy2 - iy1)
    area_a = (ax2 - ax1) * (ay2 - ay1)
    area_b = (bx2 - bx1) * (by2 - by1)
    union = area_a + area_b - inter
    return inter / union if union > 0 else 0.0


def match_detections(
    detections: list[Detection],
    gt_items: list[GroundTruthItem],
) -> tuple[list[MatchedDetection], list[GroundTruthItem]]:
    """Match detections to ground truth items.

    A detection matches a GT item if:
      - label matches (or GT label appears in the detection's merged labels)
      - AND (text overlaps OR bbox IoU > 0.1)

    Returns (matched_detections, missed_gt_items).
    """
    gt_used = [False] * len(gt_items)
    matched: list[MatchedDetection] = []

    for det in detections:
        det_labels = set(l.strip() for l in det.label.split(","))
        best_gt_idx = None
        best_score = -1

        for i, gt in enumerate(gt_items):
            if gt_used[i]:
                continue
            if gt.label not in det_labels:
                continue

            text_match = _text_overlap(det.matched_text, gt.text)
            iou = _bbox_iou(det.bbox, gt.bbox_approx)

            if text_match or iou > 0.1:
                score = iou + (1.0 if text_match else 0.0)
                if score > best_score:
                    best_score = score
                    best_gt_idx = i

        if best_gt_idx is not None:
            gt_used[best_gt_idx] = True
            gt_items[best_gt_idx].matched = True
            matched.append(MatchedDetection(detection=det, kind="TP", gt_item=gt_items[best_gt_idx]))
        else:
            matched.append(MatchedDetection(detection=det, kind="FP"))

    missed = [gt for i, gt in enumerate(gt_items) if not gt_used[i]]
    return matched, missed


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

def _get_font(size: int = 13):
    for path in [
        "/System/Library/Fonts/SFNSMono.ttf",
        "/System/Library/Fonts/Menlo.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]:
        if os.path.isfile(path):
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                continue
    return ImageFont.load_default()


def draw_preview(
    image: Image.Image,
    matched: list[MatchedDetection],
    missed: list[GroundTruthItem],
    output_path: str,
):
    """Draw color-coded bounding boxes on the image and save."""
    preview = image.copy().convert("RGB")
    draw = ImageDraw.Draw(preview)
    font = _get_font(12)

    # TP = green, FP = yellow, FN = red
    for m in matched:
        left, top, w, h = m.detection.bbox
        if m.kind == "TP":
            color = (0, 200, 0)
            label_prefix = "TP"
        else:
            color = (255, 200, 0)
            label_prefix = "FP"
        draw.rectangle([left - 2, top - 2, left + w + 2, top + h + 2], outline=color, width=2)
        draw.text((left, max(0, top - 14)), f"{label_prefix}: {m.detection.label}", fill=color, font=font)

    for gt in missed:
        x, y, w, h = gt.bbox_approx
        color = (255, 0, 0)
        draw.rectangle([x - 2, y - 2, x + w + 2, y + h + 2], outline=color, width=2)
        draw.text((x, max(0, y - 14)), f"FN: {gt.label} [{gt.text}]", fill=color, font=font)

    preview.save(output_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_benchmark(image_dir: str, config_path: str | None = None):
    gt_path = os.path.join(image_dir, "ground_truth.json")
    if not os.path.isfile(gt_path):
        print(f"Error: ground_truth.json not found in {image_dir}", file=sys.stderr)
        sys.exit(1)

    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    config = load_config(config_path)
    results: list[ImageResult] = []

    total_tp = total_fp = total_fn = 0

    print("=" * 70)
    print("BENCHMARK: OCR + Detection Accuracy")
    print("=" * 70)

    for filename, gt_raw in sorted(ground_truth.items()):
        img_path = os.path.join(image_dir, filename)
        if not os.path.isfile(img_path):
            print(f"\n  SKIP {filename} (file not found)")
            continue

        image = Image.open(img_path)

        # Run OCR
        ocr_results = run_ocr(image, config.ocr.languages, config.ocr.min_confidence, config.ocr.engine)
        ocr_text = " ".join(r.text for r in ocr_results)

        # Run detection
        detections = detect_sensitive(ocr_results, config.detection_rules)

        # Build GT items
        gt_items = [
            GroundTruthItem(label=g["label"], text=g["text"], bbox_approx=g["bbox_approx"])
            for g in gt_raw
        ]

        # Match
        matched, missed = match_detections(detections, gt_items)
        tp = sum(1 for m in matched if m.kind == "TP")
        fp = sum(1 for m in matched if m.kind == "FP")
        fn = len(missed)

        total_tp += tp
        total_fp += fp
        total_fn += fn

        result = ImageResult(
            filename=filename,
            ocr_raw_text=ocr_text,
            gt_items=gt_items,
            detections=detections,
            matched=matched,
            missed=missed,
            tp=tp, fp=fp, fn=fn,
        )
        results.append(result)

        # Print per-image report
        print(f"\n{'─' * 60}")
        print(f"  Image: {filename}")
        print(f"  OCR text: {ocr_text[:120]}{'...' if len(ocr_text) > 120 else ''}")
        print(f"  Expected: {len(gt_items)} sensitive items")
        print(f"  Detected: {len(detections)} items")
        print(f"  TP={tp}  FP={fp}  FN={fn}")

        if matched:
            for m in matched:
                tag = "\033[92mTP\033[0m" if m.kind == "TP" else "\033[93mFP\033[0m"
                print(f"    [{tag}] {m.detection.label}: \"{m.detection.matched_text}\"")
        if missed:
            for gt in missed:
                print(f"    [\033[91mFN\033[0m] {gt.label}: \"{gt.text}\"")

        # Generate preview image
        preview_path = os.path.join(image_dir, filename.replace(".png", "_preview.png"))
        draw_preview(image, matched, missed, preview_path)

    # Summary
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Images tested:  {len(results)}")
    print(f"  True Positives:  {total_tp}")
    print(f"  False Positives: {total_fp}")
    print(f"  False Negatives: {total_fn}")

    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n  Recall:    {recall:.1%}  ({total_tp}/{total_tp + total_fn})")
    print(f"  Precision: {precision:.1%}  ({total_tp}/{total_tp + total_fp})")
    print(f"  F1 Score:  {f1:.1%}")

    # Decision guidance
    print(f"\n{'─' * 60}")
    if recall >= 0.9 and precision >= 0.9:
        verdict = "GOOD - scheme is viable for production"
    elif recall >= 0.7:
        verdict = "NEEDS IMPROVEMENT - consider OCR preprocessing or supplementary OCR"
    else:
        verdict = "UNRELIABLE - consider alternative approach (local LLM, etc.)"
    print(f"  Verdict: {verdict}")
    print(f"{'=' * 70}")

    # Write JSON report
    report = {
        "summary": {
            "images": len(results),
            "tp": total_tp, "fp": total_fp, "fn": total_fn,
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "f1": round(f1, 4),
            "verdict": verdict,
        },
        "per_image": [],
    }
    for r in results:
        report["per_image"].append({
            "filename": r.filename,
            "ocr_text": r.ocr_raw_text,
            "expected": len(r.gt_items),
            "detected": len(r.detections),
            "tp": r.tp, "fp": r.fp, "fn": r.fn,
            "detections": [
                {"label": d.label, "text": d.matched_text, "bbox": list(d.bbox)}
                for d in r.detections
            ],
            "missed": [
                {"label": g.label, "text": g.text}
                for g in r.missed
            ],
        })

    report_path = os.path.join(image_dir, "benchmark_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  Full report: {report_path}")
    print(f"  Preview images: {image_dir}/*_preview.png")


def main():
    parser = argparse.ArgumentParser(description="Benchmark OCR + detection accuracy")
    parser.add_argument(
        "image_dir",
        nargs="?",
        default=os.path.join(os.path.dirname(os.path.dirname(__file__)), "tests", "real_screenshots"),
        help="Directory containing test images and ground_truth.json",
    )
    parser.add_argument("--config", "-c", help="Path to config.json")
    args = parser.parse_args()

    if not os.path.isdir(args.image_dir):
        print(f"Error: Directory not found: {args.image_dir}", file=sys.stderr)
        sys.exit(1)

    run_benchmark(args.image_dir, args.config)


if __name__ == "__main__":
    main()
