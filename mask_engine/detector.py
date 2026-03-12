"""Sensitive information detector using regex matching on OCR results."""

import re
from dataclasses import dataclass

from .ocr import OcrResult
from .config import DetectionRule


@dataclass
class Detection:
    label: str
    matched_text: str
    bbox: tuple[int, int, int, int]  # (left, top, width, height)


def _y_overlap(a: OcrResult, b: OcrResult) -> float:
    """Compute vertical overlap ratio between two OCR results.

    Returns intersection_height / min_height.  A value > 0 means the
    two results share vertical space and likely sit on the same line.
    """
    a_top, a_bot = a.bbox[1], a.bbox[1] + a.bbox[3]
    b_top, b_bot = b.bbox[1], b.bbox[1] + b.bbox[3]
    inter = max(0, min(a_bot, b_bot) - max(a_top, b_top))
    min_h = max(min(a.bbox[3], b.bbox[3]), 1)
    return inter / min_h


def _y_center(r: OcrResult) -> int:
    """Return the vertical center of an OCR result."""
    return r.bbox[1] + r.bbox[3] // 2


def _group_into_lines(
    ocr_results: list[OcrResult],
    y_threshold: int | None = None,
    overlap_ratio: float = 0.3,
) -> list[list[OcrResult]]:
    """Group OCR results into lines using vertical overlap.

    Two results are on the same line if either:
    - Their Y-center distance <= y_threshold, OR
    - Their vertical overlap ratio >= overlap_ratio

    Args:
        y_threshold: Max Y-center distance to consider same line.
                     If None, uses adaptive threshold = half median text height.
        overlap_ratio: Min vertical overlap ratio to consider same line.
    """
    if not ocr_results:
        return []

    if y_threshold is None:
        heights = sorted(r.bbox[3] for r in ocr_results)
        median_h = heights[len(heights) // 2]
        y_threshold = max(median_h // 2, 10)

    sorted_results = sorted(ocr_results, key=lambda r: (_y_center(r), r.bbox[0]))
    lines: list[list[OcrResult]] = []
    current_line: list[OcrResult] = [sorted_results[0]]
    # Use the first (anchor) item's span as the fixed reference for the line
    anchor = sorted_results[0]
    anchor_yc = _y_center(anchor)

    for result in sorted_results[1:]:
        yc_dist = abs(_y_center(result) - anchor_yc)
        overlap = _y_overlap(result, anchor)

        if yc_dist <= y_threshold or overlap >= overlap_ratio:
            current_line.append(result)
        else:
            current_line.sort(key=lambda r: r.bbox[0])
            lines.append(current_line)
            current_line = [result]
            anchor = result
            anchor_yc = _y_center(anchor)

    current_line.sort(key=lambda r: r.bbox[0])
    lines.append(current_line)
    return lines


def _build_line_text_with_mapping(line: list[OcrResult]) -> tuple[str, list[tuple[int, int, OcrResult]]]:
    """Build concatenated line text and mapping from char positions to OcrResults.

    Uses small pixel gap threshold to decide whether to insert a space between words.
    Adjacent words (gap <= 5px) are concatenated without space, helping detect
    emails/URLs split by OCR (e.g., "user@example" + ".com").

    Returns:
        (line_text, mapping) where mapping is list of (start_pos, end_pos, OcrResult)
    """
    text_parts = []
    mapping = []
    pos = 0

    for i, result in enumerate(line):
        if i > 0:
            prev = line[i - 1]
            prev_right = prev.bbox[0] + prev.bbox[2]
            cur_left = result.bbox[0]
            gap = cur_left - prev_right
            if gap > 5:
                text_parts.append(" ")
                pos += 1

        start = pos
        text_parts.append(result.text)
        pos += len(result.text)
        mapping.append((start, pos, result))

    return "".join(text_parts), mapping


def _find_covering_bboxes(
    match_start: int,
    match_end: int,
    mapping: list[tuple[int, int, OcrResult]],
) -> tuple[int, int, int, int]:
    """Find the combined bounding box covering all OcrResults that overlap with [match_start, match_end)."""
    min_left = float("inf")
    min_top = float("inf")
    max_right = 0
    max_bottom = 0

    for start, end, result in mapping:
        if start < match_end and end > match_start:
            left, top, width, height = result.bbox
            min_left = min(min_left, left)
            min_top = min(min_top, top)
            max_right = max(max_right, left + width)
            max_bottom = max(max_bottom, top + height)

    return (int(min_left), int(min_top), int(max_right - min_left), int(max_bottom - min_top))


def _merge_overlapping_bboxes(detections: list[Detection], margin: int = 5) -> list[Detection]:
    """Merge detections with overlapping or adjacent bounding boxes."""
    if len(detections) <= 1:
        return detections

    sorted_dets = sorted(detections, key=lambda d: (d.bbox[0], d.bbox[1]))
    merged = [sorted_dets[0]]

    for det in sorted_dets[1:]:
        prev = merged[-1]
        pl, pt, pw, ph = prev.bbox
        dl, dt, dw, dh = det.bbox

        if (dl <= pl + pw + margin and
            dt <= pt + ph + margin and
            dl + dw >= pl - margin and
            dt + dh >= pt - margin):
            new_left = min(pl, dl)
            new_top = min(pt, dt)
            new_right = max(pl + pw, dl + dw)
            new_bottom = max(pt + ph, dt + dh)
            merged[-1] = Detection(
                label=f"{prev.label},{det.label}" if prev.label != det.label else prev.label,
                matched_text=f"{prev.matched_text} | {det.matched_text}",
                bbox=(new_left, new_top, new_right - new_left, new_bottom - new_top),
            )
        else:
            merged.append(det)

    return merged


def detect_sensitive(
    ocr_results: list[OcrResult],
    rules: list[DetectionRule],
    y_threshold: int | None = None,
) -> list[Detection]:
    """Detect sensitive information by matching regex patterns against reconstructed text lines."""
    active_rules = [r for r in rules if r.enabled]
    if not active_rules or not ocr_results:
        return []

    lines = _group_into_lines(ocr_results, y_threshold)
    detections = []

    for line in lines:
        line_text, mapping = _build_line_text_with_mapping(line)

        for rule in active_rules:
            for match in re.finditer(rule.pattern, line_text, re.IGNORECASE):
                bbox = _find_covering_bboxes(match.start(), match.end(), mapping)
                detections.append(Detection(
                    label=rule.name,
                    matched_text=match.group(),
                    bbox=bbox,
                ))

        # Dot-normalization second pass: replace dots between digits with spaces
        # to catch OCR noise like "54019180.1888" → "54019180 1888"
        normalized = re.sub(r'(?<=\d)\.(?=\d)', ' ', line_text)
        if normalized != line_text:
            for rule in active_rules:
                for match in re.finditer(rule.pattern, normalized, re.IGNORECASE):
                    # Check this match wasn't already found in the original text
                    bbox = _find_covering_bboxes(match.start(), match.end(), mapping)
                    already_found = any(
                        d.bbox == bbox and d.label == rule.name
                        for d in detections
                    )
                    if not already_found:
                        detections.append(Detection(
                            label=rule.name,
                            matched_text=match.group(),
                            bbox=bbox,
                        ))

    return _merge_overlapping_bboxes(detections)
