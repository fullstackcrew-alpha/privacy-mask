"""Pipeline module - orchestrates OCR, detection, and masking."""

import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field

from PIL import Image

from .config import Config, load_config
from .ocr import run_ocr
from .detector import detect_sensitive, Detection
from .masker import apply_mask


@dataclass
class MaskResult:
    input_path: str
    output_path: str | None
    detections: list[Detection] = field(default_factory=list)
    summary: str = ""
    dry_run: bool = False


def _safe_save(image: Image.Image, output_path: str) -> None:
    """Save image to output_path, using a temp file + rename for safe in-place overwrite."""
    output_dir = os.path.dirname(output_path) or "."
    fd, tmp_path = tempfile.mkstemp(suffix=".png", dir=output_dir)
    os.close(fd)
    try:
        image.save(tmp_path)
        shutil.move(tmp_path, output_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _generate_output_path(input_path: str, config: Config) -> str:
    """Generate output file path based on input path and config."""
    base, ext = os.path.splitext(input_path)
    return f"{base}{config.output.suffix}.{config.output.format}"


def run_pipeline(
    input_path: str,
    output_path: str | None = None,
    config: Config | None = None,
    config_path: str | None = None,
    method: str | None = None,
    engine: str | None = None,
    dry_run: bool = False,
    detection_engine: str | None = None,
) -> MaskResult:
    """Run the full privacy masking pipeline.

    Args:
        input_path: Path to input image
        output_path: Optional output path (auto-generated if None)
        config: Optional Config object (loaded from config_path if None)
        config_path: Optional path to config.json
        method: Override masking method ('blur' or 'fill')
        engine: Override OCR engine ('tesseract', 'rapidocr', or 'combined')
        dry_run: If True, detect but don't mask/save
        detection_engine: Override detection engine ('regex' or 'ner')
    """
    if config is None:
        config = load_config(config_path)

    if method:
        config.masking.method = method

    if engine:
        config.ocr.engine = engine

    if detection_engine:
        config.detection.engine = detection_engine

    if output_path is None:
        output_path = _generate_output_path(input_path, config)

    image = Image.open(input_path)

    ocr_results = run_ocr(
        image, config.ocr.languages, config.ocr.min_confidence,
        config.ocr.engine, multi_preprocess=config.ocr.multi_preprocess,
    )

    if config.detection.engine == "ner":
        try:
            from .ner import detect_sensitive_ner
            detections = detect_sensitive_ner(ocr_results, config.ner)
        except ImportError:
            if detection_engine == "ner":
                # User explicitly asked for NER — don't silently fall back
                raise
            # Auto-fallback: NER not available, use regex instead
            print(
                "[privacy-mask] NER engine not available, falling back to regex. "
                "Install NER support: pip install privacy-mask[ner]",
                file=sys.stderr,
            )
            detections = detect_sensitive(ocr_results, config.detection_rules)
    else:
        detections = detect_sensitive(ocr_results, config.detection_rules)

    if not detections:
        summary = "No sensitive information detected."
        if not dry_run:
            _safe_save(image, output_path)
        return MaskResult(
            input_path=input_path,
            output_path=output_path if not dry_run else None,
            detections=[],
            summary=summary,
            dry_run=dry_run,
        )

    label_counts: dict[str, int] = {}
    for det in detections:
        for label in det.label.split(","):
            label = label.strip()
            label_counts[label] = label_counts.get(label, 0) + 1

    count_str = ", ".join(f"{v} {k}" for k, v in sorted(label_counts.items()))
    summary = f"Masked {len(detections)} regions: {count_str}"

    if not dry_run:
        masked_image = apply_mask(image, detections, config.masking)
        _safe_save(masked_image, output_path)

    return MaskResult(
        input_path=input_path,
        output_path=output_path if not dry_run else None,
        detections=detections,
        summary=summary,
        dry_run=dry_run,
    )
