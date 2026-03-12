"""Merge OCR results from multiple engines with deduplication."""

from __future__ import annotations

from ..bbox import bbox_overlap
from ._types import OcrResult


def merge_ocr_results(
    primary: list[OcrResult],
    secondary: list[OcrResult],
    overlap_threshold: float = 0.5,
) -> list[OcrResult]:
    """Merge two OCR result sets, keeping the higher-confidence result on overlap.

    For each pair of overlapping results, the one with higher confidence wins.
    Non-overlapping results from both sets are always included.
    """
    merged = list(primary)

    for sec in secondary:
        overlap_idx = None
        max_overlap = 0.0

        for i, pri in enumerate(merged):
            ov = bbox_overlap(sec.bbox, pri.bbox)
            if ov > max_overlap:
                max_overlap = ov
                overlap_idx = i

        if max_overlap > overlap_threshold and overlap_idx is not None:
            # Replace if secondary has higher confidence
            if sec.confidence > merged[overlap_idx].confidence:
                merged[overlap_idx] = sec
        else:
            merged.append(sec)

    return merged
