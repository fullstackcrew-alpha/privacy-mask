"""RapidOCR backend (PaddleOCR models via ONNX — fully offline)."""

from __future__ import annotations

import numpy as np
from PIL import Image

from ._types import OcrResult

# Lazy singleton to avoid re-loading models on every call.
_rapid_engine = None


def _get_rapid_engine():
    global _rapid_engine
    if _rapid_engine is None:
        from rapidocr_onnxruntime import RapidOCR
        _rapid_engine = RapidOCR()
    return _rapid_engine


def run_rapidocr(
    image: Image.Image,
    min_confidence: int,
    preprocessed: Image.Image | None = None,
) -> list[OcrResult]:
    """Run RapidOCR and return word-level results.

    Args:
        image: Original image (used if preprocessed is None).
        min_confidence: Minimum confidence threshold (0-100).
        preprocessed: Already-preprocessed image. If provided, use it directly.
    """
    engine = _get_rapid_engine()

    input_image = preprocessed if preprocessed is not None else image
    img_array = np.array(input_image)
    raw_result, _elapse = engine(img_array)

    if not raw_result:
        return []

    results = []
    for box, text, score in raw_result:
        text = text.strip()
        conf = int(float(score) * 100)
        if not text or conf < min_confidence:
            continue

        # box is [[x1,y1],[x2,y2],[x3,y3],[x4,y4]]
        xs = [pt[0] for pt in box]
        ys = [pt[1] for pt in box]
        left = int(min(xs))
        top = int(min(ys))
        width = int(max(xs) - left)
        height = int(max(ys) - top)

        results.append(OcrResult(
            text=text,
            confidence=conf,
            bbox=(left, top, width, height),
        ))

    return results
