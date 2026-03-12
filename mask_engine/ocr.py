"""OCR module supporting multiple engines: Tesseract, RapidOCR, or combined.

All engines run fully offline — no network calls.
"""

from dataclasses import dataclass

import numpy as np
from PIL import Image, ImageEnhance


@dataclass
class OcrResult:
    text: str
    confidence: float
    bbox: tuple[int, int, int, int]  # (left, top, width, height)


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

def preprocess_image(image: Image.Image) -> Image.Image:
    """Preprocess image for better OCR accuracy."""
    gray = image.convert("L")
    enhancer = ImageEnhance.Contrast(gray)
    enhanced = enhancer.enhance(1.5)
    return enhanced


# ---------------------------------------------------------------------------
# Tesseract backend
# ---------------------------------------------------------------------------

def _run_tesseract(image: Image.Image, languages: str, min_confidence: int) -> list[OcrResult]:
    """Run Tesseract OCR and return word-level results."""
    import pytesseract

    processed = preprocess_image(image)

    try:
        data = pytesseract.image_to_data(processed, lang=languages, output_type=pytesseract.Output.DICT)
    except pytesseract.TesseractNotFoundError:
        raise RuntimeError("Tesseract not found. Run setup.sh or install tesseract.")

    results = []
    n_boxes = len(data["text"])

    for i in range(n_boxes):
        text = data["text"][i].strip()
        conf = int(data["conf"][i])

        if not text or conf < min_confidence:
            continue

        results.append(OcrResult(
            text=text,
            confidence=conf,
            bbox=(data["left"][i], data["top"][i], data["width"][i], data["height"][i]),
        ))

    return results


# ---------------------------------------------------------------------------
# RapidOCR backend (PaddleOCR models via ONNX — fully offline)
# ---------------------------------------------------------------------------

# Lazy singleton to avoid re-loading models on every call.
_rapid_engine = None


def _get_rapid_engine():
    global _rapid_engine
    if _rapid_engine is None:
        from rapidocr_onnxruntime import RapidOCR
        _rapid_engine = RapidOCR()
    return _rapid_engine


def _run_rapidocr(image: Image.Image, min_confidence: int) -> list[OcrResult]:
    """Run RapidOCR and return word-level results.

    RapidOCR returns line-level 4-point polygons. We convert them to
    axis-aligned (left, top, width, height) bounding boxes.
    """
    engine = _get_rapid_engine()

    img_array = np.array(image)
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


# ---------------------------------------------------------------------------
# Combined mode: merge results from both engines, deduplicate overlaps
# ---------------------------------------------------------------------------

def _bbox_overlap(a: tuple, b: tuple) -> float:
    """Compute overlap ratio (intersection / min_area) of two (x, y, w, h) boxes."""
    ax1, ay1 = a[0], a[1]
    ax2, ay2 = a[0] + a[2], a[1] + a[3]
    bx1, by1 = b[0], b[1]
    bx2, by2 = b[0] + b[2], b[1] + b[3]

    ix1, iy1 = max(ax1, bx1), max(ay1, by1)
    ix2, iy2 = min(ax2, bx2), min(ay2, by2)

    if ix2 <= ix1 or iy2 <= iy1:
        return 0.0

    inter = (ix2 - ix1) * (iy2 - iy1)
    area_a = max((ax2 - ax1) * (ay2 - ay1), 1)
    area_b = max((bx2 - bx1) * (by2 - by1), 1)
    return inter / min(area_a, area_b)


def _merge_ocr_results(primary: list[OcrResult], secondary: list[OcrResult], overlap_threshold: float = 0.5) -> list[OcrResult]:
    """Merge two OCR result sets. Keep all primary results; add secondary results
    that don't significantly overlap with any primary result."""
    merged = list(primary)

    for sec in secondary:
        is_duplicate = False
        for pri in primary:
            if _bbox_overlap(sec.bbox, pri.bbox) > overlap_threshold:
                is_duplicate = True
                break
        if not is_duplicate:
            merged.append(sec)

    return merged


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_ocr(
    image: Image.Image,
    languages: str = "eng+chi_sim",
    min_confidence: int = 30,
    engine: str = "combined",
) -> list[OcrResult]:
    """Run OCR on image and return word-level results with bounding boxes.

    Args:
        engine: "tesseract", "rapidocr", or "combined" (both, merged).
                All engines run fully offline.
    """
    if engine == "tesseract":
        return _run_tesseract(image, languages, min_confidence)

    if engine == "rapidocr":
        return _run_rapidocr(image, min_confidence)

    if engine == "combined":
        # RapidOCR as primary (generally better on Chinese + mixed text),
        # Tesseract as secondary (catches edge cases).
        rapid_results = _run_rapidocr(image, min_confidence)
        tess_results = _run_tesseract(image, languages, min_confidence)
        return _merge_ocr_results(rapid_results, tess_results)

    raise ValueError(f"Unknown OCR engine: {engine!r}. Use 'tesseract', 'rapidocr', or 'combined'.")
