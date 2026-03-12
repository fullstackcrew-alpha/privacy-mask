"""OCR module supporting multiple engines: Tesseract, RapidOCR, or combined.

All engines run fully offline — no network calls.
"""

from PIL import Image

from ._types import OcrResult, preprocess_image, preprocess_variants
from .tesseract import run_tesseract
from .rapidocr_engine import run_rapidocr
from .merge import merge_ocr_results

# Re-export for external consumers
__all__ = ["OcrResult", "preprocess_image", "preprocess_variants", "run_ocr"]


def _run_single_pass(
    image: Image.Image,
    languages: str,
    min_confidence: int,
    engine: str,
    preprocessed: Image.Image | None = None,
) -> list[OcrResult]:
    """Run a single OCR pass with an optional pre-processed image."""
    if engine == "tesseract":
        return run_tesseract(image, languages, min_confidence, preprocessed=preprocessed)

    if engine == "rapidocr":
        return run_rapidocr(image, min_confidence, preprocessed=preprocessed)

    if engine == "combined":
        rapid_results = []
        tess_results = []
        try:
            rapid_results = run_rapidocr(image, min_confidence, preprocessed=preprocessed)
        except Exception:
            pass
        try:
            tess_results = run_tesseract(image, languages, min_confidence, preprocessed=preprocessed)
        except Exception:
            pass
        if rapid_results and tess_results:
            return merge_ocr_results(rapid_results, tess_results)
        return rapid_results or tess_results

    raise ValueError(f"Unknown OCR engine: {engine!r}. Use 'tesseract', 'rapidocr', or 'combined'.")


def run_ocr(
    image: Image.Image,
    languages: str = "eng+chi_sim",
    min_confidence: int = 30,
    engine: str = "combined",
    multi_preprocess: bool = False,
) -> list[OcrResult]:
    """Run OCR on image and return word-level results with bounding boxes.

    Args:
        engine: "tesseract", "rapidocr", or "combined" (both, merged).
                All engines run fully offline.
        multi_preprocess: If True, run OCR with multiple preprocessing strategies
                          and merge all results (keeping higher confidence on overlap).
    """
    if not multi_preprocess:
        return _run_single_pass(image, languages, min_confidence, engine)

    # Multi-strategy: run OCR on each preprocessed variant and merge iteratively
    variants = preprocess_variants(image)
    accumulated: list[OcrResult] = []

    for _name, preprocessed in variants:
        pass_results = _run_single_pass(
            image, languages, min_confidence, engine, preprocessed=preprocessed
        )
        if not accumulated:
            accumulated = pass_results
        else:
            accumulated = merge_ocr_results(accumulated, pass_results)

    return accumulated
