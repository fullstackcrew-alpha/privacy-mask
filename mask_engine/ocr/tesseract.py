"""Tesseract OCR backend."""

from __future__ import annotations

from PIL import Image

from ._types import OcrResult, preprocess_image


def run_tesseract(
    image: Image.Image,
    languages: str,
    min_confidence: int,
    preprocessed: Image.Image | None = None,
) -> list[OcrResult]:
    """Run Tesseract OCR and return word-level results.

    Args:
        image: Original image (used for preprocessing if preprocessed is None).
        languages: Tesseract language string.
        min_confidence: Minimum confidence threshold (0-100).
        preprocessed: Already-preprocessed image. If provided, skip internal preprocessing.
    """
    import pytesseract

    processed = preprocessed if preprocessed is not None else preprocess_image(image)

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
