"""OCR module using Tesseract for text detection with bounding boxes."""

from dataclasses import dataclass

import pytesseract
from PIL import Image, ImageFilter, ImageEnhance


@dataclass
class OcrResult:
    text: str
    confidence: float
    bbox: tuple[int, int, int, int]  # (left, top, width, height)


def preprocess_image(image: Image.Image) -> Image.Image:
    """Preprocess image for better OCR accuracy."""
    gray = image.convert("L")
    enhancer = ImageEnhance.Contrast(gray)
    enhanced = enhancer.enhance(1.5)
    return enhanced


def run_ocr(image: Image.Image, languages: str = "eng+chi_sim", min_confidence: int = 30) -> list[OcrResult]:
    """Run OCR on image and return word-level results with bounding boxes."""
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
