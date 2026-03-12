"""Shared OCR types and preprocessing."""

from dataclasses import dataclass

from PIL import Image, ImageEnhance, ImageFilter


@dataclass
class OcrResult:
    text: str
    confidence: float
    bbox: tuple[int, int, int, int]  # (left, top, width, height)


def preprocess_image(image: Image.Image) -> Image.Image:
    """Preprocess image for better OCR accuracy (default strategy)."""
    gray = image.convert("L")
    enhancer = ImageEnhance.Contrast(gray)
    enhanced = enhancer.enhance(1.5)
    return enhanced


def preprocess_variants(image: Image.Image) -> list[tuple[str, Image.Image]]:
    """Return multiple preprocessed versions of the image for multi-strategy OCR.

    Each variant targets a different visual scenario:
    - original: grayscale + contrast 1.5 (standard screenshots)
    - binary_high: high-contrast binarization (gradient backgrounds, embossed text)
    - binary_invert: inverted binarization (light text on dark backgrounds)
    - sharpen: sharpen + high contrast (blurry / low-contrast text)
    """
    gray = image.convert("L")

    # 1. Original strategy
    original = ImageEnhance.Contrast(gray).enhance(1.5)

    # 2. High-contrast binarization (threshold=128)
    binary_high = gray.point(lambda p: 255 if p > 128 else 0)

    # 3. Inverted binarization (for light text on dark background)
    from PIL import ImageOps
    inverted = ImageOps.invert(gray)
    binary_invert = inverted.point(lambda p: 255 if p > 128 else 0)

    # 4. Sharpen + high contrast (for blurry/low-contrast text)
    sharpened = gray.filter(ImageFilter.SHARPEN)
    sharpened = sharpened.filter(ImageFilter.SHARPEN)  # apply twice for 2x effect
    sharpen = ImageEnhance.Contrast(sharpened).enhance(2.5)

    return [
        ("original", original),
        ("binary_high", binary_high),
        ("binary_invert", binary_invert),
        ("sharpen", sharpen),
    ]
