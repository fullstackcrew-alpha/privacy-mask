"""Tests for OCR module."""

import pytest
from PIL import Image, ImageDraw, ImageFont
from mask_engine.ocr import run_ocr, preprocess_image


def _create_image_with_text(text: str, size=(400, 100)) -> Image.Image:
    """Create a test image with text rendered on it."""
    img = Image.new("RGB", size, (255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 30), text, fill=(0, 0, 0))
    return img


class TestPreprocessImage:
    def test_returns_grayscale(self):
        img = Image.new("RGB", (100, 100), (255, 0, 0))
        result = preprocess_image(img)
        assert result.mode == "L"

    def test_output_size_unchanged(self):
        img = Image.new("RGB", (200, 150))
        result = preprocess_image(img)
        assert result.size == (200, 150)


class TestRunOcr:
    def test_simple_text(self):
        """Test that OCR can detect simple English text."""
        img = _create_image_with_text("Hello World")
        results = run_ocr(img, languages="eng", min_confidence=30)
        texts = " ".join(r.text for r in results).lower()
        assert "hello" in texts or "world" in texts

    def test_returns_bboxes(self):
        img = _create_image_with_text("Test 12345")
        results = run_ocr(img, languages="eng", min_confidence=30)
        for r in results:
            left, top, width, height = r.bbox
            assert width > 0
            assert height > 0

    def test_empty_image(self):
        img = Image.new("RGB", (100, 100), (255, 255, 255))
        results = run_ocr(img, languages="eng", min_confidence=30)
        assert len(results) == 0

    def test_confidence_filtering(self):
        img = _create_image_with_text("Clear Text Here")
        # With very high threshold, fewer results
        high_conf = run_ocr(img, languages="eng", min_confidence=90)
        low_conf = run_ocr(img, languages="eng", min_confidence=10)
        assert len(low_conf) >= len(high_conf)
