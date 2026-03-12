"""Tests for OCR module."""

import pytest
from PIL import Image, ImageDraw, ImageFont
from mask_engine.ocr import run_ocr, preprocess_image
from mask_engine.ocr._types import preprocess_variants, OcrResult
from mask_engine.ocr.merge import merge_ocr_results


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


class TestPreprocessVariants:
    def test_returns_four_variants(self):
        img = Image.new("RGB", (100, 100), (128, 128, 128))
        variants = preprocess_variants(img)
        assert len(variants) == 4

    def test_variant_names(self):
        img = Image.new("RGB", (100, 100))
        variants = preprocess_variants(img)
        names = [name for name, _ in variants]
        assert names == ["original", "binary_high", "binary_invert", "sharpen"]

    def test_all_variants_are_grayscale(self):
        img = Image.new("RGB", (100, 100), (200, 100, 50))
        for name, variant in preprocess_variants(img):
            assert variant.mode == "L", f"Variant {name} should be grayscale"

    def test_all_variants_same_size(self):
        img = Image.new("RGB", (200, 150))
        for name, variant in preprocess_variants(img):
            assert variant.size == (200, 150), f"Variant {name} size mismatch"

    def test_binary_variants_are_binary(self):
        """Binary variants should only contain 0 and 255 pixel values."""
        img = Image.new("RGB", (100, 100), (128, 128, 128))
        variants = preprocess_variants(img)
        for name, variant in variants:
            if "binary" in name:
                pixels = set(variant.getdata())
                assert pixels.issubset({0, 255}), f"{name} should be binary, got {pixels}"


class TestMergeOcrResults:
    def test_keeps_higher_confidence_on_overlap(self):
        """When results overlap, the higher confidence one should win."""
        primary = [OcrResult(text="abc", confidence=60, bbox=(10, 10, 50, 20))]
        secondary = [OcrResult(text="abc", confidence=90, bbox=(10, 10, 50, 20))]
        merged = merge_ocr_results(primary, secondary)
        assert len(merged) == 1
        assert merged[0].confidence == 90

    def test_keeps_primary_when_higher_confidence(self):
        primary = [OcrResult(text="abc", confidence=90, bbox=(10, 10, 50, 20))]
        secondary = [OcrResult(text="abc", confidence=60, bbox=(10, 10, 50, 20))]
        merged = merge_ocr_results(primary, secondary)
        assert len(merged) == 1
        assert merged[0].confidence == 90

    def test_adds_non_overlapping(self):
        primary = [OcrResult(text="abc", confidence=80, bbox=(10, 10, 50, 20))]
        secondary = [OcrResult(text="xyz", confidence=70, bbox=(200, 10, 50, 20))]
        merged = merge_ocr_results(primary, secondary)
        assert len(merged) == 2

    def test_multi_round_merge(self):
        """Simulate iterative merge from multiple preprocessing variants."""
        r1 = [OcrResult(text="hello", confidence=50, bbox=(10, 10, 50, 20))]
        r2 = [OcrResult(text="hello", confidence=70, bbox=(10, 10, 50, 20))]
        r3 = [OcrResult(text="hello", confidence=90, bbox=(10, 10, 50, 20))]

        acc = r1
        acc = merge_ocr_results(acc, r2)
        acc = merge_ocr_results(acc, r3)

        assert len(acc) == 1
        assert acc[0].confidence == 90


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

    def test_multi_preprocess_returns_results(self):
        """Multi-preprocess mode should return at least as many results as single mode."""
        img = _create_image_with_text("Hello World 12345")
        single = run_ocr(img, languages="eng", min_confidence=30, multi_preprocess=False)
        multi = run_ocr(img, languages="eng", min_confidence=30, multi_preprocess=True)
        # Multi should find at least what single finds (possibly more or with higher confidence)
        assert len(multi) >= len(single)
