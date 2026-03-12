"""Tests for the image masking module."""

import pytest
from PIL import Image

from mask_engine.masker import apply_mask
from mask_engine.detector import Detection
from mask_engine.config import MaskingConfig


def _create_test_image(width=400, height=200, color=(255, 255, 255)):
    return Image.new("RGB", (width, height), color)


class TestApplyMask:
    def test_no_detections(self):
        img = _create_test_image()
        result = apply_mask(img, [], MaskingConfig())
        assert result.size == img.size

    def test_blur_modifies_region(self):
        img = _create_test_image()
        det = Detection(label="PHONE", matched_text="138xxx", bbox=(50, 50, 100, 30))
        config = MaskingConfig(method="blur", blur_radius=20, padding=4)
        result = apply_mask(img, [det], config)
        # On a uniform white image, blur won't change pixels
        # Use a non-uniform image to verify
        img2 = _create_test_image()
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img2)
        draw.text((60, 55), "13812345678", fill=(0, 0, 0))
        result2 = apply_mask(img2, [det], config)
        # The masked region should differ from original
        orig_region = img2.crop((46, 46, 154, 84))
        masked_region = result2.crop((46, 46, 154, 84))
        assert list(orig_region.getdata()) != list(masked_region.getdata())

    def test_fill_modifies_region(self):
        img = _create_test_image()
        from PIL import ImageDraw
        draw = ImageDraw.Draw(img)
        draw.text((60, 55), "secret", fill=(0, 0, 0))
        det = Detection(label="API_KEY", matched_text="secret", bbox=(50, 50, 100, 30))
        config = MaskingConfig(method="fill", fill_color=(0, 0, 0), padding=4)
        result = apply_mask(img, [det], config)
        # Check that the filled region is black
        pixel = result.getpixel((60, 60))
        assert pixel == (0, 0, 0)

    def test_surrounding_pixels_unchanged(self):
        img = _create_test_image(color=(200, 200, 200))
        det = Detection(label="TEST", matched_text="x", bbox=(100, 100, 50, 20))
        config = MaskingConfig(method="fill", fill_color=(0, 0, 0), padding=4)
        result = apply_mask(img, [det], config)
        # Pixel far from the detection should be unchanged
        assert result.getpixel((10, 10)) == (200, 200, 200)
        assert result.getpixel((300, 150)) == (200, 200, 200)

    def test_bbox_clamping(self):
        """Bboxes near image edges should not cause errors."""
        img = _create_test_image(width=100, height=100)
        det = Detection(label="TEST", matched_text="x", bbox=(0, 0, 100, 100))
        config = MaskingConfig(method="blur", blur_radius=10, padding=10)
        result = apply_mask(img, [det], config)
        assert result.size == (100, 100)
