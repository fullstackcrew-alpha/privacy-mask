"""Tests for the pipeline module."""

import os
import tempfile

import pytest
from PIL import Image, ImageDraw

from mask_engine.pipeline import run_pipeline, _generate_output_path
from mask_engine.config import Config, MaskingConfig, OcrConfig, OutputConfig, DetectionRule, DetectionConfig


def _create_test_image_with_phone(path: str):
    """Create a test image with a phone number."""
    img = Image.new("RGB", (400, 100), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 30), "Call me: 13812345678", fill=(0, 0, 0))
    img.save(path)


def _create_clean_image(path: str):
    """Create a test image with no sensitive info."""
    img = Image.new("RGB", (400, 100), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 30), "Hello World", fill=(0, 0, 0))
    img.save(path)


class TestGenerateOutputPath:
    def test_default_suffix(self):
        config = Config(output=OutputConfig(suffix="_masked", format="png"))
        result = _generate_output_path("/tmp/test.png", config)
        assert result == "/tmp/test_masked.png"

    def test_different_format(self):
        config = Config(output=OutputConfig(suffix="_safe", format="jpg"))
        result = _generate_output_path("/tmp/photo.png", config)
        assert result == "/tmp/photo_safe.jpg"


class TestPipeline:
    def test_end_to_end_with_phone(self):
        """End-to-end test: image with phone number should be masked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "test.png")
            output_path = os.path.join(tmpdir, "test_masked.png")
            _create_test_image_with_phone(input_path)

            result = run_pipeline(input_path, output_path=output_path, detection_engine="regex")

            assert os.path.exists(output_path)
            assert result.output_path == output_path
            assert result.summary != ""

    def test_dry_run(self):
        """Dry run should detect but not save."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "test.png")
            _create_test_image_with_phone(input_path)

            result = run_pipeline(input_path, dry_run=True, detection_engine="regex")

            assert result.dry_run is True
            assert result.output_path is None

    def test_clean_image(self):
        """Image without sensitive info should pass through."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "clean.png")
            output_path = os.path.join(tmpdir, "clean_masked.png")
            _create_clean_image(input_path)

            result = run_pipeline(input_path, output_path=output_path, detection_engine="regex")

            assert result.summary == "No sensitive information detected."
            assert os.path.exists(output_path)

    def test_fill_method(self):
        """Test with fill masking method."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "test.png")
            output_path = os.path.join(tmpdir, "test_masked.png")
            _create_test_image_with_phone(input_path)

            result = run_pipeline(input_path, output_path=output_path, method="fill", detection_engine="regex")

            assert os.path.exists(output_path)
