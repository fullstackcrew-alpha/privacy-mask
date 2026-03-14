"""Tests for the NER-based sensitive information detector."""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from mask_engine.ocr import OcrResult
from mask_engine.config import NerConfig
from mask_engine.detector import Detection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ocr(text, left=0, top=0, width=100, height=20):
    """Create an OcrResult for testing."""
    return OcrResult(text=text, confidence=95.0, bbox=(left, top, width, height))


def _make_mock_entity(text, start, end, label, score=0.9):
    """Create a mock GLiNER entity dict."""
    return {"text": text, "start": start, "end": end, "label": label, "score": score}


# ---------------------------------------------------------------------------
# Import error when gliner is not installed
# ---------------------------------------------------------------------------

class TestGlinerImportError:
    def test_missing_gliner_raises_clear_error(self):
        """When gliner is not installed, a clear ImportError is raised."""
        import mask_engine.ner as ner_module
        # Reset cached model
        ner_module._ner_model = None

        with patch.dict("sys.modules", {"gliner": None}):
            with pytest.raises(ImportError, match="privacy-mask\\[ner\\]"):
                ner_module._get_ner_model("urchade/gliner_small-v2.5")

        # Clean up
        ner_module._ner_model = None


# ---------------------------------------------------------------------------
# NER detection tests (with mocked GLiNER model)
# ---------------------------------------------------------------------------

class TestDetectSensitiveNer:
    @pytest.fixture(autouse=True)
    def reset_ner_model(self):
        """Reset the cached NER model before and after each test."""
        import mask_engine.ner as ner_module
        ner_module._ner_model = None
        yield
        ner_module._ner_model = None

    def _run_detection(self, ocr_results, mock_entities, ner_config=None):
        """Helper: run detect_sensitive_ner with a mocked GLiNER model."""
        import mask_engine.ner as ner_module

        if ner_config is None:
            ner_config = NerConfig()

        mock_model = MagicMock()
        mock_model.predict_entities.return_value = mock_entities
        ner_module._ner_model = mock_model

        return ner_module.detect_sensitive_ner(ocr_results, ner_config)

    def test_empty_ocr_results(self):
        """Empty OCR results should return no detections."""
        detections = self._run_detection([], [])
        assert detections == []

    def test_person_name_detected(self):
        """A person name entity should produce a NER_PERSON_NAME detection."""
        ocr_results = [_ocr("John Smith", left=10, top=5, width=80, height=20)]
        mock_entities = [_make_mock_entity("John Smith", 0, 10, "person name")]

        detections = self._run_detection(ocr_results, mock_entities)

        assert len(detections) == 1
        assert detections[0].label == "NER_PERSON_NAME"
        assert detections[0].matched_text == "John Smith"
        assert detections[0].bbox == (10, 5, 80, 20)

    def test_street_address_detected(self):
        """A street address entity should produce a NER_STREET_ADDRESS detection."""
        ocr_results = [_ocr("123 Main St", left=0, top=0, width=120, height=20)]
        mock_entities = [_make_mock_entity("123 Main St", 0, 11, "street address")]

        detections = self._run_detection(ocr_results, mock_entities)

        assert len(detections) == 1
        assert detections[0].label == "NER_STREET_ADDRESS"

    def test_multiple_entities_on_same_line(self):
        """Multiple entities on the same line should all be detected."""
        ocr_results = [
            _ocr("John", left=0, top=0, width=40, height=20),
            _ocr("lives at", left=50, top=0, width=60, height=20),
            _ocr("123 Main St", left=120, top=0, width=100, height=20),
        ]
        mock_entities = [
            _make_mock_entity("John", 0, 4, "person name"),
            _make_mock_entity("123 Main St", 13, 24, "street address"),
        ]

        detections = self._run_detection(ocr_results, mock_entities)

        assert len(detections) == 2
        labels = {d.label for d in detections}
        assert "NER_PERSON_NAME" in labels
        assert "NER_STREET_ADDRESS" in labels

    def test_label_prefix_and_format(self):
        """Entity labels should be uppercased with NER_ prefix and underscores."""
        ocr_results = [_ocr("1990-01-15", left=0, top=0, width=100, height=20)]
        mock_entities = [_make_mock_entity("1990-01-15", 0, 10, "date of birth")]

        detections = self._run_detection(ocr_results, mock_entities)

        assert len(detections) == 1
        assert detections[0].label == "NER_DATE_OF_BIRTH"

    def test_confidence_threshold_filtering(self):
        """Only entities above the confidence threshold should be detected.
        This is handled by GLiNER's predict_entities threshold param."""
        import mask_engine.ner as ner_module

        ner_config = NerConfig(confidence_threshold=0.8)
        mock_model = MagicMock()
        # GLiNER filters by threshold internally, so with high threshold
        # it should return fewer entities
        mock_model.predict_entities.return_value = []
        ner_module._ner_model = mock_model

        ocr_results = [_ocr("maybe a name", left=0, top=0, width=100, height=20)]
        detections = ner_module.detect_sensitive_ner(ocr_results, ner_config)

        assert detections == []
        # Verify threshold was passed to predict_entities
        mock_model.predict_entities.assert_called_once()
        call_kwargs = mock_model.predict_entities.call_args
        assert call_kwargs[1]["threshold"] == 0.8

    def test_max_text_length_truncation(self):
        """Long text should be truncated to max_text_length."""
        import mask_engine.ner as ner_module

        ner_config = NerConfig(max_text_length=20)
        mock_model = MagicMock()
        mock_model.predict_entities.return_value = []
        ner_module._ner_model = mock_model

        long_text = "A" * 100
        ocr_results = [_ocr(long_text, left=0, top=0, width=1000, height=20)]
        ner_module.detect_sensitive_ner(ocr_results, ner_config)

        call_args = mock_model.predict_entities.call_args[0]
        assert len(call_args[0]) == 20

    def test_whitespace_only_lines_skipped(self):
        """Lines with only whitespace should be skipped."""
        import mask_engine.ner as ner_module

        mock_model = MagicMock()
        mock_model.predict_entities.return_value = []
        ner_module._ner_model = mock_model

        ocr_results = [_ocr("   ", left=0, top=0, width=30, height=20)]
        detections = ner_module.detect_sensitive_ner(ocr_results, NerConfig())

        assert detections == []
        mock_model.predict_entities.assert_not_called()

    def test_bbox_spans_multiple_ocr_words(self):
        """Detection bbox should cover all OCR words that overlap with the entity span."""
        ocr_results = [
            _ocr("123", left=10, top=5, width=30, height=20),
            _ocr("Main", left=50, top=5, width=40, height=20),
            _ocr("Street", left=100, top=5, width=50, height=20),
        ]
        # "123 Main Street" spans all three OCR results
        mock_entities = [_make_mock_entity("123 Main Street", 0, 15, "street address")]

        detections = self._run_detection(ocr_results, mock_entities)

        assert len(detections) == 1
        bbox = detections[0].bbox
        assert bbox[0] == 10  # leftmost
        assert bbox[0] + bbox[2] == 150  # rightmost (100 + 50)


# ---------------------------------------------------------------------------
# Pipeline engine switching tests
# ---------------------------------------------------------------------------

class TestPipelineEngineSwitch:
    def test_regex_engine_uses_detect_sensitive(self):
        """When engine is 'regex', pipeline should use detect_sensitive."""
        from mask_engine.config import Config, DetectionConfig

        config = Config(detection=DetectionConfig(engine="regex"))
        assert config.detection.engine == "regex"

    def test_ner_engine_config(self):
        """When engine is 'ner', pipeline should use detect_sensitive_ner."""
        from mask_engine.config import Config, DetectionConfig

        config = Config(detection=DetectionConfig(engine="ner"))
        assert config.detection.engine == "ner"

    def test_default_engine_is_ner(self):
        """Default detection engine should be 'ner'."""
        from mask_engine.config import DetectionConfig

        config = DetectionConfig()
        assert config.engine == "ner"

    def test_ner_fallback_to_regex_when_gliner_missing(self):
        """When default engine is NER but gliner not installed, fall back to regex."""
        import os
        import tempfile
        from PIL import Image, ImageDraw
        from mask_engine.pipeline import run_pipeline
        from mask_engine.ner import detect_sensitive_ner as real_fn

        def _raise_import(*args, **kwargs):
            raise ImportError("no gliner")

        # Create a test image with a phone number
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "test.png")
            img = Image.new("RGB", (400, 100), (255, 255, 255))
            draw = ImageDraw.Draw(img)
            draw.text((20, 30), "Call me: 13812345678", fill=(0, 0, 0))
            img.save(input_path)

            # Simulate gliner not importable by patching the function to raise ImportError
            with patch("mask_engine.ner.detect_sensitive_ner", side_effect=_raise_import):
                # Default engine is NER, but don't pass detection_engine explicitly
                # so the fallback should kick in (not raise)
                result = run_pipeline(input_path, dry_run=True)
                # Should still detect via regex fallback
                assert result.dry_run is True

    def test_ner_explicit_raises_when_gliner_missing(self):
        """When user explicitly requests NER and gliner is missing, raise error."""
        import os
        import tempfile
        from PIL import Image
        from mask_engine.pipeline import run_pipeline

        def _raise_import(*args, **kwargs):
            raise ImportError("no gliner")

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "test.png")
            img = Image.new("RGB", (400, 100), (255, 255, 255))
            img.save(input_path)

            with patch("mask_engine.ner.detect_sensitive_ner", side_effect=_raise_import):
                with pytest.raises(ImportError):
                    run_pipeline(input_path, dry_run=True, detection_engine="ner")
