"""NER-based sensitive information detector using GLiNER zero-shot NER."""

from .config import NerConfig
from .detector import (
    Detection,
    _group_into_lines,
    _build_line_text_with_mapping,
    _find_covering_bboxes,
    _merge_overlapping_bboxes,
)
from .ocr import OcrResult

_ner_model = None


def _get_ner_model(model_name: str):
    """Load and cache the GLiNER model (lazy singleton)."""
    global _ner_model
    if _ner_model is None:
        try:
            from gliner import GLiNER
        except ImportError:
            raise ImportError(
                "NER detection requires 'gliner'. "
                "Install with: pip install privacy-mask[ner]"
            )
        _ner_model = GLiNER.from_pretrained(model_name)
    return _ner_model


def detect_sensitive_ner(
    ocr_results: list[OcrResult],
    ner_config: NerConfig,
    y_threshold: int | None = None,
) -> list[Detection]:
    """Detect sensitive information using GLiNER zero-shot NER.

    This is a complete detection function (parallel to detect_sensitive),
    not a sub-module called by detect_sensitive.

    Args:
        ocr_results: OCR results with text and bounding boxes.
        ner_config: NER configuration (model name, entity types, threshold).
        y_threshold: Optional Y-axis threshold for line grouping.

    Returns:
        List of Detection objects with labels, matched text, and bboxes.
    """
    if not ocr_results:
        return []

    model = _get_ner_model(ner_config.model_name)
    lines = _group_into_lines(ocr_results, y_threshold)
    detections = []

    for line in lines:
        line_text, mapping = _build_line_text_with_mapping(line)

        if not line_text.strip():
            continue

        # Truncate to max_text_length to avoid model issues
        text_to_predict = line_text[:ner_config.max_text_length]

        entities = model.predict_entities(
            text_to_predict,
            ner_config.entity_types,
            threshold=ner_config.confidence_threshold,
        )

        for entity in entities:
            start = entity["start"]
            end = entity["end"]
            label = "NER_" + entity["label"].upper().replace(" ", "_")
            matched_text = entity["text"]

            bbox = _find_covering_bboxes(start, end, mapping)
            detections.append(Detection(
                label=label,
                matched_text=matched_text,
                bbox=bbox,
            ))

    return _merge_overlapping_bboxes(detections)
