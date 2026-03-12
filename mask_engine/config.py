"""Configuration loading for privacy mask engine."""

import json
import os
from dataclasses import dataclass, field
from typing import Any


_PROJECT_CONFIG = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
_BUNDLED_CONFIG = os.path.join(os.path.dirname(__file__), "data", "config.json")
DEFAULT_CONFIG_PATH = _PROJECT_CONFIG if os.path.isfile(_PROJECT_CONFIG) else _BUNDLED_CONFIG


@dataclass
class MaskingConfig:
    method: str = "blur"
    blur_radius: int = 20
    fill_color: tuple = (0, 0, 0)
    padding: int = 4


@dataclass
class OcrConfig:
    engine: str = "combined"  # "tesseract", "rapidocr", or "combined"
    languages: str = "eng+chi_sim"
    min_confidence: int = 30
    multi_preprocess: bool = True  # run OCR with multiple preprocessing strategies


@dataclass
class OutputConfig:
    suffix: str = "_masked"
    format: str = "png"


@dataclass
class DetectionRule:
    name: str
    pattern: str
    description: str
    enabled: bool = True


@dataclass
class Config:
    detection_rules: list[DetectionRule] = field(default_factory=list)
    masking: MaskingConfig = field(default_factory=MaskingConfig)
    ocr: OcrConfig = field(default_factory=OcrConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def load_config(config_path: str | None = None) -> Config:
    """Load configuration from JSON file."""
    path = config_path or DEFAULT_CONFIG_PATH
    with open(path, "r") as f:
        data = json.load(f)

    rules = []
    for name, rule_data in data.get("detection_rules", {}).items():
        rules.append(DetectionRule(
            name=name,
            pattern=rule_data["pattern"],
            description=rule_data.get("description", ""),
            enabled=rule_data.get("enabled", True),
        ))

    masking_data = data.get("masking", {})
    masking = MaskingConfig(
        method=masking_data.get("method", "blur"),
        blur_radius=masking_data.get("blur_radius", 20),
        fill_color=tuple(masking_data.get("fill_color", [0, 0, 0])),
        padding=masking_data.get("padding", 4),
    )

    ocr_data = data.get("ocr", {})
    ocr = OcrConfig(
        engine=ocr_data.get("engine", "combined"),
        languages=ocr_data.get("languages", "eng+chi_sim"),
        min_confidence=ocr_data.get("min_confidence", 30),
        multi_preprocess=ocr_data.get("multi_preprocess", True),
    )

    output_data = data.get("output", {})
    output = OutputConfig(
        suffix=output_data.get("suffix", "_masked"),
        format=output_data.get("format", "png"),
    )

    return Config(
        detection_rules=rules,
        masking=masking,
        ocr=ocr,
        output=output,
    )
