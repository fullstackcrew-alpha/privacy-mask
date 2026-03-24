"""Local Image Privacy Mask Engine."""

__version__ = "0.3.5"

from .ocr import OcrResult, run_ocr
from .detector import Detection, detect_sensitive
from .masker import apply_mask
from .pipeline import run_pipeline, MaskResult
from .config import Config, load_config, NerConfig, DetectionConfig

__all__ = [
    "OcrResult",
    "run_ocr",
    "Detection",
    "detect_sensitive",
    "apply_mask",
    "run_pipeline",
    "MaskResult",
    "Config",
    "load_config",
    "NerConfig",
    "DetectionConfig",
]
