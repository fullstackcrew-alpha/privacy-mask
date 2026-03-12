#!/usr/bin/env python3
"""Preview detected sensitive regions without masking.

Draws colored bounding boxes around detected areas and saves a preview image.

Usage:
    python3 scripts/preview_detections.py <input_path> [--output <path>]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PIL import Image, ImageDraw, ImageFont
from mask_engine.config import load_config
from mask_engine.ocr import run_ocr
from mask_engine.detector import detect_sensitive

LABEL_COLORS = {
    "PHONE_CN": (255, 0, 0),
    "EMAIL": (0, 0, 255),
    "ID_CARD_CN": (255, 165, 0),
    "BIRTHDAY": (0, 200, 0),
    "IP_ADDRESS": (128, 0, 128),
    "API_KEY": (255, 0, 255),
    "BANK_CARD": (0, 128, 128),
}

DEFAULT_COLOR = (255, 255, 0)


def main():
    parser = argparse.ArgumentParser(description="Preview sensitive info detections")
    parser.add_argument("input", help="Path to input image")
    parser.add_argument("--output", "-o", help="Output preview path")
    parser.add_argument("--config", "-c", help="Path to config.json")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    config = load_config(args.config)
    image = Image.open(args.input)
    ocr_results = run_ocr(image, config.ocr.languages, config.ocr.min_confidence, config.ocr.engine)
    detections = detect_sensitive(ocr_results, config.detection_rules)

    preview = image.copy()
    draw = ImageDraw.Draw(preview)

    for det in detections:
        left, top, width, height = det.bbox
        primary_label = det.label.split(",")[0].strip()
        color = LABEL_COLORS.get(primary_label, DEFAULT_COLOR)
        padding = config.masking.padding

        draw.rectangle(
            [left - padding, top - padding, left + width + padding, top + height + padding],
            outline=color,
            width=2,
        )
        draw.text((left, top - 15), f"{det.label}", fill=color)

    if args.output:
        output_path = args.output
    else:
        base, ext = os.path.splitext(args.input)
        output_path = f"{base}_preview.png"

    preview.save(output_path)

    result = {
        "status": "success",
        "preview": output_path,
        "detections": [
            {"label": d.label, "text": d.matched_text, "bbox": list(d.bbox)}
            for d in detections
        ],
        "count": len(detections),
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
