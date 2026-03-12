#!/usr/bin/env python3
"""CLI tool for masking sensitive information in images.

Usage:
    python3 scripts/mask_image.py <input_path> [--output <path>] [--method blur|fill] [--dry-run]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mask_engine.pipeline import run_pipeline


def main():
    parser = argparse.ArgumentParser(description="Mask sensitive information in images")
    parser.add_argument("input", help="Path to input image")
    parser.add_argument("--output", "-o", help="Output path (default: <input>_masked.png)")
    parser.add_argument("--method", "-m", choices=["blur", "fill"], help="Masking method")
    parser.add_argument("--dry-run", "-d", action="store_true", help="Detect only, don't mask")
    parser.add_argument("--config", "-c", help="Path to config.json")
    parser.add_argument("--in-place", action="store_true", help="Overwrite input file (same as --output <input>)")
    args = parser.parse_args()

    if args.in_place and not args.output:
        args.output = args.input

    if not os.path.isfile(args.input):
        print(json.dumps({"status": "error", "message": f"File not found: {args.input}"}))
        sys.exit(1)

    try:
        result = run_pipeline(
            input_path=args.input,
            output_path=args.output,
            config_path=args.config,
            method=args.method,
            dry_run=args.dry_run,
        )

        output = {
            "status": "success",
            "input": result.input_path,
            "output": result.output_path,
            "detections": [
                {
                    "label": d.label,
                    "text": "***",
                    "bbox": list(d.bbox),
                }
                for d in result.detections
            ],
            "summary": result.summary,
            "dry_run": result.dry_run,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
