---
name: privacy-mask
description: Mask sensitive information (phone numbers, emails, IDs, API keys) in screenshots before analysis. Use when receiving screenshots that may contain private data, or when the user mentions privacy/masking/脱敏/打码.
---

# Privacy Mask Tool

Automatically detect and mask sensitive information in images before analyzing them.

## Setup (first time only)

```bash
cd /Users/wuhao/Documents/CornerExplore/local-image-privacy-mask
bash setup.sh
```

## Usage

### Mask an image before analysis

When you receive a screenshot or image path that may contain sensitive information:

1. Run the masking tool:
```bash
cd /Users/wuhao/Documents/CornerExplore/local-image-privacy-mask && source venv/bin/activate && python3 scripts/mask_image.py "<image_path>"
```

2. The tool outputs JSON with the masked image path. Use the masked image for analysis instead of the original.

3. If the tool reports detections, always use the masked version. Tell the user what categories were detected (e.g., "Found 2 phone numbers and 1 email, using masked version").

### Preview detections (no masking)

To check what would be detected without masking:
```bash
cd /Users/wuhao/Documents/CornerExplore/local-image-privacy-mask && source venv/bin/activate && python3 scripts/preview_detections.py "<image_path>"
```

### Options

- `--method blur|fill` - Masking method (default: blur)
- `--dry-run` - Detect only, don't create masked image
- `--output <path>` - Custom output path

## What it detects

- Chinese phone numbers (手机号)
- Email addresses (邮箱)
- Chinese ID card numbers (身份证号)
- Birthdays (生日)
- IP addresses
- API keys / tokens / secrets
- Bank card numbers (银行卡号)

## Important

- All processing is **local and offline** - no data leaves the machine
- The tool uses Tesseract OCR (must be installed via `brew install tesseract`)
- Configure detection rules in `config.json`
