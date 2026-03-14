---
name: privacy-mask
description: >-
  Mask and redact sensitive information (PII) in screenshots and images before
  analysis — phone numbers, emails, IDs, API keys, crypto wallets, credit cards,
  passwords, and more. Uses OCR (Tesseract + RapidOCR) and optional NER (GLiNER)
  to detect private data and applies redaction overlays. One-time setup requires
  pip install (network) and global hook registration; after that, all image
  processing is fully local and offline — no data leaves your machine. Use when
  receiving screenshots that may contain private data, or when the user mentions
  privacy / masking / redacting / PII removal / sensitive data protection.
version: 0.3.0
license: MIT
compatibility: Requires tesseract OCR and Python 3.10+. One-time pip install requires network; all subsequent image processing is local and offline.
metadata:
  author: wuhao
  openclaw:
    requires:
      bins:
        - tesseract
        - python3
    emoji: "\U0001F6E1"
    homepage: https://github.com/fullstackcrew-alpha/privacy-mask
  permissions:
    - id: pip-install
      description: >-
        One-time: runs "pip install privacy-mask" to install the CLI tool and
        its dependencies (Pillow, pytesseract, rapidocr-onnxruntime) from PyPI.
        This is the only step that requires network access.
      scope: global
      optional: false
    - id: global-hook-install
      description: >-
        One-time: runs "privacy-mask install" to register a UserPromptSubmit
        hook in ~/.claude/settings.json. The hook script is bundled in the
        package at mask_engine/data/hook.sh — no remote code is fetched.
      scope: global
      optional: false
    - id: image-cache-read
      description: >-
        At runtime, the hook reads images from ~/.claude/image-cache/ to
        perform local OCR-based detection before the image is sent to the API.
        Images are processed in-place; no copies are made or transmitted.
      scope: local
      optional: false
    - id: agent-behavior-modify
      description: >-
        The hook masks (blurs) detected sensitive regions in images before
        upload, ensuring PII never leaves the machine. This modifies the
        image content that the agent sends to the API.
      scope: local
      optional: false
---

# Privacy Mask

Detect and mask sensitive information in images locally before they leave your machine.

## When to use

- User sends a screenshot that may contain private data
- User mentions privacy, masking, or redacting
- You need to analyze an image but want to redact sensitive info first

## Quick start

```bash
pip install privacy-mask
privacy-mask install   # one-time: sets up global Claude Code hook
```

After install, all images are automatically masked before upload. No further action needed.

## Manual usage

Mask an image:
```bash
privacy-mask mask <image_path>
privacy-mask mask <image_path> --in-place
privacy-mask mask <image_path> --dry-run   # detect only
```

Output is JSON:
```json
{
  "status": "success",
  "detections": [{"label": "PHONE_CN", "text": "***", "bbox": [10, 20, 100, 30]}],
  "summary": "Masked 1 regions: 1 PHONE_CN"
}
```

## What it detects (47 rules)

- **IDs**: Chinese ID card, passport, HK/TW ID, US SSN, UK NINO, Canadian SIN, Indian Aadhaar/PAN, Korean RRN, Singapore NRIC, Malaysian IC
- **Phone**: Chinese mobile/landline, US phone, international (+prefix)
- **Financial**: Bank card, Amex, IBAN, SWIFT/BIC
- **Developer keys**: AWS, GitHub, Slack, Google, Stripe tokens, JWT, connection strings, API keys, SSH/PEM keys
- **Crypto**: Bitcoin, Ethereum wallet addresses
- **Other**: Email, birthday, IP/IPv6, MAC, UUID, license plate, MRZ, URL auth tokens

## Important

- All processing is **local and offline** — no data leaves the machine
- The hook intercepts images **before** upload to cloud API
- Configure rules in the bundled `config.json` or pass `--config` for custom rules
