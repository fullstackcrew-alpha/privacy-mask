---
name: privacy-mask
description: >-
  Mask, redact and anonymize sensitive information (PII) in screenshots and
  images — phone numbers, emails, IDs, API keys, crypto wallets, credit cards,
  passwords, and more. 100% local, 100% offline. Uses OCR with 47 regex rules
  and optional NER. Use when receiving screenshots that may contain private data,
  or when the user mentions privacy/masking/脱敏/打码.
version: 0.3.5
license: MIT
compatibility: Requires tesseract OCR, Python 3.10+, and pre-installed privacy-mask CLI.
metadata:
  author: wuhao
  openclaw:
    requires:
      bins:
        - tesseract
        - python3
        - privacy-mask
    emoji: "\U0001F6E1"
    homepage: https://github.com/fullstackcrew-alpha/privacy-mask
  permissions:
    - id: local-file-read
      description: >-
        Reads image files provided by the user to perform OCR-based
        sensitive information detection. No files are copied or transmitted.
      scope: local
      optional: false
    - id: local-file-write
      description: >-
        Writes masked output images to the local filesystem (same directory
        as input, with _masked suffix, or user-specified path).
      scope: local
      optional: false
  hooks:
    - event: UserPromptSubmit
      description: >-
        Intercepts images in Claude's local image cache and applies
        privacy masking (blur/fill redaction) in-place before they are
        sent to the API. Runs entirely locally with no network calls.
        Requires the privacy-mask CLI to be installed.
      command: scripts/mask-images.sh
      timeout: 30000
---

# Privacy Mask

Detect and mask sensitive information in images locally before they leave your machine.

## Prerequisites

This skill requires the `privacy-mask` CLI to be pre-installed on the system.
If it is not available, inform the user that they need to install it first:

1. Install via pip: `pip install privacy-mask`
2. Ensure Tesseract OCR is installed: `brew install tesseract` (macOS) or `apt install tesseract-ocr` (Linux)
3. Set up the Claude Code hook: `privacy-mask install`
4. Verify: `privacy-mask --version`

After install, all images are automatically masked before upload. No further action needed.

## When to use

- User sends a screenshot or image file (`.png`, `.jpg`, `.jpeg`, `.bmp`, `.tiff`) that may contain private data
- User mentions privacy, masking, 脱敏, or 打码
- You need to analyze an image but want to redact sensitive info first
- IF the user shares a screenshot for debugging, THEN run `privacy-mask mask <path> --dry-run` first to check for PII

## Manual usage

Mask an image:
```bash
privacy-mask mask /path/to/screenshot.png
privacy-mask mask /path/to/screenshot.png --in-place
privacy-mask mask /path/to/screenshot.png --dry-run   # detect only
privacy-mask mask /path/to/screenshot.png --detection-engine regex  # regex only, skip NER
```

Output is JSON:
```json
{
  "status": "success",
  "detections": [{"label": "PHONE_CN", "text": "***", "bbox": [10, 20, 100, 30]}],
  "summary": "Masked 1 regions: 1 PHONE_CN"
}
```

## What it detects

- **IDs**: Chinese ID card, passport, HK/TW ID, US SSN, UK NINO, Canadian SIN, Indian Aadhaar/PAN, Korean RRN, Singapore NRIC, Malaysian IC
- **Phone**: Chinese mobile/landline, US phone, international (+prefix)
- **Financial**: Bank card, Amex, IBAN, SWIFT/BIC
- **Developer keys**: AWS, GitHub, Slack, Google, Stripe tokens, JWT, connection strings, API keys, SSH/PEM keys
- **Crypto**: Bitcoin, Ethereum wallet addresses
- **Other**: Email, birthday, IP/IPv6, MAC, UUID, license plate, MRZ, URL auth tokens
- **NER** (optional): Person names, street addresses, organizations, dates of birth, medical conditions

## Constraints

- Do NOT send unmasked images to any external API or cloud service
- Do NOT skip masking when detections are found
- Do NOT modify the original image unless `--in-place` is explicitly requested

## Important

- All processing is **local and offline** — no data leaves the machine
- The hook intercepts images **before** upload to cloud API
- Configure rules in the bundled `config.json` or pass `--config` for custom rules
