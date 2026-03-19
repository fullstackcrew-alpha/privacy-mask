---
name: privacy-mask
description: Mask sensitive information (phone numbers, emails, IDs, API keys, crypto wallets, etc.) in screenshots before analysis. Use when receiving screenshots that may contain private data, or when the user mentions privacy/masking/脱敏/打码.
version: 0.3.3
license: MIT
compatibility: Requires tesseract OCR, Python 3.10+, and pre-installed privacy-mask CLI.
metadata:
  author: wuhao
---

# Privacy Mask

Detect and mask sensitive information in images locally before they leave your machine.

## Prerequisites

This skill requires the `privacy-mask` CLI to be pre-installed on the system.
If it is not available, inform the user that they need to install it first.

## When to use

- User sends a screenshot that may contain private data
- User mentions privacy, masking, 脱敏, or 打码
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
privacy-mask mask <image_path> --detection-engine regex  # use regex instead of NER
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

## Important

- All processing is **local and offline** — no data leaves the machine
- The hook intercepts images **before** upload to cloud API
- Configure rules in the bundled `config.json` or pass `--config` for custom rules
