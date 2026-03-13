---
name: privacy-mask
description: Mask sensitive information (phone numbers, emails, IDs, API keys, crypto wallets, etc.) in screenshots before analysis. Use when receiving screenshots that may contain private data, or when the user mentions privacy/masking/脱敏/打码.
license: MIT
compatibility: Requires tesseract OCR and Python 3.10+. All processing is local and offline.
metadata:
  author: wuhao
  version: "0.2.0"
---

# Privacy Mask

Detect and mask sensitive information in images locally before they leave your machine.

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
