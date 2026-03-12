# privacy-mask

Local image privacy masking — detect and redact sensitive info (IDs, phones, keys, etc.) before images leave your machine.

## Install

```bash
pip install privacy-mask
```

### Claude Code integration (recommended)

```bash
privacy-mask install    # sets up global hook, all images auto-masked before upload
privacy-mask uninstall  # remove the hook
```

### CLI usage

```bash
privacy-mask mask screenshot.png                # mask → screenshot_masked.png
privacy-mask mask screenshot.png --in-place     # overwrite original
privacy-mask mask screenshot.png --dry-run      # detect only, no masking
privacy-mask mask screenshot.png --method fill   # black fill instead of blur
```

## What it detects

47 regex rules covering:

- **IDs**: CN ID card/passport, HK/TW ID, US SSN, UK NINO, CA SIN, IN Aadhaar/PAN, KR RRN, SG NRIC, MY IC
- **Phone**: CN mobile/landline, US, international (+prefix)
- **Financial**: Bank card, Amex, IBAN, SWIFT/BIC
- **Developer**: AWS/GitHub/Slack/Google/Stripe keys, JWT, DB connection strings, API keys, SSH/PEM
- **Crypto**: BTC, ETH wallets
- **Other**: Email, birthday, IP/IPv6, MAC, UUID, CN license plate, MRZ

## How it works

1. **OCR** — Tesseract + RapidOCR extract text from the image
2. **Detect** — 47 regex rules match sensitive patterns
3. **Mask** — Blur or fill matched regions

All processing is local and offline. No data leaves your machine.

## Requirements

- Python 3.10+
- Tesseract OCR (`brew install tesseract` on macOS)

## License

MIT
