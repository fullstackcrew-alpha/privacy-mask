# privacy-mask

Local image privacy masking tool — detect and redact sensitive info via OCR + regex before images leave your machine.

## Build & Test

```bash
pip install -e .
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/ -v
```

## Project Structure

- `mask_engine/` — core library (OCR, detection, masking, CLI)
- `mask_engine/data/config.json` — 47 regex detection rules + masking/OCR settings
- `tests/test_detector.py` — detection rule tests (208+), each rule has positive and negative cases
- `SKILL.md` — agentskills.io standard skill definition
- `.claude-plugin/` / `hooks/` / `scripts/` — Claude Code plugin structure

## GitHub Operations

This repo belongs to `fullstackcrew-alpha`. Before any `gh` command (push, PR, topics, releases, etc.), switch to the correct account:

```bash
gh auth switch -u fullstackcrew-alpha
```

Switch back after if needed: `gh auth switch -u haowu77`

## ClawHub Publish

```bash
clawhub whoami                # verify logged in as fullstackcrew-alpha
clawhub publish . --version <semver> --changelog "description"
```

- `--version` is required (valid semver)
- `.clawhubignore` controls which files are included
- SKILL.md frontmatter provides metadata

## Key Conventions

- **No real secrets in source**: never write literal Stripe/AWS/GitHub test keys; use runtime string construction to avoid push protection triggers
- **config.json patterns are JSON strings**: backslashes must be double-escaped (`\\d` not `\d`)
- **False positive awareness**: when adding/modifying regex rules, always test against common English words that OCR might read as uppercase (e.g. ORGANIZATION, REQUIRED, CONTINUE)
- **Test both positive and negative**: every detection rule should have tests for valid matches AND false positive rejection
