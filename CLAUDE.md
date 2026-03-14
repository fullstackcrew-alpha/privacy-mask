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

## PyPI Publish

PyPI 发布通过 GitHub Release 自动完成（CI workflow `.github/workflows/publish.yml`）：

```bash
gh auth switch -u fullstackcrew-alpha
gh release create v<version> --title "v<version> — 描述" --notes "changelog"
```

- Token 存在 GitHub repo secrets (`PYPI_API_TOKEN`)，不需要本地凭证
- **不要**用 `twine upload` 本地发布，直接创建 Release 即可
- Release 会自动触发 build → check → publish 流程

## ClawHub Publish

```bash
clawhub whoami                # verify logged in as fullstackcrew-alpha
clawhub publish . --version <semver> --tags "privacy,pii,masking,redaction,security,ocr,screenshot,sensitive-data,data-protection,offline,local,claude-code,api-keys,secrets" --changelog "description"
```

- `--version` is required (valid semver)
- `--tags` is critical for discoverability — ClawHub uses vector search, so without semantic tags the skill won't appear in search results
- `.clawhubignore` controls which files are included
- SKILL.md frontmatter provides metadata

### Version sync checklist

When bumping versions, update **all four** locations:
1. `pyproject.toml` `version` field
2. `mask_engine/__init__.py` `__version__`
3. `SKILL.md` frontmatter `version` field
4. `marketplace.json` `version` field

### Discoverability tips

- **SKILL.md description** should be keyword-rich with synonym variants (e.g. "mask", "redact", "PII", "sensitive data", "screenshot", "OCR") — ClawHub vector search matches against this
- **Declare permissions/hooks** in SKILL.md `metadata.permissions` — undeclared hook behavior triggers "Suspicious" in security scans and scares users away

## Key Conventions

- **No real secrets in source**: never write literal Stripe/AWS/GitHub test keys; use runtime string construction to avoid push protection triggers
- **config.json patterns are JSON strings**: backslashes must be double-escaped (`\\d` not `\d`)
- **False positive awareness**: when adding/modifying regex rules, always test against common English words that OCR might read as uppercase (e.g. ORGANIZATION, REQUIRED, CONTINUE)
- **Test both positive and negative**: every detection rule should have tests for valid matches AND false positive rejection
