"""CLI for privacy-mask: local image privacy masking tool.

Usage:
    privacy-mask mask <image> [--output <path>] [--method blur|fill] [--dry-run] [--in-place]
    privacy-mask install    # Install global Claude Code hook
    privacy-mask uninstall  # Remove global Claude Code hook
    privacy-mask on         # Enable masking (default)
    privacy-mask off        # Disable masking temporarily
    privacy-mask status     # Show current status
"""

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from importlib import resources

from . import __version__


def _get_claude_settings_path():
    return os.path.expanduser("~/.claude/settings.json")


def _get_hook_install_dir():
    return os.path.expanduser("~/.claude/hooks")


def _get_bundled_hook_path():
    return str(resources.files("mask_engine").joinpath("data/hook.sh"))


def _get_state_dir():
    return os.path.expanduser("~/.claude/privacy-mask")


def _get_enabled_file():
    return os.path.join(_get_state_dir(), "enabled")


def _is_enabled():
    """Check if privacy-mask is enabled. Enabled by default."""
    enabled_file = _get_enabled_file()
    if not os.path.isfile(enabled_file):
        return True  # enabled by default
    try:
        with open(enabled_file, "r") as f:
            return f.read().strip() == "1"
    except OSError:
        return True


def _set_enabled(enabled: bool):
    """Set the enabled state."""
    state_dir = _get_state_dir()
    os.makedirs(state_dir, exist_ok=True)
    with open(_get_enabled_file(), "w") as f:
        f.write("1" if enabled else "0")


def _atomic_json_write(path: str, data: dict) -> None:
    """Write JSON atomically using tempfile + os.replace."""
    dir_name = os.path.dirname(path)
    os.makedirs(dir_name, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=dir_name)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _load_settings(path: str) -> dict:
    """Load Claude settings.json safely."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Cannot parse {path}: {e}", file=sys.stderr)
        print("Please fix or remove the file and try again.", file=sys.stderr)
        sys.exit(1)


def cmd_mask(args):
    """Mask sensitive information in an image."""
    from .pipeline import run_pipeline

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
            engine=args.engine,
            dry_run=args.dry_run,
            detection_engine=args.detection_engine,
        )

        output = {
            "status": "success",
            "input": result.input_path,
            "output": result.output_path,
            "detections": [
                {"label": d.label, "text": "***", "bbox": list(d.bbox)}
                for d in result.detections
            ],
            "summary": result.summary,
            "dry_run": result.dry_run,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)


def cmd_install(args):
    """Install global Claude Code hook for automatic image masking."""
    hook_dir = _get_hook_install_dir()
    settings_path = _get_claude_settings_path()

    # 1. Copy hook script
    os.makedirs(hook_dir, exist_ok=True)
    dest_hook = os.path.join(hook_dir, "privacy-mask.sh")
    src_hook = _get_bundled_hook_path()
    shutil.copy2(src_hook, dest_hook)
    os.chmod(dest_hook, os.stat(dest_hook).st_mode | stat.S_IEXEC)

    # 2. Update ~/.claude/settings.json atomically
    settings = _load_settings(settings_path)

    hooks = settings.setdefault("hooks", {})
    submit_hooks = hooks.setdefault("UserPromptSubmit", [])

    # Check if already installed
    already = False
    for entry in submit_hooks:
        for h in entry.get("hooks", []):
            if "privacy-mask" in h.get("command", ""):
                already = True
                break

    if not already:
        submit_hooks.append({
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": f"bash {dest_hook}",
                    "timeout": 30000,
                }
            ],
        })
        _atomic_json_write(settings_path, settings)

    print(f"[OK] Hook installed: {dest_hook}")
    print(f"[OK] Settings updated: {settings_path}")
    print()
    print("privacy-mask is now active globally.")
    print("All images sent to Claude Code will be masked locally before upload.")
    print()
    print("To uninstall: privacy-mask uninstall")


def cmd_uninstall(args):
    """Remove global Claude Code hook."""
    settings_path = _get_claude_settings_path()
    hook_path = os.path.join(_get_hook_install_dir(), "privacy-mask.sh")

    # 1. Remove hook script
    if os.path.isfile(hook_path):
        os.unlink(hook_path)
        print(f"[OK] Removed hook: {hook_path}")
    else:
        print(f"[--] Hook not found: {hook_path}")

    # 2. Remove from settings
    if os.path.isfile(settings_path):
        settings = _load_settings(settings_path)

        submit_hooks = settings.get("hooks", {}).get("UserPromptSubmit", [])
        filtered = []
        removed = False
        for entry in submit_hooks:
            keep_hooks = [
                h for h in entry.get("hooks", [])
                if "privacy-mask" not in h.get("command", "")
            ]
            if keep_hooks:
                entry["hooks"] = keep_hooks
                filtered.append(entry)
            else:
                removed = True

        if removed:
            settings["hooks"]["UserPromptSubmit"] = filtered
            if not settings["hooks"]["UserPromptSubmit"]:
                del settings["hooks"]["UserPromptSubmit"]
            if not settings["hooks"]:
                del settings["hooks"]
            _atomic_json_write(settings_path, settings)
            print(f"[OK] Settings cleaned: {settings_path}")
        else:
            print(f"[--] No privacy-mask hook found in settings")

    print()
    print("privacy-mask hook has been removed.")


def cmd_on(args):
    """Enable privacy-mask."""
    _set_enabled(True)
    print("[OK] privacy-mask is now ON — images will be masked before upload.")


def cmd_off(args):
    """Disable privacy-mask temporarily."""
    _set_enabled(False)
    print("[OK] privacy-mask is now OFF — images will NOT be masked.")
    print("Run 'privacy-mask on' to re-enable.")


def cmd_status(args):
    """Show current privacy-mask status."""
    enabled = _is_enabled()
    hook_path = os.path.join(_get_hook_install_dir(), "privacy-mask.sh")
    hook_installed = os.path.isfile(hook_path)

    print(f"privacy-mask v{__version__}")
    print(f"  Masking:   {'ON' if enabled else 'OFF'}")
    print(f"  Hook:      {'installed' if hook_installed else 'not installed'}")
    print(f"  State dir: {_get_state_dir()}")


def main():
    parser = argparse.ArgumentParser(
        prog="privacy-mask",
        description="Local image privacy masking — detect and redact sensitive info before images leave your machine.",
    )
    parser.add_argument(
        "--version", "-V", action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")

    # mask subcommand
    mask_parser = subparsers.add_parser("mask", help="Mask sensitive info in an image")
    mask_parser.add_argument("input", help="Path to input image")
    output_group = mask_parser.add_mutually_exclusive_group()
    output_group.add_argument("--output", "-o", help="Output path")
    output_group.add_argument("--in-place", action="store_true", help="Overwrite input file")
    mask_parser.add_argument("--method", "-m", choices=["blur", "fill"], help="Masking method")
    mask_parser.add_argument("--dry-run", "-d", action="store_true", help="Detect only, don't mask")
    mask_parser.add_argument("--config", "-c", help="Path to config.json")
    mask_parser.add_argument("--engine", "-e", choices=["tesseract", "rapidocr", "combined"], help="OCR engine")
    mask_parser.add_argument("--detection-engine", choices=["regex", "ner"], help="Detection engine (regex or ner)")

    # install / uninstall
    subparsers.add_parser("install", help="Install global Claude Code hook")
    subparsers.add_parser("uninstall", help="Remove global Claude Code hook")

    # on / off / status
    subparsers.add_parser("on", help="Enable masking")
    subparsers.add_parser("off", help="Disable masking temporarily")
    subparsers.add_parser("status", help="Show current status")

    args = parser.parse_args()

    if args.command == "mask":
        cmd_mask(args)
    elif args.command == "install":
        cmd_install(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    elif args.command == "on":
        cmd_on(args)
    elif args.command == "off":
        cmd_off(args)
    elif args.command == "status":
        cmd_status(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
