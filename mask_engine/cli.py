"""CLI for privacy-mask: local image privacy masking tool.

Usage:
    privacy-mask mask <image> [--output <path>] [--method blur|fill] [--dry-run] [--in-place]
    privacy-mask install    # Install global Claude Code hook
    privacy-mask uninstall  # Remove global Claude Code hook
"""

import argparse
import json
import os
import shutil
import stat
import sys
from importlib import resources


HOOK_ID_COMMENT = "# privacy-mask-hook"


def _get_claude_settings_path():
    return os.path.expanduser("~/.claude/settings.json")


def _get_hook_install_dir():
    return os.path.expanduser("~/.claude/hooks")


def _get_bundled_hook_path():
    """Get path to the bundled hook.sh template."""
    return str(resources.files("mask_engine").joinpath("data/hook.sh"))


def _get_bundled_config_path():
    """Get path to the bundled config.json."""
    return str(resources.files("mask_engine").joinpath("data/config.json"))


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
            dry_run=args.dry_run,
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

    # 2. Update ~/.claude/settings.json
    settings = {}
    if os.path.isfile(settings_path):
        with open(settings_path, "r") as f:
            settings = json.load(f)

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

        with open(settings_path, "w") as f:
            json.dump(settings, f, indent=4, ensure_ascii=False)

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
        with open(settings_path, "r") as f:
            settings = json.load(f)

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
            # Clean up empty structures
            if not settings["hooks"]["UserPromptSubmit"]:
                del settings["hooks"]["UserPromptSubmit"]
            if not settings["hooks"]:
                del settings["hooks"]

            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=4, ensure_ascii=False)
            print(f"[OK] Settings cleaned: {settings_path}")
        else:
            print(f"[--] No privacy-mask hook found in settings")

    print()
    print("privacy-mask hook has been removed.")


def main():
    parser = argparse.ArgumentParser(
        prog="privacy-mask",
        description="Local image privacy masking — detect and redact sensitive info before images leave your machine.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # mask subcommand
    mask_parser = subparsers.add_parser("mask", help="Mask sensitive info in an image")
    mask_parser.add_argument("input", help="Path to input image")
    mask_parser.add_argument("--output", "-o", help="Output path")
    mask_parser.add_argument("--method", "-m", choices=["blur", "fill"], help="Masking method")
    mask_parser.add_argument("--dry-run", "-d", action="store_true", help="Detect only, don't mask")
    mask_parser.add_argument("--config", "-c", help="Path to config.json")
    mask_parser.add_argument("--in-place", action="store_true", help="Overwrite input file")

    # install subcommand
    subparsers.add_parser("install", help="Install global Claude Code hook")

    # uninstall subcommand
    subparsers.add_parser("uninstall", help="Remove global Claude Code hook")

    args = parser.parse_args()

    if args.command == "mask":
        cmd_mask(args)
    elif args.command == "install":
        cmd_install(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
