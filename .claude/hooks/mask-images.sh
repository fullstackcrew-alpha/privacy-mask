#!/bin/bash
# UserPromptSubmit hook: intercept images in Claude's image cache and mask them in-place
# before they are sent to the cloud API.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CACHE_DIR="$HOME/.claude/image-cache"
STATE_DIR="$HOME/.claude/privacy-mask"
mkdir -p "$STATE_DIR"
MASKED_LIST="/tmp/masked_images_$(id -u).txt"
LOG_FILE="/tmp/mask-images-hook.log"
ENABLED_FILE="$STATE_DIR/enabled"

# Check if privacy-mask is disabled (enabled by default)
if [ -f "$ENABLED_FILE" ] && [ "$(cat "$ENABLED_FILE" 2>/dev/null)" = "0" ]; then
    exit 0
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

# Read hook input from stdin (JSON with session_id, etc.)
HOOK_INPUT=$(cat)
log "Hook triggered. Input: $HOOK_INPUT"

# Extract session_id from hook input
SESSION_ID=$(echo "$HOOK_INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null)
if [ -z "$SESSION_ID" ]; then
    log "No session_id found in hook input, skipping."
    exit 0
fi

SESSION_CACHE="$CACHE_DIR/$SESSION_ID"
if [ ! -d "$SESSION_CACHE" ]; then
    log "No image cache for session $SESSION_ID"
    exit 0
fi

# Create masked list file if it doesn't exist
touch "$MASKED_LIST"

# Find all images in the current session's cache directory
RECENT_IMAGES=()
while IFS= read -r -d '' img; do
    RECENT_IMAGES+=("$img")
done < <(find "$SESSION_CACHE" -type f \( -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" -o -name "*.webp" \) -print0 2>/dev/null || true)

if [ ${#RECENT_IMAGES[@]} -eq 0 ]; then
    log "No images found for session $SESSION_ID"
    exit 0
fi

MASKED_COUNT=0
SKIPPED_COUNT=0
ERRORS=()

# Determine python path — need one with PIL + rapidocr installed
PYTHON=""
# 1. Project venv
if [ -f "$PROJECT_DIR/venv/bin/python3" ]; then
    PYTHON="$PROJECT_DIR/venv/bin/python3"
# 2. Conda python (has PIL + rapidocr in base env)
elif command -v conda &>/dev/null; then
    CONDA_PYTHON="$(conda info --base 2>/dev/null)/bin/python"
    if [ -x "$CONDA_PYTHON" ]; then
        PYTHON="$CONDA_PYTHON"
    fi
fi
# 3. Fallback: try python then python3
if [ -z "$PYTHON" ]; then
    if command -v python &>/dev/null && python -c "from PIL import Image" 2>/dev/null; then
        PYTHON="python"
    else
        PYTHON="python3"
    fi
fi
log "Using Python: $PYTHON"

for img in "${RECENT_IMAGES[@]}"; do
    # Skip if already processed
    if grep -qxF "$img" "$MASKED_LIST" 2>/dev/null; then
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        log "Skipping already masked: $img"
        continue
    fi

    log "Processing: $img"

    # Run mask_image.py with output = input (in-place overwrite)
    if "$PYTHON" "$PROJECT_DIR/scripts/mask_image.py" "$img" --output "$img" 2>>"$LOG_FILE"; then
        echo "$img" >> "$MASKED_LIST"
        MASKED_COUNT=$((MASKED_COUNT + 1))
        log "Successfully masked: $img"
    else
        ERRORS+=("$img")
        log "ERROR masking: $img"
    fi
done

# Clean up old entries from masked list (keep last 500 lines)
if [ -f "$MASKED_LIST" ] && [ "$(wc -l < "$MASKED_LIST")" -gt 500 ]; then
    tail -200 "$MASKED_LIST" > "${MASKED_LIST}.tmp" && mv "${MASKED_LIST}.tmp" "$MASKED_LIST"
fi

# Output additionalContext for Claude to see
if [ $MASKED_COUNT -gt 0 ]; then
    echo "{\"additionalContext\": \"[Privacy Hook] Automatically masked $MASKED_COUNT image(s) before sending. Sensitive info (phone numbers, emails, IDs, etc.) has been redacted locally.\"}"
fi

log "Done. Masked: $MASKED_COUNT, Skipped: $SKIPPED_COUNT, Errors: ${#ERRORS[@]}"
exit 0
