#!/bin/bash
# privacy-mask: UserPromptSubmit hook
# Intercepts images in Claude's image cache and masks them LOCALLY
# before they are sent to the cloud API.

set -euo pipefail

CACHE_DIR="$HOME/.claude/image-cache"
STATE_DIR="$HOME/.claude/privacy-mask"
mkdir -p "$STATE_DIR"
MASKED_LIST="$STATE_DIR/masked.txt"
LOG_FILE="$STATE_DIR/hook.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

# Rotate log if > 1MB
if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE")" -gt 1048576 ]; then
    mv "$LOG_FILE" "$LOG_FILE.old"
fi

HOOK_INPUT=$(cat)
log "Hook triggered."

SESSION_ID=$(echo "$HOOK_INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null)
if [ -z "$SESSION_ID" ]; then
    log "No session_id found, skipping."
    exit 0
fi

SESSION_CACHE="$CACHE_DIR/$SESSION_ID"
if [ ! -d "$SESSION_CACHE" ]; then
    log "No image cache for session $SESSION_ID"
    exit 0
fi

touch "$MASKED_LIST"

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

# Find privacy-mask CLI
PM_CMD=""
if command -v privacy-mask &>/dev/null; then
    PM_CMD="privacy-mask"
else
    for p in "$HOME/.local/bin/privacy-mask" "$HOME/miniconda3/bin/privacy-mask" "$HOME/anaconda3/bin/privacy-mask"; do
        if [ -x "$p" ]; then
            PM_CMD="$p"
            break
        fi
    done
fi

if [ -z "$PM_CMD" ]; then
    log "ERROR: privacy-mask CLI not found. Run: pip install privacy-mask"
    exit 0
fi
log "Using: $PM_CMD"

for img in "${RECENT_IMAGES[@]}"; do
    if grep -qxF "$img" "$MASKED_LIST" 2>/dev/null; then
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        continue
    fi

    log "Processing: $img"
    if "$PM_CMD" mask "$img" --in-place 2>>"$LOG_FILE"; then
        echo "$img" >> "$MASKED_LIST"
        MASKED_COUNT=$((MASKED_COUNT + 1))
        log "Masked: $img"
    else
        ERRORS+=("$img")
        log "ERROR: $img"
    fi
done

# Trim masked list (keep last 200 entries)
if [ -f "$MASKED_LIST" ] && [ "$(wc -l < "$MASKED_LIST")" -gt 500 ]; then
    tail -200 "$MASKED_LIST" > "$MASKED_LIST.tmp" && mv "$MASKED_LIST.tmp" "$MASKED_LIST"
fi

if [ $MASKED_COUNT -gt 0 ]; then
    echo "{\"additionalContext\": \"[Privacy Hook] Automatically masked $MASKED_COUNT image(s) before sending. Sensitive info (phone numbers, emails, IDs, etc.) has been redacted locally.\"}"
fi

log "Done. Masked: $MASKED_COUNT, Skipped: $SKIPPED_COUNT, Errors: ${#ERRORS[@]}"
exit 0
