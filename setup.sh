#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Local Image Privacy Mask - Setup ==="

# Check tesseract
if ! command -v tesseract &> /dev/null; then
    echo "Tesseract not found. Installing via Homebrew..."
    if command -v brew &> /dev/null; then
        brew install tesseract
    else
        echo "ERROR: Homebrew not found. Please install tesseract manually."
        exit 1
    fi
else
    echo "✓ Tesseract found: $(which tesseract)"
fi

# Check Chinese language pack
if ! tesseract --list-langs 2>&1 | grep -q "chi_sim"; then
    echo "Installing Chinese language pack..."
    if command -v brew &> /dev/null; then
        brew install tesseract-lang
    else
        echo "WARNING: Cannot install chi_sim automatically. Install tesseract-lang manually."
    fi
else
    echo "✓ Chinese language pack (chi_sim) available"
fi

# Create venv
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
else
    echo "✓ Virtual environment exists"
fi

# Install dependencies
echo "Installing Python dependencies..."
source venv/bin/activate
pip install -r requirements.txt -q

echo ""
echo "=== Setup Complete ==="
echo "Activate with: source venv/bin/activate"
echo "Usage: python3 scripts/mask_image.py <image_path>"
