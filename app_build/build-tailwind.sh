#!/bin/bash

# Tailwind CSS Build Script for Header Analyzer
# This script downloads Tailwind CLI and generates CSS for production

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAILWIND_CLI="$PROJECT_ROOT/app_build/tailwindcss-linux-x64"
INPUT_CSS="$PROJECT_ROOT/web/style-input.css"
OUTPUT_CSS="$PROJECT_ROOT/web/style-tailwind.css"
CONFIG_FILE="$PROJECT_ROOT/tailwind.config.js"

echo "🎨 Building Tailwind CSS for Header Analyzer..."
echo "Project root: $PROJECT_ROOT"

# Download Tailwind CLI if it doesn't exist
if [ ! -f "$TAILWIND_CLI" ]; then
    echo "📥 Downloading Tailwind CSS CLI..."
    curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64
    mv tailwindcss-linux-x64 "$TAILWIND_CLI"
    chmod +x "$TAILWIND_CLI"
    echo "✅ Tailwind CLI downloaded"
fi

# Create tailwind.config.js if it doesn't exist
if [ ! -f "$CONFIG_FILE" ]; then
    echo "⚙️ Creating tailwind.config.js..."
    cat > "$CONFIG_FILE" << 'EOF'
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./web/**/*.html",
    "./web/**/*.js"
  ],
  theme: {
    extend: {
      colors: {
        'header-blue': '#007cba',
        'header-dark': '#1a1a1a'
      }
    },
  },
  plugins: [],
}
EOF
    echo "✅ Created tailwind.config.js"
fi

# Build CSS
echo "🔨 Building Tailwind CSS..."
if [ "$1" = "--watch" ]; then
    echo "👀 Starting watch mode..."
    "$TAILWIND_CLI" -i "$INPUT_CSS" -o "$OUTPUT_CSS" --watch
elif [ "$1" = "--dev" ]; then
    echo "🛠️ Building development CSS..."
    "$TAILWIND_CLI" -i "$INPUT_CSS" -o "$OUTPUT_CSS"
else
    echo "📦 Building production CSS (minified)..."
    "$TAILWIND_CLI" -i "$INPUT_CSS" -o "$OUTPUT_CSS" --minify
fi

echo "✅ Tailwind CSS build complete!"
echo "📍 Output: $OUTPUT_CSS"

# Show file size
if [ -f "$OUTPUT_CSS" ]; then
    SIZE=$(du -h "$OUTPUT_CSS" | cut -f1)
    echo "📊 Generated CSS size: $SIZE"
fi
