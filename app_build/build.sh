#!/bin/bash

# Main Build Script for Header Analyzer
# Builds Tailwind CSS and compiles the Go application

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/app_build"

echo "🚀 Building Header Analyzer..."
echo "Project root: $PROJECT_ROOT"

# Build Tailwind CSS first
echo "📝 Step 1: Building Tailwind CSS..."
"$BUILD_DIR/build-tailwind.sh"

# Build Go application
echo "📝 Step 2: Building Go application..."
cd "$PROJECT_ROOT"

# Set build variables
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Version: $VERSION"
echo "Build time: $BUILD_TIME"
echo "Commit: $COMMIT"

# Build for current platform
echo "🔨 Compiling for current platform..."
go build -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.commit=$COMMIT" \
    -o headeranalyzer .

echo "✅ Build complete!"
echo "📍 Binary: $PROJECT_ROOT/headeranalyzer"

# Show binary size
if [ -f "$PROJECT_ROOT/headeranalyzer" ]; then
    SIZE=$(du -h "$PROJECT_ROOT/headeranalyzer" | cut -f1)
    echo "📊 Binary size: $SIZE"
fi
