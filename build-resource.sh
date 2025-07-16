#!/bin/bash
echo "Compiling Windows resource file..."

# Check if x86_64-w64-mingw32-windres is available (for cross-compilation)
if command -v x86_64-w64-mingw32-windres >/dev/null 2>&1; then
    WINDRES="x86_64-w64-mingw32-windres"
elif command -v windres >/dev/null 2>&1; then
    WINDRES="windres"
else
    echo "Error: windres not found. Please install MinGW-w64."
    echo "On Ubuntu/Debian: sudo apt-get install mingw-w64"
    echo "On macOS: brew install mingw-w64"
    exit 1
fi

# Check if favicon.ico exists
if [ ! -f "web/favicon.ico" ]; then
    echo "Error: web/favicon.ico not found!"
    echo "Please ensure your favicon.ico file is in the web folder."
    exit 1
fi

# Compile resource file to .syso
$WINDRES -i resource.rc -o resource.syso -O coff
if [ $? -ne 0 ]; then
    echo "Error: Failed to compile resource file"
    exit 1
fi

echo "Resource file compiled successfully: resource.syso"
echo "Now you can build the executable with:"
echo "GOOS=windows GOARCH=amd64 go build -ldflags=\"-H=windowsgui\" -o headeranalyzer.exe"
