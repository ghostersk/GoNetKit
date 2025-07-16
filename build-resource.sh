#!/bin/bash
echo "Checking system dependencies..."

# Check if we're on Linux and need systray dependencies
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Linux detected - checking systray dependencies..."
    
    # Check for pkg-config
    if ! command -v pkg-config >/dev/null 2>&1; then
        echo "Error: pkg-config not found."
        echo "Installing required dependencies for systray..."
        
        # Detect package manager and install dependencies
        if command -v apt-get >/dev/null 2>&1; then
            echo "Using apt-get to install dependencies..."
            sudo apt-get update
            sudo apt-get install -y pkg-config libgtk-3-dev libayatana-appindicator3-dev
        elif command -v yum >/dev/null 2>&1; then
            echo "Using yum to install dependencies..."
            sudo yum install -y pkgconfig gtk3-devel libayatana-appindicator-gtk3-devel
        elif command -v dnf >/dev/null 2>&1; then
            echo "Using dnf to install dependencies..."
            sudo dnf install -y pkgconfig gtk3-devel libayatana-appindicator-gtk3-devel
        elif command -v pacman >/dev/null 2>&1; then
            echo "Using pacman to install dependencies..."
            sudo pacman -S --noconfirm pkg-config gtk3 libayatana-appindicator
        else
            echo "Could not detect package manager. Please install manually:"
            echo "  - pkg-config"
            echo "  - GTK 3 development libraries"
            echo "  - libayatana-appindicator development libraries"
            exit 1
        fi
    fi
    
    # Verify GTK libraries are available
    if ! pkg-config --exists gtk+-3.0; then
        echo "Error: GTK 3 development libraries not found."
        echo "Please install GTK 3 development packages for your distribution."
        exit 1
    fi
    
    echo "All Linux systray dependencies are satisfied."
fi

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
