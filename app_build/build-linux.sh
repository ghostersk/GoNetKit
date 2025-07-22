#!/bin/bash
echo "Building HeaderAnalyzer for Linux..."

# Check for required dependencies
echo "Checking system dependencies..."

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
    elif command -v zypper >/dev/null 2>&1; then
        echo "Using zypper to install dependencies..."
        sudo zypper install -y pkg-config gtk3-devel libayatana-appindicator-devel
    else
        echo "Could not detect package manager. Please install manually:"
        echo "Ubuntu/Debian: sudo apt-get install pkg-config libgtk-3-dev libayatana-appindicator3-dev"
        echo "CentOS/RHEL: sudo yum install pkgconfig gtk3-devel libayatana-appindicator-gtk3-devel"
        echo "Fedora: sudo dnf install pkgconfig gtk3-devel libayatana-appindicator-gtk3-devel"
        echo "Arch: sudo pacman -S pkg-config gtk3 libayatana-appindicator"
        echo "openSUSE: sudo zypper install pkg-config gtk3-devel libayatana-appindicator-devel"
        exit 1
    fi
fi

# Verify GTK libraries are available
if ! pkg-config --exists gtk+-3.0; then
    echo "Error: GTK 3 development libraries not found."
    echo "Please install GTK 3 development packages for your distribution."
    exit 1
fi

echo "All dependencies satisfied. Building application..."

# Build the Go application
go build -o headeranalyzer

if [ $? -eq 0 ]; then
    echo "Build successful! Executable: ./headeranalyzer"
    echo "Run with: ./headeranalyzer"
else
    echo "Build failed!"
    exit 1
fi
