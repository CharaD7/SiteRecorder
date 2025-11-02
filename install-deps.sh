#!/bin/bash

# SiteRecorder Installation Script
# This script installs all necessary system dependencies for building SiteRecorder

set -e

echo "================================================"
echo "SiteRecorder Dependency Installation Script"
echo "================================================"
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
fi

echo "Detected OS: $OS"
echo ""

if [ "$OS" == "linux" ]; then
    echo "Installing Linux dependencies..."
    echo "This requires sudo privileges."
    echo ""
    
    # Update package list
    echo "Updating package list..."
    sudo apt update
    
    # Install dependencies
    echo "Installing required packages..."
    sudo apt install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        libdbus-1-dev \
        libnotify-dev \
        libx11-dev \
        libxcb1-dev \
        libsoup2.4-dev \
        libjavascriptcoregtk-4.0-dev \
        libwebkit2gtk-4.0-dev \
        libgtk-3-dev \
        libayatana-appindicator3-dev \
        librsvg2-dev \
        patchelf \
        libavcodec-dev \
        libavformat-dev \
        libavutil-dev \
        libavfilter-dev \
        libavdevice-dev \
        libswscale-dev \
        libswresample-dev \
        chromium-browser
    
    echo ""
    echo "✅ Linux dependencies installed successfully!"
    
elif [ "$OS" == "macos" ]; then
    echo "Installing macOS dependencies..."
    echo ""
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found. Please install Homebrew first:"
        echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    echo "Installing required packages..."
    brew install pkg-config openssl ffmpeg
    
    echo ""
    echo "✅ macOS dependencies installed successfully!"
    
elif [ "$OS" == "windows" ]; then
    echo "Windows detected."
    echo "Please ensure you have:"
    echo "  1. Visual Studio Build Tools installed"
    echo "  2. FFmpeg installed and in PATH"
    echo ""
    echo "For detailed Windows setup instructions, see README.md"
    
else
    echo "❌ Unsupported operating system: $OSTYPE"
    exit 1
fi

echo ""
echo "================================================"
echo "Dependency installation complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "  1. cargo build --release"
echo "  2. cargo run -- https://example.com"
echo ""
