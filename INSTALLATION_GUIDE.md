# SiteRecorder Installation Guide

## Current Status

The SiteRecorder project is fully implemented with all 6 core modules and comprehensive documentation. However, to run the application, you need to install system dependencies.

## Installation Steps

### Step 1: Install System Dependencies

The project requires several system libraries. Run the installation script with sudo:

```bash
sudo ./install-deps.sh
```

This will install:
- Build tools (gcc, pkg-config, etc.)
- GTK and WebKit libraries (for Tauri GUI)
- FFmpeg libraries (for video recording)
- Chromium browser
- D-Bus and notification libraries

**Expected Time**: 5-10 minutes depending on your connection

### Step 2: Verify Installation

After dependencies are installed, verify with:

```bash
pkg-config --modversion libsoup-2.4
pkg-config --modversion webkit2gtk-4.0
pkg-config --modversion libavcodec
```

All should return version numbers without errors.

### Step 3: Build the Project

```bash
# Clean build (optional)
cargo clean

# Build in release mode
cargo build --release
```

**Expected Time**: 5-15 minutes on first build

### Step 4: Run Tests

```bash
cargo test
```

This will run all unit tests to verify modules are working correctly.

### Step 5: Run Your First Crawl

```bash
# Using cargo (development)
cargo run -- https://example.com

# Or using the compiled binary (production)
./target/release/site-recorder https://example.com
```

## Troubleshooting

### Issue: Missing libsoup-2.4

**Error**: `The system library 'libsoup-2.4' required by crate 'soup2-sys' was not found`

**Solution**:
```bash
sudo apt install libsoup2.4-dev
```

### Issue: Missing webkit2gtk

**Error**: `Package webkit2gtk-4.0 was not found`

**Solution**:
```bash
sudo apt install libwebkit2gtk-4.0-dev
```

### Issue: Missing FFmpeg

**Error**: `Package libavcodec was not found`

**Solution**:
```bash
sudo apt install libavcodec-dev libavformat-dev libavutil-dev \
                 libavfilter-dev libavdevice-dev libswscale-dev libswresample-dev
```

### Issue: Browser Won't Launch

**Error**: `Failed to launch browser: Could not find Chrome`

**Solution**:
```bash
sudo apt install chromium-browser
```

### Issue: Permission Denied on Recording

**Solution**:
```bash
mkdir -p recordings
chmod 755 recordings
```

## Alternative: Run Without Full Dependencies

If you want to test without installing all dependencies, you can run the simplified example that doesn't require video recording libraries:

```bash
# This requires only browser dependencies
cargo run --example simple_crawl -- https://example.com
```

## Minimal Dependencies

For the simplified example, you only need:

```bash
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    chromium-browser
```

## Platform-Specific Notes

### Ubuntu/Debian (Recommended)
Use the `install-deps.sh` script - it's designed for Debian-based systems.

### Fedora/RHEL
Replace `apt` with `dnf`:
```bash
sudo dnf install gcc pkg-config openssl-devel webkit2gtk3-devel \
                 gtk3-devel libsoup-devel chromium ffmpeg-devel
```

### Arch Linux
```bash
sudo pacman -S base-devel webkit2gtk gtk3 libsoup chromium ffmpeg
```

### macOS
```bash
brew install pkg-config openssl ffmpeg
# Chrome will be auto-downloaded
```

### Windows
- Install Visual Studio Build Tools
- Install FFmpeg and add to PATH
- Install Chrome browser

## Verification Checklist

After installation, verify:

- [ ] All system packages installed without errors
- [ ] `cargo build` completes successfully
- [ ] `cargo test` passes all tests
- [ ] Browser launches when running the app
- [ ] Recording directory is writable
- [ ] Notifications work (you see a notification on start)

## Getting Help

If you encounter issues:

1. Check the error message carefully
2. Search for the specific library in the error
3. Install that library using your package manager
4. Try building again

For more help:
- Open an issue on GitHub
- Check the CONTRIBUTING.md for development setup
- See README.md for full documentation

## Summary

**Full Installation**:
```bash
sudo ./install-deps.sh
cargo build --release
cargo test
cargo run -- https://example.com
```

**Minimal Installation** (simple example only):
```bash
sudo apt install build-essential pkg-config libssl-dev chromium-browser
cargo run --example simple_crawl -- https://example.com
```

## Next Steps

Once installed:
1. Read QUICKSTART.md for basic usage
2. Read README.md for full features
3. Customize src/main.rs for your needs
4. Check examples/ for more use cases

Happy crawling! 🚀
