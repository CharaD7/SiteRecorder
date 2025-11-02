# SiteRecorder Quick Start Guide

Get up and running with SiteRecorder in 5 minutes!

## Prerequisites

- Rust 1.70+ installed
- Git
- Linux, macOS, or Windows

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/SiteRecorder.git
cd SiteRecorder
```

### 2. Install System Dependencies

**Linux (Ubuntu/Debian)**:
```bash
chmod +x install-deps.sh
./install-deps.sh
```

**macOS**:
```bash
brew install pkg-config openssl ffmpeg
```

**Windows**:
- Install Visual Studio Build Tools
- Install FFmpeg and add to PATH

### 3. Build the Project

```bash
cargo build --release
```

This may take 5-10 minutes on first build.

### 4. Run Your First Crawl

```bash
# Using cargo
cargo run -- https://example.com

# Or using the compiled binary
./target/release/site-recorder https://example.com
```

## What Happens?

1. **Browser Launch**: A Chromium browser window opens
2. **Crawling**: The app visits pages on the site
3. **Recording**: Browser activity is recorded
4. **Notification**: You'll get notified when complete
5. **Output**: Files saved to `./recordings/` directory

## Output Files

After running, you'll find:

```
recordings/
├── recording_session_YYYYMMDD_HHMMSS_duration.mp4
└── session_YYYYMMDD_HHMMSS_data.json
```

## Configuration

Edit `src/main.rs` to customize:

```rust
let config = AppConfig {
    base_url: "https://yoursite.com".to_string(),
    max_pages: Some(50),              // Limit pages
    delay_between_pages_ms: 2000,     // 2 second delay
    output_dir: "./recordings".to_string(),
};
```

## Common Commands

```bash
# Build
cargo build

# Build release (optimized)
cargo build --release

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- https://example.com

# Format code
cargo fmt

# Lint code
cargo clippy

# Run example
cargo run --example simple_crawl -- https://example.com
```

## Troubleshooting

### Browser Won't Launch

**Error**: `Failed to launch browser`

**Solution**:
```bash
# Linux
sudo apt install chromium-browser

# macOS  
brew install --cask google-chrome
```

### Build Errors

**Error**: `package not found` or `library not found`

**Solution**: Run the dependency installation script again:
```bash
./install-deps.sh
```

### Permission Denied

**Error**: Permission denied when accessing recordings

**Solution**:
```bash
mkdir -p recordings
chmod 755 recordings
```

## Next Steps

1. **Read the full [README](README.md)** for detailed documentation
2. **Check [CONTRIBUTING](CONTRIBUTING.md)** to contribute
3. **Browse [examples/](examples/)** for more use cases
4. **Customize** the crawler for your needs

## Examples

### Crawl with Custom Settings

```bash
# Set max pages via code
# Edit src/main.rs and change max_pages value
cargo run -- https://yoursite.com
```

### Export to Different Formats

The exporter supports JSON, CSV, and HTML:

```rust
// In your code
exporter.export_to_json(&data, "output.json")?;
exporter.export_to_csv(&data, "output.csv")?;
exporter.export_to_html(&data, "output.html")?;
```

### Headless Mode

Use headless browser for background crawling:

```rust
let browser = Browser::new_headless()?;
```

## Getting Help

- **Documentation**: See [README.md](README.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/SiteRecorder/issues)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## System Requirements

- **RAM**: 2GB minimum, 4GB recommended
- **Disk**: 500MB for application, plus space for recordings
- **CPU**: Any modern processor
- **OS**: Linux (Ubuntu 20.04+), macOS (10.15+), Windows 10+

## Performance Tips

1. **Reduce FPS**: Lower video quality for smaller files
2. **Increase Delay**: Give pages more time to load
3. **Limit Pages**: Set reasonable `max_pages` value
4. **Use Headless**: Better performance without UI

## Safety & Ethics

⚠️ **Important**: 
- Only crawl websites you have permission to access
- Respect `robots.txt` and rate limits
- Be mindful of server load
- Don't use for unauthorized access or scraping

## License

MIT License - See [LICENSE](LICENSE) for details

---

**Happy Crawling! 🚀**

For more information, visit the [full documentation](README.md).
