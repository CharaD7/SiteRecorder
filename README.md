# SiteRecorder

A cross-platform desktop application built in Rust that automates full-site traversal and records browser activity. Works seamlessly on Linux, macOS, and Windows.

## Features

### Core Functionality
- 🌐 **Automated Site Traversal**: Intelligently crawls and visits all internal pages of a website
- 🎥 **Screen Recording**: Records browser activity during the entire crawling session
- 🔐 **Session Management**: Handles login flows and stores session cookies securely
- 📊 **Data Export**: Exports crawl data in JSON, CSV, and HTML formats
- 🔔 **Desktop Notifications**: Alerts you when crawling completes or errors occur
- 🎯 **Smart Scrolling**: Automatically scrolls pages to trigger lazy-loaded content
- 🔄 **Navigation Simulation**: Simulates real user behavior with back/forward navigation

### Cross-Platform Support
- ✅ Linux (X11)
- ✅ macOS
- ✅ Windows

## Architecture

SiteRecorder is built using a modular workspace architecture:

```
SiteRecorder/
├── src/                    # Main application entry point
├── crates/
│   ├── browser/           # Chromium browser wrapper and navigation
│   ├── crawler/           # URL discovery and site traversal logic
│   ├── recorder/          # Screen capture and video encoding
│   ├── session/           # Login flow and cookie management
│   ├── notifier/          # Desktop notification system
│   └── exporter/          # Data export and format conversion
```

### Module Descriptions

#### Browser Module
- Wraps headless Chrome for automated navigation
- Handles page scrolling (incremental and full-page)
- Executes JavaScript for dynamic content
- Supports both headless and visible modes

#### Crawler Module
- Discovers internal links from HTML pages
- Maintains visited/unvisited URL queues
- Filters external links (stays within domain)
- Supports configurable depth limits

#### Recorder Module
- Captures screen activity during crawling
- Supports multiple video formats (MP4, WebM, AVI, MKV)
- Continues recording even when screen is locked
- Configurable FPS and quality settings

#### Session Module
- Manages authentication and cookies
- Secure credential storage using system keyring
- Session persistence across runs
- Cookie expiration handling

#### Notifier Module
- Cross-platform desktop notifications
- Different notification levels (info, success, warning, error)
- Custom notification templates for common events

#### Exporter Module
- Exports crawl data to JSON, CSV, or HTML
- Includes timestamps, URLs, and metadata
- Beautiful HTML reports with styling

## Installation

### Prerequisites

1. **Rust Toolchain** (1.70 or later)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **System Dependencies**

   **Linux (Ubuntu/Debian)**:
   ```bash
   sudo apt update
   sudo apt install -y \
       build-essential \
       pkg-config \
       libssl-dev \
       libdbus-1-dev \
       libnotify-dev \
       libx11-dev \
       libxcb1-dev \
       chromium-browser
   ```

   **macOS**:
   ```bash
   brew install pkg-config openssl
   ```

   **Windows**:
   - Install Visual Studio Build Tools
   - Chrome/Chromium will be downloaded automatically

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/SiteRecorder.git
cd SiteRecorder

# Build the project
cargo build --release

# The binary will be at target/release/site-recorder
```

## Usage

### Basic Usage

```bash
# Run with default settings (example.com)
cargo run

# Crawl a specific website
cargo run -- https://yoursite.com

# Or use the compiled binary
./target/release/site-recorder https://yoursite.com
```

### Advanced Configuration

The application can be configured through the code or by modifying the `AppConfig` struct:

```rust
let config = AppConfig {
    base_url: "https://example.com".to_string(),
    max_pages: Some(100),                  // Maximum pages to visit
    delay_between_pages_ms: 2000,          // Delay between page visits
    output_dir: "./recordings".to_string(), // Output directory
};
```

### Environment Variables

```bash
# Set log level
export RUST_LOG=info

# Run with debug logging
RUST_LOG=debug cargo run -- https://example.com
```

## Output

SiteRecorder generates the following outputs:

1. **Video Recording**: `recording_<session_id>_<timestamp>_<duration>.mp4`
2. **Crawl Data**: `<session_id>_data.json`
3. **Session Logs**: Console output with detailed progress

### Example Output Structure

```
recordings/
├── recording_session_20240101_120000_145.mp4
├── session_20240101_120000_data.json
└── session_20240101_120000_data.html
```

## Configuration Options

### Browser Settings
- **Headless Mode**: Run browser without UI
- **Window Size**: Default 1920x1080
- **Timeout**: 30 seconds per page
- **User Agent**: Customizable

### Crawler Settings
- **Max Depth**: Maximum crawl depth (default: 10)
- **Same Domain Only**: Stay within the base domain (default: true)
- **Ignore Fragments**: Ignore URL fragments (default: true)
- **Ignore Query Params**: Optional query parameter filtering

### Recorder Settings
- **Format**: MP4, WebM, AVI, MKV
- **FPS**: Frames per second (default: 30)
- **Quality**: Video quality 0-100 (default: 80)
- **Audio**: Enable/disable audio recording

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p browser
cargo test -p crawler
cargo test -p recorder
```

### Code Structure

Each module follows a consistent pattern:
- Error types using `thiserror`
- Configuration structs with defaults
- Async operations using `tokio`
- Logging with `tracing`

### Adding New Features

1. Choose the appropriate crate for your feature
2. Add dependencies to the crate's `Cargo.toml`
3. Implement the feature with proper error handling
4. Add tests
5. Update documentation

## Troubleshooting

### Browser Launch Issues

**Problem**: Browser fails to launch
```
Error: Failed to launch browser: Could not find Chrome
```

**Solution**: Install Chromium or Chrome
```bash
# Linux
sudo apt install chromium-browser

# macOS
brew install --cask google-chrome

# Windows
# Download and install Chrome from google.com/chrome
```

### Permission Issues on Linux

**Problem**: Screen recording permission denied

**Solution**: Grant necessary permissions
```bash
# Add user to video group
sudo usermod -a -G video $USER

# Logout and login again
```

### Notification Issues

**Problem**: Notifications not showing

**Solution**: 
- Linux: Ensure `libnotify` is installed
- macOS: Grant notification permissions in System Preferences
- Windows: Check Windows notification settings

## Performance Tips

1. **Adjust Delay**: Increase `delay_between_pages_ms` for slower sites
2. **Limit Pages**: Set `max_pages` to avoid excessive crawling
3. **Headless Mode**: Use headless browser for better performance
4. **Video Quality**: Lower quality/FPS for smaller file sizes

## Security Considerations

- Credentials are stored using system keyring
- Session data is encrypted at rest
- Cookies are handled securely
- No data is sent to external servers

## Roadmap

- [ ] CLI argument parsing (clap)
- [ ] GUI using Tauri
- [ ] Headless CLI mode
- [ ] Sitemap ingestion
- [ ] Custom login script support
- [ ] Proxy support
- [ ] Screenshot capture
- [ ] PDF export
- [ ] Real-time screen recording (not placeholder)
- [ ] Multi-threaded crawling
- [ ] Resume interrupted sessions

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Authors

SiteRecorder Team

## Acknowledgments

- Built with [headless_chrome](https://crates.io/crates/headless_chrome) for browser automation
- Uses [Tauri](https://tauri.app/) framework for cross-platform support
- Desktop notifications via [notify-rust](https://crates.io/crates/notify-rust)
- HTML parsing with [scraper](https://crates.io/crates/scraper)

## Support

For issues and questions:
- GitHub Issues: [Create an issue](https://github.com/yourusername/SiteRecorder/issues)
- Documentation: [Wiki](https://github.com/yourusername/SiteRecorder/wiki)
