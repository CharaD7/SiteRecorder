# SiteRecorder

A cross-platform desktop application built in Rust that automates full-site traversal and records browser activity. Works seamlessly on Linux, macOS, and Windows.

## Documentation

- **[Installation Guide](INSTALLATION_GUIDE.md)** - Detailed setup instructions for all platforms
- **[Quick Start](QUICKSTART.md)** - Get started in minutes
- **[Quick Reference](QUICK_REFERENCE.md)** - Command and API reference
- **[Usage Guide](USAGE.md)** - Comprehensive usage documentation
- **[Contributing](CONTRIBUTING.md)** - How to contribute to the project

## Features

### Core Functionality
- Automated Site Traversal - Intelligently crawls and visits all internal pages of a website
- Dual Recording Mode - Records both the actual screen (like OBS/Kazam) AND browser screenshots simultaneously
- Real Screen Recording - Uses FFmpeg for professional screen capture with audio support
- Browser Screenshots - Captures high-quality screenshots from the browser during crawling
- Session Management - Handles login flows and stores session cookies securely
- Data Export - Exports crawl data in JSON, CSV, HTML, and PDF formats
- Desktop Notifications - Alerts you when crawling completes or errors occur
- Smart Scrolling - Automatically scrolls pages to trigger lazy-loaded content
- Navigation Simulation - Simulates real user behavior with back/forward navigation

### Security Scanner
- **20-Point Vulnerability Scan** - Comprehensive security analysis of any website
- **Active Probing** - XSS, SQLi, directory traversal, file inclusion, open redirect and exposed-file checks actively send payloads and verify real responses (no longer passive pattern matching)
- **Multi-URL Crawling** - The scanner discovers pages from the seed URL (honoring `max_depth`/`max_pages`) and tests each discovered endpoint, not just the landing page
- **Accurate TLS Verification** - Certificate validity is verified with a strict (non-lenient) client, so expired/self-signed/untrusted certs are correctly flagged
- **Detailed Findings** - Each vulnerability includes severity, description, CWE references, and remediation steps
- **Real-time Risk Scoring** - Weighted risk score from 0-10 based on severity distribution
- **Scan History & Export** - Reports are saved to `<output_dir>/scans/`, listed in the GUI, and exportable as JSON or CSV; findings can be marked as false positives (persisted per scan)
- **GUI Integration** - Full vulnerability scanner tab in the desktop application
- **CLI Support** - Run standalone scans with `site-recorder scan`, or attach a scan to a crawl via `--scan-url`

#### Vulnerability Checks:
1. **Security Headers Analysis** - X-Frame-Options, CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
2. **Cross-Site Scripting (XSS) Detection** - Reflected (active payload injection + unencoded reflection), DOM-based, and stored XSS pattern analysis
3. **SQL Injection Detection** - Active payload injection with SQL error-signature matching, form analysis, URL parameter checks
4. **Directory Traversal Detection** - Active path-traversal probing plus passive directory-listing/backup exposure checks
5. **Open Redirect Detection** - Active probing of redirect parameters via the `Location` header
6. **CSRF Vulnerability Detection** - Form token analysis, SameSite cookie checks
7. **Clickjacking Detection** - X-Frame-Options and CSP frame-ancestors analysis
8. **Mixed Content Detection** - HTTP resources on HTTPS pages
9. **Information Disclosure** - Sensitive data exposure, error messages, generator tags
10. **SSL/TLS Configuration** - Strict certificate-chain verification, HSTS enforcement
11. **Cookie Security Analysis** - Secure, HttpOnly, SameSite flag checks
12. **Server Information Leakage** - Server header, X-Powered-By, technology detection
13. **Form Security Analysis** - Autocomplete, hidden fields, GET form sensitive data
14. **File Inclusion Detection** - Active LFI/RFI payload probing (e.g. `../../etc/passwd`, `php://filter`) with leakage detection
15. **Outdated Software Detection** - WordPress, jQuery, Bootstrap, Angular, PHP version checks
16. **CORS Misconfiguration** - Detects credentialed wildcard/reflected `Access-Control-Allow-Origin`
17. **Content-Security-Policy** - Missing or weakened CSP (unsafe-inline/unsafe-eval/wildcard)
18. **Subresource Integrity** - External scripts/stylesheets loaded without `integrity`
19. **Exposed Sensitive Files** - Probes `.git/HEAD`, `.env`, `phpinfo.php`, `server-status`, `backup.zip`, etc.
20. **Directory Listing** - Detects enabled directory indexing on common paths

### Additional Features
- **Proxy Support** - Route crawling through HTTP/SOCKS proxies
- **Sitemap Ingestion** - Automatically discover URLs from sitemap.xml files
- **Session Resume** - Resume interrupted crawl sessions
- **PDF Export** - Export crawl data as professional PDF reports

### Cross-Platform Support
- Linux (X11)
- macOS
- Windows

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
│   ├── exporter/          # Data export and format conversion
│   └── scanner/           # Vulnerability scanning engine (NEW)
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
- **Proxy support** for anonymous/restricted crawling
- **Sitemap ingestion** from XML sitemaps

#### Recorder Module
- Three Recording Modes:
  - `Screen`: Real-time screen recording using FFmpeg (like OBS/Kazam)
  - `Browser`: Browser screenshot capture from headless Chrome
  - `Both`: Simultaneous screen recording AND browser screenshots (default)
- Platform-specific screen capture (x11grab for Linux, avfoundation for macOS, gdigrab for Windows)
- Supports multiple video formats (MP4, WebM, AVI, MKV)
- Optional audio recording support
- Configurable FPS and quality settings
- Automatic video encoding and frame-to-video conversion

#### Scanner Module (NEW)
- 20-point vulnerability scanning engine (active probing)
- Multi-URL discovery via crawler (honors max_depth/max_pages)
- Asynchronous HTTP-based security checks
- Detailed finding reports with CWE references
- Risk score calculation based on severity weighting
- Persisted scan reports (history) with JSON/CSV export

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
- Exports crawl data to JSON, CSV, HTML, or PDF
- Includes timestamps, URLs, and metadata
- Beautiful HTML reports with styling
- Professional PDF export with tables

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
git clone https://github.com/CharaTech/SiteRecorder.git
cd SiteRecorder

# Build the project
cargo build --release

# The binary will be at target/release/site-recorder
```

## Usage

### Using the GUI

1. Launch SiteRecorder
2. Configure your recording settings:
   - Enter the website URL
   - Choose recording mode (Screen/Browser/Both)
   - Set FPS, screen dimensions, and audio options
   - Configure max pages and delay
3. (Optional) Enable authentication for login-protected sites
4. Click "Start Recording"
5. Monitor progress in the status panel
6. Click "Stop Recording" when done

### Vulnerability Scanner (GUI)

1. Click the "Vulnerabilities" tab in the GUI
2. Set an **Output Directory** (on the Recording tab) so scans are saved to history
3. Enter the target URL to scan
4. Click "Start Scan" (the seed URL is crawled to discover additional pages, which are all tested)
5. View the risk score and severity breakdown
6. Expand individual findings for detailed information
7. Use filter buttons to show only vulnerable/warning/passed/sensitive checks
8. Mark findings as false positives (persisted per scan) and hide them with the toggle
9. Export the current report as JSON/CSV, or browse **Scan History** to load/export previous scans
10. **Vulnerabilities and sensitive data are highlighted automatically** — when a scan finds vulnerabilities or leaks of secrets/sensitive data (e.g. `.env`, `.git`, passwords, tokens, API keys), a pulsing red banner appears at the top of the results and those findings get a striped glow plus a 🔒 `SENSITIVE` badge, and are sorted to the top so your attention is drawn to them immediately

### Recording Mode Selection

Choose one of three recording modes based on your needs:

**Both (Default - Recommended)**
- Records screen AND browser screenshots simultaneously
- Complete session coverage
- Best for documentation and QA

**Screen Only**
- Real-time screen capture like OBS/Kazam
- Supports audio recording
- Best for demonstration videos

**Screenshots Only**
- Browser screenshot capture
- Lower resource usage
- Best for headless crawling

### Command Line Usage

```bash
# Run GUI (default)
site-recorder

# Basic CLI crawl
site-recorder crawl https://example.com

# Headless crawl with custom settings
site-recorder crawl https://example.com \
  --headless \
  -n 100 \
  --delay 2000 \
  -m both

# Crawl with proxy
site-recorder crawl https://example.com \
  --proxy http://proxy:8080 \
  --headless

# Crawl with sitemap ingestion
site-recorder crawl https://example.com \
  --sitemap https://example.com/sitemap.xml

# Crawl with vulnerability scan
site-recorder crawl https://example.com \
  --scan-url https://example.com \
  --headless

# Crawl with a custom login script (JavaScript executed in page context)
site-recorder crawl https://app.example.com \
  --auth-url https://app.example.com/login \
  --username admin@example.com \
  --password secret \
  --login-script ./login.js \
  --headless

# Crawl with parallel link discovery (4 concurrent workers)
site-recorder crawl https://example.com -j 4 --headless

# Screen recording of a specific region (WxH+X+Y)
site-recorder crawl https://example.com \
  -m screen --region 1280x720+100+50

# Run as daemon with logging
site-recorder crawl https://example.com \
  --daemon \
  --headless \
  --log-file /var/log/siterecorder.log \
  --pid-file /var/run/siterecorder.pid

# List previous sessions
site-recorder list --output ./recordings

# Run the vulnerability scanner standalone
site-recorder scan --url https://example.com --output ./recordings
site-recorder scan --url https://example.com --max-depth 4 --max-pages 100

# List saved scans
site-recorder scan --list --output ./recordings

# Export a saved scan (JSON or CSV)
site-recorder scan --export-id scan_20241209_150000 --format csv --output ./recordings

# Resume a session
site-recorder resume session_20241209_150000

# Show help
site-recorder --help
site-recorder crawl --help
site-recorder scan --help
```

### Daemon Mode (Headless CLI)

Run SiteRecorder as a background daemon for unattended crawling:

**Features:**
- True Unix daemon (double-fork)
- Graceful shutdown on SIGTERM/SIGINT
- PID file management
- File logging support
- No terminal attachment
- Progress bars (disabled in daemon mode)

**Example:**
```bash
# Start daemon
site-recorder crawl https://example.com \
  --daemon \
  --headless \
  --log-file /tmp/siterecorder.log \
  --pid-file /tmp/siterecorder.pid \
  -n 500

# Check if running
ps aux | grep site-recorder

# Stop gracefully
kill -TERM $(cat /tmp/siterecorder.pid)

# Or force stop
kill -9 $(cat /tmp/siterecorder.pid)

# Monitor logs
tail -f /tmp/siterecorder.log
```

**Systemd Service Example:**
```ini
[Unit]
Description=SiteRecorder Crawling Service
After=network.target

[Service]
Type=forking
User=recorder
ExecStart=/usr/local/bin/site-recorder crawl https://example.com --daemon --headless --log-file /var/log/siterecorder.log --pid-file /var/run/siterecorder.pid
PIDFile=/var/run/siterecorder.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Configuration Options

#### Recording Settings
- **Mode**: `screen`, `browser`, or `both` (default: both)
- **FPS**: 15-60 frames per second (default: 30)
- **Quality**: Video quality 0-100 (default: 80)
- **Audio**: Enable/disable audio recording (default: false)
- **Screen Size**: Resolution for screen capture (default: 1920x1080)
- **Region**: Capture only a sub-area of the screen as `WxH+X+Y`
  (e.g. `1280x720+100+50`). On Linux/X11 this uses native
  `x11grab` offset capture; on macOS/Windows and Wayland a crop
  filter is applied. Browser-screenshot mode is unaffected.

#### Crawl Settings
- **Max Pages**: Limit number of pages to visit (default: 50)
- **Delay**: Milliseconds between page visits (default: 2000)
- **Headless**: Run browser without UI (default: false)
- **Concurrency**: Number of parallel link-discovery workers (`-j`, default: 1).
  Workers fetch and parse pages over HTTP concurrently to expand the
  crawl frontier faster. The actual recording stays sequential (one tab).
- **Output Dir**: Where to save recordings
- **Proxy**: HTTP/SOCKS proxy URL for anonymous crawling
- **Sitemap**: URL to sitemap.xml for URL discovery

#### Authentication
For login-protected sites:
- Enable authentication checkbox
- Provide login URL, username, and password
- Auto-detection of login forms
- Custom CSS selectors for advanced cases
- **Custom login script**: Provide a JavaScript snippet (GUI textarea or
  `--login-script <file>`). It is executed in the login page context after
  credentials are injected as `window.__SR_USER` and `window.__SR_PASS`.
  When a script is supplied, the built-in form-fill is skipped in its favor.

#### Wayland Support
On Linux, SiteRecorder auto-detects the display server:
- **X11** (default): screen capture via FFmpeg `x11grab`.
- **Wayland** (`XDG_SESSION_TYPE=wayland` or `WAYLAND_DISPLAY` set):
  screen capture via FFmpeg `pipewire` (`-f pipewire -i default`).
  This requires a running `xdg-desktop-portal` and a PipeWire-enabled
  FFmpeg build. Region selection on Wayland is applied with a crop filter.

#### Vulnerability Scanning
- **Scan URL**: Target URL for security scanning
- **15 automated checks**: Headers, XSS, SQLi, CSRF, and more
- **Risk scoring**: Weighted severity calculation
- **Detailed reports**: CWE references, remediation steps

### Environment Variables

```bash
# Set log level
export RUST_LOG=info

# Run with debug logging
RUST_LOG=debug cargo run

# Set custom display for Linux (X11) screen recording
export DISPLAY=:0

# Force Wayland capture path (PipeWire)
export XDG_SESSION_TYPE=wayland
```

## Output

SiteRecorder generates different outputs based on the recording mode:

### Both Mode (Default)
```
recordings/
├── example_20241209_150000.mp4       # Screen recording
├── session_abc123/                   # Browser screenshots folder
│   ├── frame_000001.png
│   ├── frame_000002.png
│   └── ...
├── example_screenshots.mp4           # Video from browser frames
├── session_abc123_data.json          # Crawl metadata
└── session_abc123_scan.json          # Vulnerability scan report (if --scan-url used)
```

### Screen Mode Only
```
recordings/
├── example_20241209_150000.mp4       # Screen recording
└── session_abc123_data.json          # Crawl metadata
```

### Browser Mode Only
```
recordings/
├── session_abc123/                   # Browser screenshots folder
│   ├── frame_000001.png
│   ├── frame_000002.png
│   └── ...
├── example_screenshots.mp4           # Video from frames
└── session_abc123_data.json          # Crawl metadata
```

### File Naming Convention
- Screen recordings: `{domain}_{timestamp}.mp4`
- Screenshot folders: `session_{session_id}/`
- Data exports: `{session_id}_data.{json,csv,html,pdf}`
- Scan reports: `{session_id}_scan.json`

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
- **Proxy URL**: HTTP/SOCKS proxy for anonymous crawling
- **Sitemap URL**: URL to sitemap.xml for URL discovery

### Recorder Settings
- **Mode**: Recording mode selection
  - `Screen`: Real screen recording only (uses FFmpeg)
  - `Browser`: Browser screenshots only
  - `Both`: Simultaneous screen + browser recording (default)
- **Format**: MP4, WebM, AVI, MKV
- **FPS**: Frames per second (default: 30)
- **Quality**: Video quality 0-100 (default: 80)
- **Audio**: Enable/disable audio recording (screen mode only)
- **Screen Size**: Configurable screen dimensions (default: 1920x1080)

### Scanner Settings
- **15 automated security checks**
- **Risk score calculation** (0-10 scale)
- **Severity levels**: Critical, High, Medium, Low, Info
- **CWE references** for each finding
- **Remediation guidance** for all vulnerabilities

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p browser
cargo test -p crawler
cargo test -p recorder
cargo test -p scanner
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

### Screen Recording Issues

**Problem**: Screen recording not working or black screen

**Linux:**
```bash
# Check FFmpeg support for x11grab
ffmpeg -formats | grep x11grab

# Verify DISPLAY variable
echo $DISPLAY

# If empty, set it
export DISPLAY=:0
```

**macOS:**
- System Preferences -> Security & Privacy -> Screen Recording
- Grant permission to SiteRecorder

**Windows:**
- Ensure FFmpeg is installed and in PATH
- Run `ffmpeg -version` to verify

### Audio Recording Issues

**Problem**: Audio not being recorded

**Solutions:**
1. Ensure recording mode is "Screen" or "Both" (not "Browser")
2. Enable audio checkbox in settings
3. Check system audio permissions

**Linux:**
```bash
# Check PulseAudio
pactl list sources short

# Test audio recording
ffmpeg -f pulse -i default test.wav
```

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

### High CPU/Memory Usage

**Solutions:**
1. Lower FPS to 15-24
2. Use "Screenshots Only" mode for lower CPU usage
3. Use "Screen Only" mode for lower memory usage
4. Reduce screen resolution
5. Increase delay between pages
6. Limit max pages

### Out of Disk Space

**Problem**: Recording stops due to insufficient disk space

**Solutions:**
1. Choose a different output directory with more space
2. Lower FPS to reduce file size
3. Use "Screen Only" mode (more space-efficient)
4. Clean up old recordings
5. Enable video compression

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
5. **Proxy Support**: Use proxies for faster crawling through CDNs
6. **Sitemap**: Use sitemap ingestion for faster URL discovery

## Security Considerations

- Credentials are stored using system keyring
- Session data is encrypted at rest
- Cookies are handled securely
- No data is sent to external servers
- Proxy support for anonymous crawling
- SSL/TLS certificate verification (can be disabled for testing)

## Roadmap

- [x] Real-time screen recording (FFmpeg-based)
- [x] Screenshot capture (browser-based)
- [x] Dual recording mode (screen + screenshots)
- [x] CLI argument parsing (clap)
- [x] GUI using Tauri
- [x] Headless CLI mode
- [x] Sitemap ingestion
- [x] Proxy support
- [x] PDF export
- [x] Resume interrupted sessions
- [x] Vulnerability scanner (20-point active security scan with history/export)
- [x] Custom login script support
- [x] Multi-threaded crawling
- [x] Region-specific screen recording (select area)
- [x] Wayland support

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Authors

CharaTech - https://github.com/CharaTech

## Acknowledgments

- Built with [headless_chrome](https://crates.io/crates/headless_chrome) for browser automation
- Uses [Tauri](https://tauri.app/) framework for cross-platform support
- Desktop notifications via [notify-rust](https://crates.io/crates/notify-rust)
- HTML parsing with [scraper](https://crates.io/crates/scraper)
- PDF generation with [printpdf](https://crates.io/crates/printpdf)
- HTTP client with [reqwest](https://crates.io/crates/reqwest)

## Support

For issues and questions:
- GitHub Issues: [Create an issue](https://github.com/CharaTech/SiteRecorder/issues)
- Documentation: [Wiki](https://github.com/CharaTech/SiteRecorder/wiki)
