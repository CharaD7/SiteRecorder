# SiteRecorder Usage Guide

## Quick Start

### 1. Run with a URL

```bash
cargo run https://yourwebsite.com
```

### 2. Run with Interactive Prompt

If you don't provide a URL, the app will ask for one:

```bash
cargo run
```

You'll see:
```
No URL provided. Please enter the URL to record:
```

Just type your URL and press Enter!

### 3. Run with Options

```bash
# Visit up to 100 pages
cargo run https://example.com -- --max-pages 100

# Add 3-second delay between pages
cargo run https://example.com -- --delay 3000

# Run in headless mode (no browser window)
cargo run https://example.com -- --headless

# Custom output directory
cargo run https://example.com -- --output ./my-recordings

# Combine options
cargo run https://example.com -- --max-pages 50 --delay 2000 --headless
```

## Command Line Options

```
Usage: site-recorder [URL] [OPTIONS]

Arguments:
  [URL]  URL to crawl and record

Options:
  -m, --max-pages <MAX_PAGES>  Maximum number of pages to visit [default: 50]
  -d, --delay <DELAY>          Delay between page visits in milliseconds [default: 2000]
  -o, --output <OUTPUT>        Output directory for recordings [default: ./recordings]
      --headless               Run in headless mode (no visible browser)
  -h, --help                   Print help
  -V, --version                Print version
```

## Examples

### Record a Blog

```bash
cargo run https://myblog.com -- --max-pages 100
```

### Record a Local Development Site

```bash
cargo run http://localhost:3000
```

### Quick Scan (Headless)

```bash
cargo run https://example.com -- --max-pages 10 --headless
```

### Slow Crawl (for slow-loading sites)

```bash
cargo run https://slowsite.com -- --delay 5000
```

## Output

After running, you'll find in the `recordings/` directory:

```
recordings/
├── recording_session_20241102_210530_145.mp4
└── session_20241102_210530_data.json
```

- **MP4 file**: Video recording of the browser activity
- **JSON file**: Detailed crawl data with URLs visited, timestamps, etc.

## What the App Does

1. **Launches Browser**: Opens Chromium (visible or headless)
2. **Navigates**: Goes to your specified URL
3. **Scrolls**: Automatically scrolls to load lazy content
4. **Discovers Links**: Finds all internal links on the page
5. **Crawls**: Visits each discovered link (up to max-pages)
6. **Records**: Captures all browser activity as video
7. **Exports**: Saves video and JSON data

## Tips

- **Start Small**: Use `--max-pages 10` to test before full crawl
- **Use Headless**: Add `--headless` for faster crawling without UI
- **Adjust Delay**: Increase `--delay` for slow sites
- **Check Logs**: Use `RUST_LOG=debug cargo run` for detailed logging

## Advanced Usage

### With Environment Variables

```bash
# Debug logging
RUST_LOG=debug cargo run https://example.com

# Info logging (default)
RUST_LOG=info cargo run https://example.com
```

### Running the Compiled Binary

After `cargo build --release`:

```bash
# Direct binary execution
./target/release/site-recorder https://example.com

# With options
./target/release/site-recorder https://example.com --max-pages 100 --headless
```

## Troubleshooting

**Browser won't launch?**
```bash
sudo apt install chromium-browser
```

**Recording directory issues?**
```bash
mkdir -p recordings
chmod 755 recordings
```

**Need help?**
```bash
cargo run -- --help
```

---

**Happy Recording! 🎬**
