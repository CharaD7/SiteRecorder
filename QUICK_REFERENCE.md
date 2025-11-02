
# SiteRecorder Quick Reference

## 🚀 Quick Commands

```bash
# Install dependencies (requires sudo)
sudo ./install-deps.sh

# Build project
cargo build --release

# Run tests
cargo test

# Run application
cargo run -- https://example.com

# Run simple example (fewer dependencies)
cargo run --example simple_crawl -- https://example.com

# Format code
cargo fmt

# Lint code
cargo clippy

# Clean build artifacts
cargo clean
```

## 📖 Documentation Files

| File | Purpose |
|------|---------|
| README.md | Complete project overview and features |
| QUICKSTART.md | Get started in 5 minutes |
| INSTALLATION_GUIDE.md | Detailed installation & troubleshooting |
| CONTRIBUTING.md | Development guidelines |
| LICENSE | MIT License |

## 🏗️ Project Architecture

```
6 Workspace Crates:
├── browser    → Chromium automation & navigation
├── crawler    → URL discovery & traversal
├── recorder   → Screen recording framework
├── session    → Cookie & session management
├── notifier   → Desktop notifications
└── exporter   → JSON/CSV/HTML export
```

## 🔧 Common Tasks

### Modify Crawl Settings
Edit `src/main.rs`:
```rust
let config = AppConfig {
    base_url: "https://yoursite.com".to_string(),
    max_pages: Some(50),
    delay_between_pages_ms: 2000,
    output_dir: "./recordings".to_string(),
};
```

### Enable Debug Logging
```bash
RUST_LOG=debug cargo run -- https://example.com
```

### Check Output Files
```bash
ls -la recordings/
```

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Missing libsoup | `sudo apt install libsoup2.4-dev` |
| Missing webkit2gtk | `sudo apt install libwebkit2gtk-4.0-dev` |
| Missing FFmpeg | `sudo apt install libavcodec-dev libavformat-dev` |
| Browser won't launch | `sudo apt install chromium-browser` |

## 📦 Module Details

| Module | Key Features | Main Types |
|--------|-------------|------------|
| browser | Browser automation, scrolling, JS execution | `Browser`, `NavigationOptions` |
| crawler | Link extraction, domain filtering | `Crawler`, `CrawlConfig` |
| recorder | Video recording, metadata | `Recorder`, `RecordingConfig` |
| session | Cookie management, persistence | `SessionManager`, `SessionData` |
| notifier | Cross-platform notifications | `Notifier`, `NotificationConfig` |
| exporter | Multi-format export | `Exporter`, `RecordingData` |

## 🎯 Key Features

- ✓ Automated site traversal
- ✓ Browser recording
- ✓ Smart scrolling
- ✓ Session management
- ✓ Desktop notifications
- ✓ Multi-format export
- ✓ Cross-platform support

## 📊 Project Stats

- **Lines of Code**: 1,549
- **Documentation**: 1,135 lines
- **Modules**: 6 workspace crates
- **Tests**: Unit tests in all modules

## 🔗 Quick Links

- Full Docs: `cat README.md`
- Quick Start: `cat QUICKSTART.md`
- Installation: `cat INSTALLATION_GUIDE.md`
- Contributing: `cat CONTRIBUTING.md`

---

**Ready to start?** Run: `sudo ./install-deps.sh && cargo build --release`

