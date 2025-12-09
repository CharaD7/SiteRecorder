# Contributing to SiteRecorder

Thank you for your interest in contributing to SiteRecorder! This document provides guidelines and instructions for contributing.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Style Guide](#style-guide)

## Code of Conduct

Be respectful, inclusive, and constructive in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/SiteRecorder.git
   cd SiteRecorder
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/CharaTech/SiteRecorder.git
   ```

## Development Setup

### Prerequisites

- Rust 1.70 or later
- System dependencies (see README.md)

### Install Dependencies

**Linux**:
```bash
./install-deps.sh
```

**macOS**:
```bash
brew install pkg-config openssl ffmpeg
```

### Build the Project

```bash
# Full build
cargo build

# Release build
cargo build --release

# Build specific crate
cargo build -p browser
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p crawler

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_crawler_creation
```

## Project Structure

```
SiteRecorder/
├── src/                    # Main application
│   └── main.rs            # Entry point
├── crates/                 # Workspace crates
│   ├── browser/           # Browser automation
│   ├── crawler/           # URL discovery and crawling
│   ├── recorder/          # Screen recording
│   ├── session/           # Session management
│   ├── notifier/          # Desktop notifications
│   └── exporter/          # Data export
├── examples/               # Example applications
└── tests/                  # Integration tests
```

### Module Responsibilities

- **browser**: Chromium wrapper, page navigation, scrolling
- **crawler**: Link extraction, URL queue, domain filtering
- **recorder**: Video capture, encoding, file management
- **session**: Authentication, cookie storage, session persistence
- **notifier**: Cross-platform desktop notifications
- **exporter**: Data serialization, format conversion

## Making Changes

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

Use prefixes:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions/modifications

### 2. Make Your Changes

- Write clean, idiomatic Rust code
- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Commit Your Changes

```bash
git add .
git commit -m "feat: add support for custom user agents"
```

#### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting changes
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Example**:
```
feat: add proxy support to browser module

- Implement SOCKS5 proxy configuration
- Add HTTP/HTTPS proxy support
- Update tests for proxy scenarios

Closes #123
```

## Testing

### Unit Tests

```bash
# Test specific module
cargo test -p browser

# Test with coverage (requires tarpaulin)
cargo tarpaulin --out Html
```

### Integration Tests

```bash
# Run integration tests
cargo test --test integration_test
```

### Manual Testing

```bash
# Run the example
cargo run --example simple_crawl -- https://example.com

# Test with logging
RUST_LOG=debug cargo run -- https://example.com
```

## Submitting Changes

### 1. Update Your Branch

```bash
git fetch upstream
git rebase upstream/main
```

### 2. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 3. Create Pull Request

- Go to GitHub and create a Pull Request
- Fill out the PR template
- Link any related issues
- Request review

### Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass locally (`cargo test`)
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] No merge conflicts
- [ ] Changes are focused and atomic

## Style Guide

### Rust Code Style

Follow the official [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/).

**Key Points**:
- Use `rustfmt` for formatting
- Use `clippy` for linting
- Prefer explicit error handling over `.unwrap()`
- Use meaningful variable names
- Keep functions small and focused

### Running Formatters and Linters

```bash
# Format code
cargo fmt

# Check formatting without changes
cargo fmt -- --check

# Run clippy
cargo clippy

# Run clippy with all features
cargo clippy --all-features --all-targets
```

### Error Handling

Use `thiserror` for custom errors:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MyError {
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
```

### Logging

Use `tracing` for structured logging:

```rust
use tracing::{debug, info, warn, error};

info!("Starting operation");
debug!("Processing item: {}", item_id);
warn!("Retrying after error: {}", err);
error!("Fatal error: {}", err);
```

### Documentation

Add documentation comments to public items:

```rust
/// Navigates the browser to the specified URL.
///
/// # Arguments
///
/// * `url` - The URL to navigate to
/// * `options` - Navigation options
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if navigation fails.
///
/// # Examples
///
/// ```
/// let browser = Browser::new()?;
/// let tab = browser.get_tab()?;
/// let options = NavigationOptions::default();
/// browser.navigate(&tab, "https://example.com", &options)?;
/// ```
pub fn navigate(&self, tab: &Arc<Tab>, url: &str, options: &NavigationOptions) -> Result<(), BrowserError> {
    // Implementation
}
```

## Adding New Features

### Adding a New Module

1. Create the crate:
   ```bash
   cargo new --lib crates/new_module
   ```

2. Add to workspace in root `Cargo.toml`:
   ```toml
   [workspace]
   members = [
       "crates/new_module",
   ]
   ```

3. Define public API in `lib.rs`
4. Add tests
5. Update main application to use new module

### Adding Dependencies

Add to the appropriate `Cargo.toml`:

```toml
[dependencies]
new_crate = "1.0"
```

For optional features:

```toml
[dependencies]
optional_crate = { version = "1.0", optional = true }

[features]
my_feature = ["optional_crate"]
```

## Common Tasks

### Add a New Error Type

```rust
#[derive(Debug, Error)]
pub enum NewError {
    #[error("Description: {0}")]
    Variant(String),
}
```

### Add a Configuration Option

1. Update config struct
2. Add default value
3. Update documentation
4. Add test

### Improve Performance

1. Benchmark first
2. Profile to identify bottlenecks
3. Optimize hot paths
4. Add benchmarks to prevent regression

## Getting Help

- **Issues**: Check existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Read the code documentation

## Recognition

Contributors will be acknowledged in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for contributing to SiteRecorder!
