# Recording Modes Guide

SiteRecorder supports three different recording modes to capture your web crawling sessions.

## Recording Modes

### 1. Screen Mode 🖥️
Records the actual screen using FFmpeg (like OBS Studio or Kazam).

**Features:**
- Real-time screen capture of your entire display
- Platform-specific capture:
  - **Linux**: x11grab (X11 display capture)
  - **macOS**: avfoundation (native screen capture)
  - **Windows**: gdigrab (GDI screen capture)
- Optional audio recording
- Hardware-accelerated encoding
- Continues recording even when windows are minimized

**Best for:**
- Recording the entire browsing experience
- Capturing UI interactions and transitions
- Creating demonstration videos
- Recording with audio narration

**Configuration:**
```rust
RecordingConfig {
    mode: RecordingMode::Screen,
    audio_enabled: true,
    fps: 30,
    quality: 80,
    screen_width: Some(1920),
    screen_height: Some(1080),
    ..Default::default()
}
```

### 2. Browser Mode 📸
Captures screenshots directly from the headless Chrome browser.

**Features:**
- High-quality PNG screenshots from browser
- Captures full page content (including scrolled areas)
- Works in headless mode
- Lower resource usage than screen recording
- Frames automatically converted to video at the end

**Best for:**
- Headless browser crawling
- Capturing exact browser rendering
- Lower resource consumption
- Testing and debugging

**Configuration:**
```rust
RecordingConfig {
    mode: RecordingMode::Browser,
    fps: 10,  // Lower FPS for screenshots
    ..Default::default()
}
```

### 3. Both Mode 🎬 (Default)
Simultaneously records the screen AND captures browser screenshots.

**Features:**
- Combines benefits of both modes
- Screen recording shows the full experience
- Browser screenshots provide exact page content
- Generates two outputs: screen video + screenshot video
- Complete coverage of the crawling session

**Best for:**
- Complete documentation
- Having multiple perspectives
- Quality assurance and testing
- Comprehensive session recording

**Configuration:**
```rust
RecordingConfig {
    mode: RecordingMode::Both,
    audio_enabled: true,
    fps: 30,
    quality: 80,
    ..Default::default()
}
```

## Output Files

### Screen Mode Output
```
recordings/
└── example_20241209_143000.mp4  # Screen recording
```

### Browser Mode Output
```
recordings/
├── session_id/
│   ├── frame_000001.png
│   ├── frame_000002.png
│   └── ...
└── example_20241209_143000.mp4  # Video from frames
```

### Both Mode Output
```
recordings/
├── example_20241209_143000.mp4  # Screen recording
├── session_id/
│   ├── frame_000001.png
│   ├── frame_000002.png
│   └── ...
└── example_screenshots.mp4      # Video from browser frames
```

## Platform Requirements

### Linux
- FFmpeg with x11grab support
- X11 display server (Wayland not supported yet)
```bash
sudo apt install ffmpeg
```

### macOS
- FFmpeg with avfoundation support
```bash
brew install ffmpeg
```

### Windows
- FFmpeg with gdigrab support
- Download from: https://ffmpeg.org/download.html

## Performance Considerations

| Mode | CPU Usage | Disk I/O | Quality | Use Case |
|------|-----------|----------|---------|----------|
| Screen | High | Low | Excellent | Full recordings |
| Browser | Low | High | Perfect | Headless testing |
| Both | High | High | Best | Complete documentation |

## Audio Recording

Audio recording is only available in **Screen** and **Both** modes.

### Enable Audio:
```rust
RecordingConfig {
    audio_enabled: true,
    ..Default::default()
}
```

### Platform Audio Sources:
- **Linux**: PulseAudio (default device)
- **macOS**: System audio input
- **Windows**: Default microphone

## Troubleshooting

### Screen Recording Not Working

**Linux:**
```bash
# Check if FFmpeg supports x11grab
ffmpeg -formats | grep x11grab

# Check DISPLAY variable
echo $DISPLAY
```

**macOS:**
```bash
# Grant screen recording permission
# System Preferences → Security & Privacy → Screen Recording
```

**Windows:**
```bash
# Ensure FFmpeg is in PATH
ffmpeg -version
```

### Browser Screenshots Empty

- Ensure browser tab is set: `recorder.set_browser_tab(tab).await`
- Check browser is not in headless mode for visible content
- Verify page has loaded before screenshot

### High CPU Usage

- Reduce FPS: `fps: 15` instead of 30
- Use Browser mode instead of Screen mode
- Lower quality setting: `quality: 60`
- Reduce screen resolution

## Examples

### Minimal Screen Recording
```rust
let config = RecordingConfig {
    output_dir: PathBuf::from("./recordings"),
    mode: RecordingMode::Screen,
    fps: 24,
    quality: 70,
    ..Default::default()
};
```

### High-Quality Browser Capture
```rust
let config = RecordingConfig {
    output_dir: PathBuf::from("./screenshots"),
    mode: RecordingMode::Browser,
    fps: 5,
    format: VideoFormat::Mp4,
    ..Default::default()
};
```

### Complete Session Recording
```rust
let config = RecordingConfig {
    output_dir: PathBuf::from("./sessions"),
    mode: RecordingMode::Both,
    audio_enabled: true,
    fps: 30,
    quality: 80,
    screen_width: Some(1920),
    screen_height: Some(1080),
    ..Default::default()
};
```

## API Usage

```rust
use recorder::{Recorder, RecordingConfig, RecordingMode};

// Create recorder
let config = RecordingConfig {
    mode: RecordingMode::Both,
    ..Default::default()
};
let recorder = Recorder::new(config);

// Set browser tab (required for Browser/Both modes)
recorder.set_browser_tab(tab).await;

// Start recording
recorder.start_recording(
    "session_123".to_string(),
    Some("https://example.com".to_string())
).await?;

// ... perform crawling ...

// Stop recording
let video_path = recorder.stop_recording().await?;
println!("Recording saved to: {:?}", video_path);
```

## See Also

- [Quick Reference](QUICK_REFERENCE.md) - Command and API reference
- [Usage Guide](USAGE.md) - Comprehensive usage documentation
- [FFmpeg Setup](FFMPEG_SETUP.md) - FFmpeg installation guide
