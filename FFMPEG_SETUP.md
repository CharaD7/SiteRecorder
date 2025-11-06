# FFmpeg Installation Guide

SiteRecorder automatically converts screenshot frames into MP4 videos using FFmpeg. You need to install FFmpeg to enable this feature.

## Installation

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install ffmpeg
```

### Linux (Fedora/RHEL)
```bash
sudo dnf install ffmpeg
```

### macOS
```bash
brew install ffmpeg
```

### Windows
1. Download FFmpeg from: https://ffmpeg.org/download.html
2. Extract the archive
3. Add the `bin` folder to your system PATH
4. Restart your terminal

## Verify Installation

```bash
ffmpeg -version
```

You should see FFmpeg version information.

## What Happens Without FFmpeg?

If FFmpeg is not installed:
- ✅ Screenshots will still be captured (30 FPS)
- ✅ Frames saved to: `~/Videos/SiteRecorder/session_*/frame_*.png`
- ❌ No video file will be generated automatically
- ℹ️  You can manually convert frames later using FFmpeg:

```bash
ffmpeg -framerate 30 -i ~/Videos/SiteRecorder/session_*/frame_%06d.png -c:v libx264 -pix_fmt yuv420p output.mp4
```

## Video Output

When FFmpeg is installed, videos are automatically generated with the domain name:
- Recording `https://github.com` → `github.mp4`
- Recording `https://www.youtube.com` → `youtube.mp4`  
- Recording `https://example.com` → `example.mp4`

Videos are saved to your configured output directory (default: `~/Videos/SiteRecorder/`).
