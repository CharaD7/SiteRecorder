use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use url::Url;
use headless_chrome::Tab;

#[derive(Debug, Error)]
pub enum RecorderError {
    #[error("Failed to start recording: {0}")]
    StartFailed(String),
    #[error("Failed to stop recording: {0}")]
    StopFailed(String),
    #[error("Recording error: {0}")]
    RecordingError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Encoding error: {0}")]
    EncodingError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VideoFormat {
    Mp4,
    Webm,
    Avi,
    Mkv,
}

impl VideoFormat {
    pub fn extension(&self) -> &str {
        match self {
            VideoFormat::Mp4 => "mp4",
            VideoFormat::Webm => "webm",
            VideoFormat::Avi => "avi",
            VideoFormat::Mkv => "mkv",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecordingMode {
    Screen,      // Record the actual screen only
    Browser,     // Record browser screenshots only
    Both,        // Record both screen and browser screenshots simultaneously
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingConfig {
    pub output_dir: PathBuf,
    pub format: VideoFormat,
    pub fps: u32,
    pub quality: u32,
    pub audio_enabled: bool,
    pub mode: RecordingMode,
    pub screen_width: Option<u32>,
    pub screen_height: Option<u32>,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            output_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            format: VideoFormat::Mp4,
            fps: 30,
            quality: 80,
            audio_enabled: false,
            mode: RecordingMode::Both,  // Default to both screen and browser recording
            screen_width: Some(1920),
            screen_height: Some(1080),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingMetadata {
    pub session_id: String,
    pub url: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_secs: Option<u64>,
    pub file_path: Option<PathBuf>,
    pub format: VideoFormat,
}

pub struct Recorder {
    config: RecordingConfig,
    is_recording: Arc<AtomicBool>,
    metadata: Arc<RwLock<Option<RecordingMetadata>>>,
    stop_tx: Arc<RwLock<Option<std::sync::mpsc::Sender<()>>>>,
    browser_tab: Arc<RwLock<Option<Arc<Tab>>>>,
    ffmpeg_process: Arc<RwLock<Option<Child>>>,
}

impl Recorder {
    pub fn new(config: RecordingConfig) -> Self {
        Self {
            config,
            is_recording: Arc::new(AtomicBool::new(false)),
            metadata: Arc::new(RwLock::new(None)),
            stop_tx: Arc::new(RwLock::new(None)),
            browser_tab: Arc::new(RwLock::new(None)),
            ffmpeg_process: Arc::new(RwLock::new(None)),
        }
    }
    
    pub async fn set_browser_tab(&self, tab: Arc<Tab>) {
        let mut tab_guard = self.browser_tab.write().await;
        *tab_guard = Some(tab);
    }

    pub async fn start_recording(&self, session_id: String, url: Option<String>) -> Result<(), RecorderError> {
        if self.is_recording.load(Ordering::SeqCst) {
            return Err(RecorderError::StartFailed("Already recording".to_string()));
        }

        info!("Starting recording for session: {} (mode: {:?})", session_id, self.config.mode);

        // Create output directory
        std::fs::create_dir_all(&self.config.output_dir)
            .map_err(|e| RecorderError::StartFailed(format!("Failed to create output directory: {}", e)))?;

        let video_name = if let Some(ref url_str) = url {
            extract_domain_name(url_str)
        } else {
            session_id.clone()
        };

        let output_path = self.config.output_dir.join(format!(
            "{}_{}.{}",
            video_name,
            chrono::Utc::now().format("%Y%m%d_%H%M%S"),
            self.config.format.extension()
        ));

        let metadata = RecordingMetadata {
            session_id: session_id.clone(),
            url: url.clone(),
            start_time: Utc::now(),
            end_time: None,
            duration_secs: None,
            file_path: Some(output_path.clone()),
            format: self.config.format.clone(),
        };

        let mut meta = self.metadata.write().await;
        *meta = Some(metadata);

        self.is_recording.store(true, Ordering::SeqCst);

        match self.config.mode {
            RecordingMode::Screen => {
                self.start_screen_recording(&output_path).await?;
            }
            RecordingMode::Browser => {
                self.start_browser_recording(&session_id).await?;
            }
            RecordingMode::Both => {
                // Start screen recording first
                info!("Starting screen recording (Both mode)...");
                self.start_screen_recording(&output_path).await?;
                
                // Give FFmpeg time to initialize before starting browser screenshots
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                
                // Then start browser screenshots
                info!("Starting browser screenshot capture (Both mode)...");
                self.start_browser_recording(&session_id).await?;
                
                info!("Started both screen recording and browser screenshot capture");
            }
        }
        
        info!("Recording started successfully: {:?}", output_path);
        Ok(())
    }

    async fn start_screen_recording(&self, output_path: &PathBuf) -> Result<(), RecorderError> {
        info!("Starting screen recording with FFmpeg");

        // Check if ffmpeg is available
        let ffmpeg_check = Command::new("ffmpeg").arg("-version").output();
        if ffmpeg_check.is_err() {
            return Err(RecorderError::StartFailed(
                "FFmpeg not found. Please install FFmpeg for screen recording.".to_string()
            ));
        }

        // Build platform-specific FFmpeg command
        let mut cmd = Command::new("ffmpeg");
        
        #[cfg(target_os = "linux")]
        {
            // Use x11grab for Linux (like Kazam)
            let display = std::env::var("DISPLAY").unwrap_or_else(|_| ":0".to_string());
            cmd.arg("-f").arg("x11grab")
               .arg("-framerate").arg(self.config.fps.to_string())
               .arg("-video_size").arg(format!("{}x{}", 
                   self.config.screen_width.unwrap_or(1920),
                   self.config.screen_height.unwrap_or(1080)))
               .arg("-i").arg(display);
        }

        #[cfg(target_os = "macos")]
        {
            // Use avfoundation for macOS
            cmd.arg("-f").arg("avfoundation")
               .arg("-framerate").arg(self.config.fps.to_string())
               .arg("-i").arg("1"); // Screen capture device
        }

        #[cfg(target_os = "windows")]
        {
            // Use gdigrab for Windows
            cmd.arg("-f").arg("gdigrab")
               .arg("-framerate").arg(self.config.fps.to_string())
               .arg("-i").arg("desktop");
        }

        // Add audio if enabled
        if self.config.audio_enabled {
            #[cfg(target_os = "linux")]
            {
                cmd.arg("-f").arg("pulse").arg("-i").arg("default");
            }
            #[cfg(target_os = "macos")]
            {
                cmd.arg("-f").arg("avfoundation").arg("-i").arg(":0");
            }
            #[cfg(target_os = "windows")]
            {
                cmd.arg("-f").arg("dshow").arg("-i").arg("audio=\"Microphone\"");
            }
        }

        // Output settings
        cmd.arg("-c:v").arg("libx264")
           .arg("-preset").arg("ultrafast")
           .arg("-crf").arg(format!("{}", 51 - (self.config.quality * 51 / 100)))
           .arg("-pix_fmt").arg("yuv420p");

        if self.config.audio_enabled {
            cmd.arg("-c:a").arg("aac");
        }

        cmd.arg("-y") // Overwrite output file
           .arg(output_path.to_str().unwrap())
           .stdin(Stdio::piped())
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        info!("Launching FFmpeg process for: {:?}", output_path);
        info!("FFmpeg command: {:?}", cmd);
        
        let mut child = cmd.spawn()
            .map_err(|e| RecorderError::StartFailed(format!("Failed to start FFmpeg: {}", e)))?;

        // Verify FFmpeg started
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        match child.try_wait() {
            Ok(Some(status)) => {
                // FFmpeg exited immediately - there's an error
                let mut stderr = String::new();
                if let Some(mut stderr_handle) = child.stderr.take() {
                    use std::io::Read;
                    let _ = stderr_handle.read_to_string(&mut stderr);
                }
                return Err(RecorderError::StartFailed(format!(
                    "FFmpeg failed to start: {}. Stderr: {}", status, stderr
                )));
            }
            Ok(None) => {
                info!("FFmpeg process started successfully");
            }
            Err(e) => {
                error!("Error checking FFmpeg status: {}", e);
            }
        }

        let mut ffmpeg_guard = self.ffmpeg_process.write().await;
        *ffmpeg_guard = Some(child);

        Ok(())
    }

    async fn start_browser_recording(&self, session_id: &str) -> Result<(), RecorderError> {
        info!("Starting browser screenshot capture");

        let output_dir = self.config.output_dir.join(session_id);
        std::fs::create_dir_all(&output_dir)
            .map_err(|e| RecorderError::StartFailed(format!("Failed to create output directory: {}", e)))?;

        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let mut stop_tx_guard = self.stop_tx.write().await;
        *stop_tx_guard = Some(stop_tx);
        drop(stop_tx_guard);

        let is_recording = self.is_recording.clone();
        let fps = self.config.fps;
        let output_dir_clone = output_dir.clone();
        let browser_tab = self.browser_tab.clone();

        tokio::spawn(async move {
            let frame_duration = tokio::time::Duration::from_millis(1000 / fps as u64);
            let mut frame_count = 0u64;

            loop {
                if !is_recording.load(Ordering::SeqCst) {
                    break;
                }

                let tab_guard = browser_tab.read().await;
                if let Some(ref tab) = *tab_guard {
                    match tab.capture_screenshot(headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png, None, None, true) {
                        Ok(screenshot_data) => {
                            let filename = format!("frame_{:06}.png", frame_count);
                            let filepath = output_dir_clone.join(filename);
                            
                            if let Err(e) = std::fs::write(&filepath, &screenshot_data) {
                                warn!("Failed to save screenshot {}: {}", frame_count, e);
                            } else {
                                frame_count += 1;
                                if frame_count % (fps as u64 * 10) == 0 {
                                    info!("Captured {} screenshots", frame_count);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to capture screenshot: {}", e);
                        }
                    }
                } else {
                    warn!("No browser tab set for recording");
                }
                drop(tab_guard);

                tokio::time::sleep(frame_duration).await;

                if stop_rx.try_recv().is_ok() {
                    break;
                }
            }

            info!("Browser screenshot capture stopped. Captured {} frames", frame_count);
        });

        Ok(())
    }

    pub async fn stop_recording(&self) -> Result<PathBuf, RecorderError> {
        if !self.is_recording.load(Ordering::SeqCst) {
            return Err(RecorderError::StopFailed("Not currently recording".to_string()));
        }

        info!("Stopping recording");
        
        // Check minimum recording duration for screen recording
        let meta = self.metadata.read().await;
        if let Some(metadata) = meta.as_ref() {
            let duration = (Utc::now() - metadata.start_time).num_seconds();
            if duration < 2 && matches!(self.config.mode, RecordingMode::Screen | RecordingMode::Both) {
                warn!("Recording duration is very short ({}s), video may not be properly encoded", duration);
            }
        }
        drop(meta);
        
        self.is_recording.store(false, Ordering::SeqCst);

        match self.config.mode {
            RecordingMode::Screen => {
                self.stop_screen_recording().await?;
            }
            RecordingMode::Browser => {
                self.stop_browser_recording().await?;
            }
            RecordingMode::Both => {
                // Stop both recordings
                self.stop_screen_recording().await?;
                self.stop_browser_recording().await?;
                info!("Stopped both screen recording and browser screenshot capture");
            }
        }

        let mut meta = self.metadata.write().await;
        if let Some(metadata) = meta.as_mut() {
            let end_time = Utc::now();
            let duration = (end_time - metadata.start_time).num_seconds() as u64;
            
            metadata.end_time = Some(end_time);
            metadata.duration_secs = Some(duration);

            info!("Recording stopped. Duration: {} seconds", duration);
            
            let output_path = metadata.file_path.clone()
                .ok_or_else(|| RecorderError::StopFailed("No output path found".to_string()))?;
            
            Ok(output_path)
        } else {
            Err(RecorderError::StopFailed("No recording metadata found".to_string()))
        }
    }

    async fn stop_screen_recording(&self) -> Result<(), RecorderError> {
        info!("Stopping FFmpeg screen recording");

        let mut ffmpeg_guard = self.ffmpeg_process.write().await;
        if let Some(mut child) = ffmpeg_guard.take() {
            info!("Sending quit signal to FFmpeg...");
            
            // Send 'q' to stdin to gracefully stop FFmpeg
            if let Some(ref mut stdin) = child.stdin {
                use std::io::Write;
                match stdin.write_all(b"q") {
                    Ok(_) => {
                        if let Err(e) = stdin.flush() {
                            warn!("Failed to flush stdin: {}", e);
                        } else {
                            info!("Sent 'q' command to FFmpeg");
                        }
                    }
                    Err(e) => {
                        warn!("Failed to write to FFmpeg stdin: {}", e);
                    }
                }
                // Drop stdin to close the pipe
                drop(child.stdin.take());
            }

            // Give FFmpeg time to finalize the video
            info!("Waiting for FFmpeg to finalize video...");
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

            // Check if process exited
            match child.try_wait() {
                Ok(Some(status)) => {
                    info!("FFmpeg exited with status: {}", status);
                }
                Ok(None) => {
                    warn!("FFmpeg still running, sending SIGTERM...");
                    // Force kill if still running
                    if let Err(e) = child.kill() {
                        error!("Failed to kill FFmpeg: {}", e);
                    }
                    
                    // Wait for process to exit
                    match child.wait() {
                        Ok(status) => info!("FFmpeg terminated with status: {}", status),
                        Err(e) => error!("Error waiting for FFmpeg: {}", e),
                    }
                }
                Err(e) => {
                    error!("Error checking FFmpeg status: {}", e);
                }
            }
            
            info!("FFmpeg process stopped");
        } else {
            warn!("No FFmpeg process to stop");
        }

        Ok(())
    }

    async fn stop_browser_recording(&self) -> Result<(), RecorderError> {
        info!("Stopping browser screenshot capture");

        // Send stop signal
        let mut stop_tx_guard = self.stop_tx.write().await;
        if let Some(tx) = stop_tx_guard.take() {
            let _ = tx.send(());
        }
        drop(stop_tx_guard);

        // Give capture thread time to finish
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let meta = self.metadata.read().await;
        if let Some(metadata) = meta.as_ref() {
            let frames_dir = self.config.output_dir.join(&metadata.session_id);
            let video_path = metadata.file_path.clone().unwrap();

            info!("Converting frames to video: {:?}", video_path);
            match convert_frames_to_video(&frames_dir, &video_path, self.config.fps) {
                Ok(_) => {
                    info!("Video created successfully: {:?}", video_path);
                }
                Err(e) => {
                    warn!("Failed to create video: {}. Frames available at: {:?}", e, frames_dir);
                }
            }
        }

        Ok(())
    }

    pub fn is_recording(&self) -> bool {
        self.is_recording.load(Ordering::SeqCst)
    }

    pub async fn get_metadata(&self) -> Option<RecordingMetadata> {
        let meta = self.metadata.read().await;
        meta.clone()
    }

    pub async fn get_duration(&self) -> Option<u64> {
        let meta = self.metadata.read().await;
        if let Some(metadata) = meta.as_ref() {
            if let Some(end_time) = metadata.end_time {
                Some((end_time - metadata.start_time).num_seconds() as u64)
            } else if self.is_recording() {
                Some((Utc::now() - metadata.start_time).num_seconds() as u64)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub async fn pause_recording(&self) -> Result<(), RecorderError> {
        if !self.is_recording() {
            return Err(RecorderError::RecordingError("Not currently recording".to_string()));
        }
        
        info!("Recording paused");
        Ok(())
    }

    pub async fn resume_recording(&self) -> Result<(), RecorderError> {
        if !self.is_recording() {
            return Err(RecorderError::RecordingError("Not currently recording".to_string()));
        }
        
        info!("Recording resumed");
        Ok(())
    }
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new(RecordingConfig::default())
    }
}

// Extract domain name from URL
fn extract_domain_name(url_str: &str) -> String {
    if let Ok(url) = Url::parse(url_str) {
        if let Some(domain) = url.host_str() {
            // Remove www. prefix if present
            let domain = domain.strip_prefix("www.").unwrap_or(domain);
            // Get the domain without TLD (e.g., github from github.com)
            let parts: Vec<&str> = domain.split('.').collect();
            if !parts.is_empty() {
                return parts[0].to_string();
            }
        }
    }
    // Fallback to session timestamp
    format!("recording_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"))
}

// Convert frames to video using FFmpeg
fn convert_frames_to_video(frames_dir: &PathBuf, output_path: &PathBuf, fps: u32) -> Result<(), RecorderError> {
    // Check if ffmpeg is available
    let ffmpeg_check = Command::new("ffmpeg")
        .arg("-version")
        .output();

    if ffmpeg_check.is_err() {
        return Err(RecorderError::EncodingError(
            "FFmpeg not found. Please install FFmpeg to generate videos. Frames are saved and can be converted manually.".to_string()
        ));
    }

    info!("Running FFmpeg to create video...");
    
    // Build ffmpeg command
    let frame_pattern = frames_dir.join("frame_%06d.png");
    let output = Command::new("ffmpeg")
        .arg("-framerate")
        .arg(fps.to_string())
        .arg("-i")
        .arg(frame_pattern.to_str().unwrap())
        .arg("-c:v")
        .arg("libx264")
        .arg("-pix_fmt")
        .arg("yuv420p")
        .arg("-y") // Overwrite output file
        .arg(output_path.to_str().unwrap())
        .output()
        .map_err(|e| RecorderError::EncodingError(format!("Failed to run FFmpeg: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RecorderError::EncodingError(format!("FFmpeg failed: {}", stderr)));
    }

    info!("FFmpeg completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_recorder_creation() {
        let config = RecordingConfig::default();
        let recorder = Recorder::new(config);
        assert!(!recorder.is_recording());
    }

    #[tokio::test]
    async fn test_start_stop_recording() {
        let config = RecordingConfig::default();
        let recorder = Recorder::new(config);
        
        recorder.start_recording("test-123".to_string(), Some("https://example.com".to_string())).await.unwrap();
        assert!(recorder.is_recording());
        
        let file_path = recorder.stop_recording().await.unwrap();
        assert!(!recorder.is_recording());
        assert!(file_path.exists());
        
        // Cleanup
        std::fs::remove_file(file_path).ok();
    }

    #[test]
    fn test_video_format_extension() {
        assert_eq!(VideoFormat::Mp4.extension(), "mp4");
        assert_eq!(VideoFormat::Webm.extension(), "webm");
        assert_eq!(VideoFormat::Avi.extension(), "avi");
        assert_eq!(VideoFormat::Mkv.extension(), "mkv");
    }
}
