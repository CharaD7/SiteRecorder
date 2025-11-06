use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
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
pub struct RecordingConfig {
    pub output_dir: PathBuf,
    pub format: VideoFormat,
    pub fps: u32,
    pub quality: u32,
    pub audio_enabled: bool,
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            output_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            format: VideoFormat::Mp4,
            fps: 30,
            quality: 80,
            audio_enabled: false,
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
}

impl Recorder {
    pub fn new(config: RecordingConfig) -> Self {
        Self {
            config,
            is_recording: Arc::new(AtomicBool::new(false)),
            metadata: Arc::new(RwLock::new(None)),
            stop_tx: Arc::new(RwLock::new(None)),
            browser_tab: Arc::new(RwLock::new(None)),
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

        info!("Starting recording for session: {}", session_id);

        // Create output directory
        let output_dir = self.config.output_dir.join(&session_id);
        std::fs::create_dir_all(&output_dir)
            .map_err(|e| RecorderError::StartFailed(format!("Failed to create output directory: {}", e)))?;

        let metadata = RecordingMetadata {
            session_id: session_id.clone(),
            url,
            start_time: Utc::now(),
            end_time: None,
            duration_secs: None,
            file_path: Some(output_dir.clone()),
            format: self.config.format.clone(),
        };

        let mut meta = self.metadata.write().await;
        *meta = Some(metadata);

        self.is_recording.store(true, Ordering::SeqCst);

        // Start capture thread
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let mut stop_tx_guard = self.stop_tx.write().await;
        *stop_tx_guard = Some(stop_tx);
        drop(stop_tx_guard);

        let is_recording = self.is_recording.clone();
        let fps = self.config.fps;
        let output_dir_clone = output_dir.clone();
        let browser_tab = self.browser_tab.clone();

        tokio::spawn(async move {
            info!("Browser screenshot capture started");

            let frame_duration = tokio::time::Duration::from_millis(1000 / fps as u64);
            let mut frame_count = 0u64;

            loop {
                // Check if we should stop
                if !is_recording.load(Ordering::SeqCst) {
                    info!("Received stop signal, ending capture");
                    break;
                }

                // Get browser tab
                let tab_guard = browser_tab.read().await;
                if let Some(ref tab) = *tab_guard {
                    // Capture screenshot from browser tab
                    match tab.capture_screenshot(headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png, None, None, true) {
                        Ok(screenshot_data) => {
                            let filename = format!("frame_{:06}.png", frame_count);
                            let filepath = output_dir_clone.join(filename);
                            
                            // Save screenshot
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

                // Wait for next frame
                tokio::time::sleep(frame_duration).await;

                // Check stop signal
                if stop_rx.try_recv().is_ok() {
                    info!("Received stop signal, ending capture");
                    break;
                }
            }

            info!("Browser screenshot capture stopped. Captured {} frames total", frame_count);
        });
        
        info!("Recording started successfully");
        Ok(())
    }

    pub async fn stop_recording(&self) -> Result<PathBuf, RecorderError> {
        if !self.is_recording.load(Ordering::SeqCst) {
            return Err(RecorderError::StopFailed("Not currently recording".to_string()));
        }

        info!("Stopping recording");
        
        // Send stop signal to capture thread
        let mut stop_tx_guard = self.stop_tx.write().await;
        if let Some(tx) = stop_tx_guard.take() {
            let _ = tx.send(());
        }
        drop(stop_tx_guard);

        self.is_recording.store(false, Ordering::SeqCst);

        // Give capture thread time to finish
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let mut meta = self.metadata.write().await;
        if let Some(metadata) = meta.as_mut() {
            let end_time = Utc::now();
            let duration = (end_time - metadata.start_time).num_seconds() as u64;
            
            metadata.end_time = Some(end_time);
            metadata.duration_secs = Some(duration);

            let frames_dir = metadata.file_path.clone().unwrap_or_else(|| {
                self.config.output_dir.join(&metadata.session_id)
            });

            info!("Recording stopped. Frames saved to: {:?}", frames_dir);
            info!("Duration: {} seconds", duration);

            // Generate video from frames
            let video_name = if let Some(url) = &metadata.url {
                extract_domain_name(url)
            } else {
                metadata.session_id.clone()
            };

            let video_path = self.config.output_dir.join(format!("{}.mp4", video_name));
            
            info!("Converting frames to video: {:?}", video_path);
            match convert_frames_to_video(&frames_dir, &video_path, self.config.fps) {
                Ok(_) => {
                    info!("Video created successfully: {:?}", video_path);
                    metadata.file_path = Some(video_path.clone());
                    Ok(video_path)
                }
                Err(e) => {
                    warn!("Failed to create video: {}. Frames are still available at: {:?}", e, frames_dir);
                    Ok(frames_dir)
                }
            }
        } else {
            Err(RecorderError::StopFailed("No recording metadata found".to_string()))
        }
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
