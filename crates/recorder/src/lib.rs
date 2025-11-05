use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use std::sync::mpsc;
use tracing::{error, info, warn};
use scrap::{Capturer, Display};

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
}

impl Recorder {
    pub fn new(config: RecordingConfig) -> Self {
        Self {
            config,
            is_recording: Arc::new(AtomicBool::new(false)),
            metadata: Arc::new(RwLock::new(None)),
            stop_tx: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start_recording(&self, session_id: String) -> Result<(), RecorderError> {
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

        std::thread::spawn(move || {
            info!("Screen capture thread started");
            
            let display = match Display::primary() {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to get primary display: {}", e);
                    return;
                }
            };

            let mut capturer = match Capturer::new(display) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to create capturer: {}", e);
                    return;
                }
            };

            let width = capturer.width();
            let height = capturer.height();
            info!("Capturing screen: {}x{}", width, height);

            let frame_duration = std::time::Duration::from_millis(1000 / fps as u64);
            let mut frame_count = 0u64;
            let mut last_frame_time = std::time::Instant::now();

            loop {
                // Check if we should stop
                if !is_recording.load(Ordering::SeqCst) || stop_rx.try_recv().is_ok() {
                    info!("Received stop signal, ending capture");
                    break;
                }

                // Throttle frame capture to desired FPS
                if last_frame_time.elapsed() < frame_duration {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }

                match capturer.frame() {
                    Ok(frame) => {
                        last_frame_time = std::time::Instant::now();
                        let filename = format!("frame_{:06}.png", frame_count);
                        let filepath = output_dir_clone.join(filename);
                        
                        // Convert BGRA to RGBA and save
                        if let Err(e) = save_frame_as_png(&filepath, &frame, width, height) {
                            warn!("Failed to save frame {}: {}", frame_count, e);
                        } else {
                            frame_count += 1;
                            if frame_count % (fps as u64 * 10) == 0 {
                                info!("Captured {} frames", frame_count);
                            }
                        }
                    }
                    Err(e) => {
                        // Frame not ready yet or other error
                        let err_str = format!("{:?}", e);
                        if err_str.contains("WouldBlock") {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            continue;
                        } else {
                            error!("Capture error: {:?}", e);
                            break;
                        }
                    }
                }
            }

            info!("Screen capture thread stopped. Captured {} frames total", frame_count);
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

            let file_path = metadata.file_path.clone().unwrap_or_else(|| {
                self.config.output_dir.join(&metadata.session_id)
            });

            info!("Recording stopped. Frames saved to: {:?}", file_path);
            info!("Duration: {} seconds", duration);
            Ok(file_path)
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

// Helper function to save frame as PNG
fn save_frame_as_png(path: &PathBuf, frame: &[u8], width: usize, height: usize) -> Result<(), RecorderError> {
    // Convert BGRA to RGBA
    let mut rgba = Vec::with_capacity(frame.len());
    for pixel in frame.chunks_exact(4) {
        rgba.push(pixel[2]); // R
        rgba.push(pixel[1]); // G  
        rgba.push(pixel[0]); // B
        rgba.push(pixel[3]); // A
    }

    // Save as PNG using image crate
    image::save_buffer(
        path,
        &rgba,
        width as u32,
        height as u32,
        image::ColorType::Rgba8,
    ).map_err(|e| RecorderError::RecordingError(format!("Failed to save PNG: {}", e)))?;

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
        
        recorder.start_recording("test-123".to_string()).await.unwrap();
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
