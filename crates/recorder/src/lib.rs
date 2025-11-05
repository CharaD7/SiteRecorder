use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info};

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
}

impl Recorder {
    pub fn new(config: RecordingConfig) -> Self {
        Self {
            config,
            is_recording: Arc::new(AtomicBool::new(false)),
            metadata: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn start_recording(&self, session_id: String) -> Result<(), RecorderError> {
        if self.is_recording.load(Ordering::SeqCst) {
            return Err(RecorderError::StartFailed("Already recording".to_string()));
        }

        info!("Starting recording for session: {}", session_id);

        let metadata = RecordingMetadata {
            session_id,
            start_time: Utc::now(),
            end_time: None,
            duration_secs: None,
            file_path: None,
            format: self.config.format.clone(),
        };

        let mut meta = self.metadata.write().await;
        *meta = Some(metadata);

        self.is_recording.store(true, Ordering::SeqCst);
        
        info!("Recording started successfully");
        Ok(())
    }

    pub async fn stop_recording(&self) -> Result<PathBuf, RecorderError> {
        if !self.is_recording.load(Ordering::SeqCst) {
            return Err(RecorderError::StopFailed("Not currently recording".to_string()));
        }

        info!("Stopping recording");
        self.is_recording.store(false, Ordering::SeqCst);

        let mut meta = self.metadata.write().await;
        if let Some(metadata) = meta.as_mut() {
            let end_time = Utc::now();
            let duration = (end_time - metadata.start_time).num_seconds() as u64;
            
            metadata.end_time = Some(end_time);
            metadata.duration_secs = Some(duration);

            let filename = format!(
                "recording_{}_{}_{}.{}",
                metadata.session_id,
                metadata.start_time.format("%Y%m%d_%H%M%S"),
                duration,
                self.config.format.extension()
            );

            let file_path = self.config.output_dir.join(&filename);
            metadata.file_path = Some(file_path.clone());

            // Create placeholder file for now
            std::fs::create_dir_all(&self.config.output_dir)?;
            std::fs::write(&file_path, b"Recording data placeholder")?;

            info!("Recording stopped and saved to: {:?}", file_path);
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
