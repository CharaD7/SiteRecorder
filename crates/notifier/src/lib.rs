use anyhow::Result;
use notify_rust::Notification;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum NotifierError {
    #[error("Failed to send notification: {0}")]
    SendFailed(String),
    #[error("Notification error: {0}")]
    NotificationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub app_name: String,
    pub icon: Option<String>,
    pub timeout_ms: i32,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            app_name: "SiteRecorder".to_string(),
            icon: None,
            timeout_ms: 5000,
        }
    }
}

pub struct Notifier {
    config: NotificationConfig,
}

impl Notifier {
    pub fn new(config: NotificationConfig) -> Self {
        Self { config }
    }

    pub fn send(&self, title: &str, message: &str, level: NotificationLevel) -> Result<(), NotifierError> {
        info!("Sending notification: {} - {}", title, message);

        #[cfg(not(target_os = "macos"))]
        {
            let mut notification = Notification::new();
            notification
                .summary(title)
                .body(message)
                .timeout(self.config.timeout_ms);

            if let Some(icon) = &self.config.icon {
                notification.icon(icon);
            }

            notification
                .show()
                .map_err(|e| NotifierError::SendFailed(e.to_string()))?;
        }

        #[cfg(target_os = "macos")]
        {
            // macOS native notification
            let script = format!(
                r#"display notification "{}" with title "{}""#,
                message.replace('"', "\\\""),
                title.replace('"', "\\\"")
            );
            
            std::process::Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .output()
                .map_err(|e| NotifierError::SendFailed(e.to_string()))?;
        }

        debug!("Notification sent successfully");
        Ok(())
    }

    pub fn notify_info(&self, title: &str, message: &str) -> Result<(), NotifierError> {
        self.send(title, message, NotificationLevel::Info)
    }

    pub fn notify_success(&self, title: &str, message: &str) -> Result<(), NotifierError> {
        self.send(title, message, NotificationLevel::Success)
    }

    pub fn notify_warning(&self, title: &str, message: &str) -> Result<(), NotifierError> {
        self.send(title, message, NotificationLevel::Warning)
    }

    pub fn notify_error(&self, title: &str, message: &str) -> Result<(), NotifierError> {
        self.send(title, message, NotificationLevel::Error)
    }

    pub fn notify_recording_started(&self, session_id: &str) -> Result<(), NotifierError> {
        self.notify_info(
            "Recording Started",
            &format!("Session {} recording has started", session_id),
        )
    }

    pub fn notify_recording_stopped(&self, session_id: &str, duration_secs: u64) -> Result<(), NotifierError> {
        self.notify_success(
            "Recording Completed",
            &format!(
                "Session {} recording completed. Duration: {} seconds",
                session_id, duration_secs
            ),
        )
    }

    pub fn notify_crawl_started(&self, url: &str) -> Result<(), NotifierError> {
        self.notify_info(
            "Crawl Started",
            &format!("Started crawling {}", url),
        )
    }

    pub fn notify_crawl_completed(&self, total_pages: usize) -> Result<(), NotifierError> {
        self.notify_success(
            "Crawl Completed",
            &format!("Successfully visited {} pages", total_pages),
        )
    }

    pub fn notify_error_occurred(&self, error_msg: &str) -> Result<(), NotifierError> {
        self.notify_error(
            "Error Occurred",
            error_msg,
        )
    }

    pub fn notify_export_completed(&self, file_path: &str) -> Result<(), NotifierError> {
        self.notify_success(
            "Export Completed",
            &format!("Recording exported to {}", file_path),
        )
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new(NotificationConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notifier_creation() {
        let config = NotificationConfig::default();
        let notifier = Notifier::new(config);
        assert_eq!(notifier.config.app_name, "SiteRecorder");
    }

    #[test]
    fn test_notification_config_default() {
        let config = NotificationConfig::default();
        assert_eq!(config.app_name, "SiteRecorder");
        assert_eq!(config.timeout_ms, 5000);
        assert!(config.icon.is_none());
    }
}
