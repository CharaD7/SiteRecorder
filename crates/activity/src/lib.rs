//! Shared event and activity logging for the SiteRecorder application.
//!
//! All Tauri commands and tooling push observations here, giving the UI a
//! single source of truth for "what is happening right now". Events are stored
//! in-memory (thread-safe, tokio-aware) and are exposed to the frontend via
//! the Tauri `get_activity` command.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Log level for an activity event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    /// Verbose diagnostics from a tool.
    Debug,
    /// Normal operation milestones (start, step, complete).
    Info,
    /// Non-fatal issues worth surfacing.
    Warning,
    /// Errors and failures.
    Error,
}

impl Default for Level {
    fn default() -> Self {
        Level::Info
    }
}

/// A single activity/event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event id.
    pub id: String,
    /// When the event was recorded.
    pub timestamp: DateTime<Utc>,
    /// The tool or subsystem that produced the event.
    pub source: String,
    /// Log level.
    pub level: Level,
    /// Human-readable message.
    pub message: String,
}

/// Errors produced by the activity logger.
#[derive(Debug, Error)]
pub enum ActivityError {
    #[error("activity store error: {0}")]
    Store(String),
}

pub type Result<T> = std::result::Result<T, ActivityError>;

/// Thread-safe in-memory activity log shared across the app.
#[derive(Debug, Default)]
pub struct Activity {
    events: Arc<RwLock<Vec<Event>>>,
    max_events: usize,
}

impl Activity {
    /// Create a new activity log.
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            max_events: 1000,
        }
    }

    /// Create a new activity log with a maximum event count.
    pub fn with_max(mut self, max_events: usize) -> Self {
        self.max_events = max_events;
        self
    }

    /// Push a new event and return its id.
    pub async fn add_event(
        &self,
        source: impl Into<String>,
        level: Level,
        message: impl Into<String>,
    ) -> Result<String> {
        let event = Event {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source: source.into(),
            level,
            message: message.into(),
        };
        let id = event.id.clone();
        let mut events = self.events.write().await;
        events.insert(0, event);
        while events.len() > self.max_events {
            events.pop();
        }
        Ok(id)
    }

    /// Convenience helper for Info-level events.
    pub async fn info(
        &self,
        source: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<String> {
        self.add_event(source, Level::Info, message).await
    }

    /// Convenience helper for Debug-level events.
    pub async fn debug(
        &self,
        source: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<String> {
        self.add_event(source, Level::Debug, message).await
    }

    /// Convenience helper for Warning-level events.
    pub async fn warn(
        &self,
        source: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<String> {
        self.add_event(source, Level::Warning, message).await
    }

    /// Convenience helper for Error-level events.
    pub async fn error(
        &self,
        source: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<String> {
        self.add_event(source, Level::Error, message).await
    }

    /// Get events with pagination.
    pub async fn get_events(&self, limit: usize, offset: usize) -> Result<Vec<Event>> {
        Ok(self
            .events
            .read()
            .await
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect())
    }

    /// Total number of events.
    pub async fn len(&self) -> usize {
        self.events.read().await.len()
    }

    /// Clear all events.
    pub async fn clear(&self) -> Result<()> {
        self.events.write().await.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn logs_and_retrieves_events() {
        let activity = Activity::new();
        activity
            .add_event("test", Level::Info, "hello")
            .await
            .unwrap();
        let events = activity.get_events(10, 0).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "hello");
    }

    #[tokio::test]
    async fn respects_max_events() {
        let activity = Activity::new().with_max(3);
        for i in 0..5 {
            activity.add_event("test", Level::Info, format!("event {i}")).await.unwrap();
        }
        let events = activity.get_events(10, 0).await.unwrap();
        assert_eq!(events.len(), 3);
    }
}
