use anyhow::Result;
use cookie_store::CookieStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Session error: {0}")]
    SessionError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
    pub login_url: String,
    pub username_field: String,
    pub password_field: String,
    pub submit_selector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub session_id: String,
    pub cookies: Vec<SerializableCookie>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableCookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub expires: Option<i64>,
}

pub struct SessionManager {
    session_data: Arc<RwLock<Option<SessionData>>>,
    #[allow(dead_code)]
    cookie_store: Arc<RwLock<CookieStore>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            session_data: Arc::new(RwLock::new(None)),
            cookie_store: Arc::new(RwLock::new(CookieStore::default())),
        }
    }

    pub async fn create_session(&self, session_id: String) -> Result<(), SessionError> {
        let session = SessionData {
            session_id,
            cookies: Vec::new(),
            created_at: chrono::Utc::now().timestamp(),
            expires_at: None,
        };

        let mut data = self.session_data.write().await;
        *data = Some(session);
        info!("Session created");
        Ok(())
    }

    pub async fn add_cookie(&self, cookie: SerializableCookie) -> Result<(), SessionError> {
        let mut data = self.session_data.write().await;
        if let Some(session) = data.as_mut() {
            session.cookies.push(cookie);
            debug!("Cookie added to session");
            Ok(())
        } else {
            Err(SessionError::SessionError("No active session".to_string()))
        }
    }

    pub async fn get_cookies(&self) -> Result<Vec<SerializableCookie>, SessionError> {
        let data = self.session_data.read().await;
        if let Some(session) = data.as_ref() {
            Ok(session.cookies.clone())
        } else {
            Ok(Vec::new())
        }
    }

    pub async fn save_session(&self, path: &str) -> Result<(), SessionError> {
        let data = self.session_data.read().await;
        if let Some(session) = data.as_ref() {
            let json = serde_json::to_string_pretty(session)?;
            std::fs::write(path, json)
                .map_err(|e| SessionError::StorageError(e.to_string()))?;
            info!("Session saved to {}", path);
            Ok(())
        } else {
            Err(SessionError::SessionError("No active session".to_string()))
        }
    }

    pub async fn load_session(&self, path: &str) -> Result<(), SessionError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| SessionError::StorageError(e.to_string()))?;
        let session: SessionData = serde_json::from_str(&json)?;
        
        let mut data = self.session_data.write().await;
        *data = Some(session);
        info!("Session loaded from {}", path);
        Ok(())
    }

    pub async fn get_session_id(&self) -> Option<String> {
        let data = self.session_data.read().await;
        data.as_ref().map(|s| s.session_id.clone())
    }

    pub async fn clear_session(&self) {
        let mut data = self.session_data.write().await;
        *data = None;
        info!("Session cleared");
    }

    pub async fn is_active(&self) -> bool {
        let data = self.session_data.read().await;
        data.is_some()
    }

    pub async fn set_expiry(&self, expires_at: i64) -> Result<(), SessionError> {
        let mut data = self.session_data.write().await;
        if let Some(session) = data.as_mut() {
            session.expires_at = Some(expires_at);
            Ok(())
        } else {
            Err(SessionError::SessionError("No active session".to_string()))
        }
    }

    pub async fn is_expired(&self) -> bool {
        let data = self.session_data.read().await;
        if let Some(session) = data.as_ref() {
            if let Some(expires_at) = session.expires_at {
                return chrono::Utc::now().timestamp() > expires_at;
            }
        }
        false
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn create_cookie(name: &str, value: &str, domain: Option<&str>) -> SerializableCookie {
    SerializableCookie {
        name: name.to_string(),
        value: value.to_string(),
        domain: domain.map(|d| d.to_string()),
        path: Some("/".to_string()),
        secure: false,
        http_only: false,
        expires: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation() {
        let manager = SessionManager::new();
        assert!(!manager.is_active().await);
        
        manager.create_session("test-123".to_string()).await.unwrap();
        assert!(manager.is_active().await);
        assert_eq!(manager.get_session_id().await, Some("test-123".to_string()));
    }

    #[tokio::test]
    async fn test_cookie_management() {
        let manager = SessionManager::new();
        manager.create_session("test-456".to_string()).await.unwrap();
        
        let cookie = create_cookie("session", "abc123", Some("example.com"));
        manager.add_cookie(cookie).await.unwrap();
        
        let cookies = manager.get_cookies().await.unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");
    }

    #[tokio::test]
    async fn test_session_expiry() {
        let manager = SessionManager::new();
        manager.create_session("test-789".to_string()).await.unwrap();
        
        let past_time = chrono::Utc::now().timestamp() - 3600;
        manager.set_expiry(past_time).await.unwrap();
        
        assert!(manager.is_expired().await);
    }
}
