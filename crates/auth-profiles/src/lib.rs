use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthProfileError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Profile not found: {0}")]
    NotFound(String),
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("TOTP error: {0}")]
    TotpError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, AuthProfileError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProfile {
    pub id: String,
    pub name: String,
    pub target_url: String,
    pub auth_type: AuthType,
    pub username: Option<String>,
    pub encrypted_password: Option<String>,
    pub login_url: Option<String>,
    pub mfa_config: Option<MfaConfig>,
    pub custom_headers: Option<serde_json::Value>,
    pub login_script: Option<String>,
    pub session_ttl_minutes: i64,
    pub reauth_strategy: ReauthStrategy,
    pub created_at: String,
    pub updated_at: String,
    pub last_used: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthType {
    None,
    Form,
    Basic,
    Bearer,
    OAuth,
    ApiKey,
    Certificate,
    Script,
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthType::None => write!(f, "none"),
            AuthType::Form => write!(f, "form"),
            AuthType::Basic => write!(f, "basic"),
            AuthType::Bearer => write!(f, "bearer"),
            AuthType::OAuth => write!(f, "oauth"),
            AuthType::ApiKey => write!(f, "apikey"),
            AuthType::Certificate => write!(f, "certificate"),
            AuthType::Script => write!(f, "script"),
        }
    }
}

impl AuthType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "form" => AuthType::Form,
            "basic" => AuthType::Basic,
            "bearer" => AuthType::Bearer,
            "oauth" => AuthType::OAuth,
            "apikey" | "api_key" => AuthType::ApiKey,
            "certificate" | "cert" => AuthType::Certificate,
            "script" => AuthType::Script,
            _ => AuthType::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MfaType {
    None,
    Totp,
    Sms,
    Email,
    Push,
    Hardware,
}

impl std::fmt::Display for MfaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MfaType::None => write!(f, "none"),
            MfaType::Totp => write!(f, "totp"),
            MfaType::Sms => write!(f, "sms"),
            MfaType::Email => write!(f, "email"),
            MfaType::Push => write!(f, "push"),
            MfaType::Hardware => write!(f, "hardware"),
        }
    }
}

impl MfaType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "totp" => MfaType::Totp,
            "sms" => MfaType::Sms,
            "email" => MfaType::Email,
            "push" => MfaType::Push,
            "hardware" => MfaType::Hardware,
            _ => MfaType::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub mfa_type: MfaType,
    pub encrypted_totp_secret: Option<String>,
    pub backup_codes: Option<Vec<String>>,
    pub phone: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReauthStrategy {
    Automatic,
    TtlBased,
    Manual,
}

impl std::fmt::Display for ReauthStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReauthStrategy::Automatic => write!(f, "auto"),
            ReauthStrategy::TtlBased => write!(f, "ttl"),
            ReauthStrategy::Manual => write!(f, "manual"),
        }
    }
}

impl ReauthStrategy {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "auto" | "automatic" => ReauthStrategy::Automatic,
            "ttl" => ReauthStrategy::TtlBased,
            _ => ReauthStrategy::Manual,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTestResult {
    pub success: bool,
    pub message: String,
    pub session_token: Option<String>,
    pub cookies: Option<Vec<CookieEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieEntry {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpResult {
    pub code: String,
    pub remaining_seconds: u64,
    pub next_code: String,
}

pub struct AuthProfileManager {
    conn: Connection,
}

impl AuthProfileManager {
    pub fn new(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(db_path)?;
        let manager = Self { conn };
        manager.init_db()?;
        Ok(manager)
    }

    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let manager = Self { conn };
        manager.init_db()?;
        Ok(manager)
    }

    fn init_db(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS auth_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                auth_type TEXT NOT NULL DEFAULT 'none',
                username TEXT,
                encrypted_password TEXT,
                login_url TEXT,
                mfa_config TEXT,
                custom_headers TEXT,
                login_script TEXT,
                session_ttl_minutes INTEGER NOT NULL DEFAULT 30,
                reauth_strategy TEXT NOT NULL DEFAULT 'auto',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used TEXT
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS auth_sessions (
                id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                session_token TEXT,
                cookies TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (profile_id) REFERENCES auth_profiles(id) ON DELETE CASCADE
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                ip_address TEXT
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_profile ON auth_sessions(profile_id)",
            [],
        )?;

        Ok(())
    }

    pub fn create_profile(&self, profile: &AuthProfile) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let mfa_config_json = profile.mfa_config.as_ref()
            .and_then(|m| serde_json::to_string(m).ok());
        let headers_json = profile.custom_headers.as_ref()
            .map(|h| serde_json::to_string(h).unwrap_or_default());

        self.conn.execute(
            "INSERT INTO auth_profiles (
                id, name, target_url, auth_type, username, encrypted_password,
                login_url, mfa_config, custom_headers, login_script,
                session_ttl_minutes, reauth_strategy, created_at, updated_at, last_used
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                profile.id,
                profile.name,
                profile.target_url,
                profile.auth_type.to_string(),
                profile.username,
                profile.encrypted_password,
                profile.login_url,
                mfa_config_json,
                headers_json,
                profile.login_script,
                profile.session_ttl_minutes,
                profile.reauth_strategy.to_string(),
                now,
                now,
                Option::<String>::None,
            ],
        )?;

        Ok(())
    }

    pub fn get_profile(&self, id: &str) -> Result<Option<AuthProfile>> {
        let result = self.conn.query_row(
            "SELECT id, name, target_url, auth_type, username, encrypted_password,
                    login_url, mfa_config, custom_headers, login_script,
                    session_ttl_minutes, reauth_strategy, created_at, updated_at, last_used
             FROM auth_profiles WHERE id = ?1",
            [id],
            |row| {
                let auth_type_str: String = row.get(3)?;
                let mfa_json: Option<String> = row.get(7)?;
                let headers_json: Option<String> = row.get(8)?;
                let reauth_str: String = row.get(11)?;

                Ok(AuthProfile {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    target_url: row.get(2)?,
                    auth_type: AuthType::from_str(&auth_type_str),
                    username: row.get(4)?,
                    encrypted_password: row.get(5)?,
                    login_url: row.get(6)?,
                    mfa_config: mfa_json.and_then(|j| serde_json::from_str(&j).ok()),
                    custom_headers: headers_json.and_then(|j| serde_json::from_str(&j).ok()),
                    login_script: row.get(9)?,
                    session_ttl_minutes: row.get(10)?,
                    reauth_strategy: ReauthStrategy::from_str(&reauth_str),
                    created_at: row.get(12)?,
                    updated_at: row.get(13)?,
                    last_used: row.get(14)?,
                })
            },
        ).optional()?;

        Ok(result)
    }

    pub fn list_profiles(&self) -> Result<Vec<AuthProfile>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, target_url, auth_type, username, encrypted_password,
                    login_url, mfa_config, custom_headers, login_script,
                    session_ttl_minutes, reauth_strategy, created_at, updated_at, last_used
             FROM auth_profiles ORDER BY updated_at DESC"
        )?;

        let profiles = stmt.query_map([], |row| {
            let auth_type_str: String = row.get(3)?;
            let mfa_json: Option<String> = row.get(7)?;
            let headers_json: Option<String> = row.get(8)?;
            let reauth_str: String = row.get(11)?;

            Ok(AuthProfile {
                id: row.get(0)?,
                name: row.get(1)?,
                target_url: row.get(2)?,
                auth_type: AuthType::from_str(&auth_type_str),
                username: row.get(4)?,
                encrypted_password: row.get(5)?,
                login_url: row.get(6)?,
                mfa_config: mfa_json.and_then(|j| serde_json::from_str(&j).ok()),
                custom_headers: headers_json.and_then(|j| serde_json::from_str(&j).ok()),
                login_script: row.get(9)?,
                session_ttl_minutes: row.get(10)?,
                reauth_strategy: ReauthStrategy::from_str(&reauth_str),
                created_at: row.get(12)?,
                updated_at: row.get(13)?,
                last_used: row.get(14)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(profiles)
    }

    pub fn update_profile(&self, profile: &AuthProfile) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let mfa_config_json = profile.mfa_config.as_ref()
            .and_then(|m| serde_json::to_string(m).ok());
        let headers_json = profile.custom_headers.as_ref()
            .map(|h| serde_json::to_string(h).unwrap_or_default());

        self.conn.execute(
            "UPDATE auth_profiles SET
                name = ?2, target_url = ?3, auth_type = ?4, username = ?5,
                encrypted_password = ?6, login_url = ?7, mfa_config = ?8,
                custom_headers = ?9, login_script = ?10, session_ttl_minutes = ?11,
                reauth_strategy = ?12, updated_at = ?13
             WHERE id = ?1",
            params![
                profile.id,
                profile.name,
                profile.target_url,
                profile.auth_type.to_string(),
                profile.username,
                profile.encrypted_password,
                profile.login_url,
                mfa_config_json,
                headers_json,
                profile.login_script,
                profile.session_ttl_minutes,
                profile.reauth_strategy.to_string(),
                now,
            ],
        )?;

        Ok(())
    }

    pub fn delete_profile(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM auth_sessions WHERE profile_id = ?1", [id])?;
        self.conn.execute("DELETE FROM auth_profiles WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn update_last_used(&self, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE auth_profiles SET last_used = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }

    pub fn create_session(
        &self,
        profile_id: &str,
        session_token: Option<&str>,
        cookies_json: Option<&str>,
        ttl_minutes: i64,
    ) -> Result<String> {
        let session_id = format!("sess_{}", Utc::now().timestamp_millis());
        let now = Utc::now();
        let expires = now + chrono::Duration::minutes(ttl_minutes);

        self.conn.execute(
            "INSERT INTO auth_sessions (id, profile_id, session_token, cookies, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session_id,
                profile_id,
                session_token,
                cookies_json,
                now.to_rfc3339(),
                expires.to_rfc3339(),
            ],
        )?;

        Ok(session_id)
    }

    pub fn get_valid_session(&self, profile_id: &str) -> Result<Option<(String, Option<String>)>> {
        let now = Utc::now().to_rfc3339();

        let result = self.conn.query_row(
            "SELECT id, cookies FROM auth_sessions
             WHERE profile_id = ?1 AND expires_at > ?2
             ORDER BY created_at DESC LIMIT 1",
            params![profile_id, now],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        ).optional()?;

        Ok(result)
    }

    pub fn invalidate_session(&self, session_id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM auth_sessions WHERE id = ?1", [session_id])?;
        Ok(())
    }

    pub fn invalidate_all_sessions(&self, profile_id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM auth_sessions WHERE profile_id = ?1", [profile_id])?;
        Ok(())
    }

    pub fn cleanup_expired_sessions(&self) -> Result<usize> {
        let now = Utc::now().to_rfc3339();
        let count = self.conn.execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ?1",
            [now],
        )?;
        Ok(count)
    }

    pub fn add_audit_entry(
        &self,
        actor: &str,
        action: &str,
        target: Option<&str>,
        details: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO audit_log (timestamp, actor, action, target, details, ip_address)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![now, actor, action, target, details, ip_address],
        )?;
        Ok(())
    }

    pub fn list_audit_entries(&self, limit: Option<i64>) -> Result<Vec<AuditEntry>> {
        let limit = limit.unwrap_or(100);
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, actor, action, target, details, ip_address
             FROM audit_log ORDER BY timestamp DESC LIMIT ?1"
        )?;

        let entries = stmt.query_map([limit], |row| {
            Ok(AuditEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                actor: row.get(2)?,
                action: row.get(3)?,
                target: row.get(4)?,
                details: row.get(5)?,
                ip_address: row.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
}

pub struct TotpGenerator;

impl TotpGenerator {
    pub fn generate_code(secret: &str) -> Result<TotpResult> {
        use base64::Engine;
        use totp_rs::{Algorithm, TOTP};

        let secret_bytes = base64::engine::general_purpose::STANDARD.decode(secret)
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD.decode(secret)
            })
            .map_err(|e| AuthProfileError::TotpError(format!("Invalid secret: {}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            None,
            "SiteRecorder".to_string(),
        ).map_err(|e| AuthProfileError::TotpError(e.to_string()))?;

        let code = totp.generate_current()
            .map_err(|e| AuthProfileError::TotpError(e.to_string()))?;

        let remaining = totp.next_step(Utc::now().timestamp() as u64).saturating_sub(
            Utc::now().timestamp() as u64 - (Utc::now().timestamp() as u64 % 30)
        );

        let next_code = totp.generate(
            Utc::now().timestamp() as u64 + 30
        );

        Ok(TotpResult {
            code,
            remaining_seconds: remaining,
            next_code,
        })
    }

    pub fn validate_code(secret: &str, code: &str) -> Result<bool> {
        use base64::Engine;
        use totp_rs::{Algorithm, TOTP};

        let secret_bytes = base64::engine::general_purpose::STANDARD.decode(secret)
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD.decode(secret)
            })
            .map_err(|e| AuthProfileError::TotpError(format!("Invalid secret: {}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            None,
            "SiteRecorder".to_string(),
        ).map_err(|e| AuthProfileError::TotpError(e.to_string()))?;

        Ok(totp.check(code, Utc::now().timestamp() as u64))
    }

    pub fn generate_secret() -> String {
        use rand::RngCore;
        use base64::Engine;
        let mut secret = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut secret);
        base64::engine::general_purpose::STANDARD.encode(&secret)
    }

    pub fn get_provisioning_uri(secret: &str, account: &str, issuer: &str) -> Result<String> {
        use base64::Engine;
        use totp_rs::{Algorithm, TOTP};

        let secret_bytes = base64::engine::general_purpose::STANDARD.decode(secret)
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD_NO_PAD.decode(secret)
            })
            .map_err(|e| AuthProfileError::TotpError(format!("Invalid secret: {}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some(issuer.to_string()),
            account.to_string(),
        ).map_err(|e| AuthProfileError::TotpError(e.to_string()))?;

        Ok(totp.get_url())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get_profile() {
        let manager = AuthProfileManager::new_in_memory().unwrap();

        let profile = AuthProfile {
            id: "test_1".to_string(),
            name: "Test Profile".to_string(),
            target_url: "https://example.com".to_string(),
            auth_type: AuthType::Form,
            username: Some("user@test.com".to_string()),
            encrypted_password: Some("encrypted_pass".to_string()),
            login_url: Some("https://example.com/login".to_string()),
            mfa_config: None,
            custom_headers: None,
            login_script: None,
            session_ttl_minutes: 30,
            reauth_strategy: ReauthStrategy::Automatic,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            last_used: None,
        };

        manager.create_profile(&profile).unwrap();

        let retrieved = manager.get_profile("test_1").unwrap().unwrap();
        assert_eq!(retrieved.name, "Test Profile");
        assert_eq!(retrieved.username, Some("user@test.com".to_string()));
    }

    #[test]
    fn test_list_profiles() {
        let manager = AuthProfileManager::new_in_memory().unwrap();

        for i in 0..3 {
            let profile = AuthProfile {
                id: format!("test_{}", i),
                name: format!("Profile {}", i),
                target_url: format("https://example{}.com", i),
                auth_type: AuthType::Form,
                username: None,
                encrypted_password: None,
                login_url: None,
                mfa_config: None,
                custom_headers: None,
                login_script: None,
                session_ttl_minutes: 30,
                reauth_strategy: ReauthStrategy::Automatic,
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
                last_used: None,
            };
            manager.create_profile(&profile).unwrap();
        }

        let profiles = manager.list_profiles().unwrap();
        assert_eq!(profiles.len(), 3);
    }

    #[test]
    fn test_session_management() {
        let manager = AuthProfileManager::new_in_memory().unwrap();

        let session_id = manager.create_session(
            "profile_1",
            Some("token_abc"),
            None,
            30,
        ).unwrap();

        let session = manager.get_valid_session("profile_1").unwrap();
        assert!(session.is_some());

        manager.invalidate_session(&session_id).unwrap();
        let session = manager.get_valid_session("profile_1").unwrap();
        assert!(session.is_none());
    }

    #[test]
    fn test_totp_generation() {
        let secret = TotpGenerator::generate_secret();
        let result = TotpGenerator::generate_code(&secret).unwrap();
        assert_eq!(result.code.len(), 6);
        assert!(result.remaining_seconds <= 30);
    }

    #[test]
    fn test_totp_validation() {
        let secret = TotpGenerator::generate_secret();
        let result = TotpGenerator::generate_code(&secret).unwrap();
        let valid = TotpGenerator::validate_code(&secret, &result.code).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_audit_log() {
        let manager = AuthProfileManager::new_in_memory().unwrap();

        manager.add_audit_entry("admin", "login", None, Some("Successful login"), Some("127.0.0.1")).unwrap();
        manager.add_audit_entry("admin", "scan_start", Some("https://example.com"), None, None).unwrap();

        let entries = manager.list_audit_entries(None).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
