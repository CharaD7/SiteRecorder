use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::{Client, Response, StatusCode};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Auth error: {0}")]
    AuthError(String),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Session expired")]
    SessionExpired,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("CSRF token not found")]
    CsrfNotFound,
    #[error("OAuth error: {0}")]
    OAuthError(String),
}

type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthType {
    None,
    Basic { username: String, password: String },
    Bearer { token: String },
    ApiKey { key: String, header: String, location: ApiKeyLocation },
    Cookie { cookies: HashMap<String, String> },
    FormBased {
        login_url: String,
        username_field: String,
        password_field: String,
        username: String,
        password: String,
        extra_fields: HashMap<String, String>,
        csrf_field: Option<String>,
        success_indicator: Option<String>,
        failure_indicator: Option<String>,
    },
    OAuth2 {
        token_url: String,
        client_id: String,
        client_secret: String,
        scope: Option<String>,
        grant_type: OAuth2GrantType,
        access_token: Option<String>,
        refresh_token: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    },
    Ntlm {
        username: String,
        password: String,
        domain: Option<String>,
    },
    MutualTls {
        cert_path: String,
        key_path: String,
        ca_path: Option<String>,
    },
    Custom {
        headers: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApiKeyLocation {
    Header,
    Query,
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OAuth2GrantType {
    ClientCredentials,
    Password { username: String, password: String },
    AuthorizationCode { redirect_uri: String },
    DeviceCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub id: String,
    pub auth_type: AuthType,
    pub cookies: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub is_authenticated: bool,
    pub last_activity: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

impl AuthSession {
    pub fn new(auth_type: AuthType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            auth_type,
            cookies: HashMap::new(),
            headers: HashMap::new(),
            is_authenticated: false,
            last_activity: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    pub fn is_expired(&self, max_age_minutes: i64) -> bool {
        Utc::now().signed_duration_since(self.last_activity).num_minutes() > max_age_minutes
    }
}

pub struct AuthEngine {
    client: Client,
    sessions: Arc<RwLock<HashMap<String, AuthSession>>>,
}

impl AuthEngine {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()?;

        Ok(Self {
            client,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn authenticate(&self, auth_type: &AuthType) -> Result<AuthSession> {
        match auth_type {
            AuthType::None => {
                let mut session = AuthSession::new(auth_type.clone());
                session.is_authenticated = true;
                Ok(session)
            }
            AuthType::Basic { username, password } => {
                self.authenticate_basic(username, password).await
            }
            AuthType::Bearer { token } => {
                self.authenticate_bearer(token).await
            }
            AuthType::ApiKey { key, header, location } => {
                self.authenticate_api_key(key, header, location.clone()).await
            }
            AuthType::Cookie { cookies } => {
                self.authenticate_cookies(cookies.clone()).await
            }
            AuthType::FormBased { .. } => {
                self.authenticate_form_based(auth_type).await
            }
            AuthType::OAuth2 { .. } => {
                self.authenticate_oauth2(auth_type).await
            }
            AuthType::Ntlm { username, password, domain } => {
                self.authenticate_ntlm(username, password, domain.clone()).await
            }
            AuthType::MutualTls { cert_path, key_path, ca_path } => {
                self.authenticate_mtls(cert_path, key_path, ca_path.clone()).await
            }
            AuthType::Custom { headers } => {
                self.authenticate_custom(headers.clone()).await
            }
        }
    }

    async fn authenticate_basic(&self, username: &str, password: &str) -> Result<AuthSession> {
        let mut session = AuthSession::new(AuthType::Basic {
            username: username.to_string(),
            password: password.to_string(),
        });
        session.headers.insert(
            "Authorization".to_string(),
            format!("Basic {}", base64::encode(format!("{}:{}", username, password))),
        );
        session.is_authenticated = true;
        session.last_activity = Utc::now();
        Ok(session)
    }

    async fn authenticate_bearer(&self, token: &str) -> Result<AuthSession> {
        let mut session = AuthSession::new(AuthType::Bearer {
            token: token.to_string(),
        });
        session.headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", token),
        );
        session.is_authenticated = true;
        session.last_activity = Utc::now();
        Ok(session)
    }

    async fn authenticate_api_key(
        &self,
        key: &str,
        header: &str,
        location: ApiKeyLocation,
    ) -> Result<AuthSession> {
        let mut session = AuthSession::new(AuthType::ApiKey {
            key: key.to_string(),
            header: header.to_string(),
            location: location.clone(),
        });

        match location {
            ApiKeyLocation::Header => {
                session.headers.insert(header.to_string(), key.to_string());
            }
            ApiKeyLocation::Query => {
                session.metadata.insert("api_key_query_param".to_string(), header.to_string());
                session.metadata.insert("api_key_value".to_string(), key.to_string());
            }
            ApiKeyLocation::Cookie => {
                session.cookies.insert(header.to_string(), key.to_string());
            }
        }

        session.is_authenticated = true;
        session.last_activity = Utc::now();
        Ok(session)
    }

    async fn authenticate_cookies(&self, cookies: HashMap<String, String>) -> Result<AuthSession> {
        let mut session = AuthSession::new(AuthType::Cookie {
            cookies: cookies.clone(),
        });
        session.cookies = cookies;
        session.is_authenticated = true;
        session.last_activity = Utc::now();
        Ok(session)
    }

    async fn authenticate_form_based(&self, auth_type: &AuthType) -> Result<AuthSession> {
        let (login_url, username_field, password_field, username, password, extra_fields, csrf_field, success_indicator, failure_indicator) = match auth_type {
            AuthType::FormBased {
                login_url,
                username_field,
                password_field,
                username,
                password,
                extra_fields,
                csrf_field,
                success_indicator,
                failure_indicator,
            } => (
                login_url.clone(),
                username_field.clone(),
                password_field.clone(),
                username.clone(),
                password.clone(),
                extra_fields.clone(),
                csrf_field.clone(),
                success_indicator.clone(),
                failure_indicator.clone(),
            ),
            _ => return Err(AuthError::AuthError("Invalid auth type for form-based auth".to_string())),
        };

        let mut form_data: Vec<(String, String)> = Vec::new();

        // Extract CSRF token if needed
        if let Some(csrf_field_name) = &csrf_field {
            let csrf_token = self.extract_csrf_token(&login_url, csrf_field_name).await?;
            form_data.push((csrf_field_name.clone(), csrf_token));
        }

        // Add extra fields
        for (key, value) in &extra_fields {
            form_data.push((key.clone(), value.clone()));
        }

        // Add credentials
        form_data.push((username_field, username));
        form_data.push((password_field, password));

        // Submit login form
        let response = self.client.post(&login_url).form(&form_data).send().await?;

        let status = response.status();
        let response_url = response.url().as_str().to_string();
        let response_cookies: HashMap<String, String> = response
            .cookies()
            .map(|c| (c.name().to_string(), c.value().to_string()))
            .collect();
        let response_body = response.text().await?;

        let mut session = AuthSession::new(auth_type.clone());
        session.cookies = response_cookies.clone();

        // Check success/failure indicators
        let authenticated = if let Some(success) = &success_indicator {
            response_body.contains(success) || response_url.contains(success)
        } else if let Some(failure) = &failure_indicator {
            !response_body.contains(failure) && !response_url.contains(failure)
        } else {
            status.is_success() && !response_url.contains("login")
        };

        if authenticated {
            session.is_authenticated = true;
            session.last_activity = Utc::now();
            session.metadata.insert("login_url".to_string(), login_url);
            Ok(session)
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }

    async fn extract_csrf_token(&self, url: &str, field_name: &str) -> Result<String> {
        let response = self.client.get(url).send().await?;
        let body = response.text().await?;
        let document = Html::parse_document(&body);

        // Try meta tags first
        let meta_selector = Selector::parse(&format!("meta[name='{}'], meta[name='csrf-token'], meta[name='_csrf']", field_name))
            .map_err(|e| AuthError::ParseError(e.to_string()))?;
        if let Some(el) = document.select(&meta_selector).next() {
            if let Some(token) = el.value().attr("content") {
                return Ok(token.to_string());
            }
        }

        // Try input fields
        let input_selector = Selector::parse(&format!("input[name='{}'], input[name='_csrf'], input[name='csrf_token'], input[name='authenticity_token']", field_name))
            .map_err(|e| AuthError::ParseError(e.to_string()))?;
        if let Some(el) = document.select(&input_selector).next() {
            if let Some(token) = el.value().attr("value") {
                return Ok(token.to_string());
            }
        }

        // Try hidden inputs with common CSRF patterns
        let hidden_selector = Selector::parse("input[type='hidden']")
            .map_err(|e| AuthError::ParseError(e.to_string()))?;
        for el in document.select(&hidden_selector) {
            if let Some(name) = el.value().attr("name") {
                let name_lower = name.to_lowercase();
                if name_lower.contains("csrf") || name_lower.contains("token") || name_lower == "_token" {
                    if let Some(token) = el.value().attr("value") {
                        return Ok(token.to_string());
                    }
                }
            }
        }

        Err(AuthError::CsrfNotFound)
    }

    async fn authenticate_oauth2(&self, auth_type: &AuthType) -> Result<AuthSession> {
        let (token_url, client_id, client_secret, scope, grant_type) = match auth_type {
            AuthType::OAuth2 {
                token_url,
                client_id,
                client_secret,
                scope,
                grant_type,
                ..
            } => (
                token_url.clone(),
                client_id.clone(),
                client_secret.clone(),
                scope.clone(),
                grant_type.clone(),
            ),
            _ => return Err(AuthError::AuthError("Invalid auth type for OAuth2".to_string())),
        };

        let mut params: Vec<(String, String)> = vec![
            ("client_id".to_string(), client_id),
            ("client_secret".to_string(), client_secret),
        ];

        match &grant_type {
            OAuth2GrantType::ClientCredentials => {
                params.push(("grant_type".to_string(), "client_credentials".to_string()));
                if let Some(scope) = &scope {
                    params.push(("scope".to_string(), scope.clone()));
                }
            }
            OAuth2GrantType::Password { username, password } => {
                params.push(("grant_type".to_string(), "password".to_string()));
                params.push(("username".to_string(), username.clone()));
                params.push(("password".to_string(), password.clone()));
                if let Some(scope) = &scope {
                    params.push(("scope".to_string(), scope.clone()));
                }
            }
            _ => return Err(AuthError::OAuthError("Unsupported grant type".to_string())),
        }

        let response = self.client.post(&token_url).form(&params).send().await?;

        if !response.status().is_success() {
            return Err(AuthError::OAuthError(format!(
                "Token request failed: {}",
                response.status()
            )));
        }

        let token_response: serde_json::Value = response.json().await?;
        let access_token = token_response["access_token"]
            .as_str()
            .ok_or_else(|| AuthError::OAuthError("No access token in response".to_string()))?
            .to_string();
        let refresh_token = token_response["refresh_token"].as_str().map(|s| s.to_string());
        let expires_in = token_response["expires_in"].as_u64().unwrap_or(3600);
        let expires_at = Some(Utc::now() + chrono::Duration::seconds(expires_in as i64));

        let mut session = AuthSession::new(auth_type.clone());
        session.headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", access_token),
        );
        session.metadata.insert("access_token".to_string(), access_token);
        if let Some(rt) = &refresh_token {
            session.metadata.insert("refresh_token".to_string(), rt.clone());
        }
        session.metadata.insert("expires_at".to_string(), expires_at.unwrap().to_rfc3339());
        session.is_authenticated = true;
        session.last_activity = Utc::now();
        Ok(session)
    }

    async fn authenticate_ntlm(
        &self,
        username: &str,
        password: &str,
        domain: Option<String>,
    ) -> Result<AuthSession> {
        let mut session = AuthSession::new(AuthType::Ntlm {
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.clone(),
        });

        let full_username = match &domain {
            Some(d) => format!("{}\\{}", d, username),
            None => username.to_string(),
        };

        session.metadata.insert("ntlm_username".to_string(), full_username);
        session.metadata.insert("ntlm_password".to_string(), password.to_string());
        session.is_authenticated = true;
        session.last_activity = Utc::now();
        Ok(session)
    }

    async fn authenticate_mtls(
        &self,
        cert_path: &str,
        key_path: &str,
        ca_path: Option<String>,
    ) -> Result<AuthSession> {
        let mut session = AuthSession::new(AuthType::MutualTls {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
            ca_path: ca_path.clone(),
        });

        session.metadata.insert("cert_path".to_string(), cert_path.to_string());
        session.metadata.insert("key_path".to_string(), key_path.to_string());
        if let Some(ca) = &ca_path {
            session.metadata.insert("ca_path".to_string(), ca.clone());
        }
        session.is_authenticated = true;
        session.last_activity = Utc::now();
        Ok(session)
    }

    async fn authenticate_custom(&self, headers: HashMap<String, String>) -> Result<AuthSession> {
        let mut session = AuthSession::new(AuthType::Custom {
            headers: headers.clone(),
        });
        session.headers = headers;
        session.is_authenticated = true;
        session.last_activity = Utc::now();
        Ok(session)
    }

    pub async fn make_authenticated_request(
        &self,
        session: &AuthSession,
        method: &str,
        url: &str,
        body: Option<&str>,
    ) -> Result<Response> {
        let mut request = self.client.request(
            method.parse().map_err(|e| AuthError::AuthError(format!("Invalid method: {}", e)))?,
            url,
        );

        // Apply session headers
        for (key, value) in &session.headers {
            request = request.header(key, value);
        }

        // Apply cookies
        if !session.cookies.is_empty() {
            let cookie_str: String = session
                .cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header("Cookie", cookie_str);
        }

        // Apply API key in query if needed
        if let AuthType::ApiKey {
            location: ApiKeyLocation::Query,
            ..
        } = &session.auth_type
        {
            if let Some(param) = session.metadata.get("api_key_query_param") {
                if let Some(value) = session.metadata.get("api_key_value") {
                    let mut url = Url::parse(url).map_err(|e| AuthError::ParseError(e.to_string()))?;
                    url.query_pairs_mut().append_pair(param, value);
                    request = self.client.request(
                        method.parse().map_err(|e| AuthError::AuthError(format!("{}", e)))?,
                        url.as_str(),
                    );
                }
            }
        }

        // Apply body
        if let Some(b) = body {
            request = request.body(b.to_string());
        }

        let response = request.send().await?;
        Ok(response)
    }

    pub async fn refresh_session(&self, session: &mut AuthSession) -> Result<()> {
        match &session.auth_type {
            AuthType::OAuth2 { token_url, client_id, client_secret, grant_type, refresh_token, .. } => {
                if let Some(refresh) = refresh_token {
                    let mut params: Vec<(String, String)> = vec![
                        ("grant_type".to_string(), "refresh_token".to_string()),
                        ("refresh_token".to_string(), refresh.clone()),
                        ("client_id".to_string(), client_id.clone()),
                        ("client_secret".to_string(), client_secret.clone()),
                    ];

                    let response = self.client.post(token_url).form(&params).send().await?;
                    let token_response: serde_json::Value = response.json().await?;

                    let new_token = token_response["access_token"].as_str().unwrap_or("");
                    session.headers.insert("Authorization".to_string(), format!("Bearer {}", new_token));
                    session.metadata.insert("access_token".to_string(), new_token.to_string());

                    if let Some(new_refresh) = token_response["refresh_token"].as_str() {
                        session.metadata.insert("refresh_token".to_string(), new_refresh.to_string());
                    }

                    session.last_activity = Utc::now();
                    Ok(())
                } else {
                    Err(AuthError::AuthError("No refresh token available".to_string()))
                }
            }
            AuthType::FormBased { .. } => {
                let new_session = self.authenticate_form_based(&session.auth_type).await?;
                *session = new_session;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub async fn save_session(&self, session: AuthSession) {
        self.sessions.write().await.insert(session.id.clone(), session);
    }

    pub async fn get_session(&self, id: &str) -> Option<AuthSession> {
        self.sessions.read().await.get(id).cloned()
    }

    pub async fn remove_session(&self, id: &str) {
        self.sessions.write().await.remove(id);
    }

    pub async fn list_sessions(&self) -> Vec<AuthSession> {
        self.sessions.read().await.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bearer_auth() {
        let engine = AuthEngine::new().unwrap();
        let auth_type = AuthType::Bearer {
            token: "test_token_123".to_string(),
        };
        let session = engine.authenticate(&auth_type).await.unwrap();
        assert!(session.is_authenticated);
        assert_eq!(
            session.headers.get("Authorization").unwrap(),
            "Bearer test_token_123"
        );
    }

    #[tokio::test]
    async fn test_basic_auth() {
        let engine = AuthEngine::new().unwrap();
        let auth_type = AuthType::Basic {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };
        let session = engine.authenticate(&auth_type).await.unwrap();
        assert!(session.is_authenticated);
        assert!(session.headers.contains_key("Authorization"));
    }

    #[tokio::test]
    async fn test_api_key_header() {
        let engine = AuthEngine::new().unwrap();
        let auth_type = AuthType::ApiKey {
            key: "my_api_key".to_string(),
            header: "X-API-Key".to_string(),
            location: ApiKeyLocation::Header,
        };
        let session = engine.authenticate(&auth_type).await.unwrap();
        assert!(session.is_authenticated);
        assert_eq!(session.headers.get("X-API-Key").unwrap(), "my_api_key");
    }

    #[tokio::test]
    async fn test_cookie_auth() {
        let engine = AuthEngine::new().unwrap();
        let mut cookies = HashMap::new();
        cookies.insert("session_id".to_string(), "abc123".to_string());
        let auth_type = AuthType::Cookie { cookies };
        let session = engine.authenticate(&auth_type).await.unwrap();
        assert!(session.is_authenticated);
        assert_eq!(session.cookies.get("session_id").unwrap(), "abc123");
    }

    #[tokio::test]
    async fn test_session_expiry() {
        let session = AuthSession::new(AuthType::None);
        assert!(!session.is_expired(30));
    }
}
