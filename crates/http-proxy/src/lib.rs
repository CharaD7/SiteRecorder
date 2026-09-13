use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

type Result<T> = std::result::Result<T, ProxyError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptedRequest {
    pub id: String,
    pub timestamp: String,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_size: usize,
    pub source_ip: String,
    pub intercepted: bool,
    pub modified: bool,
    pub dropped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptedResponse {
    pub id: String,
    pub request_id: String,
    pub timestamp: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_size: usize,
    pub modified: bool,
    pub response_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySession {
    pub id: String,
    pub request: InterceptedRequest,
    pub response: Option<InterceptedResponse>,
    pub intercepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub intercept_requests: bool,
    pub intercept_responses: bool,
    pub upstream_proxy: Option<String>,
    pub ca_cert_path: Option<String>,
    pub ca_key_path: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8080,
            intercept_requests: false,
            intercept_responses: false,
            upstream_proxy: None,
            ca_cert_path: None,
            ca_key_path: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InterceptRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub condition: InterceptCondition,
    pub action: InterceptAction,
}

#[derive(Debug, Clone)]
pub enum InterceptCondition {
    UrlContains(String),
    HeaderContains(String, String),
    MethodIs(String),
    BodyContains(String),
    All,
}

#[derive(Debug, Clone)]
pub enum InterceptAction {
    Intercept,
    Forward,
    Drop,
    Modify,
}

pub struct HttpProxy {
    config: Arc<RwLock<ProxyConfig>>,
    sessions: Arc<RwLock<Vec<ProxySession>>>,
    intercept_rules: Arc<RwLock<Vec<InterceptRule>>>,
    running: Arc<RwLock<bool>>,
    tx: broadcast::Sender<ProxyEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyEvent {
    SessionStarted(ProxySession),
    RequestIntercepted(String),
    ResponseIntercepted(String),
    SessionComplete(ProxySession),
    Error(String),
}

impl HttpProxy {
    pub fn new() -> (Self, broadcast::Receiver<ProxyEvent>) {
        let (tx, rx) = broadcast::channel(1024);
        (
            Self {
                config: Arc::new(RwLock::new(ProxyConfig::default())),
                sessions: Arc::new(RwLock::new(Vec::new())),
                intercept_rules: Arc::new(RwLock::new(Vec::new())),
                running: Arc::new(RwLock::new(false)),
                tx,
            },
            rx,
        )
    }

    pub async fn start(&self) -> Result<()> {
        let config = self.config.read().await.clone();
        let addr: SocketAddr = format!("{}:{}", config.listen_addr, config.listen_port)
            .parse()
            .map_err(|e| ProxyError::InvalidRequest(format!("Invalid address: {}", e)))?;

        let listener = TcpListener::bind(addr).await?;
        *self.running.write().await = true;

        tracing::info!("HTTP Proxy listening on {}", addr);

        let sessions = self.sessions.clone();
        let intercept_rules = self.intercept_rules.clone();
        let tx = self.tx.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            while let Ok((stream, peer_addr)) = listener.accept().await {
                let io = TokioIo::new(stream);
                let sessions = sessions.clone();
                let rules = intercept_rules.clone();
                let tx = tx.clone();
                let config = config.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let sessions = sessions.clone();
                        let rules = rules.clone();
                        let tx = tx.clone();
                        let config = config.clone();
                        let peer = peer_addr.to_string();

                        async move {
                            handle_request(req, sessions, rules, tx, config, peer).await
                        }
                    });

                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        tracing::error!("Connection error: {}", e);
                    }
                });
            }
        });

        Ok(())
    }

    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn get_sessions(&self) -> Vec<ProxySession> {
        self.sessions.read().await.clone()
    }

    pub async fn get_session(&self, id: &str) -> Option<ProxySession> {
        self.sessions.read().await.iter().find(|s| s.id == id).cloned()
    }

    pub async fn clear_sessions(&self) {
        self.sessions.write().await.clear();
    }

    pub async fn add_intercept_rule(&self, rule: InterceptRule) {
        self.intercept_rules.write().await.push(rule);
    }

    pub async fn remove_intercept_rule(&self, id: &str) {
        self.intercept_rules.write().await.retain(|r| r.id != id);
    }

    pub async fn get_intercept_rules(&self) -> Vec<InterceptRule> {
        self.intercept_rules.read().await.clone()
    }

    pub async fn set_config(&self, new_config: ProxyConfig) {
        *self.config.write().await = new_config;
    }

    pub async fn get_config(&self) -> ProxyConfig {
        self.config.read().await.clone()
    }

    pub async fn forward_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
            session.intercepted = false;
        }
        Ok(())
    }

    pub async fn drop_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
            session.request.dropped = true;
        }
        Ok(())
    }
}

async fn handle_request(
    req: Request<Incoming>,
    sessions: Arc<RwLock<Vec<ProxySession>>>,
    rules: Arc<RwLock<Vec<InterceptRule>>>,
    tx: broadcast::Sender<ProxyEvent>,
    config: Arc<RwLock<ProxyConfig>>,
    peer: String,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect::<HashMap<_, _>>();

    let body_bytes = req.collect().await?.to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    let body_size = body_bytes.len();

    let request = InterceptedRequest {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        method: method.to_string(),
        url: uri.to_string(),
        headers,
        body: if body_size > 0 {
            Some(body_str)
        } else {
            None
        },
        body_size,
        source_ip: peer,
        intercepted: false,
        modified: false,
        dropped: false,
    };

    let session = ProxySession {
        id: request.id.clone(),
        request: request.clone(),
        response: None,
        intercepted: false,
    };

    sessions.write().await.push(session.clone());
    let _ = tx.send(ProxyEvent::SessionStarted(session));

    let response = forward_to_target(method, uri, &request.headers, body_bytes).await;

    match response {
        Ok((status, resp_headers, resp_body, resp_time)) => {
            let response = InterceptedResponse {
                id: Uuid::new_v4().to_string(),
                request_id: request.id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                status_code: status,
                status_text: canonical_reason(status).unwrap_or("").to_string(),
                headers: resp_headers.clone(),
                body: Some(String::from_utf8_lossy(&resp_body).to_string()),
                body_size: resp_body.len(),
                modified: false,
                response_time_ms: resp_time,
            };

            let mut sessions = sessions.write().await;
            if let Some(session) = sessions.iter_mut().find(|s| s.id == request.id) {
                session.response = Some(response.clone());
            }

            let mut resp = Response::new(Full::new(Bytes::from(resp_body)));
            *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
            for (k, v) in &resp_headers {
                if let (Ok(name), Ok(value)) = (
                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                    hyper::header::HeaderValue::from_str(v),
                ) {
                    resp.headers_mut().insert(name, value);
                }
            }

            Ok(resp)
        }
        Err(e) => {
            let mut resp = Response::new(Full::new(Bytes::from(format!("Proxy Error: {}", e))));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}

async fn forward_to_target(
    method: Method,
    uri: Uri,
    headers: &HashMap<String, String>,
    body: Bytes,
) -> std::result::Result<(u16, HashMap<String, String>, Vec<u8>, u64), String> {
    let scheme = uri.scheme_str().unwrap_or("http");
    let host = uri.host().ok_or("No host in URI")?;
    let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");

    let start = std::time::Instant::now();

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!("{}://{}:{}{}", scheme, host, port, path);
    let mut req_builder = client.request(method.as_str().parse().map_err(|_| "Invalid method".to_string())?, &url);

    for (k, v) in headers {
        if !["host", "connection"].contains(&k.as_str()) {
            req_builder = req_builder.header(k, v);
        }
    }

    if !body.is_empty() {
        req_builder = req_builder.body(body);
    }

    let resp = req_builder.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let resp_headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let resp_body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
    let elapsed = start.elapsed().as_millis() as u64;

    Ok((status, resp_headers, resp_body, elapsed))
}

fn canonical_reason(code: u16) -> Option<&'static str> {
    match code {
        200 => Some("OK"),
        201 => Some("Created"),
        204 => Some("No Content"),
        301 => Some("Moved Permanently"),
        302 => Some("Found"),
        304 => Some("Not Modified"),
        400 => Some("Bad Request"),
        401 => Some("Unauthorized"),
        403 => Some("Forbidden"),
        404 => Some("Not Found"),
        405 => Some("Method Not Allowed"),
        500 => Some("Internal Server Error"),
        502 => Some("Bad Gateway"),
        503 => Some("Service Unavailable"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert_eq!(config.listen_port, 8080);
        assert_eq!(config.listen_addr, "127.0.0.1");
    }

    #[test]
    fn test_canonical_reason() {
        assert_eq!(canonical_reason(200), Some("OK"));
        assert_eq!(canonical_reason(404), Some("Not Found"));
        assert_eq!(canonical_reason(999), None);
    }
}
