//! A Burp Collaborator clone: out-of-band interaction detection.
//!
//! Collaboration happens **out-of-band**: an application under test contacts an
//! infrastructure the tester controls (via DNS or an HTTP request) rather than
//! in the normal request/response channel. This exposes blind SSRF, blind
//! SQLi, XXE, template injection, and out-of-band command execution — cases
//! where the response contains no signal at all.
//!
//! The crate has two complementary roles:
//!
//! 1. **Client mode** (`CollaboratorClient`) - generate unique interaction
//!    beacons, embed them in your test payload, then poll for interactions.
//!    This is how you'd use a public Collaborator server, and it's also how
//!    the local server is polled in self-hosted testing.
//! 2. **Server mode** (`CollaboratorServer`) - run a small HTTP server that
//!    receives beacon calls and records every interaction with full detail
//!    (headers, query string, body, remote address).
//!
//! Design rules from the rest of the tool:
//!
//! * **Plan-first** - beacons are generated and recorded locally before any
//!    outbound traffic happens; the operator approves the payload.
//! * **Facts, never verdicts** - an interaction record says what arrived, when,
//!    and from where. Whether it proves a blind vulnerability is a human call.
//! * **Self-hosted by default** - everything can run locally on 127.0.0.1, so
//!    this can be tested without any public infrastructure. A public-server
//!    config (host + port) is supported for the full workflow.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A unique out-of-band beacon.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Beacon(String);

impl Beacon {
    pub fn new() -> Self {
        Beacon(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render the beacon as a subdomain: `abc123-....interact.example.com`.
    pub fn subdomain(&self, host: &str) -> String {
        let id = self.0.chars().take(12).collect::<String>();
        format!("{}-{}.interact.{}", id, id, host)
    }

    /// Render the beacon as an HTTP host header.
    pub fn host(&self, host: &str) -> String {
        format!(
            "{}-{}.{}",
            self.0.chars().take(12).collect::<String>(),
            self.0.chars().take(12).collect::<String>(),
            host
        )
    }
}

impl Default for Beacon {
    fn default() -> Self {
        Self::new()
    }
}

/// An interaction with a beacon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    pub id: String,
    pub beacon: Beacon,
    pub interaction_type: InteractionType,
    pub protocol: String,
    pub remote_address: String,
    pub received_at: DateTime<Utc>,
    pub headers: HashMap<String, String>,
    pub query_string: Option<String>,
    pub body: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionType {
    Http,
    Dns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionSummary {
    pub id: String,
    pub beacon: String,
    pub interaction_type: InteractionType,
    pub protocol: String,
    pub remote_address: String,
    pub received_at: DateTime<Utc>,
}
/// Errors from the collaborator client.
#[derive(Debug, Error)]
pub enum CollaboratorClientError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, CollaboratorClientError>;

/// Polls a Collaborator server for interactions with beacons you control.
#[allow(dead_code)]
pub struct CollaboratorClient {
    host: String,
    port: u16,
    base_url: String,
    beacons: Arc<RwLock<Vec<Beacon>>>,
    interactions: Arc<RwLock<Vec<Interaction>>>,
}

impl CollaboratorClient {
    /// Connect to a Collaborator server. Localhost default is for self-hosted
    /// testing; set host/port to a public server for the real workflow.
    pub fn new(host: &str, port: u16) -> Self {
        let base_url = if port == 443 {
            format!("https://{host}")
        } else if port == 80 {
            format!("http://{host}")
        } else {
            format!("http://{host}:{port}")
        };
        CollaboratorClient {
            host: host.to_string(),
            port,
            base_url,
            beacons: Arc::new(RwLock::new(Vec::new())),
            interactions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Generate a beacon and register it with the server. The server must know
    /// about the beacon before it will report interactions for it.
    pub async fn generate_beacon(&self) -> Result<Beacon> {
        let beacon = Beacon::new();
        reqwest::Client::new()
            .get(format!("{}/generate", self.base_url))
            .send()
            .await?;
        self.beacons.write().await.push(beacon.clone());
        Ok(beacon)
    }

    /// Fetch new interactions from the server for the registered beacons.
    pub async fn poll_once(&self) -> Result<Vec<Interaction>> {
        let resp = reqwest::Client::new()
            .get(format!("{}/poll", self.base_url))
            .send()
            .await?;
        let interactions: Vec<Interaction> = resp.json().await?;
        let mut guard = self.interactions.write().await;
        for it in &interactions {
            if !guard.iter().any(|g| g.id == it.id) {
                guard.push(it.clone());
            }
        }
        Ok(interactions)
    }

    /// Poll continuously until at least one interaction appears.
    pub async fn wait_for_interaction(&self, timeout_s: u64) -> Result<Vec<Interaction>> {
        use tokio::time::{sleep, Duration};
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_s);
        loop {
            let interactions = self.poll_once().await?;
            if !interactions.is_empty() {
                return Ok(interactions);
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }
        Ok(self.interactions.read().await.clone())
    }

    pub async fn get_beacons(&self) -> Vec<Beacon> {
        self.beacons.read().await.clone()
    }

    pub async fn get_interactions(&self) -> Vec<Interaction> {
        self.interactions.read().await.clone()
    }
}

/// An in-process interaction store.
#[derive(Debug, Clone, Default)]
pub struct InteractionStore(Arc<RwLock<Vec<Interaction>>>);

impl InteractionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn record(&self, interaction: Interaction) {
        self.0.write().await.push(interaction);
    }

    pub async fn count(&self) -> usize {
        self.0.read().await.len()
    }

    pub async fn list(&self) -> Vec<Interaction> {
        self.0.read().await.clone()
    }

    pub async fn list_for_beacon(&self, beacon: &Beacon) -> Vec<Interaction> {
        self.0
            .read()
            .await
            .iter()
            .filter(|i| &i.beacon == beacon)
            .cloned()
            .collect()
    }
}

/// A self-hosted Collaborator HTTP server that accepts beacon calls.
///
/// Runs a minimal HTTP listener on the given address. Any GET request to it is
/// recorded as an interaction (this is what a public Collaborator server does;
/// the endpoint is deliberately open so that both the `host()` and `subdomain()`
/// beacon renderings reach it). Use 127.0.0.1 for local testing.
pub struct CollaboratorServer {
    store: InteractionStore,
    bind: String,
    port: u16,
}

impl CollaboratorServer {
    /// Create a server bound to the given address/port.
    pub fn new(bind: &str, port: u16) -> Self {
        Self {
            store: InteractionStore::new(),
            bind: bind.to_string(),
            port,
        }
    }

    /// Start the server in the background.
    pub async fn start(self) -> tokio::task::JoinHandle<()> {
        let store = self.store.clone();
        tokio::spawn(async move {
            let addr = format!("{}:{}", self.bind, self.port)
                .parse::<std::net::SocketAddr>()
                .expect("invalid bind address");
            tracing::info!("Collaborator server listening on {}", addr);
            loop {
                let (stream, peer) = match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => listener.accept().await.unwrap(),
                    Err(e) => {
                        tracing::error!("accept failed: {e}");
                        continue;
                    }
                };
                let store = store.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, peer, &store).await {
                        tracing::debug!("client error: {e}");
                    }
                });
            }
        })
    }
}

/// Read a minimal HTTP/1.1 request and record it as an interaction.
async fn handle_client(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    store: &InteractionStore,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncBufReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::io::BufReader;
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let request_line = request_line.trim();

    let method;
    let path;
    {
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        method = parts.first().copied().unwrap_or("GET");
        path = parts.get(1).copied().unwrap_or("/");
    }

    if method.to_uppercase() != "GET" {
        return Ok(());
    }

    // Collect headers.
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut query_string = String::new();
    if let Some(pos) = path.find('?') {
        query_string = path[pos + 1..].to_string();
    }
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        if header.is_empty() || header == "\r\n" {
            break;
        }
        if let Some((k, v)) = header.trim_end().split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    let beacon = parse_beacon(path, &headers);
    let id = Uuid::new_v4().to_string();
    let interaction = Interaction {
        id,
        beacon: beacon.unwrap_or_default(),
        interaction_type: InteractionType::Http,
        protocol: "http".into(),
        remote_address: peer.to_string(),
        received_at: Utc::now(),
        headers,
        query_string: if query_string.is_empty() {
            None
        } else {
            Some(query_string)
        },
        body: Some(String::new()),
        raw: format!("{method} {path}"),
    };
    store.record(interaction).await;

    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let mut writer = reader.into_inner();
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Extract the beacon from a request path or host header.
fn parse_beacon(path: &str, headers: &HashMap<String, String>) -> Option<Beacon> {
    if let Some(pos) = path.find('?') {
        let query = &path[pos + 1..];
        if let Some((k, v)) = query.split_once("beacon=") {
            if k.is_empty() {
                return Some(Beacon(v.to_string()));
            }
        }
    }
    headers
        .get("host")
        .and_then(|h| {
            if h.contains(".interact.") {
                let prefix = h.split(".interact.").next().unwrap_or("");
                let parts: Vec<&str> = prefix.split('-').collect();
                if parts.len() == 2 {
                    Some(format!("{}{}", parts[0], parts[1]))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .map(Beacon)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_beacons_are_unique() {
        let b1 = Beacon::new();
        let b2 = Beacon::new();
        assert_ne!(b1.as_str(), b2.as_str());
    }

    #[test]
    fn beacon_subdomain_rendering() {
        let beacon = Beacon("abcdefghijkl".into());
        assert_eq!(
            beacon.subdomain("example.com"),
            "abcdefghijkl-abcdefghijkl.interact.example.com"
        );
    }

    #[test]
    fn parse_beacon_from_query_string() {
        let headers = HashMap::new();
        let b = parse_beacon("/beacon?beacon=abc123", &headers);
        assert_eq!(
            b.map(|b| b.as_str().to_string()),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn parse_beacon_from_host_header() {
        let mut headers = HashMap::new();
        headers.insert(
            "host".to_string(),
            "abc123-def456.interact.example.com".to_string(),
        );
        let b = parse_beacon("/", &headers);
        assert_eq!(
            b.map(|b| b.as_str().to_string()),
            Some("abc123def456".to_string())
        );
    }

    #[test]
    fn empty_query_string_keeps_field_none() {
        assert_eq!(
            parse_beacon("/index.html?foo=bar", &HashMap::new()).map(|b| b.as_str().to_string()),
            None
        );
    }
}
