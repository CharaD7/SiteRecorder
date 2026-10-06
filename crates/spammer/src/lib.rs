//! A Burp Spammer clone.
//!
//! Two capabilities, both plan-first:
//!
//! 1. **HTTP flood** - send a configured number of requests to a target as
//!    fast as the machine allows, for basic availability/load testing.
//!    Request count is capped so this never becomes a denial-of-service tool
//!    in your own hands.
//! 2. **Token generation** - produce large quantities of high-entropy values
//!    (UUIDs, random hex, Base64) for use as fuzzer payloads, CSRF tokens, or
//!    session identifiers.
//!
//! Nothing is sent until an operator confirms the plan. The flood is a blunt
//! instrument for measuring availability, not a finding; it reports facts
//! (counts, latencies, errors) and makes no verdict.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Trait import needed by `gen_range`.
use rand::Rng;

#[derive(Debug, Error)]
pub enum SpammerError {
    #[error("Invalid plan: {0}")]
    InvalidPlan(String),

    #[error("Request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Sender dropped")]
    SenderDropped,
}

pub type Result<T> = std::result::Result<T, SpammerError>;

/// A flood plan: what to send and how much.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloodPlan {
    pub method: String,
    pub url: String,
    pub count: usize,
    pub concurrency: usize,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl FloodPlan {
    /// Enforce the safety caps.
    pub fn validate(&self) -> Result<()> {
        if self.method.is_empty() {
            return Err(SpammerError::InvalidPlan("method is required".into()));
        }
        if self.url.is_empty() {
            return Err(SpammerError::InvalidPlan("url is required".into()));
        }
        if self.count == 0 {
            return Err(SpammerError::InvalidPlan("count must be at least 1".into()));
        }
        if self.count > 10_000 {
            return Err(SpammerError::InvalidPlan(
                "count is capped at 10,000 requests".into(),
            ));
        }
        if self.concurrency == 0 {
            return Err(SpammerError::InvalidPlan(
                "concurrency must be at least 1".into(),
            ));
        }
        if self.concurrency > 32 {
            return Err(SpammerError::InvalidPlan(
                "concurrency is capped at 32".into(),
            ));
        }
        Ok(())
    }
}

/// A token plan: what kind and how many.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TokenPlan {
    /// 32-byte UUIDs.
    Uuid { count: usize },
    /// `n` bytes as lowercase hex.
    Hex { count: usize, bytes: usize },
    /// `n` random bytes encoded Base64.
    Base64 { count: usize, bytes: usize },
}

impl TokenPlan {
    pub fn validate(&self) -> Result<()> {
        let count = match self {
            TokenPlan::Uuid { count } => *count,
            TokenPlan::Hex { count, .. } => *count,
            TokenPlan::Base64 { count, .. } => *count,
        };
        if count == 0 {
            return Err(SpammerError::InvalidPlan("count must be at least 1".into()));
        }
        if count > 100_000 {
            return Err(SpammerError::InvalidPlan(
                "token count is capped at 100,000".into(),
            ));
        }
        Ok(())
    }
}

/// Results of a token run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRun {
    pub kind: String,
    pub count: usize,
    pub samples: Vec<String>,
}

/// Results of a flood run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloodRun {
    pub plan: FloodPlan,
    pub sent: usize,
    pub ok: usize,
    pub failed: usize,
    pub elapsed_ms: u64,
    /// Status codes seen, as counts.
    pub status_distribution: Vec<(u16, usize)>,
}

/// Flood result per-request observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloodResult {
    pub attempt: usize,
    pub status: Option<u16>,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Spammer;

impl Spammer {
    /// Generate tokens. Used as a fuzzer input source or CSRF token pool.
    pub async fn generate_tokens(&self, plan: &TokenPlan) -> Result<TokenRun> {
        plan.validate()?;
        let samples = match plan {
            TokenPlan::Uuid { count } => (0..*count)
                .map(|_| Uuid::new_v4().to_string())
                .collect::<Vec<_>>(),
            TokenPlan::Hex { count, bytes } => {
                let pool = "0123456789abcdef";
                (0..*count)
                    .map(|_| {
                        // `bytes` means random bytes; each byte is 2 hex characters.
                        (0..*bytes * 2)
                            .map(|_| self.rand_hex_char(pool))
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
            }
            TokenPlan::Base64 { count, bytes } => (0..*count)
                .map(|_| {
                    let bytes = (0..*bytes)
                        .map(|_| rand::random::<u8>())
                        .collect::<Vec<_>>();
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
                })
                .collect::<Vec<_>>(),
        };
        let samples = samples.into_iter().take(10).collect();
        Ok(TokenRun {
            kind: plan.kind_str().to_string(),
            count: plan.count(),
            samples,
        })
    }

    /// Send the flood after the operator confirmed the plan.
    pub async fn flood(&self, plan: &FloodPlan) -> Result<FloodRun> {
        plan.validate()?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let start = std::time::Instant::now();
        let mut ok = 0usize;
        let mut failed = 0usize;
        let mut status_distribution: Vec<(u16, usize)> = Vec::new();

        let method =
            reqwest::Method::from_bytes(plan.method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut req = client.request(method, &plan.url);
        for (k, v) in &plan.headers {
            req = req.header(k, v);
        }
        if let Some(body) = &plan.body {
            req = req.body(body.clone());
        }

        let mut handles = Vec::new();
        for i in 0..plan.count {
            let req = req
                .try_clone()
                .ok_or_else(|| SpammerError::InvalidPlan("request cannot be cloned".into()))?;
            handles.push(tokio::spawn(async move {
                let a = i + 1;
                let t0 = std::time::Instant::now();
                match req.send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let ms = t0.elapsed().as_millis() as u64;
                        Ok::<_, SpammerError>(FloodResult {
                            attempt: a,
                            status: Some(status),
                            elapsed_ms: ms,
                            error: None,
                        })
                    }
                    Err(e) => Ok(FloodResult {
                        attempt: a,
                        status: None,
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                        error: Some(e.to_string()),
                    }),
                }
            }));
        }

        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => {
                    if let Some(expected) = result.status {
                        if let Some((_status, count)) = status_distribution
                            .iter_mut()
                            .find(|(status, _)| *status == expected)
                        {
                            *count += 1;
                        } else {
                            status_distribution.push((expected, 1));
                        }
                        ok += 1;
                    } else {
                        failed += 1;
                    }
                }
                Ok(Err(_)) => failed += 1,
                Err(_e) => {
                    tracing::error!("flood task panicked: {_e}");
                    failed += 1;
                }
            }
        }

        Ok(FloodRun {
            plan: plan.clone(),
            sent: plan.count,
            ok,
            failed,
            elapsed_ms: start.elapsed().as_millis() as u64,
            status_distribution,
        })
    }

    fn rand_hex_char(&self, pool: &str) -> char {
        let idx = rand::thread_rng().gen_range(0..pool.len());
        pool.chars().nth(idx).unwrap()
    }
}

impl TokenPlan {
    fn kind_str(&self) -> &'static str {
        match self {
            TokenPlan::Uuid { .. } => "uuid",
            TokenPlan::Hex { .. } => "hex",
            TokenPlan::Base64 { .. } => "base64",
        }
    }

    fn count(&self) -> usize {
        match self {
            TokenPlan::Uuid { count } => *count,
            TokenPlan::Hex { count, .. } => *count,
            TokenPlan::Base64 { count, .. } => *count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn flood_plan_capped_at_10000() {
        assert!(FloodPlan {
            method: "GET".into(),
            url: "http://example.com/".into(),
            count: 10_001,
            concurrency: 4,
            headers: Vec::new(),
            body: None,
        }
        .validate()
        .is_err());
        assert!(FloodPlan {
            method: "GET".into(),
            url: "http://example.com/".into(),
            count: 10_000,
            concurrency: 4,
            headers: Vec::new(),
            body: None,
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn token_plan_capped_at_100000() {
        assert!(TokenPlan::Base64 {
            count: 100_001,
            bytes: 8
        }
        .validate()
        .is_err());
    }

    #[test]
    fn generate_uuids_validates() {
        let spammer = Spammer;
        let run = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(spammer.generate_tokens(&TokenPlan::Uuid { count: 3 }));
        assert!(run.is_ok());
        let run = run.unwrap();
        assert_eq!(run.kind, "uuid");
        assert_eq!(run.count, 3);
        for t in &run.samples {
            let _u = Uuid::parse_str(t).unwrap();
        }
    }

    #[test]
    fn generate_hex_is_hexdigits() {
        let spammer = Spammer;
        let run = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(spammer.generate_tokens(&TokenPlan::Hex { count: 2, bytes: 8 }));
        let run = run.unwrap();
        for t in &run.samples {
            assert_eq!(t.len(), 16);
            assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn generate_base64_decodes() {
        let spammer = Spammer;
        let run = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(spammer.generate_tokens(&TokenPlan::Base64 {
                count: 2,
                bytes: 16,
            }));
        let run = run.unwrap();
        for t in &run.samples {
            let _b = base64::engine::general_purpose::STANDARD.decode(t).unwrap();
        }
    }

    #[test]
    fn empty_method_is_rejected() {
        assert!(FloodPlan {
            method: "".into(),
            url: "http://example.com/".into(),
            count: 1,
            concurrency: 1,
            headers: Vec::new(),
            body: None,
        }
        .validate()
        .is_err());
    }
}
