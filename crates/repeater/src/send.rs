//! Sending a parsed request over the wire.
//!
//! # What is measured, and what is not
//!
//! `elapsed_ms` is wall-clock from just before the request is issued to just
//! after the body is read. That includes DNS, TCP, TLS, and server think-time.
//! It is a useful signal for spotting anomalies -- one request that suddenly
//! takes three seconds is worth a look -- but it is **not** a server-side
//! timing measurement and cannot be used to draw conclusions about blind SQL
//! injection or similar. On localhost the client is most of the number.
//!
//! Redirects are **not** followed. A Repeater that silently chased a redirect
//! would show the operator a response to a different request than the one they
//! sent, which is exactly the confusion this tool exists to prevent.

use serde::{Deserialize, Serialize};
use std::time::Instant;

pub use crate::RepeaterError;

use crate::ParsedRequest;

/// The result of sending a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendOutcome {
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Set when the body exceeded the storage cap.
    pub body_truncated_at: Option<usize>,
    /// True size on the wire, even when truncated.
    pub body_size: usize,
    pub elapsed_ms: u64,
    /// The URL actually contacted, which may differ from what was typed when
    /// the request line used an origin-form target.
    pub url: String,
}

/// Bodies above this are truncated before storage. A login endpoint can return
/// megabytes of HTML, and holding them in UI state makes the app sluggish
/// without adding anything the operator reads.
const MAX_BODY: usize = 2 * 1024 * 1024;

/// Sends requests. Abstracted so tests can run without a network.
#[async_trait::async_trait]
pub trait Sender {
    async fn send(
        &self,
        url: &str,
        req: &ParsedRequest,
    ) -> std::result::Result<SendOutcome, RepeaterError>;
}

/// Real network sender.
pub struct HttpSender {
    client: reqwest::Client,
}

impl HttpSender {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            // A proxy must be able to see a 302 rather than follow it.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client }
    }
}

impl Default for HttpSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Sender for HttpSender {
    async fn send(
        &self,
        url: &str,
        req: &ParsedRequest,
    ) -> std::result::Result<SendOutcome, RepeaterError> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| RepeaterError::Send(format!("unsupported method: {e}")))?;

        let mut builder = self.client.request(method, url);

        for h in &req.headers {
            // `Host` is set by the client from the URL; a duplicate makes some
            // servers reject the request, which looks like a server behaviour
            // change when it is really ours. Content-Length and
            // Transfer-Encoding are likewise the client's to compute.
            if h.name.eq_ignore_ascii_case("host")
                || h.name.eq_ignore_ascii_case("content-length")
                || h.name.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            builder = builder.header(&h.name, &h.value);
        }

        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }

        let started = Instant::now();
        let response = builder
            .send()
            .await
            .map_err(|e| RepeaterError::Send(describe_send_error(&e)))?;
        let status = response.status();
        let reason = status.canonical_reason().unwrap_or("").to_string();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("<binary>").to_string(),
                )
            })
            .collect();

        let bytes = response
            .bytes()
            .await
            .map_err(|e| RepeaterError::Send(format!("response body could not be read: {e}")))?;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        let body_size = bytes.len();
        let (body, truncated) = if body_size > MAX_BODY {
            (
                String::from_utf8_lossy(&bytes[..MAX_BODY]).to_string(),
                Some(MAX_BODY),
            )
        } else {
            (String::from_utf8_lossy(&bytes).to_string(), None)
        };

        Ok(SendOutcome {
            status_code: status.as_u16(),
            reason,
            headers,
            body,
            body_truncated_at: truncated,
            body_size,
            elapsed_ms,
            url: url.to_string(),
        })
    }
}

/// Turn a reqwest error into something an operator can act on.
///
/// "error sending request" tells a beginner nothing. Naming the likely cause is
/// the difference between a message they can act on and one they will ignore.
fn describe_send_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return "The server did not respond within 30 seconds. It may be slow, or the \
                connection may be blocked rather than closed."
            .to_string();
    }
    if e.is_connect() {
        return format!(
            "Could not connect to the host. Check the address, that the port is open, and \
             that the server is running. ({e})"
        );
    }
    if e.is_redirect() {
        return "The server returned a redirect this tool will not follow, so you can see \
                exactly what came back."
            .to_string();
    }
    if e.is_body() || e.is_decode() {
        return format!("The response body could not be read. ({e})");
    }
    format!("{e}")
}
