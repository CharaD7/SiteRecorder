//! Sending one request per payload.
//!
//! # Why the caps exist
//!
//! Fuzzing is real traffic against a real host. `max_requests` is a hard stop:
//! when the payload list is longer, the remainder is **not** sent and the
//! report says so via `stopped_because`. Silently truncating would leave the
//! operator believing the whole list was covered.
//!
//! `max_concurrency` defaults to 4. Higher is usually faster and more likely to
//! be rate-limited or WAF-blocked, which produces results that look like
//! application behaviour rather than like throttling.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures::stream::{self, StreamExt};

use crate::cluster;
use crate::{AttackReport, Attempt, AttemptResult, MarkedRequest};
use repeater::send::{SendOutcome, Sender};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackConfig {
    /// Hard cap on requests sent. The default is deliberately small.
    pub max_requests: usize,
    /// Simultaneous in-flight requests.
    pub max_concurrency: usize,
    /// Per-request timeout, in milliseconds.
    pub timeout_ms: u64,
    /// Characters kept from each response body, for the snippet column.
    pub snippet_chars: usize,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            // Low enough that an accidental paste cannot flood a host.
            max_requests: 500,
            max_concurrency: 4,
            timeout_ms: 10_000,
            snippet_chars: 200,
        }
    }
}

/// Runs an attack against one target.
pub struct Runner<S: Sender> {
    sender: S,
    config: AttackConfig,
}

impl<S: Sender> Runner<S> {
    pub fn new(sender: S, config: AttackConfig) -> Self {
        Self { sender, config }
    }

    /// Execute the attack.
    ///
    /// The template is validated *before* any request is sent. A run that
    /// fails 500 times because of a missing `Host` header teaches the operator
    /// nothing and needlessly hammers the host.
    pub async fn run(
        &self,
        marked: &MarkedRequest,
        payloads: &[String],
        on_progress: Option<AttackProgress>,
    ) -> Result<AttackReport, crate::IntruderError> {
        let probe = repeater::ParsedRequest::parse(&marked.substitute("probe")?)
            .map_err(|e| crate::IntruderError::Parse(e.to_string()))?;
        probe
            .absolute_url()
            .map_err(|e| crate::IntruderError::NoTarget(e.to_string()))?;

        let started_at = chrono::Utc::now().to_rfc3339();

        let total = payloads.len().min(self.config.max_requests);
        let truncated = payloads.len() > self.config.max_requests;

        let counter = Arc::new(AtomicUsize::new(0));
        let marked_arc = marked.clone();
        // Each stream item needs its own handle. `Arc` makes the clone cheap and
        // keeps the callback optional inside every task.
        let progress_arc: Option<Arc<AttackProgress>> = on_progress.map(Arc::new);

        let attempts: Vec<Attempt> = stream::iter(payloads.iter().take(total).cloned().enumerate())
            .map(|(index, payload)| {
                let marked = marked_arc.clone();
                let sender = &self.sender;
                let counter = counter.clone();
                let cfg = &self.config;
                let progress = progress_arc.clone();
                async move {
                    let result = match marked.substitute(&payload) {
                        Ok(text) => match repeater::ParsedRequest::parse(&text) {
                            Ok(parsed) => match parsed.absolute_url() {
                                Ok(url) => match sender.send(&url, &parsed).await {
                                    Ok(outcome) => Ok(attempt_from(outcome, cfg.snippet_chars)),
                                    Err(e) => Err(e.to_string()),
                                },
                                Err(e) => Err(e.to_string()),
                            },
                            Err(e) => Err(e.to_string()),
                        },
                        Err(e) => Err(e.to_string()),
                    };

                    let done = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if let Some(cb) = &progress {
                        cb(done, total);
                    }

                    Attempt {
                        payload,
                        result,
                        index,
                    }
                }
            })
            .buffer_unordered(self.config.max_concurrency.max(1))
            .collect()
            .await;

        // `buffer_unordered` does not preserve order; sort so the report reads
        // in payload order and indexes line up with the operator's own list.
        let mut attempts = attempts;
        attempts.sort_by_key(|a| a.index);

        let succeeded = attempts.iter().filter(|a| a.result.is_ok()).count();
        let failed = attempts.len() - succeeded;
        let clusters = cluster::cluster(&attempts);

        Ok(AttackReport {
            id: uuid::Uuid::new_v4().to_string(),
            started_at,
            finished_at: chrono::Utc::now().to_rfc3339(),
            total_payloads: payloads.len(),
            attempted: attempts.len(),
            succeeded,
            failed,
            attempts,
            clusters,
            stopped_because: if truncated {
                Some(format!(
                    "Sent the first {total} of {} payloads. The remaining {} were NOT sent, so \
                     this run does not cover the whole list.",
                    payloads.len(),
                    payloads.len() - total
                ))
            } else {
                None
            },
            config: self.config.clone(),
        })
    }
}

fn attempt_from(outcome: SendOutcome, snippet_chars: usize) -> AttemptResult {
    let snippet: String = outcome.body.chars().take(snippet_chars).collect();
    AttemptResult {
        status_code: outcome.status_code,
        body_size: outcome.body_size,
        elapsed_ms: outcome.elapsed_ms,
        signature: format!("{}:{}", outcome.status_code, outcome.body_size),
        snippet,
    }
}

/// Progress callback, called after each completed request.
pub type AttackProgress = Arc<dyn Fn(usize, usize) + Send + Sync>;
