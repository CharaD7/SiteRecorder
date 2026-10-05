//! Payload-driven parameter fuzzing (Burp Suite Intruder).
//!
//! # What this is for
//!
//! Put `§` around a value, supply a list of replacements, and send one request
//! per payload. Then read the results and notice which ones changed the
//! response.
//!
//! # What this deliberately does not do
//!
//! **It does not decide which responses are "interesting".** That sounds
//! helpful and is not. Intruder traffic is compared against *itself* — this
//! payload versus that payload — and a difference in length or status proves
//! only that the server behaved differently. A 500 may be a bug, a WAF
//! reacting to a quote character, or a genuinely different code path. All three
//! look identical from here.
//!
//! So [`ResponseCluster`] groups by observable signature and [`ClusterSummary`]
//! describes the groups in plain language. The operator reads them. A tool that
//! sorted requests into "vulnerable" and "not vulnerable" would be guessing,
//! and a security tool that guesses loudly is worse than one that shows data.
//!
//! # Safety
//!
//! Fuzzing sends real traffic to a real host. [`AttackConfig`] carries a hard
//! cap on request count and a concurrency limit, both defaulting low. Someone
//! who pastes 500k payloads should get a number they can reason about, not an
//! accidental denial of service against a third party.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub mod cluster;
pub mod run;

/// Re-exported so callers can build a [`MarkedRequest`] template and a
/// [`repeater::Sender`] without depending on two crates directly.
pub use repeater;

#[cfg(test)]
mod tests;

pub use cluster::{ClusterSummary, ResponseCluster};
pub use run::{AttackConfig, AttackProgress, Runner};

#[derive(Debug, Error)]
pub enum IntruderError {
    #[error("the request could not be parsed: {0}")]
    Parse(String),
    #[error("no payload positions are marked with §")]
    NoPositions,
    #[error("the request has no target URL: {0}")]
    NoTarget(String),
    #[error("the payload list is empty")]
    NoPayloads,
    #[error("could not read the payload list: {0}")]
    PayloadFile(String),
    #[error("attack failed: {0}")]
    Run(String),
}

/// The character that marks a payload position, as in Burp.
pub const POSITION_MARKER: char = '§';

/// How a list of payloads is supplied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadSource {
    /// One entry per line from a file on disk.
    File { path: String },
    /// Values typed or pasted into the UI.
    Inline { values: Vec<String> },
}

/// A request with `§` markers around the parts to vary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarkedRequest {
    pub id: String,
    /// Raw HTTP text, containing one or more §-delimited positions.
    pub text: String,
}

impl MarkedRequest {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            text: text.into(),
        }
    }

    /// Substitute `payload` into every marked position.
    ///
    /// Every position receives the same payload. Burp's "sniper" mode, which
    /// varies one position at a time, is deliberately not implemented: it
    /// multiplies requests by the position count, and the operator has to
    /// already know which position they meant. Getting that wrong is easy and
    /// produces results that look real.
    pub fn substitute(&self, payload: &str) -> Result<String, IntruderError> {
        if !self.text.contains(POSITION_MARKER) {
            return Err(IntruderError::NoPositions);
        }
        Ok(self.text.replace(POSITION_MARKER, payload))
    }

    /// How many marked positions there are.
    pub fn position_count(&self) -> usize {
        self.text.matches(POSITION_MARKER).count() / 2
    }

    /// The template with markers replaced by a readable placeholder.
    ///
    /// The marked span is `§value§`, so the placeholders must be replaced
    /// innermost-first; replacing `§` on its own would silently delete the
    /// value and leave the operator unable to see what was being varied.
    pub fn display_text(&self) -> String {
        let re = regex::Regex::new(&format!(
            "{POSITION_MARKER}[^{POSITION_MARKER}]*{POSITION_MARKER}"
        ))
        .expect("static pattern");
        re.replace_all(&self.text, "<payload>").to_string()
    }
}

/// Load payloads from a source.
///
/// Blank lines and `#` comments are skipped, the convention every wordlist
/// already uses. An empty result is an error rather than a silent zero-request
/// attack, because "0 requests sent" looks identical to "the tool did nothing".
/// Duplicates are dropped: sending the same payload twice produces two identical
/// rows while still consuming the request cap.
pub fn load_payloads(source: &PayloadSource) -> Result<Vec<String>, IntruderError> {
    let raw = match source {
        PayloadSource::Inline { values } => {
            values.iter().map(|s| format!("{s}\n")).collect::<String>()
        }
        PayloadSource::File { path } => std::fs::read_to_string(path)
            .map_err(|e| IntruderError::PayloadFile(format!("{path}: {e}")))?,
    };

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }

    if out.is_empty() {
        return Err(IntruderError::NoPayloads);
    }
    Ok(out)
}

/// What happened for one payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Attempt {
    pub payload: String,
    /// `None` when the request never got a response. Kept distinct from a
    /// status: "no answer" and "an answer I did not understand" are different
    /// facts, and collapsing them hides a whole class of network problem.
    pub result: Result<AttemptResult, String>,
    /// Position in the payload list, so ordering stays recoverable even though
    /// requests complete out of order.
    pub index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttemptResult {
    pub status_code: u16,
    pub body_size: usize,
    pub elapsed_ms: u64,
    /// Signature used for grouping; see [`cluster`].
    pub signature: String,
    /// Short excerpt, so the operator can recognise the page.
    pub snippet: String,
}

/// The outcome of a whole attack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttackReport {
    pub id: String,
    pub started_at: String,
    pub finished_at: String,
    pub total_payloads: usize,
    /// Payloads actually attempted. Less than `total_payloads` when the run was
    /// cut short, which must be visible rather than implied.
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub attempts: Vec<Attempt>,
    pub clusters: Vec<ClusterSummary>,
    /// Set when the run stopped early, naming why.
    pub stopped_because: Option<String>,
    pub config: AttackConfig,
}

impl AttackReport {
    /// True when every payload was attempted.
    pub fn is_complete(&self) -> bool {
        self.attempted == self.total_payloads && self.stopped_because.is_none()
    }

    /// Payloads that produced no response at all.
    pub fn no_response_count(&self) -> usize {
        self.attempts.iter().filter(|a| a.result.is_err()).count()
    }
}

/// Group attempts by their observable signature.
pub fn group_by_signature(attempts: &[Attempt]) -> BTreeMap<String, Vec<usize>> {
    let mut map: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for a in attempts {
        if let Ok(r) = &a.result {
            map.entry(r.signature.clone()).or_default().push(a.index);
        }
    }
    map
}
