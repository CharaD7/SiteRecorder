//! Bug-bounty program triage.
//!
//! Thin wrapper over the external **ChainScope** toolkit
//! (`cs immune list|scope|triage|meta`). ChainScope scrapes a program's published
//! scope, fetches verified contract sources, indexes them into a SQLite code
//! graph, and ranks hotspots.
//!
//! # The load-bearing rule
//!
//! ChainScope is an *optional external dependency*. It is not vendored, and it is
//! frequently absent. When it is missing this crate returns
//! [`BountyError::ToolUnavailable`] — it never synthesises a program list, a
//! hotspot, or a triage verdict. A bounty screen that looks populated but was
//! never backed by scope data is the exact failure mode this module exists to
//! prevent.
//!
//! This complements `crates::web3`: ChainScope maps *source*, it does not audit
//! deployed bytecode, and a hotspot ranking is not a verdict. Verdicts and PoCs
//! stay with the human analyst.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Wall-clock ceiling for a single ChainScope invocation.
///
/// `cs immune triage` builds a code graph and fetches sources over the network,
/// so the ceiling is generous. Exceeding it is reported as a timeout, never as
/// an empty result.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Error)]
pub enum BountyError {
    /// ChainScope is not installed or not on `PATH`.
    ///
    /// This is the expected state on a machine without the toolkit, not a bug.
    /// Callers must surface it as "unavailable" and must not substitute data.
    #[error(
        "ChainScope is not installed or not on PATH. \
         Bounty triage is disabled; install it with `pip install -e <chain-scope-checkout>` \
         (entry points `cs` / `chain-scope`) and re-run."
    )]
    ToolUnavailable,

    #[error("ChainScope exited with status {status}: {stderr}")]
    CommandFailed { status: String, stderr: String },

    #[error("ChainScope timed out after {0:?}")]
    Timeout(Duration),

    #[error("could not parse ChainScope output as JSON: {0}")]
    Parse(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Candidate binaries, in probe order.
///
/// `cs` is ChainScope's own declared entry point; `chain-scope` is the same
/// console script under its full name.
const CANDIDATE_BINARIES: [&str; 2] = ["cs", "chain-scope"];

/// One in-scope contract address, as published in the program's scope page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopedAddress {
    /// ChainScope's Sourcify-style chain spec (e.g. `ethereum`, `arbitrum`).
    pub chain: String,
    pub address: String,
    /// Block explorer the address was scraped from; provenance for the entry.
    #[serde(default)]
    pub host: Option<String>,
}

/// A program's published in-scope surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProgramScope {
    pub slug: String,
    #[serde(default)]
    pub addresses: Vec<ScopedAddress>,
    #[serde(default)]
    pub repos: Vec<String>,
}

impl ProgramScope {
    /// True when the program page yielded no addressable surface.
    ///
    /// Distinct from an *error*: an empty scope means the program publishes no
    /// contracts we can index, which is itself a triage answer.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty() && self.repos.is_empty()
    }
}

/// One program from `cs immune list --json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BountyProgram {
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub max_bounty: Option<f64>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    /// Number of published audits; findings here are likely ineligible.
    #[serde(default)]
    pub audits: Option<u32>,
    #[serde(default)]
    pub poc: Option<bool>,
    /// Any field ChainScope did not report stays `None` rather than defaulting
    /// to zero — a missing bounty is not a zero-bounty program.
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// A code hotspot ChainScope ranked out of the indexed graph.
///
/// A hotspot is a *place worth reading*, not a vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hotspot {
    #[serde(default)]
    pub function: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u64>,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

/// Result of a full `cs immune triage` run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TriageReport {
    pub slug: String,
    #[serde(default)]
    pub scope: Option<ProgramScope>,
    /// Sources successfully fetched and indexed.
    pub fetched: usize,
    /// Fetches that failed. Non-zero means coverage below the fetched count.
    pub errors: usize,
    #[serde(default)]
    pub hotspots: Vec<Hotspot>,
}

impl TriageReport {
    /// True when nothing was successfully indexed.
    pub fn indexed_nothing(&self) -> bool {
        self.fetched == 0
    }
}

/// Availability of the external ChainScope toolkit.
#[derive(Debug, Clone, PartialEq)]
pub enum Availability {
    /// Found on `PATH`; `bin` is the working binary name.
    Available { bin: String },
    /// Not found. Carries the reason so the UI can state it rather than
    /// implying an empty program list.
    Unavailable { reason: String },
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Availability::Available { .. })
    }

    /// The binary name, when available.
    pub fn binary(&self) -> Option<&str> {
        match self {
            Availability::Available { bin } => Some(bin.as_str()),
            Availability::Unavailable { .. } => None,
        }
    }

    /// Human-readable explanation for either state.
    pub fn reason(&self) -> String {
        match self {
            Availability::Available { bin } => format!("ChainScope found at `{bin}`."),
            Availability::Unavailable { reason } => format!(
                "ChainScope is unavailable, so bounty triage is disabled. {reason}. \
                 No program or hotspot data is shown, because none was retrieved."
            ),
        }
    }
}

/// Handle to the external ChainScope CLI.
///
/// Construct via [`ChainScope::discover`], which returns `None` when the tool is
/// absent, so callers cannot accidentally treat "missing" as "empty".
pub struct ChainScope {
    bin: String,
    timeout: Duration,
}

impl ChainScope {
    /// Locate ChainScope on `PATH`.
    ///
    /// Returns `None` when no candidate binary responds to `--version`. A
    /// non-zero-status or absent response counts as missing.
    pub fn discover() -> Option<Self> {
        match Self::discover_with(&CANDIDATE_BINARIES) {
            Ok(Availability::Available { bin }) => Some(Self {
                bin,
                timeout: DEFAULT_TIMEOUT,
            }),
            _ => None,
        }
    }

    /// Probe specific binaries; exposed for tests.
    pub fn discover_with(binaries: &[&str]) -> Result<Availability, BountyError> {
        for bin in binaries {
            let ok = std::process::Command::new(bin)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                return Ok(Availability::Available {
                    bin: (*bin).to_string(),
                });
            }
        }
        Ok(Availability::Unavailable {
            reason: format!("none of {:?} responded to `--version` on PATH", binaries),
        })
    }

    /// Report availability without constructing a client.
    pub fn availability() -> Availability {
        Self::discover_with(&CANDIDATE_BINARIES).unwrap_or(Availability::Unavailable {
            reason: "the PATH probe itself failed".to_string(),
        })
    }

    /// A client bound to an explicit binary; exposed for tests.
    pub fn with_binary(bin: impl Into<String>, timeout: Duration) -> Self {
        Self {
            bin: bin.into(),
            timeout,
        }
    }

    pub fn binary(&self) -> &str {
        &self.bin
    }

    /// `cs immune list --json`
    pub async fn programs(&self) -> Result<Vec<BountyProgram>, BountyError> {
        let raw = self
            .run_json(&["immune", "list", "--json", "--top", "100"])
            .await?;
        serde_json::from_str(&raw).map_err(|e| BountyError::Parse(e.to_string()))
    }

    /// `cs immune scope <slug> --json`
    pub async fn scope(&self, slug: &str) -> Result<ProgramScope, BountyError> {
        let raw = self.run_json(&["immune", "scope", slug, "--json"]).await?;
        let body: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| BountyError::Parse(e.to_string()))?;
        // ChainScope returns {addresses, repos} without echoing the slug back.
        Ok(ProgramScope {
            slug: slug.to_string(),
            addresses: field(&body, "addresses")?,
            repos: field(&body, "repos")?,
        })
    }

    /// `cs immune meta <slug>` — parse the text table.
    ///
    /// ChainScope exposes no `--json` for `meta`, so this reads the stable
    /// `key : value` lines and leaves anything unrecognised absent.
    pub async fn meta(&self, slug: &str) -> Result<BountyMeta, BountyError> {
        let out = self.run_text(&["immune", "meta", slug]).await?;
        Ok(BountyMeta::parse(&out))
    }

    /// `cs immune triage <slug> --json`
    pub async fn triage(&self, slug: &str, max_fetch: usize) -> Result<TriageReport, BountyError> {
        let raw = self
            .run_json(&[
                "immune",
                "triage",
                slug,
                "--json",
                "--max-fetch",
                &max_fetch.to_string(),
            ])
            .await?;
        let body: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| BountyError::Parse(e.to_string()))?;
        Ok(TriageReport {
            slug: slug.to_string(),
            scope: body
                .get("scope")
                .cloned()
                .and_then(|s| serde_json::from_value(s).ok()),
            fetched: body.get("fetched").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
            errors: body.get("errors").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
            hotspots: match body.get("hotspots") {
                Some(v) => serde_json::from_value(v.clone())
                    .map_err(|e| BountyError::Parse(e.to_string()))?,
                None => Vec::new(),
            },
        })
    }

    /// Run a subcommand expecting a JSON payload, and return just that payload.
    async fn run_json(&self, args: &[&str]) -> Result<String, BountyError> {
        let stdout = self.spawn(args).await?;
        extract_json(&stdout).ok_or_else(|| {
            BountyError::Parse(format!(
                "no JSON payload in ChainScope stdout ({} bytes)",
                stdout.len()
            ))
        })
    }

    /// Run a subcommand expecting a human-readable table.
    async fn run_text(&self, args: &[&str]) -> Result<String, BountyError> {
        self.spawn(args).await
    }

    async fn spawn(&self, args: &[&str]) -> Result<String, BountyError> {
        let child = tokio::process::Command::new(&self.bin)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output();

        let output = match tokio::time::timeout(self.timeout, child).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(BountyError::IoError(e)),
            Err(_) => return Err(BountyError::Timeout(self.timeout)),
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(BountyError::CommandFailed {
                status: output.status.to_string(),
                // Truncate: ChainScope failures can print a full traceback.
                stderr: stderr.chars().take(2000).collect(),
            });
        }
        Ok(stdout)
    }
}

/// Deserialize an optional field, treating an absent key as the empty default.
///
/// A program that publishes no repos legitimately omits `repos`, which is not a
/// parse failure -- and must not become an invented one either.
fn field<T: serde::de::DeserializeOwned + Default>(
    body: &serde_json::Value,
    key: &str,
) -> Result<T, BountyError> {
    match body.get(key) {
        Some(v) => serde_json::from_value(v.clone()).map_err(|e| BountyError::Parse(e.to_string())),
        None => Ok(T::default()),
    }
}

/// Pull the trailing top-level JSON object out of noisy stdout.
///
/// `cs immune triage` prints progress lines ("aera: 3 in-scope address(es)",
/// per-fetch results) before its payload, so the JSON is the last brace-at-
/// column-0 value rather than the whole stream.
fn extract_json(text: &str) -> Option<String> {
    let start = if text.starts_with('{') || text.starts_with('[') {
        0
    } else {
        text.rfind("\n{").map(|i| i + 1)?
    };
    let candidate = text[start..].trim();
    if candidate.starts_with('{') || candidate.starts_with('[') {
        Some(candidate.to_string())
    } else {
        None
    }
}

/// Parsed `cs immune meta` output.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct BountyMeta {
    pub project: Option<String>,
    pub max_bounty: Option<f64>,
    pub network: Option<String>,
    pub poc_required: Option<bool>,
    pub known_issues: Option<String>,
    #[serde(default)]
    pub audits: Vec<String>,
}

impl BountyMeta {
    /// Parse the `key : value` table ChainScope prints.
    ///
    /// Unrecognised lines are ignored rather than guessed at.
    pub fn parse(text: &str) -> Self {
        let mut meta = BountyMeta::default();
        let mut in_audits = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            // ChainScope prints each auditor as `auditor  date  url` under an
            // "audits (n)" heading, with no key separator.
            if in_audits {
                if let Some(auditor) = line.split_whitespace().next() {
                    meta.audits.push(auditor.to_string());
                }
                continue;
            }
            if line.starts_with("audits (") {
                in_audits = true;
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match key.trim() {
                "max bounty" => {
                    meta.max_bounty = value.trim_start_matches('$').replace(',', "").parse().ok()
                }
                "network" => meta.network = Some(value.to_string()),
                "PoC required" => meta.poc_required = Some(value.eq_ignore_ascii_case("yes")),
                "known issues" => meta.known_issues = Some(value.to_string()),
                _ => {}
            }
        }
        if let Some(head) = text.lines().next().map(str::trim).filter(|h| !h.is_empty()) {
            // "Project Name  (slug)"
            meta.project = Some(head.split("  (").next().unwrap_or(head).trim().to_string());
        }
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_binary_is_reported_unavailable_not_empty() {
        let a = ChainScope::discover_with(&["definitely-not-a-real-binary-xyz"]).unwrap();
        assert!(!a.is_available(), "a missing tool must not look available");
        match a {
            Availability::Unavailable { reason } => {
                assert!(
                    reason.contains("definitely-not-a-real-binary-xyz"),
                    "{reason}"
                );
            }
            Availability::Available { .. } => panic!("must not report available"),
        }
    }

    #[test]
    fn unavailable_reason_states_that_nothing_was_retrieved() {
        let a = ChainScope::discover_with(&["nope-xyz"]).unwrap();
        assert_eq!(a.binary(), None);
        let why = a.reason();
        assert!(why.contains("disabled"), "{why}");
        assert!(why.contains("none was retrieved"), "{why}");
    }

    #[test]
    fn error_text_names_the_tool_and_the_fix() {
        let msg = BountyError::ToolUnavailable.to_string();
        assert!(msg.contains("ChainScope"), "{msg}");
        assert!(msg.contains("disabled"), "{msg}");
    }

    #[test]
    fn extract_json_skips_progress_lines() {
        let text = "aera: 3 in-scope address(es)\n  repo: https://github.com/x/y\n  [ok] ethereum:0x1 files=4\n{\"scope\": {}, \"fetched\": 1, \"errors\": 0, \"hotspots\": []}\n";
        let got = extract_json(text).expect("should find the JSON payload");
        let v: serde_json::Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["fetched"], 1);
        assert_eq!(v["hotspots"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn extract_json_handles_pure_json() {
        let got = extract_json("[{\"slug\":\"aera\"}]").expect("array payload");
        assert!(got.starts_with('['));
    }

    #[test]
    fn extract_json_returns_none_when_there_is_none() {
        assert!(extract_json("aera: no programs match\n").is_none());
        assert!(extract_json("").is_none());
    }

    #[test]
    fn scope_with_no_addresses_is_empty_not_missing() {
        let s = ProgramScope {
            slug: "quiet".into(),
            addresses: vec![],
            repos: vec![],
        };
        assert!(s.is_empty());
    }

    #[test]
    fn triage_report_flags_indexing_nothing() {
        let r = TriageReport {
            slug: "aera".into(),
            scope: None,
            fetched: 0,
            errors: 3,
            hotspots: vec![],
        };
        assert!(r.indexed_nothing());
    }

    #[test]
    fn missing_bounty_field_stays_none_not_zero() {
        let p: BountyProgram = serde_json::from_str(r#"{"slug":"aera","audits":2}"#).unwrap();
        assert_eq!(p.slug.as_deref(), Some("aera"));
        assert_eq!(p.audits, Some(2));
        // Absent, so None -- reporting 0.0 would assert the program pays nothing.
        assert_eq!(p.max_bounty, None, "absent bounty must not become 0.0");
    }

    #[test]
    fn meta_parses_the_documented_table() {
        let text = "\
Aera  (aera)
  max bounty    : $5,000,000
  launched      : 2023-01-01
  network       : Ethereum
  PoC required  : yes
  known issues  : none listed
  audits (2) - findings here are likely ineligible:
    Halborn  2024-01-01  https://example.com/a
";
        let m = BountyMeta::parse(text);
        assert_eq!(m.project.as_deref(), Some("Aera"));
        assert_eq!(m.max_bounty, Some(5_000_000.0));
        assert_eq!(m.network.as_deref(), Some("Ethereum"));
        assert_eq!(m.poc_required, Some(true));
        assert_eq!(m.known_issues.as_deref(), Some("none listed"));
        assert_eq!(m.audits.len(), 1, "{:?}", m.audits);
    }

    #[test]
    fn meta_leaves_unreported_fields_none() {
        let m = BountyMeta::parse("Something  (x)\n  network : Arbitrum\n");
        assert_eq!(m.network.as_deref(), Some("Arbitrum"));
        assert_eq!(m.max_bounty, None);
        assert_eq!(m.poc_required, None);
    }
}
