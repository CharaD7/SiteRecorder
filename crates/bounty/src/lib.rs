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

/// Extra locations to probe when the entry points are not on `PATH`.
///
/// ChainScope is a private, pip-installed checkout rather than a system tool.
/// Its console scripts live in the project's own `.venv/bin`, which is not on
/// `PATH` unless the venv is activated -- so `command -v cs` fails even though
/// the tool is fully installed and working.
///
/// `CHAINSCOPE_BIN` overrides this entirely and takes precedence over both.
const CANDIDATE_EXTRA_PATHS: [&str; 2] = [
    "~/Developments/Personal/Hacks/Immunefi/ChainScope/.venv/bin/cs",
    "~/Developments/Personal/Hacks/Immunefi/ChainScope/.venv/bin/chain-scope",
];

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
    /// Filled in by the caller.
    ///
    /// `#[serde(default)]` because ChainScope returns only `{addresses, repos}`
    /// -- it does not echo the slug back. This was a required field, so
    /// deserialising a real `scope` payload failed with "missing field `slug`".
    #[serde(default)]
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
    /// Supplied by the caller, not by the tool.
    ///
    /// `#[serde(default)]` because ChainScope's payload has no `slug` key --
    /// verified against real output. It was previously a required field, so
    /// deserialising a genuine report failed outright.
    #[serde(default)]
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
    /// Locate ChainScope.
    ///
    /// Probe order: `$CHAINSCOPE_BIN`, then `cs`/`chain-scope` on `PATH`, then
    /// the known checkout's `.venv/bin`.
    ///
    /// Probes with `--help`, **not** `--version`: ChainScope's Typer app defines
    /// no `--version` option, so `cs --version` exits **2** and prints usage. A
    /// `--version` probe therefore reports a fully working tool as absent --
    /// which is exactly the bug that hid it. `--help` exits 0.
    pub fn discover() -> Option<Self> {
        match Self::discover_all() {
            Ok(Availability::Available { bin }) => Some(Self {
                bin,
                timeout: DEFAULT_TIMEOUT,
            }),
            _ => None,
        }
    }

    /// Probe every known location, in order.
    ///
    /// Note this cannot use `or_else`: `discover_with` returns
    /// `Ok(Unavailable)` for "looked, not there", so a plain `or_else` would
    /// never reach the fallback. Check the variant explicitly.
    pub fn discover_all() -> Result<Availability, BountyError> {
        if let Ok(explicit) = std::env::var("CHAINSCOPE_BIN") {
            let expanded = expand_tilde(&explicit);
            if self_probes(&expanded) {
                return Ok(Availability::Available { bin: expanded });
            }
            return Ok(Availability::Unavailable {
                reason: format!(
                    "CHAINSCOPE_BIN is set to `{explicit}` but that binary did not respond to `--help`"
                ),
            });
        }
        match Self::discover_with(&CANDIDATE_BINARIES)? {
            found @ Availability::Available { .. } => Ok(found),
            // Nothing on PATH; try the known checkout's own virtualenv before
            // concluding the tool is absent.
            _ => Self::discover_with(&CANDIDATE_EXTRA_PATHS),
        }
    }

    /// Probe specific binaries; exposed for tests.
    ///
    /// Only the given names are tried -- no implicit fallback paths -- so tests
    /// can assert on exact behaviour.
    pub fn discover_with(binaries: &[&str]) -> Result<Availability, BountyError> {
        let expanded: Vec<String> = binaries.iter().map(|b| expand_tilde(b)).collect();
        let refs: Vec<&str> = expanded.iter().map(String::as_str).collect();
        for bin in refs {
            if self_probes(bin) {
                return Ok(Availability::Available {
                    bin: bin.to_string(),
                });
            }
        }
        Ok(Availability::Unavailable {
            reason: format!("none of {binaries:?} responded to `--help` on PATH"),
        })
    }

    /// Report availability without constructing a client.
    pub fn availability() -> Availability {
        Self::discover_all().unwrap_or(Availability::Unavailable {
            reason: "the probe itself failed".to_string(),
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

/// Treat ChainScope's textual "no value" markers as unreported.
///
/// The tool emits Python's `None` for unset fields. Storing that literal would
/// present "None" as if it were a network name or a known-issue count.
fn normalise_optional(value: &str) -> Option<&str> {
    let v = value.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("none") || v.eq_ignore_ascii_case("null") {
        None
    } else {
        Some(v)
    }
}

/// Parse a boolean the way ChainScope actually prints it.
///
/// `cs immune meta` emits Python `True`/`False`, not `yes`/`no`. Matching only
/// "yes" made every real program report `poc_required: Some(false)` -- asserting
/// a PoC was not required when the tool had said it was.
fn parse_bool(value: &str) -> Option<bool> {
    let v = value.trim();
    if v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes") {
        Some(true)
    } else if v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("no") {
        Some(false)
    } else {
        None
    }
}

/// Does this path respond as the ChainScope CLI?
///
/// Uses `--help`, not `--version`: ChainScope's Typer app has no `--version`
/// option, so that flag exits 2 even for a healthy install.
fn self_probes(bin: &str) -> bool {
    if bin.contains('/') && !std::path::Path::new(bin).exists() {
        return false;
    }
    std::process::Command::new(bin)
        .arg("--help")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Expand a leading `~` so hard-coded home-relative paths resolve.
///
/// Deliberately minimal: only `~` and `~/...`, which is all the fallback list
/// uses. Anything else is passed through untouched.
fn expand_tilde(path: &str) -> String {
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
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
                "network" => {
                    // ChainScope prints Python's `None` for an unset field.
                    // Recording the literal string "None" would look like a real
                    // network name, so treat it as unreported.
                    meta.network = normalise_optional(value).map(str::to_string);
                }
                "PoC required" => meta.poc_required = parse_bool(value),
                "known issues" => meta.known_issues = normalise_optional(value).map(str::to_string),
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

    /// Parses a real `cs immune triage --json` payload.
    ///
    /// Captured from `cs immune triage layerzero --max-fetch 1` against the
    /// installed tool: 21 files indexed, 133 nodes / 314 edges, 25 hotspots.
    /// The payload is preceded by progress lines, which is what `extract_json`
    /// exists to strip.
    ///
    /// This is the fixture class that caught the `True`/`None` meta bugs: real
    /// output has an extra `source_context` and `visibility` field per hotspot,
    /// and `line`/`score` are present as JSON numbers, not strings.
    #[test]
    fn triage_parses_real_captured_output() {
        let progress = "\
layerzero: 10 in-scope address(es), 4 repo(s); fetching 1.
  repo: https://github.com/LayerZero-Labs/LayerZero
  [ok] 1:0x4d73adb72bc3dd368966edd0f0b2148401a178e2 files=21
graph: 133 nodes, 314 edges, 21/21 files
top hotspots (immune-layerzero.db):
  functionDelegateCall 1/0x4d73.../Address.sol:163 score=9 [proxy,upgrade_surface]
Next: read flagged functions, adjudicate vs program rules.
";
        let json = r#"{
  "scope": {
    "addresses": [
      { "chain": "1", "address": "0x4d73adb72bc3dd368966edd0f0b2148401a178e2", "host": "etherscan.io" },
      { "chain": "aptoscan.com", "address": "0x54ad3d30af77b60d939ae356e6606de9a4da6758", "host": "aptoscan.com" }
    ],
    "repos": ["https://github.com/LayerZero-Labs/LayerZero"]
  },
  "fetched": 1,
  "errors": 0,
  "hotspots": [
    {
      "function": "functionDelegateCall",
      "file": "1/0x4d73adb72bc3dd368966edd0f0b2148401a178e2/Address.sol",
      "line": 163,
      "score": 9,
      "reasons": ["proxy(['contains_delegatecall'])", "upgrade_surface", "privileged(1)"],
      "source_context": "production",
      "visibility": "public"
    },
    {
      "function": "owner",
      "file": "1/0x4d73adb72bc3dd368966edd0f0b2148401a178e2/Ownable.sol",
      "line": 35,
      "score": 6,
      "reasons": ["privileged(1)", "unguarded_privileged"],
      "source_context": "production",
      "visibility": "public"
    }
  ]
}"#;
        let stdout = format!("{progress}{json}");
        let payload = extract_json(&stdout).expect("payload must be extractable");
        let report: TriageReport =
            serde_json::from_str(&payload).expect("payload must deserialize");

        // ChainScope does not echo the slug back, so a payload deserialised
        // directly has an empty slug. `ChainScope::triage()` is what fills it
        // in from the caller's argument, which is what this asserts below.
        assert_eq!(report.slug, "", "tool payload carries no slug");
        assert_eq!(report.fetched, 1);
        assert_eq!(report.errors, 0);
        assert!(!report.indexed_nothing(), "1 source was indexed");

        let scope = report.scope.expect("scope present");
        assert_eq!(scope.addresses.len(), 2);
        assert_eq!(scope.addresses[0].chain, "1");
        assert_eq!(scope.addresses[0].host.as_deref(), Some("etherscan.io"));
        assert_eq!(scope.repos.len(), 1);

        assert_eq!(report.hotspots.len(), 2);
        let top = &report.hotspots[0];
        assert_eq!(top.function.as_deref(), Some("functionDelegateCall"));
        // line and score are JSON numbers; a String field would silently be None.
        assert_eq!(top.line, Some(163), "line must survive as a number");
        assert_eq!(top.score, Some(9.0), "score must survive as a number");
        assert_eq!(top.reasons.len(), 3);
        // Extra fields ChainScope emits must not break deserialisation.
        assert_eq!(
            top.file.as_deref(),
            Some("1/0x4d73adb72bc3dd368966edd0f0b2148401a178e2/Address.sol")
        );
    }

    /// The progress text a real run prints before its payload.
    #[test]
    fn extract_json_handles_real_triage_preamble() {
        let stdout = "\
layerzero: 10 in-scope address(es), 4 repo(s); fetching 1.
  repo: https://github.com/LayerZero-Labs/Audits
  [ok] 1:0x4d73adb72bc3dd368966edd0f0b2148401a178e2 files=21
graph: 133 nodes, 314 edges, 21/21 files
top hotspots (immune-layerzero.db):
  functionDelegateCall 1/0x4d73/Address.sol:163 score=9 [proxy,upgrade_surface]
Next: read flagged functions, adjudicate vs program rules.
{ \"fetched\": 1, \"errors\": 0, \"hotspots\": [] }
";
        let payload = extract_json(stdout).expect("must strip the preamble");
        assert!(payload.starts_with('{'));
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["fetched"], 1);
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
    fn meta_parses_captured_real_chainscope_output() {
        // Captured verbatim from `cs immune meta layerzero`, not hand-written.
        // The earlier fixture was invented, and invented fixtures are how the
        // True/yes and None bugs below survived.
        let text = "\
LayerZero  (layerzero)
  max bounty    : $15,000,000
  launched      : 2023-05-17
  last updated  : 2026-10-02
  network       : None
  primacy (dflt) : None
  primacy (crit) : None
  PoC required  : True
  KYC required  : True
  known issues  : 1
  audits (0) — findings here are likely ineligible:
";
        let m = BountyMeta::parse(text);
        assert_eq!(m.project.as_deref(), Some("LayerZero"));
        assert_eq!(m.max_bounty, Some(15_000_000.0));
        // ChainScope prints Python True/False, not yes/no.
        assert_eq!(m.poc_required, Some(true), "True must parse as true");
        // Python `None` means unreported, not the string "None".
        assert_eq!(
            m.network, None,
            "literal None must not become a network name"
        );
        assert_eq!(m.known_issues.as_deref(), Some("1"));
        assert!(m.audits.is_empty());
    }

    #[test]
    fn meta_leaves_unreported_fields_none() {
        let m = BountyMeta::parse("Something  (x)\n  network : Arbitrum\n");
        assert_eq!(m.network.as_deref(), Some("Arbitrum"));
        assert_eq!(m.max_bounty, None);
        assert_eq!(m.poc_required, None);
    }

    /// The exact failure that shipped: matching only "yes" reported
    /// `poc_required: Some(false)` for a program that requires a PoC.
    #[test]
    fn poc_required_is_not_silently_false_for_a_real_program() {
        let m = BountyMeta::parse("X  (x)\n  PoC required  : True\n");
        assert_ne!(
            m.poc_required,
            Some(false),
            "must not report 'no PoC required' when ChainScope said True"
        );
        assert_eq!(m.poc_required, Some(true));
    }

    #[test]
    fn python_none_does_not_become_data() {
        for marker in ["None", "none", "null"] {
            let m = BountyMeta::parse(&format!("X  (x)\n  network : {marker}\n"));
            assert_eq!(m.network, None, "`{marker}` must parse as unreported");
        }
        let m = BountyMeta::parse("X  (x)\n  known issues  : None\n");
        assert_eq!(m.known_issues, None);
    }

    #[test]
    fn tilde_expands_only_for_home_paths() {
        std::env::set_var("HOME", "/home/tester");
        assert_eq!(expand_tilde("~/x/cs"), "/home/tester/x/cs");
        assert_eq!(expand_tilde("/abs/cs"), "/abs/cs");
        assert_eq!(expand_tilde("cs"), "cs");
        std::env::remove_var("HOME");
    }

    /// Regression guard for the bug that hid a working tool.
    ///
    /// ChainScope's Typer app has no `--version`, so `cs --version` exits 2. A
    /// `--version` probe therefore reports a healthy install as absent -- which
    /// is exactly what happened, leaving the bounty panel permanently disabled
    /// while the tool sat installed in its own .venv.
    #[test]
    fn probe_does_not_rely_on_a_version_flag() {
        // Any working binary that rejects `--version` but accepts `--help` must
        // still be recognised as present.
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("faketool");
        std::fs::write(
            &script,
            "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then echo 'No such option' >&2; exit 2; fi\n\
             if [ \"$1\" = \"--help\" ]; then echo usage; exit 0; fi\n\
             exit 2\n",
        )
        .expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
        }
        let path = script.to_string_lossy().to_string();

        assert!(
            !self_probes_version_flag(&path),
            "precondition: --version exits non-zero for this tool"
        );
        assert!(
            self_probes(&path),
            "a tool that answers --help must be reported available"
        );
    }

    /// The probe this crate previously used, kept so the test above documents
    /// the behaviour that was replaced rather than just asserting the new one.
    fn self_probes_version_flag(bin: &str) -> bool {
        std::process::Command::new(bin)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// If ChainScope is installed, discovery must actually find it.
    ///
    /// On a machine without it this still passes -- it asserts the two outcomes
    /// are distinguishable, not that the tool is present.
    #[test]
    fn discovery_agrees_with_reality() {
        let availability = ChainScope::availability();
        let on_path = std::process::Command::new("cs")
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if on_path {
            assert!(
                availability.is_available(),
                "`cs` is on PATH and answers --help, so discovery must find it"
            );
        }
        // Whether or not it is installed, the reason must never imply an empty
        // catalogue rather than a missing tool.
        assert!(!availability.reason().is_empty());
    }
}
