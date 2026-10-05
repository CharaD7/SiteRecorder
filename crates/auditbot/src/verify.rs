//! Executing a check and reporting what actually happened.
//!
//! This module is the reason the crate can be trusted. It produces one of three
//! verdicts, and `Refuted` is a first-class success of the system rather than a
//! failure to find something: a bot that can only answer "yes" gets its
//! operator banned from bounty programs.
//!
//! Nothing here infers a verdict. Every [`Verdict`] carries the exact command
//! that ran and the output that was observed, so a human can re-run it and get
//! the same answer.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// Foundry is installed under `~/.foundry/bin`, which is not on `PATH` in a
/// non-login shell. Probing the well-known location is what makes this work
/// unattended; without it every verdict would be `ToolMissing`.
const FOUNDRY_BIN_CANDIDATES: [&str; 2] = ["forge", "~/.foundry/bin/forge"];

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// What the proof of concept asserts.
///
/// A Foundry PoC states a claim, and the claim tells you how to read the
/// result. This cannot be inferred from the output alone: an exploit test that
/// *passes* proves the bug exists, while a control test that *passes* proves it
/// does not. Both are `[PASS]`. The caller declares which one is running.
///
/// Guessing here would invert the meaning of every verdict, so the caller must
/// say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    /// The PoC asserts the vulnerability is exploitable. Pass => Confirmed.
    Exploitable,
    /// The PoC asserts the control holds. Pass => Refuted.
    Safe,
}

/// Which external binary ran a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckEngine {
    /// `forge test` -- executes a fork or unit test.
    Forge,
    /// `slither` -- static analysis, no execution.
    Slither,
}

impl CheckEngine {
    pub fn binary(self) -> &'static str {
        match self {
            CheckEngine::Forge => "forge",
            CheckEngine::Slither => "slither",
        }
    }
}

/// The outcome of a check.
///
/// Three states, not two. `Inconclusive` exists because a check that could not
/// run is not the same as a check that ran and found nothing — collapsing them
/// is how "we looked and found nothing" gets asserted without looking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictKind {
    /// The check ran and reproduced the condition.
    Confirmed,
    /// The check ran and the condition did not hold. A real, useful answer.
    Refuted,
    /// The check could not produce a trustworthy answer.
    Inconclusive,
}

impl VerdictKind {
    /// Only `Confirmed` may gate a report.
    pub fn gates_report(self) -> bool {
        matches!(self, VerdictKind::Confirmed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            VerdictKind::Confirmed => "confirmed",
            VerdictKind::Refuted => "refuted",
            VerdictKind::Inconclusive => "inconclusive",
        }
    }
}

/// A verdict, with the provenance that makes it checkable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Verdict {
    pub kind: VerdictKind,
    pub engine: Option<CheckEngine>,
    /// The argv actually executed. Re-runnable by a human.
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    /// Captured output, truncated. Present so a reviewer can see the evidence
    /// rather than take the verdict on faith.
    pub output: String,
    /// Why the verdict is inconclusive, when it is. Never blank for
    /// `Inconclusive` — that is the whole point of the state.
    pub reason: Option<String>,
}

impl Verdict {
    fn inconclusive(engine: Option<CheckEngine>, reason: impl Into<String>) -> Self {
        Verdict {
            kind: VerdictKind::Inconclusive,
            engine,
            command: Vec::new(),
            exit_code: None,
            output: String::new(),
            reason: Some(reason.into()),
        }
    }

    /// Render for a human, with the confidence stated rather than implied.
    pub fn summary(&self) -> String {
        match self.kind {
            VerdictKind::Confirmed => format!(
                "CONFIRMED by {} — reproduced. Command: {}",
                self.engine.map(|e| e.binary()).unwrap_or("?"),
                self.command.join(" ")
            ),
            VerdictKind::Refuted => format!(
                "REFUTED by {} — the check ran and the condition did not hold. Command: {}",
                self.engine.map(|e| e.binary()).unwrap_or("?"),
                self.command.join(" ")
            ),
            VerdictKind::Inconclusive => format!(
                "INCONCLUSIVE — no verdict. {}",
                self.reason.as_deref().unwrap_or("no reason recorded")
            ),
        }
    }
}

/// A check to execute.
#[derive(Debug, Clone)]
pub struct VerificationRequest {
    /// Working directory containing the Foundry project.
    pub project_dir: PathBuf,
    /// Which engine to run.
    pub engine: CheckEngine,
    /// Only run tests whose name matches this, when the engine supports it.
    pub test_filter: Option<String>,
    /// What the PoC claims. Determines how a pass or fail is read.
    pub expected: ExpectedOutcome,
    pub timeout: Duration,
}

impl VerificationRequest {
    /// A PoC asserting the vulnerability is real. A passing test confirms it.
    pub fn forge_exploit(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            engine: CheckEngine::Forge,
            test_filter: None,
            expected: ExpectedOutcome::Exploitable,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// A control asserting the code is safe. A passing test refutes the claim.
    pub fn forge_control(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            expected: ExpectedOutcome::Safe,
            ..Self::forge_exploit(project_dir)
        }
    }

    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.test_filter = Some(filter.into());
        self
    }
}

/// Runs checks and turns their output into verdicts.
pub struct Verifier {
    bin: PathBuf,
}

impl Verifier {
    /// Locate Foundry, falling back to `~/.foundry/bin`.
    pub fn forge() -> Option<Self> {
        let bin = FOUNDRY_BIN_CANDIDATES
            .iter()
            .map(|c| expand_tilde(c))
            .find(|p| Path::new(p).exists() && is_executable(p))?;
        Some(Self {
            bin: PathBuf::from(bin),
        })
    }

    /// Bind to an explicit binary; used by tests.
    pub fn with_binary(bin: impl Into<PathBuf>) -> Self {
        Self { bin: bin.into() }
    }

    pub fn binary(&self) -> &Path {
        &self.bin
    }

    /// Run a check and classify the result.
    ///
    /// The mapping is deliberately conservative:
    /// - a missing tool is `Inconclusive`, never `Refuted`
    /// - a timeout is `Inconclusive` — an unfinished check has proved nothing
    /// - only an actual run that reached a verdict gets `Confirmed`/`Refuted`
    pub async fn run(&self, req: &VerificationRequest) -> Result<Verdict, crate::AuditBotError> {
        let mut argv: Vec<String> = vec![self.bin.to_string_lossy().to_string(), "test".into()];
        if let Some(f) = &req.test_filter {
            argv.push("--match-test".into());
            argv.push(f.clone());
        }
        // Deliberately no --json: `classify` reads the [PASS]/[FAIL] markers
        // from the human-readable report, and asking forge for JSON instead
        // would replace those markers with a shape we do not parse.

        let mut cmd = tokio::process::Command::new(&self.bin);
        cmd.args(&argv[1..])
            .current_dir(&req.project_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = match tokio::time::timeout(req.timeout, cmd.output()).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return Ok(Verdict::inconclusive(
                    Some(req.engine),
                    format!("could not execute {}: {e}", self.bin.display()),
                ))
            }
            Err(_) => {
                return Ok(Verdict::inconclusive(
                    Some(req.engine),
                    format!(
                        "timed out after {:?}; an unfinished check proves nothing",
                        req.timeout
                    ),
                ))
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        classify(
            req.engine,
            req.expected,
            &argv,
            output.status.code(),
            &stdout,
            &stderr,
        )
    }
}

/// Turn forge output into a verdict.
///
/// A compile error means nothing ran, and reporting `Refuted` there would
/// assert "we checked and it is fine" when in fact nothing was checked. An
/// unrecognised output shape is likewise `Inconclusive` rather than guessed at
/// — a parser that assumes "no failures mentioned means pass" would manufacture
/// a clean bill of health out of a tool crash.
pub fn classify(
    engine: CheckEngine,
    expected: ExpectedOutcome,
    command: &[String],
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> Result<Verdict, crate::AuditBotError> {
    let output = format!("{stdout}\n{stderr}");
    let truncated: String = output.chars().take(8000).collect();

    let passed = stdout.matches("[PASS").count();
    let failed = stdout.matches("[FAIL").count();

    if looks_like_compile_error(&output) {
        return Ok(Verdict {
            kind: VerdictKind::Inconclusive,
            engine: Some(engine),
            command: command.to_vec(),
            exit_code,
            output: truncated,
            reason: Some(
                "compilation failed, so no test executed and the check proves nothing".into(),
            ),
        });
    }

    if passed == 0 && failed == 0 {
        return Ok(Verdict {
            kind: VerdictKind::Inconclusive,
            engine: Some(engine),
            command: command.to_vec(),
            exit_code,
            output: truncated,
            reason: Some(
                "no [PASS] or [FAIL] markers found; the output shape was not recognised".into(),
            ),
        });
    }

    // A Foundry PoC encodes its claim as an assertion. `require` succeeding means
    // the claim held:
    //   - a PoC asserting exploitability that PASSES  => the bug is real
    //   - a control asserting safety that PASSES       => the claim is refuted
    //   - either one FAILING                           => the claim did not hold
    let claim_held = failed == 0;
    let kind = match (expected, claim_held) {
        (ExpectedOutcome::Exploitable, true) => VerdictKind::Confirmed,
        (ExpectedOutcome::Exploitable, false) => VerdictKind::Refuted,
        (ExpectedOutcome::Safe, true) => VerdictKind::Refuted,
        (ExpectedOutcome::Safe, false) => VerdictKind::Confirmed,
    };

    Ok(Verdict {
        kind,
        engine: Some(engine),
        command: command.to_vec(),
        exit_code,
        output: truncated,
        reason: None,
    })
}

fn looks_like_compile_error(output: &str) -> bool {
    output.contains("Compiler run failed")
        || output.contains("Compiler error")
        || output.contains("Error (")
        || output.contains("error[")
}

/// Expand a leading `~`.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

#[cfg(unix)]
fn is_executable(p: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &str) -> bool {
    Path::new(p).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd() -> Vec<String> {
        vec!["forge".into(), "test".into()]
    }

    #[test]
    fn passing_exploit_poc_confirms_the_vulnerability() {
        // A PoC that asserts exploitability and passes proves the bug exists.
        let out = "Ran 1 test\n[PASS] test_exploit() (gas: 100)\n";
        let v = classify(
            CheckEngine::Forge,
            ExpectedOutcome::Exploitable,
            &cmd(),
            Some(0),
            out,
            "",
        )
        .unwrap();
        assert_eq!(v.kind, VerdictKind::Confirmed);
        assert!(v.kind.gates_report());
    }

    #[test]
    fn failing_exploit_poc_refutes_rather_than_confirms() {
        // The trap: a FAILING test is not a reproduction. The claim in the PoC
        // did not hold, so the vulnerability is refuted.
        let out = "Ran 2 tests\n[FAIL: panic] test_exploit()\n[PASS] test_other()\n";
        let v = classify(
            CheckEngine::Forge,
            ExpectedOutcome::Exploitable,
            &cmd(),
            Some(1),
            out,
            "",
        )
        .unwrap();
        assert_eq!(v.kind, VerdictKind::Refuted);
    }

    #[test]
    fn passing_control_test_refutes_the_claim() {
        // The same `[PASS]` output means the opposite thing for a control.
        let out = "Ran 1 test\n[PASS] test_control() (gas: 100)\n";
        let v = classify(
            CheckEngine::Forge,
            ExpectedOutcome::Safe,
            &cmd(),
            Some(0),
            out,
            "",
        )
        .unwrap();
        assert_eq!(v.kind, VerdictKind::Refuted);
        assert!(
            !v.kind.gates_report(),
            "a safe control must not gate a report"
        );
        assert!(v.summary().contains("REFUTED"));
    }

    #[test]
    fn failing_control_test_confirms_a_broken_safety_claim() {
        let out = "Ran 1 test\n[FAIL: assertion] test_control()\n";
        let v = classify(
            CheckEngine::Forge,
            ExpectedOutcome::Safe,
            &cmd(),
            Some(1),
            out,
            "",
        )
        .unwrap();
        assert_eq!(v.kind, VerdictKind::Confirmed);
    }

    /// The failure mode this module exists to prevent: nothing ran, and the
    /// output was read as a clean result.
    #[test]
    fn compile_error_is_inconclusive_not_refuted() {
        let out = "Error (7576): Undeclared identifier.\n --> test/Foo.t.sol:5:77\n";
        let v = classify(
            CheckEngine::Forge,
            ExpectedOutcome::Exploitable,
            &cmd(),
            Some(1),
            out,
            "",
        )
        .unwrap();
        assert_eq!(v.kind, VerdictKind::Inconclusive);
        assert!(v.reason.is_some());
    }

    #[test]
    fn unrecognised_output_is_inconclusive() {
        let v = classify(
            CheckEngine::Forge,
            ExpectedOutcome::Exploitable,
            &cmd(),
            Some(0),
            "some surprise\n",
            "",
        )
        .unwrap();
        assert_eq!(v.kind, VerdictKind::Inconclusive);
        assert!(v.reason.unwrap().contains("not recognised"));
    }

    #[test]
    fn timeout_is_inconclusive() {
        let v = Verdict::inconclusive(Some(CheckEngine::Forge), "timed out");
        assert_eq!(v.kind, VerdictKind::Inconclusive);
        assert!(!v.kind.gates_report());
        assert!(v.summary().contains("no verdict"));
    }

    #[test]
    fn verdict_carries_the_command_so_it_can_be_re_run() {
        let v = classify(
            CheckEngine::Forge,
            ExpectedOutcome::Exploitable,
            &cmd(),
            Some(1),
            "[FAIL] x\n",
            "",
        )
        .unwrap();
        assert_eq!(v.command, vec!["forge", "test"]);
        assert_eq!(v.exit_code, Some(1));
        assert!(!v.output.is_empty(), "evidence must be attached");
    }

    #[test]
    fn forge_is_discoverable_without_being_on_path() {
        // Foundry lives in ~/.foundry/bin, which is not on PATH in a non-login
        // shell. If this fails, every verdict would be ToolMissing.
        if let Some(v) = Verifier::forge() {
            assert!(v.binary().exists(), "{} should exist", v.binary().display());
        } else {
            eprintln!("forge not found; static checks only");
        }
    }
}
