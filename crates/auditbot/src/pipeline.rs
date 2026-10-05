//! The gated pipeline: triage -> evidence -> verify -> dedupe -> report.
//!
//! # Where the gate binds
//!
//! Verification runs `forge`, which is process execution — a privileged
//! capability. Every run checks [`agent::Capability::ExecuteProcess`] first.
//! This is why the pipeline routes through [`agent::Gate`]: a read-only
//! operator gets a refusal, not a verdict.
//!
//! # The distinction that matters here
//!
//! A *refusal* is not a *result*. When the gate denies, or Foundry is missing,
//! this module returns a [`StepOutcome::Blocked`] naming what stopped it. It
//! does not return an empty report, and it does not return `Refuted` — because
//! "we were not allowed to check" and "we checked and it is fine" are different
//! claims, and conflating them is how an audit bot ends up certifying code it
//! never looked at.
//!
//! Nothing here submits anything. A [`report::FindingReport`] is a document for
//! a human to review, and the run stops there.

use agent::{Capability, Gate};
use thiserror::Error;

use crate::dedupe::{self, DedupeOutcome};
use crate::evidence::{self, Evidence, SnapshotRequest};
use crate::report::FindingReport;
use crate::verify::{Verdict, VerdictKind, VerificationRequest, Verifier};

/// What happened to one step of the pipeline.
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    /// The step completed and produced something.
    Done,
    /// The step could not run. `reason` says what stopped it, so a blockage is
    /// never mistaken for a negative result.
    Blocked { reason: String },
}

impl StepOutcome {
    pub fn is_blocked(&self) -> bool {
        matches!(self, StepOutcome::Blocked { .. })
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            StepOutcome::Blocked { reason } => Some(reason),
            StepOutcome::Done => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("the {capability} capability was refused: {reason}")]
    Refused {
        capability: &'static str,
        reason: String,
    },
    #[error("evidence capture failed: {0}")]
    Evidence(#[from] evidence::SnapshotError),
    #[error("verification failed to run: {0}")]
    Verification(#[from] crate::AuditBotError),
}

/// The outcome of a full run. Every field is present whether or not the run
/// succeeded, because a report that omits its own failures is the problem this
/// crate exists to avoid.
#[derive(Debug, Clone)]
pub struct AuditRun {
    pub target: crate::HuntTarget,
    pub evidence: Vec<Evidence>,
    pub verdict: Option<Verdict>,
    pub dedupe: Option<DedupeOutcome>,
    pub report: Option<FindingReport>,
    /// Which steps ran, and what blocked the ones that did not.
    pub steps: Vec<(&'static str, StepOutcome)>,
}

impl AuditRun {
    /// True when a report was produced. Only a confirmed verdict can set this.
    pub fn has_report(&self) -> bool {
        self.report.is_some()
    }

    /// The names of every step that did not run.
    pub fn blocked_steps(&self) -> Vec<&'static str> {
        self.steps
            .iter()
            .filter(|(_, o)| o.is_blocked())
            .map(|(name, _)| *name)
            .collect()
    }

    /// A one-line human summary. Names the blockage instead of implying success.
    pub fn summary(&self) -> String {
        if let Some(r) = &self.report {
            return format!(
                "REPORT DRAFTED for {} (verdict {}) — requires human review before any use.",
                self.target.function,
                r.verdict.kind.as_str()
            );
        }
        let blocked = self.blocked_steps();
        if blocked.is_empty() {
            return format!(
                "No report for {}: the check ran and did not confirm.",
                self.target.function
            );
        }
        format!(
            "No report for {}: blocked at [{}]. Nothing was verified.",
            self.target.function,
            blocked.join(", ")
        )
    }
}

/// Runs the pipeline under a capability gate.
pub struct GatedAudit {
    gate: Gate,
}

impl GatedAudit {
    pub fn new(gate: Gate) -> Self {
        Self { gate }
    }

    /// Would verification be permitted? Lets a UI show the state up front
    /// rather than after a refusal.
    pub fn can_verify(&self) -> bool {
        self.gate.check(Capability::ExecuteProcess).allowed()
    }

    /// Run the pipeline for one target.
    ///
    /// `project_dir` is the Foundry project the PoC lives in; `audit_refs` are
    /// the program's published audit references.
    pub async fn run(
        &self,
        target: crate::HuntTarget,
        project_dir: std::path::PathBuf,
        audit_refs: &[String],
    ) -> Result<AuditRun, PipelineError> {
        let mut steps: Vec<(&'static str, StepOutcome)> = Vec::new();

        // 1. Evidence. Reading source is not privileged, so it needs no grant.
        let evidence =
            evidence::capture(&SnapshotRequest::new(target.clone(), project_dir.clone()))?;
        steps.push(("evidence", StepOutcome::Done));

        // 2. Verification. This executes a process, so it is gated.
        if let agent::Decision::Deny(reason) = self.gate.check(Capability::ExecuteProcess) {
            steps.push((
                "verify",
                StepOutcome::Blocked {
                    reason: format!("process execution refused by policy: {reason}"),
                },
            ));
            return Ok(AuditRun {
                target,
                evidence,
                verdict: None,
                dedupe: None,
                report: None,
                steps,
            });
        }

        let verdict = match Verifier::forge() {
            Some(v) => {
                v.run(&VerificationRequest::forge_exploit(&project_dir))
                    .await?
            }
            None => {
                // Tool absent. Explicitly not a verdict about the code.
                steps.push((
                    "verify",
                    StepOutcome::Blocked {
                        reason: "Foundry is not installed, so no check was run; \
                                 nothing is known about this target"
                            .into(),
                    },
                ));
                return Ok(AuditRun {
                    target,
                    evidence,
                    verdict: None,
                    dedupe: None,
                    report: None,
                    steps,
                });
            }
        };
        steps.push(("verify", StepOutcome::Done));

        // 3. Dedupe, before any drafting.
        let d = dedupe::check(&target, audit_refs);

        // 4. Report. `from_verdict` is itself the gate: only a confirmed
        //    verdict yields a document.
        let report =
            FindingReport::from_verdict(target.clone(), &verdict, evidence.clone(), d.clone());

        steps.push((
            "report",
            if report.is_some() {
                StepOutcome::Done
            } else {
                StepOutcome::Blocked {
                    reason: format!(
                        "verdict was {}, so no report was drafted",
                        verdict.kind.as_str()
                    ),
                }
            },
        ));

        Ok(AuditRun {
            target,
            evidence,
            verdict: Some(verdict),
            dedupe: Some(d),
            report,
            steps,
        })
    }
}

/// True when a verdict may be treated as a finding.
pub fn is_reportable(v: &Verdict) -> bool {
    v.kind == VerdictKind::Confirmed
}
