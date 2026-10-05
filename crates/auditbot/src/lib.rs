//! Bounty audit bot.
//!
//! Triage -> verify -> report. The middle step is deliberately not optional:
//! a report is *rendered from* a verification result, never written alongside
//! one and justified afterwards.
//!
//! # Why the ordering matters
//!
//! Bounty triage is a funnel with hostile economics. A large program has
//! hundreds of contracts and a published audit list, so most of what any
//! scanner surfaces is already known. A bot that drafts a confident writeup
//! first and hunts for a PoC afterwards will manufacture plausible reports for
//! things that are duplicates, or not vulnerabilities at all — and a junk report
//! is how an account gets flagged from serious programs.
//!
//! So this crate cannot emit a [`report::FindingReport`] without a
//! [`verify::Verdict`] of [`verify::VerdictKind::Confirmed`], and that verdict
//! carries the command that produced it plus the output that was observed.
//!
//! # What this crate will not do
//!
//! It does not submit. Nothing here transmits to a bug bounty program. A
//! false positive stops at this process; the moment a bot can publish a
//! claim unattended, a false positive becomes a public accusation against a
//! named project. Submission stays a human action.
//!
//! It also does not adjudicate. [`verify::VerdictKind::Confirmed`] means "the
//! check fired", not "this is a novel vulnerability". Novelty requires
//! [`dedupe`] against the program's published audits, and the final call is
//! always the analyst's.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod dedupe;
pub mod evidence;
pub mod pipeline;
pub mod report;
pub mod verify;

pub use dedupe::{DedupeOutcome, DedupeVerdict};
pub use evidence::{Evidence, EvidenceKind, SnapshotRequest};
pub use pipeline::{AuditRun, GatedAudit, PipelineError, StepOutcome};
pub use report::{FindingReport, ReportSections};
pub use verify::{Verdict, VerdictKind, VerificationRequest, Verifier};

#[derive(Debug, Error)]
pub enum AuditBotError {
    #[error("evidence could not be captured: {0}")]
    Evidence(String),

    #[error("verification could not be run: {0}")]
    Verification(String),

    #[error("the external tool is unavailable: {0}")]
    ToolUnavailable(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A single triage target: one hotspot in one program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HuntTarget {
    /// Immunefi program slug, e.g. "layerzero".
    pub program: String,
    /// The contract function ChainScope flagged.
    pub function: String,
    /// Repository-relative source path.
    pub file: String,
    pub line: Option<u64>,
    /// ChainScope's ranking score. A ranking hint, never a severity.
    pub score: Option<f64>,
    /// Why ChainScope flagged it.
    pub reasons: Vec<String>,
}

impl HuntTarget {
    pub fn new(program: &str, function: &str, file: &str) -> Self {
        Self {
            program: program.to_string(),
            function: function.to_string(),
            file: file.to_string(),
            line: None,
            score: None,
            reasons: Vec::new(),
        }
    }

    /// Stable identifier for correlating evidence, verdicts and reports.
    pub fn id(&self) -> String {
        format!("{}:{}:{}", self.program, self.file, self.function)
    }
}

/// Build a [`HuntTarget`] from a triage report's hotspot.
pub fn target_from_hotspot(program: &str, h: &bounty::Hotspot) -> Option<HuntTarget> {
    Some(HuntTarget {
        program: program.to_string(),
        function: h.function.clone()?,
        file: h.file.clone()?,
        line: h.line,
        score: h.score,
        reasons: h.reasons.clone(),
    })
}
