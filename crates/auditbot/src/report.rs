//! Rendering a report from evidence.
//!
//! A report is a *rendering* of a confirmed verdict, never a premise for one.
//! [`FindingReport::from_verdict`] returns `None` for anything that is not
//! [`crate::verify::VerdictKind::Confirmed`], so there is no code path that
//! produces a confident writeup from a check that did not reproduce.
//!
//! # What the report deliberately does not assert
//!
//! Novelty is not asserted — [`crate::dedupe`] only establishes "not obviously
//! already reported". Severity is not asserted. Impact describes what the PoC
//! demonstrated, not what an attacker could achieve in production, because that
//! extrapolation is where overclaiming starts.

use serde::{Deserialize, Serialize};

use crate::dedupe::DedupeOutcome;
use crate::evidence::Evidence;
use crate::verify::{Verdict, VerdictKind};

/// The sections a report carries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportSections {
    pub executive_summary: String,
    pub vulnerability_detail: String,
    pub impact: String,
    pub mitigation: String,
    pub steps_to_reproduce: Vec<String>,
    pub proof_of_concept: String,
}

/// A report, with everything needed to challenge it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingReport {
    pub target: crate::HuntTarget,
    pub sections: ReportSections,
    pub evidence: Vec<Evidence>,
    /// The verdict that gated this report, so a reviewer can re-run it.
    pub verdict: Verdict,
    pub dedupe: DedupeOutcome,
    /// Always populated. Carries the novelty situation explicitly.
    pub novelty_caveat: Option<String>,
}

impl FindingReport {
    /// Build a report, or decline.
    ///
    /// Returns `None` when the verdict did not confirm. This is the single gate
    /// that keeps "triage flagged something interesting" from becoming "we found
    /// a vulnerability".
    pub fn from_verdict(
        target: crate::HuntTarget,
        verdict: &Verdict,
        evidence: Vec<Evidence>,
        dedupe: DedupeOutcome,
    ) -> Option<Self> {
        if verdict.kind != VerdictKind::Confirmed {
            return None;
        }

        let novelty_clears = dedupe.verdict.clears_for_reporting();
        let novelty_caveat = if novelty_clears {
            Some(
                "Novelty is NOT established. The target did not overlap the audit \
                 references available for this program, which is weaker than proving \
                 it unreported. An analyst must confirm against the full audit texts \
                 and the program's disclosure policy before submission."
                    .to_string(),
            )
        } else {
            Some(
                "This target overlaps a published audit reference, so it is NOT novel. \
                 Do not submit."
                    .to_string(),
            )
        };

        let exec = format!(
            "A check against {} reproduced at {}:{}. The reproduction is recorded below \
             with the command and its output. Severity, novelty and real-world impact \
             are NOT established by this report and require analyst review.",
            target.function,
            target.file,
            target
                .line
                .map(|l| l.to_string())
                .unwrap_or_else(|| "unknown line".into())
        );

        let detail = format!(
            "ChainScope ranked this function (score {}) for reasons: {}. A {} check \
             reproduced the condition. The evidence below is the source the check ran \
             against.",
            target
                .score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unscored".into()),
            if target.reasons.is_empty() {
                "none recorded".to_string()
            } else {
                target.reasons.join(", ")
            },
            verdict.engine.map(|e| e.binary()).unwrap_or("external")
        );

        let steps = vec![
            format!("Obtain the source: {}", target.file),
            "Apply the proof of concept in the section below.".to_string(),
            format!("Run: {}", verdict.command.join(" ")),
            format!(
                "Observed outcome: {} (exit code {:?}).",
                verdict.kind.as_str(),
                verdict.exit_code
            ),
        ];

        Some(Self {
            target,
            sections: ReportSections {
                executive_summary: exec,
                vulnerability_detail: detail,
                impact: "What the reproduction demonstrated, and nothing more. Real-world \
                          impact depends on reachability, privilege and the program's own \
                          severity definitions, none of which this report evaluates. Do not \
                          read this as a severity rating."
                    .to_string(),
                mitigation: "Not assessed. Mitigation depends on the specific defect and the \
                              protocol's design; proposing one without understanding the root \
                              cause would be guesswork."
                    .to_string(),
                steps_to_reproduce: steps,
                proof_of_concept: verdict.output.clone(),
            },
            evidence,
            verdict: verdict.clone(),
            dedupe,
            novelty_caveat,
        })
    }

    /// Render as Markdown for a human to read.
    pub fn to_markdown(&self) -> String {
        let s = &self.sections;
        let mut out = String::new();
        out.push_str(&format!("# Audit finding: {}\n\n", self.target.function));
        out.push_str(&format!("**Program:** {}\n\n", self.target.program));
        out.push_str("## Executive summary\n\n");
        out.push_str(&s.executive_summary);
        out.push_str("\n\n## Vulnerability detail\n\n");
        out.push_str(&s.vulnerability_detail);
        out.push_str("\n\n## Impact\n\n");
        out.push_str(&s.impact);
        out.push_str("\n\n## Mitigation\n\n");
        out.push_str(&s.mitigation);
        out.push_str("\n\n## Steps to reproduce\n\n");
        for (i, step) in s.steps_to_reproduce.iter().enumerate() {
            out.push_str(&format!("{}. {step}\n", i + 1));
        }
        out.push_str("\n## Proof of concept (verbatim tool output)\n\n```\n");
        out.push_str(&s.proof_of_concept);
        out.push_str("\n```\n\n## Evidence\n\n");
        for e in &self.evidence {
            out.push_str(&format!("- [{}] {}\n", e.kind.as_str(), e.cite()));
        }
        if let Some(c) = &self.novelty_caveat {
            out.push_str(&format!("\n> **Novelty caveat.** {c}\n"));
        }
        out.push_str(
            "\n---\n\nNot for automated submission. A human analyst must review this \
             against the program's rules before it is sent anywhere.\n",
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{CheckEngine, VerdictKind};

    fn confirmed() -> Verdict {
        Verdict {
            kind: VerdictKind::Confirmed,
            engine: Some(CheckEngine::Forge),
            command: vec!["forge".into(), "test".into()],
            exit_code: Some(1),
            output: "[FAIL: panic] test_exploit()".into(),
            reason: None,
        }
    }

    fn target() -> crate::HuntTarget {
        crate::HuntTarget::new("layerzero", "withdraw", "src/Vault.sol")
    }

    fn clear_dedupe() -> DedupeOutcome {
        DedupeOutcome {
            verdict: crate::dedupe::DedupeVerdict::NoKnownOverlap,
            considered: vec!["halborn".into()],
        }
    }

    #[test]
    fn a_confirmed_verdict_produces_a_report_with_every_section() {
        let r = FindingReport::from_verdict(target(), &confirmed(), vec![], clear_dedupe())
            .expect("confirmed verdict must produce a report");
        let s = &r.sections;
        assert!(!s.executive_summary.is_empty());
        assert!(!s.vulnerability_detail.is_empty());
        assert!(!s.impact.is_empty());
        assert!(!s.mitigation.is_empty());
        assert_eq!(s.steps_to_reproduce.len(), 4);
        assert!(s.proof_of_concept.contains("FAIL"));
    }

    /// The gate. A refuted check must not yield a writeup.
    #[test]
    fn a_refuted_verdict_produces_no_report() {
        let v = Verdict {
            kind: VerdictKind::Refuted,
            ..confirmed()
        };
        assert!(FindingReport::from_verdict(target(), &v, vec![], clear_dedupe()).is_none());
    }

    #[test]
    fn an_inconclusive_verdict_produces_no_report() {
        let v = Verdict {
            kind: VerdictKind::Inconclusive,
            reason: Some("compile error".into()),
            ..confirmed()
        };
        assert!(FindingReport::from_verdict(target(), &v, vec![], clear_dedupe()).is_none());
    }

    #[test]
    fn novelty_is_never_asserted_even_when_dedupe_clears() {
        let r = FindingReport::from_verdict(target(), &confirmed(), vec![], clear_dedupe())
            .expect("report");
        let caveat = r.novelty_caveat.expect("a caveat is always present");
        assert!(caveat.contains("NOT established"), "{caveat}");
    }

    #[test]
    fn known_overlap_says_do_not_submit() {
        let dedupe = DedupeOutcome {
            verdict: crate::dedupe::DedupeVerdict::KnownOverlap {
                audit: "halborn".into(),
                matched_on: vec!["vault".into()],
            },
            considered: vec!["halborn".into()],
        };
        let r =
            FindingReport::from_verdict(target(), &confirmed(), vec![], dedupe).expect("report");
        assert!(r.novelty_caveat.unwrap().contains("Do not submit"));
    }

    #[test]
    fn markdown_refuses_to_look_submittable() {
        let r = FindingReport::from_verdict(target(), &confirmed(), vec![], clear_dedupe())
            .expect("report");
        let md = r.to_markdown();
        assert!(md.contains("Not for automated submission"));
        assert!(
            md.contains("do not read this as a severity rating")
                || md.contains("Do not read this as a severity rating")
        );
    }
}
