//! Novelty checking against a program's published audits.
//!
//! This is the difference between a finding and a re-report. Immunefi programs
//! routinely publish audit reports from firms like Halborn or Trail of Bits;
//! finding one of those again earns nothing and costs credibility. ChainScope
//! already hands over `audit_refs` per program, so the check is cheap.
//!
//! **What this can and cannot do.** It matches identifiers an auditor would
//! recognise — the function name, the file, the contract — against the text of
//! each reference. ChainScope supplies `audit_refs` as URLs, so this is a cheap
//! screen over reference titles, not a reading of the audit PDFs. A
//! [`DedupeVerdict::NoKnownOverlap`] therefore means "not obviously already
//! reported", never "provably novel", and the report layer attaches that caveat
//! to every report it renders. Only an analyst can close the question.

use serde::{Deserialize, Serialize};

/// Shorter identifiers match everywhere ("own", "get") and would flag every
/// target as a duplicate, so they are not evidence of anything.
const MIN_TOKEN_LEN: usize = 5;

/// Why a target was or was not considered novel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupeVerdict {
    /// No overlap found with any published audit. Not a novelty proof.
    NoKnownOverlap,
    /// The target overlaps a published disclosure. Do not report.
    KnownOverlap {
        audit: String,
        matched_on: Vec<String>,
    },
    /// Overlap could not be assessed. Treat as "unknown", not "novel".
    Unassessable { reason: String },
}

impl DedupeVerdict {
    /// Only an explicit lack of overlap may proceed. `Unassessable` must not
    /// silently read as novelty.
    pub fn clears_for_reporting(&self) -> bool {
        matches!(self, DedupeVerdict::NoKnownOverlap)
    }
}

/// The dedupe result plus what it was based on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupeOutcome {
    pub verdict: DedupeVerdict,
    /// Audits considered. Recorded so a reviewer can see the search was real.
    pub considered: Vec<String>,
}

/// Check a target against a program's published audit references.
///
/// `audit_refs` comes from `bounty::BountyMeta`. When it is empty the program
/// publishes no audit index we can see, and claiming novelty from that would be
/// exactly the unwarranted certainty this crate exists to avoid.
pub fn check(target: &crate::HuntTarget, audit_refs: &[String]) -> DedupeOutcome {
    if audit_refs.is_empty() {
        return DedupeOutcome {
            verdict: DedupeVerdict::Unassessable {
                reason: "no published audit references were available for this program, \
                         so novelty cannot be assessed from the audit list"
                    .into(),
            },
            considered: Vec::new(),
        };
    }

    // Search the audit references for the target's identifiers -- not the other
    // way round. Comparing the target against its own text would report an
    // overlap for every single target, which is worse than not checking.
    let audit_text = audit_refs.join(" ").to_lowercase();
    let matched: Vec<String> = identifiers(target)
        .into_iter()
        .filter(|t| t.chars().count() >= MIN_TOKEN_LEN && audit_text.contains(t))
        .collect();

    if matched.is_empty() {
        DedupeOutcome {
            verdict: DedupeVerdict::NoKnownOverlap,
            considered: audit_refs.to_vec(),
        }
    } else {
        let mut matched = matched;
        matched.sort();
        matched.dedup();
        let audit = audit_refs
            .iter()
            .find(|a| matched.iter().any(|m| a.to_lowercase().contains(m)))
            .cloned()
            .unwrap_or_else(|| audit_refs[0].clone());
        DedupeOutcome {
            verdict: DedupeVerdict::KnownOverlap {
                audit,
                matched_on: matched,
            },
            considered: audit_refs.to_vec(),
        }
    }
}

/// Tokens worth matching on: the file, the function, and reason flags.
fn identifiers(target: &crate::HuntTarget) -> Vec<String> {
    let mut out = vec![target.function.to_lowercase()];
    if let Some(stem) = target.file.rsplit('/').next() {
        out.push(stem.trim_end_matches(".sol").to_lowercase());
        // The contract name, for `contract Ownable is ...`.
        if let Some((_, rest)) = stem.split_once('.') {
            out.push(rest.to_lowercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs() -> Vec<String> {
        vec!["https://halborn.com/audits/layerzero".into()]
    }

    #[test]
    fn empty_audit_list_is_unassessable_not_novel() {
        let t = crate::HuntTarget::new("layerzero", "withdraw", "src/Vault.sol");
        let out = check(&t, &[]);
        assert!(
            !out.verdict.clears_for_reporting(),
            "an absent audit list must not read as novelty"
        );
        assert!(matches!(out.verdict, DedupeVerdict::Unassessable { .. }));
    }

    /// ChainScope's `audit_refs` are URLs, so a match only happens when the
    /// identifier appears in the URL or title. That makes this check a cheap
    /// screen, not a novelty proof — which is why `NoKnownOverlap` never
    /// licenses a claim of novelty on its own.
    #[test]
    fn an_identifier_in_the_audit_reference_is_flagged_as_known_overlap() {
        let t = crate::HuntTarget::new("layerzero", "withdraw", "src/Vault.sol");
        let out = check(
            &t,
            &["https://halborn.com/audits/vault-withdrawal".to_string()],
        );
        assert!(!out.verdict.clears_for_reporting());
        match out.verdict {
            DedupeVerdict::KnownOverlap { audit, matched_on } => {
                assert!(audit.contains("halborn"));
                assert!(matched_on.iter().any(|m| m == "withdraw"), "{matched_on:?}");
            }
            other => panic!("expected KnownOverlap, got {other:?}"),
        }
    }

    #[test]
    fn unrelated_target_proceeds_but_records_what_was_searched() {
        let t = crate::HuntTarget::new("layerzero", "withdraw", "src/UnrelatedVault.sol");
        let out = check(&t, &refs());
        assert_eq!(out.verdict, DedupeVerdict::NoKnownOverlap);
        assert_eq!(out.considered.len(), 1, "the search must be auditable");
    }

    #[test]
    fn short_tokens_are_ignored_to_avoid_noise() {
        // "own" appears everywhere; matching on it would flag every target.
        let t = crate::HuntTarget::new("layerzero", "own", "src/Thing.sol");
        assert_eq!(check(&t, &refs()).verdict, DedupeVerdict::NoKnownOverlap);
    }
}
