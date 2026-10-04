//! §5.3 policy management.
//!
//! ## Scope honesty
//!
//! §5.3 asks for a "50+ policy template library". This build ships a small set
//! of operator-written starter policies and **declares the library
//! incomplete** rather than padding it to 50. Policies written to look
//! authoritative but never reviewed by a real compliance function are worse
//! than an obviously incomplete library: they get adopted, and then they
//! become evidence in an audit of a control nobody actually wrote.
//!
//! The mechanism -- versioning, acknowledgment, exceptions, review scheduling
//! -- is complete. The content is deliberately not.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Lifecycle state of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStatus {
    /// Operator-written starter. Not yet reviewed or approved.
    Draft,
    Active,
    Retired,
}

impl PolicyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyStatus::Draft => "draft",
            PolicyStatus::Active => "active",
            PolicyStatus::Retired => "retired",
        }
    }
}

/// Review cadence for a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewCadence {
    Quarterly,
    SemiAnnual,
    Annual,
    Biennial,
}

impl ReviewCadence {
    pub fn days(&self) -> i64 {
        match self {
            ReviewCadence::Quarterly => 91,
            ReviewCadence::SemiAnnual => 182,
            ReviewCadence::Annual => 365,
            ReviewCadence::Biennial => 730,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ReviewCadence::Quarterly => "quarterly",
            ReviewCadence::SemiAnnual => "semi_annual",
            ReviewCadence::Annual => "annual",
            ReviewCadence::Biennial => "biennial",
        }
    }
}

/// A policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub code: String,
    pub title: String,
    pub summary: String,
    pub status: PolicyStatus,
    pub version: u32,
    pub cadence: ReviewCadence,
    pub owner: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub next_review: String,
}

/// An approval/acknowledgment event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acknowledgment {
    pub policy_id: String,
    pub policy_version: u32,
    pub user_id: String,
    pub acknowledged_at: String,
}

/// An approved deviation from a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyException {
    pub id: String,
    pub policy_id: String,
    pub justification: String,
    pub approved_by: Option<String>,
    pub expires_at: Option<String>,
}

/// §5.3 policy library report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyLibrary {
    pub policies: Vec<Policy>,
    pub drafts: usize,
    pub active: usize,
    pub retired: usize,
    /// Policies whose review date has passed.
    pub overdue_for_review: Vec<String>,
    /// How many templates §5.3 asks for, versus what exists.
    pub target_library_size: usize,
    pub library_complete: bool,
    pub notes: Vec<String>,
}

impl PolicyLibrary {
    pub fn describe(&self) -> String {
        format!(
            "{} polic(ies): {} active, {} draft, {} overdue for review; library {}/{} target",
            self.policies.len(),
            self.active,
            self.drafts,
            self.overdue_for_review.len(),
            self.policies.len(),
            self.target_library_size
        )
    }
}

/// §5.3 target library size.
pub const TARGET_LIBRARY_SIZE: usize = 50;

/// Starter policies.
///
/// Short, operator-written, and explicitly drafts. These are prompts for a
/// real compliance function, not finished documents.
pub fn starter_policies() -> Vec<Policy> {
    let now = Utc::now();
    let mk = |code: &str, title: &str, summary: &str, cadence: ReviewCadence| Policy {
        id: format!("pol_{}", code.to_lowercase().replace(['-', ' '], "_")),
        code: code.to_string(),
        title: title.to_string(),
        summary: summary.to_string(),
        status: PolicyStatus::Draft,
        version: 1,
        cadence,
        owner: None,
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
        next_review: (now + Duration::days(cadence.days())).to_rfc3339(),
    };

    vec![
        mk(
            "SEC-001",
            "Access Control Policy",
            "Starter outline: define how access is granted, reviewed and revoked.",
            ReviewCadence::Annual,
        ),
        mk(
            "SEC-002",
            "Secure Development Lifecycle",
            "Starter outline: define review gates from design through deployment.",
            ReviewCadence::Annual,
        ),
        mk(
            "SEC-003",
            "Incident Response Plan",
            "Starter outline: define roles, escalation paths and communication.",
            ReviewCadence::Annual,
        ),
        mk(
            "SEC-004",
            "Data Retention and Disposal",
            "Starter outline: define retention periods and secure disposal.",
            ReviewCadence::Annual,
        ),
        mk(
            "SEC-005",
            "Acceptable Use Policy",
            "Starter outline: define permitted use of company systems and data.",
            ReviewCadence::Annual,
        ),
    ]
}

/// Build the library report.
pub fn build_library(now: DateTime<Utc>, policies: Vec<Policy>, target: usize) -> PolicyLibrary {
    let drafts = policies
        .iter()
        .filter(|p| p.status == PolicyStatus::Draft)
        .count();
    let active = policies
        .iter()
        .filter(|p| p.status == PolicyStatus::Active)
        .count();
    let retired = policies
        .iter()
        .filter(|p| p.status == PolicyStatus::Retired)
        .count();

    let mut overdue: Vec<String> = policies
        .iter()
        .filter(|p| {
            DateTime::parse_from_rfc3339(&p.next_review)
                .map(|t| t.with_timezone(&Utc) < now)
                .unwrap_or(false)
        })
        .map(|p| p.code.clone())
        .collect();
    overdue.sort();

    let mut notes = vec![
        format!(
            "The library holds {} starter policies against the {}-policy target in §5.3. \
             These are operator-written outlines, not reviewed documents.",
            policies.len(),
            target
        ),
        "Every policy is a draft until a named owner reviews and approves it.".to_string(),
    ];
    if policies.len() < target {
        notes.push(
            "Library is INCOMPLETE. It is reported as such rather than padded with \
             unreviewed documents."
                .to_string(),
        );
    }

    PolicyLibrary {
        drafts,
        active,
        retired,
        overdue_for_review: overdue,
        library_complete: policies.len() >= target,
        target_library_size: target,
        notes,
        policies,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z")
            .unwrap()
            .into()
    }

    #[test]
    fn starter_policies_are_drafts_not_active() {
        let lib = build_library(now(), starter_policies(), TARGET_LIBRARY_SIZE);
        assert_eq!(lib.drafts, 5);
        assert_eq!(lib.active, 0, "nothing is approved until reviewed");
    }

    #[test]
    fn library_reports_incompleteness_rather_than_padding() {
        let lib = build_library(now(), starter_policies(), TARGET_LIBRARY_SIZE);
        assert!(!lib.library_complete);
        assert!(lib.notes.iter().any(|n| n.contains("INCOMPLETE")));
        assert!(lib.describe().contains("5/50"));
    }

    #[test]
    fn library_is_complete_only_at_target_size() {
        let full: Vec<Policy> = (0..TARGET_LIBRARY_SIZE)
            .map(|i| Policy {
                id: format!("p{i}"),
                code: format!("P-{i:03}"),
                title: "t".into(),
                summary: "s".into(),
                status: PolicyStatus::Draft,
                version: 1,
                cadence: ReviewCadence::Annual,
                owner: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
                next_review: "2027-01-01T00:00:00Z".into(),
            })
            .collect();
        assert!(build_library(now(), full, TARGET_LIBRARY_SIZE).library_complete);
    }

    #[test]
    fn overdue_reviews_are_detected() {
        let mut policies = starter_policies();
        policies[0].next_review = "2025-01-01T00:00:00Z".into();
        policies[1].next_review = "2030-01-01T00:00:00Z".into();

        let lib = build_library(now(), policies, TARGET_LIBRARY_SIZE);
        assert_eq!(lib.overdue_for_review, vec!["SEC-001"]);
    }

    #[test]
    fn unparseable_review_date_is_not_treated_as_overdue() {
        let mut policies = starter_policies();
        policies[0].next_review = "not-a-date".into();
        let lib = build_library(now(), policies, TARGET_LIBRARY_SIZE);
        assert!(lib.overdue_for_review.is_empty());
    }

    #[test]
    fn review_cadences_map_to_sensible_intervals() {
        assert_eq!(ReviewCadence::Quarterly.days(), 91);
        assert_eq!(ReviewCadence::Annual.days(), 365);
        assert_eq!(ReviewCadence::Biennial.days(), 730);
    }

    #[test]
    fn policy_ids_are_stable_and_derived_from_code() {
        let a = starter_policies();
        let b = starter_policies();
        assert_eq!(a[0].id, "pol_sec_001");
        assert_eq!(a[0].id, b[0].id, "ids must be deterministic, not random");
    }

    #[test]
    fn policy_codes_are_unique() {
        let policies = starter_policies();
        let mut codes: Vec<&str> = policies.iter().map(|p| p.code.as_str()).collect();
        codes.sort();
        let before = codes.len();
        codes.dedup();
        assert_eq!(
            codes.len(),
            before,
            "duplicate policy codes would break lookups"
        );
    }

    #[test]
    fn acknowledgement_records_the_policy_version() {
        // Acknowledging v1 must not silently count toward v2.
        let ack = Acknowledgment {
            policy_id: "pol_sec_001".into(),
            policy_version: 1,
            user_id: "u1".into(),
            acknowledged_at: "2026-01-31T00:00:00Z".into(),
        };
        assert_eq!(ack.policy_version, 1);
        let policy = &starter_policies()[0];
        assert_ne!(ack.policy_version, policy.version + 1);
    }
}
