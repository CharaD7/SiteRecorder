//! §5.4 vendor risk management.
//!
//! ## What this measures, and what it refuses to compute
//!
//! A vendor's tier follows from two facts the operator supplies: what data they
//! hold, and how critical that data is. Score follows from the answers to the
//! recorded questionnaire. Both are inputs, not discoveries -- this tool cannot
//! observe a vendor's controls, and it does not pretend to.
//!
//! Consequently there is no "vendor security score" derived from outside
//! evidence, no breach-notification monitoring, and no continuous rating feed.
//! Those are stated as unavailable rather than approximated.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Risk tier, ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Low,
    Medium,
    High,
    Critical,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Low => "low",
            Tier::Medium => "medium",
            Tier::High => "high",
            Tier::Critical => "critical",
        }
    }

    /// Business-criticality weight, summed with data access to derive a tier.
    pub fn weight(&self) -> f64 {
        match self {
            Tier::Low => 1.0,
            Tier::Medium => 2.0,
            Tier::High => 3.0,
            Tier::Critical => 4.0,
        }
    }

    pub fn from_str(s: &str) -> Option<Tier> {
        match s {
            "low" => Some(Tier::Low),
            "medium" => Some(Tier::Medium),
            "high" => Some(Tier::High),
            "critical" => Some(Tier::Critical),
            _ => None,
        }
    }
}

/// What data the vendor holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataAccess {
    None,
    Internal,
    Confidential,
    Regulated,
}

impl DataAccess {
    pub fn as_str(&self) -> &'static str {
        match self {
            DataAccess::None => "none",
            DataAccess::Internal => "internal",
            DataAccess::Confidential => "confidential",
            DataAccess::Regulated => "regulated",
        }
    }

    pub fn from_str(s: &str) -> Option<DataAccess> {
        match s {
            "none" => Some(DataAccess::None),
            "internal" => Some(DataAccess::Internal),
            "confidential" => Some(DataAccess::Confidential),
            "regulated" => Some(DataAccess::Regulated),
            _ => None,
        }
    }

    pub fn weight(&self) -> f64 {
        match self {
            DataAccess::None => 0.0,
            DataAccess::Internal => 2.0,
            DataAccess::Confidential => 4.0,
            DataAccess::Regulated => 6.0,
        }
    }
}

/// Assessment lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    NotStarted,
    UnderReview,
    Complete,
    Expired,
}

impl AssessmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssessmentStatus::NotStarted => "not_started",
            AssessmentStatus::UnderReview => "under_review",
            AssessmentStatus::Complete => "complete",
            AssessmentStatus::Expired => "expired",
        }
    }
}

/// A vendor record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vendor {
    pub id: String,
    pub name: String,
    pub category: String,
    pub data_access: DataAccess,
    pub criticality: Tier,
    pub status: AssessmentStatus,
    pub owner: Option<String>,
    /// Questionnaire key -> answer. Answers are operator-recorded.
    pub questionnaire: BTreeMap<String, String>,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Vendor {
    /// Derive tier from data access and business criticality.
    ///
    /// Both are operator inputs. Neither is discovered by this tool, which is
    /// why the result is labelled as derived rather than measured.
    pub fn derive_tier(&self) -> Tier {
        match self.data_access.weight() + self.criticality.weight() {
            x if x >= 9.0 => Tier::Critical,
            x if x >= 6.0 => Tier::High,
            x if x >= 3.0 => Tier::Medium,
            _ => Tier::Low,
        }
    }

    /// Fraction of questionnaire questions answered, 0.0-1.0.
    pub fn questionnaire_coverage(&self) -> f64 {
        const TOTAL: f64 = 8.0;
        if TOTAL == 0.0 {
            return 0.0;
        }
        (self.questionnaire.len() as f64 / TOTAL).min(1.0)
    }
}

/// Questions this build asks. Operator-written, not a licensed SIG/CAIQ copy.
pub fn questionnaire() -> Vec<String> {
    vec![
        "data_encryption_at_rest".into(),
        "data_encryption_in_transit".into(),
        "access_control_mfa".into(),
        "incident_response_plan".into(),
        "subprocessor_disclosure".into(),
        "breach_notification_terms".into(),
        "penetration_test_evidence".into(),
        "right_to_audit".into(),
    ]
}

/// §5.4 register report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorRegister {
    pub vendors: Vec<Vendor>,
    pub by_tier: BTreeMap<String, i64>,
    /// Vendors with an incomplete or expired assessment.
    pub needs_attention: Vec<String>,
    pub questionnaire_size: usize,
    pub notes: Vec<String>,
}

impl VendorRegister {
    pub fn describe(&self) -> String {
        format!(
            "{} vendor(s): {} critical, {} needing attention",
            self.vendors.len(),
            self.by_tier.get("critical").copied().unwrap_or(0),
            self.needs_attention.len()
        )
    }
}

/// Build the register.
pub fn build_register(vendors: Vec<Vendor>) -> VendorRegister {
    let questions = questionnaire();

    let mut by_tier: BTreeMap<String, i64> = BTreeMap::new();
    let mut needs_attention: Vec<String> = Vec::new();

    for v in &vendors {
        let tier = v.derive_tier();
        *by_tier.entry(tier.as_str().to_string()).or_insert(0) += 1;

        // Incomplete or lapsed assessment is what actually needs action.
        if v.status != AssessmentStatus::Complete || v.questionnaire_coverage() < 1.0 {
            needs_attention.push(v.name.clone());
        }
    }
    needs_attention.sort();

    VendorRegister {
        vendors,
        by_tier,
        needs_attention,
        questionnaire_size: questions.len(),
        notes: vec![
            "Tiers are derived from operator-supplied data access and business \
             criticality. This tool does not observe a vendor's controls."
                .to_string(),
            "SIG and CAIQ are licensed questionnaires; only operator-written \
             questions are included here."
                .to_string(),
        ],
    }
}

/// Models this build will not fabricate.
pub fn unavailable_capabilities() -> Vec<(String, String)> {
    vec![
        (
            "Continuous security rating".into(),
            "Requires a paid third-party feed. No rating data is ingested.".into(),
        ),
        (
            "Breach-notification monitoring".into(),
            "Requires a breach-intelligence subscription and a matching entity \
             resolution step."
                .into(),
        ),
        (
            "Contractual control enforcement".into(),
            "Requires contract text. This tool cannot read or verify a contract.".into(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vendor(name: &str, access: DataAccess, crit: Tier, answered: usize) -> Vendor {
        let mut q = BTreeMap::new();
        for k in questionnaire().into_iter().take(answered) {
            q.insert(k, "yes".to_string());
        }
        Vendor {
            id: format!("v_{name}"),
            name: name.to_string(),
            category: "saas".into(),
            data_access: access,
            criticality: crit,
            status: AssessmentStatus::Complete,
            owner: None,
            questionnaire: q,
            notes: String::new(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn regulated_data_and_critical_business_is_critical_tier() {
        let v = vendor("Acme", DataAccess::Regulated, Tier::Critical, 8);
        assert_eq!(v.derive_tier(), Tier::Critical);
    }

    #[test]
    fn no_data_and_low_criticality_is_low_tier() {
        let v = vendor("Cafe", DataAccess::None, Tier::Low, 8);
        assert_eq!(v.derive_tier(), Tier::Low);
    }

    #[test]
    fn data_access_alone_can_escalate_tier() {
        let v = vendor("Payroll", DataAccess::Regulated, Tier::Low, 8);
        assert!(
            v.derive_tier() >= Tier::High,
            "regulated data must escalate regardless of business criticality"
        );
    }

    #[test]
    fn questionnaire_coverage_is_capped_at_one() {
        let mut v = vendor("Extra", DataAccess::None, Tier::Low, 8);
        for k in ["a", "b", "c"] {
            v.questionnaire.insert(k.into(), "yes".into());
        }
        assert_eq!(v.questionnaire_coverage(), 1.0);
    }

    #[test]
    fn incomplete_questionnaire_needs_attention() {
        let v = vendor("Partial", DataAccess::Internal, Tier::Medium, 3);
        let reg = build_register(vec![v]);
        assert_eq!(reg.needs_attention, vec!["Partial"]);
    }

    #[test]
    fn complete_assessment_clears_attention() {
        let v = vendor("Clean", DataAccess::Internal, Tier::Medium, 8);
        let reg = build_register(vec![v]);
        assert!(reg.needs_attention.is_empty());
    }

    #[test]
    fn lapsed_assessment_needs_attention_even_if_answered() {
        let mut v = vendor("Lapsed", DataAccess::Internal, Tier::Medium, 8);
        v.status = AssessmentStatus::Expired;
        let reg = build_register(vec![v]);
        assert_eq!(reg.needs_attention.len(), 1);
    }

    #[test]
    fn register_tallies_tiers() {
        let reg = build_register(vec![
            vendor("A", DataAccess::Regulated, Tier::Critical, 8),
            vendor("B", DataAccess::None, Tier::Low, 8),
            vendor("C", DataAccess::Internal, Tier::Medium, 8),
        ]);
        assert_eq!(reg.vendors.len(), 3);
        assert!(reg.by_tier.values().sum::<i64>() == 3);
    }

    #[test]
    fn tiers_order_correctly() {
        assert!(Tier::Low < Tier::Medium);
        assert!(Tier::High < Tier::Critical);
    }

    #[test]
    fn tier_and_access_parse_round_trip() {
        for t in [Tier::Low, Tier::Medium, Tier::High, Tier::Critical] {
            assert_eq!(Tier::from_str(t.as_str()), Some(t));
        }
        for a in [
            DataAccess::None,
            DataAccess::Internal,
            DataAccess::Confidential,
            DataAccess::Regulated,
        ] {
            assert_eq!(DataAccess::from_str(a.as_str()), Some(a));
        }
        assert_eq!(Tier::from_str("nonsense"), None);
    }

    #[test]
    fn unavailable_capabilities_all_carry_reasons() {
        let caps = unavailable_capabilities();
        assert!(caps.iter().any(|(n, _)| n.contains("rating")));
        assert!(caps.iter().any(|(n, _)| n.contains("Breach")));
        assert!(caps.iter().all(|(_, r)| r.len() > 20));
    }

    #[test]
    fn register_discloses_that_tiers_are_operator_supplied() {
        let reg = build_register(vec![vendor("A", DataAccess::None, Tier::Low, 8)]);
        assert!(reg.notes.iter().any(|n| n.contains("operator-supplied")));
    }
}
