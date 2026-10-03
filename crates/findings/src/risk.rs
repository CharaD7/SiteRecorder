//! §5.2 risk register derived from real findings.
//!
//! ## What is computed, and on what basis
//!
//! Each open finding becomes a risk entry. Score is `likelihood x impact`,
//! where both factors are derived from data the tool actually holds:
//!
//! * **Likelihood** from finding severity, via a published, auditable table.
//! * **Impact** from the affected asset's criticality, falling back to a
//!   documented default when the asset is unknown.
//!
//! Every factor is reported alongside the score, so an operator can see exactly
//! why a risk ranks where it does and challenge it.
//!
//! ## What is deliberately not computed
//!
//! §5.2 also asks for FAIR modelling, Monte Carlo simulation and loss
//! exceedance curves. All three need an organisation-specific loss model:
//! asset values, business impact factors, historical loss data. None of that
//! exists in this tool, and inventing it would produce curves that look
//! authoritative and mean nothing. They are reported as unavailable with
//! reasons.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Treatment decision for a risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Treatment {
    Accept,
    Mitigate,
    Transfer,
    Avoid,
    /// No decision recorded yet.
    Undecided,
}

impl Treatment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Treatment::Accept => "accept",
            Treatment::Mitigate => "mitigate",
            Treatment::Transfer => "transfer",
            Treatment::Avoid => "avoid",
            Treatment::Undecided => "undecided",
        }
    }
}

/// Likelihood bands, 1 (rare) to 5 (almost certain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Likelihood {
    Rare,
    Unlikely,
    Possible,
    Likely,
    AlmostCertain,
}

impl Likelihood {
    pub fn score(&self) -> f64 {
        match self {
            Likelihood::Rare => 1.0,
            Likelihood::Unlikely => 2.0,
            Likelihood::Possible => 3.0,
            Likelihood::Likely => 4.0,
            Likelihood::AlmostCertain => 5.0,
        }
    }

    /// Map a finding severity to likelihood. Published rather than hidden so a
    /// reviewer can disagree with it explicitly.
    pub fn from_severity(severity: &str) -> Likelihood {
        match severity.to_uppercase().as_str() {
            "CRITICAL" => Likelihood::AlmostCertain,
            "HIGH" => Likelihood::Likely,
            "MEDIUM" => Likelihood::Possible,
            "LOW" => Likelihood::Unlikely,
            _ => Likelihood::Rare,
        }
    }
}

/// Impact bands, 1 (negligible) to 5 (severe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Impact {
    Negligible,
    Minor,
    Moderate,
    Major,
    Severe,
}

impl Impact {
    pub fn score(&self) -> f64 {
        match self {
            Impact::Negligible => 1.0,
            Impact::Minor => 2.0,
            Impact::Moderate => 3.0,
            Impact::Major => 4.0,
            Impact::Severe => 5.0,
        }
    }

    /// Impact from the affected asset's criticality.
    ///
    /// An unknown asset defaults to Moderate rather than Severe: inflating
    /// every unattached finding to maximum would distort the whole register.
    pub fn from_criticality(criticality: Option<&str>) -> Impact {
        match criticality.unwrap_or("").to_ascii_lowercase().as_str() {
            "critical" => Impact::Severe,
            "high" => Impact::Major,
            "medium" => Impact::Moderate,
            "low" => Impact::Minor,
            "" => Impact::Moderate,
            _ => Impact::Moderate,
        }
    }
}

/// Severity band for prioritisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        };
        write!(f, "{}", s)
    }
}

/// One risk entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEntry {
    pub id: String,
    /// The finding this risk was derived from.
    pub finding_id: String,
    pub title: String,
    pub category: String,
    pub asset_id: Option<String>,
    pub likelihood: Likelihood,
    pub impact: Impact,
    pub score: f64,
    pub level: RiskLevel,
    pub treatment: Treatment,
    pub owner: Option<String>,
    /// Whether the mapping factors were observed or defaulted.
    pub impact_basis: String,
}

fn level_for(score: f64) -> RiskLevel {
    match score {
        s if s >= 20.0 => RiskLevel::Critical,
        s if s >= 12.0 => RiskLevel::High,
        s if s >= 6.0 => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

/// A risk assessment input, projected from stored findings.
#[derive(Debug, Clone)]
pub struct RiskInput {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub asset_id: Option<String>,
    pub asset_criticality: Option<String>,
    pub open: bool,
}

/// A quantitative model this build refuses to fabricate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnavailableModel {
    pub name: String,
    pub reason: String,
}

/// §5.2 register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskRegister {
    pub generated_at: String,
    pub entries: Vec<RiskEntry>,
    pub by_level: BTreeMap<String, i64>,
    pub by_treatment: BTreeMap<String, i64>,
    /// Total across all open risks, before treatment.
    pub residual_score: f64,
    pub unavailable_models: Vec<UnavailableModel>,
    pub notes: Vec<String>,
}

impl RiskRegister {
    pub fn describe(&self) -> String {
        format!(
            "{} risk entr(ies), {} critical, residual score {:.1}",
            self.entries.len(),
            self.by_level.get("critical").copied().unwrap_or(0),
            self.residual_score
        )
    }
}

/// Build the register from projected findings.
pub fn build_register(now: chrono::DateTime<chrono::Utc>, inputs: &[RiskInput]) -> RiskRegister {
    let mut entries: Vec<RiskEntry> = inputs
        .iter()
        .filter(|i| i.open)
        .map(|i| {
            let likelihood = Likelihood::from_severity(&i.severity);
            let impact = Impact::from_criticality(i.asset_criticality.as_deref());
            let score = likelihood.score() * impact.score();

            let impact_basis = match i.asset_criticality.as_deref() {
                Some(c) if !c.is_empty() => format!("asset criticality: {}", c),
                // Be explicit when a factor was defaulted, so the score is not
                // mistaken for a measured one.
                _ => "no asset criticality recorded; defaulted to Moderate".to_string(),
            };

            RiskEntry {
                id: format!("risk_{}", i.finding_id),
                finding_id: i.finding_id.clone(),
                title: i.title.clone(),
                category: i.category.clone(),
                asset_id: i.asset_id.clone(),
                likelihood,
                impact,
                score,
                level: level_for(score),
                treatment: Treatment::Undecided,
                owner: None,
                impact_basis,
            }
        })
        .collect();

    // Highest risk first, so the register reads as a work queue.
    entries.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.title.cmp(&b.title))
    });

    let mut by_level: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_treatment: BTreeMap<String, i64> = BTreeMap::new();
    let mut residual = 0.0;
    for e in &entries {
        *by_level.entry(e.level.to_string()).or_insert(0) += 1;
        *by_treatment.entry(e.treatment.as_str().to_string()).or_insert(0) += 1;
        residual += e.score;
    }

    RiskRegister {
        generated_at: now.to_rfc3339(),
        entries,
        by_level,
        by_treatment,
        residual_score: residual,
        unavailable_models: unavailable_models(),
        notes: vec![
            "Scores come from a published severity-to-likelihood and \
             criticality-to-impact mapping, not from breach data. They rank work; \
             they are not actuarial values."
                .to_string(),
            "Residual score assumes no treatment has been applied, since none is \
             modelled in this build."
                .to_string(),
        ],
    }
}

/// Record a treatment decision for a risk.
pub fn set_treatment(register: &mut RiskRegister, risk_id: &str, treatment: Treatment) -> bool {
    if let Some(entry) = register.entries.iter_mut().find(|e| e.id == risk_id) {
        entry.treatment = treatment;
        *register
            .by_treatment
            .entry(treatment.as_str().to_string())
            .or_insert(0) += 1;
        *register.by_treatment.entry("undecided".to_string()).or_insert(0) -= 1;
        if register.by_treatment["undecided"] <= 0 {
            register.by_treatment.remove("undecided");
        }
        true
    } else {
        false
    }
}

/// Models this build will not fabricate.
pub fn unavailable_models() -> Vec<UnavailableModel> {
    vec![
        UnavailableModel {
            name: "FAIR (Factor Analysis of Information Risk)".to_string(),
            reason: "Needs asset values, business impact factors and exposure estimates \
                     for this organisation. No loss model is configured."
                .to_string(),
        },
        UnavailableModel {
            name: "Monte Carlo simulation".to_string(),
            reason: "Needs a distribution of loss magnitudes. Without loss data, any \
                     simulation would sample invented numbers."
                .to_string(),
        },
        UnavailableModel {
            name: "Loss exceedance curve".to_string(),
            reason: "Derived from the same missing loss data as Monte Carlo.".to_string(),
        },
        UnavailableModel {
            name: "Residual risk after treatment".to_string(),
            reason: "Requires recorded treatment effectiveness, which is not measured."
                .to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(sev: &str, criticality: Option<&str>, open: bool) -> RiskInput {
        RiskInput {
            finding_id: format!("f_{sev}_{}", criticality.unwrap_or("none")),
            title: format!("{} finding", sev),
            severity: sev.to_string(),
            category: "web".into(),
            asset_id: Some("a1".into()),
            asset_criticality: criticality.map(|c| c.to_string()),
            open,
        }
    }

    #[test]
    fn critical_finding_on_critical_asset_scores_maximum() {
        let r = build_register(now(), &[input("CRITICAL", Some("critical"), true)]);
        let e = &r.entries[0];
        assert_eq!(e.score, 25.0);
        assert_eq!(e.level, RiskLevel::Critical);
    }

    #[test]
    fn closed_findings_produce_no_risk() {
        let r = build_register(now(), &[input("CRITICAL", Some("critical"), false)]);
        assert!(r.entries.is_empty(), "remediated findings are not open risk");
    }

    #[test]
    fn ordering_is_highest_risk_first() {
        let r = build_register(
            now(),
            &[
                input("LOW", Some("low"), true),      // 2 * 2 = 4
                input("CRITICAL", Some("critical"), true), // 5 * 5 = 25
                input("MEDIUM", Some("medium"), true),   // 3 * 3 = 9
            ],
        );
        let scores: Vec<f64> = r.entries.iter().map(|e| e.score).collect();
        assert_eq!(scores, vec![25.0, 9.0, 4.0]);
    }

    #[test]
    fn unknown_asset_defaults_to_moderate_not_severe() {
        let r = build_register(now(), &[input("CRITICAL", None, true)]);
        let e = &r.entries[0];
        assert_eq!(e.score, 15.0, "5 x 3, not 5 x 5");
        assert!(
            e.impact_basis.contains("defaulted"),
            "a defaulted factor must be disclosed: {}",
            e.impact_basis
        );
    }

    #[test]
    fn known_asset_records_its_criticality_as_basis() {
        let r = build_register(now(), &[input("HIGH", Some("high"), true)]);
        assert!(r.entries[0].impact_basis.contains("high"));
        assert!(!r.entries[0].impact_basis.contains("defaulted"));
    }

    #[test]
    fn level_bands_are_consistent_with_score() {
        for (sev, crit, expected) in [
            ("CRITICAL", "critical", RiskLevel::Critical),
            ("HIGH", "high", RiskLevel::High),
            ("MEDIUM", "medium", RiskLevel::Medium),
            ("LOW", "low", RiskLevel::Low),
        ] {
            let r = build_register(now(), &[input(sev, Some(crit), true)]);
            assert_eq!(r.entries[0].level, expected, "{sev}/{crit}");
        }
    }

    #[test]
    fn every_open_finding_gets_an_entry() {
        let r = build_register(now(), &[input("HIGH", Some("high"), true), input("LOW", Some("low"), true)]);
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.by_level.values().sum::<i64>(), 2);
    }

    #[test]
    fn residual_score_is_the_sum_before_treatment() {
        let r = build_register(
            now(),
            &[input("HIGH", Some("high"), true), input("MEDIUM", Some("medium"), true)],
        );
        // HIGH=4 x high-criticality=4 = 16; MEDIUM=3 x medium=3 = 9.
        assert_eq!(r.residual_score, 16.0 + 9.0);
    }

    #[test]
    fn treatment_is_recorded_and_moves_between_tallies() {
        let mut r = build_register(now(), &[input("HIGH", Some("high"), true)]);
        let id = r.entries[0].id.clone();
        assert_eq!(r.by_treatment["undecided"], 1);

        assert!(set_treatment(&mut r, &id, Treatment::Mitigate));
        assert_eq!(r.by_treatment["mitigate"], 1);
        assert!(!r.by_treatment.contains_key("undecided"));
        assert_eq!(r.entries[0].treatment, Treatment::Mitigate);
    }

    #[test]
    fn treating_an_unknown_risk_is_a_no_op() {
        let mut r = build_register(now(), &[input("HIGH", Some("high"), true)]);
        let before = r.entries.len();
        assert!(!set_treatment(&mut r, "risk_does_not_exist", Treatment::Accept));
        assert_eq!(r.entries.len(), before);
    }

    #[test]
    fn quantitative_models_are_refused_with_reasons() {
        let models = unavailable_models();
        let names: Vec<&str> = models.iter().map(|m| m.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("FAIR")));
        assert!(names.iter().any(|n| n.contains("Monte Carlo")));
        assert!(names.iter().any(|n| n.contains("Loss exceedance")));
        assert!(models.iter().all(|m| m.reason.len() > 20), "reasons must be substantive");
    }

    #[test]
    fn register_always_carries_its_scoring_basis_caveat() {
        let r = build_register(now(), &[input("HIGH", Some("high"), true)]);
        assert!(r.notes.iter().any(|n| n.contains("not actuarial")));
    }

    #[test]
    fn empty_register_is_valid_and_still_refuses_models() {
        let r = build_register(now(), &[]);
        assert!(r.entries.is_empty());
        assert_eq!(r.residual_score, 0.0);
        assert!(!r.unavailable_models.is_empty());
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z").unwrap().into()
    }
}
