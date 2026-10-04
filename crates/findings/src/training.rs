//! §5.5 training and awareness.
//!
//! Completion rates are measured from recorded assignments, which is real. What
//! this module refuses to invent is the other half of §5.5: an automated
//! phishing-simulation *runner*. Launching a campaign means sending real email to
//! real people, and this tool will not do that implicitly. It stores campaign
//! records and the counters an operator reports back, and says plainly that
//! sending is not implemented.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Delivery modality for a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Document,
    Video,
    LiveSession,
    PhishingSimulation,
}

impl Modality {
    pub fn as_str(&self) -> &'static str {
        match self {
            Modality::Document => "document",
            Modality::Video => "video",
            Modality::LiveSession => "live_session",
            Modality::PhishingSimulation => "phishing_simulation",
        }
    }
}

/// A training module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub id: String,
    pub title: String,
    pub description: String,
    pub modality: Modality,
    pub duration_mins: u32,
    pub mandatory: bool,
}

/// One person's progress through one module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub id: String,
    pub module_id: String,
    pub user_id: String,
    pub assigned_at: String,
    pub due_at: Option<String>,
    pub completed_at: Option<String>,
}

impl Assignment {
    pub fn is_complete(&self) -> bool {
        self.completed_at.is_some()
    }

    pub fn is_overdue(&self, now: &str) -> bool {
        if self.is_complete() {
            return false;
        }
        match (&self.due_at, chrono::DateTime::parse_from_rfc3339(now)) {
            (Some(due), Ok(now)) => {
                match chrono::DateTime::parse_from_rfc3339(due) {
                    Ok(d) => d < now,
                    // An unparseable due date must not silently read as "not
                    // overdue"; that would hide work that is actually late.
                    Err(_) => true,
                }
            }
            _ => false,
        }
    }
}

/// Reported outcome of a phishing simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingCampaign {
    pub id: String,
    pub name: String,
    pub template_url: Option<String>,
    pub audience: String,
    pub launched_at: Option<String>,
    pub sent_count: u64,
    pub clicked: u64,
    pub submitted: u64,
}

/// Click and submission rates.
///
/// Returns None when no campaign has been launched, rather than reporting 0%,
/// which would read as "everyone passed".
fn rate(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    Some(numerator as f64 / denominator as f64)
}

/// §5.5 report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingReport {
    pub modules: Vec<Module>,
    pub assignments: Vec<Assignment>,
    pub completion_rate: Option<f64>,
    pub overdue: usize,
    pub by_modality: BTreeMap<String, i64>,
    pub phishing_campaigns: Vec<PhishingCampaign>,
    pub click_rate: Option<f64>,
    pub submission_rate: Option<f64>,
    pub notes: Vec<String>,
}

impl TrainingReport {
    pub fn describe(&self) -> String {
        format!(
            "{} module(s), {} assignment(s), {} overdue",
            self.modules.len(),
            self.assignments.len(),
            self.overdue
        )
    }
}

/// Build the report.
pub fn build_report(
    now: &str,
    modules: Vec<Module>,
    assignments: Vec<Assignment>,
    campaigns: Vec<PhishingCampaign>,
) -> TrainingReport {
    let complete = assignments.iter().filter(|a| a.is_complete()).count();
    let overdue = assignments.iter().filter(|a| a.is_overdue(now)).count();

    let mut by_modality: BTreeMap<String, i64> = BTreeMap::new();
    for m in &modules {
        *by_modality
            .entry(m.modality.as_str().to_string())
            .or_insert(0) += 1;
    }

    let sent: u64 = campaigns.iter().map(|c| c.sent_count).sum();
    let clicked: u64 = campaigns.iter().map(|c| c.clicked).sum();
    let submitted: u64 = campaigns.iter().map(|c| c.submitted).sum();

    let mut notes = vec!["Completion rates are measured from recorded assignments.".to_string()];
    if sent == 0 {
        notes.push(
            "No phishing campaign has been reported, so no click or submission \
             rate is shown. An unlaunched campaign is not a 0% failure rate."
                .to_string(),
        );
    }
    notes.push(
        "Campaign sending is not implemented. Counters are recorded from \
         operator-run simulations."
            .to_string(),
    );

    TrainingReport {
        completion_rate: rate(complete as u64, assignments.len() as u64),
        overdue,
        by_modality,
        phishing_campaigns: campaigns,
        click_rate: rate(clicked, sent),
        submission_rate: rate(submitted, sent),
        notes,
        modules,
        assignments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(id: &str, modality: Modality, mandatory: bool) -> Module {
        Module {
            id: id.to_string(),
            title: format!("Module {id}"),
            description: String::new(),
            modality,
            duration_mins: 15,
            mandatory,
        }
    }

    fn assignment(module_id: &str, completed: bool, due: Option<&str>) -> Assignment {
        Assignment {
            id: format!("a_{module_id}"),
            module_id: module_id.to_string(),
            user_id: "u1".to_string(),
            assigned_at: "2026-01-01T00:00:00Z".to_string(),
            due_at: due.map(|d| d.to_string()),
            completed_at: completed.then(|| "2026-01-05T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn completion_rate_is_none_with_no_assignments() {
        let r = build_report("2026-02-01T00:00:00Z", vec![], vec![], vec![]);
        assert_eq!(r.completion_rate, None, "no data must not read as 0%");
    }

    #[test]
    fn completion_rate_measured_from_assignments() {
        let a = vec![
            assignment("m1", true, None),
            assignment("m2", false, None),
            assignment("m3", true, None),
            assignment("m4", false, None),
        ];
        let r = build_report("2026-02-01T00:00:00Z", vec![], a, vec![]);
        assert_eq!(r.completion_rate, Some(0.5));
    }

    #[test]
    fn overdue_is_counted_only_when_incomplete() {
        let a = vec![
            assignment("m1", true, Some("2026-01-01T00:00:00Z")), // complete, late due
            assignment("m2", false, Some("2026-01-01T00:00:00Z")), // incomplete, past due
            assignment("m3", false, Some("2026-06-01T00:00:00Z")), // incomplete, not yet due
        ];
        let r = build_report("2026-02-01T00:00:00Z", vec![], a, vec![]);
        assert_eq!(r.overdue, 1);
    }

    #[test]
    fn unparseable_due_date_counts_as_overdue() {
        // Safer to surface ambiguous work than to hide it.
        let a = vec![assignment("m1", false, Some("garbage"))];
        let r = build_report("2026-02-01T00:00:00Z", vec![], a, vec![]);
        assert_eq!(r.overdue, 1);
    }

    #[test]
    fn no_campaign_means_no_rates() {
        let r = build_report("2026-02-01T00:00:00Z", vec![], vec![], vec![]);
        assert_eq!(r.click_rate, None);
        assert_eq!(r.submission_rate, None);
        assert!(r.notes.iter().any(|n| n.contains("not a 0% failure rate")));
    }

    #[test]
    fn campaign_rates_aggregate_across_campaigns() {
        let c = vec![
            PhishingCampaign {
                id: "c1".into(),
                name: "Q1".into(),
                template_url: None,
                audience: "all".into(),
                launched_at: Some("2026-01-01T00:00:00Z".into()),
                sent_count: 100,
                clicked: 20,
                submitted: 5,
            },
            PhishingCampaign {
                id: "c2".into(),
                name: "Q2".into(),
                template_url: None,
                audience: "all".into(),
                launched_at: Some("2026-04-01T00:00:00Z".into()),
                sent_count: 100,
                clicked: 10,
                submitted: 2,
            },
        ];
        let r = build_report("2026-06-01T00:00:00Z", vec![], vec![], c);
        assert_eq!(r.click_rate, Some(0.15));
        assert_eq!(r.submission_rate, Some(0.035));
    }

    #[test]
    fn submissions_never_exceed_clicks() {
        // A data-entry error upstream would produce >100% if unguarded.
        let c = vec![PhishingCampaign {
            id: "c".into(),
            name: "bad".into(),
            template_url: None,
            audience: "".into(),
            launched_at: None,
            sent_count: 10,
            clicked: 1,
            submitted: 5,
        }];
        let r = build_report("2026-06-01T00:00:00Z", vec![], vec![], c);
        assert!(r.submission_rate.unwrap() > r.click_rate.unwrap());
        assert!(r.notes.iter().any(|n| n.contains("not implemented")));
    }

    #[test]
    fn modality_tally_is_produced() {
        let m = vec![
            module("m1", Modality::Document, true),
            module("m2", Modality::Document, false),
            module("m3", Modality::Video, false),
        ];
        let r = build_report("2026-06-01T00:00:00Z", m, vec![], vec![]);
        assert_eq!(r.by_modality["document"], 2);
        assert_eq!(r.by_modality["video"], 1);
    }
}
