//! §5.6 metrics over stored findings.
//!
//! Derives posture from measurement rather than assertion.
//!
//! ## Why some metrics are deliberately absent
//!
//! MTTD, MTTR and MTTC are the headline figures an executive expects from a
//! security tool, and this build reports them as **unavailable with a reason**
//! rather than approximating them. MTTD needs a detection event correlated with
//! a vulnerability; MTTR/MTTC need incident timelines with contained/closed
//! timestamps. Nothing writes to `incidents` yet, so any number here would be
//! invented. An invented MTTR is worse than no MTTR.
//!
//! Vulnerability metrics, by contrast, are fully derivable from `findings`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Findings open for work (not false positive, not accepted risk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMetrics {
    pub total: i64,
    pub open: i64,
    pub by_severity: BTreeMap<String, i64>,
    /// Days-open buckets for unresolved findings (§5.6 aging).
    pub aging: AgingBuckets,
    /// Share of triaged findings marked false positive.
    pub false_positive_rate: f64,
    /// Share of open findings already remediated.
    pub remediation_rate: f64,
    /// Findings per asset actually scanned.
    pub findings_per_asset: f64,
    pub assets_total: i64,
    pub assets_with_findings: i64,
}

/// Aging distribution. Day counts are calendar days since `created_at`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgingBuckets {
    pub d0_30: i64,
    pub d31_60: i64,
    pub d61_90: i64,
    pub d90_plus: i64,
    /// Oldest unresolved finding in days, if any.
    pub oldest_open_days: Option<i64>,
}

impl AgingBuckets {
    pub fn total(&self) -> i64 {
        self.d0_30 + self.d31_60 + self.d61_90 + self.d90_plus
    }
}

/// A metric this build cannot compute, with the reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnavailableMetric {
    pub name: String,
    pub reason: String,
}

/// Full §5.6 report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsReport {
    pub generated_at: String,
    pub vulnerability: VulnerabilityMetrics,
    pub findings_by_category: Vec<(String, i64)>,
    /// New findings per day for the trailing window.
    pub discovery_trend: Vec<(String, i64)>,
    pub unavailable: Vec<UnavailableMetric>,
}

impl MetricsReport {
    pub fn describe(&self) -> String {
        format!(
            "{} open finding(s) across {} asset(s); {} unavailable metric(s)",
            self.vulnerability.open,
            self.vulnerability.assets_total,
            self.unavailable.len()
        )
    }
}

/// Days between two RFC3339 timestamps, or None if unparseable.
fn days_between(from: &str, to: DateTime<Utc>) -> Option<i64> {
    DateTime::parse_from_rfc3339(from)
        .ok()
        .map(|t| (to - t.with_timezone(&Utc)).num_days())
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Build the §5.6 report from projected findings.
pub fn build(
    now: DateTime<Utc>,
    findings: &[crate::compliance::FindingProjection],
    by_category: Vec<(String, i64)>,
) -> MetricsReport {
    let mut by_severity: BTreeMap<String, i64> = BTreeMap::new();
    let mut aging = AgingBuckets::default();
    let mut open = 0i64;
    let mut triaged = 0i64;
    let mut false_positive = 0i64;
    let mut remediated = 0i64;

    for f in findings {
        *by_severity
            .entry(f.severity.to_uppercase())
            .or_insert(0) += 1;
        triaged += 1;

        if !f.counts_against_posture {
            if f.status == "false_positive" {
                false_positive += 1;
            }
            continue;
        }

        // Remediated findings are resolved work, not open risk. Counting them
        // as open would double-count them in both the open total and the
        // remediation denominator.
        if f.status == "remediated" {
            remediated += 1;
            continue;
        }

        open += 1;
        let age = days_between(&f.created_at, now).unwrap_or(0).max(0);
        match age {
            0..=30 => aging.d0_30 += 1,
            31..=60 => aging.d31_60 += 1,
            61..=90 => aging.d61_90 += 1,
            _ => aging.d90_plus += 1,
        };
        if aging.oldest_open_days.map_or(true, |o| age > o) {
            aging.oldest_open_days = Some(age);
        }
    }

    let assets_total = findings
        .iter()
        .filter_map(|f| f.asset_id.as_deref())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as i64;
    let assets_with_findings = findings
        .iter()
        .filter(|f| f.counts_against_posture && f.asset_id.is_some())
        .map(|f| f.asset_id.clone().unwrap_or_default())
        .collect::<std::collections::BTreeSet<_>>()
        .len() as i64;

    MetricsReport {
        generated_at: now.to_rfc3339(),
        vulnerability: VulnerabilityMetrics {
        total: triaged,
        open,
        by_severity,
        aging,
        // Rate over triaged findings, i.e. those a human has looked at.
        false_positive_rate: if triaged > 0 {
            false_positive as f64 / triaged as f64
        } else {
            0.0
        },
        remediation_rate: if open + remediated > 0 {
            remediated as f64 / (open + remediated) as f64
        } else {
            0.0
        },
        findings_per_asset: if assets_with_findings > 0 {
            open as f64 / assets_with_findings as f64
        } else {
            0.0
        },
        assets_total,
        assets_with_findings,
        },
        findings_by_category: by_category,
        discovery_trend: Vec::new(),
        unavailable: Vec::new(),
    }
}

/// Metrics this build refuses to invent.
pub fn unavailable_metrics(incident_count: i64) -> Vec<UnavailableMetric> {
    vec![
        UnavailableMetric {
            name: "MTTD (mean time to detect)".to_string(),
            reason: "Requires a detection event correlated with a finding. No detection \
                     pipeline is wired to findings yet."
                .to_string(),
        },
        UnavailableMetric {
            name: "MTTR (mean time to respond)".to_string(),
            reason: if incident_count == 0 {
                "Requires recorded incidents with response timestamps; the incidents table \
                 is empty."
                    .to_string()
            } else {
                "Requires consistent response timestamps on incidents.".to_string()
            },
        },
        UnavailableMetric {
            name: "MTTC (mean time to contain)".to_string(),
            reason: "Requires incident containment timestamps; nothing writes to incidents.".to_string(),
        },
        UnavailableMetric {
            name: "Patch compliance".to_string(),
            reason: "Requires a software inventory per asset. No patch data source exists.".to_string(),
        },
        UnavailableMetric {
            name: "Risk trend / posture change".to_string(),
            reason: "Requires multiple scan periods on the same assets. Only a single \
                     observation exists, so no trend can be computed honestly."
                .to_string(),
        },
    ]
}

/// New findings per day over the trailing `window_days`.
pub fn discovery_trend(
    findings: &[crate::compliance::FindingProjection],
    now: DateTime<Utc>,
    window_days: i64,
) -> Vec<(String, i64)> {
    let mut buckets: BTreeMap<String, i64> = BTreeMap::new();

    for offset in (0..window_days).rev() {
        let day = now - chrono::Duration::days(offset);
        buckets.insert(day.format("%Y-%m-%d").to_string(), 0);
    }

    for f in findings {
        let Some(ts) = parse_ts(&f.created_at) else {
            continue;
        };
        let key = ts.format("%Y-%m-%d").to_string();
        buckets.entry(key).and_modify(|v| *v += 1).or_insert(1);
    }

    buckets.into_iter().collect()
}

/// Count rows in a table, used to decide whether incident metrics exist yet.
pub fn count_rows(conn: &rusqlite::Connection, table: &str) -> Result<i64, rusqlite::Error> {
    // `table` is a compile-time constant from this module, never user input.
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::FindingProjection;

    fn p(sev: &str, status: &str, created: &str, asset: Option<&str>) -> FindingProjection {
        FindingProjection {
            id: "f".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            severity: sev.to_string(),
            status: status.to_string(),
            counts_against_posture: !matches!(status, "false_positive" | "accepted"),
            created_at: created.to_string(),
            updated_at: created.to_string(),
            asset_id: asset.map(|s| s.to_string()),
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z").unwrap().into()
    }

    fn days_ago(n: i64) -> String {
        (now() - chrono::Duration::days(n)).to_rfc3339()
    }

    #[test]
    fn open_findings_count_and_exclude_triaged_ones() {
        let fs = vec![
            p("CRITICAL", "new", &days_ago(5), Some("a1")),
            p("HIGH", "new", &days_ago(10), Some("a1")),
            p("LOW", "false_positive", &days_ago(10), Some("a1")),
            p("INFO", "accepted", &days_ago(10), Some("a1")),
        ];
        let m = build(now(), &fs, vec![]);
        assert_eq!(m.vulnerability.total, 4);
        assert_eq!(m.vulnerability.open, 2, "false positives and accepted are not open");
    }

    #[test]
    fn aging_buckets_are_calendar_correct() {
        let fs = vec![
            p("HIGH", "new", &days_ago(10), None),    // 0-30
            p("HIGH", "new", &days_ago(45), None),    // 31-60
            p("HIGH", "new", &days_ago(75), None),    // 61-90
            p("HIGH", "new", &days_ago(200), None),   // 90+
        ];
        let m = build(now(), &fs, vec![]);
        assert_eq!(m.vulnerability.aging.d0_30, 1);
        assert_eq!(m.vulnerability.aging.d31_60, 1);
        assert_eq!(m.vulnerability.aging.d61_90, 1);
        assert_eq!(m.vulnerability.aging.d90_plus, 1);
        assert_eq!(m.vulnerability.aging.total(), 4);
        assert_eq!(m.vulnerability.aging.oldest_open_days, Some(200));
    }

    #[test]
    fn boundary_days_land_in_the_right_bucket() {
        let fs = vec![
            p("HIGH", "new", &days_ago(30), None),
            p("HIGH", "new", &days_ago(31), None),
            p("HIGH", "new", &days_ago(60), None),
            p("HIGH", "new", &days_ago(61), None),
            p("HIGH", "new", &days_ago(90), None),
            p("HIGH", "new", &days_ago(91), None),
        ];
        // 30 -> 0-30; 31 and 60 -> 31-60; 61 and 90 -> 61-90; 91 -> 90+.
        let a = build(now(), &fs, vec![]).vulnerability.aging;
        assert_eq!((a.d0_30, a.d31_60, a.d61_90, a.d90_plus), (1, 2, 2, 1));
        assert_eq!(a.total(), 6);
    }

    #[test]
    fn false_positive_rate_uses_triaged_as_denominator() {
        let fs = vec![
            p("HIGH", "new", &days_ago(1), None),
            p("LOW", "false_positive", &days_ago(1), None),
            p("LOW", "false_positive", &days_ago(1), None),
            p("INFO", "accepted", &days_ago(1), None),
        ];
        let m = build(now(), &fs, vec![]);
        assert_eq!(m.vulnerability.false_positive_rate, 0.5, "2 of 4 triaged");
    }

    #[test]
    fn remediation_rate_counts_remediated_against_resolved_set() {
        let fs = vec![
            p("HIGH", "new", &days_ago(1), None),
            p("HIGH", "remediated", &days_ago(30), None),
            p("LOW", "remediated", &days_ago(30), None),
        ];
        let m = build(now(), &fs, vec![]);
        assert_eq!(m.vulnerability.open, 1, "remediated findings are not open");
        assert!(
            (m.vulnerability.remediation_rate - 2.0 / 3.0).abs() < 1e-9,
            "2 remediated of (1 open + 2 remediated)"
        );
    }

    #[test]
    fn rates_are_zero_not_nan_when_empty() {
        let m = build(now(), &[], vec![]);
        assert_eq!(m.vulnerability.false_positive_rate, 0.0);
        assert_eq!(m.vulnerability.remediation_rate, 0.0);
        assert_eq!(m.vulnerability.findings_per_asset, 0.0);
        assert!(m.vulnerability.aging.oldest_open_days.is_none());
    }

    #[test]
    fn per_asset_density_uses_assets_with_findings() {
        let fs = vec![
            p("HIGH", "new", &days_ago(1), Some("a1")),
            p("HIGH", "new", &days_ago(1), Some("a1")),
            p("LOW", "new", &days_ago(1), Some("a2")),
        ];
        let m = build(now(), &fs, vec![]);
        assert_eq!(m.vulnerability.assets_total, 2);
        assert_eq!(m.vulnerability.assets_with_findings, 2);
        assert_eq!(m.vulnerability.findings_per_asset, 1.5);
    }

    #[test]
    fn unparseable_timestamps_are_treated_as_new_not_skipped() {
        let fs = vec![p("HIGH", "new", "not-a-date", None)];
        let m = build(now(), &fs, vec![]);
        assert_eq!(m.vulnerability.aging.d0_30, 1);
    }

    #[test]
    fn headline_metrics_are_refused_with_reasons() {
        let u = unavailable_metrics(0);
        let names: Vec<&str> = u.iter().map(|m| m.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("MTTD")));
        assert!(names.iter().any(|n| n.contains("MTTR")));
        assert!(names.iter().any(|n| n.contains("MTTC")));
        assert!(names.iter().any(|n| n.contains("Patch compliance")));
        assert!(u.iter().all(|m| !m.reason.is_empty()), "every refusal needs a reason");
    }

    #[test]
    fn discovery_trend_is_dense_and_counts_today() {
        let fs = vec![
            p("HIGH", "new", &days_ago(0), None),
            p("HIGH", "new", &days_ago(0), None),
            p("LOW", "new", &days_ago(3), None),
        ];
        let trend = discovery_trend(&fs, now(), 7);
        assert_eq!(trend.len(), 7, "one bucket per day, no gaps");
        let last = trend.last().unwrap();
        assert_eq!(last.1, 2, "today has both findings");
        assert_eq!(trend.first().unwrap().1, 0);
    }
}
