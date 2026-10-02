//! Scanner-to-findings ingestion (Wave 2.3).
//!
//! The web scanner is the one genuinely real engine in the codebase: 47 checks
//! that actually probe the target. Until now its output died in per-scan JSON
//! files, so nothing could aggregate, trend, or report on it. This module is
//! the bridge.
//!
//! Two rules govern the conversion:
//!
//! 1. **Only real findings are ingested.** A check that returned
//!    `NotVulnerable`, `Skipped` or `Error` contributes nothing. Storing "no
//!    problem found" as a finding would corrupt every downstream count.
//! 2. **IDs are derived deterministically** from scan id + check name, so
//!    re-ingesting the same scan updates rows rather than duplicating them.

use crate::{insert_many, resolve_or_create_asset, FindingFilter};
use db::models::{Evidence, Finding, FindingStatus, Severity};
use db::Result;
use rusqlite::Connection;
use scanner::{ScanReport, ScanStatus};

/// Map the scanner's severity onto the converged model.
fn map_severity(s: &scanner::Severity) -> Severity {
    match s {
        scanner::Severity::Critical => Severity::Critical,
        scanner::Severity::High => Severity::High,
        scanner::Severity::Medium => Severity::Medium,
        scanner::Severity::Low => Severity::Low,
        scanner::Severity::Info => Severity::Info,
    }
}

/// True when a check result represents something actually detected.
fn is_actionable(status: &ScanStatus) -> bool {
    matches!(status, ScanStatus::Vulnerable | ScanStatus::Warning)
}

/// Deterministic id so re-ingesting the same scan is idempotent.
fn finding_id(scan_id: &str, check_name: &str, index: usize) -> String {
    format!("{}_{}_{}", scan_id, slug(check_name), index)
}

/// Reduce a check name to a filesystem- and URL-safe token.
fn slug(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
}

/// Convert a report into findings without writing anything.
pub fn convert(report: &ScanReport, asset_id: Option<String>, user_id: Option<String>) -> Vec<Finding> {
    let mut out = Vec::new();

    for result in &report.results {
        if !is_actionable(&result.status) {
            continue;
        }

        // A check with no individual findings (e.g. a warning-level header
        // result) still represents a real observation, so synthesise one.
        if result.findings.is_empty() {
            out.push(Finding {
                id: finding_id(&report.scan_id, &result.check_name, 0),
                scan_id: Some(report.scan_id.clone()),
                asset_id: asset_id.clone(),
                title: result.check_name.clone(),
                severity: map_severity(&result.severity),
                status: FindingStatus::New,
                category: "web".to_string(),
                cwe_id: None,
                cve_ids: vec![],
                cvss_score: None,
                description: format!("{} check reported {}", result.check_name, result.status),
                remediation: "See the scanner check documentation for remediation guidance."
                    .to_string(),
                references: vec![],
                mitre_techniques: vec![],
                evidence: vec![Evidence {
                    kind: "check_result".to_string(),
                    description: format!(
                        "check={} status={} severity={} duration_ms={}",
                        result.check_name, result.status, result.severity, result.scan_duration_ms
                    ),
                    data: None,
                    captured_at: report.timestamp.clone(),
                }],
                assignee: None,
                due_date: None,
                created_at: report.timestamp.clone(),
                updated_at: report.timestamp.clone(),
                user_id: user_id.clone(),
            });
            continue;
        }

        for (i, vf) in result.findings.iter().enumerate() {
            out.push(Finding {
                id: finding_id(&report.scan_id, &result.check_name, i),
                scan_id: Some(report.scan_id.clone()),
                asset_id: asset_id.clone(),
                title: vf.title.clone(),
                severity: map_severity(&vf.severity),
                status: FindingStatus::New,
                category: "web".to_string(),
                cwe_id: vf.cwe_id.clone(),
                cve_ids: vec![],
                cvss_score: None,
                description: vf.description.clone(),
                remediation: vf.remediation.clone(),
                references: vf.references.clone(),
                mitre_techniques: vec![],
                evidence: vec![Evidence {
                    kind: "scanner_detail".to_string(),
                    description: vf.details.join("; "),
                    data: vf.details.first().cloned(),
                    captured_at: report.timestamp.clone(),
                }],
                assignee: None,
                due_date: None,
                created_at: report.timestamp.clone(),
                updated_at: report.timestamp.clone(),
                user_id: user_id.clone(),
            });
        }
    }

    out
}

/// Outcome of ingesting one report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IngestOutcome {
    pub scan_id: String,
    pub asset_id: Option<String>,
    pub findings_written: usize,
    pub checks_considered: usize,
    pub checks_skipped: usize,
}

/// Convert and persist a report in one step.
pub fn ingest_report(
    conn: &Connection,
    report: &ScanReport,
    user_id: Option<&str>,
) -> Result<IngestOutcome> {
    let asset_id = resolve_or_create_asset(conn, &report.url, user_id)?;
    let converted = convert(report, Some(asset_id.clone()), user_id.map(|s| s.to_string()));

    let checks_considered = report.results.len();
    let checks_skipped = report
        .results
        .iter()
        .filter(|r| !is_actionable(&r.status))
        .count();

    let written = insert_many(conn, &converted)?;

    Ok(IngestOutcome {
        scan_id: report.scan_id.clone(),
        asset_id: Some(asset_id),
        findings_written: written,
        checks_considered,
        checks_skipped,
    })
}

/// Total stored findings for an asset; used by dashboards.
pub fn count_for_asset(conn: &Connection, asset_id: &str) -> Result<i64> {
    crate::count(
        conn,
        &FindingFilter {
            asset_id: Some(asset_id.to_string()),
            ..Default::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use db::Db;
    use scanner::{ScanResult, Severity as ScanSev, VulnerabilityFinding};

    fn finding(title: &str, sev: ScanSev) -> VulnerabilityFinding {
        VulnerabilityFinding {
            title: title.into(),
            severity: sev,
            status: ScanStatus::Vulnerable,
            description: "desc".into(),
            details: vec!["detail".into()],
            remediation: "fix it".into(),
            cwe_id: Some("CWE-79".into()),
            references: vec!["https://example.com/ref".into()],
        }
    }

    fn report(results: Vec<ScanResult>) -> ScanReport {
        ScanReport {
            url: "https://example.com".into(),
            scan_id: "scan_test".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            summary: scanner::ScanSummary {
                total_checks: 0,
                vulnerable: 0,
                not_vulnerable: 0,
                warnings: 0,
                errors: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
                risk_score: 0.0,
            },
            results,
        }
    }

    fn result(name: &str, status: ScanStatus, sev: ScanSev, f: Vec<VulnerabilityFinding>) -> ScanResult {
        ScanResult {
            check_name: name.into(),
            status,
            severity: sev,
            findings: f,
            scan_duration_ms: 12,
            timestamp: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn skips_clean_checks() {
        let r = report(vec![result(
            "SQL Injection",
            ScanStatus::NotVulnerable,
            ScanSev::Critical,
            vec![],
        )]);
        let out = convert(&r, None, None);
        assert!(out.is_empty(), "a clean check must not become a finding");
    }

    #[test]
    fn ingests_vulnerable_checks() {
        let r = report(vec![result(
            "SQL Injection",
            ScanStatus::Vulnerable,
            ScanSev::Critical,
            vec![finding("SQLi in login", ScanSev::Critical)],
        )]);
        let out = convert(&r, None, None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Critical);
        assert_eq!(out[0].cwe_id.as_deref(), Some("CWE-79"));
        assert_eq!(out[0].category, "web");
    }

    #[test]
    fn warnings_are_ingested() {
        let r = report(vec![result(
            "Security Headers",
            ScanStatus::Warning,
            ScanSev::Medium,
            vec![finding("Missing CSP", ScanSev::Medium)],
        )]);
        assert_eq!(convert(&r, None, None).len(), 1);
    }

    #[test]
    fn errors_and_skips_are_not_findings() {
        let r = report(vec![
            result("A", ScanStatus::Error, ScanSev::High, vec![finding("x", ScanSev::High)]),
            result("B", ScanStatus::Skipped, ScanSev::High, vec![finding("y", ScanSev::High)]),
        ]);
        assert!(convert(&r, None, None).is_empty());
    }

    #[test]
    fn action_without_details_synthesises_a_finding() {
        let r = report(vec![result(
            "Cookie Flags",
            ScanStatus::Warning,
            ScanSev::Low,
            vec![],
        )]);
        let out = convert(&r, None, None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].title, "Cookie Flags");
        assert_eq!(out[0].severity, Severity::Low);
    }

    #[test]
    fn ids_are_deterministic_across_runs() {
        let r = report(vec![result(
            "SQL Injection",
            ScanStatus::Vulnerable,
            ScanSev::High,
            vec![finding("a", ScanSev::High), finding("b", ScanSev::High)],
        )]);
        let first = convert(&r, None, None);
        let second = convert(&r, None, None);
        let ids_a: Vec<_> = first.iter().map(|f| f.id.clone()).collect();
        let ids_b: Vec<_> = second.iter().map(|f| f.id.clone()).collect();
        assert_eq!(ids_a, ids_b, "re-ingest must update, not duplicate");
        assert_ne!(ids_a[0], ids_a[1]);
    }

    #[test]
    fn slug_normalises_check_names() {
        assert_eq!(slug("Server-Side Request Forgery (SSRF)"), "server_side_request_forgery__ssrf_");
    }

    #[test]
    fn end_to_end_creates_asset_and_rows() {
        let db = Db::open_in_memory().unwrap();
        let r = report(vec![
            result("SQL Injection", ScanStatus::Vulnerable, ScanSev::Critical,
                   vec![finding("SQLi", ScanSev::Critical)]),
            result("TLS", ScanStatus::NotVulnerable, ScanSev::High, vec![]),
        ]);

        let outcome = ingest_report(db.conn(), &r, None).unwrap();
        assert_eq!(outcome.findings_written, 1);
        assert_eq!(outcome.checks_considered, 2);
        assert_eq!(outcome.checks_skipped, 1);

        let asset_id = outcome.asset_id.unwrap();
        assert_eq!(count_for_asset(db.conn(), &asset_id).unwrap(), 1);
    }

    #[test]
    fn re_ingest_does_not_duplicate_rows() {
        let db = Db::open_in_memory().unwrap();
        let r = report(vec![result(
            "SQL Injection",
            ScanStatus::Vulnerable,
            ScanSev::Critical,
            vec![finding("SQLi", ScanSev::Critical)],
        )]);

        ingest_report(db.conn(), &r, None).unwrap();
        let second = ingest_report(db.conn(), &r, None).unwrap();
        assert_eq!(second.findings_written, 1);

        let total: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(total, 1, "deterministic ids must upsert");
    }

    #[test]
    fn asset_is_reused_for_the_same_url() {
        let db = Db::open_in_memory().unwrap();
        let a = crate::resolve_or_create_asset(db.conn(), "https://example.com", None).unwrap();
        let b = crate::resolve_or_create_asset(db.conn(), "https://example.com", None).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn separate_urls_get_separate_assets() {
        let db = Db::open_in_memory().unwrap();
        let a = crate::resolve_or_create_asset(db.conn(), "https://a.example", None).unwrap();
        let b = crate::resolve_or_create_asset(db.conn(), "https://b.example", None).unwrap();
        assert_ne!(a, b);
    }
}
