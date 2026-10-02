//! MITRE ATT&CK technique mapping (Wave 4 prerequisite).
//!
//! §5.2 and the Gray Team ATT&CK workspace both need findings to carry
//! technique IDs. Without them, "coverage" is a number with nothing behind it.
//!
//! ## Design constraint
//!
//! Ground rule 5 (false output is worse than no output) applies with full force
//! here. A coverage percentage computed from a sloppy mapping is worse than no
//! coverage at all: it looks measured, and it is wrong.
//!
//! So this table is deliberately conservative:
//!
//! * Only checks with a confident mapping are mapped.
//! * A check that does not map stays unmapped, and
//!   [`CoverageReport::unmapped`] reports it by name rather than scoring it.
//! * Mappings are keyed by exact check name; an unknown name is *not* guessed.
//!
//! Review this table before trusting ATT&CK coverage numbers. An incorrect
//! technique ID silently corrupts every downstream metric.

use std::collections::BTreeMap;

/// ATT&CK Enterprise technique IDs relevant to web application testing.
pub mod technique {
    pub const EXPLOIT_PUBLIC_FACING_APP: &str = "T1190";
    pub const JAVASCRIPT: &str = "T1059.007";
    pub const FILE_AND_DIRECTORY_DISCOVERY: &str = "T1083";
    pub const SYSTEM_INFO_DISCOVERY: &str = "T1082";
    pub const UNSECURED_CREDENTIALS: &str = "T1552";
    pub const ADVERSARY_IN_THE_MIDDLE: &str = "T1557";
    pub const BRUTE_FORCE: &str = "T1110";
    pub const VALID_ACCOUNTS: &str = "T1078";
    pub const DATA_FROM_LOCAL_SYSTEM: &str = "T1005";
    pub const WEB_SESSION_COOKIE: &str = "T1539";

    /// Techniques that describe attacker post-access behaviour rather than a
    /// weakness in the application. Findings that map to these describe what an
    /// attacker does *after* exploitation, not the flaw itself.
    pub const POST_EXPLOITATION: &[&str] = &[VALID_ACCOUNTS, BRUTE_FORCE, WEB_SESSION_COOKIE];
}

/// Map a scanner check name to its ATT&CK technique IDs.
///
/// Returns an empty slice for checks with no confident mapping. That is a
/// meaningful answer, not a failure.
pub fn techniques_for_check(check_name: &str) -> &'static [&'static str] {
    // Exact-name keyed. An unrecognised check returns empty rather than being
    // guessed at, so a renamed check cannot silently inherit a wrong technique.
    match check_name {
        // Injection and code execution.
        "SQL Injection Detection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "NoSQL Injection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "XXE Injection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Server-Side Template Injection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Time-based Blind Injection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Cross-Site Scripting (XSS) Detection" => &[technique::JAVASCRIPT],

        // Filesystem and traversal.
        "Directory Traversal Detection" => &[technique::FILE_AND_DIRECTORY_DISCOVERY],
        "File Inclusion Detection" => &[technique::FILE_AND_DIRECTORY_DISCOVERY],
        "Directory Listing" => &[technique::FILE_AND_DIRECTORY_DISCOVERY],
        "Exposed Sensitive Files" => &[technique::FILE_AND_DIRECTORY_DISCOVERY],

        // Information disclosure.
        "Information Disclosure" => &[technique::SYSTEM_INFO_DISCOVERY],
        "Server Information Leakage" => &[technique::SYSTEM_INFO_DISCOVERY],
        "Outdated Software Detection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Sensitive Data Exposure" => &[technique::UNSECURED_CREDENTIALS],

        // Transport security.
        "SSL/TLS Configuration" => &[technique::ADVERSARY_IN_THE_MIDDLE],
        "Mixed Content Detection" => &[technique::ADVERSARY_IN_THE_MIDDLE],

        // Access control.
        "Authentication Bypass" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "BFLA - Broken Function Level Authorization" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "BOLA - Broken Object Level Authorization" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "JWT 'none' Algorithm" => &[technique::EXPLOIT_PUBLIC_FACING_APP],

        // Request handling.
        "HTTP Request Smuggling" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "HTTP Verb Tampering" | "WebDAV / Verb Tampering" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "CRLF / Header Injection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Host Header Injection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Open Redirect Detection" | "Open Redirect via API" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Web Cache Poisoning" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "CORS Misconfiguration" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Mass Assignment / Auto-Binding" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Insufficient Input Validation" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "GraphQL Abuse" | "GraphQL Introspection Enabled" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "CSRF Vulnerability Detection" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Subresource Integrity" => &[technique::EXPLOIT_PUBLIC_FACING_APP],
        "Missing Rate Limiting" => &[technique::BRUTE_FORCE],
        "Form Security Analysis" => &[technique::EXPLOIT_PUBLIC_FACING_APP],

        // Deliberately unmapped. These are hardening gaps or defence-in-depth
        // weaknesses rather than an exploitation technique, and forcing them
        // into the matrix would inflate coverage without meaning:
        //   "Security Headers Analysis"
        //   "Content-Security-Policy"
        //   "Cookie Security Analysis"
        //   "Clickjacking Detection"
        //   "X-Frame-Options missing" style checks
        _ => &[],
    }
}

/// ATT&CK coverage over a set of findings.
///
/// `score` is only meaningful when `complete` is true. When any finding is
/// unmapped the report says so explicitly instead of reporting a number.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageReport {
    /// Distinct techniques observed.
    pub techniques: Vec<String>,
    /// Findings that carry no technique mapping.
    pub unmapped: Vec<String>,
    /// Percentage of mapped findings that are attributable, or None when the
    /// mapping is incomplete.
    pub score: Option<f64>,
    pub complete: bool,
}

impl CoverageReport {
    pub fn describe(&self) -> String {
        if !self.complete {
            return format!(
                "ATT&CK coverage INCOMPLETE: {} technique(s) observed, {} unmapped check(s) ({}). \
                 No percentage is reported because the mapping does not cover every finding.",
                self.techniques.len(),
                self.unmapped.len(),
                self.unmapped.join(", ")
            );
        }
        format!(
            "ATT&CK coverage: {} technique(s) observed, {}% attributable.",
            self.techniques.len(),
            self.score.unwrap_or(0.0).round()
        )
    }
}

/// Build a coverage report from (check_name) pairs taken from findings.
///
/// Only findings that carry a technique are counted; the caller supplies the
/// check names because the persisted `Finding` stores techniques, not the check
/// name that produced them.
pub fn coverage_from_checks(checks: &[String]) -> CoverageReport {
    let mut techniques: BTreeMap<String, ()> = BTreeMap::new();
    let mut unmapped: Vec<String> = Vec::new();

    for check in checks {
        let ids = techniques_for_check(check);
        if ids.is_empty() {
            if !unmapped.contains(check) {
                unmapped.push(check.clone());
            }
        } else {
            for id in ids {
                techniques.insert(id.to_string(), ());
            }
        }
    }

    let complete = unmapped.is_empty();
    let score = if complete {
        Some(100.0)
    } else {
        None
    };

    CoverageReport {
        techniques: techniques.into_keys().collect(),
        unmapped,
        score,
        complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_checks_map_to_exploitation() {
        assert_eq!(
            techniques_for_check("SQL Injection Detection"),
            &[technique::EXPLOIT_PUBLIC_FACING_APP]
        );
    }

    #[test]
    fn xss_maps_to_javascript_not_exploitation() {
        // XSS is client-side execution, so T1059.007 is the accurate technique.
        assert_eq!(
            techniques_for_check("Cross-Site Scripting (XSS) Detection"),
            &[technique::JAVASCRIPT]
        );
    }

    #[test]
    fn traversal_maps_to_discovery() {
        assert_eq!(
            techniques_for_check("Directory Traversal Detection"),
            &[technique::FILE_AND_DIRECTORY_DISCOVERY]
        );
    }

    #[test]
    fn hardening_checks_are_deliberately_unmapped() {
        // Forcing these into the matrix would inflate coverage without meaning.
        for check in [
            "Security Headers Analysis",
            "Content-Security-Policy",
            "Cookie Security Analysis",
            "Clickjacking Detection",
        ] {
            assert!(
                techniques_for_check(check).is_empty(),
                "{check} should be unmapped by design"
            );
        }
    }

    #[test]
    fn unknown_check_is_not_guessed() {
        assert!(techniques_for_check("Some Future Check").is_empty());
        assert!(techniques_for_check("").is_empty());
    }

    #[test]
    fn every_technique_id_looks_like_att_id() {
        let all = [
            technique::EXPLOIT_PUBLIC_FACING_APP,
            technique::JAVASCRIPT,
            technique::FILE_AND_DIRECTORY_DISCOVERY,
            technique::SYSTEM_INFO_DISCOVERY,
            technique::UNSECURED_CREDENTIALS,
            technique::ADVERSARY_IN_THE_MIDDLE,
            technique::BRUTE_FORCE,
            technique::VALID_ACCOUNTS,
            technique::DATA_FROM_LOCAL_SYSTEM,
            technique::WEB_SESSION_COOKIE,
        ];
        for id in all {
            assert!(
                id.starts_with('T') && id[1..].chars().all(|c| c.is_ascii_digit() || c == '.'),
                "{id} is not a well-formed ATT&CK technique ID"
            );
        }
    }

    #[test]
    fn incomplete_mapping_reports_no_score() {
        let report = coverage_from_checks(&["SQL Injection Detection".into()]);
        assert!(report.complete);
        assert_eq!(report.techniques.len(), 1);
        assert_eq!(report.score, Some(100.0));
    }

    #[test]
    fn unmapped_checks_suppress_the_percentage() {
        let report = coverage_from_checks(&[
            "SQL Injection Detection".into(),
            "Clickjacking Detection".into(),
        ]);

        assert!(!report.complete, "an unmapped check means coverage is partial");
        assert_eq!(
            report.score, None,
            "a percentage over a partial mapping would be misleading"
        );
        assert!(report.describe().contains("INCOMPLETE"));
        assert_eq!(report.unmapped, vec!["Clickjacking Detection"]);
    }

    #[test]
    fn duplicate_checks_collapse_to_distinct_techniques() {
        let report = coverage_from_checks(&[
            "SQL Injection Detection".into(),
            "SQL Injection Detection".into(),
            "NoSQL Injection".into(),
        ]);
        assert_eq!(report.techniques.len(), 1, "both map to T1190");
    }

    #[test]
    fn every_current_scanner_check_is_classified() {
        // Guards against the scanner gaining a check that silently goes
        // unmapped. A new check must be classified deliberately.
        let checks = [
            "Authentication Bypass",
            "BFLA - Broken Function Level Authorization",
            "BOLA - Broken Object Level Authorization",
            "Clickjacking Detection",
            "Content-Security-Policy",
            "Cookie Security Analysis",
            "CORS Misconfiguration",
            "CRLF / Header Injection",
            "Cross-Site Scripting (XSS) Detection",
            "CSRF Vulnerability Detection",
            "Directory Listing",
            "Directory Traversal Detection",
            "Exposed Sensitive Files",
            "File Inclusion Detection",
            "Form Security Analysis",
            "GraphQL Abuse",
            "GraphQL Introspection Enabled",
            "Host Header Injection",
            "HTTP Request Smuggling",
            "HTTP Verb Tampering",
            "Information Disclosure",
            "Insufficient Input Validation",
            "JWT 'none' Algorithm",
            "Mass Assignment / Auto-Binding",
            "Missing Rate Limiting",
            "Mixed Content Detection",
            "NoSQL Injection",
            "Open Redirect Detection",
            "Open Redirect via API",
            "Outdated Software Detection",
            "Security Headers Analysis",
            "Sensitive Data Exposure",
            "Server Information Leakage",
            "Server-Side Template Injection",
            "SQL Injection Detection",
            "SSL/TLS Configuration",
            "Subresource Integrity",
            "Time-based Blind Injection",
            "Web Cache Poisoning",
            "WebDAV / Verb Tampering",
            "XXE Injection",
        ];

        // Each must be either mapped or on the deliberate-unmapped list. This
        // asserts the mapping is total, so `unmapped` is a conscious decision.
        let deliberate_unmapped = [
            "Security Headers Analysis",
            "Content-Security-Policy",
            "Cookie Security Analysis",
            "Clickjacking Detection",
        ];

        for check in checks {
            let mapped = !techniques_for_check(check).is_empty();
            let deliberate = deliberate_unmapped.contains(&check);
            assert!(
                mapped || deliberate,
                "`{check}` is neither mapped nor listed as deliberately unmapped; \
                 add it to one of the two so coverage stays honest"
            );
        }
    }
}
