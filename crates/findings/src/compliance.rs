//! Compliance control mapping (Wave 4.3.1 / §5.1).
//!
//! Maps real findings onto framework controls so compliance posture is derived
//! from measurement rather than asserted.
//!
//! ## Three deliberate constraints
//!
//! 1. **Control text is not embedded.** CIS, NIST 800-53 and OWASP ASVS are
//!    licensed normative documents. This crate stores control identifiers and
//!    short operator-written summaries only. Full normative text must come from
//!    a licensed source at integration time.
//! 2. **No control is invented.** A control appears only if it is listed here.
//!    Unmapped findings suppress the readiness score rather than defaulting to
//!    a guess.
//! 3. **Mappings carry confidence.** ATT&CK and framework mappings derived
//!    from knowledge rather than a normative lookup are marked accordingly, and
//!    the report says so.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A control within a framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    /// Operator-written summary. Not normative text.
    pub summary: String,
}

/// A framework and the controls this build knows about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Framework {
    pub id: String,
    pub name: String,
    pub version: String,
    /// False when only part of the framework is modelled.
    pub complete: bool,
    pub controls: Vec<Control>,
}

/// OWASP Top 10 (2021) categories.
pub mod owasp_top10_2021 {
    pub const A01: &str = "A01:2021-Broken Access Control";
    pub const A02: &str = "A02:2021-Cryptographic Failures";
    pub const A03: &str = "A03:2021-Injection";
    pub const A04: &str = "A04:2021-Insecure Design";
    pub const A05: &str = "A05:2021-Security Misconfiguration";
    pub const A06: &str = "A06:2021-Vulnerable and Outdated Components";
    pub const A07: &str = "A07:2021-Identification and Authentication Failures";
    pub const A08: &str = "A08:2021-Software and Data Integrity Failures";
    pub const A09: &str = "A09:2021-Security Logging and Monitoring Failures";
    pub const A10: &str = "A10:2021-Server-Side Request Forgery";
}

/// How much to trust a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Normative crosswalk consulted.
    High,
    /// Mapped from operator knowledge; verify before reporting externally.
    Medium,
}

/// Map a CWE to OWASP Top 10 (2021) categories.
///
/// Returns empty for CWEs with no confident mapping. Every CWE the scanner can
/// emit is classified, so an unmapped CWE is always a deliberate decision.
pub fn owasp_categories_for_cwe(cwe: &str) -> &'static [&'static str] {
    // Normalise "CWE-89" / "89" / "cwe-89".
    let id = cwe
        .trim()
        .trim_start_matches("CWE-")
        .trim_start_matches("cwe-");

    match id {
        // Access control.
        "22" => &[owasp_top10_2021::A01],   // Path Traversal
        "200" => &[owasp_top10_2021::A01],  // Exposure of Sensitive Information
        "285" => &[owasp_top10_2021::A01],  // Improper Authorization
        "639" => &[owasp_top10_2021::A01],  // Insecure Authorization (BOLA)
        "601" => &[owasp_top10_2021::A01],  // Open Redirect
        "1021" => &[owasp_top10_2021::A01], // Clickjacking (UI layer restriction)
        "352" => &[owasp_top10_2021::A01],  // CSRF
        "93" => &[owasp_top10_2021::A01],   // CRLF Injection

        // Cryptography.
        "311" | "319" | "327" | "325" => &[owasp_top10_2021::A02],
        "295" => &[owasp_top10_2021::A02], // Improper Certificate Validation
        "614" => &[owasp_top10_2021::A02], // Sensitive Cookie Without Secure Flag
        "615" => &[owasp_top10_2021::A02], // Sensitive Cookie Without HttpOnly

        // Injection.
        "89" => &[owasp_top10_2021::A03],  // SQL Injection
        "79" => &[owasp_top10_2021::A03],  // XSS
        "77" => &[owasp_top10_2021::A03],  // Command Injection
        "94" => &[owasp_top10_2021::A03],  // Code Injection
        "98" => &[owasp_top10_2021::A03],  // PHP File Inclusion
        "611" => &[owasp_top10_2021::A03], // XXE
        "943" => &[owasp_top10_2021::A03], // Improper Neutralization in Data Query Logic

        // Insecure design.
        "770" => &[owasp_top10_2021::A04], // Allocation Without Limits (rate limiting)
        "20" => &[owasp_top10_2021::A04],  // Improper Input Validation

        // Misconfiguration.
        "942" => &[owasp_top10_2021::A05],  // Permissive CORS
        "548" => &[owasp_top10_2021::A05],  // Exposure Through Directory Listing
        "538" => &[owasp_top10_2021::A05],  // Sensitive File in Temp Directory
        "530" => &[owasp_top10_2021::A05],  // Exposure of Backup File
        "1004" => &[owasp_top10_2021::A05], // Sensitive Cookie Without HttpOnly (cookie variant)
        "525" => &[owasp_top10_2021::A05],  // Use of Web Browser Cache
        "598" => &[owasp_top10_2021::A05], // Use of GET Request Method With Sensitive Query Strings
        "693" => &[owasp_top10_2021::A05], // Protection Mechanism Failure

        // Components. CWE-1104 (unmaintained third-party components) is the
        // canonical A06 mapping; it previously duplicated an A05 arm.
        "1035" | "1104" | "937" => &[owasp_top10_2021::A06],

        // Authentication.
        "306" => &[owasp_top10_2021::A07], // Missing Authentication for Critical Function
        "798" => &[owasp_top10_2021::A07], // Use of Hard-coded Credentials

        // Integrity.
        "353" => &[owasp_top10_2021::A08], // Missing Support for Integrity Check
        "494" => &[owasp_top10_2021::A08], // Download of Code Without Integrity Check
        "915" => &[owasp_top10_2021::A08], // Improperly Controlled Modification of Dynamically-Determined Object Attributes

        // Other: no confident single category.
        _ => &[],
    }
}

/// Confidence in the mapping quality for this build.
pub const MAPPING_CONFIDENCE: Confidence = Confidence::Medium;

/// OWASP Top 10 (2021) as modelled by this build.
pub fn owasp_top10() -> Framework {
    Framework {
        id: "owasp-top-10-2021".to_string(),
        name: "OWASP Top 10".to_string(),
        version: "2021".to_string(),
        complete: true,
        controls: vec![
            Control { id: owasp_top10_2021::A01.into(), title: "Broken Access Control".into(),
                summary: "Access controls enforce policy so users cannot act outside their intended permissions.".into() },
            Control { id: owasp_top10_2021::A02.into(), title: "Cryptographic Failures".into(),
                summary: "Data in transit and at rest is protected with algorithms and protocols that are not obsolete.".into() },
            Control { id: owasp_top10_2021::A03.into(), title: "Injection".into(),
                summary: "User-supplied input is treated as data, never as code or structure.".into() },
            Control { id: owasp_top10_2021::A04.into(), title: "Insecure Design".into(),
                summary: "The application design accounts for abuse cases, including resource and rate limits.".into() },
            Control { id: owasp_top10_2021::A05.into(), title: "Security Misconfiguration".into(),
                summary: "Secure defaults, hardened configuration, and no information disclosure through diagnostics.".into() },
            Control { id: owasp_top10_2021::A06.into(), title: "Vulnerable and Outdated Components".into(),
                summary: "Components are inventoried, supported, and patched against known vulnerabilities.".into() },
            Control { id: owasp_top10_2021::A07.into(), title: "Identification and Authentication Failures".into(),
                summary: "Authentication is enforced on every privileged path, with credentials handled correctly.".into() },
            Control { id: owasp_top10_2021::A08.into(), title: "Software and Data Integrity Failures".into(),
                summary: "Code and data integrity is verified before use, including updates and deserialization.".into() },
            Control { id: owasp_top10_2021::A09.into(), title: "Security Logging and Monitoring Failures".into(),
                summary: "Security-relevant events are logged, integrity-protected, and monitored.".into() },
            Control { id: owasp_top10_2021::A10.into(), title: "Server-Side Request Forgery".into(),
                summary: "Server-side fetches validate destination against an allow-list.".into() },
        ],
    }
}

/// Frameworks this build can actually evaluate.
///
/// §9.1 lists 13 frameworks. Only OWASP Top 10 is modelled here; the rest are
/// reported as unavailable rather than approximated, because an approximate
/// compliance score is indistinguishable from a real one and is worse.
pub fn available_frameworks() -> Vec<Framework> {
    vec![owasp_top10()]
}

/// Frameworks named in the spec but not yet modelled.
pub const SPEC_FRAMEWORKS_PENDING: &[&str] = &[
    "OWASP ASVS",
    "PCI-DSS v4.0",
    "SOC 2 Trust Services Criteria",
    "ISO 27001 Annex A",
    "NIST CSF",
    "NIST 800-53",
    "HIPAA Security Rule",
    "GDPR Articles 32-36",
    "CCPA",
    "FedRAMP",
    "CIS Controls v8",
];

/// Result of evaluating findings against a framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAssessment {
    pub framework_id: String,
    /// Findings mapped to this control.
    pub open_findings: i64,
    pub severity_breakdown: std::collections::BTreeMap<String, i64>,
    /// Findings that could not be attributed to any control.
    pub unmapped_findings: i64,
    /// Controls with at least one finding (i.e. observed weaknesses).
    pub controls_with_findings: Vec<String>,
    /// Controls with no observed findings. NOT proof of compliance: the
    /// scanner only exercises the checks it implements.
    pub controls_without_findings: Vec<String>,
    /// Only populated when every finding was attributable AND the framework is
    /// fully modelled. Otherwise None.
    pub readiness_score: Option<f64>,
    pub complete: bool,
    pub notes: Vec<String>,
}

impl ControlAssessment {
    pub fn describe(&self) -> String {
        if let Some(score) = self.readiness_score {
            return format!(
                "{}: {} control(s) with findings, readiness {:.0}%",
                self.framework_id,
                self.controls_with_findings.len(),
                score
            );
        }
        format!(
            "{}: {} control(s) with findings, {} finding(s) unmapped -- no score reported",
            self.framework_id,
            self.controls_with_findings.len(),
            self.unmapped_findings
        )
    }
}

/// One finding reduced to what the mapper needs.
#[derive(Debug, Clone)]
pub struct FindingProjection {
    pub id: String,
    pub cwe_id: Option<String>,
    pub severity: String,
    /// Workflow status: new, confirmed, false_positive, remediated, accepted.
    pub status: String,
    /// False positives and accepted risks are excluded from the posture.
    pub counts_against_posture: bool,
    pub created_at: String,
    pub updated_at: String,
    pub asset_id: Option<String>,
}

/// Evaluate findings against a framework.
pub fn assess(framework: &Framework, findings: &[FindingProjection]) -> ControlAssessment {
    let mut with_findings: BTreeSet<String> = BTreeSet::new();
    let mut breakdown: std::collections::BTreeMap<String, i64> = Default::default();
    let mut unmapped = 0i64;

    for f in findings.iter().filter(|f| f.counts_against_posture) {
        let cwe = match &f.cwe_id {
            Some(c) if !c.trim().is_empty() => c,
            _ => {
                unmapped += 1;
                continue;
            }
        };

        let categories = owasp_categories_for_cwe(cwe);
        if categories.is_empty() {
            unmapped += 1;
            continue;
        }

        for cat in categories {
            with_findings.insert((*cat).to_string());
            *breakdown.entry((*cat).to_string()).or_insert(0) += 1;
        }
    }

    let all_controls: BTreeSet<String> = framework.controls.iter().map(|c| c.id.clone()).collect();
    let without: Vec<String> = all_controls.difference(&with_findings).cloned().collect();

    let complete = unmapped == 0 && framework.complete;
    let readiness = if complete && !framework.controls.is_empty() {
        let failing = with_findings.len() as f64;
        Some(
            ((framework.controls.len() as f64 - failing) / framework.controls.len() as f64) * 100.0,
        )
    } else {
        None
    };

    let mut notes = vec![format!(
        "Controls without findings are NOT evidence of compliance: the scanner exercises only \
         the checks it implements."
    )];
    if MAPPING_CONFIDENCE == Confidence::Medium {
        notes.push(
            "CWE-to-category mappings are derived from operator knowledge, not a normative \
             crosswalk. Verify before reporting externally."
                .to_string(),
        );
    }
    if !framework.complete {
        notes.push(format!(
            "Only part of {} is modelled in this build.",
            framework.name
        ));
    }

    ControlAssessment {
        framework_id: framework.id.clone(),
        open_findings: findings.iter().filter(|f| f.counts_against_posture).count() as i64,
        severity_breakdown: breakdown,
        unmapped_findings: unmapped,
        controls_with_findings: with_findings.into_iter().collect(),
        controls_without_findings: without,
        readiness_score: readiness,
        complete,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(cwe: Option<&str>, sev: &str, counts: bool) -> FindingProjection {
        FindingProjection {
            id: "f1".into(),
            cwe_id: cwe.map(|s| s.to_string()),
            severity: sev.into(),
            status: if counts {
                "new".into()
            } else {
                "false_positive".into()
            },
            counts_against_posture: counts,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            asset_id: None,
        }
    }

    #[test]
    fn sqli_maps_to_injection() {
        assert_eq!(owasp_categories_for_cwe("CWE-89"), &[owasp_top10_2021::A03]);
    }

    #[test]
    fn cwe_formatting_variants_all_parse() {
        for variant in ["CWE-89", "cwe-89", "89"] {
            assert_eq!(
                owasp_categories_for_cwe(variant),
                &[owasp_top10_2021::A03],
                "{variant} should parse"
            );
        }
    }

    #[test]
    fn xss_and_sqli_share_the_injection_category() {
        // Both are injection, so they legitimately collapse to the same
        // category. They must still land there, not under access control.
        assert_eq!(owasp_categories_for_cwe("CWE-79"), &[owasp_top10_2021::A03]);
        assert_eq!(owasp_categories_for_cwe("CWE-89"), &[owasp_top10_2021::A03]);
    }

    #[test]
    fn traversal_lands_under_access_control_not_injection() {
        assert_eq!(owasp_categories_for_cwe("CWE-22"), &[owasp_top10_2021::A01]);
    }

    #[test]
    fn unknown_cwe_is_unmapped_not_guessed() {
        assert!(owasp_categories_for_cwe("CWE-99999").is_empty());
        assert!(owasp_categories_for_cwe("").is_empty());
    }

    #[test]
    fn every_scanner_cwe_is_classified_or_deliberate() {
        // The CWEs the scanner actually emits.
        let emitted = [
            "CWE-1004", "CWE-1021", "CWE-1104", "CWE-20", "CWE-200", "CWE-22", "CWE-285",
            "CWE-295", "CWE-306", "CWE-319", "CWE-327", "CWE-352", "CWE-353", "CWE-444", "CWE-525",
            "CWE-530", "CWE-538", "CWE-548", "CWE-598", "CWE-601", "CWE-611", "CWE-614", "CWE-615",
            "CWE-639", "CWE-644", "CWE-650", "CWE-693", "CWE-749", "CWE-77", "CWE-770", "CWE-79",
            "CWE-89", "CWE-915", "CWE-93", "CWE-94", "CWE-942", "CWE-943", "CWE-98",
        ];

        // Deliberately unmapped: no single OWASP category applies confidently.
        let deliberate = ["CWE-444", "CWE-644", "CWE-650", "CWE-749"];

        for cwe in emitted {
            let mapped = !owasp_categories_for_cwe(cwe).is_empty();
            assert!(
                mapped || deliberate.contains(&cwe),
                "{cwe} is neither mapped nor listed as deliberately unmapped"
            );
        }
    }

    #[test]
    fn unmapped_finding_suppresses_readiness_score() {
        let fw = owasp_top10();
        let findings = vec![
            f(Some("CWE-89"), "CRITICAL", true),
            f(Some("CWE-99999"), "HIGH", true),
        ];
        let a = assess(&fw, &findings);
        assert!(!a.complete);
        assert_eq!(a.readiness_score, None, "no score over a partial mapping");
        assert_eq!(a.unmapped_findings, 1);
        assert!(a.describe().contains("no score"));
    }

    #[test]
    fn fully_mapped_posture_reports_a_score() {
        let fw = owasp_top10();
        let findings = vec![f(Some("CWE-89"), "CRITICAL", true)];
        let a = assess(&fw, &findings);
        assert!(a.complete);
        assert_eq!(a.readiness_score, Some(90.0), "1 of 10 categories failing");
        assert_eq!(a.controls_with_findings, vec![owasp_top10_2021::A03]);
        assert_eq!(a.controls_without_findings.len(), 9);
    }

    #[test]
    fn false_positives_do_not_count_against_posture() {
        let fw = owasp_top10();
        let findings = vec![f(Some("CWE-89"), "CRITICAL", false)];
        let a = assess(&fw, &findings);
        assert_eq!(a.open_findings, 0);
        assert!(a.controls_with_findings.is_empty());
        assert_eq!(a.readiness_score, Some(100.0));
    }

    #[test]
    fn finding_without_cwe_counts_as_unmapped() {
        let fw = owasp_top10();
        let a = assess(&fw, &[f(None, "LOW", true)]);
        assert_eq!(a.unmapped_findings, 1);
        assert_eq!(a.readiness_score, None);
    }

    #[test]
    fn no_findings_is_complete_and_perfectly_scored() {
        let fw = owasp_top10();
        let a = assess(&fw, &[]);
        assert!(a.complete);
        assert_eq!(a.readiness_score, Some(100.0));
    }

    #[test]
    fn clean_absence_never_claims_compliance() {
        // The note must always be present: zero findings is not a clean bill.
        let a = assess(&owasp_top10(), &[]);
        assert!(a
            .notes
            .iter()
            .any(|n| n.contains("NOT evidence of compliance")));
        assert!(a
            .notes
            .iter()
            .any(|n| n.contains("Verify before reporting")));
    }

    #[test]
    fn pending_frameworks_are_declared_not_faked() {
        // §5.1 names 13; we model 1 and declare the rest rather than guess.
        assert_eq!(SPEC_FRAMEWORKS_PENDING.len(), 11);
        assert_eq!(available_frameworks().len(), 1);
        assert!(SPEC_FRAMEWORKS_PENDING.contains(&"NIST 800-53"));
    }
}
