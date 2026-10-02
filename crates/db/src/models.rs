//! Domain models shared across crates.
//!
//! `Finding` previously existed in four or more incompatible shapes (in
//! `scanner`, `os-pentest`, `mobile`, `cloud`, `web3`). This is the single
//! converged shape; per-module detail belongs in `evidence`.

use serde::{Deserialize, Serialize};

/// Role in the access model. See D0.1 - enterprise-grade requires least privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
    Auditor,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Viewer => "viewer",
            Role::Auditor => "auditor",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "operator" => Ok(Role::Operator),
            "viewer" => Ok(Role::Viewer),
            "auditor" => Ok(Role::Auditor),
            other => Err(format!("unknown role: {}", other)),
        }
    }
}

/// An operator identity. Single-operator deployments still record one, so audit
/// entries always have a resolvable actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub role: Role,
    pub created_at: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetType {
    Domain,
    Ip,
    Range,
    App,
    CloudAccount,
    Repo,
    Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Production,
    Staging,
    Development,
    Test,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Criticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Criticality::Critical => "critical",
            Criticality::High => "high",
            Criticality::Medium => "medium",
            Criticality::Low => "low",
        };
        write!(f, "{}", s)
    }
}

/// A scannable or tracked target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub name: String,
    pub asset_type: AssetType,
    pub url: Option<String>,
    pub ip_addresses: Vec<String>,
    pub tags: Vec<String>,
    pub owner: Option<String>,
    pub environment: Environment,
    pub criticality: Criticality,
    pub auth_profile_ids: Vec<String>,
    pub compliance_scope: Vec<String>,
    pub metadata: serde_json::Value,
    pub created_at: String,
    pub updated_at: String,
    pub last_scan: Option<String>,
    pub risk_score: Option<f64>,
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Ok(Severity::Critical),
            "HIGH" => Ok(Severity::High),
            "MEDIUM" => Ok(Severity::Medium),
            "LOW" => Ok(Severity::Low),
            "INFO" => Ok(Severity::Info),
            other => Err(format!("unknown severity: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    New,
    Confirmed,
    FalsePositive,
    Remediated,
    Accepted,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FindingStatus::New => "new",
            FindingStatus::Confirmed => "confirmed",
            FindingStatus::FalsePositive => "false_positive",
            FindingStatus::Remediated => "remediated",
            FindingStatus::Accepted => "accepted",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for FindingStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "new" => Ok(FindingStatus::New),
            "confirmed" => Ok(FindingStatus::Confirmed),
            "false_positive" | "falsepositive" => Ok(FindingStatus::FalsePositive),
            "remediated" => Ok(FindingStatus::Remediated),
            "accepted" => Ok(FindingStatus::Accepted),
            other => Err(format!("unknown finding status: {}", other)),
        }
    }
}

/// Supporting evidence captured for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub description: String,
    pub data: Option<String>,
    pub captured_at: String,
}

/// The converged finding shape used by every module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scan_id: Option<String>,
    pub asset_id: Option<String>,
    pub title: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub category: String,
    pub cwe_id: Option<String>,
    pub cve_ids: Vec<String>,
    pub cvss_score: Option<f64>,
    pub description: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub assignee: Option<String>,
    pub due_date: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub user_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn severity_round_trips_through_string() {
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            assert_eq!(Severity::from_str(&sev.to_string()).unwrap(), sev);
        }
    }

    #[test]
    fn severity_parse_is_case_insensitive() {
        assert_eq!(Severity::from_str("critical").unwrap(), Severity::Critical);
        assert_eq!(Severity::from_str("HiGh").unwrap(), Severity::High);
    }

    #[test]
    fn severity_orders_by_risk() {
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn finding_status_accepts_both_spellings() {
        assert_eq!(
            FindingStatus::from_str("false_positive").unwrap(),
            FindingStatus::FalsePositive
        );
        assert_eq!(
            FindingStatus::from_str("FalsePositive").unwrap(),
            FindingStatus::FalsePositive
        );
    }

    #[test]
    fn unknown_values_are_rejected_not_defaulted() {
        // Defaulting an unknown severity would silently mis-rank a finding.
        assert!(Severity::from_str("catastrophic").is_err());
        assert!(FindingStatus::from_str("maybe").is_err());
        assert!("superuser".parse::<Role>().is_err());
    }

    #[test]
    fn finding_serialises_with_expected_field_names() {
        let finding = Finding {
            id: "f1".into(),
            scan_id: Some("s1".into()),
            asset_id: None,
            title: "SQL injection".into(),
            severity: Severity::Critical,
            status: FindingStatus::New,
            category: "web".into(),
            cwe_id: Some("CWE-89".into()),
            cve_ids: vec!["CVE-2024-0001".into()],
            cvss_score: Some(9.8),
            description: "d".into(),
            remediation: "r".into(),
            references: vec![],
            mitre_techniques: vec!["T1190".into()],
            evidence: vec![],
            assignee: None,
            due_date: None,
            created_at: "now".into(),
            updated_at: "now".into(),
            user_id: None,
        };

        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["severity"], "CRITICAL");
        assert_eq!(json["status"], "new");
        assert_eq!(json["cve_ids"][0], "CVE-2024-0001");
        assert_eq!(json["mitre_techniques"][0], "T1190");
    }
}
