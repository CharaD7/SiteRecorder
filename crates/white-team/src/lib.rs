use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum WhiteTeamError {
    #[error("Error: {0}")]
    Error(String),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
}

type Result<T> = std::result::Result<T, WhiteTeamError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub categories: Vec<ComplianceCategory>,
    pub overall_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCategory {
    pub id: String,
    pub name: String,
    pub description: String,
    pub controls: Vec<Control>,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub name: String,
    pub description: String,
    pub status: ControlStatus,
    pub evidence: Vec<String>,
    pub gaps: Vec<String>,
    pub owner: String,
    pub due_date: Option<String>,
    pub completed_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ControlStatus {
    NotStarted,
    InProgress,
    Implemented,
    NotApplicable,
    Failed,
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlStatus::NotStarted => write!(f, "Not Started"),
            ControlStatus::InProgress => write!(f, "In Progress"),
            ControlStatus::Implemented => write!(f, "Implemented"),
            ControlStatus::NotApplicable => write!(f, "N/A"),
            ControlStatus::Failed => write!(f, "Failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskRegister {
    pub id: String,
    pub name: String,
    pub description: String,
    pub risks: Vec<Risk>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: RiskCategory,
    pub likelihood: RiskLikelihood,
    pub impact: RiskImpact,
    pub risk_score: f64,
    pub inherent_score: f64,
    pub residual_score: f64,
    pub treatment: RiskTreatment,
    pub owner: String,
    pub status: RiskStatus,
    pub mitigations: Vec<String>,
    pub review_date: String,
    pub related_controls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskCategory {
    Strategic,
    Operational,
    Financial,
    Compliance,
    Technology,
    Reputational,
    Cyber,
    Legal,
}

impl std::fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskCategory::Strategic => write!(f, "Strategic"),
            RiskCategory::Operational => write!(f, "Operational"),
            RiskCategory::Financial => write!(f, "Financial"),
            RiskCategory::Compliance => write!(f, "Compliance"),
            RiskCategory::Technology => write!(f, "Technology"),
            RiskCategory::Reputational => write!(f, "Reputational"),
            RiskCategory::Cyber => write!(f, "Cyber"),
            RiskCategory::Legal => write!(f, "Legal"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLikelihood {
    Rare,
    Unlikely,
    Possible,
    Likely,
    AlmostCertain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskImpact {
    Negligible,
    Minor,
    Moderate,
    Major,
    Catastrophic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskTreatment {
    Avoid,
    Mitigate,
    Transfer,
    Accept,
}

impl std::fmt::Display for RiskTreatment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskTreatment::Avoid => write!(f, "Avoid"),
            RiskTreatment::Mitigate => write!(f, "Mitigate"),
            RiskTreatment::Transfer => write!(f, "Transfer"),
            RiskTreatment::Accept => write!(f, "Accept"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskStatus {
    Open,
    Assessed,
    Treating,
    Monitored,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: PolicyCategory,
    pub status: PolicyStatus,
    pub version: String,
    pub owner: String,
    pub approved_by: Option<String>,
    pub effective_date: String,
    pub review_date: String,
    pub content: String,
    pub acknowledgments: Vec<Acknowledgment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyCategory {
    InformationSecurity,
    AcceptableUse,
    DataProtection,
    AccessControl,
    IncidentResponse,
    BusinessContinuity,
    VendorManagement,
    HR,
    Other,
}

impl std::fmt::Display for PolicyCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyCategory::InformationSecurity => write!(f, "Information Security"),
            PolicyCategory::AcceptableUse => write!(f, "Acceptable Use"),
            PolicyCategory::DataProtection => write!(f, "Data Protection"),
            PolicyCategory::AccessControl => write!(f, "Access Control"),
            PolicyCategory::IncidentResponse => write!(f, "Incident Response"),
            PolicyCategory::BusinessContinuity => write!(f, "Business Continuity"),
            PolicyCategory::VendorManagement => write!(f, "Vendor Management"),
            PolicyCategory::HR => write!(f, "Human Resources"),
            PolicyCategory::Other => write!(f, "Other"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyStatus {
    Draft,
    UnderReview,
    Approved,
    Published,
    Archived,
    Superseded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acknowledgment {
    pub user_id: String,
    pub user_name: String,
    pub acknowledged_at: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vendor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tier: VendorTier,
    pub risk_level: VendorRiskLevel,
    pub status: VendorStatus,
    pub contact_email: String,
    pub contract_start: String,
    pub contract_end: String,
    pub services: Vec<String>,
    pub data_access: Vec<String>,
    pub assessments: Vec<VendorAssessment>,
    pub documents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VendorTier {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VendorRiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for VendorRiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VendorRiskLevel::Critical => write!(f, "Critical"),
            VendorRiskLevel::High => write!(f, "High"),
            VendorRiskLevel::Medium => write!(f, "Medium"),
            VendorRiskLevel::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VendorStatus {
    Active,
    UnderReview,
    PendingAssessment,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorAssessment {
    pub id: String,
    pub assessment_date: String,
    pub assessor: String,
    pub score: f64,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub next_assessment_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingModule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: TrainingCategory,
    pub duration_minutes: u32,
    pub required: bool,
    pub completion_rate: f64,
    pub enrollments: Vec<TrainingEnrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrainingCategory {
    SecurityAwareness,
    Phishing,
    DataProtection,
    Compliance,
    IncidentResponse,
    SecureCoding,
    Privacy,
}

impl std::fmt::Display for TrainingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrainingCategory::SecurityAwareness => write!(f, "Security Awareness"),
            TrainingCategory::Phishing => write!(f, "Phishing"),
            TrainingCategory::DataProtection => write!(f, "Data Protection"),
            TrainingCategory::Compliance => write!(f, "Compliance"),
            TrainingCategory::IncidentResponse => write!(f, "Incident Response"),
            TrainingCategory::SecureCoding => write!(f, "Secure Coding"),
            TrainingCategory::Privacy => write!(f, "Privacy"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingEnrollment {
    pub user_id: String,
    pub user_name: String,
    pub enrolled_at: String,
    pub completed_at: Option<String>,
    pub score: Option<f64>,
    pub status: EnrollmentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnrollmentStatus {
    Enrolled,
    InProgress,
    Completed,
    Overdue,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrcDashboard {
    pub compliance_score: f64,
    pub open_risks: usize,
    pub critical_risks: usize,
    pub policy_compliance_rate: f64,
    pub vendor_risk_score: f64,
    pub training_completion_rate: f64,
    pub overdue_items: usize,
    pub upcoming_reviews: usize,
    pub frameworks: Vec<FrameworkSummary>,
    pub risk_trend: Vec<RiskTrendPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSummary {
    pub name: String,
    pub score: f64,
    pub controls_total: usize,
    pub controls_passed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTrendPoint {
    pub date: String,
    pub open_count: usize,
    pub closed_count: usize,
    pub avg_score: f64,
}

pub struct WhiteTeam;

impl WhiteTeam {
    pub fn get_compliance_frameworks() -> Vec<ComplianceFramework> {
        vec![
            ComplianceFramework {
                id: "cis-v8".to_string(),
                name: "CIS Controls".to_string(),
                version: "v8".to_string(),
                description: "Center for Internet Security Critical Security Controls".to_string(),
                categories: vec![
                    ComplianceCategory {
                        id: "cis-ig1".to_string(),
                        name: "IG1 - Basic".to_string(),
                        description: "Essential cyber hygiene".to_string(),
                        controls: vec![
                            Control {
                                id: "CIS-1.1".to_string(),
                                name: "Inventory of Enterprise Assets".to_string(),
                                description: "Establish and maintain detailed inventory of enterprise assets.".to_string(),
                                status: ControlStatus::Implemented,
                                evidence: vec!["Asset inventory spreadsheet".to_string()],
                                gaps: vec![],
                                owner: "IT Team".to_string(),
                                due_date: None,
                                completed_date: Some("2024-01-15".to_string()),
                            },
                            Control {
                                id: "CIS-2.1".to_string(),
                                name: "Inventory of Software Assets".to_string(),
                                description: "Establish and maintain a software inventory.".to_string(),
                                status: ControlStatus::InProgress,
                                evidence: vec![],
                                gaps: vec!["Automated discovery needed".to_string()],
                                owner: "IT Team".to_string(),
                                due_date: Some("2024-12-31".to_string()),
                                completed_date: None,
                            },
                        ],
                        score: 75.0,
                    },
                ],
                overall_score: 72.0,
            },
            ComplianceFramework {
                id: "pci-dss-4".to_string(),
                name: "PCI DSS".to_string(),
                version: "v4.0".to_string(),
                description: "Payment Card Industry Data Security Standard".to_string(),
                categories: vec![
                    ComplianceCategory {
                        id: "pci-req1".to_string(),
                        name: "Network Security".to_string(),
                        description: "Install and maintain network security controls.".to_string(),
                        controls: vec![
                            Control {
                                id: "PCI-1.1".to_string(),
                                name: "Network Security Controls".to_string(),
                                description: "Processes and mechanisms for network security controls are defined.".to_string(),
                                status: ControlStatus::Implemented,
                                evidence: vec!["Firewall rules documented".to_string()],
                                gaps: vec![],
                                owner: "Security Team".to_string(),
                                due_date: None,
                                completed_date: Some("2024-02-01".to_string()),
                            },
                        ],
                        score: 85.0,
                    },
                ],
                overall_score: 82.0,
            },
            ComplianceFramework {
                id: "soc2".to_string(),
                name: "SOC 2".to_string(),
                version: "2017".to_string(),
                description: "Service Organization Control 2 - Trust Services Criteria".to_string(),
                categories: vec![
                    ComplianceCategory {
                        id: "soc2-cc".to_string(),
                        name: "Common Criteria".to_string(),
                        description: "Control environment and monitoring.".to_string(),
                        controls: vec![
                            Control {
                                id: "CC-1".to_string(),
                                name: "Control Environment".to_string(),
                                description: "Demonstrates commitment to integrity and ethical values.".to_string(),
                                status: ControlStatus::Implemented,
                                evidence: vec!["Code of conduct".to_string(), "Org chart".to_string()],
                                gaps: vec![],
                                owner: "Management".to_string(),
                                due_date: None,
                                completed_date: Some("2024-01-01".to_string()),
                            },
                        ],
                        score: 88.0,
                    },
                ],
                overall_score: 85.0,
            },
        ]
    }

    pub fn get_risk_register() -> RiskRegister {
        RiskRegister {
            id: Uuid::new_v4().to_string(),
            name: "Enterprise Risk Register".to_string(),
            description: "Organization-wide risk register".to_string(),
            risks: vec![
                Risk {
                    id: Uuid::new_v4().to_string(),
                    title: "Ransomware Attack".to_string(),
                    description: "Critical systems encrypted by ransomware leading to operational disruption.".to_string(),
                    category: RiskCategory::Cyber,
                    likelihood: RiskLikelihood::Possible,
                    impact: RiskImpact::Catastrophic,
                    risk_score: 20.0,
                    inherent_score: 25.0,
                    residual_score: 12.0,
                    treatment: RiskTreatment::Mitigate,
                    owner: "CISO".to_string(),
                    status: RiskStatus::Monitored,
                    mitigations: vec![
                        "Endpoint detection and response".to_string(),
                        "Regular offline backups".to_string(),
                        "Network segmentation".to_string(),
                        "User awareness training".to_string(),
                    ],
                    review_date: (Utc::now() + Duration::days(90)).to_rfc3339(),
                    related_controls: vec!["CIS-10.1".to_string(), "CIS-11.1".to_string()],
                },
                Risk {
                    id: Uuid::new_v4().to_string(),
                    title: "Data Breach via Third Party".to_string(),
                    description: "Sensitive data exposed through vendor system compromise.".to_string(),
                    category: RiskCategory::Compliance,
                    likelihood: RiskLikelihood::Possible,
                    impact: RiskImpact::Major,
                    risk_score: 16.0,
                    inherent_score: 20.0,
                    residual_score: 10.0,
                    treatment: RiskTreatment::Transfer,
                    owner: "DPO".to_string(),
                    status: RiskStatus::Assessed,
                    mitigations: vec![
                        "Vendor security assessments".to_string(),
                        "Data processing agreements".to_string(),
                        "Contractual security requirements".to_string(),
                    ],
                    review_date: (Utc::now() + Duration::days(60)).to_rfc3339(),
                    related_controls: vec!["PCI-12.8".to_string()],
                },
                Risk {
                    id: Uuid::new_v4().to_string(),
                    title: "Insider Threat".to_string(),
                    description: "Malicious or negligent insider causing data loss or system damage.".to_string(),
                    category: RiskCategory::Operational,
                    likelihood: RiskLikelihood::Unlikely,
                    impact: RiskImpact::Major,
                    risk_score: 12.0,
                    inherent_score: 15.0,
                    residual_score: 8.0,
                    treatment: RiskTreatment::Mitigate,
                    owner: "HR Director".to_string(),
                    status: RiskStatus::Open,
                    mitigations: vec![
                        "User behavior analytics".to_string(),
                        "Least privilege access".to_string(),
                        "Background checks".to_string(),
                        "Exit procedures".to_string(),
                    ],
                    review_date: (Utc::now() + Duration::days(120)).to_rfc3339(),
                    related_controls: vec!["CIS-6.1".to_string()],
                },
            ],
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        }
    }

    pub fn get_policies() -> Vec<Policy> {
        vec![
            Policy {
                id: Uuid::new_v4().to_string(),
                name: "Information Security Policy".to_string(),
                description: "Organization-wide information security requirements.".to_string(),
                category: PolicyCategory::InformationSecurity,
                status: PolicyStatus::Published,
                version: "2.1".to_string(),
                owner: "CISO".to_string(),
                approved_by: Some("CEO".to_string()),
                effective_date: "2024-01-01".to_string(),
                review_date: "2025-01-01".to_string(),
                content: "1. Purpose\n2. Scope\n3. Policy Statements...".to_string(),
                acknowledgments: vec![
                    Acknowledgment {
                        user_id: "user1".to_string(),
                        user_name: "John Doe".to_string(),
                        acknowledged_at: "2024-01-15T10:00:00Z".to_string(),
                        version: "2.1".to_string(),
                    },
                ],
            },
            Policy {
                id: Uuid::new_v4().to_string(),
                name: "Acceptable Use Policy".to_string(),
                description: "Rules for acceptable use of company IT resources.".to_string(),
                category: PolicyCategory::AcceptableUse,
                status: PolicyStatus::Published,
                version: "1.3".to_string(),
                owner: "IT Director".to_string(),
                approved_by: Some("CTO".to_string()),
                effective_date: "2024-02-01".to_string(),
                review_date: "2025-02-01".to_string(),
                content: "1. Purpose\n2. Scope\n3. Acceptable Use...".to_string(),
                acknowledgments: vec![],
            },
            Policy {
                id: Uuid::new_v4().to_string(),
                name: "Data Protection Policy".to_string(),
                description: "Requirements for handling personal and sensitive data.".to_string(),
                category: PolicyCategory::DataProtection,
                status: PolicyStatus::UnderReview,
                version: "3.0".to_string(),
                owner: "DPO".to_string(),
                approved_by: None,
                effective_date: "2024-06-01".to_string(),
                review_date: "2025-06-01".to_string(),
                content: "1. Purpose\n2. Scope\n3. Data Classification...".to_string(),
                acknowledgments: vec![],
            },
        ]
    }

    pub fn get_vendors() -> Vec<Vendor> {
        vec![
            Vendor {
                id: Uuid::new_v4().to_string(),
                name: "CloudHost Pro".to_string(),
                description: "Primary cloud infrastructure provider".to_string(),
                tier: VendorTier::Critical,
                risk_level: VendorRiskLevel::Medium,
                status: VendorStatus::Active,
                contact_email: "security@cloudhost.example.com".to_string(),
                contract_start: "2023-01-01".to_string(),
                contract_end: "2025-12-31".to_string(),
                services: vec!["IaaS".to_string(), "Managed Database".to_string()],
                data_access: vec!["Customer PII".to_string(), "Financial data".to_string()],
                assessments: vec![
                    VendorAssessment {
                        id: Uuid::new_v4().to_string(),
                        assessment_date: "2024-06-15".to_string(),
                        assessor: "Security Team".to_string(),
                        score: 85.0,
                        findings: vec!["Minor logging gaps".to_string()],
                        recommendations: vec!["Enable comprehensive audit logging".to_string()],
                        next_assessment_date: "2025-06-15".to_string(),
                    },
                ],
                documents: vec!["SOC 2 Type II".to_string(), "ISO 27001".to_string()],
            },
            Vendor {
                id: Uuid::new_v4().to_string(),
                name: "PayFlow Services".to_string(),
                description: "Payment processing provider".to_string(),
                tier: VendorTier::Critical,
                risk_level: VendorRiskLevel::High,
                status: VendorStatus::Active,
                contact_email: "compliance@payflow.example.com".to_string(),
                contract_start: "2023-06-01".to_string(),
                contract_end: "2025-05-31".to_string(),
                services: vec!["Payment Processing".to_string(), "Fraud Detection".to_string()],
                data_access: vec!["Cardholder data".to_string(), "Transaction records".to_string()],
                assessments: vec![],
                documents: vec!["PCI DSS Attestation".to_string()],
            },
        ]
    }

    pub fn get_training_modules() -> Vec<TrainingModule> {
        vec![
            TrainingModule {
                id: Uuid::new_v4().to_string(),
                name: "Security Awareness Fundamentals".to_string(),
                description: "Annual security awareness training for all employees.".to_string(),
                category: TrainingCategory::SecurityAwareness,
                duration_minutes: 45,
                required: true,
                completion_rate: 87.5,
                enrollments: vec![
                    TrainingEnrollment {
                        user_id: "user1".to_string(),
                        user_name: "John Doe".to_string(),
                        enrolled_at: "2024-01-01".to_string(),
                        completed_at: Some("2024-01-15".to_string()),
                        score: Some(92.0),
                        status: EnrollmentStatus::Completed,
                    },
                ],
            },
            TrainingModule {
                id: Uuid::new_v4().to_string(),
                name: "Phishing Simulation".to_string(),
                description: "Identify and report phishing attempts.".to_string(),
                category: TrainingCategory::Phishing,
                duration_minutes: 20,
                required: true,
                completion_rate: 92.0,
                enrollments: vec![],
            },
            TrainingModule {
                id: Uuid::new_v4().to_string(),
                name: "GDPR Data Protection".to_string(),
                description: "Data protection requirements under GDPR.".to_string(),
                category: TrainingCategory::DataProtection,
                duration_minutes: 30,
                required: true,
                completion_rate: 78.0,
                enrollments: vec![],
            },
        ]
    }

    pub fn get_grc_dashboard() -> GrcDashboard {
        GrcDashboard {
            compliance_score: 79.0,
            open_risks: 12,
            critical_risks: 3,
            policy_compliance_rate: 85.0,
            vendor_risk_score: 65.0,
            training_completion_rate: 86.0,
            overdue_items: 5,
            upcoming_reviews: 8,
            frameworks: vec![
                FrameworkSummary { name: "CIS v8".to_string(), score: 72.0, controls_total: 15, controls_passed: 11 },
                FrameworkSummary { name: "PCI DSS".to_string(), score: 82.0, controls_total: 12, controls_passed: 10 },
                FrameworkSummary { name: "SOC 2".to_string(), score: 85.0, controls_total: 8, controls_passed: 7 },
            ],
            risk_trend: vec![
                RiskTrendPoint { date: "2024-06".to_string(), open_count: 15, closed_count: 3, avg_score: 14.2 },
                RiskTrendPoint { date: "2024-07".to_string(), open_count: 13, closed_count: 5, avg_score: 13.1 },
                RiskTrendPoint { date: "2024-08".to_string(), open_count: 12, closed_count: 4, avg_score: 12.5 },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_frameworks() {
        let frameworks = WhiteTeam::get_compliance_frameworks();
        assert_eq!(frameworks.len(), 3);
    }

    #[test]
    fn test_risk_register() {
        let register = WhiteTeam::get_risk_register();
        assert!(register.risks.len() >= 3);
    }

    #[test]
    fn test_policies() {
        let policies = WhiteTeam::get_policies();
        assert_eq!(policies.len(), 3);
    }

    #[test]
    fn test_vendors() {
        let vendors = WhiteTeam::get_vendors();
        assert_eq!(vendors.len(), 2);
    }

    #[test]
    fn test_training() {
        let modules = WhiteTeam::get_training_modules();
        assert_eq!(modules.len(), 3);
    }

    #[test]
    fn test_grc_dashboard() {
        let dashboard = WhiteTeam::get_grc_dashboard();
        assert!(dashboard.compliance_score > 0.0);
    }
}
