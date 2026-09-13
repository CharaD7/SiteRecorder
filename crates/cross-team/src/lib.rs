use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CrossTeamError {
    #[error("Error: {0}")]
    Error(String),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
}

type Result<T> = std::result::Result<T, CrossTeamError>;

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
    pub auth_profile_id: Option<String>,
    pub compliance_scope: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub risk_score: Option<f64>,
    pub last_scan: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AssetType {
    Domain,
    IpRange,
    Application,
    CloudAccount,
    Repository,
    MobileApp,
    Device,
    NetworkDevice,
}

impl std::fmt::Display for AssetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetType::Domain => write!(f, "Domain"),
            AssetType::IpRange => write!(f, "IP Range"),
            AssetType::Application => write!(f, "Application"),
            AssetType::CloudAccount => write!(f, "Cloud Account"),
            AssetType::Repository => write!(f, "Repository"),
            AssetType::MobileApp => write!(f, "Mobile App"),
            AssetType::Device => write!(f, "Device"),
            AssetType::NetworkDevice => write!(f, "Network Device"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Environment {
    Production,
    Staging,
    Development,
    Testing,
    DisasterRecovery,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Production => write!(f, "Production"),
            Environment::Staging => write!(f, "Staging"),
            Environment::Development => write!(f, "Development"),
            Environment::Testing => write!(f, "Testing"),
            Environment::DisasterRecovery => write!(f, "Disaster Recovery"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Criticality {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Criticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Criticality::Critical => write!(f, "Critical"),
            Criticality::High => write!(f, "High"),
            Criticality::Medium => write!(f, "Medium"),
            Criticality::Low => write!(f, "Low"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub title: String,
    pub message: String,
    pub notification_type: NotificationType,
    pub severity: NotificationSeverity,
    pub read: bool,
    pub action_url: Option<String>,
    pub source: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NotificationType {
    Alert,
    ScanComplete,
    Incident,
    Compliance,
    Risk,
    System,
    Finding,
    AuthExpiry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NotificationSeverity {
    Info,
    Success,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub condition: AlertCondition,
    pub channels: Vec<NotificationChannel>,
    pub enabled: bool,
    pub throttle_minutes: u32,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    pub event_type: String,
    pub severity_threshold: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NotificationChannel {
    InApp,
    Email,
    Slack,
    Discord,
    PagerDuty,
    Webhook,
    Sms,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub report_type: ReportType,
    pub sections: Vec<ReportSection>,
    pub format: ReportFormat,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportType {
    Executive,
    Technical,
    Compliance,
    Trend,
    Comparison,
    Incident,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    pub id: String,
    pub title: String,
    pub section_type: SectionType,
    pub enabled: bool,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SectionType {
    Summary,
    Findings,
    SeverityChart,
    TrendChart,
    Compliance,
    Recommendations,
    Appendix,
    Evidence,
    Metrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportFormat {
    Pdf,
    Html,
    Json,
    Csv,
    Docx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedReport {
    pub id: String,
    pub template_id: String,
    pub name: String,
    pub format: ReportFormat,
    pub generated_at: String,
    pub file_path: Option<String>,
    pub status: ReportStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportStatus {
    Generating,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integration {
    pub id: String,
    pub name: String,
    pub integration_type: IntegrationType,
    pub status: IntegrationStatus,
    pub config: HashMap<String, String>,
    pub last_sync: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrationType {
    Nessus,
    Qualys,
    BurpSuite,
    SonarQube,
    Splunk,
    Elastic,
    Jira,
    ServiceNow,
    VirusTotal,
    Shodan,
    Misp,
    Censys,
}

impl std::fmt::Display for IntegrationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrationType::Nessus => write!(f, "Nessus"),
            IntegrationType::Qualys => write!(f, "Qualys"),
            IntegrationType::BurpSuite => write!(f, "Burp Suite"),
            IntegrationType::SonarQube => write!(f, "SonarQube"),
            IntegrationType::Splunk => write!(f, "Splunk"),
            IntegrationType::Elastic => write!(f, "Elastic"),
            IntegrationType::Jira => write!(f, "Jira"),
            IntegrationType::ServiceNow => write!(f, "ServiceNow"),
            IntegrationType::VirusTotal => write!(f, "VirusTotal"),
            IntegrationType::Shodan => write!(f, "Shodan"),
            IntegrationType::Misp => write!(f, "MISP"),
            IntegrationType::Censys => write!(f, "Censys"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrationStatus {
    Connected,
    Disconnected,
    Error,
    Configuring,
}

pub struct CrossTeam;

impl CrossTeam {
    pub fn get_assets() -> Vec<Asset> {
        vec![
            Asset {
                id: Uuid::new_v4().to_string(),
                name: "Production Web App".to_string(),
                asset_type: AssetType::Application,
                url: Some("https://app.example.com".to_string()),
                ip_addresses: vec!["10.0.1.100".to_string()],
                tags: vec!["production".to_string(), "web".to_string(), "customer-facing".to_string()],
                owner: Some("Web Team".to_string()),
                environment: Environment::Production,
                criticality: Criticality::Critical,
                auth_profile_id: None,
                compliance_scope: vec!["PCI-DSS".to_string(), "SOC2".to_string()],
                metadata: HashMap::new(),
                risk_score: Some(7.5),
                last_scan: Some(Utc::now().to_rfc3339()),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
            Asset {
                id: Uuid::new_v4().to_string(),
                name: "API Gateway".to_string(),
                asset_type: AssetType::Application,
                url: Some("https://api.example.com".to_string()),
                ip_addresses: vec!["10.0.1.101".to_string()],
                tags: vec!["production".to_string(), "api".to_string()],
                owner: Some("Platform Team".to_string()),
                environment: Environment::Production,
                criticality: Criticality::High,
                auth_profile_id: None,
                compliance_scope: vec!["SOC2".to_string()],
                metadata: HashMap::new(),
                risk_score: Some(6.2),
                last_scan: Some((Utc::now() - Duration::days(7)).to_rfc3339()),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
            Asset {
                id: Uuid::new_v4().to_string(),
                name: "Database Server".to_string(),
                asset_type: AssetType::Device,
                url: None,
                ip_addresses: vec!["10.0.2.50".to_string()],
                tags: vec!["production".to_string(), "database".to_string()],
                owner: Some("DBA Team".to_string()),
                environment: Environment::Production,
                criticality: Criticality::Critical,
                auth_profile_id: None,
                compliance_scope: vec!["PCI-DSS".to_string(), "SOC2".to_string(), "HIPAA".to_string()],
                metadata: HashMap::new(),
                risk_score: Some(8.1),
                last_scan: Some((Utc::now() - Duration::days(3)).to_rfc3339()),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
        ]
    }

    pub fn get_notifications() -> Vec<Notification> {
        let now = Utc::now();
        vec![
            Notification {
                id: Uuid::new_v4().to_string(),
                title: "Critical Vulnerability Found".to_string(),
                message: "SQL Injection discovered in https://app.example.com/login".to_string(),
                notification_type: NotificationType::Finding,
                severity: NotificationSeverity::Critical,
                read: false,
                action_url: Some("/red-team/scanner".to_string()),
                source: "Vulnerability Scanner".to_string(),
                timestamp: now.to_rfc3339(),
            },
            Notification {
                id: Uuid::new_v4().to_string(),
                title: "Scan Completed".to_string(),
                message: "Network scan of 192.168.1.0/24 completed. 3 hosts found.".to_string(),
                notification_type: NotificationType::ScanComplete,
                severity: NotificationSeverity::Success,
                read: false,
                action_url: Some("/red-team/network".to_string()),
                source: "Network Scanner".to_string(),
                timestamp: (now - Duration::minutes(30)).to_rfc3339(),
            },
            Notification {
                id: Uuid::new_v4().to_string(),
                title: "Auth Session Expiring".to_string(),
                message: "Production admin session expires in 15 minutes.".to_string(),
                notification_type: NotificationType::AuthExpiry,
                severity: NotificationSeverity::Warning,
                read: true,
                action_url: None,
                source: "Session Manager".to_string(),
                timestamp: (now - Duration::hours(1)).to_rfc3339(),
            },
            Notification {
                id: Uuid::new_v4().to_string(),
                title: "Compliance Threshold Breached".to_string(),
                message: "CIS v8 compliance dropped below 70% threshold.".to_string(),
                notification_type: NotificationType::Compliance,
                severity: NotificationSeverity::Error,
                read: true,
                action_url: Some("/white-team/compliance".to_string()),
                source: "GRC Engine".to_string(),
                timestamp: (now - Duration::hours(3)).to_rfc3339(),
            },
        ]
    }

    pub fn get_alert_rules() -> Vec<AlertRule> {
        vec![
            AlertRule {
                id: Uuid::new_v4().to_string(),
                name: "Critical Finding".to_string(),
                description: "Trigger when critical severity finding is discovered".to_string(),
                condition: AlertCondition {
                    event_type: "finding_created".to_string(),
                    severity_threshold: Some("Critical".to_string()),
                    tags: vec![],
                },
                channels: vec![NotificationChannel::InApp, NotificationChannel::Slack],
                enabled: true,
                throttle_minutes: 15,
                created_at: Utc::now().to_rfc3339(),
            },
            AlertRule {
                id: Uuid::new_v4().to_string(),
                name: "Production Incident".to_string(),
                description: "Trigger on any production incident".to_string(),
                condition: AlertCondition {
                    event_type: "incident_created".to_string(),
                    severity_threshold: None,
                    tags: vec!["production".to_string()],
                },
                channels: vec![NotificationChannel::InApp, NotificationChannel::PagerDuty],
                enabled: true,
                throttle_minutes: 5,
                created_at: Utc::now().to_rfc3339(),
            },
        ]
    }

    pub fn get_report_templates() -> Vec<ReportTemplate> {
        vec![
            ReportTemplate {
                id: Uuid::new_v4().to_string(),
                name: "Executive Summary".to_string(),
                description: "High-level security posture for leadership".to_string(),
                report_type: ReportType::Executive,
                sections: vec![
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Summary".to_string(), section_type: SectionType::Summary, enabled: true, order: 1 },
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Risk Overview".to_string(), section_type: SectionType::SeverityChart, enabled: true, order: 2 },
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Trend Analysis".to_string(), section_type: SectionType::TrendChart, enabled: true, order: 3 },
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Recommendations".to_string(), section_type: SectionType::Recommendations, enabled: true, order: 4 },
                ],
                format: ReportFormat::Pdf,
                created_at: Utc::now().to_rfc3339(),
            },
            ReportTemplate {
                id: Uuid::new_v4().to_string(),
                name: "Technical Findings".to_string(),
                description: "Detailed technical vulnerability report".to_string(),
                report_type: ReportType::Technical,
                sections: vec![
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Findings".to_string(), section_type: SectionType::Findings, enabled: true, order: 1 },
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Evidence".to_string(), section_type: SectionType::Evidence, enabled: true, order: 2 },
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Metrics".to_string(), section_type: SectionType::Metrics, enabled: true, order: 3 },
                ],
                format: ReportFormat::Html,
                created_at: Utc::now().to_rfc3339(),
            },
            ReportTemplate {
                id: Uuid::new_v4().to_string(),
                name: "Compliance Report".to_string(),
                description: "Framework compliance status report".to_string(),
                report_type: ReportType::Compliance,
                sections: vec![
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Compliance Status".to_string(), section_type: SectionType::Compliance, enabled: true, order: 1 },
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Gap Analysis".to_string(), section_type: SectionType::Findings, enabled: true, order: 2 },
                    ReportSection { id: Uuid::new_v4().to_string(), title: "Appendix".to_string(), section_type: SectionType::Appendix, enabled: true, order: 3 },
                ],
                format: ReportFormat::Pdf,
                created_at: Utc::now().to_rfc3339(),
            },
        ]
    }

    pub fn get_integrations() -> Vec<Integration> {
        vec![
            Integration {
                id: Uuid::new_v4().to_string(),
                name: "VirusTotal".to_string(),
                integration_type: IntegrationType::VirusTotal,
                status: IntegrationStatus::Connected,
                config: HashMap::new(),
                last_sync: Some(Utc::now().to_rfc3339()),
            },
            Integration {
                id: Uuid::new_v4().to_string(),
                name: "Splunk SIEM".to_string(),
                integration_type: IntegrationType::Splunk,
                status: IntegrationStatus::Connected,
                config: HashMap::new(),
                last_sync: Some((Utc::now() - Duration::hours(1)).to_rfc3339()),
            },
            Integration {
                id: Uuid::new_v4().to_string(),
                name: "Jira".to_string(),
                integration_type: IntegrationType::Jira,
                status: IntegrationStatus::Connected,
                config: HashMap::new(),
                last_sync: Some(Utc::now().to_rfc3339()),
            },
            Integration {
                id: Uuid::new_v4().to_string(),
                name: "Nessus".to_string(),
                integration_type: IntegrationType::Nessus,
                status: IntegrationStatus::Disconnected,
                config: HashMap::new(),
                last_sync: None,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assets() {
        let assets = CrossTeam::get_assets();
        assert_eq!(assets.len(), 3);
    }

    #[test]
    fn test_notifications() {
        let notifications = CrossTeam::get_notifications();
        assert!(notifications.len() >= 4);
    }

    #[test]
    fn test_alert_rules() {
        let rules = CrossTeam::get_alert_rules();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_report_templates() {
        let templates = CrossTeam::get_report_templates();
        assert_eq!(templates.len(), 3);
    }

    #[test]
    fn test_integrations() {
        let integrations = CrossTeam::get_integrations();
        assert_eq!(integrations.len(), 4);
    }
}
