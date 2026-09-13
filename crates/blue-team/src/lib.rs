use chrono::{Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum BlueTeamError {
    #[error("Error: {0}")]
    Error(String),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
}

type Result<T> = std::result::Result<T, BlueTeamError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocDashboard {
    pub total_alerts: usize,
    pub open_incidents: usize,
    pub mean_time_to_detect_minutes: f64,
    pub mean_time_to_respond_minutes: f64,
    pub alerts_last_24h: usize,
    pub alerts_last_7d: usize,
    pub false_positive_rate: f64,
    pub top_alert_sources: Vec<AlertSource>,
    pub severity_distribution: SeverityDistribution,
    pub recent_alerts: Vec<Alert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSource {
    pub name: String,
    pub count: usize,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityDistribution {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub source: String,
    pub timestamp: String,
    pub assignee: Option<String>,
    pub mitre_techniques: Vec<String>,
    pub indicators: Vec<String>,
    pub raw_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Critical => write!(f, "CRITICAL"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::Low => write!(f, "LOW"),
            AlertSeverity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    New,
    Triaged,
    Investigating,
    Contained,
    Closed,
    FalsePositive,
}

impl std::fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertStatus::New => write!(f, "New"),
            AlertStatus::Triaged => write!(f, "Triaged"),
            AlertStatus::Investigating => write!(f, "Investigating"),
            AlertStatus::Contained => write!(f, "Contained"),
            AlertStatus::Closed => write!(f, "Closed"),
            AlertStatus::FalsePositive => write!(f, "False Positive"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub category: IncidentCategory,
    pub source_alert_ids: Vec<String>,
    pub timeline: Vec<TimelineEvent>,
    pub assignee: Option<String>,
    pub team: String,
    pub impact: String,
    pub containment_actions: Vec<String>,
    pub eradication_actions: Vec<String>,
    pub recovery_actions: Vec<String>,
    pub lessons_learned: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub closed_at: Option<String>,
    pub duration_minutes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentSeverity {
    P1,
    P2,
    P3,
    P4,
}

impl std::fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentSeverity::P1 => write!(f, "P1 - Critical"),
            IncidentSeverity::P2 => write!(f, "P2 - High"),
            IncidentSeverity::P3 => write!(f, "P3 - Medium"),
            IncidentSeverity::P4 => write!(f, "P4 - Low"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    New,
    Triaged,
    Investigating,
    Contained,
    Eradicated,
    Recovering,
    Closed,
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentStatus::New => write!(f, "New"),
            IncidentStatus::Triaged => write!(f, "Triaged"),
            IncidentStatus::Investigating => write!(f, "Investigating"),
            IncidentStatus::Contained => write!(f, "Contained"),
            IncidentStatus::Eradicated => write!(f, "Eradicated"),
            IncidentStatus::Recovering => write!(f, "Recovering"),
            IncidentStatus::Closed => write!(f, "Closed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentCategory {
    Malware,
    Phishing,
    DataBreach,
    DDoS,
    InsiderThreat,
    UnauthorizedAccess,
    Ransomware,
    APT,
    PolicyViolation,
    Other,
}

impl std::fmt::Display for IncidentCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentCategory::Malware => write!(f, "Malware"),
            IncidentCategory::Phishing => write!(f, "Phishing"),
            IncidentCategory::DataBreach => write!(f, "Data Breach"),
            IncidentCategory::DDoS => write!(f, "DDoS"),
            IncidentCategory::InsiderThreat => write!(f, "Insider Threat"),
            IncidentCategory::UnauthorizedAccess => write!(f, "Unauthorized Access"),
            IncidentCategory::Ransomware => write!(f, "Ransomware"),
            IncidentCategory::APT => write!(f, "APT"),
            IncidentCategory::PolicyViolation => write!(f, "Policy Violation"),
            IncidentCategory::Other => write!(f, "Other"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: String,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub details: String,
    pub event_type: TimelineEventType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimelineEventType {
    Detection,
    Triage,
    Investigation,
    Containment,
    Eradication,
    Recovery,
    Communication,
    Note,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeed {
    pub id: String,
    pub name: String,
    pub feed_type: FeedType,
    pub description: String,
    pub url: Option<String>,
    pub last_updated: String,
    pub indicator_count: usize,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FeedType {
    Stix,
    Taxii,
    Misp,
    Csv,
    Json,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub id: String,
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: u8,
    pub severity: AlertSeverity,
    pub source: String,
    pub description: String,
    pub tags: Vec<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Email,
    Cve,
    YaraRule,
    SigmaRule,
    Mutex,
    UserAgent,
    Certificate,
    BitcoinAddress,
}

impl std::fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndicatorType::IpAddress => write!(f, "IP Address"),
            IndicatorType::Domain => write!(f, "Domain"),
            IndicatorType::Url => write!(f, "URL"),
            IndicatorType::FileHash => write!(f, "File Hash"),
            IndicatorType::Email => write!(f, "Email"),
            IndicatorType::Cve => write!(f, "CVE"),
            IndicatorType::YaraRule => write!(f, "YARA Rule"),
            IndicatorType::SigmaRule => write!(f, "Sigma Rule"),
            IndicatorType::Mutex => write!(f, "Mutex"),
            IndicatorType::UserAgent => write!(f, "User Agent"),
            IndicatorType::Certificate => write!(f, "Certificate"),
            IndicatorType::BitcoinAddress => write!(f, "Bitcoin Address"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub motivation: String,
    pub sophistication: String,
    pub country: Option<String>,
    pub sector_targets: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub indicators: Vec<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsCase {
    pub id: String,
    pub title: String,
    pub description: String,
    pub case_type: ForensicsType,
    pub status: ForensicsStatus,
    pub evidence: Vec<Evidence>,
    pub timeline: Vec<TimelineEvent>,
    pub examiner: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ForensicsType {
    DiskImage,
    MemoryDump,
    NetworkPcap,
    MalwareAnalysis,
    MobileDevice,
    EmailForensics,
    DatabaseForensics,
    LogAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ForensicsStatus {
    Open,
    InProgress,
    Analysis,
    Report,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub name: String,
    pub evidence_type: EvidenceType,
    pub hash_md5: Option<String>,
    pub hash_sha256: Option<String>,
    pub size_bytes: u64,
    pub collected_at: String,
    pub collected_by: String,
    pub chain_of_custody: Vec<CustodyEntry>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceType {
    DiskImage,
    MemoryDump,
    PcapFile,
    LogFile,
    MalwareSample,
    EmailFile,
    MobileBackup,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub timestamp: String,
    pub action: String,
    pub actor: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareAnalysis {
    pub id: String,
    pub sample_name: String,
    pub file_type: String,
    pub file_size: u64,
    pub md5: String,
    pub sha256: String,
    pub sha1: String,
    pub ssdeep: Option<String>,
    pub imphash: Option<String>,
    pub signatures: Vec<MalwareSignature>,
    pub behavior: Vec<BehaviorIndicator>,
    pub network_indicators: Vec<String>,
    pub file_indicators: Vec<String>,
    pub registry_indicators: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareSignature {
    pub name: String,
    pub description: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorIndicator {
    pub category: String,
    pub description: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntHypothesis {
    pub id: String,
    pub title: String,
    pub description: String,
    pub mitre_technique: String,
    pub data_sources: Vec<String>,
    pub search_queries: Vec<String>,
    pub status: HuntStatus,
    pub findings: Vec<String>,
    pub hunter: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HuntStatus {
    Draft,
    Active,
    Completed,
    Archived,
}

pub struct BlueTeam;

impl BlueTeam {
    pub fn get_soc_dashboard() -> SocDashboard {
        let now = Utc::now();
        let alerts = Self::generate_sample_alerts();

        SocDashboard {
            total_alerts: alerts.len(),
            open_incidents: 3,
            mean_time_to_detect_minutes: 12.5,
            mean_time_to_respond_minutes: 45.0,
            alerts_last_24h: 15,
            alerts_last_7d: 87,
            false_positive_rate: 0.23,
            top_alert_sources: vec![
                AlertSource { name: "EDR".to_string(), count: 45, severity: AlertSeverity::High },
                AlertSource { name: "SIEM".to_string(), count: 32, severity: AlertSeverity::Medium },
                AlertSource { name: "Firewall".to_string(), count: 28, severity: AlertSeverity::Low },
                AlertSource { name: "Email Gateway".to_string(), count: 12, severity: AlertSeverity::Critical },
            ],
            severity_distribution: SeverityDistribution {
                critical: 3,
                high: 12,
                medium: 35,
                low: 25,
                info: 12,
            },
            recent_alerts: alerts,
        }
    }

    fn generate_sample_alerts() -> Vec<Alert> {
        let now = Utc::now();
        vec![
            Alert {
                id: Uuid::new_v4().to_string(),
                title: "Suspicious PowerShell Execution".to_string(),
                description: "Encoded PowerShell command detected on workstation WS-001".to_string(),
                severity: AlertSeverity::High,
                status: AlertStatus::New,
                source: "EDR".to_string(),
                timestamp: now.to_rfc3339(),
                assignee: None,
                mitre_techniques: vec!["T1059.001".to_string()],
                indicators: vec!["powershell.exe".to_string(), "-enc".to_string()],
                raw_data: None,
            },
            Alert {
                id: Uuid::new_v4().to_string(),
                title: "Failed Brute Force Login".to_string(),
                description: "Multiple failed login attempts from external IP".to_string(),
                severity: AlertSeverity::Medium,
                status: AlertStatus::Triaged,
                source: "SIEM".to_string(),
                timestamp: (now - Duration::minutes(15)).to_rfc3339(),
                assignee: Some("analyst1".to_string()),
                mitre_techniques: vec!["T1110".to_string()],
                indicators: vec!["192.168.1.100".to_string()],
                raw_data: None,
            },
            Alert {
                id: Uuid::new_v4().to_string(),
                title: "Malware Detection".to_string(),
                description: "Known malware hash detected on endpoint".to_string(),
                severity: AlertSeverity::Critical,
                status: AlertStatus::Investigating,
                source: "Antivirus".to_string(),
                timestamp: (now - Duration::minutes(30)).to_rfc3339(),
                assignee: Some("analyst2".to_string()),
                mitre_techniques: vec!["T1204".to_string()],
                indicators: vec!["d41d8cd98f00b204e9800998ecf8427e".to_string()],
                raw_data: None,
            },
            Alert {
                id: Uuid::new_v4().to_string(),
                title: "Data Exfiltration Attempt".to_string(),
                description: "Large outbound data transfer to unknown destination".to_string(),
                severity: AlertSeverity::High,
                status: AlertStatus::New,
                source: "DLP".to_string(),
                timestamp: (now - Duration::hours(1)).to_rfc3339(),
                assignee: None,
                mitre_techniques: vec!["T1041".to_string()],
                indicators: vec!["10.50.2.100".to_string(), "4.5GB".to_string()],
                raw_data: None,
            },
            Alert {
                id: Uuid::new_v4().to_string(),
                title: "Phishing Email Detected".to_string(),
                description: "Suspicious email with malicious attachment blocked".to_string(),
                severity: AlertSeverity::Medium,
                status: AlertStatus::Closed,
                source: "Email Gateway".to_string(),
                timestamp: (now - Duration::hours(2)).to_rfc3339(),
                assignee: Some("analyst1".to_string()),
                mitre_techniques: vec!["T1566.001".to_string()],
                indicators: vec!["invoice.pdf.exe".to_string()],
                raw_data: None,
            },
        ]
    }

    pub fn create_incident(title: &str, description: &str, severity: IncidentSeverity, category: IncidentCategory) -> Incident {
        let now = Utc::now();
        Incident {
            id: format!("INC-{}", Utc::now().timestamp_millis()),
            title: title.to_string(),
            description: description.to_string(),
            severity,
            status: IncidentStatus::New,
            category,
            source_alert_ids: Vec::new(),
            timeline: vec![
                TimelineEvent {
                    id: Uuid::new_v4().to_string(),
                    timestamp: now.to_rfc3339(),
                    actor: "System".to_string(),
                    action: "Incident Created".to_string(),
                    details: format!("Incident '{}' created", title),
                    event_type: TimelineEventType::Detection,
                },
            ],
            assignee: None,
            team: "SOC".to_string(),
            impact: "Under investigation".to_string(),
            containment_actions: Vec::new(),
            eradication_actions: Vec::new(),
            recovery_actions: Vec::new(),
            lessons_learned: None,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
            closed_at: None,
            duration_minutes: None,
        }
    }

    pub fn get_threat_intel_feeds() -> Vec<ThreatIntelFeed> {
        vec![
            ThreatIntelFeed {
                id: Uuid::new_v4().to_string(),
                name: "AlienVault OTX".to_string(),
                feed_type: FeedType::Stix,
                description: "Open Threat Exchange community feed".to_string(),
                url: Some("https://otx.alienvault.com/api/v1/indicators/".to_string()),
                last_updated: Utc::now().to_rfc3339(),
                indicator_count: 15420,
                enabled: true,
            },
            ThreatIntelFeed {
                id: Uuid::new_v4().to_string(),
                name: "MISP Community".to_string(),
                feed_type: FeedType::Misp,
                description: "MISP threat sharing platform".to_string(),
                url: Some("https://misp.example.com/events/restSearch".to_string()),
                last_updated: Utc::now().to_rfc3339(),
                indicator_count: 8930,
                enabled: true,
            },
            ThreatIntelFeed {
                id: Uuid::new_v4().to_string(),
                name: "VirusTotal Intelligence".to_string(),
                feed_type: FeedType::Json,
                description: "File hash and URL reputation".to_string(),
                url: Some("https://www.virustotal.com/api/v3/".to_string()),
                last_updated: Utc::now().to_rfc3339(),
                indicator_count: 52100,
                enabled: true,
            },
            ThreatIntelFeed {
                id: Uuid::new_v4().to_string(),
                name: "Abuse.ch URLhaus".to_string(),
                feed_type: FeedType::Csv,
                description: "Malware distribution URLs".to_string(),
                url: Some("https://urlhaus-api.abuse.ch/v1/".to_string()),
                last_updated: Utc::now().to_rfc3339(),
                indicator_count: 3200,
                enabled: true,
            },
        ]
    }

    pub fn get_threat_actors() -> Vec<ThreatActor> {
        vec![
            ThreatActor {
                id: Uuid::new_v4().to_string(),
                name: "APT28".to_string(),
                aliases: vec!["Fancy Bear".to_string(), "Sofacy".to_string(), "STRONTIUM".to_string()],
                description: "Russian state-sponsored cyber espionage group.".to_string(),
                motivation: "Espionage".to_string(),
                sophistication: "High".to_string(),
                country: Some("Russia".to_string()),
                sector_targets: vec!["Government".to_string(), "Defense".to_string(), "Energy".to_string()],
                mitre_techniques: vec!["T1566".to_string(), "T1059".to_string(), "T1003".to_string()],
                indicators: vec!["185.220.101.*".to_string(), "update-msdn.com".to_string()],
                last_seen: Some(Utc::now().to_rfc3339()),
            },
            ThreatActor {
                id: Uuid::new_v4().to_string(),
                name: "Lazarus Group".to_string(),
                aliases: vec!["Hidden Cobra".to_string(), "Guardians of Peace".to_string()],
                description: "North Korean state-sponsored group targeting financial institutions.".to_string(),
                motivation: "Financial gain".to_string(),
                sophistication: "High".to_string(),
                country: Some("North Korea".to_string()),
                sector_targets: vec!["Financial".to_string(), "Cryptocurrency".to_string(), "Gaming".to_string()],
                mitre_techniques: vec!["T1486".to_string(), "T1490".to_string(), "T1059".to_string()],
                indicators: vec!["175.45.176.*".to_string(), "swift-mt799.com".to_string()],
                last_seen: Some((Utc::now() - Duration::days(7)).to_rfc3339()),
            },
        ]
    }

    pub fn get_sample_indicators() -> Vec<Indicator> {
        vec![
            Indicator {
                id: Uuid::new_v4().to_string(),
                indicator_type: IndicatorType::IpAddress,
                value: "185.220.101.42".to_string(),
                confidence: 85,
                severity: AlertSeverity::High,
                source: "AlienVault OTX".to_string(),
                description: "Known C2 server associated with APT28".to_string(),
                tags: vec!["c2".to_string(), "apt28".to_string(), "russia".to_string()],
                valid_from: Utc::now().to_rfc3339(),
                valid_until: Some((Utc::now() + Duration::days(30)).to_rfc3339()),
                mitre_techniques: vec!["T1071".to_string()],
            },
            Indicator {
                id: Uuid::new_v4().to_string(),
                indicator_type: IndicatorType::Domain,
                value: "evil-c2.example.com".to_string(),
                confidence: 95,
                severity: AlertSeverity::Critical,
                source: "Internal Hunt".to_string(),
                description: "Malicious domain identified during threat hunt".to_string(),
                tags: vec!["malware".to_string(), "c2".to_string()],
                valid_from: Utc::now().to_rfc3339(),
                valid_until: None,
                mitre_techniques: vec!["T1568".to_string()],
            },
            Indicator {
                id: Uuid::new_v4().to_string(),
                indicator_type: IndicatorType::FileHash,
                value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                confidence: 100,
                severity: AlertSeverity::Critical,
                source: "VirusTotal".to_string(),
                description: "Known ransomware sample".to_string(),
                tags: vec!["ransomware".to_string(), "lockbit".to_string()],
                valid_from: Utc::now().to_rfc3339(),
                valid_until: None,
                mitre_techniques: vec!["T1486".to_string()],
            },
        ]
    }

    pub fn create_forensics_case(title: &str, description: &str, case_type: ForensicsType) -> ForensicsCase {
        let now = Utc::now();
        ForensicsCase {
            id: format!("CASE-{}", Utc::now().timestamp_millis()),
            title: title.to_string(),
            description: description.to_string(),
            case_type,
            status: ForensicsStatus::Open,
            evidence: Vec::new(),
            timeline: vec![
                TimelineEvent {
                    id: Uuid::new_v4().to_string(),
                    timestamp: now.to_rfc3339(),
                    actor: "Examiner".to_string(),
                    action: "Case Opened".to_string(),
                    details: format!("Case '{}' created", title),
                    event_type: TimelineEventType::Note,
                },
            ],
            examiner: "forensics_analyst".to_string(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        }
    }

    pub fn get_sample_malware_analysis() -> MalwareAnalysis {
        MalwareAnalysis {
            id: Uuid::new_v4().to_string(),
            sample_name: "invoice_2024.pdf.exe".to_string(),
            file_type: "PE32 executable (GUI) Intel 80386".to_string(),
            file_size: 245760,
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            ssdeep: Some("768:abc123:def456".to_string()),
            imphash: Some("f34d5f2d4577ed6d9ceec516c1f5a744".to_string()),
            signatures: vec![
                MalwareSignature {
                    name: "Ransomware.LockBit".to_string(),
                    description: "Matches LockBit 3.0 ransomware indicators".to_string(),
                    severity: AlertSeverity::Critical,
                },
                MalwareSignature {
                    name: "Persistence.Registry".to_string(),
                    description: "Creates registry run key for persistence".to_string(),
                    severity: AlertSeverity::High,
                },
            ],
            behavior: vec![
                BehaviorIndicator {
                    category: "File System".to_string(),
                    description: "Encrypts files with .lockbit extension".to_string(),
                    severity: AlertSeverity::Critical,
                },
                BehaviorIndicator {
                    category: "Network".to_string(),
                    description: "Connects to Tor C2 infrastructure".to_string(),
                    severity: AlertSeverity::High,
                },
                BehaviorIndicator {
                    category: "Process".to_string(),
                    description: "Injects code into explorer.exe".to_string(),
                    severity: AlertSeverity::High,
                },
            ],
            network_indicators: vec![
                "185.220.101.42:443".to_string(),
                "tor-c2.onion".to_string(),
            ],
            file_indicators: vec![
                "C:\\Windows\\Temp\\svchost.exe".to_string(),
                "C:\\Users\\Public\\readme.txt".to_string(),
            ],
            registry_indicators: vec![
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update".to_string(),
            ],
            mitre_techniques: vec!["T1486".to_string(), "T1055".to_string(), "T1547".to_string()],
            risk_score: 95,
        }
    }

    pub fn create_hunt_hypothesis(title: &str, description: &str, mitre_technique: &str) -> HuntHypothesis {
        HuntHypothesis {
            id: Uuid::new_v4().to_string(),
            title: title.to_string(),
            description: description.to_string(),
            mitre_technique: mitre_technique.to_string(),
            data_sources: vec!["EDR".to_string(), "Windows Event Logs".to_string(), "Sysmon".to_string()],
            search_queries: match mitre_technique {
                "T1059" => vec![
                    "EventID=4688 AND NewProcessName=*powershell*".to_string(),
                    "EventID=1 AND CommandLine=*enc*".to_string(),
                ],
                "T1003" => vec![
                    "EventID=4656 AND ObjectName=*lsass*".to_string(),
                    "EventID=4663 AND ObjectName=*SAM*".to_string(),
                ],
                _ => vec![],
            },
            status: HuntStatus::Draft,
            findings: Vec::new(),
            hunter: "threat_hunter".to_string(),
            created_at: Utc::now().to_rfc3339(),
        }
    }

    pub fn get_ir_playbooks() -> HashMap<String, Vec<String>> {
        let mut playbooks = HashMap::new();
        playbooks.insert("Ransomware".to_string(), vec![
            "1. Isolate affected systems from network".to_string(),
            "2. Identify patient zero and scope".to_string(),
            "3. Preserve evidence (memory, disk)".to_string(),
            "4. Notify management and legal".to_string(),
            "5. Engage incident response team".to_string(),
            "6. Determine ransomware variant".to_string(),
            "7. Check for data exfiltration".to_string(),
            "8. Begin recovery from backups".to_string(),
        ]);
        playbooks.insert("Phishing".to_string(), vec![
            "1. Identify affected users".to_string(),
            "2. Block sender and malicious URLs".to_string(),
            "3. Reset compromised credentials".to_string(),
            "4. Check for malware execution".to_string(),
            "5. Send awareness notification".to_string(),
        ]);
        playbooks.insert("Data Breach".to_string(), vec![
            "1. Determine scope of data exposed".to_string(),
            "2. Identify attack vector".to_string(),
            "3. Contain the breach".to_string(),
            "4. Preserve forensic evidence".to_string(),
            "5. Notify affected parties".to_string(),
            "6. Engage legal and compliance".to_string(),
            "7. File regulatory notifications".to_string(),
        ]);
        playbooks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soc_dashboard() {
        let dashboard = BlueTeam::get_soc_dashboard();
        assert!(dashboard.total_alerts > 0);
        assert!(dashboard.recent_alerts.len() > 0);
    }

    #[test]
    fn test_create_incident() {
        let incident = BlueTeam::create_incident(
            "Test Incident",
            "Test description",
            IncidentSeverity::P1,
            IncidentCategory::Malware,
        );
        assert!(incident.id.starts_with("INC-"));
        assert_eq!(incident.status, IncidentStatus::New);
    }

    #[test]
    fn test_threat_feeds() {
        let feeds = BlueTeam::get_threat_intel_feeds();
        assert_eq!(feeds.len(), 4);
    }

    #[test]
    fn test_threat_actors() {
        let actors = BlueTeam::get_threat_actors();
        assert!(actors.len() >= 2);
    }

    #[test]
    fn test_indicators() {
        let indicators = BlueTeam::get_sample_indicators();
        assert_eq!(indicators.len(), 3);
    }

    #[test]
    fn test_forensics_case() {
        let case = BlueTeam::create_forensics_case("Test", "Test case", ForensicsType::DiskImage);
        assert!(case.id.starts_with("CASE-"));
    }

    #[test]
    fn test_malware_analysis() {
        let analysis = BlueTeam::get_sample_malware_analysis();
        assert!(analysis.risk_score > 80);
    }

    #[test]
    fn test_hunt_hypothesis() {
        let hypothesis = BlueTeam::create_hunt_hypothesis("Test", "Test hunt", "T1059");
        assert_eq!(hypothesis.mitre_technique, "T1059");
    }

    #[test]
    fn test_ir_playbooks() {
        let playbooks = BlueTeam::get_ir_playbooks();
        assert!(playbooks.contains_key("Ransomware"));
        assert!(playbooks.contains_key("Phishing"));
    }
}
