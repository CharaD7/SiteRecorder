use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum GrayTeamError {
    #[error("Error: {0}")]
    Error(String),
}

type Result<T> = std::result::Result<T, GrayTeamError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttckMatrix {
    pub domains: Vec<AttckDomain>,
    pub techniques: Vec<AttckTechnique>,
    pub coverage: HashMap<String, TechniqueCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttckDomain {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tactics: Vec<AttckTactic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttckTactic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub short_name: String,
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttckTechnique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tactic: String,
    pub domain: String,
    pub platform: Vec<String>,
    pub data_sources: Vec<String>,
    pub detection: String,
    pub mitigation: String,
    pub sub_techniques: Vec<String>,
    pub parent_technique: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCoverage {
    pub technique_id: String,
    pub covered: bool,
    pub detection_level: DetectionLevel,
    pub prevention_level: PreventionLevel,
    pub tested: bool,
    pub test_results: Option<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionLevel {
    None,
    Partial,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PreventionLevel {
    None,
    Partial,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModel {
    pub id: String,
    pub name: String,
    pub description: String,
    pub scope: String,
    pub created_at: String,
    pub updated_at: String,
    pub threats: Vec<Threat>,
    pub assets: Vec<Asset>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub data_flows: Vec<DataFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub name: String,
    pub description: String,
    pub stride_category: StrideCategory,
    pub severity: ThreatSeverity,
    pub likelihood: Likelihood,
    pub impact: Impact,
    pub risk_score: f64,
    pub mitigations: Vec<String>,
    pub status: ThreatStatus,
    pub related_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StrideCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

impl std::fmt::Display for StrideCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrideCategory::Spoofing => write!(f, "Spoofing"),
            StrideCategory::Tampering => write!(f, "Tampering"),
            StrideCategory::Repudiation => write!(f, "Repudiation"),
            StrideCategory::InformationDisclosure => write!(f, "Information Disclosure"),
            StrideCategory::DenialOfService => write!(f, "Denial of Service"),
            StrideCategory::ElevationOfPrivilege => write!(f, "Elevation of Privilege"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Likelihood {
    VeryHigh,
    High,
    Medium,
    Low,
    VeryLow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Impact {
    VeryHigh,
    High,
    Medium,
    Low,
    VeryLow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatStatus {
    Identified,
    Assessed,
    Mitigated,
    Accepted,
    Transferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub name: String,
    pub asset_type: AssetType,
    pub description: String,
    pub sensitivity: Sensitivity,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AssetType {
    Data,
    Application,
    Server,
    Network,
    User,
    Device,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Sensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub from_zone: String,
    pub to_zone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    pub id: String,
    pub name: String,
    pub from_asset: String,
    pub to_asset: String,
    pub protocol: String,
    pub data_classification: Sensitivity,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamExercise {
    pub id: String,
    pub name: String,
    pub description: String,
    pub status: ExerciseStatus,
    pub created_at: String,
    pub scenarios: Vec<AttackScenario>,
    pub results: Vec<ExerciseResult>,
    pub overall_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExerciseStatus {
    Draft,
    Scheduled,
    InProgress,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    pub id: String,
    pub name: String,
    pub description: String,
    pub attack_type: String,
    pub mitre_techniques: Vec<String>,
    pub target_systems: Vec<String>,
    pub expected_detection: bool,
    pub actual_detection: Option<bool>,
    pub red_team_notes: String,
    pub blue_team_notes: String,
    pub duration_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseResult {
    pub scenario_id: String,
    pub technique_id: String,
    pub detected: bool,
    pub prevented: bool,
    pub time_to_detect_seconds: Option<u64>,
    pub time_to_respond_seconds: Option<u64>,
    pub gaps_identified: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rule_type: DetectionRuleType,
    pub content: String,
    pub language: String,
    pub mitre_techniques: Vec<String>,
    pub tested: bool,
    pub test_result: Option<String>,
    pub author: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionRuleType {
    Sigma,
    Yara,
    Snort,
    Suricata,
    KQL,
    Splunk,
    Elastic,
    Custom,
}

impl std::fmt::Display for DetectionRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionRuleType::Sigma => write!(f, "Sigma"),
            DetectionRuleType::Yara => write!(f, "YARA"),
            DetectionRuleType::Snort => write!(f, "Snort"),
            DetectionRuleType::Suricata => write!(f, "Suricata"),
            DetectionRuleType::KQL => write!(f, "KQL"),
            DetectionRuleType::Splunk => write!(f, "Splunk"),
            DetectionRuleType::Elastic => write!(f, "Elastic"),
            DetectionRuleType::Custom => write!(f, "Custom"),
        }
    }
}

pub struct GrayTeam;

impl GrayTeam {
    pub fn get_attck_matrix() -> AttckMatrix {
        let domains = vec![
            AttckDomain {
                id: "enterprise".to_string(),
                name: "Enterprise".to_string(),
                description: "Techniques targeting enterprise networks".to_string(),
                tactics: vec![
                    AttckTactic {
                        id: "TA0001".to_string(),
                        name: "Initial Access".to_string(),
                        description: "Techniques to gain initial access to a network".to_string(),
                        short_name: "initial-access".to_string(),
                        techniques: vec!["T1566".to_string(), "T1190".to_string(), "T1133".to_string(), "T1078".to_string()],
                    },
                    AttckTactic {
                        id: "TA0002".to_string(),
                        name: "Execution".to_string(),
                        description: "Techniques to run malicious code".to_string(),
                        short_name: "execution".to_string(),
                        techniques: vec!["T1059".to_string(), "T1204".to_string(), "T1053".to_string(), "T1106".to_string()],
                    },
                    AttckTactic {
                        id: "TA0003".to_string(),
                        name: "Persistence".to_string(),
                        description: "Techniques to maintain access".to_string(),
                        short_name: "persistence".to_string(),
                        techniques: vec!["T1547".to_string(), "T1053".to_string(), "T1136".to_string(), "T1543".to_string()],
                    },
                    AttckTactic {
                        id: "TA0004".to_string(),
                        name: "Privilege Escalation".to_string(),
                        description: "Techniques to gain higher-level permissions".to_string(),
                        short_name: "privilege-escalation".to_string(),
                        techniques: vec!["T1548".to_string(), "T1134".to_string(), "T1068".to_string(), "T1055".to_string()],
                    },
                    AttckTactic {
                        id: "TA0005".to_string(),
                        name: "Defense Evasion".to_string(),
                        description: "Techniques to avoid detection".to_string(),
                        short_name: "defense-evasion".to_string(),
                        techniques: vec!["T1070".to_string(), "T1036".to_string(), "T1027".to_string(), "T1140".to_string()],
                    },
                    AttckTactic {
                        id: "TA0006".to_string(),
                        name: "Credential Access".to_string(),
                        description: "Techniques to steal credentials".to_string(),
                        short_name: "credential-access".to_string(),
                        techniques: vec!["T1003".to_string(), "T1110".to_string(), "T1557".to_string(), "T1552".to_string()],
                    },
                    AttckTactic {
                        id: "TA0007".to_string(),
                        name: "Discovery".to_string(),
                        description: "Techniques to learn about the environment".to_string(),
                        short_name: "discovery".to_string(),
                        techniques: vec!["T1087".to_string(), "T1083".to_string(), "T1046".to_string(), "T1135".to_string()],
                    },
                    AttckTactic {
                        id: "TA0008".to_string(),
                        name: "Lateral Movement".to_string(),
                        description: "Techniques to move through the environment".to_string(),
                        short_name: "lateral-movement".to_string(),
                        techniques: vec!["T1021".to_string(), "T1570".to_string(), "T1563".to_string(), "T1080".to_string()],
                    },
                    AttckTactic {
                        id: "TA0009".to_string(),
                        name: "Collection".to_string(),
                        description: "Techniques to gather data".to_string(),
                        short_name: "collection".to_string(),
                        techniques: vec!["T1560".to_string(), "T1123".to_string(), "T1119".to_string(), "T1115".to_string()],
                    },
                    AttckTactic {
                        id: "TA0011".to_string(),
                        name: "Command and Control".to_string(),
                        description: "Techniques to communicate with compromised systems".to_string(),
                        short_name: "command-and-control".to_string(),
                        techniques: vec!["T1071".to_string(), "T1572".to_string(), "T1001".to_string(), "T1105".to_string()],
                    },
                    AttckTactic {
                        id: "TA0010".to_string(),
                        name: "Exfiltration".to_string(),
                        description: "Techniques to steal data".to_string(),
                        short_name: "exfiltration".to_string(),
                        techniques: vec!["T1041".to_string(), "T1048".to_string(), "T1567".to_string(), "T1029".to_string()],
                    },
                    AttckTactic {
                        id: "TA0040".to_string(),
                        name: "Impact".to_string(),
                        description: "Techniques to disrupt systems or data".to_string(),
                        short_name: "impact".to_string(),
                        techniques: vec!["T1486".to_string(), "T1489".to_string(), "T1499".to_string(), "T1529".to_string()],
                    },
                ],
            },
            AttckDomain {
                id: "mobile".to_string(),
                name: "Mobile".to_string(),
                description: "Techniques targeting mobile devices".to_string(),
                tactics: vec![
                    AttckTactic {
                        id: "TA0027".to_string(),
                        name: "Initial Access".to_string(),
                        description: "Mobile initial access techniques".to_string(),
                        short_name: "initial-access".to_string(),
                        techniques: vec!["T1444".to_string(), "T1476".to_string(), "T1401".to_string()],
                    },
                ],
            },
        ];

        let techniques = vec![
            AttckTechnique {
                id: "T1566".to_string(),
                name: "Phishing".to_string(),
                description: "Adversaries send malicious messages to trick users into revealing credentials or executing code.".to_string(),
                tactic: "TA0001".to_string(),
                domain: "enterprise".to_string(),
                platform: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string(), "Office 365".to_string(), "SaaS".to_string()],
                data_sources: vec!["Application Log".to_string(), "Network Traffic".to_string(), "Email".to_string()],
                detection: "Monitor for suspicious email attachments and URLs. Analyze email headers.".to_string(),
                mitigation: "User email security training. Implement email filtering and DMARC.".to_string(),
                sub_techniques: vec!["T1566.001".to_string(), "T1566.002".to_string(), "T1566.003".to_string()],
                parent_technique: None,
                references: vec!["https://attack.mitre.org/techniques/T1566".to_string()],
            },
            AttckTechnique {
                id: "T1059".to_string(),
                name: "Command and Scripting Interpreter".to_string(),
                description: "Adversaries abuse command-line interfaces and scripts for execution.".to_string(),
                tactic: "TA0002".to_string(),
                domain: "enterprise".to_string(),
                platform: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
                data_sources: vec!["Process Monitoring".to_string(), "Command Execution".to_string(), "Script Execution".to_string()],
                detection: "Monitor process creation events. Analyze command-line arguments.".to_string(),
                mitigation: "Restrict script execution. Use application whitelisting.".to_string(),
                sub_techniques: vec!["T1059.001".to_string(), "T1059.003".to_string(), "T1059.005".to_string(), "T1059.007".to_string()],
                parent_technique: None,
                references: vec!["https://attack.mitre.org/techniques/T1059".to_string()],
            },
            AttckTechnique {
                id: "T1078".to_string(),
                name: "Valid Accounts".to_string(),
                description: "Adversaries use legitimate credentials to access systems.".to_string(),
                tactic: "TA0001".to_string(),
                domain: "enterprise".to_string(),
                platform: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string(), "Office 365".to_string(), "Azure AD".to_string(), "SaaS".to_string(), "IaaS".to_string()],
                data_sources: vec!["Authentication Logs".to_string(), "Active Directory".to_string()],
                detection: "Monitor for unusual login patterns and account usage.".to_string(),
                mitigation: "Implement MFA. Monitor account creation and modification.".to_string(),
                sub_techniques: vec!["T1078.001".to_string(), "T1078.002".to_string(), "T1078.003".to_string(), "T1078.004".to_string()],
                parent_technique: None,
                references: vec!["https://attack.mitre.org/techniques/T1078".to_string()],
            },
            AttckTechnique {
                id: "T1003".to_string(),
                name: "OS Credential Dumping".to_string(),
                description: "Adversaries attempt to dump credentials from operating systems.".to_string(),
                tactic: "TA0006".to_string(),
                domain: "enterprise".to_string(),
                platform: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
                data_sources: vec!["Process Monitoring".to_string(), "API Monitoring".to_string(), "Windows Event Logs".to_string()],
                detection: "Monitor for access to LSASS process. Detect Mimikatz usage.".to_string(),
                mitigation: "Enable Credential Guard. Restrict debug privileges.".to_string(),
                sub_techniques: vec!["T1003.001".to_string(), "T1003.002".to_string(), "T1003.003".to_string(), "T1003.008".to_string()],
                parent_technique: None,
                references: vec!["https://attack.mitre.org/techniques/T1003".to_string()],
            },
            AttckTechnique {
                id: "T1055".to_string(),
                name: "Process Injection".to_string(),
                description: "Adversaries inject code into processes to evade detection.".to_string(),
                tactic: "TA0004".to_string(),
                domain: "enterprise".to_string(),
                platform: vec!["Windows".to_string(), "macOS".to_string(), "Linux".to_string()],
                data_sources: vec!["API Monitoring".to_string(), "Process Monitoring".to_string(), "DLL Monitoring".to_string()],
                detection: "Monitor for suspicious process memory operations.".to_string(),
                mitigation: "Enable ASLR and DEP. Use endpoint detection.".to_string(),
                sub_techniques: vec!["T1055.001".to_string(), "T1055.002".to_string(), "T1055.003".to_string(), "T1055.012".to_string()],
                parent_technique: None,
                references: vec!["https://attack.mitre.org/techniques/T1055".to_string()],
            },
        ];

        let mut coverage = HashMap::new();
        for technique in &techniques {
            coverage.insert(technique.id.clone(), TechniqueCoverage {
                technique_id: technique.id.clone(),
                covered: false,
                detection_level: DetectionLevel::None,
                prevention_level: PreventionLevel::None,
                tested: false,
                test_results: None,
                notes: String::new(),
            });
        }

        AttckMatrix {
            domains,
            techniques,
            coverage,
        }
    }

    pub fn create_threat_model(name: &str, description: &str) -> ThreatModel {
        ThreatModel {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            scope: String::new(),
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            threats: Vec::new(),
            assets: Vec::new(),
            trust_boundaries: Vec::new(),
            data_flows: Vec::new(),
        }
    }

    pub fn add_stride_threats(model: &mut ThreatModel) {
        model.threats.extend(vec![
            Threat {
                id: Uuid::new_v4().to_string(),
                name: "Spoofing of User Identity".to_string(),
                description: "An attacker impersonates a legitimate user to gain unauthorized access.".to_string(),
                stride_category: StrideCategory::Spoofing,
                severity: ThreatSeverity::High,
                likelihood: Likelihood::Medium,
                impact: Impact::High,
                risk_score: 7.5,
                mitigations: vec![
                    "Implement multi-factor authentication".to_string(),
                    "Use strong password policies".to_string(),
                    "Monitor for unusual login patterns".to_string(),
                ],
                status: ThreatStatus::Identified,
                related_techniques: vec!["T1078".to_string(), "T1566".to_string()],
            },
            Threat {
                id: Uuid::new_v4().to_string(),
                name: "Tampering with Data in Transit".to_string(),
                description: "An attacker modifies data being transmitted between components.".to_string(),
                stride_category: StrideCategory::Tampering,
                severity: ThreatSeverity::High,
                likelihood: Likelihood::Medium,
                impact: Impact::High,
                risk_score: 7.0,
                mitigations: vec![
                    "Implement TLS 1.3 for all communications".to_string(),
                    "Use message authentication codes (HMAC)".to_string(),
                    "Implement certificate pinning".to_string(),
                ],
                status: ThreatStatus::Identified,
                related_techniques: vec!["T1557".to_string()],
            },
            Threat {
                id: Uuid::new_v4().to_string(),
                name: "Information Disclosure via Error Messages".to_string(),
                description: "Detailed error messages expose sensitive system information.".to_string(),
                stride_category: StrideCategory::InformationDisclosure,
                severity: ThreatSeverity::Medium,
                likelihood: Likelihood::High,
                impact: Impact::Medium,
                risk_score: 5.5,
                mitigations: vec![
                    "Implement generic error messages".to_string(),
                    "Log detailed errors server-side only".to_string(),
                    "Sanitize all output".to_string(),
                ],
                status: ThreatStatus::Identified,
                related_techniques: vec!["T1552".to_string()],
            },
            Threat {
                id: Uuid::new_v4().to_string(),
                name: "Denial of Service".to_string(),
                description: "An attacker overwhelms the system to make it unavailable.".to_string(),
                stride_category: StrideCategory::DenialOfService,
                severity: ThreatSeverity::Medium,
                likelihood: Likelihood::Medium,
                impact: Impact::High,
                risk_score: 6.0,
                mitigations: vec![
                    "Implement rate limiting".to_string(),
                    "Use CDN and DDoS protection".to_string(),
                    "Configure connection timeouts".to_string(),
                ],
                status: ThreatStatus::Identified,
                related_techniques: vec!["T1499".to_string(), "T1498".to_string()],
            },
            Threat {
                id: Uuid::new_v4().to_string(),
                name: "Elevation of Privilege via Injection".to_string(),
                description: "An attacker exploits injection flaws to gain elevated privileges.".to_string(),
                stride_category: StrideCategory::ElevationOfPrivilege,
                severity: ThreatSeverity::Critical,
                likelihood: Likelihood::Medium,
                impact: Impact::VeryHigh,
                risk_score: 9.0,
                mitigations: vec![
                    "Use parameterized queries".to_string(),
                    "Implement input validation".to_string(),
                    "Apply principle of least privilege".to_string(),
                ],
                status: ThreatStatus::Identified,
                related_techniques: vec!["T1055".to_string(), "T1003".to_string()],
            },
        ]);
    }

    pub fn create_purple_team_exercise(name: &str, description: &str) -> PurpleTeamExercise {
        PurpleTeamExercise {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            status: ExerciseStatus::Draft,
            created_at: Utc::now().to_rfc3339(),
            scenarios: vec![
                AttackScenario {
                    id: Uuid::new_v4().to_string(),
                    name: "Phishing Campaign".to_string(),
                    description: "Simulated phishing attack targeting employees".to_string(),
                    attack_type: "Phishing".to_string(),
                    mitre_techniques: vec!["T1566.001".to_string(), "T1566.002".to_string()],
                    target_systems: vec!["Email Gateway".to_string(), "Workstations".to_string()],
                    expected_detection: true,
                    actual_detection: None,
                    red_team_notes: String::new(),
                    blue_team_notes: String::new(),
                    duration_minutes: 60,
                },
                AttackScenario {
                    id: Uuid::new_v4().to_string(),
                    name: "Credential Dumping".to_string(),
                    description: "Attempt to dump credentials from compromised workstation".to_string(),
                    attack_type: "Credential Access".to_string(),
                    mitre_techniques: vec!["T1003.001".to_string()],
                    target_systems: vec!["Workstation".to_string(), "Domain Controller".to_string()],
                    expected_detection: true,
                    actual_detection: None,
                    red_team_notes: String::new(),
                    blue_team_notes: String::new(),
                    duration_minutes: 30,
                },
                AttackScenario {
                    id: Uuid::new_v4().to_string(),
                    name: "Lateral Movement".to_string(),
                    description: "Move from workstation to server using stolen credentials".to_string(),
                    attack_type: "Lateral Movement".to_string(),
                    mitre_techniques: vec!["T1021.001".to_string(), "T1078".to_string()],
                    target_systems: vec!["Workstation".to_string(), "File Server".to_string()],
                    expected_detection: true,
                    actual_detection: None,
                    red_team_notes: String::new(),
                    blue_team_notes: String::new(),
                    duration_minutes: 45,
                },
            ],
            results: Vec::new(),
            overall_score: 0.0,
        }
    }

    pub fn get_sample_sigma_rules() -> Vec<DetectionRule> {
        vec![
            DetectionRule {
                id: Uuid::new_v4().to_string(),
                name: "Suspicious Process Creation".to_string(),
                description: "Detects suspicious process creation patterns".to_string(),
                rule_type: DetectionRuleType::Sigma,
                content: r#"title: Suspicious Process Creation
status: test
description: Detects suspicious process creation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'powershell -enc'
            - 'cmd /c'
            - 'wscript'
            - 'cscript'
    condition: selection
falsepositives:
    - Legitimate admin scripts
level: medium"#.to_string(),
                language: "YAML".to_string(),
                mitre_techniques: vec!["T1059".to_string()],
                tested: false,
                test_result: None,
                author: "SiteRecorder".to_string(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
            DetectionRule {
                id: Uuid::new_v4().to_string(),
                name: "LSASS Access".to_string(),
                description: "Detects processes accessing LSASS for credential dumping".to_string(),
                rule_type: DetectionRuleType::Sigma,
                content: r#"title: LSASS Access
status: test
description: Detects LSASS process access
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage: '*\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x143a'
    condition: selection
falsepositives:
    - Antivirus software
    - System processes
level: high"#.to_string(),
                language: "YAML".to_string(),
                mitre_techniques: vec!["T1003.001".to_string()],
                tested: false,
                test_result: None,
                author: "SiteRecorder".to_string(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
        ]
    }

    pub fn calculate_coverage_score(matrix: &AttckMatrix) -> f64 {
        let total = matrix.coverage.len();
        if total == 0 { return 0.0; }

        let covered = matrix.coverage.values()
            .filter(|c| c.covered)
            .count();

        (covered as f64 / total as f64) * 100.0
    }

    pub fn get_apt_group_techniques(group: &str) -> Vec<String> {
        match group.to_lowercase().as_str() {
            "apt28" | "fancy bear" => vec![
                "T1566".to_string(), "T1059".to_string(), "T1003".to_string(),
                "T1055".to_string(), "T1078".to_string(), "T1021".to_string(),
            ],
            "apt29" | "cozy bear" => vec![
                "T1566".to_string(), "T1059".to_string(), "T1003".to_string(),
                "T1552".to_string(), "T1078".to_string(), "T1105".to_string(),
            ],
            "lazarus" => vec![
                "T1566".to_string(), "T1486".to_string(), "T1490".to_string(),
                "T1059".to_string(), "T1003".to_string(), "T1055".to_string(),
            ],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attck_matrix() {
        let matrix = GrayTeam::get_attck_matrix();
        assert!(matrix.domains.len() > 0);
        assert!(matrix.techniques.len() > 0);
    }

    #[test]
    fn test_threat_model() {
        let mut model = GrayTeam::create_threat_model("Test", "Test model");
        GrayTeam::add_stride_threats(&mut model);
        assert_eq!(model.threats.len(), 5);
    }

    #[test]
    fn test_purple_team() {
        let exercise = GrayTeam::create_purple_team_exercise("Test", "Test exercise");
        assert_eq!(exercise.scenarios.len(), 3);
    }

    #[test]
    fn test_coverage_score() {
        let matrix = GrayTeam::get_attck_matrix();
        let score = GrayTeam::calculate_coverage_score(&matrix);
        assert!(score >= 0.0 && score <= 100.0);
    }

    #[test]
    fn test_apt_groups() {
        let techniques = GrayTeam::get_apt_group_techniques("apt28");
        assert!(techniques.len() > 0);
    }

    #[test]
    fn test_sigma_rules() {
        let rules = GrayTeam::get_sample_sigma_rules();
        assert_eq!(rules.len(), 2);
    }
}
