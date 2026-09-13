use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use browser::{Browser, NavigationOptions, ScrollBehavior};
use crawler::{CrawlConfig, Crawler};
use exporter::{Exporter, RecordingData};
use notifier::{Notifier, NotificationConfig};
use recorder::{Recorder, RecordingConfig, VideoFormat};
use scanner::{ScanConfig, VulnerabilityScanner, ScanReport};
use session::SessionManager;

use auth_engine::{AuthEngine, AuthType as EngineAuthType, AuthSession, ApiKeyLocation, OAuth2GrantType};
use auth_profiles::{AuthProfile, AuthProfileManager, AuthType as ProfileAuthType, MfaConfig, MfaType, ReauthStrategy};
use credentials::CredentialVault;
use network::{NetworkScanner, ScanConfig as NetworkScanConfig, ScanType as NetworkScanType};
use passwords::{PasswordCracker, CrackConfig, CrackMethod, HashType};
use os_pentest::{OsPentest, OsScanConfig, TargetOs};
use mobile::{MobileAnalyzer, MobileScanConfig, MobileTarget};
use cloud::{CloudAuditor, CloudScanConfig, CloudProvider};
use web3::{Web3Auditor, ContractScanConfig, WalletSecurityConfig, Blockchain};
use gray_team::{GrayTeam, AttckMatrix};
use blue_team::{BlueTeam, IncidentSeverity, IncidentCategory};
use white_team::WhiteTeam;
use cross_team::CrossTeam;
use http_proxy::{HttpProxy, ProxyConfig};
use packet_capture::{PacketCapture, CaptureFilter, FilterType};

mod cli;
use cli::{Cli, Commands, CrawlArgs, RecordingModeArg};

mod daemon;
use daemon::DaemonManager;

mod progress;
use progress::CrawlProgress;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordingSettings {
    url: String,
    max_pages: usize,
    delay_ms: u64,
    headless: bool,
    output_dir: String,
    fps: Option<u32>,
    requires_auth: bool,
    auth_url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    username_selector: Option<String>,
    password_selector: Option<String>,
    submit_selector: Option<String>,
    recording_mode: Option<String>, // "screen", "browser", or "both"
    enable_audio: Option<bool>,
    screen_width: Option<u32>,
    screen_height: Option<u32>,
    screen_region: Option<(i32, i32, i32, i32)>,
    daemon: bool,
    progress: bool,
    log_file: Option<std::path::PathBuf>,
    pid_file: Option<std::path::PathBuf>,
    proxy: Option<String>,
    sitemap: Option<String>,
    scan_url: Option<String>,
    login_script: Option<String>,
    concurrency: Option<usize>,
}

impl RecordingSettings {
    pub fn from_crawl_args(args: CrawlArgs) -> Self {
        let auth_url = args.auth_url.clone();
        RecordingSettings {
            url: args.url,
            max_pages: args.max_pages,
            delay_ms: args.delay,
            headless: args.headless,
            output_dir: args.output.to_string_lossy().to_string(),
            fps: Some(args.fps),
            requires_auth: auth_url.is_some(),
            auth_url,
            username: args.username,
            password: args.password,
            username_selector: None,
            password_selector: None,
            submit_selector: None,
            recording_mode: Some(match args.recording_mode {
                RecordingModeArg::Screen => "screen".to_string(),
                RecordingModeArg::Browser => "browser".to_string(),
                RecordingModeArg::Both => "both".to_string(),
            }),
            enable_audio: Some(args.audio),
            screen_width: Some(args.screen_width),
            screen_height: Some(args.screen_height),
            screen_region: args.region,
            daemon: args.daemon,
            progress: args.progress,
            log_file: args.log_file,
            pid_file: args.pid_file,
            proxy: args.proxy,
            sitemap: args.sitemap,
            scan_url: args.scan_url,
            login_script: args.login_script,
            concurrency: Some(args.concurrency),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CrawlStatus {
    is_running: bool,
    current_url: String,
    pages_visited: usize,
    pages_discovered: usize,
    session_id: String,
}

impl Default for CrawlStatus {
    fn default() -> Self {
        Self {
            is_running: false,
            current_url: String::new(),
            pages_visited: 0,
            pages_discovered: 0,
            session_id: String::new(),
        }
    }
}

struct AppState {
    status: Arc<Mutex<CrawlStatus>>,
    session_manager: Arc<Mutex<SessionManager>>,
    scan_results: Arc<Mutex<Option<ScanReport>>>,
    auth_manager: Arc<Mutex<AuthProfileManager>>,
    credential_vault: Arc<Mutex<CredentialVault>>,
    http_proxy: Arc<Mutex<Option<HttpProxy>>>,
    packet_capture: Arc<Mutex<Option<PacketCapture>>>,
    auth_engine: Arc<AuthEngine>,
}

#[tauri::command]
async fn start_recording(
    settings: RecordingSettings,
    state: State<'_, AppState>,
) -> Result<String, String> {
    eprintln!("=== START RECORDING CALLED ===");
    eprintln!("Settings: {:?}", settings);
    info!("Starting recording with settings: {:?}", settings);

    let mut status = state.status.lock().await;
    eprintln!("Got status lock, is_running: {}", status.is_running);
    
    if status.is_running {
        eprintln!("ERROR: Recording already in progress");
        return Err("Recording already in progress".to_string());
    }

    status.is_running = true;
    status.session_id = format!("session_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    status.current_url = settings.url.clone();
    status.pages_visited = 0;
    status.pages_discovered = 0;
    let session_id = status.session_id.clone();
    eprintln!("Created session: {}", session_id);
    drop(status);

    let status_arc = state.status.clone();
    let session_manager_arc = state.session_manager.clone();

    eprintln!("Spawning background task...");
    // Spawn background task
    tokio::spawn(async move {
        eprintln!("Background task started");
        if let Err(e) = run_recording(settings, status_arc, session_manager_arc).await {
            eprintln!("Recording failed: {}", e);
            error!("Recording failed: {}", e);
        }
        eprintln!("Background task completed");
    });

    eprintln!("Returning session_id: {}", session_id);
    Ok(session_id)
}

#[tauri::command]
async fn stop_recording(state: State<'_, AppState>) -> Result<(), String> {
    let mut status = state.status.lock().await;
    status.is_running = false;
    Ok(())
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<CrawlStatus, String> {
    let status = state.status.lock().await;
    Ok(status.clone())
}

#[tauri::command]
async fn run_vulnerability_scan(
    url: String,
    output_dir: Option<String>,
    state: State<'_, AppState>,
) -> Result<ScanReport, String> {
    info!("Starting vulnerability scan for: {}", url);

    let mut config = ScanConfig::new(&url).map_err(|e| e.to_string())?;
    if let Some(dir) = output_dir {
        config = config.with_output_dir(std::path::PathBuf::from(dir));
    }
    let mut scanner = VulnerabilityScanner::new(config).map_err(|e| e.to_string())?;

    let report = scanner.run_full_scan().await.map_err(|e| e.to_string())?;

    if let Err(e) = scanner.save_report(&report) {
        warn!("Could not persist scan report: {}", e);
    }

    let mut scan_results = state.scan_results.lock().await;
    *scan_results = Some(report.clone());

    info!("Vulnerability scan completed. Risk score: {:.1}", report.summary.risk_score);

    Ok(report)
}

#[tauri::command]
async fn get_scan_results(state: State<'_, AppState>) -> Result<Option<ScanReport>, String> {
    let scan_results = state.scan_results.lock().await;
    Ok(scan_results.clone())
}

#[tauri::command]
async fn list_vuln_scans(output_dir: String) -> Result<Vec<scanner::ScanMeta>, String> {
    let dir = std::path::PathBuf::from(output_dir);
    Ok(VulnerabilityScanner::list_scans(&dir))
}

#[tauri::command]
async fn load_vuln_scan(output_dir: String, scan_id: String) -> Result<ScanReport, String> {
    let path = std::path::PathBuf::from(output_dir)
        .join("scans")
        .join(format!("{}.json", scan_id));
    let data = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let report: ScanReport = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    Ok(report)
}

#[tauri::command]
async fn delete_vuln_scan(output_dir: String, scan_id: String) -> Result<(), String> {
    let path = std::path::PathBuf::from(output_dir)
        .join("scans")
        .join(format!("{}.json", scan_id));
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        info!("Deleted scan report {:?}", path);
    }
    Ok(())
}

#[tauri::command]
async fn export_vuln_scan(
    output_dir: String,
    scan_id: String,
    format: String,
) -> Result<String, String> {
    let report = load_vuln_scan(output_dir, scan_id).await?;
    if format.eq_ignore_ascii_case("csv") {
        Ok(report.to_csv())
    } else {
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn save_export(
    output_dir: String,
    scan_id: String,
    format: String,
    dest_path: String,
) -> Result<(), String> {
    let report = load_vuln_scan(output_dir, scan_id).await?;
    let content = if format.eq_ignore_ascii_case("csv") {
        report.to_csv()
    } else {
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    };
    std::fs::write(&dest_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

// ==================== AUTH PROFILE COMMANDS ====================

#[tauri::command]
async fn list_auth_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<AuthProfile>, String> {
    let manager = state.auth_manager.lock().await;
    manager.list_profiles().map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_auth_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<Option<AuthProfile>, String> {
    let manager = state.auth_manager.lock().await;
    manager.get_profile(&id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_auth_profile(
    profile: AuthProfile,
    state: State<'_, AppState>,
) -> Result<AuthProfile, String> {
    let manager = state.auth_manager.lock().await;
    manager.create_profile(&profile).map_err(|e| e.to_string())?;

    manager.add_audit_entry(
        "operator",
        "auth_profile_created",
        Some(&profile.target_url),
        Some(&format!("Created auth profile: {}", profile.name)),
        None,
    ).ok();

    Ok(profile)
}

#[tauri::command]
async fn update_auth_profile(
    profile: AuthProfile,
    state: State<'_, AppState>,
) -> Result<AuthProfile, String> {
    let manager = state.auth_manager.lock().await;
    manager.update_profile(&profile).map_err(|e| e.to_string())?;

    manager.add_audit_entry(
        "operator",
        "auth_profile_updated",
        Some(&profile.target_url),
        Some(&format!("Updated auth profile: {}", profile.name)),
        None,
    ).ok();

    Ok(profile)
}

#[tauri::command]
async fn delete_auth_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = state.auth_manager.lock().await;
    manager.delete_profile(&id).map_err(|e| e.to_string())?;

    manager.add_audit_entry(
        "operator",
        "auth_profile_deleted",
        None,
        Some(&format!("Deleted auth profile: {}", id)),
        None,
    ).ok();

    Ok(())
}

#[tauri::command]
async fn test_auth_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<auth_profiles::AuthTestResult, String> {
    let manager = state.auth_manager.lock().await;
    let profile = manager.get_profile(&id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Profile not found".to_string())?;

    manager.update_last_used(&id).ok();

    Ok(auth_profiles::AuthTestResult {
        success: true,
        message: format!("Authentication profile '{}' is valid. Full login test requires browser automation.", profile.name),
        session_token: None,
        cookies: None,
    })
}

#[tauri::command]
async fn generate_totp(
    secret: String,
) -> Result<auth_profiles::TotpResult, String> {
    auth_profiles::TotpGenerator::generate_code(&secret)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn validate_totp(
    secret: String,
    code: String,
) -> Result<bool, String> {
    auth_profiles::TotpGenerator::validate_code(&secret, &code)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn generate_totp_secret() -> Result<String, String> {
    Ok(auth_profiles::TotpGenerator::generate_secret())
}

#[tauri::command]
async fn get_totp_provisioning_uri(
    secret: String,
    account: String,
    issuer: String,
) -> Result<String, String> {
    auth_profiles::TotpGenerator::get_provisioning_uri(&secret, &account, &issuer)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn unlock_vault(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let mut vault = state.credential_vault.lock().await;
    vault.unlock(&master_password)
        .map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
async fn lock_vault(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut vault = state.credential_vault.lock().await;
    vault.lock();
    Ok(())
}

#[tauri::command]
async fn is_vault_locked(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let vault = state.credential_vault.lock().await;
    Ok(vault.is_locked())
}

#[tauri::command]
async fn list_audit_entries(
    limit: Option<i64>,
    state: State<'_, AppState>,
) -> Result<Vec<auth_profiles::AuditEntry>, String> {
    let manager = state.auth_manager.lock().await;
    manager.list_audit_entries(limit).map_err(|e| e.to_string())
}

// ==================== NETWORK SCANNER COMMANDS ====================

#[tauri::command]
async fn network_port_scan(
    target: String,
    ports: Option<Vec<u16>>,
    timeout_ms: Option<u64>,
) -> Result<network::ScanResult, String> {
    let mut config = NetworkScanConfig::default();
    config.target = target;
    if let Some(p) = ports { config.ports = p; }
    if let Some(t) = timeout_ms { config.timeout_ms = t; }

    NetworkScanner::scan_ports(config).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn network_dns_lookup(domain: String) -> Result<network::DnsResult, String> {
    NetworkScanner::dns_lookup(&domain).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn network_subdomain_enum(
    domain: String,
    wordlist: Option<Vec<String>>,
) -> Result<network::SubdomainResult, String> {
    NetworkScanner::enumerate_subdomains(&domain, wordlist).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn network_ssl_check(
    hostname: String,
    port: Option<u16>,
) -> Result<network::SslInfo, String> {
    let port = port.unwrap_or(443);
    NetworkScanner::check_ssl(&hostname, port).await.map_err(|e| e.to_string())
}

// ==================== PASSWORD ATTACK COMMANDS ====================

#[tauri::command]
async fn password_identify_hash(hash: String) -> Result<Vec<passwords::HashInfo>, String> {
    Ok(PasswordCracker::identify_hash(&hash))
}

#[tauri::command]
async fn password_crack(
    hash: String,
    hash_type: String,
    wordlist: Vec<String>,
    max_attempts: Option<usize>,
) -> Result<passwords::CrackResult, String> {
    let hash_type = match hash_type.as_str() {
        "md5" => HashType::Md5,
        "sha1" => HashType::Sha1,
        "sha256" => HashType::Sha256,
        "sha512" => HashType::Sha512,
        _ => HashType::Unknown(hash_type),
    };

    let config = CrackConfig {
        hash,
        hash_type,
        wordlist,
        max_attempts: max_attempts.unwrap_or(1_000_000),
        ..Default::default()
    };

    Ok(PasswordCracker::crack_hash(&config))
}

#[tauri::command]
async fn password_generate_mask(
    charset: String,
    min_length: usize,
    max_length: usize,
) -> Result<Vec<String>, String> {
    use passwords::MaskConfig;
    use passwords::MaskCharset;

    let charset = match charset.as_str() {
        "lowercase" => MaskCharset::Lowercase,
        "uppercase" => MaskCharset::Uppercase,
        "digits" => MaskCharset::Digits,
        "alpha" => MaskCharset::Alpha,
        "alphanumeric" => MaskCharset::Alphanumeric,
        "all" => MaskCharset::All,
        custom => MaskCharset::Custom(custom.to_string()),
    };

    let config = MaskConfig {
        charset,
        min_length,
        max_length,
        pattern: None,
    };

    Ok(PasswordCracker::generate_mask_candidates(&config))
}

#[tauri::command]
async fn password_get_wordlists() -> Result<Vec<passwords::WordlistInfo>, String> {
    Ok(PasswordCracker::get_wordlist_info())
}

#[tauri::command]
async fn password_get_default_wordlist() -> Result<Vec<String>, String> {
    Ok(PasswordCracker::get_default_wordlist())
}

// ==================== OS PENTEST COMMANDS ====================

#[tauri::command]
async fn os_pentest_scan(
    target_os: String,
) -> Result<os_pentest::OsScanResult, String> {
    let target = match target_os.as_str() {
        "linux" => TargetOs::Linux,
        "windows" => TargetOs::Windows,
        "macos" => TargetOs::MacOS,
        _ => TargetOs::Linux,
    };

    let config = OsScanConfig {
        target_os: target.clone(),
        ..Default::default()
    };

    let result = match target {
        TargetOs::Linux => OsPentest::scan_linux(&config),
        TargetOs::Windows => OsPentest::scan_windows(&config),
        TargetOs::MacOS => OsPentest::scan_macos(&config),
    };

    Ok(result)
}

// ==================== MOBILE ANALYSIS COMMANDS ====================

#[tauri::command]
async fn mobile_analyze(
    target: String,
) -> Result<mobile::MobileScanResult, String> {
    let target_type = match target.as_str() {
        "android" => MobileTarget::Android,
        "ios" => MobileTarget::IOS,
        _ => MobileTarget::Android,
    };

    let config = MobileScanConfig {
        target_type: target_type.clone(),
        apk_path: None,
        ipa_path: None,
        deep_analysis: false,
        check_categories: vec![
            mobile::MobileCheckCategory::Manifest,
            mobile::MobileCheckCategory::Storage,
            mobile::MobileCheckCategory::Network,
            mobile::MobileCheckCategory::Cryptography,
            mobile::MobileCheckCategory::WebView,
            mobile::MobileCheckCategory::Authentication,
            mobile::MobileCheckCategory::Binary,
        ],
    };

    let result = match target_type {
        MobileTarget::Android => MobileAnalyzer::analyze_apk(&config),
        MobileTarget::IOS => MobileAnalyzer::analyze_ipa(&config),
    };

    Ok(result)
}

// ==================== CLOUD SECURITY COMMANDS ====================

#[tauri::command]
async fn cloud_scan(
    provider: String,
) -> Result<cloud::CloudScanResult, String> {
    let provider = match provider.as_str() {
        "aws" => CloudProvider::AWS,
        "azure" => CloudProvider::Azure,
        "gcp" => CloudProvider::GCP,
        _ => CloudProvider::AWS,
    };

    let config = CloudScanConfig {
        provider: provider.clone(),
        account_id: None,
        regions: vec!["us-east-1".to_string()],
        checks: vec![
            cloud::CloudCheck::IAM,
            cloud::CloudCheck::Storage,
            cloud::CloudCheck::Network,
            cloud::CloudCheck::Logging,
            cloud::CloudCheck::Encryption,
            cloud::CloudCheck::Database,
            cloud::CloudCheck::Compute,
        ],
    };

    let result = match provider {
        CloudProvider::AWS => CloudAuditor::scan_aws(&config),
        CloudProvider::Azure => CloudAuditor::scan_azure(&config),
        CloudProvider::GCP => CloudAuditor::scan_gcp(&config),
    };

    Ok(result)
}

// ==================== WEB3 SECURITY COMMANDS ====================

#[tauri::command]
async fn web3_scan_contract(
    chain: String,
) -> Result<web3::ContractScanResult, String> {
    let chain = match chain.as_str() {
        "ethereum" => Blockchain::Ethereum,
        "polygon" => Blockchain::Polygon,
        "bsc" => Blockchain::BSC,
        "arbitrum" => Blockchain::Arbitrum,
        "optimism" => Blockchain::Optimism,
        "solana" => Blockchain::Solana,
        _ => Blockchain::Ethereum,
    };

    let config = ContractScanConfig {
        contract_address: None,
        source_code: None,
        chain,
        check_categories: vec![
            web3::ContractCheck::Reentrancy,
            web3::ContractCheck::AccessControl,
            web3::ContractCheck::Arithmetic,
            web3::ContractCheck::FrontRunning,
            web3::ContractCheck::OracleManipulation,
            web3::ContractCheck::FlashLoan,
            web3::ContractCheck::Logic,
            web3::ContractCheck::Proxy,
            web3::ContractCheck::Gas,
        ],
    };

    Ok(Web3Auditor::scan_contract(&config))
}

#[tauri::command]
async fn web3_analyze_wallet(
    address: String,
    chain: String,
) -> Result<web3::WalletSecurityResult, String> {
    let chain = match chain.as_str() {
        "ethereum" => Blockchain::Ethereum,
        "polygon" => Blockchain::Polygon,
        "bsc" => Blockchain::BSC,
        _ => Blockchain::Ethereum,
    };

    let config = WalletSecurityConfig {
        address,
        chain,
        check_categories: vec![
            web3::WalletCheck::Approvals,
            web3::WalletCheck::Exposure,
            web3::WalletCheck::Phishing,
            web3::WalletCheck::Compliance,
        ],
    };

    Ok(Web3Auditor::analyze_wallet(&config))
}

// ==================== API SCANNER COMMANDS ====================

#[tauri::command]
async fn api_scan(
    base_url: String,
    auth_token: Option<String>,
    auth_type: Option<String>,
    endpoints: Option<Vec<String>>,
) -> Result<scanner::ApiScanReport, String> {
    let auth_type = match auth_type.as_deref() {
        Some("bearer") => scanner::ApiAuthType::Bearer,
        Some("apikey") => scanner::ApiAuthType::ApiKey,
        Some("basic") => scanner::ApiAuthType::Basic,
        Some("oauth2") => scanner::ApiAuthType::OAuth2,
        _ => scanner::ApiAuthType::None,
    };

    let config = scanner::ApiScanConfig {
        base_url,
        auth_token,
        auth_type,
        endpoints: endpoints.unwrap_or_default(),
        timeout_secs: 30,
    };

    let scanner = scanner::ApiScanner::new(config).map_err(|e| e.to_string())?;
    scanner.run_api_scan().await.map_err(|e| e.to_string())
}

// ==================== GRAY TEAM COMMANDS ====================

#[tauri::command]
async fn grayteam_get_attck_matrix() -> Result<gray_team::AttckMatrix, String> {
    Ok(GrayTeam::get_attck_matrix())
}

#[tauri::command]
async fn grayteam_create_threat_model(
    name: String,
    description: String,
) -> Result<gray_team::ThreatModel, String> {
    let mut model = GrayTeam::create_threat_model(&name, &description);
    GrayTeam::add_stride_threats(&mut model);
    Ok(model)
}

#[tauri::command]
async fn grayteam_create_purple_exercise(
    name: String,
    description: String,
) -> Result<gray_team::PurpleTeamExercise, String> {
    Ok(GrayTeam::create_purple_team_exercise(&name, &description))
}

#[tauri::command]
async fn grayteam_get_sigma_rules() -> Result<Vec<gray_team::DetectionRule>, String> {
    Ok(GrayTeam::get_sample_sigma_rules())
}

#[tauri::command]
async fn grayteam_get_apt_techniques(group: String) -> Result<Vec<String>, String> {
    Ok(GrayTeam::get_apt_group_techniques(&group))
}

// ==================== BLUE TEAM COMMANDS ====================

#[tauri::command]
async fn blueteam_get_soc_dashboard() -> Result<blue_team::SocDashboard, String> {
    Ok(BlueTeam::get_soc_dashboard())
}

#[tauri::command]
async fn blueteam_create_incident(
    title: String,
    description: String,
    severity: String,
    category: String,
) -> Result<blue_team::Incident, String> {
    let severity = match severity.as_str() {
        "P1" => IncidentSeverity::P1,
        "P2" => IncidentSeverity::P2,
        "P3" => IncidentSeverity::P3,
        _ => IncidentSeverity::P4,
    };
    let category = match category.as_str() {
        "malware" => IncidentCategory::Malware,
        "phishing" => IncidentCategory::Phishing,
        "breach" => IncidentCategory::DataBreach,
        "ddos" => IncidentCategory::DDoS,
        "ransomware" => IncidentCategory::Ransomware,
        "apt" => IncidentCategory::APT,
        _ => IncidentCategory::Other,
    };
    Ok(BlueTeam::create_incident(&title, &description, severity, category))
}

#[tauri::command]
async fn blueteam_get_threat_feeds() -> Result<Vec<blue_team::ThreatIntelFeed>, String> {
    Ok(BlueTeam::get_threat_intel_feeds())
}

#[tauri::command]
async fn blueteam_get_threat_actors() -> Result<Vec<blue_team::ThreatActor>, String> {
    Ok(BlueTeam::get_threat_actors())
}

#[tauri::command]
async fn blueteam_get_indicators() -> Result<Vec<blue_team::Indicator>, String> {
    Ok(BlueTeam::get_sample_indicators())
}

#[tauri::command]
async fn blueteam_get_malware_analysis() -> Result<blue_team::MalwareAnalysis, String> {
    Ok(BlueTeam::get_sample_malware_analysis())
}

#[tauri::command]
async fn blueteam_create_hunt(
    title: String,
    description: String,
    mitre_technique: String,
) -> Result<blue_team::HuntHypothesis, String> {
    Ok(BlueTeam::create_hunt_hypothesis(&title, &description, &mitre_technique))
}

#[tauri::command]
async fn blueteam_get_ir_playbooks() -> Result<HashMap<String, Vec<String>>, String> {
    Ok(BlueTeam::get_ir_playbooks())
}

// ==================== WHITE TEAM COMMANDS ====================

#[tauri::command]
async fn whiteteam_get_grc_dashboard() -> Result<white_team::GrcDashboard, String> {
    Ok(WhiteTeam::get_grc_dashboard())
}

#[tauri::command]
async fn whiteteam_get_compliance_frameworks() -> Result<Vec<white_team::ComplianceFramework>, String> {
    Ok(WhiteTeam::get_compliance_frameworks())
}

#[tauri::command]
async fn whiteteam_get_risk_register() -> Result<white_team::RiskRegister, String> {
    Ok(WhiteTeam::get_risk_register())
}

#[tauri::command]
async fn whiteteam_get_policies() -> Result<Vec<white_team::Policy>, String> {
    Ok(WhiteTeam::get_policies())
}

#[tauri::command]
async fn whiteteam_get_vendors() -> Result<Vec<white_team::Vendor>, String> {
    Ok(WhiteTeam::get_vendors())
}

#[tauri::command]
async fn whiteteam_get_training() -> Result<Vec<white_team::TrainingModule>, String> {
    Ok(WhiteTeam::get_training_modules())
}

// ==================== CROSS-TEAM COMMANDS ====================

#[tauri::command]
async fn cross_get_assets() -> Result<Vec<cross_team::Asset>, String> {
    Ok(CrossTeam::get_assets())
}

#[tauri::command]
async fn cross_get_notifications() -> Result<Vec<cross_team::Notification>, String> {
    Ok(CrossTeam::get_notifications())
}

#[tauri::command]
async fn cross_get_alert_rules() -> Result<Vec<cross_team::AlertRule>, String> {
    Ok(CrossTeam::get_alert_rules())
}

#[tauri::command]
async fn cross_get_report_templates() -> Result<Vec<cross_team::ReportTemplate>, String> {
    Ok(CrossTeam::get_report_templates())
}

#[tauri::command]
async fn cross_get_integrations() -> Result<Vec<cross_team::Integration>, String> {
    Ok(CrossTeam::get_integrations())
}

// ==================== HTTP PROXY COMMANDS ====================

#[tauri::command]
async fn proxy_start(
    port: Option<u16>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut proxy_lock = state.http_proxy.lock().await;
    if proxy_lock.is_some() {
        return Err("Proxy already running".to_string());
    }
    let (proxy, _rx) = HttpProxy::new();
    let mut config = ProxyConfig::default();
    if let Some(p) = port {
        config.listen_port = p;
    }
    proxy.set_config(config).await;
    proxy.start().await.map_err(|e| e.to_string())?;
    *proxy_lock = Some(proxy);
    let addr = format!("http://127.0.0.1:{}", port.unwrap_or(8080));
    info!("HTTP Proxy started on {}", addr);
    Ok(format!("Proxy started on {}", addr))
}

#[tauri::command]
async fn proxy_stop(
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut proxy_lock = state.http_proxy.lock().await;
    if let Some(proxy) = proxy_lock.take() {
        proxy.stop().await;
        info!("HTTP Proxy stopped");
        Ok("Proxy stopped".to_string())
    } else {
        Err("Proxy not running".to_string())
    }
}

#[tauri::command]
async fn proxy_get_sessions(
    state: State<'_, AppState>,
) -> Result<Vec<http_proxy::ProxySession>, String> {
    let proxy_lock = state.http_proxy.lock().await;
    if let Some(proxy) = proxy_lock.as_ref() {
        Ok(proxy.get_sessions().await)
    } else {
        Ok(Vec::new())
    }
}

#[tauri::command]
async fn proxy_get_config(
    state: State<'_, AppState>,
) -> Result<ProxyConfig, String> {
    let proxy_lock = state.http_proxy.lock().await;
    if let Some(proxy) = proxy_lock.as_ref() {
        Ok(proxy.get_config().await)
    } else {
        Ok(ProxyConfig::default())
    }
}

#[tauri::command]
async fn proxy_set_config(
    config: ProxyConfig,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let proxy_lock = state.http_proxy.lock().await;
    if let Some(proxy) = proxy_lock.as_ref() {
        proxy.set_config(config).await;
        Ok(())
    } else {
        Err("Proxy not running".to_string())
    }
}

#[tauri::command]
async fn proxy_clear_sessions(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let proxy_lock = state.http_proxy.lock().await;
    if let Some(proxy) = proxy_lock.as_ref() {
        proxy.clear_sessions().await;
        Ok(())
    } else {
        Err("Proxy not running".to_string())
    }
}

// ==================== PACKET CAPTURE COMMANDS ====================

#[tauri::command]
async fn packet_list_interfaces() -> Result<Vec<packet_capture::NetworkInterfaceInfo>, String> {
    Ok(PacketCapture::list_interfaces().await)
}

#[tauri::command]
async fn packet_start_capture(
    interface: String,
    promiscuous: Option<bool>,
    filter: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut capture_lock = state.packet_capture.lock().await;
    if capture_lock.is_some() {
        return Err("Capture already running".to_string());
    }
    let (capture, _rx) = PacketCapture::new();
    capture.start_capture(&interface, promiscuous.unwrap_or(false), filter.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    *capture_lock = Some(capture);
    info!("Packet capture started on {}", interface);
    Ok(format!("Capture started on {}", interface))
}

#[tauri::command]
async fn packet_stop_capture(
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut capture_lock = state.packet_capture.lock().await;
    if let Some(capture) = capture_lock.as_ref() {
        capture.stop_capture().await;
    }
    capture_lock.take();
    info!("Packet capture stopped");
    Ok("Capture stopped".to_string())
}

#[tauri::command]
async fn packet_get_packets(
    limit: Option<usize>,
    state: State<'_, AppState>,
) -> Result<Vec<packet_capture::PacketInfo>, String> {
    let capture_lock = state.packet_capture.lock().await;
    if let Some(capture) = capture_lock.as_ref() {
        let packets = capture.get_packets().await;
        let limit = limit.unwrap_or(1000);
        Ok(packets.into_iter().take(limit).collect())
    } else {
        Ok(Vec::new())
    }
}

#[tauri::command]
async fn packet_get_stats(
    state: State<'_, AppState>,
) -> Result<packet_capture::CaptureStats, String> {
    let capture_lock = state.packet_capture.lock().await;
    if let Some(capture) = capture_lock.as_ref() {
        Ok(capture.get_stats().await)
    } else {
        Ok(packet_capture::CaptureStats {
            total_packets: 0,
            total_bytes: 0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
            protocol_distribution: std::collections::HashMap::new(),
            top_talkers: Vec::new(),
            errors: 0,
        })
    }
}

#[tauri::command]
async fn packet_clear_packets(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let capture_lock = state.packet_capture.lock().await;
    if let Some(capture) = capture_lock.as_ref() {
        capture.clear_packets().await;
        Ok(())
    } else {
        Err("No capture running".to_string())
    }
}

// ==================== AUTH ENGINE COMMANDS ====================

#[tauri::command]
async fn auth_authenticate(
    auth_type: String,
    config: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<auth_engine::AuthSession, String> {
    let auth = parse_auth_type(&auth_type, &config)?;
    let session = state.auth_engine.authenticate(&auth).await.map_err(|e| e.to_string())?;
    state.auth_engine.save_session(session.clone()).await;
    Ok(session)
}

#[tauri::command]
async fn auth_test_session(
    session_id: String,
    url: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let session = state.auth_engine.get_session(&session_id).await
        .ok_or_else(|| "Session not found".to_string())?;

    let response = state.auth_engine.make_authenticated_request(&session, "GET", &url, None).await
        .map_err(|e| e.to_string())?;

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    Ok(serde_json::json!({
        "status": status,
        "body_preview": body.chars().take(500).collect::<String>(),
        "authenticated": session.is_authenticated,
    }))
}

#[tauri::command]
async fn auth_refresh_session(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<auth_engine::AuthSession, String> {
    let mut session = state.auth_engine.get_session(&session_id).await
        .ok_or_else(|| "Session not found".to_string())?;

    state.auth_engine.refresh_session(&mut session).await.map_err(|e| e.to_string())?;
    state.auth_engine.save_session(session.clone()).await;
    Ok(session)
}

fn parse_auth_type(auth_type: &str, config: &serde_json::Value) -> Result<EngineAuthType, String> {
    match auth_type {
        "none" => Ok(EngineAuthType::None),
        "basic" => {
            let username = config["username"].as_str().unwrap_or("").to_string();
            let password = config["password"].as_str().unwrap_or("").to_string();
            Ok(EngineAuthType::Basic { username, password })
        }
        "bearer" => {
            let token = config["token"].as_str().unwrap_or("").to_string();
            Ok(EngineAuthType::Bearer { token })
        }
        "apikey" => {
            let key = config["key"].as_str().unwrap_or("").to_string();
            let header = config["header"].as_str().unwrap_or("X-API-Key").to_string();
            let location = match config["location"].as_str() {
                Some("query") => ApiKeyLocation::Query,
                Some("cookie") => ApiKeyLocation::Cookie,
                _ => ApiKeyLocation::Header,
            };
            Ok(EngineAuthType::ApiKey { key, header, location })
        }
        "cookie" => {
            let mut cookies = std::collections::HashMap::new();
            if let Some(obj) = config["cookies"].as_object() {
                for (k, v) in obj {
                    if let Some(val) = v.as_str() {
                        cookies.insert(k.clone(), val.to_string());
                    }
                }
            }
            Ok(EngineAuthType::Cookie { cookies })
        }
        "form" => {
            let login_url = config["login_url"].as_str().unwrap_or("").to_string();
            let username_field = config["username_field"].as_str().unwrap_or("username").to_string();
            let password_field = config["password_field"].as_str().unwrap_or("password").to_string();
            let username = config["username"].as_str().unwrap_or("").to_string();
            let password = config["password"].as_str().unwrap_or("").to_string();
            let csrf_field = config["csrf_field"].as_str().map(|s| s.to_string());
            let success_indicator = config["success_indicator"].as_str().map(|s| s.to_string());
            let failure_indicator = config["failure_indicator"].as_str().map(|s| s.to_string());
            let extra_fields = std::collections::HashMap::new();
            Ok(EngineAuthType::FormBased {
                login_url,
                username_field,
                password_field,
                username,
                password,
                extra_fields,
                csrf_field,
                success_indicator,
                failure_indicator,
            })
        }
        "oauth2" => {
            let token_url = config["token_url"].as_str().unwrap_or("").to_string();
            let client_id = config["client_id"].as_str().unwrap_or("").to_string();
            let client_secret = config["client_secret"].as_str().unwrap_or("").to_string();
            let scope = config["scope"].as_str().map(|s| s.to_string());
            Ok(EngineAuthType::OAuth2 {
                token_url,
                client_id,
                client_secret,
                scope,
                grant_type: OAuth2GrantType::ClientCredentials,
                access_token: None,
                refresh_token: None,
                expires_at: None,
            })
        }
        "custom" => {
            let mut headers = std::collections::HashMap::new();
            if let Some(obj) = config["headers"].as_object() {
                for (k, v) in obj {
                    if let Some(val) = v.as_str() {
                        headers.insert(k.clone(), val.to_string());
                    }
                }
            }
            Ok(EngineAuthType::Custom { headers })
        }
        _ => Err(format!("Unknown auth type: {}", auth_type)),
    }
}

async fn run_recording(
    settings: RecordingSettings,
    status: Arc<Mutex<CrawlStatus>>,
    session_manager: Arc<Mutex<SessionManager>>,
) -> Result<()> {
    eprintln!("=== RUN RECORDING STARTED ===");
    eprintln!("Settings: {:?}", settings);
    
    // Initialize components
    eprintln!("Creating browser...");
    let browser = if settings.headless {
        Browser::new_headless()?
    } else {
        Browser::new()?
    };
    eprintln!("Browser created successfully");

    let crawl_config = CrawlConfig::new(&settings.url)?;
    let crawl_config = if let Some(ref proxy) = settings.proxy {
        crawl_config.with_proxy(proxy)
    } else {
        crawl_config
    };
    let crawl_config = if let Some(ref sitemap) = settings.sitemap {
        crawl_config.with_sitemap(sitemap)
    } else {
        crawl_config
    };
    let crawl_config = crawl_config.with_concurrency(settings.concurrency.unwrap_or(1));
    let crawler = Arc::new(Mutex::new(Crawler::new(crawl_config)));

    // Ingest sitemap if provided
    if settings.sitemap.is_some() {
        if let Ok(count) = crawler.lock().await.ingest_sitemap().await {
            info!("Ingested {} URLs from sitemap", count);
        }
    }

    // Spawn concurrent prefetch workers to expand the crawl frontier in parallel
    let concurrency = settings.concurrency.unwrap_or(1).max(1);
    let prefetch_active = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if concurrency > 1 {
        for _ in 0..concurrency {
            let crawler_clone = crawler.clone();
            let active = prefetch_active.clone();
            let status_clone = status.clone();
            worker_handles.push(tokio::spawn(async move {
                loop {
                    if !status_clone.lock().await.is_running {
                        break;
                    }
                    let url = { crawler_clone.lock().await.next_prefetch_url() };
                    match url {
                        Some(u) => {
                            let links = crawler_clone.lock().await.prefetch_links(&u).await;
                            crawler_clone.lock().await.add_discovered_links(links);
                        }
                        None => {
                            if !active.load(std::sync::atomic::Ordering::SeqCst) {
                                break;
                            }
                            sleep(Duration::from_millis(150)).await;
                        }
                    }
                }
            }));
        }
        info!("Started {} concurrent crawl workers", concurrency);
    }

    // Parse recording mode from settings
    let recording_mode = match settings.recording_mode.as_deref() {
        Some("screen") => recorder::RecordingMode::Screen,
        Some("browser") => recorder::RecordingMode::Browser,
        Some("both") => recorder::RecordingMode::Both,
        _ => recorder::RecordingMode::Both, // Default to Both
    };

    let recording_config = RecordingConfig {
        output_dir: std::path::PathBuf::from(&settings.output_dir),
        format: VideoFormat::Mp4,
        fps: settings.fps.unwrap_or(30),
        quality: 80,
        audio_enabled: settings.enable_audio.unwrap_or(false),
            mode: recording_mode,
            screen_width: settings.screen_width.or(Some(1920)),
            screen_height: settings.screen_height.or(Some(1080)),
            screen_region: settings.screen_region,
        };
        let recorder = Recorder::new(recording_config);

    let notifier = Notifier::new(NotificationConfig::default());
    let exporter = Exporter::new();

    // Get session ID
    let session_id = status.lock().await.session_id.clone();

    // Create session
    session_manager.lock().await.create_session(session_id.clone()).await?;

    // Start recording
    recorder.start_recording(session_id.clone(), Some(settings.url.clone())).await?;
    notifier.notify_recording_started(&session_id)?;

    // Get browser tab
    let tab = browser.get_tab()?;
    
    // Set browser tab for recording
    recorder.set_browser_tab(tab.clone()).await;

    let nav_options = NavigationOptions {
        timeout_ms: 30000,
        wait_for_idle: true,
        scroll_behavior: ScrollBehavior::Incremental {
            steps: 5,
            delay_ms: 500,
        },
    };

    // Handle authentication if required
    if settings.requires_auth {
        if let Some(auth_url) = &settings.auth_url {
            info!("Navigating to login page: {}", auth_url);
            
            match browser.navigate(&tab, auth_url, &nav_options) {
                Ok(_) => {
                    info!("Login page loaded, attempting authentication...");

                    if let Some(script) = &settings.login_script {
                        // Custom login script path
                        let username = settings.username.clone().unwrap_or_default();
                        let password = settings.password.clone().unwrap_or_default();
                        let setup = format!(
                            "window.__SR_USER = {}; window.__SR_PASS = {};",
                            js_quote(&username),
                            js_quote(&password)
                        );
                        if let Err(e) = browser.execute_script(&tab, &setup) {
                            warn!("Failed to inject credentials for login script: {}", e);
                        }
                        match browser.execute_script(&tab, script) {
                            Ok(_) => {
                                info!("Custom login script executed");
                                notifier.notify_info("Authentication", "Custom login script executed")?;
                                sleep(Duration::from_millis(3000)).await; // Wait for redirect
                            }
                            Err(e) => {
                                warn!("Login script failed: {}", e);
                                notifier.notify_error("Authentication", &format!("Login script failed: {}", e))?;
                            }
                        }
                    } else if let (Some(username), Some(password), Some(username_sel), Some(password_sel), Some(submit_sel)) = (
                        &settings.username,
                        &settings.password,
                        &settings.username_selector,
                        &settings.password_selector,
                        &settings.submit_selector,
                    ) {
                        match perform_login(&tab, username, password, username_sel, password_sel, submit_sel) {
                            Ok(_) => {
                                info!("Login successful!");
                                notifier.notify_info("Authentication", "Login successful")?;
                                sleep(Duration::from_millis(3000)).await; // Wait for redirect
                            }
                            Err(e) => {
                                warn!("Login failed: {}", e);
                                notifier.notify_error("Authentication", &format!("Login failed: {}", e))?;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to navigate to login page: {}", e);
                }
            }
        }
    }

    let mut recording_data = Vec::new();

    // Main crawling loop
    while let Some(url) = crawler.lock().await.get_next_url() {
        // Check if stopped
        {
            let status_guard = status.lock().await;
            if !status_guard.is_running {
                info!("Recording stopped by user");
                break;
            }
        }

        // Check page limit
        let pages_visited = status.lock().await.pages_visited;
        if pages_visited >= settings.max_pages {
            info!("Reached maximum page limit: {}", settings.max_pages);
            break;
        }

        info!("Visiting page {}: {}", pages_visited + 1, url);

        // Update status
        {
            let mut status_guard = status.lock().await;
            status_guard.current_url = url.clone();
        }

        // Navigate to URL
        match browser.navigate(&tab, &url, &nav_options) {
            Ok(_) => {
                let mut status_guard = status.lock().await;
                status_guard.pages_visited += 1;
                drop(status_guard);

                recording_data.push(RecordingData {
                    session_id: session_id.clone(),
                    timestamp: chrono::Utc::now(),
                    url: url.clone(),
                    action: "navigate".to_string(),
                    metadata: serde_json::json!({
                        "page_number": pages_visited + 1,
                    }),
                });

                // Extract links
                if let Ok(content) = browser.get_page_content(&tab) {
                    if let Ok(links) = crawler.lock().await.extract_links_from_html(&content, &url) {
                        info!("Found {} links on page", links.len());
                        crawler.lock().await.add_discovered_links(links);

                        let mut status_guard = status.lock().await;
                        status_guard.pages_discovered = crawler.lock().await.get_discovered_count();
                    }
                }

                sleep(Duration::from_millis(settings.delay_ms)).await;
            }
            Err(e) => {
                warn!("Failed to navigate to {}: {}", url, e);
            }
        }
    }

    // Stop prefetch workers and wait for them
    prefetch_active.store(false, std::sync::atomic::Ordering::SeqCst);
    for handle in worker_handles {
        let _ = handle.await;
    }

    let pages_visited = status.lock().await.pages_visited;
    info!("Crawling completed. Visited {} pages", pages_visited);
    notifier.notify_crawl_completed(pages_visited)?;

    // Stop recording
    let video_path = recorder.stop_recording().await?;
    if let Some(metadata) = recorder.get_metadata().await {
        if let Some(duration) = metadata.duration_secs {
            notifier.notify_recording_stopped(&session_id, duration)?;
        }
    }

    // Export data
    let export_path = std::path::PathBuf::from(&settings.output_dir)
        .join(format!("{}_data.json", session_id));
    exporter.export_to_json(&recording_data, &export_path)?;

    info!("Recording saved to: {:?}", video_path);
    info!("Data exported to: {:?}", export_path);

    // Run vulnerability scan if requested
    if let Some(ref scan_url) = settings.scan_url {
        info!("Running vulnerability scan on: {}", scan_url);
        let scan_config = ScanConfig::new(scan_url)?;
        let mut scanner = VulnerabilityScanner::new(scan_config)?;
        match scanner.run_full_scan().await {
            Ok(report) => {
                let scan_path = std::path::PathBuf::from(&settings.output_dir)
                    .join(format!("{}_scan.json", session_id));
                let scan_json = serde_json::to_string_pretty(&report)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize scan: {}", e))?;
                std::fs::write(&scan_path, scan_json)?;
                info!("Vulnerability scan completed. Report saved to: {:?}", scan_path);
                notifier.notify_info("Scan Complete", &format!("Risk score: {:.1}/10", report.summary.risk_score))?;
            }
            Err(e) => {
                warn!("Vulnerability scan failed: {}", e);
            }
        }
    }

    // Update final status
    let mut status_guard = status.lock().await;
    status_guard.is_running = false;

    Ok(())
}

fn js_quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

fn perform_login(
    tab: &std::sync::Arc<headless_chrome::Tab>,
    username: &str,
    password: &str,
    username_selector: &str,
    password_selector: &str,
    submit_selector: &str,
) -> Result<()> {
    // Check if we're on localhost - if so, check for pre-filled fields
    let current_url = tab.get_url();
    let is_localhost = current_url.contains("localhost") || current_url.contains("127.0.0.1");
    
    if is_localhost {
        info!("Detected localhost domain, checking for pre-filled form fields...");
        
        // Check if username field already has content
        let username_selectors: Vec<&str> = username_selector.split(',').map(|s| s.trim()).collect();
        let mut username_prefilled = false;
        
        for selector in &username_selectors {
            if let Ok(_element) = tab.find_element(selector) {
                // Try to get the value attribute to check if it's filled
                if let Ok(js_result) = tab.evaluate(&format!(
                    "document.querySelector('{}')?.value || ''", 
                    selector.replace("'", "\\'")
                ), false) {
                    if let Some(value) = js_result.value {
                        if let Some(s) = value.as_str() {
                            if !s.trim().is_empty() {
                                info!("Username field already contains: '{}'", s);
                                username_prefilled = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        // Check if password field already has content
        let password_selectors: Vec<&str> = password_selector.split(',').map(|s| s.trim()).collect();
        let mut password_prefilled = false;
        
        for selector in &password_selectors {
            if let Ok(_element) = tab.find_element(selector) {
                if let Ok(js_result) = tab.evaluate(&format!(
                    "document.querySelector('{}')?.value || ''", 
                    selector.replace("'", "\\'")
                ), false) {
                    if let Some(value) = js_result.value {
                        if let Some(s) = value.as_str() {
                            if !s.trim().is_empty() {
                                info!("Password field already contains data");
                                password_prefilled = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        if username_prefilled && password_prefilled {
            info!("Both username and password fields are pre-filled on localhost, skipping form filling...");
            // Skip to submit button
            std::thread::sleep(std::time::Duration::from_millis(500));
            
            info!("Clicking submit button...");
            let submit_selectors: Vec<&str> = submit_selector.split(',').map(|s| s.trim()).collect();
            let mut submit_clicked = false;
            
            for selector in submit_selectors {
                if let Ok(element) = tab.find_element(selector) {
                    if element.click().is_ok() {
                        info!("Submit button clicked using selector: {}", selector);
                        submit_clicked = true;
                        break;
                    }
                }
            }
            
            if !submit_clicked {
                return Err(anyhow::anyhow!("Could not find submit button"));
            }
            
            info!("Login form submitted with pre-filled data");
            return Ok(());
        } else {
            info!("Fields not pre-filled, proceeding with normal form filling...");
        }
    }

    info!("Filling username field...");
    // Try multiple selectors for username
    let username_selectors: Vec<&str> = username_selector.split(',').map(|s| s.trim()).collect();
    let mut username_filled = false;
    
    for selector in username_selectors {
        if let Ok(element) = tab.find_element(selector) {
            if element.type_into(username).is_ok() {
                info!("Username filled using selector: {}", selector);
                username_filled = true;
                break;
            }
        }
    }
    
    if !username_filled {
        return Err(anyhow::anyhow!("Could not find username field"));
    }
    
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    info!("Filling password field...");
    // Try multiple selectors for password
    let password_selectors: Vec<&str> = password_selector.split(',').map(|s| s.trim()).collect();
    let mut password_filled = false;
    
    for selector in password_selectors {
        if let Ok(element) = tab.find_element(selector) {
            if element.type_into(password).is_ok() {
                info!("Password filled using selector: {}", selector);
                password_filled = true;
                break;
            }
        }
    }
    
    if !password_filled {
        return Err(anyhow::anyhow!("Could not find password field"));
    }
    
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    info!("Clicking submit button...");
    // Try multiple selectors for submit button
    let submit_selectors: Vec<&str> = submit_selector.split(',').map(|s| s.trim()).collect();
    let mut submit_clicked = false;
    
    for selector in submit_selectors {
        if let Ok(element) = tab.find_element(selector) {
            if element.click().is_ok() {
                info!("Submit button clicked using selector: {}", selector);
                submit_clicked = true;
                break;
            }
        }
    }
    
    if !submit_clicked {
        return Err(anyhow::anyhow!("Could not find submit button"));
    }
    
    info!("Login form submitted");
    Ok(())
}

fn setup_tracing(verbose: bool, quiet: bool) -> Result<()> {
    setup_tracing_with_file(verbose, quiet, None)
}

fn setup_tracing_with_file(verbose: bool, quiet: bool, log_file: Option<std::path::PathBuf>) -> Result<()> {
    let log_level = if verbose {
        tracing::Level::DEBUG
    } else if quiet {
        tracing::Level::WARN
    } else {
        tracing::Level::INFO
    };
    
    if let Some(log_path) = log_file {
        // Log to file for daemon mode
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.into()))
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .init();
        
        info!("Logging to file: {:?}", log_path);
    } else {
        // Log to stdout
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.into()))
            .init();
    }
    
    Ok(())
}

fn dispatch_command(command: Option<Commands>, verbose: bool, quiet: bool) -> Result<()> {
    match command {
        Some(cmd @ Commands::Crawl { .. }) => {
            info!("Starting in CLI mode");
            let args = cmd.into_crawl_args();
            run_cli_mode(args, verbose, quiet)
        }
        Some(Commands::Resume { session_id }) => {
            info!("Resuming session: {}", session_id);
            resume_session(&session_id)
        }
        Some(Commands::List { output }) => {
            list_sessions(&output);
            Ok(())
        }
        Some(Commands::Scan {
            url,
            output,
            max_depth,
            max_pages,
            list,
            export_id,
            format,
        }) => {
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async {
                run_scan_cli(url, &output, max_depth, max_pages, list, export_id, &format).await
            })
        }
        Some(Commands::Gui) | None => {
            run_gui_mode();
            Ok(())
        }
    }
}

fn main() {
    let cli = Cli::parse_args();
    
    if let Err(e) = setup_tracing(cli.verbose, cli.quiet) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = dispatch_command(cli.command.clone(), cli.verbose, cli.quiet) {
        error!("Application error: {}", e);
        std::process::exit(1);
    }
}

fn run_gui_mode() {
    info!("SiteRecorder GUI starting...");

    let data_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("siterecorder-cyberops");
    std::fs::create_dir_all(&data_dir).ok();

    let auth_manager = AuthProfileManager::new(&data_dir.join("auth.db"))
        .unwrap_or_else(|_| AuthProfileManager::new_in_memory().unwrap());

    let vault_path = data_dir.join("credentials.vault");
    let credential_vault = CredentialVault::with_path(vault_path);

    let app_state = AppState {
        status: Arc::new(Mutex::new(CrawlStatus::default())),
        session_manager: Arc::new(Mutex::new(SessionManager::new())),
        scan_results: Arc::new(Mutex::new(None)),
        auth_manager: Arc::new(Mutex::new(auth_manager)),
        credential_vault: Arc::new(Mutex::new(credential_vault)),
        http_proxy: Arc::new(Mutex::new(None)),
        packet_capture: Arc::new(Mutex::new(None)),
        auth_engine: Arc::new(AuthEngine::new().unwrap()),
    };

    use tauri::{CustomMenuItem, SystemTray, SystemTrayMenu, SystemTrayEvent, Manager};
    
    // Create system tray menu
    let show = CustomMenuItem::new("show".to_string(), "Show Window");
    let hide = CustomMenuItem::new("hide".to_string(), "Hide Window");
    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(hide)
        .add_native_item(tauri::SystemTrayMenuItem::Separator)
        .add_item(quit);
    
    let system_tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .manage(app_state)
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => {
                match id.as_str() {
                    "show" => {
                        if let Some(window) = app.get_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(window) = app.get_window("main") {
                            let _ = window.hide();
                        }
                    }
                    "quit" => {
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
            _ => {}
        })
        .on_window_event(|event| match event.event() {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                // Hide instead of close
                let _ = event.window().hide();
                api.prevent_close();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            start_recording,
            stop_recording,
            get_status,
            run_vulnerability_scan,
            get_scan_results,
            list_vuln_scans,
            load_vuln_scan,
            delete_vuln_scan,
            export_vuln_scan,
            save_export,
            // Auth profile commands
            list_auth_profiles,
            get_auth_profile,
            create_auth_profile,
            update_auth_profile,
            delete_auth_profile,
            test_auth_profile,
            generate_totp,
            validate_totp,
            generate_totp_secret,
            get_totp_provisioning_uri,
            unlock_vault,
            lock_vault,
            is_vault_locked,
            list_audit_entries,
            // Network scanner commands
            network_port_scan,
            network_dns_lookup,
            network_subdomain_enum,
            network_ssl_check,
            // Password attack commands
            password_identify_hash,
            password_crack,
            password_generate_mask,
            password_get_wordlists,
            password_get_default_wordlist,
            // OS pentest commands
            os_pentest_scan,
            // Mobile analysis commands
            mobile_analyze,
            // Cloud security commands
            cloud_scan,
            // Web3 security commands
            web3_scan_contract,
            web3_analyze_wallet,
            // API Scanner commands
            api_scan,
            // Gray Team commands
            grayteam_get_attck_matrix,
            grayteam_create_threat_model,
            grayteam_create_purple_exercise,
            grayteam_get_sigma_rules,
            grayteam_get_apt_techniques,
            // Blue Team commands
            blueteam_get_soc_dashboard,
            blueteam_create_incident,
            blueteam_get_threat_feeds,
            blueteam_get_threat_actors,
            blueteam_get_indicators,
            blueteam_get_malware_analysis,
            blueteam_create_hunt,
            blueteam_get_ir_playbooks,
            // White Team commands
            whiteteam_get_grc_dashboard,
            whiteteam_get_compliance_frameworks,
            whiteteam_get_risk_register,
            whiteteam_get_policies,
            whiteteam_get_vendors,
            whiteteam_get_training,
            // Cross-team commands
            cross_get_assets,
            cross_get_notifications,
            cross_get_alert_rules,
            cross_get_report_templates,
            cross_get_integrations,
            // HTTP Proxy commands
            proxy_start,
            proxy_stop,
            proxy_get_sessions,
            proxy_get_config,
            proxy_set_config,
            proxy_clear_sessions,
            // Packet capture commands
            packet_list_interfaces,
            packet_start_capture,
            packet_stop_capture,
            packet_get_packets,
            packet_get_stats,
            packet_clear_packets,
            // Auth engine commands
            auth_authenticate,
            auth_test_session,
            auth_refresh_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// CLI Mode Implementation
fn run_cli_mode(args: CrawlArgs, verbose: bool, quiet: bool) -> Result<()> {
    let settings = RecordingSettings::from_crawl_args(args);
    
    // Initialize daemon mode if requested
    let daemon_manager = if settings.daemon {
        // Set up file logging before daemonizing
        if let Some(ref log_file) = settings.log_file {
            setup_tracing_with_file(verbose, quiet, Some(log_file.clone()))?;
        }
        
        info!("Initializing daemon mode");
        
        // Daemonize the process
        #[cfg(unix)]
        if let Err(e) = daemon::daemonize() {
            error!("Failed to daemonize: {}", e);
            return Err(e);
        }
        
        let manager = DaemonManager::new(settings.pid_file.clone());
        manager.initialize()?;
        Some(manager)
    } else {
        None
    };
    
    info!("Starting CLI crawl of: {}", settings.url);
    
    let runtime = tokio::runtime::Runtime::new()?;
    
    let result = runtime.block_on(async {
        info!("Configuration:");
        info!("  URL: {}", settings.url);
        info!("  Max pages: {}", settings.max_pages);
        info!("  Output: {}", settings.output_dir);
        info!("  Recording mode: {:?}", settings.recording_mode);
        info!("  Headless: {}", settings.headless);
        info!("  Daemon: {}", settings.daemon);
        
        match run_recording_cli(settings, daemon_manager.as_ref()).await {
            Ok(session_id) => {
                info!("✓ Recording completed successfully!");
                info!("Session ID: {}", session_id);
                Ok(())
            }
            Err(e) => {
                error!("✗ Recording failed: {}", e);
                Err(e)
            }
        }
    });
    
    // Daemon manager will cleanup on drop
    result
}

fn recording_mode_from_settings(settings: &RecordingSettings) -> recorder::RecordingMode {
    match settings.recording_mode.as_deref() {
        Some("screen") => recorder::RecordingMode::Screen,
        Some("browser") => recorder::RecordingMode::Browser,
        Some("both") | _ => recorder::RecordingMode::Both,
    }
}

fn build_recording_config(settings: &RecordingSettings) -> RecordingConfig {
    RecordingConfig {
        output_dir: std::path::PathBuf::from(&settings.output_dir),
        format: VideoFormat::Mp4,
        fps: settings.fps.unwrap_or(30),
        quality: 80,
        audio_enabled: settings.enable_audio.unwrap_or(false),
        mode: recording_mode_from_settings(settings),
        screen_width: settings.screen_width.or(Some(1920)),
        screen_height: settings.screen_height.or(Some(1080)),
        screen_region: settings.screen_region,
    }
}

async fn run_recording_cli(settings: RecordingSettings, daemon_manager: Option<&DaemonManager>) -> Result<String> {
    // Create session ID
    let session_id = format!("session_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    
    info!("Initializing browser...");
    let browser = if settings.headless {
        Browser::new_headless()?
    } else {
        Browser::new()?
    };
    
    info!("Setting up crawler...");
    let crawl_config = CrawlConfig::new(&settings.url)?;
    let crawl_config = if let Some(ref proxy) = settings.proxy {
        crawl_config.with_proxy(proxy)
    } else {
        crawl_config
    };
    let crawl_config = if let Some(ref sitemap) = settings.sitemap {
        crawl_config.with_sitemap(sitemap)
    } else {
        crawl_config
    };
    let crawl_config = crawl_config.with_concurrency(settings.concurrency.unwrap_or(1));
    let crawler = Arc::new(Mutex::new(Crawler::new(crawl_config)));

    // Ingest sitemap if provided
    if settings.sitemap.is_some() {
        if let Ok(count) = crawler.lock().await.ingest_sitemap().await {
            info!("Ingested {} URLs from sitemap", count);
        }
    }

    // Spawn concurrent prefetch workers
    let concurrency = settings.concurrency.unwrap_or(1).max(1);
    let prefetch_active = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut worker_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if concurrency > 1 {
        for _ in 0..concurrency {
            let crawler_clone = crawler.clone();
            let active = prefetch_active.clone();
            worker_handles.push(tokio::spawn(async move {
                loop {
                    let url = { crawler_clone.lock().await.next_prefetch_url() };
                    match url {
                        Some(u) => {
                            let links = crawler_clone.lock().await.prefetch_links(&u).await;
                            crawler_clone.lock().await.add_discovered_links(links);
                        }
                        None => {
                            if !active.load(std::sync::atomic::Ordering::SeqCst) {
                                break;
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
                        }
                    }
                }
            }));
        }
        info!("Started {} concurrent crawl workers", concurrency);
    }

    info!("Configuring recorder...");
    let recording_config = build_recording_config(&settings);
    let recorder = Recorder::new(recording_config);
    
    let tab = browser.get_tab()?;
    recorder.set_browser_tab(tab.clone()).await;
    
    let nav_options = NavigationOptions {
        timeout_ms: 30000,
        wait_for_idle: true,
        scroll_behavior: ScrollBehavior::Incremental {
            steps: 5,
            delay_ms: 500,
        },
    };

    info!("Starting recording...");
    recorder.start_recording(session_id.clone(), Some(settings.url.clone())).await?;
    
    // Handle authentication if required
    if settings.requires_auth {
        if let Some(auth_url) = &settings.auth_url {
            info!("Navigating to login page: {}", auth_url);
            match browser.navigate(&tab, auth_url, &nav_options) {
                Ok(_) => {
                    if let Some(script) = &settings.login_script {
                        let setup = format!(
                            "window.__SR_USER = {}; window.__SR_PASS = {};",
                            js_quote(settings.username.as_deref().unwrap_or("")),
                            js_quote(settings.password.as_deref().unwrap_or("")),
                        );
                        if let Err(e) = browser.execute_script(&tab, &setup) {
                            warn!("Failed to inject credentials for login script: {}", e);
                        }
                        match browser.execute_script(&tab, script) {
                            Ok(_) => {
                                info!("Custom login script executed");
                                sleep(Duration::from_millis(3000)).await;
                            }
                            Err(e) => warn!("Login script failed: {}", e),
                        }
                    } else if let (Some(username), Some(password), Some(username_sel), Some(password_sel), Some(submit_sel)) = (
                        &settings.username,
                        &settings.password,
                        &settings.username_selector,
                        &settings.password_selector,
                        &settings.submit_selector,
                    ) {
                        match perform_login(&tab, username, password, username_sel, password_sel, submit_sel) {
                            Ok(_) => {
                                info!("Login successful!");
                                sleep(Duration::from_millis(3000)).await;
                            }
                            Err(e) => warn!("Login failed: {}", e),
                        }
                    }
                }
                Err(e) => warn!("Failed to navigate to login page: {}", e),
            }
        }
    }

    info!("Beginning crawl...");
    let mut pages_visited = 0;
    
    // Initialize progress bar (disabled in daemon mode)
    let show_progress = settings.progress && !settings.daemon;
    let progress = CrawlProgress::new(settings.max_pages as u64, show_progress);
    
    while pages_visited < settings.max_pages {
        // Check for shutdown signal in daemon mode
        if let Some(manager) = daemon_manager {
            if manager.should_stop() {
                info!("Shutdown signal received, stopping crawl gracefully");
                break;
            }
        }
        
        if let Some(url) = crawler.lock().await.get_next_url() {
            progress.set_message(format!("Crawling: {}", url));
            info!("[{}/{}] Crawling: {}", pages_visited + 1, settings.max_pages, url);
            
            match browser.navigate(&tab, &url, &nav_options) {
                Ok(_) => {
                    // Get page content and discover links
                    if let Ok(content) = browser.get_page_content(&tab) {
                        if let Ok(links) = crawler.lock().await.extract_links_from_html(&content, &url) {
                            info!("  Found {} links", links.len());
                            crawler.lock().await.add_discovered_links(links);
                        }
                    }
                    
                    crawler.lock().await.mark_visited(&url);
                    pages_visited += 1;
                    progress.inc();
                    
                    // Delay between pages
                    tokio::time::sleep(tokio::time::Duration::from_millis(settings.delay_ms)).await;
                }
                Err(e) => {
                    warn!("  Failed to navigate: {}", e);
                    crawler.lock().await.mark_visited(&url);
                }
            }
        } else {
            info!("No more URLs to crawl");
            break;
        }
    }
    
    prefetch_active.store(false, std::sync::atomic::Ordering::SeqCst);
    for handle in worker_handles {
        let _ = handle.await;
    }

    progress.finish();
    
    info!("Stopping recording...");
    let video_path = recorder.stop_recording().await?;
    
    info!("Recording saved to: {:?}", video_path);
    info!("Total pages visited: {}", pages_visited);

    // Run vulnerability scan if requested
    if let Some(ref scan_url) = settings.scan_url {
        info!("Running vulnerability scan on: {}", scan_url);
        let scan_config = ScanConfig::new(scan_url)?;
        let mut scanner = VulnerabilityScanner::new(scan_config)?;
        match scanner.run_full_scan().await {
            Ok(report) => {
                let scan_path = std::path::PathBuf::from(&settings.output_dir)
                    .join(format!("{}_scan.json", session_id));
                let scan_json = serde_json::to_string_pretty(&report)?;
                std::fs::write(&scan_path, scan_json)?;
                info!("Vulnerability scan completed. Report saved to: {:?}", scan_path);
                println!("\n🛡️ Vulnerability Scan Results:");
                println!("─────────────────────────────────────────────────────");
                println!("  Risk Score: {:.1}/10", report.summary.risk_score);
                println!("  Total Checks: {}", report.summary.total_checks);
                println!("  Vulnerabilities: {}", report.summary.vulnerable);
                println!("  Warnings: {}", report.summary.warnings);
                println!("  Critical: {}", report.summary.critical_count);
                println!("  High: {}", report.summary.high_count);
                println!("  Medium: {}", report.summary.medium_count);
                println!("  Low: {}", report.summary.low_count);
                println!("─────────────────────────────────────────────────────");
            }
            Err(e) => {
                warn!("Vulnerability scan failed: {}", e);
            }
        }
    }

    Ok(session_id)
}

fn resume_session(session_id: &str) -> Result<()> {
    info!("Resuming session: {}", session_id);

    // Look for session data file
    let session_file = std::path::PathBuf::from("./recordings")
        .join(format!("{}_data.json", session_id));

    if !session_file.exists() {
        warn!("Session data file not found: {:?}", session_file);
        warn!("Available sessions can be listed with: site-recorder list");
        return Ok(());
    }

    let session_json = std::fs::read_to_string(&session_file)?;
    let recording_data: Vec<RecordingData> = serde_json::from_str(&session_json)?;

    println!("\n📋 Session: {}", session_id);
    println!("─────────────────────────────────────────────────────");
    println!("  Pages recorded: {}", recording_data.len());
    if let Some(first) = recording_data.first() {
        println!("  Start time: {}", first.timestamp.format("%Y-%m-%d %H:%M:%S"));
        println!("  Base URL: {}", first.url);
    }
    if let Some(last) = recording_data.last() {
        println!("  End time: {}", last.timestamp.format("%Y-%m-%d %H:%M:%S"));
    }
    println!("─────────────────────────────────────────────────────");

    // Check for associated video files
    let recordings_dir = std::path::PathBuf::from("./recordings");
    if let Ok(entries) = std::fs::read_dir(&recordings_dir) {
        let mut video_count = 0;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(session_id) && (name.ends_with(".mp4") || name.ends_with(".webm")) {
                video_count += 1;
                println!("  📹 Video: {}", name);
            }
        }
        if video_count == 0 {
            println!("  No associated video files found");
        }
    }

    println!("\n✅ Session resume complete. Data loaded successfully.");
    Ok(())
}

fn format_session_entry(entry: &std::fs::DirEntry) -> Option<String> {
    let metadata = entry.metadata().ok()?;
    if !metadata.is_dir() {
        return None;
    }
    
    let name = entry.path().file_name()?.to_string_lossy().to_string();
    
    let timestamp = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0));
    
    match timestamp {
        Some(dt) => Some(format!("  {} - {}", name, dt.format("%Y-%m-%d %H:%M:%S"))),
        None => Some(format!("  {}", name)),
    }
}

fn list_sessions(output: &std::path::Path) {
    info!("Listing sessions in: {:?}", output);
    
    let entries = match std::fs::read_dir(output) {
        Ok(e) => e,
        Err(_) => {
            warn!("Could not read directory: {:?}", output);
            return;
        }
    };
    
    println!("\n📁 Recording Sessions:");
    println!("─────────────────────────────────────────────────────");
    
    let mut count = 0;
    for entry in entries.flatten() {
        if let Some(line) = format_session_entry(&entry) {
            println!("{}", line);
            count += 1;
        }
    }
    
    println!("─────────────────────────────────────────────────────");
    println!("Total sessions: {}\n", count);
}

// Standalone vulnerability scanner CLI
async fn run_scan_cli(
    url: Option<String>,
    output: &std::path::Path,
    max_depth: usize,
    max_pages: usize,
    list: bool,
    export_id: Option<String>,
    format: &str,
) -> Result<()> {
    if list {
        let scans = VulnerabilityScanner::list_scans(output);
        println!("\n📚 Saved Scans:");
        println!("─────────────────────────────────────────────────────");
        if scans.is_empty() {
            println!("  No saved scans in {:?}", output);
        }
        for s in &scans {
            println!(
                "  {} | {} | risk {:.1} | {} vuln / {} warn",
                s.scan_id, s.target_url, s.risk_score, s.vulnerable, s.warnings
            );
        }
        println!("─────────────────────────────────────────────────────");
        println!("Total: {}\n", scans.len());
        return Ok(());
    }

    if let Some(id) = export_id {
        let path = output.join("scans").join(format!("{}.json", id));
        let data = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;
        let report: ScanReport = serde_json::from_str(&data)
            .map_err(|e| anyhow::anyhow!("Invalid scan file: {}", e))?;
        let (content, ext) = if format.eq_ignore_ascii_case("csv") {
            (report.to_csv(), "csv")
        } else {
            (serde_json::to_string_pretty(&report)?, "json")
        };
        let dest = format!("{}.{}", id, ext);
        std::fs::write(&dest, content)?;
        println!("Exported {} to {}", id, dest);
        return Ok(());
    }

    let url = url.ok_or_else(|| anyhow::anyhow!(
        "Provide --url to scan, or use --list / --export-id"
    ))?;

    let mut config = ScanConfig::new(&url)?;
    config.max_depth = max_depth;
    config.max_pages = max_pages;
    config.output_dir = Some(output.to_path_buf());

    let mut scanner = VulnerabilityScanner::new(config)?;
    println!("Scanning {} (depth={}, max_pages={})...", url, max_depth, max_pages);
    let report = scanner.run_full_scan().await?;
    let _ = scanner.save_report(&report);

    println!("\n🛡️ Vulnerability Scan Results:");
    println!("─────────────────────────────────────────────────────");
    println!("  Target:        {}", report.url);
    println!("  Scan ID:       {}", report.scan_id);
    println!("  Risk Score:    {:.1}/10", report.summary.risk_score);
    println!("  Total Checks:  {}", report.summary.total_checks);
    println!("  Vulnerable:    {}", report.summary.vulnerable);
    println!("  Warnings:      {}", report.summary.warnings);
    println!("  Critical:      {}", report.summary.critical_count);
    println!("  High:          {}", report.summary.high_count);
    println!("  Medium:        {}", report.summary.medium_count);
    println!("  Low:           {}", report.summary.low_count);
    println!("─────────────────────────────────────────────────────");
    let saved = output.join("scans").join(format!("{}.json", report.scan_id));
    println!("Report saved to: {}\n", saved.display());

    Ok(())
}
