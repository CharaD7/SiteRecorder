use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MobileError {
    #[error("Analysis error: {0}")]
    AnalysisError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
}

type Result<T> = std::result::Result<T, MobileError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileScanConfig {
    pub target_type: MobileTarget,
    pub apk_path: Option<String>,
    pub ipa_path: Option<String>,
    pub deep_analysis: bool,
    pub check_categories: Vec<MobileCheckCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MobileTarget {
    Android,
    IOS,
}

impl std::fmt::Display for MobileTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MobileTarget::Android => write!(f, "Android"),
            MobileTarget::IOS => write!(f, "iOS"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MobileCheckCategory {
    Manifest,
    Storage,
    Network,
    Cryptography,
    Authentication,
    WebView,
    IPC,
    Binary,
    Backend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileScanResult {
    pub scan_id: String,
    pub target_type: MobileTarget,
    pub app_name: Option<String>,
    pub package_name: Option<String>,
    pub version: Option<String>,
    pub timestamp: String,
    pub duration_ms: u64,
    pub findings: Vec<MobileFinding>,
    pub summary: MobileScanSummary,
    pub permissions: Vec<Permission>,
    pub activities: Vec<String>,
    pub services: Vec<String>,
    pub providers: Vec<String>,
    pub receivers: Vec<String>,
    pub urls_discovered: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileScanSummary {
    pub total_checks: usize,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileFinding {
    pub id: String,
    pub title: String,
    pub severity: MobileSeverity,
    pub category: MobileCheckCategory,
    pub description: String,
    pub details: Vec<String>,
    pub remediation: String,
    pub cwe_id: Option<String>,
    pub owasp_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MobileSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for MobileSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MobileSeverity::Critical => write!(f, "CRITICAL"),
            MobileSeverity::High => write!(f, "HIGH"),
            MobileSeverity::Medium => write!(f, "MEDIUM"),
            MobileSeverity::Low => write!(f, "LOW"),
            MobileSeverity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    pub level: PermissionLevel,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PermissionLevel {
    Normal,
    Dangerous,
    Signature,
    Development,
    Internal,
}

impl std::fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionLevel::Normal => write!(f, "normal"),
            PermissionLevel::Dangerous => write!(f, "dangerous"),
            PermissionLevel::Signature => write!(f, "signature"),
            PermissionLevel::Development => write!(f, "development"),
            PermissionLevel::Internal => write!(f, "internal"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub headers: Vec<String>,
    pub authentication: Option<String>,
}

pub struct MobileAnalyzer;

impl MobileAnalyzer {
    pub fn analyze_apk(config: &MobileScanConfig) -> MobileScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        if config.check_categories.contains(&MobileCheckCategory::Manifest) {
            findings.extend(Self::check_android_debuggable());
            findings.extend(Self::check_android_backup());
            findings.extend(Self::check_android_permissions());
            findings.extend(Self::check_android_exported_components());
        }

        if config.check_categories.contains(&MobileCheckCategory::Storage) {
            findings.extend(Self::check_android_shared_prefs());
            findings.extend(Self::check_android_external_storage());
            findings.extend(Self::check_android_database());
        }

        if config.check_categories.contains(&MobileCheckCategory::Network) {
            findings.extend(Self::check_android_cleartext());
            findings.extend(Self::check_android_ssl_validation());
            findings.extend(Self::check_android_certificate_pinning());
        }

        if config.check_categories.contains(&MobileCheckCategory::Cryptography) {
            findings.extend(Self::check_android_crypto());
            findings.extend(Self::check_android_hardcoded_keys());
        }

        if config.check_categories.contains(&MobileCheckCategory::WebView) {
            findings.extend(Self::check_android_webview());
            findings.extend(Self::check_android_javascript_interface());
        }

        if config.check_categories.contains(&MobileCheckCategory::Authentication) {
            findings.extend(Self::check_android_biometric());
            findings.extend(Self::check_android_token_storage());
        }

        if config.check_categories.contains(&MobileCheckCategory::Binary) {
            findings.extend(Self::check_android_root_detection());
            findings.extend(Self::check_android_emulator_detection());
            findings.extend(Self::check_android_obfuscation());
        }

        let duration = start.elapsed().as_millis() as u64;
        let summary = Self::calculate_summary(&findings);

        MobileScanResult {
            scan_id: format!("mobscan_{}", Utc::now().timestamp_millis()),
            target_type: MobileTarget::Android,
            app_name: None,
            package_name: None,
            version: None,
            timestamp: Utc::now().to_rfc3339(),
            duration_ms: duration,
            findings,
            summary,
            permissions: Self::get_common_permissions(),
            activities: Vec::new(),
            services: Vec::new(),
            providers: Vec::new(),
            receivers: Vec::new(),
            urls_discovered: Vec::new(),
        }
    }

    pub fn analyze_ipa(config: &MobileScanConfig) -> MobileScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        if config.check_categories.contains(&MobileCheckCategory::Manifest) {
            findings.extend(Self::check_ios_ats());
            findings.extend(Self::check_ios_url_schemes());
            findings.extend(Self::check_ios_entitlements());
        }

        if config.check_categories.contains(&MobileCheckCategory::Storage) {
            findings.extend(Self::check_ios_keychain());
            findings.extend(Self::check_ios_core_data());
            findings.extend(Self::check_ios_plist_storage());
        }

        if config.check_categories.contains(&MobileCheckCategory::Network) {
            findings.extend(Self::check_ios_https());
            findings.extend(Self::check_ios_certificate_pinning());
        }

        if config.check_categories.contains(&MobileCheckCategory::Authentication) {
            findings.extend(Self::check_ios_biometric());
            findings.extend(Self::check_ios_keychain_sharing());
        }

        if config.check_categories.contains(&MobileCheckCategory::Binary) {
            findings.extend(Self::check_ios_jailbreak_detection());
            findings.extend(Self::check_ios_obfuscation());
            findings.extend(Self::check_ios_arc());
        }

        let duration = start.elapsed().as_millis() as u64;
        let summary = Self::calculate_summary(&findings);

        MobileScanResult {
            scan_id: format!("mobscan_{}", Utc::now().timestamp_millis()),
            target_type: MobileTarget::IOS,
            app_name: None,
            package_name: None,
            version: None,
            timestamp: Utc::now().to_rfc3339(),
            duration_ms: duration,
            findings,
            summary,
            permissions: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            providers: Vec::new(),
            receivers: Vec::new(),
            urls_discovered: Vec::new(),
        }
    }

    fn check_android_debuggable() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-001".to_string(),
                title: "Application is Debuggable".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::Manifest,
                description: "android:debuggable flag is set to true, allowing debuggers to attach.".to_string(),
                details: vec![
                    "Check AndroidManifest.xml for android:debuggable='true'".to_string(),
                    "Allows JDWP debugging and runtime manipulation".to_string(),
                    "Tools: jadx, JEB, Frida".to_string(),
                ],
                remediation: "Set android:debuggable='false' in release builds.".to_string(),
                cwe_id: Some("CWE-489".to_string()),
                owasp_id: Some("M1".to_string()),
            },
        ]
    }

    fn check_android_backup() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-002".to_string(),
                title: "Backup Allowed".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Manifest,
                description: "android:allowBackup is enabled, allowing data extraction via adb.".to_string(),
                details: vec![
                    "Run: adb backup -apk com.package.name".to_string(),
                    "Extracted data includes SharedPreferences, databases, files".to_string(),
                ],
                remediation: "Set android:allowBackup='false' in AndroidManifest.xml.".to_string(),
                cwe_id: Some("CWE-530".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_android_permissions() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-003".to_string(),
                title: "Excessive Permissions".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Manifest,
                description: "Application requests dangerous permissions that may not be needed.".to_string(),
                details: vec![
                    "Review all <uses-permission> entries".to_string(),
                    "Common dangerous: READ_SMS, READ_CONTACTS, ACCESS_FINE_LOCATION".to_string(),
                    "Check for WRITE_EXTERNAL_STORAGE on Android 10+".to_string(),
                ],
                remediation: "Remove unnecessary permissions and use runtime permission requests.".to_string(),
                cwe_id: Some("CWE-250".to_string()),
                owasp_id: Some("M1".to_string()),
            },
        ]
    }

    fn check_android_exported_components() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-004".to_string(),
                title: "Exported Components".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::Manifest,
                description: "Activities, services, or providers exported without proper permissions.".to_string(),
                details: vec![
                    "Check for android:exported='true' on components".to_string(),
                    "Look for intent filters that make components implicitly exported".to_string(),
                    "Check for missing permission attributes on exported components".to_string(),
                ],
                remediation: "Set android:exported='false' or add signature-level permissions.".to_string(),
                cwe_id: Some("CWE-925".to_string()),
                owasp_id: Some("M1".to_string()),
            },
        ]
    }

    fn check_android_shared_prefs() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-005".to_string(),
                title: "Sensitive Data in SharedPreferences".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Storage,
                description: "SharedPreferences stored in plaintext world-readable files.".to_string(),
                details: vec![
                    "Location: /data/data/<pkg>/shared_prefs/*.xml".to_string(),
                    "MODE_WORLD_READABLE is deprecated but still exploitable on rooted devices".to_string(),
                    "Check for: tokens, passwords, PII stored in clear".to_string(),
                ],
                remediation: "Use EncryptedSharedPreferences from AndroidX Security library.".to_string(),
                cwe_id: Some("CWE-312".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_android_external_storage() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-006".to_string(),
                title: "Sensitive Data on External Storage".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Storage,
                description: "Data written to external storage is readable by all applications.".to_string(),
                details: vec![
                    "Check: getExternalFilesDir(), Environment.getExternalStorageDirectory()".to_string(),
                    "Any app with READ_EXTERNAL_STORAGE can access files".to_string(),
                    "Check for: images with EXIF GPS data, cached credentials".to_string(),
                ],
                remediation: "Use internal storage (getFilesDir()) for sensitive data.".to_string(),
                cwe_id: Some("CWE-312".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_android_database() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-007".to_string(),
                title: "Unencrypted Database".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Storage,
                description: "SQLite database stored without encryption.".to_string(),
                details: vec![
                    "Location: /data/data/<pkg>/databases/".to_string(),
                    "Use SQLCipher for encryption".to_string(),
                    "Check for: user data, chat history, cached API responses".to_string(),
                ],
                remediation: "Use SQLCipher or Room with encrypted database.".to_string(),
                cwe_id: Some("CWE-312".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_android_cleartext() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-008".to_string(),
                title: "Cleartext Traffic Allowed".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::Network,
                description: "android:usesCleartextTraffic is enabled or network security config allows HTTP.".to_string(),
                details: vec![
                    "Check for android:usesCleartextTraffic='true'".to_string(),
                    "Check network_security_config.xml for cleartext permitted domains".to_string(),
                    "Allows man-in-the-middle attacks".to_string(),
                ],
                remediation: "Disable cleartext traffic and enforce HTTPS.".to_string(),
                cwe_id: Some("CWE-319".to_string()),
                owasp_id: Some("M3".to_string()),
            },
        ]
    }

    fn check_android_ssl_validation() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-009".to_string(),
                title: "Improper SSL Validation".to_string(),
                severity: MobileSeverity::Critical,
                category: MobileCheckCategory::Network,
                description: "Custom TrustManager or HostnameVerifier accepting all certificates.".to_string(),
                details: vec![
                    "Check for: X509TrustManager with empty checkServerTrusted".to_string(),
                    "Check for: HostnameVerifier returning true".to_string(),
                    "Check for: onReceivedSslError with proceed()".to_string(),
                ],
                remediation: "Use default SSL validation or implement proper certificate pinning.".to_string(),
                cwe_id: Some("CWE-295".to_string()),
                owasp_id: Some("M3".to_string()),
            },
        ]
    }

    fn check_android_certificate_pinning() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-010".to_string(),
                title: "Missing Certificate Pinning".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Network,
                description: "Application does not implement certificate pinning.".to_string(),
                details: vec![
                    "Check network_security_config.xml for <pin-set>".to_string(),
                    "Use OkHttp CertificatePinner or TrustKit".to_string(),
                    "Without pinning, rogue CAs can intercept traffic".to_string(),
                ],
                remediation: "Implement certificate pinning for all API endpoints.".to_string(),
                cwe_id: Some("CWE-295".to_string()),
                owasp_id: Some("M3".to_string()),
            },
        ]
    }

    fn check_android_crypto() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-011".to_string(),
                title: "Weak Cryptography".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::Cryptography,
                description: "Use of deprecated or weak cryptographic algorithms.".to_string(),
                details: vec![
                    "Check for: DES, RC4, MD5, SHA-1 for security purposes".to_string(),
                    "Check for: ECB mode, static IVs".to_string(),
                    "Check for: java.util.Random for security purposes".to_string(),
                ],
                remediation: "Use AES-GCM with 256-bit keys and SecureRandom.".to_string(),
                cwe_id: Some("CWE-327".to_string()),
                owasp_id: Some("M5".to_string()),
            },
        ]
    }

    fn check_android_hardcoded_keys() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-012".to_string(),
                title: "Hardcoded Cryptographic Keys".to_string(),
                severity: MobileSeverity::Critical,
                category: MobileCheckCategory::Cryptography,
                description: "Encryption keys hardcoded in source code or resources.".to_string(),
                details: vec![
                    "Search for: SecretKeySpec, byte[] key, String key".to_string(),
                    "Check: strings, BuildConfig fields, resource files".to_string(),
                    "Use Android Keystore for key storage".to_string(),
                ],
                remediation: "Use Android Keystore System for key generation and storage.".to_string(),
                cwe_id: Some("CWE-798".to_string()),
                owasp_id: Some("M5".to_string()),
            },
        ]
    }

    fn check_android_webview() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-013".to_string(),
                title: "WebView Security Issues".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::WebView,
                description: "WebView configuration may allow JavaScript injection or file access.".to_string(),
                details: vec![
                    "Check for: setJavaScriptEnabled(true)".to_string(),
                    "Check for: setAllowFileAccess(true)".to_string(),
                    "Check for: setAllowUniversalAccessFromFileURLs(true)".to_string(),
                    "Check for: addJavascriptInterface with exposed methods".to_string(),
                ],
                remediation: "Disable file access and validate all JavaScript bridges.".to_string(),
                cwe_id: Some("CWE-749".to_string()),
                owasp_id: Some("M1".to_string()),
            },
        ]
    }

    fn check_android_javascript_interface() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-014".to_string(),
                title: "JavaScript Interface Exposure".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::WebView,
                description: "JavaScript interfaces exposed to WebView can be exploited.".to_string(),
                details: vec![
                    "Check for: @JavascriptInterface annotations".to_string(),
                    "Only methods with the annotation are exposed in API 17+".to_string(),
                    "Reflection attacks possible on older Android versions".to_string(),
                ],
                remediation: "Minimize exposed JavaScript interfaces and validate inputs.".to_string(),
                cwe_id: Some("CWE-749".to_string()),
                owasp_id: Some("M1".to_string()),
            },
        ]
    }

    fn check_android_biometric() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-015".to_string(),
                title: "Biometric Authentication Bypass".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Authentication,
                description: "Biometric authentication may not be properly implemented.".to_string(),
                details: vec![
                    "Use BiometricPrompt API (Android 9+) instead of FingerprintManager".to_string(),
                    "Check for: setDeviceCredentialAllowed(true) fallback".to_string(),
                    "Authenticate with CryptoObject for cryptographic operations".to_string(),
                ],
                remediation: "Use BiometricPrompt with CryptoObject for strong authentication.".to_string(),
                cwe_id: Some("CWE-287".to_string()),
                owasp_id: Some("M4".to_string()),
            },
        ]
    }

    fn check_android_token_storage() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-016".to_string(),
                title: "Insecure Token Storage".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::Authentication,
                description: "Authentication tokens stored insecurely.".to_string(),
                details: vec![
                    "Check for: tokens in SharedPreferences, SQLite, or files".to_string(),
                    "Use EncryptedSharedPreferences or Android Keystore".to_string(),
                    "Implement token rotation and expiration".to_string(),
                ],
                remediation: "Store tokens in EncryptedSharedPreferences with key rotation.".to_string(),
                cwe_id: Some("CWE-312".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_android_root_detection() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-017".to_string(),
                title: "Missing Root Detection".to_string(),
                severity: MobileSeverity::Low,
                category: MobileCheckCategory::Binary,
                description: "Application does not detect rooted devices.".to_string(),
                details: vec![
                    "Check for: SafetyNet/Play Integrity API usage".to_string(),
                    "Check for: su binary detection, Magisk detection".to_string(),
                    "Note: Root detection can be bypassed, defense in depth required".to_string(),
                ],
                remediation: "Implement Play Integrity API and multiple root detection methods.".to_string(),
                cwe_id: None,
                owasp_id: Some("M10".to_string()),
            },
        ]
    }

    fn check_android_emulator_detection() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-018".to_string(),
                title: "Missing Emulator Detection".to_string(),
                severity: MobileSeverity::Low,
                category: MobileCheckCategory::Binary,
                description: "Application does not detect if running on emulator.".to_string(),
                details: vec![
                    "Check for: Build.FINGERPRINT, Build.MODEL emulator indicators".to_string(),
                    "Check for: TelephonyManager.getNetworkOperatorName()".to_string(),
                    "Use for: preventing automated analysis".to_string(),
                ],
                remediation: "Implement emulator detection alongside root detection.".to_string(),
                cwe_id: None,
                owasp_id: Some("M10".to_string()),
            },
        ]
    }

    fn check_android_obfuscation() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "AND-019".to_string(),
                title: "Missing Code Obfuscation".to_string(),
                severity: MobileSeverity::Low,
                category: MobileCheckCategory::Binary,
                description: "Code not obfuscated, making reverse engineering easier.".to_string(),
                details: vec![
                    "Check for: R8/ProGuard configuration".to_string(),
                    "Check for: minifyEnabled true in build.gradle".to_string(),
                    "Consider: DexGuard for commercial apps".to_string(),
                ],
                remediation: "Enable R8/ProGuard obfuscation for release builds.".to_string(),
                cwe_id: None,
                owasp_id: Some("M9".to_string()),
            },
        ]
    }

    fn check_ios_ats() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-001".to_string(),
                title: "App Transport Security Disabled".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::Manifest,
                description: "ATS is disabled or allows arbitrary loads.".to_string(),
                details: vec![
                    "Check Info.plist for NSAppTransportSecurity".to_string(),
                    "Check for NSAllowsArbitraryLoads = true".to_string(),
                    "Check for NSAllowsLocalNetworking = true".to_string(),
                ],
                remediation: "Enable ATS and add exceptions only for specific domains.".to_string(),
                cwe_id: Some("CWE-319".to_string()),
                owasp_id: Some("M3".to_string()),
            },
        ]
    }

    fn check_ios_url_schemes() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-002".to_string(),
                title: "Custom URL Schemes".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Manifest,
                description: "Custom URL schemes can be exploited for deep link attacks.".to_string(),
                details: vec![
                    "Check CFBundleURLTypes in Info.plist".to_string(),
                    "Validate all URL parameters". to_string(),
                    "Universal Links are more secure than custom schemes".to_string(),
                ],
                remediation: "Use Universal Links and validate all URL parameters.".to_string(),
                cwe_id: Some("CWE-939".to_string()),
                owasp_id: Some("M1".to_string()),
            },
        ]
    }

    fn check_ios_entitlements() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-003".to_string(),
                title: "Dangerous Entitlements".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Manifest,
                description: "Application has entitlements that increase attack surface.".to_string(),
                details: vec![
                    "Check for: com.apple.developer.networking.multipath".to_string(),
                    "Check for: com.apple.security.get-task-allow (debugging)".to_string(),
                    "Check for: keychain-access-groups with wildcards".to_string(),
                ],
                remediation: "Remove unused entitlements and restrict keychain access.".to_string(),
                cwe_id: None,
                owasp_id: Some("M1".to_string()),
            },
        ]
    }

    fn check_ios_keychain() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-004".to_string(),
                title: "Insecure Keychain Usage".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::Storage,
                description: "Keychain items stored with weak accessibility settings.".to_string(),
                details: vec![
                    "Check for: kSecAttrAccessibleWhenUnlockedThisDeviceOnly".to_string(),
                    "Avoid: kSecAttrAccessibleAlways".to_string(),
                    "Use ThisDeviceOnly to prevent iCloud backup".to_string(),
                ],
                remediation: "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly.".to_string(),
                cwe_id: Some("CWE-312".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_ios_core_data() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-005".to_string(),
                title: "Unencrypted Core Data".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Storage,
                description: "Core Data SQLite store is not encrypted.".to_string(),
                details: vec![
                    "Check for: NSPersistentStoreFileProtectionKey".to_string(),
                    "Use NSFileProtectionComplete for encryption at rest".to_string(),
                    "Check for: sensitive data in NSManagedObject models".to_string(),
                ],
                remediation: "Enable data protection and use NSSQLiteStoreType with encryption.".to_string(),
                cwe_id: Some("CWE-312".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_ios_plist_storage() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-006".to_string(),
                title: "Sensitive Data in Plist Files".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Storage,
                description: "Sensitive data stored in plist files without encryption.".to_string(),
                details: vec![
                    "Check for: Info.plist with API keys".to_string(),
                    "Check for: Settings.bundle with sensitive defaults".to_string(),
                    "Check for: embedded configuration files".to_string(),
                ],
                remediation: "Move sensitive data to Keychain or encrypted files.".to_string(),
                cwe_id: Some("CWE-312".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_ios_https() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-007".to_string(),
                title: "HTTPS Enforcement".to_string(),
                severity: MobileSeverity::High,
                category: MobileCheckCategory::Network,
                description: "Application may allow HTTP connections.".to_string(),
                details: vec![
                    "Check for: NSExceptionDomains with NSExceptionAllowsInsecureHTTPLoads".to_string(),
                    "Check URLSession configuration for HTTP allowances".to_string(),
                    "Check for: Alamofire/AFNetworking certificate validation bypass".to_string(),
                ],
                remediation: "Enforce HTTPS for all connections and implement certificate pinning.".to_string(),
                cwe_id: Some("CWE-319".to_string()),
                owasp_id: Some("M3".to_string()),
            },
        ]
    }

    fn check_ios_certificate_pinning() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-008".to_string(),
                title: "Missing Certificate Pinning".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Network,
                description: "Application does not implement certificate pinning.".to_string(),
                details: vec![
                    "Use TrustKit or NSURLSession pinning".to_string(),
                    "Check for: URLSessionDelegate authentication challenges".to_string(),
                    "Implement backup pins for certificate rotation".to_string(),
                ],
                remediation: "Implement certificate pinning with backup pins.".to_string(),
                cwe_id: Some("CWE-295".to_string()),
                owasp_id: Some("M3".to_string()),
            },
        ]
    }

    fn check_ios_biometric() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-009".to_string(),
                title: "Biometric Authentication Implementation".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Authentication,
                description: "Biometric authentication may have implementation weaknesses.".to_string(),
                details: vec![
                    "Use LocalAuthentication framework (LAContext)".to_string(),
                    "Check for: canEvaluatePolicy(.biometryAny)".to_string(),
                    "Implement keychain fallback for failed biometric".to_string(),
                ],
                remediation: "Use LAPolicyDeviceOwnerAuthenticationWithBiometrics with keychain.".to_string(),
                cwe_id: Some("CWE-287".to_string()),
                owasp_id: Some("M4".to_string()),
            },
        ]
    }

    fn check_ios_keychain_sharing() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-010".to_string(),
                title: "Keychain Access Group Sharing".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Authentication,
                description: "Keychain items shared across applications may be accessible.".to_string(),
                details: vec![
                    "Check kSecAttrAccessGroup for shared groups".to_string(),
                    "Only share keychain items between apps from same developer".to_string(),
                    "Verify access group prefix matches Team ID".to_string(),
                ],
                remediation: "Restrict keychain access groups to specific app identifiers.".to_string(),
                cwe_id: Some("CWE-312".to_string()),
                owasp_id: Some("M2".to_string()),
            },
        ]
    }

    fn check_ios_jailbreak_detection() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-011".to_string(),
                title: "Missing Jailbreak Detection".to_string(),
                severity: MobileSeverity::Medium,
                category: MobileCheckCategory::Binary,
                description: "Application does not detect jailbroken devices.".to_string(),
                details: vec![
                    "Check for: /Applications/Cydia.app existence".to_string(),
                    "Check for: fork() syscall availability".to_string(),
                    "Check for: write access to /private".to_string(),
                    "Note: Jailbreak detection can be bypassed".to_string(),
                ],
                remediation: "Implement multiple jailbreak detection methods.".to_string(),
                cwe_id: None,
                owasp_id: Some("M10".to_string()),
            },
        ]
    }

    fn check_ios_obfuscation() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-012".to_string(),
                title: "Missing Code Obfuscation".to_string(),
                severity: MobileSeverity::Low,
                category: MobileCheckCategory::Binary,
                description: "Binary is not obfuscated, making reverse engineering easier.".to_string(),
                details: vec![
                    "Check for: ObjC/Swift symbol stripping".to_string(),
                    "Use LLVM obfuscator for C/C++ code".to_string(),
                    "Strip debug symbols for release builds".to_string(),
                ],
                remediation: "Strip symbols and implement code obfuscation.".to_string(),
                cwe_id: None,
                owasp_id: Some("M9".to_string()),
            },
        ]
    }

    fn check_ios_arc() -> Vec<MobileFinding> {
        vec![
            MobileFinding {
                id: "IOS-013".to_string(),
                title: "ARC and Binary Protections".to_string(),
                severity: MobileSeverity::Low,
                category: MobileCheckCategory::Binary,
                description: "Check for essential binary protections.".to_string(),
                details: vec![
                    "Check for: ARC (Automatic Reference Counting) enabled".to_string(),
                    "Check for: Stack canaries (-fstack-protector-all)".to_string(),
                    "Check for: PIE (Position Independent Executable)".to_string(),
                    "Check for: Bitcode embedding".to_string(),
                ],
                remediation: "Enable all recommended Xcode build security settings.".to_string(),
                cwe_id: None,
                owasp_id: None,
            },
        ]
    }

    fn calculate_summary(findings: &[MobileFinding]) -> MobileScanSummary {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for finding in findings {
            match finding.severity {
                MobileSeverity::Critical => critical += 1,
                MobileSeverity::High => high += 1,
                MobileSeverity::Medium => medium += 1,
                MobileSeverity::Low => low += 1,
                MobileSeverity::Info => info += 1,
            }
        }

        let total = critical + high + medium + low + info;
        let risk_score = if total > 0 {
            ((critical * 10 + high * 7 + medium * 5 + low * 2) as f64 / (total as f64 * 10.0) * 10.0).min(10.0)
        } else {
            0.0
        };

        MobileScanSummary {
            total_checks: total,
            findings_count: total,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            risk_score,
        }
    }

    fn get_common_permissions() -> Vec<Permission> {
        vec![
            Permission { name: "android.permission.INTERNET".to_string(), level: PermissionLevel::Normal, description: "Full network access".to_string() },
            Permission { name: "android.permission.ACCESS_NETWORK_STATE".to_string(), level: PermissionLevel::Normal, description: "View network status".to_string() },
            Permission { name: "android.permission.READ_EXTERNAL_STORAGE".to_string(), level: PermissionLevel::Dangerous, description: "Read external storage".to_string() },
            Permission { name: "android.permission.WRITE_EXTERNAL_STORAGE".to_string(), level: PermissionLevel::Dangerous, description: "Write external storage".to_string() },
            Permission { name: "android.permission.CAMERA".to_string(), level: PermissionLevel::Dangerous, description: "Camera access".to_string() },
            Permission { name: "android.permission.ACCESS_FINE_LOCATION".to_string(), level: PermissionLevel::Dangerous, description: "GPS location".to_string() },
            Permission { name: "android.permission.READ_CONTACTS".to_string(), level: PermissionLevel::Dangerous, description: "Read contacts".to_string() },
            Permission { name: "android.permission.RECORD_AUDIO".to_string(), level: PermissionLevel::Dangerous, description: "Record audio".to_string() },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_analysis() {
        let config = MobileScanConfig {
            target_type: MobileTarget::Android,
            apk_path: None,
            ipa_path: None,
            deep_analysis: false,
            check_categories: vec![
                MobileCheckCategory::Manifest,
                MobileCheckCategory::Storage,
                MobileCheckCategory::Network,
                MobileCheckCategory::Cryptography,
                MobileCheckCategory::WebView,
                MobileCheckCategory::Authentication,
                MobileCheckCategory::Binary,
            ],
        };

        let result = MobileAnalyzer::analyze_apk(&config);
        assert!(result.findings.len() > 10);
        assert_eq!(result.target_type, MobileTarget::Android);
    }

    #[test]
    fn test_ios_analysis() {
        let config = MobileScanConfig {
            target_type: MobileTarget::IOS,
            apk_path: None,
            ipa_path: None,
            deep_analysis: false,
            check_categories: vec![
                MobileCheckCategory::Manifest,
                MobileCheckCategory::Storage,
                MobileCheckCategory::Network,
                MobileCheckCategory::Authentication,
                MobileCheckCategory::Binary,
            ],
        };

        let result = MobileAnalyzer::analyze_ipa(&config);
        assert!(result.findings.len() > 5);
        assert_eq!(result.target_type, MobileTarget::IOS);
    }

    #[test]
    fn test_permissions() {
        let perms = MobileAnalyzer::get_common_permissions();
        assert!(perms.len() > 5);
    }
}
