use anyhow::Result;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};
use url::Url;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Scan error: {0}")]
    ScanError(String),
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Vulnerable,
    NotVulnerable,
    Warning,
    Error,
    Skipped,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Vulnerable => write!(f, "VULNERABLE"),
            ScanStatus::NotVulnerable => write!(f, "NOT VULNERABLE"),
            ScanStatus::Warning => write!(f, "WARNING"),
            ScanStatus::Error => write!(f, "ERROR"),
            ScanStatus::Skipped => write!(f, "SKIPPED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub title: String,
    pub severity: Severity,
    pub status: ScanStatus,
    pub description: String,
    pub details: Vec<String>,
    pub remediation: String,
    pub cwe_id: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub check_name: String,
    pub status: ScanStatus,
    pub severity: Severity,
    pub findings: Vec<VulnerabilityFinding>,
    pub scan_duration_ms: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub url: String,
    pub scan_id: String,
    pub timestamp: String,
    pub results: Vec<ScanResult>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_checks: usize,
    pub vulnerable: usize,
    pub not_vulnerable: usize,
    pub warnings: usize,
    pub errors: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub risk_score: f64,
}

/// Lightweight metadata for listing saved scans without loading full reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMeta {
    pub scan_id: String,
    pub target_url: String,
    pub timestamp: String,
    pub risk_score: f64,
    pub total_checks: usize,
    pub vulnerable: usize,
    pub warnings: usize,
}

impl ScanReport {
    /// Serialize the full report to CSV (one row per finding).
    pub fn to_csv(&self) -> String {
        let mut out = String::new();
        out.push_str("scan_id,target_url,timestamp,check_name,finding_title,severity,status,cwe,remediation\n");
        let esc = |s: &str| -> String {
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };
        for result in &self.results {
            for f in &result.findings {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    esc(&self.scan_id),
                    esc(&self.url),
                    esc(&self.timestamp),
                    esc(&result.check_name),
                    esc(&f.title),
                    f.severity,
                    f.status,
                    esc(f.cwe_id.as_deref().unwrap_or("")),
                    esc(&f.remediation),
                ));
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub url: String,
    pub timeout_secs: u64,
    pub follow_redirects: bool,
    pub max_depth: usize,
    pub max_pages: usize,
    pub output_dir: Option<std::path::PathBuf>,
}

impl ScanConfig {
    pub fn new(url: &str) -> Result<Self, ScanError> {
        Url::parse(url).map_err(|e| ScanError::ParseError(e.to_string()))?;
        Ok(Self {
            url: url.to_string(),
            timeout_secs: 30,
            follow_redirects: true,
            max_depth: 2,
            max_pages: 25,
            output_dir: None,
        })
    }

    pub fn with_output_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.output_dir = Some(dir);
        self
    }
}

pub struct VulnerabilityScanner {
    config: ScanConfig,
    client: reqwest::Client,
    targets: Vec<String>,
}

impl VulnerabilityScanner {
    pub fn new(config: ScanConfig) -> Result<Self, ScanError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(true)
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()
            .map_err(|e| ScanError::ScanError(e.to_string()))?;

        Ok(Self { config, client, targets: Vec::new() })
    }

    /// Discover crawlable same-domain URLs (breadth-first) up to max_depth,
    /// capped at max_pages. The root URL is always included first.
    async fn discover_targets(&mut self) {
        let root = self.config.url.clone();
        let base = match Url::parse(&root) {
            Ok(u) => u,
            Err(_) => {
                self.targets = vec![root];
                return;
            }
        };
        let base_domain = base.domain().map(|d| d.to_string());

        let mut visited: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut discovered: Vec<String> = vec![root.clone()];
        visited.insert(root.clone());

        let mut depth = 0usize;
        let mut idx = 0usize;
        while depth < self.config.max_depth && visited.len() < self.config.max_pages {
            let current_batch: Vec<String> = discovered[idx..]
                .iter()
                .take(self.config.max_pages.saturating_sub(visited.len()).max(1))
                .cloned()
                .collect();
            if current_batch.is_empty() {
                break;
            }
            idx = discovered.len();
            depth += 1;

            for url in current_batch {
                if visited.len() >= self.config.max_pages {
                    break;
                }
                let body = match self.fetch_page_content(&url).await {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let doc = Html::parse_document(&body);
                let link_sel = match Selector::parse("a[href]") {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                for el in doc.select(&link_sel) {
                    if let Some(href) = el.value().attr("href") {
                        if let Ok(abs) = base.join(href) {
                            let mut abs = abs;
                            abs.set_fragment(None);
                            let s = abs.to_string();
                            if abs.domain() == base_domain.as_deref() && !visited.contains(&s) {
                                visited.insert(s.clone());
                                discovered.push(s);
                                if visited.len() >= self.config.max_pages {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        info!(
            "Discovered {} target URL(s) for scanning (depth {})",
            discovered.len(),
            self.config.max_depth
        );
        self.targets = discovered;
    }

    pub async fn run_full_scan(&mut self) -> Result<ScanReport, ScanError> {
        let scan_id = format!("scan_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        let timestamp = chrono::Utc::now().to_rfc3339();

        info!("Starting full vulnerability scan for: {}", self.config.url);

        self.discover_targets().await;
        let target_count = self.targets.len();

        let mut results = Vec::new();

        results.push(self.scan_security_headers().await);
        results.push(self.scan_xss_vulnerabilities().await);
        results.push(self.scan_sql_injection().await);
        results.push(self.scan_directory_traversal().await);
        results.push(self.scan_open_redirect().await);
        results.push(self.scan_csrf().await);
        results.push(self.scan_clickjacking().await);
        results.push(self.scan_mixed_content().await);
        results.push(self.scan_information_disclosure().await);
        results.push(self.scan_ssl_tls_config().await);
        results.push(self.scan_cookie_security().await);
        results.push(self.scan_server_info_leakage().await);
        results.push(self.scan_form_security().await);
        results.push(self.scan_file_inclusion().await);
        results.push(self.scan_outdated_software().await);
        results.push(self.scan_cors_misconfig().await);
        results.push(self.scan_csp().await);
        results.push(self.scan_subresource_integrity().await);
        results.push(self.scan_exposed_files().await);
        results.push(self.scan_directory_listing().await);

        let summary = self.calculate_summary(&results);

        info!(
            "Scan completed across {} URL(s). Risk score: {:.1}/10",
            target_count, summary.risk_score
        );

        let report = ScanReport {
            url: self.config.url.clone(),
            scan_id: scan_id.clone(),
            timestamp,
            results,
            summary,
        };

        if let Err(e) = self.save_report(&report) {
            warn!("Failed to persist scan report: {}", e);
        }

        Ok(report)
    }

    /// Persist a scan report to `<output_dir>/scans/<scan_id>.json`.
    pub fn save_report(&self, report: &ScanReport) -> Result<(), ScanError> {
        let dir = self
            .config
            .output_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("scans");
        std::fs::create_dir_all(&dir)
            .map_err(|e| ScanError::ScanError(format!("create dir: {}", e)))?;
        let path = dir.join(format!("{}.json", report.scan_id));
        let json = serde_json::to_string_pretty(report)
            .map_err(|e| ScanError::ScanError(e.to_string()))?;
        std::fs::write(&path, json)
            .map_err(|e| ScanError::ScanError(format!("write: {}", e)))?;
        info!("Scan report saved to {:?}", path);
        Ok(())
    }

    /// List previously saved scan reports from an output directory.
    pub fn list_scans(output_dir: &std::path::Path) -> Vec<ScanMeta> {
        let dir = output_dir.join("scans");
        let mut metas = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return metas,
        };
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(data) = std::fs::read_to_string(entry.path()) {
                if let Ok(report) = serde_json::from_str::<ScanReport>(&data) {
                    metas.push(ScanMeta {
                        scan_id: report.scan_id,
                        target_url: report.url,
                        timestamp: report.timestamp,
                        risk_score: report.summary.risk_score,
                        total_checks: report.summary.total_checks,
                        vulnerable: report.summary.vulnerable,
                        warnings: report.summary.warnings,
                    });
                }
            }
        }
        metas.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        metas
    }

    fn calculate_summary(&self, results: &[ScanResult]) -> ScanSummary {
        let mut summary = ScanSummary {
            total_checks: results.len(),
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
        };

        for result in results {
            match result.status {
                ScanStatus::Vulnerable => summary.vulnerable += 1,
                ScanStatus::NotVulnerable => summary.not_vulnerable += 1,
                ScanStatus::Warning => summary.warnings += 1,
                ScanStatus::Error => summary.errors += 1,
                ScanStatus::Skipped => {}
            }

            match result.severity {
                Severity::Critical => summary.critical_count += 1,
                Severity::High => summary.high_count += 1,
                Severity::Medium => summary.medium_count += 1,
                Severity::Low => summary.low_count += 1,
                Severity::Info => summary.info_count += 1,
            }
        }

        // Calculate risk score (0-10, higher is worse)
        let critical_weight = 10.0;
        let high_weight = 7.5;
        let medium_weight = 5.0;
        let low_weight = 2.5;
        let info_weight = 0.5;

        let total_weighted = (summary.critical_count as f64 * critical_weight)
            + (summary.high_count as f64 * high_weight)
            + (summary.medium_count as f64 * medium_weight)
            + (summary.low_count as f64 * low_weight)
            + (summary.info_count as f64 * info_weight);

        let max_possible = results.len() as f64 * critical_weight;
        summary.risk_score = if max_possible > 0.0 {
            (total_weighted / max_possible * 10.0).min(10.0)
        } else {
            0.0
        };

        summary
    }

    async fn fetch_page(&self, url: &str) -> Result<(String, reqwest::header::HeaderMap), ScanError> {
        let response = self.client.get(url).send().await?;
        let headers = response.headers().clone();
        let body = response.text().await?;
        Ok((body, headers))
    }

    async fn fetch_page_content(&self, url: &str) -> Result<String, ScanError> {
        let response = self.client.get(url).send().await?;
        let body = response.text().await?;
        Ok(body)
    }

    /// Active probe: inject `value` into the GET parameter `param` of `base`
    /// (preserving all other parameters) and return the response body, if any.
    async fn probe_param(&self, base: &Url, param: &str, value: &str) -> Option<String> {
        let original: Vec<(String, String)> = base
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if original.is_empty() {
            return None;
        }
        let mut test = base.clone();
        {
            let mut q = test.query_pairs_mut();
            q.clear();
            for (k, v) in &original {
                if k == param {
                    q.append_pair(k, value);
                } else {
                    q.append_pair(k, v);
                }
            }
        }
        self.fetch_page_content(&test.to_string()).await.ok()
    }

    /// GET parameters present on a URL (empty if none).
    fn url_params(base: &Url) -> Vec<(String, String)> {
        base.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    /// Verify the TLS certificate chain is trusted (strict client, no
    /// invalid-cert tolerance). Returns true only if the handshake succeeds.
    async fn verify_tls(&self, url: &str) -> bool {
        let strict = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .redirect(if self.config.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build();
        match strict {
            Ok(client) => client.get(url).send().await.is_ok(),
            Err(_) => false,
        }
    }

    // ========================================================================
    // CHECK 1: Security Headers Analysis
    // ========================================================================
    async fn scan_security_headers(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        match self.fetch_page(&self.config.url).await {
            Ok((_, headers)) => {
                // headers is already available from destructuring

                // Check for X-Frame-Options
                if let Some(xfo) = headers.get("x-frame-options") {
                    let val = xfo.to_str().unwrap_or("");
                    if val.to_lowercase() == "deny" || val.to_lowercase() == "sameorigin" {
                        findings.push(VulnerabilityFinding {
                            title: "X-Frame-Options Header Present".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "The X-Frame-Options header is properly set to prevent clickjacking attacks.".to_string(),
                            details: vec![format!("Value: {}", val)],
                            remediation: "No action needed. The header is correctly configured.".to_string(),
                            cwe_id: Some("CWE-1021".to_string()),
                            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options".to_string()],
                        });
                    } else {
                        findings.push(VulnerabilityFinding {
                            title: "Weak X-Frame-Options Configuration".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Vulnerable,
                            description: "The X-Frame-Options header is set to an insecure value.".to_string(),
                            details: vec![format!("Current value: {}", val), "Expected: DENY or SAMEORIGIN".to_string()],
                            remediation: "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.".to_string(),
                            cwe_id: Some("CWE-1021".to_string()),
                            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options".to_string()],
                        });
                    }
                } else {
                    findings.push(VulnerabilityFinding {
                        title: "Missing X-Frame-Options Header".to_string(),
                        severity: Severity::Medium,
                        status: ScanStatus::Vulnerable,
                        description: "The X-Frame-Options header is missing, making the site susceptible to clickjacking attacks.".to_string(),
                        details: vec!["No X-Frame-Options header found in HTTP response".to_string()],
                        remediation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header to all HTTP responses.".to_string(),
                        cwe_id: Some("CWE-1021".to_string()),
                        references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options".to_string()],
                    });
                }

                // Check for Content-Security-Policy
                if let Some(csp) = headers.get("content-security-policy") {
                    let val = csp.to_str().unwrap_or("");
                    if val.contains("script-src") && !val.contains("'unsafe-inline'") && !val.contains("'unsafe-eval'") {
                        findings.push(VulnerabilityFinding {
                            title: "Strong Content-Security-Policy".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "The CSP header is properly configured with restrictive script directives.".to_string(),
                            details: vec![format!("CSP: {}", val.chars().take(200).collect::<String>())],
                            remediation: "No action needed. CSP is well configured.".to_string(),
                            cwe_id: Some("CWE-1021".to_string()),
                            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy".to_string()],
                        });
                    } else {
                        findings.push(VulnerabilityFinding {
                            title: "Weak Content-Security-Policy".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Warning,
                            description: "The CSP header contains unsafe directives that may weaken security.".to_string(),
                            details: vec![format!("CSP: {}", val.chars().take(200).collect::<String>())],
                            remediation: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src directive. Use nonces or hashes instead.".to_string(),
                            cwe_id: Some("CWE-1021".to_string()),
                            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy".to_string()],
                        });
                    }
                } else {
                    findings.push(VulnerabilityFinding {
                        title: "Missing Content-Security-Policy Header".to_string(),
                        severity: Severity::High,
                        status: ScanStatus::Vulnerable,
                        description: "No Content-Security-Policy header found. This increases the risk of XSS and data injection attacks.".to_string(),
                        details: vec!["CSP header is completely absent".to_string()],
                        remediation: "Implement a Content-Security-Policy header with appropriate directives for your application.".to_string(),
                        cwe_id: Some("CWE-693".to_string()),
                        references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy".to_string()],
                    });
                }

                // Check for Strict-Transport-Security
                if let Some(hsts) = headers.get("strict-transport-security") {
                    let val = hsts.to_str().unwrap_or("");
                    if val.contains("max-age=") {
                        let max_age_str = val.split("max-age=").nth(1).unwrap_or("0").split(';').next().unwrap_or("0");
                        if let Ok(max_age) = max_age_str.trim().parse::<u64>() {
                            if max_age >= 31536000 {
                                findings.push(VulnerabilityFinding {
                                    title: "Strong HSTS Configuration".to_string(),
                                    severity: Severity::Info,
                                    status: ScanStatus::NotVulnerable,
                                    description: "HSTS is configured with a sufficiently long max-age.".to_string(),
                                    details: vec![format!("Max-Age: {} seconds ({} days)", max_age, max_age / 86400)],
                                    remediation: "No action needed. HSTS is properly configured.".to_string(),
                                    cwe_id: Some("CWE-319".to_string()),
                                    references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security".to_string()],
                                });
                            } else {
                                findings.push(VulnerabilityFinding {
                                    title: "Weak HSTS Max-Age".to_string(),
                                    severity: Severity::Medium,
                                    status: ScanStatus::Vulnerable,
                                    description: "The HSTS max-age is too short.".to_string(),
                                    details: vec![format!("Max-Age: {} seconds (recommended: 31536000+)", max_age)],
                                    remediation: "Set HSTS max-age to at least 31536000 seconds (1 year). Consider adding 'includeSubDomains' and 'preload'.".to_string(),
                                    cwe_id: Some("CWE-319".to_string()),
                                    references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security".to_string()],
                                });
                            }
                        }
                    }
                } else {
                    findings.push(VulnerabilityFinding {
                        title: "Missing HSTS Header".to_string(),
                        severity: Severity::High,
                        status: ScanStatus::Vulnerable,
                        description: "The Strict-Transport-Security header is missing. Users may be vulnerable to protocol downgrade attacks.".to_string(),
                        details: vec!["HSTS header is completely absent".to_string()],
                        remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.".to_string(),
                        cwe_id: Some("CWE-319".to_string()),
                        references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security".to_string()],
                    });
                }

                // Check for X-Content-Type-Options
                if let Some(xcto) = headers.get("x-content-type-options") {
                    let val = xcto.to_str().unwrap_or("");
                    if val.to_lowercase() == "nosniff" {
                        findings.push(VulnerabilityFinding {
                            title: "X-Content-Type-Options Present".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "The X-Content-Type-Options header prevents MIME-type sniffing.".to_string(),
                            details: vec![format!("Value: {}", val)],
                            remediation: "No action needed.".to_string(),
                            cwe_id: Some("CWE-693".to_string()),
                            references: vec![],
                        });
                    }
                } else {
                    findings.push(VulnerabilityFinding {
                        title: "Missing X-Content-Type-Options Header".to_string(),
                        severity: Severity::Low,
                        status: ScanStatus::Vulnerable,
                        description: "The X-Content-Type-Options header is missing, potentially allowing MIME-type sniffing.".to_string(),
                        details: vec!["Header absent from response".to_string()],
                        remediation: "Add 'X-Content-Type-Options: nosniff' to all responses.".to_string(),
                        cwe_id: Some("CWE-693".to_string()),
                        references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options".to_string()],
                    });
                }

                // Check for X-XSS-Protection
                if let Some(xss_header) = headers.get("x-xss-protection") {
                    let val = xss_header.to_str().unwrap_or("");
                    if val == "0" || val.contains("1; mode=block") {
                        findings.push(VulnerabilityFinding {
                            title: "X-XSS-Protection Configured".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "The X-XSS-Protection header is configured.".to_string(),
                            details: vec![format!("Value: {}", val)],
                            remediation: "No action needed. Consider using CSP instead.".to_string(),
                            cwe_id: Some("CWE-79".to_string()),
                            references: vec![],
                        });
                    }
                } else {
                    findings.push(VulnerabilityFinding {
                        title: "Missing X-XSS-Protection Header".to_string(),
                        severity: Severity::Low,
                        status: ScanStatus::Warning,
                        description: "The X-XSS-Protection header is missing. While modern browsers rely on CSP, this provides defense-in-depth.".to_string(),
                        details: vec!["Header absent from response".to_string()],
                        remediation: "Add 'X-XSS-Protection: 1; mode=block' as a defense-in-depth measure.".to_string(),
                        cwe_id: Some("CWE-79".to_string()),
                        references: vec![],
                    });
                }

                // Check for Referrer-Policy
                if let Some(rp) = headers.get("referrer-policy") {
                    let val = rp.to_str().unwrap_or("");
                    if val == "no-referrer" || val == "strict-origin-when-cross-origin" || val == "same-origin" {
                        findings.push(VulnerabilityFinding {
                            title: "Referrer-Policy Configured".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "The Referrer-Policy header is properly configured.".to_string(),
                            details: vec![format!("Value: {}", val)],
                            remediation: "No action needed.".to_string(),
                            cwe_id: Some("CWE-200".to_string()),
                            references: vec![],
                        });
                    } else {
                        findings.push(VulnerabilityFinding {
                            title: "Weak Referrer-Policy".to_string(),
                            severity: Severity::Low,
                            status: ScanStatus::Warning,
                            description: "The Referrer-Policy is set but could be more restrictive.".to_string(),
                            details: vec![format!("Value: {}", val)],
                            remediation: "Consider using 'strict-origin-when-cross-origin' or 'no-referrer'.".to_string(),
                            cwe_id: Some("CWE-200".to_string()),
                            references: vec![],
                        });
                    }
                } else {
                    findings.push(VulnerabilityFinding {
                        title: "Missing Referrer-Policy Header".to_string(),
                        severity: Severity::Low,
                        status: ScanStatus::Warning,
                        description: "No Referrer-Policy header found. Sensitive information in URLs may leak via Referer headers.".to_string(),
                        details: vec!["Header absent from response".to_string()],
                        remediation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.".to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        references: vec![],
                    });
                }

                // Check for Permissions-Policy
                if let Some(pp) = headers.get("permissions-policy") {
                    let val = pp.to_str().unwrap_or("");
                    findings.push(VulnerabilityFinding {
                        title: "Permissions-Policy Present".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::NotVulnerable,
                        description: "The Permissions-Policy header is configured.".to_string(),
                        details: vec![format!("Value: {}", val.chars().take(200).collect::<String>())],
                        remediation: "No action needed.".to_string(),
                        cwe_id: None,
                        references: vec![],
                    });
                } else {
                    findings.push(VulnerabilityFinding {
                        title: "Missing Permissions-Policy Header".to_string(),
                        severity: Severity::Low,
                        status: ScanStatus::Warning,
                        description: "No Permissions-Policy header found. Browser features are not restricted.".to_string(),
                        details: vec!["Header absent from response".to_string()],
                        remediation: "Add a Permissions-Policy header to restrict browser features.".to_string(),
                        cwe_id: None,
                        references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy".to_string()],
                    });
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page for header analysis: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        let has_warning = findings.iter().any(|f| f.status == ScanStatus::Warning);

        ScanResult {
            check_name: "Security Headers Analysis".to_string(),
            status: if has_vuln {
                ScanStatus::Vulnerable
            } else if has_warning {
                ScanStatus::Warning
            } else {
                ScanStatus::NotVulnerable
            },
            severity: if has_vuln {
                Severity::High
            } else if has_warning {
                Severity::Medium
            } else {
                Severity::Info
            },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 2: XSS Vulnerabilities
    // ========================================================================
    async fn scan_xss_vulnerabilities(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };

        let payloads = vec![
            "><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><svg/onload=alert(1)>",
        ];

        let mut reflected_count = 0u32;
        let mut reflected_samples: Vec<String> = Vec::new();
        let mut forms_total = 0u32;
        let mut js_href_total = 0u32;
        let mut dom_sinks = 0u32;

        let dom_patterns = [
            "document.write(",
            "innerHTML",
            "outerHTML",
            "eval(",
            "setTimeout(",
            "setInterval(",
            "document.location",
            "window.location",
        ];

        for url in &targets {
            // Active reflected-XSS probe: inject each payload into every GET parameter
            // and check whether the exact payload is reflected unencoded in the response.
            if let Ok(parsed) = Url::parse(url) {
                let original: Vec<(String, String)> = parsed
                    .query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                if !original.is_empty() {
                    for (param, _) in &original {
                        for p in &payloads {
                            let mut test = parsed.clone();
                            {
                                let mut q = test.query_pairs_mut();
                                q.clear();
                                for (k, v) in &original {
                                    if k == param {
                                        q.append_pair(k, p);
                                    } else {
                                        q.append_pair(k, v);
                                    }
                                }
                            }
                            if let Ok(body) = self.fetch_page_content(&test.to_string()).await {
                                if body.contains(p) {
                                    reflected_count += 1;
                                    if reflected_samples.len() < 5 {
                                        reflected_samples.push(format!(
                                            "Reflected payload in param '{}' of {}",
                                            param, url
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Passive signals (informational, not proof of exploitability)
            if let Ok(html) = self.fetch_page_content(url).await {
                let doc = Html::parse_document(&html);
                forms_total += doc.select(&Selector::parse("form").unwrap()).count() as u32;
                js_href_total += doc
                    .select(&Selector::parse("a[href^='javascript:']").unwrap())
                    .count() as u32;
                for pat in &dom_patterns {
                    if html.contains(pat) {
                        dom_sinks += 1;
                    }
                }
            }
        }

        if reflected_count > 0 {
            findings.push(VulnerabilityFinding {
                title: "Reflected XSS Confirmed".to_string(),
                severity: Severity::Critical,
                status: ScanStatus::Vulnerable,
                description: format!(
                    "{} reflected-XSS probe(s) returned the injected payload unencoded in the response body, confirming reflected cross-site scripting.",
                    reflected_count
                ),
                details: reflected_samples,
                remediation:
                    "HTML-encode and contextually sanitize all reflected output. Enforce a Content-Security-Policy.".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
            });
        }

        if js_href_total > 0 {
            findings.push(VulnerabilityFinding {
                title: "JavaScript URLs in Links".to_string(),
                severity: Severity::High,
                status: ScanStatus::Warning,
                description: format!(
                    "Found {} link(s) using javascript: URLs across scanned pages; these execute script when activated.",
                    js_href_total
                ),
                details: vec![format!("Total javascript: links: {}", js_href_total)],
                remediation: "Remove javascript: URLs from href attributes; use addEventListener instead.".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
            });
        }

        if dom_sinks > 0 {
            findings.push(VulnerabilityFinding {
                title: "DOM-based XSS Sinks Detected".to_string(),
                severity: Severity::Medium,
                status: ScanStatus::Warning,
                description: format!(
                    "Found {} potentially dangerous DOM sink(s) (innerHTML, eval, document.write, etc.) that can lead to DOM-based XSS if fed untrusted input.",
                    dom_sinks
                ),
                details: dom_patterns
                    .iter()
                    .map(|p| format!("Monitored sink: {}", p))
                    .collect(),
                remediation: "Use safe DOM APIs (textContent) and sanitize untrusted data before sink assignment.".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
            });
        }

        if reflected_count == 0 && forms_total > 0 {
            findings.push(VulnerabilityFinding {
                title: "Forms Present (No Reflected XSS Observed)".to_string(),
                severity: Severity::Info,
                status: ScanStatus::Warning,
                description: format!(
                    "Found {} form(s) across scanned pages. No reflected-XSS was confirmed via GET-parameter probing, but inputs should still be validated server-side.",
                    forms_total
                ),
                details: vec![format!("Forms found: {}", forms_total)],
                remediation: "Validate and encode all user input server-side regardless of client checks.".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
            });
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        let has_warning = findings.iter().any(|f| f.status == ScanStatus::Warning);

        ScanResult {
            check_name: "Cross-Site Scripting (XSS) Detection".to_string(),
            status: if has_vuln {
                ScanStatus::Vulnerable
            } else if has_warning {
                ScanStatus::Warning
            } else {
                ScanStatus::NotVulnerable
            },
            severity: if has_vuln {
                Severity::Critical
            } else if has_warning {
                Severity::Medium
            } else {
                Severity::Info
            },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 3: SQL Injection Detection
    // ========================================================================
    async fn scan_sql_injection(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };

        let sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "microsoft ole db provider for odbc drivers",
            "microsoft ole db provider for sql server",
            "incorrect syntax near",
            "unterminated string",
            "ora-00933",
            "ora-00921",
            "postgresql",
            "sqlite3::",
            "sqlite::",
            "sql syntax",
            "syntax error",
            "mysql_fetch",
            "pg_query",
            "pg_exec",
        ];

        let payloads = ["'", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "1' AND '1'='1"];

        let mut confirmed = 0u32;
        let mut confirmed_samples: Vec<String> = Vec::new();

        for url in &targets {
            if let Ok(parsed) = Url::parse(url) {
                let params = Self::url_params(&parsed);
                if params.is_empty() {
                    continue;
                }
                for (param, _) in &params {
                    for p in &payloads {
                        if let Some(body) = self.probe_param(&parsed, param, p).await {
                            let lower = body.to_lowercase();
                            let hit = sql_errors.iter().any(|e| lower.contains(e));
                            if hit {
                                confirmed += 1;
                                if confirmed_samples.len() < 5 {
                                    confirmed_samples.push(format!(
                                        "SQL error triggered via param '{}' on {}",
                                        param, url
                                    ));
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        if confirmed > 0 {
            findings.push(VulnerabilityFinding {
                title: "SQL Injection Confirmed".to_string(),
                severity: Severity::Critical,
                status: ScanStatus::Vulnerable,
                description: format!(
                    "{} active probe(s) returned database error signatures, confirming SQL injection.",
                    confirmed
                ),
                details: confirmed_samples,
                remediation:
                    "Use parameterized queries / prepared statements everywhere. Disable verbose SQL errors in production.".to_string(),
                cwe_id: Some("CWE-89".to_string()),
                references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
            });
        }

        if confirmed == 0 {
            let mut params_total = 0u32;
            let mut forms_total = 0u32;
            for url in &targets {
                if let Ok(html) = self.fetch_page_content(url).await {
                    let doc = Html::parse_document(&html);
                    forms_total += doc.select(&Selector::parse("form").unwrap()).count() as u32;
                    if let Ok(parsed) = Url::parse(url) {
                        params_total += Self::url_params(&parsed).len() as u32;
                    }
                }
            }
            if params_total > 0 || forms_total > 0 {
                findings.push(VulnerabilityFinding {
                    title: "Injectable Parameters/Forms Present".to_string(),
                    severity: Severity::Medium,
                    status: ScanStatus::Warning,
                    description: format!(
                        "Found {} URL parameter(s) and {} form(s) across scanned pages. No SQL error was triggered via probing, but inputs should still be parameterized.",
                        params_total, forms_total
                    ),
                    details: vec![
                        format!("Params: {}", params_total),
                        format!("Forms: {}", forms_total),
                    ],
                    remediation:
                        "Validate and parameterize all inputs server-side. Use an ORM or query builder.".to_string(),
                    cwe_id: Some("CWE-89".to_string()),
                    references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        let has_warning = findings.iter().any(|f| f.status == ScanStatus::Warning);

        ScanResult {
            check_name: "SQL Injection Detection".to_string(),
            status: if has_vuln {
                ScanStatus::Vulnerable
            } else if has_warning {
                ScanStatus::Warning
            } else {
                ScanStatus::NotVulnerable
            },
            severity: if has_vuln {
                Severity::Critical
            } else if has_warning {
                Severity::Medium
            } else {
                Severity::Info
            },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 4: Directory Traversal
    // ========================================================================
    async fn scan_directory_traversal(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };

        let traversal_payloads = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\etc\\passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        ];
        let signatures = [
            "root:x:0:0:",
            "daemon:x:",
            "/bin/bash",
            "/bin/sh",
            "[boot loader]",
            "; for 16-bit app support",
        ];

        // Active path-traversal / LFI probing: inject payloads into every GET
        // parameter and look for local file content leaking into the response.
        let mut leaked = 0u32;
        let mut samples: Vec<String> = Vec::new();
        for url in &targets {
            if let Ok(parsed) = Url::parse(url) {
                let params = Self::url_params(&parsed);
                if params.is_empty() {
                    continue;
                }
                for (param, _) in &params {
                    for p in &traversal_payloads {
                        if let Some(body) = self.probe_param(&parsed, param, p).await {
                            if signatures.iter().any(|s| body.contains(s)) {
                                leaked += 1;
                                if samples.len() < 5 {
                                    samples.push(format!(
                                        "Local file disclosed via param '{}' on {}",
                                        param, url
                                    ));
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        if leaked > 0 {
            findings.push(VulnerabilityFinding {
                title: "Local File Disclosure (Path Traversal) Confirmed".to_string(),
                severity: Severity::Critical,
                status: ScanStatus::Vulnerable,
                description: format!(
                    "{} probe(s) returned local file contents, confirming path traversal / LFI.",
                    leaked
                ),
                details: samples,
                remediation: "Canonicalize and validate file paths; reject '..' sequences; use an allowlist of base directories.".to_string(),
                cwe_id: Some("CWE-22".to_string()),
                references: vec!["https://owasp.org/www-community/attacks/Path_Traversal".to_string()],
            });
        }

        // Passive: check if the base URL responds with directory listing indicators
        match self.fetch_page(&self.config.url).await {
            Ok((html, _)) => {
                let html_lower = html.to_lowercase();

                // Check for directory listing
                if html_lower.contains("index of /") || html_lower.contains("directory listing") || html_lower.contains("parent directory") {
                    findings.push(VulnerabilityFinding {
                        title: "Directory Listing Enabled".to_string(),
                        severity: Severity::Medium,
                        status: ScanStatus::Vulnerable,
                        description: "The web server has directory listing enabled, exposing file structure.".to_string(),
                        details: vec!["Directory listing detected in page content".to_string()],
                        remediation: "Disable directory listing in your web server configuration. Add index files to directories.".to_string(),
                        cwe_id: Some("CWE-548".to_string()),
                        references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Enumerate_Infrastructure_and_Application_Admin_Interfaces".to_string()],
                    });
                }

                // Check for backup files exposed
                let backup_extensions = vec![
                    ".bak", ".backup", ".old", ".orig", ".save", ".swp",
                    ".sql", ".dump", ".tar.gz", ".zip",
                ];

                let document = Html::parse_document(&html);
                let a_selector = Selector::parse("a[href]").ok();
                if let Some(sel) = a_selector {
                    let links: Vec<String> = document.select(&sel)
                        .filter_map(|e| e.value().attr("href").map(|h| h.to_string()))
                        .collect();

                    let mut exposed_backups = Vec::new();
                    for link in &links {
                        for ext in &backup_extensions {
                            if link.ends_with(ext) {
                                exposed_backups.push(link.clone());
                                break;
                            }
                        }
                    }

                    if !exposed_backups.is_empty() {
                        findings.push(VulnerabilityFinding {
                            title: "Backup Files Exposed".to_string(),
                            severity: Severity::High,
                            status: ScanStatus::Vulnerable,
                            description: format!("Found {} backup file(s) accessible via web, potentially exposing sensitive data.", exposed_backups.len()),
                            details: exposed_backups.iter().map(|f| format!("File: {}", f)).collect(),
                            remediation: "Remove backup files from web-accessible directories. Configure web server to deny access to backup file extensions.".to_string(),
                            cwe_id: Some("CWE-530".to_string()),
                            references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Endpoint_Group Enumeration".to_string()],
                        });
                    }
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for Directory Traversal Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "Directory Traversal Detection".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 5: Open Redirect Detection
    // ========================================================================
    async fn scan_open_redirect(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        let redirect_params = vec![
            "url", "redirect", "redirect_url", "redirect_uri", "return",
            "return_to", "next", "goto", "continue", "dest", "destination",
            "redir", "redirect_uri", "return_url", "checkout_url",
        ];

        // Active open-redirect probe: for each redirect-like parameter, send an
        // external target and check whether the response Location header follows it.
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };
        let evil = "https://evil-example.com/";
        for url in &targets {
            if let Ok(parsed) = Url::parse(url) {
                let params = Self::url_params(&parsed);
                for (param, _) in &params {
                    if !redirect_params.iter().any(|p| param.to_lowercase().contains(p)) {
                        continue;
                    }
                    let mut test = parsed.clone();
                    {
                        let mut q = test.query_pairs_mut();
                        q.clear();
                        for (k, v) in &params {
                            if k == param {
                                q.append_pair(k, evil);
                            } else {
                                q.append_pair(k, v);
                            }
                        }
                    }
                    if let Ok(resp) = self.client.get(test.to_string()).send().await {
                        if let Some(loc) = resp.headers().get("location") {
                            let loc = loc.to_str().unwrap_or("").to_string();
                            if loc.starts_with("https://evil-example.com")
                                || loc.starts_with("//evil-example.com")
                            {
                                findings.push(VulnerabilityFinding {
                                    title: "Open Redirect Confirmed".to_string(),
                                    severity: Severity::High,
                                    status: ScanStatus::Vulnerable,
                                    description: format!(
                                        "Parameter '{}' forwarded an attacker-controlled URL to an external domain via the Location header.",
                                        param
                                    ),
                                    details: vec![format!("Redirect -> {}", loc)],
                                    remediation:
                                        "Whitelist redirect destinations server-side; never trust user-supplied URLs.".to_string(),
                                    cwe_id: Some("CWE-601".to_string()),
                                    references: vec!["https://owasp.org/www-community/attacks/Unsafe_Redirects".to_string()],
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Check current URL for redirect parameters
        if let Ok(parsed_url) = Url::parse(&self.config.url) {
            let params: Vec<(String, String)> = parsed_url.query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            for (key, value) in &params {
                let key_lower = key.to_lowercase();
                if redirect_params.iter().any(|p| key_lower.contains(p)) {
                    // Check if the parameter contains an external URL
                    if value.starts_with("http://") || value.starts_with("https://") || value.starts_with("//") {
                        findings.push(VulnerabilityFinding {
                            title: "Potential Open Redirect via URL Parameter".to_string(),
                            severity: Severity::High,
                            status: ScanStatus::Warning,
                            description: format!("URL parameter '{}' contains an external URL which may be used for open redirect attacks.", key),
                            details: vec![
                                format!("Parameter: {}={}", key, value),
                                "External URLs in redirect parameters can be exploited for phishing".to_string(),
                            ],
                            remediation: "Validate redirect URLs against a whitelist of allowed domains. Never redirect to user-supplied URLs without validation.".to_string(),
                            cwe_id: Some("CWE-601".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/Unsafe_Redirects".to_string()],
                        });
                    }
                }
            }
        }

        // Check the page for meta refresh redirects and JavaScript redirects
        match self.fetch_page(&self.config.url).await {
            Ok((html, headers)) => {
                let html_lower = html.to_lowercase();

                // Check for meta refresh redirect
                if html_lower.contains("meta http-equiv=\"refresh\"") || html_lower.contains("meta http-equiv='refresh'") {
                    let document = Html::parse_document(&html);
                    let meta_selector = Selector::parse("meta[http-equiv='refresh'], meta[http-equiv=\"refresh\"]").ok();
                    if let Some(sel) = meta_selector {
                        let metas: Vec<_> = document.select(&sel).collect();
                        for meta in &metas {
                            if let Some(content) = meta.value().attr("content") {
                                if content.to_lowercase().contains("url=") {
                                    let redirect_url = content.split("url=").nth(1).unwrap_or("");
                                    if redirect_url.starts_with("http://") || redirect_url.starts_with("https://") {
                                        findings.push(VulnerabilityFinding {
                                            title: "Meta Refresh External Redirect".to_string(),
                                            severity: Severity::Medium,
                                            status: ScanStatus::Warning,
                                            description: "The page uses meta refresh to redirect to an external URL.".to_string(),
                                            details: vec![format!("Redirect target: {}", redirect_url)],
                                            remediation: "Avoid using meta refresh for external redirects. Use server-side redirects with proper validation.".to_string(),
                                            cwe_id: Some("CWE-601".to_string()),
                                            references: vec![],
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for JavaScript-based redirects
                let js_redirect_patterns = vec![
                    "window.location.href",
                    "window.location.replace",
                    "window.location =",
                    "document.location.href",
                    "document.location =",
                ];

                let mut js_redirects = Vec::new();
                for pattern in &js_redirect_patterns {
                    if html_lower.contains(pattern) {
                        js_redirects.push(pattern.to_string());
                    }
                }

                if !js_redirects.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "JavaScript Redirects Detected".to_string(),
                        severity: Severity::Medium,
                        status: ScanStatus::Warning,
                        description: format!("Found {} JavaScript redirect pattern(s) that could be used for open redirects.", js_redirects.len()),
                        details: js_redirects,
                        remediation: "Validate redirect targets in JavaScript. Avoid using user-controlled input in redirect URLs.".to_string(),
                        cwe_id: Some("CWE-601".to_string()),
                        references: vec!["https://owasp.org/www-community/attacks/Unsafe_Redirects".to_string()],
                    });
                }

                // Check for 3xx redirects in response
                if let Some(location) = headers.get("location") {
                    let loc = location.to_str().unwrap_or("");
                    if loc.starts_with("http://") || loc.starts_with("https://") {
                        if let Ok(redirect_url) = Url::parse(loc) {
                            if let Ok(base_url) = Url::parse(&self.config.url) {
                                if redirect_url.host_str() != base_url.host_str() {
                                    findings.push(VulnerabilityFinding {
                                        title: "External Redirect in Response Headers".to_string(),
                                        severity: Severity::Medium,
                                        status: ScanStatus::Warning,
                                        description: "The server redirects to an external domain via the Location header.".to_string(),
                                        details: vec![format!("Redirect from: {}", self.config.url), format!("Redirect to: {}", loc)],
                                        remediation: "Ensure redirects only go to allowed domains. Validate the target URL before redirecting.".to_string(),
                                        cwe_id: Some("CWE-601".to_string()),
                                        references: vec![],
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for Open Redirect Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        let has_warning = findings.iter().any(|f| f.status == ScanStatus::Warning);

        ScanResult {
            check_name: "Open Redirect Detection".to_string(),
            status: if has_vuln {
                ScanStatus::Vulnerable
            } else if has_warning {
                ScanStatus::Warning
            } else {
                ScanStatus::NotVulnerable
            },
            severity: if has_vuln { Severity::High } else if has_warning { Severity::Medium } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 6: CSRF Detection
    // ========================================================================
    async fn scan_csrf(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        match self.fetch_page(&self.config.url).await {
            Ok((html, _)) => {
                let document = Html::parse_document(&html);

                // Find all forms
                let form_selector = Selector::parse("form").ok();
                let input_selector = Selector::parse("input[name]").ok();

                if let Some(sel) = form_selector {
                    let forms: Vec<_> = document.select(&sel).collect();

                    for (i, form) in forms.iter().enumerate() {
                        let method = form.value().attr("method").unwrap_or("GET").to_uppercase();
                        let action = form.value().attr("action").unwrap_or("N/A");

                        // Check for state-changing forms without CSRF tokens
                        if method == "POST" || method == "PUT" || method == "DELETE" {
                            let has_csrf_token = if let Some(isel) = &input_selector {
                                form.select(isel).any(|input| {
                                    let name = input.value().attr("name").unwrap_or("").to_lowercase();
                                    let input_type = input.value().attr("type").unwrap_or("").to_lowercase();
                                    name.contains("csrf") || name.contains("token") || name.contains("_token")
                                        || name.contains("nonce") || name.contains("xsrf")
                                        || (input_type == "hidden" && (name.contains("csrf") || name.contains("token")))
                                })
                            } else {
                                false
                            };

                            // Also check for CSRF meta tags
                            let has_csrf_meta = {
                                let meta_selector = Selector::parse("meta[name*='csrf'], meta[name*='token']").ok();
                                if let Some(msel) = meta_selector {
                                    document.select(&msel).count() > 0
                                } else {
                                    false
                                }
                            };

                            // Check for custom headers (X-CSRF-Token, X-XSRF-TOKEN)
                            // Note: We can't check response headers for this from HTML, but we check patterns in JS
                            let has_csrf_header = html.contains("X-CSRF-Token") || html.contains("X-XSRF-TOKEN")
                                || html.contains("x-csrf-token") || html.contains("x-xsrf-token");

                            if !has_csrf_token && !has_csrf_meta && !has_csrf_header {
                                findings.push(VulnerabilityFinding {
                                    title: format!("Form #{} Missing CSRF Protection", i + 1),
                                    severity: Severity::High,
                                    status: ScanStatus::Vulnerable,
                                    description: format!("State-changing form ({}) without CSRF token detected. Action: {}", method, action),
                                    details: vec![
                                        format!("Form method: {}", method),
                                        format!("Form action: {}", action),
                                        "No CSRF token found in form fields, meta tags, or headers".to_string(),
                                    ],
                                    remediation: "Implement CSRF tokens in all state-changing forms. Use SameSite cookie attribute. Consider using the Synchronizer Token Pattern or SameSite cookie-based CSRF protection.".to_string(),
                                    cwe_id: Some("CWE-352".to_string()),
                                    references: vec!["https://owasp.org/www-community/attacks/csrf".to_string()],
                                });
                            } else {
                                findings.push(VulnerabilityFinding {
                                    title: format!("Form #{} Has CSRF Protection", i + 1),
                                    severity: Severity::Info,
                                    status: ScanStatus::NotVulnerable,
                                    description: format!("Form ({}) has CSRF protection implemented.", method),
                                    details: vec![
                                        format!("Form action: {}", action),
                                        "CSRF token or protection mechanism detected".to_string(),
                                    ],
                                    remediation: "No action needed. CSRF protection is in place.".to_string(),
                                    cwe_id: Some("CWE-352".to_string()),
                                    references: vec![],
                                });
                            }
                        }
                    }

                    if forms.is_empty() {
                        findings.push(VulnerabilityFinding {
                            title: "No Forms Detected".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "No forms were found on the page, so CSRF risk is minimal.".to_string(),
                            details: vec![],
                            remediation: "Ensure any AJAX-based state changes use anti-CSRF tokens.".to_string(),
                            cwe_id: Some("CWE-352".to_string()),
                            references: vec![],
                        });
                    }
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for CSRF Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "CSRF Vulnerability Detection".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 7: Clickjacking Detection
    // ========================================================================
    async fn scan_clickjacking(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        match self.fetch_page(&self.config.url).await {
            Ok((_, headers)) => {
                // headers is already a HeaderMap

                let has_xfo = headers.contains_key("x-frame-options");
                let has_csp_frame = headers.get("content-security-policy")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.contains("frame-ancestors"))
                    .unwrap_or(false);

                if has_xfo || has_csp_frame {
                    let mut details = Vec::new();
                    if has_xfo {
                        if let Some(val) = headers.get("x-frame-options") {
                            details.push(format!("X-Frame-Options: {}", val.to_str().unwrap_or("")));
                        }
                    }
                    if has_csp_frame {
                        if let Some(val) = headers.get("content-security-policy") {
                            let csp = val.to_str().unwrap_or("");
                            if let Some(fa) = csp.split("frame-ancestors").nth(1) {
                                let value = fa.split(';').next().unwrap_or("").trim();
                                details.push(format!("CSP frame-ancestors: {}", value));
                            }
                        }
                    }

                    findings.push(VulnerabilityFinding {
                        title: "Clickjacking Protection Enabled".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::NotVulnerable,
                        description: "The page has clickjacking protection via X-Frame-Options or CSP frame-ancestors.".to_string(),
                        details,
                        remediation: "No action needed. Clickjacking protection is in place.".to_string(),
                        cwe_id: Some("CWE-1021".to_string()),
                        references: vec!["https://owasp.org/www-community/attacks/Clickjacking".to_string()],
                    });
                } else {
                    findings.push(VulnerabilityFinding {
                        title: "Missing Clickjacking Protection".to_string(),
                        severity: Severity::Medium,
                        status: ScanStatus::Vulnerable,
                        description: "The page can be embedded in an iframe, making it susceptible to clickjacking attacks.".to_string(),
                        details: vec![
                            "No X-Frame-Options header found".to_string(),
                            "No CSP frame-ancestors directive found".to_string(),
                        ],
                        remediation: "Add 'X-Frame-Options: DENY' header or implement CSP with 'frame-ancestors' directive.".to_string(),
                        cwe_id: Some("CWE-1021".to_string()),
                        references: vec!["https://owasp.org/www-community/attacks/Clickjacking".to_string()],
                    });
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for Clickjacking Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "Clickjacking Detection".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::Medium } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 8: Mixed Content Detection
    // ========================================================================
    async fn scan_mixed_content(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        if !self.config.url.starts_with("https://") {
            findings.push(VulnerabilityFinding {
                title: "Site Not Using HTTPS".to_string(),
                severity: Severity::High,
                status: ScanStatus::Warning,
                description: "The site does not use HTTPS, making all content susceptible to interception and modification.".to_string(),
                details: vec![format!("URL: {}", self.config.url)],
                remediation: "Migrate the entire site to HTTPS. Use HSTS to enforce secure connections.".to_string(),
                cwe_id: Some("CWE-319".to_string()),
                references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_SSL_TLS_Ciphers".to_string()],
            });
        } else {
            match self.fetch_page(&self.config.url).await {
                Ok((html, _)) => {
                    let document = Html::parse_document(&html);

                    // Check for HTTP resources on HTTPS page
                    let mut http_resources = Vec::new();

                    // Check script src
                    let script_selector = Selector::parse("script[src^='http://']").ok();
                    if let Some(sel) = script_selector {
                        for elem in document.select(&sel) {
                            if let Some(src) = elem.value().attr("src") {
                                http_resources.push(("script", src.to_string()));
                            }
                        }
                    }

                    // Check link href (CSS)
                    let link_selector = Selector::parse("link[href^='http://']").ok();
                    if let Some(sel) = link_selector {
                        for elem in document.select(&sel) {
                            if let Some(href) = elem.value().attr("href") {
                                http_resources.push(("stylesheet", href.to_string()));
                            }
                        }
                    }

                    // Check img src
                    let img_selector = Selector::parse("img[src^='http://']").ok();
                    if let Some(sel) = img_selector {
                        for elem in document.select(&sel) {
                            if let Some(src) = elem.value().attr("src") {
                                http_resources.push(("image", src.to_string()));
                            }
                        }
                    }

                    // Check iframe src
                    let iframe_selector = Selector::parse("iframe[src^='http://']").ok();
                    if let Some(sel) = iframe_selector {
                        for elem in document.select(&sel) {
                            if let Some(src) = elem.value().attr("src") {
                                http_resources.push(("iframe", src.to_string()));
                            }
                        }
                    }

                    if !http_resources.is_empty() {
                        findings.push(VulnerabilityFinding {
                            title: "Mixed Content Detected".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Vulnerable,
                            description: format!("Found {} HTTP resource(s) loaded on an HTTPS page, which can be intercepted or modified by attackers.", http_resources.len()),
                            details: http_resources.iter().map(|(t, u)| format!("[{}] {}", t, u)).collect(),
                            remediation: "Change all resource URLs to use HTTPS. Update relative URLs to be protocol-relative or absolute HTTPS.".to_string(),
                            cwe_id: Some("CWE-319".to_string()),
                            references: vec!["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content".to_string()],
                        });
                    } else {
                        findings.push(VulnerabilityFinding {
                            title: "No Mixed Content Detected".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "All resources are loaded over HTTPS.".to_string(),
                            details: vec![],
                            remediation: "No action needed.".to_string(),
                            cwe_id: Some("CWE-319".to_string()),
                            references: vec![],
                        });
                    }
                }
                Err(e) => {
                    findings.push(VulnerabilityFinding {
                        title: "Failed to Fetch Page for Mixed Content Analysis".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::Error,
                        description: format!("Could not retrieve the page: {}", e),
                        details: vec![],
                        remediation: "Ensure the target URL is accessible.".to_string(),
                        cwe_id: None,
                        references: vec![],
                    });
                }
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "Mixed Content Detection".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::Medium } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 9: Information Disclosure
    // ========================================================================
    async fn scan_information_disclosure(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        match self.fetch_page(&self.config.url).await {
            Ok((html, _response)) => {
                let html_lower = html.to_lowercase();

                // Check for email addresses in HTML
                let document = Html::parse_document(&html);

                // Check for common information disclosure patterns
                let disclosure_patterns = vec![
                    ("<!--", "HTML comment containing potential sensitive info"),
                    ("debug", "Debug information in page"),
                    ("stack trace", "Stack trace exposed"),
                    ("exception", "Exception details exposed"),
                    ("internal server error", "Server error message"),
                    ("phpinfo()", "PHP info page detected"),
                    ("wp-config", "WordPress configuration reference"),
                    ("database", "Database reference in page"),
                    ("password", "Password reference in page source"),
                    ("api_key", "API key reference in page source"),
                    ("secret", "Secret reference in page source"),
                ];

                let mut disclosed_items = Vec::new();
                for (pattern, description) in &disclosure_patterns {
                    if html_lower.contains(pattern) {
                        disclosed_items.push(format!("{}: '{}'", description, pattern));
                    }
                }

                if !disclosed_items.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "Potential Information Disclosure".to_string(),
                        severity: Severity::Medium,
                        status: ScanStatus::Warning,
                        description: "The page may contain sensitive information that could aid attackers.".to_string(),
                        details: disclosed_items,
                        remediation: "Remove sensitive information from HTML source code, comments, and error messages. Implement proper error handling that doesn't expose internals.".to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/".to_string()],
                    });
                }

                // Check for source code exposure
                if html_lower.contains(".php") && html_lower.contains("fatal error") {
                    findings.push(VulnerabilityFinding {
                        title: "PHP Error Exposure".to_string(),
                        severity: Severity::High,
                        status: ScanStatus::Vulnerable,
                        description: "PHP error messages are visible, potentially exposing server configuration and file paths.".to_string(),
                        details: vec!["PHP fatal error detected in page content".to_string()],
                        remediation: "Disable display_errors in php.ini. Use custom error pages. Log errors server-side only.".to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        references: vec![],
                    });
                }

                // Check for .env file exposure
                if html_lower.contains(".env") || html_lower.contains("db_password") || html_lower.contains("database_url") {
                    findings.push(VulnerabilityFinding {
                        title: "Environment Variable Exposure".to_string(),
                        severity: Severity::Critical,
                        status: ScanStatus::Vulnerable,
                        description: "The page may contain references to environment variables or configuration files with secrets.".to_string(),
                        details: vec!["Sensitive configuration references detected in page content".to_string()],
                        remediation: "Never expose environment variables in client-side code. Use proper secret management.".to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        references: vec![],
                    });
                }

                // Check for generator meta tag
                let meta_selector = Selector::parse("meta[name='generator']").ok();
                if let Some(sel) = meta_selector {
                    let metas: Vec<_> = document.select(&sel).collect();
                    for meta in &metas {
                        if let Some(content) = meta.value().attr("content") {
                            findings.push(VulnerabilityFinding {
                                title: "CMS/Generator Information Exposed".to_string(),
                                severity: Severity::Low,
                                status: ScanStatus::Warning,
                                description: "The page reveals the software/framework being used via a generator meta tag.".to_string(),
                                details: vec![format!("Generator: {}", content)],
                                remediation: "Remove the generator meta tag to reduce information leakage.".to_string(),
                                cwe_id: Some("CWE-200".to_string()),
                                references: vec![],
                            });
                        }
                    }
                }

                if findings.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "No Obvious Information Disclosure Detected".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::NotVulnerable,
                        description: "No obvious sensitive information was found in the page source.".to_string(),
                        details: vec![],
                        remediation: "Continue regular security audits.".to_string(),
                        cwe_id: None,
                        references: vec![],
                    });
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for Information Disclosure Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "Information Disclosure".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 10: SSL/TLS Configuration
    // ========================================================================
    async fn scan_ssl_tls_config(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        if !self.config.url.starts_with("https://") {
            findings.push(VulnerabilityFinding {
                title: "HTTPS Not Used".to_string(),
                severity: Severity::Critical,
                status: ScanStatus::Vulnerable,
                description: "The site does not use HTTPS. All traffic is sent in plaintext and can be intercepted.".to_string(),
                details: vec![format!("URL: {}", self.config.url)],
                remediation: "Implement HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS. Enable HSTS.".to_string(),
                cwe_id: Some("CWE-319".to_string()),
                references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_SSL_TLS_Ciphers".to_string()],
            });
        } else {
            match self.fetch_page(&self.config.url).await {
                Ok((_, headers)) => {
                    let url = self.config.url.clone();

                    // Check certificate validity with a strict (non-lenient) client
                    // so an invalid/expired/self-signed cert is actually detected.
                    if self.verify_tls(&url).await {
                        findings.push(VulnerabilityFinding {
                            title: "SSL/TLS Certificate Valid".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "The SSL/TLS certificate is valid and the connection is encrypted.".to_string(),
                            details: vec![
                                format!("URL: {}", url),
                                "Certificate chain verified".to_string(),
                            ],
                            remediation: "No action needed. Ensure certificates are renewed before expiration.".to_string(),
                            cwe_id: Some("CWE-319".to_string()),
                            references: vec![],
                        });
                    } else {
                        findings.push(VulnerabilityFinding {
                            title: "SSL/TLS Certificate Untrusted".to_string(),
                            severity: Severity::Critical,
                            status: ScanStatus::Vulnerable,
                            description: "The TLS handshake failed: the certificate is invalid, expired, self-signed, or the chain is untrusted.".to_string(),
                            details: vec![format!("URL: {}", url)],
                            remediation: "Install a valid certificate from a trusted CA and ensure the full chain is served.".to_string(),
                            cwe_id: Some("CWE-295".to_string()),
                            references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_SSL_TLS_Ciphers".to_string()],
                        });
                    }

                    // Check TLS version from headers
                    if headers.contains_key("strict-transport-security") {
                        findings.push(VulnerabilityFinding {
                            title: "HSTS Enabled".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::NotVulnerable,
                            description: "HTTP Strict Transport Security is enabled, enforcing HTTPS connections.".to_string(),
                            details: vec![],
                            remediation: "No action needed.".to_string(),
                            cwe_id: Some("CWE-319".to_string()),
                            references: vec![],
                        });
                    } else {
                        findings.push(VulnerabilityFinding {
                            title: "HSTS Not Enabled".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Warning,
                            description: "HSTS is not enabled, users could be downgraded to HTTP via MITM attacks.".to_string(),
                            details: vec!["Strict-Transport-Security header not found".to_string()],
                            remediation: "Enable HSTS with max-age=31536000; includeSubDomains".to_string(),
                            cwe_id: Some("CWE-319".to_string()),
                            references: vec![],
                        });
                    }
                }
                Err(e) => {
                    findings.push(VulnerabilityFinding {
                        title: "SSL/TLS Connection Failed".to_string(),
                        severity: Severity::Critical,
                        status: ScanStatus::Vulnerable,
                        description: format!("Failed to establish SSL/TLS connection: {}", e),
                        details: vec![],
                        remediation: "Check certificate validity and TLS configuration. Ensure the certificate is signed by a trusted CA.".to_string(),
                        cwe_id: Some("CWE-295".to_string()),
                        references: vec![],
                    });
                }
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "SSL/TLS Configuration".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::Critical } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 11: Cookie Security
    // ========================================================================
    async fn scan_cookie_security(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        match self.fetch_page(&self.config.url).await {
            Ok((_, headers)) => {
                let cookies: Vec<String> = headers
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
                    .collect();

                if cookies.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "No Cookies Set".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::NotVulnerable,
                        description: "No cookies were set by the server on this page.".to_string(),
                        details: vec![],
                        remediation: "No action needed.".to_string(),
                        cwe_id: Some("CWE-614".to_string()),
                        references: vec![],
                    });
                }

                for cookie in &cookies {
                    let cookie_lower = cookie.to_lowercase();

                    // Check for Secure flag
                    let has_secure = cookie_lower.contains("secure");
                    if !has_secure && self.config.url.starts_with("https://") {
                        findings.push(VulnerabilityFinding {
                            title: "Cookie Missing Secure Flag".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Vulnerable,
                            description: "A cookie is set without the Secure flag on an HTTPS site.".to_string(),
                            details: vec![format!("Cookie: {}", cookie.chars().take(200).collect::<String>())],
                            remediation: "Add the 'Secure' flag to all cookies set over HTTPS.".to_string(),
                            cwe_id: Some("CWE-614".to_string()),
                            references: vec!["https://owasp.org/www-community/controls/SecureCookieAttribute".to_string()],
                        });
                    }

                    // Check for HttpOnly flag
                    let has_httponly = cookie_lower.contains("httponly");
                    if !has_httponly {
                        findings.push(VulnerabilityFinding {
                            title: "Cookie Missing HttpOnly Flag".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Vulnerable,
                            description: "A cookie is set without the HttpOnly flag, making it accessible to JavaScript.".to_string(),
                            details: vec![format!("Cookie: {}", cookie.chars().take(200).collect::<String>())],
                            remediation: "Add the 'HttpOnly' flag to cookies containing sensitive data to prevent XSS attacks from stealing them.".to_string(),
                            cwe_id: Some("CWE-1004".to_string()),
                            references: vec!["https://owasp.org/www-community/controls/HttpOnly".to_string()],
                        });
                    }

                    // Check for SameSite attribute
                    let has_samesite = cookie_lower.contains("samesite");
                    if !has_samesite {
                        findings.push(VulnerabilityFinding {
                            title: "Cookie Missing SameSite Attribute".to_string(),
                            severity: Severity::Low,
                            status: ScanStatus::Warning,
                            description: "A cookie is set without the SameSite attribute, potentially allowing CSRF attacks.".to_string(),
                            details: vec![format!("Cookie: {}", cookie.chars().take(200).collect::<String>())],
                            remediation: "Add 'SameSite=Strict' or 'SameSite=Lax' to cookies.".to_string(),
                            cwe_id: Some("CWE-352".to_string()),
                            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite".to_string()],
                        });
                    }

                    // Check for sensitive cookie names
                    let sensitive_names = vec![
                        "session", "token", "auth", "jwt", "access_token",
                        "refresh_token", "api_key", "secret", "password",
                    ];

                    let cookie_name = cookie.split('=').next().unwrap_or("").trim().to_lowercase();
                    if sensitive_names.iter().any(|n| cookie_name.contains(n)) {
                        if !has_secure || !has_httponly {
                            findings.push(VulnerabilityFinding {
                                title: format!("Sensitive Cookie '{}' Without Full Protection", cookie_name),
                                severity: Severity::High,
                                status: ScanStatus::Vulnerable,
                                description: format!("Cookie '{}' contains sensitive data but is missing security flags.", cookie_name),
                                details: vec![
                                    format!("Has Secure: {}", has_secure),
                                    format!("Has HttpOnly: {}", has_httponly),
                                    format!("Has SameSite: {}", has_samesite),
                                ],
                                remediation: "Ensure sensitive cookies have Secure, HttpOnly, and SameSite=Strict flags.".to_string(),
                                cwe_id: Some("CWE-614".to_string()),
                                references: vec![],
                            });
                        }
                    }
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for Cookie Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "Cookie Security Analysis".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 12: Server Information Leakage
    // ========================================================================
    async fn scan_server_info_leakage(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        match self.fetch_page(&self.config.url).await {
            Ok((_, headers)) => {
                // headers is already a HeaderMap

                // Check Server header
                if let Some(server) = headers.get("server") {
                    let server_val = server.to_str().unwrap_or("");
                    findings.push(VulnerabilityFinding {
                        title: "Server Header Exposes Version Information".to_string(),
                        severity: Severity::Low,
                        status: ScanStatus::Warning,
                        description: "The Server header reveals the web server software and version, which can help attackers identify known vulnerabilities.".to_string(),
                        details: vec![format!("Server: {}", server_val)],
                        remediation: "Remove or obfuscate the Server header. Configure the web server to suppress version information.".to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Enumerate_Infrastructure_and_Application_Admin_Interfaces".to_string()],
                    });
                }

                // Check X-Powered-By header
                if let Some(powered_by) = headers.get("x-powered-by") {
                    let val = powered_by.to_str().unwrap_or("");
                    findings.push(VulnerabilityFinding {
                        title: "X-Powered-By Header Exposes Technology".to_string(),
                        severity: Severity::Medium,
                        status: ScanStatus::Vulnerable,
                        description: "The X-Powered-By header reveals the technology stack, aiding attackers in targeted attacks.".to_string(),
                        details: vec![format!("X-Powered-By: {}", val)],
                        remediation: "Remove the X-Powered-By header from all responses.".to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Enumerate_Infrastructure_and_Application_Admin_Interfaces".to_string()],
                    });
                }

                // Check for common technology-specific headers
                let tech_headers = vec![
                    "x-aspnet-version",
                    "x-aspnetmvc-version",
                    "x-generator",
                    "x-drupal-cache",
                    "x-varnish",
                    "x-powered-by-plesk",
                    "x-powered-by-cachenginx",
                    "x-debug-mode",
                    "x-request-id",
                ];

                for header_name in &tech_headers {
                    if let Some(val) = headers.get(*header_name) {
                        let val_str = val.to_str().unwrap_or("");
                        if !val_str.is_empty() {
                            findings.push(VulnerabilityFinding {
                                title: format!("Technology Header '{}' Detected", header_name),
                                severity: Severity::Low,
                                status: ScanStatus::Warning,
                                description: format!("The '{}' header reveals technology information.", header_name),
                                details: vec![format!("{}: {}", header_name, val_str)],
                                remediation: format!("Remove the '{}' header in production.", header_name),
                                cwe_id: Some("CWE-200".to_string()),
                                references: vec![],
                            });
                        }
                    }
                }

                if findings.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "No Server Information Leakage Detected".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::NotVulnerable,
                        description: "No sensitive server information headers were found.".to_string(),
                        details: vec![],
                        remediation: "No action needed.".to_string(),
                        cwe_id: None,
                        references: vec![],
                    });
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for Server Info Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "Server Information Leakage".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::Medium } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 13: Form Security
    // ========================================================================
    async fn scan_form_security(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        match self.fetch_page(&self.config.url).await {
            Ok((html, _)) => {
                let document = Html::parse_document(&html);
                let form_selector = Selector::parse("form").ok();
                let input_selector = Selector::parse("input").ok();

                if let Some(sel) = form_selector {
                    let forms: Vec<_> = document.select(&sel).collect();

                    for (i, form) in forms.iter().enumerate() {
                        let method = form.value().attr("method").unwrap_or("GET").to_uppercase();
                        let action = form.value().attr("action").unwrap_or("N/A");

                        // Check for forms without action
                        if action == "N/A" || action.is_empty() {
                            findings.push(VulnerabilityFinding {
                                title: format!("Form #{} Without Action URL", i + 1),
                                severity: Severity::Low,
                                status: ScanStatus::Warning,
                                description: "A form lacks an action attribute, which may cause unexpected behavior.".to_string(),
                                details: vec![format!("Form method: {}", method)],
                                remediation: "Specify an explicit action URL for all forms.".to_string(),
                                cwe_id: Some("CWE-20".to_string()),
                                references: vec![],
                            });
                        }

                        // Check for autocomplete on sensitive fields
                        if let Some(isel) = &input_selector {
                            let inputs: Vec<_> = form.select(isel).collect();
                            for input in &inputs {
                                let input_type = input.value().attr("type").unwrap_or("text").to_lowercase();
                                let name = input.value().attr("name").unwrap_or("").to_lowercase();
                                let autocomplete = input.value().attr("autocomplete").unwrap_or("");

                                if (input_type == "password" || name.contains("password") || name.contains("credit")
                                    || name.contains("ssn") || name.contains("secret"))
                                    && autocomplete != "off"
                                {
                                    findings.push(VulnerabilityFinding {
                                        title: "Sensitive Field Without autocomplete=off".to_string(),
                                        severity: Severity::Low,
                                        status: ScanStatus::Warning,
                                        description: format!("Input field '{}' may store sensitive data in browser autocomplete.", name),
                                        details: vec![
                                            format!("Field name: {}", name),
                                            format!("Field type: {}", input_type),
                                            format!("Autocomplete: {}", if autocomplete.is_empty() { "not set" } else { autocomplete }),
                                        ],
                                        remediation: "Set autocomplete='off' on sensitive input fields like passwords and credit card numbers.".to_string(),
                                        cwe_id: Some("CWE-525".to_string()),
                                        references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage".to_string()],
                                    });
                                }
                            }
                        }

                        // Check for hidden fields with sensitive data
                        let hidden_selector = Selector::parse("input[type='hidden']").ok();
                        if let Some(hsel) = hidden_selector {
                            let hidden_inputs: Vec<_> = form.select(&hsel).collect();
                            for input in &hidden_inputs {
                                let name = input.value().attr("name").unwrap_or("").to_lowercase();
                                let value = input.value().attr("value").unwrap_or("");

                                if name.contains("token") || name.contains("secret") || name.contains("key")
                                    || name.contains("password") || name.contains("auth")
                                {
                                    findings.push(VulnerabilityFinding {
                                        title: "Sensitive Data in Hidden Form Field".to_string(),
                                        severity: Severity::Medium,
                                        status: ScanStatus::Warning,
                                        description: format!("Hidden field '{}' may contain sensitive data that can be modified by users.", name),
                                        details: vec![
                                            format!("Field name: {}", name),
                                            format!("Value length: {} chars", value.len()),
                                        ],
                                        remediation: "Never store sensitive data in hidden form fields. Use server-side sessions instead.".to_string(),
                                        cwe_id: Some("CWE-615".to_string()),
                                        references: vec![],
                                    });
                                }
                            }
                        }

                        // Check for GET forms with sensitive fields
                        if method == "GET" {
                            let sensitive_in_get = if let Some(isel) = &input_selector {
                                form.select(isel).any(|input| {
                                    let input_type = input.value().attr("type").unwrap_or("text").to_lowercase();
                                    let name = input.value().attr("name").unwrap_or("").to_lowercase();
                                    input_type == "password" || name.contains("password") || name.contains("secret")
                                })
                            } else {
                                false
                            };

                            if sensitive_in_get {
                                findings.push(VulnerabilityFinding {
                                    title: "Password Field in GET Form".to_string(),
                                    severity: Severity::High,
                                    status: ScanStatus::Vulnerable,
                                    description: "A password field is in a GET form, meaning the password will appear in the URL and browser history.".to_string(),
                                    details: vec![format!("Form action: {}", action)],
                                    remediation: "Change the form method to POST for forms containing sensitive fields.".to_string(),
                                    cwe_id: Some("CWE-598".to_string()),
                                    references: vec!["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url".to_string()],
                                });
                            }
                        }
                    }
                }

                if findings.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "No Form Security Issues Detected".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::NotVulnerable,
                        description: "No obvious form security issues were found.".to_string(),
                        details: vec![],
                        remediation: "No action needed.".to_string(),
                        cwe_id: None,
                        references: vec![],
                    });
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for Form Security Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "Form Security Analysis".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 14: File Inclusion Detection
    // ========================================================================
    async fn scan_file_inclusion(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };

        let lfi_payloads = [
            "../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
        ];
        let rfi_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://example.com/shell.txt",
        ];
        let sigs = [
            "root:x:0:0:",
            "/bin/bash",
            "[boot loader]",
            "ami-id",
            "instance-id",
        ];

        let mut leaked = 0u32;
        let mut samples: Vec<String> = Vec::new();
        for url in &targets {
            if let Ok(parsed) = Url::parse(url) {
                let params = Self::url_params(&parsed);
                if !params.is_empty() {
                    for (param, _) in &params {
                        for p in lfi_payloads.iter().chain(rfi_payloads.iter()) {
                            if let Some(body) = self.probe_param(&parsed, param, p).await {
                                if sigs.iter().any(|s| body.contains(*s)) {
                                    leaked += 1;
                                    if samples.len() < 5 {
                                        samples.push(format!(
                                            "File inclusion via '{}' on {}",
                                            param, url
                                        ));
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if leaked > 0 {
            findings.push(VulnerabilityFinding {
                title: "File Inclusion (LFI/RFI) Confirmed".to_string(),
                severity: Severity::Critical,
                status: ScanStatus::Vulnerable,
                description: format!(
                    "{} probe(s) returned included file contents, confirming local/remote file inclusion.",
                    leaked
                ),
                details: samples,
                remediation:
                    "Never pass user input to include/require/file_get_contents. Use an allowlist of files.".to_string(),
                cwe_id: Some("CWE-98".to_string()),
                references:
                    vec!["https://owasp.org/www-community/vulnerabilities/Local_File_Inclusion".to_string()],
            });
        }

        match self.fetch_page(&self.config.url).await {
            Ok((html, _)) => {
                let document = Html::parse_document(&html);

                // Check for file inclusion patterns in URLs/links
                let lfi_patterns = vec![
                    "../", "..%2f", "..\\", "..%5c",
                    "/etc/passwd", "/etc/shadow", "/proc/self",
                    "C:\\Windows", "C%3A%5CWindows",
                    "php://filter", "php://input", "expect://",
                    "data://", "zip://", "phar://",
                ];

                let mut lfi_found = Vec::new();

                // Check all links and form actions
                let a_selector = Selector::parse("a[href]").ok();
                if let Some(sel) = a_selector {
                    for elem in document.select(&sel) {
                        if let Some(href) = elem.value().attr("href") {
                            let href_lower = href.to_lowercase();
                            for pattern in &lfi_patterns {
                                if href_lower.contains(&pattern.to_lowercase()) {
                                    lfi_found.push(format!("Link href: {} (pattern: {})", href, pattern));
                                }
                            }
                        }
                    }
                }

                // Check for file inclusion in page source
                let html_lower = html.to_lowercase();
                for pattern in &lfi_patterns {
                    if html_lower.contains(&pattern.to_lowercase()) {
                        lfi_found.push(format!("Page source contains: {}", pattern));
                    }
                }

                if !lfi_found.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "Potential File Inclusion Detected".to_string(),
                        severity: Severity::Critical,
                        status: ScanStatus::Vulnerable,
                        description: "Potential Local File Inclusion (LFI) or Remote File Inclusion (RFI) patterns detected.".to_string(),
                        details: lfi_found,
                        remediation: "Validate and sanitize all file path inputs. Use a whitelist of allowed files. Avoid user-controlled file paths entirely.".to_string(),
                        cwe_id: Some("CWE-98".to_string()),
                        references: vec!["https://owasp.org/www-community/vulnerabilities/Local_File_Inclusion".to_string()],
                    });
                }

                // Check for include/require in visible content (possible code disclosure)
                let code_patterns = vec![
                    "include(", "require(", "include_once(", "require_once(",
                    "import(", "from(", "loadfile(",
                ];

                for pattern in &code_patterns {
                    if html_lower.contains(pattern) {
                        findings.push(VulnerabilityFinding {
                            title: "Potential Code Inclusion Pattern".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Warning,
                            description: format!("Found '{}' pattern in page which could indicate code inclusion functionality.", pattern),
                            details: vec![format!("Pattern: {}", pattern)],
                            remediation: "Ensure file inclusion is not controlled by user input.".to_string(),
                            cwe_id: Some("CWE-98".to_string()),
                            references: vec![],
                        });
                    }
                }

                if findings.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "No File Inclusion Detected".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::NotVulnerable,
                        description: "No obvious file inclusion vulnerabilities were found.".to_string(),
                        details: vec![],
                        remediation: "No action needed.".to_string(),
                        cwe_id: None,
                        references: vec![],
                    });
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for File Inclusion Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "File Inclusion Detection".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::Critical } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 15: Outdated Software Detection
    // ========================================================================
    async fn scan_outdated_software(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        match self.fetch_page(&self.config.url).await {
            Ok((html, headers)) => {
                let html_lower = html.to_lowercase();

                // Check for outdated WordPress
                if html_lower.contains("wp-content") || html_lower.contains("wp-includes") {
                let version_patterns = vec![
                    "wp-content/themes/",
                    "wp-includes/js/jquery/jquery.min.js?ver=",
                    "content=\"WordPress ",
                ];

                let mut wp_version = None;
                for pattern in &version_patterns {
                    if let Some(start_idx) = html.find(pattern) {
                        let chunk = &html[start_idx..(start_idx + 200).min(html.len())];
                        if let Some(ver_start) = chunk.find("ver=") {
                            let ver_end = chunk[ver_start + 4..].find('&').unwrap_or(20);
                            wp_version = Some(chunk[ver_start + 4..ver_start + 4 + ver_end].to_string());
                        } else if let Some(ver_start) = chunk.find("WordPress ") {
                            let ver_chunk = &chunk[ver_start + 10..];
                            let ver_end = ver_chunk.find('"').unwrap_or(10);
                            if ver_end > 0 {
                                wp_version = Some(ver_chunk[..ver_end].to_string());
                            }
                        }
                    }
                }

                    findings.push(VulnerabilityFinding {
                        title: "WordPress CMS Detected".to_string(),
                        severity: if wp_version.is_some() { Severity::Medium } else { Severity::Low },
                        status: ScanStatus::Warning,
                        description: "WordPress installation detected. Ensure it's kept up-to-date with security patches.".to_string(),
                        details: vec![
                            wp_version.map(|v| format!("Version: {}", v)).unwrap_or_else(|| "Version: unknown".to_string()),
                            "WordPress is the most targeted CMS for attacks".to_string(),
                        ],
                        remediation: "Keep WordPress core, themes, and plugins updated. Remove unused plugins and themes. Implement a security plugin.".to_string(),
                        cwe_id: Some("CWE-1104".to_string()),
                        references: vec!["https://codex.wordpress.org/Hardening_WordPress".to_string()],
                    });
                }

                // Check for outdated jQuery
                if let Some(ver_start) = html.find("jquery") {
                    let chunk = &html[ver_start..(ver_start + 200).min(html.len())];
                    if let Some(v) = chunk.find("ver=") {
                        let ver_end = chunk[v + 4..].find('&').unwrap_or(20);
                        let version = &chunk[v + 4..v + 4 + ver_end];
                        if version.starts_with("1.") || version.starts_with("2.") {
                            findings.push(VulnerabilityFinding {
                                title: "Outdated jQuery Version".to_string(),
                                severity: Severity::Medium,
                                status: ScanStatus::Vulnerable,
                                description: "The site uses an outdated jQuery version with known XSS vulnerabilities.".to_string(),
                                details: vec![format!("jQuery version: {}", version), "jQuery < 3.5.0 has known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023)".to_string()],
                                remediation: "Update jQuery to the latest stable version (3.5.0+).".to_string(),
                                cwe_id: Some("CWE-1104".to_string()),
                                references: vec!["https://blog.jquery.com/2020/04/10/jquery-3.5.0-released/".to_string()],
                            });
                        }
                    }
                }

                // Check for outdated Bootstrap
                if html_lower.contains("bootstrap") {
                    if let Some(bs_start) = html_lower.find("bootstrap") {
                        let chunk = &html_lower[bs_start..(bs_start + 200).min(html_lower.len())];
                        if chunk.contains("3.") || chunk.contains("2.") {
                            findings.push(VulnerabilityFinding {
                                title: "Outdated Bootstrap Version".to_string(),
                                severity: Severity::Low,
                                status: ScanStatus::Warning,
                                description: "The site uses an outdated Bootstrap version.".to_string(),
                                details: vec![format!("Found in: {}", &html_lower[bs_start..(bs_start + 100).min(html_lower.len())])],
                                remediation: "Update Bootstrap to version 5.x for the latest security fixes.".to_string(),
                                cwe_id: Some("CWE-1104".to_string()),
                                references: vec![],
                            });
                        }
                    }
                }

                // Check for outdated Angular
                if html_lower.contains("angular") {
                    if let Some(ng_start) = html_lower.find("angular") {
                        let chunk = &html_lower[ng_start..(ng_start + 200).min(html_lower.len())];
                        if chunk.contains("1.") {
                            findings.push(VulnerabilityFinding {
                                title: "Outdated AngularJS (1.x)".to_string(),
                                severity: Severity::High,
                                status: ScanStatus::Vulnerable,
                                description: "The site uses AngularJS 1.x which has reached end-of-life and contains known vulnerabilities.".to_string(),
                                details: vec![format!("Found: {}", &html_lower[ng_start..(ng_start + 100).min(html_lower.len())])],
                                remediation: "Migrate from AngularJS to Angular 2+ or an alternative framework. AngularJS 1.x is no longer maintained.".to_string(),
                                cwe_id: Some("CWE-1104".to_string()),
                                references: vec!["https://endoflife.date/angular".to_string()],
                            });
                        }
                    }
                }

                // Check for outdated React
                if html_lower.contains("react") {
                    if let Some(react_start) = html_lower.find("react") {
                        let chunk = &html_lower[react_start..(react_start + 200).min(html_lower.len())];
                        if chunk.contains("15.") || chunk.contains("14.") || chunk.contains("16.") {
                            findings.push(VulnerabilityFinding {
                                title: "Potentially Outdated React Version".to_string(),
                                severity: Severity::Low,
                                status: ScanStatus::Warning,
                                description: "The site may use an older React version.".to_string(),
                                details: vec![format!("Found: {}", &html_lower[react_start..(react_start + 100).min(html_lower.len())])],
                                remediation: "Update React to the latest stable version.".to_string(),
                                cwe_id: Some("CWE-1104".to_string()),
                                references: vec![],
                            });
                        }
                    }
                }

                // Check for outdated PHP
                if let Some(x_powered) = headers.get("x-powered-by") {
                    let val = x_powered.to_str().unwrap_or("").to_lowercase();
                    if val.contains("php/") {
                        let version = val.split("php/").nth(1).unwrap_or("unknown");
                        let major = version.split('.').next().unwrap_or("0");
                        let minor = version.split('.').nth(1).unwrap_or("0");

                        if major == "7" && minor.parse::<u32>().unwrap_or(0) < 4 {
                            findings.push(VulnerabilityFinding {
                                title: "Outdated PHP Version".to_string(),
                                severity: Severity::High,
                                status: ScanStatus::Vulnerable,
                                description: "The server runs an outdated PHP version with known security vulnerabilities.".to_string(),
                                details: vec![format!("PHP Version: {}", version), "PHP < 7.4 has reached end-of-life".to_string()],
                                remediation: "Update PHP to version 8.1+ for the latest security patches and features.".to_string(),
                                cwe_id: Some("CWE-1104".to_string()),
                                references: vec!["https://www.php.net/supported-versions.php".to_string()],
                            });
                        } else if major == "5" {
                            findings.push(VulnerabilityFinding {
                                title: "Critical: PHP 5.x (End of Life)".to_string(),
                                severity: Severity::Critical,
                                status: ScanStatus::Vulnerable,
                                description: "PHP 5.x has been end-of-life since 2018 and contains numerous unpatched vulnerabilities.".to_string(),
                                details: vec![format!("PHP Version: {}", version)],
                                remediation: "Immediately update PHP to version 8.1+. PHP 5.x receives no security updates.".to_string(),
                                cwe_id: Some("CWE-1104".to_string()),
                                references: vec!["https://www.php.net/supported-versions.php".to_string()],
                            });
                        }
                    }
                }

                if findings.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "No Outdated Software Detected".to_string(),
                        severity: Severity::Info,
                        status: ScanStatus::NotVulnerable,
                        description: "No obviously outdated software versions were detected.".to_string(),
                        details: vec![],
                        remediation: "Continue keeping all software up-to-date.".to_string(),
                        cwe_id: None,
                        references: vec![],
                    });
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for Software Analysis".to_string(),
                    severity: Severity::Info,
                    status: ScanStatus::Error,
                    description: format!("Could not retrieve the page: {}", e),
                    details: vec![],
                    remediation: "Ensure the target URL is accessible.".to_string(),
                    cwe_id: None,
                    references: vec![],
                });
            }
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);

        ScanResult {
            check_name: "Outdated Software Detection".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 16: CORS Misconfiguration
    // ========================================================================
    async fn scan_cors_misconfig(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };

        for url in &targets {
            let probe = self
                .client
                .get(url)
                .header("Origin", "https://evil-example.com")
                .send()
                .await;
            if let Ok(resp) = probe {
                let acao = resp
                    .headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let acac = resp
                    .headers()
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();
                let reflected = acao == "https://evil-example.com" || acao == "*";
                if reflected && acac == "true" {
                    findings.push(VulnerabilityFinding {
                        title: "CORS Misconfiguration (credentialed)".to_string(),
                        severity: Severity::High,
                        status: ScanStatus::Vulnerable,
                        description: "The server reflects arbitrary origins together with Access-Control-Allow-Credentials: true, allowing theft of authenticated cross-origin data.".to_string(),
                        details: vec![format!("URL: {}", url), format!("ACAO: {}", acao)],
                        remediation: "Never combine a wildcard or reflected ACAO with ACA-Credentials: true. Use a strict origin allowlist.".to_string(),
                        cwe_id: Some("CWE-942".to_string()),
                        references: vec!["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny".to_string()],
                    });
                } else if acao == "*" {
                    findings.push(VulnerabilityFinding {
                        title: "CORS Allows Any Origin".to_string(),
                        severity: Severity::Low,
                        status: ScanStatus::Warning,
                        description: "Access-Control-Allow-Origin is '*'. Sensitive or authenticated endpoints should restrict allowed origins.".to_string(),
                        details: vec![format!("URL: {}", url)],
                        remediation: "Restrict ACAO to trusted origins where the resource is sensitive.".to_string(),
                        cwe_id: Some("CWE-942".to_string()),
                        references: vec![],
                    });
                }
            }
        }

        if findings.is_empty() {
            findings.push(VulnerabilityFinding {
                title: "No CORS Misconfiguration Detected".to_string(),
                severity: Severity::Info,
                status: ScanStatus::NotVulnerable,
                description: "No permissive CORS policy was detected.".to_string(),
                details: vec![],
                remediation: "No action needed.".to_string(),
                cwe_id: None,
                references: vec![],
            });
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        ScanResult {
            check_name: "CORS Misconfiguration".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 17: Content-Security-Policy
    // ========================================================================
    async fn scan_csp(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };

        for url in &targets {
            if let Ok(resp) = self.client.get(url).send().await {
                match resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok()) {
                    Some(csp) => {
                        let csp_l = csp.to_lowercase();
                        if csp_l.contains("unsafe-inline")
                            || csp_l.contains("unsafe-eval")
                            || csp_l.contains("default-src *")
                        {
                            findings.push(VulnerabilityFinding {
                                title: "Weak Content-Security-Policy".to_string(),
                                severity: Severity::Medium,
                                status: ScanStatus::Warning,
                                description: "A CSP is present but permits unsafe-inline/unsafe-eval or a wildcard default-src, weakening XSS protection.".to_string(),
                                details: vec![format!("URL: {}", url), format!("CSP: {}", csp)],
                                remediation: "Remove unsafe-inline/unsafe-eval and avoid wildcard sources; use nonces/hashes.".to_string(),
                                cwe_id: Some("CWE-1021".to_string()),
                                references: vec!["https://owasp.org/www-project-secure-headers/".to_string()],
                            });
                        }
                    }
                    None => {
                        findings.push(VulnerabilityFinding {
                            title: "Content-Security-Policy Not Enabled".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Warning,
                            description: "No Content-Security-Policy header was found, leaving the site more exposed to XSS and data injection.".to_string(),
                            details: vec![format!("URL: {}", url)],
                            remediation: "Deploy a restrictive CSP (default-src 'self'; script-src with nonces).".to_string(),
                            cwe_id: Some("CWE-1021".to_string()),
                            references: vec!["https://owasp.org/www-project-secure-headers/".to_string()],
                        });
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(VulnerabilityFinding {
                title: "Strong Content-Security-Policy Detected".to_string(),
                severity: Severity::Info,
                status: ScanStatus::NotVulnerable,
                description: "A CSP is present and does not contain obvious weakeners.".to_string(),
                details: vec![],
                remediation: "No action needed.".to_string(),
                cwe_id: None,
                references: vec![],
            });
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        ScanResult {
            check_name: "Content-Security-Policy".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 18: Subresource Integrity
    // ========================================================================
    async fn scan_subresource_integrity(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };
        let script_sel = Selector::parse("script[src]").ok();
        let link_sel = Selector::parse("link[rel~=\"stylesheet\"][href]").ok();

        for url in &targets {
            if let Ok((html, _)) = self.fetch_page(url).await {
                let doc = Html::parse_document(&html);
                let mut check = |sel: &Option<Selector>, attr: &str, tag: &str| {
                    if let Some(s) = sel {
                        for elem in doc.select(s) {
                            let val = elem.value().attr(attr).unwrap_or("").to_string();
                            let is_external = val.starts_with("http://")
                                || val.starts_with("https://")
                                || (val.starts_with("//"));
                            if is_external && elem.value().attr("integrity").is_none() {
                                findings.push(VulnerabilityFinding {
                                    title: "External Resource Without SRI".to_string(),
                                    severity: Severity::Low,
                                    status: ScanStatus::Warning,
                                    description: format!("An external {} is loaded without an integrity attribute, allowing silent supply-chain tampering.", tag),
                                    details: vec![format!("{}: {}", tag, val)],
                                    remediation: "Add integrity (and crossorigin) attributes to external scripts/stylesheets.".to_string(),
                                    cwe_id: Some("CWE-353".to_string()),
                                    references: vec!["https://owasp.org/www-community/attacks/Subresource_Integrity".to_string()],
                                });
                            }
                        }
                    }
                };
                check(&script_sel, "src", "script");
                check(&link_sel, "href", "stylesheet");
            }
        }

        if findings.is_empty() {
            findings.push(VulnerabilityFinding {
                title: "All External Resources Use SRI".to_string(),
                severity: Severity::Info,
                status: ScanStatus::NotVulnerable,
                description: "No external scripts/stylesheets were found loading without Subresource Integrity.".to_string(),
                details: vec![],
                remediation: "No action needed.".to_string(),
                cwe_id: None,
                references: vec![],
            });
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        ScanResult {
            check_name: "Subresource Integrity".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 19: Exposed Sensitive Files
    // ========================================================================
    async fn scan_exposed_files(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };
        let sensitive = [
            ("/.git/HEAD", "ref:", Severity::Critical),
            ("/.env", "APP_", Severity::Critical),
            ("/config.php", "<?php", Severity::High),
            ("/phpinfo.php", "phpinfo", Severity::High),
            ("/server-status", "Apache Status", Severity::Medium),
            ("/backup.zip", "PK", Severity::High),
            ("/.htaccess", "RewriteEngine", Severity::Medium),
        ];

        for url in &targets {
            if let Ok(base) = Url::parse(url) {
                for (path, sig, sev) in sensitive.iter() {
                    if let Ok(test) = base.join(path) {
                        if let Ok(resp) = self.client.get(test.to_string()).send().await {
                            if resp.status() == reqwest::StatusCode::OK {
                                if let Ok(body) = resp.text().await {
                                    if !body.is_empty() && body.contains(*sig) {
                                        findings.push(VulnerabilityFinding {
                                            title: format!("Exposed Sensitive File: {}", path),
                                            severity: sev.clone(),
                                            status: ScanStatus::Vulnerable,
                                            description: format!("The file '{}' is publicly accessible and exposes sensitive information.", path),
                                            details: vec![format!("URL: {}", test)],
                                            remediation: "Block access to source/metadata files via the web server; remove them from the docroot.".to_string(),
                                            cwe_id: Some("CWE-538".to_string()),
                                            references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration".to_string()],
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(VulnerabilityFinding {
                title: "No Exposed Sensitive Files Detected".to_string(),
                severity: Severity::Info,
                status: ScanStatus::NotVulnerable,
                description: "No publicly accessible sensitive files were found.".to_string(),
                details: vec![],
                remediation: "No action needed.".to_string(),
                cwe_id: None,
                references: vec![],
            });
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        ScanResult {
            check_name: "Exposed Sensitive Files".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    // ========================================================================
    // CHECK 20: Directory Listing Enabled
    // ========================================================================
    async fn scan_directory_listing(&self) -> ScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();
        let targets = if self.targets.is_empty() {
            vec![self.config.url.clone()]
        } else {
            self.targets.clone()
        };
        let dirs = ["/images/", "/css/", "/js/", "/uploads/", "/assets/", "/backup/", "/files/"];

        for url in &targets {
            if let Ok(base) = Url::parse(url) {
                for d in dirs.iter() {
                    if let Ok(test) = base.join(d) {
                        if let Ok(resp) = self.client.get(test.to_string()).send().await {
                            if resp.status() == reqwest::StatusCode::OK {
                                if let Ok(body) = resp.text().await {
                                    if body.contains("Index of ") || body.contains("<title>Index of") {
                                        findings.push(VulnerabilityFinding {
                                            title: "Directory Listing Enabled".to_string(),
                                            severity: Severity::Medium,
                                            status: ScanStatus::Warning,
                                            description: format!("Directory listing is enabled at '{}', disclosing file names and structure.", test),
                                            details: vec![format!("URL: {}", test)],
                                            remediation: "Disable directory indexing (e.g., Options -Indexes in Apache, autoindex off in nginx).".to_string(),
                                            cwe_id: Some("CWE-548".to_string()),
                                            references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling".to_string()],
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(VulnerabilityFinding {
                title: "No Directory Listing Detected".to_string(),
                severity: Severity::Info,
                status: ScanStatus::NotVulnerable,
                description: "No enabled directory listings were found on probed paths.".to_string(),
                details: vec![],
                remediation: "No action needed.".to_string(),
                cwe_id: None,
                references: vec![],
            });
        }

        let has_vuln = findings.iter().any(|f| f.status == ScanStatus::Vulnerable);
        ScanResult {
            check_name: "Directory Listing".to_string(),
            status: if has_vuln { ScanStatus::Vulnerable } else { ScanStatus::NotVulnerable },
            severity: if has_vuln { Severity::High } else { Severity::Info },
            findings,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            url: "https://example.com".to_string(),
            timeout_secs: 30,
            follow_redirects: true,
            max_depth: 3,
            max_pages: 50,
            output_dir: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_config_creation() {
        let config = ScanConfig::new("https://example.com").unwrap();
        assert_eq!(config.url, "https://example.com");
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Info.to_string(), "INFO");
    }

    #[test]
    fn test_scan_status_display() {
        assert_eq!(ScanStatus::Vulnerable.to_string(), "VULNERABLE");
        assert_eq!(ScanStatus::NotVulnerable.to_string(), "NOT VULNERABLE");
    }

    #[test]
    fn test_summary_calculation() {
        let config = ScanConfig::new("https://example.com").unwrap();
        let scanner = VulnerabilityScanner::new(config).unwrap();

        let results = vec![
            ScanResult {
                check_name: "Test1".to_string(),
                status: ScanStatus::Vulnerable,
                severity: Severity::High,
                findings: vec![],
                scan_duration_ms: 0,
                timestamp: String::new(),
            },
            ScanResult {
                check_name: "Test2".to_string(),
                status: ScanStatus::NotVulnerable,
                severity: Severity::Info,
                findings: vec![],
                scan_duration_ms: 0,
                timestamp: String::new(),
            },
        ];

        let summary = scanner.calculate_summary(&results);
        assert_eq!(summary.total_checks, 2);
        assert_eq!(summary.vulnerable, 1);
        assert_eq!(summary.not_vulnerable, 1);
        assert_eq!(summary.high_count, 1);
    }
}
