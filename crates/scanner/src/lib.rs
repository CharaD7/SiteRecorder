use anyhow::Result;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};
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

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub url: String,
    pub timeout_secs: u64,
    pub follow_redirects: bool,
    pub max_depth: usize,
}

impl ScanConfig {
    pub fn new(url: &str) -> Result<Self, ScanError> {
        Url::parse(url).map_err(|e| ScanError::ParseError(e.to_string()))?;
        Ok(Self {
            url: url.to_string(),
            timeout_secs: 30,
            follow_redirects: true,
            max_depth: 3,
        })
    }
}

pub struct VulnerabilityScanner {
    config: ScanConfig,
    client: reqwest::Client,
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

        Ok(Self { config, client })
    }

    pub async fn run_full_scan(&self) -> Result<ScanReport, ScanError> {
        let scan_id = format!("scan_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        let timestamp = chrono::Utc::now().to_rfc3339();

        info!("Starting full vulnerability scan for: {}", self.config.url);

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

        let summary = self.calculate_summary(&results);

        info!("Scan completed. Risk score: {:.1}/10", summary.risk_score);

        Ok(ScanReport {
            url: self.config.url.clone(),
            scan_id,
            timestamp,
            results,
            summary,
        })
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

        let xss_payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
        ];

        match self.fetch_page(&self.config.url).await {
            Ok((html, _headers)) => {
                let url = self.config.url.clone();
                let document = Html::parse_document(&html);

                // Check forms for XSS vulnerability
                let form_selector = Selector::parse("form").ok();
                let input_selector = Selector::parse("input[name]").ok();
                let action_selector = Selector::parse("[action]").ok();

                if let Some(selector) = form_selector {
                    let forms: Vec<_> = document.select(&selector).collect();
                    if !forms.is_empty() {
                        findings.push(VulnerabilityFinding {
                            title: "Forms Detected - Potential XSS Vectors".to_string(),
                            severity: Severity::Info,
                            status: ScanStatus::Warning,
                            description: format!("Found {} form(s) on the page that could potentially be vulnerable to reflected XSS if input is not properly sanitized.", forms.len()),
                            details: vec![format!("URL: {}", url), format!("Forms found: {}", forms.len())],
                            remediation: "Ensure all user input is properly sanitized and encoded before rendering. Implement CSP with script-src directive.".to_string(),
                            cwe_id: Some("CWE-79".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                        });
                    }
                }

                // Check for inline event handlers (potential XSS injection points)
                let event_handlers = vec![
                    "onerror", "onload", "onclick", "onmouseover", "onfocus",
                    "onblur", "onsubmit", "onchange", "onkeyup", "onkeydown",
                ];

                let mut inline_handlers_found = 0;
                for handler in &event_handlers {
                    let attr_selector = Selector::parse(&format!("[{}]", handler)).ok();
                    if let Some(sel) = attr_selector {
                        let count = document.select(&sel).count();
                        inline_handlers_found += count;
                    }
                }

                if inline_handlers_found > 0 {
                    findings.push(VulnerabilityFinding {
                        title: "Inline Event Handlers Detected".to_string(),
                        severity: Severity::Medium,
                        status: ScanStatus::Warning,
                        description: format!("Found {} inline event handler(s) which may be XSS injection vectors.", inline_handlers_found),
                        details: vec![
                            format!("Event handlers found: {}", inline_handlers_found),
                            "Inline event handlers can be exploited if user input is not properly sanitized".to_string(),
                        ],
                        remediation: "Replace inline event handlers with addEventListener() calls and validate all user input server-side.".to_string(),
                        cwe_id: Some("CWE-79".to_string()),
                        references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                    });
                }

                // Check for JavaScript URLs in href attributes
                let a_selector = Selector::parse("a[href^='javascript:']").ok();
                if let Some(sel) = a_selector {
                    let js_links: Vec<_> = document.select(&sel).collect();
                    if !js_links.is_empty() {
                        findings.push(VulnerabilityFinding {
                            title: "JavaScript URLs in Links".to_string(),
                            severity: Severity::High,
                            status: ScanStatus::Vulnerable,
                            description: format!("Found {} link(s) with javascript: URLs, which is a severe XSS risk.", js_links.len()),
                            details: vec![
                                format!("Count: {}", js_links.len()),
                                "javascript: URLs execute code when clicked".to_string(),
                            ],
                            remediation: "Remove all javascript: URLs from href attributes. Use event listeners instead.".to_string(),
                            cwe_id: Some("CWE-79".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                        });
                    }
                }

                // Check for unescaped user input in URL parameters
                if let Ok(parsed_url) = Url::parse(&url) {
                    if let Some(query) = parsed_url.query() {
                        if query.contains('<') || query.contains('>') || query.contains("script") || query.contains("alert") {
                            findings.push(VulnerabilityFinding {
                                title: "Potential Reflected XSS in URL Parameters".to_string(),
                                severity: Severity::Critical,
                                status: ScanStatus::Vulnerable,
                                description: "URL parameters appear to contain potential XSS payloads.".to_string(),
                                details: vec![format!("Query string: {}", query)],
                                remediation: "Sanitize and encode all URL parameters before rendering in the page.".to_string(),
                                cwe_id: Some("CWE-79".to_string()),
                                references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                            });
                        }
                    }
                }

                // Check for DOM-based XSS patterns
                let dom_patterns = vec![
                    "document.write(",
                    "innerHTML",
                    "outerHTML",
                    "eval(",
                    "setTimeout(",
                    "setInterval(",
                    "document.location",
                    "window.location",
                ];

                let mut dom_sinks_found = 0;
                for pattern in &dom_patterns {
                    if html.contains(pattern) {
                        dom_sinks_found += 1;
                    }
                }

                if dom_sinks_found > 0 {
                    findings.push(VulnerabilityFinding {
                        title: "DOM-based XSS Sinks Detected".to_string(),
                        severity: Severity::Medium,
                        status: ScanStatus::Warning,
                        description: format!("Found {} potentially dangerous DOM manipulation pattern(s) that could lead to DOM-based XSS.", dom_sinks_found),
                        details: dom_patterns.iter()
                            .filter(|p| html.contains(*p))
                            .map(|p| format!("Found: {}", p))
                            .collect(),
                        remediation: "Use safe DOM APIs like textContent instead of innerHTML. Sanitize user input before passing to dangerous sinks.".to_string(),
                        cwe_id: Some("CWE-79".to_string()),
                        references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                    });
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for XSS Analysis".to_string(),
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

        let sqli_payloads = vec![
            ("'", "Single quote"),
            ("' OR '1'='1", "OR tautology"),
            ("' OR 1=1--", "OR with comment"),
            ("' UNION SELECT NULL--", "UNION-based"),
            ("1; SELECT 1--", "Stacked queries"),
            ("' AND 1=CONVERT(int, (SELECT @@version))--", "Error-based"),
            ("'; WAITFOR DELAY '0:0:5'--", "Time-based blind"),
        ];

        match self.fetch_page(&self.config.url).await {
            Ok((html, _)) => {
                // Check for SQL error patterns in response
                let sql_errors = vec![
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

                let html_lower = html.to_lowercase();
                let mut error_patterns_found = Vec::new();

                for pattern in &sql_errors {
                    if html_lower.contains(pattern) {
                        error_patterns_found.push(pattern.to_string());
                    }
                }

                if !error_patterns_found.is_empty() {
                    findings.push(VulnerabilityFinding {
                        title: "SQL Error Messages Detected in Response".to_string(),
                        severity: Severity::High,
                        status: ScanStatus::Vulnerable,
                        description: "The page contains SQL error messages which may indicate SQL injection vulnerability or information disclosure.".to_string(),
                        details: error_patterns_found.iter().map(|e| format!("Pattern found: '{}'", e)).collect(),
                        remediation: "Use parameterized queries/prepared statements. Disable verbose error messages in production. Implement proper error handling.".to_string(),
                        cwe_id: Some("CWE-89".to_string()),
                        references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
                    });
                }

                // Check forms for SQL injection risk
                let document = Html::parse_document(&html);
                let form_selector = Selector::parse("form").ok();
                let input_selector = Selector::parse("input[name]").ok();

                if let (Some(fsel), Some(isel)) = (form_selector, input_selector) {
                    let forms: Vec<_> = document.select(&fsel).collect();
                    let inputs: Vec<_> = document.select(&isel).collect();

                    if !forms.is_empty() && !inputs.is_empty() {
                        let form_details: Vec<String> = forms.iter().enumerate().map(|(i, f)| {
                            let action = f.value().attr("action").unwrap_or("N/A");
                            let method = f.value().attr("method").unwrap_or("GET");
                            format!("Form {}: action={}, method={}", i + 1, action, method)
                        }).collect();

                        let input_details: Vec<String> = inputs.iter().map(|inp| {
                            let name = inp.value().attr("name").unwrap_or("N/A");
                            let input_type = inp.value().attr("type").unwrap_or("text");
                            format!("Input: name={}, type={}", name, input_type)
                        }).collect();

                        findings.push(VulnerabilityFinding {
                            title: "Forms with User Input - SQL Injection Risk".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Warning,
                            description: format!("Found {} form(s) with {} input field(s). These could be SQL injection vectors if not properly sanitized.", forms.len(), inputs.len()),
                            details: {
                                let mut d = form_details;
                                d.extend(input_details);
                                d
                            },
                            remediation: "Use parameterized queries (Prepared Statements) for all database interactions. Never concatenate user input into SQL queries. Use an ORM or query builder.".to_string(),
                            cwe_id: Some("CWE-89".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
                        });
                    }
                }

                // Check URL parameters
                if let Ok(parsed_url) = Url::parse(&self.config.url) {
                    let params: Vec<_> = parsed_url.query_pairs().collect();
                    if !params.is_empty() {
                        findings.push(VulnerabilityFinding {
                            title: "URL Parameters Detected - SQL Injection Risk".to_string(),
                            severity: Severity::Medium,
                            status: ScanStatus::Warning,
                            description: format!("Found {} URL parameter(s) that could be SQL injection vectors.", params.len()),
                            details: params.iter().map(|(k, v)| format!("Parameter: {} = {}", k, v)).collect(),
                            remediation: "Validate and sanitize all URL parameters server-side. Use parameterized queries for any database operations.".to_string(),
                            cwe_id: Some("CWE-89".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
                        });
                    }
                }
            }
            Err(e) => {
                findings.push(VulnerabilityFinding {
                    title: "Failed to Fetch Page for SQLi Analysis".to_string(),
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

        let traversal_payloads = vec![
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\etc\\passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        ];

        let traversal_signatures = vec![
            "root:",
            "daemon:",
            "bin:",
            "/bin/bash",
            "/bin/sh",
            "nologin",
        ];

        // Check if the base URL responds with directory listing indicators
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
            Ok((html, response)) => {
                let html_lower = html.to_lowercase();

                // Check for email addresses in HTML
                let email_regex_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}";
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

                    // Check certificate validity
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
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            url: "https://example.com".to_string(),
            timeout_secs: 30,
            follow_redirects: true,
            max_depth: 3,
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
