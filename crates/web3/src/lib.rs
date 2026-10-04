use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Web3Error {
    #[error("Analysis error: {0}")]
    AnalysisError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
}

// Public crate convention; kept for callers even where the crate
// currently returns infallible results.
#[allow(dead_code)]
type Result<T> = std::result::Result<T, Web3Error>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractScanConfig {
    pub contract_address: Option<String>,
    pub source_code: Option<String>,
    pub chain: Blockchain,
    pub check_categories: Vec<ContractCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Blockchain {
    Ethereum,
    Polygon,
    BSC,
    Arbitrum,
    Optimism,
    Solana,
    Cosmos,
}

impl std::fmt::Display for Blockchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Blockchain::Ethereum => write!(f, "Ethereum"),
            Blockchain::Polygon => write!(f, "Polygon"),
            Blockchain::BSC => write!(f, "BNB Smart Chain"),
            Blockchain::Arbitrum => write!(f, "Arbitrum"),
            Blockchain::Optimism => write!(f, "Optimism"),
            Blockchain::Solana => write!(f, "Solana"),
            Blockchain::Cosmos => write!(f, "Cosmos"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContractCheck {
    Reentrancy,
    AccessControl,
    Arithmetic,
    FrontRunning,
    OracleManipulation,
    FlashLoan,
    Logic,
    Proxy,
    Gas,
    CodeQuality,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractScanResult {
    pub scan_id: String,
    pub contract_address: Option<String>,
    pub chain: Blockchain,
    pub timestamp: String,
    pub duration_ms: u64,
    pub findings: Vec<ContractFinding>,
    pub summary: ContractSummary,
    /// No score is reported unless a contract was actually analysed.
    pub score: Option<f64>,
    /// What was examined, and why the rest is unavailable.
    pub coverage: AnalysisCoverage,
}

/// States plainly what was analysed, so an empty result is not mistaken for a
/// clean bill of health.
///
/// This exists because the previous implementation returned the same ten
/// hardcoded findings -- including a Critical reentrancy bug -- for every
/// contract, with no code, no line numbers, and no relationship to the input.
/// An empty findings list is only honest alongside this field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisCoverage {
    pub examined: String,
    pub unavailable_reason: String,
    pub requires: Vec<String>,
    pub implemented: bool,
}

impl AnalysisCoverage {
    fn contract_analysis(requested: usize) -> Self {
        AnalysisCoverage {
            examined: "Nothing. No bytecode was fetched and no source was parsed.".to_string(),
            unavailable_reason: format!(
                "Static contract analysis is not implemented. {} checks were requested;                  none were performed.",
                requested
            ),
            requires: vec![
                "Verified source for the target, fetched from a block explorer or supplied locally".to_string(),
                "A Solidity parser to resolve inheritance, modifiers and internal call graphs".to_string(),
                "Call-graph analysis to prove reachability of state-changing sinks".to_string(),
            ],
            implemented: false,
        }
    }

    fn wallet_analysis(requested: usize) -> Self {
        AnalysisCoverage {
            examined: "Nothing. No chain RPC was queried.".to_string(),
            unavailable_reason: format!(
                "On-chain wallet analysis is not implemented. {} checks were requested;                  none were performed.",
                requested
            ),
            requires: vec![
                "An archive RPC endpoint for the target chain".to_string(),
                "Approval and exposure decoding from token contracts".to_string(),
            ],
            implemented: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSummary {
    pub total_checks: usize,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub optimization_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractFinding {
    pub id: String,
    pub title: String,
    pub severity: ContractSeverity,
    pub category: ContractCheck,
    pub description: String,
    pub details: Vec<String>,
    pub remediation: String,
    pub cwe_id: Option<String>,
    pub swc_id: Option<String>,
    pub line_number: Option<usize>,
    pub code_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContractSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Optimization,
}

impl std::fmt::Display for ContractSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractSeverity::Critical => write!(f, "CRITICAL"),
            ContractSeverity::High => write!(f, "HIGH"),
            ContractSeverity::Medium => write!(f, "MEDIUM"),
            ContractSeverity::Low => write!(f, "LOW"),
            ContractSeverity::Info => write!(f, "INFO"),
            ContractSeverity::Optimization => write!(f, "OPTIMIZATION"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSecurityConfig {
    pub address: String,
    pub chain: Blockchain,
    pub check_categories: Vec<WalletCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WalletCheck {
    Approvals,
    Exposure,
    Phishing,
    Compliance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSecurityResult {
    pub scan_id: String,
    pub address: String,
    pub chain: Blockchain,
    pub timestamp: String,
    pub risk_score: Option<f64>,
    pub findings: Vec<WalletFinding>,
    pub approvals: Vec<TokenApproval>,
    pub exposure: Option<ExposureAnalysis>,
    pub coverage: AnalysisCoverage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFinding {
    pub title: String,
    pub severity: ContractSeverity,
    pub description: String,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenApproval {
    pub token: String,
    pub spender: String,
    pub amount: String,
    pub risk: ApprovalRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalRisk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureAnalysis {
    pub total_usd_value: f64,
    pub high_risk_exposure: f64,
    pub nft_count: usize,
    pub token_count: usize,
    pub defi_protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefiProtocol {
    pub name: String,
    pub category: DefiCategory,
    pub tvl: Option<f64>,
    pub risks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DefiCategory {
    DEX,
    Lending,
    Yield,
    Bridge,
    Derivatives,
    Stablecoin,
    Insurance,
    Aggregator,
    LiquidStaking,
}

pub struct Web3Auditor;

impl Web3Auditor {
    /// Contract analysis.
    ///
    /// Returns no findings and no score. It does not fetch bytecode and does
    /// not parse source, so it has nothing to report; the `coverage` field
    /// states this explicitly so an empty result cannot be read as "clean".
    ///
    /// This previously returned ten hardcoded findings for every input.
    pub fn scan_contract(config: &ContractScanConfig) -> ContractScanResult {
        let start = std::time::Instant::now();
        let coverage = AnalysisCoverage::contract_analysis(config.check_categories.len());

        ContractScanResult {
            scan_id: format!("web3scan_{}", Utc::now().timestamp_millis()),
            contract_address: config.contract_address.clone(),
            chain: config.chain.clone(),
            timestamp: Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            findings: Vec::new(),
            summary: calculate_summary(&[]),
            score: None,
            coverage,
        }
    }

    /// Wallet analysis.
    ///
    /// Returns no findings, no risk score, and no exposure figures. No RPC is
    /// queried, so reporting zeros would assert a clean wallet that was never
    /// looked at.
    pub fn analyze_wallet(config: &WalletSecurityConfig) -> WalletSecurityResult {
        let coverage = AnalysisCoverage::wallet_analysis(config.check_categories.len());

        WalletSecurityResult {
            scan_id: format!("walletscan_{}", Utc::now().timestamp_millis()),
            address: config.address.clone(),
            chain: config.chain.clone(),
            timestamp: Utc::now().to_rfc3339(),
            risk_score: None,
            findings: Vec::new(),
            approvals: Vec::new(),
            exposure: None,
            coverage,
        }
    }
}

fn calculate_summary(findings: &[ContractFinding]) -> ContractSummary {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;
        let mut optimization = 0;

        for finding in findings {
            match finding.severity {
                ContractSeverity::Critical => critical += 1,
                ContractSeverity::High => high += 1,
                ContractSeverity::Medium => medium += 1,
                ContractSeverity::Low => low += 1,
                ContractSeverity::Info => info += 1,
                ContractSeverity::Optimization => optimization += 1,
            }
        }

        ContractSummary {
            total_checks: critical + high + medium + low + info + optimization,
            findings_count: critical + high + medium + low + info,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            optimization_count: optimization,
        }
    }

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ContractScanConfig {
        ContractScanConfig {
            contract_address: Some("0x1234".to_string()),
            source_code: None,
            chain: Blockchain::Ethereum,
            check_categories: vec![
                ContractCheck::Reentrancy,
                ContractCheck::AccessControl,
                ContractCheck::Arithmetic,
            ],
        }
    }

    /// Regression: this returned ten hardcoded findings, including a Critical
    /// reentrancy bug, for every contract regardless of input.
    #[test]
    fn contract_scan_reports_no_invented_findings() {
        let result = Web3Auditor::scan_contract(&cfg());
        assert!(
            result.findings.is_empty(),
            "no analysis is performed, so there is nothing to report"
        );
        assert!(result.summary.findings_count == 0);
    }

    /// A fabricated "100/100" would read as a clean bill of health.
    #[test]
    fn contract_scan_withholds_a_score() {
        let result = Web3Auditor::scan_contract(&cfg());
        assert!(
            result.score.is_none(),
            "an unanalysed contract must not receive a security score"
        );
    }

    #[test]
    fn contract_scan_states_what_was_not_done() {
        let result = Web3Auditor::scan_contract(&cfg());
        assert!(!result.coverage.implemented);
        assert!(result.coverage.unavailable_reason.contains("not implemented"));
        assert!(result.coverage.requires.iter().any(|r| r.contains("source")));
    }

    /// The old code was input-independent; that is what made the fabrication
    /// visible, so the honest result must be too.
    #[test]
    fn contract_scan_is_independent_of_input() {
        let mut other = cfg();
        other.contract_address = Some("0xdeadbeef".to_string());
        let a = Web3Auditor::scan_contract(&cfg());
        let b = Web3Auditor::scan_contract(&other);
        assert_eq!(a.findings.len(), b.findings.len());
        assert_eq!(a.score, b.score);
        assert_eq!(a.coverage, b.coverage);
    }

    #[test]
    fn wallet_analysis_withholds_risk_and_exposure() {
        let result = Web3Auditor::analyze_wallet(&WalletSecurityConfig {
            address: "0xabc".to_string(),
            chain: Blockchain::Ethereum,
            check_categories: vec![WalletCheck::Approvals],
        });
        assert!(result.findings.is_empty());
        assert!(result.risk_score.is_none(), "zeros would imply a clean wallet");
        assert!(result.exposure.is_none());
        assert!(!result.coverage.implemented);
    }
}
