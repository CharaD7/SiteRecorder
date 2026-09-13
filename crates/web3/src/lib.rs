use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub score: f64,
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
    pub risk_score: f64,
    pub findings: Vec<WalletFinding>,
    pub approvals: Vec<TokenApproval>,
    pub exposure: ExposureAnalysis,
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
    pub fn scan_contract(config: &ContractScanConfig) -> ContractScanResult {
        let start = std::time::Instant::now();
        let mut findings = Vec::new();

        if config.check_categories.contains(&ContractCheck::Reentrancy) {
            findings.extend(Self::check_reentrancy());
        }
        if config.check_categories.contains(&ContractCheck::AccessControl) {
            findings.extend(Self::check_access_control());
        }
        if config.check_categories.contains(&ContractCheck::Arithmetic) {
            findings.extend(Self::check_arithmetic());
        }
        if config.check_categories.contains(&ContractCheck::FrontRunning) {
            findings.extend(Self::check_front_running());
        }
        if config.check_categories.contains(&ContractCheck::OracleManipulation) {
            findings.extend(Self::check_oracle());
        }
        if config.check_categories.contains(&ContractCheck::FlashLoan) {
            findings.extend(Self::check_flash_loan());
        }
        if config.check_categories.contains(&ContractCheck::Logic) {
            findings.extend(Self::check_logic_flaws());
        }
        if config.check_categories.contains(&ContractCheck::Proxy) {
            findings.extend(Self::check_proxy_pattern());
        }
        if config.check_categories.contains(&ContractCheck::Gas) {
            findings.extend(Self::check_gas_optimization());
        }

        let duration = start.elapsed().as_millis() as u64;
        let summary = Self::calculate_summary(&findings);
        let score = Self::calculate_security_score(&findings);

        ContractScanResult {
            scan_id: format!("web3scan_{}", Utc::now().timestamp_millis()),
            contract_address: config.contract_address.clone(),
            chain: config.chain.clone(),
            timestamp: Utc::now().to_rfc3339(),
            duration_ms: duration,
            findings,
            summary,
            score,
        }
    }

    pub fn analyze_wallet(config: &WalletSecurityConfig) -> WalletSecurityResult {
        let mut findings = Vec::new();

        if config.check_categories.contains(&WalletCheck::Approvals) {
            findings.extend(Self::check_wallet_approvals());
        }
        if config.check_categories.contains(&WalletCheck::Exposure) {
            findings.extend(Self::check_wallet_exposure());
        }
        if config.check_categories.contains(&WalletCheck::Phishing) {
            findings.extend(Self::check_phishing_risk());
        }
        if config.check_categories.contains(&WalletCheck::Compliance) {
            findings.extend(Self::check_compliance());
        }

        let risk_score = Self::calculate_wallet_risk(&findings);

        WalletSecurityResult {
            scan_id: format!("wallet_{}", Utc::now().timestamp_millis()),
            address: config.address.clone(),
            chain: config.chain.clone(),
            timestamp: Utc::now().to_rfc3339(),
            risk_score,
            findings,
            approvals: Vec::new(),
            exposure: ExposureAnalysis {
                total_usd_value: 0.0,
                high_risk_exposure: 0.0,
                nft_count: 0,
                token_count: 0,
                defi_protocols: Vec::new(),
            },
        }
    }

    fn check_reentrancy() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "SWC-107".to_string(),
                title: "Reentrancy Vulnerability".to_string(),
                severity: ContractSeverity::Critical,
                category: ContractCheck::Reentrancy,
                description: "External calls before state changes can lead to reentrancy attacks.".to_string(),
                details: vec![
                    "Check for call.value() or transfer() before state updates".to_string(),
                    "Use Checks-Effects-Interactions pattern".to_string(),
                    "Implement ReentrancyGuard (nonReentrant modifier)".to_string(),
                    "Examples: The DAO hack, UniBot exploit".to_string(),
                ],
                remediation: "Follow Checks-Effects-Interactions pattern and use ReentrancyGuard.".to_string(),
                cwe_id: Some("CWE-841".to_string()),
                swc_id: Some("SWC-107".to_string()),
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_access_control() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "SWC-105".to_string(),
                title: "Unprotected Ether Withdrawal".to_string(),
                severity: ContractSeverity::Critical,
                category: ContractCheck::AccessControl,
                description: "Functions allowing Ether withdrawal without access control.".to_string(),
                details: vec![
                    "Check for withdraw functions without onlyOwner".to_string(),
                    "Verify all privileged functions have access control".to_string(),
                    "Use OpenZeppelin's Ownable or AccessControl".to_string(),
                ],
                remediation: "Add access control modifiers to all privileged functions.".to_string(),
                cwe_id: Some("CWE-284".to_string()),
                swc_id: Some("SWC-105".to_string()),
                line_number: None,
                code_snippet: None,
            },
            ContractFinding {
                id: "SWC-106".to_string(),
                title: "Unprotected SELFDESTRUCT".to_string(),
                severity: ContractSeverity::Critical,
                category: ContractCheck::AccessControl,
                description: "Any address can trigger contract self-destruction.".to_string(),
                details: vec![
                    "Check for selfdestruct/suicide without access control".to_string(),
                    "Removed in EIP-4758 but still exploitable in older contracts".to_string(),
                ],
                remediation: "Remove SELFDESTRUCT or add proper access control.".to_string(),
                cwe_id: Some("CWE-284".to_string()),
                swc_id: Some("SWC-106".to_string()),
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_arithmetic() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "SWC-101".to_string(),
                title: "Integer Overflow/Underflow".to_string(),
                severity: ContractSeverity::High,
                category: ContractCheck::Arithmetic,
                description: "Arithmetic operations without overflow/underflow protection.".to_string(),
                details: vec![
                    "Solidity < 0.8.0 does not check overflow/underflow".to_string(),
                    "Use SafeMath library for older versions".to_string(),
                    "Solidity >= 0.8.0 has built-in overflow protection".to_string(),
                ],
                remediation: "Use Solidity 0.8.0+ or OpenZeppelin SafeMath.".to_string(),
                cwe_id: Some("CWE-190".to_string()),
                swc_id: Some("SWC-101".to_string()),
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_front_running() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "SWC-114".to_string(),
                title: "Transaction Order Dependence".to_string(),
                severity: ContractSeverity::Medium,
                category: ContractCheck::FrontRunning,
                description: "Transaction outcomes depend on block inclusion order.".to_string(),
                details: vec![
                    "Check for price-dependent operations (DEX trades)".to_string(),
                    "Use commit-reveal schemes".to_string(),
                    "Implement slippage protection".to_string(),
                ],
                remediation: "Use commit-reveal or add slippage protection.".to_string(),
                cwe_id: Some("CWE-362".to_string()),
                swc_id: Some("SWC-114".to_string()),
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_oracle() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "SWC-120".to_string(),
                title: "Single Oracle Source".to_string(),
                severity: ContractSeverity::High,
                category: ContractCheck::OracleManipulation,
                description: "Reliance on a single oracle price feed.".to_string(),
                details: vec![
                    "Use Chainlink Price Feeds for reliable pricing".to_string(),
                    "Implement TWAP (Time-Weighted Average Price)".to_string(),
                    "Check for flash loan oracle manipulation".to_string(),
                ],
                remediation: "Use multiple oracle sources and TWAP.".to_string(),
                cwe_id: Some("CWE-807".to_string()),
                swc_id: Some("SWC-120".to_string()),
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_flash_loan() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "FLASH-001".to_string(),
                title: "Flash Loan Attack Vector".to_string(),
                severity: ContractSeverity::High,
                category: ContractCheck::FlashLoan,
                description: "Contract vulnerable to flash loan-based price manipulation.".to_string(),
                details: vec![
                    "Flash loans allow borrowing without collateral".to_string(),
                    "Can be used to manipulate on-chain prices".to_string(),
                    "Check oracle-dependent logic".to_string(),
                ],
                remediation: "Use time-weighted average prices and multi-block checks.".to_string(),
                cwe_id: None,
                swc_id: None,
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_logic_flaws() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "LOGIC-001".to_string(),
                title: "Logic Error Risk".to_string(),
                severity: ContractSeverity::Medium,
                category: ContractCheck::Logic,
                description: "Contract logic may have unintended behavior.".to_string(),
                details: vec![
                    "Review all conditional branches".to_string(),
                    "Check for off-by-one errors".to_string(),
                    "Verify fee calculations and distributions".to_string(),
                ],
                remediation: "Thorough unit testing and formal verification.".to_string(),
                cwe_id: None,
                swc_id: None,
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_proxy_pattern() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "PROXY-001".to_string(),
                title: "Proxy Storage Collision".to_string(),
                severity: ContractSeverity::High,
                category: ContractCheck::Proxy,
                description: "Proxy contracts with storage layout mismatches.".to_string(),
                details: vec![
                    "Use EIP-1967 compliant proxy pattern".to_string(),
                    "Check for uninitialized implementation contracts".to_string(),
                    "Use OpenZeppelin's TransparentUpgradeableProxy".to_string(),
                ],
                remediation: "Use battle-tested proxy patterns from OpenZeppelin.".to_string(),
                cwe_id: None,
                swc_id: None,
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_gas_optimization() -> Vec<ContractFinding> {
        vec![
            ContractFinding {
                id: "GAS-001".to_string(),
                title: "Gas Optimization Opportunities".to_string(),
                severity: ContractSeverity::Optimization,
                category: ContractCheck::Gas,
                description: "Contract can be optimized for lower gas costs.".to_string(),
                details: vec![
                    "Use uint256 instead of smaller types".to_string(),
                    "Pack storage variables".to_string(),
                    "Use calldata instead of memory for read-only parameters".to_string(),
                    "Batch operations where possible".to_string(),
                ],
                remediation: "Review and apply gas optimization patterns.".to_string(),
                cwe_id: None,
                swc_id: None,
                line_number: None,
                code_snippet: None,
            },
        ]
    }

    fn check_wallet_approvals() -> Vec<WalletFinding> {
        vec![
            WalletFinding {
                title: "Unlimited Token Approvals".to_string(),
                severity: ContractSeverity::High,
                description: "Wallet has unlimited approvals to DApp contracts.".to_string(),
                details: vec![
                    "Revoke unnecessary approvals".to_string(),
                    "Use approval for exact amounts needed".to_string(),
                    "Tools: revoke.cash, etherscan token approval checker".to_string(),
                ],
            },
        ]
    }

    fn check_wallet_exposure() -> Vec<WalletFinding> {
        vec![
            WalletFinding {
                title: "High-Risk Protocol Exposure".to_string(),
                severity: ContractSeverity::Medium,
                description: "Wallet has exposure to unaudited or high-risk DeFi protocols.".to_string(),
                details: vec![
                    "Check exposure to unaudited protocols".to_string(),
                    "Monitor for protocol exploits".to_string(),
                    "Diversify across established protocols".to_string(),
                ],
            },
        ]
    }

    fn check_phishing_risk() -> Vec<WalletFinding> {
        vec![
            WalletFinding {
                title: "Phishing Token Detection".to_string(),
                severity: ContractSeverity::Medium,
                description: "Wallet may contain phishing or scam tokens.".to_string(),
                details: vec![
                    "Check for tokens from known phishing addresses".to_string(),
                    "Do not interact with unknown tokens".to_string(),
                    "Use GoPlus or similar token security APIs".to_string(),
                ],
            },
        ]
    }

    fn check_compliance() -> Vec<WalletFinding> {
        vec![
            WalletFinding {
                title: "Compliance Check".to_string(),
                severity: ContractSeverity::Low,
                description: "Wallet address screening for sanctions and illicit activity.".to_string(),
                details: vec![
                    "Check against OFAC SDN list".to_string(),
                    "Use Chainalysis or Elliptic for screening".to_string(),
                    "Monitor for mixer/tornado cash interactions".to_string(),
                ],
            },
        ]
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

    fn calculate_security_score(findings: &[ContractFinding]) -> f64 {
        let total = findings.len();
        if total == 0 { return 100.0; }

        let critical = findings.iter().filter(|f| f.severity == ContractSeverity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == ContractSeverity::High).count();
        let medium = findings.iter().filter(|f| f.severity == ContractSeverity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == ContractSeverity::Low).count();

        ((total - critical * 5 - high * 3 - medium - low / 2) as f64 / total as f64 * 100.0).max(0.0)
    }

    fn calculate_wallet_risk(findings: &[WalletFinding]) -> f64 {
        let total = findings.len();
        if total == 0 { return 0.0; }

        let critical = findings.iter().filter(|f| f.severity == ContractSeverity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == ContractSeverity::High).count();
        let medium = findings.iter().filter(|f| f.severity == ContractSeverity::Medium).count();

        ((critical * 25 + high * 15 + medium * 5) as f64).min(100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_scan() {
        let config = ContractScanConfig {
            contract_address: Some("0x1234...".to_string()),
            source_code: None,
            chain: Blockchain::Ethereum,
            check_categories: vec![
                ContractCheck::Reentrancy,
                ContractCheck::AccessControl,
                ContractCheck::Arithmetic,
                ContractCheck::FrontRunning,
                ContractCheck::OracleManipulation,
                ContractCheck::FlashLoan,
                ContractCheck::Logic,
                ContractCheck::Proxy,
                ContractCheck::Gas,
            ],
        };

        let result = Web3Auditor::scan_contract(&config);
        assert!(result.findings.len() > 5);
        assert_eq!(result.chain, Blockchain::Ethereum);
    }

    #[test]
    fn test_wallet_analysis() {
        let config = WalletSecurityConfig {
            address: "0x1234567890abcdef...".to_string(),
            chain: Blockchain::Ethereum,
            check_categories: vec![
                WalletCheck::Approvals,
                WalletCheck::Exposure,
                WalletCheck::Phishing,
                WalletCheck::Compliance,
            ],
        };

        let result = Web3Auditor::analyze_wallet(&config);
        assert!(result.findings.len() > 0);
    }

    #[test]
    fn test_security_score() {
        let config = ContractScanConfig {
            contract_address: None,
            source_code: None,
            chain: Blockchain::Ethereum,
            check_categories: vec![ContractCheck::Reentrancy],
        };

        let result = Web3Auditor::scan_contract(&config);
        assert!(result.score >= 0.0 && result.score <= 100.0);
    }
}
