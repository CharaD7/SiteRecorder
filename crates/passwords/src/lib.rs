use chrono::Utc;
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Crack error: {0}")]
    CrackError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Hash not found")]
    HashNotFound,
}

type Result<T> = std::result::Result<T, PasswordError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashInfo {
    pub hash: String,
    pub hash_type: HashType,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Md5Crypt,
    Bcrypt,
    Scrypt,
    Ntlm,
    MySQL,
    PostgreSQL,
    Oracle,
    MSSQL,
    Sha256Crypt,
    Sha512Crypt,
    Unknown(String),
}

impl std::fmt::Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashType::Md5 => write!(f, "MD5"),
            HashType::Sha1 => write!(f, "SHA-1"),
            HashType::Sha256 => write!(f, "SHA-256"),
            HashType::Sha512 => write!(f, "SHA-512"),
            HashType::Md5Crypt => write!(f, "md5crypt"),
            HashType::Bcrypt => write!(f, "bcrypt"),
            HashType::Scrypt => write!(f, "scrypt"),
            HashType::Ntlm => write!(f, "NTLM"),
            HashType::MySQL => write!(f, "MySQL"),
            HashType::PostgreSQL => write!(f, "PostgreSQL"),
            HashType::Oracle => write!(f, "Oracle"),
            HashType::MSSQL => write!(f, "MSSQL"),
            HashType::Sha256Crypt => write!(f, "sha256crypt"),
            HashType::Sha512Crypt => write!(f, "sha512crypt"),
            HashType::Unknown(s) => write!(f, "Unknown({})", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackConfig {
    pub hash: String,
    pub hash_type: HashType,
    pub wordlist: Vec<String>,
    pub rules: Vec<CrackRule>,
    pub max_attempts: usize,
    pub timeout_seconds: u64,
}

impl Default for CrackConfig {
    fn default() -> Self {
        Self {
            hash: String::new(),
            hash_type: HashType::Md5,
            wordlist: Vec::new(),
            rules: Vec::new(),
            max_attempts: 1_000_000,
            timeout_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    pub hash: String,
    pub hash_type: HashType,
    pub plaintext: Option<String>,
    pub attempts: usize,
    pub duration_ms: u64,
    pub status: CrackStatus,
    pub method: CrackMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CrackStatus {
    Pending,
    Running,
    Found,
    NotFound,
    Timeout,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CrackMethod {
    Dictionary,
    BruteForce,
    Mask,
    RuleBased,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackRule {
    pub name: String,
    pub transformation: Transformation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transformation {
    Lowercase,
    Uppercase,
    Capitalize,
    Reverse,
    Append(String),
    Prepend(String),
    Replace(char, char),
    Duplicate,
    TrimRight(u8),
    TrimLeft(u8),
    ToggleCase,
    ShiftNumbers,
    LeetSpeak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayConfig {
    pub target: String,
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    pub delay_ms: u64,
    pub max_attempts: usize,
    pub lockout_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayResult {
    pub target: String,
    pub attempts: Vec<SprayAttempt>,
    pub successful: Vec<SprayAttempt>,
    pub total_attempts: usize,
    pub duration_ms: u64,
    pub status: SprayStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayAttempt {
    pub username: String,
    pub password: String,
    pub success: bool,
    pub timestamp: String,
    pub response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SprayStatus {
    Pending,
    Running,
    Completed,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistInfo {
    pub name: String,
    pub size: usize,
    pub description: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskConfig {
    pub charset: MaskCharset,
    pub min_length: usize,
    pub max_length: usize,
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaskCharset {
    Lowercase,
    Uppercase,
    Digits,
    Alpha,
    Alphanumeric,
    All,
    Custom(String),
}

pub struct PasswordCracker;

impl PasswordCracker {
    pub fn identify_hash(hash: &str) -> Vec<HashInfo> {
        let mut results = Vec::new();
        let hash = hash.trim();

        if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Md5,
                confidence: 90,
            });
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Ntlm,
                confidence: 70,
            });
        }

        if hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Sha1,
                confidence: 85,
            });
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::MySQL,
                confidence: 60,
            });
        }

        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Sha256,
                confidence: 90,
            });
        }

        if hash.len() == 128 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Sha512,
                confidence: 90,
            });
        }

        if hash.starts_with("$1$") {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Md5Crypt,
                confidence: 95,
            });
        }

        if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Bcrypt,
                confidence: 95,
            });
        }

        if hash.starts_with("$5$") {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Sha256Crypt,
                confidence: 95,
            });
        }

        if hash.starts_with("$6$") {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Sha512Crypt,
                confidence: 95,
            });
        }

        if hash.starts_with("0x") && hash.len() == 90 {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::MSSQL,
                confidence: 80,
            });
        }

        if results.is_empty() {
            results.push(HashInfo {
                hash: hash.to_string(),
                hash_type: HashType::Unknown("unrecognized".to_string()),
                confidence: 0,
            });
        }

        results
    }

    pub fn crack_hash(config: &CrackConfig) -> CrackResult {
        let start = std::time::Instant::now();
        let mut attempts = 0;

        for word in &config.wordlist {
            if attempts >= config.max_attempts {
                return CrackResult {
                    hash: config.hash.clone(),
                    hash_type: config.hash_type.clone(),
                    plaintext: None,
                    attempts,
                    duration_ms: start.elapsed().as_millis() as u64,
                    status: CrackStatus::Timeout,
                    method: CrackMethod::Dictionary,
                };
            }

            let variants = Self::apply_rules(word, &config.rules);

            for variant in &variants {
                if Self::check_hash(&config.hash, variant, &config.hash_type) {
                    return CrackResult {
                        hash: config.hash.clone(),
                        hash_type: config.hash_type.clone(),
                        plaintext: Some(variant.clone()),
                        attempts,
                        duration_ms: start.elapsed().as_millis() as u64,
                        status: CrackStatus::Found,
                        method: CrackMethod::Dictionary,
                    };
                }
                attempts += 1;
            }
        }

        CrackResult {
            hash: config.hash.clone(),
            hash_type: config.hash_type.clone(),
            plaintext: None,
            attempts,
            duration_ms: start.elapsed().as_millis() as u64,
            status: CrackStatus::NotFound,
            method: CrackMethod::Dictionary,
        }
    }

    fn check_hash(hash: &str, plaintext: &str, hash_type: &HashType) -> bool {
        match hash_type {
            HashType::Md5 => {
                let computed = format!("{:x}", Md5::digest(plaintext.as_bytes()));
                computed.eq_ignore_ascii_case(hash)
            }
            HashType::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(plaintext.as_bytes());
                let computed = format!("{:x}", hasher.finalize());
                computed.eq_ignore_ascii_case(hash)
            }
            HashType::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(plaintext.as_bytes());
                let computed = format!("{:x}", hasher.finalize());
                computed.eq_ignore_ascii_case(hash)
            }
            HashType::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(plaintext.as_bytes());
                let computed = format!("{:x}", hasher.finalize());
                computed.eq_ignore_ascii_case(hash)
            }
            _ => false,
        }
    }

    fn apply_rules(word: &str, rules: &[CrackRule]) -> Vec<String> {
        let mut variants = vec![word.to_string()];

        if rules.is_empty() {
            variants.extend_from_slice(&[
                word.to_lowercase(),
                word.to_uppercase(),
                Self::capitalize(word),
            ]);
            variants.dedup();
            return variants;
        }

        for rule in rules {
            let mut new_variants = Vec::new();
            for variant in &variants {
                let transformed = Self::apply_transformation(variant, &rule.transformation);
                new_variants.push(transformed);
            }
            variants.extend(new_variants);
        }

        variants.dedup();
        variants
    }

    fn apply_transformation(input: &str, transformation: &Transformation) -> String {
        match transformation {
            Transformation::Lowercase => input.to_lowercase(),
            Transformation::Uppercase => input.to_uppercase(),
            Transformation::Capitalize => Self::capitalize(input),
            Transformation::Reverse => input.chars().rev().collect(),
            Transformation::Append(s) => format!("{}{}", input, s),
            Transformation::Prepend(s) => format!("{}{}", s, input),
            Transformation::Replace(from, to) => input.replace(*from, &to.to_string()),
            Transformation::Duplicate => format!("{}{}", input, input),
            Transformation::TrimRight(n) => {
                let n = (*n as usize).min(input.len());
                input[..input.len() - n].to_string()
            }
            Transformation::TrimLeft(n) => {
                let n = (*n as usize).min(input.len());
                input[n..].to_string()
            }
            Transformation::ToggleCase => {
                input.chars().map(|c| {
                    if c.is_ascii_lowercase() { c.to_ascii_uppercase() }
                    else if c.is_ascii_uppercase() { c.to_ascii_lowercase() }
                    else { c }
                }).collect()
            }
            Transformation::ShiftNumbers => {
                input.chars().map(|c| {
                    if c.is_ascii_digit() {
                        let d = c.to_digit(10).unwrap();
                        char::from_digit((d + 1) % 10, 10).unwrap()
                    } else { c }
                }).collect()
            }
            Transformation::LeetSpeak => {
                input.chars().map(|c| match c {
                    'a' | 'A' => '4',
                    'e' | 'E' => '3',
                    'i' | 'I' => '1',
                    'o' | 'O' => '0',
                    's' | 'S' => '5',
                    't' | 'T' => '7',
                    _ => c,
                }).collect()
            }
        }
    }

    fn capitalize(s: &str) -> String {
        let mut chars = s.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
        }
    }

    pub fn generate_mask_candidates(config: &MaskConfig) -> Vec<String> {
        let charset = match &config.charset {
            MaskCharset::Lowercase => "abcdefghijklmnopqrstuvwxyz",
            MaskCharset::Uppercase => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            MaskCharset::Digits => "0123456789",
            MaskCharset::Alpha => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            MaskCharset::Alphanumeric => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            MaskCharset::All => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()",
            MaskCharset::Custom(s) => s,
        };

        let mut results = Vec::new();
        let chars: Vec<char> = charset.chars().collect();

        for len in config.min_length..=config.max_length {
            if len > 6 { break; }
            let total = chars.len().pow(len as u32);
            if total > 100_000 { break; }

            let mut indices = vec![0usize; len];
            loop {
                let candidate: String = indices.iter().map(|&i| chars[i]).collect();
                results.push(candidate);

                let mut carry = 1;
                for i in (0..len).rev() {
                    indices[i] += carry;
                    if indices[i] >= chars.len() {
                        indices[i] = 0;
                        carry = 1;
                    } else {
                        carry = 0;
                        break;
                    }
                }
                if carry > 0 { break; }
            }
        }

        results
    }

    pub fn get_default_wordlist() -> Vec<String> {
        vec![
            "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
            "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
            "princess", "football", "charlie", "shadow", "michael", "password1",
            "password123", "admin", "admin123", "root", "toor", "letmein", "welcome",
            "monkey123", "dragon123", "login", "starwars", "solo", "access", "flower",
            "flower123", "passw0rd", "hello", "charlie1", "donald", "qwerty123",
            "password1!", "1234", "12345", "123456789", "1234567890", "123123",
            "696969", "batman", "access14", "hello123", "pussy", "6969", "killer",
            "pepper", "buster", "summer", "buster", "george", "harley", "andrea",
            "joshua", "daniel", "hunter", "jordan", "thomas", "robert", "hockey",
            "ranger", "starwars", "klaster", "george", "computer", "michelle",
            "jessica", "pepper", "amanda", "summer", "ashley", "nicole", "biteme",
            "access", "dallas", "austin", "thunder", "taylor", "matrix", "minecraft",
        ].iter().map(|s| s.to_string()).collect()
    }

    pub fn get_wordlist_info() -> Vec<WordlistInfo> {
        vec![
            WordlistInfo {
                name: "default".to_string(),
                size: 100,
                description: "Common passwords list".to_string(),
                category: "common".to_string(),
            },
            WordlistInfo {
                name: "top1000".to_string(),
                size: 1000,
                description: "Top 1000 most common passwords".to_string(),
                category: "common".to_string(),
            },
            WordlistInfo {
                name: "rockyou".to_string(),
                size: 14_341_564,
                description: "RockYou breach wordlist".to_string(),
                category: "breach".to_string(),
            },
            WordlistInfo {
                name: "subdomains".to_string(),
                size: 114_000,
                description: "Common subdomain names".to_string(),
                category: "recon".to_string(),
            },
            WordlistInfo {
                name: "directories".to_string(),
                size: 85_000,
                description: "Common directory names".to_string(),
                category: "recon".to_string(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_md5() {
        let results = PasswordCracker::identify_hash("5f4dcc3b5aa765d61d8327deb882cf99");
        assert!(results.iter().any(|r| r.hash_type == HashType::Md5));
    }

    #[test]
    fn test_identify_sha1() {
        let results = PasswordCracker::identify_hash("5baa61e4c9b93f3f0682250b6cf8331b68ee9c9e");
        assert!(results.iter().any(|r| r.hash_type == HashType::Sha1));
    }

    #[test]
    fn test_crack_md5() {
        let config = CrackConfig {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            hash_type: HashType::Md5,
            wordlist: vec!["password".to_string(), "admin".to_string()],
            rules: vec![],
            max_attempts: 1000,
            timeout_seconds: 30,
        };

        let result = PasswordCracker::crack_hash(&config);
        assert_eq!(result.status, CrackStatus::Found);
        assert_eq!(result.plaintext, Some("password".to_string()));
    }

    #[test]
    fn test_crack_sha256() {
        let config = CrackConfig {
            hash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8".to_string(),
            hash_type: HashType::Sha256,
            wordlist: vec!["password".to_string()],
            rules: vec![],
            max_attempts: 1000,
            timeout_seconds: 30,
        };

        let result = PasswordCracker::crack_hash(&config);
        assert_eq!(result.status, CrackStatus::Found);
    }

    #[test]
    fn test_apply_rules() {
        let rules = vec![
            CrackRule { name: "capitalize".to_string(), transformation: Transformation::Capitalize },
        ];
        let variants = PasswordCracker::apply_rules("hello", &rules);
        assert!(variants.contains(&"Hello".to_string()));
    }

    #[test]
    fn test_leet_speak() {
        let result = PasswordCracker::apply_transformation("password", &Transformation::LeetSpeak);
        assert_eq!(result, "p455w0rd");
    }

    #[test]
    fn test_mask_generation() {
        let config = MaskConfig {
            charset: MaskCharset::Digits,
            min_length: 1,
            max_length: 2,
            pattern: None,
        };
        let candidates = PasswordCracker::generate_mask_candidates(&config);
        assert!(candidates.len() > 0);
        assert!(candidates.contains(&"0".to_string()));
        assert!(candidates.contains(&"99".to_string()));
    }
}
