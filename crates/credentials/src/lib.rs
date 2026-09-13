use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{self, Argon2, password_hash::SaltString};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("Vault is locked — master password required")]
    VaultLocked,
    #[error("Invalid master password")]
    InvalidPassword,
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Credential not found: {0}")]
    NotFound(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, CredentialError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub ciphertext: String,
    pub nonce: String,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct CredentialValue {
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub id: String,
    pub name: String,
    pub credential_type: CredentialType,
    pub encrypted: EncryptedBlob,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CredentialType {
    Password,
    ApiToken,
    SshKey,
    Certificate,
    TotpSecret,
    OAuthToken,
    RefreshToken,
    BackupCode,
    Custom(String),
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::Password => write!(f, "password"),
            CredentialType::ApiToken => write!(f, "api_token"),
            CredentialType::SshKey => write!(f, "ssh_key"),
            CredentialType::Certificate => write!(f, "certificate"),
            CredentialType::TotpSecret => write!(f, "totp_secret"),
            CredentialType::OAuthToken => write!(f, "oauth_token"),
            CredentialType::RefreshToken => write!(f, "refresh_token"),
            CredentialType::BackupCode => write!(f, "backup_code"),
            CredentialType::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

pub struct CredentialVault {
    path: Option<std::path::PathBuf>,
    master_key: Option<[u8; 32]>,
    entries: HashMap<String, CredentialEntry>,
    is_locked: bool,
}

impl CredentialVault {
    pub fn new() -> Self {
        Self {
            path: None,
            master_key: None,
            entries: HashMap::new(),
            is_locked: true,
        }
    }

    pub fn with_path(path: std::path::PathBuf) -> Self {
        Self {
            path: Some(path),
            master_key: None,
            entries: HashMap::new(),
            is_locked: true,
        }
    }

    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        if let Some(path) = &self.path {
            if path.exists() {
                let data = std::fs::read_to_string(path)?;
                let vault_data: VaultFile = serde_json::from_str(&data)?;

                let salt = BASE64.decode(&vault_data.salt)
                    .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;
                let key = Self::derive_key(master_password, &salt)?;

                let test_nonce = Nonce::from_slice(&[0u8; 12]);
                let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key));
                let test_ct = BASE64.decode(&vault_data.verification)
                    .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;

                cipher.decrypt(test_nonce, test_ct.as_ref())
                    .map_err(|_| CredentialError::InvalidPassword)?;

                self.master_key = Some(key);
                self.is_locked = false;

                if !vault_data.entries_json.is_empty() {
                    let nonce_bytes = BASE64.decode(&vault_data.entries_nonce)
                        .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;
                    let ct_bytes = BASE64.decode(&vault_data.entries_json)
                        .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;

                    let nonce = Nonce::from_slice(&nonce_bytes);
                    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&self.master_key.unwrap()));
                    let plaintext = cipher.decrypt(nonce, ct_bytes.as_ref())
                        .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;

                    let entries: Vec<CredentialEntry> = serde_json::from_slice(&plaintext)?;
                    self.entries = entries.into_iter().map(|e| (e.id.clone(), e)).collect();
                }
            } else {
                let salt: [u8; 16] = rand::random();
                let key = Self::derive_key(master_password, &salt)?;
                self.master_key = Some(key);
                self.is_locked = false;
                self.save()?;
            }
        } else {
            let salt: [u8; 16] = rand::random();
            let key = Self::derive_key(master_password, &salt)?;
            self.master_key = Some(key);
            self.is_locked = false;
        }
        Ok(())
    }

    pub fn lock(&mut self) {
        self.master_key = None;
        self.is_locked = true;
    }

    pub fn add_credential(
        &mut self,
        id: &str,
        name: &str,
        cred_type: CredentialType,
        value: &str,
    ) -> Result<()> {
        if self.is_locked {
            return Err(CredentialError::VaultLocked);
        }

        let key = self.master_key.ok_or(CredentialError::VaultLocked)?;
        let encrypted = self.encrypt_value(value, &key)?;
        let now = chrono::Utc::now().to_rfc3339();

        let entry = CredentialEntry {
            id: id.to_string(),
            name: name.to_string(),
            credential_type: cred_type,
            encrypted,
            created_at: now.clone(),
            updated_at: now,
        };

        self.entries.insert(id.to_string(), entry);
        self.save()?;
        Ok(())
    }

    pub fn get_credential(&self, id: &str) -> Result<(CredentialEntry, String)> {
        if self.is_locked {
            return Err(CredentialError::VaultLocked);
        }

        let entry = self.entries.get(id)
            .ok_or_else(|| CredentialError::NotFound(id.to_string()))?
            .clone();

        let key = self.master_key.ok_or(CredentialError::VaultLocked)?;
        let plaintext = self.decrypt_value(&entry.encrypted, &key)?;

        Ok((entry, plaintext))
    }

    pub fn get_all_entries(&self) -> Vec<CredentialEntry> {
        self.entries.values().cloned().collect()
    }

    pub fn remove_credential(&mut self, id: &str) -> Result<()> {
        if self.is_locked {
            return Err(CredentialError::VaultLocked);
        }

        self.entries.remove(id)
            .ok_or_else(|| CredentialError::NotFound(id.to_string()))?;
        self.save()?;
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        let path = match &self.path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        if self.is_locked {
            return Err(CredentialError::VaultLocked);
        }

        let key = self.master_key.ok_or(CredentialError::VaultLocked)?;

        let salt: [u8; 16] = rand::random();
        let verification_plaintext = b"SITE_RECORDER_VAULT_OK";
        let verification_nonce = Nonce::from_slice(&[0u8; 12]);
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key));
        let verification_ct = cipher.encrypt(verification_nonce, verification_plaintext.as_ref())
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;

        let entries_json = serde_json::to_vec(&self.entries.values().collect::<Vec<_>>())?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, entries_json.as_ref())
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;

        let vault_file = VaultFile {
            version: 1,
            salt: BASE64.encode(&salt),
            verification: BASE64.encode(&verification_ct),
            verification_nonce: BASE64.encode(&[0u8; 12]),
            entries_json: BASE64.encode(&ct),
            entries_nonce: BASE64.encode(&nonce_bytes),
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(&vault_file)?)?;
        Ok(())
    }

    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;
        Ok(key)
    }

    fn encrypt_value(&self, plaintext: &str, key: &[u8; 32]) -> Result<EncryptedBlob> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let salt: [u8; 16] = rand::random();

        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let ct = cipher.encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;

        Ok(EncryptedBlob {
            ciphertext: BASE64.encode(&ct),
            nonce: BASE64.encode(&nonce_bytes),
            salt: BASE64.encode(&salt),
        })
    }

    fn decrypt_value(&self, blob: &EncryptedBlob, key: &[u8; 32]) -> Result<String> {
        let nonce_bytes = BASE64.decode(&blob.nonce)
            .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;
        let ct_bytes = BASE64.decode(&blob.ciphertext)
            .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(key));
        let plaintext = cipher.decrypt(nonce, ct_bytes.as_ref())
            .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;

        String::from_utf8(plaintext)
            .map_err(|e| CredentialError::DecryptionError(e.to_string()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    salt: String,
    verification: String,
    verification_nonce: String,
    entries_json: String,
    entries_nonce: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlock_and_add() {
        let mut vault = CredentialVault::new();
        vault.unlock("test_password_123").unwrap();

        vault.add_credential("test1", "Test Password", CredentialType::Password, "secret123").unwrap();

        let (entry, value) = vault.get_credential("test1").unwrap();
        assert_eq!(entry.name, "Test Password");
        assert_eq!(value, "secret123");
    }

    #[test]
    fn test_wrong_password() {
        let mut vault = CredentialVault::new();
        vault.unlock("correct_password").unwrap();
        vault.add_credential("test1", "Test", CredentialType::Password, "secret").unwrap();
        vault.lock();

        let result = vault.unlock("wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_persistence() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_vault_delete_me.json");

        {
            let mut vault = CredentialVault::with_path(path.clone());
            vault.unlock("master_pass").unwrap();
            vault.add_credential("cred1", "API Key", CredentialType::ApiToken, "sk-abc123").unwrap();
        }

        {
            let mut vault = CredentialVault::with_path(path.clone());
            vault.unlock("master_pass").unwrap();
            let (_, value) = vault.get_credential("cred1").unwrap();
            assert_eq!(value, "sk-abc123");
        }

        let _ = std::fs::remove_file(&path);
    }
}
