use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use aes_gcm::aead::consts::U12;
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
    /// Argon2 salt bound to the master key. MUST be persisted with the vault and
    /// reused on every save, otherwise the derived key can never be reproduced.
    salt: Option<[u8; 16]>,
    /// Encrypted known-plaintext used to verify a candidate master password.
    /// Required for pathless (in-memory) vaults, which otherwise accept any password.
    verifier: Option<EncryptedBlob>,
    entries: HashMap<String, CredentialEntry>,
    is_locked: bool,
}

impl CredentialVault {
    pub fn new() -> Self {
        Self {
            path: None,
            master_key: None,
            salt: None,
            verifier: None,
            entries: HashMap::new(),
            is_locked: true,
        }
    }

    pub fn with_path(path: std::path::PathBuf) -> Self {
        Self {
            path: Some(path),
            master_key: None,
            salt: None,
            verifier: None,
            entries: HashMap::new(),
            is_locked: true,
        }
    }

    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        const VERIFIER_PLAINTEXT: &[u8] = b"SITE_RECORDER_VAULT_OK";

        // 1. Load the on-disk envelope (if the vault is file-backed and already exists).
        let loaded: Option<VaultFile> = match &self.path {
            Some(path) if path.exists() => {
                let data = std::fs::read_to_string(path)?;
                Some(serde_json::from_str(&data)?)
            }
            _ => None,
        };

        // 2. Reuse the persisted salt; only mint a new one when creating the vault.
        let salt: [u8; 16] = match &loaded {
            Some(vault_data) => {
                let bytes = BASE64.decode(&vault_data.salt)
                    .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;
                if bytes.len() != 16 {
                    return Err(CredentialError::DecryptionError(
                        "vault salt must be 16 bytes".to_string(),
                    ));
                }
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&bytes);
                salt
            }
            None => match self.salt {
                Some(salt) => salt,
                None => {
                    let salt: [u8; 16] = rand::random();
                    self.salt = Some(salt);
                    salt
                }
            },
        };

        let key = Self::derive_key(master_password, &salt)?;

        // 3. Verify the candidate password against the known-plaintext blob.
        //    This MUST happen for in-memory vaults too, otherwise any password unlocks them.
        let existing_verifier: Option<(Vec<u8>, Vec<u8>)> = match &loaded {
            Some(vault_data) => Some((
                BASE64.decode(&vault_data.verification_nonce)
                    .map_err(|e| CredentialError::DecryptionError(e.to_string()))?,
                BASE64.decode(&vault_data.verification)
                    .map_err(|e| CredentialError::DecryptionError(e.to_string()))?,
            )),
            None => self.verifier.as_ref().map(|blob| {
                (
                    BASE64.decode(&blob.nonce).unwrap_or_default(),
                    BASE64.decode(&blob.ciphertext).unwrap_or_default(),
                )
            }),
        };

        if let Some((nonce_bytes, ct_bytes)) = existing_verifier {
            if nonce_bytes.len() == 12 {
                let cipher = Aes256Gcm::new(&Self::key_from_bytes(&key));
                let nonce = Self::nonce_from_slice(&nonce_bytes)?;
                cipher
                    .decrypt(&nonce, ct_bytes.as_ref())
                    .map_err(|_| CredentialError::InvalidPassword)?;
            }
        }

        self.master_key = Some(key);
        self.is_locked = false;
        self.salt = Some(salt);

        // 4. Ensure we hold a verifier so subsequent unlocks (incl. in-memory) are checked.
        if self.verifier.is_none() {
            let key = self.master_key.expect("key just set");
            self.verifier = Some(self.encrypt_value(
                &String::from_utf8_lossy(VERIFIER_PLAINTEXT),
                &key,
            )?);
        }

        // 5. Decrypt entries.
        if let Some(vault_data) = &loaded {
            if !vault_data.entries_json.is_empty() {
                let nonce_bytes = BASE64.decode(&vault_data.entries_nonce)
                    .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;
                let ct_bytes = BASE64.decode(&vault_data.entries_json)
                    .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;

                let nonce = Self::nonce_from_slice(&nonce_bytes)?;
                let cipher = Aes256Gcm::new(&Self::key_from_bytes(&key));
                let plaintext = cipher
                    .decrypt(&nonce, ct_bytes.as_ref())
                    .map_err(|e| CredentialError::DecryptionError(e.to_string()))?;

                let entries: Vec<CredentialEntry> = serde_json::from_slice(&plaintext)?;
                self.entries = entries.into_iter().map(|e| (e.id.clone(), e)).collect();
            }
        }

        // 6. Persist immediately when we just created the vault file.
        if loaded.is_none() && self.path.is_some() {
            self.save()?;
        }

        Ok(())
    }

    pub fn lock(&mut self) {
        self.master_key = None;
        self.is_locked = true;
        // Keep `salt`/`verifier` so the correct password still unlocks this instance.
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

    pub fn save(&mut self) -> Result<()> {
        let path = match &self.path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        if self.is_locked {
            return Err(CredentialError::VaultLocked);
        }

        let key = self.master_key.ok_or(CredentialError::VaultLocked)?;

        // The salt MUST stay stable: the master key is derived from it, so
        // regenerating it here would make the vault permanently unopenable.
        let salt = self
            .salt
            .ok_or_else(|| CredentialError::EncryptionError("vault salt missing".to_string()))?;

        // Likewise the verifier blob is re-encrypted under the same key with a
        // fresh nonce each write; only its ciphertext/nonce pair is stored.
        let verification_plaintext = b"SITE_RECORDER_VAULT_OK";
        let mut verification_nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut verification_nonce_bytes);
        let verification_nonce = Nonce::from(verification_nonce_bytes);
        let cipher = Aes256Gcm::new(&Self::key_from_bytes(&key));
        let verification_ct = cipher
            .encrypt(&verification_nonce, verification_plaintext.as_ref())
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;

        let entries_json = serde_json::to_vec(&self.entries.values().collect::<Vec<_>>())?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Self::nonce_from_slice(&nonce_bytes)?;
        let ct = cipher.encrypt(&nonce, entries_json.as_ref())
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;

        let vault_file = VaultFile {
            version: 1,
            salt: BASE64.encode(&salt),
            verification: BASE64.encode(&verification_ct),
            verification_nonce: BASE64.encode(&verification_nonce_bytes),
            entries_json: BASE64.encode(&ct),
            entries_nonce: BASE64.encode(&nonce_bytes),
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(&vault_file)?)?;

        // Keep the in-memory verifier in sync with what we just wrote.
        self.verifier = Some(EncryptedBlob {
            ciphertext: BASE64.encode(&verification_ct),
            nonce: BASE64.encode(&verification_nonce_bytes),
            salt: BASE64.encode(&salt),
        });

        Ok(())
    }

    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| CredentialError::EncryptionError(e.to_string()))?;
        Ok(key)
    }

    /// Builds a GCM nonce from a byte slice without the deprecated
    /// `GenericArray::from_slice` (generic-array 1.x removed it).
    fn nonce_from_slice(bytes: &[u8]) -> Result<Nonce<U12>> {
        let mut arr = [0u8; 12];
        if bytes.len() != arr.len() {
            return Err(CredentialError::DecryptionError(format!(
                "nonce must be 12 bytes, got {}",
                bytes.len()
            )));
        }
        arr.copy_from_slice(bytes);
        Ok(Nonce::from(arr))
    }

    /// Builds an AES-256 key without the deprecated `GenericArray::from_slice`.
    fn key_from_bytes(key: &[u8; 32]) -> Key<Aes256Gcm> {
        Key::<Aes256Gcm>::from(*key)
    }

    fn encrypt_value(&self, plaintext: &str, key: &[u8; 32]) -> Result<EncryptedBlob> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let salt: [u8; 16] = rand::random();

        let nonce = Self::nonce_from_slice(&nonce_bytes)?;
        let cipher = Aes256Gcm::new(&Self::key_from_bytes(key));
        let ct = cipher.encrypt(&nonce, plaintext.as_bytes())
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

        let nonce = Self::nonce_from_slice(&nonce_bytes)?;
        let cipher = Aes256Gcm::new(&Self::key_from_bytes(key));
        let plaintext = cipher.decrypt(&nonce, ct_bytes.as_ref())
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
        // Unique path so a leftover file from an earlier run cannot affect the result.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let _ = std::fs::remove_file(&path);

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

        // A wrong master password must not open a persisted vault.
        {
            let mut vault = CredentialVault::with_path(path.clone());
            assert!(vault.unlock("not_master_pass").is_err());
        }
    }

    #[test]
    fn test_multiple_saves_keep_key_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        let mut vault = CredentialVault::with_path(path.clone());
        vault.unlock("pw").unwrap();
        vault.add_credential("a", "A", CredentialType::Password, "1").unwrap();
        vault.add_credential("b", "B", CredentialType::Password, "2").unwrap();
        drop(vault);

        let mut reopened = CredentialVault::with_path(path);
        reopened.unlock("pw").unwrap();
        assert_eq!(reopened.get_all_entries().len(), 2);
    }
}
