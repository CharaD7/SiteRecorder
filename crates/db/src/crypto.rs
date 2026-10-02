//! Encryption-at-rest for assessment data (Wave 1.6).
//!
//! D0.1 ("enterprise-grade") requires that assessment output — not just
//! secrets — is protected at rest. Today only `credentials`, `auth-profiles`
//! and `session` encrypt; scans, findings and assets are plaintext.
//!
//! ## Policy
//!
//! | Data | At rest |
//! |------|---------|
//! | Credential vault, auth profiles, session stores | Encrypted (existing `credentials` crate) |
//! | Findings `description` / `evidence` / `remediation` | **Encrypted** via [`seal`]/[`open_value`] |
//! | Finding titles, severities, CVE/CWE ids, asset names | Plaintext — required for SQL filtering, grouping and indexing |
//! | Audit log | Plaintext + SHA-256 hash chain (see [`crate::audit`]) |
//!
//! Sensitive free-text is encrypted; identifiers are not. Encrypting titles and
//! severities would make severity filters and index-backed queries impossible.
//! This is a deliberate, documented trade-off rather than an oversight.

use crate::{DbError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Version tag written into every sealed blob, so the scheme can change later
/// without silently misreading old data.
const FORMAT_VERSION: &str = "v1";

/// A derived, non-exportable key.
pub struct DataKey {
    cipher: Aes256Gcm,
}

impl DataKey {
    /// Derive a key from a master secret using SHA-256 over a fixed label.
    ///
    /// This is key *derivation from an existing secret*, not password hashing:
    /// the caller supplies a high-entropy secret (see [`load_or_create_secret`]).
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"siterecorder.data.v1");
        hasher.update(secret);
        let digest = hasher.finalize();
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&digest);

        DataKey {
            cipher: Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_bytes)),
        }
    }
}

/// Encrypt `plaintext`, binding it to `context` (e.g. a finding id).
///
/// The context is authenticated but not encrypted, so a blob cannot be moved
/// between records undetected.
pub fn seal(key: &DataKey, plaintext: &str, context: &str) -> Result<String> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = key
        .cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: context.as_bytes(),
            },
        )
        .map_err(|e| DbError::Migration(format!("encryption failed: {}", e)))?;

    // Separator is '.' because the base64 standard alphabet cannot contain it,
    // so field splitting is unambiguous. A ':' separator is ambiguous here.
    Ok(format!(
        "{}.{}.{}",
        FORMAT_VERSION,
        BASE64.encode(&nonce_bytes),
        BASE64.encode(&ciphertext)
    ))
}

/// Decrypt a blob produced by [`seal`], authenticating `context`.
pub fn open_value(key: &DataKey, blob: &str, context: &str) -> Result<String> {
    let mut parts = blob.splitn(3, '.');
    let version = parts
        .next()
        .ok_or_else(|| DbError::Migration("sealed value is empty".into()))?;
    if version != FORMAT_VERSION {
        return Err(DbError::Migration(format!(
            "unsupported sealed-value format: {}",
            version
        )));
    }
    let nonce_b64 = parts
        .next()
        .ok_or_else(|| DbError::Migration("sealed value missing nonce".into()))?;
    let ct_b64 = parts
        .next()
        .ok_or_else(|| DbError::Migration("sealed value missing ciphertext".into()))?;

    let nonce_bytes = BASE64
        .decode(nonce_b64)
        .map_err(|e| DbError::DecryptionError(e.to_string()))?;
    if nonce_bytes.len() != 12 {
        return Err(DbError::DecryptionError("nonce must be 12 bytes".into()));
    }
    let ct = BASE64
        .decode(ct_b64)
        .map_err(|e| DbError::DecryptionError(e.to_string()))?;

    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_bytes);
    let plaintext = key
        .cipher
        .decrypt(
            &Nonce::from(nonce_arr),
            Payload {
                msg: &ct,
                aad: context.as_bytes(),
            },
        )
        .map_err(|_| DbError::DecryptionError("authentication failed".into()))?;

    String::from_utf8(plaintext).map_err(|e| DbError::DecryptionError(e.to_string()))
}

/// Read the app's data-encryption secret, or create one on first run.
///
/// Stored beside the database with owner-only permissions where the platform
/// supports it. This protects data at rest from casual inspection and backup
/// leakage; it is not a substitute for full-disk encryption.
pub fn load_or_create_secret(path: &std::path::Path) -> Result<Vec<u8>> {
    if path.exists() {
        return Ok(std::fs::read(path)?);
    }

    let mut secret = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &secret)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(secret)
}

/// Default location of the data-encryption secret.
pub fn secret_path() -> std::path::PathBuf {
    crate::paths::data_dir().join("data.key")
}

/// Convenience: load (or create) the secret and derive a [`DataKey`].
pub fn default_key() -> Result<DataKey> {
    Ok(DataKey::from_secret(&load_or_create_secret(&secret_path())?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DataKey {
        DataKey::from_secret(b"a-test-secret-value")
    }

    #[test]
    fn round_trips() {
        let k = key();
        let text = "SQL injection in /login: password parameter is unparameterised";
        let blob = seal(&k, text, "finding-1").unwrap();
        assert_eq!(open_value(&k, &blob, "finding-1").unwrap(), text);
    }

    #[test]
    fn ciphertext_does_not_leak_plaintext() {
        let k = key();
        let blob = seal(&k, "top-secret-finding-body", "finding-1").unwrap();
        assert!(!blob.contains("top-secret"));
        assert!(blob.starts_with("v1."));
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let sealed = seal(&key(), "sensitive", "finding-1").unwrap();
        let other = DataKey::from_secret(b"different-secret");
        assert!(open_value(&other, &sealed, "finding-1").is_err());
    }

    #[test]
    fn blob_cannot_be_moved_to_another_record() {
        let k = key();
        let sealed = seal(&k, "sensitive", "finding-1").unwrap();
        // Context is authenticated, so replaying under another id must fail.
        assert!(open_value(&k, &sealed, "finding-2").is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let k = key();
        let sealed = seal(&k, "sensitive", "f1").unwrap();
        let parts: Vec<&str> = sealed.split('.').collect();
        // Flip a byte in the ciphertext payload.
        let mut ct = BASE64.decode(parts[2]).unwrap();
        ct[0] ^= 0xFF;
        let tampered = format!("{}.{}.{}", parts[0], parts[1], BASE64.encode(&ct));

        assert!(open_value(&k, &tampered, "f1").is_err());
    }

    #[test]
    fn unknown_format_version_is_rejected() {
        let k = key();
        assert!(open_value(&k, "v9.AAAA.BBBB", "f1").is_err());
        assert!(open_value(&k, "garbage", "f1").is_err());
    }

    #[test]
    fn secret_is_stable_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.key");

        let first = load_or_create_secret(&path).unwrap();
        assert!(path.exists());
        let second = load_or_create_secret(&path).unwrap();
        assert_eq!(first, second, "secret must be reused, not regenerated");
    }

    #[test]
    fn distinct_nonces_for_same_plaintext() {
        let k = key();
        let a = seal(&k, "same", "f1").unwrap();
        let b = seal(&k, "same", "f1").unwrap();
        assert_ne!(a, b, "nonce reuse would leak equality under AES-GCM");
    }
}
