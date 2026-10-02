//! Tamper-evident audit log (Wave 1.5).
//!
//! Plan 6.4 requires a hash-chained, tamper-evident log. Each entry stores the
//! hash of the previous entry, so altering or removing any row invalidates every
//! hash after it. `verify_integrity()` detects that.

use crate::{DbError, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Genesis value for the first entry's `prev_hash`.
pub const GENESIS_HASH: &str = "GENESIS";

/// One audit record plus its chain position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

/// Input to `append`; the chain fields are computed, not supplied.
#[derive(Debug, Clone)]
pub struct NewAuditEntry {
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
}

/// Canonical hash over an entry's content plus its predecessor's hash.
///
/// Field order is fixed and separators are explicit so the digest is stable
/// across runs and platforms.
fn compute_hash(
    id: &str,
    timestamp: &str,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details: Option<&str>,
    ip_address: Option<&str>,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        id,
        timestamp,
        actor,
        action,
        target.unwrap_or(""),
        details.unwrap_or(""),
        ip_address.unwrap_or(""),
        prev_hash,
    ] {
        hasher.update(field.as_bytes());
        hasher.update(b"\x1f");
    }
    format!("{:x}", hasher.finalize())
}

/// Append an entry, linking it to the current chain head.
pub fn append(conn: &rusqlite::Connection, entry: NewAuditEntry) -> Result<AuditEntry> {
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let prev_hash: String = conn
        .query_row(
            "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| GENESIS_HASH.to_string());

    let hash = compute_hash(
        &id,
        &timestamp,
        &entry.actor,
        &entry.action,
        entry.target.as_deref(),
        entry.details.as_deref(),
        entry.ip_address.as_deref(),
        &prev_hash,
    );

    conn.execute(
        "INSERT INTO audit_log (id, timestamp, actor, action, target, details, ip_address, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![id, timestamp, entry.actor, entry.action, entry.target, entry.details,
                entry.ip_address, prev_hash, hash],
    )?;

    Ok(AuditEntry {
        id,
        timestamp,
        actor: entry.actor,
        action: entry.action,
        target: entry.target,
        details: entry.details,
        ip_address: entry.ip_address,
        prev_hash,
        hash,
    })
}

/// Read entries newest-first.
pub fn list(conn: &rusqlite::Connection, limit: Option<i64>) -> Result<Vec<AuditEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, actor, action, target, details, ip_address, prev_hash, hash
         FROM audit_log ORDER BY seq DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit.unwrap_or(500)], |row| {
        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            actor: row.get(2)?,
            action: row.get(3)?,
            target: row.get(4)?,
            details: row.get(5)?,
            ip_address: row.get(6)?,
            prev_hash: row.get(7)?,
            hash: row.get(8)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Result of an integrity check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub valid: bool,
    pub entries_checked: usize,
    /// 1-based position of the first bad entry, if any.
    pub first_invalid_seq: Option<i64>,
    pub reason: Option<String>,
}

impl IntegrityReport {
    pub fn describe(&self) -> String {
        if self.valid {
            return format!("Audit log intact ({} entries).", self.entries_checked);
        }
        format!(
            "AUDIT LOG TAMPERED: entry {} failed verification ({})",
            self.first_invalid_seq.unwrap_or(0),
            self.reason.as_deref().unwrap_or("unknown reason")
        )
    }
}

/// Walk the chain oldest-first, recomputing every hash.
pub fn verify_integrity(conn: &rusqlite::Connection) -> Result<IntegrityReport> {
    let mut stmt = conn.prepare(
        "SELECT seq, id, timestamp, actor, action, target, details, ip_address, prev_hash, hash
         FROM audit_log ORDER BY seq ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,   // seq
            row.get::<_, String>(1)?, // id
            row.get::<_, String>(2)?, // timestamp
            row.get::<_, String>(3)?, // actor
            row.get::<_, String>(4)?, // action
            row.get::<_, Option<String>>(5)?, // target
            row.get::<_, Option<String>>(6)?, // details
            row.get::<_, Option<String>>(7)?, // ip_address
            row.get::<_, String>(8)?, // prev_hash
            row.get::<_, String>(9)?, // hash
        ))
    })?;

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut checked = 0usize;

    for row in rows {
        let (seq, id, timestamp, actor, action, target, details, ip, prev_hash, hash) = row?;
        checked += 1;

        if prev_hash != expected_prev {
            return Ok(IntegrityReport {
                valid: false,
                entries_checked: checked,
                first_invalid_seq: Some(seq),
                reason: Some(format!(
                    "prev_hash mismatch: expected {}, found {}",
                    expected_prev, prev_hash
                )),
            });
        }

        let recomputed = compute_hash(
            &id, &timestamp, &actor, &action, target.as_deref(), details.as_deref(),
            ip.as_deref(), &prev_hash,
        );

        if recomputed != hash {
            return Ok(IntegrityReport {
                valid: false,
                entries_checked: checked,
                first_invalid_seq: Some(seq),
                reason: Some("content does not match stored hash (row was modified)".to_string()),
            });
        }

        expected_prev = hash;
    }

    Ok(IntegrityReport {
        valid: true,
        entries_checked: checked,
        first_invalid_seq: None,
        reason: None,
    })
}

/// Convenience wrapper returning an error when verification fails.
pub fn verify_or_err(conn: &rusqlite::Connection) -> Result<()> {
    let report = verify_integrity(conn)?;
    if report.valid {
        Ok(())
    } else {
        Err(DbError::Migration(report.describe()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    fn entry(actor: &str, action: &str) -> NewAuditEntry {
        NewAuditEntry {
            actor: actor.to_string(),
            action: action.to_string(),
            target: Some("https://example.com".to_string()),
            details: None,
            ip_address: Some("127.0.0.1".to_string()),
        }
    }

    #[test]
    fn empty_log_is_valid() {
        let db = Db::open_in_memory().unwrap();
        let report = verify_integrity(db.conn()).unwrap();
        assert!(report.valid);
        assert_eq!(report.entries_checked, 0);
    }

    #[test]
    fn chain_links_and_verifies() {
        let db = Db::open_in_memory().unwrap();
        let first = append(db.conn(), entry("admin", "login")).unwrap();
        let second = append(db.conn(), entry("admin", "scan_start")).unwrap();
        let third = append(db.conn(), entry("operator", "scan_complete")).unwrap();

        assert_eq!(first.prev_hash, GENESIS_HASH);
        assert_eq!(second.prev_hash, first.hash);
        assert_eq!(third.prev_hash, second.hash);

        let report = verify_integrity(db.conn()).unwrap();
        assert!(report.valid, "{}", report.describe());
        assert_eq!(report.entries_checked, 3);
    }

    #[test]
    fn modified_row_is_detected() {
        let db = Db::open_in_memory().unwrap();
        append(db.conn(), entry("admin", "login")).unwrap();
        append(db.conn(), entry("admin", "scan_start")).unwrap();

        // Tamper with the first entry's content, leaving its hash untouched.
        db.conn()
            .execute("UPDATE audit_log SET action = 'deleted_everything' WHERE seq = 1", [])
            .unwrap();

        let report = verify_integrity(db.conn()).unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_seq, Some(1));
        assert!(report.describe().contains("TAMPERED"));
    }

    #[test]
    fn deleted_row_is_detected() {
        let db = Db::open_in_memory().unwrap();
        append(db.conn(), entry("admin", "login")).unwrap();
        append(db.conn(), entry("admin", "scan_start")).unwrap();
        append(db.conn(), entry("admin", "scan_complete")).unwrap();

        // Remove the middle entry. The deletion itself is unobservable, but the
        // surviving next entry's prev_hash no longer resolves, so the break is
        // detected at that row.
        db.conn()
            .execute("DELETE FROM audit_log WHERE seq = 2", [])
            .unwrap();

        let report = verify_integrity(db.conn()).unwrap();
        assert!(!report.valid);
        assert_eq!(report.first_invalid_seq, Some(3));
        assert!(report.reason.unwrap().contains("prev_hash mismatch"));
    }

    #[test]
    fn verify_or_err_raises_on_tamper() {
        let db = Db::open_in_memory().unwrap();
        append(db.conn(), entry("admin", "login")).unwrap();
        assert!(verify_or_err(db.conn()).is_ok());

        db.conn()
            .execute("UPDATE audit_log SET actor = 'someone_else' WHERE seq = 1", [])
            .unwrap();
        assert!(verify_or_err(db.conn()).is_err());
    }

    #[test]
    fn list_returns_newest_first() {
        let db = Db::open_in_memory().unwrap();
        append(db.conn(), entry("a", "first")).unwrap();
        append(db.conn(), entry("b", "second")).unwrap();

        let entries = list(db.conn(), None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "second");
        assert_eq!(entries[1].action, "first");
    }
}
