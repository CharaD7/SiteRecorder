//! Shared SQLite persistence layer.
//!
//! Provides a connection wrapper with schema versioning and migrations, plus the
//! domain models that every other crate converges on. Replaces the ad-hoc
//! `init_db()` pattern previously duplicated across five crates.

pub mod audit;
pub mod crypto;
pub mod models;
pub mod paths;
pub mod users;

use rusqlite::Connection;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("migration failed: {0}")]
    Migration(String),
    #[error("decryption error: {0}")]
    DecryptionError(String),
    #[error("record not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, DbError>;

/// Current schema version. Bump when adding a migration.
pub const SCHEMA_VERSION: i64 = 3;

/// A single forward-only schema change.
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

/// Ordered migrations. Never edit an applied migration; add a new one.
const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial_schema",
    sql: include_str!("schema.sql"),
},
Migration {
    version: 2,
    name: "policies",
    sql: r#"
        CREATE TABLE IF NOT EXISTS policies (
            id          TEXT PRIMARY KEY,
            code        TEXT NOT NULL UNIQUE,
            title       TEXT NOT NULL,
            summary     TEXT NOT NULL DEFAULT '',
            status      TEXT NOT NULL DEFAULT 'draft',
            version     INTEGER NOT NULL DEFAULT 1,
            cadence     TEXT NOT NULL DEFAULT 'annual',
            owner       TEXT,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            next_review TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS policy_acknowledgments (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id        TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
            policy_version   INTEGER NOT NULL,
            user_id          TEXT NOT NULL,
            acknowledged_at  TEXT NOT NULL,
            UNIQUE (policy_id, policy_version, user_id)
        );

        CREATE TABLE IF NOT EXISTS policy_exceptions (
            id           TEXT PRIMARY KEY,
            policy_id    TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
            justification TEXT NOT NULL,
            approved_by  TEXT,
            expires_at   TEXT,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
        CREATE INDEX IF NOT EXISTS idx_policy_ack_policy ON policy_acknowledgments(policy_id);
    "#,
},
Migration {
    version: 3,
    name: "vendor_risk_and_training",
    sql: r#"
        CREATE TABLE IF NOT EXISTS vendors (
            id            TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            category      TEXT NOT NULL DEFAULT 'other',
            tier          TEXT NOT NULL DEFAULT 'medium',
            data_access   TEXT NOT NULL DEFAULT 'none',
            status        TEXT NOT NULL DEFAULT 'under_review',
            owner         TEXT,
            questionnaire TEXT NOT NULL DEFAULT '{}',
            score         REAL,
            notes         TEXT NOT NULL DEFAULT '',
            reviewed_at   TEXT,
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL,
            user_id       TEXT REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS training_modules (
            id            TEXT PRIMARY KEY,
            title         TEXT NOT NULL,
            description   TEXT NOT NULL DEFAULT '',
            modality      TEXT NOT NULL DEFAULT 'document',
            duration_mins INTEGER NOT NULL DEFAULT 15,
            mandatory     INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS training_assignments (
            id            TEXT PRIMARY KEY,
            module_id     TEXT NOT NULL REFERENCES training_modules(id) ON DELETE CASCADE,
            user_id       TEXT NOT NULL,
            assigned_at   TEXT NOT NULL,
            due_at        TEXT,
            completed_at  TEXT,
            UNIQUE (module_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS phishing_campaigns (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            template_url TEXT,
            audience     TEXT NOT NULL DEFAULT '',
            launched_at  TEXT,
            launched_by  TEXT,
            sent_count   INTEGER NOT NULL DEFAULT 0,
            clicked      INTEGER NOT NULL DEFAULT 0,
            submitted    INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_vendors_tier ON vendors(tier);
        CREATE INDEX IF NOT EXISTS idx_training_assign_due ON training_assignments(due_at);
    "#,
}];

/// Connection wrapper owning schema lifecycle.
pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open (creating if needed) a file-backed database and migrate it.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an in-memory database and migrate it. Used by tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        // Enforce FK constraints; SQLite disables them by default, which is how
        // the auth-profiles FK test could fail unexpectedly in other setups.
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let db = Db { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Apply any migrations not yet recorded in `schema_version`.
    fn migrate(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version    INTEGER PRIMARY KEY,
                name       TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )",
            [],
        )?;

        let current: i64 = self
            .conn
            .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);

        for migration in MIGRATIONS.iter().filter(|m| m.version > current) {
            self.conn.execute_batch(migration.sql).map_err(|e| {
                DbError::Migration(format!("v{} ({}): {}", migration.version, migration.name, e))
            })?;
            self.conn.execute(
                "INSERT INTO schema_version (version, name, applied_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    migration.version,
                    migration.name,
                    chrono::Utc::now().to_rfc3339()
                ],
            )?;
        }

        Ok(())
    }

    /// Schema version currently applied.
    pub fn version(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |r| {
                r.get(0)
            })
            .unwrap_or(0))
    }

    /// Borrow the underlying connection for crate-specific repositories.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_initial_migration() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn creates_expected_tables() {
        let db = Db::open_in_memory().unwrap();
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN
                 ('users','assets','findings','scan_jobs','incidents','audit_log','schema_version',
                  'policies','policy_acknowledgments','policy_exceptions',
                  'vendors','training_modules','training_assignments','phishing_campaigns')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 14, "all tables from every migration must exist");
    }

    #[test]
    fn migration_is_idempotent_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.db");

        {
            let db = Db::open(&path).unwrap();
            assert_eq!(db.version().unwrap(), SCHEMA_VERSION);
        }
        // Reopening must not re-apply or duplicate rows.
        let db = Db::open(&path).unwrap();
        assert_eq!(db.version().unwrap(), SCHEMA_VERSION);
        let applied: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            applied, SCHEMA_VERSION,
            "reopening must not re-apply migrations, so the count equals the version"
        );
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let db = Db::open_in_memory().unwrap();

        // NULL asset_id is allowed.
        let ok = db.conn().execute(
            "INSERT INTO findings (id, title, severity, category, created_at, updated_at)
             VALUES ('f1', 'x', 'HIGH', 'web', 'now', 'now')",
            [],
        );
        assert!(ok.is_ok());

        // A dangling asset_id must be rejected.
        let bad = db.conn().execute(
            "INSERT INTO findings (id, title, severity, category, created_at, updated_at, asset_id)
             VALUES ('f2', 'x', 'HIGH', 'web', 'now', 'now', 'does-not-exist')",
            [],
        );
        assert!(bad.is_err(), "FK constraint should reject unknown asset_id");
    }

    #[test]
    fn deleting_asset_cascades_to_findings() {
        let db = Db::open_in_memory().unwrap();
        db.conn().execute(
            "INSERT INTO assets (id, name, asset_type, created_at, updated_at)
             VALUES ('a1', 'prod', 'domain', 'now', 'now')",
            [],
        ).unwrap();
        db.conn().execute(
            "INSERT INTO findings (id, title, severity, category, created_at, updated_at, asset_id)
             VALUES ('f1', 'x', 'HIGH', 'web', 'now', 'now', 'a1')",
            [],
        ).unwrap();

        db.conn().execute("DELETE FROM assets WHERE id = 'a1'", []).unwrap();

        let remaining: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM findings WHERE asset_id = 'a1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 0, "findings should cascade with their asset");
    }
}