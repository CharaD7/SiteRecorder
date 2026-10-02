//! Standard on-disk locations (Wave 1.3).
//!
//! Everything the app persists lives under one app data directory so it can be
//! backed up, encrypted at the filesystem level, or wiped as a unit.

use crate::{Db, Result};
use std::path::PathBuf;

/// Root directory for persistent application data.
///
/// Uses the platform data dir (`~/.local/share`, `~/Library/Application Support`,
/// `%APPDATA%`) rather than the config dir — scan output and findings are data,
/// not configuration.
pub fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("siterecorder")
}

/// Path of the primary SQLite database.
pub fn database_path() -> PathBuf {
    data_dir().join("siterecorder.db")
}

/// Path of the encrypted credential vault.
pub fn vault_path() -> PathBuf {
    data_dir().join("credentials.vault")
}

/// Path of the auth-profile database.
pub fn auth_db_path() -> PathBuf {
    data_dir().join("auth.db")
}

/// Directory holding exported recordings.
pub fn recordings_dir() -> PathBuf {
    data_dir().join("recordings")
}

/// Directory holding persisted scan reports.
pub fn scans_dir() -> PathBuf {
    data_dir().join("scans")
}

/// Open (creating and migrating as needed) the primary database.
pub fn open_database() -> Result<Db> {
    Db::open(&database_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_paths_share_one_root() {
        let root = data_dir();
        for p in [database_path(), vault_path(), auth_db_path()] {
            assert_eq!(p.parent().unwrap(), root.as_path());
        }
        assert_eq!(recordings_dir().parent().unwrap(), root.as_path());
        assert_eq!(scans_dir().parent().unwrap(), root.as_path());
    }

    #[test]
    fn paths_are_distinct() {
        let paths = [database_path(), vault_path(), auth_db_path()];
        for (i, a) in paths.iter().enumerate() {
            for b in paths.iter().skip(i + 1) {
                assert_ne!(a, b, "storage paths must not collide");
            }
        }
    }

    #[test]
    fn root_ends_with_app_name() {
        assert!(
            data_dir().to_string_lossy().ends_with("siterecorder"),
            "unexpected data dir: {}",
            data_dir().display()
        );
    }
}
