//! User identity and the single-operator bootstrap (Wave 1.4).
//!
//! D0.1 requires least privilege and resolvable audit actors. Whether
//! "enterprise" means one operator on a hardened workstation or a team over a
//! shared backend is still open, so this layer is deliberately minimal: a
//! `users` table, a repository, and a bootstrap that guarantees at least one
//! resolvable operator exists. Adding real multi-user auth later is a change
//! *here*, not a retrofit across every crate.

use crate::models::{Role, User};
use crate::{DbError, Result};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Request to create a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub display_name: Option<String>,
    pub role: Role,
}

fn map_err(e: rusqlite::Error) -> DbError {
    DbError::Sqlite(e)
}

fn insert(conn: &rusqlite::Connection, user: &User) -> Result<()> {
    conn.execute(
        "INSERT INTO users (id, username, display_name, role, created_at, disabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            user.id,
            user.username,
            user.display_name,
            user.role.to_string(),
            user.created_at,
            user.disabled as i64,
        ],
    )
    .map_err(map_err)?;
    Ok(())
}

/// Create a user, rejecting a duplicate username.
pub fn create(conn: &rusqlite::Connection, new: NewUser) -> Result<User> {
    if new.username.trim().is_empty() {
        return Err(DbError::Migration("username must not be empty".into()));
    }

    if get_by_username(conn, &new.username)?.is_some() {
        return Err(DbError::Migration(format!(
            "username already exists: {}",
            new.username
        )));
    }

    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username: new.username,
        display_name: new.display_name,
        role: new.role,
        created_at: chrono::Utc::now().to_rfc3339(),
        disabled: false,
    };
    insert(conn, &user)?;
    Ok(user)
}

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let role_str: String = row.get(3)?;
    // An unrecognised role in the DB is a data-integrity problem, not a
    // transient read failure, so surface it explicitly rather than defaulting.
    let role = role_str.parse::<Role>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            format!("unknown role stored in users.role: {}", role_str).into(),
        )
    })?;

    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        role,
        created_at: row.get(4)?,
        disabled: row.get::<_, i64>(5)? != 0,
    })
}

const SELECT_COLS: &str = "id, username, display_name, role, created_at, disabled";

pub fn get(conn: &rusqlite::Connection, id: &str) -> Result<Option<User>> {
    let user = conn
        .query_row(
            &format!("SELECT {} FROM users WHERE id = ?1", SELECT_COLS),
            params![id],
            row_to_user,
        )
        .optional()
        .map_err(map_err)?;
    Ok(user)
}

pub fn get_by_username(conn: &rusqlite::Connection, username: &str) -> Result<Option<User>> {
    let user = conn
        .query_row(
            &format!("SELECT {} FROM users WHERE username = ?1", SELECT_COLS),
            params![username],
            row_to_user,
        )
        .optional()
        .map_err(map_err)?;
    Ok(user)
}

pub fn list(conn: &rusqlite::Connection) -> Result<Vec<User>> {
    let mut stmt = conn
        .prepare(&format!("SELECT {} FROM users ORDER BY created_at ASC", SELECT_COLS))
        .map_err(map_err)?;
    let rows = stmt
        .query_map([], row_to_user)
        .map_err(map_err)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_err)?;
    Ok(rows)
}

/// Grant a role. Least-privilege changes should be audited by the caller.
pub fn set_role(conn: &rusqlite::Connection, id: &str, role: Role) -> Result<()> {
    let changed = conn
        .execute(
            "UPDATE users SET role = ?2 WHERE id = ?1",
            params![id, role.to_string()],
        )
        .map_err(map_err)?;
    if changed == 0 {
        return Err(DbError::NotFound(id.to_string()));
    }
    Ok(())
}

pub fn set_disabled(conn: &rusqlite::Connection, id: &str, disabled: bool) -> Result<()> {
    let changed = conn
        .execute(
            "UPDATE users SET disabled = ?2 WHERE id = ?1",
            params![id, disabled as i64],
        )
        .map_err(map_err)?;
    if changed == 0 {
        return Err(DbError::NotFound(id.to_string()));
    }
    Ok(())
}

/// Ensure at least one operator exists and return it.
///
/// Audit entries reference actors by id, so an installation with no users could
/// not attribute any action. This creates a default `local-operator` on first
/// run and is a no-op thereafter.
pub fn ensure_default_operator(conn: &rusqlite::Connection) -> Result<User> {
    if let Some(existing) = list(conn)?.into_iter().find(|u| !u.disabled) {
        return Ok(existing);
    }

    create(
        conn,
        NewUser {
            username: "local-operator".to_string(),
            display_name: Some("Local Operator".to_string()),
            role: Role::Operator,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    #[test]
    fn bootstrap_creates_one_operator() {
        let db = Db::open_in_memory().unwrap();
        let user = ensure_default_operator(db.conn()).unwrap();
        assert_eq!(user.role, Role::Operator);
        assert_eq!(user.username, "local-operator");
        assert_eq!(list(db.conn()).unwrap().len(), 1);
    }

    #[test]
    fn bootstrap_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let first = ensure_default_operator(db.conn()).unwrap();
        let second = ensure_default_operator(db.conn()).unwrap();
        assert_eq!(first.id, second.id, "must not create a second operator");
        assert_eq!(list(db.conn()).unwrap().len(), 1);
    }

    #[test]
    fn create_and_fetch_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let created = create(
            db.conn(),
            NewUser {
                username: "alice".into(),
                display_name: Some("Alice".into()),
                role: Role::Auditor,
            },
        )
        .unwrap();

        let fetched = get(db.conn(), &created.id).unwrap().unwrap();
        assert_eq!(fetched.username, "alice");
        assert_eq!(fetched.role, Role::Auditor);
        assert!(!fetched.disabled);
    }

    #[test]
    fn duplicate_username_is_rejected() {
        let db = Db::open_in_memory().unwrap();
        let new = NewUser {
            username: "alice".into(),
            display_name: None,
            role: Role::Viewer,
        };
        create(db.conn(), new.clone()).unwrap();
        assert!(create(db.conn(), new).is_err(), "duplicate username must fail");
    }

    #[test]
    fn empty_username_is_rejected() {
        let db = Db::open_in_memory().unwrap();
        let result = create(
            db.conn(),
            NewUser {
                username: "   ".into(),
                display_name: None,
                role: Role::Viewer,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn role_can_be_changed() {
        let db = Db::open_in_memory().unwrap();
        let user = ensure_default_operator(db.conn()).unwrap();
        set_role(db.conn(), &user.id, Role::Admin).unwrap();
        assert_eq!(get(db.conn(), &user.id).unwrap().unwrap().role, Role::Admin);
    }

    #[test]
    fn unknown_user_updates_are_rejected() {
        let db = Db::open_in_memory().unwrap();
        assert!(set_role(db.conn(), "nope", Role::Admin).is_err());
        assert!(set_disabled(db.conn(), "nope", true).is_err());
    }

    #[test]
    fn disabled_flag_persists() {
        let db = Db::open_in_memory().unwrap();
        let user = ensure_default_operator(db.conn()).unwrap();
        set_disabled(db.conn(), &user.id, true).unwrap();
        assert!(get(db.conn(), &user.id).unwrap().unwrap().disabled);
    }
}
