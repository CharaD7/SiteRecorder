//! Finding storage and lifecycle (Wave 2.2).
//!
//! This is where scan output stops being a transient JSON file and becomes a
//! queryable record. §5 (White Team) cannot be real until this exists, because
//! every compliance figure, risk score and MTTD metric is an aggregate over
//! stored findings.

pub mod attack;
pub mod compliance;
pub mod metrics;
pub mod ingest;

use db::models::{AssetType, Finding, FindingStatus, Severity};
use db::{DbError, Result};
use rusqlite::{params, OptionalExtension, Row, ToSql};
use serde::{Deserialize, Serialize};

/// Filter for listing findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingFilter {
    pub severity: Option<Severity>,
    pub status: Option<FindingStatus>,
    pub category: Option<String>,
    pub asset_id: Option<String>,
    pub scan_id: Option<String>,
    pub limit: Option<i64>,
}

fn map_err(e: rusqlite::Error) -> DbError {
    DbError::Sqlite(e)
}

const COLS: &str = "id, scan_id, asset_id, title, severity, status, category, cwe_id, cve_ids, \
     cvss_score, description, remediation, references_json, mitre_techniques, evidence, \
     assignee, due_date, created_at, updated_at, user_id";

fn row_to_finding(row: &Row<'_>) -> rusqlite::Result<Finding> {
    let json_to_vec = |raw: String| -> rusqlite::Result<Vec<String>> {
        serde_json::from_str(&raw).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })
    };

    Ok(Finding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        asset_id: row.get(2)?,
        title: row.get(3)?,
        severity: parse_severity(&row.get::<_, String>(4)?)?,
        status: parse_status(&row.get::<_, String>(5)?)?,
        category: row.get(6)?,
        cwe_id: row.get(7)?,
        cve_ids: json_to_vec(row.get(8)?)?,
        cvss_score: row.get(9)?,
        description: row.get(10)?,
        remediation: row.get(11)?,
        references: json_to_vec(row.get(12)?)?,
        mitre_techniques: json_to_vec(row.get(13)?)?,
        evidence: serde_json::from_str(&row.get::<_, String>(14)?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                14,
                rusqlite::types::Type::Text,
                Box::new(e),
            )
        })?,
        assignee: row.get(15)?,
        due_date: row.get(16)?,
        created_at: row.get(17)?,
        updated_at: row.get(18)?,
        user_id: row.get(19)?,
    })
}

/// Unknown values in the DB surface as errors rather than silently defaulting;
/// a mis-ranked finding is worse than a failed read.
fn parse_severity(raw: &str) -> rusqlite::Result<Severity> {
    raw.parse::<Severity>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            format!("unknown severity in findings.severity: {}", raw).into(),
        )
    })
}

fn parse_status(raw: &str) -> rusqlite::Result<FindingStatus> {
    raw.parse::<FindingStatus>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            format!("unknown status in findings.status: {}", raw).into(),
        )
    })
}

/// Insert a finding, replacing any existing row with the same id.
pub fn insert(conn: &rusqlite::Connection, finding: &Finding) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO findings (
            id, scan_id, asset_id, title, severity, status, category, cwe_id, cve_ids,
            cvss_score, description, remediation, references_json, mitre_techniques, evidence,
            assignee, due_date, created_at, updated_at, user_id
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        params![
            finding.id,
            finding.scan_id,
            finding.asset_id,
            finding.title,
            finding.severity.to_string(),
            finding.status.to_string(),
            finding.category,
            finding.cwe_id,
            serde_json::to_string(&finding.cve_ids)?,
            finding.cvss_score,
            finding.description,
            finding.remediation,
            serde_json::to_string(&finding.references)?,
            serde_json::to_string(&finding.mitre_techniques)?,
            serde_json::to_string(&finding.evidence)?,
            finding.assignee,
            finding.due_date,
            finding.created_at,
            finding.updated_at,
            finding.user_id,
        ],
    )
    .map_err(map_err)?;
    Ok(())
}

/// Insert many findings in one transaction.
pub fn insert_many(conn: &rusqlite::Connection, items: &[Finding]) -> Result<usize> {
    if items.is_empty() {
        return Ok(0);
    }
    conn.execute_batch("BEGIN").map_err(map_err)?;
    let result = (|| -> Result<()> {
        for f in items {
            insert(conn, f)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT").map_err(map_err)?;
            Ok(items.len())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

pub fn get(conn: &rusqlite::Connection, id: &str) -> Result<Option<Finding>> {
    Ok(conn
        .query_row(
            &format!("SELECT {} FROM findings WHERE id = ?1", COLS),
            params![id],
            row_to_finding,
        )
        .optional()
        .map_err(map_err)?)
}

/// Build the WHERE clause for a filter.
fn build_filter(filter: &FindingFilter) -> (String, Vec<Box<dyn ToSql>>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<Box<dyn ToSql>> = Vec::new();

    if let Some(s) = filter.severity {
        clauses.push("severity = ?".to_string());
        binds.push(Box::new(s.to_string()));
    }
    if let Some(s) = filter.status {
        clauses.push("status = ?".to_string());
        binds.push(Box::new(s.to_string()));
    }
    if let Some(ref c) = filter.category {
        clauses.push("category = ?".to_string());
        binds.push(Box::new(c.clone()));
    }
    if let Some(ref a) = filter.asset_id {
        clauses.push("asset_id = ?".to_string());
        binds.push(Box::new(a.clone()));
    }
    if let Some(ref s) = filter.scan_id {
        clauses.push("scan_id = ?".to_string());
        binds.push(Box::new(s.clone()));
    }

    let sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    (sql, binds)
}

/// List findings newest-first with an optional filter.
pub fn list(conn: &rusqlite::Connection, filter: &FindingFilter) -> Result<Vec<Finding>> {
    let (where_sql, binds) = build_filter(filter);
    let limit = filter.limit.unwrap_or(1000);

    let sql = format!(
        "SELECT {} FROM findings{} ORDER BY created_at DESC, id ASC LIMIT {}",
        COLS, where_sql, limit
    );

    let mut stmt = conn.prepare(&sql).map_err(map_err)?;
    let refs: Vec<&dyn ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(refs.as_slice(), row_to_finding).map_err(map_err)?;

    Ok(rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)?)
}

pub fn count(conn: &rusqlite::Connection, filter: &FindingFilter) -> Result<i64> {
    let (where_sql, binds) = build_filter(filter);
    let sql = format!("SELECT COUNT(*) FROM findings{}", where_sql);

    let mut stmt = conn.prepare(&sql).map_err(map_err)?;
    let refs: Vec<&dyn ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let n = stmt.query_row(refs.as_slice(), |r| r.get(0)).map_err(map_err)?;
    Ok(n)
}

/// Transition a finding's status, stamping `updated_at`.
pub fn set_status(
    conn: &rusqlite::Connection,
    id: &str,
    status: FindingStatus,
) -> Result<()> {
    let changed = conn
        .execute(
            "UPDATE findings SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, status.to_string(), chrono::Utc::now().to_rfc3339()],
        )
        .map_err(map_err)?;
    if changed == 0 {
        return Err(DbError::NotFound(id.to_string()));
    }
    Ok(())
}

pub fn set_assignee(conn: &rusqlite::Connection, id: &str, assignee: Option<&str>) -> Result<()> {
    let changed = conn
        .execute(
            "UPDATE findings SET assignee = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, assignee, chrono::Utc::now().to_rfc3339()],
        )
        .map_err(map_err)?;
    if changed == 0 {
        return Err(DbError::NotFound(id.to_string()));
    }
    Ok(())
}

pub fn delete(conn: &rusqlite::Connection, id: &str) -> Result<()> {
    let changed = conn
        .execute("DELETE FROM findings WHERE id = ?1", params![id])
        .map_err(map_err)?;
    if changed == 0 {
        return Err(DbError::NotFound(id.to_string()));
    }
    Ok(())
}

/// Counts by severity, used by dashboards and §5.6 metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    pub total: i64,
}

pub fn severity_breakdown(conn: &rusqlite::Connection) -> Result<SeverityBreakdown> {
    let mut counts = SeverityBreakdown::default();
    let mut stmt = conn
        .prepare("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
        .map_err(map_err)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(map_err)?;

    for row in rows {
        let (sev, n) = row.map_err(map_err)?;
        match sev.as_str() {
            "CRITICAL" => counts.critical = n,
            "HIGH" => counts.high = n,
            "MEDIUM" => counts.medium = n,
            "LOW" => counts.low = n,
            "INFO" => counts.info = n,
            other => {
                return Err(DbError::Migration(format!(
                    "unexpected severity '{}' in findings table",
                    other
                )))
            }
        }
    }
    counts.total = counts.critical + counts.high + counts.medium + counts.low + counts.info;
    Ok(counts)
}

/// Findings grouped by category.
/// ATT&CK coverage over stored findings.
///
/// Returns an incomplete report (no percentage) when any finding is unmapped,
/// rather than a number that looks measured but is not.
pub fn attack_coverage(conn: &rusqlite::Connection) -> Result<attack::CoverageReport> {
    let mut stmt = conn
        .prepare("SELECT mitre_techniques FROM findings")
        .map_err(map_err)?;

    let mut techniques: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut unmapped: Vec<String> = Vec::new();
    let mut total = 0usize;
    let _ = total;

    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(map_err)?;

    for row in rows {
        let raw = row.map_err(map_err)?;
        total += 1;
        let ids: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
        if ids.is_empty() {
            unmapped.push("one or more findings".to_string());
        } else {
            techniques.extend(ids);
        }
    }

    let complete = unmapped.is_empty();
    Ok(attack::CoverageReport {
        techniques: techniques.into_iter().collect(),
        unmapped,
        score: if complete { Some(100.0) } else { None },
        complete,
    })
}

/// Project stored findings into the shape the compliance mapper needs.
///
/// Findings marked false positive or accepted are excluded: they are recorded
/// workflow state, not current posture.
pub fn project_findings(conn: &rusqlite::Connection) -> Result<Vec<compliance::FindingProjection>> {
    let mut stmt = conn
        .prepare("SELECT id, cwe_id, severity, status, created_at, updated_at, asset_id FROM findings")
        .map_err(map_err)?;

    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
            ))
        })
        .map_err(map_err)?;

    let mut out = Vec::new();
    for row in rows {
        let (id, cwe_id, severity, status, created_at, updated_at, asset_id) = row.map_err(map_err)?;
        let counts = !matches!(status.as_str(), "false_positive" | "accepted");
        out.push(compliance::FindingProjection {
            id,
            cwe_id,
            severity,
            status,
            counts_against_posture: counts,
            created_at,
            updated_at,
            asset_id,
        });
    }
    Ok(out)
}

/// Evaluate every modelled framework against stored findings.
pub fn assess_all(conn: &rusqlite::Connection) -> Result<Vec<compliance::ControlAssessment>> {
    let projected = project_findings(conn)?;
    Ok(compliance::available_frameworks()
        .iter()
        .map(|fw| compliance::assess(fw, &projected))
        .collect())
}

/// §5.6 metrics over stored findings.
pub fn metrics_report(
    conn: &rusqlite::Connection,
    window_days: i64,
) -> Result<metrics::MetricsReport> {
    let projected = project_findings(conn)?;
    let now = chrono::Utc::now();
    let incidents = metrics::count_rows(conn, "incidents").unwrap_or(0);

    let mut report = metrics::build(now, &projected, by_category(conn)?);
    report.discovery_trend = metrics::discovery_trend(&projected, now, window_days);
    report.unavailable = metrics::unavailable_metrics(incidents);
    Ok(report)
}

pub fn by_category(conn: &rusqlite::Connection) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn
        .prepare("SELECT category, COUNT(*) FROM findings GROUP BY category ORDER BY COUNT(*) DESC")
        .map_err(map_err)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(map_err)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map_err)?)
}

/// Resolve an asset for a scanned URL, creating one if absent.
///
/// Every finding needs a target, so ingestion resolves-or-creates rather than
/// leaving `asset_id` NULL.
pub fn resolve_or_create_asset(
    conn: &rusqlite::Connection,
    url: &str,
    user_id: Option<&str>,
) -> Result<String> {
    if let Some(id) = find_asset_by_url(conn, url)? {
        return Ok(id);
    }

    let host = url::Url::parse(url)
        .map(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or(None);

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO assets (id, name, asset_type, url, ip_addresses, tags, environment,
                             criticality, auth_profile_ids, compliance_scope, metadata,
                             created_at, updated_at, user_id)
         VALUES (?1,?2,?3,?4,'[]','[]','unknown','medium','[]','[]','{}',?5,?5,?6)",
        params![
            id,
            host.clone().unwrap_or_else(|| url.to_string()),
            match (&host, url) {
                (Some(h), _) if h.chars().all(|c| c.is_ascii_digit() || c == '.') => {
                    AssetType::Ip.as_str()
                }
                (Some(_), _) => AssetType::Domain.as_str(),
                (None, _) => AssetType::App.as_str(),
            },
            url,
            now,
            user_id,
        ],
    )
    .map_err(map_err)?;

    Ok(id)
}

pub fn find_asset_by_url(conn: &rusqlite::Connection, url: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT id FROM assets WHERE url = ?1", params![url], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .map_err(map_err)?)
}
