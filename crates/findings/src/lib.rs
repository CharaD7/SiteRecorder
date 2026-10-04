//! Finding storage and lifecycle (Wave 2.2).
//!
//! This is where scan output stops being a transient JSON file and becomes a
//! queryable record. §5 (White Team) cannot be real until this exists, because
//! every compliance figure, risk score and MTTD metric is an aggregate over
//! stored findings.

pub mod attack;
pub mod compliance;
pub mod ingest;
pub mod metrics;
pub mod policies;
pub mod risk;
pub mod training;
pub mod vendors;

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
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
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
            rusqlite::Error::FromSqlConversionFailure(14, rusqlite::types::Type::Text, Box::new(e))
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
    let rows = stmt
        .query_map(refs.as_slice(), row_to_finding)
        .map_err(map_err)?;

    Ok(rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_err)?)
}

pub fn count(conn: &rusqlite::Connection, filter: &FindingFilter) -> Result<i64> {
    let (where_sql, binds) = build_filter(filter);
    let sql = format!("SELECT COUNT(*) FROM findings{}", where_sql);

    let mut stmt = conn.prepare(&sql).map_err(map_err)?;
    let refs: Vec<&dyn ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let n = stmt
        .query_row(refs.as_slice(), |r| r.get(0))
        .map_err(map_err)?;
    Ok(n)
}

/// Transition a finding's status, stamping `updated_at`.
pub fn set_status(conn: &rusqlite::Connection, id: &str, status: FindingStatus) -> Result<()> {
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
        .prepare(
            "SELECT id, cwe_id, severity, status, created_at, updated_at, asset_id FROM findings",
        )
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
        let (id, cwe_id, severity, status, created_at, updated_at, asset_id) =
            row.map_err(map_err)?;
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

/// Build the §5.2 risk register from stored findings.
///
/// Asset criticality is joined in so impact is measured where known, and
/// defaulted (and disclosed) where it is not.
pub fn risk_register(conn: &rusqlite::Connection) -> Result<risk::RiskRegister> {
    let mut stmt = conn
        .prepare(
            "SELECT f.id, f.title, f.severity, f.category, f.status, f.asset_id, a.criticality
             FROM findings f
             LEFT JOIN assets a ON a.id = f.asset_id",
        )
        .map_err(map_err)?;

    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
            ))
        })
        .map_err(map_err)?;

    let mut inputs = Vec::new();
    for row in rows {
        let (id, title, severity, category, status, asset_id, criticality) =
            row.map_err(map_err)?;
        inputs.push(risk::RiskInput {
            finding_id: id,
            title,
            severity,
            category,
            asset_id,
            asset_criticality: criticality,
            open: !matches!(
                status.as_str(),
                "false_positive" | "accepted" | "remediated"
            ),
        });
    }

    Ok(risk::build_register(chrono::Utc::now(), &inputs))
}

/// Ensure the starter policy library exists. Idempotent.
pub fn seed_policies(conn: &rusqlite::Connection) -> Result<()> {
    for p in policies::starter_policies() {
        conn.execute(
            "INSERT OR IGNORE INTO policies
             (id, code, title, summary, status, version, cadence, owner, created_at, updated_at, next_review)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                p.id, p.code, p.title, p.summary, p.status.as_str(), p.version as i64,
                p.cadence.as_str(), p.owner, p.created_at, p.updated_at, p.next_review,
            ],
        )
        .map_err(map_err)?;
    }
    Ok(())
}

fn policy_from_row(row: &Row<'_>) -> rusqlite::Result<policies::Policy> {
    Ok(policies::Policy {
        id: row.get(0)?,
        code: row.get(1)?,
        title: row.get(2)?,
        summary: row.get(3)?,
        status: match row.get::<_, String>(4)?.as_str() {
            "active" => policies::PolicyStatus::Active,
            "retired" => policies::PolicyStatus::Retired,
            _ => policies::PolicyStatus::Draft,
        },
        version: row.get::<_, i64>(5)? as u32,
        cadence: match row.get::<_, String>(6)?.as_str() {
            "quarterly" => policies::ReviewCadence::Quarterly,
            "semi_annual" => policies::ReviewCadence::SemiAnnual,
            "biennial" => policies::ReviewCadence::Biennial,
            _ => policies::ReviewCadence::Annual,
        },
        owner: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        next_review: row.get(10)?,
    })
}

/// §5.3 policy library, seeding starters on first use.
pub fn policy_library(
    conn: &rusqlite::Connection,
    target: Option<usize>,
) -> Result<policies::PolicyLibrary> {
    seed_policies(conn)?;

    let mut stmt = conn
        .prepare(
            "SELECT id, code, title, summary, status, version, cadence, owner,
                    created_at, updated_at, next_review
             FROM policies ORDER BY code",
        )
        .map_err(map_err)?;
    let rows = stmt.query_map([], policy_from_row).map_err(map_err)?;
    let all: Vec<policies::Policy> = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_err)?;

    Ok(policies::build_library(
        chrono::Utc::now(),
        all,
        target.unwrap_or(policies::TARGET_LIBRARY_SIZE),
    ))
}

/// Record that a user acknowledged a specific policy version.
pub fn acknowledge_policy(
    conn: &rusqlite::Connection,
    policy_id: &str,
    user_id: &str,
) -> Result<()> {
    let version: i64 = conn
        .query_row(
            "SELECT version FROM policies WHERE id = ?1",
            params![policy_id],
            |r| r.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DbError::NotFound(policy_id.to_string()),
            other => DbError::Sqlite(other),
        })?;

    conn.execute(
        "INSERT OR IGNORE INTO policy_acknowledgments (policy_id, policy_version, user_id, acknowledged_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![policy_id, version, user_id, chrono::Utc::now().to_rfc3339()],
    )
    .map_err(map_err)?;
    Ok(())
}

/// Acknowledgment coverage for a policy: how many distinct users, at which version.
pub fn acknowledgment_coverage(
    conn: &rusqlite::Connection,
    policy_id: &str,
) -> Result<(usize, u32)> {
    let version: u32 = conn
        .query_row(
            "SELECT version FROM policies WHERE id = ?1",
            params![policy_id],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as u32)
        .unwrap_or(0);

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT user_id) FROM policy_acknowledgments
             WHERE policy_id = ?1 AND policy_version = ?2",
            params![policy_id, version as i64],
            |r| r.get(0),
        )
        .unwrap_or(0);

    Ok((count as usize, version))
}

/// §5.4 vendor register from stored vendors.
pub fn vendor_register(conn: &rusqlite::Connection) -> Result<vendors::VendorRegister> {
    let mut stmt = conn
        .prepare(
            "SELECT id, name, category, data_access, criticality, status, owner,
                    questionnaire, notes, created_at, updated_at
             FROM vendors ORDER BY name",
        )
        .map_err(map_err)?;

    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, String>(10)?,
            ))
        })
        .map_err(map_err)?;

    let mut all = Vec::new();
    for row in rows {
        let (id, name, category, access, criticality, status, owner, q, notes, created, updated) =
            row.map_err(map_err)?;

        let question: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&q).unwrap_or_default();

        all.push(vendors::Vendor {
            id,
            name,
            category,
            data_access: vendors::DataAccess::from_str(&access)
                .ok_or_else(|| DbError::Migration(format!("unknown data_access: {}", access)))?,
            criticality: vendors::Tier::from_str(&criticality).ok_or_else(|| {
                DbError::Migration(format!("unknown criticality: {}", criticality))
            })?,
            status: match status.as_str() {
                "under_review" => vendors::AssessmentStatus::UnderReview,
                "complete" => vendors::AssessmentStatus::Complete,
                "expired" => vendors::AssessmentStatus::Expired,
                _ => vendors::AssessmentStatus::NotStarted,
            },
            owner,
            questionnaire: question,
            notes,
            created_at: created,
            updated_at: updated,
        });
    }

    let mut reg = vendors::build_register(all);
    reg.notes.push(format!(
        "{} capability(s) are not implemented; see unavailable_capabilities().",
        vendors::unavailable_capabilities().len()
    ));
    Ok(reg)
}

/// Seed the operator-written training modules. Idempotent.
pub fn seed_training_modules(conn: &rusqlite::Connection) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let starters: Vec<(&str, &str, &str, &str, u32, bool)> = vec![
        (
            "tm_phishing",
            "Recognising Phishing",
            "Spot phishing lures and report them.",
            "document",
            20,
            true,
        ),
        (
            "tm_passwords",
            "Password Hygiene",
            "Password managers, length, and reuse.",
            "document",
            15,
            true,
        ),
        (
            "tm_social",
            "Social Engineering",
            "Pretexting, vishing and tailgating.",
            "document",
            20,
            false,
        ),
        (
            "tm_reporting",
            "Reporting an Incident",
            "What to report and to whom, fast.",
            "document",
            10,
            true,
        ),
    ];
    for (id, title, desc, modality, mins, mandatory) in starters {
        conn.execute(
            "INSERT OR IGNORE INTO training_modules
             (id, title, description, modality, duration_mins, mandatory, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?7)",
            params![
                id,
                title,
                desc,
                modality,
                mins as i64,
                mandatory as i64,
                now
            ],
        )
        .map_err(map_err)?;
    }
    Ok(())
}

/// §5.5 training report from stored modules, assignments and campaigns.
pub fn training_report(conn: &rusqlite::Connection) -> Result<training::TrainingReport> {
    seed_training_modules(conn)?;

    let mut modules = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id, title, description, modality, duration_mins, mandatory
                 FROM training_modules ORDER BY title",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(training::Module {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    description: r.get(2)?,
                    modality: match r.get::<_, String>(3)?.as_str() {
                        "video" => training::Modality::Video,
                        "live_session" => training::Modality::LiveSession,
                        "phishing_simulation" => training::Modality::PhishingSimulation,
                        _ => training::Modality::Document,
                    },
                    duration_mins: r.get::<_, i64>(4)? as u32,
                    mandatory: r.get::<_, i64>(5)? != 0,
                })
            })
            .map_err(map_err)?;
        for row in rows {
            modules.push(row.map_err(map_err)?);
        }
    }

    let mut assignments = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id, module_id, user_id, assigned_at, due_at, completed_at
                 FROM training_assignments ORDER BY assigned_at DESC",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(training::Assignment {
                    id: r.get(0)?,
                    module_id: r.get(1)?,
                    user_id: r.get(2)?,
                    assigned_at: r.get(3)?,
                    due_at: r.get(4)?,
                    completed_at: r.get(5)?,
                })
            })
            .map_err(map_err)?;
        for row in rows {
            assignments.push(row.map_err(map_err)?);
        }
    }

    let mut campaigns = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT id, name, template_url, audience, launched_at, sent_count, clicked, submitted
                 FROM phishing_campaigns ORDER BY created_at DESC",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(training::PhishingCampaign {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    template_url: r.get(2)?,
                    audience: r.get(3)?,
                    launched_at: r.get(4)?,
                    sent_count: r.get::<_, i64>(5)? as u64,
                    clicked: r.get::<_, i64>(6)? as u64,
                    submitted: r.get::<_, i64>(7)? as u64,
                })
            })
            .map_err(map_err)?;
        for row in rows {
            campaigns.push(row.map_err(map_err)?);
        }
    }

    Ok(training::build_report(
        &chrono::Utc::now().to_rfc3339(),
        modules,
        assignments,
        campaigns,
    ))
}

pub fn by_category(conn: &rusqlite::Connection) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn
        .prepare("SELECT category, COUNT(*) FROM findings GROUP BY category ORDER BY COUNT(*) DESC")
        .map_err(map_err)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(map_err)?;
    Ok(rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_err)?)
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
