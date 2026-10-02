CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT,
    role         TEXT NOT NULL DEFAULT 'operator',
    created_at   TEXT NOT NULL,
    disabled     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS assets (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    asset_type       TEXT NOT NULL,
    url              TEXT,
    ip_addresses     TEXT NOT NULL DEFAULT '[]',
    tags             TEXT NOT NULL DEFAULT '[]',
    owner            TEXT,
    environment      TEXT NOT NULL DEFAULT 'unknown',
    criticality      TEXT NOT NULL DEFAULT 'medium',
    auth_profile_ids TEXT NOT NULL DEFAULT '[]',
    compliance_scope TEXT NOT NULL DEFAULT '[]',
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    last_scan        TEXT,
    risk_score       REAL,
    user_id          TEXT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id               TEXT PRIMARY KEY,
    scan_id          TEXT,
    asset_id         TEXT REFERENCES assets(id) ON DELETE CASCADE,
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'new',
    category         TEXT NOT NULL,
    cwe_id           TEXT,
    cve_ids          TEXT NOT NULL DEFAULT '[]',
    cvss_score       REAL,
    description      TEXT NOT NULL DEFAULT '',
    remediation      TEXT NOT NULL DEFAULT '',
    references_json  TEXT NOT NULL DEFAULT '[]',
    mitre_techniques TEXT NOT NULL DEFAULT '[]',
    evidence         TEXT NOT NULL DEFAULT '[]',
    assignee         TEXT,
    due_date         TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    user_id          TEXT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id             TEXT PRIMARY KEY,
    module         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    targets        TEXT NOT NULL DEFAULT '[]',
    config         TEXT NOT NULL DEFAULT '{}',
    progress       REAL NOT NULL DEFAULT 0.0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    started_at     TEXT,
    completed_at   TEXT,
    created_at     TEXT NOT NULL,
    user_id        TEXT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new',
    category    TEXT NOT NULL,
    team        TEXT,
    impact      TEXT NOT NULL DEFAULT '',
    assignee    TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    closed_at   TEXT,
    user_id     TEXT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT NOT NULL UNIQUE,
    timestamp  TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT,
    details    TEXT,
    ip_address TEXT,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
