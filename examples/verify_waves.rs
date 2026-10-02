//! One-off live verification of Waves 1-3. Not part of the test suite because
//! it touches the network and the real filesystem.

use db::audit;
use db::models::{Finding, FindingStatus, Severity};
use findings::{ingest, FindingFilter};
use network::NetworkScanner;
use os_pentest::OsPentest;
use std::net::TcpListener;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let mut failures = 0;
    let mut check = |name: &str, ok: bool, detail: String| {
        println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };

    // ---- Wave 1: real file-backed DB + audit chain across a restart ----
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verify.db");

    let user = {
        let database = db::Db::open(&path).unwrap();
        let u = db::users::ensure_default_operator(database.conn()).unwrap();
        audit::append(
            database.conn(),
            audit::NewAuditEntry {
                actor: u.id.clone(),
                action: "verify".into(),
                target: Some("https://example.com".into()),
                details: None,
                ip_address: None,
            },
        )
        .unwrap();
        audit::verify_integrity(database.conn()).unwrap().valid
    };
    check("wave1 audit chain valid", user, "chain intact after reopen path".into());

    // Tamper, confirm detection, on the real file.
    let tampered_detected = {
        let database = db::Db::open(&path).unwrap();
        database
            .conn()
            .execute("UPDATE audit_log SET action = 'forged'", [])
            .unwrap();
        !audit::verify_integrity(database.conn()).unwrap().valid
    };
    check("wave1 tamper detected", tampered_detected, "forged row rejected".into());

    // ---- Wave 1.6: encryption round trip ----
    let key = db::crypto::DataKey::from_secret(b"verify-secret");
    let sealed = db::crypto::seal(&key, "sensitive finding body", "f1").unwrap();
    let opened = db::crypto::open_value(&key, &sealed, "f1").unwrap();
    check(
        "wave1.6 encryption round trip",
        opened == "sensitive finding body" && !sealed.contains("sensitive"),
        "plaintext absent from blob".into(),
    );

    // ---- Wave 2: pipeline against a REAL scanner report ----
    let scanned = {
        let dir = tempfile::tempdir().unwrap();
        let cfg = scanner::ScanConfig::new("https://example.com")
            .unwrap()
            .with_output_dir(dir.path().to_path_buf());
        let mut s = scanner::VulnerabilityScanner::new(cfg).unwrap();
        match s.run_full_scan().await {
            Ok(r) => Some(r),
            Err(e) => {
                println!("  (scan failed: {e})");
                None
            }
        }
    };

    let last_report = scanned.clone();
    if let Some(report) = scanned {
        let database = db::Db::open_in_memory().unwrap();
        let outcome = ingest::ingest_report(database.conn(), &report, None).unwrap();
        println!(
            "  real scan: {} checks, {} findings ingested, {} skipped",
            outcome.checks_considered, outcome.findings_written, outcome.checks_skipped
        );
        check(
            "wave2 real report ingested",
            outcome.findings_written > 0,
            format!("{} rows written from a live scan", outcome.findings_written),
        );

        // Re-ingest must not duplicate.
        let before: i64 = database
            .conn()
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        ingest::ingest_report(database.conn(), &report, None).unwrap();
        let after: i64 = database
            .conn()
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        check(
            "wave2 re-ingest idempotent",
            before == after,
            format!("{before} rows before, {after} after"),
        );

        let breakdown = findings::severity_breakdown(database.conn()).unwrap();
        println!("  severity breakdown: {breakdown:?}");
        check(
            "wave2 breakdown totals match",
            breakdown.total == before,
            format!("total {} == rows {}", breakdown.total, before),
        );

        // No clean check may have become a finding.
        let skipped: i64 = database
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE title LIKE 'X-Health%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        check("wave2 no fabricated clean findings", skipped == 0, "0 health-check rows".into());
    } else {
        check("wave2 real scan", false, "scan did not complete".into());
    }

    // ---- Wave 2: filtering ----
    {
        let database = db::Db::open_in_memory().unwrap();
        for (i, sev) in [Severity::Critical, Severity::High, Severity::Low].iter().enumerate() {
            findings::insert(
                database.conn(),
                &Finding {
                    id: format!("f{i}"),
                    scan_id: None,
                    asset_id: None,
                    title: format!("finding {i}"),
                    severity: *sev,
                    status: FindingStatus::New,
                    category: "web".into(),
                    cwe_id: None,
                    cve_ids: vec![],
                    cvss_score: None,
                    description: String::new(),
                    remediation: String::new(),
                    references: vec![],
                    mitre_techniques: vec![],
                    evidence: vec![],
                    assignee: None,
                    due_date: None,
                    created_at: "2026-01-01T00:00:00Z".into(),
                    updated_at: "2026-01-01T00:00:00Z".into(),
                    user_id: None,
                },
            )
            .unwrap();
        }
        let crit = findings::list(
            database.conn(),
            &FindingFilter { severity: Some(Severity::Critical), ..Default::default() },
        )
        .unwrap();
        check("wave2 severity filter", crit.len() == 1, "1 CRITICAL".into());

        findings::set_status(database.conn(), "f0", FindingStatus::FalsePositive).unwrap();
        let fp = findings::list(
            database.conn(),
            &FindingFilter { status: Some(FindingStatus::FalsePositive), ..Default::default() },
        )
        .unwrap();
        check("wave2 status transition", fp.len() == 1, "1 false_positive".into());
    }

    // ---- Wave 4 prerequisite: ATT&CK coverage from a real scan ----
    if let Some(report) = &last_report {
        let database = db::Db::open_in_memory().unwrap();
        ingest::ingest_report(database.conn(), report, None).unwrap();
        let cov = findings::attack_coverage(database.conn()).unwrap();
        println!("  ATT&CK: {} techniques, complete={}, score={:?}", cov.techniques.len(), cov.complete, cov.score);
        println!("  {}", cov.describe());
        // Against a well-configured target the only findings are hardening gaps
        // (headers, clickjacking), which are deliberately unmapped. The correct
        // behaviour is therefore an INCOMPLETE report with no percentage -- not
        // a fabricated 100%. Assert that honesty rather than non-emptiness.
        check(
            "wave4 refuses to score an incomplete mapping",
            !cov.complete && cov.score.is_none(),
            format!(
                "{} techniques, complete={}, score={:?} (no percentage over a partial mapping)",
                cov.techniques.len(),
                cov.complete,
                cov.score
            ),
        );

        // And prove the mapping itself applies when a mapped check does fire.
        let mapped = ingest::convert(
            &scanner::ScanReport {
                url: report.url.clone(),
                scan_id: "mapped-probe".into(),
                timestamp: report.timestamp.clone(),
                summary: report.summary.clone(),
                results: vec![scanner::ScanResult {
                    check_name: "SQL Injection Detection".into(),
                    status: scanner::ScanStatus::Vulnerable,
                    severity: scanner::Severity::Critical,
                    findings: vec![scanner::VulnerabilityFinding {
                        title: "probe".into(),
                        severity: scanner::Severity::Critical,
                        status: scanner::ScanStatus::Vulnerable,
                        description: String::new(),
                        details: vec![],
                        remediation: String::new(),
                        cwe_id: Some("CWE-89".into()),
                        references: vec![],
                    }],
                    scan_duration_ms: 1,
                    timestamp: report.timestamp.clone(),
                }],
            },
            None,
            None,
        );
        check(
            "wave4 mapping yields techniques",
            mapped.first().map(|f| f.mitre_techniques.as_slice()) == Some(&["T1190".to_string()][..]),
            format!("{:?}", mapped.first().map(|f| f.mitre_techniques.clone())),
        );
    }

    // ---- Wave 3.1: real TLS against a live host ----
    match NetworkScanner::check_ssl("example.com", 443).await {
        Ok(info) => {
            println!("  issuer:   {:?}", info.issuer);
            println!("  expires:  {:?}", info.not_after);
            println!("  cipher:   {:?}", info.cipher_suite);
            println!("  SANs:     {:?}", info.san);
            check(
                "wave3.1 TLS inspection",
                info.issuer.is_some() && info.protocol_version.is_some(),
                "issuer + protocol parsed from live socket".into(),
            );
        }
        Err(e) => check("wave3.1 TLS inspection", false, format!("{e}")),
    }

    // ---- Wave 3.1: real banner grab against a local listener ----
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = served.clone();
    let handle = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            use std::io::{Read, Write};
            let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n");
            let mut buf = [0u8; 128];
            let _ = sock.read(&mut buf);
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let cfg = network::ScanConfig {
        target: "127.0.0.1".into(),
        ports: vec![port],
        timeout_ms: 3000,
        concurrency: 10,
        scan_type: network::ScanType::Connect,
        service_detection: true,
        os_fingerprint: false,
    };
    match NetworkScanner::scan_ports(cfg).await {
        Ok(res) => {
            let banner = res
                .hosts
                .iter()
                .flat_map(|h| h.ports.iter())
                .find_map(|p| p.banner.clone());
            println!("  banner: {banner:?}");
            check(
                "wave3.1 banner grab",
                banner.is_some(),
                "read banner from a live socket".into(),
            );
        }
        Err(e) => check("wave3.1 banner grab", false, format!("{e}")),
    }
    let _ = handle.join();

    // ---- Wave 3.2: real enumeration of THIS machine ----
    let result = OsPentest::scan_linux(&os_pentest::OsScanConfig::default());
    println!(
        "  measured_local={} findings={} skipped={} inspected={}",
        result.scanned_local,
        result.findings.len(),
        result.skipped_checks.len(),
        result.paths_inspected.len()
    );
    for f in result.findings.iter().take(5) {
        println!("    [{}] {} — {}", f.severity, f.id, f.title);
    }
    for s in result.skipped_checks.iter().take(3) {
        println!("    skipped: {s}");
    }
    check(
        "wave3.2 measured this host",
        result.scanned_local,
        format!("{} real findings", result.findings.len()),
    );
    check(
        "wave3.2 all findings verified",
        result.findings.iter().all(|f| f.verified),
        "verified invariant holds".into(),
    );

    println!("\n{}", if failures == 0 { "ALL LIVE CHECKS PASSED" } else { "SOME CHECKS FAILED" });
    if failures > 0 {
        std::process::exit(1);
    }
}
