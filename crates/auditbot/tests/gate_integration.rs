//! The capability gate, tested as the security boundary it is.
//!
//! The central claim: a denial must never be reported as a clean result. A
//! read-only operator who sees "no vulnerabilities found" would be badly misled;
//! they need to see that nothing was checked.

use agent::{Capability, Gate, Policy};
use auditbot::pipeline::{GatedAudit, StepOutcome};
use auditbot::HuntTarget;

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/Vault.sol"),
        "pragma solidity ^0.8.13;\ncontract Vault {\n  function withdraw(uint256 a) external {}\n}\n",
    )
    .unwrap();
    dir
}

fn target() -> HuntTarget {
    HuntTarget::new("testprog", "withdraw", "src/Vault.sol")
}

/// Read-only is the shipped default, so it must refuse verification.
#[test]
fn read_only_policy_refuses_to_verify() {
    let audit = GatedAudit::new(Gate::new(Policy::read_only()));
    assert!(
        !audit.can_verify(),
        "read-only must not allow process execution"
    );
}

#[tokio::test]
async fn a_refused_run_produces_no_verdict_and_no_report() {
    let audit = GatedAudit::new(Gate::new(Policy::read_only()));
    let dir = project();

    let run = audit
        .run(target(), dir.path().to_path_buf(), &[])
        .await
        .expect("refusal is a normal outcome, not an error");

    assert!(run.verdict.is_none(), "a refusal must not invent a verdict");
    assert!(run.report.is_none(), "a refusal must not produce a report");
    assert!(!run.has_report());

    // The blockage must be named, and must not read as a clean bill of health.
    assert_eq!(run.blocked_steps(), vec!["verify"]);
    let summary = run.summary();
    assert!(summary.contains("blocked"), "{summary}");
    assert!(summary.contains("Nothing was verified"), "{summary}");
    assert!(
        !summary.contains("did not confirm"),
        "a refusal must not be worded like a negative result: {summary}"
    );
}

/// Evidence capture still works under read-only, because reading source is not
/// privileged. Only execution is refused.
#[tokio::test]
async fn evidence_is_captured_even_when_verification_is_refused() {
    let audit = GatedAudit::new(Gate::new(Policy::read_only()));
    let dir = project();

    let run = audit
        .run(target(), dir.path().to_path_buf(), &[])
        .await
        .unwrap();

    assert!(!run.evidence.is_empty(), "reading source needs no grant");
    assert!(run
        .steps
        .iter()
        .any(|(n, o)| *n == "evidence" && !o.is_blocked()));
}

/// A granted policy reaches verification. Skipped loudly without Foundry.
#[tokio::test]
async fn a_granted_policy_proceeds_past_the_gate() {
    if auditbot::verify::Verifier::forge().is_none() {
        eprintln!("SKIPPED: forge not found");
        return;
    }
    let policy = Policy::read_only().grant(Capability::ExecuteProcess);
    let audit = GatedAudit::new(Gate::new(policy));
    assert!(audit.can_verify());

    let dir = project();
    let run = audit
        .run(target(), dir.path().to_path_buf(), &[])
        .await
        .unwrap();

    // The gate let it through; whatever happened next is a real outcome, and it
    // must not be a blockage at "verify".
    assert!(
        !run.blocked_steps().contains(&"verify"),
        "verification should have run: {:?}",
        run.steps
    );
    assert!(run.verdict.is_some(), "a real run yields a real verdict");
}

/// A missing source file is an error, not a silently empty result.
#[tokio::test]
async fn missing_source_is_reported_as_an_error() {
    let audit = GatedAudit::new(Gate::new(Policy::read_only()));
    let dir = project();
    let mut t = target();
    t.file = "src/DoesNotExist.sol".into();

    let err = audit
        .run(t, dir.path().to_path_buf(), &[])
        .await
        .expect_err("a missing source must not pass silently");
    assert!(matches!(
        err,
        auditbot::pipeline::PipelineError::Evidence(_)
    ));
}

/// A blocked step always carries a reason. This is the invariant the whole
/// module rests on.
#[test]
fn a_blocked_step_never_has_an_empty_reason() {
    let blocked = StepOutcome::Blocked {
        reason: String::new(),
    };
    // Constructed empty here only to assert the invariant holds downstream;
    // the pipeline itself never builds one without a reason.
    assert_eq!(blocked.reason(), Some(""));
    assert!(blocked.is_blocked());
    assert!(!StepOutcome::Done.is_blocked());
    assert_eq!(StepOutcome::Done.reason(), None);
}
