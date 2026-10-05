//! End-to-end vertical slice, exercised against the real Foundry binary.
//!
//! These tests are the ones that matter. A parser unit test only proves the
//! parser agrees with itself; running actual `forge test` proves the bot can
//! tell a reproduction from a non-reproduction in practice, which is the
//! property the whole design rests on.
//!
//! Every test here is skipped *loudly* when Foundry is absent, so a green run
//! is never mistaken for coverage that did not happen.

use auditbot::dedupe::DedupeVerdict;
use auditbot::evidence::{self, SnapshotRequest};
use auditbot::report::FindingReport;
use auditbot::verify::{Verdict, VerdictKind, VerificationRequest, Verifier};
use auditbot::HuntTarget;
use std::path::Path;

/// The reproduction: asserts the attacker CAN drain, and that assertion holds.
/// This is what a real PoC looks like — it passes when the bug is present.
const EXPLOIT: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Vault} from "../src/Vault.sol";

contract ExploitTest {
    function test_anyone_can_withdraw_from_the_vault() public {
        Vault v = new Vault();
        v.deposit{value: 1 ether}();
        // We are demonstrably not the owner.
        require(v.owner() != address(this), "precondition");
        // No privilege: the withdrawal goes through anyway. If this require
        // holds, the access control is absent.
        v.withdraw(1 ether);
        require(address(v).balance == 0, "vault was not drained");
    }

    // The drained ether lands here, so this contract must accept it.
    receive() external payable {}
}
"#;

/// A genuinely vulnerable implementation: `withdraw` has no access control.
const VULNERABLE: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Vault {
    address public owner;

    // Pinned to a third party: the test contract deploys this Vault, so using
    // msg.sender here would make the test the owner and defeat the PoC.
    constructor() { owner = address(0xB0B); }

    function deposit() external payable {}

    // The drain sends plain ether; without this the call reverts and the PoC
    // would fail for the wrong reason.
    receive() external payable {}

    // BUG: no owner check, so anyone may drain the contract.
    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
"#;

/// The control: the same exploit against a properly guarded implementation.
/// It reverts on the owner check, so the assertion does NOT hold.
const NON_EXPLOIT: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Vault} from "../src/Vault.sol";

contract BenignTest {
    function test_non_owner_cannot_withdraw() public {
        Vault v = new Vault();
        v.deposit{value: 1 ether}();
        require(v.owner() != address(this), "precondition");
        v.withdraw(1 ether);
    }

    receive() external payable {}
}
"#;

/// The safe implementation the control runs against.
const SAFE: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Vault {
    address public owner;

    // Pinned to a third party: the test contract deploys this Vault, so using
    // msg.sender here would make the test the owner and defeat the PoC.
    constructor() { owner = address(0xB0B); }

    function deposit() external payable {}

    // The drain sends plain ether; without this the call reverts and the PoC
    // would fail for the wrong reason.
    receive() external payable {}

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
"#;

/// Neither reproduction nor refutation: nothing compiles.
const BROKEN: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
contract BrokenTest {
    function test_broken() public { require(nonexistentSymbol, "x"); }
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new(victim: &str, test_src: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::create_dir_all(dir.path().join("test")).unwrap();
        std::fs::write(
            dir.path().join("foundry.toml"),
            "[profile.default]\nsrc = \"src\"\nout = \"out\"\nlibs = []\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/Vault.sol"), victim).unwrap();
        std::fs::write(dir.path().join("test/Exploit.t.sol"), test_src).unwrap();
        Self { _dir: dir }
    }

    /// A vulnerable target with an exploit PoC.
    fn exploitable() -> Self {
        Self::new(VULNERABLE, EXPLOIT)
    }

    /// A safe target with the same PoC, which must fail.
    fn safe() -> Self {
        Self::new(SAFE, NON_EXPLOIT)
    }

    /// A target whose PoC does not compile.
    fn broken() -> Self {
        Self::new(VULNERABLE, BROKEN)
    }

    fn path(&self) -> &Path {
        self._dir.path()
    }
}

/// Return the verifier, or skip loudly when Foundry is missing.
macro_rules! require_forge {
    () => {
        match Verifier::forge() {
            Some(v) => v,
            None => {
                eprintln!("SKIPPED: forge not found; no Foundry-backed coverage");
                return;
            }
        }
    };
}

fn run(verifier: &Verifier, fx: &Fixture) -> Verdict {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let req = VerificationRequest::forge_exploit(fx.path());
    rt.block_on(verifier.run(&req)).expect("verification runs")
}

/// The load-bearing test. The same PoC run against a vulnerable and a safe
/// implementation must produce opposite verdicts. If this passes, the bot can
/// actually tell a real vulnerability from a safe contract.
#[test]
fn real_exploit_poc_confirms_only_against_the_vulnerable_contract() {
    let verifier = require_forge!();

    let confirmed = run(&verifier, &Fixture::exploitable());
    assert_eq!(
        confirmed.kind,
        VerdictKind::Confirmed,
        "a passing exploit PoC proves the bug. Output:\n{}",
        confirmed.output
    );
    assert!(confirmed.command.iter().any(|a| a.contains("forge")));
    assert!(!confirmed.output.is_empty(), "evidence must be captured");

    let refuted = run(&verifier, &Fixture::safe());
    assert_eq!(
        refuted.kind,
        VerdictKind::Refuted,
        "the same PoC against a guarded contract must refute. Output:\n{}",
        refuted.output
    );
}

/// A compile failure must never read as a clean result.
#[test]
fn real_compile_failure_is_inconclusive_not_refuted() {
    let verifier = require_forge!();
    let v = run(&verifier, &Fixture::broken());
    assert_eq!(v.kind, VerdictKind::Inconclusive, "output:\n{}", v.output);
    assert!(v.reason.is_some(), "the reason must be recorded");
    assert!(!v.kind.gates_report());
}

/// The full slice: evidence -> verdict -> dedupe -> report, and no report
/// unless the verdict actually confirmed.
#[test]
fn full_slice_renders_a_report_only_from_a_confirmed_verdict() {
    let verifier = require_forge!();

    let target = HuntTarget::new("testprog", "withdraw", "src/Vault.sol");
    let fx = Fixture::exploitable();

    // 1. Evidence: capture the source under review.
    let ev = evidence::capture(&SnapshotRequest::new(target.clone(), fx.path()))
        .expect("source is present");
    assert!(!ev.is_empty(), "evidence must not be empty");

    // 2. Verdict: run the real check.
    let verdict = run(&verifier, &fx);
    assert_eq!(verdict.kind, VerdictKind::Confirmed);

    // 3. Dedupe: a target unrelated to the audit list.
    let d = auditbot::dedupe::check(&target, &["https://halborn.com/audits/other".to_string()]);
    assert_eq!(d.verdict, DedupeVerdict::NoKnownOverlap);

    // 4. Report: rendered from the confirmed verdict.
    let report =
        FindingReport::from_verdict(target.clone(), &verdict, ev, d.clone()).expect("report");
    let md = report.to_markdown();
    assert!(md.contains("withdraw"));
    assert!(md.contains("Proof of concept"), "PoC included verbatim");
    assert!(md.contains("Not for automated submission"));
    assert!(
        report.novelty_caveat.is_some(),
        "novelty must never be asserted"
    );

    // The same pipeline must refuse when the check refutes.
    let benign = Fixture::safe();
    let refuted = run(&verifier, &benign);
    assert!(FindingReport::from_verdict(target, &refuted, vec![], d).is_none());
}

/// Dedupe must catch the duplicate before any drafting happens.
#[test]
fn known_overlap_is_stopped_before_drafting() {
    let verifier = require_forge!();
    let fx = Fixture::exploitable();
    let target = HuntTarget::new("testprog", "withdraw", "src/Vault.sol");

    let verdict = run(&verifier, &fx);
    assert_eq!(verdict.kind, VerdictKind::Confirmed, "the bug is real...");

    let d = auditbot::dedupe::check(&target, &["halborn-2023-vault-withdrawal".to_string()]);
    match &d.verdict {
        DedupeVerdict::KnownOverlap { audit, .. } => assert!(audit.contains("halborn")),
        other => panic!("expected KnownOverlap for a matching name, got {other:?}"),
    }

    // A real bug that is already published is not a finding.
    let report = FindingReport::from_verdict(target, &verdict, vec![], d).expect("renders");
    assert!(report.novelty_caveat.unwrap().contains("Do not submit"));
}

/// Missing Foundry must degrade to an honest unavailable state, never a
/// silent pass.
#[test]
fn a_missing_binary_yields_inconclusive_not_a_fake_verdict() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fx = Fixture::exploitable();
    let verifier = Verifier::with_binary("/nonexistent/forge");
    let v = rt
        .block_on(verifier.run(&VerificationRequest::forge_exploit(fx.path())))
        .expect("runs");
    assert_eq!(v.kind, VerdictKind::Inconclusive);
    assert!(!v.kind.gates_report());
    assert!(v.reason.is_some());
}
