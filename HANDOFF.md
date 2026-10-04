# HANDOFF

Start here when resuming. `BUILD_ORDER.md` holds the decision record;
`UI_REDESIGN_PLAN.md` is the specification. This file records *current state*
and what to do first.

## Verified baseline

`main` @ `9ad6aed`, pushed. 283 Rust tests, 0 warnings.

```bash
cargo fmt --check
cargo test --workspace --no-fail-fast
cargo check --workspace --all-targets
node --check ui/app.js
```

## Ground rule (load-bearing, not stylistic)

**No fabricated findings, scores, or compliance results.** Incomplete analysis
returns empty + `None` + an explicit reason. Never a plausible-looking zero or
a disclaimer beside a success message — the success message is what gets acted
on.

## Do these three things first

### 1. Move the Playwright stub out of `/tmp` (~10 min, blocking)

`/tmp/srtest/stub.js` is in temp storage and dies on reboot, taking the test
harness with it. Nothing below is verifiable without it.

- Stub lives at `/tmp/srtest/stub.js`, read by every spec as a const
- Specs: `~/Developments/Personal/PTest/tests/siterecorder_ui.spec.ts`,
  `sr_findings_layout.spec.ts`
- That directory holds ~20 unrelated suites (eoro, Wyze, LambdaTest). Run
  SiteRecorder specs explicitly; a bare `playwright test` launches all 58
- Tests need `--workers=1`; this machine is slow and parallel runs hang

### 2. Build a browser-driven audit (do not extend the grep)

The existing unreferenced-control list is a **known lower bound** and it
produced at least one false positive: it reported the team badges as dead
because `updateTeamBadges` builds IDs dynamically as `` `${team}Badge` ``, which
a grep for literal IDs cannot see.

The grep missed six fabrications that a browser can see. It found none of them.

**Definition of done:** render every template, record (a) controls with no
listener, (b) controls reporting success with no backend call, (c) panels whose
data has no provenance. That is the real version of the control list.

### 3. Then ChainScope bounty triage

Unbuilt. Now unblocked — the substrate is honest.

- Tool: `~/Developments/Personal/Hacks/Immunefi/ChainScope`, entry `cs` /
  `chain-scope`
- Has `cs immune list/scope/triage` (Immunefi), plus `hacken`, `bugcrowd`,
  `intigriti`; indexes repos into SQLite code graphs
- Not a research project — accept a program slug / GitHub repo, shell out,
  parse output
- **Must** disable the control when ChainScope is absent rather than fabricate
- Complements `crates/web3`; it maps source, it does not audit deployed
  bytecode

## Open questions — yours, not the engineer's

- **CWE→OWASP needs qualified review.** `crates/findings/src/compliance.rs`,
  `owasp_categories_for_cwe`. Six mappings are low-confidence; **CWE `1004` I
  believe is simply wrong**. This gate holds the §5.1 scores and the readiness
  number.
- **Deployment model** — single hardened workstation vs shared multi-user
  backend with RBAC. Unresolved.
- **Agent model/inference residency** — deferred by you. Currently inert by
  design.
- **README links to two untracked docs.** `README.md:7-8` links
  `BUILD_ORDER.md` and `UI_REDESIGN_PLAN.md`, which are deliberately untracked,
  so a fresh clone has broken links. Either commit them or drop the links.
  *Not resolved because committing the planning docs was not authorised.*
- **Exploitation / Wireless** — no crates exist. `BUILD_ORDER.md` Wave 6
  recommends integration (Metasploit RPC, `aircrack-ng` / `bluetoothctl`) over
  reimplementation.

## Also unbuilt

- White/Gray/Blue chart containers (`mttr`, `patchRate`, `phishRate`,
  `severityBar`, `metricsRiskTrend`, `remediationTrend`) — need §5 backend
  before they have anything real to draw
- Auth profile form fields (11 controls) — real CRUD backend exists
- `assetSearch` / `profileSearch` — genuinely wireable, both have real data