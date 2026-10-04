# HANDOFF

Start here when resuming. `BUILD_ORDER.md` holds the decision record;
`UI_REDESIGN_PLAN.md` is the specification. This file records *current state*
and what to do first.

## Verified baseline

`main` @ `3ad7850`. **294 Rust tests pass, 0 failures** (283 prior + 11 in
`crates/bounty`). **20 Playwright tests pass** (17 + 3 audit), all with
`--retries=0` so no green test is hiding a flake.

```bash
cargo test --workspace --no-fail-fast
cargo check --workspace --all-targets
node --check ui/app.js

cd ~/Developments/Personal/PTest
pnpm exec playwright test tests/siterecorder_ui.spec.ts \
  tests/sr_search_badges.spec.ts tests/sr_findings_layout.spec.ts \
  --workers=1 --retries=0

# The audit needs BOTH budgets raised; see the comment atop the spec.
pnpm exec playwright test tests/sr_control_audit.spec.ts \
  --workers=1 --retries=0 --timeout=1500000 --global-timeout=2700000
```

Audit result: **54 sections, `all_flags=0`, 0 console errors** — no control
faking success, no dead control, no unreachable section. That figure started at
18 flags and 4 console errors.

### The audit's own false positives (found and fixed)

Worth recording, because it is the same failure mode the old grep had:

- **16 `no-listener` reports were wrong.** The audit classified controls lazily,
  interleaved with clicking them. `newOpBtn` navigates on click, which replaces
  `#contentArea` and detaches the delegation root, so every *later* control was
  reported dead. All 16 were wired via `#contentArea` delegation. Fixed by
  splitting into two passes — classify everything, then click.
  `delegated dashboard controls are not misreported as dead` now guards it.
- **2 `no-provenance` reports were the harness's fault.** `switchTeam()`
  early-returns when the team is already active, so clicking a team tab did not
  force `renderSidebar()` and `gray-dashboard` / `white-dashboard` never
  materialised. Fixed by calling `switchTeam` directly, with a click fallback.

A standalone test asserts the prototype hook sees `#contentArea`'s listener, so
if delegation detection ever breaks the audit fails loudly instead of quietly
emitting confident nonsense.

### Trap: `globalTimeout`, not just `timeout`

`playwright.config.ts` sets `globalTimeout: 300 * 1000`, which caps the **entire
suite** regardless of the per-test `timeout`. Raising only the per-test budget
produces `Timed out waiting 300s for the test suite to run` and *no results at
all* — which reads like a crash rather than a config ceiling. The audit needs
`--global-timeout=2700000` as well. That config is shared by ~20 unrelated suites
(eoro, Wyze, LambdaTest), so pass it per-invocation instead of editing the file.

### `cargo fmt --check` does NOT pass — correction

The previous version of this file listed `cargo fmt --check` as green. It is not.
At `1f4ca7d` it reports **687 diffs across the workspace**, in committed code
(working tree clean apart from the two deliberately untracked planning docs).
This predates this session's work. `crates/bounty` *is* fmt-clean; the other 687
are not. **Not fixed here** — a 687-file reformat would bury the substantive
commits. Either commit that as a standalone "reformat" change or amend the
claim here.

## Ground rule (load-bearing, not stylistic)

**No fabricated findings, scores, or compliance results.** Incomplete analysis
returns empty + `None` + an explicit reason. Never a plausible-looking zero or
a disclaimer beside a success message — the success message is what gets acted
on.

Applied twice this session, both in the UI:

- **Team badges.** Gray/Blue/White showed `0`, computed from `state.data`
  arrays that *no* backend command ever populates (`state.data.risks` is never
  assigned anywhere in `app.js`). A `0` there asserted "we queried and found
  nothing". They now show `—` with a tooltip saying no backend call reports a
  count. Red keeps its real count — `targets` and `findings` are genuinely
  DB-backed.
- **Search with no matches.** Hiding every row silently reads as an empty list,
  which is a different and false statement. `.filter-no-match` now says so.

## Done this session

### 1. Playwright stub moved out of `/tmp` — was blocking

`/tmp/srtest/stub.js` now lives at **`tests/browser/stub.js`**, tracked in the
repo (checksum-verified identical). All three specs read from there; the only
remaining `/tmp` mentions in them are explanatory comments.

The stub also carries the audit instrumentation (prototype-level
`addEventListener` / `on*` hooks) described below.

- Specs: `~/Developments/Personal/PTest/tests/siterecorder_ui.spec.ts`,
  `sr_findings_layout.spec.ts`, `sr_search_badges.spec.ts`,
  `sr_control_audit.spec.ts` (new)
- **Run with `pnpm`**, not `npx` — `package.json` pins `packageManager: pnpm` and
  `npx` hard-fails with `EBADDEVENGINES`.
- Tests need `--workers=1`; this machine is slow and parallel runs hang.

### 2. Browser-driven audit built — `sr_control_audit.spec.ts`

Renders all 54 sections and records:

- **(a) controls with no listener** — resolved by hooking
  `EventTarget.prototype.addEventListener` and the `on*` setters *before*
  `app.js` runs, so dynamically-built elements are captured. This is the fix for
  the grep's `${team}Badge` false positive: it observes what was actually
  attached to real elements, not literal ids in source.
- **(b) controls claiming success with no backend call** — clicks each control
  and diffs `window.__calls` (populated by the stub). Requires *both* a text
  change to success wording *and* zero invokes, so neither half alone can
  produce a finding.
- **(c) console errors** across every template.

Skips destructive controls and secret/file inputs rather than clicking them.

**It found five real bugs, none of which the grep could see:**

| where | defect |
|---|---|
| `renderContent` | called `setupAuthProfiles()`, which was never defined → section threw and rendered inert |
| `loadInterfaces` | `.map` on a null reply from `packet_list_interfaces` |
| `loadIrPlaybooks` | `Object.entries(null)` throws |
| `loadThreatFeeds` | `.map` on a null reply |
| `loadThreatActors` | `.map` on a null reply |
| `loadIndicators` | `.map` on a null reply |

The four null cases share one shape: the command answers `null` when nothing is
configured, and the loader treated that as a crash. They now guard and say so.

**Caveat on scope.** The audit now reports `all_flags=0`, but only
`fake-success` and the delegation regression test *assert*. The audit skips
destructive controls and secret/file inputs rather than clicking them, so those
paths remain unexercised by design. A clean run means "nothing found in the paths
this audit can safely walk", not "the UI is correct".

### 3. `assetSearch` / `profileSearch` wired

The handoff called these "genuinely wireable". Added `filterRenderedRows` in
`ui/app.js` (exported for inline use, following `filterScans`), `data-search`
haystacks on asset and profile rows, and `.filter-no-match` CSS. Multi-term
queries AND together, so `"web database"` narrows rather than widens.

**Note:** `sr_search_badges.spec.ts` was written test-first against an
unimplemented function, and its expectation was *inverted* — it asserted that
searching `"database"` shows the `"web server production critical"` row. Corrected
the spec rather than the implementation; a filter that shows non-matches is not a
filter.

### 4. ChainScope bounty triage built — `crates/bounty`

Wraps `cs immune list|scope|triage|meta`, shelling out and parsing output.

**ChainScope is NOT installed on this machine.** No `cs`, no `chain-scope`, and
`pip show chain-scope` finds nothing. So the handoff's rule — *"must disable the
control when ChainScope is absent rather than fabricate"* — is the **primary**
path here, and it is the tested one: `absent_binary_is_reported_unavailable_not_empty`
and `unavailable_reason_states_that_nothing_was_retrieved` both assert that a
missing tool yields an explicit reason, never an empty-looking success.

`extract_json` pulls the trailing payload out of noisy stdout, because
`cs immune triage` prints progress lines before its JSON. `meta` has no `--json`,
so it parses the `key : value` table and leaves unrecognised fields `None` —
`missing_bounty_field_stays_none_not_zero` guards against an absent bounty
becoming `0.0`.

Complements `crates/web3`: ChainScope maps source, does not audit deployed
bytecode, and a hotspot ranking is not a verdict.

## Next

- **`CWE→OWASP` qualified review** — still open, still gating §5.1. See below.
- **Build the bounty UI.** The IPC commands are registered and
  `ipc_contract` 3/3, but no template calls them yet. Branch on
  `available`; when false, render the disabled reason — never an empty list.
- **Decide the `cargo fmt` question** (687 diffs, above).

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
- `assetSearch` / `profileSearch` — **now wired**, see "Done" above

## Also fixed this session (were pre-existing red tests)

Two `sr_search_badges.spec.ts` tests were **failing at HEAD**, not written but
never made green. Both were genuine defects rather than bad expectations:

- `filterRenderedRows` did not exist anywhere in `app.js`; the spec was
  test-first against an unimplemented function.
- Gray/Blue/White badges showed a fabricated `0`.

`sr_control_audit.spec.ts` is the harness that would have caught both without me
having to notice them by reading a log.