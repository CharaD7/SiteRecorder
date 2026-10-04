# HANDOFF

Start here when resuming. `BUILD_ORDER.md` holds the decision record;
`UI_REDESIGN_PLAN.md` is the specification. This file records *current state*
and what to do first.

## Verified baseline

`main` @ `1f4ca7d`. 294 Rust tests pass (283 prior + 11 in `crates/bounty`),
0 failures. 5 SiteRecorder Playwright tests pass.

```bash
cargo test --workspace --no-fail-fast
cargo check --workspace --all-targets
node --check ui/app.js
pnpm exec playwright test tests/sr_search_badges.spec.ts \
  tests/sr_findings_layout.spec.ts --workers=1
```

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
- **Run the audit's `(a)`/`(c)` arms and triage the output.** `(b)` is wired;
  the no-listener and console-error findings need a human read before any fix.
- **Wire `crates/bounty` into the UI and `src/main.rs`.** The crate is built and
  tested but not yet exposed over IPC, so nothing in the app calls it yet.
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