# HANDOFF

Start here when resuming. `BUILD_ORDER.md` holds the decision record;
`UI_REDESIGN_PLAN.md` is the specification. This file records *current state*
and what to do first.

## Verified baseline

`main` @ `c3408f2`. **341 Rust tests pass, 0 failures** (306 prior + 29 in
`crates/auditbot` + 6 gate-integration). **Playwright: 29 pass** (25 prior + 4
new skeleton/aria-busy tests), all with `--retries=0` so no green test is
hiding a flake. `cargo fmt --all --check` is clean; `cargo clippy --all-targets`
has zero warnings.

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

### `cargo fmt --check` — resolved

An earlier version of this file listed `cargo fmt --check` as green, then
corrected it to red (687 diffs at `1f4ca7d`) and deferred the reformat as too
burdensome. **That is now fixed**: `cargo fmt --all --check` passes across the
whole workspace. The counts above were taken after the fix.

## CWE→OWASP review — done, three corrections

`crates/findings/src/compliance.rs`. Every arm checked against the OWASP Top Ten
2021 CWE categories (CWE-1348..1357), which MITRE derives from the mappings
cited in the 2021 OWASP Top 10.

| CWE | was | now | why |
|---|---|---|---|
| 1021 (clickjacking) | A01 | **A04** | MITRE lists 1021 under "1348 OWASP Top Ten 2021 Category A04:2021 - Insecure Design". A design failure, not access control. |
| 614 (missing Secure flag) | A02 | **A05** | Listed under 1349 (A05). |
| 615 | A02 | **A05** | Both the category *and* the comment were wrong — see below. |

**The handoff's suspicion about CWE-1004 was wrong, and the reason matters.**
1004 → A05 is correct; MITRE lists "1004 Sensitive Cookie Without 'HttpOnly'
Flag" under 1349. The actual bug was next to it: CWE-615 was commented
*"Sensitive Cookie Without HttpOnly"* — which is **1004's description**, not
615's. CWE-615 is *Inclusion of Sensitive Information in Source Code Comments*.
A copy-paste made two distinct weaknesses look interchangeable, and the
comment would have led a reviewer to mis-file a real finding regardless of the
category. Five tests now pin these arms, each citing the page it was checked
against.

These feed the OWASP readiness score, so the three were shifting findings
between categories rather than merely mislabelling them.

### 5. Bounty panel built (`red-web3`)

The IPC commands now have a caller. The panel lives on the Web3 page and asks
`bounty_status` on entry.

The branch that matters is the **disabled** one, because ChainScope is absent
here. `available: false` renders the backend's own `reason` and hides the
controls — never an empty results area, which would assert that no bounty
programs exist. The reason string is taken verbatim from the crate rather than
reworded in JS, so the UI and the crate cannot disagree about why it is off.

`listBountyPrograms` distinguishes "tool reachable, catalogue empty" from
"tool absent". `triageBountyProgram` refuses a blank slug without submitting,
and states plainly when nothing was indexed — including that this is not a
verdict on the program's security.

The stub answers `bounty_status` with `available: false` to mirror the real
machine. A test asserts the badge, the reason, hidden controls, that
`bounty_status` was genuinely invoked, and that `#bountyResults` is empty.

## Loading states — measured, and mostly missing

Answering "do we have sleek loading animations?" honestly: **the animation
primitives exist; almost nothing uses them.**

Present:
- `.spinner` / `-sm` / `-lg` with `@keyframes spin` — used at **15 call sites**
- `.skeleton` with a `@keyframes shimmer` gradient
- `fadeIn` / `slideUp` / `toastIn` / `slideInRight`

Missing:
- **`.skeleton` is never emitted.** `class="skeleton"` appears nowhere in
  `index.html` or `app.js`. It is fully-styled dead CSS.
- ~~**33 `async function load*` loaders. 0 of them render a loading state before
  awaiting `invoke()`.**~~ **Fixed for 16 panes.** Every `showSkeleton` call
  site now clears on both the success path and the failure path.

Measured, not inferred — `loading panes currently show nothing while awaiting
the backend` delays `list_findings` by 1.5s and samples mid-flight:

```
MIDFLIGHT: {"spinner":false,"skeleton":false,"anyLoadingText":false,"childCount":3}
SKELETON_IN_DOM: false
```

`childCount: 3` is the *previous* render still sitting there. So the worst case
is not a blank pane — it is a pane showing **stale data with no indication it is
stale**, which reads as current. That is a subtler failure than no spinner, and
it is the same failure mode as the rest of this file: a plausible-looking result
(previous rows) that is not the result just requested.

The test asserts the *current* behaviour, so adding real skeletons will fail it
loudly. That is intentional — it should be changed deliberately.

**Not built yet:** a `withLoading(pane, fn)` helper that renders a shape-matched
skeleton before `await` and swaps it for real content after. The `.skeleton` CSS
is already there to receive it.

> **Superseded** — see "Loading states — closed for the three main panes" below.
> The gap above is now measured, fixed for `#findingsList` / `#assetList` /
> `#profileList`, and covered by two browser tests. ~30 other loaders remain.

## Loading states — closed for the three main panes

The gap measured earlier was real: `.skeleton` was defined but never emitted,
and 33 `load*` functions rendered nothing before awaiting. The worst case was
not a blank pane but **stale rows presented with nothing to indicate they were
stale**, which reads as current.

Now shipped for `#findingsList`, `#assetList`, `#profileList`:
- `showSkeleton(pane, rows)` / `clearSkeleton(pane)` in `app.js`
- `.skeleton-row`, `.skeleton-list`, `.skeleton-row-title|badge|icon` in CSS,
  mirroring `.finding-card` geometry so the pane does not jump
- `aria-busy` while loading, cleared on **every** exit path including errors —
  a pane stuck at `aria-busy` would tell assistive tech it loads forever
- `@media (prefers-reduced-motion: reduce)`: shimmer off, placeholder still
  visible. Nothing in the app honoured that setting before.

Measured in-browser:

```
MIDFLIGHT:      {"skeletonRows":3,"ariaBusy":"true","findingCards":0,"hasRealContent":false}
REDUCED_MOTION: {"animationName":"none","height":12,"visible":true}
```

**Two bugs my own fix introduced, both caught by the test:**

1. I gated the skeleton on `dataset.loaded` to avoid re-shimmering on filter
   changes. Wrong: the attribute lives on the container, which survives section
   switches, so a genuine refresh never showed one — reproducing the original
   stale-rows bug. Removed the gate entirely.
2. The test patched `window.__TAURI__.invoke` *after* boot to inject a delay.
   `app.js` captures that into `state.tauri` during init (app.js:71), so the
   override was silently ignored and the test reported "no skeleton" — an
   artefact of the test, not the app. Fixed with `addInitScript` via a shared
   `delayListFindings` helper.

Worth noting: bug 2 is the same shape as every other mistake in this file — a
plausible reading produced by instrumentation that was not doing what it
appeared to.

**Still not done:** ~30 other loaders. The helper is there; each needs a call.

## Three bugs the "ChainScope is absent" belief produced

Worth recording, because each one is a case of trusting a plausible inference
over a direct check:

1. **`cs --version` exits 2, not 0.** ChainScope's Typer app defines no
   `--version`, so the probe reported a fully working tool as missing — even
   given the correct path. Now probes `--help`, which exits 0.
   `probe_does_not_rely_on_a_version_flag` pins this with a stub binary that
   rejects `--version` and accepts `--help`.
2. **`command -v cs` failing proved nothing.** The tool is installed in the
   project's own `.venv/bin`, which is not on `PATH` until the venv is
   activated. Discovery now also probes that checkout directly, and honours
   `CHAINSCOPE_BIN` as an override.
3. **The `meta` parser was fitted to a fixture I invented.** Against real output
   it was wrong twice: ChainScope prints Python `True`/`False`, not `yes`/`no`
   (so every program reported `poc_required: Some(false)`), and prints `None` for
   unset fields (so `network` came back as the literal string `"None"`). The
   tests now use output captured verbatim from the real tool — invented fixtures
   are exactly how these survived.

Net effect: had the tool genuinely been absent, all three would have been latent.
None would have been visible from tests alone. Only running the real thing found
them.

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

**ChainScope IS installed.** `~/Developments/Personal/Hacks/Immunefi/ChainScope`
has its own `.venv` with working `cs` and `chain-scope` entry points. Verified
live: `cs immune list --json` returns 100 real Immunefi programs, `cs immune meta
layerzero` returns its real bounty and flags.

An earlier session concluded it was "not installed" from `command -v cs` being
empty and `pip show chain-scope` failing. Both inferences were wrong — see below
for the three bugs that mistake caused.

Wrapscs immune list/scope/triage/meta, shelling out and parsing output.

`extract_json` pulls the trailing payload out of noisy stdout, because
`cs immune triage` prints progress lines before its JSON. `meta` has no `--json`,
so it parses the `key : value` table.

Complements `crates/web3`: ChainScope maps source, does not audit deployed
bytecode, and a hotspot ranking is not a verdict.

## Next

- ~~**~29 loaders still have no loading state.**~~ **Done for 16 panes.**
  `showSkeleton`/`clearSkeleton` cover `#findingsList`, `#assetList`,
  `#authProfilesList` (via `loadAuthProfilesList`), `#authProfilesList`
  (`loadAuthProfiles`), `#threatFeedsContainer`, `#threatActorsContainer`,
  `#indicatorsContainer`, `#irPlaybooks`, `#vendorResults`,
  `#malwareAnalysisContainer`, `#aptResults`, `#wordlistManagerContent`,
  `#notificationList`, `#reportTemplates`, `#integrationList`.
  The remaining `load*` functions either populate stat tiles with no pane of
  their own, or read from `state.data` with no backend call.

  **Counting these by grep is unreliable and was wrong twice.** `grep -c
  "showSkeleton("` returns 16, which includes the function declaration, so 15
  call sites — but several use variable indirection (`const list =
  $('#profileList')` then `showSkeleton(list, 2)`), so a naive selector grep
  finds nothing. Ground truth is `tests/sr_skeleton_loading.spec.ts`, which
  resolves the pane in the live DOM.

  **`loadAptTechniques` was wrongly listed as unwired.** It is wired: the
  button listener is at `app.js:4743` and the function at `app.js:4792`. The
  earlier claim that its wiring "was not conclusively removed" is resolved —
  it was never removed.

### Two real defects found while verifying the above

- **`#malwareAnalysisContainer` had no loading state at all.** The HANDOFF
  previously claimed it was covered "(button path)"; it was not. `grep` said
  otherwise because the pane is assigned to a local after the `await`. Fixed:
  placeholder before the await, cleared on both paths.
- **11 loaders leaked `aria-busy="true"` permanently when their backend call
  failed.** `clearSkeleton` removes only the attribute; the skeleton markup is
  removed by whatever writes `innerHTML` next. Loaders whose `catch` only called
  `showToast` or `console.error` therefore left a pane telling assistive tech
  it was still loading, forever. This is worse than showing an error — the user
  is told to wait for something that will never arrive. Fixed in all 11, plus
  `loadAuthProfilesList` and `loadWordlistManager`, whose `catch` set `innerHTML`
  but left the attribute.

  **12 in total, not 11** — I first reported 11 from a detector that scanned a
  fixed six-line window after each `catch`, which missed `loadFindings`. The
  corrected check scans from the `catch` to the end of the function and reports
  **15 skeleton loaders, zero leaks**.

### Pre-existing bug found while verifying: the Wordlists tab is dead

`loadWordlistManager` is **unreachable**. `addWordlistTab()` looks for
`$('#content-passwordattack .tabs')`, but `id="content-passwordattack"` sits on
the `<template>` element itself, and `renderTemplate()` does
`container.appendChild(template.content.cloneNode(true))` — cloning `.content`
**drops the template's own id**. The selector therefore always returns `null`,
the Wordlists tab button is never created, and `#wordlistManagerContent` never
enters the DOM.

This means the `aria-busy` fix in `loadWordlistManager` is currently
unobservable in the browser: the code path cannot be reached. The fix is still
correct and will apply once the wiring is repaired, but it is **not** covered by
the Playwright spec, which says so explicitly rather than implying coverage.

The same pattern appears in `setupOsint()` (`$$('#content-osint .tab')` at
`app.js:3850`). Whether its tabs are dead too was not determined.

**Not fixed here** — repairing the wiring changes what the page renders and is
outside the scope of a loading-state fix. The fix is either to give the cloned
wrapper the id, or to scope those selectors to `#contentArea`.

### The test that caught them, and the test that did not

The first version of `sr_skeleton_loading.spec.ts` **passed against the broken
code**, which made it worthless. Three separate causes, each of which made the
assertion vacuous:

1. It checked panes in `white-reports`, where **none** of them are rendered —
   they live in `<template id="content-blue-intel">` and friends. With a
   "skip when missing" check, an absent pane looks identical to a clean one.
2. `addInitScript` was registered **after** `page.goto`. It only applies to
   *subsequent* navigations, so the failing shim never ran — and
   `app.js` captures the stub's `invoke` into `state.tauri` at init, so the
   app kept calling the original regardless.
3. Even slowed, the loaders resolved faster than the sample, so `aria-busy` had
   already been cleared by observation time.

The spec now registers its hooks before `goto`, samples **mid-flight** against a
delayed backend, and has a guard test that fails loudly if the pane→section
mapping goes stale. **Verified by negative control**: with the fixes reverted it
fails and names all 5 affected panes; with them applied it passes 4/4.
- **`CWE→OWASP` still needs a human sign-off.** I corrected three arms against
  the MITRE taxonomy, but I am not a qualified reviewer. §5.1 and the readiness
  number still depend on this being reviewed by someone who can own it.
- ~~**Run `cs immune triage` once for real.**~~ **Done.** Ran against the live
  tool: 10 in-scope addresses, 4 repos, 21 files indexed, 133 nodes / 314 edges,
  25 hotspots. Running it for real found **two deserialisation bugs** that no
  amount of invented-fixture testing would have: `TriageReport.slug` and
  `ProgramScope.slug` were both required fields, but ChainScope emits neither.
  Deserialising a genuine report failed with `missing field 'slug'`. Both are
  now `#[serde(default)]`, and the slug is filled in by `ChainScope::triage()`
  from the caller's argument. Captured real output is a test fixture now.

## Open questions — yours, not the engineer's

- **CWE→OWASP needs qualified review.** `crates/findings/src/compliance.rs`,
  `owasp_categories_for_cwe`. **Partially done:** three arms were corrected
  against the MITRE taxonomy (1021→A04, 614→A05, 615→A05), and the belief that
  CWE `1004` was wrong turned out to be incorrect — see the CWE section. The
  remaining arms are still operator-knowledge mappings. This gate holds the §5.1
  scores and the readiness number, and I cannot sign it off.
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

## `crates/auditbot` — evidence-gated bounty pipeline

New crate. Triage → evidence → verify → dedupe → report, where **a report is
rendered from a confirmed verdict and never from a premise established before
one**. `FindingReport::from_verdict` returns `None` for anything that is not
`Confirmed`; that single gate is the whole design.

**Verification runs Foundry**, which is at `~/.foundry/bin/forge` (1.7.1) and
**not on `PATH`**. `Verifier::forge()` probes the well-known path explicitly —
without that, every verdict would be `ToolMissing` in a non-login shell.

### The bug worth remembering

The verdict semantics were **backwards at first**. I wrote `[FAIL] →
Confirmed`, reasoning "a failing test reproduces the bug." Running against real
Foundry disproved it: a Foundry PoC encodes its claim as a `require`, so an
exploit test that **passes** proves the vulnerability exists, and the same
`[PASS]` from a control test proves it does not. The original code would have
published every non-reproduction as a finding.

The fix is `ExpectedOutcome::Exploitable | Safe` on the request: the caller
declares what the PoC claims, because the mapping cannot be inferred from
output. The load-bearing test runs **one PoC against a vulnerable and a safe
contract** and asserts opposite verdicts.

Building those fixtures surfaced three real PoC-authoring requirements: the
drained ether needs a `receive()` hook on both the vault and the test, the
deploying contract otherwise *is* the owner, and the owner must not be
`msg.sender`.

### Honesty properties, each covered by a test

- A compile error is `Inconclusive`, **never `Refuted`** — nothing ran, so "we
  checked and it is fine" would be false.
- An unrecognised output shape is `Inconclusive`, not guessed at. A parser
  assuming "no failures mentioned means pass" manufactures a clean bill of
  health from a tool crash.
- `Inconclusive` always carries a reason.
- No report without `Confirmed`.
- Novelty is never asserted. `audit_refs` are URLs, so dedupe is a cheap screen
  over reference titles, not a reading of the audit texts. Every report carries
  that caveat verbatim.
- A missing binary yields `Inconclusive`, so the gate degrades honestly.

### Gating (`pipeline.rs`)

Verification is process execution, so it checks `Capability::ExecuteProcess`
before anything else. **A refusal is not a result**: the run returns
`StepOutcome::Blocked { reason }` naming what stopped it — not a verdict, not an
empty report, and specifically not worded like a negative result. The summary
test asserts the wording `"did not confirm"` is *absent*, because "we were not
allowed to check" and "we checked and it is fine" are different claims.

**Submission remains manual.** Nothing in the crate transmits to a program.

### Known limitations

- Integration tests are **unit** PoCs, not fork tests. Real fork testing needs
  an RPC URL and forge-std.
- Dedupe matches identifiers against audit-reference URLs only.
- The CWE→OWASP mapping still needs a qualified human sign-off; this crate does
  not change that.
## New: manual-testing crates wired to the Tauri frontend (Packet Inspector, Spammer, Sequencer, Collaborator)

Four new workspace crates were exposed through the existing Tauri command layer and fully wired into the vanilla-JS frontend (`ui/`):

**Rust (`src/main.rs`)**
- AppState fields: `packet_inspector`, `spammer`, `sequencer`, `collaborator_client` (`Arc<Mutex<...>>`)
- 17 new `#[tauri::command]` handlers, appended after `packet_clear_packets`:
  - **Packet Inspector (9)**: `inspector_list_interfaces`, `inspector_start_capture`, `inspector_stop_capture`, `inspector_get_packets`, `inspector_get_stats`, `inspector_get_session`, `inspector_is_capturing`, `inspector_add_filter`, `inspector_get_filters`
  - **Spammer (2)**: `spammer_generate_tokens`, `spammer_flood`
  - **Sequencer (2)**: `sequencer_preview`, `sequencer_run`
  - **Collaborator (4)**: `collaborator_beacon_generate`, `collaborator_beacon_interactions`, `collaborator_list_beacons`, `collaborator_list_interactions`

**Frontend (`ui/index.html` + `ui/app.js`)**
- New sidebar entries under **"Testing Tools"**: `packet-inspector`, `spammer`, `sequencer`, `collaborator`
- New templates: `content-packet-inspector`, `content-spammer`, `content-sequencer`, `content-collaborator` (stat cards, interface/plan controls, results tables, empty states)
- New `setup*()` functions and state fields: `inspectorCaptureRunning`/`inspectorFilters`/`inspectorPackets`, `spammerStatus`/`spammerTokens`, `sequencerPreview`, `collaboratorBeacons`/`collaboratorInteractions`
- Route cases in `renderContent()`, `getSectionConfig` entries (fallback toolpage), and `mockResponse` entries so web-mode works end to end

**Verification**
- `node --check ui/app.js` — syntactically valid
- Templates balanced: 66 open / 66 close `<template>` tags
- Every element ID referenced by the new setup functions resolves in the templates
- `cargo check --workspace` — clean
- **`tests/ipc_contract.rs` — all 3 tests pass**, including `every_ui_invoke_has_a_registered_command` which proves each of the 18 new UI `invoke()` calls maps to a registered Tauri command (no generic "command not found" at runtime)
- Workspace lib suite and the four crates' smoke suites pass (spammer 6, sequencer 4, collaborator 5, packet-inspector 4)

Known outstanding items (unchanged from prior state):
- Collaborator DNS out-of-band reception remains unimplemented (self-hosted TCP only)
- No Playwright/Visual UI tests yet for the four new tool pages
