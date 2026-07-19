# Verification and Adversarial Test Plan

This document owns the ChangeGuard verification matrix. Passing a model-generated explanation is never sufficient; deterministic contracts and negative controls must pass.

## Verification layers

| Layer | Required checks |
|---|---|
| Plugin package | manifest validation; declared component paths exist; no unsupported fields; install/uninstall smoke |
| Schemas | Draft 2020-12 schema check; valid fixtures pass; extra fields and malformed provenance fail |
| Fingerprint | stable normalization across usernames, timestamps, ports, and path separators; OS/version/surface differences remain distinct |
| Issue matcher | true candidate ranking; version/platform/component hard gates; negative control rejection; explicit negative-evidence penalty |
| Change-to-Local Graph | only deterministic code creates edges; every edge has a source and matcher; model cannot add or mutate edges |
| GPT-5.6 compiler | valid Impact Contract; source spans exist; counterevidence retained; probe-refuted claim cannot remain high confidence |
| Probe registry | registered IDs only; no shell text; platform guard; timeout/output cap; result hash; refusal and error are distinct |
| Privacy | token/env/path fixtures redacted; disclosure manifest exactly matches exported fields; Issue injection is quarantined |
| Recovery | trust-tier policy; exact target hash/pattern count; disposable-copy dry-run; backup/smoke/rollback receipt tests |
| Follow-up (Ticket 12) | explicit subscribe, needs-info capsule, no-new-evidence refresh, duplicate migration, measured supersession, regression hold, CLI/MCP parity, SessionStart due/not-due, snapshot_path/witness refusal, persistence fail-closed |
| Hooks / instances (Ticket 03) | first baseline, unchanged silent SessionStart, multi-instance upgrade, downgrade, PATH precedence drift, actual-instance evidence, ambiguous repair refusal, hook untrusted/skipped/failed, manual scan fallback, CLI/MCP scan equivalence, SessionStart changed/no-change duration &lt;10s, raw-path non-disclosure, symlink state refusal, ChatGPT.app desktop+PATH dedupe + plist version, legacy Codex.app non-regression, health classification (`evidence_incomplete` vs identity/budget), `affected_resolution_reason` (`no_observed_context` including sole instance) |
| Platform macOS (Ticket 13) | adapter alias/operation/constraint contracts; isolation refuses active `~/.codex` and protected roots; receipt validator Full-only-with-proof + leak refusal; CLI/MCP `platform-status` / `platform-receipt-validate`; real-machine harness on darwin covers core diagnose, multi-instance, config repair, auto-rollback, explicit rollback, plugin-cache repair/rollback, KNOWN_GOOD/canary, privacy refuse, upstream zero-network, package smoke; support matrix docs |
| Judge path | clean install; no judge API key; live matcher/probe; offline snapshot; visible evidence state; under 90 seconds |
| Demo / Ticket 17 (S4 package/profile) | shared demo core (CLI/MCP/Skill); disposable temp only; no network default; rollback + cleanup; CLI/MCP equivalence; clean-profile install/uninstall residual smoke (`npm run package:clean-profile`); packaged prebuilt path Node >= 20 without on-host rebuild; pure Node deterministic ustar+gzip (stable order/metadata; symlink/special fail-closed; package-repro); package smoke stages install and runs `demo` from non-repo cwd; local readiness aggregator `npm run ready:local` — **Ticket 17 `LOCAL_COMPLETE`** (historical R13: Root 27/27 + 552/552 + ready:local 10/10; R13 both `PASS_NO_P0_P1`; post-R13: package-repro 9/9 + full **561/561** + ready:local 10/10 + R19 `REPRO_REVIEW: PASS_NO_P0_P1`); Gate C still `NOT_STARTED` |

## Fixture expectations

### Protected-process positive fixture

- known SHA-256 and AST signature are detected
- failure phase remains before extension handshake
- Issue #32925 is a candidate, not an official root-cause assertion
- local component can reach `SOURCE_COMPONENT_LOCATED`
- only a successful deterministic reproduction plus negative control can reach `LOCAL_REPRO_CONFIRMED`
- Ticket 02: isolated experimental T1 repair may reach `RESOLVED_VERIFIED` only after scope-bound authorization, verified backup, atomic apply, original-failure absence, and core health

### Negative control

- different surface, error class, phase, and no affected AST signature
- protected-process and invalid-TOML Issues cannot reach high confidence
- expected terminal state is `INCONCLUSIVE` or low-confidence `ISSUE_CANDIDATE`

### Windows in-app Browser crash family

- the same phrase “Codex crashes when Browser opens” cannot collapse distinct exception, process, timing, page-capability, and concurrency signatures
- `0xC0000005` / `CrBrowserMain` / `chrome.dll+0x2e08f46`, `0xc06d007f`, and GPU `101457950 -> 18` fixtures rank different candidates
- a no-Browser control and a neutral-page Browser probe remain separate observations
- “disable Browser”, “move to SSD”, and “disable SecureLink” remain hypotheses or mitigations until their own controlled A/B tests pass
- an open GitHub Issue without verified Issue/PR/commit/release linkage cannot reach `FIX_COMMIT_LINKED`

## Ticket 07 Scenario Harness (config/startup fault pack)

Black-box coverage in `tests/ticket07-config-startup.test.ts`:

- distinct fingerprints for invalid TOML, wrong type, obsolete key, source conflict
- valid `config_set` / `config_remove` repair → `RESOLVED_VERIFIED` with startup verification (original failure, config reload, registered command)
- wrong candidate (negative control) refused
- managed policy → `ADMIN_ACTION_REQUIRED` + IT handoff; no privilege-elevation ops

## Ticket 15 Scenario Harness (Linux / WSL / enterprise)

Synthetic fixtures and capability injection only — **no Full claim** without real-machine receipt.

| ID | Scenario | Expected |
| --- | --- | --- |
| T15-S01 | unknown adapter | capability `READ_ONLY`; writes disabled |
| T15-S02 | native linux PATH CLI | `LIMITED`; `install_source` path/package never `wsl`; RO discovery |
| T15-S03 | WSL + Windows MSIX coexist | ≥2 instances; distinct platforms/domains; no identity collapse |
| T15-S04 | managed.policy.json enterprise_mdm | `ADMIN_ACTION_REQUIRED` + IT Handoff (risk/rollback/official ref); no capsule/auth; no sudo/chmod language |
| T15-S05 | admin/permission_bound block | mutation refused; handoff |
| T15-S06 | symlink config root | refuse; no follow |
| T15-S08 | `/mnt/c` host mount as linux root | refuse by default |
| T15-S09 | network compare RO playbook | branch labels only; `network_used:false`; no settings mutation |
| T15-S10 | capability upgrade without real-machine receipt | remains Limited; cannot claim Full |
| T15-S11 | CLI/MCP `platform-status` equivalence | stable fields; path/secret redaction |
| write-disabled | LIMITED/READ_ONLY capability on repair-preview/apply | `WRITE_DISABLED`; tree hash unchanged |
| fixture-seam-env-only | `CHANGEGUARD_INTERNAL_FIXTURE_SEAM=1` on in-repo fixture (CLI+MCP) | env alone is not authorization; `WRITE_DISABLED`; no capsule/authorization; tree hash unchanged |
| fixture-seam-mkdtemp | env=1 + `mkdtemp(os.tmpdir())` isolated copy | preview → apply → verify → rollback allowed; only the copy mutates |
| fixture-seam-temp-root-eq | env=1 + exact user-owned trusted temp root (`TMPDIR`/`TMP`/`TEMP` overlay) | `proveIsolatedFixtureTarget=false`; CLI+MCP `WRITE_DISABLED`; no auth; root tree unchanged; strict `mkdtemp` child still preview/apply/verify/rollback |
| fixture-seam-refuse | leaf/mid symlink, active `~/.codex` alias, HOME ordinary dir, `/mnt/<drive>` | isolation proof fails; stays `production_unknown` / `WRITE_DISABLED` |
| fixture-seam-auth-bind | disposable preview auth applied to unproven repo path | apply refused; repo tree unchanged |
- induced verification failure auto-rollbacks exact config bytes
- invalid TOML diagnosed but not auto-repaired
- no project-source read (sentinel file)
- symlink / path-escape refused
- replay after apply refused; TOCTOU hash change refuses apply
- CLI/MCP diagnose and repair-preview equivalence
- explicit rollback restores original bytes
- prior Ticket 02 protected-process path still works
- oversized config and malformed incident fail closed

## Ticket 08 Scenario Harness (plugin cache / skew / reconciliation)

Black-box seam coverage in `tests/ticket08-plugin-cache-harness.test.ts`:

- four exclusive mechanisms via inventory/manifest comparison (`bundled_file_corruption`, `stale_shared_cache`, `dependency_version_skew`, `reconciliation_overwrite`)
- dependency-install-like negative control stays `INCONCLUSIVE` and refuses repair (no conflation)
- successful `repair-preview` → `repair-apply` → `RESOLVED_VERIFIED` after recon cycle + restart/health
- recurrence after reconciliation auto-rollbacks; cannot claim `RESOLVED_VERIFIED`
- induced verification failure restores exact original cache + manifest hashes
- explicit rollback restores exact original cache + manifest hashes (mitigation only)
- path/symlink/oversize refuse; tampered backup and stale auth fail closed; token replay refused
- CLI/MCP diagnose and repair-preview stable-field equivalence
- Ticket 01–02 protected-process / negative-control regressions still pass
- no package-manager install scripts, recursive cache delete, or signed-binary mutation

## Ticket 09 Scenario Harness (Desktop Browser crash-family classifier)

Black-box + classifier coverage in `tests/ticket09-crash-family.test.ts`
(fixtures under `fixtures/crash-family/`):

- `0xC0000005` / `CrBrowserMain` / `chrome.dll+0x2e08f46` → `openai/codex#32683` Top 3 (`UPSTREAM_BLOCKED`, no fix linkage); Top 3 excludes `#32094` / `#33762` without their defining mechanism axes
- `0xc06d007f` interaction family → `openai/codex#33710` Top 3
- GPU `101457950 -> 18` media/canvas family → `openai/codex#32094` Top 3
- concurrency / WebView attach family → `openai/codex#33202` Top 3
- distinct families produce four distinct primary candidates
- macOS / different-module negative control hard-gates Windows families
- title / “click/open Browser then crash” similarity alone cannot reach high confidence or Top 3
- absent GPU codes hard-gate the GPU family; absent concrete page capability hard-gates complex-page family
- shared `neutral_dom_ready` / `in_app_browser` soft hits alone cannot promote no-mechanism candidates into Top 3
- ambiguous evidence → `INCONCLUSIVE` with concrete next evidence requirements
- no-isolation + active probe → stop; refuse primary-instance crash
- `local_mechanism` / `upstream_match` / `fix_applicability` remain separate axes
- no Repair Capsule / authorization eligibility without safe applicability; `repair-preview` refused
- optional model ranking cannot override hard gates, invent provenance, or resurrect no-mechanism GPU/complex candidates
- CLI/MCP stable-field equivalence; malformed extra crash_metadata key refused; oversized incident refused; path redaction; dump-contents parse/export refused
- prior-ticket regression: protected-process + negative-control diagnose unchanged

## Ticket 13 Scenario Harness (macOS Full support receipt)

Coverage in `tests/ticket13-macos-support.test.ts` + `scripts/run-macos-harness.mjs`:

- macOS capabilities expose only registered install sources, path aliases, and operations; all safety constraints remain closed
- synthetic `fixtures/platform-macos/` multi-instance inventory scans without raw path export or binary execution
- isolation refuses active Codex home and protected system roots; disposable temps only
- receipt validator accepts path-free Full receipts only when every required scenario passes; forged Full + leaks fail
- CLI/MCP `platform-status` / `platform-receipt-validate` are read-only and path-free; `platform-status` surfaces Windows `status` (default PREVIEW), Ticket 15 capability `reports` / `default_status` (Linux/WSL Limited, unknown Read-only), and macOS capability fields without mutual overwrite
- on a real darwin host, the isolated harness must pass all required scenarios and emit `support_level: full` only with live harness witness (otherwise Preview + exact gaps); external/forged receipts stay non-Full; never fabricates a receipt
- product claim for macOS Full is **receipt-scoped** to the verified harness (not universal for every macOS/Codex version); see `docs/SUPPORT_MATRIX.md`
- package smoke remains part of the Full required set and is self-contained: always production `npm run package` then `package:smoke` + packaged diagnose (no dependency on residual/stale `release/` or test order); phase-labeled failure summaries for package build vs smoke vs diagnose

### Session-expired evidence boundary

- a symptom-only report returns `INCONCLUSIVE`, not an invented IP-change root cause
- status, surface, app/browser version, sign-in method, and network A/B results may be collected without credential values
- tokens, cookies, account identifiers, passwords, one-time codes, and full browser storage never enter the fingerprint or disclosure manifest
- the resolver distinguishes service incident, network/security control, authentication-method mismatch, local session state, and unresolved account-side failure

## Ticket 14 Scenario Harness (Windows 11 adapter + platform status)

Black-box + unit coverage in `tests/ticket14-windows11.test.ts`
(fixtures under `fixtures/windows11/`; host may be macOS CI with injected caps):

- Windows adapter distinguishes MSIX, Desktop app, Desktop-bundled CLI, PATH CLI, WSL, and multi-profile rows without collapsing `instance_id`s
- system adapter delegates `platform=windows` to the namespaced adapter; never executes candidates
- crash metadata window accepts allowlisted fields only; dump bodies refused; Ticket 09 families stay distinct; wrong candidates cannot reach repair authorization
- user-owned repair binds exact instance fingerprint and reuses Ticket 02 backup/atomic apply/verify/rollback on isolated targets
- managed / MSIX package / Program Files → `ADMIN_ACTION_REQUIRED` + IT handoff (no chmod/runas/elevation language)
- platform status default PREVIEW with explicit critical-scenario gaps
- synthetic, forged-full, non-Windows, and missing-critical receipts cannot authorize FULL
- complete self-reported `real_machine` objects (memory/file/CLI/MCP/JSON clone) stay PREVIEW without a process-local live witness (`FULL_REQUIRES_LIVE_WITNESS`)
- only a matching in-process `sealWindowsLiveHarnessWitness` unit seam can authorize FULL; any bound field mismatch → PREVIEW
- top-level / scenario / attestation unknown keys fail closed; intermediate directory symlink receipt paths refused
- real-machine runner plan lists W11-S01…S11 and forbidden actions; validate-receipt-only mode (no live witness seal)
- CLI `platform-status` / MCP `changeguard_platform_status` PREVIEW equivalence
- T13 macOS live harness Full / external macOS JSON non-Full regression
- no Windows Full product claim without a real Windows 11 host live harness; framework integration does not upgrade Preview → Full

## Kill criteria

Stop or downscope the current implementation if any condition remains after the first implementation day:

1. Issue similarity can bypass version/platform/surface hard gates.
2. A model can create a Change-to-Local edge or overwrite a probe result.
3. The protected-process positive and negative fixtures cannot be separated deterministically.
4. Export can contain token, environment value, absolute user path, or complete session content.
5. The judge path is only a pre-rendered page rather than a working Plugin/fixture flow.
6. The main demo does not include one model hypothesis being supported or refuted by a live probe.
7. The product collapses into changelog summary or generic Issue search.

## Ticket 02 Scenario Harness (repair public seams)

Black-box seam: invoke CLI/MCP recovery commands and observe outcomes plus the
isolated target filesystem (implemented in `tests/ticket02-repair-harness.test.ts`):

- positive fixture reproduces protected-process failure before handshake (diagnose)
- successful `repair-preview` → `repair-apply` → `RESOLVED_VERIFIED` with artifact hash proof
- mechanism-different negative control cannot receive/apply the same repair
- stale/mismatched authorization refused (hash/count/scope/binding change)
- induced verification failure (harness sentinel) auto-rollbacks to exact original bytes
- explicit `rollback` restores exact original SHA-256; status is mitigation, not resolve
- CLI/MCP capsule stable-field equivalence; diagnose remains read-only
- adversarial: backup path redirect refused; `expected_result_sha256` null/removal refused; extra capsule fields refused
- adversarial: preview whole-tree hash unchanged and no `.changeguard`; self-contained token round-trip
- adversarial: expired/malformed token refused; successful-apply and post-rollback replay refused; fresh preview re-applies
- adversarial: production-boundary rejects recovery `rmSync`/`copyFileSync` and non-atomic recovery module writes

## Ticket 01 Scenario Harness (public seams)

Highest approved black-box seam: invoke CLI/MCP and observe outcomes plus the
isolated target filesystem. The harness owns whole-target before/after hashing.

Mandatory cases (implemented in `tests/scenario-harness.test.ts`):

- positive fixture → `SOURCE_COMPONENT_LOCATED` from independently measured hash + structural shim signature, with surface/error/phase applicability gates
- negative control → `INCONCLUSIVE`, no root-cause claim; Ticket 01 user statuses only from the allowed non-resolved set
- target bytes/hash unchanged before vs after diagnosis
- CLI/MCP comprehensive stable-field equivalence (positive, negative, error); normalize only receipt IDs
- distinct user vs upstream receipt IDs on success and error/usage paths
- `network_used:false` plus independent production-boundary guard (`npm run check:boundary`)
- target directory symlink refused; intermediate `artifacts` directory symlink refused; incident/artifact leaf symlink refused; non-file candidates refused; no outside marker leakage
- only named allowlisted candidates read; nested unreadable/sentinel path not read
- incident size bound; malformed JSON; extra top-level and nested fields; duplicate `path_alias`; AST id length > 128
- credential and full-width Unicode secret redaction after NFKC; generic POSIX/Windows/UNC absolute path redaction
- MCP bounded frame accumulator (inclusive bound: exactly-limit + newline accepted; limit+1 rejected; split chunks at boundary; overflow without newline; recovery; partial UTF-8 / multi-frame); extra-arg and extra top-level param rejection
- structural signature: exact block once; comment/string/regex-literal spoof; division negative; two blocks; missing/reordered/different-shim; old surrogate does not match
- fixture metadata: artifact bytes, `.hash.txt`, incident declared hash, recovery original hash agree; incident `local_facts_digest` equals core recomputation
- no absolute disposable path or raw exception leak on public stdout
- production-boundary guard self-tests on synthetic snippets (default/fs.promises non-read-only methods under a read-only allowlist policy, descriptor write/truncate/createWriteStream, mkdtemp/lchown/lchmod and unknown-future-API fail-closed, require/dynamic-import/`node:module`/`createRequire` loader prohibition, static `process`/`node:process` import and re-export prohibition at the module-policy layer (default/namespace/named import forms plus bare `process` and re-export controls) with opposite safe global-`process` control (`process.argv`/`process.cwd`/`process.env.NODE_ENV`/`globalThis.process.argv` without any `node:process` import), receiver wrappers `as`/non-null/comma-sequence, proven `node:fs` namespace **value-escape** closure — namespace may not escape via simple/chained alias (including former “safe” read-only alias open forms), Proxy, object spread, `Object.create`, `Object.assign`, container/shorthand store, return, pass, or nested `fs.promises` escape while direct `fs.promises.readFile` and named static read-only method imports remain allowed — plus destructured mutation/`open`/object-rest capability extracts including chained/renamed forms, capability-reference bypasses — value pass, `Reflect.apply`, comma-sequence call, `.bind`, callback supply, array/object storage, and bare `open`/`openSync` references or named imports — conditional open flags with proven `fs.constants` provenance including fake-object / unknown-parameter / object-literal `O_RDONLY` bypasses, parameter and nested-local shadowing of imported `fs` / `constants` aliases, and real unshadowed `fsConstants.O_RDONLY | O_NOFOLLOW` / `fs.constants.O_RDONLY` direct-namespace read-only open allowances with direct calls only, indirect eval/Function acquisition and sequence use, network globals `fetch`/`WebSocket`/`XMLHttpRequest` as capability references including alias/pass/`Reflect.apply`/sequence/construct-through-alias and `globalThis`/`global`/`window` member plus static-string element forms, process native-loader surfaces `dlopen`/`binding`/`getBuiltinModule`/`_linkedBinding`/`mainModule` as property references or calls on proven `process`/alias/`globalThis.process` roots with dynamic-key fail-closed, process object value-escape closure — whole-`process` must not escape via destructure (including `getBuiltinModule` extract and rest), `Proxy`, object spread, `Object.create`, simple/chained alias, return, pass, or array/object container forms — opposite safe controls for direct `process.argv`/`process.cwd`/`process.env`/`process.env.NODE_ENV`/`process.stdout.write`/`globalThis.process.argv` and static ESM read-only `fs.openSync`, CommonJS `module` and global `Reflect` host/meta capability prohibition, computed/reflective require loaders (`module["require"]`, `process["mainModule"]["require"]`, mainModule alias + computed require, `Reflect.get(module|process.mainModule, "require")`, any-receiver static terminal `require` property/element access) with opposite safe `frame.module` property-name control, and existing `require` alias/`module.require`/`process.mainModule.require`/`require.main.require` controls) plus production graph scan that follows relative static ESM re-exports (graph-closure self-test for a hidden mutator reached only via `export … from`)
- package smoke: `npm run package` then `npm run package:smoke` from a non-repo cwd; smoke reads packaged `.mcp.json`, enforces exact top-level allowlist (includes bilingual `README.md` + `README.zh-CN.md`), exact public docs set (`ARCHITECTURE.md`/`SECURITY.md`/`SUPPORT_MATRIX.md`/`TEST_PLAN.md`/`CASE_STUDIES.md` only), no broken local Markdown links, and no repository-only paths (`AGENTS.md`/`HANDOFF.md`/`docs/agents`/`src`/`scripts`/`node_modules`/`.scratch`)

## Ticket 03 Scenario Harness

Implemented in `tests/instance-scan.test.ts` (public CLI/MCP + shared core):

- first baseline across Desktop / PATH / package-manager / MSIX / native Linux / WSL identities
- unchanged SessionStart is silent and does not rewrite state
- multi-instance upgrade does not auto-select highest version as affected
- downgrade classification
- PATH precedence drift without collapsing instances
- untrusted / skipped / failed hook statuses; manual scan fallback
- SessionStart on change runs bounded read-only health check under 10s
- actual process-path evidence identifies the failing instance
- ambiguous multi-instance refuses repair binding; broadcast refused
- CLI/MCP scan stable-field consistency; raw-path non-disclosure; symlink state refused

## Ticket 04 Scenario Harness (official evidence + Impact Card)

Black-box and contract coverage in `tests/ticket04-evidence-impact.test.ts`:

- disclosure manifest exact fields before any transport; non-device_only field set equals sanitized outbound request keys
- disclosure refusal / not_requested → zero transport calls + bundled snapshot (snapshot hash + stale age/risk); `transport_request: null`
- approved online refresh via deterministic **fake** transport (live snapshot, one call) with exact disclosed payload only
- transport failure → stale immutable snapshot fallback with elevated stale risk
- malicious upstream injection → quarantine; maintainer_status preserved; no execution
- official host/repo allowlist rejection (userinfo, non-default port, github/api/raw forms, query secret strip)
- Impact Card deterministic intersections only (config/plugin/skill/hook/artifact/version)
- wrong local intersection → `REJECTED_WRONG_INTERSECTION`
- no-mapper official change → `UNMAPPED_CHANGE` (not whole-version unsupported)
- model edge-escalation payload refused; graph SHA unchanged
- CLI `impact --disclose-refused` public seam; target tree hash unchanged; no path leaks
- observed_facts / user_reports / hypotheses separated on public outputs
- adversarial integrity matrix: missing/mismatched snapshot hash; item title/structured/state tamper with old hash; forged origin/allowlist; null version endpoints and wrong version; ancient/future `fetched_at`; API/raw URL forms; refusal zero transport

## Ticket 05 Scenario Harness (untrusted page / URL diagnosis)

Black-box and contract coverage in `tests/ticket05-page-analysis.test.ts`:

- valid candidate page vs protected-process local fingerprint → `applicable_candidate` with confidence cap; DSL candidates only
- wrong platform hard gate → `wrong_platform`, confidence `none`, not eligible for repair validation
- prompt injection / agent instructions / exfil commands quarantined; `policy_mutations_blocked`; no repair authorization
- unsupported/no-evidence assertion → `unsupported_assertion`
- logged-page privacy boundary: clean `logged_visible` works; cookie/storage/token/auth/request fields refused
- ChatGPT / session / account page → `chatgpt_out_of_scope`
- malformed JSON, oversized visible_text, extra keys, URL userinfo fail closed
- CLI/MCP `analyze-page` / `changeguard_analyze_page` stable-field equivalence; target tree hash unchanged
- disclosure refused/not_requested → zero page transport calls; logged_visible never transports; approved requires injection
- wrong mechanism (non-matching stack) → `wrong_mechanism`; destructive shell DSL not eligible for validation

## Ticket 10 Scenario Harness (upstream draft routing — preview only)

Black-box and contract coverage in `tests/ticket10-upstream-preview.test.ts`:

- four routes: `GITHUB_ISSUE`, `GITHUB_DISCUSSIONS`, `BUGCROWD`, `OPENAI_SUPPORT`
- four Issue forms: APP / CLI / EXTENSION / OTHER (`1-codex-app.yml`, `3-cli.yml`, `2-extension.yml`, `4-bug-report.yml`)
- security → Bugcrowd private-only (no public Issue draft body)
- exact duplicate zero Evidence Delta → `subscribe_or_upvote`, null body/comment, empty cross-links
- exact duplicate material Evidence Delta → structured comment preview
- related-not-same → separate body + cross-links
- new incident → `open_new` with maintainer-value body; facts/reports/hypotheses separated
- content-addressed `capsule_id` / `capsule_content_sha256`: two new incidents with same routing and empty delta but different behavior yield distinct ids/hashes
- maintainer-value gate fails when technical signals or privacy review missing (`GATE_FAILED`, `ok: false`, recommendation `blocked`, null drafts; free text stripped)
- privacy_review.passed = no injection AND request secrets_redacted AND paths_redacted AND session_excluded (not OR-lifted from doctor; same four operands as gate privacy check)
- privacy/gate failure precedes BUGCROWD `ROUTED_PRIVATE`; only gate-passed private route is `ROUTED_PRIVATE`
- doctor sanitization + inclusion manifest; forbidden doctor keys fail closed; secrets/paths redacted in doctor_inclusion only
- immutable form snapshot integrity (main commit + blob SHAs + `integrity_sha256`); stale vs fresh labels
- approved fake form transport (one call, official allowlist only); refused / zero transport (`transport_calls: 0`)
- injected transport refresh failure: `transport_calls: 1` / `network_used: true` but `source=bundled_immutable` with bundled freshness (never transport_refresh/live)
- prompt injection quarantine (`PREVIEW_BLOCKED`); platform/version side-channels scanned after NFKC + format/ZWSP/bidi strip; CLI/MCP side-channel coverage
- export invariant: only `PREVIEW_READY` may export public/discussion drafts; `blocked` for blocked/failed; zero-delta exact dup keeps `subscribe_or_upvote` + null drafts + no cross-links
- schema contracts: exact `QuarantineRecord` shape; allowlisted doctor `sanitized_summary` (`additionalProperties: false`)
- malformed/oversized/extra fields fail closed
- CLI/MCP `upstream-preview` / `changeguard_upstream_preview` stable-field equivalence; target tree hash unchanged
- package-smoke invokes packaged `upstream-preview` for PREVIEW_READY (exit 0) and PREVIEW_BLOCKED (nonzero, null drafts, no raw injection) from outside repo cwd
- capsule never `SUBMITTED`/`POSTED`; `external_write: false`; schema `preview_only`

## Ticket 11 Scenario Harness (confirmed upstream actions)

Black-box and contract coverage in `tests/ticket11-upstream-actions.test.ts`:

- capsule gate: only integrity-valid `PREVIEW_READY` capsules with privacy + maintainer gate + actionable recommendation; blocked/injection and content-hash tamper refused
- each action preview: `create_issue`, `comment_with_delta`, `react_upvote`, `subscribe`, `attachment_upload`
- attachment privacy failure refused; wrong recommendation/action pairing refused
- success via controlled remote double → minimal Upstream Contribution Receipt (no body/secrets/repair status)
- cancellation remains pure draft; nonce consumed (no later confirm)
- auth unavailable / default unavailable adapter never simulate success
- invalid / expired / replayed confirmation refused
- idempotency: exact same diagnosis/action returns `DUPLICATE_EXISTING` with existing receipt
- timeout found → existing receipt; timeout not-found/uncertain/query-throw → `UNCERTAIN_NO_RETRY` + durable `terminal_uncertain` (no blind retry; second call `REPLAYED_CONFIRMATION`, `executeCalls` stays 1)
- durable confirmation ledger (HMAC key + registered/consumed/terminal_uncertain, TTL, capacity, symlink-safe atomic replace); CLI cross-process preview/cancel/replay; offline forge / non-official target / tampered body or attachment refused
- CLI/MCP `upstream-action-preview` / `changeguard_upstream_action_preview` equivalence; production path `network_used: false`, auth `unavailable`
- target tree hash unchanged; no token/cookie leakage in JSON
- package-smoke: packaged action-preview exit 0, confirm without adapter → `ADAPTER_UNAVAILABLE`, blocked capsule refused

## Ticket 16 release / privacy / regression gate

Canonical command (one summary JSON; fail-closed; never `scripts/run-verification.sh`):

```bash
npm run verify:release
```

Orchestrator: `scripts/verify-release.mjs`. Ordered mandatory steps and stable reason codes:

| Order | Step id | Reason on failure | Kind |
| --- | --- | --- | --- |
| 1 | `typecheck` | `GATE_TYPECHECK` | `npm run typecheck` |
| 2 | `test` | `GATE_TEST` | `npm test` |
| 3 | `boundary` | `GATE_BOUNDARY` | `npm run check:boundary` |
| 4 | `boundary_selftest` | `GATE_BOUNDARY_SELFTEST` | `node scripts/check-production-boundary.mjs --self-test` |
| 5 | `schema` | `GATE_SCHEMA` | pure schema structural + fixture bind |
| 6 | `fixture_accounting` | `GATE_FIXTURE_ACCOUNTING` | pure 2/2/3 public-seam accounting |
| 7 | `privacy` | `GATE_PRIVACY` | pure outbound/capsule/doctor zero-leak corpus |
| 8 | `injection` | `GATE_INJECTION` | pure injection/evidence matrix bind |
| 9 | `write_path` | `GATE_WRITE_PATH` | pure production write-path inventory |
| 10 | `package` | `GATE_PACKAGE` | `npm run package` |
| 11 | `package_smoke` | `GATE_PACKAGE_SMOKE` | `npm run package:smoke` |
| 12 | `package_audit` | `GATE_PACKAGE_AUDIT` | pure package threat audit |
| 13 | `cli_hash` | `GATE_CLI_HASH` | `node scripts/cli-hash-proof.mjs` |
| 14 | `diff_check` | `GATE_DIFF_CHECK` | `git diff --check` |

Exit 0 only when every step passes. First failure prints bounded JSON
`{ok:false, failed_step, reason_code, steps}` and exits nonzero. Unknown CLI
arguments or unknown `--self-test=` modes fail with `GATE_UNKNOWN_STEP`.

### Fixture accounting (2 / 2 / 3)

Mechanical public-seam binds (test file + name substring + fixture path); does not re-run repair engines:

| Bucket | Min | Example binds |
| --- | --- | --- |
| `resolved_verified` | ≥2 | T02 protected-process repair; T07 config_set; T08 plugin-cache |
| `mitigation_or_upstream_blocked` | ≥2 | T06 surface rollback mitigation; T09 crash UPSTREAM_BLOCKED; T02 explicit rollback |
| `wrong_repair_refusal` | ≥3 | T02 negative control; T07 wrong candidate; T09 symptom repair refuse; T08 plugin-cache negative |

### Privacy zero-leak corpus

- Inspects redactor, instrumented transport (refuse + approved), outbound request shapes, capsule/doctor export seams when present.
- `external_disclosure_count === 0` required.
- Failure output uses label digests/seams only — never emits corpus secret values.
- Stdout redaction alone is not sufficient.

### Injection / evidence matrix

Binds existing Ticket 05/04/10/11/12/09/15 tests for malicious page, Issue/upstream injection, official prose quarantine, model edge-escalation refuse, blocked actions, follow-up authority, repair DSL candidate-only, platform capability closed, official-fix supersession.

### Write-path inventory

Every production writer classified as `repair` | `state` | `ledger`. Repair requires backup / atomic replace / rollback markers and companion “RESOLVED_VERIFIED is impossible” on verify failure. State/ledger must not be forced into a false repair contract. Unregistered writers under known write surfaces fail the gate.

### Package threat audit

Audits built `release/codex-changeguard-plugin/`: top-level allowlist, forbidden paths, no `node_modules`, no dynamic install scripts, no runtime deps, MCP node-only. Executable capability scan (not prose word-search): `setInterval` = daemon; bounded `setTimeout` alone is not; network modules, child_process in `dist/`, telemetry hosts, OpenAI binary names, planted secrets. Plant negatives use an isolated temp copy and never poison canonical `release/`.

### Gate-of-gate negative controls

Public script only (`node scripts/verify-release.mjs --self-test=<mode>`). Do **not** recursively invoke full `verify:release` from `npm test`.

| Mode | Expected reason |
| --- | --- |
| `undercount` | `GATE_FIXTURE_ACCOUNTING` |
| `fixture_missing_test` | `GATE_FIXTURE_ACCOUNTING` |
| `privacy_poison` | `GATE_PRIVACY` |
| `missing_writer` | `GATE_WRITE_PATH` |
| `schema_fail` | `GATE_SCHEMA` |
| `package_secret` / `package_network` / `package_shell` / `package_daemon` / `package_binary` | `GATE_PACKAGE_AUDIT` |
| `unknown_step` | `GATE_UNKNOWN_STEP` |
| unknown arg / unknown self-test mode | `GATE_UNKNOWN_STEP` |

Coverage: `tests/ticket16-release-gate.test.ts`.

## Initial commands

```bash
npm ci
npm run typecheck
npm run build
npm test
npm run check:boundary
npm run package
npm run package:smoke
npm run verify:release
node scripts/cli-hash-proof.mjs
node scripts/check-production-boundary.mjs --self-test
node bin/changeguard.js diagnose fixtures/protected-process
node bin/changeguard.js diagnose fixtures/negative-control
node bin/changeguard.js diagnose fixtures/crash-family/access-violation-crbrowser
node bin/changeguard.js impact fixtures/impact-local --disclose-refused
# Ticket 05 (orchestrator-supplied page envelope; no hidden network):
# node bin/changeguard.js analyze-page fixtures/protected-process --envelope=fixtures/page-evidence/valid-protected-process.json --disclose-refused
# Ticket 10 (upstream draft preview only; no external write):
# node bin/changeguard.js upstream-preview fixtures/protected-process --request=fixtures/upstream/request-new-incident-cli.json --disclose-refused
# Ticket 11 (confirmed actions; production injects no real adapter):
# node bin/changeguard.js upstream-action-preview <target> --capsule=<capsule.json> --action=create_issue
# node bin/changeguard.js upstream-action-confirm <target> --confirmation=<ua1.…> --decision=cancel
# Ticket 02 (isolated disposable copy only):
# node bin/changeguard.js repair-preview <isolated-target>
# node bin/changeguard.js repair-apply <isolated-target> <authorization_binding>
# node bin/changeguard.js verify <isolated-target>
# node bin/changeguard.js rollback <isolated-target>
# Ticket 03 (inventory fixtures built in tests; illustrative CLI forms):
# node bin/changeguard.js scan <inventory-root>
# node bin/changeguard.js scan-system --state-dir=<dir>
# node bin/changeguard.js session-start <inventory-root> --hook-trust=trusted
```

A clean source checkout is not claimed runnable before `npm ci && npm run build`
(or `npm run package`). Generated `dist/` need not be committed when package +
package smoke prove the published artifact.

Additional static checks remain:

- official Plugin validator (when available)
- JSON syntax and JSON Schema meta-validation
- fixture validation against schemas
- Markdown link/path verification
- clean Git status after a verified checkpoint

## Ticket 17 — competition demo and release-readiness surface

Ticket 17 is **`LOCAL_COMPLETE`** for the competition-demo and local release-readiness surface on implementation commit `2e5f463250c3749731418b661e1a3527bf049e62` (historical R13 Root: Ticket17 focused **27/27**, full suite **552/552**, `npm run ready:local` 10/10; independent R13 double review both `PASS_NO_P0_P1`). Post-R13 deterministic-tarball correction (current): pure Node **ustar + gzip** with stable order/metadata and symlink/special fail-closed; Root package-repro **9/9**; full suite **561/561** (0 fail, ~73.0s); final `ready:local` 10/10 `ok=true` (all external action flags false); R19 read-only `REPRO_REVIEW: PASS_NO_P0_P1`. Reproducibility is scoped to identical package inputs plus a fixed Node toolchain — not arbitrary Node/zlib identity. Gate C / publication / registration / upload / submission remain `NOT_STARTED`. Local verification themes:

| Theme | Required evidence |
| --- | --- |
| Shared demo core | `/changeguard demo` and `node bin/changeguard.js demo` exercise real fixture/probe path via the same cores as product CLI/MCP — not a static page (`tests/ticket17-demo-*.test.ts`) |
| Disposable temp | Demo targets refuse active `~/.codex` / primary profile; only strict temp descendants mutate; proofs never hash live home/profile |
| No network | Default demo/diagnose production seams: `network_used: false` derived from aggregated seam observations in `security_evidence`; no sockets; no judge API key; no GitHub login |
| Security evidence | Completed demos require `security_evidence.proven`; network observations from diagnose/apply/impact/crash; disposable-root proofs; `local_only_no_adapter`; unproven evidence ⇒ `ok: false` |
| Nested symlink refuse | Allowlisted fixture copy recursively refuses nested symlinks / non-regular objects (source + dest); synthetic nested-symlink tests (`tests/ticket17-demo-core.test.ts`) |
| Schema-valid errors | CLI `INVALID_ARGS` and all public demo receipts satisfy `schemas/demo-receipt.schema.json` including `steps.minItems=10` (schema-level test, not length-only) |
| Rollback + cleanup | Isolated repair demo path: backup → apply → verify → rollback/cleanup; failed verify cannot claim `RESOLVED_VERIFIED` |
| CLI/MCP equivalence | Stable-field match for demo-visible diagnose/repair outcomes |
| Clean-profile uninstall | `npm run package:clean-profile`: isolated temp HOME only; after uninstall no daemon, LaunchAgent/service, shell-profile edit, global Codex config edit, credential requirement, background process, or product-owned residue |
| Packaged judge path | `npm run package` → self-contained tree (+ `.tgz` via pure Node deterministic ustar+gzip); `npm run package:smoke` stages install, runs packaged `demo` from non-repo cwd, checks 10 ordered steps + security_evidence + rollback invariants, uninstalls |
| Deterministic package repro | package-repro focused tests (**9/9**); stable content + tar hashes under identical inputs + fixed Node toolchain; gzip mtime 0 / OS 255; symlink/special fail-closed; system tar extract + extracted demo ok |
| Local readiness aggregator | `npm run ready:local` — package structure, package smoke, clean-profile smoke, docs/legal/parity, boundary, tests, `verify:release`, `git diff --check`; **local only** (no remote/Gate C) |
| Local vs Gate C | `npm run verify:release` / `ready:local` = local automated readiness only; public remote / Release / registration / upload / submission remain Gate C / `NOT_STARTED` |

Ticket 17 / HANDOFF local closeout is complete with historical R13 Root + post-R13 correction evidence above; package smoke alone was never sufficient — Gate C items stay unchecked.

## Ticket 12 — maintainer follow-up / upstream fix

Public seams: `changeguard followup` / MCP `changeguard_followup` / packaged SessionStart follow-up hint.

Required coverage:

- Domain: `tests/ticket12-followup-core.test.ts` (Phase A authority + ledger + disposition)
- P2 hardening: `tests/ticket12-phaseb-p2.test.ts` (version syntax, persistence fail-closed, witness non-mutation, snapshot_path refusal)
- Scenario Harness: `tests/ticket12-followup-harness.test.ts` (CLI/MCP/SessionStart + schema)
- Package smoke: packaged CLI followup status, MCP tool list includes `changeguard_followup`, schema present, SessionStart no path leak

Invariants: no network/daemon/external write; no JSON-serializable live witness; no auto-reopen/cross-post; supersession only with live witness + bundled official bind.
