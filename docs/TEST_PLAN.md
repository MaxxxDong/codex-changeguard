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
| Hooks / instances (Ticket 03) | first baseline, unchanged silent SessionStart, multi-instance upgrade, downgrade, PATH precedence drift, actual-instance evidence, ambiguous repair refusal, hook untrusted/skipped/failed, manual scan fallback, CLI/MCP scan equivalence, SessionStart changed/no-change duration &lt;10s, raw-path non-disclosure, symlink state refusal |
| Platform macOS (Ticket 13) | adapter alias/operation/constraint contracts; isolation refuses active `~/.codex` and protected roots; receipt validator Full-only-with-proof + leak refusal; CLI/MCP `platform-status` / `platform-receipt-validate`; real-machine harness on darwin covers core diagnose, multi-instance, config repair, auto-rollback, explicit rollback, plugin-cache repair/rollback, KNOWN_GOOD/canary, privacy refuse, upstream zero-network, package smoke; support matrix docs |
| Judge path | clean install; no judge API key; live matcher/probe; offline snapshot; visible evidence state; under 90 seconds |

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
- CLI/MCP `platform-status` / `platform-receipt-validate` are read-only and path-free
- on a real darwin host, the isolated harness must pass all required scenarios and emit `support_level: full` (otherwise Preview + exact gaps); never fabricates a receipt
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
- real-machine runner plan lists W11-S01…S11 and forbidden actions; validate-receipt-only mode
- CLI `platform-status` / MCP `changeguard_platform_status` PREVIEW equivalence
- no LOCAL_COMPLETE / Full product claim without a real Windows 11 host receipt

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
- package smoke: `npm run package` then `npm run package:smoke` from a non-repo cwd; smoke reads packaged `.mcp.json`, enforces exact top-level allowlist, exact public docs set (`ARCHITECTURE.md`/`SECURITY.md`/`TEST_PLAN.md`/`CASE_STUDIES.md` only), no broken local Markdown links, and no repository-only paths (`AGENTS.md`/`HANDOFF.md`/`docs/agents`/`src`/`scripts`/`node_modules`/`.scratch`)

## Ticket 03 Scenario Harness

Implemented in `tests/instance-scan.test.ts` (public CLI/MCP + shared core):

- first baseline across Desktop / PATH / package-manager / MSIX / WSL identities
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

## Initial commands

```bash
npm ci
npm run typecheck
npm run build
npm test
npm run check:boundary
npm run package
npm run package:smoke
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
