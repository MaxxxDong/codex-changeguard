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

### Session-expired evidence boundary

- a symptom-only report returns `INCONCLUSIVE`, not an invented IP-change root cause
- status, surface, app/browser version, sign-in method, and network A/B results may be collected without credential values
- tokens, cookies, account identifiers, passwords, one-time codes, and full browser storage never enter the fingerprint or disclosure manifest
- the resolver distinguishes service incident, network/security control, authentication-method mismatch, local session state, and unresolved account-side failure

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
