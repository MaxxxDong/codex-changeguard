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
| Hooks | first install, upgrade, downgrade, multiple binaries, hook untrusted, hook failure, and manual scan fallback |
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
# Ticket 02 (isolated disposable copy only):
# node bin/changeguard.js repair-preview <isolated-target>
# node bin/changeguard.js repair-apply <isolated-target> <authorization_binding>
# node bin/changeguard.js verify <isolated-target>
# node bin/changeguard.js rollback <isolated-target>
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
