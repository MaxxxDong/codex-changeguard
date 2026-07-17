# Architecture and Evidence Contracts

This document is the canonical owner of ChangeGuard's product scope, evidence model, detection algorithm, and implementation boundaries.

## 1. Product promise

ChangeGuard answers four different questions without collapsing them:

1. What officially changed between the installed and target Codex versions?
2. Which of those changes deterministically intersect the user's local Codex surface?
3. Which known Issues are plausible matches for the observed failure?
4. What can be safely probed, previewed, or recovered without pretending that correlation is root-cause proof?

The Plugin may precisely detect an affected local pattern when it has an exact artifact, AST, schema, stack, or reproduction match. It may only report a high-confidence Issue candidate when the upstream Issue remains user-reported or the local mechanism has not been reproduced.

## 2. Component model

```text
Trusted SessionStart hint or manual scan
                    |
                    v
Local Fingerprint Collector (deterministic, redacted)
                    |
                    +------> Disclosure Manifest
                    |
                    v
Official Evidence Index
docs / releases / compare / commits / files / Issues / linked PRs
                    |
                    v
Change-to-Local Graph (deterministic edges only)
                    |
                    v
Candidate Retriever + Evidence Gate
lexical/structural retrieval -> semantic rerank -> hard constraints
                    |
                    v
GPT-5.6 Hypothesis Compiler
Impact Contracts and Recovery hypotheses only
                    |
                    v
Allowlisted Probe Registry (deterministic adjudication)
                    |
                    v
Evidence-locked verdict + Recovery Capsule preview
```

### 2.1 Plugin surfaces

- `skills/changeguard/`: user-facing orchestration instructions
- `.mcp.json`: read-only MCP server (`changeguard_diagnose` → shared core)
- `bin/changeguard.js` / `dist/cli/main.js`: Rescue CLI (`changeguard diagnose`)
- `src/core/diagnose.ts`: single shared diagnosis core used by CLI and MCP
- `hooks/hooks.json`: optional `SessionStart` hint after explicit trust (later)
- `schemas/`: portable contracts for fingerprints, claims, probes, and recovery
- lightweight inspector UI: planned only after the CLI/fixture path is verified

### 2.2 Ticket 01 read-only diagnosis spine

Public seams:

1. `changeguard diagnose <isolated-target>` (repository wrapper `bin/changeguard.js`)
2. MCP tool `changeguard_diagnose` with argument `{ target }` only (no extra top-level `tools/call` params)

Both call `diagnose()` and return the same `DiagnosisResult` shape:

- `diagnosis_state` (evidence ladder state; Ticket 01 max is `SOURCE_COMPONENT_LOCATED`)
- `incident_fingerprint` (schema-validated, redacted; nested objects reject extra fields)
- independent `user_resolution` and `upstream_contribution` receipts (distinct receipt IDs)
- `network_used: false`, `target_mutated: false`, `repair_applied: false` (markers only; boundary also enforced by `scripts/check-production-boundary.mjs`)

Core I/O rules:

- read only named candidates (`incident.json`, optional `artifacts/browser-client.mjs`)
- fail-closed no-follow: refuse a target that is itself a symlink; refuse any symlink in any intermediate segment or leaf of named candidates (even if it currently resolves inside the target)
- open with `O_NOFOLLOW` when available, `fstat` the fd, require a regular file, enforce the byte limit from the fd, and compare stable pre-open metadata where meaningful
- explicit byte limits; never recursively crawl a project tree
- independently measure artifact SHA-256 and a syntax-aware structural signature of the exact protected-process shim block; declared JSON hashes/ids never self-prove; fixture `.hash.txt`, incident declared hash, recovery original hash, and measured bytes must agree, and `local_facts_digest` must equal the core recomputation
- surface / error class / failure phase remain applicability gates after independent measurements
- MCP stdio uses a bounded byte-oriented NDJSON frame accumulator; frames with byte length `<= MAX_MCP_REQUEST_BYTES` are accepted, only `>` the limit is rejected, before `JSON.parse`
- Scenario Harness owns whole-target before/after hashing, not the diagnosis core
- Packaging: `npm run package` builds `release/codex-changeguard-plugin/` with exact public top-level surface (`.codex-plugin`, `.mcp.json`, `README.md`, `bin`, `dist`, `docs`, `fixtures`, `package.json`, `schemas`, `skills`); public `docs/` is only `ARCHITECTURE.md`, `SECURITY.md`, `TEST_PLAN.md`, and `CASE_STUDIES.md` (no `docs/agents`); packaged `README.md` omits the repository-only `HANDOFF.md` link; no `node_modules`, `AGENTS.md`, `HANDOFF.md`, `src`, or `scripts`. Package smoke launches MCP via packaged `.mcp.json` and fails on broken local Markdown links or forbidden packaged paths. A clean source checkout is not claimed runnable before `npm ci && npm run build` (or package).

### 2.3 Ticket 02 protected-process verified repair (isolated target)

Product specification is canonical: experimental repair is allowed on an **isolated** target after one scope-bound authorization. This is not a second ad-hoc engine — CLI and MCP call the same recovery modules under `src/core/recovery/`.

Public seams (shared core):

1. `changeguard repair-preview <isolated-target>` / MCP `changeguard_repair_preview` `{ target }`
2. `changeguard repair-apply <isolated-target> <authorization-binding>` / MCP `changeguard_repair_apply` `{ target, authorization }`
3. `changeguard verify <isolated-target>` / MCP `changeguard_verify` `{ target }`
4. `changeguard rollback <isolated-target>` / MCP `changeguard_rollback` `{ target }`

Repair Capsule (preview) includes: one target path alias, original SHA-256, exact expected pattern count, operation digest, authorization tier, risk, verified backup plan, verification plan, rollback recipe, expiry/invalidation digests, and disclosure metadata **without** source bytes or secrets. Preview persists the exact capsule under the isolated target (`.changeguard/capsule-preview.json`) so apply uses the same one-shot binding.

Authorization is deterministically bound to the exact capsule material and live scope. Any target hash, pattern count, scope, operation, permission, or capsule change invalidates the binding. There is no reusable global trust token.

Mutation contract (registered recovery only):

1. resolve isolated target; refuse symlink targets and symlink path segments;
2. re-check opened target identity (TOCTOU);
3. create verified backup of original bytes under `.changeguard/backup/`;
4. write sibling temp, fsync where supported, atomic rename;
5. verify resulting hash/metadata;
6. run original-failure + core-health verification;
7. on any verification failure, automatically restore exact original bytes — `RESOLVED_VERIFIED` is impossible;
8. explicit `rollback` restores original bytes from the verified backup.

`user_resolution.status = RESOLVED_VERIFIED` requires: original protected-process failure no longer reproduces **and** registered core health checks pass. User-resolution and upstream-contribution receipts remain independent; recovery never claims external submission.

Diagnosis modules stay read-only. The production-boundary guard allows only a narrow registered write method set inside `src/core/recovery/`; network, shell, loaders, and host-capability controls remain fail-closed everywhere.

## 3. Detection and localization ladder

| Level | State | Minimum evidence | Permitted claim | Forbidden claim |
|---:|---|---|---|---|
| 0 | `INCONCLUSIVE` | Missing or conflicting version/platform/surface facts | Insufficient evidence; list missing probes | Healthy, fixed, or no issue |
| 1 | `SIGNATURE_DETECTED` | Stable normalized error, stack, phase, or AST signature | A local failure signature was observed | Matching a specific Issue or cause |
| 2 | `ISSUE_CANDIDATE` | Retrieval score passes candidate threshold | These upstream reports are candidates | This Issue is the root cause |
| 3 | `HIGH_CONFIDENCE_MATCH` | Version, platform, surface/component gates plus a strong structural or semantic signature | The local incident matches this Issue pattern with high confidence | Officially confirmed cause unless the upstream graph says so |
| 4 | `SOURCE_COMPONENT_LOCATED` | Local artifact/file/symbol/schema/AST match with hash or stable structural evidence | The affected local component or exact pattern is located | The complete causal mechanism is reproduced |
| 5 | `LOCAL_REPRO_CONFIRMED` | Allowlisted probe reproduces the mechanism and a negative control does not | The same local failure mechanism was reproduced | Every report with similar wording has the same cause |
| 6 | `FIX_COMMIT_LINKED` | Issue/PR/commit/release relationship is verified from official sources | An official or maintainer-linked fix exists | The installed system is fixed without version/probe evidence |
| 7 | `SAFE_FIX_AVAILABLE` | Applicable fix, exact backup, dry-run, smoke, rollback, and receipt all pass | A reversible fix is available for explicit approval | Silent or risk-free automatic repair |
| — | `CONFLICT` | Strong evidence sources disagree | Evidence conflicts; show both sides | Pick the most convenient explanation |

Levels 3–6 are not a single linear counter: component localization, local reproduction, and upstream fix linkage are separate evidence axes. The UI shows each axis rather than hiding them behind one confidence number.

## 4. Incident fingerprint

Stable fields:

- installed Codex version and optional build SHA
- surface: Desktop, CLI, plugin, MCP, browser control, app-server
- OS, architecture, sandbox/permission profile
- normalized error class and message tokens
- stack frames: package/module, file basename, symbol, line bucket
- failure phase: startup, hook load, extension handshake, tab discovery, navigation, tool call, output decode, shutdown
- config-key presence and schema validity; never credential values
- enabled feature, Skill, Plugin, and MCP identifiers
- installed artifact hashes and safe AST signatures

Allowed normalization:

- replace usernames, workspace roots, random IDs, timestamps, ports, and memory addresses with typed placeholders
- line-number bucketing when builds cause small drift
- canonicalize path separators and platform aliases
- preserve error class, symbol, module, feature key, failure phase, and version range

Forbidden over-normalization:

- removing OS/surface/version distinctions
- merging different exception classes into a generic error
- discarding negation, permission mode, sandbox state, or pre/post-handshake phase
- treating translated prose similarity as equivalent stack or component evidence

## 5. Issue matching

Candidate retrieval is hybrid but evidence-gated:

1. Hard prefilter on repository, surface, platform compatibility, and version range when known.
2. Structural retrieval over error class, stack symbol, component, config keys, artifact/AST signatures, and failure phase.
3. Lexical BM25 over sanitized titles and descriptions.
4. GPT-5.6 or embeddings may rerank surviving candidates, but cannot bypass hard gates.
5. Deterministic probes produce supporting or counter evidence.

Proposed score before hard gates:

```text
0.28 exact_or_structural_signature
+ 0.14 platform_arch
+ 0.12 version_range
+ 0.12 surface_component
+ 0.10 stack_symbol
+ 0.08 config_feature_keys
+ 0.10 failure_phase
+ 0.06 upstream_linkage
- explicit_negative_evidence
```

- Candidate threshold: `>= 0.55`
- High-confidence threshold: `>= 0.82`
- High confidence additionally requires compatible platform, version or an explicit unknown-version label, matching surface/component, and at least one stack/symbol/AST/schema/reproduction signature.
- A local deterministic reproduction may establish the mechanism even when Issue prose is poor; it does not invent upstream confirmation.

## 6. Change-to-Local Graph

Allowed deterministic edge types:

- official commit/file/hunk -> config schema key
- official file/module -> local installed artifact or package
- official component -> enabled Skill/Plugin/MCP/feature identifier
- Issue -> linked PR -> commit -> release
- installed version -> official tag/compare range
- probe -> observed local evidence

GPT-5.6 can explain existing edges and compile hypotheses from them. It cannot call `add_edge`, change an evidence source's provenance, or upgrade a user report to an official statement.

## 7. Probe contract

Every probe is registered code, not model-generated shell. It declares:

- probe ID and schema version
- supported platform/surface and preconditions
- allowlisted operations and structured arguments
- timeout and output-size cap
- expected evidence and counter evidence
- sensitive-data/redaction policy
- input digest and result hashes
- result: pass, fail, not-applicable, error, or refused

MVP allowlist:

- read version and file metadata
- hash a reviewed file
- validate TOML/JSON against a schema
- count or match an AST pattern
- inspect a safe property descriptor
- run syntax validation on a disposable copy
- execute bundled synthetic fixtures

Network access, arbitrary shell, privilege elevation, and writes to installed files are not probe operations.

## 8. Recovery trust and transaction contract

| Trust tier | Source | Preview | Dry-run | Apply (product spec) |
|---|---|---:|---:|---|
| T4 | Official released fix | yes | yes | upgrade guidance only (no local binary rewrite) |
| T3 | Official merged commit, not released | yes | fixture/disposable copy | experimental only after isolated proof |
| T2 | Maintainer-confirmed workaround | yes | fixture/disposable copy | experimental only after isolated proof |
| T1 | Community workaround | yes (quarantined) | fixture/disposable copy | **Ticket 02:** one experimental apply on isolated protected-process fixture after scope-bound authorization |
| T0 | Model-generated fix | hypothesis only | generated test fixture only | not auto-applied |

Ticket 02 implements the explicitly authorized apply path for the isolated protected-process fixture only:

1. resolve and classify the exact target path under an isolated root;
2. record original bytes, metadata, and SHA-256;
3. require the expected pattern count and applicable hash;
4. create a verified backup;
5. write a sibling temporary file and atomically replace;
6. run original-failure + core-health verification;
7. restore exact original bytes on any failure (automatic rollback);
8. emit receipts without secrets or full file contents; never claim external submission.

## 9. Update detection

There is no assumed native software-update event.

- Trusted `SessionStart` hook: enumerate Desktop-bundled and PATH Codex binaries separately, compare version/build fingerprints with last-seen local state, and offer a scan when any fingerprint changes.
- First install: establish a baseline; do not claim an update.
- Downgrade: display a reverse delta.
- Multiple binaries: never collapse them; show path hashes and surface labels.
- Hook skipped, untrusted, or failed: preserve `/changeguard scan` and expose hook status honestly.

## 10. Primary fixtures

### Fixture A — protected process shim

Inputs:

- known affected `browser-client.mjs` SHA-256 (independently measured from fixture bytes; also recorded in `.hash.txt`, incident `artifact_hashes`, and recovery `backup.original_sha256`)
- the exact three-statement protected-process shim block (structural match, not regex over raw text):
  - `globalThis.process = <shim>;`
  - `globalThis.global = globalThis.global ?? globalThis;`
  - `globalThis.global.process = <same shim>;`
- exactly one such block per file; comments, string/template contents, and regex literals cannot spoof a match
- failure phase before extension handshake (applicability gate)
- community Issue comment as untrusted workaround evidence

Expected path:

1. Detect error/phase/surface applicability gates from the incident.
2. Hash the packaged copies and identify identical artifacts via independent SHA-256.
3. Match the structural shim signature and require exactly one target block per file.
4. Report Issue #32925 as a candidate; the comment remains community evidence.
5. Run the property-descriptor and bundled module fixture probes (later tickets for live repro).
6. Reach `SOURCE_COMPONENT_LOCATED` from measured hash + structural signature + gates; reach `LOCAL_REPRO_CONFIRMED` only if the deterministic fixture reproduces and the negative control does not.
7. Produce a T1 Repair Capsule preview for the local shim on an isolated target. Ticket 02 may apply one experimental repair only after exact scope-bound authorization; never patch real Codex/Profile installs or non-isolated caches.

The precise claim is: “The exact affected pattern is present in these local artifacts and the bundled probe reproduces the same protected-process failure mechanism.” It is not: “OpenAI officially confirmed Issue #32925 as the root cause.” After verified repair on an isolated fixture, `RESOLVED_VERIFIED` means only that the original local failure no longer reproduces and core health checks passed.

### Fixture B — invalid TOML setup hang

Synthetic Windows config with an invalid `shell_environment_policy.set` value. The TOML/schema probe must identify the invalid structure; Issue #33790 remains a user-reported pattern unless official linkage exists.

### Fixture C — untracked Skill handoff omission

Synthetic repo containing tracked, ignored, and nonignored untracked Skill files. A deterministic manifest/diff probe confirms whether the handoff payload omitted the nonignored file; Issue #33789 is then ranked with platform/version labels.

### Fixture D — negative control

A superficially similar startup error from macOS with a different module, configurable `process`, and no matching AST block. The matcher must refuse the Windows TOML and protected-process Issues and return `INCONCLUSIVE` or a low-confidence candidate.

### Fixture E — Windows in-app Browser crash family

A sanitized Windows fixture models a full desktop exit after the in-app Browser is attached. The same user-visible symptom has multiple upstream candidates and must fork on deterministic evidence instead of title similarity:

- `0xC0000005`, `CrBrowserMain`, and `chrome.dll+0x2e08f46` after a neutral page reaches DOM-ready point toward openai/codex#32683.
- `0xc06d007f` after a link or button interaction points toward openai/codex#33710.
- GPU child exit `101457950` followed by relaunch failure `18` on media/canvas-capable pages points toward openai/codex#32094.
- a crash only under several concurrent side chats, immediately after Browser WebView attachment, points toward openai/codex#33202.

The fixture may rank these as Issue candidates. It reaches `LOCAL_REPRO_CONFIRMED` only when a safe neutral-page probe reproduces the same local signature and a no-Browser control does not. Disabling the in-app Browser or using external Chrome is a mitigation, not proof of the native root cause. Security software, storage pressure, and GPU hypotheses remain separate until controlled A/B evidence supports them.

### Fixture F — underspecified session-expired boundary

A ChatGPT report containing only “session expired” plus an unverified claim about changing IP addresses must not be mapped to a Codex source component. ChangeGuard may run an adjacent authentication/network playbook using status, surface, version, sign-in method, redacted response status, and controlled network comparisons. It must return `INCONCLUSIVE` until one of these branches is supported:

- active service incident;
- VPN/proxy/firewall/SSL-inspection path failure;
- authentication-method or SSO mismatch;
- app/browser-local storage or session-state failure;
- unresolved account-side invalidation requiring OpenAI Support.

The playbook never reads or exports cookie values, tokens, passwords, one-time codes, or full browser storage. A changed public IP is a hypothesis, not a permitted root-cause claim.

## 11. Competition MVP

### Must

- Plugin manifest and one installable Skill path
- read-only local fingerprint collector
- pinned official evidence snapshot plus official-only refresh interface
- deterministic Change-to-Local Graph
- evidence-gated Issue matcher
- Impact Contract schema
- allowlisted probe registry
- Fixtures A and D, including negative control
- Fixture E crash-family classifier and Fixture F evidence-boundary case
- disclosure manifest and repro-pack export
- English README, install/platform/judge instructions, live fixture path, tests

### Should

- Fixture B or C
- `SessionStart` version-change hint after trust
- Recovery Capsule preview (Ticket 02 implements isolated protected-process preview + authorized apply/verify/rollback)
- lightweight inspector UI

### Later

- authenticated official GitHub refresh
- broader version history and more platforms
- source-map-aware packaged-code mapping
- broader apply/rollback beyond the Ticket 02 isolated protected-process vertical slice

### Not Doing

- universal root-cause claims
- automatic execution of community patches
- arbitrary shell probes
- hidden upload of configs, sessions, or environment data
- real-time indexing of every external forum
- merging SpecTrial into this product

## 12. Precise capability statement

ChangeGuard can precisely identify a local affected pattern when hashes, AST/schema signatures, stack/component evidence, or deterministic reproduction agree. It can rank and explain upstream Issue candidates using version, platform, surface, component, and failure-stage evidence. It does not claim that a similar Issue is the root cause until local reproduction or verified official Issue/PR/commit/release linkage supports that conclusion. When evidence is missing or contradictory, it says so.
