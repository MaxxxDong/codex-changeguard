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
- `.mcp.json`: MCP server (`changeguard_diagnose`, `changeguard_impact`, `changeguard_analyze_page`, recovery tools, `changeguard_scan`, `changeguard_scan_system`, `changeguard_session_start` → shared core)
- `bin/changeguard.js` / `dist/cli/main.js`: Rescue CLI (`diagnose|impact|analyze-page|repair-*|verify|rollback|scan|scan-system|session-start`)
- `src/core/diagnose.ts`: single shared diagnosis core used by CLI and MCP
- `src/core/crash-family.ts`: Ticket 09 Desktop Browser crash-family classifier (deterministic gates; Fixture E)
- `src/core/recovery/`: Ticket 02 isolated protected-process repair + Ticket 07 config set/remove + Ticket 08 plugin-cache recovery (preview/apply/verify/rollback; one engine)
- `src/core/plugin-cache/`: Ticket 08 bounded plugin-cache inventory/manifest observation and mechanism classification (read-only)
- `src/core/config/`: Ticket 07 bounded Codex control TOML parser/validator and fault probe (read-only)
- `src/evidence/*` + `src/impact/*`: official evidence refresh/snapshot, Change-to-Local Graph, Impact Card (Ticket 04)
- `src/page/*`: untrusted page-evidence envelope, extraction, comparison, and candidate-only Repair DSL (Ticket 05)
- `src/instances/`: multi-instance enumeration, version-fingerprint state, affected-instance resolution, repair-target binding contract
- `src/instances/system-adapter.ts`: production registered system enumeration (capability-injectable)
- `src/hooks/`: trusted SessionStart core, packaged SessionStart entrypoint, bounded read-only health check
- `hooks/hooks.json`: optional `SessionStart` registration with `$PLUGIN_ROOT` / `%PLUGIN_ROOT%` (host must explicitly trust)
- `schemas/`: portable contracts for fingerprints, claims, probes, recovery, and version-fingerprint state
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

- read only named candidates (`incident.json`, optional `artifacts/browser-client.mjs`, Ticket 07 registered control paths `config/config.toml`, `config/config.override.toml`, `config/managed.policy.json`, and Ticket 08 named plugin-cache inventory/manifest/entry paths under `plugin-cache/`)
- fail-closed no-follow: refuse a target that is itself a symlink; refuse any symlink in any intermediate segment or leaf of named candidates (even if it currently resolves inside the target)
- open with `O_NOFOLLOW` when available, `fstat` the fd, require a regular file, enforce the byte limit from the fd, and compare stable pre-open metadata where meaningful
- explicit byte limits; never recursively crawl a project tree
- independently measure artifact SHA-256 and a syntax-aware structural signature of the exact protected-process shim block; declared JSON hashes/ids never self-prove; fixture `.hash.txt`, incident declared hash, recovery original hash, and measured bytes must agree, and `local_facts_digest` must equal the core recomputation
- surface / error class / failure phase remain applicability gates after independent measurements
- MCP stdio uses a bounded byte-oriented NDJSON frame accumulator; frames with byte length `<= MAX_MCP_REQUEST_BYTES` are accepted, only `>` the limit is rejected, before `JSON.parse`
- Scenario Harness owns whole-target before/after hashing, not the diagnosis core
- Packaging: `npm run package` builds `release/codex-changeguard-plugin/` with exact public top-level surface (`.codex-plugin`, `.mcp.json`, `README.md`, `bin`, `dist`, `docs`, `fixtures`, `hooks`, `package.json`, `schemas`, `skills`); public `docs/` is only `ARCHITECTURE.md`, `SECURITY.md`, `TEST_PLAN.md`, and `CASE_STUDIES.md` (no `docs/agents`); packaged `README.md` omits the repository-only `HANDOFF.md` link; no `node_modules`, `AGENTS.md`, `HANDOFF.md`, `src`, or `scripts`. Package smoke launches MCP via packaged `.mcp.json` and fails on broken local Markdown links or forbidden packaged paths. A clean source checkout is not claimed runnable before `npm ci && npm run build` (or package).

### 2.3 Ticket 02 protected-process verified repair (isolated target)

Product specification is canonical: experimental repair is allowed on an **isolated** target after one scope-bound authorization. This is not a second ad-hoc engine — CLI and MCP call the same recovery modules under `src/core/recovery/`.

Public seams (shared core):

1. `changeguard repair-preview <isolated-target>` / MCP `changeguard_repair_preview` `{ target }`
2. `changeguard repair-apply <isolated-target> <authorization-binding>` / MCP `changeguard_repair_apply` `{ target, authorization }`
3. `changeguard verify <isolated-target>` / MCP `changeguard_verify` `{ target }`
4. `changeguard rollback <isolated-target>` / MCP `changeguard_rollback` `{ target }`

Repair Capsule (preview) includes: one target path alias, original SHA-256, exact expected pattern count, required expected result SHA-256, operation digest, authorization tier, risk, verified backup plan (registered backup relative path only), verification plan, rollback recipe, nonce, expiry/invalidation digests, and disclosure metadata **without** source bytes or secrets. Preview is completely read-only over the entire target tree — it does **not** write `.changeguard/` or any other target-local state. Cross-process CLI/MCP preview→apply uses a self-contained bounded authorization token (`cg1.…`) whose expiry and capsule material are encoded so apply can reconstruct and revalidate without process-global memory or a daemon.

Authorization is deterministically bound to the exact capsule material (including nonce, expiry, expected result hash, and registered backup path) and live scope. Any target hash, pattern count, scope, operation, permission, or capsule change invalidates the binding. Decoded capsules reject unknown/extra/mismatched fields. Apply and rollback never trust a backup path from mutable token or session JSON — backup writes always use the registered constant under `.changeguard/backup/`. There is no reusable global trust token. After a successful apply the same token is consumed in ChangeGuard-owned session state and cannot apply again; after explicit rollback the token remains consumed so it cannot silently re-authorize a different session.

Mutation contract (registered recovery only):

1. resolve isolated target; refuse symlink targets and symlink path segments;
2. decode and strictly validate the self-contained authorization token; refuse expired/replayed tokens;
3. re-check opened target identity (TOCTOU) and revalidate every live precondition against the token;
4. create verified backup of original bytes under the registered `.changeguard/backup/` path (first authorized write);
5. write sibling temp, fsync where supported, atomic rename;
6. verify resulting hash/metadata;
7. run original-failure + core-health verification;
8. on any verification failure, automatically restore exact original bytes — `RESOLVED_VERIFIED` is impossible;
9. explicit `rollback` restores original bytes from the verified backup using the registered path only.

`user_resolution.status = RESOLVED_VERIFIED` requires: original protected-process failure no longer reproduces **and** registered core health checks pass. User-resolution and upstream-contribution receipts remain independent; recovery never claims external submission.

Diagnosis modules stay read-only. The production-boundary guard allows only a narrow registered write method set inside the exact `src/core/recovery/atomic-write.ts` module (`writeSync`/`fsyncSync`/`renameSync`/`mkdirSync`/`unlinkSync` plus proven write open flags); `rmSync`, `copyFileSync`, recursive delete, and write APIs in any other recovery/CLI/MCP/core module are rejected. Network, shell, loaders, and host-capability controls remain fail-closed everywhere.

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

### 6.1 Ticket 04 official evidence refresh and Impact Card

Public seams (in addition to Ticket 01 diagnose):

1. `changeguard impact <isolated-target> [--disclose-approved|--disclose-refused]`
2. MCP tool `changeguard_impact` with `{ target, disclosure_decision? }`

Shared core: `src/impact/assess.ts` → `src/evidence/*` + deterministic matchers in `src/impact/*`.

Contracts:

- **Disclosure first:** `buildDisclosureManifest(local_context)` always runs before any transport use. Each field records `field_name`, `trust_class`, `source_class`, `transformation`, `destination`, `purpose`, and `optional`. The manifest's non-`device_only` field set is exactly the sanitized outbound `OfficialTransportRequest` key set (fixed allowlist metadata + only populated sendable local fields: version/surface/platform/config key names/feature ids/error class). Explicit device-only exclusions document paths/secrets/logs/sessions/source as never sent. `refused` / `not_requested` still load the bundled timestamped snapshot and set `transport_calls: 0` with `transport_request: null` (never invoke transport).
- **Official evidence items** cover kinds `doc | release | tag | diff | issue | pr | commit` with `canonical_url`, derived `origin`, `fetched_at`, `version_range`, `evidence_state`, `content_sha256`, and `snapshot_id`. Item `content_sha256` is over canonical persisted material (kind/url/origin/title/structured/version_range/maintainer_status/evidence_state/quarantine) and is fail-closed on missing/malformed/mismatch. Snapshot `content_sha256` is over full validated items + metadata and is fail-closed (never silently recomputed). Serialized `origin` is never trusted; origin is derived from the validated URL and mismatches fail closed. `origin_allowlist` must be the exact official allowlist or an exact validated subset. Hosts/repos are allowlisted (`github.com` / `api.github.com` / `raw.githubusercontent.com` + `openai/codex` only); userinfo and non-default ports are rejected; fragments and query strings are stripped from the canonical resource URL. Schemas and sizes are bounded.
- **Transport interface** (`OfficialTransport`) is injectable only by trusted orchestration after disclosure approval. The approved transport receives exactly the disclosed payload and nothing else. Production CLI/MCP never open sockets; they accept at most a disclosure decision and use the local snapshot (or stale fallback when approved without a transport). Scenario Harness proves online refresh with a deterministic **fake** transport and zero calls on refusal. Transport `fetched_at` is syntax- and future-skew-validated; ancient/high-stale responses cannot be labeled `fresh`/`live_refresh` (stale fallback; no fresh+high contradiction).
- **Offline / transport failure:** immutable snapshot with `evidence_state: stale|snapshot`, `stale_age_seconds`, and `stale_risk` (`none|low|medium|high|unavailable`).
- **Untrusted prose:** release notes, Issue/PR/comment/commit text are data. Instruction-like content is quarantined (`quarantine` record + placeholder); never executed, interpolated as instructions, or accepted as code/commands/patches. `maintainer_status` stays separate from quarantine.
- **Change-to-Local Graph:** edges only from registered matchers (`version_tag_to_installed`, `config_key_intersection`, `component_to_feature`, `component_to_plugin_skill_mcp_hook`, `artifact_alias_intersection`, `surface_runtime_intersection`, `platform_intersection`). Version-range null endpoints are non-participating (not wildcards); both-null never creates a version edge. Model payloads cannot add/modify edges, provenance, confidence, or evidence state (`refuseModelGraphMutation`).
- **Impact Card:** only changes with a deterministic intersection to the observed instance/config key/Plugin/Skill/MCP/Hook/runtime/artifact surface. Wrong intersections → `REJECTED_WRONG_INTERSECTION`. Changes without a registered mapper → `UNMAPPED_CHANGE` (does not mark the whole version unsupported). Public outputs separate `observed_facts`, `user_reports`, and `hypotheses`. Markers: `network_used: false`, `target_mutated: false`, `repair_applied: false`.

### 6.2 Ticket 05 untrusted page / URL diagnosis

Public seams (shared core `src/page/analyze.ts`):

1. `changeguard analyze-page <isolated-target> --envelope=<page-envelope.json> [--disclose-approved|--disclose-refused]`
2. MCP tool `changeguard_analyze_page` with `{ target, envelope, disclosure_decision? }`

Contracts:

- **Page-evidence envelope:** bounded JSON (`schema_version`, `url`, `page_mode` `public|logged_visible`, `visible_title`, `visible_text`, allowlisted `metadata` only). Extra keys fail closed. Forbidden privacy fields (`cookie`/`storage`/`token`/`authorization`/`request_body`/session material and variants) are rejected — logged-page mode never reads Cookie, Storage, tokens, auth headers, request bodies, or complete browser requests.
- **Orchestrator-supplied content first:** production CLI/MCP accept sanitized visible document content from the orchestrator. Optional public retrieval requires explicit displayed disclosure **and** an injected bounded `PageTransport`; production seams never inject transport (`transport_calls: 0`, no hidden network). `logged_visible` never uses transport.
- **Extraction labels:** separately record `observed_facts`, `author_claims`, `commands_workarounds`, and `inferences`, plus structured symptoms/platform/surface/versions/errors/stack symbols/failure phase/operations/cited sources/conclusions. All page-derived values carry `trust: untrusted_page`.
- **Quarantine:** all page text—including prompt injection, agent instructions, encoded/full-width variants, data-exfiltration requests, and shell fences—is untrusted data. Instruction-like content is quarantined. Page text cannot alter policy, provenance, local facts, deterministic graph edges, authorization, paths, disclosure decisions, or tool selection (`policy_mutations_blocked: true`).
- **Repair DSL candidates only:** page commands convert to bounded untrusted Repair DSL candidates (`status: candidate_only`, `trust: untrusted_page`). Never execute, authorize, or upgrade them. Ticket 02 experimental repair gates remain the only apply path. `repair_authorized: false` always on this seam.
- **Comparison:** compare page claims with the local Incident Fingerprint (via shared diagnose). Output applicability, missing evidence, refuting evidence, risk, safe isolation experiment, and whether a candidate is eligible to enter later Repair Capsule **validation** (not apply). Confidence is hard-capped (`none|low|medium`); wrong platform/surface/mechanism cannot gain high confidence from lexical similarity.
- **ChatGPT hard gate:** generic ChatGPT/account/session pages (`chatgpt.com`, `chat.openai.com`, session-expired/account language without Codex surface signals) map to `chatgpt_out_of_scope` and cannot become Codex component defects.
- Markers: `network_used: false`, `target_mutated: false`, `repair_applied: false`, `repair_authorized: false`.

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

## 9. Update detection (Ticket 03)

There is no assumed native software-update event.

### 9.1 Instance enumeration

ChangeGuard enumerates Desktop-bundled, PATH, supported package-manager, Windows MSIX, and WSL candidates as **separate identities**. Multiple instances never collapse into one row.

Two public enumeration modes share the same scan core:

| Mode | Public seams | Discovery |
| --- | --- | --- |
| Fixture inventory | `changeguard scan <inventory-root>`, MCP `changeguard_scan` | Isolated `inventory.json` under an explicit inventory root (tests/demo) |
| Registered system adapter | `changeguard scan-system`, MCP `changeguard_scan_system`, packaged SessionStart | Bounded known candidates only: Desktop paths, PATH `codex` entries (hard-capped), registered package-manager roots, Windows MSIX / App Execution Alias paths, WSL paths |

Production system defaults inspect only known Codex locations and PATH entries under hard caps. They never perform broad home traversal and never execute discovered binaries. Missing permissions or version metadata yield explicit `version_provenance: "unavailable"`.

Platform / env / filesystem capability injection supports deterministic macOS / Windows / Linux / WSL tests.

Each public identity includes:

- stable `instance_id` and `path_hash` / `path_alias` (raw user paths are never exported)
- `surface`, `install_source`, `platform`, `arch`
- profile/config root **aliases** only
- `version` / `build` with `version_provenance`

Version/build evidence is read only from metadata/manifest files (`version.json`, `package.json`, `Info.plist`, `AppxManifest.xml`, or fixture-declared fields) and only under **explicit allowed roots** (inventory root and/or system-adapter trusted install roots). Implicit parent traversal (`../Info.plist`, npm parent paths) is not used; parent metadata requires a separately registered trusted root and remains bounded with Ticket 01-equivalent no-follow checks.

### 9.1.1 macOS platform adapter and support receipts (Ticket 13)

`src/platform/macos/` is the namespaced macOS adapter. It advertises only bounded registered install sources (`desktop_bundled`, `path`, `package_manager`), path-role **aliases** (profile/config/log/cache/crash metadata), and registered operations. Constraints are fixed closed: no broad home crawl, no raw path export, no executing discovered binaries for version, no sudo, no system certificate/proxy/security-control change, no signed-app or OpenAI binary mutation, no active primary-profile mutation.

Public seams:

| Seam | Role |
| --- | --- |
| `changeguard platform-status` / MCP `changeguard_platform_status` | Read-only capabilities + optional receipt validation |
| `changeguard platform-receipt-validate` / MCP `changeguard_platform_receipt_validate` | Strict receipt validation (schema, leak checks, Full-only-with-proof) |
| `npm run harness:macos` / `scripts/run-macos-harness.mjs` | Real-machine isolated Scenario Harness (black-box CLI; disposable temps only) |

`schemas/platform-support-receipt.schema.json` is the receipt contract. Full support is declared only when every required real-machine scenario passes and validation succeeds; otherwise the receipt stays **Preview** with exact `uncovered_gaps`. See `docs/SUPPORT_MATRIX.md`.

### 9.2 Affected-instance resolution

The actually affected instance is resolved from observed process, log, and launch-context evidence (path hash or sole-instance rules). ChangeGuard **never** selects the highest/newest version by default. When evidence does not identify exactly one instance, `affected_resolution` remains `ambiguous`.

### 9.3 Transition classification

Comparing current identities to local version-fingerprint state classifies:

- `first_baseline` (no prior state)
- `upgrade` / `downgrade` / `unchanged`
- `newly_discovered` / `removed`
- `path_precedence_drift` (PATH order changes without collapsing instances)

### 9.4 Version-fingerprint state

Local state is versioned JSON (`schema_version: 1`) under an isolated state directory:

- atomic safe write (temp sibling + rename)
- strict schema, size bound, and no-symlink handling
- no daemon, no telemetry, no network, no continuous logging

### 9.5 SessionStart and manual scan

- Packaged plugin `SessionStart` uses a dedicated entrypoint `dist/hooks/session-start-entry.js` invoked with POSIX `$PLUGIN_ROOT` and Windows `commandWindows` `%PLUGIN_ROOT%` (see `hooks/hooks.json`). Codex runs hooks with session `cwd`, supplies `PLUGIN_ROOT` / `PLUGIN_DATA`, and JSON on stdin. Version-fingerprint state is stored under `PLUGIN_DATA`, never the project/session cwd. Stdin is parsed under a size bound; `cwd` is observed context only.
- Trusted packaged SessionStart runs the **system** enumeration + shared scan core only when the **overall** fingerprint changed, then completes a bounded read-only health check under 10 seconds.
- With no fingerprint change, the packaged hook exits **0 with no stdout** (and `silent: true` on the internal result). On change it may emit valid SessionStart JSON (`hookSpecificOutput.additionalContext`) without raw paths.
- Hook timeout remains **10 seconds**. Untrusted / skipped / failed behavior is enforced by Codex hook trust; manual paths still represent those states for tests (`changeguard session-start … --hook-trust=`).
- Manual scan paths: fixture `changeguard scan` / `changeguard_scan`, and production `changeguard scan-system` / `changeguard_scan_system`. All share one `ScanResult` shape without duplicate decision logic.

### 9.6 Repair-target binding

`bindRepairTarget` accepts exactly one observed `instance_id` (optionally corroborated by instance fingerprint) and refuses broadcast / multi-id / ambiguous targets. Integration with Ticket 02 is this interface/contract only — no mutation engine here.

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

### 2.7 Ticket 07 configuration / schema-drift / startup fault pack

Bounded read-only probe of registered Codex control files under an isolated instance/config root. Distinct measured fault classes become distinct Incident Fingerprints:

| Fault class | Meaning |
| --- | --- |
| `ConfigTomlSyntaxError` | Invalid TOML syntax / unsupported structure / size bound |
| `ConfigSchemaTypeError` | Known key with wrong value type (or unknown key refused) |
| `ConfigObsoleteKeyError` | Registered obsolete key present |
| `ConfigSourceConflictError` | Same key differs between primary and override |

Parser/validator is deterministic and fail-closed: no configuration execution, no project-code import, no silent accept of unknown structure. Ordinary project source/data/Git history is never scanned.

Repair uses the **same** Ticket 02 recovery engine with narrowly extended operation kinds `config_set` / `config_remove`:

- Capsule shows target alias, redacted old-value type/summary, new value (non-secret registered literals only), precondition hash, backup, verification, rollback, authorization scope
- Startup verification (isolated fixture, no shell): original fault absent + config reload + basic registered command preconditions; any failure auto-rolls back
- Managed/admin-owned/signed/permission-bound targets → `ADMIN_ACTION_REQUIRED` + bounded IT handoff facts; never chmod/privilege-elevation guidance

### Fixture B — invalid TOML / config schema drift (Ticket 07)

Synthetic control-root fixtures under `fixtures/config-*` cover invalid TOML, wrong `shell_environment_policy.set` type, obsolete keys, source conflicts, and managed policy. The TOML/schema probe identifies the invalid structure; Issue #33790 remains a user-reported pattern unless official linkage exists. Registered experimental repairs may set/remove only allowlisted control keys on isolated fixtures.

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

The classifier (`src/core/crash-family.ts`, invoked from `diagnose`) uses optional sanitized `crash_metadata` on the incident fingerprint (exception code, normalized module/symbol/offset bucket, GPU child exit/relaunch codes, interaction phase, page capability, concurrency context, isolation flags). Dump bodies are never parsed or exported. Hard gates reject incompatible platform/surface/mechanism; defining-mechanism gates additionally require GPU families to present their required GPU signals (and reject foreign concrete exception conflict), require concrete page-capability families to observe a compatible capability, and require Top-3 survivors to carry at least one defining-mechanism structural hit (exception/module/symbol/offset/GPU/concrete page/concurrency multi/non-shared phase) so shared `neutral_dom_ready` / `in_app_browser` soft signals alone cannot promote an incompatible catalog family. Title similarity cannot alone produce high confidence or root-cause attribution. Ranking keeps `local_mechanism`, `upstream_match`, and `fix_applicability` separate; optional model ranking cannot override gates or invent provenance. Without a disposable isolated profile, active crash probes are refused — prefer natural-failure metadata. Open Issues without verified fix linkage yield `ISSUE_CANDIDATE` / `HIGH_CONFIDENCE_MATCH` with user-resolution `UPSTREAM_BLOCKED` and `repair_authorization_eligible: false` (wrong symptom-level patches never enter authorization). `LOCAL_REPRO_CONFIRMED` remains reserved for a later safe neutral-page probe plus no-Browser control. Disabling the in-app Browser or using external Chrome is a mitigation, not proof of the native root cause.

### Fixture F — bundled Plugin cache / version skew / reconciliation (Ticket 08)

Isolated named candidates under `plugin-cache/` (inventory, manifest, cache entry, bundled baseline, trusted rebuild source, optional recon-state and local-intent). No recursive cache crawl and no execution of cached code.

Deterministic inventory/manifest comparison classifies exactly one of:

| Mechanism | Signal |
| --- | --- |
| `bundled_file_corruption` | Current generation/version; measured cache hash ≠ expected/trusted |
| `stale_shared_cache` | Shared-cache provenance with generation lag |
| `dependency_version_skew` | Inventory component version ≠ required manifest version with hash mismatch |
| `reconciliation_overwrite` | Recon markers show local intent overwritten by bundled baseline |

A visually similar dependency-install-failure negative control must remain `INCONCLUSIVE` and must not receive the plugin-cache repair. Diagnosis records instance id, cache path hash (not raw path), component hashes, manifest/version relation, provenance, and verified rebuild source.

Repair (same Ticket 02 authorization/backup/rollback seams) allows only exact atomic replacement, verified resource copy from the registered trusted source, or rename-to-quarantine. Verification requires one reconciliation cycle plus restart/health check; immediate recurrence blocks `RESOLVED_VERIFIED` and auto-rollbacks. Explicit rollback restores exact original cache and manifest bytes/hashes.

### Fixture G — underspecified session-expired boundary

A ChatGPT report containing only “session expired” plus an unverified claim about changing IP addresses must not be mapped to a Codex source component. ChangeGuard may run an adjacent authentication/network playbook using status, surface, version, sign-in method, redacted response status, and controlled network comparisons. It must return `INCONCLUSIVE` until one of these branches is supported:

- active service incident;
- VPN/proxy/firewall/SSL-inspection path failure;
- authentication-method or SSO mismatch;
- app/browser-local storage or session-state failure;
- unresolved account-side invalidation requiring OpenAI Support.

## 10b. Upstream Submission Capsule (Ticket 10 — preview only)

Shared core: `src/upstream/` (`previewUpstream`). Public seams:

- Rescue CLI: `changeguard upstream-preview <target> --request=<request.json> [--disclose-approved|--disclose-refused]`
- MCP: `changeguard_upstream_preview` with `{ target, request, disclosure_decision? }`

Both return the same `UpstreamPreviewResult` / `UpstreamSubmissionCapsule` JSON. Capsule invariants:

- `mode: preview_only`, `locality: local_only`, `repair_authorized: false`, `external_write: false`
- `requires_ticket11_confirmation: true` — Ticket 11 owns any real write after separate preview+confirmation
- `submission_status` on the result is always `none`; capsule `status` is never `SUBMITTED` / `POSTED`
- Capsule `status` is one of `PREVIEW_READY` | `PREVIEW_BLOCKED` | `GATE_FAILED` | `ROUTED_PRIVATE`
- Result `ok` is true only for `PREVIEW_READY` and gate-passed `ROUTED_PRIVATE`. `PREVIEW_BLOCKED` and `GATE_FAILED` are non-ready (`ok: false`, CLI non-zero / MCP error)

### Channel routing

| Case kind | Route |
| --- | --- |
| `validated_security_vulnerability` | `BUGCROWD` (private; never public Issue draft) |
| `account_billing_private` | `OPENAI_SUPPORT` |
| `product_support_question` | `GITHUB_DISCUSSIONS` |
| `codex_product_bug` | `GITHUB_ISSUE` → form map |

GitHub Issue form map (current official templates): `APP` → `1-codex-app.yml`, `CLI` → `3-cli.yml` (includes `codex doctor --json`), `EXTENSION` → `2-extension.yml`, `OTHER` → `4-bug-report.yml`.

Injection and gate failure take precedence over private routing: only a gate-passed Bugcrowd path becomes `ROUTED_PRIVATE`. A privacy/gate failure on a security request is `GATE_FAILED` (or `PREVIEW_BLOCKED` on injection), never a false-ready private route.

### Duplicate states and export invariant

Exact enums: `EXACT_DUPLICATE`, `RELATED_NOT_SAME`, `NEW_INCIDENT`.

Recommendations include a non-executable `blocked` value used only for `PREVIEW_BLOCKED` / `GATE_FAILED` (empty cross-links/labels; null `draft_title` / `draft_body` / `draft_comment`).

Central export invariant:

- Only `PREVIEW_READY` may export public/discussion draft content.
- `ROUTED_PRIVATE` exports only private guidance and `private_report` recommendation (null public drafts).
- Exact duplicate with **zero** material Evidence Delta on `PREVIEW_READY` → `subscribe_or_upvote` only; `draft_body`, `draft_comment`, and `cross_link_issue_ids` are empty/null (official “search first / react only” guidance; no cross-link actions).
- Exact duplicate with **material** Evidence Delta → `comment_with_delta` structured comment preview only.
- Related mechanisms remain separate (`RELATED_NOT_SAME`) with cross-links; symptom similarity alone cannot merge incidents.
- `GATE_FAILED` strips submission-reconstructable free text (`observed_facts` / `user_reports` / `hypotheses` / `error_strings` / `command_strings`) and keeps structured gate diagnostics / quarantine-safe metadata only.

### Capsule identity

`capsule_id` is content-addressed from a canonical capsule payload that excludes `capsule_id` and `capsule_content_sha256` (drafts, facts, doctor inclusion, form snapshot, gate, privacy, route/status). Distinct safe content with identical routing/form/state/delta therefore yields distinct ids. `capsule_content_sha256` is then derived from the final capsule contract (including `capsule_id`, with content hash nulled for the hash input) — no circular hashing.

### Maintainer-value gate

Requires: route, duplicate search (Issue path), surface, platform/version or explicit unknown reason, actual behavior, ≥1 technical signal, sanitized baseline diagnostics (doctor inclusion or explicit refusal), privacy review flags, reproduction quality or intermittent marker, and material value over an existing Issue. Separates `observed_facts`, `user_reports`, and `hypotheses`. Exact technical error/command strings are preserved except required secret/path redaction (except on `GATE_FAILED`, where free text is stripped).

Capsule `privacy_review.passed` is exactly: no injection **and** request `secrets_redacted` **and** `paths_redacted` **and** `session_excluded`. Those three booleans are the explicit request privacy review only; doctor redaction stays in `doctor_inclusion` and is never OR-lifted into the request review. The maintainer-gate `privacy_review` check uses the same four operands. Prompt-injection scanning after NFKC plus strip of Unicode format / zero-width / bidi controls covers every free-text field that can enter a capsule/draft, including `platform.os` / `platform.arch` / `platform.unknown_reason`, `codex_version`, and `version_unknown_reason`. Quarantine evidence hashes the scan-normalized material only — never raw malicious text.

### Doctor envelope

Orchestrator may supply a bounded `codex doctor --json` object. ChangeGuard sanitizes allowlisted keys, shows an inclusion manifest, and never executes `codex` or arbitrary shell. Capsule schema constrains `doctor_inclusion.sanitized_summary` to that allowlist (`additionalProperties: false`) and `privacy_review.quarantine` to the exact `QuarantineRecord` shape.

### Official form snapshot

Bundled immutable snapshot (`fixtures/upstream/form-snapshot-2026-07-18.json`) records main commit `3a067484584861606ad842de5bc4ac735a865ddf` and form blob SHAs verified 2026-07-18. Snapshot carries exact `integrity_sha256` and is labeled `fresh` / `stale` by age. Optional form refresh requires disclosure `approved` **and** an injected official-only transport; production CLI/MCP inject null (`transport_calls: 0`). When an injected transport fails after being called, `transport_calls: 1` and `network_used: true` remain truthful, but `form_snapshot.source` stays `bundled_immutable` with freshness derived from the bundled snapshot age (never mislabeled `transport_refresh` / live). The snapshot is testable immutable evidence, not a claim of perpetual currency.

Schema: `schemas/upstream-submission-capsule.schema.json`. Synthetic fixtures: `fixtures/upstream/*`.

The playbook never reads or exports cookie values, tokens, passwords, one-time codes, or full browser storage. A changed public IP is a hypothesis, not a permitted root-cause claim.

## 10c. Confirmed upstream actions (Ticket 11)

Shared core: `src/upstream/actions/` (`previewUpstreamAction`, `confirmUpstreamAction`).
Public seams:

- Rescue CLI: `changeguard upstream-action-preview <target> --capsule=<capsule.json> --action=<kind> [--attachments=<manifest.json>]`
- Rescue CLI: `changeguard upstream-action-confirm <target> --confirmation=<ua1.…|path> --decision=confirm|cancel`
- MCP: `changeguard_upstream_action_preview` / `changeguard_upstream_action_confirm`

### Capsule eligibility

Only Ticket 10 capsules that pass all of the following may become actions:

- `mode: preview_only`, `locality: local_only`, `external_write: false`, `requires_ticket11_confirmation: true`
- `status: PREVIEW_READY` (never `PREVIEW_BLOCKED`, `GATE_FAILED`, or `ROUTED_PRIVATE`)
- `privacy_review.passed` and secrets/paths/session flags true; no injection quarantine
- `maintainer_value_gate.passed`
- `capsule_content_sha256` recomputes to the same integrity digest
- recommendation maps to an allowlisted action set (`open_new` → create_issue/attachment_upload; `comment_with_delta` → comment/attachment; `subscribe_or_upvote` → react_upvote/subscribe). `blocked` / private / support recommendations never become actions.

### Action kinds (separately previewed + confirmed)

`create_issue` | `comment_with_delta` | `react_upvote` | `subscribe` | `attachment_upload`

Each confirmation binds: exact canonical target, action, body/attachment manifest,
incident fingerprint digest, evidence delta hash, `capsule_content_sha256`, privacy
result, one-shot nonce, and expiry (`ua1.…` token; not an access token). Tokens are
authenticated with an install-local HMAC key stored only under ChangeGuard-owned
confirmation state (`CHANGEGUARD_CONFIRMATION_STATE_DIR` / `PLUGIN_DATA` /
XDG state); the key never enters the token, logs, or receipts. Mint registers the
nonce in a durable, bounded, symlink-safe confirmation ledger before return;
confirm revalidates official canonical target allowlist, recomputes
idempotency/body/attachment digests, and refuses unregistered or offline-forged
tokens. Cancel, success, and `UNCERTAIN_NO_RETRY` permanently terminate the nonce
(`consumed` / `terminal_uncertain`) so the same token cannot re-`adapter.execute`.

### Auth capability and adapter

- Capability kinds: `gh_authenticated` | `visible_browser_authenticated` | `unavailable`
- Production CLI/MCP inject null adapter → `createUnavailableAdapter()`; never child_process/`gh`, never tokens/cookies/sessions
- Host integration supplies `UpstreamActionAdapter` (`getAuthCapability`, `execute`, `queryByIdempotencyKey`)
- Cancellation or auth/adapter unavailable remains pure draft (`external_write: false`); never simulates success

### Idempotency and timeout

Idempotency key = SHA-256 over canonical target + incident digest + evidence delta +
action + body/attachment content hashes. Exact same diagnosis/action/content cannot
execute twice (`DUPLICATE_EXISTING` returns the existing receipt).

Ambiguous timeout: query remote with the same idempotency key. Found → return existing
receipt. Not found / uncertain / query throw → `UNCERTAIN_NO_RETRY` (never blind retry)
and mark the confirmation `terminal_uncertain` in the durable ledger so a later call
returns `REPLAYED_CONFIRMATION` without a second execute.

### Upstream Contribution Receipt

On success (or found duplicate), emit a separate minimal receipt
(`kind: upstream_contribution_action`): action, canonical URL, timestamp,
`receipt_hash`, `idempotency_key`, optional `remote_receipt_id`. No local repair
status, secrets, or body text. Schema: `schemas/upstream-action-receipt.schema.json`.

Scenario Harness uses an in-memory controlled remote double
(`createFakeRemoteAdapter`) covering success, cancel, auth failure, invalid/expired/
replayed confirmation, timeout found/not-found/uncertain, duplicate, attachment
privacy, blocked capsule, CLI/MCP equivalence, and default no-network path.

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
- Fixture E crash-family classifier, Fixture F plugin-cache mechanisms, and Fixture G evidence-boundary case
- disclosure manifest and repro-pack export
- English README, install/platform/judge instructions, live fixture path, tests

### Should

- Fixture B or C
- `SessionStart` version-change detection after trust (Ticket 03 core implemented; host trust still explicit)
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
