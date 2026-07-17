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
- `.mcp.json`: planned read-only MCP server definition
- `hooks/hooks.json`: optional `SessionStart` hint after explicit trust
- `schemas/`: portable contracts for fingerprints, claims, probes, and recovery
- lightweight inspector UI: planned only after the CLI/fixture path is verified

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

| Trust tier | Source | Preview | Dry-run | Apply in competition MVP |
|---|---|---:|---:|---:|
| T4 | Official released fix | yes | yes | no; upgrade guidance only |
| T3 | Official merged commit, not released | yes | fixture/disposable copy | no |
| T2 | Maintainer-confirmed workaround | yes | fixture/disposable copy | no |
| T1 | Community workaround | quarantined preview | fixture only | no |
| T0 | Model-generated fix | hypothesis only | generated test fixture only | no |

A future explicitly authorized apply engine must:

1. resolve and classify the exact target path;
2. record original bytes, metadata, and SHA-256;
3. require the expected pattern count and applicable version/hash;
4. create a verified backup;
5. write a sibling temporary file and atomically replace;
6. run syntax and minimal functional smoke checks;
7. restore exact original bytes on any failure;
8. emit a receipt without secrets or full file contents.

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

- known affected `browser-client.mjs` SHA-256
- the three assignment statements that redefine global process/global
- failure phase before extension handshake
- community Issue comment as untrusted workaround evidence

Expected path:

1. Detect error/phase signature.
2. Hash the packaged copies and identify identical artifacts.
3. Match the AST pattern and require exactly one target block per file.
4. Report Issue #32925 as a candidate; the comment remains community evidence.
5. Run the property-descriptor and bundled module fixture probes.
6. Reach `SOURCE_COMPONENT_LOCATED`; reach `LOCAL_REPRO_CONFIRMED` only if the deterministic fixture reproduces and the negative control does not.
7. Produce a T1 Recovery Capsule preview for the local shim; never patch real caches in the competition demo.

The precise claim is: “The exact affected pattern is present in these local artifacts and the bundled probe reproduces the same protected-process failure mechanism.” It is not: “OpenAI officially confirmed Issue #32925 as the root cause.”

### Fixture B — invalid TOML setup hang

Synthetic Windows config with an invalid `shell_environment_policy.set` value. The TOML/schema probe must identify the invalid structure; Issue #33790 remains a user-reported pattern unless official linkage exists.

### Fixture C — untracked Skill handoff omission

Synthetic repo containing tracked, ignored, and nonignored untracked Skill files. A deterministic manifest/diff probe confirms whether the handoff payload omitted the nonignored file; Issue #33789 is then ranked with platform/version labels.

### Fixture D — negative control

A superficially similar startup error from macOS with a different module, configurable `process`, and no matching AST block. The matcher must refuse the Windows TOML and protected-process Issues and return `INCONCLUSIVE` or a low-confidence candidate.

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
- disclosure manifest and repro-pack export
- English README, install/platform/judge instructions, live fixture path, tests

### Should

- Fixture B or C
- `SessionStart` version-change hint after trust
- Recovery Capsule preview
- lightweight inspector UI

### Later

- authenticated official GitHub refresh
- broader version history and more platforms
- source-map-aware packaged-code mapping
- explicitly authorized apply/rollback engine

### Not Doing

- universal root-cause claims
- automatic execution of community patches
- arbitrary shell probes
- hidden upload of configs, sessions, or environment data
- real-time indexing of every external forum
- merging SpecTrial into this product

## 12. Precise capability statement

ChangeGuard can precisely identify a local affected pattern when hashes, AST/schema signatures, stack/component evidence, or deterministic reproduction agree. It can rank and explain upstream Issue candidates using version, platform, surface, component, and failure-stage evidence. It does not claim that a similar Issue is the root cause until local reproduction or verified official Issue/PR/commit/release linkage supports that conclusion. When evidence is missing or contradictory, it says so.
