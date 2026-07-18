# Codex ChangeGuard

Codex ChangeGuard is an evidence-bound Codex Plugin for update impact analysis, incident localization, and reversible recovery planning.

It is designed around one rule:

> Models may propose hypotheses; deterministic probes adjudicate facts.

ChangeGuard is not a generic changelog summarizer, Issue chatbot, environment doctor, or automatic community-patch installer. It maps official Codex changes to redacted local facts, assigns explicit evidence levels, and refuses false precision when an Issue cannot be confirmed locally.

## Current status

- Competition: OpenAI Build Week 2026
- Track: `track-openai-build-week-codex-changeguard-20260717`
- Gate B: approved, option A
- Tickets 01–04: `LOCAL_COMPLETE` on integrated commit `c20ddc5` (Ticket 01 first closed on `d7d917b`; Wave 2 tip `c20ddc5`)
- Tickets 05–09: `LOCAL_COMPLETE` on integrated HEAD `5aa12c6` (Wave 3 tip; Root full regression 212/212; final review `changeguard-wave3-final-review-r2` → `NO_P0_P1`)
- Ticket 10: `LOCAL_COMPLETE` on integrated HEAD `3265acd` (commits `0829936` → `7ef87e6` → `26d58b4` → `3265acd`; Root full regression 260/260; final static review `changeguard-ticket10-regression-review-r7` → `NO_P0_P1`, empty patch)
- Broader product: still `IN_PROGRESS` (Tickets 12, 15–17 not complete; Ticket 11 implemented surfaces are local-only with no real adapter by default; Tickets 13–14 platform surfaces are integrated as framework code)
- Residual platform claims: macOS Full requires a Ticket 13 real-machine Scenario Harness receipt with live harness witness (see [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)); Windows Full remains Ticket 14 and stays **Preview** until a real Windows 11 host receipt covers W11-S01…S11; Linux·WSL Limited is Ticket 15; Ticket 06 CLI/Desktop **version** rollback stays `preview_only` / Desktop may be `limited`
- Ticket 10 residual: upstream capsules stay `preview_only` / `local_only` / `external_write: false`; immutable form snapshot date/commit/blob provenance recorded in [HANDOFF.md](HANDOFF.md)
- Ticket 11 surfaces: separate `upstream-action-preview` / `upstream-action-confirm` (CLI + MCP) with capability-injected adapter; production default is `ADAPTER_UNAVAILABLE` and never simulates success or real GitHub/browser writes. Not marked complete here; no external submission claimed.
- Ticket 13 surfaces: `platform-status` / `platform-receipt-validate` (CLI + MCP), macOS adapter/harness/receipt schema, and support matrix. Full is never claimed from external JSON alone — only with a real-machine Scenario Harness receipt that passes live validation.
- Ticket 14 surfaces: Windows adapter, write-scope gate, crash-metadata bounds, and Windows support receipt evaluation are integrated under `src/instances/windows/` + `src/platform/windows/`. **Windows support remains PREVIEW** on this host; no real Windows 11 receipt; no Full / published / submitted claim.
- Registration and external submission: `NOT_STARTED`; Gate C not authorized; no public publication, upload, or real external GitHub writes
- Exact local-verification evidence: [HANDOFF.md](HANDOFF.md)

## Start here

- [Architecture and evidence contracts](docs/ARCHITECTURE.md)
- [Security and privacy boundary](docs/SECURITY.md)
- [Verification and adversarial test plan](docs/TEST_PLAN.md)
- [Real-world diagnosis case studies](docs/CASE_STUDIES.md)
- [Platform support matrix](docs/SUPPORT_MATRIX.md)
- [Current handoff](HANDOFF.md)
- [Plugin manifest](.codex-plugin/plugin.json)
- [Schemas](schemas/)
- [Synthetic fixtures](fixtures/)

## Public surfaces (Tickets 01–11, 13–14)

Rescue CLI and MCP share the same cores. A clean source checkout is not runnable
until dependencies are installed and the project is built (or packaged):

```bash
npm ci
npm run build
npm test
npm run check:boundary
npm run package
npm run package:smoke
node bin/changeguard.js diagnose fixtures/protected-process
node bin/changeguard.js diagnose fixtures/negative-control
node bin/changeguard.js diagnose fixtures/crash-family/access-violation-crbrowser
node bin/changeguard.js analyze-page fixtures/protected-process --envelope=fixtures/page-evidence/valid-protected-process.json --disclose-refused
node bin/changeguard.js upstream-preview fixtures/protected-process --request=fixtures/upstream/request-new-incident-cli.json --disclose-refused
```

Implemented public commands (repository wrapper: `node bin/changeguard.js …`):

| Area | CLI | MCP |
| --- | --- | --- |
| Diagnose (Ticket 01) | `changeguard diagnose <target>` | `changeguard_diagnose` |
| Impact Card (Ticket 04) | `changeguard impact <target> [--disclose-approved\|--disclose-refused]` | `changeguard_impact` |
| Page analysis (Ticket 05) | `changeguard analyze-page <target> --envelope=<page.json> [--disclose-…]` | `changeguard_analyze_page` |
| Upstream preview (Ticket 10) | `changeguard upstream-preview <target> --request=<request.json> [--disclose-…]` | `changeguard_upstream_preview` |
| Lifecycle (Ticket 06) | `changeguard lifecycle <operation> <target>` | `changeguard_lifecycle` |
| Repair (Ticket 02) | `repair-preview` / `repair-apply` / `verify` / `rollback` | `changeguard_repair_*` / `changeguard_verify` / `changeguard_rollback` |
| Instances (Ticket 03) | `scan` / `scan-system` / `session-start` | `changeguard_scan` / `changeguard_scan_system` / `changeguard_session_start` |
| Upstream actions (Ticket 11) | `upstream-action-preview` / `upstream-action-confirm` | `changeguard_upstream_action_preview` / `changeguard_upstream_action_confirm` |
| Platform status (Ticket 13) | `platform-status` / `platform-receipt-validate` | `changeguard_platform_status` / `changeguard_platform_receipt_validate` |

- Skill: `/changeguard diagnose`, `/changeguard diagnose <URL>` (analyze-page), `/changeguard impact`, `/changeguard scan`, and repair-preview orchestration use the same seams (`skills/changeguard/SKILL.md`)
- Package: `npm run package` writes `release/codex-changeguard-plugin/` with the exact public top-level surface (compiled JS + manifest + MCP + Skill + hooks + fixtures + public docs + schemas; no `node_modules`, `AGENTS.md`, `HANDOFF.md`, or `docs/agents`); packaged README drops the repository-only handoff link; `package:smoke` launches MCP via packaged `.mcp.json` and checks local Markdown links

### Read-only diagnosis (Ticket 01)

The flow is read-only: no network, no target mutation, and never claims repair from
diagnose. Positive protected-process fixture may reach `SOURCE_COMPONENT_LOCATED`
only when artifact bytes are independently hashed and the structural signature is
measured locally. The negative control stays `INCONCLUSIVE`. User-resolution and
upstream-contribution receipts are always separate.

### Isolated verified repair (Ticket 02)

Experimental repair is limited to isolated targets after an exact scope-bound
one-shot authorization token. `RESOLVED_VERIFIED` requires original-failure absence
plus core health; verification failure auto-rollbacks; live Codex/Profile installs
are out of scope.

### Instance scan and SessionStart (Ticket 03)

Multi-instance enumeration keeps independent identities (path hashes/aliases only).
An optional trusted `SessionStart` hook notices version-fingerprint changes and runs
a bounded read-only health check under ten seconds; unchanged fingerprints stay silent.
Untrusted, skipped, or failed hooks are explicit; manual `scan` / `scan-system` always
remain available.

### Official evidence and Impact Card (Ticket 04)

Disclosure manifest is shown before any external refresh. Refusing disclosure still
allows local snapshot Impact Cards. Production CLI/MCP do not open network sockets by
default; Change-to-Local Graph edges are deterministic only; unmapped changes are
labeled `UNMAPPED_CHANGE` without declaring an entire version unsupported.

### Untrusted page / URL diagnosis (Ticket 05)

Orchestrator-supplied page envelopes (URL + sanitized visible content) are analyzed
against the local incident fingerprint. Page text is quarantined untrusted data;
commands become candidate-only Repair DSL and never authorize apply. Logged-page mode
never reads cookies, storage, tokens, or full browser requests. Generic ChatGPT or
account/session pages are hard-gated away from Codex component defects.

### KNOWN_GOOD / rollback lifecycle (Ticket 06)

Isolated lifecycle ledger retains repair backups (age + successful starts) and the last
three healthy control-surface checkpoints as `KNOWN_GOOD`. Update-regression claims
require controlled A/B evidence (timestamps alone refuse). Exact-instance control-surface
rollback returns `MITIGATED_VERIFIED_BY_ROLLBACK` only. CLI and Desktop **version**
rollback seams are registered `preview_only` guidance (official pin / signed media);
ChangeGuard never stores or redistributes OpenAI binaries. Desktop version rollback is
`limited` without signed history or lawful media. Canary and upstream supersession emit
exact guidance enums. Real-machine platform Full/Preview/Limited claims remain Tickets 13–15.

### Configuration / startup fault pack (Ticket 07)

Isolated control-root fixtures classify invalid TOML, wrong types, obsolete keys, and
source conflicts with distinct fingerprints. Registered `config_set` / `config_remove`
repairs run through the Ticket 02 engine with startup verification and automatic
rollback; managed policy targets return `ADMIN_ACTION_REQUIRED` without bypass guidance.

### Plugin cache / skew / reconciliation (Ticket 08)

Isolated `fixtures/plugin-cache/*` targets distinguish bundled corruption, stale
shared cache, dependency/version skew, and reconciliation overwrite (never generic
dependency-install failure). Repair reuses Ticket 02 authorization with verified
resource copy / atomic replace / rename-to-quarantine only; verification crosses one
reconciliation cycle and a restart/health check. Immediate recurrence cannot claim
`RESOLVED_VERIFIED`.

### Desktop Browser crash-family classifier (Ticket 09)

Sanitized Windows crash fixtures under `fixtures/crash-family/` fork distinct
exception / GPU / interaction / concurrency families via deterministic gates.
Compatible fixtures rank the correct `openai/codex#…` Issue in the Top 3;
title similarity alone cannot create high confidence. Without a verified fix,
diagnosis returns `UPSTREAM_BLOCKED` (or `INCONCLUSIVE`) and never authorizes a
symptom-level Repair Capsule. Active crash probes require disposable isolation.

### Windows 11 adapter + platform status (Ticket 14) — PREVIEW

Namespaced Windows adapter (`src/instances/windows/`) distinguishes MSIX, Desktop
app, Desktop-bundled CLI, PATH CLI, WSL, and multi-profile identities under
injected env/fs capabilities. User-owned cache/control repair binds an exact
instance and reuses the Ticket 02 engine; managed/admin/MSIX package targets
return `ADMIN_ACTION_REQUIRED` with IT handoff only.

Platform support is evaluated from auditable receipts
(`schemas/platform-support-receipt.schema.json`):

```bash
node bin/changeguard.js platform-status
node bin/changeguard.js platform-status --plan
node bin/changeguard.js platform-status --receipt=fixtures/windows11/receipts/synthetic-preview.json
```

**Status remains PREVIEW** until a real Windows 11 host receipt covers every
critical scenario (W11-S01…S11). Synthetic / cross-platform / forged receipts
never authorize FULL. This ticket does **not** claim `LOCAL_COMPLETE` or
real-machine Full support.

### Upstream draft routing (Ticket 10) — preview only

`changeguard upstream-preview` / `changeguard_upstream_preview` builds a local-only
Upstream Submission Capsule: routes among GitHub Issue, Discussions, Bugcrowd, and
OpenAI Support; maps Issue surfaces to APP/CLI/EXTENSION/OTHER forms; classifies
duplicates as `EXACT_DUPLICATE` / `RELATED_NOT_SAME` / `NEW_INCIDENT`; zero Evidence
Delta exact duplicates recommend subscribe/upvote only (no body); material deltas
may preview a structured comment. Validated security never becomes a public Issue
draft. Optional `codex doctor --json` is orchestrator-supplied, sanitized, and shown
via an inclusion manifest — ChangeGuard never executes codex or opens production
network sockets. Capsules are `preview_only` / `local_only` with `external_write: false`
and require separate Ticket 11 confirmation before any real write.

### Confirmed upstream actions (Ticket 11) — adapter-gated

`changeguard upstream-action-preview` / `changeguard_upstream_action_preview` binds one
action (`create_issue`, `comment_with_delta`, `react_upvote`, `subscribe`,
`attachment_upload`) to a valid Ticket 10 `PREVIEW_READY` capsule (integrity,
privacy, recommendation, content hash). Blocked/gate-failed capsules never become
actions. Preview emits a one-shot confirmation (`ua1.…`) binding canonical target,
body/attachment manifest, incident fingerprint digest, evidence delta hash,
capsule content hash, privacy result, nonce, and expiry. Tokens are HMAC-authenticated
with an install-local key held only in ChangeGuard confirmation state (not a
GitHub/API token; never in logs/receipts) and registered in a durable one-shot ledger
before return.

`changeguard upstream-action-confirm` / `changeguard_upstream_action_confirm` accepts
`decision=confirm|cancel`. Cancel remains pure draft. Production injects no real
`gh`/browser adapter (auth capability `unavailable`); confirm returns
`ADAPTER_UNAVAILABLE` and never simulates success. Host integration may inject an
adapter that reports only `gh_authenticated` or `visible_browser_authenticated`
(never request/store/display tokens, cookies, or sessions). Idempotency keys prevent
duplicate same-diagnosis actions; ambiguous timeout queries remote by the same key
and stops with `UNCERTAIN_NO_RETRY` (ledger `terminal_uncertain`) rather than blind
retry. Cancel/success/uncertain permanently terminate the nonce. Success yields a
minimal Upstream Contribution Receipt (action, canonical URL, timestamp,
receipt/idempotency hashes only).


### macOS platform support (Ticket 13) — receipt-gated Full

`changeguard platform-status` / `changeguard_platform_status` reports read-only
macOS adapter capabilities (registered install sources, path-role aliases, operations,
and closed safety constraints). Optional receipt objects surface a validated
`verified_support_level`. Production never executes discovered binaries, never mutates
the host, and never opens the network.

`changeguard platform-receipt-validate` / `changeguard_platform_receipt_validate`
validates a Scenario Harness receipt (schema, leak checks, Full-only-with-proof).
**Full** is declared only when every required real-machine scenario passes and
validation succeeds; a hand-authored external JSON receipt alone never upgrades a
platform to Full. See [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md).
Repository harness: `npm run harness:macos` (darwin real-machine path).

## Plugin surfaces

- Skill commands for update scanning, incident diagnosis, page analysis, Impact Card, recovery preview, upstream action preview/confirm, and platform status
- A local-facts MCP server with explicit tool approval (`changeguard_diagnose`, `changeguard_impact`, `changeguard_analyze_page`, `changeguard_upstream_preview`, `changeguard_upstream_action_preview`, `changeguard_upstream_action_confirm`, `changeguard_platform_status`, `changeguard_platform_receipt_validate`, `changeguard_lifecycle`, repair/scan tools)
- An optional trusted `SessionStart` hook that notices version-fingerprint changes (Ticket 03)
- A manual scan path that always works when hooks are disabled or untrusted

Official Codex documentation currently demonstrates lifecycle hooks such as `SessionStart`, but does not establish a dedicated software-update event. ChangeGuard therefore compares version fingerprints at session start and never claims native update-event coverage.

## Development boundary

This repository owns the ChangeGuard product only. Portfolio research, Gate approvals, and competition status remain canonical in the separate `xfyun-competition-portfolio` repository. Existing orchestration or competition projects may contribute general engineering principles, but their product code and submitted artifacts are not copied into this repository.

## License

License and public-release terms will be frozen before Gate C. No public publication or submission has occurred.
