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
- Broader product: still `IN_PROGRESS` (Tickets 05–17 not complete)
- Registration and external submission: `NOT_STARTED`; Gate C not authorized; no public publication or upload
- Exact local-verification evidence: [HANDOFF.md](HANDOFF.md)

## Start here

- [Architecture and evidence contracts](docs/ARCHITECTURE.md)
- [Security and privacy boundary](docs/SECURITY.md)
- [Verification and adversarial test plan](docs/TEST_PLAN.md)
- [Real-world diagnosis case studies](docs/CASE_STUDIES.md)
- [Current handoff](HANDOFF.md)
- [Plugin manifest](.codex-plugin/plugin.json)
- [Schemas](schemas/)
- [Synthetic fixtures](fixtures/)

## Public surfaces (Tickets 01–04)

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
```

Implemented public commands (repository wrapper: `node bin/changeguard.js …`):

| Area | CLI | MCP |
| --- | --- | --- |
| Diagnose (Ticket 01) | `changeguard diagnose <target>` | `changeguard_diagnose` |
| Impact Card (Ticket 04) | `changeguard impact <target> [--disclose-approved\|--disclose-refused]` | `changeguard_impact` |
| Repair (Ticket 02) | `repair-preview` / `repair-apply` / `verify` / `rollback` | `changeguard_repair_*` / `changeguard_verify` / `changeguard_rollback` |
| Instances (Ticket 03) | `scan` / `scan-system` / `session-start` | `changeguard_scan` / `changeguard_scan_system` / `changeguard_session_start` |

- Skill: `/changeguard diagnose`, `/changeguard impact`, `/changeguard scan`, and repair-preview orchestration use the same seams (`skills/changeguard/SKILL.md`)
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

## Plugin surfaces

- Skill commands for update scanning, incident diagnosis, Impact Card, and recovery preview
- A local-facts MCP server with explicit tool approval (`changeguard_diagnose`, `changeguard_impact`, repair/scan tools)
- An optional trusted `SessionStart` hook that notices version-fingerprint changes (Ticket 03)
- A manual scan path that always works when hooks are disabled or untrusted

Official Codex documentation currently demonstrates lifecycle hooks such as `SessionStart`, but does not establish a dedicated software-update event. ChangeGuard therefore compares version fingerprints at session start and never claims native update-event coverage.

## Development boundary

This repository owns the ChangeGuard product only. Portfolio research, Gate approvals, and competition status remain canonical in the separate `xfyun-competition-portfolio` repository. Existing orchestration or competition projects may contribute general engineering principles, but their product code and submitted artifacts are not copied into this repository.

## License

License and public-release terms will be frozen before Gate C. No public publication or submission has occurred.
