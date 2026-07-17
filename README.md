# Codex ChangeGuard

Codex ChangeGuard is an evidence-bound Codex Plugin for update impact analysis, incident localization, and reversible recovery planning.

It is designed around one rule:

> Models may propose hypotheses; deterministic probes adjudicate facts.

ChangeGuard is not a generic changelog summarizer, Issue chatbot, environment doctor, or automatic community-patch installer. It maps official Codex changes to redacted local facts, assigns explicit evidence levels, and refuses false precision when an Issue cannot be confirmed locally.

## Current status

- Competition: OpenAI Build Week 2026
- Track: `track-openai-build-week-codex-changeguard-20260717`
- Gate B: approved, option A
- Local scope: Ticket 01 read-only diagnosis spine (CLI + MCP + shared core); broader product remains in progress
- Registration and external submission: not started; Gate C not authorized

## Start here

- [Architecture and evidence contracts](docs/ARCHITECTURE.md)
- [Security and privacy boundary](docs/SECURITY.md)
- [Verification and adversarial test plan](docs/TEST_PLAN.md)
- [Real-world diagnosis case studies](docs/CASE_STUDIES.md)
- [Current handoff](HANDOFF.md)
- [Plugin manifest](.codex-plugin/plugin.json)
- [Schemas](schemas/)
- [Synthetic fixtures](fixtures/)

## Read-only diagnosis (Ticket 01)

Rescue CLI and MCP share one diagnosis core. Both return the same structured
`DiagnosisResult` / `IncidentFingerprint`. The flow is read-only: no network,
no target mutation, no repair, and never `RESOLVED_VERIFIED`.

A clean source checkout is not runnable until dependencies are installed and the
project is built (or packaged):

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

- CLI: `changeguard diagnose <isolated-target-directory>`
- MCP tool: `changeguard_diagnose` with `{ "target": "<isolated-target-directory>" }` only
- Skill: `/changeguard diagnose` orchestrates the same seams (see `skills/changeguard/SKILL.md`)
- Package: `npm run package` writes `release/codex-changeguard-plugin/` (compiled JS + manifest + MCP + Skill + fixtures/docs/schemas; no `node_modules`)

Positive protected-process fixture may reach `SOURCE_COMPONENT_LOCATED` only when
artifact bytes are independently hashed and the protected-process structural
signature is measured locally (exactly one real shim block; comments/strings
cannot spoof). Declared hashes or AST ids inside incident JSON never self-prove;
surface/error/phase remain applicability gates. The negative control stays
`INCONCLUSIVE` and does not claim a root cause. User-resolution and
upstream-contribution receipts are always separate.

## Plugin surfaces

- Skill commands for update scanning, incident diagnosis, and repro-pack export
- A read-only local-facts MCP server (`changeguard_diagnose`) with explicit tool approval
- An optional trusted `SessionStart` hook that notices version changes (later tickets)
- A manual scan path that always works when hooks are disabled or untrusted

Official Codex documentation currently demonstrates lifecycle hooks such as `SessionStart`, but does not establish a dedicated software-update event. ChangeGuard therefore compares version fingerprints at session start and never claims native update-event coverage.

## Development boundary

This repository owns the ChangeGuard product only. Portfolio research, Gate approvals, and competition status remain canonical in the separate `xfyun-competition-portfolio` repository. Existing orchestration or competition projects may contribute general engineering principles, but their product code and submitted artifacts are not copied into this repository.

## License

License and public-release terms will be frozen before Gate C. No public publication or submission has occurred.
