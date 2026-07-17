# Codex ChangeGuard

Codex ChangeGuard is an evidence-bound Codex Plugin for update impact analysis, incident localization, and reversible recovery planning.

It is designed around one rule:

> Models may propose hypotheses; deterministic probes adjudicate facts.

ChangeGuard is not a generic changelog summarizer, Issue chatbot, environment doctor, or automatic community-patch installer. It maps official Codex changes to redacted local facts, assigns explicit evidence levels, and refuses false precision when an Issue cannot be confirmed locally.

## Current status

- Competition: OpenAI Build Week 2026
- Track: `track-openai-build-week-codex-changeguard-20260717`
- Gate B: approved, option A
- Local scope: architecture and plugin scaffold in progress
- Registration and external submission: not started; Gate C not authorized

## Start here

- [Architecture and evidence contracts](docs/ARCHITECTURE.md)
- [Security and privacy boundary](docs/SECURITY.md)
- [Verification and adversarial test plan](docs/TEST_PLAN.md)
- [Current handoff](HANDOFF.md)
- [Plugin manifest](.codex-plugin/plugin.json)
- [Schemas](schemas/)
- [Synthetic fixtures](fixtures/)

## Planned Plugin surfaces

- Skill commands for update scanning, incident diagnosis, and repro-pack export
- A read-only local-facts MCP server with explicit tool approval
- An optional trusted `SessionStart` hook that notices version changes
- A manual scan path that always works when hooks are disabled or untrusted

Official Codex documentation currently demonstrates lifecycle hooks such as `SessionStart`, but does not establish a dedicated software-update event. ChangeGuard therefore compares version fingerprints at session start and never claims native update-event coverage.

## Development boundary

This repository owns the ChangeGuard product only. Portfolio research, Gate approvals, and competition status remain canonical in the separate `xfyun-competition-portfolio` repository. Existing orchestration or competition projects may contribute general engineering principles, but their product code and submitted artifacts are not copied into this repository.

## License

License and public-release terms will be frozen before Gate C. No public publication or submission has occurred.
