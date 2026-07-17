# Codex ChangeGuard Handoff

## Current state

- Date: 2026-07-17 Asia/Shanghai
- Track ID: `track-openai-build-week-codex-changeguard-20260717`
- Gate B: `APPROVED`, option A
- Current scope status: `IN_PROGRESS`
- Registration: `NOT_STARTED`
- External submission: `NOT_STARTED`
- Gate C: not authorized

The official Plugin scaffold exists and the architecture/evidence schemas are being frozen. Product implementation has not started. A planned Grok 4.5/high architecture red-team was blocked because sending the work order and real incident fixture to an external model requires renewed explicit user authorization after disclosure.

## Canonical documents

- Product entry and stable boundary: [README.md](README.md)
- Technical design and evidence levels: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Security/privacy contract: [docs/SECURITY.md](docs/SECURITY.md)
- Portfolio Gate B decision: `../xfyun-competition-portfolio/docs/gate-b-research/openai-build-week-gate-b-theme-matrix-2026-07-17.md`
- Pending Grok work order: `../xfyun-competition-portfolio/docs/work-orders/wo-openai-changeguard-detection-localization-r5-20260717.md`

## Verified facts

- Plugin manifest location: `.codex-plugin/plugin.json`
- Optional components supported by official docs: skills, lifecycle hooks, app/connectors, MCP servers, assets
- Plugin hooks are skipped until the user reviews and trusts their current definition
- No dedicated Codex software-update hook is assumed; `SessionStart` fingerprint comparison plus manual scan is the planned path

## Next steps

1. Obtain explicit authorization to send the disclosed architecture work order and synthetic/real incident facts to external Grok.
2. Review the Grok return package; accept only claims supported by deterministic evidence contracts.
3. Implement the local fingerprint collector, official evidence index, Issue matcher, probe registry, and the two primary fixtures.
4. Validate the Plugin structure, schemas, redaction, negative controls, and judge path.

## Boundaries

- Do not register, publish, upload, or submit before Gate C authorization.
- Do not auto-apply community workarounds.
- Do not read or export secret values, complete environment variables, or complete session rollouts.
- Do not describe a user-reported Issue as a confirmed root cause without local reproduction or official linkage.
