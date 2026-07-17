# Repository Rules

- This repository owns only the Codex ChangeGuard Plugin and its tests, fixtures, schemas, and submission artifacts.
- `README.md` is the entry point; `docs/ARCHITECTURE.md` owns technical contracts; `docs/SECURITY.md` owns trust and privacy rules; `HANDOFF.md` owns transient continuation state.
- Models may propose hypotheses but may not create deterministic evidence edges, override probe results, or promote user-reported Issues to confirmed causes.
- Local probes are allowlisted, bounded, read-only by default, and must emit structured evidence with hashes.
- Community fixes and model-generated fixes must first pass isolated reproduction, negative-control, backup, verification, and rollback checks. A proven candidate may run once as an experimental repair only after explicit, scope-bound user authorization; any failed verification triggers automatic rollback.
- Never collect or export tokens, API keys, complete environment-variable values, or complete session rollouts.
- Registration, publication, upload, and submission require separate Gate C authorization.
- Use Grok Worker only when external disclosure has been explicitly authorized for the exact disclosed context; Root Codex remains dispatcher and reviewer.

## Agent skills

### Issue tracker

Specifications and implementation tickets use the repository-local Markdown tracker. See `docs/agents/issue-tracker.md`.

### Domain docs

The project uses a single-context domain documentation layout. See `docs/agents/domain.md`.
