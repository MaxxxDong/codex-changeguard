---
name: changeguard
description: Analyze Codex version changes and incidents using redacted local facts, official evidence, deterministic probes, and evidence-bound recovery previews.
---

# ChangeGuard

Use this Skill when the user asks what changed in Codex, whether a local Codex failure matches a known upstream Issue, or how to prepare a reversible recovery plan.

## Required behavior

1. Obtain or generate a disclosure manifest before any local facts leave the device.
2. Keep official facts, local observations, user-reported upstream content, model inference, and unknowns separate.
3. Use only registered read-only probe tools from the bundled ChangeGuard MCP server.
4. Never turn semantic similarity alone into a root-cause claim.
5. Never execute a community or model-generated workaround.
6. Produce Impact Contracts that validate against `schemas/impact-contract.schema.json` when that path is active.
7. Treat probe results as locked facts that the model cannot override.
8. End with one of the evidence states defined in `docs/ARCHITECTURE.md` and state what evidence is still missing.
9. For Ticket 01 diagnosis, orchestrate the **shared core** through the public seams below — do not reimplement diagnosis logic in the Skill.

## Ticket 01 — read-only diagnose

### Public seams (same core)

1. Rescue CLI: `changeguard diagnose <isolated-target-directory>`
   - repository wrapper: `node bin/changeguard.js diagnose <target>`
2. MCP tool: `changeguard_diagnose` with arguments `{ "target": "<isolated-target-directory>" }` only

Both return the same structured `DiagnosisResult` / `IncidentFingerprint` JSON.
User-resolution and upstream-contribution receipts are independent.

### Orchestration steps for `/changeguard diagnose`

1. Resolve an isolated fixture or user-approved target directory (never invent a live install path).
2. Call either the Rescue CLI or MCP `changeguard_diagnose` — not a parallel heuristic.
3. Present:
   - `diagnosis_state`
   - redacted `incident_fingerprint`
   - `user_resolution` receipt
   - `upstream_contribution` receipt (candidates only; never claim official root cause)
4. State explicitly that the run was read-only: no network, no target mutation, no repair.
5. If state is `INCONCLUSIVE`, list missing independent measurements; do not upgrade similarity to a cause.
6. If state is `SOURCE_COMPONENT_LOCATED`, emphasize that localization came from measured local hash/AST evidence and that upstream Issues remain candidates only.

### Forbidden in Ticket 01

- claiming `RESOLVED_VERIFIED` or applying a repair from diagnose
- submitting or drafting an Issue without a later ticket’s preview flow
- reading ordinary project source trees or unbounded file crawls
- treating declared incident JSON hashes/AST ids as self-proving evidence

## Ticket 02 — isolated protected-process verified repair

Public seams (same recovery core as CLI):

1. `changeguard repair-preview <isolated-target>` / MCP `changeguard_repair_preview`
2. `changeguard repair-apply <isolated-target> <authorization_binding>` / MCP `changeguard_repair_apply`
3. `changeguard verify <isolated-target>` / MCP `changeguard_verify`
4. `changeguard rollback <isolated-target>` / MCP `changeguard_rollback`

Orchestration:

1. Prefer a disposable/isolated fixture copy — never the live Codex profile.
2. Preview the Repair Capsule; present target alias, hash, pattern count, risk, backup, verification, rollback, and the one-shot `authorization_binding`.
3. Apply only with the exact binding from that preview; any target/scope change invalidates it.
4. `RESOLVED_VERIFIED` only when verification proves the original failure is gone and core health passes.
5. On verification failure, automatic rollback restores original bytes; never claim resolved.
6. Explicit rollback is mitigation (`MITIGATED_VERIFIED_BY_ROLLBACK`), not root-cause resolution.
7. Keep user-resolution and upstream-contribution receipts separate; never claim external submission.

## Planned commands

- `/changeguard scan`: compare installed and last-seen Codex fingerprints and map official changes to local surfaces
- `/changeguard diagnose`: build an incident fingerprint via the shared core (Ticket 01 implemented for isolated targets)
- `/changeguard repro-pack`: show the disclosure manifest and export a redacted evidence package after confirmation
- `/changeguard recovery-preview` / repair-preview: build a Repair Capsule (Ticket 02 for protected-process isolated targets)
- `/changeguard verify` / `/changeguard rollback`: Ticket 02 recovery seams

Upstream submission remains a later ticket. This Skill freezes the safety contract and routes diagnosis/repair through the shared core only.
