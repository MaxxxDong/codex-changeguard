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
6. Produce Impact Contracts that validate against `schemas/impact-contract.schema.json`.
7. Treat probe results as locked facts that the model cannot override.
8. End with one of the evidence states defined in `docs/ARCHITECTURE.md` and state what evidence is still missing.

## Planned commands

- `/changeguard scan`: compare installed and last-seen Codex fingerprints and map official changes to local surfaces
- `/changeguard diagnose`: build an incident fingerprint, rank Issue candidates, and propose deterministic probes
- `/changeguard repro-pack`: show the disclosure manifest and export a redacted evidence package after confirmation
- `/changeguard recovery-preview`: build a Recovery Capsule without applying it

The implementation of these commands is pending. This file freezes their safety and evidence contract; it does not claim the runtime is complete.
