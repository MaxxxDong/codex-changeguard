# Domain Documentation

ChangeGuard uses a single-context domain documentation layout.

## Before Exploring

- Read `CONTEXT.md` at the repository root when it exists.
- Read relevant ADRs under `docs/adr/` when they exist.
- If either location is absent, proceed without creating placeholder documents.

## Vocabulary

Use the project's canonical terms in specifications, tickets, code, tests, and user-facing explanations. Existing terms include:

- Incident Fingerprint
- Change-to-Local Graph
- Repair Capsule
- Evidence Delta
- KNOWN_GOOD
- RESOLVED_VERIFIED
- MITIGATED_VERIFIED
- UPSTREAM_BLOCKED
- INCONCLUSIVE

Do not replace a canonical term with a near-synonym that changes its meaning. If a needed concept is not defined, record the gap for domain modeling instead of silently inventing competing language.

## Architecture Decisions

When proposed work conflicts with an existing ADR or an architectural contract, surface the conflict explicitly. Do not silently override the earlier decision.
