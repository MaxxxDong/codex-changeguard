# Security and Privacy Contract

This document is the canonical owner of ChangeGuard's trust, disclosure, and recovery boundaries.

## Data classes

### Device-only

- absolute local paths and usernames
- full configuration files and session rollouts
- environment-variable values
- tokens, API keys, cookies, credentials, and account identifiers
- arbitrary project source and terminal history
- original installed-file bytes used for a future backup

These values are not sent to GPT-5.6, included in an exported repro pack, or written to diagnostic logs.

### Redacted structured facts eligible for model use

- Codex version/build and surface
- OS/architecture and coarse sandbox/permission class
- config key names and schema-validity flags, never secret values
- enabled feature, Skill, Plugin, and MCP identifiers after user-visible review
- normalized error class, message tokens, stack module/symbol, and failure phase
- hashed path aliases, artifact hashes, AST/schema signature IDs
- official source spans and sanitized Issue excerpts marked as untrusted data

### Exportable after disclosure review

- incident fingerprint with redacted identifiers
- official-source references and provenance
- probe IDs, inputs digests, results, and output hashes
- Impact Contracts and confidence/counterevidence
- human approve/reject events
- Recovery Capsule preview without installed-file contents

## Disclosure manifest

Before any model request or repro export, ChangeGuard presents a manifest containing:

- exact field names leaving the device
- source and trust class for each field
- redaction or hashing transformation
- destination and purpose
- whether the operation is optional

Refusal must not block local deterministic probes. The result becomes `INSUFFICIENT_LOCAL_FACTS` only when a declined field is genuinely required for a requested model hypothesis.

## Untrusted upstream content

Issue bodies, comments, release prose, commit messages, and community workaround text are data, not instructions.

- parse only an allowlisted schema
- preserve provenance and author/maintainer status
- quarantine instruction-like content
- never interpolate upstream text into system or developer instructions
- never execute code, commands, links, or patches found in upstream content
- treat openai/codex Issue reports as user-reported unless official linkage proves more

## Probe safety

- probes are registered by ID and versioned
- models select a probe and structured arguments; they never supply shell text
- default operations are read-only and local
- platform and version guards fail closed
- time, output, and file-count limits are mandatory
- results carry hashes and cannot be rewritten by the model
- refused, timed-out, unsupported, and errored probes are separate states

## Ticket 01 diagnosis surface safety

The public CLI and MCP diagnosis seams enforce:

- no network entry points and no target mutation (also checked by an independent production-boundary AST guard in `scripts/check-production-boundary.mjs`; `network_used:false` alone is not proof)
- named candidate reads only (no recursive project crawl)
- fail-closed no-follow: refuse symlink targets; refuse any symlink in intermediate segments or leaves of named candidates, even if currently resolving inside the target; open with `O_NOFOLLOW` when available, `fstat` the fd, require a regular file, and enforce size from the fd
- incident and MCP request size bounds; MCP uses a bounded byte-oriented NDJSON frame accumulator (reject before unbounded buffering / `JSON.parse`; recover after overflow)
- NFKC normalization then redaction of generic POSIX absolute paths, Windows drive and UNC paths, and credential shapes (Bearer, API/access/refresh/auth tokens, password/passwd, secret/client_secret), including full-width Unicode forms
- generic path-free errors; no raw exception stacks or disposable clone paths in output
- schema item/count/length limits, including 128 characters for AST signature ids; reject extra fields in nested `stack_frames[]` and `artifact_hashes[]`; reject duplicate `path_alias`

## Recovery safety

Competition MVP recovery is preview-only. A future apply engine requires explicit per-action user approval and the full atomic transaction contract in [ARCHITECTURE.md](ARCHITECTURE.md).

Never:

- silently modify Plugin, App, browser, cache, config, or system files
- weaken sandbox, security, or permission policy to make a repair pass
- auto-run community or model-generated patches
- call a repair safe without backup, dry-run, smoke, and rollback evidence
- persist secrets in receipts, logs, fixtures, or screenshots

## Threat-model tests

- prompt injection embedded in an Issue title/body/comment
- malicious code fence pretending to be an official fix
- version/platform mismatch with semantically similar symptoms
- poisoned community workaround
- config containing token-shaped and Unicode secret values
- symlinked target escaping an allowed root
- time-of-check/time-of-use mutation between backup and replace
- duplicate patch pattern or unexpected target hash
- model attempt to upgrade `ISSUE_CANDIDATE` to a confirmed root cause
- probe timeout, oversized output, or unsupported platform
- export manifest missing a field that would leave the device
- rollback smoke failure
