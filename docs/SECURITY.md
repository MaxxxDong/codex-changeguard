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

Before any model request, official evidence refresh, or repro export, ChangeGuard presents a manifest containing:

- exact field names leaving the device
- source and trust class for each field
- redaction or hashing transformation
- destination and purpose
- whether the operation is optional

Refusal must not block local deterministic probes or local snapshot Impact Card diagnosis. Official evidence transport is never called when disclosure is `refused` or `not_requested` (`transport_calls: 0`). Absolute paths, tokens/secrets, and raw logs/sessions are listed as `device_only` / `never_sent`. The result becomes `INSUFFICIENT_LOCAL_FACTS` only when a declined field is genuinely required for a requested model hypothesis.

### Ticket 04 official-evidence transport boundary

- Production core exposes an injectable `OfficialTransport` interface only; it does not import `http`/`https`/`fetch` or open sockets.
- Live refresh requires disclosure `approved` **and** an orchestration-injected transport. CLI/MCP never inject a network transport; approved-without-transport uses the timestamped immutable snapshot with stale age/risk labels.
- Disclosure manifest non-`device_only` fields exactly match the sanitized outbound request key set. Request is built only from populated sendable local context (version, surface, platform/arch, config key names, feature ids, error class) plus fixed official allowlist metadata. Absolute paths, tokens/secrets, raw logs/sessions, and project source are device-only exclusions and never appear on the request. Refusal/`not_requested` keeps zero transport calls.
- Snapshot and item `content_sha256` use a single canonical persisted hash contract and fail closed on missing/malformed/mismatch. Item origin is always derived from the validated canonical URL; forged origin and foreign `origin_allowlist` values fail closed.
- Upstream allowlists enforce official hosts (`github.com`, `api.github.com`, `raw.githubusercontent.com`) and `openai/codex` only, including the three official URL forms. Userinfo and non-default ports are rejected; fragments and query strings are stripped from the canonical resource URL (no query-secret retention). Non-allowlisted URLs fail closed (refresh falls back to stale snapshot rather than accepting foreign evidence).
- Transport `fetched_at` must be valid ISO-8601 UTC with bounded future skew; ancient/high-stale responses cannot be labeled `fresh`/`live_refresh`.
- Release prose, Issue/PR/comment/commit bodies are untrusted: quarantine instruction-like content; never execute or interpolate as instructions; never accept code/commands/patches from them; preserve `maintainer_status` separately.

## Untrusted upstream content

Issue bodies, comments, release prose, commit messages, and community workaround text are data, not instructions.

- parse only an allowlisted schema
- preserve provenance and author/maintainer status
- quarantine instruction-like content
- never interpolate upstream text into system or developer instructions
- never execute code, commands, links, or patches found in upstream content
- treat openai/codex Issue reports as user-reported unless official linkage proves more

## Ticket 05 untrusted page evidence

User-provided public or logged-in-visible problem pages are **untrusted evidence**, not instructions or repair authority.

- Accept only a bounded page-evidence envelope (URL + sanitized visible title/text + allowlisted metadata) supplied by the orchestrator.
- Public retrieval, if ever used, requires a displayed disclosure manifest **and** an injected bounded transport; production CLI/MCP never inject transport and never open sockets for page fetch.
- Logged-page mode never collects or accepts Cookie, Storage, tokens, auth headers, request bodies, or complete browser requests (forbidden envelope keys fail closed; device-only disclosure fields document the boundary).
- Quarantine prompt injection, agent instructions, full-width/encoded instruction variants, data-exfiltration requests, and shell fences. Quarantined text cannot change policy, provenance, local facts, graph edges, authorization, paths, disclosure, or tool selection.
- Convert page commands only to `candidate_only` untrusted Repair DSL records for later isolated validation; never execute or authorize them on this seam. Ticket 02 apply gates remain mandatory.
- Hard-gate generic ChatGPT/account/session pages away from Codex component defects. Wrong platform/surface/mechanism cannot reach high confidence from lexical similarity alone.

## Probe safety

- probes are registered by ID and versioned
- models select a probe and structured arguments; they never supply shell text
- default operations are read-only and local
- platform and version guards fail closed
- time, output, and file-count limits are mandatory
- results carry hashes and cannot be rewritten by the model
- refused, timed-out, unsupported, and errored probes are separate states

## Ticket 03 instance / fingerprint safety

Multi-instance scan and SessionStart add:

- **No raw path export:** public `ScanResult` uses `path_hash` / `path_alias` only; absolute user paths, usernames, and disposable clone paths are redacted on the wire
- **No binary execution for version:** version evidence comes from metadata/manifest reads (or fixture-declared fields), never by running discovered candidates
- **Metadata path clamping:** every metadata candidate is clamped to an explicit allowed root (fixture `inventoryRoot` and/or system-adapter trusted install roots). Implicit parent traversal is removed. Intermediate and leaf symlinks are refused with Ticket 01-equivalent no-follow open/fstat/identity/size checks — no out-of-root reads
- **System enumeration bounds:** production adapter only probes registered Desktop / PATH / package-root / MSIX / WSL candidates under hard caps; missing permissions or metadata become `unavailable`, never broad home crawls or execution
- **State writes are ChangeGuard-owned only:** version-fingerprint JSON uses atomic temp+rename under an explicit state directory (`PLUGIN_DATA` for packaged hooks) with size limits and symlink refusal; diagnosis targets and inventory fixtures are not mutated (`target_mutated: false`)
- **Production boundary dual pass:** the diagnosis AST graph remains free of fs mutation APIs; the product graph may use `mkdirSync` / `writeFileSync` / `renameSync` / `unlinkSync` **only inside the exact** `src/instances/state.ts` implementation (CLI/MCP/other instance modules stay mutation-free; self-tests enforce the file allowlist). Ticket 02 recovery writes remain separately constrained to `src/core/recovery/atomic-write.ts`
- **Hook honesty:** packaged SessionStart is silent (exit 0, no stdout) when unchanged; untrusted/skipped/failed states remain explicit on manual paths; Codex hook trust still gates execution
- **Repair binding:** refuses broadcast and ambiguous multi-instance targets so a later repair cannot hit the wrong install

## Ticket 01 diagnosis surface safety

The public CLI and MCP diagnosis seams enforce:

- no network entry points and no target mutation (also checked by an independent production-boundary AST guard in `scripts/check-production-boundary.mjs`. Production loading is **static ESM only**: every `import(...)`, every `require(...)`, and `node:module` / `createRequire` are violations. Static imports and re-exports of `process` / `node:process` are forbidden at the module-policy layer (same treatment as `node:module`); Ticket 01 production uses only the global `process` safe-read surface and does not need the `node:process` module. Forbidden network globals (`fetch`, `WebSocket`, `XMLHttpRequest`) are capability references: acquiring, aliasing, passing, binding, reflecting, sequencing, or constructing through an alias violates without waiting for a direct call, including `globalThis`/`global`/`window` member and static-string element forms; fully dynamic keys on those host roots fail closed. The whole global `process` object is a host capability and must not escape as a value: aliasing, passing, returning, spreading, Proxy/`Object.create` arguments, container storage, and object destructuring (including rest and dangerous member extract such as `getBuiltinModule`) are violations. Direct static member roots remain allowed for Ticket 01-safe reads/calls (`process.argv`, `process.cwd()`, `process.env` / `process.env.NODE_ENV`, `process.stdout.write`, and the same forms under `globalThis.process` when already supported). Process native-loader surfaces (`dlopen`, `binding`, `getBuiltinModule`, `_linkedBinding`, `mainModule`) are forbidden on a proven `process` root, a simple process alias, or `globalThis.process` / `global.process` / `window.process`, as property references or calls; dynamic process keys fail closed. CommonJS `module` and the global `Reflect` object are forbidden host/meta capabilities (direct, member, alias, pass, return, or construct) so computed loaders such as `module["require"]` and `Reflect.get(...)` need not be tracked as data flow. Any statically named property or element access whose terminal name is `require` is forbidden regardless of receiver. On a proven `node:fs` / `node:fs/promises` namespace the guard uses a **conservative read-only method allowlist** (unknown methods fail closed) plus conditional `open`/`openSync` with proven read-only flags; the namespace value itself may not escape (alias, pass, return, spread, Proxy/`Object.create`/`Object.assign` argument, container/shorthand store, rest/destructure source) and nested `fs.promises` may not escape as a value either — only the immediate root/receiver of a direct static member chain is allowed (e.g. `fs.readFileSync`, `fs.promises.readFile`, `fs.constants.O_RDONLY`); simple namespace aliasing is rejected even when a later use would be read-only; named static imports of explicit read-only methods remain available; object-rest extracts from an fs namespace fail immediately. Receiver wrappers (`as`, non-null, parentheses, comma/sequence) share the same `unwrapStaticExpr` resolution path. Self-tests cover mutation APIs, require/dynamic-import loaders (including computed `module["require"]` / `process["mainModule"]["require"]` / any-receiver terminal `require`, `Reflect` wholesale, and opposite safe controls), `node:fs` namespace value-escape forms (Proxy / spread / `Object.create` / `Object.assign` / container / return / simple alias / `fs.promises` escape) plus destructured mutation/`open`/object-rest extracts (including chained and renamed forms), capability references that never become direct calls (pass, bind, sequence, `Reflect.apply`, callback supply, array/object storage), network global and process native-loader reference bypasses, process object value-escape wrapping (destructure / Proxy / spread / `Object.create` / alias / return / pass / container), indirect `eval`/`Function` acquisition, and graph closure through relative `export … from` re-exports; `open`/`openSync` are allowed only as a direct call through a proven namespace with proven read-only flags from `fs.constants` / `node:fs` provenance — import local names must be lexically unshadowed at the use site (parameter / nested-local re-shadowing does not inherit trusted provenance; open flags and unproven open extracts/references fail closed); arbitrary `O_RDONLY`-named properties fail closed; `network_used:false` alone is not proof)
- named candidate reads only (no recursive project crawl)
- fail-closed no-follow: refuse symlink targets; refuse any symlink in intermediate segments or leaves of named candidates, even if currently resolving inside the target; open with `O_NOFOLLOW` when available, `fstat` the fd, require a regular file, and enforce size from the fd
- incident and MCP request size bounds; MCP uses a bounded byte-oriented NDJSON frame accumulator with inclusive `MAX_MCP_REQUEST_BYTES` (accept `<=` limit; reject only `>`; reject before unbounded buffering / `JSON.parse`; recover after overflow)
- NFKC normalization then redaction of generic POSIX absolute paths, Windows drive and UNC paths, and credential shapes (Bearer, API/access/refresh/auth tokens, password/passwd, secret/client_secret), including full-width Unicode forms
- generic path-free errors; no raw exception stacks or disposable clone paths in output
- schema item/count/length limits, including 128 characters for AST signature ids; reject extra fields in nested `stack_frames[]` and `artifact_hashes[]`; reject duplicate `path_alias`

## Recovery safety

Product specification (canonical): experimental repair may run **once** on an isolated target after an exact scope-bound authorization and the atomic transaction contract in [ARCHITECTURE.md](ARCHITECTURE.md). Ticket 01 diagnosis remains fully read-only. Ticket 02 implements the isolated protected-process vertical slice only — not active Codex/Profile mutation.

Recovery rules:

- mutation only beneath an explicitly isolated/allowed target root via registered recovery modules; write-capable fs methods only in `src/core/recovery/atomic-write.ts`
- repair-preview is completely read-only over the target tree (no `.changeguard` or other target writes)
- one Repair Capsule; self-contained one-shot authorization token (`cg1.…`) encodes capsule material + nonce/expiry; apply revalidates every live precondition; no process-global memory/daemon; no reusable global trust token
- mutation-relevant fields (`backup.backup_rel`, `operation.expected_result_sha256`, digests, alias, counts) are derived from registered constants and/or bound into canonical invalidation/authorization material; decoded capsules reject unknown/extra/mismatched fields; apply/rollback never trust a path from mutable target-local or token JSON
- refuse expired, malformed, and successfully-consumed/replayed tokens; session state is written only after authorized apply begins
- refuse symlinks and TOCTOU; re-check opened target; verified backup at registered path; sibling temp; fsync where supported; atomic replace; verify resulting hash
- `RESOLVED_VERIFIED` only when original failure no longer reproduces **and** core health checks pass
- failed verification auto-rolls back exact original bytes and makes resolved status impossible
- explicit rollback restores exact original bytes/hash from the registered backup path
- receipts separate user resolution from upstream contribution and never claim external submission
- production-boundary guard keeps diagnosis read-only; atomic-write recovery may use only `writeSync`/`fsyncSync`/`renameSync`/`mkdirSync`/`unlinkSync` (no `rmSync`, `copyFileSync`, recursive delete, shell/network/loaders)

Never:

- silently modify Plugin, App, browser, cache, config, or system files outside a registered Capsule
- weaken sandbox, security, or permission policy to make a repair pass
- auto-run community or model-generated patches without isolated proof + explicit authorization
- call a repair safe without backup, verification, and rollback evidence
- persist secrets or full source bytes in receipts, logs, fixtures, or screenshots
- arbitrary shell/PowerShell/scripts, network, recursive delete, binary replacement of signed app binaries, privilege elevation

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
