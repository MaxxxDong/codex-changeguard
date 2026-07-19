# Platform support matrix

Platform Full / Preview / Limited / Read-only claims require a fresh
**real-machine Scenario Harness receipt** (plus live harness witness where
required). Synthetic fixtures alone never upgrade a platform to Full.
**Full is receipt-scoped**, not a universal claim for every OS release,
architecture, or Codex version.

| Platform | Declared aim | Current product claim | Claim rule | Adapter status | Notes |
| --- | --- | --- | --- | --- | --- |
| macOS | Full (first full path) | **Full** (receipt-scoped on verified real-machine harness for this host; Ticket 13 `LOCAL_COMPLETE`) | Full only when real-machine receipt has every required scenario `pass` **and** current-process live harness witness validation succeeds; external/CLI/MCP/arbitrary JSON alone is at most **Preview** | Namespaced adapter in `src/platform/macos/` | Disposable temp fixtures only; never active `~/.codex` (logical or realpath; symlink fail-closed). Not a universal macOS/Codex guarantee |
| Windows 11 | Full after Ticket 14 real-machine loop | **Preview** (framework integrated; not Full) | Full only with a real Windows 11 `host_kind=real_machine` receipt covering W11-S01…S11 **and** a process-local live harness witness (external/CLI/MCP/JSON alone is at most Preview) | Namespaced adapter in `src/instances/windows/` + `src/platform/windows/` | No admin bypass; signed `.exe/.dll/.sys` always refused; no WindowsApps / Program Files mutation; synthetic fixtures never Full; no real W11-S01…S11 receipt yet |
| Linux | Limited CLI | **Limited** / read-only (Ticket 15 framework; no real host receipt) | Writes disabled by default; synthetic capability cannot Full | Namespaced adapter in `src/platform/linux-adapter.ts` + capability matrix | Registered PATH / package roots only; no Desktop full repair claim; `/mnt/<drive>` refused |
| WSL | Limited CLI + IT handoff | **Limited** (Ticket 15 framework; no real host receipt) | Windows host + WSL identities never collapse; writes fail closed without disposable isolation proof | Namespaced adapter in `src/platform/wsl-adapter.ts` | Enterprise policy → IT Handoff; host mounts refused; no sudo/chmod/UAC bypass |
| Unknown / unverified | Read-only | **Read-only**; mutation refused | Fail closed until a trusted adapter is identified | Generic discovery only | — |
| Enterprise managed | Read-only + IT Handoff | **Read-only + IT Handoff**; local mutation refused | Policy recognition only; no elevation | Policy recognition only | `ADMIN_ACTION_REQUIRED` + path/secret-cleaned IT Handoff |

## macOS Full required scenarios

Required scenario ids (see `MACOS_REQUIRED_SCENARIO_IDS`):

1. `core_read_only_detection`
2. `multi_instance_scan`
3. `config_repair_success`
4. `forced_verify_fail_auto_rollback`
5. `explicit_rollback`
6. `plugin_cache_repair_rollback`
7. `known_good_canary`
8. `privacy_refusal_local_diagnosis`
9. `upstream_preview_zero_network`
10. `package_smoke`

## Safety constraints (all platforms)

Adapters must keep these constraints fixed at `false` / refused:

- broad home crawl
- raw path export in public outputs
- executing discovered binaries for version
- sudo requirement
- system certificate / proxy / security-control changes
- signed app or OpenAI binary mutation
- active primary Codex profile mutation
- WSL host mount roots (`/mnt/<drive>`) as trusted evidence
- intermediate or leaf symlink laundering into refused roots
- network/proxy/certificate/SSO/firewall live probes or settings mutation

## How to produce a macOS receipt

On a real macOS host, from a built tree:

```bash
npm ci
npm run build
npm run harness:macos
# or: node scripts/run-macos-harness.mjs --out=<dir>
```

The `package_smoke` scenario is self-contained: it always runs production
`npm run package` before `package:smoke` and packaged diagnose, so a missing or
stale T11-era `release/` tree does not require a prior manual package step.

The harness writes a path-free `macos-platform-support-receipt.json` and a
summary. Validate with:

```bash
node bin/changeguard.js platform-receipt-validate <receipt.json>
# MCP: changeguard_platform_receipt_validate
```

Read-only capabilities without running the harness:

```bash
node bin/changeguard.js platform-status
# Optional: --adapter=linux|wsl|windows|macos|unknown|enterprise_managed
# Optional: --receipt=<windows-receipt.json> --plan
# MCP: changeguard_platform_status
```

## Schema

`schemas/platform-support-receipt.schema.json` is a **oneOf** contract:

1. macOS Scenario Harness receipt (Ticket 13; `receipt_id` + `scenarios` + `isolation`)
2. Windows 11 support receipt (Ticket 14; `host_kind` + `critical_scenarios`)

Ticket 15 lightweight capability claims use `schemas/platform-capability.schema.json`
and `SupportReceipt` in `src/platform/support-receipt.ts` — a **distinct** contract
from the harness receipts above. Validators never share a second truth source:

- macOS: `src/platform/receipt.ts`
- Windows: `src/platform/windows/`
- Linux/WSL capability matrix: `src/platform/capability.ts` + `support-receipt.ts`

Receipts must not contain usernames, home paths, disposable clone paths, or raw
temp paths.

IT Handoff wire shape: `schemas/it-handoff.schema.json`.

## Residual product boundaries

- Ticket 06 CLI/Desktop **version** rollback remains `preview_only` / Desktop may be `limited`.
- Ticket 10 upstream capsules remain `preview_only` / `local_only` / `external_write: false`.
- Ticket 11 local confirmation engine is integrated; production default adapter remains unavailable — no real external GitHub write is authorized by documentation status alone.
- Ticket 12 (maintainer follow-up / upstream fix) is `LOCAL_COMPLETE` on clean commit `6083c6f`; follow-up remains preview-only / local-only / no external write.
- Ticket 16 (security / privacy / release gate) is `LOCAL_COMPLETE`; canonical local gate is `npm run verify:release`. That is product-local automated readiness only.
- Gate C / registration / publication / upload / external submission remain unauthorized / `NOT_STARTED` until separate approval. Creating a public remote, Release, or real GitHub write is **not** implied by Ticket 16 local complete.
- Ticket 13 macOS Full is **receipt-scoped** (current real-machine harness on this host only); it does not upgrade Windows or Linux claims and is not a universal macOS/Codex guarantee.
- Ticket 14 remains **Preview** without a real Windows 11 host receipt + live witness. Do not inflate T14 to Full from framework integration alone.
- Ticket 15 framework is integrated; Linux/WSL remain **Limited / Read-only** without real-machine host receipts. Enterprise managed remains **Read-only + IT Handoff**. Do not inflate T15 to Full from synthetic capability alone.
- Ticket 17 (competition demo + release-readiness surface) is **`LOCAL_COMPLETE`** on implementation commit `2e5f463250c3749731418b661e1a3527bf049e62`: shared demo core via `node bin/changeguard.js demo` / `/changeguard demo` / `changeguard_demo`, packaged no-build judge path (`npm run package` + `package:smoke`; pure Node deterministic ustar+gzip, stable order/metadata, symlink/special fail-closed), clean-profile uninstall smoke (`package:clean-profile`), historical R13 Root gates (Ticket17 **27/27**, full suite **552/552**, `ready:local` 10/10) and independent R13 double review both `PASS_NO_P0_P1`, plus post-R13 correction evidence (package-repro **9/9**, full suite **561/561**, final `ready:local` 10/10, R19 `REPRO_REVIEW: PASS_NO_P0_P1`). Reproducibility scoped to identical inputs + fixed Node toolchain. Gate C / registration / publication / upload / submission remain unauthorized / `NOT_STARTED` — local complete does **not** authorize external publication.
- This does **not** mark the whole product externally complete. Broader product status stays `IN_PROGRESS` only for Gate C / external actions and honest platform Full gaps (Ticket 14 Windows Preview; Ticket 15 Linux/WSL Limited), not because Tickets 16/17 are incomplete.
- Public CLI/MCP write paths are gated by trusted host capability; unknown/Linux/WSL/managed policies fail closed. External JSON/CLI/MCP arguments cannot downgrade the host or enable writes.
- Repository-only operational closeout evidence (Wave tip, harness counts, Gate C state) lives in the repo `HANDOFF.md` — not packaged with the plugin.
- Release checklist (local vs Gate C): repository `docs/RELEASE_CHECKLIST.md` (not part of the five packaged public docs).
