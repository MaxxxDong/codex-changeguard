# Platform support matrix

Platform Full / Preview / Limited / Read-only claims require a fresh
**real-machine Scenario Harness receipt**. Synthetic fixtures alone never
upgrade a platform to Full.

| Platform | Declared aim | Current claim rule | Adapter status | Notes |
| --- | --- | --- | --- | --- |
| macOS | Full (first full path) | Full only when Ticket 13 real-machine receipt has every required scenario `pass` **and** current-process live harness witness validation succeeds; external/CLI/MCP/arbitrary JSON alone is at most **Preview** | Namespaced adapter in `src/platform/macos/` | Disposable temp fixtures only; never active `~/.codex` (logical or realpath; symlink fail-closed) |
| Windows 11 | Full after Ticket 14 real-machine loop | **Preview** (current product claim). Framework integrated; Full only with a real Windows 11 `host_kind=real_machine` receipt covering W11-S01…S11 | Namespaced adapter in `src/instances/windows/` + `src/platform/windows/` | No admin bypass; signed `.exe/.dll/.sys` always refused; no WindowsApps / Program Files mutation; synthetic fixtures never Full |
| Linux | Limited CLI | **Limited** / read-only generic until Ticket 15 | Registered PATH / package roots only | No Desktop full repair claim |
| WSL | Limited CLI + IT handoff | **Limited** until Ticket 15 | Registered WSL paths | Enterprise policy → IT Handoff |

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
# MCP: changeguard_platform_status
```

## Schema

`schemas/platform-support-receipt.schema.json` is a **oneOf** contract:

1. macOS Scenario Harness receipt (Ticket 13; `receipt_id` + `scenarios` + `isolation`)
2. Windows 11 support receipt (Ticket 14; `host_kind` + `critical_scenarios`)

Receipts must not contain usernames, home paths, disposable clone paths, or raw
temp paths. The two variants never share a second truth source: validators live
under `src/platform/receipt.ts` (macOS) and `src/platform/windows/` (Windows).

## Residual product boundaries

- Ticket 06 CLI/Desktop **version** rollback remains `preview_only` / Desktop may be `limited`.
- Ticket 10 upstream capsules remain `preview_only` / `local_only` / `external_write: false`.
- Gate C / registration / publication / upload / external submission remain unauthorized until separate approval.
- Ticket 13 does **not** mark the whole product complete; Tickets 14–17 remain open.
