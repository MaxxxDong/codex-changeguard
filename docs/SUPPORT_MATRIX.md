# Platform support matrix

Platform Full / Preview / Limited / Read-only claims require a fresh
**real-machine Scenario Harness receipt**. Synthetic fixtures alone never
upgrade a platform to Full.

| Platform | Declared aim | Current claim rule | Adapter status | Notes |
| --- | --- | --- | --- | --- |
| macOS | Full (first full path) | Full only when Ticket 13 real-machine receipt has every required scenario `pass` **and** current-process live harness witness validation succeeds; external/CLI/MCP/arbitrary JSON alone is at most **Preview** | Namespaced adapter in `src/platform/macos/` | Disposable temp fixtures only; never active `~/.codex` (logical or realpath; symlink fail-closed) |
| Windows 11 | Full after Ticket 14 real-machine loop | **Preview** (current product claim). Framework integrated; Full only with a real Windows 11 `host_kind=real_machine` receipt covering W11-S01…S11 **and** a process-local live harness witness (external/CLI/MCP/JSON alone is at most Preview) | Namespaced adapter in `src/instances/windows/` + `src/platform/windows/` | No admin bypass; signed `.exe/.dll/.sys` always refused; no WindowsApps / Program Files mutation; synthetic fixtures never Full; no production path seals a Windows live witness yet |
| Linux | Limited CLI | **Limited** / read-only (Ticket 15 framework). No real Linux host Scenario Harness receipt in this repository; writes disabled by default | Namespaced adapter in `src/platform/linux-adapter.ts` + capability matrix | Registered PATH / package roots only; no Desktop full repair claim; `/mnt/<drive>` refused |
| WSL | Limited CLI + IT handoff | **Limited** (Ticket 15 framework). No real WSL host receipt; Windows host + WSL identities never collapse | Namespaced adapter in `src/platform/wsl-adapter.ts` | Enterprise policy → IT Handoff; host mounts refused; no sudo/chmod/UAC bypass |
| Unknown / unverified | Read-only | **Read-only**; mutation refused | Generic discovery only | Fail closed until a trusted adapter is identified |
| Enterprise managed | Limited + IT Handoff | **Limited**; local mutation refused | Policy recognition only | `ADMIN_ACTION_REQUIRED` + path/secret-cleaned IT Handoff; no elevation recipes |

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
- Gate C / registration / publication / upload / external submission remain unauthorized until separate approval.
- Ticket 15 framework is integrated; Linux/WSL remain **Limited / Read-only** without real-machine host receipts. This does **not** mark the whole product complete; Tickets 16–17 remain open. Broader product status stays `IN_PROGRESS`.
- Public CLI/MCP write paths are gated by trusted host capability; unknown/Linux/WSL/managed policies fail closed. External JSON/CLI/MCP arguments cannot downgrade the host or enable writes.
