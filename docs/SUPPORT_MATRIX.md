# Platform support matrix

Platform Full / Preview / Limited / Read-only claims require a fresh
**real-machine Scenario Harness receipt**. Synthetic fixtures alone never
upgrade a platform to Full.

| Platform | Declared aim | Current claim rule | Adapter status | Notes |
| --- | --- | --- | --- | --- |
| macOS | Full (first full path) | Full only when Ticket 13 real-machine receipt has every required scenario `pass` and receipt validation succeeds; otherwise **Preview** with exact `uncovered_gaps` | Namespaced adapter in `src/platform/macos/` | Disposable temp fixtures only; never active `~/.codex` |
| Windows 11 | Full after Ticket 14 real-machine loop | **Preview** until Ticket 14 receipt | Partial system enumeration (MSIX / Desktop / PATH) | No admin bypass; no WindowsApps mutation |
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
npm run package
npm run harness:macos
# or: node scripts/run-macos-harness.mjs --out=<dir>
```

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

`schemas/platform-support-receipt.schema.json` is the strict receipt contract.
Receipts must not contain usernames, home paths, disposable clone paths, or raw
temp paths.

## Residual product boundaries

- Ticket 06 CLI/Desktop **version** rollback remains `preview_only` / Desktop may be `limited`.
- Ticket 10 upstream capsules remain `preview_only` / `local_only` / `external_write: false`.
- Gate C / registration / publication / upload / external submission remain unauthorized until separate approval.
- Ticket 13 does **not** mark the whole product complete; Tickets 14–17 remain open.
