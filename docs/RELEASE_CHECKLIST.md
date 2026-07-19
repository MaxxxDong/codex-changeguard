# Release checklist

This checklist separates **product-local automated readiness** from **Gate C / external actions**. Completing the local side does **not** authorize public remotes, Releases, registration, upload, submission, or real GitHub writes.

## A. Local automated readiness (run and record)

Canonical gate (fail-closed; one summary JSON):

```bash
npm run verify:release
```

Record pass/fail for each area below. Prefer the orchestrated gate over ad-hoc partial runs when cutting a candidate.

| # | Check | Command / evidence | Local pass? |
| --- | --- | --- | --- |
| A1 | Typecheck | `npm run typecheck` (also inside `verify:release`) | ☐ |
| A2 | Tests | `npm test` | ☐ |
| A3 | Production boundary | `npm run check:boundary` (+ self-test via gate) | ☐ |
| A4 | Package build | `npm run package` → `release/codex-changeguard-plugin/` (+ `.tgz`; LICENSE; no source maps) | ☐ |
| A5 | Package smoke | `npm run package:smoke` (staged install + packaged demo + uninstall) | ☐ |
| A5b | Clean-profile residual | `npm run package:clean-profile` | ☐ |
| A5c | Local readiness aggregator | `npm run ready:local` | ☐ |
| A6 | Full release gate | `npm run verify:release` → `ok=true` | ☐ |
| A7 | Working-tree whitespace | `git diff --check` | ☐ |
| A8 | Docs honesty | README EN/ZH parity; support matrix matches receipts; packaged judge path accurate (no false “demo no-build from bare source”) | ☐ |
| A9 | License surface | Root [LICENSE](../LICENSE) MIT + `package.json` `"license": "MIT"`; package remains private until publication policy says otherwise | ☐ |
| A10 | Fixtures | Synthetic/redacted only; protected-process + negative-control still separable | ☐ |

### Ticket 17 demo / uninstall requirements (implementation evidence themes)

Local S4 package/profile work exercises these themes. **Whole Ticket 17 product closeout** still requires independent review and must not be marked closed from this checklist alone:

| # | Requirement | Evidence commands (local) |
| --- | --- | --- |
| T17-1 | Shared demo core used by CLI, MCP, and Skill (`/changeguard demo` / `node bin/changeguard.js demo`) | `npm test` (ticket17 surfaces) + packaged demo in `package:smoke` |
| T17-2 | Disposable temp targets only; no active primary Codex/Profile mutation | demo receipt `live_profile_mutated: false` |
| T17-3 | Demo path: no network on default production seams | `network_used: false` on demo receipt |
| T17-4 | Rollback + cleanup after authorized isolated repair demo | `hash_proof.restored` + `cleanup.temp_removed` |
| T17-5 | CLI/MCP equivalence for demo-visible outcomes | ticket17 surface tests + staged MCP demo in smoke |
| T17-6 | Clean-profile install + uninstall smoke (no daemon / no ChangeGuard global config residue) | `npm run package:clean-profile` |
| T17-7 | Packaged judge path: Node >= 20, prebuilt package, no GitHub login, no API key, no on-host product rebuild | `npm run package` + `package:smoke` from non-repo cwd |

Do **not** mark Ticket 17 / HANDOFF closed solely because A5–A5c pass.

## B. Gate C / external actions (unchecked by default)

Leave these **unchecked** until separate, scope-bound authorization exists. Local green checks never flip these to done.

| # | Action | Authorized? | Done? |
| --- | --- | --- | --- |
| B1 | Create or push a **public** remote | Gate C | ☐ |
| B2 | Publish a GitHub **Release** / distribution upload | Gate C | ☐ |
| B3 | Competition **registration** | Gate C | ☐ |
| B4 | **Upload** or **submit** competition artifacts | Gate C | ☐ |
| B5 | Real **external GitHub write** (Issue/comment/react/subscribe/upload) via production adapter | Separate host adapter + user confirmation; production default remains unavailable | ☐ |
| B6 | Claim universal platform Full beyond receipt-scoped evidence | Forbidden without new real-machine receipts | ☐ |

**Default product truth:** Gate C items remain `NOT_STARTED` until explicitly authorized. Product-local release readiness (section A) is allowed and is what `npm run verify:release` measures.

## C. Platform claim snapshot (do not inflate)

Canonical detail: [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

| Platform | Claim |
| --- | --- |
| macOS | Receipt-scoped Full **on this host only** (Ticket 13); not universal |
| Windows 11 | Preview until real W11 receipt **and** live witness |
| Linux / WSL | Limited / Read-only without real host receipt |
| Enterprise managed | Read-only + IT Handoff |

## D. Related docs

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [SECURITY.md](SECURITY.md)
- [TEST_PLAN.md](TEST_PLAN.md)
- [../README.md](../README.md) / [../README.zh-CN.md](../README.zh-CN.md)
- [../CONTRIBUTING.md](../CONTRIBUTING.md)
- [../LICENSE](../LICENSE)
