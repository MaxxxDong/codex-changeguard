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
| A1 | Typecheck | `npm run typecheck` (also inside `verify:release`) | ☑ pass on `2e5f463` (historical R13) and post-R13 correction tip |
| A2 | Tests | `npm test` | ☑ historical R13 **552/552** on `2e5f463`; current post-R13 full suite **561/561**, 0 fail (~73.0s) |
| A3 | Production boundary | `npm run check:boundary` (+ self-test via gate) | ☑ via `ready:local` / release path |
| A4 | Package build | `npm run package` → `release/codex-changeguard-plugin/` (+ `.tgz`; LICENSE; no source maps) | ☑ pure Node deterministic ustar+gzip (stable order/metadata; symlink/special fail-closed); **465** files; no node_modules/AGENTS/HANDOFF/docs/agents/source maps; MIT; private. **Pre-doc-finalization only** (not final; two consecutive runs): content SHA256 `ec05b6576731b68bd470becaf77225876220ab9046f71c0656cf4d851edb70c2`; tar SHA256 `f7b590d530797bca69a056d3b8ccafcc8583a99d33335cac7931aede09c13e80` (gzip mtime 0, OS 255). **Post-doc final freeze (R20; Root-verified two consecutive runs):** `package_content_sha256` `5b27ae6fa958521a2c57513b2e6568d06b8bc94230f43d165664d4902b1c0b5c`; `package_file_count` **465**; `tarball_sha256` `aac7723b60c6ed9c331121a0ca476b986e8bdf3de297365af212a262108d627b`; `reproducible_tarball` true; surface flags false for node_modules/AGENTS/HANDOFF/docs/agents/source maps; `has_license` true; `private` true; `license` MIT. R20 docs patch SHA256 `e794b83b88abd389e348b31e955e076c935c71fefebfc7be2097b386ad4045bf`. Do not treat pre-doc or obsolete pre-correction host-`tar` freezes as final |
| A5 | Package smoke | `npm run package:smoke` (staged install + packaged demo + uninstall) | ☑ via final `ready:local` 10/10; system tar extract + extracted demo `ok=true`, 10 steps, `network_used=false` |
| A5b | Clean-profile residual | `npm run package:clean-profile` | ☑ via `ready:local` 10/10 |
| A5c | Local readiness aggregator | `npm run ready:local` | ☑ final post-R13 `ok=true`, all 10 steps pass, `local_only=true`, `gate_c=false`, `remote_publish=false`, `registration=false`, `competition_submission=false`, `real_github_write=false` |
| A6 | Full release gate | `npm run verify:release` → `ok=true` | ☑ via `ready:local` path |
| A7 | Working-tree whitespace | `git diff --check` | ☑ pass |
| A8 | Docs honesty | README EN/ZH parity; support matrix matches receipts; packaged judge path accurate (no false “demo no-build from bare source”) | ☑ bilingual README + matrix honesty retained |
| A9 | License surface | Root [LICENSE](../LICENSE) MIT + `package.json` `"license": "MIT"`; package remains private until publication policy says otherwise | ☑ MIT; package remains private |
| A10 | Fixtures | Synthetic/redacted only; protected-process + negative-control still separable | ☑ synthetic/redacted fixtures retained |

### Ticket 17 demo / uninstall requirements (implementation evidence themes)

Local S4 package/profile work, **historical R13** Root gates on clean tip `2e5f463250c3749731418b661e1a3527bf049e62` (Ticket17 focused **27/27**, full suite **552/552**, `ready:local` 10/10), independent R13 double review both `PASS_NO_P0_P1`, plus **post-R13** deterministic-tarball correction (package-repro **9/9**, full suite **561/561**, final `ready:local` 10/10, R19 `REPRO_REVIEW: PASS_NO_P0_P1`) support Ticket 17 **`LOCAL_COMPLETE`**. Local closeout is complete; **Gate C / external publication remain unauthorized**.

| # | Requirement | Evidence commands (local) |
| --- | --- | --- |
| T17-1 | Shared demo core used by CLI, MCP, and Skill (`/changeguard demo` / `node bin/changeguard.js demo`) | `npm test` (ticket17 surfaces) + packaged demo in `package:smoke` |
| T17-2 | Disposable temp targets only; no active primary Codex/Profile mutation | demo receipt `live_profile_mutated: false` |
| T17-3 | Demo path: no network on default production seams | `network_used: false` on demo receipt |
| T17-4 | Rollback + cleanup after authorized isolated repair demo | `hash_proof.restored` + `cleanup.temp_removed` |
| T17-5 | CLI/MCP equivalence for demo-visible outcomes | ticket17 surface tests + staged MCP demo in smoke |
| T17-6 | Clean-profile install + uninstall smoke (no daemon / no ChangeGuard global config residue) | `npm run package:clean-profile` |
| T17-7 | Packaged judge path: Node >= 20, prebuilt package, no GitHub login, no API key, no on-host product rebuild | `npm run package` + `package:smoke` from non-repo cwd |
| T17-8 | Deterministic portable tarball (post-R13): pure Node ustar+gzip; stable order/metadata; symlink/special fail-closed; package-repro focused tests | package-repro **9/9**; pre-doc-finalization dual-run `ec05`/`f7b590` retained as non-final only; **post-doc final freeze (R20)** content/tar hashes in A4 |

Ticket 17 local closeout is complete with Root + R13 historical and post-R13 correction evidence. Do **not** treat local green checks as Gate C authorization. Reproducibility is scoped to **identical package inputs + fixed Node toolchain**, not arbitrary Node/zlib version identity.

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
