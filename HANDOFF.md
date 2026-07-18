# Codex ChangeGuard Handoff

## Current state

- Date: 2026-07-18 Asia/Shanghai
- Track ID: `track-openai-build-week-codex-changeguard-20260717`
- Gate B: `APPROVED`, option A
- Current scope status: `IN_PROGRESS` (broader product; Tickets 11–17 are not complete)
- Ticket 01 (read-only diagnosis spine): `LOCAL_COMPLETE` / locally verified on commit `d7d917b03fc8b2ddd6b9b42b961cf58b4af4e5b2`
- Ticket 02 (protected-process verified repair): `LOCAL_COMPLETE` / integrated through `e06e254`, verified on `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e`
- Ticket 03 (instance / version detection): `LOCAL_COMPLETE` / integrated as `075d318`, verified on `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e`
- Ticket 04 (official evidence + Impact Card): `LOCAL_COMPLETE` / integrated as `c20ddc5`, verified on `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e`
- Ticket 05 (untrusted page / URL diagnosis): `LOCAL_COMPLETE` / integrated as `607be8f`, verified on `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`
- Ticket 06 (KNOWN_GOOD / rollback lifecycle): `LOCAL_COMPLETE` / integrated as `50117ca`, verified on `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`
- Ticket 07 (config / startup fault pack): `LOCAL_COMPLETE` / integrated as `42bbf5c`, verified on `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`
- Ticket 08 (plugin cache / skew / reconciliation): `LOCAL_COMPLETE` / integrated as `5b0b608`, verified on `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`
- Ticket 09 (Desktop Browser crash-family classifier): `LOCAL_COMPLETE` / integrated as `a7e1cea` (+ hard-gate `45c79b5`), verified on `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`
- Ticket 10 (upstream draft routing preview): `LOCAL_COMPLETE` / integrated through `0829936` → `7ef87e6` → `26d58b4` → `3265acd`, verified on `3265acd11fa260d4e2c857705a73bd36b7b002b6`
- Registration: `NOT_STARTED`
- External submission: `NOT_STARTED`
- Gate C: not authorized
- No public publication, upload, or submission has occurred
- Real external GitHub writes: unauthorized / `NOT_STARTED`

## Canonical documents

- Product entry and stable boundary: [README.md](README.md)
- Technical design and evidence levels: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Security/privacy contract: [docs/SECURITY.md](docs/SECURITY.md)
- Verification plan: [docs/TEST_PLAN.md](docs/TEST_PLAN.md)
- Ticket 01 issue record: [.scratch/changeguard/issues/01-read-only-diagnosis-spine.md](.scratch/changeguard/issues/01-read-only-diagnosis-spine.md)
- Ticket 02 issue record: [.scratch/changeguard/issues/02-protected-process-verified-repair.md](.scratch/changeguard/issues/02-protected-process-verified-repair.md)
- Ticket 03 issue record: [.scratch/changeguard/issues/03-instance-version-detection.md](.scratch/changeguard/issues/03-instance-version-detection.md)
- Ticket 04 issue record: [.scratch/changeguard/issues/04-official-evidence-impact-card.md](.scratch/changeguard/issues/04-official-evidence-impact-card.md)
- Ticket 05 issue record: [.scratch/changeguard/issues/05-untrusted-url-diagnosis.md](.scratch/changeguard/issues/05-untrusted-url-diagnosis.md)
- Ticket 06 issue record: [.scratch/changeguard/issues/06-known-good-rollback-lifecycle.md](.scratch/changeguard/issues/06-known-good-rollback-lifecycle.md)
- Ticket 07 issue record: [.scratch/changeguard/issues/07-config-startup-fault-pack.md](.scratch/changeguard/issues/07-config-startup-fault-pack.md)
- Ticket 08 issue record: [.scratch/changeguard/issues/08-plugin-cache-skew-fault-pack.md](.scratch/changeguard/issues/08-plugin-cache-skew-fault-pack.md)
- Ticket 09 issue record: [.scratch/changeguard/issues/09-desktop-browser-crash-classifier.md](.scratch/changeguard/issues/09-desktop-browser-crash-classifier.md)
- Ticket 10 issue record: [.scratch/changeguard/issues/10-upstream-draft-routing.md](.scratch/changeguard/issues/10-upstream-draft-routing.md)

## Ticket 01 local completion (canonical evidence)

Ticket 01 read-only diagnosis spine is `LOCAL_COMPLETE` on clean commit
`d7d917b03fc8b2ddd6b9b42b961cf58b4af4e5b2`. This does **not** complete the
broader ChangeGuard product or Tickets 02–17 (Tickets 02–04 were completed later
in Wave 2; Tickets 05–09 in Wave 3; Ticket 10 later; see closeouts below).

### Root independent verification (passed)

- `npm ci`
- `npm run typecheck`
- `npm run build`
- `npm test`: 43/43 pass
- `npm run check:boundary`: 10 production files, zero violations
- `npm run package`
- `npm run package:smoke`
- `node scripts/cli-hash-proof.mjs`: both fixtures unchanged, `allOk=true`
- `node scripts/check-production-boundary.mjs --self-test`: 165/165 pass
- `git diff --check`

### Final bounded Grok review R19

- Result: `NO_P0_P1`
- Probes: 18/18
- Patch: empty
- Working tree: clean

R19 artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| `changes.patch` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `verification.txt` | `775733e0c1810c6fede95adaaf3d52c49f4b63c9895e14425eacf8d15b1fedb2` |
| `worker.log` | `b3991e66fb64d1683356b14cbd19ea1ed577a1778c26efc38111f34f6a1a53f4` |

## Wave 2 closeout (Tickets 02–04; canonical evidence)

Tickets 02, 03, and 04 each meet their ticket acceptance criteria locally and are
`LOCAL_COMPLETE`, verified on integrated clean main commit
`c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e`. Broader ChangeGuard remains
`IN_PROGRESS`. Gate B remains `APPROVED`, option A. Gate C is not authorized.
Registration and external submission remain `NOT_STARTED`; no public publication,
upload, or submission occurred.

### Integration commits

| Ticket | Integration commit | Notes |
| --- | --- | --- |
| 02 | `e06e254` | Reviewed implementation fast-forwarded through this commit |
| 03 | `075d318` | Integrated on top of Ticket 02 |
| 04 | `c20ddc5` | Integrated on top of Ticket 03; tip of Wave 2 closeout |

### Root integrated verification on `c20ddc5` (passed)

- `npm test`: 110/110 pass
- `npm run typecheck`
- `npm run check:boundary`: zero violations
- Boundary self-test: 175/175 pass
- `npm run package`
- `npm run package:smoke`
- Arbitrary-cwd packaged Hook proof
- Product tree clean

### Final combined Grok review (`changeguard-wave2-combined-review-r1`)

- Result: `NO_P0_P1`
- Independent cross-ticket probes: 31/31
- Patch: empty
- Working tree / product tree: clean

Combined review artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| `changes.patch` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `verification.txt` | `12a9f5d6e43a7ef8fe37f6c728bdd07a43abf6ef0b65db9d5f1c3371419dca29` |
| `worker.log` | `e9364b5b50afd41d4585bd5b047cc85370a07535469c57820eca98cc12968b54` |

The clean integrated combined review above is the canonical final proof for Wave 2
product closeout on `c20ddc5`.

## Wave 3 closeout (Tickets 05–09; canonical evidence)

Tickets 05, 06, 07, 08, and 09 each meet their ticket acceptance criteria locally
and are `LOCAL_COMPLETE`, verified on integrated clean HEAD
`5aa12c6c7370d9da84be3078c14fc63cf7e90fec` (`fix: close Wave 3 lifecycle trust gaps`).
Broader ChangeGuard remains `IN_PROGRESS`; at Wave 3 closeout Tickets 10–17 were
still incomplete (Ticket 10 was closed later; Tickets 11–17 remain incomplete).
Gate B remains `APPROVED`, option A. Gate C is not authorized. Registration,
publication, upload, and external submission remain `NOT_STARTED`. Real external
GitHub writes remain unauthorized / `NOT_STARTED`.

### Integration commits

| Ticket | Integration commit | Notes |
| --- | --- | --- |
| 09 | `a7e1cea` (+ hard-gate `45c79b5`) | Desktop Browser crash-family classifier |
| 07 | `42bbf5c` | Config / startup fault pack + recovery |
| 08 | `5b0b608` | Plugin cache / skew / reconciliation recovery |
| 05 | `607be8f` | Untrusted page / URL diagnosis |
| 06 | `50117ca` (+ clean `00074d2`, tip trust fix `5aa12c6`) | KNOWN_GOOD / rollback lifecycle |

Wave 3 verification tip (all of 05–09): `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`.

### Root integrated verification on `5aa12c6` (dynamic; passed)

Root dispatcher evidence (not Grok-run in this docs closeout):

- Full regression: `npm test` **212/212** pass, **0** failures
- `npm run typecheck` pass
- `npm run check:boundary` pass
- `npm run package` pass
- `npm run package:smoke` pass

### Final independent review (`changeguard-wave3-final-review-r2`)

- Task id: `changeguard-wave3-final-review-r2`
- Result: `NO_P0_P1`
- Role: independent **static** review of integrated Wave 3 HEAD
- Distinction: Root owns the dynamic 212/212 regression and typecheck/boundary/package/package-smoke evidence above; the final review task did **not** re-run dynamic tests as Grok analysis authority. Do not collapse Root dynamic proof into Grok static review.

### Residual Preview / Limited boundaries (still truthful)

Wave 3 local completion does **not** upgrade platform support claims:

- macOS Full / Windows Full / Linux·WSL Limited real-machine matrix remains Tickets 13–15 (`NOT_STARTED` / incomplete).
- Ticket 06 CLI and Desktop **version** rollback seams are registered `preview_only` guidance: no OpenAI binary store, download, redistribution, or package-manager shell install.
- Desktop version rollback is additionally `limited` without official signed history or lawful user media evidence.
- Ticket 05 page commands remain candidate-only Repair DSL (`repair_authorized: false`); Ticket 09 crash families without verified fix stay `UPSTREAM_BLOCKED` / `INCONCLUSIVE` and refuse symptom-level repair authorization.
- Gate C / registration / publication / upload / submission / real external GitHub writes remain unauthorized.

The clean integrated Root regression plus `changeguard-wave3-final-review-r2` (`NO_P0_P1`) above are the canonical final proof for Wave 3 local ticket closeout on `5aa12c6`.

## Ticket 10 closeout (upstream draft routing preview; canonical evidence)

Ticket 10 meets its acceptance criteria locally and is `LOCAL_COMPLETE`, verified on
integrated clean HEAD `3265acd11fa260d4e2c857705a73bd36b7b002b6`
(`test: close Ticket 10 consumer gaps`). Broader ChangeGuard remains `IN_PROGRESS`;
Tickets 11–17 are **not** complete. Gate B remains `APPROVED`, option A. Gate C is
not authorized. Registration, publication, upload, and external submission remain
`NOT_STARTED`. Real external GitHub writes remain unauthorized / `NOT_STARTED`.
Ticket 11 remains required for any separately confirmed external action.

### Integration commits

| Commit | Role |
| --- | --- |
| `0829936` | `feat: implement Ticket 10 upstream preview` |
| `7ef87e6` | `fix: harden Ticket 10 preview gates` |
| `26d58b4` | `fix: enforce Ticket 10 ready-state invariant` |
| `3265acd` | `test: close Ticket 10 consumer gaps` (verification tip) |

Full tip SHA: `3265acd11fa260d4e2c857705a73bd36b7b002b6`.

### Root integrated verification on `3265acd` (dynamic; passed)

Root dispatcher evidence (not Grok-run in this docs closeout):

- Full regression: `npm test` **260/260** pass, **0** failures
- `npm run typecheck` pass
- `npm run check:boundary` pass
- Boundary self-test pass
- `npm run package` pass
- `npm run package:smoke` pass, including packaged Ticket 10:
  - `upstream-preview` PREVIEW_READY → exit **0**
  - `upstream-preview` PREVIEW_BLOCKED → exit **nonzero**
  - no network / production transport null (`transport_calls: 0`)

### Final independent review (`changeguard-ticket10-regression-review-r7`)

- Task id: `changeguard-ticket10-regression-review-r7`
- Result: `NO_P0_P1`
- Role: independent **static** review of integrated Ticket 10 HEAD
- Patch: empty
- Distinction: Root owns the dynamic 260/260 regression and typecheck / boundary /
  package / package-smoke evidence above; the final review task did **not** re-run
  dynamic tests as Grok analysis authority. Do not collapse Root dynamic proof into
  Grok static review. This docs closeout does **not** claim Grok dynamic tests.

### Residual Ticket 10 / product boundaries (still truthful)

Ticket 10 local completion does **not** authorize external writes or whole-product completion:

- Upstream Submission Capsules remain `preview_only` / `local_only` with
  `external_write: false` and `repair_authorized: false`; status never
  `SUBMITTED` / `POSTED`.
- Immutable official form snapshot provenance (bundled fixture
  `fixtures/upstream/form-snapshot-2026-07-18.json`):
  - `snapshot_id`: `official_issue_forms_2026-07-18`
  - `fetched_at`: `2026-07-18T00:00:00.000Z`
  - main commit: `3a067484584861606ad842de5bc4ac735a865ddf`
  - per-form git `blob_sha` (not content SHA-256):
    - `1-codex-app.yml` → `6e294ee27bc924fc2c68b743bad26260297d13f9`
    - `2-extension.yml` → `599bc08b428d6328c712f526549350daf0aada79`
    - `3-cli.yml` → `cfd368c0ba798d4f513edd5548fd185d761ed15d`
    - `4-bug-report.yml` → `4de88414600e6100720fefa2a324ce41d759cd7f`
    - `5-feature-request.yml` → `745c347965c2e58f8e8e4437009f2c8ae0059878`
    - `6-docs-issue.yml` → `1957b6035a58950329d87d4c24e67faf98c00572`
  - Snapshot is testable immutable evidence, not perpetual currency; stale labels apply by age.
- Ticket 11 confirmation is mandatory before any real Issue/Discussion/Bugcrowd/Support write.
- Gate C / registration / publication / upload / submission / real external GitHub writes remain unauthorized / `NOT_STARTED`.

The clean integrated Root regression plus `changeguard-ticket10-regression-review-r7`
(`NO_P0_P1`, empty patch) above are the canonical final proof for Ticket 10 local
closeout on `3265acd`.

## Verified facts (Tickets 01–10)

- Shared diagnosis core: `src/core/diagnose.ts` (named candidates only; fail-closed symlink policy; structural shim signature)
- Protected-process recovery: `src/core/recovery/` (preview / one-shot authorize / apply / verify / rollback on isolated targets only)
- Instance / version scan: `src/instances/` + optional trusted `SessionStart` (`hooks/hooks.json` → `dist/hooks/session-start-entry.js`)
- Official evidence + Impact Card: `src/evidence/` + `src/impact/` (disclosure-gated; production seams default to bundled snapshot with zero transport)
- Untrusted page analysis: `src/page/` (`analyze-page` / `changeguard_analyze_page`; candidate-only Repair DSL)
- Lifecycle / KNOWN_GOOD: `src/core/lifecycle/` (`lifecycle` / `changeguard_lifecycle`; surface rollback apply; CLI/Desktop version rollback preview-only)
- Config / startup faults: `src/core/config/` + recovery `config_set` / `config_remove`
- Plugin-cache faults: `src/core/plugin-cache/` + recovery resource copy / atomic replace / quarantine rename
- Crash-family classifier: `src/core/crash-family.ts` (deterministic gates; Fixture E)
- Upstream draft routing preview: `src/upstream/` (`upstream-preview` / `changeguard_upstream_preview`; preview-only capsule; immutable form snapshot)
- Public CLI: `bin/changeguard.js` → `dist/cli/main.js` (`diagnose`, `impact`, `analyze-page`, `upstream-preview`, `repair-preview`, `repair-apply`, `verify`, `rollback`, `scan`, `scan-system`, `session-start`, `lifecycle`)
- Public MCP tools: `changeguard_diagnose`, `changeguard_impact`, `changeguard_analyze_page`, `changeguard_upstream_preview`, `changeguard_repair_*`, `changeguard_verify`, `changeguard_rollback`, `changeguard_scan`, `changeguard_scan_system`, `changeguard_session_start`, `changeguard_lifecycle`
- `.mcp.json` uses `cwd: "."` and `./dist/mcp/server.js`
- Release package: `npm run package` → `release/codex-changeguard-plugin/` (self-contained JS, no `node_modules`)
- Package smoke: `npm run package:smoke` from a non-repo cwd (includes packaged SessionStart / MCP wiring checks and Ticket 10 upstream-preview ready/blocked)
- Production boundary guard: `npm run check:boundary`
- Positive protected-process fixture may reach `SOURCE_COMPONENT_LOCATED` / experimental `RESOLVED_VERIFIED` only under measured local evidence and Ticket 02 authorization rules
- Never claims external submission, Gate C authorization, whole-product completion, Ticket 11 confirmed writes, or real-machine platform Full beyond verified tickets

## Ticket 15 integration note (framework only; not product complete)

Ticket 15 Linux/WSL/enterprise capability matrix, bounded discovery, IT Handoff,
network compare, and write-disable gates are **semantically integrated** into the
unified platform surface with Tickets 13–14. Broader product remains
`IN_PROGRESS`. This is **not** `LOCAL_COMPLETE` for real-machine Linux/WSL Full,
and does **not** authorize Gate C / registration / publication / submission.

Truthful residual claims after integration:

- Linux and WSL remain **Limited / Read-only** without a real host Scenario Harness receipt.
- Synthetic or caller-injected capability validates the framework only; it cannot upgrade production Full.
- Public CLI/MCP recovery paths fail closed on unknown/Linux/WSL/managed policy; the internal fixture env seam alone is not authorization — isolated PREVIEW also requires exact-target disposable proof (OS temp).
- WSL host mounts (`/mnt/<drive>`), symlink laundering, and admin elevation recipes are refused.
- Network compare is local-input only (`network_used: false`).
- `platform-status` unifies T13 macOS fields, T14 Windows PREVIEW/`status`/plan/live-witness limits, and T15 capability `reports` without a second receipt truth source.

## Next steps

1. Continue broader product tickets (16–17); Tickets 01–15 framework work does not complete the product.
2. Keep Gate C / registration / publication / upload / submission / real external GitHub writes blocked until separate authorization.
3. Preserve residual Preview/Limited boundaries (version-rollback preview-only; Ticket 10 upstream preview-only / local-only / no external write; macOS Full needs live witness; Windows Full needs real host + live witness; Linux/WSL stay Limited without real receipts).
4. Ticket 11 owns separately confirmed external actions after a fresh Ticket 10 preview; do not treat Ticket 10 closeout as write authorization.
5. Do not treat a clean source checkout as runnable before `npm ci && npm run build` (or `npm run package`).

## Boundaries

- Do not register, publish, upload, or submit before Gate C authorization.
- Do not auto-apply community workarounds outside the isolated Ticket 02 authorization contract.
- Do not read or export secret values, complete environment variables, or complete session rollouts.
- Do not describe a user-reported Issue as a confirmed root cause without local reproduction or official linkage.
- Do not claim Grok dynamic test execution for Wave 3 final review or Ticket 10 regression review; Root owns dynamic regression evidence.
