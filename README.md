# Codex ChangeGuard

Evidence-bound Codex Plugin for update impact analysis, incident localization, and reversible recovery planning. **Unofficial community project — not an OpenAI product, official support channel, or certification.**

> Models may propose hypotheses; deterministic probes adjudicate facts.

| Language | Entry |
| --- | --- |
| English | this file (`README.md`) — default package entry |
| 中文 | [README.zh-CN.md](README.zh-CN.md) — packaged bilingual surface (same public themes) |

## 1. Product and disclaimer

ChangeGuard maps official Codex changes to redacted local facts, assigns explicit evidence levels, and refuses false precision when an Issue cannot be confirmed locally. It is not a generic changelog summarizer, Issue chatbot, environment doctor, or automatic community-patch installer.

When the installed Codex build is newer than published notes, ChangeGuard still records a **path-free local installed-artifact baseline/diff** (`ScanResult.local_artifact_diff`) so “what changed in my current Codex version?” can separate **official evidence**, **observed local named-component deltas**, and **inferences**. Real installs use `scan-system` (or packaged SessionStart); fixture `scan` is for explicit inventories. Named-artifact measurement always runs under size caps and a SessionStart wall-clock budget (~4 s default) with explicit gap status when incomplete — full measurement is not deferred until after a change is detected. A missing changelog is not an excuse to invent history: first baselines are honest, and official feature-level notes can be unavailable while a local component delta is still verified.

ChangeGuard is independent of OpenAI. Names, branding, and docs must not imply official ownership or endorsement.

## 2. Five-minute judge path (prebuilt package)

**Packaged judge path (Ticket 17):** from a prebuilt plugin package and **Node.js >= 20**, a judge can run a live demo without building the repository, signing into GitHub, or supplying an API key. No network is required on the default path.

| Step | Expectation |
| --- | --- |
| Runtime | Node.js >= 20 only |
| Artifact | Prebuilt / packaged plugin tree (not a bare source checkout) |
| Build | **Not** required for the packaged judge path |
| GitHub login | **Not** required |
| API key | **Not** required |
| Network | **Not** required on the default demo path |

**How to obtain the package (maintainer / candidate builder)**

```bash
# Inside a developer checkout (build once to produce the artifact):
npm ci
npm run package
# → release/codex-changeguard-plugin/  (self-contained tree)
# → release/codex-changeguard-plugin.tgz  (portable archive)
```

**How a judge runs it (no repo, no TypeScript, no GitHub, no API key)**

```bash
# Unpack the prebuilt tree (or the .tgz) to any directory, then:
cd /path/to/codex-changeguard-plugin
node bin/changeguard.js demo
# Skill surface (when the host Skill is installed): /changeguard demo
# MCP: changeguard_demo (optional budget_ms only)
```

**Important — source checkout vs package**

- The **packaged** tree is no-build runnable for `demo` with Node.js >= 20 only.
- A **source checkout** still needs `npm ci` and `npm run build` (or `npm run package`) before CLI/MCP work.
- The package includes compiled JS, fixtures, schemas, Skill, public docs, and MIT `LICENSE` only — no `src/`, no `node_modules`, no source maps, no Git metadata.

## 3. `/changeguard demo` story and boundaries

The demo story (flagship protected-process fixture path; shared `runDemo` core):

1. Isolate allowlisted synthetic fixtures under a **disposable** OS-temp child (never live `~/.codex`).
2. Diagnose → explain structured evidence → repair preview → apply → verify → explicit rollback.
3. Prove a model-edge graph mutation is **refused** (graph unchanged).
4. Prove a crash-family path is **repair-authorization ineligible** and preview **refused**.
5. Cleanup removes demo-owned temp; receipt is path-alias / digest only.

Hard boundaries for the demo and product judge path:

| Boundary | Rule |
| --- | --- |
| Deterministic adjudication | Models may propose; registered probes and fixtures decide facts |
| Non-model core | Public CLI and MCP share the same non-model diagnosis/recovery cores |
| No network | Production demo / diagnose seams do not open sockets; offline snapshot evidence only unless a separate disclosure + injected transport exists (not on the default judge path) |
| No live Codex install mutation | Never patch the judge’s active primary Codex/Profile; disposable temp targets only |
| no daemon | No background agent, continuous logger, or install-time service |

### How we used Codex

Codex was the primary development and verification environment for ChangeGuard. We used it to turn the product principles into a specification and ticketed implementation, build the Plugin, Skill, MCP, and CLI surfaces, create adversarial fixtures, run security-boundary and packaging checks, test clean-profile installation, and inspect real platform receipts.

The product is intentionally Codex-native: users can invoke the guided Skill, call 18 structured MCP tools from an agent workflow, or run the same verified core through the CLI. It does not require a separate dashboard.

### How we used GPT-5.6

GPT-5.6 is used where model reasoning helps: compiling sanitized local facts into testable hypotheses, ranking compatible candidates after deterministic hard filters, and explaining Impact Contracts or recovery hypotheses in clear language.

GPT-5.6 is deliberately not the source of truth. It cannot create evidence edges, overwrite probe results, promote a user report to an official cause, or authorize a repair. Deterministic code and allowlisted probes decide what becomes evidence. The demo includes adversarial attempts to upgrade model output into evidence; every attempt is refused and the evidence graph remains unchanged.

## 4. Developer install vs packaged judge install

### Packaged judge install (evaluation)

1. Obtain a **prebuilt** plugin package (`npm run package` → `release/codex-changeguard-plugin/` or the portable `.tgz`, or an authorized distribution artifact when Gate C allows).
2. Ensure Node.js >= 20.
3. From the package directory (any non-repo cwd): `node bin/changeguard.js demo` (Skill: `/changeguard demo`; MCP: `changeguard_demo`).
4. Do not require repository clone, TypeScript build, GitHub auth, model API keys, or network for that path.

### Developer source install

```bash
npm ci
npm run build
npm test
npm run check:boundary
npm run package
npm run package:smoke
npm run package:clean-profile
npm run ready:local
npm run verify:release
node bin/changeguard.js demo
node bin/changeguard.js diagnose fixtures/protected-process
node bin/changeguard.js diagnose fixtures/negative-control
```

A clean source checkout is **not** claimed runnable before `npm ci && npm run build` (or `npm run package`).

Implemented public commands (repository wrapper: `node bin/changeguard.js …`):

| Area | CLI | MCP |
| --- | --- | --- |
| **Demo (judge)** | `changeguard demo [--budget-ms=N]` | `changeguard_demo` |
| Diagnose | `changeguard diagnose <target>` | `changeguard_diagnose` |
| Impact Card | `changeguard impact <target> [--disclose-…]` | `changeguard_impact` |
| Page analysis | `changeguard analyze-page <target> --envelope=…` | `changeguard_analyze_page` |
| Upstream preview | `changeguard upstream-preview <target> --request=…` | `changeguard_upstream_preview` |
| Lifecycle | `changeguard lifecycle <operation> <target>` | `changeguard_lifecycle` |
| Follow-up | `changeguard followup <operation> <target>` | `changeguard_followup` |
| Repair | `repair-preview` / `repair-apply` / `verify` / `rollback` | `changeguard_repair_*` / `changeguard_verify` / `changeguard_rollback` |
| Instances | `scan` / `scan-system` / `session-start` | `changeguard_scan` / `changeguard_scan_system` / `changeguard_session_start` |
| Upstream actions | `upstream-action-preview` / `upstream-action-confirm` | `changeguard_upstream_action_*` |
| Platform status | `platform-status` / `platform-receipt-validate` | `changeguard_platform_status` / `changeguard_platform_receipt_validate` |
| **Local staged update** | `compare-local-update [--format=json\|markdown]` | `changeguard_compare_local_update` |

**`compare-local-update`** (manual, read-only): spatial comparison of the installed macOS `ChatGPT.app` versus a Sparkle-staged updater app under the allowlisted Installation cache. Returns three separate truth sections — `official_evidence` (offline version-bound only), `local_observations` (measured bytes/metadata), `inference_and_unknowns` (conservative). Never installs, mutates, or writes staged packages into instance/SessionStart state; not the temporal `local_artifact_diff` baseline. Windows/Linux default to an honest unsupported discovery state.

Skill orchestration: `skills/changeguard/SKILL.md` (includes `/changeguard demo`).

### Uninstall and clean profile

- Uninstall removes the plugin package / Skill registration used for evaluation (delete the staged package tree and any host Skill registration pointing at it).
- Clean-profile smoke: `npm run package:clean-profile` installs under an **isolated temporary HOME only**, runs the packaged demo, uninstalls, and asserts no daemon, LaunchAgent/service/scheduled-task residue, shell-profile edit, global Codex config edit, credential requirement, background process, or leftover product-owned path. It never mutates the real home/profile/global config.
- This product does **not** install a system daemon and does **not** claim global OS configuration mutation as part of install or uninstall.
- Manual residual cleanup, if any host-side Skill cache remains, is limited to removing the packaged plugin tree and any explicit ChangeGuard state directories created during the session — never a broad home crawl.

## 5. Platform support matrix

Honest, receipt-scoped claims live in **[docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)**. Summary:

| Platform | Current product claim |
| --- | --- |
| **macOS** | Receipt-scoped **Full** on **this host only** after Ticket 13 real-machine harness (not universal for every macOS/Codex version; external JSON alone is at most Preview). Official Desktop discovery includes **ChatGPT.app** (`Contents/Resources/codex`) and legacy **Codex.app**; version from bundle `Info.plist` only |
| **Windows 11** | **Preview** — framework integrated; remains Preview without a real Windows 11 receipt **and** process-local live witness |
| **Linux / WSL** | **Limited / Read-only** — Ticket 15 framework; writes fail closed without a real host receipt |
| **Enterprise managed** | **Read-only + IT Handoff** — no local elevation or policy bypass |

Ticket 06 CLI/Desktop **version** rollback stays `preview_only` / Desktop may be `limited`.

## 6. Architecture, security, verification, and release readiness

| Doc | Role |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Evidence contracts, surfaces, demo-core requirements |
| [docs/SECURITY.md](docs/SECURITY.md) | Trust, disclosure, privacy, recovery boundaries |
| [docs/TEST_PLAN.md](docs/TEST_PLAN.md) | Verification layers and adversarial plan |
| [docs/CASE_STUDIES.md](docs/CASE_STUDIES.md) | Real-world diagnosis narratives |
| [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) | Platform Full / Preview / Limited rules |
| `docs/RELEASE_CHECKLIST.md` | Local readiness vs Gate C external actions (repository surface; not in the five packaged public docs) |
| [Current handoff](HANDOFF.md) | Repository-only operational evidence (not packaged) |

**Local readiness aggregator (Ticket 17; product-local only):**

```bash
npm run ready:local
```

Runs package structure checks, package demo smoke, clean-profile install/uninstall residual smoke, docs/link/parity/legal checks, production boundary, tests, `npm run verify:release`, and `git diff --check`. **Local only** — does not create a remote, Release, account, upload, registration, competition submission, or real GitHub write.

**Canonical local automated release gate:**

```bash
npm run verify:release
```

That command is the product-local release gate (typecheck, tests, boundary, package, smoke, privacy/write-path audits, `git diff --check`, and related steps). Passing it means **local automated readiness only**.

| Ready locally | Still Gate C / `NOT_STARTED` until separate authorization |
| --- | --- |
| `npm run ready:local` / `npm run verify:release` and related local checks | Creating a public remote |
| Product docs, MIT text, support matrix honesty | Publishing a GitHub Release |
| Synthetic fixture demos on disposable targets | Registration, upload, or competition submission |
| Clean-profile install/uninstall smoke (`npm run package:clean-profile`) | Real GitHub write / external publication |

See repository `docs/RELEASE_CHECKLIST.md` for the full local vs Gate C checklist.

## 7. Synthetic and redacted fixtures

Fixtures under [`fixtures/`](fixtures/) are **synthetic and redacted**:

- They model Codex-like layouts and failure signatures without shipping private user logs, full configs, crash dump bodies, cookies, tokens, or session rollouts.
- Positive and negative controls (for example `fixtures/protected-process` and `fixtures/negative-control`) exist so deterministic probes can separate real mechanism matches from look-alikes.
- Hashes, AST/schema signatures, and path **aliases** are used instead of raw home paths or secrets.
- Fixture data is for local diagnosis, packaging smoke, and Scenario Harness — not a claim about any specific end-user install.

## 8. Contributing

Contribution rules, review expectations, and safety boundaries: repository root `CONTRIBUTING.md` (bilingual one-file; source tree).

High-level rules:

- Prefer deterministic evidence over model prose.
- Do not add network, daemon, or secret-exporting paths in production surfaces.
- Experimental repair stays isolated, authorized, verified, and roll-backable.
- Do not treat documentation status as Gate C publication authority.

## 9. License and publication status

- License text: repository root `LICENSE` (MIT).
- `package.json` declares `"license": "MIT"`. The package remains `"private": true` in this repository slice.
- This source repository is publicly available under the MIT License. `"private": true` prevents accidental npm publication; it does not change the repository license.
- A public repository is not an OpenAI endorsement, an official support channel, or proof that a Devpost submission has been finalized. Competition status is determined by the Devpost portal.

---

### Plugin surfaces (reference)

- Skill, MCP (`changeguard_*` tools), Rescue CLI, optional trusted `SessionStart` hook
- Packaging: `npm run package` → `release/codex-changeguard-plugin/` (+ portable `.tgz`; exact public surface including `LICENSE`, `README.md`, and `README.zh-CN.md`; no `node_modules`, source maps, `AGENTS.md`, `HANDOFF.md`, or `docs/agents`)
- Package smoke: `npm run package:smoke` (stages install under temp profile, runs packaged demo from non-repo cwd, uninstalls)
- Clean-profile residual: `npm run package:clean-profile`
- Local readiness: `npm run ready:local`

### Development boundary

This repository owns the ChangeGuard product only. Portfolio research, Gate approvals, and competition status remain canonical outside this tree when applicable.
