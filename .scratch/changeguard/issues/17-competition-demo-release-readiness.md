# 17 — 完成比赛演示与公开发布准备

**What to build:** 评委可以在五分钟内安装并运行真实 ChangeGuard 演示，看到从故障到验证修复、错误候选拒绝与回滚的完整产品路径；仓库达到 MIT 公开发布准备状态但不会在未授权时实际发布或提交。Ticket 10 打包的 upstream-preview 是产品表面（可在包内单独调用），**不是**约两分钟 Ticket 17 主演示路径内的必做步骤。

**Blocked by:** 02 — 打通受保护 process 故障的验证修复; 13 — 取得 macOS Full 支持凭据; 14 — 完成 Windows 11 适配与真实验证; 16 — 建立隐私、安全和回归发布门.

**Status:** `LOCAL_COMPLETE` on implementation commit `2e5f463250c3749731418b661e1a3527bf049e62` (historical R13: Ticket17 focused **27/27**; full suite **552/552**; `npm run ready:local` 10/10 `ok=true`; R13 independent double review both `PASS_NO_P0_P1`). Post-R13 deterministic-tarball correction current evidence: Root package-repro **9/9**; full `npm test` **561/561** (0 fail); final `ready:local` 10/10 `ok=true` with all external action flags false; R19 read-only review `REPRO_REVIEW: PASS_NO_P0_P1`. Gate C / publication / registration / upload / submission remain **`NOT_STARTED`**.

- [x] Judge 从安装到启动 `/changeguard demo` 不超过五分钟，无需构建、GitHub 登录或额外 API Key。
- [x] 主演示在约两分钟内完成受保护属性故障的复现、解释、授权修复、验证和回滚展示。
- [x] 演示包含一个被确定性探针否定的模型假设，以及一个拒绝危险修复的 Windows 崩溃家族案例。
- [x] README 作为单一入口链接安装、平台支持、架构、安全、演示、贡献和卸载说明，中文与英文内容保持等价。
- [x] 仓库包含 MIT License、非官方声明、支持矩阵、验证命令、发布清单和经过脱敏的合成 Fixture。
- [x] Plugin 安装和卸载均通过干净 Profile 烟雾测试，卸载不遗留后台进程或全局配置。
- [x] 本工单只形成发布就绪凭据；创建公开远端、发布 Release、报名、上传和提交仍需独立 Gate C 授权。

## Evidence separation

| Layer | Owner | Status |
| --- | --- | --- |
| Implementation + local gates on clean tip `2e5f463` (historical R13) | Root dispatcher | **passed** — Ticket17 focused **27/27**; full `npm test` **552/552** (0 fail); `npm run typecheck` / `npm run build` / `git diff --check` pass; `npm run ready:local` `ok=true`, all 10 steps pass, `local_only=true`, `gate_c=false`, `remote_publish=false`, `registration=false`, `competition_submission=false`, `real_github_write=false` |
| Independent static double-review (R13) | Spec + security review tasks | **passed** — spec `worker.log` SHA256 `0b79a2c830c640f4b1db670f2a2acff322bcbf548dcd970cf37735c596ad2962`, verdict `PASS_NO_P0_P1`; security `worker.log` SHA256 `09077abb7a782d82edb52983d24eb1cd652060bf431237d86aec8b8b3d394052`, verdict `PASS_NO_P0_P1` |
| Late-correction artifact trail | R10–R12 patches | R10 `changes.patch` SHA256 `85fea5c3fbcb5205b897279e67ab8b95c5a4ad7b5debb5c109428e24e8475c9e`; R11 `75329bf8d895443adc19594ac4fb238b6fcbc0f376d759f02457291b1705363c`; R12 `3da3d8ea66fb9c32b2ef46ceafa2868aabf05579a62d9c7a525427293602a030` |
| Pre-closeout public package snapshot (historical) | Root package | 465 files; no `node_modules` / `AGENTS` / `HANDOFF` / `docs/agents` / source maps; MIT LICENSE; bilingual README — do **not** freeze pre-closeout hashes as final (see pre-doc vs post-doc final freeze below) |

### Post-R13 correction / current evidence (deterministic tarball)

Root found **nondeterministic host `tar` hashes** despite stable package **content**. Correction trail and current gates (do not rewrite R13 history above):

| Item | Evidence |
| --- | --- |
| R16 implementation patch | `changes.patch` SHA256 `4c39cf3753c48edaf6081ede68b43fd3b853d743a8d82b9c84a0e39dd2f8ada4` |
| R18 correction patch | `changes.patch` SHA256 `a66bf79e863be49a480db253475b81ae91b6d0a996daefec5dced482068de08e` |
| R20 docs patch (public-doc finalization trail) | `changes.patch` SHA256 `e794b83b88abd389e348b31e955e076c935c71fefebfc7be2097b386ad4045bf` |
| Root focused package-repro | **9/9** pass |
| Final full regression | `npm test` **561/561**, 0 fail, duration ~**73.0s** |
| Final `ready:local` | **10/10** `ok=true`; `local_only=true`; all external action flags false (`gate_c`, `remote_publish`, `registration`, `competition_submission`, `real_github_write`) |
| Pre-doc-finalization package (two consecutive runs; **not final**) | content SHA256 `ec05b6576731b68bd470becaf77225876220ab9046f71c0656cf4d851edb70c2`; tar SHA256 `f7b590d530797bca69a056d3b8ccafcc8583a99d33335cac7931aede09c13e80`; gzip mtime **0**, OS **255**; system tar extract + extracted demo `ok=true`, 10 steps, `network_used=false`, **465** files |
| R19 final read-only review | `changes.patch` empty; valid EndTurn verdict `REPRO_REVIEW: PASS_NO_P0_P1`; `worker.log` SHA256 `e05479ccd1f167d1d4751666064184de98cc5c1c6262e4d4b93a98223d2f8757` |
| **Post-doc final freeze (R20; Root-verified two consecutive runs)** | `package_content_sha256` `5b27ae6fa958521a2c57513b2e6568d06b8bc94230f43d165664d4902b1c0b5c`; `package_file_count` **465**; `tarball_sha256` `aac7723b60c6ed9c331121a0ca476b986e8bdf3de297365af212a262108d627b`; `reproducible_tarball` **true**; `has_node_modules` false; `has_agents_md` false; `has_handoff_md` false; `has_docs_agents` false; `has_source_maps` false; `has_license` true; `private` true; `license` MIT |

**Packaging contract (public):** pure Node deterministic **ustar + gzip**; stable member order and metadata; symlink / special-file paths **fail closed**. **Reproducibility scope:** identical package inputs plus a fixed Node toolchain — **not** a claim of identity across arbitrary Node/zlib versions.

**Final package freeze:** the post-doc R20 dual-run values above are the Root-verified final package evidence. The pre-doc-finalization `ec05`/`f7b590` pair remains historical evidence only and is **not** the final freeze.

## Explicit non-claims

- Ticket 17 is `LOCAL_COMPLETE` for competition-demo and local release-readiness acceptance only.
- Gate C / registration / publication / upload / external submission / real GitHub writes remain unauthorized / `NOT_STARTED`.
- Broader product status may remain `IN_PROGRESS` only for external/Gate C work and honest platform Full gaps (Ticket 14 Windows Preview; Ticket 15 Linux/WSL Limited), not because Ticket 16/17 product tickets are incomplete.
- Ticket 10 packaged `upstream-preview` is an available product surface, not a required step inside the two-minute Ticket 17 demo path.
