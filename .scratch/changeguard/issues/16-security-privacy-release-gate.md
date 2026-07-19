# 16 — 建立隐私、安全和回归发布门

**What to build:** 用户和维护者可以依赖一个统一发布门证明 ChangeGuard 不泄漏敏感信息、不误修相似故障、不会在验证失败后留下修改，并且没有隐藏遥测或越权操作。

**Blocked by:** 05 — 安全分析用户提供的网页; 06 — 建立 KNOWN_GOOD 与回滚生命周期; 07 — 完成配置与启动故障包; 08 — 完成 Plugin 缓存与版本偏移故障包; 09 — 完成 Desktop Browser 崩溃分类器; 11 — 执行经确认的 GitHub 上游操作; 12 — 完成维护者跟进与官方修复闭环; 13 — 取得 macOS Full 支持凭据; 14 — 完成 Windows 11 适配与真实验证; 15 — 提供 Linux、WSL 与企业受管环境路径.

**Status:** `LOCAL_COMPLETE` (implementation candidate **R24**; Root independently reproduced all R24 RED/GREEN probes; R25 independent double review both PASS / `NO_P0_P1:true`). Does **not** complete Ticket 17 or whole-product closeout.

- [x] 对令牌、Cookie、密码、一次性验证码、完整环境变量、绝对路径、会话内容和项目源代码执行泄漏对抗测试，外部泄漏数必须为零。 *(Root dynamic: privacy corpus + GitHub PAT corpus under `npm run verify:release`; Ticket16 focused 49/49; full suite 525/525)*
- [x] 对恶意网页、Issue 文本和提示注入验证模型无法绕过证据、授权、DSL 或平台边界。 *(Injection matrix: 15 rows, including official-bind absence refusal and binary-install absence independently bound; Root dynamic re-verification passed)*
- [x] 至少两个正向 Fixture 完成验证修复，至少两个完成验证缓解或上游阻塞，至少三个相似症状负向 Fixture 拒绝错误修复。 *(Root dynamic fixture accounting under release gate; thresholds 2/2/3 held)*
- [x] 每条写路径验证前置条件、备份、原子变更、成功检查和真实回滚；任何失败都会阻止 resolved 状态。 *(Root dynamic `write-path-inventory` contracts under release gate)*
- [x] 审计发布产物不存在守护进程、隐藏网络、遥测、动态依赖安装、任意 shell 或 OpenAI 二进制。 *(Root dynamic `package-audit` under release gate; `npm run verify:release` `ok=true`)*
- [x] 一条仓库级验证命令运行 Plugin、Schema、Fixture、CLI、MCP、Hook、恢复、上游和隐私检查。 *(Canonical: `npm run verify:release` → `scripts/verify-release.mjs`; never `run-verification.sh`)*
- [x] 任一强制条件失败时发布流程非零退出并给出准确失败原因。 *(Stable `GATE_*` reason codes + gate-of-gate negatives; Root `verify:release` `ok=true`, no failed step, `diff_check=ok`)*

## Evidence separation

| Layer | Owner | Status |
| --- | --- | --- |
| Implementation candidate | Worker (R24) | R24 candidate integrated; mechanical gate-of-gate + release-gate inventory |
| Full regression / typecheck / build / `verify:release` on clean tip | Root dispatcher | **passed** — Ticket16 focused **49/49**; full suite **525/525**; `npm run typecheck` pass; `npm run build` pass; `npm run verify:release` `ok=true`, no failed step, `diff_check=ok`; `git diff --check` pass |
| Independent static double-review / closure | R25 review tasks | **passed** — standards `worker.log` SHA256 `da262901325a2fd6bcb509b96fb58a367fd7f20dd33cb384ab48d2ad6b626a21`, verdict PASS, `NO_P0_P1:true`; spec/security `worker.log` SHA256 `70e7dca729b0c23e7d94f8b68884b0edbbb0266e089d5feb4df1211a24bac40c`, verdict PASS, `NO_P0_P1:true` |

## Explicit non-claims

- Ticket 16 is `LOCAL_COMPLETE` for the security/privacy/release-gate acceptance criteria only.
- Does **not** complete Ticket 17 or whole-product closeout.
- Gate C / registration / publication / upload / external submission / real GitHub writes remain unauthorized / `NOT_STARTED`.
