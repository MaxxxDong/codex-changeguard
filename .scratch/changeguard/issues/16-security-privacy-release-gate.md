# 16 — 建立隐私、安全和回归发布门

**What to build:** 用户和维护者可以依赖一个统一发布门证明 ChangeGuard 不泄漏敏感信息、不误修相似故障、不会在验证失败后留下修改，并且没有隐藏遥测或越权操作。

**Blocked by:** 05 — 安全分析用户提供的网页; 06 — 建立 KNOWN_GOOD 与回滚生命周期; 07 — 完成配置与启动故障包; 08 — 完成 Plugin 缓存与版本偏移故障包; 09 — 完成 Desktop Browser 崩溃分类器; 11 — 执行经确认的 GitHub 上游操作; 12 — 完成维护者跟进与官方修复闭环; 13 — 取得 macOS Full 支持凭据; 14 — 完成 Windows 11 适配与真实验证; 15 — 提供 Linux、WSL 与企业受管环境路径.

**Status:** review-ready candidate (Worker implementation complete; **not** `LOCAL_COMPLETE`; awaiting Root dynamic verification + independent double-review)

- [x] 对令牌、Cookie、密码、一次性验证码、完整环境变量、绝对路径、会话内容和项目源代码执行泄漏对抗测试，外部泄漏数必须为零。 *(Worker: `privacy-corpus.mjs` + self-test `privacy_poison`; Root must re-run full gate)*
- [x] 对恶意网页、Issue 文本和提示注入验证模型无法绕过证据、授权、DSL 或平台边界。 *(Worker: `injection-matrix.mjs` binds existing Ticket 05/04/10/11/12/09/15 tests)*
- [x] 至少两个正向 Fixture 完成验证修复，至少两个完成验证缓解或上游阻塞，至少三个相似症状负向 Fixture 拒绝错误修复。 *(Worker: fixture accounting 2/2/3 mechanical binds)*
- [x] 每条写路径验证前置条件、备份、原子变更、成功检查和真实回滚；任何失败都会阻止 resolved 状态。 *(Worker: `write-path-inventory.mjs`)*
- [x] 审计发布产物不存在守护进程、隐藏网络、遥测、动态依赖安装、任意 shell 或 OpenAI 二进制。 *(Worker: `package-audit.mjs` capability scan; plants on isolated temp copy)*
- [x] 一条仓库级验证命令运行 Plugin、Schema、Fixture、CLI、MCP、Hook、恢复、上游和隐私检查。 *(Worker: `npm run verify:release` → `scripts/verify-release.mjs`; never `run-verification.sh`)*
- [x] 任一强制条件失败时发布流程非零退出并给出准确失败原因。 *(Worker: stable `GATE_*` reason codes + gate-of-gate negatives in `tests/ticket16-release-gate.test.ts`)*

## Evidence separation

| Layer | Owner | Status |
| --- | --- | --- |
| Implementation + targeted tests + local `verify:release` | Grok Worker (this clone) | candidate for Root review |
| Full regression / package smoke / boundary self-test counts on clean tip | Root dispatcher | **not yet claimed** |
| Independent static double-review | Future review tasks | **not yet claimed** |

## Explicit non-claims

- **Not** `LOCAL_COMPLETE`.
- Does **not** complete Ticket 17 or whole-product closeout.
- Gate C / registration / publication / upload / external submission / real GitHub writes remain unauthorized / `NOT_STARTED`.
