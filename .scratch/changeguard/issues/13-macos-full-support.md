# 13 — 取得 macOS Full 支持凭据

**What to build:** macOS 用户可以在真实环境完成 ChangeGuard 核心检测、修复、回滚、隐私和上游草稿流程，产品以可审计 Scenario Harness 回执而不是开发者声明标记 Full 支持。

**Blocked by:** 06 — 建立 KNOWN_GOOD 与回滚生命周期; 07 — 完成配置与启动故障包; 08 — 完成 Plugin 缓存与版本偏移故障包; 09 — 完成 Desktop Browser 崩溃分类器; 10 — 生成低噪声上游反馈草稿.

**Status:** `LOCAL_COMPLETE` (macOS Full receipt-gated on integrated clean main `407789ca847b984dbd935e26edf8ad58ad0cf688`)

Broader ChangeGuard product remains `IN_PROGRESS`. **Platform claim is receipt-scoped Full**, not a universal claim for every macOS release, architecture, or Codex version. Full requires a fresh real-machine Scenario Harness receipt with every required scenario `pass` **and** process-local live harness witness; external/CLI/MCP/arbitrary JSON alone is at most Preview. Gate C / registration / publication / submission remain unauthorized / `NOT_STARTED`.

Exact operational evidence is canonical in [HANDOFF.md](../../../HANDOFF.md) § Wave 4 closeout and [docs/SUPPORT_MATRIX.md](../../../docs/SUPPORT_MATRIX.md).

- [x] macOS 适配器发现受支持安装来源、Profile、配置、日志、缓存和注册操作。
- [x] 真实机器运行核心故障包和多实例场景，不使用主活动 Codex Profile 执行危险复现。（Root-verified real macOS harness; disposable isolation; active profile non-mutation）
- [x] 修复、失败自动回滚、显式回滚和 `KNOWN_GOOD` canary 均产生可复核回执。
- [x] 外部刷新和上游草稿通过隐私检查，拒绝披露时本地诊断仍可运行。
- [x] 不需要 sudo，不修改系统证书、代理、安全控制或签名应用二进制。
- [x] 支持矩阵以本次测试的系统、架构、Codex 版本和能力为依据，并记录未覆盖范围。（Full = 本机 harness 回执范围；非全版本保证）

## Implementation notes (Ticket 13)

- Adapter: `src/platform/macos/`; public seams `platform-status` / `platform-receipt-validate` (CLI + MCP).
- Harness: `npm run harness:macos` / `scripts/run-macos-harness.mjs` (darwin real-machine path).
- Required scenarios: see `MACOS_REQUIRED_SCENARIO_IDS` in [docs/SUPPORT_MATRIX.md](../../../docs/SUPPORT_MATRIX.md).
- Safety: no broad home crawl; no raw path export; no binary execution for version; disposable temps only; symlink fail-closed.

## Local completion closeout

- Local status: `LOCAL_COMPLETE` with current real-machine macOS Full harness evidence on this host (Root-verified: `ok=true`, `support_level=full`, `network_used=false`, all 10 required scenarios pass).
- Not claimed: universal macOS/Codex coverage; Windows Full; Linux/WSL Full; Gate C; whole-product completion.
