# 03 — 识别多实例与版本变化

**What to build:** 用户可以看到实际运行的 Codex 实例、安装来源、Profile 和版本变化，不会因为 PATH、Desktop 内置 CLI 或多份缓存并存而修错对象。

**Blocked by:** 01 — 建立只读诊断主链.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets 10–17 are not complete. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred.

Exact operational evidence (root integrated verification, combined Wave 2 review, artifact hashes) is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 枚举 Desktop 内置、PATH、受支持包管理器、Windows MSIX 和 WSL 实例时保持独立身份与路径哈希。
- [x] 能从进程、日志或启动上下文确定实际故障实例，不把最高版本自动视为故障实例。
- [x] 首次安装、升级、降级和路径优先级漂移产生不同且准确的结果。
- [x] SessionStart 仅在版本指纹变化时执行不超过十秒的只读健康检查；无变化时保持安静。
- [x] Hook 未受信任、跳过或失败时明确显示状态，并保留等价的手动扫描入口。
- [x] Repair Capsule 永远只绑定一个已观察实例，不向其他实例广播。
- [x] Scenario Harness 覆盖首次基线、多实例升级、降级和 PATH 漂移。

## Implementation notes (Ticket 03)

- Instance core: `src/instances/` (enumerate, resolve, compare, scan, state, repair-binding, system-adapter).
- Hooks: `hooks/hooks.json` → `dist/hooks/session-start-entry.js`; core `src/hooks/session-start.ts` + bounded health check.
- Public seams: `changeguard scan|scan-system|session-start` and MCP `changeguard_scan|changeguard_scan_system|changeguard_session_start`.
- Raw install paths never exported (path hashes/aliases only); version evidence is metadata-only under allowed roots.
- Harness: `tests/instance-scan.test.ts`, `tests/ticket03-corrections.test.ts` (baseline, silent SessionStart, upgrade/downgrade/PATH drift, hook trust states, packaged hook path).

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated commit `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e` (integrated on top of Ticket 02 as `075d318`).
- Root integrated verification and Wave 2 combined review (`NO_P0_P1`): see [HANDOFF.md](../../../HANDOFF.md) § Wave 2 closeout.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets 10–17.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized.
