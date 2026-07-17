# 09 — 完成 Desktop Browser 崩溃分类器

**What to build:** 用户面对相似的 Codex Desktop Browser 崩溃时，可以得到按平台、组件、失败阶段和结构签名区分的候选结果；缺乏适用证据时产品会拒绝危险补丁。

**Blocked by:** 01 — 建立只读诊断主链; 03 — 识别多实例与版本变化; 04 — 提供官方证据刷新与更新影响卡.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets 10–17 are not complete. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred. Real-machine Windows Full support remains Ticket 14 (not claimed here).

Exact operational evidence (Root integrated verification, Wave 3 final review, residual boundaries) is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 不同 Windows 崩溃家族按异常码、栈符号、GPU 退出码、交互阶段和组件分开建模。
- [x] 兼容 Fixture 的正确 Issue 候选进入 Top 3，不兼容平台或机制被硬门排除。
- [x] 标题或“点击后崩溃”等症状相似性不能单独产生高置信度根因。
- [x] 无安全隔离时只使用已有日志和崩溃元数据，不主动崩溃用户主实例。
- [x] 没有可验证修复时返回 `UPSTREAM_BLOCKED` 或 `INCONCLUSIVE`，并生成可行动的下一步证据要求。
- [x] Scenario Harness 包含多个相似症状负向控制，并证明错误修复永不进入授权阶段。

## Implementation notes (Ticket 09)

- Classifier core: `src/core/crash-family.ts` (deterministic hard gates; Fixture E families under `fixtures/crash-family/`).
- Invoked from shared `diagnose` when sanitized `crash_metadata` is present; dump bodies are never parsed or exported.
- Without verified fix linkage, outcomes stay `UPSTREAM_BLOCKED` or `INCONCLUSIVE`; `repair-preview` is refused for symptom-level crash families.
- Harness: `tests/ticket09-crash-family.test.ts`.

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec` (implemented as `a7e1cea`; mechanism hard-gate fix `45c79b5`).
- Root integrated verification (dynamic) and Wave 3 final independent review (`changeguard-wave3-final-review-r2`, `NO_P0_P1`, static): see [HANDOFF.md](../../../HANDOFF.md) § Wave 3 closeout.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets 10–17 or Windows real-machine Full claims.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized.
