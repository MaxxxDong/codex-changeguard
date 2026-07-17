# 02 — 打通受保护 process 故障的验证修复

**What to build:** 用户可以在隔离环境中复现受保护 `process` 属性故障，查看完整 Repair Capsule，授权一次实验性修复，并通过原始故障复测和回滚证明获得可信的 `RESOLVED_VERIFIED` 结果。

**Blocked by:** 01 — 建立只读诊断主链.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets 05–17 are not complete. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred.

Exact operational evidence (root integrated verification, combined Wave 2 review, artifact hashes) is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 正向 Fixture 稳定复现受保护属性异常，并证明故障发生在 Browser 发现或握手之前。
- [x] 相似但机制不同的负向 Fixture 不会获得同一修复建议。
- [x] Repair Capsule 显示目标实例、哈希、精确匹配数、变更、风险、备份、验证和回滚。
- [x] 只有范围一致的显式授权可以触发原子修复，任何前置条件变化都会使授权失效。
- [x] 原始故障不再复现且核心健康检查通过后，结果才可为 `RESOLVED_VERIFIED`。
- [x] 人为制造验证失败时自动回滚；显式回滚后目标哈希与原始状态一致。
- [x] Scenario Harness 同时验证成功修复、拒绝错误候选和失败自动回滚三条路径。

## Implementation notes (Ticket 02)

- Recovery core: `src/core/recovery/` (`engine.ts`, `auth-token.ts`, `protected-process.ts`, `atomic-write.ts`).
- Public seams: `changeguard repair-preview|repair-apply|verify|rollback` and MCP `changeguard_repair_preview|changeguard_repair_apply|changeguard_verify|changeguard_rollback`.
- One-shot self-contained authorization token (`cg1.…`); scope/target/token mismatch fails closed; successful apply consumes the token.
- Isolated protected-process vertical slice only — not live Codex/Profile mutation.
- Harness: `tests/ticket02-repair-harness.test.ts` (success path, negative control, stale auth, induced verification auto-rollback).

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated commit `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e` (Ticket 02 reviewed implementation fast-forwarded through `e06e254`).
- Root integrated verification and Wave 2 combined review (`NO_P0_P1`): see [HANDOFF.md](../../../HANDOFF.md) § Wave 2 closeout.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets 05–17.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized.
