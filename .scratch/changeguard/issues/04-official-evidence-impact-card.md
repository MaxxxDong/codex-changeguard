# 04 — 提供官方证据刷新与更新影响卡

**What to build:** 用户在批准最小披露清单后，可以看到与本机 Codex 表面真正相交的官方版本变化、证据来源和过期状态，而不是一份泛化更新摘要。

**Blocked by:** 01 — 建立只读诊断主链.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets 10–17 are not complete. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred.

Exact operational evidence (root integrated verification, combined Wave 2 review, artifact hashes) is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 外部刷新前显示准确的 disclosure manifest，拒绝授权时仍可使用本地快照诊断。
- [x] 证据优先从官方文档、Release、Tag、Diff、Issue、PR 和 Commit 获取，并记录来源、抓取时间、版本、状态与哈希。
- [x] 无网络或官方源不可用时使用带时间戳的固定快照，并明确标记过期风险。
- [x] Change-to-Local Graph 仅由确定性规则添加边，模型无法修改来源或提升证据等级。
- [x] 更新影响卡只展示与当前实例、配置、Plugin、Skill、MCP、Hook 或运行时表面存在证据交集的变化。
- [x] 未映射的新变化标记为 `UNMAPPED_CHANGE`，不会导致整个新版本被称为不支持。
- [x] Scenario Harness 验证在线刷新、快照回退、拒绝披露和错误交集四种路径。

## Implementation notes (Ticket 04)

- Evidence + impact cores: `src/evidence/` (disclosure, refresh, snapshot, allowlist, quarantine) and `src/impact/` (assess, card, graph, matchers, local-surface).
- Public seams: `changeguard impact [--disclose-approved|--disclose-refused]` and MCP `changeguard_impact`.
- Production CLI/MCP never inject a live network transport; refused / not_requested / approved-without-transport use the bundled official-evidence snapshot with `transport_calls: 0`.
- Graph edges come only from registered deterministic matchers; model payloads cannot add or escalate edges.
- Harness: `tests/ticket04-evidence-impact.test.ts` (disclosure, refuse/snapshot, online fake refresh, transport failure stale fallback, intersection / unmapped).

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated commit `c20ddc5c3b36b373e3b2c5791aa1db2678a45a8e` (integrated on top of Ticket 03 as `c20ddc5`).
- Root integrated verification and Wave 2 combined review (`NO_P0_P1`): see [HANDOFF.md](../../../HANDOFF.md) § Wave 2 closeout.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets 10–17.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized.
