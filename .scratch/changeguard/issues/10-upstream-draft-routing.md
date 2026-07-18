# 10 — 生成低噪声上游反馈草稿

**What to build:** 用户可以从未解决或已本地解决但可复现的 Codex 缺陷生成正确路由、去重、脱敏且对维护者有新增价值的反馈草稿，整个过程不执行外部写入。

**Blocked by:** 04 — 提供官方证据刷新与更新影响卡; 05 — 安全分析用户提供的网页; 09 — 完成 Desktop Browser 崩溃分类器.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `3265acd11fa260d4e2c857705a73bd36b7b002b6`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets 11–17 are not complete. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred. Real external GitHub writes remain unauthorized / `NOT_STARTED`. Ticket 11 is still required for any separately confirmed external write.

Exact operational evidence (Root integrated verification dynamic, Ticket 10 final independent static review, residual preview-only boundaries) is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 在 Issue、Discussions、Bugcrowd 和 OpenAI Support 之间先完成渠道路由。
- [x] Issue 表面进一步映射到当前 App、CLI、Extension 或 Other Bug 表单。
- [x] 重复判断区分 `EXACT_DUPLICATE`、`RELATED_NOT_SAME` 和 `NEW_INCIDENT`。
- [x] 完全重复且没有 Evidence Delta 时只建议点赞或订阅，不生成低价值评论。
- [x] 草稿通过维护者价值门，分离事实、用户报告和假设，并保持技术错误与命令原文。
- [x] 支持时收集并脱敏 `codex doctor --json`；官方表单变化时动态映射，离线快照标记过期。
- [x] 输出 Upstream Submission Capsule，但没有用户确认和外部写入能力。

## Implementation notes (Ticket 10)

- Upstream preview core: `src/upstream/` (`preview.ts`, routing, duplicate, maintainer-gate, doctor, form-snapshot, request, transport, limits).
- Public seams: `changeguard upstream-preview <target> --request=<request.json> [--disclose-…]` and MCP `changeguard_upstream_preview`.
- Capsule invariants: `mode: preview_only`, `locality: local_only`, `external_write: false`, `repair_authorized: false`, `requires_ticket11_confirmation: true`; never `SUBMITTED` / `POSTED`.
- Bundled immutable official form snapshot: `fixtures/upstream/form-snapshot-2026-07-18.json` (`snapshot_id` `official_issue_forms_2026-07-18`, `fetched_at` `2026-07-18T00:00:00.000Z`, main commit `3a067484584861606ad842de5bc4ac735a865ddf`, per-form git `blob_sha` provenance).
- Production CLI/MCP inject null transport (`transport_calls: 0`); optional form refresh requires disclosure approved **and** injected official-only transport.
- Harness: `tests/ticket10-upstream-preview.test.ts`; packaged smoke covers PREVIEW_READY exit 0 / PREVIEW_BLOCKED nonzero / no network.

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated clean HEAD `3265acd11fa260d4e2c857705a73bd36b7b002b6`.
- Integration commits: `0829936` (feat), `7ef87e6` (preview gates), `26d58b4` (ready-state invariant), `3265acd` (consumer gaps / verification tip).
- Root integrated verification (dynamic) and final independent static review (`changeguard-ticket10-regression-review-r7`, `NO_P0_P1`, empty patch): see [HANDOFF.md](../../../HANDOFF.md) § Ticket 10 closeout. Do not collapse Root dynamic proof into Grok static review; this docs closeout does not claim Grok-run dynamic tests.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets 11–17 or authorize any real external write.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized; publication / upload / real GitHub writes unauthorized / `NOT_STARTED`.
