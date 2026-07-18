# 05 — 安全分析用户提供的网页

**What to build:** 用户可以把任意公开或已登录可见的问题页面交给 ChangeGuard，获得与本机证据对照后的适用性分析，而页面中的命令、提示注入和未经证实的结论不能直接影响本机。

**Blocked by:** 01 — 建立只读诊断主链; 04 — 提供官方证据刷新与更新影响卡.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`)

Broader ChangeGuard product remains `IN_PROGRESS`. At Ticket 05 local closeout, Tickets 11–17 were still open. Wave 4 later closed local/framework status for 11/13/14/15 (see [HANDOFF.md](../../../HANDOFF.md) § Wave 4). Current open product tickets are **12, 16, 17**; Ticket 14 platform Full and Ticket 15 real-host remain platform gaps. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred.

Exact operational evidence (Root integrated verification, Wave 3 final review, residual boundaries) is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 提取症状、平台、版本、错误、操作、证据来源和作者结论，并把事实与推断分开。
- [x] 页面中的代理指令、提示注入和要求泄漏数据的内容被隔离为不可信文本。
- [x] 页面命令只能转换为待验证的 Repair DSL 候选，不能直接执行。
- [x] 读取已登录页面时不采集 Cookie、Storage、令牌或完整浏览器请求内容。
- [x] 输出明确包含适用性、缺失证据、反证、风险、隔离测试和可否进入 Repair Capsule。
- [x] 泛化 ChatGPT 会话问题不会被错误映射为 Codex 组件缺陷。
- [x] Scenario Harness 覆盖有效候选、错误平台、提示注入、无证据断言和登录页面边界。

## Implementation notes (Ticket 05)

- Page analysis core: `src/page/` (`analyze.ts`, `envelope.ts`, `extract.ts`, `compare.ts`, `dsl-candidates.ts`, disclosure/transport).
- Public seams: `changeguard analyze-page <target> --envelope=<page.json> [--disclose-…]` and MCP `changeguard_analyze_page`.
- Orchestrator-supplied page envelopes only in production; optional transport requires explicit disclosure injection and is never auto-wired.
- Page text is untrusted data; Repair DSL is always `candidate_only` with `repair_authorized: false`.
- Harness: `tests/ticket05-page-analysis.test.ts`.

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec` (integrated as `607be8f`).
- Root integrated verification (dynamic) and Wave 3 final independent review (`changeguard-wave3-final-review-r2`, `NO_P0_P1`, static): see [HANDOFF.md](../../../HANDOFF.md) § Wave 3 closeout.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets **12, 16, 17**. Wave 4 local/framework closeout for 11/13/14/15 is recorded in [HANDOFF.md](../../../HANDOFF.md) § Wave 4 (T14 Full and T15 real-host remain platform gaps).
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized.
