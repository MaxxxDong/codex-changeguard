# 11 — 执行经确认的 GitHub 上游操作

**What to build:** 用户可以逐次预览并确认新建 Issue、补充实质评论、点赞或订阅，ChangeGuard 使用现有认证会话安全执行并提供不可混同于本地修复的上游回执。

**Blocked by:** 10 — 生成低噪声上游反馈草稿.

**Status:** `LOCAL_COMPLETE` (local confirmation/action engine on integrated clean main `407789ca847b984dbd935e26edf8ad58ad0cf688`)

Broader ChangeGuard product remains `IN_PROGRESS`. **Local capability only:** production/default adapter remains `ADAPTER_UNAVAILABLE`; no real `gh`/browser adapter, no authenticated external session, and no real external GitHub write was exercised or authorized. Ticket 11 does **not** complete Tickets 12/16/17 or authorize Gate C. Registration, publication, upload, external submission, and real external GitHub writes remain `NOT_STARTED` / unauthorized.

Exact operational evidence is canonical in [HANDOFF.md](../../../HANDOFF.md) § Wave 4 closeout.

- [ ] 只使用已经认证的 `gh` 或可见浏览器会话，不索取、保存或显示访问令牌。
  - **Boundary (open for real adapter):** production injects no real adapter (`auth=unavailable` → `ADAPTER_UNAVAILABLE`). Capability kinds are only `gh_authenticated` | `visible_browser_authenticated` | `unavailable`; tokens/cookies/sessions are never requested, stored, or displayed. Real authenticated `gh`/browser execution was **not** run.
- [x] 新建、评论、点赞、订阅和附件上传分别展示目标、正文、附件与隐私检查结果，并分别确认。（CLI/MCP `upstream-action-preview` / `upstream-action-confirm`）
- [x] 用户取消或认证不可用时保持纯草稿状态，不产生模拟成功结果。
- [x] canonical target、Incident Fingerprint 和 Evidence Delta hash 共同保证一次诊断只产生一次同类动作。
- [x] 超时或响应不明确时先查询远端状态；无法确认时停止而不是重试制造重复。（可控假远端：`UNCERTAIN_NO_RETRY` / durable ledger）
- [x] 成功操作生成独立 Upstream Contribution Receipt，只记录必要 URL、动作和时间。（假远端成功路径；非真实 GitHub 回执）
- [x] Scenario Harness 使用可控远端替身验证成功、取消、认证失败、超时和已存在动作。

## Implementation notes (Ticket 11)

- Core: `src/upstream/actions/` (`previewUpstreamAction`, `confirmUpstreamAction`).
- Public seams: `upstream-action-preview` / `upstream-action-confirm` (CLI + MCP).
- Production default: null adapter → `ADAPTER_UNAVAILABLE`; never simulates success or opens real network.
- Controlled fake remote: cancellation / auth unavailable / timeout / duplicate / ledger / concurrency / privacy gates verified in harness.
- Confirmation tokens use install-local HMAC (not a GitHub/API token); durable one-shot ledger; cancel/success/uncertain terminate nonce.

## Local completion closeout

- Local status: `LOCAL_COMPLETE` for the confirmation/action engine on `407789c` with the production-adapter boundary above.
- Platform / product: does **not** claim real external submission, Gate C, or whole-product completion.
- Remaining open product tickets: 12, 16, 17 (and Ticket 14 Full / Ticket 15 real-host remain platform gaps, not Ticket 11 scope).
