# 12 — 完成维护者跟进与官方修复闭环

**What to build:** 用户订阅的事件收到维护者追问、重复判定或候选修复后，ChangeGuard 可以协助补充最小证据、验证新版本并结束临时补丁生命周期，但不会自动回复或对抗上游决定。

**Blocked by:** 06 — 建立 KNOWN_GOOD 与回滚生命周期; 11 — 执行经确认的 GitHub 上游操作.

**Status:** `LOCAL_COMPLETE` (locally verified on clean commit `6083c6f3ce75acddd982c151e5c6831a79ad7b2c`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets **16, 17** remain open. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication, upload, or real external GitHub write has occurred. Follow-up capsules and reply drafts stay `preview_only` / `local_only` / `external_write: false`; Ticket 11 confirmation remains required before any separately confirmed external action (production adapter still unavailable by default).

Exact operational evidence (Root integrated verification dynamic, Ticket 12 final independent static reviews) is canonical in [HANDOFF.md](../../../HANDOFF.md) § Ticket 12 closeout.

- [x] 仅检查用户明确订阅的事件，且通过 SessionStart 或手动操作低频刷新，不运行后台守护进程。
- [x] 维护者请求被转换为新的范围受限证据 Capsule，并只运行直接相关的安全检查。
- [x] 补充材料完成隐私扫描并生成回复草稿，未经用户确认不发布。
- [x] duplicate、needs-info、cannot-reproduce、by-design、not-planned 和 closed 状态按既定策略处理，不自动重开或跨贴。
- [x] 候选修复版本在隔离环境复现原始问题和核心回归，再生成升级建议。
- [x] 官方修复通过后，临时方案标记为 `SUPERSEDED_BY_UPSTREAM_FIX` 并停止推荐。
- [x] Scenario Harness 验证追问、无新证据、重复迁移、修复成功和修复回归路径。

## Implementation notes (Ticket 12)

- Core: `src/upstream/followup/` (subscribe/status/session_hint/refresh/process_event/validate_candidate; fail-closed ledger; measured candidate supersession).
- Public seams: `changeguard followup <operation> <target>` and MCP `changeguard_followup`.
- Capsule / draft invariants: `preview_only`, `local_only`, `external_write: false`, `requires_ticket11_confirmation: true`; never auto-comment / auto-reopen / cross-post; production never opens network or installs binaries.
- Packaged SessionStart: path-free refresh-due hint only when trusted hook + active subscription is due; unsubscribed / not-due / untrusted / corrupt state stay silent.
- Harness: `tests/ticket12-followup-core.test.ts`, `tests/ticket12-followup-harness.test.ts`.

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on clean commit `6083c6f3ce75acddd982c151e5c6831a79ad7b2c` (`fix: close Ticket 12 public wire authority seams`).
- Final independent static reviews (Root-recorded): `changeguard-ticket12-final-spec-review-r5` → `NO_P0_P1`, `ACCEPT`; `changeguard-ticket12-final-security-review-r5` → no P0/P1, `ACCEPT`.
- Root dynamic verification on clean `6083c6f` (authoritative): typecheck/build; Ticket 06+12 targeted **99/99**; production boundary + boundary self-test **175/175**; package + package-smoke + diff; Ticket 13 rerun **35/35** after one explicitly recorded transient; full regression **474/474**. See [HANDOFF.md](../../../HANDOFF.md).
- Product-wide status remains `IN_PROGRESS`; this ticket does **not** complete Tickets 16–17, registration, Gate C, or authorize real external GitHub writes.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized; publication / upload / real GitHub writes unauthorized / `NOT_STARTED`.
