# 08 — 完成 Plugin 缓存与版本偏移故障包

**What to build:** 用户可以区分 bundled Plugin 文件损坏、共享缓存陈旧、依赖版本偏移和 reconciliation 重新覆盖，安全恢复一致状态并证明问题不会在下一次启动立即复发。

**Blocked by:** 02 — 打通受保护 process 故障的验证修复; 03 — 识别多实例与版本变化.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets 11–17 are not complete. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred.

Exact operational evidence (Root integrated verification, Wave 3 final review, residual boundaries) is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 本地清单比较能区分损坏、陈旧缓存、版本偏移和 reconciliation 覆盖四类机制。
- [x] 诊断记录安装实例、缓存身份、组件哈希和重建来源，而不把共享缓存错误泛化为依赖安装失败。
- [x] 修复只允许精确替换、已验证资源复制或重命名隔离，不递归删除缓存或修改签名应用二进制。
- [x] 修复后跨越一次 reconciliation 和重新启动验证；复发时不得返回 `RESOLVED_VERIFIED`。
- [x] 备份和显式回滚能够恢复原始缓存与清单状态。
- [x] Scenario Harness 覆盖四种机制、相似负向 Fixture、复发和回滚。

## Implementation notes (Ticket 08)

- Plugin-cache core: `src/core/plugin-cache/` (inventory/manifest observation and exclusive mechanism classification).
- Recovery reuses Ticket 02 authorization with verified resource copy / atomic replace / rename-to-quarantine only.
- Public seams: diagnose + `repair-preview` / `repair-apply` / `verify` / `rollback` on isolated `fixtures/plugin-cache/*` targets.
- Immediate post-reconciliation recurrence cannot claim `RESOLVED_VERIFIED`.
- Harness: `tests/ticket08-plugin-cache-harness.test.ts`.

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec` (integrated as `5b0b608`).
- Root integrated verification (dynamic) and Wave 3 final independent review (`changeguard-wave3-final-review-r2`, `NO_P0_P1`, static): see [HANDOFF.md](../../../HANDOFF.md) § Wave 3 closeout.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets 11–17.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized.
