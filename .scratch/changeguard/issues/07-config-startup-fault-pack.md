# 07 — 完成配置与启动故障包

**What to build:** 用户可以定位无效配置、配置 Schema 漂移和启动失败，获得范围受限、可回滚且经过启动验证的修复，而 ChangeGuard 不读取或修改普通项目代码。

**Blocked by:** 02 — 打通受保护 process 故障的验证修复; 03 — 识别多实例与版本变化.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets 11–17 are not complete. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred.

Exact operational evidence (Root integrated verification, Wave 3 final review, residual boundaries) is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 无效 TOML、错误字段类型、过期键和配置来源冲突产生不同的 Incident Fingerprint。
- [x] 只读取与故障相关的 Codex 控制文件；项目源代码、数据和 Git 历史保持未访问。
- [x] 修复使用受限配置动作，并显示精确目标、旧值摘要、新值、备份和回滚。
- [x] 启动验证覆盖原始失败、基本命令和配置重新加载，任一失败都会自动回滚。
- [x] 受管策略或需要管理员权限的配置返回 `ADMIN_ACTION_REQUIRED`，不提供绕过操作。
- [x] Scenario Harness 覆盖有效修复、错误候选、受管策略和验证失败四条路径。

## Implementation notes (Ticket 07)

- Config fault core: `src/core/config/` (bounded TOML parse/validate, fault probe, redaction).
- Recovery reuses Ticket 02 engine with registered `config_set` / `config_remove` only on isolated control roots.
- Public seams: diagnose + `repair-preview` / `repair-apply` / `verify` / `rollback` (same CLI/MCP recovery tools).
- Managed policy → `ADMIN_ACTION_REQUIRED` + IT handoff; no privilege-elevation guidance.
- Harness: `tests/ticket07-config-startup.test.ts`.

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec` (integrated as `42bbf5c`).
- Root integrated verification (dynamic) and Wave 3 final independent review (`changeguard-wave3-final-review-r2`, `NO_P0_P1`, static): see [HANDOFF.md](../../../HANDOFF.md) § Wave 3 closeout.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets 11–17.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized.
