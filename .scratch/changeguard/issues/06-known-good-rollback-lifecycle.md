# 06 — 建立 KNOWN_GOOD 与回滚生命周期

**What to build:** 用户在更新引入回归时可以识别上一个健康检查点、回滚单一实例、继续跟踪官方修复，并在新版本隔离验证通过后安全升级。

**Blocked by:** 02 — 打通受保护 process 故障的验证修复; 03 — 识别多实例与版本变化.

**Status:** `LOCAL_COMPLETE` (locally verified on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec`)

Broader ChangeGuard product remains `IN_PROGRESS`. Tickets 11–17 are not complete. Registration, external submission, and Gate C remain not authorized / `NOT_STARTED`. No public publication or upload has occurred.

Residual product boundaries remain truthful: CLI and Desktop **version** rollback seams are `preview_only` guidance (no OpenAI binary store/download/redistribution); Desktop remains `limited` without official signed history or lawful media; platform Full/Preview/Limited claims for real machines stay with Tickets 13–15. Exact operational evidence is canonical in [HANDOFF.md](../../../HANDOFF.md).

- [x] 普通修复备份至少保留七天并跨越三次成功启动，最后三个健康控制面检查点保留为 `KNOWN_GOOD`。
- [x] 更新回归结论由受控 A/B 证据建立，而不是仅根据更新时间推断。
- [x] 配置、Plugin、Skill、MCP、Hook 和缓存使用 ChangeGuard 自有备份回滚，且仅影响目标实例。
- [x] CLI 版本回滚只通过官方安装来源和显式版本固定；ChangeGuard 不保存或分发 OpenAI 二进制。
- [x] 回滚成功返回 `MITIGATED_VERIFIED_BY_ROLLBACK`，不会宣称根因已修复。
- [x] 新版本可在隔离环境执行原始故障与核心回归 canary，并输出准确的升级建议状态。
- [x] 官方修复验证通过后，旧临时方案被标记为 `SUPERSEDED_BY_UPSTREAM_FIX`。

## Implementation notes (Ticket 06)

- Lifecycle core: `src/core/lifecycle/` (`engine.ts`, `ledger.ts`, `dispatch.ts`, retention / A/B / surface rollback / canary / supersession).
- Public seams: `changeguard lifecycle <operation> <target>` and MCP `changeguard_lifecycle`.
- Exact-instance control-surface rollback can mutate isolated target state and return `MITIGATED_VERIFIED_BY_ROLLBACK`.
- CLI/Desktop **version** rollback remain registered **preview-only** operations (`mode: "preview_only"`); never store, download, or shell-install OpenAI binaries.
- Desktop version rollback is additionally `limited` when signed history / lawful media evidence is unavailable.
- Harness: `tests/ticket06-lifecycle.test.ts` (retention, KNOWN_GOOD, A/B, surface rollback, provenance fail-closed, canary enums, supersession, ledger integrity).

## Local completion closeout

- Local status: `LOCAL_COMPLETE` on integrated commit `5aa12c6c7370d9da84be3078c14fc63cf7e90fec` (integrated as `50117ca`; Wave 3 tip trust-gap fix `5aa12c6`).
- Root integrated verification (dynamic) and Wave 3 final independent review (`changeguard-wave3-final-review-r2`, `NO_P0_P1`, static): see [HANDOFF.md](../../../HANDOFF.md) § Wave 3 closeout.
- Product-wide status remains `IN_PROGRESS`; this ticket does not complete Tickets 11–17 or real-machine platform Full claims.
- Registration `NOT_STARTED`; external submission `NOT_STARTED`; Gate C not authorized.
