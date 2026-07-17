# 01 — 建立只读诊断主链

**What to build:** 用户可以从 ChangeGuard Plugin 或 Rescue CLI 对隔离 Fixture 发起同一条只读诊断流程，并获得结构化 Incident Fingerprint、明确的诊断状态以及相互独立的用户解决结果和上游贡献结果。

**Blocked by:** None — can start immediately.

**Status:** implemented

- [x] Plugin、MCP 和 Rescue CLI 通过同一套共享核心处理诊断，不存在重复判断逻辑。
- [x] 对受支持 Fixture 执行公开诊断入口时，输出满足契约的 Incident Fingerprint 和双结果回执。
- [x] 证据不足时返回 `INCONCLUSIVE`，且不把症状相似性描述为根因。
- [x] 默认流程不访问外部网络、不修改本地目标，也不读取普通项目源代码或无关用户数据。
- [x] 发布产物为可直接运行的自包含 JavaScript，不在运行时安装依赖。
- [x] Scenario Harness 从公开入口验证最终状态、回执和零目标文件变更。

## Implementation notes (Ticket 01)

- Shared core: `src/core/diagnose.ts` (named candidates only; fail-closed no-follow for target and all candidate segments; `O_NOFOLLOW` + fstat; byte limits).
- Public seams: `bin/changeguard.js` → `dist/cli/main.js` (`changeguard diagnose <target>`); MCP tool `changeguard_diagnose` via `dist/mcp/server.js` with bounded NDJSON frames.
- Skill orchestrates the same CLI/MCP contracts (`skills/changeguard/SKILL.md`).
- Positive fixture may reach `SOURCE_COMPONENT_LOCATED` only from independently measured artifact hash + structural shim signature (exactly one real block); surface/error/phase are applicability gates.
- Negative control remains `INCONCLUSIVE` with separate user/upstream receipts.
- Package: `npm run package` / `npm run package:smoke`; boundary: `npm run check:boundary`.
- Never claims `RESOLVED_VERIFIED`, applies a repair, submits an Issue, uses the network, or mutates the target.
