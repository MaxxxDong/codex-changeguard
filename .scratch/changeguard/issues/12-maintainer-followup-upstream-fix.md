# 12 — 完成维护者跟进与官方修复闭环

**What to build:** 用户订阅的事件收到维护者追问、重复判定或候选修复后，ChangeGuard 可以协助补充最小证据、验证新版本并结束临时补丁生命周期，但不会自动回复或对抗上游决定。

**Blocked by:** 06 — 建立 KNOWN_GOOD 与回滚生命周期; 11 — 执行经确认的 GitHub 上游操作.

**Status:** ready-for-agent

- [ ] 仅检查用户明确订阅的事件，且通过 SessionStart 或手动操作低频刷新，不运行后台守护进程。
- [ ] 维护者请求被转换为新的范围受限证据 Capsule，并只运行直接相关的安全检查。
- [ ] 补充材料完成隐私扫描并生成回复草稿，未经用户确认不发布。
- [ ] duplicate、needs-info、cannot-reproduce、by-design、not-planned 和 closed 状态按既定策略处理，不自动重开或跨贴。
- [ ] 候选修复版本在隔离环境复现原始问题和核心回归，再生成升级建议。
- [ ] 官方修复通过后，临时方案标记为 `SUPERSEDED_BY_UPSTREAM_FIX` 并停止推荐。
- [ ] Scenario Harness 验证追问、无新证据、重复迁移、修复成功和修复回归路径。
