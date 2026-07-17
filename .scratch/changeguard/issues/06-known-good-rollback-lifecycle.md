# 06 — 建立 KNOWN_GOOD 与回滚生命周期

**What to build:** 用户在更新引入回归时可以识别上一个健康检查点、回滚单一实例、继续跟踪官方修复，并在新版本隔离验证通过后安全升级。

**Blocked by:** 02 — 打通受保护 process 故障的验证修复; 03 — 识别多实例与版本变化.

**Status:** ready-for-agent

- [ ] 普通修复备份至少保留七天并跨越三次成功启动，最后三个健康控制面检查点保留为 `KNOWN_GOOD`。
- [ ] 更新回归结论由受控 A/B 证据建立，而不是仅根据更新时间推断。
- [ ] 配置、Plugin、Skill、MCP、Hook 和缓存使用 ChangeGuard 自有备份回滚，且仅影响目标实例。
- [ ] CLI 版本回滚只通过官方安装来源和显式版本固定；ChangeGuard 不保存或分发 OpenAI 二进制。
- [ ] 回滚成功返回 `MITIGATED_VERIFIED_BY_ROLLBACK`，不会宣称根因已修复。
- [ ] 新版本可在隔离环境执行原始故障与核心回归 canary，并输出准确的升级建议状态。
- [ ] 官方修复验证通过后，旧临时方案被标记为 `SUPERSEDED_BY_UPSTREAM_FIX`。
