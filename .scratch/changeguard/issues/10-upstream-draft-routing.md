# 10 — 生成低噪声上游反馈草稿

**What to build:** 用户可以从未解决或已本地解决但可复现的 Codex 缺陷生成正确路由、去重、脱敏且对维护者有新增价值的反馈草稿，整个过程不执行外部写入。

**Blocked by:** 04 — 提供官方证据刷新与更新影响卡; 05 — 安全分析用户提供的网页; 09 — 完成 Desktop Browser 崩溃分类器.

**Status:** ready-for-agent

- [ ] 在 Issue、Discussions、Bugcrowd 和 OpenAI Support 之间先完成渠道路由。
- [ ] Issue 表面进一步映射到当前 App、CLI、Extension 或 Other Bug 表单。
- [ ] 重复判断区分 `EXACT_DUPLICATE`、`RELATED_NOT_SAME` 和 `NEW_INCIDENT`。
- [ ] 完全重复且没有 Evidence Delta 时只建议点赞或订阅，不生成低价值评论。
- [ ] 草稿通过维护者价值门，分离事实、用户报告和假设，并保持技术错误与命令原文。
- [ ] 支持时收集并脱敏 `codex doctor --json`；官方表单变化时动态映射，离线快照标记过期。
- [ ] 输出 Upstream Submission Capsule，但没有用户确认和外部写入能力。
