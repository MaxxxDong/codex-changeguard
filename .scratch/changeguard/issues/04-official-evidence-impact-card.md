# 04 — 提供官方证据刷新与更新影响卡

**What to build:** 用户在批准最小披露清单后，可以看到与本机 Codex 表面真正相交的官方版本变化、证据来源和过期状态，而不是一份泛化更新摘要。

**Blocked by:** 01 — 建立只读诊断主链.

**Status:** ready-for-agent

- [ ] 外部刷新前显示准确的 disclosure manifest，拒绝授权时仍可使用本地快照诊断。
- [ ] 证据优先从官方文档、Release、Tag、Diff、Issue、PR 和 Commit 获取，并记录来源、抓取时间、版本、状态与哈希。
- [ ] 无网络或官方源不可用时使用带时间戳的固定快照，并明确标记过期风险。
- [ ] Change-to-Local Graph 仅由确定性规则添加边，模型无法修改来源或提升证据等级。
- [ ] 更新影响卡只展示与当前实例、配置、Plugin、Skill、MCP、Hook 或运行时表面存在证据交集的变化。
- [ ] 未映射的新变化标记为 `UNMAPPED_CHANGE`，不会导致整个新版本被称为不支持。
- [ ] Scenario Harness 验证在线刷新、快照回退、拒绝披露和错误交集四种路径。
