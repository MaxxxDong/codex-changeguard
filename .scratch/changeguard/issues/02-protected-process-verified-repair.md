# 02 — 打通受保护 process 故障的验证修复

**What to build:** 用户可以在隔离环境中复现受保护 `process` 属性故障，查看完整 Repair Capsule，授权一次实验性修复，并通过原始故障复测和回滚证明获得可信的 `RESOLVED_VERIFIED` 结果。

**Blocked by:** 01 — 建立只读诊断主链.

**Status:** ready-for-agent

- [ ] 正向 Fixture 稳定复现受保护属性异常，并证明故障发生在 Browser 发现或握手之前。
- [ ] 相似但机制不同的负向 Fixture 不会获得同一修复建议。
- [ ] Repair Capsule 显示目标实例、哈希、精确匹配数、变更、风险、备份、验证和回滚。
- [ ] 只有范围一致的显式授权可以触发原子修复，任何前置条件变化都会使授权失效。
- [ ] 原始故障不再复现且核心健康检查通过后，结果才可为 `RESOLVED_VERIFIED`。
- [ ] 人为制造验证失败时自动回滚；显式回滚后目标哈希与原始状态一致。
- [ ] Scenario Harness 同时验证成功修复、拒绝错误候选和失败自动回滚三条路径。
