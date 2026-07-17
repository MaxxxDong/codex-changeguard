# 08 — 完成 Plugin 缓存与版本偏移故障包

**What to build:** 用户可以区分 bundled Plugin 文件损坏、共享缓存陈旧、依赖版本偏移和 reconciliation 重新覆盖，安全恢复一致状态并证明问题不会在下一次启动立即复发。

**Blocked by:** 02 — 打通受保护 process 故障的验证修复; 03 — 识别多实例与版本变化.

**Status:** ready-for-agent

- [ ] 本地清单比较能区分损坏、陈旧缓存、版本偏移和 reconciliation 覆盖四类机制。
- [ ] 诊断记录安装实例、缓存身份、组件哈希和重建来源，而不把共享缓存错误泛化为依赖安装失败。
- [ ] 修复只允许精确替换、已验证资源复制或重命名隔离，不递归删除缓存或修改签名应用二进制。
- [ ] 修复后跨越一次 reconciliation 和重新启动验证；复发时不得返回 `RESOLVED_VERIFIED`。
- [ ] 备份和显式回滚能够恢复原始缓存与清单状态。
- [ ] Scenario Harness 覆盖四种机制、相似负向 Fixture、复发和回滚。
