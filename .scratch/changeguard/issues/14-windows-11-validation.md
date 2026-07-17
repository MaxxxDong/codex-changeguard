# 14 — 完成 Windows 11 适配与真实验证

**What to build:** Windows 11 用户可以获得针对 MSIX、Desktop Browser、CLI、缓存和崩溃元数据的安全诊断与恢复；只有真实机器完整回归通过后，平台状态才从 Preview 升级为 Full。

**Blocked by:** 06 — 建立 KNOWN_GOOD 与回滚生命周期; 08 — 完成 Plugin 缓存与版本偏移故障包; 09 — 完成 Desktop Browser 崩溃分类器; 10 — 生成低噪声上游反馈草稿.

**Status:** ready-for-agent

- [ ] Windows 适配器区分 MSIX、Desktop 内置 CLI、PATH CLI、WSL 和不同用户 Profile。
- [ ] 只读取允许的崩溃元数据与日志窗口，不修改 WindowsApps、Program Files、注册表策略或系统安全设置。
- [ ] Browser 崩溃家族在真实 Windows 11 环境保持可区分，错误候选无法进入修复授权。
- [ ] 用户拥有的缓存或控制文件支持备份、原子变更、验证和实际回滚。
- [ ] 无管理员权限可完成受支持路径；管理员或受管策略要求转为明确的 IT Handoff。
- [ ] Full 状态必须由真实机器 Scenario Harness 回执支持；缺少任何关键路径时保持 Preview 并列出缺口。
