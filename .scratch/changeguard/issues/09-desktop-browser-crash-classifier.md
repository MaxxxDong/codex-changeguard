# 09 — 完成 Desktop Browser 崩溃分类器

**What to build:** 用户面对相似的 Codex Desktop Browser 崩溃时，可以得到按平台、组件、失败阶段和结构签名区分的候选结果；缺乏适用证据时产品会拒绝危险补丁。

**Blocked by:** 01 — 建立只读诊断主链; 03 — 识别多实例与版本变化; 04 — 提供官方证据刷新与更新影响卡.

**Status:** ready-for-agent

- [ ] 不同 Windows 崩溃家族按异常码、栈符号、GPU 退出码、交互阶段和组件分开建模。
- [ ] 兼容 Fixture 的正确 Issue 候选进入 Top 3，不兼容平台或机制被硬门排除。
- [ ] 标题或“点击后崩溃”等症状相似性不能单独产生高置信度根因。
- [ ] 无安全隔离时只使用已有日志和崩溃元数据，不主动崩溃用户主实例。
- [ ] 没有可验证修复时返回 `UPSTREAM_BLOCKED` 或 `INCONCLUSIVE`，并生成可行动的下一步证据要求。
- [ ] Scenario Harness 包含多个相似症状负向控制，并证明错误修复永不进入授权阶段。
