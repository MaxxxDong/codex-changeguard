# 15 — 提供 Linux、WSL 与企业受管环境路径

**What to build:** Linux、WSL 和企业受管环境用户可以获得与能力边界相符的诊断、有限恢复或 IT Handoff，不会因为平台未知或策略阻塞而收到越权修复建议。

**Blocked by:** 03 — 识别多实例与版本变化; 07 — 完成配置与启动故障包; 10 — 生成低噪声上游反馈草稿.

**Status:** ready-for-agent

- [ ] Linux 与 WSL 适配器提供 CLI 实例、配置、日志和用户拥有缓存的只读发现。
- [ ] 未验证的平台能力明确标记 Read-only 或 Limited，写操作默认禁用。
- [ ] 受管策略来源被识别和展示，但不尝试覆盖、绕过或提权。
- [ ] 管理员动作产生 `ADMIN_ACTION_REQUIRED` 和 IT Handoff，包含最小证据、建议动作、风险、回滚与官方参考。
- [ ] 网络、代理、证书、SSO 和防火墙只执行非破坏性比较与诊断。
- [ ] Scenario Harness 覆盖未知适配器、WSL/Windows 实例并存、受管策略和管理员阻塞。
