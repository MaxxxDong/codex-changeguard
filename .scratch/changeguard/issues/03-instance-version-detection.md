# 03 — 识别多实例与版本变化

**What to build:** 用户可以看到实际运行的 Codex 实例、安装来源、Profile 和版本变化，不会因为 PATH、Desktop 内置 CLI 或多份缓存并存而修错对象。

**Blocked by:** 01 — 建立只读诊断主链.

**Status:** ready-for-agent

- [ ] 枚举 Desktop 内置、PATH、受支持包管理器、Windows MSIX 和 WSL 实例时保持独立身份与路径哈希。
- [ ] 能从进程、日志或启动上下文确定实际故障实例，不把最高版本自动视为故障实例。
- [ ] 首次安装、升级、降级和路径优先级漂移产生不同且准确的结果。
- [ ] SessionStart 仅在版本指纹变化时执行不超过十秒的只读健康检查；无变化时保持安静。
- [ ] Hook 未受信任、跳过或失败时明确显示状态，并保留等价的手动扫描入口。
- [ ] Repair Capsule 永远只绑定一个已观察实例，不向其他实例广播。
- [ ] Scenario Harness 覆盖首次基线、多实例升级、降级和 PATH 漂移。
