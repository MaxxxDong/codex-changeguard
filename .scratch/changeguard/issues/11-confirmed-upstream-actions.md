# 11 — 执行经确认的 GitHub 上游操作

**What to build:** 用户可以逐次预览并确认新建 Issue、补充实质评论、点赞或订阅，ChangeGuard 使用现有认证会话安全执行并提供不可混同于本地修复的上游回执。

**Blocked by:** 10 — 生成低噪声上游反馈草稿.

**Status:** ready-for-agent

- [ ] 只使用已经认证的 `gh` 或可见浏览器会话，不索取、保存或显示访问令牌。
- [ ] 新建、评论、点赞、订阅和附件上传分别展示目标、正文、附件与隐私检查结果，并分别确认。
- [ ] 用户取消或认证不可用时保持纯草稿状态，不产生模拟成功结果。
- [ ] canonical target、Incident Fingerprint 和 Evidence Delta hash 共同保证一次诊断只产生一次同类动作。
- [ ] 超时或响应不明确时先查询远端状态；无法确认时停止而不是重试制造重复。
- [ ] 成功操作生成独立 Upstream Contribution Receipt，只记录必要 URL、动作和时间。
- [ ] Scenario Harness 使用可控远端替身验证成功、取消、认证失败、超时和已存在动作。
