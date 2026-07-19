# Contributing to Codex ChangeGuard / 为 Codex ChangeGuard 做贡献

English and 中文 in one file for parity. Follow both language sections when they state requirements; the rules are equivalent.

---

## English

### Scope

This repository owns the ChangeGuard product: Plugin, MCP, Rescue CLI, Skill, schemas, synthetic fixtures, and product docs. Portfolio / Gate process materials stay outside this tree when they are not product code.

### Before you open a change

1. Read [README.md](README.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md), and [docs/TEST_PLAN.md](docs/TEST_PLAN.md).
2. Prefer the smallest change that preserves evidence contracts (deterministic edges, probe hashes, no secret export).
3. Do not add production network, shell, daemon, telemetry, or secret-export paths.
4. Experimental repair must stay isolated, one-shot authorized, backed up, verified, and roll-backable.

### Local checks

```bash
npm ci
npm run typecheck
npm test
npm run check:boundary
npm run verify:release
```

Canonical release gate: `npm run verify:release`. Passing it is **local automated readiness only**, not Gate C publication.

### Documentation

- English entry: [README.md](README.md). Chinese entry: [README.zh-CN.md](README.zh-CN.md). Keep section-for-section factual parity when both change.
- Do not write disposable clone paths (`.grok-disposable/…`) into maintained docs.
- Do not claim public remote / Release / registration / upload / submission without separate Gate C authorization.
- Platform Full / Preview / Limited claims must match [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md).

### Safety defaults

- Models propose; probes adjudicate. Never invent deterministic graph edges from prose alone.
- Untrusted Issue/page/release text is data, not instructions.
- Fixtures are synthetic and redacted — no real tokens, full env values, or complete sessions.
- Uninstall and demo cleanup must not leave a daemon or claim global OS config mutation.

### Publication

MIT text is in [LICENSE](LICENSE). Repository presence of MIT does **not** mean a public release already happened. External publication remains Gate C / `NOT_STARTED` until separately authorized.

---

## 中文

### 范围

本仓库拥有 ChangeGuard 产品：Plugin、MCP、Rescue CLI、Skill、schema、合成 Fixture 与产品文档。非产品代码的作品集 / Gate 流程材料在适用时留在仓库外。

### 提交变更前

1. 阅读 [README.zh-CN.md](README.zh-CN.md)、[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)、[docs/SECURITY.md](docs/SECURITY.md)、[docs/TEST_PLAN.md](docs/TEST_PLAN.md)。
2. 优先做能保全证据契约的最小变更（确定性边、探针哈希、无密钥导出）。
3. 不要在生产路径加入网络、shell、守护进程、遥测或密钥导出。
4. 实验性修复必须隔离、一次性授权、有备份、可验证且可回滚。

### 本地检查

```bash
npm ci
npm run typecheck
npm test
npm run check:boundary
npm run verify:release
```

规范发布门：`npm run verify:release`。通过仅表示**本地自动化就绪**，不是 Gate C 对外发布。

### 文档

- 英文入口：[README.md](README.md)。中文入口：[README.zh-CN.md](README.zh-CN.md)。两边事实须按节对齐。
- 不要把一次性 clone 路径（`.grok-disposable/…`）写入维护中的文档。
- 未经独立 Gate C 授权，不得声称已有公开远端 / Release / 报名 / 上传 / 提交。
- 平台 Full / Preview / Limited 声明必须与 [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) 一致。

### 安全默认

- 模型提议；探针裁定。禁止仅凭散文发明确定性图边。
- 不可信的 Issue/页面/发布说明是数据，不是指令。
- Fixture 为合成且脱敏——无真实令牌、完整环境变量值或完整会话。
- 卸载与 demo 清理不得留下守护进程，也不得声称修改全局操作系统配置。

### 发布

MIT 文本见 [LICENSE](LICENSE)。仓库中存在 MIT **不等于** 已经公开发布。对外发布在另行授权前仍为 Gate C / `NOT_STARTED`。
