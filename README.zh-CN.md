# Codex ChangeGuard

面向 Codex 更新影响分析、故障定位与可回滚恢复规划的证据约束型插件。**非官方社区项目——不是 OpenAI 产品、官方支持渠道或认证。**

> 模型可以提出假设；确定性探针裁定事实。

| 语言 | 入口 |
| --- | --- |
| English | [README.md](README.md) — 默认包入口 |
| 中文 | 本文件（`README.zh-CN.md`）— 打包双语表面（与英文入口主题对等） |

## 1. 产品与免责声明

ChangeGuard 将官方 Codex 变更映射为经脱敏的本地事实，给出明确的证据等级，并在无法本地确认 Issue 时拒绝虚假精度。它不是通用变更日志摘要器、Issue 聊天机器人、环境医生，也不是自动社区补丁安装器。

ChangeGuard 独立于 OpenAI。名称、品牌与文档不得暗示官方归属或背书。

## 2. 五分钟评委路径（预构建包）

**打包评委路径（Ticket 17）：** 使用预构建插件包与 **Node.js >= 20**，评委可在无需构建本仓库、无需 GitHub 登录、无需提供 API Key 的情况下运行实机演示。默认路径**不需要**网络。

| 步骤 | 期望 |
| --- | --- |
| 运行时 | 仅需 Node.js >= 20 |
| 产物 | 预构建 / 已打包的插件目录（不是裸源码检出） |
| 构建 | 打包评委路径 **不** 要求现场构建 |
| GitHub 登录 | **不** 需要 |
| API Key | **不** 需要 |
| 网络 | 默认 demo 路径 **不** 需要 |

**如何获得包（维护者 / 候选构建方）**

```bash
# 在开发者检出内（构建一次以产出产物）：
npm ci
npm run package
# → release/codex-changeguard-plugin/  （自包含目录）
# → release/codex-changeguard-plugin.tgz  （可移植归档）
```

**评委如何运行（无仓库、无 TypeScript、无 GitHub、无 API Key）**

```bash
# 将预构建目录（或 .tgz）解压到任意目录后：
cd /path/to/codex-changeguard-plugin
node bin/changeguard.js demo
# 宿主已安装 Skill 时：/changeguard demo
# MCP：changeguard_demo（仅可选 budget_ms）
```

**重要——源码检出 vs 打包产物**

- **打包后的**目录对 `demo` 而言仅需 Node.js >= 20 即可运行（无需现场构建）。
- **源码检出**在 CLI/MCP 可用前仍需要 `npm ci` 与 `npm run build`（或 `npm run package`）。
- 包内仅含编译后的 JS、fixtures、schemas、Skill、公共文档与 MIT `LICENSE`——无 `src/`、无 `node_modules`、无 source map、无 Git 元数据。

## 3. `/changeguard demo` 故事与边界

演示故事（旗舰受保护 process Fixture 路径；共享 `runDemo` 核心）：

1. 在**一次性** OS 临时子目录下隔离 allowlist 合成 Fixture（永不触碰实机 `~/.codex`）。
2. 诊断 → 解释结构化证据 → 修复预览 → 应用 → 验证 → 显式回滚。
3. 证明模型边图突变被**拒绝**（图不变）。
4. 证明崩溃家族路径**不具备修复授权资格**且预览被**拒绝**。
5. 清理移除 demo 自有临时目录；收据仅含路径别名 / 摘要。

演示与产品评委路径的硬边界：

| 边界 | 规则 |
| --- | --- |
| 确定性裁定 | 模型可提议；注册探针与 Fixture 决定事实 |
| 非模型核心 | 公共 CLI 与 MCP 共享同一套非模型诊断/恢复核心 |
| 无网络 | 生产 demo / diagnose 缝不打开套接字；默认评委路径仅使用离线快照证据（除非另有披露 + 注入传输，且不在默认路径上） |
| 不修改实机 Codex | 永不修补评委的主用 Codex/Profile；仅使用一次性临时目标 |
| 无守护进程 | 无后台代理、持续日志服务或安装时系统服务 |

## 4. 开发者安装 vs 打包评委安装

### 打包评委安装（评估）

1. 获取**预构建**插件包（`npm run package` → `release/codex-changeguard-plugin/` 或可移植 `.tgz`，或在 Gate C 授权后的分发产物）。
2. 确保 Node.js >= 20。
3. 在包目录中（任意非仓库 cwd）：`node bin/changeguard.js demo`（Skill：`/changeguard demo`；MCP：`changeguard_demo`）。
4. 该路径不要求克隆仓库、TypeScript 构建、GitHub 认证、模型 API Key 或网络。

### 开发者源码安装

```bash
npm ci
npm run build
npm test
npm run check:boundary
npm run package
npm run package:smoke
npm run package:clean-profile
npm run ready:local
npm run verify:release
node bin/changeguard.js demo
node bin/changeguard.js diagnose fixtures/protected-process
node bin/changeguard.js diagnose fixtures/negative-control
```

干净的源码检出在 `npm ci && npm run build`（或 `npm run package`）之前**不**声称可运行。

已实现的公共命令（仓库包装器：`node bin/changeguard.js …`）：

| 领域 | CLI | MCP |
| --- | --- | --- |
| **演示（评委）** | `changeguard demo [--budget-ms=N]` | `changeguard_demo` |
| 诊断 | `changeguard diagnose <target>` | `changeguard_diagnose` |
| Impact Card | `changeguard impact <target> [--disclose-…]` | `changeguard_impact` |
| 页面分析 | `changeguard analyze-page <target> --envelope=…` | `changeguard_analyze_page` |
| 上游预览 | `changeguard upstream-preview <target> --request=…` | `changeguard_upstream_preview` |
| 生命周期 | `changeguard lifecycle <operation> <target>` | `changeguard_lifecycle` |
| 跟进 | `changeguard followup <operation> <target>` | `changeguard_followup` |
| 修复 | `repair-preview` / `repair-apply` / `verify` / `rollback` | `changeguard_repair_*` / `changeguard_verify` / `changeguard_rollback` |
| 实例 | `scan` / `scan-system` / `session-start` | `changeguard_scan` / `changeguard_scan_system` / `changeguard_session_start` |
| 上游动作 | `upstream-action-preview` / `upstream-action-confirm` | `changeguard_upstream_action_*` |
| 平台状态 | `platform-status` / `platform-receipt-validate` | `changeguard_platform_status` / `changeguard_platform_receipt_validate` |

Skill 编排：`skills/changeguard/SKILL.md`（含 `/changeguard demo`）。

### 卸载与干净 Profile

- 卸载会移除用于评估的插件包 / Skill 注册（删除已暂存的包目录及指向它的宿主 Skill 注册）。
- 干净 Profile 烟雾：`npm run package:clean-profile` 仅在**隔离的临时 HOME** 下安装、运行打包 demo、卸载，并断言无守护进程、无 LaunchAgent/服务/计划任务残留、无 shell profile 编辑、无全局 Codex 配置编辑、无凭据要求、无后台进程、无产品自有路径残留。**永不**修改真实 home/profile/全局配置。
- 本产品**不**安装系统守护进程，也**不**声称安装/卸载会修改全局操作系统配置。
- 若宿主侧仍有 Skill 缓存残留，手动清理仅限于删除已打包插件树与会话中显式创建的 ChangeGuard 状态目录——绝不大范围扫描用户主目录。

## 5. 平台支持矩阵

诚实的、以收据为范围的声明见 **[docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md)**。摘要：

| 平台 | 当前产品声明 |
| --- | --- |
| **macOS** | 仅在**本机**经 Ticket 13 真机 harness 后的收据范围 **Full**（非对每一 macOS/Codex 版本的通用保证；仅有外部 JSON 至多 Preview）。官方 Desktop 发现含 **ChatGPT.app**（`Contents/Resources/codex`）与旧版 **Codex.app**；版本仅来自 Bundle `Info.plist` |
| **Windows 11** | **Preview**——框架已集成；在缺少真实 Windows 11 收据 **且** 进程内 live witness 之前保持 Preview |
| **Linux / WSL** | **Limited / Read-only**——Ticket 15 框架；无真实主机收据时写操作失败关闭 |
| **企业托管** | **Read-only + IT Handoff**——无本地提权或策略绕过 |

Ticket 06 CLI/Desktop **版本**回滚仍为 `preview_only` / Desktop 可能为 `limited`。

## 6. 架构、安全、验证与发布就绪

| 文档 | 作用 |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 证据契约、表面、demo 核心要求 |
| [docs/SECURITY.md](docs/SECURITY.md) | 信任、披露、隐私、恢复边界 |
| [docs/TEST_PLAN.md](docs/TEST_PLAN.md) | 验证分层与对抗计划 |
| [docs/CASE_STUDIES.md](docs/CASE_STUDIES.md) | 真实诊断叙事 |
| [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md) | 平台 Full / Preview / Limited 规则 |
| `docs/RELEASE_CHECKLIST.md` | 本地就绪 vs Gate C 外部动作（仓库表面；不在五份打包公共文档中） |
| [当前交接](HANDOFF.md) | 仅仓库内的运行证据（不打包） |

**本地就绪聚合器（Ticket 17；仅产品本地）：**

```bash
npm run ready:local
```

运行包结构检查、打包 demo smoke、干净 Profile 安装/卸载残留 smoke、文档/链接/对等/法律表面检查、生产边界、测试、`npm run verify:release` 与 `git diff --check`。**仅本地**——不创建远端、Release、账户、上传、报名、比赛提交或真实 GitHub 写入。

**规范的本地自动化发布门：**

```bash
npm run verify:release
```

该命令是产品本地发布门（typecheck、测试、边界、打包、smoke、隐私/写路径审计、`git diff --check` 及相关步骤）。通过仅表示**本地自动化就绪**。

| 本地可就绪 | 在另行授权前仍为 Gate C / `NOT_STARTED` |
| --- | --- |
| `npm run ready:local` / `npm run verify:release` 及相关本地检查 | 创建公开远端 |
| 产品文档、MIT 文本、支持矩阵诚实性 | 发布 GitHub Release |
| 在一次性目标上的合成 Fixture 演示 | 报名、上传或比赛提交 |
| 干净 Profile 安装/卸载烟雾（`npm run package:clean-profile`） | 真实 GitHub 写入 / 对外公开发布 |

完整的本地 vs Gate C 清单见仓库 `docs/RELEASE_CHECKLIST.md`。

## 7. 合成与脱敏 Fixture

[`fixtures/`](fixtures/) 下的 Fixture 均为**合成且脱敏**：

- 它们建模类 Codex 布局与故障签名，不附带私有用户日志、完整配置、崩溃转储正文、Cookie、令牌或会话卷展。
- 正负对照（例如 `fixtures/protected-process` 与 `fixtures/negative-control`）使确定性探针能区分真实机制匹配与貌合神离的案例。
- 使用哈希、AST/schema 签名与路径**别名**，而非原始主目录路径或密钥。
- Fixture 数据用于本地诊断、打包 smoke 与 Scenario Harness——不代表任何特定终端用户安装。

## 8. 贡献

贡献规则、评审期望与安全边界见仓库根目录 `CONTRIBUTING.md`（中英合一；源码树）。

高层规则：

- 优先确定性证据，而非模型散文。
- 不要在生产表面加入网络、守护进程或密钥导出路径。
- 实验性修复必须隔离、经授权、可验证且可回滚。
- 不要将文档状态当作 Gate C 发布授权。

## 9. 许可证与对外发布非声明

- 许可证文本：仓库根目录 `LICENSE`（MIT）。
- `package.json` 声明 `"license": "MIT"`。本仓库切片中包仍保持 `"private": true`。
- 磁盘上的 MIT 表示面向**经授权的未来发布**的预期开源许可。
- **本仓库不声称已经发生公开 Release、远端、上传或比赛提交。** 对外发布在另行授权前仍为 Gate C / `NOT_STARTED`。

---

### 插件表面（参考）

- Skill、MCP（`changeguard_*` 工具）、Rescue CLI、可选受信任的 `SessionStart` 钩子
- 打包：`npm run package` → `release/codex-changeguard-plugin/`（+ 可移植 `.tgz`；精确公共表面含 `LICENSE`、`README.md` 与 `README.zh-CN.md`；无 `node_modules`、source map、`AGENTS.md`、`HANDOFF.md` 或 `docs/agents`）
- 包烟雾：`npm run package:smoke`（在临时 profile 下暂存安装、从非仓库 cwd 运行打包 demo、卸载）
- 干净 Profile 残留：`npm run package:clean-profile`
- 本地就绪：`npm run ready:local`

### 开发边界

本仓库仅拥有 ChangeGuard 产品本身。作品集研究、Gate 批准与比赛状态在适用时仍以仓库外的规范位置为准。
