# 15 — 提供 Linux、WSL 与企业受管环境路径

**What to build:** Linux、WSL 和企业受管环境用户可以获得与能力边界相符的诊断、有限恢复或 IT Handoff，不会因为平台未知或策略阻塞而收到越权修复建议。

**Blocked by:** 03 — 识别多实例与版本变化; 07 — 完成配置与启动故障包; 10 — 生成低噪声上游反馈草稿.

**Status:** framework / local harness integrated — platform **Limited / Read-only** (not Full; integrated on clean main `407789ca847b984dbd935e26edf8ad58ad0cf688`)

Broader ChangeGuard product remains `IN_PROGRESS`. This is **not** real-machine Linux/WSL Full. No real Linux/WSL host Scenario Harness receipt exists in this repository. Public writes are disabled by default; internal fixture env alone is not authorization; isolated PREVIEW writes require strict disposable child proof only. Synthetic/injected capability validates the framework only and cannot upgrade production Full. Gate C / registration / publication / submission remain unauthorized / `NOT_STARTED`.

Exact operational evidence is canonical in [HANDOFF.md](../../../HANDOFF.md) § Wave 4 closeout and [docs/SUPPORT_MATRIX.md](../../../docs/SUPPORT_MATRIX.md).

- [x] Linux 与 WSL 适配器提供 CLI 实例、配置、日志和用户拥有缓存的只读发现。
- [x] 未验证的平台能力明确标记 Read-only 或 Limited，写操作默认禁用。
- [x] 受管策略来源被识别和展示，但不尝试覆盖、绕过或提权。
- [x] 管理员动作产生 `ADMIN_ACTION_REQUIRED` 和 IT Handoff，包含最小证据、建议动作、风险、回滚与官方参考。
- [x] 网络、代理、证书、SSO 和防火墙只执行非破坏性比较与诊断。（local-input only; `network_used: false`）
- [x] Scenario Harness 覆盖未知适配器、WSL/Windows 实例并存、受管策略和管理员阻塞。（synthetic fixtures / capability injection; not a real-host Full receipt）

## Implementation notes (Ticket 15)

- Capability matrix + discovery + IT Handoff + network compare under `src/platform/` (linux/wsl adapters + shared gates).
- Public writes fail closed on unknown/Linux/WSL/managed policy unless exact-target disposable isolation proves PREVIEW.
- `platform-status` unifies T13 macOS fields, T14 Windows PREVIEW, and T15 capability `reports` without a second receipt truth source.
- Open residual: real Linux/WSL host Scenario Harness receipt (platform remains Limited until then).

## Local status closeout

- Framework / local harness: integrated and verified on `407789c`.
- Platform support claim: **Limited / Read-only** (no real host receipt; not Full).
- Remaining open product tickets: 12, 16, 17.
