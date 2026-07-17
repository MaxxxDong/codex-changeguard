# Codex ChangeGuard Handoff

## Current state

- Date: 2026-07-17 Asia/Shanghai
- Track ID: `track-openai-build-week-codex-changeguard-20260717`
- Gate B: `APPROVED`, option A
- Current scope status: `IN_PROGRESS` (broader product)
- Ticket 01 (read-only diagnosis spine): implementation/correction complete only after the verification commands in this handoff and `docs/TEST_PLAN.md` pass on a clean build
- Registration: `NOT_STARTED`
- External submission: `NOT_STARTED`
- Gate C: not authorized

## Canonical documents

- Product entry and stable boundary: [README.md](README.md)
- Technical design and evidence levels: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Security/privacy contract: [docs/SECURITY.md](docs/SECURITY.md)
- Verification plan: [docs/TEST_PLAN.md](docs/TEST_PLAN.md)

## Verified facts (Ticket 01 spine)

- Shared core: `src/core/diagnose.ts` (named candidates only; fail-closed symlink policy; structural shim signature)
- Public seams: `bin/changeguard.js` → `dist/cli/main.js`; MCP `changeguard_diagnose` via `dist/mcp/server.js`
- `.mcp.json` uses `cwd: "."` and `./dist/mcp/server.js`
- Release package: `npm run package` → `release/codex-changeguard-plugin/` (self-contained JS, no `node_modules`)
- Package smoke: `npm run package:smoke` from a non-repo cwd
- Production boundary guard: `npm run check:boundary` (TypeScript AST; not a runtime dependency)
- Positive fixture may reach `SOURCE_COMPONENT_LOCATED` only from independently measured hash + structural signature; surface/error/phase remain applicability gates
- Never claims `RESOLVED_VERIFIED`, repair, network use, or target mutation

## Next steps

1. Continue broader product tickets beyond the Ticket 01 read-only spine.
2. Keep Gate C / registration / submission blocked until separate authorization.
3. Do not treat a clean source checkout as runnable before `npm ci && npm run build` (or `npm run package`).

## Boundaries

- Do not register, publish, upload, or submit before Gate C authorization.
- Do not auto-apply community workarounds.
- Do not read or export secret values, complete environment variables, or complete session rollouts.
- Do not describe a user-reported Issue as a confirmed root cause without local reproduction or official linkage.
