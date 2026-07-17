/**
 * Black-box Scenario Harness for Ticket 01 public seams.
 * Exercises CLI + MCP only; owns whole-target before/after hashing.
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";
import test from "node:test";
import {
  copyFixtureToTemp,
  hashTargetTree,
  mcpServerEntry,
  repoPath,
  runCliDiagnose,
  runMcpDiagnose,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import { MAX_MCP_REQUEST_BYTES } from "../src/core/limits.js";
import { measureProtectedProcessAst } from "../src/core/measure.js";
import { NdjsonFrameAccumulator } from "../src/mcp/server.js";
import { baseIncident, makeTempDir, writeJson } from "./helpers.js";

const ALLOWED_USER_STATUSES = new Set([
  "INCONCLUSIVE",
  "DIAGNOSIS_COMPLETE",
  "INSUFFICIENT_LOCAL_FACTS",
]);

function assertNoForbiddenClaims(result: {
  diagnosis_state: string;
  repair_applied: boolean;
  network_used: boolean;
  target_mutated: boolean;
  user_resolution?: { status: string };
}): void {
  assert.notEqual(result.diagnosis_state, "RESOLVED_VERIFIED");
  assert.notEqual(result.diagnosis_state, "SAFE_FIX_AVAILABLE");
  assert.notEqual(result.diagnosis_state, "LOCAL_REPRO_CONFIRMED");
  assert.equal(result.repair_applied, false);
  assert.equal(result.network_used, false);
  assert.equal(result.target_mutated, false);
  if (result.user_resolution) {
    assert.ok(
      ALLOWED_USER_STATUSES.has(result.user_resolution.status),
      `unexpected user status ${result.user_resolution.status}`,
    );
  }
}

function assertNoLeakText(text: string): void {
  assert.equal(/\/Users\//.test(text), false, "absolute Users path leak");
  assert.equal(/\/etc\//.test(text), false, "absolute /etc path leak");
  assert.equal(/\/root\//.test(text), false, "absolute /root path leak");
  assert.equal(/\/Applications\//.test(text), false, "absolute Applications path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text), false, "Bearer leak");
  assert.equal(
    /\b(?:api[_-]?key|password|secret)\s*[:=]\s*\S+/i.test(text),
    false,
    "credential shape leak",
  );
  assert.equal(/at\s+\S+\s+\([^)]+:\d+:\d+\)/.test(text), false, "raw stack frame leak");
}

/** Compare CLI/MCP stable fields; normalize only intentionally nondeterministic receipt IDs. */
function assertCliMcpEquivalence(
  cli: NonNullable<ReturnType<typeof runCliDiagnose>["result"]>,
  mcp: Awaited<ReturnType<typeof runMcpDiagnose>>,
): void {
  assert.equal(cli.schema_version, mcp.schema_version);
  assert.equal(cli.ok, mcp.ok);
  assert.equal(cli.diagnosis_state, mcp.diagnosis_state);
  assert.equal(cli.error_code, mcp.error_code);
  assert.equal(cli.error_message, mcp.error_message);
  assert.equal(cli.network_used, mcp.network_used);
  assert.equal(cli.target_mutated, mcp.target_mutated);
  assert.equal(cli.repair_applied, mcp.repair_applied);
  assert.equal(cli.user_resolution.status, mcp.user_resolution.status);
  assert.equal(cli.user_resolution.summary, mcp.user_resolution.summary);
  assert.equal(cli.upstream_contribution.status, mcp.upstream_contribution.status);
  assert.equal(cli.upstream_contribution.summary, mcp.upstream_contribution.summary);
  assert.deepEqual(
    cli.upstream_contribution.issue_candidates,
    mcp.upstream_contribution.issue_candidates,
  );
  assert.deepEqual(cli.incident_fingerprint, mcp.incident_fingerprint);
  assert.deepEqual(
    cli.evidence.map((e) => ({ kind: e.kind, detail: e.detail, measured: e.measured })),
    mcp.evidence.map((e) => ({ kind: e.kind, detail: e.detail, measured: e.measured })),
  );
  // Receipt IDs must be distinct within each surface, but may differ across surfaces.
  assert.notEqual(cli.user_resolution.receipt_id, cli.upstream_contribution.receipt_id);
  assert.notEqual(mcp.user_resolution.receipt_id, mcp.upstream_contribution.receipt_id);
  assert.ok(ALLOWED_USER_STATUSES.has(cli.user_resolution.status));
  assert.ok(ALLOWED_USER_STATUSES.has(mcp.user_resolution.status));
}

const REAL_SHIM_BLOCK = `const __cg_shim = Object.create(null);
globalThis.process = __cg_shim;
globalThis.global = globalThis.global ?? globalThis;
globalThis.global.process = __cg_shim;
`;

test("positive protected-process fixture reaches SOURCE_COMPONENT_LOCATED via CLI", () => {
  const tmp = makeTempDir("cg-pos-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const before = hashTargetTree(target);
  const { exitCode, result, stdout } = runCliDiagnose(target);
  const after = hashTargetTree(target);

  assert.equal(before, after, "target bytes/hash unchanged");
  assert.equal(exitCode, 0);
  assert.ok(result);
  assert.equal(result!.diagnosis_state, "SOURCE_COMPONENT_LOCATED");
  assert.equal(result!.ok, true);
  assertNoForbiddenClaims(result!);
  assert.ok(result!.incident_fingerprint);
  assert.equal(result!.incident_fingerprint!.schema_version, 1);
  assert.ok(
    result!.incident_fingerprint!.artifact_hashes?.some(
      (a) =>
        a.path_alias === "BROWSER_CLIENT_COPY_A" && /^[a-f0-9]{64}$/.test(a.sha256),
    ),
  );
  assert.ok(
    result!.incident_fingerprint!.ast_signature_ids?.includes(
      "js.global-process-shim-redefinition.v1",
    ),
  );
  assert.equal(result!.user_resolution.status, "DIAGNOSIS_COMPLETE");
  assert.equal(result!.upstream_contribution.status, "CANDIDATE_ONLY");
  assert.ok(
    result!.upstream_contribution.issue_candidates.includes("openai/codex#32925"),
  );
  assertNoLeakText(stdout);
  assert.notEqual(
    result!.user_resolution.receipt_id,
    result!.upstream_contribution.receipt_id,
  );
});

test("negative control stays INCONCLUSIVE and claims no root cause", () => {
  const tmp = makeTempDir("cg-neg-");
  const target = copyFixtureToTemp("fixtures/negative-control", tmp);
  const before = hashTargetTree(target);
  const { exitCode, result } = runCliDiagnose(target);
  const after = hashTargetTree(target);

  assert.equal(before, after);
  assert.equal(exitCode, 0);
  assert.ok(result);
  assert.equal(result!.diagnosis_state, "INCONCLUSIVE");
  assert.equal(result!.user_resolution.status, "INCONCLUSIVE");
  assert.equal(result!.upstream_contribution.status, "NONE");
  assert.deepEqual(result!.upstream_contribution.issue_candidates, []);
  assertNoForbiddenClaims(result!);
  assert.equal(result!.incident_fingerprint?.ast_signature_ids?.length ?? 0, 0);
});

test("CLI and MCP return equivalent structured DiagnosisResult (positive)", async () => {
  const tmp = makeTempDir("cg-eq-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const before = hashTargetTree(target);
  const cli = runCliDiagnose(target);
  const mcp = await runMcpDiagnose(target);
  const after = hashTargetTree(target);

  assert.equal(before, after);
  assert.ok(cli.result);
  assertCliMcpEquivalence(cli.result!, mcp);
});

test("CLI and MCP return equivalent structured DiagnosisResult (negative)", async () => {
  const tmp = makeTempDir("cg-eqn-");
  const target = copyFixtureToTemp("fixtures/negative-control", tmp);
  const cli = runCliDiagnose(target);
  const mcp = await runMcpDiagnose(target);
  assert.ok(cli.result);
  assertCliMcpEquivalence(cli.result!, mcp);
});

test("CLI and MCP return equivalent structured DiagnosisResult (error/missing)", async () => {
  const tmp = makeTempDir("cg-eqe-");
  const target = path.join(tmp, "empty");
  fs.mkdirSync(target, { recursive: true });
  const cli = runCliDiagnose(target);
  const mcp = await runMcpDiagnose(target);
  assert.ok(cli.result);
  assertCliMcpEquivalence(cli.result!, mcp);
  assert.equal(cli.result!.ok, false);
});

test("synthetic fixture artifact hash equals actual bytes", () => {
  const artifact = repoPath(
    "fixtures/protected-process/artifacts/browser-client.mjs",
  );
  const buf = fs.readFileSync(artifact);
  const measured = crypto.createHash("sha256").update(buf).digest("hex");
  const tmp = makeTempDir("cg-hash-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const { result } = runCliDiagnose(target);
  assert.ok(result?.incident_fingerprint?.artifact_hashes?.[0]);
  assert.equal(
    result!.incident_fingerprint!.artifact_hashes![0]!.sha256,
    measured,
  );
  // Structural signature matches the real shim block exactly once.
  const ast = measureProtectedProcessAst(buf.toString("utf8"));
  assert.equal(ast.matched, true);
  assert.equal(ast.blockCount, 1);
});

test("declared-only AST id without measured artifact stays INCONCLUSIVE", () => {
  const tmp = makeTempDir("cg-declared-");
  const target = path.join(tmp, "declared-only");
  fs.mkdirSync(target, { recursive: true });
  writeJson(
    path.join(target, "incident.json"),
    baseIncident({
      surface: "browser_control",
      failure_phase: "extension_handshake",
      error: {
        class: "TypeError",
        normalized_message:
          "protected global process binding rejected assignment",
        message_digest:
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      },
      stack_frames: [
        {
          module: "browser-client",
          file: "browser-client.mjs",
          symbol: "module_initialization",
          line_bucket: 30,
        },
      ],
      feature_ids: ["browser_control"],
      ast_signature_ids: ["js.global-process-shim-redefinition.v1"],
      artifact_hashes: [
        {
          path_alias: "BROWSER_CLIENT_COPY_A",
          sha256:
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        },
      ],
    }),
  );
  const { result } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.diagnosis_state, "INCONCLUSIVE");
  assert.equal(result!.incident_fingerprint?.ast_signature_ids?.length ?? 0, 0);
});

test("malformed incident JSON fails safely", () => {
  const tmp = makeTempDir("cg-mal-");
  const target = path.join(tmp, "bad");
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, "incident.json"), "{not-json", "utf8");
  const { exitCode, result, stdout } = runCliDiagnose(target);
  assert.notEqual(exitCode, 0);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.diagnosis_state, "INCONCLUSIVE");
  assert.match(result!.error_code ?? "", /MALFORMED/);
  assertNoLeakText(stdout);
  assert.equal(stdout.includes("SyntaxError"), false);
  assert.notEqual(
    result!.user_resolution.receipt_id,
    result!.upstream_contribution.receipt_id,
  );
});

test("unknown CLI arguments fail safely with distinct receipt ids", () => {
  const res = spawnSync(
    process.execPath,
    [repoPath("bin/changeguard.js"), "diagnose", "--evil", "x"],
    { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } },
  );
  assert.notEqual(res.status, 0);
  assertNoLeakText(res.stdout ?? "");
  assert.ok(res.stdout);
  const parsed = JSON.parse(res.stdout) as {
    ok: boolean;
    error_code: string;
    user_resolution: { receipt_id: string };
    upstream_contribution: { receipt_id: string };
  };
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error_code, "USAGE");
  assert.notEqual(
    parsed.user_resolution.receipt_id,
    parsed.upstream_contribution.receipt_id,
  );
});

// --- Path containment / symlink / TOCTOU ---

test("target directory that is a symlink is refused", () => {
  const tmp = makeTempDir("cg-sym-tgt-");
  const realDir = path.join(tmp, "real");
  const linkDir = path.join(tmp, "link");
  fs.mkdirSync(realDir, { recursive: true });
  writeJson(path.join(realDir, "incident.json"), baseIncident());
  fs.symlinkSync(realDir, linkDir);
  const { result, stdout } = runCliDiagnose(linkDir);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "SYMLINK_ESCAPE");
  assertNoLeakText(stdout);
});

test("incident leaf symlink is refused without reading outside content", () => {
  const tmp = makeTempDir("cg-sym-inc-");
  const target = path.join(tmp, "target");
  const outside = path.join(tmp, "outside-secret.txt");
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(outside, "SECRET_SHOULD_NOT_BE_READ=1\n", "utf8");
  fs.symlinkSync(outside, path.join(target, "incident.json"));
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "SYMLINK_ESCAPE");
  assert.equal(stdout.includes("SECRET_SHOULD_NOT_BE_READ"), false);
  assertNoLeakText(stdout);
});

test("artifact leaf symlink is refused without reading outside content", () => {
  const tmp = makeTempDir("cg-sym-art-");
  const target = path.join(tmp, "target");
  const outside = path.join(tmp, "outside-bytes.mjs");
  fs.mkdirSync(path.join(target, "artifacts"), { recursive: true });
  writeJson(
    path.join(target, "incident.json"),
    baseIncident({
      surface: "browser_control",
      failure_phase: "extension_handshake",
      error: {
        class: "TypeError",
        normalized_message:
          "protected global process binding rejected assignment",
        message_digest:
          "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      },
      stack_frames: [
        {
          module: "browser-client",
          file: "browser-client.mjs",
          symbol: "module_initialization",
          line_bucket: 30,
        },
      ],
      feature_ids: ["browser_control"],
    }),
  );
  fs.writeFileSync(outside, REAL_SHIM_BLOCK, "utf8");
  fs.symlinkSync(outside, path.join(target, "artifacts", "browser-client.mjs"));
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "SYMLINK_ESCAPE");
  assert.equal(stdout.includes("outside-bytes"), false);
  assert.equal(stdout.includes("protected-process-shim"), false);
});

test("artifacts intermediate-directory symlink escaping outside is refused", () => {
  const tmp = makeTempDir("cg-sym-mid-");
  const target = path.join(tmp, "target");
  const outsideDir = path.join(tmp, "outside-art");
  fs.mkdirSync(target, { recursive: true });
  fs.mkdirSync(outsideDir, { recursive: true });
  writeJson(
    path.join(target, "incident.json"),
    baseIncident({
      surface: "browser_control",
      failure_phase: "extension_handshake",
      error: {
        class: "TypeError",
        normalized_message:
          "protected global process binding rejected assignment",
        message_digest:
          "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      },
      stack_frames: [
        {
          module: "browser-client",
          file: "browser-client.mjs",
          symbol: "module_initialization",
          line_bucket: 30,
        },
      ],
      feature_ids: ["browser_control"],
    }),
  );
  fs.writeFileSync(
    path.join(outsideDir, "browser-client.mjs"),
    `${REAL_SHIM_BLOCK}export const MARKER_OUTSIDE = 'LEAK_ME';\n`,
    "utf8",
  );
  // Intermediate directory symlink: artifacts -> outsideDir
  fs.symlinkSync(outsideDir, path.join(target, "artifacts"));
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "SYMLINK_ESCAPE");
  assert.equal(stdout.includes("LEAK_ME"), false);
  assert.equal(stdout.includes("MARKER_OUTSIDE"), false);
  assertNoLeakText(stdout);
});

test("non-file candidate (directory named as incident) is refused", () => {
  const tmp = makeTempDir("cg-nonfile-");
  const target = path.join(tmp, "target");
  fs.mkdirSync(path.join(target, "incident.json"), { recursive: true });
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "INVALID_CANDIDATE");
  assertNoLeakText(stdout);
});

test("target directory that is a file fails safely", () => {
  const tmp = makeTempDir("cg-file-");
  const file = path.join(tmp, "not-a-dir");
  fs.writeFileSync(file, "x", "utf8");
  const { result } = runCliDiagnose(file);
  assert.ok(result);
  assert.equal(result!.ok, false);
});

test("oversized incident is refused", () => {
  const tmp = makeTempDir("cg-big-");
  const target = path.join(tmp, "big");
  fs.mkdirSync(target, { recursive: true });
  const big = Buffer.alloc(65 * 1024, 0x61);
  fs.writeFileSync(path.join(target, "incident.json"), big);
  const { result } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "SIZE_LIMIT");
});

test("AST signature id over 128 characters is refused", () => {
  const tmp = makeTempDir("cg-astlen-");
  const target = path.join(tmp, "ast");
  fs.mkdirSync(target, { recursive: true });
  writeJson(
    path.join(target, "incident.json"),
    baseIncident({
      ast_signature_ids: ["x".repeat(129)],
    }),
  );
  const { result } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "FIELD_LIMIT");
});

test("extra unexpected incident fields fail safely", () => {
  const tmp = makeTempDir("cg-extra-");
  const target = path.join(tmp, "extra");
  fs.mkdirSync(target, { recursive: true });
  writeJson(path.join(target, "incident.json"), {
    ...baseIncident(),
    evil_field: true,
  });
  const { result } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "MALFORMED_INCIDENT");
});

test("extra nested stack_frames fields are rejected", () => {
  const tmp = makeTempDir("cg-stackx-");
  const target = path.join(tmp, "stackx");
  fs.mkdirSync(target, { recursive: true });
  writeJson(
    path.join(target, "incident.json"),
    baseIncident({
      stack_frames: [
        {
          module: "m",
          file: "f.js",
          symbol: "s",
          line_bucket: 1,
          evil: true,
        },
      ],
    }),
  );
  const { result } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "MALFORMED_INCIDENT");
});

test("extra nested artifact_hashes fields are rejected", () => {
  const tmp = makeTempDir("cg-artx-");
  const target = path.join(tmp, "artx");
  fs.mkdirSync(target, { recursive: true });
  writeJson(
    path.join(target, "incident.json"),
    baseIncident({
      artifact_hashes: [
        {
          path_alias: "A",
          sha256:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          note: "nope",
        },
      ],
    }),
  );
  const { result } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "MALFORMED_INCIDENT");
});

test("duplicate artifact_hashes path_alias is rejected", () => {
  const tmp = makeTempDir("cg-dup-");
  const target = path.join(tmp, "dup");
  fs.mkdirSync(target, { recursive: true });
  writeJson(
    path.join(target, "incident.json"),
    baseIncident({
      artifact_hashes: [
        {
          path_alias: "SAME",
          sha256:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        {
          path_alias: "SAME",
          sha256:
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
      ],
    }),
  );
  const { result } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "MALFORMED_INCIDENT");
});

test("redacts credentials, full-width secrets, and generic absolute paths after NFKC", () => {
  const tmp = makeTempDir("cg-redact-");
  const target = path.join(tmp, "redact");
  fs.mkdirSync(target, { recursive: true });
  const fullWidth =
    "ＡＰＩ＿ＫＥＹ＝ｓｅｃｒｅｔｖａｌｕｅ Bearer sk-live-ABCDEFGH password=hunter2 " +
    "path=/etc/passwd also=/root/.ssh/id_rsa and=/Applications/Codex.app " +
    "win=C:\\Users\\x\\secret.txt unc=\\\\server\\share\\file";
  writeJson(
    path.join(target, "incident.json"),
    baseIncident({
      error: {
        class: "Error",
        normalized_message: fullWidth,
        message_digest:
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      },
    }),
  );
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, true);
  assertNoLeakText(stdout);
  assert.equal(stdout.includes("hunter2"), false);
  assert.equal(stdout.includes("sk-live-ABCDEFGH"), false);
  assert.equal(stdout.includes("ｓｅｃｒｅｔｖａｌｕｅ"), false);
  assert.equal(stdout.includes("secretvalue"), false);
  assert.equal(stdout.includes("/etc/passwd"), false);
  assert.equal(stdout.includes("/root/.ssh"), false);
  assert.equal(stdout.includes("/Applications/Codex"), false);
  assert.equal(stdout.includes("C:\\Users"), false);
});

test("does not recursively crawl project tree; nested unreadable sentinel not read", () => {
  const tmp = makeTempDir("cg-crawl-");
  const target = path.join(tmp, "tree");
  const nestedDir = path.join(target, "deep", "nested", "src");
  fs.mkdirSync(nestedDir, { recursive: true });
  writeJson(path.join(target, "incident.json"), baseIncident());
  const sentinel = path.join(nestedDir, "app.ts");
  fs.writeFileSync(
    sentinel,
    "export const secret = 'should-not-be-read';\n",
    "utf8",
  );
  // Cross-platform: make nested file unreadable when chmod is supported.
  try {
    fs.chmodSync(sentinel, 0);
  } catch {
    /* platform may not support; black-box content check still applies */
  }
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, true);
  assert.equal(result!.diagnosis_state, "INCONCLUSIVE");
  assert.equal(stdout.includes("should-not-be-read"), false);
  assert.equal(stdout.includes("app.ts"), false);
  // Restore perms for cleanup
  try {
    fs.chmodSync(sentinel, 0o644);
  } catch {
    /* ignore */
  }
});

test("MCP rejects unknown/extra tool arguments", async () => {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    await client.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "t", version: "0" },
    });
    await assert.rejects(
      () =>
        client.request("tools/call", {
          name: "changeguard_diagnose",
          arguments: { target: "/tmp", extra: true },
        }),
      /argument|Unknown|extra|Invalid/i,
    );
  } finally {
    await client.close();
  }
});

test("MCP rejects extra top-level tools/call params", async () => {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    await client.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "t", version: "0" },
    });
    await assert.rejects(
      () =>
        client.request("tools/call", {
          name: "changeguard_diagnose",
          arguments: { target: "/tmp" },
          evil: true,
        }),
      /extra|Unknown|param/i,
    );
  } finally {
    await client.close();
  }
});

test("MCP handles partial stdout chunks and clears timers", async () => {
  const client = new McpTestClient({
    serverEntry: mcpServerEntry(),
    timeoutMs: 5000,
  });
  try {
    client.start();
    const tmp = makeTempDir("cg-mcp-");
    const target = copyFixtureToTemp("fixtures/negative-control", tmp);
    const result = await client.diagnose(target);
    assert.equal(result.diagnosis_state, "INCONCLUSIVE");
  } finally {
    await client.close();
  }
});

test("MCP malformed JSON-RPC fails safely", async () => {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(process.execPath, [mcpServerEntry()], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("timeout"));
    }, 5000);
    timer.unref?.();
    rl.on("line", (line) => {
      clearTimeout(timer);
      try {
        const msg = JSON.parse(line) as { error?: { message?: string } };
        assert.ok(msg.error);
        assertNoLeakText(line);
        child.kill();
        rl.close();
        resolve();
      } catch (e) {
        child.kill();
        reject(e);
      }
    });
    child.stdin.write("not-json\n");
  });
});

// --- MCP bounded frame accumulator ---

test("MCP frame accumulator rejects >128KiB with no newline without unbounded accumulation", () => {
  const frames: string[] = [];
  let overflows = 0;
  const acc = new NdjsonFrameAccumulator(
    MAX_MCP_REQUEST_BYTES,
    (f) => frames.push(f),
    () => {
      overflows += 1;
    },
  );
  // Stream >128KiB in chunks with no newline.
  const chunk = Buffer.alloc(16 * 1024, 0x61);
  let totalPushed = 0;
  for (let i = 0; i < 10; i++) {
    acc.push(chunk);
    totalPushed += chunk.length;
    assert.ok(
      acc.retainedBytes <= MAX_MCP_REQUEST_BYTES,
      `retained ${acc.retainedBytes} after pushing ${totalPushed}`,
    );
  }
  assert.equal(overflows, 1);
  assert.equal(frames.length, 0);
  assert.ok(acc.retainedBytes <= MAX_MCP_REQUEST_BYTES);
});

test("MCP frame accumulator recovers after oversized frame then valid ping", () => {
  const frames: string[] = [];
  let overflows = 0;
  const acc = new NdjsonFrameAccumulator(
    MAX_MCP_REQUEST_BYTES,
    (f) => frames.push(f),
    () => {
      overflows += 1;
    },
  );
  // Oversized frame (no newline until after bound), then a valid ping frame.
  const big = Buffer.alloc(MAX_MCP_REQUEST_BYTES + 100, 0x62);
  acc.push(big);
  assert.equal(overflows, 1);
  // End oversized with newline and append valid frame in same/next chunk.
  const ping = Buffer.from(
    '\n{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}\n',
    "utf8",
  );
  acc.push(ping);
  assert.equal(frames.length, 1);
  assert.match(frames[0]!, /"method":"ping"/);
});

test("MCP frame accumulator handles partial UTF-8 and multiple frames", () => {
  const frames: string[] = [];
  const acc = new NdjsonFrameAccumulator(
    MAX_MCP_REQUEST_BYTES,
    (f) => frames.push(f),
    () => {
      throw new Error("unexpected overflow");
    },
  );
  // Multi-byte UTF-8 euro sign € = e2 82 ac split across chunks.
  const line1 = Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping","note":"', "utf8");
  const euro = Buffer.from([0xe2, 0x82, 0xac]);
  const line1end = Buffer.from('"}\n', "utf8");
  const line2 = Buffer.from(
    '{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}\n',
    "utf8",
  );
  acc.push(line1);
  acc.push(euro.subarray(0, 1));
  acc.push(euro.subarray(1, 2));
  acc.push(Buffer.concat([euro.subarray(2), line1end]));
  acc.push(line2.subarray(0, 10));
  acc.push(line2.subarray(10));
  assert.equal(frames.length, 2);
  assert.ok(frames[0]!.includes("€") || frames[0]!.includes("\u20ac"));
  assert.match(frames[1]!, /"id":2/);
});

// --- Structural protected-process signature ---

test("structural signature matches exact real block once", () => {
  const src = REAL_SHIM_BLOCK + 'export const x = 1;\n';
  const r = measureProtectedProcessAst(src);
  assert.equal(r.matched, true);
  assert.equal(r.blockCount, 1);
  assert.equal(r.signatureId, "js.global-process-shim-redefinition.v1");
  assert.equal(r.assignmentCount, 3);
});

test("structural signature ignores comment-only spoof", () => {
  const src = `
// globalThis.process = shim;
// globalThis.global = globalThis.global ?? globalThis;
// globalThis.global.process = shim;
const x = 1;
`;
  const r = measureProtectedProcessAst(src);
  assert.equal(r.matched, false);
  assert.equal(r.blockCount, 0);
});

test("structural signature ignores string/template-only spoof", () => {
  const src = `
const a = "globalThis.process = shim; globalThis.global = globalThis.global ?? globalThis; globalThis.global.process = shim;";
const b = \`globalThis.process = shim;
globalThis.global = globalThis.global ?? globalThis;
globalThis.global.process = shim;\`;
`;
  const r = measureProtectedProcessAst(src);
  assert.equal(r.matched, false);
  assert.equal(r.blockCount, 0);
});

test("structural signature refuses two real blocks", () => {
  const src = REAL_SHIM_BLOCK + "\n" + REAL_SHIM_BLOCK;
  const r = measureProtectedProcessAst(src);
  assert.equal(r.matched, false);
  assert.equal(r.blockCount, 2);
});

test("structural signature refuses missing/reordered/different-shim assignments", () => {
  const missingThird = `globalThis.process = s;
globalThis.global = globalThis.global ?? globalThis;
`;
  assert.equal(measureProtectedProcessAst(missingThird).matched, false);

  const reordered = `globalThis.global = globalThis.global ?? globalThis;
globalThis.process = s;
globalThis.global.process = s;
`;
  assert.equal(measureProtectedProcessAst(reordered).matched, false);

  const differentShim = `globalThis.process = a;
globalThis.global = globalThis.global ?? globalThis;
globalThis.global.process = b;
`;
  assert.equal(measureProtectedProcessAst(differentShim).matched, false);

  // Old inaccurate surrogate must not match.
  const oldSurrogate = `globalThis.process = s;
global.process = s;
process = s;
`;
  assert.equal(measureProtectedProcessAst(oldSurrogate).matched, false);
});

test("no network entry points used (markers + independent boundary guard)", async () => {
  const tmp = makeTempDir("cg-net-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const cli = runCliDiagnose(target);
  const mcp = await runMcpDiagnose(target);
  assert.equal(cli.result!.network_used, false);
  assert.equal(mcp.network_used, false);
  // Independent evidence: production boundary script must pass.
  const guard = spawnSync(process.execPath, [repoPath("scripts/check-production-boundary.mjs")], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  assert.equal(guard.status, 0, guard.stdout + guard.stderr);
  const report = JSON.parse(guard.stdout) as { ok: boolean; violations: string[] };
  assert.equal(report.ok, true);
  assert.deepEqual(report.violations, []);
});

test("invalid fixture path / missing incident fails safely", () => {
  const tmp = makeTempDir("cg-miss-");
  const target = path.join(tmp, "empty");
  fs.mkdirSync(target, { recursive: true });
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "CANDIDATE_NOT_FOUND");
  assertNoLeakText(stdout);
});
