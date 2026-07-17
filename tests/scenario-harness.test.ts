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
import { baseIncident, makeTempDir, writeJson } from "./helpers.js";

function assertNoForbiddenClaims(result: {
  diagnosis_state: string;
  repair_applied: boolean;
  network_used: boolean;
  target_mutated: boolean;
}): void {
  assert.notEqual(result.diagnosis_state, "RESOLVED_VERIFIED");
  assert.notEqual(result.diagnosis_state, "SAFE_FIX_AVAILABLE");
  assert.notEqual(result.diagnosis_state, "LOCAL_REPRO_CONFIRMED");
  assert.equal(result.repair_applied, false);
  assert.equal(result.network_used, false);
  assert.equal(result.target_mutated, false);
}

function assertNoLeakText(text: string): void {
  // Public product surfaces must not emit absolute user paths or secrets.
  // Node bootstrap errors on stderr (e.g. missing build) are not product output.
  assert.equal(/\/Users\//.test(text), false, "absolute Users path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text), false, "Bearer leak");
  assert.equal(
    /\b(?:api[_-]?key|password|secret)\s*[:=]\s*\S+/i.test(text),
    false,
    "credential shape leak",
  );
}

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

test("CLI and MCP return equivalent structured DiagnosisResult", async () => {
  const tmp = makeTempDir("cg-eq-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const before = hashTargetTree(target);
  const cli = runCliDiagnose(target);
  const mcp = await runMcpDiagnose(target);
  const after = hashTargetTree(target);

  assert.equal(before, after);
  assert.ok(cli.result);
  assert.equal(cli.result!.diagnosis_state, mcp.diagnosis_state);
  assert.equal(cli.result!.ok, mcp.ok);
  assert.equal(cli.result!.network_used, mcp.network_used);
  assert.equal(cli.result!.target_mutated, mcp.target_mutated);
  assert.equal(cli.result!.repair_applied, mcp.repair_applied);
  const mcpFp = mcp.incident_fingerprint as {
    local_facts_digest?: string;
    artifact_hashes?: unknown;
    ast_signature_ids?: unknown;
  } | null;
  assert.equal(
    cli.result!.incident_fingerprint?.local_facts_digest,
    mcpFp?.local_facts_digest ?? null,
  );
  assert.deepEqual(
    cli.result!.incident_fingerprint?.artifact_hashes,
    mcpFp?.artifact_hashes,
  );
  assert.deepEqual(
    cli.result!.incident_fingerprint?.ast_signature_ids,
    mcpFp?.ast_signature_ids,
  );
  assert.equal(
    cli.result!.upstream_contribution.status,
    (mcp.upstream_contribution as { status: string }).status,
  );
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
});

test("unknown CLI arguments fail safely", () => {
  const res = spawnSync(
    process.execPath,
    [repoPath("bin/changeguard.js"), "diagnose", "--evil", "x"],
    { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } },
  );
  assert.notEqual(res.status, 0);
  // Product stdout must be path-free structured error JSON.
  assertNoLeakText(res.stdout ?? "");
  assert.ok(res.stdout);
  const parsed = JSON.parse(res.stdout) as { ok: boolean; error_code: string };
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error_code, "USAGE");
});

test("incident symlink escape is refused without reading outside content", () => {
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

test("artifact symlink escape is refused without reading outside content", () => {
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
  fs.writeFileSync(
    outside,
    "globalThis.process = {};\nglobal.process = {};\nprocess = {};\n",
    "utf8",
  );
  fs.symlinkSync(outside, path.join(target, "artifacts", "browser-client.mjs"));
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, false);
  assert.equal(result!.error_code, "SYMLINK_ESCAPE");
  assert.equal(stdout.includes("outside-bytes"), false);
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

test("redacts credentials and full-width Unicode secret shapes after NFKC", () => {
  const tmp = makeTempDir("cg-redact-");
  const target = path.join(tmp, "redact");
  fs.mkdirSync(target, { recursive: true });
  const fullWidth =
    "ＡＰＩ＿ＫＥＹ＝ｓｅｃｒｅｔｖａｌｕｅ Bearer sk-live-ABCDEFGH password=hunter2";
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
});

test("does not recursively crawl project tree for extra files", () => {
  const tmp = makeTempDir("cg-crawl-");
  const target = path.join(tmp, "tree");
  fs.mkdirSync(path.join(target, "deep", "nested", "src"), { recursive: true });
  writeJson(path.join(target, "incident.json"), baseIncident());
  fs.writeFileSync(
    path.join(target, "deep", "nested", "src", "app.ts"),
    "export const secret = 'should-not-be-read';\n",
    "utf8",
  );
  const { result, stdout } = runCliDiagnose(target);
  assert.ok(result);
  assert.equal(result!.ok, true);
  assert.equal(result!.diagnosis_state, "INCONCLUSIVE");
  assert.equal(stdout.includes("should-not-be-read"), false);
  assert.equal(stdout.includes("app.ts"), false);
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

test("no network entry points used (diagnosis result markers)", async () => {
  const tmp = makeTempDir("cg-net-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const cli = runCliDiagnose(target);
  const mcp = await runMcpDiagnose(target);
  assert.equal(cli.result!.network_used, false);
  assert.equal(mcp.network_used, false);
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
