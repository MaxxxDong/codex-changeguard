/**
 * Ticket 02 Scenario Harness — protected-process verified repair vertical slice.
 * Black-box via public CLI/MCP seams; owns target hash proofs for apply/rollback.
 * Includes adversarial RED/GREEN cases for auth token, capsule mutation, and
 * recovery write-boundary self-tests (via check:boundary).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  copyFixtureToTemp,
  hashTargetTree,
  mcpServerEntry,
  runCliDiagnose,
  runCliJson,
  runCliRepairApply,
  runCliRepairPreview,
  runCliRollback,
  runCliVerify,
  runMcpDiagnose,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import { measureProtectedProcessAst, sha256Buffer } from "../src/core/measure.js";
import {
  decodeAuthorizationToken,
  encodeAuthorizationToken,
  strictValidateCapsule,
  AuthTokenError,
} from "../src/core/recovery/auth-token.js";
import { INDUCE_VERIFY_FAIL_REL } from "../src/core/recovery/index.js";
import { registeredBackupRel } from "../src/core/recovery/types.js";
import { makeTempDir } from "./helpers.js";

const PROTECTED_ARTIFACT_SHA =
  "33af4a7ad7a4ec2d18cb928a2ef69922e69031007dd07672334c5fe45faec48f";
const ARTIFACT_REL = "artifacts/browser-client.mjs";

function artifactSha(target: string): string {
  const buf = fs.readFileSync(path.join(target, ARTIFACT_REL));
  return sha256Buffer(buf);
}

function artifactSource(target: string): string {
  return fs.readFileSync(path.join(target, ARTIFACT_REL), "utf8");
}

function assertNoLeakText(text: string): void {
  assert.equal(/\/Users\//.test(text), false, "absolute Users path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text), false, "Bearer leak");
}

function capsuleFields(result: Record<string, unknown>) {
  const capsule = result.capsule as Record<string, unknown> | null;
  assert.ok(capsule, "capsule required");
  return capsule;
}

function authFromPreview(result: Record<string, unknown>): string {
  const auth = result.authorization;
  assert.equal(typeof auth, "string", "self-contained authorization token required");
  assert.ok(String(auth).startsWith("cg1."), "token prefix cg1.");
  return String(auth);
}

test("Ticket02: positive fixture reproduces protected-process failure before handshake (diagnose)", () => {
  const tmp = makeTempDir("cg-t02-diag-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const beforeSha = artifactSha(target);
  assert.equal(beforeSha, PROTECTED_ARTIFACT_SHA);
  const ast = measureProtectedProcessAst(artifactSource(target));
  assert.equal(ast.matched, true);
  assert.equal(ast.blockCount, 1);

  const { exitCode, result, stdout } = runCliDiagnose(target);
  assert.equal(exitCode, 0);
  assert.ok(result);
  assert.equal(result!.diagnosis_state, "SOURCE_COMPONENT_LOCATED");
  assert.equal(result!.repair_applied, false);
  assert.equal(result!.target_mutated, false);
  assert.equal(result!.user_resolution.status, "DIAGNOSIS_COMPLETE");
  // Failure phase gate remains pre-handshake (extension_handshake).
  assert.equal(result!.incident_fingerprint?.failure_phase, "extension_handshake");
  assert.equal(artifactSha(target), beforeSha, "diagnose must not mutate");
  assertNoLeakText(stdout);
});

test("Ticket02: successful repair preview → apply → RESOLVED_VERIFIED with hash proof", () => {
  const tmp = makeTempDir("cg-t02-ok-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const originalSha = artifactSha(target);
  assert.equal(originalSha, PROTECTED_ARTIFACT_SHA);
  const beforeTree = hashTargetTree(target);

  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  assert.ok(preview.result);
  assert.equal(preview.result!.ok, true);
  assert.equal(preview.result!.operation, "preview");
  assert.equal(preview.result!.target_mutated, false);
  assert.equal(preview.result!.repair_applied, false);
  assert.equal(
    (preview.result!.user_resolution as { status: string }).status,
    "REPAIR_PREVIEWED",
  );

  const capsule = capsuleFields(preview.result!);
  assert.equal(capsule.target_path_alias, "BROWSER_CLIENT_COPY_A");
  assert.equal(capsule.original_sha256, originalSha);
  assert.equal(capsule.expected_pattern_count, 1);
  assert.equal(typeof capsule.authorization_binding, "string");
  assert.match(String(capsule.authorization_binding), /^[a-f0-9]{64}$/);
  assert.ok(capsule.operation && typeof capsule.operation === "object");
  const op = capsule.operation as Record<string, unknown>;
  assert.equal(op.kind, "exact_block_removal");
  assert.match(String(op.operation_digest), /^[a-f0-9]{64}$/);
  assert.match(String(op.expected_result_sha256), /^[a-f0-9]{64}$/);
  assert.equal(capsule.authorization_tier, "experimental_one_shot");
  assert.equal(capsule.risk, "moderate");
  assert.ok(capsule.backup && typeof capsule.backup === "object");
  assert.equal(
    (capsule.backup as { backup_rel: string }).backup_rel,
    registeredBackupRel(),
  );
  assert.ok(capsule.verification && typeof capsule.verification === "object");
  assert.ok(capsule.rollback && typeof capsule.rollback === "object");
  assert.ok(capsule.expires_at);
  assert.ok(capsule.invalidation_digest);
  assert.match(String(capsule.nonce), /^[a-f0-9]{32}$/);
  assert.ok(capsule.disclosure && typeof capsule.disclosure === "object");
  const disclosure = capsule.disclosure as Record<string, unknown>;
  assert.equal(disclosure.includes_source_bytes, false);
  assert.equal(disclosure.includes_secrets, false);
  // Capsule must not embed source file bytes.
  const previewText = preview.stdout;
  assert.equal(previewText.includes("globalThis.process = __cg_shim"), false);
  assertNoLeakText(previewText);
  // Preview is whole-tree read-only: no .changeguard, tree hash unchanged.
  assert.equal(hashTargetTree(target), beforeTree, "preview must not mutate tree");
  assert.equal(
    fs.existsSync(path.join(target, ".changeguard")),
    false,
    "preview must not create .changeguard",
  );
  assert.equal(artifactSha(target), originalSha, "preview must not mutate artifact");

  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  assert.ok(apply.result);
  assert.equal(apply.result!.ok, true);
  assert.equal(apply.result!.repair_applied, true);
  assert.equal(apply.result!.target_mutated, true);
  assert.equal(apply.result!.auto_rolled_back, false);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
  assert.notEqual(
    (apply.result!.user_resolution as { receipt_id: string }).receipt_id,
    (apply.result!.upstream_contribution as { receipt_id: string }).receipt_id,
  );
  // Never claim external submission.
  assert.equal(apply.result!.contribution_claim, "none");
  assert.notEqual(
    (apply.result!.upstream_contribution as { status: string }).status,
    "SUBMITTED",
  );

  const afterSha = artifactSha(target);
  assert.notEqual(afterSha, originalSha);
  assert.equal(apply.result!.resulting_sha256, afterSha);
  const afterAst = measureProtectedProcessAst(artifactSource(target));
  assert.equal(afterAst.matched, false);
  assert.equal(afterAst.blockCount, 0);
  assert.match(artifactSource(target), /export const marker/);

  const verify = runCliVerify(target);
  assert.equal(verify.exitCode, 0, verify.stdout);
  assert.equal(
    (verify.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
  assert.equal(artifactSha(target), afterSha);
});

test("Ticket02: negative control refuses same repair (wrong mechanism)", () => {
  const tmp = makeTempDir("cg-t02-neg-");
  const target = copyFixtureToTemp("fixtures/negative-control", tmp);
  const before = hashTargetTree(target);

  const preview = runCliRepairPreview(target);
  assert.notEqual(preview.exitCode, 0);
  assert.ok(preview.result);
  assert.equal(preview.result!.ok, false);
  assert.equal(preview.result!.error_code, "NOT_APPLICABLE");
  assert.equal(
    (preview.result!.user_resolution as { status: string }).status,
    "REPAIR_REFUSED",
  );
  assert.equal(preview.result!.capsule, null);
  assert.equal(preview.result!.authorization, null);
  assert.equal(hashTargetTree(target), before);

  // Applying a forged authorization without a valid token must fail closed.
  const forged = crypto.createHash("sha256").update("forged").digest("hex");
  const apply = runCliRepairApply(target, forged);
  assert.notEqual(apply.exitCode, 0);
  assert.equal(apply.result!.ok, false);
  assert.ok(
    apply.result!.error_code === "AUTH_INVALID" ||
      apply.result!.error_code === "AUTH_MALFORMED" ||
      apply.result!.error_code === "NOT_APPLICABLE",
  );
  assert.equal(hashTargetTree(target), before);
});

test("Ticket02: stale or mismatched authorization is refused", () => {
  const tmp = makeTempDir("cg-t02-auth-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0);
  const auth = authFromPreview(preview.result!);
  const originalSha = artifactSha(target);

  // Wrong token.
  const wrong = "cg1." + Buffer.from(JSON.stringify({ v: 1, capsule: {} })).toString("base64url");
  const bad = runCliRepairApply(target, wrong);
  assert.notEqual(bad.exitCode, 0);
  assert.equal(bad.result!.error_code, "AUTH_INVALID");
  assert.equal(artifactSha(target), originalSha);

  // Mutate target after preview → binding invalidates.
  fs.writeFileSync(
    path.join(target, ARTIFACT_REL),
    artifactSource(target) + "\n// drift\n",
    "utf8",
  );
  const stale = runCliRepairApply(target, auth);
  assert.notEqual(stale.exitCode, 0);
  assert.ok(
    stale.result!.error_code === "AUTH_INVALID" ||
      stale.result!.error_code === "NOT_APPLICABLE",
  );
});

test("Ticket02: induced verification failure auto-rollbacks to original bytes", () => {
  const tmp = makeTempDir("cg-t02-ind-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const originalSha = artifactSha(target);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0);
  const auth = authFromPreview(preview.result!);

  // Harness plants sentinel under isolated target (black-box induce).
  const sentinel = path.join(target, INDUCE_VERIFY_FAIL_REL);
  fs.mkdirSync(path.dirname(sentinel), { recursive: true });
  fs.writeFileSync(sentinel, "induce\n", "utf8");

  const apply = runCliRepairApply(target, auth);
  assert.notEqual(apply.exitCode, 0, apply.stdout);
  assert.ok(apply.result);
  assert.equal(apply.result!.ok, false);
  assert.equal(apply.result!.auto_rolled_back, true);
  assert.equal(apply.result!.repair_applied, false);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "REPAIR_FAILED_ROLLED_BACK",
  );
  assert.notEqual(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
  assert.equal(artifactSha(target), originalSha, "auto-rollback restores exact original");
  // Original failure still present after failed apply.
  assert.equal(measureProtectedProcessAst(artifactSource(target)).matched, true);
});

test("Ticket02: explicit rollback restores exact original bytes/hash", () => {
  const tmp = makeTempDir("cg-t02-rb-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const originalSha = artifactSha(target);
  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  const repairedSha = artifactSha(target);
  assert.notEqual(repairedSha, originalSha);

  const rb = runCliRollback(target);
  assert.equal(rb.exitCode, 0, rb.stdout);
  assert.ok(rb.result);
  assert.equal(rb.result!.ok, true);
  assert.equal(
    (rb.result!.user_resolution as { status: string }).status,
    "MITIGATED_VERIFIED_BY_ROLLBACK",
  );
  assert.equal(artifactSha(target), originalSha);
  assert.equal(rb.result!.resulting_sha256, originalSha);
  assert.equal(measureProtectedProcessAst(artifactSource(target)).matched, true);
  // User resolution after rollback is mitigation, not RESOLVED_VERIFIED.
  assert.notEqual(
    (rb.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
});

test("Ticket02: CLI and MCP repair-preview equivalence on positive fixture", async () => {
  const tmp = makeTempDir("cg-t02-mcp-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const cli = runCliRepairPreview(target);
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const mcp = await client.repairPreview(target);
    assert.equal(cli.result!.ok, mcp.ok);
    assert.equal(cli.result!.operation, mcp.operation);
    assert.equal(
      (cli.result!.user_resolution as { status: string }).status,
      mcp.user_resolution.status,
    );
    const cliCap = cli.result!.capsule as Record<string, unknown>;
    const mcpCap = mcp.capsule!;
    // Stable capsule fields must match across seams; binding includes expires_at
    // and nonce so successive previews mint distinct one-shot tokens (not reusable).
    assert.equal(cliCap.original_sha256, mcpCap.original_sha256);
    assert.equal(cliCap.expected_pattern_count, mcpCap.expected_pattern_count);
    assert.equal(cliCap.target_path_alias, mcpCap.target_path_alias);
    assert.equal(cliCap.capsule_id, mcpCap.capsule_id);
    assert.equal(
      (cliCap.operation as { operation_digest: string }).operation_digest,
      (mcpCap.operation as { operation_digest: string }).operation_digest,
    );
    assert.match(String(mcpCap.authorization_binding), /^[a-f0-9]{64}$/);
    assert.equal(typeof mcp.authorization, "string");
    assert.ok(String(mcp.authorization).startsWith("cg1."));
    assert.equal(cli.result!.network_used, false);
    assert.equal(mcp.network_used, false);
  } finally {
    await client.close();
  }
});

test("Ticket02: diagnose remains read-only after Ticket 02 (no RESOLVED_VERIFIED from diagnose)", async () => {
  const tmp = makeTempDir("cg-t02-ro-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const cli = runCliDiagnose(target);
  const mcp = await runMcpDiagnose(target);
  assert.equal(cli.result!.user_resolution.status, "DIAGNOSIS_COMPLETE");
  assert.notEqual(cli.result!.user_resolution.status, "RESOLVED_VERIFIED");
  assert.equal(cli.result!.repair_applied, false);
  assert.equal(mcp.repair_applied, false);
  assert.equal(cli.result!.target_mutated, false);
});

test("Ticket02: usage errors remain generic and path-free", () => {
  const res = runCliJson(["repair-apply"]);
  assert.notEqual(res.exitCode, 0);
  assert.ok(res.result);
  assert.equal(res.result!.error_code, "USAGE");
  assertNoLeakText(res.stdout);
});

// ---------------------------------------------------------------------------
// Adversarial RED/GREEN cases (Ticket 02 corrections)
// ---------------------------------------------------------------------------

test("Ticket02 adversarial: backup path redirect to incident.json is refused", () => {
  const tmp = makeTempDir("cg-t02-adv-backup-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0);
  const capsule = { ...(capsuleFields(preview.result!) as object) } as Record<
    string,
    unknown
  >;
  const backup = { ...(capsule.backup as object) } as Record<string, unknown>;
  backup.backup_rel = "incident.json"; // redirect attack
  capsule.backup = backup;
  // Tampered capsule must fail strict validation (binding + path constant).
  assert.throws(
    () => strictValidateCapsule(capsule),
    (e: unknown) => e instanceof AuthTokenError,
  );
  // Even if an attacker re-encodes with a forged binding field, apply rejects.
  const forgedToken =
    "cg1." +
    Buffer.from(
      JSON.stringify({
        v: 1,
        capsule: {
          ...capsule,
          authorization_binding: "0".repeat(64),
          invalidation_digest: "1".repeat(64),
        },
      }),
    ).toString("base64url");
  const apply = runCliRepairApply(target, forgedToken);
  assert.notEqual(apply.exitCode, 0);
  assert.equal(apply.result!.ok, false);
  assert.ok(
    apply.result!.error_code === "AUTH_INVALID" ||
      apply.result!.error_code === "AUTH_MALFORMED",
  );
  assert.equal(artifactSha(target), PROTECTED_ARTIFACT_SHA);
  // incident.json must remain intact (never used as backup target).
  const incidentPath = path.join(target, "incident.json");
  assert.equal(fs.existsSync(incidentPath), true);
  const incident = fs.readFileSync(incidentPath, "utf8");
  assert.ok(incident.length > 0);
  assert.equal(JSON.parse(incident).schema_version !== undefined || incident.length > 10, true);
});

test("Ticket02 adversarial: expected_result_sha256 null/removal is refused", () => {
  const tmp = makeTempDir("cg-t02-adv-hash-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0);
  const capsule = structuredClone(capsuleFields(preview.result!)) as Record<
    string,
    unknown
  >;
  const op = { ...(capsule.operation as object) } as Record<string, unknown>;

  op.expected_result_sha256 = null;
  capsule.operation = op;
  assert.throws(() => strictValidateCapsule(capsule), AuthTokenError);

  delete op.expected_result_sha256;
  capsule.operation = op;
  assert.throws(() => strictValidateCapsule(capsule), AuthTokenError);

  // Wrong expected hash also fails.
  const capsule2 = structuredClone(capsuleFields(preview.result!)) as Record<
    string,
    unknown
  >;
  const op2 = { ...(capsule2.operation as object) } as Record<string, unknown>;
  op2.expected_result_sha256 = "a".repeat(64);
  capsule2.operation = op2;
  assert.throws(() => strictValidateCapsule(capsule2), AuthTokenError);

  const forged =
    "cg1." +
    Buffer.from(JSON.stringify({ v: 1, capsule: capsule2 })).toString("base64url");
  const apply = runCliRepairApply(target, forged);
  assert.notEqual(apply.exitCode, 0);
  assert.equal(apply.result!.ok, false);
});

test("Ticket02 adversarial: extra capsule fields are refused", () => {
  const tmp = makeTempDir("cg-t02-adv-extra-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0);
  const capsule = structuredClone(capsuleFields(preview.result!)) as Record<
    string,
    unknown
  >;
  capsule.evil_field = "pwn";
  assert.throws(() => strictValidateCapsule(capsule), AuthTokenError);

  const op = { ...(capsule.operation as object) } as Record<string, unknown>;
  delete capsule.evil_field;
  // Restore a valid clone then inject extra operation field.
  const good = structuredClone(capsuleFields(preview.result!)) as Record<
    string,
    unknown
  >;
  const opGood = { ...(good.operation as object) } as Record<string, unknown>;
  opGood.extra_op = true;
  good.operation = opGood;
  assert.throws(() => strictValidateCapsule(good), AuthTokenError);

  const forged =
    "cg1." +
    Buffer.from(JSON.stringify({ v: 1, capsule: good })).toString("base64url");
  const apply = runCliRepairApply(target, forged);
  assert.notEqual(apply.exitCode, 0);
  assert.equal(apply.result!.ok, false);
  void op;
  void target;
});

test("Ticket02 adversarial: preview leaves whole-tree hash unchanged and no .changeguard", () => {
  const tmp = makeTempDir("cg-t02-adv-preview-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const before = hashTargetTree(target);
  assert.equal(fs.existsSync(path.join(target, ".changeguard")), false);

  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  assert.equal(preview.result!.target_mutated, false);
  assert.equal(hashTargetTree(target), before);
  assert.equal(fs.existsSync(path.join(target, ".changeguard")), false);
  assert.equal(
    fs.existsSync(path.join(target, ".changeguard", "capsule-preview.json")),
    false,
  );
  // Token is self-contained and round-trips without target state.
  const auth = authFromPreview(preview.result!);
  const decoded = decodeAuthorizationToken(auth);
  assert.equal(decoded.original_sha256, PROTECTED_ARTIFACT_SHA);
  assert.equal(decoded.authorization_binding, capsuleFields(preview.result!).authorization_binding);
});

test("Ticket02 adversarial: stale/expired/replayed token refused", () => {
  const tmp = makeTempDir("cg-t02-adv-replay-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0);
  const auth = authFromPreview(preview.result!);
  const originalSha = artifactSha(target);

  // Expired token: re-mint capsule with past expiry (strict validate recomputes binding).
  const capsule = decodeAuthorizationToken(auth);
  const expired = {
    ...capsule,
    expires_at: new Date(Date.now() - 60_000).toISOString(),
  };
  // Binding no longer matches after expiry change unless we rebuild — either way apply fails.
  assert.throws(() => encodeAuthorizationToken(expired as typeof capsule), AuthTokenError);

  // Apply once successfully.
  const apply1 = runCliRepairApply(target, auth);
  assert.equal(apply1.exitCode, 0, apply1.stdout);
  assert.equal(apply1.result!.repair_applied, true);
  const repairedSha = artifactSha(target);
  assert.notEqual(repairedSha, originalSha);

  // Replay same token after successful apply → refused.
  const replay = runCliRepairApply(target, auth);
  assert.notEqual(replay.exitCode, 0);
  assert.equal(replay.result!.ok, false);
  assert.ok(
    replay.result!.error_code === "AUTH_REPLAY" ||
      replay.result!.error_code === "AUTH_INVALID",
  );

  // After rollback, same token still must not re-apply (consumed).
  const rb = runCliRollback(target);
  assert.equal(rb.exitCode, 0, rb.stdout);
  assert.equal(artifactSha(target), originalSha);
  const afterRb = runCliRepairApply(target, auth);
  assert.notEqual(afterRb.exitCode, 0);
  assert.equal(afterRb.result!.ok, false);
  assert.ok(
    afterRb.result!.error_code === "AUTH_REPLAY" ||
      afterRb.result!.error_code === "AUTH_INVALID",
  );

  // Fresh preview mints a new token that can apply on restored target.
  const preview2 = runCliRepairPreview(target);
  assert.equal(preview2.exitCode, 0);
  const auth2 = authFromPreview(preview2.result!);
  assert.notEqual(auth2, auth);
  const apply2 = runCliRepairApply(target, auth2);
  assert.equal(apply2.exitCode, 0, apply2.stdout);
  assert.equal(apply2.result!.repair_applied, true);
});

test("Ticket02 adversarial: recovery rmSync/copyFileSync and non-atomic write rejected by boundary", () => {
  // Boundary self-test covers synthetic recovery-atomic-write forbidden methods
  // and non-atomic recovery module writes. Run the dedicated self-test binary.
  const res = spawnSync(
    process.execPath,
    [path.join(process.cwd(), "scripts/check-production-boundary.mjs"), "--self-test"],
    { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } },
  );
  assert.equal(res.status, 0, res.stdout + res.stderr);
  // Production scan must also pass (atomic-write only exemption).
  const prod = spawnSync(
    process.execPath,
    [path.join(process.cwd(), "scripts/check-production-boundary.mjs")],
    { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } },
  );
  assert.equal(prod.status, 0, prod.stdout + prod.stderr);
});
