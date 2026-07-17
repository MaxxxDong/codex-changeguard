/**
 * Ticket 08 Scenario Harness — plugin cache / version-skew / reconciliation.
 * Black-box via public CLI/MCP seams; owns target hash proofs for apply/rollback.
 * Covers four mechanisms, negative control, recurrence, repair, auto-rollback,
 * explicit rollback, path/symlink/oversize, CLI/MCP equivalence, Ticket 01–04 regressions.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  copyFixtureToTemp,
  hashTargetTree,
  mcpServerEntry,
  runCliDiagnose,
  runCliRepairApply,
  runCliRepairPreview,
  runCliRollback,
  runCliVerify,
  runMcpDiagnose,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import { sha256Buffer } from "../src/core/measure.js";
import {
  decodeAuthorizationToken,
  encodeAuthorizationToken,
  AuthTokenError,
} from "../src/core/recovery/auth-token.js";
import { INDUCE_VERIFY_FAIL_REL } from "../src/core/recovery/index.js";
import { registeredBackupRel } from "../src/core/recovery/types.js";
import { makeTempDir } from "./helpers.js";

const CACHE_REL = "plugin-cache/cache/entry.js";
const MANIFEST_REL = "plugin-cache/manifest.json";
const MECHANISMS = [
  "bundled_file_corruption",
  "stale_shared_cache",
  "dependency_version_skew",
  "reconciliation_overwrite",
] as const;

function cacheSha(target: string): string {
  return sha256Buffer(fs.readFileSync(path.join(target, CACHE_REL)));
}

function manifestSha(target: string): string {
  return sha256Buffer(fs.readFileSync(path.join(target, MANIFEST_REL)));
}

function assertNoLeakText(text: string): void {
  assert.equal(/\/Users\//.test(text), false, "absolute Users path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text), false, "Bearer leak");
}

function mechanismFromResult(result: Record<string, unknown>): string | null {
  const evidence = result.evidence as Array<{ kind?: string; detail?: string }> | undefined;
  if (!Array.isArray(evidence)) return null;
  for (const e of evidence) {
    if (e.kind === "plugin_cache_mechanism" && typeof e.detail === "string") {
      const m = e.detail.match(/mechanism=([a-z_]+)/);
      if (m) return m[1]!;
    }
  }
  return null;
}

function authFromPreview(result: Record<string, unknown>): string {
  const auth = result.authorization;
  assert.equal(typeof auth, "string");
  assert.ok(String(auth).startsWith("cg1."));
  return String(auth);
}

function capsuleFields(result: Record<string, unknown>) {
  const capsule = result.capsule as Record<string, unknown> | null;
  assert.ok(capsule, "capsule required");
  return capsule;
}

// ---- Four mechanism classification ----

for (const [fixture, expected] of [
  ["corruption", "bundled_file_corruption"],
  ["stale-cache", "stale_shared_cache"],
  ["version-skew", "dependency_version_skew"],
  ["reconciliation", "reconciliation_overwrite"],
] as const) {
  test(`Ticket08: diagnose classifies ${fixture} as ${expected}`, () => {
    const tmp = makeTempDir(`cg-t08-diag-${fixture}-`);
    const target = copyFixtureToTemp(`fixtures/plugin-cache/${fixture}`, tmp);
    const before = hashTargetTree(target);
    const { exitCode, result, stdout } = runCliDiagnose(target);
    assert.equal(exitCode, 0, stdout);
    assert.ok(result);
    assert.equal(result!.diagnosis_state, "SOURCE_COMPONENT_LOCATED");
    assert.equal(result!.repair_applied, false);
    assert.equal(result!.target_mutated, false);
    assert.equal(result!.network_used, false);
    assert.equal(mechanismFromResult(result! as unknown as Record<string, unknown>), expected);
    assert.equal(hashTargetTree(target), before, "diagnose must not mutate");
    assertNoLeakText(stdout);
    // Explicitly distinguishes from generic dependency-install failure.
    assert.match(
      String((result!.user_resolution as { summary: string }).summary),
      /Not a generic dependency-install failure/,
    );
    assert.equal(
      String((result!.user_resolution as { summary: string }).summary).includes(
        "classified as dependency_install",
      ),
      false,
    );
  });
}

test("Ticket08: negative control (dependency-install-like) is INCONCLUSIVE", () => {
  const tmp = makeTempDir("cg-t08-neg-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/negative-control", tmp);
  const before = hashTargetTree(target);
  const { exitCode, result, stdout } = runCliDiagnose(target);
  assert.equal(exitCode, 0, stdout);
  assert.ok(result);
  assert.equal(result!.diagnosis_state, "INCONCLUSIVE");
  assert.equal(mechanismFromResult(result! as unknown as Record<string, unknown>), null);
  assert.equal(result!.repair_applied, false);
  assert.equal(hashTargetTree(target), before);
  assertNoLeakText(stdout);
  // No four-mechanism claim.
  for (const m of MECHANISMS) {
    assert.equal(JSON.stringify(result).includes(`mechanism=${m}`), false);
  }
});

/**
 * P1-B: trusted_verified must compare trusted_entry.measured_sha256 to
 * manifest.rebuild_source.expected_sha256. Mismatch must not be overstated
 * as verified; repair remains refused. Path/symlink/digest/provenance gates
 * stay tight.
 */
test("Ticket08 P1-B: trusted rebuild mismatch reports trusted_verified=false and refuses repair", () => {
  const tmp = makeTempDir("cg-t08-trusted-mm-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const trustedPath = path.join(target, "plugin-cache/trusted/entry.js");
  // Mutate trusted rebuild source so measured hash ≠ manifest expectation.
  fs.writeFileSync(
    trustedPath,
    "// untrusted / mismatched rebuild source bytes\nexport const VERSION = 'bad';\n",
  );
  const before = hashTargetTree(target);
  const { exitCode, result, stdout } = runCliDiagnose(target);
  assert.equal(exitCode, 0, stdout);
  assert.ok(result);
  const evidence = result!.evidence as Array<{ kind?: string; detail?: string }>;
  const manifestEv = evidence.find((e) => e.kind === "plugin_cache_manifest_relation");
  assert.ok(manifestEv, "plugin_cache_manifest_relation evidence required");
  assert.match(String(manifestEv!.detail), /trusted_verified=false/);
  assert.equal(
    String(manifestEv!.detail).includes("trusted_verified=true"),
    false,
    "must not overstate trusted verification on hash mismatch",
  );
  // Corruption mechanism requires trusted match — do not claim it.
  assert.equal(
    mechanismFromResult(result! as unknown as Record<string, unknown>),
    null,
  );
  assert.notEqual(result!.diagnosis_state, "SOURCE_COMPONENT_LOCATED");
  assert.equal(result!.repair_applied, false);
  assert.equal(result!.target_mutated, false);
  assert.equal(hashTargetTree(target), before, "diagnose must not mutate");

  const preview = runCliRepairPreview(target);
  assert.notEqual(preview.exitCode, 0);
  assert.equal(preview.result!.ok, false);
  assert.ok(
    preview.result!.error_code === "NOT_APPLICABLE" ||
      preview.result!.error_code === "TRUSTED_SOURCE_MISMATCH" ||
      (preview.result!.user_resolution as { status?: string } | null)?.status ===
        "REPAIR_REFUSED",
  );
  assertNoLeakText(stdout);
  assertNoLeakText(preview.stdout);
});

test("Ticket08 P1-B: matching trusted rebuild reports trusted_verified=true", () => {
  const tmp = makeTempDir("cg-t08-trusted-ok-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const { exitCode, result, stdout } = runCliDiagnose(target);
  assert.equal(exitCode, 0, stdout);
  assert.ok(result);
  const evidence = result!.evidence as Array<{ kind?: string; detail?: string }>;
  const manifestEv = evidence.find((e) => e.kind === "plugin_cache_manifest_relation");
  assert.ok(manifestEv);
  assert.match(String(manifestEv!.detail), /trusted_verified=true/);
  assert.equal(
    mechanismFromResult(result! as unknown as Record<string, unknown>),
    "bundled_file_corruption",
  );
});

// ---- Successful repair path ----

test("Ticket08: successful repair preview → apply → RESOLVED_VERIFIED (corruption)", () => {
  const tmp = makeTempDir("cg-t08-ok-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const originalCache = cacheSha(target);
  const originalManifest = manifestSha(target);
  const beforeTree = hashTargetTree(target);

  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  assert.ok(preview.result);
  assert.equal(preview.result!.ok, true);
  assert.equal(preview.result!.operation, "preview");
  assert.equal(preview.result!.target_mutated, false);
  assert.equal(
    (preview.result!.user_resolution as { status: string }).status,
    "REPAIR_PREVIEWED",
  );
  const capsule = capsuleFields(preview.result!);
  assert.equal(capsule.target_path_alias, "PLUGIN_CACHE_ENTRY");
  assert.equal(capsule.original_sha256, originalCache);
  assert.equal((capsule.operation as { kind: string }).kind, "verified_resource_copy");
  assert.equal(
    (capsule.backup as { backup_rel: string }).backup_rel,
    registeredBackupRel("PLUGIN_CACHE_ENTRY"),
  );
  assert.equal(hashTargetTree(target), beforeTree, "preview read-only");
  assert.equal(fs.existsSync(path.join(target, ".changeguard")), false);
  assertNoLeakText(preview.stdout);

  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  assert.ok(apply.result);
  assert.equal(apply.result!.ok, true);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
  assert.equal(apply.result!.repair_applied, true);
  assert.equal(apply.result!.auto_rolled_back, false);
  assert.notEqual(cacheSha(target), originalCache);
  assert.equal(manifestSha(target), originalManifest, "manifest bytes preserved on success");
  assertNoLeakText(apply.stdout);

  const verify = runCliVerify(target);
  assert.equal(verify.exitCode, 0, verify.stdout);
  assert.equal(
    (verify.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
});

// ---- Recurrence after reconciliation ----

test("Ticket08: recurrence after reconciliation cannot yield RESOLVED_VERIFIED", () => {
  const tmp = makeTempDir("cg-t08-recur-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/reconciliation-recurs", tmp);
  const originalCache = cacheSha(target);
  const originalManifest = manifestSha(target);

  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.notEqual(apply.exitCode, 0, apply.stdout);
  assert.ok(apply.result);
  assert.equal(apply.result!.ok, false);
  assert.equal(apply.result!.auto_rolled_back, true);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "REPAIR_FAILED_ROLLED_BACK",
  );
  assert.notEqual(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
  assert.equal(cacheSha(target), originalCache, "auto-rollback restores cache");
  assert.equal(manifestSha(target), originalManifest, "auto-rollback restores manifest");
  assert.ok(
    apply.result!.error_code === "RECURRENCE_BLOCKED" ||
      apply.result!.error_code === "VERIFY_FAILED",
  );
});

// ---- Induced verify fail auto-rollback ----

test("Ticket08: induced verification failure auto-rollbacks exact cache+manifest", () => {
  const tmp = makeTempDir("cg-t08-ind-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/stale-cache", tmp);
  const originalCache = cacheSha(target);
  const originalManifest = manifestSha(target);

  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  const auth = authFromPreview(preview.result!);

  fs.mkdirSync(path.join(target, ".changeguard"), { recursive: true });
  fs.writeFileSync(path.join(target, INDUCE_VERIFY_FAIL_REL), "force\n");

  const apply = runCliRepairApply(target, auth);
  assert.notEqual(apply.exitCode, 0);
  assert.equal(apply.result!.auto_rolled_back, true);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "REPAIR_FAILED_ROLLED_BACK",
  );
  assert.equal(cacheSha(target), originalCache);
  assert.equal(manifestSha(target), originalManifest);
});

// ---- Explicit rollback ----

test("Ticket08: explicit rollback restores exact original cache+manifest hashes", () => {
  const tmp = makeTempDir("cg-t08-rb-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/version-skew", tmp);
  const originalCache = cacheSha(target);
  const originalManifest = manifestSha(target);

  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
  assert.notEqual(cacheSha(target), originalCache);

  const rb = runCliRollback(target);
  assert.equal(rb.exitCode, 0, rb.stdout);
  assert.equal(
    (rb.result!.user_resolution as { status: string }).status,
    "MITIGATED_VERIFIED_BY_ROLLBACK",
  );
  assert.equal(cacheSha(target), originalCache);
  assert.equal(manifestSha(target), originalManifest);
  assert.equal(rb.result!.repair_applied, false);
});

// ---- Negative control refuses repair ----

test("Ticket08: negative control refuses repair preview", () => {
  const tmp = makeTempDir("cg-t08-neg-repair-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/negative-control", tmp);
  const preview = runCliRepairPreview(target);
  assert.notEqual(preview.exitCode, 0);
  assert.equal(preview.result!.ok, false);
  assert.ok(
    preview.result!.error_code === "NOT_APPLICABLE" ||
      (preview.result!.user_resolution as { status: string }).status === "REPAIR_REFUSED",
  );
});

// ---- CLI/MCP equivalence ----

test("Ticket08: CLI/MCP diagnose equivalence for version-skew", async () => {
  const tmp = makeTempDir("cg-t08-eq-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/version-skew", tmp);
  const cli = runCliDiagnose(target);
  const mcp = await runMcpDiagnose(target);
  assert.equal(cli.exitCode, 0);
  assert.equal(cli.result!.diagnosis_state, mcp.diagnosis_state);
  assert.equal(
    mechanismFromResult(cli.result! as unknown as Record<string, unknown>),
    mechanismFromResult(mcp as unknown as Record<string, unknown>),
  );
  assert.equal(cli.result!.network_used, false);
  assert.equal(mcp.network_used, false);
});

test("Ticket08: CLI/MCP repair-preview capsule stable fields", async () => {
  const tmp = makeTempDir("cg-t08-eq-prev-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const cli = runCliRepairPreview(target);
  assert.equal(cli.exitCode, 0, cli.stdout);
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const mcp = (await client.callTool("changeguard_repair_preview", {
      target,
    })) as Record<string, unknown>;
    const cCli = capsuleFields(cli.result!);
    const cMcp = capsuleFields(mcp);
    assert.equal(cCli.capsule_id, cMcp.capsule_id);
    assert.equal(cCli.target_path_alias, cMcp.target_path_alias);
    assert.equal(cCli.original_sha256, cMcp.original_sha256);
    assert.equal(
      (cCli.operation as { kind: string }).kind,
      (cMcp.operation as { kind: string }).kind,
    );
  } finally {
    await client.close();
  }
});

// ---- Adversarial path / symlink / oversize ----

test("Ticket08: symlink cache entry refused", () => {
  const tmp = makeTempDir("cg-t08-sym-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const cachePath = path.join(target, CACHE_REL);
  fs.unlinkSync(cachePath);
  fs.symlinkSync("/etc/hosts", cachePath);
  const diag = runCliDiagnose(target);
  assert.notEqual(diag.exitCode, 0);
  assert.equal(diag.result!.ok, false);
});

test("Ticket08: oversize inventory refused", () => {
  const tmp = makeTempDir("cg-t08-osz-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const inv = path.join(target, "plugin-cache/inventory.json");
  fs.writeFileSync(inv, "x".repeat(40 * 1024));
  const diag = runCliDiagnose(target);
  assert.notEqual(diag.exitCode, 0);
  assert.equal(diag.result!.ok, false);
});

test("Ticket08: tampered backup fails closed on rollback", () => {
  const tmp = makeTempDir("cg-t08-tamp-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);

  const bak = path.join(
    target,
    registeredBackupRel("PLUGIN_CACHE_ENTRY"),
  );
  assert.ok(fs.existsSync(bak));
  fs.writeFileSync(bak, "tampered-backup-bytes\n");

  const rb = runCliRollback(target);
  assert.notEqual(rb.exitCode, 0);
  assert.equal(rb.result!.ok, false);
  assert.ok(
    rb.result!.error_code === "BACKUP_MISMATCH" ||
      rb.result!.error_code === "ROLLBACK_MISMATCH" ||
      rb.result!.error_code === "ROLLBACK_ERROR",
  );
});

test("Ticket08: stale authorization refused after target change", () => {
  const tmp = makeTempDir("cg-t08-stale-auth-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  // Mutate cache so original hash no longer matches.
  fs.writeFileSync(path.join(target, CACHE_REL), "// mutated after preview\n");
  const apply = runCliRepairApply(target, auth);
  assert.notEqual(apply.exitCode, 0);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "REPAIR_REFUSED",
  );
});

test("Ticket08: successful apply consumes token (replay refused)", () => {
  const tmp = makeTempDir("cg-t08-replay-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/stale-cache", tmp);
  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  const apply1 = runCliRepairApply(target, auth);
  assert.equal(apply1.exitCode, 0, apply1.stdout);
  // After resolve, cache matches trusted — second apply with same token fails.
  const apply2 = runCliRepairApply(target, auth);
  assert.notEqual(apply2.exitCode, 0);
  assert.ok(
    apply2.result!.error_code === "AUTH_REPLAY" ||
      apply2.result!.error_code === "AUTH_INVALID" ||
      apply2.result!.error_code === "NOT_APPLICABLE",
  );
});

// ---- Prior ticket regressions (smoke) ----

test("Ticket08 regression: protected-process diagnose still works", () => {
  const tmp = makeTempDir("cg-t08-reg-pp-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const { exitCode, result } = runCliDiagnose(target);
  assert.equal(exitCode, 0);
  assert.equal(result!.diagnosis_state, "SOURCE_COMPONENT_LOCATED");
});

test("Ticket08 regression: negative-control diagnose remains INCONCLUSIVE", () => {
  const tmp = makeTempDir("cg-t08-reg-nc-");
  const target = copyFixtureToTemp("fixtures/negative-control", tmp);
  const { exitCode, result } = runCliDiagnose(target);
  assert.equal(exitCode, 0);
  assert.equal(result!.diagnosis_state, "INCONCLUSIVE");
});

test("Ticket08 regression: protected-process repair still resolves", () => {
  const tmp = makeTempDir("cg-t08-reg-pp-r-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
});

test("Ticket08: all four mechanisms are distinct under parallel fixtures", () => {
  const seen = new Set<string>();
  for (const fixture of [
    "corruption",
    "stale-cache",
    "version-skew",
    "reconciliation",
  ] as const) {
    const tmp = makeTempDir(`cg-t08-dist-${fixture}-`);
    const target = copyFixtureToTemp(`fixtures/plugin-cache/${fixture}`, tmp);
    const { result } = runCliDiagnose(target);
    const m = mechanismFromResult(result! as unknown as Record<string, unknown>);
    assert.ok(m);
    seen.add(m!);
  }
  assert.equal(seen.size, 4);
  for (const m of MECHANISMS) assert.ok(seen.has(m), m);
});

test("Ticket08: authorization token rejects unknown operation kind", () => {
  const tmp = makeTempDir("cg-t08-tok-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  const capsule = decodeAuthorizationToken(auth);
  const mutated = {
    ...capsule,
    operation: { ...capsule.operation, kind: "exact_block_removal" as const },
  };
  assert.throws(() => encodeAuthorizationToken(mutated as typeof capsule), AuthTokenError);
});

test("Ticket08: no package-manager / recursive-delete claims in public output", () => {
  const tmp = makeTempDir("cg-t08-claims-");
  const target = copyFixtureToTemp("fixtures/plugin-cache/corruption", tmp);
  const preview = runCliRepairPreview(target);
  const text = preview.stdout.toLowerCase();
  assert.equal(text.includes("npm install"), false);
  assert.equal(text.includes("rm -rf"), false);
  assert.equal(text.includes("recursive delete"), false);
});
