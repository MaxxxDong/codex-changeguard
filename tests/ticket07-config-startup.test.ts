/**
 * Ticket 07 Scenario Harness — config/schema-drift/startup fault pack.
 * Black-box via public CLI/MCP seams; owns target hash proofs.
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
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import { INDUCE_VERIFY_FAIL_REL } from "../src/core/recovery/index.js";
import { makeTempDir } from "./helpers.js";

function assertNoLeakText(text: string): void {
  assert.equal(/\/Users\//.test(text), false, "absolute Users path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text), false, "Bearer leak");
  assert.equal(/project-source-must-not-be-read/.test(text), false, "project secret leak");
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

const FAULT_CLASSES = [
  "ConfigTomlSyntaxError",
  "ConfigSchemaTypeError",
  "ConfigObsoleteKeyError",
  "ConfigSourceConflictError",
] as const;

test("Ticket07: distinct fingerprints for four config fault classes", () => {
  const cases: { fixture: string; fault: string }[] = [
    { fixture: "fixtures/config-invalid-toml", fault: "ConfigTomlSyntaxError" },
    { fixture: "fixtures/config-wrong-type", fault: "ConfigSchemaTypeError" },
    { fixture: "fixtures/config-obsolete-key", fault: "ConfigObsoleteKeyError" },
    { fixture: "fixtures/config-source-conflict", fault: "ConfigSourceConflictError" },
  ];
  const digests = new Set<string>();
  const classes = new Set<string>();
  for (const c of cases) {
    const tmp = makeTempDir("cg-t07-fp-");
    const target = copyFixtureToTemp(c.fixture, tmp);
    const before = hashTargetTree(target);
    const { exitCode, result, stdout } = runCliDiagnose(target);
    assert.equal(exitCode, 0, stdout);
    assert.ok(result);
    assert.equal(result!.ok, true);
    assert.equal(result!.diagnosis_state, "SOURCE_COMPONENT_LOCATED");
    assert.equal(result!.repair_applied, false);
    assert.equal(result!.target_mutated, false);
    const fp = result!.incident_fingerprint as {
      error: { class: string };
      failure_phase: string;
      local_facts_digest: string;
      config_keys?: string[];
    };
    assert.equal(fp.error.class, c.fault);
    assert.equal(fp.failure_phase, "startup");
    classes.add(fp.error.class);
    digests.add(fp.local_facts_digest);
    assertNoLeakText(stdout);
    assert.equal(hashTargetTree(target), before, "diagnose must not mutate");
  }
  assert.equal(classes.size, 4, "four distinct fault classes");
  assert.equal(digests.size, 4, "four distinct local_facts digests");
  for (const f of FAULT_CLASSES) assert.ok(classes.has(f));
});

test("Ticket07: valid fix path config_set → RESOLVED_VERIFIED with startup verification", () => {
  const tmp = makeTempDir("cg-t07-ok-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const configPath = path.join(target, "config/config.toml");
  const original = fs.readFileSync(configPath);
  const beforeTree = hashTargetTree(target);

  const diag = runCliDiagnose(target);
  assert.equal(diag.exitCode, 0);
  assert.equal(
    (diag.result!.incident_fingerprint as { error: { class: string } }).error
      .class,
    "ConfigSchemaTypeError",
  );

  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  assert.equal(preview.result!.ok, true);
  assert.equal(
    (preview.result!.user_resolution as { status: string }).status,
    "REPAIR_PREVIEWED",
  );
  const capsule = capsuleFields(preview.result!);
  assert.equal(capsule.target_path_alias, "CODEX_CONFIG_PRIMARY");
  const op = capsule.operation as Record<string, unknown>;
  assert.equal(op.kind, "config_set");
  assert.equal(op.config_key, "shell_environment_policy.set");
  assert.equal(typeof op.old_value_type, "string");
  assert.equal(typeof op.old_value_summary, "string");
  assert.equal(op.new_value, "{}");
  assert.match(String(op.old_value_summary), /redacted|string|table/i);
  // Secret path content must not appear.
  assert.equal(String(op.old_value_summary).includes("/usr/bin"), false);
  assert.ok(capsule.backup && capsule.verification && capsule.rollback);
  assert.equal(hashTargetTree(target), beforeTree, "preview read-only");
  assert.equal(fs.existsSync(path.join(target, ".changeguard")), false);

  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  assert.equal(apply.result!.ok, true);
  assert.equal(apply.result!.repair_applied, true);
  assert.equal(apply.result!.auto_rolled_back, false);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
  const after = fs.readFileSync(configPath);
  assert.notEqual(after.equals(original), true);
  assert.match(after.toString("utf8"), /set\s*=\s*\{\s*\}/);
  const verification = apply.result!.verification as {
    passed: boolean;
    checks: { id: string; passed: boolean }[];
  };
  assert.equal(verification.passed, true);
  const ids = new Set(verification.checks.map((c) => c.id));
  assert.ok(ids.has("original_failure_absent"));
  assert.ok(ids.has("config_reload"));
  assert.ok(ids.has("registered_command"));
  assertNoLeakText(apply.stdout);

  const verify = runCliVerify(target);
  assert.equal(verify.exitCode, 0);
  assert.equal(
    (verify.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
});

test("Ticket07: wrong candidate (negative control) refuses config repair", () => {
  const tmp = makeTempDir("cg-t07-neg-");
  const target = copyFixtureToTemp("fixtures/negative-control", tmp);
  const before = hashTargetTree(target);
  const preview = runCliRepairPreview(target);
  assert.notEqual(preview.exitCode, 0);
  assert.equal(preview.result!.ok, false);
  assert.equal(preview.result!.error_code, "NOT_APPLICABLE");
  assert.equal(
    (preview.result!.user_resolution as { status: string }).status,
    "REPAIR_REFUSED",
  );
  assert.equal(hashTargetTree(target), before);
});

test("Ticket07: managed policy returns ADMIN_ACTION_REQUIRED with IT handoff", () => {
  const tmp = makeTempDir("cg-t07-admin-");
  const target = copyFixtureToTemp("fixtures/config-managed-policy", tmp);
  const before = hashTargetTree(target);
  const preview = runCliRepairPreview(target);
  assert.notEqual(preview.exitCode, 0);
  assert.equal(preview.result!.ok, false);
  assert.equal(preview.result!.error_code, "ADMIN_ACTION_REQUIRED");
  assert.equal(
    (preview.result!.user_resolution as { status: string }).status,
    "ADMIN_ACTION_REQUIRED",
  );
  const handoff = preview.result!.admin_handoff as Record<string, unknown>;
  assert.ok(handoff);
  assert.equal(handoff.policy_class, "enterprise_mdm");
  assert.equal(handoff.admin_owned, true);
  assert.equal(handoff.signed, true);
  assert.equal(handoff.permission_bound, true);
  assert.equal(typeof handoff.requested_action, "string");
  assert.equal(preview.result!.capsule, null);
  assert.equal(preview.result!.authorization, null);
  // Must not offer privilege-elevation or policy-circumvention operations.
  assert.equal(/chmod|disable.?security|sudo|setfacl/i.test(preview.stdout), false);
  assert.equal(hashTargetTree(target), before);
  assertNoLeakText(preview.stdout);
});

test("Ticket07: induced verification failure auto-rollbacks config repair", () => {
  const tmp = makeTempDir("cg-t07-ind-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const configPath = path.join(target, "config/config.toml");
  const original = fs.readFileSync(configPath);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0);
  const auth = authFromPreview(preview.result!);
  // Plant harness sentinel before apply.
  fs.mkdirSync(path.join(target, ".changeguard"), { recursive: true });
  fs.writeFileSync(path.join(target, INDUCE_VERIFY_FAIL_REL), "1\n");
  const apply = runCliRepairApply(target, auth);
  assert.notEqual(apply.exitCode, 0);
  assert.equal(apply.result!.ok, false);
  assert.equal(apply.result!.error_code, "VERIFY_FAILED");
  assert.equal(apply.result!.auto_rolled_back, true);
  assert.equal(apply.result!.repair_applied, false);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "REPAIR_FAILED_ROLLED_BACK",
  );
  assert.ok(original.equals(fs.readFileSync(configPath)));
});

test("Ticket07: obsolete key config_remove repair path", () => {
  const tmp = makeTempDir("cg-t07-obs-");
  const target = copyFixtureToTemp("fixtures/config-obsolete-key", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  const op = (capsuleFields(preview.result!).operation as Record<string, unknown>);
  assert.equal(op.kind, "config_remove");
  assert.equal(op.config_key, "legacy_experimental_shell");
  assert.equal(op.new_value, null);
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
  const text = fs.readFileSync(path.join(target, "config/config.toml"), "utf8");
  assert.equal(/legacy_experimental_shell/.test(text), false);
});

test("Ticket07: source-conflict remove on override", () => {
  const tmp = makeTempDir("cg-t07-sc-");
  const target = copyFixtureToTemp("fixtures/config-source-conflict", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  const capsule = capsuleFields(preview.result!);
  assert.equal(capsule.target_path_alias, "CODEX_CONFIG_OVERRIDE");
  const op = capsule.operation as Record<string, unknown>;
  assert.equal(op.kind, "config_remove");
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
});

test("Ticket07: invalid TOML is diagnosed but not auto-repaired", () => {
  const tmp = makeTempDir("cg-t07-syn-");
  const target = copyFixtureToTemp("fixtures/config-invalid-toml", tmp);
  const diag = runCliDiagnose(target);
  assert.equal(diag.exitCode, 0);
  assert.equal(
    (diag.result!.incident_fingerprint as { error: { class: string } }).error
      .class,
    "ConfigTomlSyntaxError",
  );
  const preview = runCliRepairPreview(target);
  assert.notEqual(preview.exitCode, 0);
  assert.equal(preview.result!.error_code, "NOT_APPLICABLE");
});

test("Ticket07: no project source read (sentinel intact + absent from output)", () => {
  const tmp = makeTempDir("cg-t07-proj-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const secretPath = path.join(target, "src/secret.ts");
  const beforeSecret = fs.readFileSync(secretPath);
  const beforeMtime = fs.statSync(secretPath).mtimeMs;
  const diag = runCliDiagnose(target);
  assert.equal(diag.exitCode, 0);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0);
  assert.ok(beforeSecret.equals(fs.readFileSync(secretPath)));
  assert.equal(fs.statSync(secretPath).mtimeMs, beforeMtime);
  assertNoLeakText(diag.stdout + preview.stdout);
});

test("Ticket07: symlink config path refused", () => {
  const tmp = makeTempDir("cg-t07-sym-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const realConfig = path.join(target, "config/config.toml");
  const outside = path.join(tmp, "outside.toml");
  fs.writeFileSync(outside, 'model = "x"\n');
  fs.unlinkSync(realConfig);
  fs.symlinkSync(outside, realConfig);
  const diag = runCliDiagnose(target);
  assert.notEqual(diag.exitCode, 0);
  assert.ok(
    diag.result!.error_code === "SYMLINK_ESCAPE" ||
      diag.result!.error_code === "PATH_ESCAPE",
  );
});

test("Ticket07: path escape candidate refused via parent segments", () => {
  // Diagnose only reads registered names; craft a target that is itself a symlink.
  const tmp = makeTempDir("cg-t07-esc-");
  const real = path.join(tmp, "real");
  fs.mkdirSync(real);
  fs.writeFileSync(
    path.join(real, "incident.json"),
    fs.readFileSync("fixtures/config-wrong-type/incident.json"),
  );
  const link = path.join(tmp, "link-target");
  fs.symlinkSync(real, link);
  const diag = runCliDiagnose(link);
  assert.notEqual(diag.exitCode, 0);
  assert.equal(diag.result!.error_code, "SYMLINK_ESCAPE");
});

test("Ticket07: replay after successful apply refused", () => {
  const tmp = makeTempDir("cg-t07-replay-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  const apply1 = runCliRepairApply(target, auth);
  assert.equal(apply1.exitCode, 0);
  const apply2 = runCliRepairApply(target, auth);
  assert.notEqual(apply2.exitCode, 0);
  assert.ok(
    apply2.result!.error_code === "AUTH_REPLAY" ||
      apply2.result!.error_code === "AUTH_INVALID" ||
      apply2.result!.error_code === "NOT_APPLICABLE",
  );
});

test("Ticket07: TOCTOU hash change after preview refuses apply", () => {
  const tmp = makeTempDir("cg-t07-toc-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  fs.appendFileSync(path.join(target, "config/config.toml"), "\n# drift\n");
  const apply = runCliRepairApply(target, auth);
  assert.notEqual(apply.exitCode, 0);
  assert.ok(
    apply.result!.error_code === "AUTH_INVALID" ||
      apply.result!.error_code === "NOT_APPLICABLE",
  );
});

test("Ticket07: CLI/MCP diagnose equivalence for config fault", async () => {
  const tmp = makeTempDir("cg-t07-mcp-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const cli = runCliDiagnose(target);
  assert.equal(cli.exitCode, 0);
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    const mcp = await client.callTool("changeguard_diagnose", { target });
    assert.equal(mcp.ok, true);
    const cliFp = cli.result!.incident_fingerprint as {
      error: { class: string };
      failure_phase: string;
    };
    const mcpFp = mcp.incident_fingerprint as typeof cliFp;
    assert.equal(mcpFp.error.class, cliFp.error.class);
    assert.equal(mcpFp.failure_phase, cliFp.failure_phase);
    assert.equal(mcp.diagnosis_state, cli.result!.diagnosis_state);
  } finally {
    await client.close();
  }
});

test("Ticket07: CLI/MCP repair-preview equivalence for config_set", async () => {
  const tmp = makeTempDir("cg-t07-mcp-rp-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const cli = runCliRepairPreview(target);
  assert.equal(cli.exitCode, 0);
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    const mcp = await client.callTool("changeguard_repair_preview", { target });
    assert.equal(mcp.ok, true);
    const cliOp = (cli.result!.capsule as { operation: { kind: string; config_key: string } })
      .operation;
    const mcpOp = (mcp.capsule as { operation: { kind: string; config_key: string } })
      .operation;
    assert.equal(mcpOp.kind, cliOp.kind);
    assert.equal(mcpOp.config_key, cliOp.config_key);
  } finally {
    await client.close();
  }
});

test("Ticket07: explicit rollback after config repair restores original bytes", () => {
  const tmp = makeTempDir("cg-t07-rb-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const configPath = path.join(target, "config/config.toml");
  const original = fs.readFileSync(configPath);
  const preview = runCliRepairPreview(target);
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0);
  assert.notEqual(fs.readFileSync(configPath).equals(original), true);
  const rb = runCliRollback(target);
  assert.equal(rb.exitCode, 0, rb.stdout);
  assert.equal(
    (rb.result!.user_resolution as { status: string }).status,
    "MITIGATED_VERIFIED_BY_ROLLBACK",
  );
  assert.ok(fs.readFileSync(configPath).equals(original));
});

test("Ticket07: prior ticket protected-process repair still works", () => {
  const tmp = makeTempDir("cg-t07-reg-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stdout);
  const op = (capsuleFields(preview.result!).operation as { kind: string });
  assert.equal(op.kind, "exact_block_removal");
  const auth = authFromPreview(preview.result!);
  const apply = runCliRepairApply(target, auth);
  assert.equal(apply.exitCode, 0, apply.stdout);
  assert.equal(
    (apply.result!.user_resolution as { status: string }).status,
    "RESOLVED_VERIFIED",
  );
});

test("Ticket07: oversized config file fails closed", () => {
  const tmp = makeTempDir("cg-t07-size-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const big = "x".repeat(65 * 1024);
  fs.writeFileSync(path.join(target, "config/config.toml"), big);
  const diag = runCliDiagnose(target);
  // Size limit may surface as syntax-class fault or SIZE_LIMIT.
  assert.ok(diag.result);
  if (diag.exitCode === 0) {
    const cls = (diag.result!.incident_fingerprint as { error: { class: string } })
      .error.class;
    assert.equal(cls, "ConfigTomlSyntaxError");
  } else {
    assert.ok(
      diag.result!.error_code === "SIZE_LIMIT" ||
        diag.result!.error_code === "CONFIG_PROBE_ERROR",
    );
  }
});

test("Ticket07: malformed incident still fails closed (regression)", () => {
  const tmp = makeTempDir("cg-t07-mal-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  fs.writeFileSync(path.join(target, "incident.json"), "{not-json");
  const diag = runCliDiagnose(target);
  assert.notEqual(diag.exitCode, 0);
  assert.ok(diag.result!.error_code === "MALFORMED_JSON" || diag.result!.ok === false);
});
