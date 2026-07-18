/**
 * Ticket 06 Scenario Harness — KNOWN_GOOD, retention, A/B regression,
 * exact-instance surface rollback, CLI/Desktop provenance, canary, supersession.
 * Black-box via public CLI/MCP seams; adversarial integrity probes included.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  copyFixtureToTemp,
  mcpServerEntry,
  runCliJson,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import {
  REPAIR_BACKUP_MIN_AGE_MS,
  REPAIR_BACKUP_MIN_STARTS,
  LIFECYCLE_LEDGER_REL,
  dispatchLifecycle,
  previewCliVersionRollback,
  isTrustedRollbackProvenance,
  TRUSTED_PROVENANCE_ALLOWLIST,
  runCanary,
  supersedeRecipe,
} from "../src/core/lifecycle/index.js";
import {
  LedgerError,
  parseLedger,
  sealLedger,
  emptyLedger,
  sealRepairBackup,
  sealKnownGood,
} from "../src/core/lifecycle/ledger.js";
import type { LifecycleLedger } from "../src/core/lifecycle/types.js";
import { makeTempDir } from "./helpers.js";

const INSTANCE = "inst-a";
const DAY = 24 * 60 * 60 * 1000;

function assertNoLeakText(text: string): void {
  assert.equal(/\/Users\//.test(text), false, "absolute Users path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text), false, "Bearer leak");
}

function runLifecycle(
  target: string,
  operation: string,
  flags: string[] = [],
): {
  exitCode: number;
  stdout: string;
  result: Record<string, unknown> | null;
} {
  return runCliJson(["lifecycle", operation, target, ...flags]);
}

function ledgerOf(result: Record<string, unknown> | null): LifecycleLedger {
  assert.ok(result?.ledger, "ledger required");
  return result!.ledger as LifecycleLedger;
}

function sha256Text(s: string): string {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function writeControl(
  target: string,
  surface: string,
  body: Record<string, unknown>,
): void {
  const p = path.join(target, "control", `${surface}.json`);
  fs.writeFileSync(p, JSON.stringify(body, null, 2) + "\n", "utf8");
}

function readControl(target: string, surface: string): string {
  return fs.readFileSync(path.join(target, "control", `${surface}.json`), "utf8");
}

test("Ticket06 RED→GREEN: repair backup age+starts retention keeps until both thresholds", () => {
  const tmp = makeTempDir("cg-t06-ret-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
  const t0 = 1_700_000_000_000;

  const rec = runLifecycle(target, "record_repair_backup", [
    `--instance-id=${INSTANCE}`,
    "--source-rel=artifact.txt",
    "--surface=artifact",
    `--now-ms=${t0}`,
  ]);
  assert.equal(rec.exitCode, 0, rec.stdout);
  assert.equal(rec.result!.ok, true);
  assert.equal(rec.result!.target_mutated, true);
  let led = ledgerOf(rec.result);
  assert.equal(led.repair_backups.length, 1);
  assert.equal(led.repair_backups[0]!.status, "active");
  assert.equal(led.repair_backups[0]!.successful_start_count, 0);

  // Age alone past 7d without 3 starts → keep
  let ret = runLifecycle(target, "apply_retention", [
    `--instance-id=${INSTANCE}`,
    `--now-ms=${t0 + REPAIR_BACKUP_MIN_AGE_MS + DAY}`,
  ]);
  assert.equal(ret.exitCode, 0, ret.stdout);
  led = ledgerOf(ret.result);
  assert.equal(led.repair_backups[0]!.status, "active");
  const decisions = (ret.result!.retention as { decisions: { reason: string }[] })
    .decisions;
  assert.ok(decisions.some((d) => d.reason === "within_min_starts"));

  // 3 starts but still young → keep
  for (let i = 0; i < REPAIR_BACKUP_MIN_STARTS; i++) {
    const st = runLifecycle(target, "record_successful_start", [
      `--instance-id=${INSTANCE}`,
      `--now-ms=${t0 + i + 1}`,
    ]);
    assert.equal(st.exitCode, 0, st.stdout);
  }
  ret = runLifecycle(target, "apply_retention", [
    `--instance-id=${INSTANCE}`,
    `--now-ms=${t0 + 1000}`,
  ]);
  assert.equal(ret.exitCode, 0);
  led = ledgerOf(ret.result);
  assert.equal(led.repair_backups[0]!.status, "active");
  assert.ok(
    (ret.result!.retention as { decisions: { reason: string }[] }).decisions.some(
      (d) => d.reason === "within_min_age",
    ),
  );

  // Both thresholds → prune with receipt; never outside registered state
  ret = runLifecycle(target, "apply_retention", [
    `--instance-id=${INSTANCE}`,
    `--now-ms=${t0 + REPAIR_BACKUP_MIN_AGE_MS + DAY}`,
  ]);
  assert.equal(ret.exitCode, 0);
  led = ledgerOf(ret.result);
  assert.equal(led.repair_backups[0]!.status, "pruned");
  const receipt = ret.result!.retention as {
    deleted_outside_registered_state: boolean;
    pruned_ids: string[];
  };
  assert.equal(receipt.deleted_outside_registered_state, false);
  assert.equal(receipt.pruned_ids.length, 1);
  assertNoLeakText(ret.stdout);
});

test("Ticket06: KNOWN_GOOD retains last three healthy checkpoints per surface", () => {
  const tmp = makeTempDir("cg-t06-kg-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
  const t0 = 1_700_000_100_000;
  const ids: string[] = [];

  for (let i = 0; i < 4; i++) {
    writeControl(target, "config", {
      schema_version: 1,
      surface: "config",
      healthy: true,
      setting: `v${i}`,
    });
    const r = runLifecycle(target, "record_known_good", [
      `--instance-id=${INSTANCE}`,
      "--surface=config",
      `--now-ms=${t0 + i * 1000}`,
    ]);
    assert.equal(r.exitCode, 0, r.stdout);
    const led = ledgerOf(r.result);
    const active = led.known_good.filter(
      (k) => k.surface === "config" && k.status === "retained_known_good",
    );
    assert.ok(active.length <= 3, `active count ${active.length}`);
    const newest = led.known_good
      .filter((k) => k.surface === "config")
      .sort((a, b) => b.created_at_ms - a.created_at_ms)[0]!;
    ids.push(newest.checkpoint_id);
  }

  const status = runLifecycle(target, "status", [`--instance-id=${INSTANCE}`]);
  assert.equal(status.exitCode, 0);
  const led = ledgerOf(status.result);
  const retained = led.known_good.filter(
    (k) => k.surface === "config" && k.status === "retained_known_good",
  );
  const pruned = led.known_good.filter(
    (k) => k.surface === "config" && k.status === "pruned",
  );
  assert.equal(retained.length, 3);
  assert.equal(pruned.length, 1);
  // Oldest of the four should be pruned
  assert.equal(pruned[0]!.checkpoint_id, ids[0]);
  assert.ok(retained.some((k) => k.checkpoint_id === ids[3]));
});

test("Ticket06: update regression requires controlled A/B; timestamps alone refused", () => {
  const tmp = makeTempDir("cg-t06-ab-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);

  const control = {
    version: "0.40.0",
    fault_reproduced: false,
    measured: true,
    mechanism_id: "process-shim",
    instance_id: INSTANCE,
  };
  const treatment = {
    version: "0.41.0",
    fault_reproduced: true,
    measured: true,
    mechanism_id: "process-shim",
    instance_id: INSTANCE,
  };

  const ok = runLifecycle(target, "assess_update_regression", [
    `--control-json=${JSON.stringify(control)}`,
    `--treatment-json=${JSON.stringify(treatment)}`,
  ]);
  assert.equal(ok.exitCode, 0, ok.stdout);
  assert.equal(ok.result!.ok, true);
  const reg = ok.result!.regression as { established: boolean; reason_code: string };
  assert.equal(reg.established, true);
  assert.equal(reg.reason_code, "AB_REGRESSION_ESTABLISHED");

  const tsOnly = runLifecycle(target, "assess_update_regression", [
    "--timestamp-only=true",
    `--control-json=${JSON.stringify(control)}`,
    `--treatment-json=${JSON.stringify(treatment)}`,
  ]);
  assert.notEqual(tsOnly.exitCode, 0);
  const reg2 = tsOnly.result!.regression as {
    established: boolean;
    reason_code: string;
  };
  assert.equal(reg2.established, false);
  assert.equal(reg2.reason_code, "TIMESTAMP_ONLY_INSUFFICIENT");

  // False attribution: different instance
  const badInst = runLifecycle(target, "assess_update_regression", [
    `--control-json=${JSON.stringify(control)}`,
    `--treatment-json=${JSON.stringify({ ...treatment, instance_id: "other" })}`,
  ]);
  assert.equal(
    (badInst.result!.regression as { reason_code: string }).reason_code,
    "INSTANCE_MISMATCH",
  );

  // Different mechanism
  const badMech = runLifecycle(target, "assess_update_regression", [
    `--control-json=${JSON.stringify(control)}`,
    `--treatment-json=${JSON.stringify({ ...treatment, mechanism_id: "other" })}`,
  ]);
  assert.equal(
    (badMech.result!.regression as { reason_code: string }).reason_code,
    "MECHANISM_MISMATCH",
  );
});

test("Ticket06: exact-instance surface rollback → MITIGATED_VERIFIED_BY_ROLLBACK", () => {
  const tmp = makeTempDir("cg-t06-rb-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
  const t0 = 1_700_000_200_000;
  const original = readControl(target, "config");

  const kg = runLifecycle(target, "record_known_good", [
    `--instance-id=${INSTANCE}`,
    "--surface=config",
    `--now-ms=${t0}`,
  ]);
  assert.equal(kg.exitCode, 0, kg.stdout);
  const checkpoint_id = ledgerOf(kg.result).known_good[0]!.checkpoint_id;
  const goodSha = ledgerOf(kg.result).known_good[0]!.content_sha256;

  // Mutate live config (simulate bad update)
  writeControl(target, "config", {
    schema_version: 1,
    surface: "config",
    healthy: false,
    setting: "broken-after-update",
  });
  assert.notEqual(readControl(target, "config"), original);

  // Wrong instance refused
  const wrong = runLifecycle(target, "rollback_surface", [
    "--instance-id=other-inst",
    "--surface=config",
    `--checkpoint-id=${checkpoint_id}`,
  ]);
  assert.notEqual(wrong.exitCode, 0);

  const rb = runLifecycle(target, "rollback_surface", [
    `--instance-id=${INSTANCE}`,
    "--surface=config",
    `--checkpoint-id=${checkpoint_id}`,
  ]);
  assert.equal(rb.exitCode, 0, rb.stdout);
  assert.equal(rb.result!.ok, true);
  assert.equal(
    (rb.result!.user_resolution as { status: string }).status,
    "MITIGATED_VERIFIED_BY_ROLLBACK",
  );
  assert.equal(rb.result!.repair_applied, false);
  const sr = rb.result!.surface_rollback as { resulting_sha256: string };
  assert.equal(sr.resulting_sha256, goodSha);
  assert.equal(readControl(target, "config"), original);
  assertNoLeakText(rb.stdout);

  // Failed rollback: missing checkpoint
  const fail = runLifecycle(target, "rollback_surface", [
    `--instance-id=${INSTANCE}`,
    "--surface=config",
    "--checkpoint-id=does-not-exist",
  ]);
  assert.notEqual(fail.exitCode, 0);
  assert.equal(fail.result!.error_code, "CHECKPOINT_NOT_FOUND");
});

test("Ticket06: CLI version rollback preview refuses absent/untrusted provenance; never binary ops", () => {
  const tmp = makeTempDir("cg-t06-cli-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);

  const good = runLifecycle(target, "cli_version_rollback_preview", [
    "--official-source=official_npm",
    "--version-pin=0.40.0",
    "--provenance=trusted_official",
  ]);
  assert.equal(good.exitCode, 0, good.stdout);
  const prev = good.result!.cli_preview as Record<string, unknown>;
  assert.equal(prev.accepted, true);
  assert.equal(prev.binary_stored, false);
  assert.equal(prev.binary_downloaded, false);
  assert.equal(prev.package_manager_shell_invoked, false);
  assert.equal(prev.mode, "preview_only");

  const absent = runLifecycle(target, "cli_version_rollback_preview", [
    "--official-source=official_npm",
    "--version-pin=0.40.0",
    "--provenance=absent",
  ]);
  assert.notEqual(absent.exitCode, 0);
  assert.equal(
    (absent.result!.cli_preview as { refuse_code: string }).refuse_code,
    "PROVENANCE_ABSENT",
  );

  const untrusted = runLifecycle(target, "cli_version_rollback_preview", [
    "--official-source=untrusted",
    "--version-pin=0.40.0",
    "--provenance=untrusted",
  ]);
  assert.notEqual(untrusted.exitCode, 0);
  assert.equal(
    (untrusted.result!.cli_preview as { refuse_code: string }).refuse_code,
    "PROVENANCE_UNTRUSTED",
  );

  const desk = runLifecycle(target, "desktop_version_rollback_preview", [
    "--signed-history=false",
    "--lawful-media=false",
  ]);
  assert.notEqual(desk.exitCode, 0);
  assert.equal(
    (desk.result!.desktop_preview as { limited: boolean }).limited,
    true,
  );
});

/**
 * P1: CLI rollback provenance is fail-closed allowlist (exact `trusted_official`
 * only). Denylist of absent/untrusted previously accepted forged labels such as
 * `forged_trust_label`. Repro must refuse at core, dispatch, CLI, and MCP seams.
 */
function assertCliPreviewRefused(
  result: {
    ok?: unknown;
    cli_preview?: unknown;
    error_code?: unknown;
  },
  expectedRefuse: string,
): void {
  assert.equal(result.ok, false);
  const prev = result.cli_preview as {
    accepted: boolean;
    refuse_code: string | null;
    binary_stored: boolean;
    binary_downloaded: boolean;
    package_manager_shell_invoked: boolean;
    provenance: string;
  };
  assert.ok(prev, "cli_preview required");
  assert.equal(prev.accepted, false);
  assert.equal(prev.refuse_code, expectedRefuse);
  assert.equal(prev.binary_stored, false);
  assert.equal(prev.binary_downloaded, false);
  assert.equal(prev.package_manager_shell_invoked, false);
  assert.equal(result.error_code, expectedRefuse);
}

test("Ticket06 P1: forged/unknown provenance fails closed at core/CLI/MCP (allowlist only)", async () => {
  const tmp = makeTempDir("cg-t06-prov-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);

  // Source-of-truth allowlist: only exact trusted_official.
  assert.deepEqual([...TRUSTED_PROVENANCE_ALLOWLIST], ["trusted_official"]);
  assert.equal(isTrustedRollbackProvenance("trusted_official"), true);
  assert.equal(isTrustedRollbackProvenance("forged_trust_label"), false);
  assert.equal(isTrustedRollbackProvenance("Trusted_Official"), false);
  assert.equal(isTrustedRollbackProvenance(" trusted_official"), false);
  assert.equal(isTrustedRollbackProvenance("trusted_official "), false);
  // Cyrillic small і (U+0456) confusable in "official"
  assert.equal(
    isTrustedRollbackProvenance("trusted_offic\u0456al"),
    false,
  );

  // --- Core seam: direct engine call with forged label (the reported repro) ---
  const coreForged = previewCliVersionRollback({
    targetPath: target,
    official_source: "official_npm",
    version_pin: "0.1.0",
    provenance: "forged_trust_label",
  });
  assertCliPreviewRefused(coreForged, "PROVENANCE_UNTRUSTED");
  assert.equal(coreForged.cli_preview!.provenance, "untrusted");

  // Core: missing / empty / case / whitespace / confusable / future label
  const coreNegatives: Array<{ provenance: string; refuse: string }> = [
    { provenance: "absent", refuse: "PROVENANCE_ABSENT" },
    { provenance: "", refuse: "PROVENANCE_ABSENT" },
    { provenance: "untrusted", refuse: "PROVENANCE_UNTRUSTED" },
    { provenance: "Trusted_Official", refuse: "PROVENANCE_UNTRUSTED" },
    { provenance: "TRUSTED_OFFICIAL", refuse: "PROVENANCE_UNTRUSTED" },
    { provenance: " trusted_official", refuse: "PROVENANCE_UNTRUSTED" },
    { provenance: "trusted_official ", refuse: "PROVENANCE_UNTRUSTED" },
    { provenance: "trusted_official\n", refuse: "PROVENANCE_UNTRUSTED" },
    {
      provenance: "trusted_offic\u0456al",
      refuse: "PROVENANCE_UNTRUSTED",
    },
    { provenance: "trusted_official_v2", refuse: "PROVENANCE_UNTRUSTED" },
    { provenance: "future_unsupported_label", refuse: "PROVENANCE_UNTRUSTED" },
  ];
  for (const n of coreNegatives) {
    const r = previewCliVersionRollback({
      targetPath: target,
      official_source: "official_npm",
      version_pin: "0.1.0",
      provenance: n.provenance,
    });
    assertCliPreviewRefused(r, n.refuse);
  }

  // Core positive: exact trusted_official + official source + pin
  const coreOk = previewCliVersionRollback({
    targetPath: target,
    official_source: "official_npm",
    version_pin: "0.1.0",
    provenance: "trusted_official",
  });
  assert.equal(coreOk.ok, true);
  assert.equal(coreOk.cli_preview!.accepted, true);
  assert.equal(coreOk.cli_preview!.provenance, "trusted_official");
  assert.equal(coreOk.cli_preview!.binary_stored, false);
  assert.equal(coreOk.cli_preview!.binary_downloaded, false);
  assert.equal(coreOk.cli_preview!.package_manager_shell_invoked, false);

  // --- Dispatch seam: no cast bypass for forged labels ---
  const dispForged = dispatchLifecycle({
    target,
    operation: "cli_version_rollback_preview",
    official_source: "official_npm",
    version_pin: "0.1.0",
    provenance: "forged_trust_label",
  });
  assertCliPreviewRefused(dispForged, "PROVENANCE_UNTRUSTED");

  const dispMissing = dispatchLifecycle({
    target,
    operation: "cli_version_rollback_preview",
    official_source: "official_npm",
    version_pin: "0.1.0",
    // provenance omitted → absent
  });
  assertCliPreviewRefused(dispMissing, "PROVENANCE_ABSENT");

  // --- CLI public seam ---
  const cliForged = runLifecycle(target, "cli_version_rollback_preview", [
    "--official-source=official_npm",
    "--version-pin=0.1.0",
    "--provenance=forged_trust_label",
  ]);
  assert.notEqual(cliForged.exitCode, 0);
  assertCliPreviewRefused(
    cliForged.result as {
      ok?: unknown;
      cli_preview?: unknown;
      error_code?: unknown;
    },
    "PROVENANCE_UNTRUSTED",
  );

  const cliCase = runLifecycle(target, "cli_version_rollback_preview", [
    "--official-source=official_npm",
    "--version-pin=0.1.0",
    "--provenance=Trusted_Official",
  ]);
  assert.notEqual(cliCase.exitCode, 0);
  assertCliPreviewRefused(
    cliCase.result as {
      ok?: unknown;
      cli_preview?: unknown;
      error_code?: unknown;
    },
    "PROVENANCE_UNTRUSTED",
  );

  const cliWs = runLifecycle(target, "cli_version_rollback_preview", [
    "--official-source=official_npm",
    "--version-pin=0.1.0",
    "--provenance= trusted_official",
  ]);
  assert.notEqual(cliWs.exitCode, 0);
  assertCliPreviewRefused(
    cliWs.result as {
      ok?: unknown;
      cli_preview?: unknown;
      error_code?: unknown;
    },
    "PROVENANCE_UNTRUSTED",
  );

  // --- MCP public seam ---
  const tmpMcp = makeTempDir("cg-t06-prov-mcp-");
  const targetMcp = copyFixtureToTemp("fixtures/lifecycle", tmpMcp);
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const mcpForged = await client.callTool("changeguard_lifecycle", {
      target: targetMcp,
      operation: "cli_version_rollback_preview",
      official_source: "official_npm",
      version_pin: "0.1.0",
      provenance: "forged_trust_label",
    });
    assertCliPreviewRefused(
      mcpForged as {
        ok?: unknown;
        cli_preview?: unknown;
        error_code?: unknown;
      },
      "PROVENANCE_UNTRUSTED",
    );
    assert.equal(mcpForged.network_used, false);

    const mcpOk = await client.callTool("changeguard_lifecycle", {
      target: targetMcp,
      operation: "cli_version_rollback_preview",
      official_source: "official_npm",
      version_pin: "0.1.0",
      provenance: "trusted_official",
    });
    assert.equal(mcpOk.ok, true);
    const mp = mcpOk.cli_preview as {
      accepted: boolean;
      binary_stored: boolean;
      binary_downloaded: boolean;
      package_manager_shell_invoked: boolean;
    };
    assert.equal(mp.accepted, true);
    assert.equal(mp.binary_stored, false);
    assert.equal(mp.binary_downloaded, false);
    assert.equal(mp.package_manager_shell_invoked, false);

    // Extra key at MCP tool args must fail closed (strict schema).
    let extraKeyBlocked = false;
    try {
      await client.callTool("changeguard_lifecycle", {
        target: targetMcp,
        operation: "cli_version_rollback_preview",
        official_source: "official_npm",
        version_pin: "0.1.0",
        provenance: "trusted_official",
        extra_attack_field: "injected",
      });
    } catch {
      extraKeyBlocked = true;
    }
    assert.equal(extraKeyBlocked, true, "MCP must refuse extra tool args");
  } finally {
    await client.close();
  }
});

test("Ticket06: canary pass/fail guidance exact enum", () => {
  const tmp = makeTempDir("cg-t06-can-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
  // Seed KNOWN_GOOD so HOLD is meaningful
  runLifecycle(target, "record_known_good", [
    `--instance-id=default`,
    "--surface=plugin",
  ]);

  // Ticket 12 authority: public/CLI boolean-only path cannot RECOMMEND_UPGRADE.
  // All-true executed canary without live witness → availability guidance only.
  const pass = runLifecycle(target, "canary", [
    "--candidate-version=0.42.0",
    "--original-fault-absent=true",
    "--core-regressions-passed=true",
    "--canary-executed=true",
  ]);
  assert.equal(pass.exitCode, 0, pass.stdout);
  assert.equal(pass.result!.version_guidance, "UPGRADE_CANARY_AVAILABLE");
  assert.notEqual(pass.result!.version_guidance, "RECOMMEND_UPGRADE");

  const fail = runLifecycle(target, "canary", [
    "--candidate-version=0.42.1",
    "--original-fault-absent=false",
    "--core-regressions-passed=true",
    "--canary-executed=true",
  ]);
  assert.equal(fail.exitCode, 0);
  assert.equal(fail.result!.version_guidance, "HOLD_KNOWN_GOOD");

  const avail = runLifecycle(target, "canary", [
    "--candidate-version=0.43.0",
    "--original-fault-absent=true",
    "--core-regressions-passed=true",
    "--canary-executed=false",
  ]);
  assert.equal(avail.exitCode, 0);
  assert.equal(avail.result!.version_guidance, "UPGRADE_CANARY_AVAILABLE");
});

/**
 * P1-A: canary_executed must fail closed. Only exact true means executed;
 * omitted/false must yield UPGRADE_CANARY_AVAILABLE even when result
 * booleans are true. Caller-declared booleans are not independently measured.
 */
test("Ticket06 P1-A: omitted canary_executed fails closed to UPGRADE_CANARY_AVAILABLE", () => {
  const tmp = makeTempDir("cg-t06-can-omit-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);

  // Core seam: omit canary_executed entirely.
  const core = runCanary({
    targetPath: target,
    candidate_version: "0.60.0",
    original_fault_absent: true,
    core_regressions_passed: true,
  });
  assert.equal(core.ok, true);
  assert.equal(core.version_guidance, "UPGRADE_CANARY_AVAILABLE");
  assert.equal(core.canary?.version_guidance, "UPGRADE_CANARY_AVAILABLE");
  // Public CanaryResult booleans remain caller-supplied values.
  assert.equal(core.canary?.original_fault_absent, true);
  assert.equal(core.canary?.core_regressions_passed, true);
  const coreEvidence = core.evidence.find((e) => e.kind === "canary_result");
  assert.ok(coreEvidence);
  assert.equal(
    coreEvidence!.measured,
    false,
    "caller-declared canary outcomes must not be labeled independently measured",
  );

  // CLI seam: omit --canary-executed (result booleans true).
  const tmpCli = makeTempDir("cg-t06-can-omit-cli-");
  const targetCli = copyFixtureToTemp("fixtures/lifecycle", tmpCli);
  const cli = runLifecycle(targetCli, "canary", [
    "--candidate-version=0.60.1",
    "--original-fault-absent=true",
    "--core-regressions-passed=true",
  ]);
  assert.equal(cli.exitCode, 0, cli.stdout);
  assert.equal(cli.result!.version_guidance, "UPGRADE_CANARY_AVAILABLE");
  assert.notEqual(cli.result!.version_guidance, "RECOMMEND_UPGRADE");
  const cliEvidence = (
    cli.result!.evidence as Array<{ kind?: string; measured?: boolean }>
  ).find((e) => e.kind === "canary_result");
  assert.ok(cliEvidence);
  assert.equal(cliEvidence!.measured, false);
});

test("Ticket06 P1-A: CLI/MCP omitted canary_executed equivalence", async () => {
  const tmp = makeTempDir("cg-t06-can-omit-eq-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
  const cli = runLifecycle(target, "canary", [
    "--candidate-version=0.61.0",
    "--original-fault-absent=true",
    "--core-regressions-passed=true",
  ]);
  assert.equal(cli.exitCode, 0, cli.stdout);
  assert.equal(cli.result!.version_guidance, "UPGRADE_CANARY_AVAILABLE");

  const tmp2 = makeTempDir("cg-t06-can-omit-eq2-");
  const target2 = copyFixtureToTemp("fixtures/lifecycle", tmp2);
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    // Omit canary_executed from MCP args entirely.
    const mcpResult = await client.callTool("changeguard_lifecycle", {
      target: target2,
      operation: "canary",
      candidate_version: "0.61.0",
      original_fault_absent: true,
      core_regressions_passed: true,
    });
    assert.equal(mcpResult.ok, true);
    assert.equal(mcpResult.version_guidance, "UPGRADE_CANARY_AVAILABLE");
    assert.equal(mcpResult.version_guidance, cli.result!.version_guidance);
    assert.equal(mcpResult.operation, "canary");
    assert.equal(mcpResult.network_used, false);
    const mcpEvidence = (
      mcpResult.evidence as Array<{ kind?: string; measured?: boolean }>
    ).find((e) => e.kind === "canary_result");
    assert.ok(mcpEvidence);
    assert.equal(mcpEvidence!.measured, false);
    assertNoLeakText(JSON.stringify(mcpResult));
  } finally {
    await client.close();
  }
});

test("Ticket06: upstream supersession requires live measurement witness (boolean path closed)", () => {
  const tmp = makeTempDir("cg-t06-sup-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
  const digest = sha256Text("upstream-fix-evidence-v1");

  // Ticket 12 authority: CLI/public verified booleans alone cannot supersede.
  const sup = runLifecycle(target, "supersede_recipe", [
    "--recipe-id=workaround-process-shim",
    "--upstream-ref=openai/codex#32925",
    `--upstream-evidence-digest=${digest}`,
    "--upstream-verified=true",
  ]);
  assert.notEqual(sup.exitCode, 0, sup.stdout);
  // Boolean path closed: official bind and/or live witness refuse supersession.
  assert.ok(
    sup.result!.error_code === "LIVE_WITNESS_REQUIRED" ||
      sup.result!.error_code === "UPSTREAM_NOT_VERIFIED" ||
      sup.result!.error_code === "OFFICIAL_EVIDENCE_REF_REFUSED" ||
      sup.result!.error_code === "OFFICIAL_EVIDENCE_UNBOUND" ||
      sup.result!.error_code === "OFFICIAL_EVIDENCE_REQUIRED",
  );
  assert.notEqual(sup.result!.version_guidance, "RECOMMEND_UPGRADE");

  // Unverified still refused
  const unver = runLifecycle(target, "supersede_recipe", [
    "--recipe-id=other",
    "--upstream-ref=openai/codex#1",
    `--upstream-evidence-digest=${digest}`,
    "--upstream-verified=false",
  ]);
  assert.notEqual(unver.exitCode, 0);
  assert.equal(unver.result!.error_code, "UPSTREAM_NOT_VERIFIED");

  // Direct core seam without witness also refuses (no SUPERSEDED_BY_UPSTREAM_FIX).
  // Non-official/forged refs fail official bind before witness; use real mechanism-
  // linked digest+URL so the remaining gate is LIVE_WITNESS_REQUIRED.
  const core = supersedeRecipe({
    targetPath: target,
    recipe_id: "workaround-process-shim",
    candidate_version: "0.50.0",
    upstream: {
      ref: "https://github.com/openai/codex/compare/rust-v0.49.0...rust-v0.50.0",
      evidence_digest:
        "eeb1ccc7913c4a8489c1e1de3919c4cc93bdd0de2eec87dc680c80a67aeed7d7",
      verified: true,
      measured_validation: true,
    },
  });
  assert.equal(core.ok, false);
  assert.equal(core.error_code, "LIVE_WITNESS_REQUIRED");
  assert.notEqual(core.version_guidance, "RECOMMEND_UPGRADE");
  void digest;
});

test("Ticket06: corrupt/tampered/symlink ledger refused", () => {
  const tmp = makeTempDir("cg-t06-adv-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);

  // Bootstrap valid ledger
  const boot = runLifecycle(target, "record_repair_backup", [
    `--instance-id=${INSTANCE}`,
    "--source-rel=artifact.txt",
  ]);
  assert.equal(boot.exitCode, 0);

  // Tamper digest
  const ledgerPath = path.join(target, LIFECYCLE_LEDGER_REL);
  const raw = JSON.parse(fs.readFileSync(ledgerPath, "utf8")) as Record<
    string,
    unknown
  >;
  raw.ledger_digest =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  fs.writeFileSync(ledgerPath, JSON.stringify(raw, null, 2) + "\n");

  const tampered = runLifecycle(target, "status", [`--instance-id=${INSTANCE}`]);
  assert.notEqual(tampered.exitCode, 0);
  assert.equal(tampered.result!.error_code, "TAMPERED_LEDGER");

  // Corrupt JSON
  fs.writeFileSync(ledgerPath, "{not-json", "utf8");
  const corrupt = runLifecycle(target, "status", [`--instance-id=${INSTANCE}`]);
  assert.notEqual(corrupt.exitCode, 0);
  assert.ok(
    corrupt.result!.error_code === "CORRUPT_LEDGER" ||
      corrupt.result!.error_code === "LEDGER_IO",
  );

  // Symlink ledger refused
  const tmp2 = makeTempDir("cg-t06-sym-");
  const target2 = copyFixtureToTemp("fixtures/lifecycle", tmp2);
  const lcDir = path.join(target2, ".changeguard", "lifecycle");
  fs.mkdirSync(lcDir, { recursive: true });
  const outside = path.join(tmp2, "evil-ledger.json");
  fs.writeFileSync(outside, JSON.stringify({ schema_version: 1 }), "utf8");
  fs.symlinkSync(outside, path.join(lcDir, "ledger.json"));
  const sym = runLifecycle(target2, "status", [`--instance-id=${INSTANCE}`]);
  assert.notEqual(sym.exitCode, 0);
  assert.ok(
    sym.result!.error_code === "SYMLINK_REFUSED" ||
      sym.result!.error_code === "SYMLINK_ESCAPE",
  );
});

/**
 * P1: extra keys must fail closed (CORRUPT_LEDGER / TAMPERED_LEDGER).
 * Repro: inject extra_attack_field while retaining digests over the known
 * canonical body — parsers must not strip unknowns and accept the ledger.
 */
function assertLedgerExtraKeyRefused(
  error: unknown,
): asserts error is LedgerError {
  assert.ok(error instanceof LedgerError, "expected LedgerError");
  assert.ok(
    error.code === "CORRUPT_LEDGER" || error.code === "TAMPERED_LEDGER",
    `unexpected code ${error.code}`,
  );
}

function assertLifecycleExtraKeyExit(result: {
  exitCode: number;
  result: Record<string, unknown> | null;
}): void {
  assert.notEqual(result.exitCode, 0);
  const code = result.result!.error_code;
  assert.ok(
    code === "CORRUPT_LEDGER" || code === "TAMPERED_LEDGER",
    `unexpected error_code ${String(code)}`,
  );
}

test("Ticket06 P1: top-level and nested extra ledger keys fail closed", () => {
  const now = 1_700_000_000_000;

  // Unit: top-level extra key with retained canonical digest
  const empty = emptyLedger(INSTANCE, now);
  assert.throws(
    () => parseLedger({ ...empty, extra_attack_field: "injected" }),
    (e: unknown) => {
      assertLedgerExtraKeyRefused(e);
      return true;
    },
  );

  // Unit: nested repair backup extra key (digests retained over clean body)
  const repair = sealRepairBackup({
    schema_version: 1,
    kind: "repair",
    backup_id: "bk_test",
    backup_rel: "lifecycle/backups/bk_test.bin",
    original_sha256: "a".repeat(64),
    surface: "artifact",
    instance_id: INSTANCE,
    created_at_ms: now,
    successful_start_count: 0,
    status: "active",
  });
  const sealedRepair = sealLedger({
    schema_version: 1,
    instance_id: INSTANCE,
    repair_backups: [repair],
    known_good: [],
    recipes: [],
    last_retention: null,
    last_regression: null,
    last_canary: null,
    version_guidance: "GENERAL_UPDATE_ONLY",
    successful_start_total: 0,
    updated_at_ms: now,
  });
  assert.throws(
    () =>
      parseLedger({
        ...sealedRepair,
        repair_backups: [{ ...repair, extra_attack_field: "nested" }],
      }),
    (e: unknown) => {
      assertLedgerExtraKeyRefused(e);
      return true;
    },
  );

  // Unit: nested known_good extra key
  const kg = sealKnownGood({
    schema_version: 1,
    kind: "known_good",
    checkpoint_id: "kg_test",
    surface: "config",
    instance_id: INSTANCE,
    target_rel: "control/config.json",
    backup_rel: "lifecycle/backups/kg_test.bin",
    content_sha256: "b".repeat(64),
    created_at_ms: now,
    status: "retained_known_good",
    healthy: true,
  });
  const sealedKg = sealLedger({
    schema_version: 1,
    instance_id: INSTANCE,
    repair_backups: [],
    known_good: [kg],
    recipes: [],
    last_retention: null,
    last_regression: null,
    last_canary: null,
    version_guidance: "GENERAL_UPDATE_ONLY",
    successful_start_total: 0,
    updated_at_ms: now,
  });
  assert.throws(
    () =>
      parseLedger({
        ...sealedKg,
        known_good: [{ ...kg, extra_attack_field: true }],
      }),
    (e: unknown) => {
      assertLedgerExtraKeyRefused(e);
      return true;
    },
  );

  // Unit: nested recipe extra key
  const recipe = {
    recipe_id: "workaround-process-shim",
    status: "ACTIVE_WORKAROUND" as const,
    upstream_ref: null,
    upstream_evidence_digest: null,
    superseded_at_ms: null,
    recommendable: true,
  };
  const sealedRecipe = sealLedger({
    schema_version: 1,
    instance_id: INSTANCE,
    repair_backups: [],
    known_good: [],
    recipes: [recipe],
    last_retention: null,
    last_regression: null,
    last_canary: null,
    version_guidance: "GENERAL_UPDATE_ONLY",
    successful_start_total: 0,
    updated_at_ms: now,
  });
  assert.throws(
    () =>
      parseLedger({
        ...sealedRecipe,
        recipes: [{ ...recipe, extra_attack_field: 1 }],
      }),
    (e: unknown) => {
      assertLedgerExtraKeyRefused(e);
      return true;
    },
  );

  // Unit: retention receipt + nested decision extra keys
  const retention = {
    schema_version: 1 as const,
    evaluated_at_ms: now,
    decisions: [
      {
        backup_id: "bk",
        action: "keep" as const,
        reason: "within_min_age" as const,
        receipt_id: "r1",
      },
    ],
    pruned_ids: [] as string[],
    kept_ids: ["bk"],
    deleted_outside_registered_state: false as const,
  };
  const sealedRet = sealLedger({
    schema_version: 1,
    instance_id: INSTANCE,
    repair_backups: [],
    known_good: [],
    recipes: [],
    last_retention: retention,
    last_regression: null,
    last_canary: null,
    version_guidance: "GENERAL_UPDATE_ONLY",
    successful_start_total: 0,
    updated_at_ms: now,
  });
  assert.throws(
    () =>
      parseLedger({
        ...sealedRet,
        last_retention: { ...retention, extra_attack_field: "x" },
      }),
    (e: unknown) => {
      assertLedgerExtraKeyRefused(e);
      return true;
    },
  );
  assert.throws(
    () =>
      parseLedger({
        ...sealedRet,
        last_retention: {
          ...retention,
          decisions: [{ ...retention.decisions[0]!, extra_attack_field: "d" }],
        },
      }),
    (e: unknown) => {
      assertLedgerExtraKeyRefused(e);
      return true;
    },
  );

  // Unit: regression / canary extra keys
  const regression = {
    established: false,
    reason_code: "UNMEASURED" as const,
    instance_id: null,
    mechanism_id: null,
    version_before: null,
    version_after: null,
  };
  const sealedReg = sealLedger({
    schema_version: 1,
    instance_id: INSTANCE,
    repair_backups: [],
    known_good: [],
    recipes: [],
    last_retention: null,
    last_regression: regression,
    last_canary: null,
    version_guidance: "GENERAL_UPDATE_ONLY",
    successful_start_total: 0,
    updated_at_ms: now,
  });
  assert.throws(
    () =>
      parseLedger({
        ...sealedReg,
        last_regression: { ...regression, extra_attack_field: "r" },
      }),
    (e: unknown) => {
      assertLedgerExtraKeyRefused(e);
      return true;
    },
  );

  const canaryRec = {
    candidate_version: "0.50.0",
    original_fault_absent: true,
    core_regressions_passed: true,
    isolated_profile: true as const,
    version_guidance: "RECOMMEND_UPGRADE" as const,
    detail: "ok",
  };
  const sealedCan = sealLedger({
    schema_version: 1,
    instance_id: INSTANCE,
    repair_backups: [],
    known_good: [],
    recipes: [],
    last_retention: null,
    last_regression: null,
    last_canary: canaryRec,
    version_guidance: "GENERAL_UPDATE_ONLY",
    successful_start_total: 0,
    updated_at_ms: now,
  });
  assert.throws(
    () =>
      parseLedger({
        ...sealedCan,
        last_canary: { ...canaryRec, extra_attack_field: "c" },
      }),
    (e: unknown) => {
      assertLedgerExtraKeyRefused(e);
      return true;
    },
  );

  // CLI black-box: default instance so canary/supersede share the same ledger file.
  const defaultInst = "default";
  const tmp = makeTempDir("cg-t06-p1-extra-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
  const boot = runLifecycle(target, "record_repair_backup", [
    `--instance-id=${defaultInst}`,
    "--source-rel=artifact.txt",
  ]);
  assert.equal(boot.exitCode, 0, boot.stdout);
  const ledgerPath = path.join(target, LIFECYCLE_LEDGER_REL);
  const raw = JSON.parse(fs.readFileSync(ledgerPath, "utf8")) as Record<
    string,
    unknown
  >;
  // Retain digests over the known canonical body; inject only an unknown key.
  raw.extra_attack_field = "injected";
  fs.writeFileSync(ledgerPath, JSON.stringify(raw, null, 2) + "\n");

  const status = runLifecycle(target, "status", [`--instance-id=${defaultInst}`]);
  assertLifecycleExtraKeyExit(status);

  // Corrupt ledger must not prune, rollback, recommend upgrade, or supersede
  const prune = runLifecycle(target, "apply_retention", [
    `--instance-id=${defaultInst}`,
  ]);
  assertLifecycleExtraKeyExit(prune);

  const rollback = runLifecycle(target, "rollback_surface", [
    `--instance-id=${defaultInst}`,
    "--surface=config",
    "--checkpoint-id=does-not-exist",
  ]);
  assertLifecycleExtraKeyExit(rollback);

  const canary = runLifecycle(target, "canary", [
    "--candidate-version=0.50.0",
    "--original-fault-absent=true",
    "--core-regressions-passed=true",
    "--canary-executed=true",
  ]);
  assertLifecycleExtraKeyExit(canary);

  const sup = runLifecycle(target, "supersede_recipe", [
    "--recipe-id=workaround-process-shim",
    "--upstream-ref=openai/codex#32925",
    `--upstream-evidence-digest=${"c".repeat(64)}`,
    "--upstream-verified=true",
  ]);
  assertLifecycleExtraKeyExit(sup);

  // Nested repair extra on disk with retained digests
  const tmp2 = makeTempDir("cg-t06-p1-nested-");
  const target2 = copyFixtureToTemp("fixtures/lifecycle", tmp2);
  const boot2 = runLifecycle(target2, "record_repair_backup", [
    `--instance-id=${INSTANCE}`,
    "--source-rel=artifact.txt",
  ]);
  assert.equal(boot2.exitCode, 0, boot2.stdout);
  const ledgerPath2 = path.join(target2, LIFECYCLE_LEDGER_REL);
  const raw2 = JSON.parse(fs.readFileSync(ledgerPath2, "utf8")) as Record<
    string,
    unknown
  >;
  const backups = raw2.repair_backups as Record<string, unknown>[];
  assert.ok(backups.length >= 1);
  backups[0]!.extra_attack_field = "nested_inject";
  fs.writeFileSync(ledgerPath2, JSON.stringify(raw2, null, 2) + "\n");
  const nestedStatus = runLifecycle(target2, "status", [
    `--instance-id=${INSTANCE}`,
  ]);
  assertLifecycleExtraKeyExit(nestedStatus);
});

test("Ticket06: CLI/MCP lifecycle equivalence for status+canary", async () => {
  const tmp = makeTempDir("cg-t06-eq-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);

  const cli = runLifecycle(target, "canary", [
    "--candidate-version=0.50.0",
    "--original-fault-absent=true",
    "--core-regressions-passed=true",
    "--canary-executed=true",
  ]);
  assert.equal(cli.exitCode, 0, cli.stdout);

  const tmp2 = makeTempDir("cg-t06-eq2-");
  const target2 = copyFixtureToTemp("fixtures/lifecycle", tmp2);
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const mcpResult = await client.callTool("changeguard_lifecycle", {
      target: target2,
      operation: "canary",
      candidate_version: "0.50.0",
      original_fault_absent: true,
      core_regressions_passed: true,
      canary_executed: true,
    });
    assert.equal(mcpResult.ok, true);
    assert.equal(mcpResult.version_guidance, cli.result!.version_guidance);
    assert.equal(mcpResult.operation, "canary");
    assert.equal(mcpResult.network_used, false);
    assertNoLeakText(JSON.stringify(mcpResult));
  } finally {
    await client.close();
  }
});

test("Ticket06: prior-ticket regression diagnose still works on protected-process", () => {
  const tmp = makeTempDir("cg-t06-reg-");
  const target = copyFixtureToTemp("fixtures/protected-process", tmp);
  const diag = runCliJson(["diagnose", target]);
  assert.equal(diag.exitCode, 0, diag.stdout);
  assert.equal(diag.result!.diagnosis_state, "SOURCE_COMPONENT_LOCATED");
  assert.equal(diag.result!.repair_applied, false);
  assert.equal(diag.result!.target_mutated, false);
});

test("Ticket06: dispatch core seam rejects unknown operation", () => {
  const tmp = makeTempDir("cg-t06-disp-");
  const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
  const r = dispatchLifecycle({
    target,
    operation: "not_a_real_op",
  });
  assert.equal(r.ok, false);
  assert.equal(r.error_code, "UNKNOWN_OPERATION");
  assert.equal(r.network_used, false);
});
