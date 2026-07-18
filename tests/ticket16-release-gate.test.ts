/**
 * Ticket 16 — release / privacy / regression gate (public script surface).
 *
 * Exercises scripts/verify-release.mjs via --self-test modes and pure success
 * checks. Does NOT invoke full `npm run verify:release` (that would recurse
 * into npm test). Production full-gate proof is a separate maintainer command.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { findRepoRoot } from "../src/paths.js";

const repoRoot = findRepoRoot(import.meta.url);
const verifyScript = path.join(repoRoot, "scripts/verify-release.mjs");

/** Dynamic import of release-gate helpers (plain .mjs; no TS types required). */
async function loadGate(name: string): Promise<Record<string, unknown>> {
  const href = pathToFileURL(path.join(repoRoot, "scripts/release-gate", name)).href;
  return import(href) as Promise<Record<string, unknown>>;
}

type GateSummary = {
  ok: boolean;
  failed_step: string | null;
  reason_code: string | null;
  steps: { id: string; ok: boolean; reason_code: string | null; detail?: string }[];
};

/**
 * Run the public gate script. Never uses npm run verify:release (avoids recursion).
 */
function runVerify(extraArgs: string[] = []): {
  status: number;
  stdout: string;
  stderr: string;
  summary: GateSummary | null;
} {
  const res = spawnSync(process.execPath, [verifyScript, ...extraArgs], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    maxBuffer: 16 * 1024 * 1024,
  });
  const stdout = res.stdout ?? "";
  const stderr = res.stderr ?? "";
  let summary: GateSummary | null = null;
  try {
    const trimmed = stdout.trim();
    const start = trimmed.indexOf("{");
    if (start >= 0) {
      summary = JSON.parse(trimmed.slice(start)) as GateSummary;
    }
  } catch {
    summary = null;
  }
  return {
    status: res.status ?? 1,
    stdout,
    stderr,
    summary,
  };
}

async function secretValues(): Promise<string[]> {
  const mod = await loadGate("privacy-corpus.mjs");
  const fn = mod.secretValues as () => string[];
  return fn();
}

function assertNoSecretCorpusInText(text: string, secrets: string[]): void {
  for (const v of secrets) {
    assert.equal(text.includes(v), false, "secret corpus must not appear in logs/errors");
  }
}

test("Ticket16: package.json wires verify:release to scripts/verify-release.mjs", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8")) as {
    scripts: Record<string, string>;
  };
  assert.equal(pkg.scripts["verify:release"], "node scripts/verify-release.mjs");
  assert.ok(fs.existsSync(verifyScript));
  const src = fs.readFileSync(verifyScript, "utf8");
  // Documented distinction only — never invoked
  assert.match(src, /never invokes run-verification\.sh/i);
  assert.equal(/spawnSync\([^)]*run-verification\.sh/.test(src), false);
  assert.equal(src.includes('["bash", "scripts/run-verification.sh"]'), false);
  assert.equal(src.includes("run-verification.sh\""), false);
});

test("Ticket16: MANDATORY_STEPS order and reason codes are stable", async () => {
  const mod = await loadGate("reason-codes.mjs");
  const steps = mod.MANDATORY_STEPS as { id: string; reason: string }[];
  const REASON = mod.REASON as Record<string, string>;
  const ids = steps.map((s) => s.id);
  assert.deepEqual(ids, [
    "typecheck",
    "test",
    "boundary",
    "boundary_selftest",
    "schema",
    "fixture_accounting",
    "privacy",
    "injection",
    "write_path",
    "package",
    "package_smoke",
    "package_audit",
    "cli_hash",
    "diff_check",
  ]);
  assert.equal(REASON.GATE_FIXTURE_ACCOUNTING, "GATE_FIXTURE_ACCOUNTING");
  assert.equal(REASON.GATE_PRIVACY, "GATE_PRIVACY");
  assert.equal(REASON.GATE_PACKAGE_AUDIT, "GATE_PACKAGE_AUDIT");
  assert.equal(REASON.GATE_UNKNOWN_STEP, "GATE_UNKNOWN_STEP");
});

test("Ticket16 pure success: schema + fixture accounting + injection + write_path", async () => {
  const schemaMod = await loadGate("schema-gate.mjs");
  const fixMod = await loadGate("fixture-accounting.mjs");
  const injMod = await loadGate("injection-matrix.mjs");
  const writeMod = await loadGate("write-path-inventory.mjs");
  const schema = (schemaMod.checkSchemaGate as (r: string) => { ok: boolean; detail?: string })(
    repoRoot,
  );
  assert.equal(schema.ok, true, schema.detail);
  const fix = (
    fixMod.checkFixtureAccounting as (r: string) => {
      ok: boolean;
      errors?: string[];
      counts?: Record<string, number>;
    }
  )(repoRoot);
  assert.equal(fix.ok, true, JSON.stringify(fix.errors));
  assert.ok((fix.counts?.resolved_verified ?? 0) >= 2);
  assert.ok((fix.counts?.mitigation_or_upstream_blocked ?? 0) >= 2);
  assert.ok((fix.counts?.wrong_repair_refusal ?? 0) >= 3);
  const inj = (injMod.checkInjectionMatrix as (r: string) => { ok: boolean; errors?: string[] })(
    repoRoot,
  );
  assert.equal(inj.ok, true, JSON.stringify(inj.errors));
  const write = (
    writeMod.checkWritePathInventory as (r: string) => { ok: boolean; errors?: string[] }
  )(repoRoot);
  assert.equal(write.ok, true, JSON.stringify(write.errors));
});

test("Ticket16 pure success: privacy corpus zero external disclosure (needs dist)", async () => {
  assert.ok(fs.existsSync(path.join(repoRoot, "dist/core/redact.js")), "dist redact required");
  const privMod = await loadGate("privacy-corpus.mjs");
  const priv = await (
    privMod.checkPrivacyCorpus as (r: string) => Promise<{
      ok: boolean;
      detail?: string;
      external_disclosure_count: number;
      leaks: unknown[];
    }>
  )(repoRoot);
  assert.equal(priv.ok, true, priv.detail);
  assert.equal(priv.external_disclosure_count, 0);
  assert.deepEqual(priv.leaks, []);
  const secrets = await secretValues();
  assertNoSecretCorpusInText(JSON.stringify(priv), secrets);
});

test("Ticket16 self-test undercount → GATE_FIXTURE_ACCOUNTING", async () => {
  const r = runVerify(["--self-test=undercount"]);
  assert.notEqual(r.status, 0);
  assert.ok(r.summary);
  assert.equal(r.summary!.ok, false);
  assert.equal(r.summary!.reason_code, "GATE_FIXTURE_ACCOUNTING");
  assert.equal(r.summary!.failed_step, "fixture_accounting");
  assertNoSecretCorpusInText(r.stdout + r.stderr, await secretValues());
});

test("Ticket16 self-test fixture_missing_test → GATE_FIXTURE_ACCOUNTING", () => {
  const r = runVerify(["--self-test=fixture_missing_test"]);
  assert.notEqual(r.status, 0);
  assert.ok(r.summary);
  assert.equal(r.summary!.reason_code, "GATE_FIXTURE_ACCOUNTING");
  assert.equal(r.summary!.failed_step, "fixture_accounting");
});

test("Ticket16 self-test privacy_poison → GATE_PRIVACY without corpus values in output", async () => {
  const r = runVerify(["--self-test=privacy_poison"]);
  assert.notEqual(r.status, 0);
  assert.ok(r.summary);
  assert.equal(r.summary!.ok, false);
  assert.equal(r.summary!.reason_code, "GATE_PRIVACY");
  assert.equal(r.summary!.failed_step, "privacy");
  const secrets = await secretValues();
  assertNoSecretCorpusInText(r.stdout + r.stderr, secrets);
});

test("Ticket16 self-test missing_writer → GATE_WRITE_PATH", () => {
  const r = runVerify(["--self-test=missing_writer"]);
  assert.notEqual(r.status, 0);
  assert.ok(r.summary);
  assert.equal(r.summary!.reason_code, "GATE_WRITE_PATH");
  assert.equal(r.summary!.failed_step, "write_path");
});

test("Ticket16 self-test schema_fail → GATE_SCHEMA", () => {
  const r = runVerify(["--self-test=schema_fail"]);
  assert.notEqual(r.status, 0);
  assert.ok(r.summary);
  assert.equal(r.summary!.reason_code, "GATE_SCHEMA");
  assert.equal(r.summary!.failed_step, "schema");
});

test("Ticket16 self-test unknown_step → GATE_UNKNOWN_STEP", () => {
  const r = runVerify(["--self-test=unknown_step"]);
  assert.notEqual(r.status, 0);
  assert.ok(r.summary);
  assert.equal(r.summary!.reason_code, "GATE_UNKNOWN_STEP");
  assert.equal(r.summary!.failed_step, "unknown_forced");
});

test("Ticket16 unknown argument → GATE_UNKNOWN_STEP nonzero", () => {
  const r = runVerify(["--not-a-real-flag"]);
  assert.notEqual(r.status, 0);
  assert.ok(r.summary);
  assert.equal(r.summary!.reason_code, "GATE_UNKNOWN_STEP");
  assert.equal(r.summary!.failed_step, "orchestrator");
  assert.match(r.summary!.steps[0]!.detail ?? "", /unknown_arg/);
});

test("Ticket16 unknown self-test mode → GATE_UNKNOWN_STEP", () => {
  const r = runVerify(["--self-test=not_a_mode"]);
  assert.notEqual(r.status, 0);
  assert.ok(r.summary);
  assert.equal(r.summary!.reason_code, "GATE_UNKNOWN_STEP");
});

function ensurePackageBuilt(): void {
  const bin = path.join(repoRoot, "release/codex-changeguard-plugin/bin/changeguard.js");
  if (fs.existsSync(bin)) return;
  const res = spawnSync("npm", ["run", "package"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    maxBuffer: 32 * 1024 * 1024,
  });
  assert.equal(res.status, 0, `package build failed: ${res.stderr}`);
}

function assertCanonicalPackageNotPoisoned(): void {
  const pkg = path.join(repoRoot, "release/codex-changeguard-plugin");
  if (!fs.existsSync(pkg)) return;
  const planted = [
    "dist/__t16_planted_secret.js",
    "dist/__t16_planted_net.js",
    "dist/__t16_planted_shell.js",
    "dist/__t16_planted_daemon.js",
    "dist/Codex.exe",
    "dist/__t16_bounded_timer.js",
  ];
  for (const rel of planted) {
    assert.equal(
      fs.existsSync(path.join(pkg, rel)),
      false,
      `canonical package poisoned: ${rel}`,
    );
  }
}

const packagePlantCases: { mode: string; reason: string }[] = [
  { mode: "package_secret", reason: "GATE_PACKAGE_AUDIT" },
  { mode: "package_network", reason: "GATE_PACKAGE_AUDIT" },
  { mode: "package_shell", reason: "GATE_PACKAGE_AUDIT" },
  { mode: "package_daemon", reason: "GATE_PACKAGE_AUDIT" },
  { mode: "package_binary", reason: "GATE_PACKAGE_AUDIT" },
];

for (const c of packagePlantCases) {
  test(`Ticket16 self-test ${c.mode} → ${c.reason} without poisoning release/`, async () => {
    ensurePackageBuilt();
    const r = runVerify([`--self-test=${c.mode}`]);
    assert.notEqual(r.status, 0, `${c.mode} should fail closed`);
    assert.ok(r.summary, `${c.mode} must emit JSON summary`);
    assert.equal(r.summary!.ok, false);
    assert.equal(r.summary!.reason_code, c.reason);
    assert.equal(r.summary!.failed_step, "package_audit");
    assertCanonicalPackageNotPoisoned();
    const secrets = await secretValues();
    assertNoSecretCorpusInText(r.stdout + r.stderr, secrets);
  });
}

test("Ticket16 package audit success on real package (when present)", async () => {
  ensurePackageBuilt();
  const mod = await loadGate("package-audit.mjs");
  const audit = (
    mod.checkPackageAudit as (r: string) => { ok: boolean; errors?: string[] }
  )(repoRoot);
  assert.equal(audit.ok, true, JSON.stringify(audit.errors));
  assertCanonicalPackageNotPoisoned();
});

test("Ticket16 pure package plant does not leave files in release/", async () => {
  ensurePackageBuilt();
  const mod = await loadGate("package-audit.mjs");
  const checkPackageAudit = mod.checkPackageAudit as (
    r: string,
    opts?: { plant?: { rel: string; content: string } },
  ) => { ok: boolean; reason_code: string | null; errors?: string[] };
  const poisoned = checkPackageAudit(repoRoot, {
    plant: {
      rel: "dist/__t16_planted_secret.js",
      content: "export const x = 'cg-t16-planted-package-secret';\n",
    },
  });
  assert.equal(poisoned.ok, false);
  assert.equal(poisoned.reason_code, "GATE_PACKAGE_AUDIT");
  assertCanonicalPackageNotPoisoned();
});

test("Ticket16 setTimeout is not treated as daemon (isolated plant)", async () => {
  ensurePackageBuilt();
  const mod = await loadGate("package-audit.mjs");
  const checkPackageAudit = mod.checkPackageAudit as (
    r: string,
    opts?: { plant?: { rel: string; content: string } },
  ) => { ok: boolean; errors?: string[] };
  const okTimer = checkPackageAudit(repoRoot, {
    plant: {
      rel: "dist/__t16_bounded_timer.js",
      content: "setTimeout(() => {}, 100);\n",
    },
  });
  assert.equal(okTimer.ok, true, JSON.stringify(okTimer.errors));
  assertCanonicalPackageNotPoisoned();
});
