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

// ---------------------------------------------------------------------------
// P1 correction R3 — Root-confirmed false-green closures
// ---------------------------------------------------------------------------

const ROOT_PACKAGE_PLANTS: { name: string; content: string; errorSubstr: string }[] = [
  {
    name: "fetch_global",
    content: 'fetch("https://example.invalid/leak");\n',
    errorSubstr: "network_global",
  },
  {
    name: "child_process_bare_spawn_sh",
    content: 'import { spawn } from "child_process"; spawn("sh", ["-c", "echo x"]);\n',
    errorSubstr: "shell_child_process",
  },
  {
    name: "sk_proj_credential",
    content: 'export const k = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";\n',
    errorSubstr: "embedded_credential",
  },
  {
    name: "websocket_global",
    content: 'new WebSocket("wss://example.invalid");\n',
    errorSubstr: "network_global",
  },
  {
    name: "npm_install_capability",
    content: 'const cmd = "npm i evil-package";\n',
    errorSubstr: "dynamic_install",
  },
];

for (const plant of ROOT_PACKAGE_PLANTS) {
  test(`Ticket16 package audit rejects Root plant: ${plant.name}`, async () => {
    ensurePackageBuilt();
    const mod = await loadGate("package-audit.mjs");
    const checkPackageAudit = mod.checkPackageAudit as (
      r: string,
      opts?: { plant?: { rel: string; content: string } },
    ) => { ok: boolean; reason_code: string | null; errors?: string[] };
    const r = checkPackageAudit(repoRoot, {
      plant: {
        rel: `dist/__t16_root_${plant.name}.js`,
        content: plant.content,
      },
    });
    assert.equal(r.ok, false, `${plant.name} must fail closed`);
    assert.equal(r.reason_code, "GATE_PACKAGE_AUDIT");
    assert.ok(
      (r.errors ?? []).some((e) => e.includes(plant.errorSubstr)),
      `expected error containing ${plant.errorSubstr}, got ${JSON.stringify(r.errors)}`,
    );
    assertCanonicalPackageNotPoisoned();
    const secrets = await secretValues();
    assertNoSecretCorpusInText(JSON.stringify(r), secrets);
  });
}

test("Ticket16 package audit rejects symlink in package tree (safe temp copy)", async () => {
  ensurePackageBuilt();
  const fsPromises = await import("node:fs");
  const os = await import("node:os");
  const pathMod = await import("node:path");
  const canonical = pathMod.join(repoRoot, "release/codex-changeguard-plugin");
  const tempRoot = fsPromises.mkdtempSync(pathMod.join(os.tmpdir(), "cg-t16-symlink-"));
  const isolated = pathMod.join(tempRoot, "codex-changeguard-plugin");
  // Shallow copy of package for symlink plant
  fsPromises.cpSync(canonical, isolated, { recursive: true });
  const linkPath = pathMod.join(isolated, "dist", "__t16_symlink_escape.js");
  try {
    fsPromises.symlinkSync("/etc/hosts", linkPath);
  } catch {
    // Windows may require elevation; skip if symlink unsupported
    fsPromises.rmSync(tempRoot, { recursive: true, force: true });
    assert.ok(true, "symlink unsupported on platform — treated as non-blocking");
    return;
  }
  const mod = await loadGate("package-audit.mjs");
  const checkPackageAudit = mod.checkPackageAudit as (
    r: string,
    opts?: { packageDir?: string },
  ) => { ok: boolean; reason_code: string | null; errors?: string[] };
  const r = checkPackageAudit(repoRoot, { packageDir: isolated });
  fsPromises.rmSync(tempRoot, { recursive: true, force: true });
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "GATE_PACKAGE_AUDIT");
  assert.ok(
    (r.errors ?? []).some((e) => e.includes("package_symlink")),
    JSON.stringify(r.errors),
  );
  assertCanonicalPackageNotPoisoned();
});

test("Ticket16 package audit rejects shell spawn inside allowlisted harness file plant", async () => {
  ensurePackageBuilt();
  const mod = await loadGate("package-audit.mjs");
  const checkPackageAudit = mod.checkPackageAudit as (
    r: string,
    opts?: { plant?: { rel: string; content: string } },
  ) => { ok: boolean; reason_code: string | null; errors?: string[] };
  // Plant content that looks like harness path but with shell interpreter
  const r = checkPackageAudit(repoRoot, {
    plant: {
      rel: "dist/harness/scenario.js",
      content:
        'import { spawn } from "node:child_process";\nspawn("sh", ["-c", "echo pwn"]);\n',
    },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "GATE_PACKAGE_AUDIT");
  assert.ok(
    (r.errors ?? []).some((e) => e.includes("arbitrary_shell")),
    JSON.stringify(r.errors),
  );
  assertCanonicalPackageNotPoisoned();
});

test("Ticket16 package audit rejects bare network import (not only node: prefix)", async () => {
  ensurePackageBuilt();
  const mod = await loadGate("package-audit.mjs");
  const checkPackageAudit = mod.checkPackageAudit as (
    r: string,
    opts?: { plant?: { rel: string; content: string } },
  ) => { ok: boolean; reason_code: string | null; errors?: string[] };
  const r = checkPackageAudit(repoRoot, {
    plant: {
      rel: "dist/__t16_bare_https.js",
      content: 'import https from "https";\nexport const h = https;\n',
    },
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "GATE_PACKAGE_AUDIT");
  assert.ok((r.errors ?? []).some((e) => e.includes("network_module")));
  assertCanonicalPackageNotPoisoned();
});

test("Ticket16 outbound disclosure rejects Root Cookie/OTP/session smuggle", async () => {
  assert.ok(fs.existsSync(path.join(repoRoot, "dist/evidence/disclosure.js")));
  const href = pathToFileURL(path.join(repoRoot, "dist/evidence/disclosure.js")).href;
  const disc = (await import(href)) as {
    buildDisclosureManifest: (c: Record<string, unknown>) => { fields: unknown[] };
    buildTransportRequest: (
      m: { fields: unknown[] },
      c: Record<string, unknown>,
    ) => Record<string, unknown>;
    sanitizeSendableLocalFields: (c: Record<string, unknown>) => Record<string, unknown>;
    isSendableDisclosureToken: (v: string) => boolean;
  };
  const smuggles = [
    "Cookie: session_id=cg-t16-cookie-value-DEADBEEF",
    "one-time-code=847291",
    "session_rollout_content=COMPLETE_ROLLOUT_BODY_cg-t16-session-payload-NOEXPORT",
  ];
  const base = {
    codex_version: "0.50.0",
    surface: "browser_control",
    platform_os: "macos",
    platform_arch: "arm64",
    config_keys: ["shell_environment_policy.set"],
    feature_ids: ["browser"],
  };
  for (const s of smuggles) {
    assert.equal(disc.isSendableDisclosureToken(s), false, `token must reject: ${s.slice(0, 24)}`);
    const ctx = { ...base, error_class: s };
    const sendable = disc.sanitizeSendableLocalFields(ctx);
    assert.equal(sendable.error_class, undefined, "error_class must be omitted");
    const manifest = disc.buildDisclosureManifest(ctx);
    const req = disc.buildTransportRequest(manifest, ctx);
    const text = JSON.stringify(req);
    assert.equal(text.includes(s), false, "smuggle must not appear on request");
    assert.equal(text.includes("cg-t16-cookie-value-DEADBEEF"), false);
    assert.equal(text.includes("847291"), false);
    assert.equal(text.includes("COMPLETE_ROLLOUT_BODY_cg-t16"), false);
    assert.equal("error_class" in req, false);
  }
  // Legitimate identifiers still accepted
  assert.equal(disc.isSendableDisclosureToken("0.50.0"), true);
  assert.equal(disc.isSendableDisclosureToken("browser_control"), true);
  assert.equal(disc.isSendableDisclosureToken("macos"), true);
  assert.equal(disc.isSendableDisclosureToken("arm64"), true);
  assert.equal(disc.isSendableDisclosureToken("shell_environment_policy.set"), true);
  assert.equal(disc.isSendableDisclosureToken("plugin:cache-manager"), true);
  assert.equal(disc.isSendableDisclosureToken("Error"), true);
  const secrets = await secretValues();
  // Full corpus cannot enter any scalar/list sendable field
  for (const v of secrets) {
    assert.equal(disc.isSendableDisclosureToken(v), false);
    for (const field of ["codex_version", "surface", "platform_os", "platform_arch", "error_class"]) {
      const ctx = { ...base, [field]: v };
      const sendable = disc.sanitizeSendableLocalFields(ctx);
      assert.equal(
        JSON.stringify(sendable).includes(v),
        false,
        `secret must not appear in sendable after ${field}`,
      );
    }
    for (const field of ["config_keys", "feature_ids"]) {
      const ctx = { ...base, [field]: [v] };
      const sendable = disc.sanitizeSendableLocalFields(ctx);
      assert.equal(JSON.stringify(sendable).includes(v), false);
    }
  }
});
