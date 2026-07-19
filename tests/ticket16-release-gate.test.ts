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

// ---------------------------------------------------------------------------
// P1 correction R10 — GitHub PAT, outcome-bound gates, package fail-closed
// ---------------------------------------------------------------------------

const GITHUB_PAT_CLASSIC = ["gh", "p_", "cgT16GitHubPatNOTREAL0001ABCDEF"].join("");
const GITHUB_PAT_FINE = [
  "github",
  "_pat_",
  "11CGT16NOTREAL_abcdefghijklmnopqrstuvwx",
].join("");

test("Ticket16: GitHub PAT shapes fail isSendableDisclosureToken and free-text redaction", async () => {
  assert.ok(fs.existsSync(path.join(repoRoot, "dist/evidence/disclosure.js")));
  assert.ok(fs.existsSync(path.join(repoRoot, "dist/core/redact.js")));
  const disc = (await import(
    pathToFileURL(path.join(repoRoot, "dist/evidence/disclosure.js")).href
  )) as {
    isSendableDisclosureToken: (v: string) => boolean;
    sanitizeSendableLocalFields: (c: Record<string, unknown>) => Record<string, unknown>;
    buildDisclosureManifest: (c: Record<string, unknown>) => { fields: unknown[] };
    buildTransportRequest: (
      m: { fields: unknown[] },
      c: Record<string, unknown>,
    ) => Record<string, unknown>;
  };
  const redact = (await import(
    pathToFileURL(path.join(repoRoot, "dist/core/redact.js")).href
  )) as { redactText: (s: string) => string };

  for (const pat of [GITHUB_PAT_CLASSIC, GITHUB_PAT_FINE]) {
    assert.equal(disc.isSendableDisclosureToken(pat), false, `must reject ${pat.slice(0, 12)}`);
    const redacted = redact.redactText(`prefix ${pat} suffix`);
    assert.equal(redacted.includes(pat), false, "redactor must strip PAT body");
    assert.match(redacted, /redacted-secret/);
  }

  // Legitimate identifiers must remain sendable (no broad false positives).
  for (const ok of [
    "0.50.0",
    "browser_control",
    "macos",
    "arm64",
    "shell_environment_policy.set",
    "plugin:cache-manager",
    "Error",
    "github",
    "gh-pages",
    "feature_github_integration",
  ]) {
    assert.equal(disc.isSendableDisclosureToken(ok), true, `must accept ${ok}`);
  }

  const base = {
    codex_version: "0.50.0",
    surface: "browser_control",
    platform_os: "macos",
    platform_arch: "arm64",
    config_keys: ["shell_environment_policy.set"],
    feature_ids: ["browser"],
  };
  for (const pat of [GITHUB_PAT_CLASSIC, GITHUB_PAT_FINE]) {
    for (const field of [
      "codex_version",
      "surface",
      "platform_os",
      "platform_arch",
      "error_class",
    ] as const) {
      const ctx = { ...base, [field]: pat };
      const sendable = disc.sanitizeSendableLocalFields(ctx);
      assert.equal(JSON.stringify(sendable).includes(pat), false);
      const manifest = disc.buildDisclosureManifest(ctx);
      const req = disc.buildTransportRequest(manifest, ctx);
      assert.equal(JSON.stringify(req).includes(pat), false);
    }
    for (const field of ["config_keys", "feature_ids"] as const) {
      const ctx = { ...base, [field]: [pat, "safe.id"] };
      const sendable = disc.sanitizeSendableLocalFields(ctx);
      assert.equal(JSON.stringify(sendable).includes(pat), false);
      const manifest = disc.buildDisclosureManifest(ctx);
      const req = disc.buildTransportRequest(manifest, ctx);
      assert.equal(JSON.stringify(req).includes(pat), false);
    }
  }
});

test("Ticket16 fixture accounting rejects title-only / status-outside / wrong-status hollow tests", async () => {
  const os = await import("node:os");
  const fixMod = await loadGate("fixture-accounting.mjs");
  const checkFixtureAccounting = fixMod.checkFixtureAccounting as (
    r: string,
    opts?: { rows?: unknown[]; thresholds?: Record<string, number> },
  ) => { ok: boolean; errors?: string[] };
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-fix-acc-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  const fixtureDir = path.join(tmpRoot, "fixtures", "protected-process");
  fs.mkdirSync(fixtureDir, { recursive: true });
  fs.writeFileSync(path.join(fixtureDir, "marker.txt"), "x\n");

  const title =
    "successful repair preview → apply → RESOLVED_VERIFIED hollow title only";
  // Title-only: same title + fixture/seam calls, but no outcome status assert
  fs.writeFileSync(
    path.join(testsDir, "hollow-title.test.ts"),
    `import test from "node:test";\ntest("${title}", () => {\n  const target = copyFixtureToTemp("fixtures/protected-process", tmp);\n  runCliRepairApply(target, auth);\n  const x = 1;\n});\n`,
  );
  // Status outside the named test (fixture/seam inside; assert outside)
  fs.writeFileSync(
    path.join(testsDir, "status-outside.test.ts"),
    `import assert from "node:assert/strict";\nimport test from "node:test";\nassert.equal("RESOLVED_VERIFIED", "RESOLVED_VERIFIED");\ntest("${title}", () => {\n  const target = copyFixtureToTemp("fixtures/protected-process", tmp);\n  runCliRepairApply(target, auth);\n  const x = 1;\n});\n`,
  );
  // Wrong status inside test
  fs.writeFileSync(
    path.join(testsDir, "wrong-status.test.ts"),
    `import assert from "node:assert/strict";\nimport test from "node:test";\ntest("${title}", () => {\n  assert.equal("MITIGATED_VERIFIED_BY_ROLLBACK", "MITIGATED_VERIFIED_BY_ROLLBACK");\n  copyFixtureToTemp("fixtures/protected-process", tmp);\n  runCliRepairApply(target, auth);\n});\n`,
  );
  // GREEN control: correct status + fixture bind
  fs.writeFileSync(
    path.join(testsDir, "green-status.test.ts"),
    `import assert from "node:assert/strict";\nimport test from "node:test";\ntest("${title}", () => {\n  const target = copyFixtureToTemp("fixtures/protected-process", tmp);\n  assert.equal(result.status, "RESOLVED_VERIFIED");\n  runCliRepairApply(target, auth);\n});\n`,
  );
  // RED: tautological literal-vs-literal status assert inside the named test
  fs.writeFileSync(
    path.join(testsDir, "tautology-status.test.ts"),
    `import assert from "node:assert/strict";\nimport test from "node:test";\ntest("${title}", () => {\n  assert.equal("RESOLVED_VERIFIED", "RESOLVED_VERIFIED");\n  copyFixtureToTemp("fixtures/protected-process", tmp);\n  runCliRepairApply(target, auth);\n});\n`,
  );
  // RED: status text only in assert message / unrelated variable
  fs.writeFileSync(
    path.join(testsDir, "message-only-status.test.ts"),
    `import assert from "node:assert/strict";\nimport test from "node:test";\ntest("${title}", () => {\n  const msg = "RESOLVED_VERIFIED";\n  assert.equal(1, 1, "RESOLVED_VERIFIED");\n  copyFixtureToTemp("fixtures/protected-process", tmp);\n  runCliRepairApply(target, auth);\n});\n`,
  );
  // GREEN: reversed argument order status, literal first
  fs.writeFileSync(
    path.join(testsDir, "green-status-reversed.test.ts"),
    `import assert from "node:assert/strict";\nimport test from "node:test";\ntest("${title}", () => {\n  const target = copyFixtureToTemp("fixtures/protected-process", tmp);\n  assert.equal("RESOLVED_VERIFIED", result.status);\n  runCliRepairApply(target, auth);\n});\n`,
  );

  const baseRow = {
    id: "adv-row",
    bucket: "resolved_verified",
    expected_status: "RESOLVED_VERIFIED",
    fixture: "fixtures/protected-process",
    public_seam: "repair-preview → repair-apply",
    test_name_substr: title,
  };
  const thresholds = {
    resolved_verified: 1,
    mitigation_or_upstream_blocked: 0,
    wrong_repair_refusal: 0,
  };

  const titleOnly = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/hollow-title.test.ts" }],
    thresholds,
  });
  assert.equal(titleOnly.ok, false);
  assert.ok(
    (titleOnly.errors ?? []).some((e) => e.includes("missing_outcome_assert")),
    JSON.stringify(titleOnly.errors),
  );

  const outside = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/status-outside.test.ts" }],
    thresholds,
  });
  assert.equal(outside.ok, false);
  assert.ok(
    (outside.errors ?? []).some((e) => e.includes("missing_outcome_assert")),
    JSON.stringify(outside.errors),
  );

  const wrong = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/wrong-status.test.ts" }],
    thresholds,
  });
  assert.equal(wrong.ok, false);
  assert.ok(
    (wrong.errors ?? []).some((e) => e.includes("missing_outcome_assert")),
    JSON.stringify(wrong.errors),
  );
  const green = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/green-status.test.ts" }],
    thresholds,
  });
  assert.equal(green.ok, true, JSON.stringify(green.errors));

  const tautology = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/tautology-status.test.ts" }],
    thresholds,
  });
  assert.equal(tautology.ok, false);
  assert.ok(
    (tautology.errors ?? []).some((e) => e.includes("missing_outcome_assert")),
    JSON.stringify(tautology.errors),
  );

  const messageOnly = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/message-only-status.test.ts" }],
    thresholds,
  });
  assert.equal(messageOnly.ok, false);
  assert.ok(
    (messageOnly.errors ?? []).some((e) => e.includes("missing_outcome_assert")),
    JSON.stringify(messageOnly.errors),
  );

  const greenReversed = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/green-status-reversed.test.ts" }],
    thresholds,
  });
  assert.equal(greenReversed.ok, true, JSON.stringify(greenReversed.errors));

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test("Ticket16 injection matrix rejects missing / outside-block must_not assertions", async () => {
  const os = await import("node:os");
  const injMod = await loadGate("injection-matrix.mjs");
  const checkInjectionMatrix = injMod.checkInjectionMatrix as (
    r: string,
    opts?: { rows?: unknown[] },
  ) => { ok: boolean; errors?: string[] };
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-inj-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  const title = "prompt injection hollow authority test";

  fs.writeFileSync(
    path.join(testsDir, "hollow-inj.test.ts"),
    `import test from "node:test";\ntest("${title}", () => {\n  const page = loadEnvelope("x");\n});\n`,
  );
  fs.writeFileSync(
    path.join(testsDir, "assert-outside.test.ts"),
    `import assert from "node:assert/strict";\nimport test from "node:test";\nassert.equal(result.repair_authorized, false);\ntest("${title}", () => {\n  const page = 1;\n});\n`,
  );
  fs.writeFileSync(
    path.join(testsDir, "green-inj.test.ts"),
    `import assert from "node:assert/strict";\nimport test from "node:test";\ntest("${title}", () => {\n  assert.equal(result.repair_authorized, false);\n  assert.equal(result.page_evidence.injection_quarantined, true);\n});\n`,
  );

  const baseRow = {
    id: "adv-inj",
    class: "malicious_page",
    invariant: "no repair",
    test_name_substr: title,
    fixture: null,
    must_not: ["authorize_repair"],
  };

  // Class coverage requires full class set — pass one row of each required class
  // via a minimal GREEN set, then poison only the malicious_page row under test.
  const requiredClasses = [
    "malicious_page",
    "issue_upstream",
    "official_prose",
    "blocked_action",
    "followup_authority",
    "repair_dsl",
    "platform_capability",
    "official_fix",
    "change_to_local",
  ];
  function padRows(poisonFile: string): unknown[] {
    const rows: unknown[] = [];
    for (const c of requiredClasses) {
      if (c === "malicious_page") {
        rows.push({ ...baseRow, class: c, test_file: `tests/${poisonFile}` });
      } else {
        // Point at green-inj which has authorize_repair assert — other must_not
        // tokens for non-malicious classes still need matching patterns; use
        // empty must_not and rely on assert presence for those padding rows.
        rows.push({
          id: `pad-${c}`,
          class: c,
          invariant: "pad",
          test_file: "tests/green-inj.test.ts",
          test_name_substr: title,
          fixture: null,
          must_not: [],
        });
      }
    }
    return rows;
  }

  const hollow = checkInjectionMatrix(tmpRoot, { rows: padRows("hollow-inj.test.ts") });
  assert.equal(hollow.ok, false);
  assert.ok((hollow.errors ?? []).some((e) => e.includes("missing_must_not_assert")));

  const outside = checkInjectionMatrix(tmpRoot, {
    rows: padRows("assert-outside.test.ts"),
  });
  assert.equal(outside.ok, false);
  assert.ok((outside.errors ?? []).some((e) => e.includes("missing_must_not_assert")));

  const green = checkInjectionMatrix(tmpRoot, { rows: padRows("green-inj.test.ts") });
  assert.equal(green.ok, true, JSON.stringify(green.errors));

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test("Ticket16 injection matrix: network_used=false cannot satisfy supersede_without_witness", async () => {
  const os = await import("node:os");
  const injMod = await loadGate("injection-matrix.mjs");
  const bindMod = await loadGate("test-case-bind.mjs");
  const checkInjectionMatrix = injMod.checkInjectionMatrix as (
    r: string,
    opts?: { rows?: unknown[] },
  ) => { ok: boolean; errors?: string[] };
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;

  // Direct unit: generic network_used=false is not witness proof.
  assert.equal(
    bodySatisfiesMustNot(`assert.equal(r.network_used, false);`, "supersede_without_witness"),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.error_code, "LIVE_WITNESS_REQUIRED");`,
      "supersede_without_witness",
    ),
    true,
  );
  // Bare FORGED/CONFIRMATION must not mint_confirmation.
  assert.equal(
    bodySatisfiesMustNot(`assert.equal(label, "CONFIRMATION");`, "mint_confirmation"),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(`assert.equal(x, "FORGED");`, "mint_confirmation"),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(preview.confirmation_token, null);`,
      "mint_confirmation",
    ),
    true,
  );

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-inj-witness-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  const title = "subscribe lifecycle hollow witness row";
  fs.writeFileSync(
    path.join(testsDir, "net-only.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  assert.equal(sub.network_used, false);`,
      `  assert.equal(sub.external_write, false);`,
      `});`,
      "",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(testsDir, "witness-green.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  assert.equal(r.ok, false);`,
      `  assert.equal(r.error_code, "LIVE_WITNESS_REQUIRED");`,
      `});`,
      "",
    ].join("\n"),
  );

  const requiredClasses = [
    "malicious_page",
    "issue_upstream",
    "official_prose",
    "blocked_action",
    "followup_authority",
    "repair_dsl",
    "platform_capability",
    "official_fix",
    "change_to_local",
  ];
  function pad(poisonFile: string, mustNot: string[]): unknown[] {
    return requiredClasses.map((c) => {
      if (c === "followup_authority") {
        return {
          id: "adv-witness",
          class: c,
          invariant: "witness",
          test_file: `tests/${poisonFile}`,
          test_name_substr: title,
          fixture: null,
          must_not: mustNot,
        };
      }
      return {
        id: `pad-${c}`,
        class: c,
        invariant: "pad",
        test_file: "tests/witness-green.test.ts",
        test_name_substr: title,
        fixture: null,
        must_not: [],
      };
    });
  }

  const red = checkInjectionMatrix(tmpRoot, {
    rows: pad("net-only.test.ts", ["supersede_without_witness"]),
  });
  assert.equal(red.ok, false);
  assert.ok(
    (red.errors ?? []).some((e) => e.includes("missing_must_not_assert")),
    JSON.stringify(red.errors),
  );

  const green = checkInjectionMatrix(tmpRoot, {
    rows: pad("witness-green.test.ts", ["supersede_without_witness"]),
  });
  assert.equal(green.ok, true, JSON.stringify(green.errors));

  // Canonical matrix still green (separate row binds real supersede witness test).
  const canonical = checkInjectionMatrix(repoRoot);
  assert.equal(canonical.ok, true, JSON.stringify(canonical.errors));

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test("Ticket16 fixture identity bind rejects generic helpers without row path", async () => {
  const os = await import("node:os");
  const fixMod = await loadGate("fixture-accounting.mjs");
  const bindMod = await loadGate("test-case-bind.mjs");
  const checkFixtureAccounting = fixMod.checkFixtureAccounting as (
    r: string,
    opts?: { rows?: unknown[]; thresholds?: Record<string, number> },
  ) => { ok: boolean; errors?: string[] };
  const bodyBindsFixtureOrSeam = bindMod.bodyBindsFixtureOrSeam as (
    body: string,
    fixture: string | null,
    publicSeam: string | null,
  ) => boolean;
  const expandSameFileHelpers = bindMod.expandSameFileHelpers as (
    testBody: string,
    fullSource: string,
  ) => string;

  // Unit: generic helper names alone never bind a concrete fixture path.
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const t = fixtureTemp(PROTECTED); makeTarget(); makeBaselineCandidatePair(); FAMILY_FIXTURES;`,
      "fixtures/protected-process",
      null,
    ),
    false,
  );
  assert.equal(
    bodyBindsFixtureOrSeam(
      `copyFixtureToTemp("fixtures/protected-process", tmp);`,
      "fixtures/protected-process",
      null,
    ),
    true,
  );

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-fix-id-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  fs.mkdirSync(path.join(tmpRoot, "fixtures", "protected-process"), { recursive: true });
  fs.writeFileSync(
    path.join(tmpRoot, "fixtures", "protected-process", "marker.txt"),
    "x\n",
  );
  const title =
    "successful repair preview → apply → RESOLVED_VERIFIED fixture identity";
  // RED: wrong fixture identity with only generic helpers / other family path
  fs.writeFileSync(
    path.join(testsDir, "generic-helper-wrong.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `const FAMILY_FIXTURES = { access: "fixtures/crash-family/access-violation-crbrowser" };`,
      `const PROTECTED = "fixtures/lifecycle";`,
      `function fixtureTemp(rel: string) { return copyFixtureToTemp(rel, tmp); }`,
      `function makeTarget() { return copyFixtureToTemp("fixtures/lifecycle", tmp); }`,
      `test("${title}", () => {`,
      `  const t = fixtureTemp(FAMILY_FIXTURES.access);`,
      `  makeTarget();`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(t, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  // RED: no fixture path at all
  fs.writeFileSync(
    path.join(testsDir, "no-fixture.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  // GREEN: direct path bind
  fs.writeFileSync(
    path.join(testsDir, "direct-green.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  const target = copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  // GREEN: same-file helper/const expansion that actually names the fixture
  fs.writeFileSync(
    path.join(testsDir, "helper-const-green.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `const PROTECTED = "fixtures/protected-process";`,
      `function fixtureTemp(rel: string) { return copyFixtureToTemp(rel, tmp); }`,
      `test("${title}", () => {`,
      `  const target = fixtureTemp(PROTECTED);`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );

  const baseRow = {
    id: "adv-fix-id",
    bucket: "resolved_verified",
    expected_status: "RESOLVED_VERIFIED",
    fixture: "fixtures/protected-process",
    public_seam: "repair-preview → repair-apply",
    test_name_substr: title,
  };
  const thresholds = {
    resolved_verified: 1,
    mitigation_or_upstream_blocked: 0,
    wrong_repair_refusal: 0,
  };

  const wrong = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/generic-helper-wrong.test.ts" }],
    thresholds,
  });
  assert.equal(wrong.ok, false);
  assert.ok(
    (wrong.errors ?? []).some((e) => e.includes("missing_fixture_or_seam_in_test")),
    JSON.stringify(wrong.errors),
  );

  const none = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/no-fixture.test.ts" }],
    thresholds,
  });
  assert.equal(none.ok, false);
  assert.ok(
    (none.errors ?? []).some((e) => e.includes("missing_fixture_or_seam_in_test")),
    JSON.stringify(none.errors),
  );

  const direct = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/direct-green.test.ts" }],
    thresholds,
  });
  assert.equal(direct.ok, true, JSON.stringify(direct.errors));

  const helperGreen = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/helper-const-green.test.ts" }],
    thresholds,
  });
  assert.equal(helperGreen.ok, true, JSON.stringify(helperGreen.errors));

  // Expanded helper source still carries the path identity.
  const helperSrc = fs.readFileSync(
    path.join(tmpRoot, "tests/helper-const-green.test.ts"),
    "utf8",
  );
  const expanded = expandSameFileHelpers(
    `{ const target = fixtureTemp(PROTECTED); assert.equal(result.status, "RESOLVED_VERIFIED"); }`,
    helperSrc,
  );
  assert.equal(
    bodyBindsFixtureOrSeam(expanded, "fixtures/protected-process", null),
    true,
  );

  // Canonical accounting still green
  const canonical = checkFixtureAccounting(repoRoot);
  assert.equal(canonical.ok, true, JSON.stringify(canonical.errors));

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test("Ticket16 write-path inventory enforces forbid_false_repair_claim and behavioral binds", async () => {
  const writeMod = await loadGate("write-path-inventory.mjs");
  const checkWritePathInventory = writeMod.checkWritePathInventory as (
    r: string,
    opts?: { inventory?: unknown[] },
  ) => { ok: boolean; errors?: string[] };

  // Preserve markers but hollow out behavioral assertion (relocate).
  const hollowBehavioral = checkWritePathInventory(repoRoot, {
    inventory: [
      {
        id: "recovery-atomic-write",
        class: "repair",
        rel: "src/core/recovery/atomic-write.ts",
        required_markers: [
          "createVerifiedBackup",
          "atomicReplaceFile",
          "restoreFromBackup",
        ],
        companion_rel: "src/core/recovery/engine.ts",
        companion_markers: [
          "RESOLVED_VERIFIED is impossible",
          "auto_rollback",
          "createVerifiedBackup",
        ],
        boundary_bind: "recovery",
        behavioral_tests: [
          {
            id: "hollow",
            test_file: "tests/ticket02-repair-harness.test.ts",
            test_name_substr: "usage errors remain generic and path-free",
            require_assert_substrings: ["RESOLVED_VERIFIED", "backup", "runCliRepairApply"],
            require_outcome: "RESOLVED_VERIFIED",
          },
        ],
      },
      {
        id: "instance-fingerprint-state",
        class: "state",
        rel: "src/instances/state.ts",
        required_markers: ["writeFileSync", "renameSync"],
        forbid_false_repair_claim: true,
        boundary_bind: "state_allowlist",
        behavioral_tests: [
          {
            id: "state_symlink_refuse",
            test_file: "tests/instance-scan.test.ts",
            test_name_substr: "state refuses symlink state file",
            require_assert_substrings: ["symlink", "assert"],
          },
        ],
      },
      {
        id: "upstream-confirmation-ledger",
        class: "ledger",
        rel: "src/upstream/actions/ledger.ts",
        required_markers: ["writeFileSync", "renameSync"],
        forbid_false_repair_claim: true,
        boundary_bind: "state_allowlist",
        behavioral_tests: [
          {
            id: "offline_forge_refuse",
            test_file: "tests/ticket11-upstream-actions.test.ts",
            test_name_substr:
              "offline forged token without preview registration is refused",
            require_assert_substrings: ["assert", "forged"],
          },
        ],
      },
      {
        id: "followup-ledger",
        class: "ledger",
        rel: "src/upstream/followup/ledger.ts",
        required_markers: ["writeFileSync", "renameSync"],
        forbid_false_repair_claim: true,
        boundary_bind: "state_allowlist",
        behavioral_tests: [
          {
            id: "followup_ledger_schema",
            test_file: "tests/ticket12-followup-core.test.ts",
            test_name_substr:
              "Ticket12 ledger: exact schema, digest, capacity, no secrets/raw paths",
            require_assert_substrings: ["ledger_digest", "assert"],
          },
        ],
      },
      {
        id: "lifecycle-ledger",
        class: "ledger",
        rel: "src/core/lifecycle/ledger.ts",
        required_markers: ["KNOWN_GOOD", "checkpoint"],
        forbid_false_repair_claim: true,
        boundary_bind: "lifecycle",
        behavioral_tests: [
          {
            id: "lifecycle_corrupt_refuse",
            test_file: "tests/ticket06-lifecycle.test.ts",
            test_name_substr: "corrupt/tampered/symlink ledger refused",
            require_assert_substrings: ["assert", "ledger"],
          },
        ],
      },
    ],
  });
  assert.equal(hollowBehavioral.ok, false);
  assert.ok(
    (hollowBehavioral.errors ?? []).some(
      (e) =>
        e.includes("missing_behavioral_assert") ||
        e.includes("missing_behavioral_outcome"),
    ),
    JSON.stringify(hollowBehavioral.errors),
  );

  // State writer must keep forbid_false_repair_claim (missing flag fails).
  const missingForbid = checkWritePathInventory(repoRoot, {
    inventory: [
      {
        id: "instance-fingerprint-state",
        class: "state",
        rel: "src/instances/state.ts",
        required_markers: ["writeFileSync", "renameSync"],
        // forbid_false_repair_claim intentionally omitted
        boundary_bind: "state_allowlist",
        behavioral_tests: [
          {
            id: "state_symlink_refuse",
            test_file: "tests/instance-scan.test.ts",
            test_name_substr: "state refuses symlink state file",
            require_assert_substrings: ["symlink", "assert"],
          },
        ],
      },
    ],
  });
  assert.equal(missingForbid.ok, false);
  assert.ok(
    (missingForbid.errors ?? []).some(
      (e) =>
        e.includes("missing_forbid_false_repair_claim") ||
        e.includes("missing_inventory_for_allowlist") ||
        e.includes("missing_recovery_inventory"),
    ),
  );

  // Canonical inventory still green
  const green = checkWritePathInventory(repoRoot);
  assert.equal(green.ok, true, JSON.stringify(green.errors));
});

test("Ticket16 write-path AST evidence rejects string/comment/tautology behavioral spoofs", async () => {
  const os = await import("node:os");
  const writeMod = await loadGate("write-path-inventory.mjs");
  const bindBehavioralTest = writeMod.bindBehavioralTest as (
    r: string,
    bt: Record<string, unknown>,
    entryId: string,
  ) => string[];
  const bodyProvesNotResolvedOnFailure = writeMod.bodyProvesNotResolvedOnFailure as (
    body: string,
  ) => boolean;
  const bodyHasAssertToken = writeMod.bodyHasAssertToken as (
    body: string,
    token: string,
  ) => boolean;

  // Unit: non-call string payload is not executable evidence for tokens.
  assert.equal(
    bodyHasAssertToken(`const spoof = "auto_rolled_back";`, "auto_rolled_back"),
    false,
  );
  assert.equal(
    bodyHasAssertToken(`assert.equal(apply.result!.auto_rolled_back, true);`, "auto_rolled_back"),
    true,
  );
  assert.equal(
    bodyProvesNotResolvedOnFailure(
      `assert.equal("REPAIR_FAILED_ROLLED_BACK", "REPAIR_FAILED_ROLLED_BACK");\nassert.equal("RESOLVED_VERIFIED", "RESOLVED_VERIFIED");`,
    ),
    false,
  );
  assert.equal(
    bodyProvesNotResolvedOnFailure(
      [
        `assert.equal(apply.result!.auto_rolled_back, true);`,
        `assert.equal((apply.result!.user_resolution as { status: string }).status, "REPAIR_FAILED_ROLLED_BACK");`,
        `assert.notEqual((apply.result!.user_resolution as { status: string }).status, "RESOLVED_VERIFIED");`,
      ].join("\n"),
    ),
    true,
  );

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-wp-ast-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  const title = "induced verification failure auto-rollbacks hollow";
  // RED: tokens only in comments / non-call strings + tautological status
  fs.writeFileSync(
    path.join(testsDir, "spoof-behavioral.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  // auto_rolled_back REPAIR_FAILED_ROLLED_BACK RESOLVED_VERIFIED backup`,
      `  const spoof = "auto_rolled_back REPAIR_FAILED_ROLLED_BACK RESOLVED_VERIFIED";`,
      `  assert.equal("RESOLVED_VERIFIED", "RESOLVED_VERIFIED");`,
      `  assert.equal("REPAIR_FAILED_ROLLED_BACK", "REPAIR_FAILED_ROLLED_BACK");`,
      `});`,
      "",
    ].join("\n"),
  );
  // GREEN-shaped: real failure path asserts
  fs.writeFileSync(
    path.join(testsDir, "green-behavioral.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  assert.equal(apply.result!.auto_rolled_back, true);`,
      `  assert.equal((apply.result!.user_resolution as { status: string }).status, "REPAIR_FAILED_ROLLED_BACK");`,
      `  assert.notEqual((apply.result!.user_resolution as { status: string }).status, "RESOLVED_VERIFIED");`,
      `});`,
      "",
    ].join("\n"),
  );

  const spoofErrs = bindBehavioralTest(
    tmpRoot,
    {
      id: "spoof",
      test_file: "tests/spoof-behavioral.test.ts",
      test_name_substr: title,
      require_assert_substrings: [
        "auto_rolled_back",
        "REPAIR_FAILED_ROLLED_BACK",
        "RESOLVED_VERIFIED",
      ],
      require_not_resolved_on_failure: true,
    },
    "recovery-atomic-write",
  );
  assert.ok(spoofErrs.length > 0, "spoof must fail");
  assert.ok(
    spoofErrs.some(
      (e) =>
        e.includes("missing_behavioral_assert") ||
        e.includes("missing_no_resolved_on_failure"),
    ),
    JSON.stringify(spoofErrs),
  );

  const greenErrs = bindBehavioralTest(
    tmpRoot,
    {
      id: "green",
      test_file: "tests/green-behavioral.test.ts",
      test_name_substr: title,
      require_assert_substrings: [
        "auto_rolled_back",
        "REPAIR_FAILED_ROLLED_BACK",
        "RESOLVED_VERIFIED",
      ],
      require_not_resolved_on_failure: true,
    },
    "recovery-atomic-write",
  );
  assert.deepEqual(greenErrs, [], JSON.stringify(greenErrs));

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// P1 correction R12 — AST binder rejects comment/string/disabled-test false-greens
// ---------------------------------------------------------------------------

test("Ticket16 AST binder: comment/string/disabled-test/ambiguity false-greens rejected", async () => {
  const os = await import("node:os");
  const fixMod = await loadGate("fixture-accounting.mjs");
  const bindMod = await loadGate("test-case-bind.mjs");
  const checkFixtureAccounting = fixMod.checkFixtureAccounting as (
    r: string,
    opts?: { rows?: unknown[]; thresholds?: Record<string, number> },
  ) => { ok: boolean; errors?: string[] };
  const extractNamedTestCase = bindMod.extractNamedTestCase as (
    source: string,
    titleSubstr: string,
  ) => { title: string; body: string } | null;
  const expandSameFileHelpers = bindMod.expandSameFileHelpers as (
    testBody: string,
    fullSource: string,
  ) => string;
  const bodyHasOutcomeAssert = bindMod.bodyHasOutcomeAssert as (
    body: string,
    expected: string,
  ) => boolean;

  const title =
    "successful repair preview → apply → RESOLVED_VERIFIED hollow title only";
  const thresholds = {
    resolved_verified: 1,
    mitigation_or_upstream_blocked: 0,
    wrong_repair_refusal: 0,
  };
  const baseRow = {
    id: "adv-ast-row",
    bucket: "resolved_verified",
    expected_status: "RESOLVED_VERIFIED",
    fixture: "fixtures/protected-process",
    public_seam: "repair-preview → repair-apply",
    test_name_substr: title,
  };

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-ast-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  const fixtureDir = path.join(tmpRoot, "fixtures", "protected-process");
  fs.mkdirSync(fixtureDir, { recursive: true });
  fs.writeFileSync(path.join(fixtureDir, "marker.txt"), "x\n");

  function writeCase(name: string, source: string): string {
    const rel = `tests/${name}`;
    fs.writeFileSync(path.join(tmpRoot, rel), source);
    return rel;
  }

  function expectMissingOutcome(rel: string): void {
    const r = checkFixtureAccounting(tmpRoot, {
      rows: [{ ...baseRow, test_file: rel }],
      thresholds,
    });
    assert.equal(r.ok, false, `expected fail for ${rel}`);
    assert.ok(
      (r.errors ?? []).some(
        (e) =>
          e.includes("missing_outcome_assert") ||
          e.includes("missing_or_ambiguous_test_case"),
      ),
      `expected missing_outcome / missing_or_ambiguous for ${rel}: ${JSON.stringify(r.errors)}`,
    );
  }

  // Line-commented test(...) — not executable; binder must not find it.
  writeCase(
    "line-commented.test.ts",
    [
      `// test("${title}", () => {`,
      `//   assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `//   copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `//   runCliRepairApply(target, auth);`,
      `// });`,
      "",
    ].join("\n"),
  );
  expectMissingOutcome("tests/line-commented.test.ts");
  assert.equal(
    extractNamedTestCase(
      fs.readFileSync(path.join(tmpRoot, "tests/line-commented.test.ts"), "utf8"),
      title,
    ),
    null,
  );

  // Block-commented test(...) — same.
  writeCase(
    "block-commented.test.ts",
    [
      `/* test("${title}", () => {`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  runCliRepairApply(target, auth);`,
      `}); */`,
      "",
    ].join("\n"),
  );
  expectMissingOutcome("tests/block-commented.test.ts");
  assert.equal(
    extractNamedTestCase(
      fs.readFileSync(path.join(tmpRoot, "tests/block-commented.test.ts"), "utf8"),
      title,
    ),
    null,
  );

  // Live test with required status only in a line comment.
  writeCase(
    "status-in-comment.test.ts",
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  // assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  const target = copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  expectMissingOutcome("tests/status-in-comment.test.ts");

  // Live test with assertion-shaped text only in ordinary string/template literal.
  writeCase(
    "status-in-string.test.ts",
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  const spoof = 'assert.equal(result.status, "RESOLVED_VERIFIED")';`,
      "  const spoof2 = `assert.equal(result.status, \"RESOLVED_VERIFIED\")`;",
      `  const target = copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  expectMissingOutcome("tests/status-in-string.test.ts");

  // Commented-out helper contains the only assertion; live test calls helper.
  writeCase(
    "commented-helper.test.ts",
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `// function helperAssert() { assert.equal(result.status, "RESOLVED_VERIFIED"); }`,
      `test("${title}", () => {`,
      `  helperAssert();`,
      `  const target = copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  expectMissingOutcome("tests/commented-helper.test.ts");

  // test.skip / test.todo are not executed proof.
  writeCase(
    "skipped-test.test.ts",
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test.skip("${title}", () => {`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  const target = copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  expectMissingOutcome("tests/skipped-test.test.ts");
  assert.equal(
    extractNamedTestCase(
      fs.readFileSync(path.join(tmpRoot, "tests/skipped-test.test.ts"), "utf8"),
      title,
    ),
    null,
  );

  // Duplicate / substring title ambiguity fails closed unless exactly one
  // exact title equality exists.
  const ambTitleA = "ambiguous repair title alpha";
  const ambTitleB = "ambiguous repair title beta";
  const ambSubstr = "ambiguous repair title"; // matches both; equals neither
  writeCase(
    "ambiguous-titles.test.ts",
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${ambTitleA}", () => {`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      `test("${ambTitleB}", () => {`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  const ambSource = fs.readFileSync(
    path.join(tmpRoot, "tests/ambiguous-titles.test.ts"),
    "utf8",
  );
  // Shared substring matches both titles and equals neither → fail closed.
  assert.equal(extractNamedTestCase(ambSource, ambSubstr), null);
  // Exact title equality is the only safe disambiguation.
  assert.equal(extractNamedTestCase(ambSource, ambTitleA)?.title, ambTitleA);
  assert.equal(extractNamedTestCase(ambSource, ambTitleB)?.title, ambTitleB);
  const ambRow = checkFixtureAccounting(tmpRoot, {
    rows: [
      {
        ...baseRow,
        id: "adv-ast-ambig",
        test_file: "tests/ambiguous-titles.test.ts",
        test_name_substr: ambSubstr,
      },
    ],
    thresholds,
  });
  assert.equal(ambRow.ok, false);
  assert.ok((ambRow.errors ?? []).some((e) => e.includes("missing_or_ambiguous_test_case")));

  // GREEN: actual helper-chain assertion remains accepted.
  writeCase(
    "helper-chain-green.test.ts",
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `function helperAssert() {`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `}`,
      `test("${title}", () => {`,
      `  helperAssert();`,
      `  const target = copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  const greenHelper = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/helper-chain-green.test.ts" }],
    thresholds,
  });
  assert.equal(greenHelper.ok, true, JSON.stringify(greenHelper.errors));
  const greenSrc = fs.readFileSync(
    path.join(tmpRoot, "tests/helper-chain-green.test.ts"),
    "utf8",
  );
  const greenEx = extractNamedTestCase(greenSrc, title);
  assert.ok(greenEx);
  const expanded = expandSameFileHelpers(greenEx!.body, greenSrc);
  assert.equal(bodyHasOutcomeAssert(expanded, "RESOLVED_VERIFIED"), true);

  // GREEN: inline assert remains accepted.
  writeCase(
    "inline-green.test.ts",
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  const target = copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  const greenInline = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/inline-green.test.ts" }],
    thresholds,
  });
  assert.equal(greenInline.ok, true, JSON.stringify(greenInline.errors));

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test("Ticket16 package audit fails closed on unreadable files, bare fetch(var), arbitrary exec", async () => {
  ensurePackageBuilt();
  const mod = await loadGate("package-audit.mjs");
  const checkPackageAudit = mod.checkPackageAudit as (
    r: string,
    opts?: {
      plant?: { rel: string; content: string };
      readFileUtf8?: (abs: string) => string;
    },
  ) => { ok: boolean; reason_code: string | null; errors?: string[] };

  // Unreadable package file → fail closed (not silent skip)
  const unread = checkPackageAudit(repoRoot, {
    readFileUtf8: () => {
      throw new Error("EACCES");
    },
  });
  assert.equal(unread.ok, false);
  assert.equal(unread.reason_code, "GATE_PACKAGE_AUDIT");
  assert.ok(
    (unread.errors ?? []).some((e) => e.includes("unreadable_package_file")),
    JSON.stringify(unread.errors),
  );

  // Bare fetch with variable / computed argument
  const fetchVar = checkPackageAudit(repoRoot, {
    plant: {
      rel: "dist/__t16_fetch_var.js",
      content: 'const u = "https://example.invalid";\nfetch(u);\n',
    },
  });
  assert.equal(fetchVar.ok, false);
  assert.ok(
    (fetchVar.errors ?? []).some((e) => e.includes("network_global")),
    JSON.stringify(fetchVar.errors),
  );

  // Arbitrary executable on non-allowlisted surface
  const arb = checkPackageAudit(repoRoot, {
    plant: {
      rel: "dist/__t16_arb_exec.js",
      content:
        'import { spawn } from "node:child_process";\nspawn("curl", ["https://evil"]);\n',
    },
  });
  assert.equal(arb.ok, false);
  assert.ok(
    (arb.errors ?? []).some(
      (e) => e.includes("shell_child_process") || e.includes("arbitrary_shell"),
    ),
    JSON.stringify(arb.errors),
  );

  // Arbitrary executable even on allowlisted harness path
  const arbAllow = checkPackageAudit(repoRoot, {
    plant: {
      rel: "dist/harness/scenario.js",
      content:
        'import { spawnSync } from "node:child_process";\nspawnSync("python", ["-c", "print(1)"]);\n',
    },
  });
  assert.equal(arbAllow.ok, false);
  assert.ok(
    (arbAllow.errors ?? []).some((e) => e.includes("arbitrary_shell")),
    JSON.stringify(arbAllow.errors),
  );

  assertCanonicalPackageNotPoisoned();
});

// ---------------------------------------------------------------------------
// P1 correction R15 — Root R14 residual evidence-spoof probes
// ---------------------------------------------------------------------------

test("Ticket16 R15: residual Root probes reject dead fixture / token / witness spoofs", async () => {
  const bindMod = await loadGate("test-case-bind.mjs");
  const writeMod = await loadGate("write-path-inventory.mjs");
  const fixMod = await loadGate("fixture-accounting.mjs");
  const injMod = await loadGate("injection-matrix.mjs");
  const bodyBindsFixtureOrSeam = bindMod.bodyBindsFixtureOrSeam as (
    body: string,
    fixture: string | null,
    publicSeam: string | null,
  ) => boolean;
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;
  const expandSameFileHelpers = bindMod.expandSameFileHelpers as (
    testBody: string,
    fullSource: string,
  ) => string;
  const bodyHasAssertToken = writeMod.bodyHasAssertToken as (
    body: string,
    token: string,
  ) => boolean;
  const checkFixtureAccounting = fixMod.checkFixtureAccounting as (
    r: string,
    opts?: { rows?: unknown[]; thresholds?: Record<string, number> },
  ) => { ok: boolean; errors?: string[] };
  const checkWritePathInventory = writeMod.checkWritePathInventory as (
    r: string,
  ) => { ok: boolean; errors?: string[] };
  const checkInjectionMatrix = injMod.checkInjectionMatrix as (
    r: string,
  ) => { ok: boolean; errors?: string[] };

  // --- Root-confirmed residual false-greens (must all be false) ---
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const unused = "fixtures/protected-process"; makeTarget(); assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "fixtures/protected-process",
      null,
    ),
    false,
    "dead fixture string must not bind",
  );
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const PROTECTED = "fixtures/protected-process"; const unused = PROTECTED; makeTarget(); assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "fixtures/protected-process",
      null,
    ),
    false,
    "unreferenced const path must not bind",
  );
  // Alias / order / comment / string-equivalent spoofs
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const pathAlias = 'fixtures/protected-process'; /* copyFixtureToTemp */ assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "fixtures/protected-process",
      null,
    ),
    false,
  );
  assert.equal(
    bodyBindsFixtureOrSeam(
      `assert.equal(result.status, "RESOLVED_VERIFIED"); const dead = \`fixtures/protected-process\`;`,
      "fixtures/protected-process",
      null,
    ),
    false,
  );
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const bag = { f: "fixtures/protected-process" }; assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "fixtures/protected-process",
      null,
    ),
    false,
    "object property path not flowing into consumer must not bind",
  );

  assert.equal(
    bodyHasAssertToken(
      `const backupOnly = 1; assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "backup",
    ),
    false,
    "superstring identifier backupOnly is not backup evidence",
  );
  assert.equal(
    bodyHasAssertToken(
      `const backup = true; assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "backup",
    ),
    false,
    "dead backup binding without assert/property role is not evidence",
  );
  assert.equal(
    bodyHasAssertToken(`// backup\nassert.equal(1, 1);`, "backup"),
    false,
  );
  assert.equal(
    bodyHasAssertToken(`const s = "backup"; assert.equal(1, 1);`, "backup"),
    false,
  );

  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(label, "LIVE_WITNESS_REQUIRED");`,
      "supersede_without_witness",
    ),
    false,
    "unrelated label assert is not witness refusal",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.status, "LIVE_WITNESS_REQUIRED");`,
      "supersede_without_witness",
    ),
    false,
    "unrelated .status equal to LIVE_WITNESS_* is not witness refusal",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(msg, "need LIVE_WITNESS_REQUIRED");`,
      "supersede_without_witness",
    ),
    false,
  );
  // mint_confirmation: unrelated property spoof must stay closed
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(label, "BLOCKED_CAPSULE");`,
      "mint_confirmation",
    ),
    false,
  );

  // --- GREEN controls ---
  assert.equal(
    bodyBindsFixtureOrSeam(
      `copyFixtureToTemp("fixtures/protected-process", tmp); assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "fixtures/protected-process",
      null,
    ),
    true,
    "direct consumer path argument is GREEN",
  );
  {
    const full = [
      `const PROTECTED = "fixtures/protected-process";`,
      `function fixtureTemp(rel: string) { return copyFixtureToTemp(rel, tmp); }`,
      `test("t", () => {`,
      `  const target = fixtureTemp(PROTECTED);`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `});`,
    ].join("\n");
    const body = `{ const target = fixtureTemp(PROTECTED); assert.equal(result.status, "RESOLVED_VERIFIED"); }`;
    const expanded = expandSameFileHelpers(body, full);
    assert.equal(
      bodyBindsFixtureOrSeam(expanded, "fixtures/protected-process", null),
      true,
      "const→fixtureTemp→copyFixtureToTemp flow is GREEN",
    );
  }
  {
    // Object-map + CRASH_ROOT template style (ticket09)
    const full = [
      `const CRASH_ROOT = "fixtures/crash-family";`,
      `const FAMILY_FIXTURES = { access: \`\${CRASH_ROOT}/access-violation-crbrowser\` };`,
      `function fixtureTemp(rel: string) { return copyFixtureToTemp(rel, tmp); }`,
      `test("t", () => { fixtureTemp(FAMILY_FIXTURES.access); });`,
    ].join("\n");
    const body = `{ fixtureTemp(FAMILY_FIXTURES.access); }`;
    const expanded = expandSameFileHelpers(body, full);
    assert.equal(
      bodyBindsFixtureOrSeam(
        expanded,
        "fixtures/crash-family/access-violation-crbrowser",
        null,
      ),
      true,
      "FAMILY_FIXTURES template flow is GREEN",
    );
  }

  assert.equal(
    bodyHasAssertToken(
      `assert.ok(capsule.backup && typeof capsule.backup === "object");`,
      "backup",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `assert.equal((capsule.backup as { backup_rel: string }).backup_rel, rel);`,
      "backup",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `runCliRepairApply(target, auth); assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "runCliRepairApply",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `assert.equal(apply.result!.auto_rolled_back, true);`,
      "auto_rolled_back",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `fs.symlinkSync(a, b); assert.equal(scan.error_code, "SYMLINK_REFUSED");`,
      "symlink",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `assert.match(empty.ledger_digest, /^[a-f0-9]{64}$/);`,
      "ledger_digest",
    ),
    true,
  );

  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.error_code, "LIVE_WITNESS_REQUIRED");`,
      "supersede_without_witness",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(sup.error_code, "LIVE_WITNESS_REPLAY");`,
      "supersede_without_witness",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(isLiveMeasurementWitness(cloned), false);`,
      "supersede_without_witness",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(preview.confirmation_token, null);`,
      "mint_confirmation",
    ),
    true,
  );

  // Canonical matrices / inventories remain GREEN
  const fix = checkFixtureAccounting(repoRoot);
  assert.equal(fix.ok, true, JSON.stringify(fix.errors));
  const write = checkWritePathInventory(repoRoot);
  assert.equal(write.ok, true, JSON.stringify(write.errors));
  const inj = checkInjectionMatrix(repoRoot);
  assert.equal(inj.ok, true, JSON.stringify(inj.errors));
});

// ---------------------------------------------------------------------------
// P1 correction R16 — semantic evidence contracts; residual generic-token
// false-greens (path.join-as-consumer, unrelated.backup, forged bare,
// other.status mint_confirmation)
// ---------------------------------------------------------------------------

test("Ticket16 R16: residual Root probes reject path.join/token/mint false-greens", async () => {
  const os = await import("node:os");
  const bindMod = await loadGate("test-case-bind.mjs");
  const writeMod = await loadGate("write-path-inventory.mjs");
  const fixMod = await loadGate("fixture-accounting.mjs");
  const injMod = await loadGate("injection-matrix.mjs");
  const bodyBindsFixtureOrSeam = bindMod.bodyBindsFixtureOrSeam as (
    body: string,
    fixture: string | null,
    publicSeam: string | null,
  ) => boolean;
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;
  const bodyHasAssertToken = writeMod.bodyHasAssertToken as (
    body: string,
    token: string,
  ) => boolean;
  const bindBehavioralTest = writeMod.bindBehavioralTest as (
    r: string,
    bt: Record<string, unknown>,
    entryId: string,
  ) => string[];
  const checkFixtureAccounting = fixMod.checkFixtureAccounting as (
    r: string,
    opts?: { rows?: unknown[]; thresholds?: Record<string, number> },
  ) => { ok: boolean; errors?: string[] };
  const checkWritePathInventory = writeMod.checkWritePathInventory as (
    r: string,
  ) => { ok: boolean; errors?: string[] };
  const checkInjectionMatrix = injMod.checkInjectionMatrix as (
    r: string,
    opts?: { rows?: unknown[] },
  ) => { ok: boolean; errors?: string[] };

  // --- Root-confirmed residual REDs (must all be false) ---
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const p = path.join("fixtures/protected-process", "unused.json"); makeTarget(); assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "fixtures/protected-process",
      null,
    ),
    false,
    "unused path.join assignment must not bind fixture",
  );
  assert.equal(
    bodyHasAssertToken(`assert.equal(unrelated.backup, 1);`, "backup"),
    false,
    "unrelated.backup leaf is not capsule.backup evidence",
  );
  assert.equal(
    bodyHasAssertToken(`assert.equal(forged, true);`, "forged"),
    false,
    "local forged variable is not confirmation refusal proof",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(other.status, "BLOCKED_CAPSULE");`,
      "mint_confirmation",
    ),
    false,
    "unrelated other.status is not mint_confirmation evidence",
  );

  // Alias / order / comment / string variants of the residual probes
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const joined = path.join('fixtures/protected-process', "leaf.json"); assert.equal(1, 1);`,
      "fixtures/protected-process",
      null,
    ),
    false,
  );
  assert.equal(
    bodyBindsFixtureOrSeam(
      `// path.join("fixtures/protected-process")\nassert.equal(result.status, "RESOLVED_VERIFIED");`,
      "fixtures/protected-process",
      null,
    ),
    false,
  );
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const s = "path.join(fixtures/protected-process)"; assert.equal(1, 1);`,
      "fixtures/protected-process",
      null,
    ),
    false,
  );
  assert.equal(
    bodyHasAssertToken(
      `assert.equal(1, unrelated.backup); // reverse order leaf`,
      "backup",
    ),
    false,
  );
  assert.equal(
    bodyHasAssertToken(`const forged = { mac: "x" }; assert.ok(forged);`, "forged"),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal("BLOCKED_CAPSULE", other.status);`,
      "mint_confirmation",
    ),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(label, "PREVIEW_BLOCKED");`,
      "mint_confirmation",
    ),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(x, "INVALID_CONFIRMATION");`,
      "mint_confirmation",
    ),
    false,
  );

  // --- GREEN: nested path.join inside real I/O consumer ---
  assert.equal(
    bodyBindsFixtureOrSeam(
      `fs.readFileSync(path.join("fixtures/protected-process", "marker.txt"));`,
      "fixtures/protected-process",
      null,
    ),
    true,
    "nested path.join inside fs.readFileSync is GREEN",
  );
  assert.equal(
    bodyBindsFixtureOrSeam(
      `const raw = fs.readFileSync(path.join(REPO_ROOT, "fixtures/protected-process", "incident.json"), "utf8");`,
      "fixtures/protected-process",
      null,
    ),
    true,
  );
  assert.equal(
    bodyBindsFixtureOrSeam(
      `copyFixtureToTemp("fixtures/protected-process", tmp);`,
      "fixtures/protected-process",
      null,
    ),
    true,
  );

  // --- GREEN: real repair / ledger / refusal field assertions ---
  assert.equal(
    bodyHasAssertToken(
      `assert.ok(capsule.backup && typeof capsule.backup === "object");`,
      "backup",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `assert.equal((capsule.backup as { backup_rel: string }).backup_rel, rel);`,
      "backup",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `assert.equal(apply.result!.auto_rolled_back, true);`,
      "auto_rolled_back",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `assert.equal(scan.error_code, "SYMLINK_REFUSED");`,
      "symlink",
    ),
    true,
  );
  assert.equal(
    bodyHasAssertToken(
      `assert.match(empty.ledger_digest, /^[a-f0-9]{64}$/);`,
      "ledger_digest",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(preview.confirmation_token, null);`,
      "mint_confirmation",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(preview.status, "BLOCKED_CAPSULE");`,
      "mint_confirmation",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(confirm.error_code, "UNREGISTERED_CONFIRMATION");`,
      "mint_confirmation",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(gate.passed, false);`,
      "mint_confirmation",
    ),
    true,
  );

  // Production binder RED: hollow offline forge (forged name only)
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-r16-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  const forgeTitle = "offline forged token without preview registration is refused";
  fs.writeFileSync(
    path.join(testsDir, "hollow-forge.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${forgeTitle}", () => {`,
      `  const forged = true;`,
      `  assert.equal(forged, true);`,
      `});`,
      "",
    ].join("\n"),
  );
  const hollowForgeErrs = bindBehavioralTest(
    tmpRoot,
    {
      id: "offline_forge_refuse",
      test_file: "tests/hollow-forge.test.ts",
      test_name_substr: forgeTitle,
      require_evidence: [
        {
          kind: "field_assert",
          field: "external_write",
          equals: false,
          roots: ["confirm", "result", "r", "preview"],
        },
        {
          kind: "one_of_field_codes",
          fields: ["status", "error_code"],
          codes: [
            "INVALID_CONFIRMATION",
            "UNREGISTERED_CONFIRMATION",
            "MALFORMED_CONFIRMATION",
          ],
          roots: ["confirm", "result", "r", "preview"],
        },
      ],
    },
    "upstream-confirmation-ledger",
  );
  assert.ok(hollowForgeErrs.length > 0, "hollow forged name must fail binder");
  assert.ok(
    hollowForgeErrs.some((e) => e.includes("missing_behavioral_assert")),
    JSON.stringify(hollowForgeErrs),
  );

  // Production binder RED: unused path.join via fixture accounting
  const title =
    "successful repair preview → apply → RESOLVED_VERIFIED path join residual";
  fs.mkdirSync(path.join(tmpRoot, "fixtures", "protected-process"), {
    recursive: true,
  });
  fs.writeFileSync(
    path.join(tmpRoot, "fixtures", "protected-process", "marker.txt"),
    "x\n",
  );
  fs.writeFileSync(
    path.join(testsDir, "unused-join.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  const p = path.join("fixtures/protected-process", "unused.json");`,
      `  makeTarget();`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(testsDir, "nested-join-green.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  const raw = fs.readFileSync(path.join("fixtures/protected-process", "marker.txt"));`,
      `  assert.equal(result.status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  const thresholds = {
    resolved_verified: 1,
    mitigation_or_upstream_blocked: 0,
    wrong_repair_refusal: 0,
  };
  const baseRow = {
    id: "adv-r16-join",
    bucket: "resolved_verified",
    expected_status: "RESOLVED_VERIFIED",
    fixture: "fixtures/protected-process",
    public_seam: "repair-preview → repair-apply",
    test_name_substr: title,
  };
  const unusedJoin = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/unused-join.test.ts" }],
    thresholds,
  });
  assert.equal(unusedJoin.ok, false);
  assert.ok(
    (unusedJoin.errors ?? []).some((e) =>
      e.includes("missing_fixture_or_seam_in_test"),
    ),
    JSON.stringify(unusedJoin.errors),
  );
  const nestedJoin = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/nested-join-green.test.ts" }],
    thresholds,
  });
  assert.equal(nestedJoin.ok, true, JSON.stringify(nestedJoin.errors));

  // Injection matrix RED: other.status mint spoof through production binder
  const injTitle = "mint confirmation hollow other status";
  fs.writeFileSync(
    path.join(testsDir, "mint-other.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${injTitle}", () => {`,
      `  assert.equal(other.status, "BLOCKED_CAPSULE");`,
      `  assert.equal(label, "PREVIEW_BLOCKED");`,
      `});`,
      "",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(testsDir, "mint-green.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${injTitle}", () => {`,
      `  assert.equal(preview.status, "BLOCKED_CAPSULE");`,
      `  assert.equal(preview.confirmation_token, null);`,
      `});`,
      "",
    ].join("\n"),
  );
  const requiredClasses = [
    "malicious_page",
    "issue_upstream",
    "official_prose",
    "blocked_action",
    "followup_authority",
    "repair_dsl",
    "platform_capability",
    "official_fix",
    "change_to_local",
  ];
  function padMint(poisonFile: string): unknown[] {
    return requiredClasses.map((c) => {
      if (c === "blocked_action") {
        return {
          id: "adv-mint-r16",
          class: c,
          invariant: "mint",
          test_file: `tests/${poisonFile}`,
          test_name_substr: injTitle,
          fixture: null,
          must_not: ["mint_confirmation"],
        };
      }
      return {
        id: `pad-${c}`,
        class: c,
        invariant: "pad",
        test_file: "tests/mint-green.test.ts",
        test_name_substr: injTitle,
        fixture: null,
        must_not: [],
      };
    });
  }
  const mintRed = checkInjectionMatrix(tmpRoot, {
    rows: padMint("mint-other.test.ts"),
  });
  assert.equal(mintRed.ok, false);
  assert.ok(
    (mintRed.errors ?? []).some((e) => e.includes("missing_must_not_assert")),
    JSON.stringify(mintRed.errors),
  );
  const mintGreen = checkInjectionMatrix(tmpRoot, {
    rows: padMint("mint-green.test.ts"),
  });
  assert.equal(mintGreen.ok, true, JSON.stringify(mintGreen.errors));

  // Canonical inventory / matrix / accounting remain GREEN
  assert.equal(
    checkWritePathInventory(repoRoot).ok,
    true,
    JSON.stringify(checkWritePathInventory(repoRoot).errors),
  );
  assert.equal(
    checkFixtureAccounting(repoRoot).ok,
    true,
    JSON.stringify(checkFixtureAccounting(repoRoot).errors),
  );
  assert.equal(
    checkInjectionMatrix(repoRoot).ok,
    true,
    JSON.stringify(checkInjectionMatrix(repoRoot).errors),
  );

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// P1 correction R18 — product-root-bound outcomes; assertion message args are
// not evidence; package-audit GitHub PAT symmetry (R17 independent-review)
// ---------------------------------------------------------------------------

const R18_GITHUB_PAT_CLASSIC = ["gh", "p_", "cgT16GitHubPatNOTREAL0001ABCDEF"].join(
  "",
);
const R18_GITHUB_PAT_FINE = [
  "github",
  "_pat_",
  "11CGT16NOTREAL_abcdefghijklmnopqrstuvwx",
].join("");

test("Ticket16 R18: Root probes reject unrooted status and message-arg false-greens", async () => {
  const bindMod = await loadGate("test-case-bind.mjs");
  const bodyHasOutcomeAssert = bindMod.bodyHasOutcomeAssert as (
    body: string,
    expected: string,
  ) => boolean;
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;

  // --- Root-confirmed REDs (must all be false) ---
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(other.status, "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    false,
    "other.status is not product-root outcome evidence",
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `const status = "x"; assert.equal(status, "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    false,
    "bare status identifier is not product-root outcome evidence",
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(1, 1, "repair_authorized, false");`,
      "refused",
    ),
    false,
    "equality message arg cannot satisfy refused",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(1, 1, "repair_authorized, false");`,
      "authorize_repair",
    ),
    false,
    "equality message arg cannot satisfy authorize_repair",
  );

  // Alias / family REDs: unrelated roots + message args across assert methods
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(fake.status, "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    false,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal("RESOLVED_VERIFIED", other.status);`,
      "RESOLVED_VERIFIED",
    ),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.strictEqual(true, true, "repair_authorized, false");`,
      "authorize_repair",
    ),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.deepEqual({}, {}, "repair_authorized, false");`,
      "authorize_repair",
    ),
    false,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.ok(1 === 1, "repair_authorized, false");`,
      "refused",
    ),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.ok(true, "confidence, \\"none\\"");`,
      "raise_confidence",
    ),
    false,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(1, 1, "NOT_APPLICABLE");`,
      "refused",
    ),
    false,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(1, 1, "authorize_repair");`,
      "authorize_repair",
    ),
    false,
  );

  // --- GREEN: product-root outcomes + field-bound must_not production shapes ---
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(result.status, "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal((apply.result!.user_resolution as { status: string }).status, "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal("RESOLVED_VERIFIED", result.status);`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(result["status"], "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal((result as { status: string }).status, "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(result.diagnosis_state, "UPSTREAM_BLOCKED");`,
      "UPSTREAM_BLOCKED",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal((preview.result!.user_resolution as { status: string }).status, "REPAIR_REFUSED");`,
      "refused",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(preview.result!.error_code, "NOT_APPLICABLE");`,
      "refused",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(preview.result!.authorization, null);`,
      "refused",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(result.repair_authorized, false);`,
      "authorize_repair",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(preview.result!.authorization, null);`,
      "authorize_repair",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(c.status, "candidate_only");`,
      "authorize_repair",
    ),
    true,
  );

  // --- R19/R20 P1 A: Root-reproduced hollow refused / must_not false-greens ---
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal("NOT_APPLICABLE","NOT_APPLICABLE")`,
      "refused",
    ),
    false,
    "tautology NOT_APPLICABLE cannot satisfy refused",
  );
  assert.equal(
    bodyHasOutcomeAssert(`assert.equal(label,"NOT_APPLICABLE")`, "refused"),
    false,
    "bare label identifier cannot satisfy refused",
  );
  assert.equal(
    bodyHasOutcomeAssert(`assert.equal(other.ok,false)`, "refused"),
    false,
    "unrelated other.ok cannot satisfy refused",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(label,"NOT_APPLICABLE")`,
      "authorize_repair",
    ),
    false,
    "label NOT_APPLICABLE cannot satisfy authorize_repair",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(other.status,"candidate_only")`,
      "authorize_repair",
    ),
    false,
    "other.status candidate_only cannot satisfy authorize_repair",
  );

  // --- R19/R20 P1 B: free-standing / OR outcome false-greens ---
  assert.equal(
    bodyHasOutcomeAssert(
      `result.status === "RESOLVED_VERIFIED";`,
      "RESOLVED_VERIFIED",
    ),
    false,
    "free-standing status comparison is not forcing assertion evidence",
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.ok(result.status === "RESOLVED_VERIFIED" || true);`,
      "RESOLVED_VERIFIED",
    ),
    false,
    "assert.ok OR true does not force status outcome",
  );

  // --- R19/R20 GREEN: canonical refusal / authz / forcing outcomes ---
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(preview.result.error_code, "NOT_APPLICABLE")`,
      "refused",
    ),
    true,
    "canonical preview.error_code NOT_APPLICABLE is refused evidence",
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(result.repair_authorized, false)`,
      "refused",
    ),
    true,
    "canonical result.repair_authorized false is refused evidence",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(result.repair_authorized, false)`,
      "authorize_repair",
    ),
    true,
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.equal(result.status, "RESOLVED_VERIFIED")`,
      "RESOLVED_VERIFIED",
    ),
    true,
    "canonical assert.equal status outcome remains GREEN",
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.ok(result.status === "RESOLVED_VERIFIED")`,
      "RESOLVED_VERIFIED",
    ),
    true,
    "canonical assert.ok pure status comparison remains GREEN",
  );
  assert.equal(
    bodyHasOutcomeAssert(
      `assert.ok(result.status === "RESOLVED_VERIFIED" && other.flag)`,
      "RESOLVED_VERIFIED",
    ),
    true,
    "assert.ok AND chain with mandatory status comparison remains GREEN",
  );
});

test("Ticket16 R18: production binder rejects message-arg / unrooted outcome spoofs", async () => {
  const os = await import("node:os");
  const fixMod = await loadGate("fixture-accounting.mjs");
  const injMod = await loadGate("injection-matrix.mjs");
  const checkFixtureAccounting = fixMod.checkFixtureAccounting as (
    r: string,
    opts?: { rows?: unknown[]; thresholds?: Record<string, number> },
  ) => { ok: boolean; errors?: string[] };
  const checkInjectionMatrix = injMod.checkInjectionMatrix as (
    r: string,
    opts?: { rows?: unknown[] },
  ) => { ok: boolean; errors?: string[] };

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-r18-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  fs.mkdirSync(path.join(tmpRoot, "fixtures", "protected-process"), {
    recursive: true,
  });
  fs.writeFileSync(
    path.join(tmpRoot, "fixtures", "protected-process", "marker.txt"),
    "x\n",
  );

  const title =
    "successful repair preview → apply → RESOLVED_VERIFIED r18 root bind";
  const thresholds = {
    resolved_verified: 1,
    mitigation_or_upstream_blocked: 0,
    wrong_repair_refusal: 0,
  };
  const baseRow = {
    id: "adv-r18-outcome",
    bucket: "resolved_verified",
    expected_status: "RESOLVED_VERIFIED",
    fixture: "fixtures/protected-process",
    public_seam: "repair-preview → repair-apply",
    test_name_substr: title,
  };

  // RED: other.status spoof
  fs.writeFileSync(
    path.join(testsDir, "other-status.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  assert.equal(other.status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  const otherRed = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/other-status.test.ts" }],
    thresholds,
  });
  assert.equal(otherRed.ok, false);
  assert.ok(
    (otherRed.errors ?? []).some((e) => e.includes("missing_outcome_assert")),
    JSON.stringify(otherRed.errors),
  );

  // RED: message-arg spoof
  fs.writeFileSync(
    path.join(testsDir, "msg-arg.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  assert.equal(1, 1, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  const msgRed = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/msg-arg.test.ts" }],
    thresholds,
  });
  assert.equal(msgRed.ok, false);
  assert.ok(
    (msgRed.errors ?? []).some((e) => e.includes("missing_outcome_assert")),
    JSON.stringify(msgRed.errors),
  );

  // GREEN: product-root user_resolution.status shape used in production fixtures
  fs.writeFileSync(
    path.join(testsDir, "product-green.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${title}", () => {`,
      `  copyFixtureToTemp("fixtures/protected-process", tmp);`,
      `  assert.equal((apply.result!.user_resolution as { status: string }).status, "RESOLVED_VERIFIED");`,
      `  runCliRepairApply(target, auth);`,
      `});`,
      "",
    ].join("\n"),
  );
  const productGreen = checkFixtureAccounting(tmpRoot, {
    rows: [{ ...baseRow, test_file: "tests/product-green.test.ts" }],
    thresholds,
  });
  assert.equal(productGreen.ok, true, JSON.stringify(productGreen.errors));

  // Injection matrix: message-arg cannot satisfy authorize_repair
  const injTitle = "r18 authorize message arg spoof";
  const requiredClasses = [
    "malicious_page",
    "issue_upstream",
    "official_prose",
    "blocked_action",
    "followup_authority",
    "repair_dsl",
    "platform_capability",
    "official_fix",
    "change_to_local",
  ];
  fs.writeFileSync(
    path.join(testsDir, "auth-msg-red.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${injTitle}", () => {`,
      `  assert.equal(1, 1, "repair_authorized, false");`,
      `});`,
      "",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(testsDir, "auth-field-green.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${injTitle}", () => {`,
      `  assert.equal(result.repair_authorized, false);`,
      `});`,
      "",
    ].join("\n"),
  );
  function padAuth(poisonFile: string): unknown[] {
    return requiredClasses.map((c) => {
      if (c === "malicious_page") {
        return {
          id: "adv-auth-r18",
          class: c,
          invariant: "no repair",
          test_file: `tests/${poisonFile}`,
          test_name_substr: injTitle,
          fixture: null,
          must_not: ["authorize_repair"],
        };
      }
      return {
        id: `pad-${c}`,
        class: c,
        invariant: "pad",
        test_file: "tests/auth-field-green.test.ts",
        test_name_substr: injTitle,
        fixture: null,
        must_not: [],
      };
    });
  }
  const authMsgRed = checkInjectionMatrix(tmpRoot, {
    rows: padAuth("auth-msg-red.test.ts"),
  });
  assert.equal(authMsgRed.ok, false);
  assert.ok(
    (authMsgRed.errors ?? []).some((e) => e.includes("missing_must_not_assert")),
    JSON.stringify(authMsgRed.errors),
  );
  const authFieldGreen = checkInjectionMatrix(tmpRoot, {
    rows: padAuth("auth-field-green.test.ts"),
  });
  assert.equal(authFieldGreen.ok, true, JSON.stringify(authFieldGreen.errors));

  // Canonical matrices remain GREEN after R18 binder tightening
  assert.equal(
    checkFixtureAccounting(repoRoot).ok,
    true,
    JSON.stringify(checkFixtureAccounting(repoRoot).errors),
  );
  assert.equal(
    checkInjectionMatrix(repoRoot).ok,
    true,
    JSON.stringify(checkInjectionMatrix(repoRoot).errors),
  );

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test("Ticket16 R18: package audit rejects embedded GitHub PAT shapes (isolated plant)", async () => {
  ensurePackageBuilt();
  const mod = await loadGate("package-audit.mjs");
  const checkPackageAudit = mod.checkPackageAudit as (
    r: string,
    opts?: { plant?: { rel: string; content: string } },
  ) => { ok: boolean; reason_code: string | null; errors?: string[] };

  for (const [name, token] of [
    ["classic", R18_GITHUB_PAT_CLASSIC],
    ["fine", R18_GITHUB_PAT_FINE],
  ] as const) {
    const r = checkPackageAudit(repoRoot, {
      plant: {
        rel: `dist/__t16_r18_pat_${name}.js`,
        content: `export const k = ${JSON.stringify(token)};\n`,
      },
    });
    assert.equal(r.ok, false, `${name} PAT must fail closed`);
    assert.equal(r.reason_code, "GATE_PACKAGE_AUDIT");
    assert.ok(
      (r.errors ?? []).some((e) => e.includes("embedded_credential")),
      `expected embedded_credential for ${name}, got ${JSON.stringify(r.errors)}`,
    );
    // Failure report must not echo the synthetic token body.
    assert.equal(JSON.stringify(r).includes(token), false);
  }

  // GREEN: legitimate identifiers that mention github/gh without PAT body
  const green = checkPackageAudit(repoRoot, {
    plant: {
      rel: "dist/__t16_r18_pat_green.js",
      content:
        'export const feature = "feature_github_integration";\nexport const pages = "gh-pages";\n',
    },
  });
  assert.equal(green.ok, true, JSON.stringify(green.errors));
  assertCanonicalPackageNotPoisoned();
});

// ---------------------------------------------------------------------------
// P1 correction R22 — systemic must_not forcing-evidence: no free binary /
// string-literal / OR-true / regex-hollow false-greens for any mandatory token
// ---------------------------------------------------------------------------

/** All mandatory injection must_not tokens (matrix inventory). */
const R22_MUST_NOT_TOKENS = [
  "raise_confidence",
  "authorize_repair",
  "mint_confirmation",
  "external_write",
  "add_change_to_local_edge",
  "execute_prose",
  "supersede_without_witness",
  "supersede_recipe_from_caller_path",
  "claim_full_without_receipt",
  "supersede_without_official_bind",
  "binary_install",
] as const;

/** Canonical GREEN production shapes inventory-backed by injection matrix rows. */
const R22_MUST_NOT_GREEN: { token: string; body: string }[] = [
  {
    token: "raise_confidence",
    body: `assert.equal(result.comparison!.confidence, "none");`,
  },
  {
    token: "raise_confidence",
    body: `assert.equal(result.page_evidence!.injection_quarantined, true);`,
  },
  {
    token: "authorize_repair",
    body: `assert.equal(result.repair_authorized, false);`,
  },
  {
    token: "authorize_repair",
    body: `assert.equal(pr.authorization, null);`,
  },
  {
    token: "authorize_repair",
    body: `assert.equal(c.status, "candidate_only");`,
  },
  {
    token: "mint_confirmation",
    body: `assert.equal(preview.confirmation_token, null);`,
  },
  {
    token: "mint_confirmation",
    body: `assert.equal(preview.status, "BLOCKED_CAPSULE");`,
  },
  {
    token: "mint_confirmation",
    body: `assert.ok(confirm.status === "INVALID_CONFIRMATION" || confirm.error_code === "UNREGISTERED_CONFIRMATION" || confirm.error_code === "INVALID_CONFIRMATION" || confirm.error_code === "MALFORMED_CONFIRMATION");`,
  },
  {
    token: "external_write",
    body: `assert.equal(result.external_write, false);`,
  },
  {
    token: "add_change_to_local_edge",
    body: `assert.equal(result.model_mutation_refused, true);`,
  },
  {
    token: "add_change_to_local_edge",
    body: `assert.ok(result.model_mutation_reasons.includes("MODEL_ADD_EDGE_REFUSED"));`,
  },
  {
    token: "execute_prose",
    body: `assert.ok(q.safe_text.startsWith("<quarantined:"));`,
  },
  {
    token: "execute_prose",
    body: `assert.ok(q.quarantine);`,
  },
  {
    token: "supersede_without_witness",
    body: `assert.equal(r.error_code, "LIVE_WITNESS_REQUIRED");`,
  },
  {
    token: "supersede_without_witness",
    body: `assert.equal(isLiveMeasurementWitness(cloned), false);`,
  },
  {
    token: "supersede_recipe_from_caller_path",
    body: `assert.ok(bad.code === "FORBIDDEN_FIELD" || bad.code === "EXTRA_FIELD");`,
  },
  {
    token: "claim_full_without_receipt",
    body: `assert.equal(v.reason_code, "FULL_REQUIRES_REAL_MACHINE");`,
  },
  {
    token: "claim_full_without_receipt",
    body: `assert.equal(status.full_support_claimed, false);`,
  },
  {
    token: "supersede_without_official_bind",
    body: `assert.equal(r.error_code, "MEASUREMENT_SELF_ATTESTATION_DEPRECATED");`,
  },
  {
    token: "binary_install",
    body: `assert.equal(r.candidate?.binary_installed, false);`,
  },
];

test("Ticket16 R22: Root probes reject free-binary / string-literal / OR-true must_not spoofs", async () => {
  const bindMod = await loadGate("test-case-bind.mjs");
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;

  // --- Eight Root-reproduced hollow false-greens (must all be false) ---
  assert.equal(
    bodySatisfiesMustNot(
      `preview.confirmation_token === null;`,
      "mint_confirmation",
    ),
    false,
    "free-standing confirmation_token comparison is not forcing evidence",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.ok(true || confirm.status === "INVALID_CONFIRMATION");`,
      "mint_confirmation",
    ),
    false,
    "assert.ok OR true cannot satisfy mint_confirmation",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `result.error_code === "LIVE_WITNESS_REQUIRED";`,
      "supersede_without_witness",
    ),
    false,
    "free-standing error_code comparison is not forcing evidence",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.ok(true || result.error_code === "LIVE_WITNESS_REQUIRED");`,
      "supersede_without_witness",
    ),
    false,
    "assert.ok OR true cannot satisfy supersede_without_witness",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.ok("quarantined never treated as instructions");`,
      "execute_prose",
    ),
    false,
    "assert.ok string literal is not execute_prose evidence",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.ok("quarantined never treated as instructions");`,
      "add_change_to_local_edge",
    ),
    false,
    "assert.ok string literal is not add_change_to_local_edge evidence",
  );
  assert.equal(
    bodySatisfiesMustNot(`assert.ok("platform_mismatch");`, "raise_confidence"),
    false,
    "assert.ok string literal is not raise_confidence evidence",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.ok("FULL_REQUIRES_REAL_MACHINE");`,
      "claim_full_without_receipt",
    ),
    false,
    "assert.ok string literal is not claim_full_without_receipt evidence",
  );
});

test("Ticket16 R22: table-driven must_not hollow variants fail for every mandatory token", async () => {
  const bindMod = await loadGate("test-case-bind.mjs");
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;

  /** Representative reason-code / phrase strings that used to hollow-match. */
  const hollowStrings: Record<(typeof R22_MUST_NOT_TOKENS)[number], string> = {
    raise_confidence: "platform_mismatch",
    authorize_repair: "REPAIR_REFUSED",
    mint_confirmation: "INVALID_CONFIRMATION",
    external_write: "external_write",
    add_change_to_local_edge: "quarantined never treated as instructions",
    execute_prose: "quarantined never treated as instructions",
    supersede_without_witness: "LIVE_WITNESS_REQUIRED",
    supersede_recipe_from_caller_path: "FORBIDDEN_FIELD",
    claim_full_without_receipt: "FULL_REQUIRES_REAL_MACHINE",
    supersede_without_official_bind: "MEASUREMENT_SELF_ATTESTATION_DEPRECATED",
    binary_install: "binary_installed",
  };

  /** Product field leaves used in free-binary / OR spoofs per token. */
  const productFields: Record<(typeof R22_MUST_NOT_TOKENS)[number], string> = {
    raise_confidence: `result.comparison.confidence === "none"`,
    authorize_repair: `result.repair_authorized === false`,
    mint_confirmation: `preview.confirmation_token === null`,
    external_write: `result.external_write === false`,
    add_change_to_local_edge: `result.model_mutation_refused === true`,
    execute_prose: `q.quarantine === true`,
    supersede_without_witness: `result.error_code === "LIVE_WITNESS_REQUIRED"`,
    supersede_recipe_from_caller_path: `bad.code === "FORBIDDEN_FIELD"`,
    claim_full_without_receipt: `v.reason_code === "FULL_REQUIRES_REAL_MACHINE"`,
    supersede_without_official_bind: `r.error_code === "MEASUREMENT_SELF_ATTESTATION_DEPRECATED"`,
    binary_install: `r.candidate.binary_installed === false`,
  };

  for (const token of R22_MUST_NOT_TOKENS) {
    const lit = hollowStrings[token];
    const fieldCmp = productFields[token];

    // String-only assert.ok
    assert.equal(
      bodySatisfiesMustNot(`assert.ok(${JSON.stringify(lit)});`, token),
      false,
      `${token}: string-only assert.ok must fail`,
    );

    // Bare identifier
    assert.equal(
      bodySatisfiesMustNot(`assert.equal(label, ${JSON.stringify(lit)});`, token),
      false,
      `${token}: bare label identifier must fail`,
    );

    // Unrelated root
    assert.equal(
      bodySatisfiesMustNot(
        `assert.equal(other.status, ${JSON.stringify(lit)});`,
        token,
      ),
      false,
      `${token}: unrelated other.status must fail`,
    );

    // Free-standing binary (no assert wrapper)
    assert.equal(
      bodySatisfiesMustNot(`${fieldCmp};`, token),
      false,
      `${token}: free-standing binary must fail`,
    );

    // OR-true bypass
    assert.equal(
      bodySatisfiesMustNot(`assert.ok(true || (${fieldCmp}));`, token),
      false,
      `${token}: assert.ok OR true must fail`,
    );

    // Message-arg spoof
    assert.equal(
      bodySatisfiesMustNot(
        `assert.equal(1, 1, ${JSON.stringify(lit)});`,
        token,
      ),
      false,
      `${token}: message-arg must fail`,
    );
  }
});

test("Ticket16 R22: GREEN production shapes bind every mandatory must_not token", async () => {
  const bindMod = await loadGate("test-case-bind.mjs");
  const injMod = await loadGate("injection-matrix.mjs");
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;
  const checkInjectionMatrix = injMod.checkInjectionMatrix as (
    r: string,
  ) => { ok: boolean; errors?: string[] };

  const covered = new Set<string>();
  for (const { token, body } of R22_MUST_NOT_GREEN) {
    assert.equal(
      bodySatisfiesMustNot(body, token),
      true,
      `GREEN must bind ${token}: ${body}`,
    );
    covered.add(token);
  }
  for (const token of R22_MUST_NOT_TOKENS) {
    assert.ok(
      covered.has(token),
      `missing GREEN coverage for mandatory token ${token}`,
    );
  }

  // Canonical injection matrix remains GREEN under forcing contracts
  const inj = checkInjectionMatrix(repoRoot);
  assert.equal(inj.ok, true, JSON.stringify(inj.errors));
});

// ---------------------------------------------------------------------------
// P1 correction R23/R24 — narrow semantic contracts: no arbitrary graph SHA,
// no success/binary-as-refusal for official bind, no free-binary negative status
// ---------------------------------------------------------------------------

test("Ticket16 R23: Root probes reject graph-SHA / success-token / free-binary false-greens", async () => {
  const bindMod = await loadGate("test-case-bind.mjs");
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;
  const bodyHasNegativeStatusAssert = bindMod.bodyHasNegativeStatusAssert as (
    body: string,
    status: string,
  ) => boolean;

  // --- Four Root-reproduced hollow false-greens (must all be false) ---
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(result.graph.graph_sha256,"x");`,
      "add_change_to_local_edge",
    ),
    false,
    "arbitrary graph SHA equality is not add_change_to_local_edge evidence",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.candidate.binary_installed,false);`,
      "supersede_without_official_bind",
    ),
    false,
    "binary_installed false is binary_install evidence, not official-bind refusal",
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.status,"SUPERSEDED");`,
      "supersede_without_official_bind",
    ),
    false,
    "successful SUPERSEDED status cannot prove supersede_without_official_bind",
  );
  assert.equal(
    bodyHasNegativeStatusAssert(
      `result.status !== "RESOLVED_VERIFIED";`,
      "RESOLVED_VERIFIED",
    ),
    false,
    "free-standing status inequality is not negative outcome forcing evidence",
  );

  // Additional hollow variants that must stay red
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.candidate.recipe_status, "SUPERSEDED_BY_UPSTREAM_FIX");`,
      "supersede_without_official_bind",
    ),
    false,
    "recipe_status SUPERSEDED_BY_UPSTREAM_FIX proves success, not refusal",
  );
  assert.equal(
    bodyHasNegativeStatusAssert(
      `assert.ok(true || result.status !== "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    false,
    "assert.ok OR true cannot force negative RESOLVED_VERIFIED evidence",
  );
  assert.equal(
    bodyHasNegativeStatusAssert(
      `assert.notEqual(1, 1, "RESOLVED_VERIFIED");`,
      "RESOLVED_VERIFIED",
    ),
    false,
    "message-arg spoof is not negative status evidence",
  );
});

test("Ticket16 R23: GREEN add-edge refusal, official-bind refusal, binary-install, negative status", async () => {
  const bindMod = await loadGate("test-case-bind.mjs");
  const injMod = await loadGate("injection-matrix.mjs");
  const writeMod = await loadGate("write-path-inventory.mjs");
  const bodySatisfiesMustNot = bindMod.bodySatisfiesMustNot as (
    body: string,
    mustNot: string,
  ) => boolean;
  const bodyHasNegativeStatusAssert = bindMod.bodyHasNegativeStatusAssert as (
    body: string,
    status: string,
  ) => boolean;
  const checkInjectionMatrix = injMod.checkInjectionMatrix as (
    r: string,
  ) => { ok: boolean; errors?: string[]; row_count?: number };
  const checkWritePathInventory = writeMod.checkWritePathInventory as (
    r: string,
  ) => { ok: boolean; errors?: string[] };

  // Canonical add-edge refusal (not graph SHA alone)
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(result.model_mutation_refused, true);`,
      "add_change_to_local_edge",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.ok(result.model_mutation_reasons.includes("MODEL_ADD_EDGE_REFUSED"));`,
      "add_change_to_local_edge",
    ),
    true,
  );

  // Official-bind absence refusal (fixed product-rooted error_code)
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.error_code, "MEASUREMENT_SELF_ATTESTATION_DEPRECATED");`,
      "supersede_without_official_bind",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.error_code, "OFFICIAL_EVIDENCE_DIGEST_MISMATCH");`,
      "supersede_without_official_bind",
    ),
    true,
  );

  // binary_install remains separately proven
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.candidate?.binary_installed, false);`,
      "binary_install",
    ),
    true,
  );
  assert.equal(
    bodySatisfiesMustNot(
      `assert.equal(r.candidate?.binary_downloaded, false);`,
      "binary_install",
    ),
    true,
  );

  // Negative outcome: only supported executable assertion forms
  assert.equal(
    bodyHasNegativeStatusAssert(
      `assert.notEqual(result.status, "RESOLVED_VERIFIED")`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );
  assert.equal(
    bodyHasNegativeStatusAssert(
      `assert.notStrictEqual(result.status, "RESOLVED_VERIFIED")`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );
  assert.equal(
    bodyHasNegativeStatusAssert(
      `assert.ok(result.status !== "RESOLVED_VERIFIED")`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );
  assert.equal(
    bodyHasNegativeStatusAssert(
      `assert.ok(result.ok === false && result.status !== "RESOLVED_VERIFIED")`,
      "RESOLVED_VERIFIED",
    ),
    true,
  );

  // Live matrix + write-path inventory stay green after retarget
  const inj = checkInjectionMatrix(repoRoot);
  assert.equal(inj.ok, true, JSON.stringify(inj.errors));
  const wp = checkWritePathInventory(repoRoot);
  assert.equal(wp.ok, true, JSON.stringify(wp.errors));
});

test("Ticket16 R22: production injection binder rejects free-binary mint spoof", async () => {
  const os = await import("node:os");
  const injMod = await loadGate("injection-matrix.mjs");
  const checkInjectionMatrix = injMod.checkInjectionMatrix as (
    r: string,
    opts?: { rows?: unknown[] },
  ) => { ok: boolean; errors?: string[] };

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-r22-"));
  const testsDir = path.join(tmpRoot, "tests");
  fs.mkdirSync(testsDir, { recursive: true });
  const injTitle = "r22 free binary mint confirmation spoof";
  fs.writeFileSync(
    path.join(testsDir, "mint-free-red.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${injTitle}", () => {`,
      `  preview.confirmation_token === null;`,
      `  assert.ok(true || confirm.status === "INVALID_CONFIRMATION");`,
      `});`,
      "",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(testsDir, "mint-force-green.test.ts"),
    [
      `import assert from "node:assert/strict";`,
      `import test from "node:test";`,
      `test("${injTitle}", () => {`,
      `  assert.equal(preview.confirmation_token, null);`,
      `  assert.equal(preview.status, "BLOCKED_CAPSULE");`,
      `});`,
      "",
    ].join("\n"),
  );
  const requiredClasses = [
    "malicious_page",
    "issue_upstream",
    "official_prose",
    "blocked_action",
    "followup_authority",
    "repair_dsl",
    "platform_capability",
    "official_fix",
    "change_to_local",
  ];
  function padMint(poisonFile: string): unknown[] {
    return requiredClasses.map((c) => {
      if (c === "blocked_action") {
        return {
          id: "adv-mint-r22",
          class: c,
          invariant: "mint",
          test_file: `tests/${poisonFile}`,
          test_name_substr: injTitle,
          fixture: null,
          must_not: ["mint_confirmation"],
        };
      }
      return {
        id: `pad-${c}`,
        class: c,
        invariant: "pad",
        test_file: "tests/mint-force-green.test.ts",
        test_name_substr: injTitle,
        fixture: null,
        must_not: [],
      };
    });
  }
  const mintRed = checkInjectionMatrix(tmpRoot, {
    rows: padMint("mint-free-red.test.ts"),
  });
  assert.equal(mintRed.ok, false);
  assert.ok(
    (mintRed.errors ?? []).some((e) => e.includes("missing_must_not_assert")),
    JSON.stringify(mintRed.errors),
  );
  const mintGreen = checkInjectionMatrix(tmpRoot, {
    rows: padMint("mint-force-green.test.ts"),
  });
  assert.equal(mintGreen.ok, true, JSON.stringify(mintGreen.errors));

  assert.equal(
    checkInjectionMatrix(repoRoot).ok,
    true,
    JSON.stringify(checkInjectionMatrix(repoRoot).errors),
  );
  fs.rmSync(tmpRoot, { recursive: true, force: true });
});
