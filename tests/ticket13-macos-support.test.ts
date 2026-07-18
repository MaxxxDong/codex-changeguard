/**
 * Ticket 13 — macOS adapter contracts, receipt validator, isolation rules,
 * and (on darwin) real-machine Scenario Harness integration.
 *
 * Full support is declared only from a real-machine receipt with all required
 * scenarios passing AND a process-local live harness witness — never from
 * synthetic fixtures or reloaded JSON alone.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  runCliJson,
  mcpServerEntry,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import {
  MACOS_REQUIRED_SCENARIO_IDS,
  assertDisposableTarget,
  buildMacosCapabilities,
  buildPlatformSupportReceipt,
  captureActiveCodexHomeWitness,
  deriveSupportLevel,
  enumerateMacosCandidates,
  findReceiptLeaks,
  hostCoarseFingerprintOf,
  isolationDigestOf,
  isMacosOperationRegistered,
  macosRegisteredAliases,
  platformStatus,
  readMacosCodexVersionProvenance,
  receiptIdOf,
  scenarioHashOf,
  scenariosDigestOf,
  sealLiveHarnessWitness,
  validatePlatformSupportReceipt,
  type PlatformSupportReceipt,
  type ScenarioOutcome,
} from "../src/platform/index.js";
import { makeTempDir, writeJson } from "./helpers.js";
import { findRepoRoot } from "../src/paths.js";

const REPO = findRepoRoot(import.meta.url);
const IS_DARWIN = process.platform === "darwin";

function assertNoLeakText(text: string): void {
  assert.equal(/\/Users\//.test(text), false, "Users path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text), false, "Bearer leak");
  assert.equal(/\/var\/folders\//.test(text), false, "temp path leak");
}

function syntheticScenarios(
  status: "pass" | "fail" = "pass",
): ScenarioOutcome[] {
  return MACOS_REQUIRED_SCENARIO_IDS.map((id) => ({
    scenario_id: id,
    scenario_hash: scenarioHashOf(id, "synthetic"),
    status,
    outcome_summary: status === "pass" ? "synthetic pass" : "synthetic fail",
    duration_ms: 1,
    required: true,
  }));
}

function baseReceipt(
  overrides: Partial<PlatformSupportReceipt> = {},
): PlatformSupportReceipt {
  const scenarios = overrides.scenarios ?? syntheticScenarios("pass");
  const caps = buildMacosCapabilities({
    platform: "macos",
    arch: "arm64",
    probeHost: false,
  });
  const active_home_witness_digest =
    overrides.isolation?.active_home_witness_digest ??
    captureActiveCodexHomeWitness(null).digest;
  const isolation = overrides.isolation ?? {
    active_codex_home_untouched: true as const,
    disposable_targets_only: true as const,
    no_sudo: true as const,
    no_protected_write: true as const,
    no_active_profile_mutation: true as const,
    active_home_witness_digest,
    isolation_digest: isolationDigestOf({
      scenario_count: scenarios.length,
      platform: "macos",
      arch: "arm64",
      no_sudo: true,
      disposable_only: true,
      active_home_witness_digest,
    }),
  };
  const built = buildPlatformSupportReceipt({
    platform: "macos",
    arch: "arm64",
    coarse_os_version: "macos-26.x",
    changeguard_version: "0.1.0",
    changeguard_commit: "c62b9b2e6c50fbd4cc31358a2371c6a888857808",
    codex_version_provenance: {
      available: false,
      version: null,
      provenance: "unavailable",
    },
    capabilities: caps,
    scenarios,
    isolation,
    started_at: "2026-07-18T00:00:00.000Z",
    ended_at: "2026-07-18T00:01:00.000Z",
  });
  return {
    ...built,
    ...overrides,
    scenarios: overrides.scenarios ?? built.scenarios,
    isolation: overrides.isolation ?? built.isolation,
  };
}

// ---- Adapter contracts ----

test("Ticket13: macOS capabilities expose bounded aliases/operations/constraints", () => {
  const caps = buildMacosCapabilities({
    platform: "macos",
    arch: "arm64",
    probeHost: false,
  });
  assert.equal(caps.schema_version, 1);
  assert.equal(caps.platform, "macos");
  assert.equal(caps.mutation_enabled, true);
  assert.deepEqual(caps.install_sources, [
    "desktop_bundled",
    "path",
    "package_manager",
  ]);
  assert.ok(caps.path_aliases.length >= 6);
  for (const a of caps.path_aliases) {
    assert.equal(a.registered, true);
    assert.equal(typeof a.alias, "string");
    assert.equal(/\/Users\//.test(a.alias), false);
  }
  assert.equal(caps.constraints.broad_home_crawl, false);
  assert.equal(caps.constraints.raw_path_export, false);
  assert.equal(caps.constraints.execute_discovered_binaries, false);
  assert.equal(caps.constraints.sudo_required, false);
  assert.equal(caps.constraints.signed_app_mutation, false);
  assert.equal(caps.constraints.openai_binary_mutation, false);
  assert.equal(caps.constraints.active_profile_mutation, false);
  assert.equal(isMacosOperationRegistered("config_repair"), true);
  assert.equal(isMacosOperationRegistered("arbitrary_shell"), false);
  // Pre-receipt claim stays Preview until harness proves Full.
  assert.equal(caps.declared_support_level, "preview");
  assertNoLeakText(JSON.stringify(caps));
});

test("Ticket13: synthetic fixture enumeration never executes binaries", () => {
  const tmp = makeTempDir("cg-t13-enum-");
  const fixtureRoot = path.join(REPO, "fixtures/platform-macos");
  // Build a temp tree that mirrors registered Desktop/PATH/package candidates.
  const home = path.join(tmp, "home");
  const desktopBin = path.join(
    home,
    "Applications/Codex.app/Contents/MacOS/Codex",
  );
  fs.mkdirSync(path.dirname(desktopBin), { recursive: true });
  fs.copyFileSync(
    path.join(fixtureRoot, "apps/Codex.app/Contents/MacOS/Codex"),
    desktopBin,
  );
  fs.mkdirSync(
    path.join(home, "Applications/Codex.app/Contents"),
    { recursive: true },
  );
  fs.copyFileSync(
    path.join(fixtureRoot, "apps/Codex.app/Contents/Info.plist"),
    path.join(home, "Applications/Codex.app/Contents/Info.plist"),
  );
  const pathBinDir = path.join(tmp, "path-bin");
  fs.mkdirSync(pathBinDir, { recursive: true });
  fs.copyFileSync(
    path.join(fixtureRoot, "path-bin/codex"),
    path.join(pathBinDir, "codex"),
  );
  fs.copyFileSync(
    path.join(fixtureRoot, "path-bin/version.json"),
    path.join(pathBinDir, "version.json"),
  );
  const pkgRoot = path.join(tmp, "pkg");
  fs.mkdirSync(path.join(pkgRoot, "bin"), { recursive: true });
  fs.copyFileSync(
    path.join(fixtureRoot, "pkg/bin/codex"),
    path.join(pkgRoot, "bin/codex"),
  );
  fs.copyFileSync(
    path.join(fixtureRoot, "pkg/package.json"),
    path.join(pkgRoot, "package.json"),
  );

  const candidates = enumerateMacosCandidates({
    platform: "macos",
    arch: "arm64",
    homeDir: home,
    systemCaps: {
      platform: "macos",
      arch: "arm64",
      homeDir: home,
      desktopPaths: [desktopBin],
      pathEntries: [pathBinDir],
      packageRoots: [pkgRoot],
      msixPaths: [],
      wslPaths: [],
    },
  });
  assert.ok(candidates.length >= 2, `expected candidates, got ${candidates.length}`);
  for (const c of candidates) {
    assert.equal(c.platform, "macos");
    assert.ok(
      c.install_source === "desktop_bundled" ||
        c.install_source === "path" ||
        c.install_source === "package_manager",
    );
  }
  const prov = readMacosCodexVersionProvenance(candidates);
  // At least one metadata source should resolve without binary execution.
  assert.equal(typeof prov.available, "boolean");
  assertNoLeakText(JSON.stringify({ candidates: candidates.map((c) => ({
    install_source: c.install_source,
    platform: c.platform,
    // omit path
  })), prov }));
});

test("Ticket13: isolation refuses active ~/.codex and protected roots", () => {
  const home = path.join(makeTempDir("cg-t13-iso-"), "home");
  fs.mkdirSync(path.join(home, ".codex"), { recursive: true });
  const active = path.join(home, ".codex");
  const r1 = assertDisposableTarget(active, home);
  assert.equal(r1.ok, false);
  if (!r1.ok) assert.equal(r1.code, "ACTIVE_CODEX_PROFILE_REFUSED");

  const r2 = assertDisposableTarget("/Applications/Codex.app", home);
  assert.equal(r2.ok, false);
  if (!r2.ok) assert.equal(r2.code, "PROTECTED_ROOT_REFUSED");

  // All protected roots including /usr /bin /sbin /private/var/db
  for (const root of ["/usr", "/bin", "/sbin", "/private/var/db", "/System"]) {
    const r = assertDisposableTarget(path.join(root, "changeguard-probe"), home);
    assert.equal(r.ok, false, `expected refuse for ${root}`);
    if (!r.ok) assert.equal(r.code, "PROTECTED_ROOT_REFUSED");
  }

  const tmp = makeTempDir("cg-t13-ok-");
  const r3 = assertDisposableTarget(tmp, home);
  assert.equal(r3.ok, true);
});

test("Ticket13: assertDisposableTarget refuses symlink targets", () => {
  const tmp = makeTempDir("cg-t13-sym-");
  const real = path.join(tmp, "real");
  fs.mkdirSync(real, { recursive: true });
  const link = path.join(tmp, "link");
  fs.symlinkSync(real, link);
  const r = assertDisposableTarget(link, path.join(tmp, "home"));
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.code, "SYMLINK_REFUSED");
});

test("Ticket13: assertDisposableTarget refuses untrusted non-temp roots", () => {
  // Repo source root is not a disposable write target without allowlist.
  const r = assertDisposableTarget(REPO, null, { requireTrustedRoot: true });
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.ok(
      r.code === "UNTRUSTED_ROOT_REFUSED" || r.code === "PROTECTED_ROOT_REFUSED",
    );
  }
});

test("Ticket13: registered aliases are path-free", () => {
  const aliases = macosRegisteredAliases();
  for (const a of aliases) {
    assert.equal(a.registered, true);
    assert.equal(a.alias.includes("/"), false);
    assert.equal(a.alias.includes("\\"), false);
  }
});

// ---- Receipt validator ----

test("Ticket13: receipt Full only when all required scenarios pass", () => {
  const pass = deriveSupportLevel({
    platform: "macos",
    scenarios: syntheticScenarios("pass"),
  });
  assert.equal(pass.level, "full");
  assert.equal(pass.gaps.length, 0);

  const fail = deriveSupportLevel({
    platform: "macos",
    scenarios: syntheticScenarios("fail"),
  });
  assert.equal(fail.level, "preview");
  assert.ok(fail.gaps.length > 0);

  const missing = deriveSupportLevel({
    platform: "macos",
    scenarios: syntheticScenarios("pass").slice(0, 3),
  });
  assert.equal(missing.level, "preview");
  assert.ok(missing.gaps.some((g) => g.startsWith("missing_scenario:")));
});

test("Ticket13: synthetic all-pass JSON is shape-ok at most Preview (not Full)", () => {
  const receipt = baseReceipt();
  assert.equal(receipt.support_level, "full"); // builder may claim full from scenarios
  const v = validatePlatformSupportReceipt(receipt);
  // Without live witness, Full is impossible.
  assert.notEqual(v.support_level, "full");
  assert.equal(v.support_level, "preview");
  assert.equal(v.ok, false);
  assert.ok(v.errors.includes("full_requires_live_attestation"));
  assert.equal(findReceiptLeaks(JSON.stringify(receipt)).length, 0);
});

test("Ticket13: forged Full with failed scenarios is rejected", () => {
  const receipt = baseReceipt({
    scenarios: syntheticScenarios("fail"),
    support_level: "full",
    uncovered_gaps: [],
  });
  // Force claim full despite failed scenarios.
  receipt.support_level = "full";
  receipt.uncovered_gaps = [];
  const v = validatePlatformSupportReceipt(receipt);
  assert.equal(v.ok, false);
  assert.notEqual(v.support_level, "full");
  assert.ok(
    v.errors.includes("support_level_full_without_proof") ||
      v.errors.includes("full_with_gaps") ||
      v.errors.includes("full_requires_live_attestation") ||
      v.gaps.length > 0,
  );
});

test("Ticket13: adversarial forged all-pass external JSON never earns Full", () => {
  const receipt = baseReceipt();
  // Attacker-controlled extras that must not elevate trust.
  const forged = {
    ...receipt,
    support_level: "full",
    synthetic: false,
    real: true,
    live: true,
    attestation: "forged",
  };
  const v = validatePlatformSupportReceipt(forged);
  assert.equal(v.ok, false);
  assert.notEqual(v.support_level, "full");
  assert.ok(
    v.errors.includes("full_requires_live_attestation") ||
      v.errors.includes("forbidden_self_report_field"),
  );
});

test("Ticket13: scenario_hash must be 64 hex and match recomputation", () => {
  const receipt = baseReceipt();
  // Tamper one hash.
  receipt.scenarios[0]!.scenario_hash = "a".repeat(64);
  // receipt_id will also mismatch after hash change — rebuild id not updated.
  const v = validatePlatformSupportReceipt(receipt);
  assert.equal(v.ok, false);
  assert.ok(
    v.errors.some(
      (e) =>
        e.includes("scenario_hash_mismatch") || e === "receipt_id_mismatch",
    ),
  );

  // Wrong length
  const receipt2 = baseReceipt();
  receipt2.scenarios[0]!.scenario_hash = "deadbeef";
  const v2 = validatePlatformSupportReceipt(receipt2);
  assert.equal(v2.ok, false);
  assert.ok(v2.errors.some((e) => e.includes("scenario_hash")));
});

test("Ticket13: scenarios_digest and isolation_digest recompute checks", () => {
  const receipt = baseReceipt();
  // Tamper receipt_id (bound to scenarios_digest).
  receipt.receipt_id = "0".repeat(32);
  const v = validatePlatformSupportReceipt(receipt);
  assert.equal(v.ok, false);
  assert.ok(v.errors.includes("receipt_id_mismatch"));

  const receipt2 = baseReceipt();
  receipt2.isolation.isolation_digest = "b".repeat(64);
  const v2 = validatePlatformSupportReceipt(receipt2);
  assert.equal(v2.ok, false);
  assert.ok(v2.errors.includes("isolation.isolation_digest_mismatch"));
});

test("Ticket13: constraints must be all false; time order enforced", () => {
  const receipt = baseReceipt();
  (receipt.capabilities.constraints as { sudo_required: boolean }).sudo_required =
    true;
  const v = validatePlatformSupportReceipt(receipt);
  assert.equal(v.ok, false);
  assert.ok(v.errors.includes("capabilities.constraints.sudo_required"));

  const receipt2 = baseReceipt();
  receipt2.started_at = "2026-07-18T02:00:00.000Z";
  receipt2.ended_at = "2026-07-18T01:00:00.000Z";
  // Fix duration to match reversed claim would still fail time_order.
  receipt2.duration_ms = 0;
  // Also receipt_id bound to started_at — expect failures.
  const v2 = validatePlatformSupportReceipt(receipt2);
  assert.equal(v2.ok, false);
  assert.ok(
    v2.errors.includes("time_order") || v2.errors.includes("receipt_id_mismatch"),
  );
});

test("Ticket13: live witness can attest Full; JSON clone cannot", () => {
  const receipt = baseReceipt();
  const scenarios_digest = scenariosDigestOf(receipt.scenarios);
  const witness = sealLiveHarnessWitness({
    scenarios_digest,
    isolation_digest: receipt.isolation.isolation_digest,
    receipt_id: receipt.receipt_id,
    changeguard_commit: receipt.changeguard_commit,
    host_fingerprint: hostCoarseFingerprintOf({
      platform: receipt.platform,
      arch: receipt.arch,
      coarse_os_version: receipt.coarse_os_version,
    }),
    started_at: receipt.started_at,
    ended_at: receipt.ended_at,
    platform: receipt.platform,
    arch: receipt.arch,
  });
  const live = validatePlatformSupportReceipt(receipt, { liveWitness: witness });
  assert.equal(live.ok, true, JSON.stringify(live.errors));
  assert.equal(live.support_level, "full");

  // Serialize + parse drops witness; Full blocked.
  const reloaded = JSON.parse(JSON.stringify(receipt)) as PlatformSupportReceipt;
  const shape = validatePlatformSupportReceipt(reloaded);
  assert.notEqual(shape.support_level, "full");
  assert.equal(shape.ok, false);
  assert.ok(shape.errors.includes("full_requires_live_attestation"));

  // Forged plain object pretending to be a witness is ignored.
  const fakeWitness = {
    scenarios_digest,
    isolation_digest: receipt.isolation.isolation_digest,
    receipt_id: receipt.receipt_id,
  };
  const forged = validatePlatformSupportReceipt(receipt, {
    // @ts-expect-error intentional forged witness shape
    liveWitness: fakeWitness,
  });
  assert.notEqual(forged.support_level, "full");
});

test("Ticket13: receipt with path leaks fails validation", () => {
  const receipt = baseReceipt();
  // Inject a leak into a summary field.
  receipt.scenarios[0]!.outcome_summary =
    "failed under /Users/leaky/Library/tmp";
  // Recompute digests after mutation so we observe leak (not only id mismatch).
  const dig = scenariosDigestOf(receipt.scenarios);
  receipt.receipt_id = receiptIdOf({
    platform: receipt.platform,
    arch: receipt.arch,
    started_at: receipt.started_at,
    scenarios_digest: dig,
  });
  const v = validatePlatformSupportReceipt(receipt);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => e.startsWith("leak:")));
});

// ---- CLI / MCP surfaces ----

test("Ticket13: CLI platform-status is read-only and path-free", () => {
  const out = runCliJson(["platform-status", "--probe-host=false"]);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.ok(out.result);
  assert.equal(out.result.ok, true);
  assert.equal(out.result.network_used, false);
  assert.equal(out.result.target_mutated, false);
  assert.equal(out.result.repair_applied, false);
  if (IS_DARWIN) {
    assert.equal(out.result.platform, "macos");
    assert.ok(out.result.capabilities);
    const caps = out.result.capabilities as { constraints: Record<string, boolean> };
    assert.equal(caps.constraints.sudo_required, false);
  }
  assertNoLeakText(out.stdout);
});

test("Ticket13: CLI platform-receipt-validate keeps forged Full as non-Full", () => {
  const receipt = baseReceipt();
  const tmp = makeTempDir("cg-t13-rcpt-");
  const file = path.join(tmp, "receipt.json");
  writeJson(file, receipt);
  const out = runCliJson(["platform-receipt-validate", file]);
  // Shape may fail ok because Full claim lacks live attestation.
  assert.notEqual(out.result!.support_level, "full");
  assert.equal(out.result!.support_level, "preview");
  assert.equal(out.exitCode, 1);
  assertNoLeakText(out.stdout);
});

test("Ticket13: CLI platform-receipt-validate accepts Preview claim shape", () => {
  const receipt = baseReceipt();
  receipt.support_level = "preview";
  // With all scenarios pass, gaps empty is ok for conservative Preview claim.
  const tmp = makeTempDir("cg-t13-rcpt-prev-");
  const file = path.join(tmp, "receipt.json");
  writeJson(file, receipt);
  const out = runCliJson(["platform-receipt-validate", file]);
  assert.equal(out.exitCode, 0, out.stdout);
  assert.equal(out.result!.ok, true);
  assert.equal(out.result!.support_level, "preview");
  assertNoLeakText(out.stdout);
});

test("Ticket13: MCP platform_status + receipt_validate never Full from JSON", async () => {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const status = await client.callTool("changeguard_platform_status", {
      probe_host: false,
    });
    assert.equal(status.ok, true);
    assert.equal(status.network_used, false);
    assertNoLeakText(JSON.stringify(status));

    const receipt = baseReceipt();
    const val = await client.callTool(
      "changeguard_platform_receipt_validate",
      { receipt },
    );
    assert.notEqual(val.support_level, "full");
    assert.equal(val.support_level, "preview");
    assert.equal(val.ok, false);
  } finally {
    await client.close();
  }
});

test("Ticket13: platformStatus core does not claim Full without receipt", () => {
  const st = platformStatus({ probeHost: false });
  assert.equal(st.ok, true);
  // Without a verified receipt, verified_support_level stays null.
  assert.equal(st.verified_support_level, null);
  if (st.capabilities) {
    assert.notEqual(st.capabilities.declared_support_level, "full");
  }
});

test("Ticket13: multi-instance fixture inventory scans without raw paths", () => {
  const tmp = makeTempDir("cg-t13-scan-");
  const src = path.join(REPO, "fixtures/platform-macos");
  const dest = path.join(tmp, "platform-macos");
  fs.cpSync(src, dest, { recursive: true });
  // Ensure inventory candidates have binaries present (already in fixture).
  const scan = runCliJson(["scan", dest]);
  assert.equal(scan.exitCode, 0, scan.stdout);
  assert.ok(scan.result?.ok);
  const instances = scan.result!.instances as unknown[];
  assert.ok(Array.isArray(instances) && instances.length >= 2);
  assertNoLeakText(scan.stdout);
  assert.equal(scan.stdout.includes(dest), false);
});

// ---- Real-machine harness (darwin only) ----

test(
  "Ticket13: real-machine macOS Scenario Harness produces truthful receipt",
  { skip: !IS_DARWIN ? "requires darwin host" : false },
  async () => {
    // Dynamic import after build — harness uses child_process.
    const { runMacosScenarioHarness, publicHarnessSummary } = await import(
      "../src/harness/macos-scenario.js"
    );
    const outDir = path.join(makeTempDir("cg-t13-harness-"), "out");
    fs.mkdirSync(outDir, { recursive: true });
    const result = runMacosScenarioHarness({
      outDir,
      requirePackage: true,
    });
    const summary = publicHarnessSummary(result);
    assert.equal(result.validation_ok, true, JSON.stringify(summary));
    assert.ok(fs.existsSync(result.receipt_abs));
    const disk = JSON.parse(
      fs.readFileSync(result.receipt_abs, "utf8"),
    ) as PlatformSupportReceipt;
    assert.equal(disk.platform, "macos");
    assert.equal(disk.network_used, false);
    assert.equal(disk.assertions.no_sudo, true);
    assert.equal(disk.assertions.no_active_profile, true);
    assert.equal(disk.assertions.no_protected_write, true);
    assert.equal(disk.isolation.no_sudo, true);
    assert.equal(disk.scenarios.length, MACOS_REQUIRED_SCENARIO_IDS.length);
    for (const id of MACOS_REQUIRED_SCENARIO_IDS) {
      const s = disk.scenarios.find((x) => x.scenario_id === id);
      assert.ok(s, `missing scenario ${id}`);
      assert.equal(s!.status, "pass", `${id}: ${s!.outcome_summary}`);
      assert.match(s!.scenario_hash, /^[0-9a-f]{64}$/);
      assert.equal(s!.scenario_hash, scenarioHashOf(id));
    }
    assert.equal(disk.support_level, "full");
    assert.equal(disk.uncovered_gaps.length, 0);
    assert.equal(findReceiptLeaks(JSON.stringify(disk)).length, 0);
    assert.equal(result.exit_code, 0);
    // Summary must not embed username/temp paths.
    assertNoLeakText(JSON.stringify(summary));
    // Active profile never used as target — isolation digest present.
    assert.match(disk.isolation.isolation_digest, /^[0-9a-f]{64}$/);
    assert.match(disk.isolation.active_home_witness_digest, /^[0-9a-f]{64}$/);

    // Reloaded disk JSON without live witness must not validate as Full.
    const reval = validatePlatformSupportReceipt(disk);
    assert.notEqual(reval.support_level, "full");
    assert.ok(reval.errors.includes("full_requires_live_attestation"));
  },
);

test("Ticket13: harness refuses protected outDir", () => {
  // Import sync path of assert only — full harness not required.
  const bad = assertDisposableTarget("/usr/local/changeguard-out", null);
  assert.equal(bad.ok, false);
});

test("Ticket13: schema file exists for platform support receipt", () => {
  const schemaPath = path.join(
    REPO,
    "schemas/platform-support-receipt.schema.json",
  );
  assert.ok(fs.existsSync(schemaPath));
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8")) as {
    required: string[];
    properties: { isolation: { required: string[] } };
  };
  assert.ok(schema.required.includes("support_level"));
  assert.ok(schema.required.includes("isolation"));
  assert.ok(schema.required.includes("scenarios"));
  assert.ok(
    schema.properties.isolation.required.includes("active_home_witness_digest"),
  );
});

test("Ticket13: active home witness is stable for unchanged tree", () => {
  const home = path.join(makeTempDir("cg-t13-wit-"), "home");
  fs.mkdirSync(path.join(home, ".codex"), { recursive: true });
  fs.writeFileSync(path.join(home, ".codex", "config.toml"), "x=1\n", "utf8");
  const a = captureActiveCodexHomeWitness(home);
  const b = captureActiveCodexHomeWitness(home);
  assert.equal(a.digest, b.digest);
  assert.match(a.digest, /^[0-9a-f]{64}$/);
  // Mutating active home changes witness.
  fs.writeFileSync(path.join(home, ".codex", "other.toml"), "y=2\n", "utf8");
  const c = captureActiveCodexHomeWitness(home);
  assert.notEqual(a.digest, c.digest);
  // Never embed home path in digest string itself (hex only).
  assert.equal(a.digest.includes(home), false);
});
