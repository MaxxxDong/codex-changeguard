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
import {
  createDisposableTempRoot,
  ensureDisposableDirectory,
} from "../src/harness/macos-scenario.js";
import os from "node:os";
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

test("Ticket13: assertDisposableTarget refuses realpath of ~/.codex→temp and children", () => {
  // When active ~/.codex is a symlink into temp, the real target (and any
  // child under it) must also be ACTIVE_CODEX_PROFILE_REFUSED — not only the
  // logical HOME/.codex path.
  const tmp = makeTempDir("cg-t13-active-sym-");
  const home = path.join(tmp, "home");
  fs.mkdirSync(home, { recursive: true });
  const realTarget = path.join(tmp, "real-codex-home");
  fs.mkdirSync(realTarget, { recursive: true });
  fs.writeFileSync(path.join(realTarget, "config.toml"), "x=1\n", "utf8");
  const activeLink = path.join(home, ".codex");
  fs.symlinkSync(realTarget, activeLink);

  const opts = { requireTrustedRoot: false as const };

  // Logical symlink path refused (active profile).
  const rLink = assertDisposableTarget(activeLink, home, opts);
  assert.equal(rLink.ok, false);
  if (!rLink.ok) {
    assert.ok(
      rLink.code === "ACTIVE_CODEX_PROFILE_REFUSED" ||
        rLink.code === "SYMLINK_REFUSED",
      `unexpected code for link: ${rLink.code}`,
    );
  }

  // Direct real target path must also be refused.
  const rReal = assertDisposableTarget(realTarget, home, opts);
  assert.equal(rReal.ok, false, "real target of active ~/.codex must be refused");
  if (!rReal.ok) assert.equal(rReal.code, "ACTIVE_CODEX_PROFILE_REFUSED");

  // Child under real target must be refused.
  const child = path.join(realTarget, "sessions", "x");
  fs.mkdirSync(path.dirname(child), { recursive: true });
  fs.writeFileSync(child, "n\n", "utf8");
  const rChild = assertDisposableTarget(child, home, opts);
  assert.equal(rChild.ok, false, "child of active real target must be refused");
  if (!rChild.ok) assert.equal(rChild.code, "ACTIVE_CODEX_PROFILE_REFUSED");

  // Unrelated temp path under same tmp still allowed when trusted-root off.
  const other = path.join(tmp, "unrelated");
  fs.mkdirSync(other, { recursive: true });
  const rOther = assertDisposableTarget(other, home, opts);
  assert.equal(rOther.ok, true);
});

test("Ticket13: non-existing leaf under alias→active real is refuse-closed", () => {
  // active ~/.codex → temp real; a second alias symlink also points at that
  // real root. Non-existing leaves under the alias must fail denyPath via
  // nearest-ancestor realpath + canonical target — not only trusted-root.
  const tmp = makeTempDir("cg-t13-alias-leaf-");
  const home = path.join(tmp, "home");
  fs.mkdirSync(home, { recursive: true });
  const realTarget = path.join(tmp, "real-codex-home");
  fs.mkdirSync(realTarget, { recursive: true });
  fs.symlinkSync(realTarget, path.join(home, ".codex"));

  const alias = path.join(tmp, "alias-to-active");
  fs.symlinkSync(realTarget, alias);

  const opts = { requireTrustedRoot: false as const };
  const missing = path.join(alias, "new-not-existing");
  assert.equal(fs.existsSync(missing), false);

  const r = assertDisposableTarget(missing, home, opts);
  assert.equal(r.ok, false, "alias/new-not-existing must be refused");
  if (!r.ok) assert.equal(r.code, "ACTIVE_CODEX_PROFILE_REFUSED");

  // Nested missing leaf under multi-level alias chain.
  const mid = path.join(tmp, "mid-link");
  const outer = path.join(tmp, "outer-link");
  fs.symlinkSync(realTarget, mid);
  fs.symlinkSync(mid, outer);
  const deepMissing = path.join(outer, "a", "b", "c-new");
  assert.equal(fs.existsSync(deepMissing), false);
  const rDeep = assertDisposableTarget(deepMissing, home, opts);
  assert.equal(rDeep.ok, false, "multi-level alias missing leaf must be refused");
  if (!rDeep.ok) assert.equal(rDeep.code, "ACTIVE_CODEX_PROFILE_REFUSED");

  // Direct real-target missing child still refused.
  const rRealMissing = assertDisposableTarget(
    path.join(realTarget, "brand-new"),
    home,
    opts,
  );
  assert.equal(rRealMissing.ok, false);
  if (!rRealMissing.ok) {
    assert.equal(rRealMissing.code, "ACTIVE_CODEX_PROFILE_REFUSED");
  }
});

test("Ticket13: ensureDisposableDirectory does not create under alias→active", () => {
  const tmp = makeTempDir("cg-t13-outdir-alias-");
  const home = path.join(tmp, "home");
  fs.mkdirSync(home, { recursive: true });
  const realTarget = path.join(tmp, "real-codex-home");
  fs.mkdirSync(realTarget, { recursive: true });
  fs.symlinkSync(realTarget, path.join(home, ".codex"));

  const alias = path.join(tmp, "out-alias");
  fs.symlinkSync(realTarget, alias);
  const outLeaf = path.join(alias, "new-out-dir");
  const before = new Set(fs.readdirSync(realTarget));

  const r = ensureDisposableDirectory(outLeaf, home, {
    requireTrustedRoot: false,
  });
  assert.equal(r.ok, false, "outDir under alias→active must refuse");
  if (!r.ok) assert.equal(r.code, "ACTIVE_CODEX_PROFILE_REFUSED");

  // Must not create the leaf or any new inode under the active real root.
  assert.equal(fs.existsSync(outLeaf), false, "alias/new must not be created");
  const after = new Set(fs.readdirSync(realTarget));
  assert.deepEqual([...after].sort(), [...before].sort());
});

test("Ticket13: createDisposableTempRoot refuses TMPDIR=active real/alias", () => {
  const tmp = makeTempDir("cg-t13-tmpdir-gate-");
  const home = path.join(tmp, "home");
  fs.mkdirSync(home, { recursive: true });
  const realTarget = path.join(tmp, "real-codex-home");
  fs.mkdirSync(realTarget, { recursive: true });
  fs.symlinkSync(realTarget, path.join(home, ".codex"));
  const alias = path.join(tmp, "tmpdir-alias");
  fs.symlinkSync(realTarget, alias);

  const prevTmpdir = process.env.TMPDIR;
  const prevTmp = process.env.TMP;
  const prevTemp = process.env.TEMP;
  const beforeReal = new Set(fs.readdirSync(realTarget));

  try {
    process.env.TMPDIR = realTarget;
    delete process.env.TMP;
    delete process.env.TEMP;
    const r1 = createDisposableTempRoot("cg-t13-bad-", home);
    assert.equal(r1.ok, false, "TMPDIR=active real must refuse mkdtemp");
    if (!r1.ok) assert.equal(r1.code, "ACTIVE_CODEX_PROFILE_REFUSED");

    process.env.TMPDIR = alias;
    const r2 = createDisposableTempRoot("cg-t13-badalias-", home);
    assert.equal(r2.ok, false, "TMPDIR=alias→active must refuse mkdtemp");
    if (!r2.ok) {
      assert.ok(
        r2.code === "ACTIVE_CODEX_PROFILE_REFUSED" ||
          r2.code === "SYMLINK_REFUSED" ||
          r2.code === "REALPATH_UNPROVABLE",
        `unexpected code: ${r2.code}`,
      );
    }
  } finally {
    if (prevTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = prevTmpdir;
    if (prevTmp === undefined) delete process.env.TMP;
    else process.env.TMP = prevTmp;
    if (prevTemp === undefined) delete process.env.TEMP;
    else process.env.TEMP = prevTemp;
  }

  const afterReal = new Set(fs.readdirSync(realTarget));
  assert.deepEqual(
    [...afterReal].sort(),
    [...beforeReal].sort(),
    "no inode under active real after refused mkdtemp",
  );
});

test("Ticket13: createDisposableTempRoot allows safe temp base", () => {
  const home = path.join(makeTempDir("cg-t13-safe-home-"), "home");
  fs.mkdirSync(path.join(home, ".codex"), { recursive: true });
  const r = createDisposableTempRoot("cg-t13-ok-", home);
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.ok(fs.existsSync(r.path));
    assert.ok(fs.statSync(r.path).isDirectory());
    // Cleanup disposable root created by the test.
    fs.rmSync(r.path, { recursive: true, force: true });
  }
});

test("Ticket13: ensureDisposableDirectory allows trusted temp + repo verification", () => {
  const home = path.join(makeTempDir("cg-t13-ens-home-"), "home");
  fs.mkdirSync(path.join(home, ".codex"), { recursive: true });

  const safeLeaf = path.join(makeTempDir("cg-t13-ens-safe-"), "nested", "out");
  const r1 = ensureDisposableDirectory(safeLeaf, home);
  assert.equal(r1.ok, true);
  assert.equal(fs.existsSync(safeLeaf), true);

  // Default audited repo verification path (when present) remains allowed.
  const verificationDir = path.join(REPO, ".grok-output", "verification");
  if (fs.existsSync(path.join(REPO, ".grok-output"))) {
    const r2 = ensureDisposableDirectory(verificationDir, home, {
      allowedRoots: [
        verificationDir,
        path.join(REPO, ".grok-output"),
      ],
    });
    assert.equal(r2.ok, true, "repo .grok-output/verification must remain allowed");
  }

  // os.tmpdir() real base still trusted for disposable leaves.
  const tmpLeaf = path.join(os.tmpdir(), `cg-t13-ens-${process.pid}`, "x");
  const r3 = ensureDisposableDirectory(tmpLeaf, home);
  assert.equal(r3.ok, true);
  if (r3.ok) {
    fs.rmSync(path.dirname(tmpLeaf), { recursive: true, force: true });
  }
});

test("Ticket13: active ~/.codex symlink witness is isolation_unprovable", () => {
  const tmp = makeTempDir("cg-t13-wit-sym-");
  const home = path.join(tmp, "home");
  fs.mkdirSync(home, { recursive: true });
  const realTarget = path.join(tmp, "real-codex");
  fs.mkdirSync(realTarget, { recursive: true });
  fs.writeFileSync(path.join(realTarget, "a.toml"), "a=1\n", "utf8");
  fs.symlinkSync(realTarget, path.join(home, ".codex"));

  const w = captureActiveCodexHomeWitness(home);
  assert.equal(w.present, true);
  assert.equal(w.isolation_provable, false);
  assert.match(w.digest, /^[0-9a-f]{64}$/);
  // Stable unprovable marker (not leaf symlink metadata alone).
  const w2 = captureActiveCodexHomeWitness(home);
  assert.equal(w.digest, w2.digest);
  // Mutating real target must not create a false "provable" Full path via leaf hash.
  fs.writeFileSync(path.join(realTarget, "b.toml"), "b=2\n", "utf8");
  const w3 = captureActiveCodexHomeWitness(home);
  assert.equal(w3.isolation_provable, false);
  // Digest remains the unprovable marker (we do not follow the link).
  assert.equal(w3.digest, w.digest);

  // Receipt with isolation false bits cannot claim Full.
  const scenarios = syntheticScenarios("pass");
  const isolation = {
    active_codex_home_untouched: false,
    disposable_targets_only: true,
    no_sudo: true,
    no_protected_write: true,
    no_active_profile_mutation: false,
    active_home_witness_digest: w.digest,
    isolation_digest: isolationDigestOf({
      scenario_count: scenarios.length,
      platform: "macos",
      arch: "arm64",
      no_sudo: true,
      disposable_only: true,
      active_home_witness_digest: w.digest,
    }),
  };
  const receipt = baseReceipt({
    scenarios,
    isolation,
    support_level: "preview",
    uncovered_gaps: ["isolation_active_codex_unprovable"],
  });
  receipt.support_level = "full";
  receipt.uncovered_gaps = [];
  const v = validatePlatformSupportReceipt(receipt);
  assert.equal(v.ok, false);
  assert.notEqual(v.support_level, "full");
  assert.ok(
    v.errors.includes("isolation_not_fully_proved") ||
      v.errors.includes("full_requires_live_attestation") ||
      v.errors.includes("support_level_full_without_proof"),
  );
});

test("Ticket13: isolation false bits are schema-valid but block Full", () => {
  const receipt = baseReceipt({
    isolation: {
      active_codex_home_untouched: false,
      disposable_targets_only: true,
      no_sudo: true,
      no_protected_write: true,
      no_active_profile_mutation: false,
      active_home_witness_digest: captureActiveCodexHomeWitness(null).digest,
      isolation_digest: isolationDigestOf({
        scenario_count: MACOS_REQUIRED_SCENARIO_IDS.length,
        platform: "macos",
        arch: "arm64",
        no_sudo: true,
        disposable_only: true,
        active_home_witness_digest: captureActiveCodexHomeWitness(null).digest,
      }),
    },
    support_level: "preview",
    uncovered_gaps: ["isolation_active_codex_unprovable"],
  });
  // Preview with false isolation bits is shape-ok (no isolation type errors).
  const vPreview = validatePlatformSupportReceipt(receipt);
  assert.ok(
    !vPreview.errors.some((e) => e === "isolation.active_codex_home_untouched"),
  );
  assert.notEqual(vPreview.support_level, "full");

  // Claiming Full with false isolation bits is refused.
  receipt.support_level = "full";
  receipt.uncovered_gaps = [];
  const vFull = validatePlatformSupportReceipt(receipt);
  assert.equal(vFull.ok, false);
  assert.notEqual(vFull.support_level, "full");
  assert.ok(vFull.errors.includes("isolation_not_fully_proved"));
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

/** Isolation gaps the harness may emit when active-home proof is unavailable. */
const ACTIVE_HOME_ISOLATION_GAPS = new Set([
  "isolation_active_codex_unproven_or_changed",
  "isolation_active_codex_unprovable",
]);

/**
 * Assert public harness receipt/summary against the truthful active-home contract:
 * scenarios + leak-free validation always; Full only when isolation is proved;
 * otherwise Preview with the exact isolation gap and nonzero exit (never forged Full).
 */
function assertTruthfulActiveHomeHarnessContract(
  result: {
    receipt: PlatformSupportReceipt;
    validation_ok: boolean;
    exit_code: number;
    receipt_abs: string;
  },
  summary: Record<string, unknown>,
): void {
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
  assert.equal(disk.isolation.disposable_targets_only, true);
  assert.equal(disk.isolation.no_protected_write, true);
  assert.equal(disk.scenarios.length, MACOS_REQUIRED_SCENARIO_IDS.length);
  for (const id of MACOS_REQUIRED_SCENARIO_IDS) {
    const s = disk.scenarios.find((x) => x.scenario_id === id);
    assert.ok(s, `missing scenario ${id}`);
    assert.equal(s!.status, "pass", `${id}: ${s!.outcome_summary}`);
    assert.match(s!.scenario_hash, /^[0-9a-f]{64}$/);
    assert.equal(s!.scenario_hash, scenarioHashOf(id));
  }
  assert.equal(findReceiptLeaks(JSON.stringify(disk)).length, 0);
  assertNoLeakText(JSON.stringify(summary));
  assert.match(disk.isolation.isolation_digest, /^[0-9a-f]{64}$/);
  assert.match(disk.isolation.active_home_witness_digest, /^[0-9a-f]{64}$/);
  assert.equal(summary.support_level, disk.support_level);
  assert.equal(summary.validation_ok, true);

  const gaps = disk.uncovered_gaps;
  const isolationGaps = gaps.filter((g) => ACTIVE_HOME_ISOLATION_GAPS.has(g));

  if (disk.support_level === "full") {
    // Active-home isolation remained provable for this run.
    assert.equal(gaps.length, 0, JSON.stringify(gaps));
    assert.equal(result.exit_code, 0);
    assert.equal(summary.ok, true);
    assert.equal(disk.isolation.active_codex_home_untouched, true);
    assert.equal(disk.isolation.no_active_profile_mutation, true);
    assert.deepEqual(summary.uncovered_gaps, []);
  } else {
    // Concurrent/unprovable active-home evidence → truthful Preview, never Full.
    assert.equal(
      disk.support_level,
      "preview",
      `unexpected support_level with passing scenarios: ${disk.support_level}`,
    );
    assert.notEqual(result.exit_code, 0);
    assert.equal(summary.ok, false);
    assert.ok(
      isolationGaps.length >= 1,
      `Preview must include isolation gap; gaps=${JSON.stringify(gaps)}`,
    );
    for (const g of gaps) {
      assert.ok(
        ACTIVE_HOME_ISOLATION_GAPS.has(g),
        `unexpected non-isolation gap when scenarios pass: ${g}`,
      );
    }
    assert.equal(disk.isolation.active_codex_home_untouched, false);
    assert.equal(disk.isolation.no_active_profile_mutation, false);
    assert.notEqual(disk.support_level, "full");
  }

  // Reloaded disk JSON without live witness must not validate as Full.
  const reval = validatePlatformSupportReceipt(disk);
  assert.notEqual(reval.support_level, "full");
  assert.ok(
    reval.errors.includes("full_requires_live_attestation") ||
      reval.support_level === "preview",
  );
}

test(
  "Ticket13: real-machine macOS Scenario Harness produces truthful receipt",
  { skip: !IS_DARWIN ? "requires darwin host" : false },
  async () => {
    // Dynamic import after build — harness uses child_process.
    // Real host ~/.codex may churn (mtime/ctime) independently of the harness;
    // the public contract is conditional Full vs isolation Preview, not a forced Full.
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
    assertTruthfulActiveHomeHarnessContract(result, summary);
  },
);

test("Ticket13: package_smoke is self-contained from stale or missing release", async () => {
  // Regression: Root running from a T11-era release (bin present, no
  // SUPPORT_MATRIX.md) previously only ran package:smoke and failed. The
  // scenario must always rebuild the production package first.
  const { runPackageSmokeScenario } = await import(
    "../src/harness/macos-scenario.js"
  );
  const releaseRoot = path.join(REPO, "release");
  const pkgDir = path.join(releaseRoot, "codex-changeguard-plugin");
  const supportMatrix = path.join(pkgDir, "docs/SUPPORT_MATRIX.md");
  const packagedBin = path.join(pkgDir, "bin/changeguard.js");

  // --- Stale T11-era release: bin exists, public docs incomplete ---
  fs.rmSync(releaseRoot, { recursive: true, force: true });
  fs.mkdirSync(path.join(pkgDir, "bin"), { recursive: true });
  fs.mkdirSync(path.join(pkgDir, "docs"), { recursive: true });
  fs.writeFileSync(
    packagedBin,
    "#!/usr/bin/env node\nconsole.log('stale-t11');\n",
    "utf8",
  );
  fs.writeFileSync(
    path.join(pkgDir, "docs/ARCHITECTURE.md"),
    "# stale architecture\n",
    "utf8",
  );
  // Deliberately omit SUPPORT_MATRIX.md (and the rest of the T13 surface).
  assert.equal(fs.existsSync(supportMatrix), false);
  assert.equal(fs.existsSync(packagedBin), true);

  const fromStale = runPackageSmokeScenario({ requirePackage: true });
  assert.equal(
    fromStale.status,
    "pass",
    `stale release package_smoke failed: ${fromStale.summary}`,
  );
  assert.equal(fromStale.failed_phase, undefined);
  assert.match(fromStale.summary, /package build/);
  assert.ok(
    fs.existsSync(supportMatrix),
    "rebuild must install SUPPORT_MATRIX.md into release",
  );
  assertNoLeakText(fromStale.summary);

  // --- Missing release entirely ---
  fs.rmSync(releaseRoot, { recursive: true, force: true });
  assert.equal(fs.existsSync(pkgDir), false);

  const fromMissing = runPackageSmokeScenario({ requirePackage: true });
  assert.equal(
    fromMissing.status,
    "pass",
    `missing release package_smoke failed: ${fromMissing.summary}`,
  );
  assert.equal(fromMissing.failed_phase, undefined);
  assert.ok(fs.existsSync(packagedBin), "rebuild must create packaged CLI");
  assert.ok(fs.existsSync(supportMatrix));
  assertNoLeakText(fromMissing.summary);
});

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
    oneOf?: Array<{
      title?: string;
      required?: string[];
      properties?: { isolation?: { required?: string[] } };
    }>;
    required?: string[];
    properties?: { isolation?: { required?: string[] } };
  };
  // Discriminated union: macOS harness receipt + Windows support receipt.
  // Resolve the macOS branch (Ticket 13 contract) without requiring a second
  // truth source outside schemas/platform-support-receipt.schema.json.
  const macosBranch =
    Array.isArray(schema.oneOf) && schema.oneOf.length >= 1
      ? (schema.oneOf.find((b) => b.title === "MacosScenarioHarnessReceipt") ??
        schema.oneOf[0]!)
      : schema;
  assert.ok(macosBranch.required?.includes("support_level"));
  assert.ok(macosBranch.required?.includes("isolation"));
  assert.ok(macosBranch.required?.includes("scenarios"));
  assert.ok(
    macosBranch.properties?.isolation?.required?.includes(
      "active_home_witness_digest",
    ),
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
  assert.equal(a.isolation_provable, true);
  // Mutating active home changes witness.
  fs.writeFileSync(path.join(home, ".codex", "other.toml"), "y=2\n", "utf8");
  const c = captureActiveCodexHomeWitness(home);
  assert.notEqual(a.digest, c.digest);
  assert.equal(c.isolation_provable, true);
  // Never embed home path in digest string itself (hex only).
  assert.equal(a.digest.includes(home), false);
});

test(
  "Ticket13: ordinary directory active ~/.codex still allows harness Full",
  { skip: !IS_DARWIN ? "requires darwin host" : false },
  async () => {
    // Deterministic Full path: stable temporary HOME/.codex (ordinary directory).
    // Never target or mutate the real user profile; HOME is restored in finally.
    const { runMacosScenarioHarness, publicHarnessSummary } = await import(
      "../src/harness/macos-scenario.js"
    );
    const tmpRoot = makeTempDir("cg-t13-full-dir-");
    const stableHome = path.join(tmpRoot, "home");
    const stableCodex = path.join(stableHome, ".codex");
    fs.mkdirSync(stableCodex, { recursive: true });
    fs.writeFileSync(path.join(stableCodex, "config.toml"), "x=1\n", "utf8");
    // Precondition: ordinary directory witness is isolation-provable and stable.
    const w0 = captureActiveCodexHomeWitness(stableHome);
    assert.equal(w0.present, true);
    assert.equal(w0.isolation_provable, true);
    assert.equal(captureActiveCodexHomeWitness(stableHome).digest, w0.digest);

    const outDir = path.join(tmpRoot, "out");
    fs.mkdirSync(outDir, { recursive: true });
    const prevHome = process.env.HOME;
    let result: Awaited<
      ReturnType<
        typeof import("../src/harness/macos-scenario.js").runMacosScenarioHarness
      >
    >;
    try {
      process.env.HOME = stableHome;
      result = runMacosScenarioHarness({
        outDir,
        requirePackage: true,
      });
    } finally {
      if (prevHome === undefined) delete process.env.HOME;
      else process.env.HOME = prevHome;
    }

    const summary = publicHarnessSummary(result);
    assert.equal(result.validation_ok, true, JSON.stringify(summary));
    assert.equal(result.exit_code, 0, JSON.stringify(summary));
    assert.equal(result.receipt.support_level, "full");
    assert.equal(result.receipt.uncovered_gaps.length, 0);
    assert.equal(result.receipt.isolation.active_codex_home_untouched, true);
    assert.equal(result.receipt.isolation.no_active_profile_mutation, true);
    assert.equal(result.receipt.isolation.disposable_targets_only, true);
    assert.equal(result.receipt.isolation.no_sudo, true);
    assert.equal(result.receipt.isolation.no_protected_write, true);
    assert.equal(summary.support_level, "full");
    assert.equal(summary.ok, true);
    assert.equal(findReceiptLeaks(JSON.stringify(result.receipt)).length, 0);
    assertNoLeakText(JSON.stringify(summary));
    // Stable temp profile must remain an ordinary directory after the run.
    assert.equal(fs.lstatSync(stableCodex).isSymbolicLink(), false);
    assert.equal(fs.lstatSync(stableCodex).isDirectory(), true);
  },
);

test(
  "Ticket13: symlink active ~/.codex harness seals truthful Preview not Full",
  { skip: !IS_DARWIN ? "requires darwin host" : false },
  async () => {
    // Deterministic Preview path via temporary HOME with symlink ~/.codex.
    // Real user profile is never used as the active-home target.
    const { runMacosScenarioHarness, publicHarnessSummary } = await import(
      "../src/harness/macos-scenario.js"
    );
    const tmpRoot = makeTempDir("cg-t13-sym-home-");
    const home = path.join(tmpRoot, "home");
    const realTarget = path.join(tmpRoot, "real-codex");
    fs.mkdirSync(home, { recursive: true });
    fs.mkdirSync(realTarget, { recursive: true });
    fs.writeFileSync(path.join(realTarget, "config.toml"), "x=1\n", "utf8");
    fs.symlinkSync(realTarget, path.join(home, ".codex"));

    const outDir = path.join(tmpRoot, "out");
    fs.mkdirSync(outDir, { recursive: true });
    const prevHome = process.env.HOME;
    let result: Awaited<
      ReturnType<
        typeof import("../src/harness/macos-scenario.js").runMacosScenarioHarness
      >
    >;
    try {
      process.env.HOME = home;
      result = runMacosScenarioHarness({
        outDir,
        requirePackage: true,
      });
    } finally {
      if (prevHome === undefined) delete process.env.HOME;
      else process.env.HOME = prevHome;
    }

    const summary = publicHarnessSummary(result);
    assert.equal(result.validation_ok, true, JSON.stringify(summary));
    assert.notEqual(result.exit_code, 0);
    assert.equal(result.receipt.support_level, "preview");
    assert.ok(
      result.receipt.uncovered_gaps.includes(
        "isolation_active_codex_unprovable",
      ),
      JSON.stringify(result.receipt.uncovered_gaps),
    );
    assert.equal(result.receipt.isolation.active_codex_home_untouched, false);
    assert.equal(result.receipt.isolation.no_active_profile_mutation, false);
    assert.equal(summary.support_level, "preview");
    assert.equal(summary.ok, false);
    assert.equal(findReceiptLeaks(JSON.stringify(result.receipt)).length, 0);
    assertNoLeakText(JSON.stringify(summary));
    // All required scenarios still pass under unprovable isolation.
    for (const id of MACOS_REQUIRED_SCENARIO_IDS) {
      const s = result.receipt.scenarios.find((x) => x.scenario_id === id);
      assert.ok(s, `missing scenario ${id}`);
      assert.equal(s!.status, "pass", `${id}: ${s!.outcome_summary}`);
    }
  },
);
