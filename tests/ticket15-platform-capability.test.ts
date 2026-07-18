/**
 * Ticket 15 — Linux / WSL / enterprise managed paths Scenario Harness.
 * Synthetic fixtures only; never claims Full without real-machine receipt.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  enumerateSystemCandidates,
  scanInstances,
} from "../src/instances/index.js";
import {
  assertNoIdentityCollapse,
  buildITHandoff,
  compareNetworkPaths,
  discoverBoundedSurfaces,
  evaluateWriteGate,
  INTERNAL_FIXTURE_SEAM_ENV,
  INTERNAL_FIXTURE_SEAM_VALUE,
  isHostMountPath,
  isolatedFixtureRepairCapabilityOptions,
  linuxCapabilityReport,
  platformStatus,
  productionRepairCapabilityOptions,
  proveIsolatedFixtureTarget,
  resolvePublicRepairCapability,
  syntheticLimitedReceipt,
  validateSupportReceipt,
  wslCapabilityReport,
} from "../src/platform/index.js";
import type { NetworkCompareObservation } from "../src/platform/types.js";
import {
  previewRepair,
  applyRepair,
} from "../src/core/recovery/index.js";
import {
  cliEntry,
  copyFixtureToTemp,
  hashTargetTree,
  harnessProcessEnv,
  mcpServerEntry,
  runCliJson,
  runCliRepairApply,
  runCliRepairPreview,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import { findRepoRoot } from "../src/paths.js";
import { makeTempDir, writeJson } from "./helpers.js";
import { spawnSync } from "node:child_process";
import os from "node:os";

const repoRoot = findRepoRoot(import.meta.url);

function assertNoLeakText(text: string): void {
  assert.equal(/\/home\/|\/Users\/|[A-Za-z]:\\/i.test(text), false);
  assert.equal(
    /\b(Bearer|sk-[a-zA-Z0-9]|api[_-]?key|password\s*=)\b/i.test(text),
    false,
  );
  assert.equal(
    /\b(sudo|chmod|setfacl|takeown|disable\s*security)\b/i.test(text),
    false,
  );
}

// --- T15-S01 unknown adapter ---
test("T15-S01: unknown adapter is READ_ONLY with writes disabled", () => {
  const status = platformStatus({ adapter: "unknown" });
  assert.equal(status.ok, true);
  assert.equal(status.full_support_claimed, false);
  assert.equal(status.default_status, "READ_ONLY");
  const report = status.reports[0]!;
  assert.equal(report.status, "READ_ONLY");
  assert.equal(report.writes_enabled, false);
  assert.equal(report.mutation_disabled_by_default, true);
  const gate = evaluateWriteGate({
    capability_status: "READ_ONLY",
    isolation: "isolated_fixture",
    managed_policy: false,
    admin_permission_bound: false,
  });
  assert.equal(gate.may_mutate, false);
});

// --- T15-S02 native linux ---
test("T15-S02: native linux PATH CLI uses path install_source (never wsl)", () => {
  const tmp = makeTempDir("cg-t15-linux-");
  const binDir = path.join(tmp, "usr", "local", "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const bin = path.join(binDir, "codex");
  fs.writeFileSync(bin, "#!/bin/sh\n# never execute\n", "utf8");
  writeJson(path.join(binDir, "version.json"), { version: "0.51.0" });
  const configRoot = path.join(tmp, "xdg-config", "codex");
  fs.mkdirSync(path.join(configRoot, "config"), { recursive: true });
  fs.writeFileSync(
    path.join(configRoot, "config", "config.toml"),
    'model = "gpt-5"\n',
    "utf8",
  );
  const logRoot = path.join(tmp, "logs");
  fs.mkdirSync(logRoot, { recursive: true });
  fs.writeFileSync(path.join(logRoot, "codex.log"), "ok\n", "utf8");

  const caps = {
    platform: "linux" as const,
    arch: "x64",
    env: { HOME: tmp, PATH: binDir },
    pathEntries: [binDir],
    desktopPaths: [] as string[],
    packageRoots: [] as string[],
    msixPaths: [] as string[],
    wslPaths: [] as string[],
    linuxPaths: [bin],
  };
  const candidates = enumerateSystemCandidates(caps);
  assert.ok(candidates.length >= 1);
  for (const c of candidates) {
    assert.notEqual(c.install_source, "wsl");
    assert.ok(
      c.install_source === "path" || c.install_source === "package_manager",
    );
    assert.equal(c.platform, "linux");
    assert.equal(c.runtime_domain, "native_linux");
  }
  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.ok(scan.platform_capability);
  assert.equal(scan.platform_capability!.status, "LIMITED");
  assert.equal(scan.platform_capability!.writes_enabled, false);
  assert.equal(scan.platform_capability!.full_support_claimed, false);
  const dumped = JSON.stringify(scan);
  assert.equal(dumped.includes(tmp), false);
  assert.equal(dumped.includes(bin), false);

  const report = linuxCapabilityReport({
    configRoots: [configRoot],
    logRoots: [logRoot],
    cacheRoots: [tmp],
  });
  assert.equal(report.status, "LIMITED");
  assert.ok(report.discoveries.some((d) => d.kind === "config" && d.present));
  assert.ok(report.discoveries.some((d) => d.kind === "log"));
});

// --- T15-S03 WSL + Windows coexistence ---
test("T15-S03: WSL CLI + Windows MSIX coexist without identity collapse", () => {
  const tmp = makeTempDir("cg-t15-coex-");
  const wslBin = path.join(tmp, "wsl", "usr", "local", "bin", "codex");
  fs.mkdirSync(path.dirname(wslBin), { recursive: true });
  fs.writeFileSync(wslBin, "x", "utf8");
  writeJson(path.join(path.dirname(wslBin), "version.json"), {
    version: "0.51.0",
  });
  const msix = path.join(tmp, "WindowsApps", "codex.exe");
  fs.mkdirSync(path.dirname(msix), { recursive: true });
  fs.writeFileSync(msix, "MZ", "utf8");
  fs.writeFileSync(
    path.join(path.dirname(msix), "AppxManifest.xml"),
    `<Package><Identity Version="0.51.0.0"/></Package>`,
    "utf8",
  );
  const caps = {
    platform: "windows" as const,
    arch: "x64",
    env: {
      LOCALAPPDATA: path.join(tmp, "Local"),
      WSL_DISTRO_NAME: undefined,
    },
    pathEntries: [] as string[],
    desktopPaths: [] as string[],
    packageRoots: [] as string[],
    msixPaths: [msix],
    wslPaths: [wslBin],
    linuxPaths: [] as string[],
  };
  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  const platforms = new Set(scan.instances.map((i) => i.platform));
  assert.ok(platforms.has("windows"));
  assert.ok(platforms.has("wsl"));
  const wsl = scan.instances.filter((i) => i.platform === "wsl");
  const win = scan.instances.filter((i) => i.platform === "windows");
  assert.ok(wsl.length >= 1);
  assert.ok(win.length >= 1);
  for (const i of wsl) {
    assert.equal(i.install_source, "wsl");
    assert.equal(i.runtime_domain, "wsl_distro");
  }
  for (const i of win) {
    assert.notEqual(i.install_source, "wsl");
    assert.equal(i.runtime_domain, "windows_host");
  }
  const collapse = assertNoIdentityCollapse(scan.instances);
  assert.equal(collapse.ok, true);
  const ids = new Set(scan.instances.map((i) => i.instance_id));
  assert.equal(ids.size, scan.instances.length);
  assert.equal(JSON.stringify(scan).includes(tmp), false);
});

// --- T15-S04 managed policy IT handoff ---
test("T15-S04: managed policy returns ADMIN_ACTION_REQUIRED + full IT Handoff", () => {
  const tmp = makeTempDir("cg-t15-admin-");
  const target = copyFixtureToTemp("fixtures/config-managed-policy", tmp);
  const before = hashTargetTree(target);
  const preview = runCliRepairPreview(target);
  assert.notEqual(preview.exitCode, 0);
  assert.equal(preview.result!.error_code, "ADMIN_ACTION_REQUIRED");
  const handoff = preview.result!.admin_handoff as Record<string, unknown>;
  assert.ok(handoff);
  assert.equal(handoff.policy_class, "enterprise_mdm");
  assert.equal(handoff.admin_owned, true);
  assert.equal(handoff.signed, true);
  assert.equal(handoff.permission_bound, true);
  assert.equal(handoff.schema_version, 1);
  assert.equal(handoff.status, "ADMIN_ACTION_REQUIRED");
  assert.equal(typeof handoff.risk, "string");
  assert.equal(typeof handoff.rollback, "string");
  assert.ok(handoff.official_reference);
  assert.equal(handoff.secrets_present, false);
  assert.equal(handoff.absolute_paths_present, false);
  assert.equal(preview.result!.capsule, null);
  assert.equal(preview.result!.authorization, null);
  assertNoLeakText(preview.stdout);
  assert.equal(
    /\b(sudo|chmod|setfacl|disable\s*security|bypass)\b/i.test(preview.stdout),
    false,
  );
  assert.equal(hashTargetTree(target), before);
});

// --- T15-S05 admin block without repairable fault ---
test("T15-S05: permission-bound managed marker blocks mutation with handoff", () => {
  const handoff = buildITHandoff({
    policy_class: "enterprise_mdm",
    target_path_alias: "MANAGED_POLICY",
    config_key: null,
    evidence_digests: [
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ],
    admin_owned: true,
    signed: true,
    permission_bound: true,
    adapter_status: "LIMITED",
  });
  assert.equal(handoff.status, "ADMIN_ACTION_REQUIRED");
  assert.ok(handoff.minimal_evidence.observed_flags.includes("permission_bound"));
  const gate = evaluateWriteGate({
    capability_status: "LIMITED",
    isolation: "isolated_fixture",
    managed_policy: true,
    admin_permission_bound: true,
  });
  assert.equal(gate.may_mutate, false);
  assert.equal(gate.reason_code, "ADMIN_OR_MANAGED_BLOCK");
});

// --- T15-S06 symlink refuse ---
test("T15-S06: symlink config root is refused (no follow)", () => {
  const tmp = makeTempDir("cg-t15-sym-");
  const real = path.join(tmp, "real-config");
  const link = path.join(tmp, "link-config");
  fs.mkdirSync(path.join(real, "config"), { recursive: true });
  fs.writeFileSync(
    path.join(real, "config", "config.toml"),
    'model = "x"\n',
    "utf8",
  );
  fs.symlinkSync(real, link);
  const obs = discoverBoundedSurfaces({ configRoots: [link] });
  assert.ok(obs.length >= 1);
  assert.ok(obs.every((o) => o.refused_reason === "SYMLINK_REFUSED" || !o.readable));
});

// --- T15-S07 / T15-S08 host mount refuse ---
test("T15-S08: /mnt/c host paths refused as linux trusted roots", () => {
  assert.equal(isHostMountPath("/mnt/c/Users/someone/.codex"), true);
  assert.equal(isHostMountPath("/mnt/C/Users/someone/.codex"), true);
  assert.equal(isHostMountPath("/mnt//z/Tools/codex"), true);
  assert.equal(isHostMountPath("/mnt/z"), true);
  assert.equal(isHostMountPath("/usr/local/bin/codex"), false);
  assert.equal(isHostMountPath("/mnt/wsl/foo"), false);
  const obs = discoverBoundedSurfaces({
    configRoots: ["/mnt/c/Users/someone/.codex"],
  });
  assert.ok(
    obs.some((o) => o.refused_reason === "HOST_MOUNT_OR_REFUSED_PREFIX"),
  );
});

test("T15-P1: PATH /mnt/c and /mnt/z never become WSL trusted roots or instance evidence", () => {
  const mntC = "/mnt/c/Program Files/Codex/bin";
  const mntZ = "/mnt/z/Tools/codex-bin";
  const native = "/usr/local/bin";
  const pathKind = (p: string) => {
    const n = p.replace(/\\/g, "/");
    if (
      n === mntC ||
      n === mntZ ||
      n === native ||
      n.endsWith("/bin") ||
      n.endsWith("/codex-bin")
    ) {
      return "dir" as const;
    }
    if (n.endsWith("/codex") || n.endsWith("/codex.exe")) return "file" as const;
    return "missing" as const;
  };
  const cands = enumerateSystemCandidates({
    platform: "wsl",
    arch: "x64",
    env: {
      WSL_DISTRO_NAME: "Ubuntu",
      PATH: `${mntC}:${mntZ}:${native}`,
      HOME: "/home/test",
    },
    pathEntries: [mntC, mntZ, native],
    pathKind,
    desktopPaths: [],
    packageRoots: [],
    msixPaths: [],
    wslPaths: [],
    linuxPaths: [],
  });
  // Host-mount PATH entries must not produce candidates or trusted roots.
  for (const c of cands) {
    assert.equal(isHostMountPath(c.path), false);
    for (const root of c.trusted_metadata_roots ?? []) {
      assert.equal(isHostMountPath(root), false);
    }
    assert.equal(c.path.includes("/mnt/c"), false);
    assert.equal(c.path.includes("/mnt/z"), false);
  }
  // Native path may still appear.
  assert.ok(cands.some((c) => c.path.replace(/\\/g, "/").includes("/usr/local/bin")));
});

test("T15-P1: package root under host mount is refused", () => {
  const pkg = "/mnt/c/npm/codex-pkg";
  const pathKind = (p: string) => {
    const n = p.replace(/\\/g, "/");
    if (n === pkg) return "dir" as const;
    if (n.endsWith("package.json")) return "file" as const;
    if (n.includes("/bin/codex")) return "file" as const;
    return "missing" as const;
  };
  const cands = enumerateSystemCandidates({
    platform: "linux",
    arch: "x64",
    pathKind,
    packageRoots: [pkg],
    pathEntries: [],
    desktopPaths: [],
    msixPaths: [],
    wslPaths: [],
    // Non-empty override so default registered linux paths are not injected.
    linuxPaths: ["/__no_such_linux_cli__/codex"],
  });
  assert.equal(
    cands.filter((c) => c.install_source === "package_manager").length,
    0,
  );
  assert.ok(!cands.some((c) => isHostMountPath(c.path)));
  assert.ok(!cands.some((c) => c.path.includes("/mnt/c")));
});

test("T15-P1: symlink into host mount is refused by isHostMountPath", () => {
  const tmp = makeTempDir("cg-t15-mnt-sym-");
  const link = path.join(tmp, "launder-to-host");
  // Create symlink whose target text is a host mount (need not exist).
  fs.symlinkSync("/mnt/c/Users/x/.codex/bin", link);
  assert.equal(isHostMountPath(link), true);
  // PATH dir that is itself a symlink is already non-dir; also refuse host shape.
  const pathKind = (p: string) => {
    if (p === link) return "symlink" as const;
    return "missing" as const;
  };
  const cands = enumerateSystemCandidates({
    platform: "wsl",
    arch: "x64",
    env: { WSL_DISTRO_NAME: "Ubuntu", PATH: link },
    pathEntries: [link],
    pathKind,
    desktopPaths: [],
    packageRoots: [],
    msixPaths: [],
    wslPaths: [],
    linuxPaths: [],
  });
  assert.equal(cands.length, 0);
});

// --- T15-S09 network compare ---
test("T15-S09: network compare is pure RO labels (no sockets)", () => {
  const filterPath = path.join(
    repoRoot,
    "fixtures/platform-network-compare/observation-filter.json",
  );
  const incidentPath = path.join(
    repoRoot,
    "fixtures/platform-network-compare/observation-incident.json",
  );
  const filter = JSON.parse(
    fs.readFileSync(filterPath, "utf8"),
  ) as NetworkCompareObservation;
  const incident = JSON.parse(
    fs.readFileSync(incidentPath, "utf8"),
  ) as NetworkCompareObservation;
  const r1 = compareNetworkPaths(filter);
  assert.equal(r1.branch, "network_security_path");
  assert.equal(r1.network_used, false);
  assert.equal(r1.settings_mutated, false);
  assert.ok(r1.official_reference?.url_allowlisted.startsWith("https://"));
  const r2 = compareNetworkPaths(incident);
  assert.equal(r2.branch, "service_incident");
  assert.equal(r2.network_used, false);
});

// --- T15-S10 capability upgrade without receipt ---
test("T15-S10: synthetic receipt cannot claim FULL", () => {
  const bad = syntheticLimitedReceipt("linux", ["T15-S02"]);
  assert.equal(bad.claimed_status, "LIMITED");
  assert.equal(bad.real_machine, false);
  const forged = {
    ...bad,
    claimed_status: "FULL" as const,
    real_machine: false,
  };
  const v = validateSupportReceipt(forged, "linux");
  assert.equal(v.ok, false);
  assert.equal(v.reason_code, "FULL_REQUIRES_REAL_MACHINE");
  const status = platformStatus({ adapter: "linux" });
  assert.equal(status.full_support_claimed, false);
  assert.equal(status.default_status, "LIMITED");
});

// --- T15 write-disabled capability ---
test("T15: LIMITED/READ_ONLY write-disabled refuses repair-preview mutation path", () => {
  const tmp = makeTempDir("cg-t15-wd-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const before = hashTargetTree(target);
  const refused = previewRepair(target, {
    capability_status: "LIMITED",
    isolation: "isolated_fixture",
  });
  assert.equal(refused.ok, false);
  assert.equal(refused.error_code, "WRITE_DISABLED");
  assert.equal(refused.capsule, null);
  assert.equal(hashTargetTree(target), before);

  const ro = previewRepair(target, {
    capability_status: "READ_ONLY",
  });
  assert.equal(ro.ok, false);
  assert.equal(ro.error_code, "WRITE_DISABLED");

  // Default (no capability) is fail-closed — never invent PREVIEW/isolated_fixture.
  const defaulted = previewRepair(target);
  assert.equal(defaulted.ok, false);
  assert.equal(defaulted.error_code, "WRITE_DISABLED");
  assert.equal(defaulted.capsule, null);
  assert.equal(hashTargetTree(target), before);

  // Explicit internal fixture seam allows isolated config repair.
  const allowed = previewRepair(target, isolatedFixtureRepairCapabilityOptions());
  assert.equal(allowed.ok, true);
  assert.ok(allowed.authorization);

  // LIMITED only with allow_limited_user_owned_recovery + user-owned isolation.
  const limitedAllowed = previewRepair(target, {
    capability_status: "LIMITED",
    isolation: "user_owned_registered",
    allow_limited_user_owned_recovery: true,
  });
  assert.equal(limitedAllowed.ok, true);
  assert.ok(limitedAllowed.authorization);
});

test("T15-P1: public repair capability resolves fail-closed for unknown/linux/wsl", () => {
  for (const platform of ["linux", "unknown"] as const) {
    const opts = productionRepairCapabilityOptions(
      platform === "linux" ? {} : {},
      platform === "linux" ? "linux" : "aix",
    );
    assert.ok(
      opts.capability_status === "LIMITED" ||
        opts.capability_status === "READ_ONLY",
    );
    assert.equal(opts.isolation, "production_unknown");
    assert.equal(opts.allow_limited_user_owned_recovery, false);
    const gate = evaluateWriteGate({
      capability_status: opts.capability_status,
      isolation: opts.isolation,
      managed_policy: false,
      admin_permission_bound: false,
      allow_limited_user_owned_recovery: false,
    });
    assert.equal(gate.may_mutate, false);
  }
  const wsl = productionRepairCapabilityOptions(
    { WSL_DISTRO_NAME: "Ubuntu" },
    "linux",
  );
  assert.equal(wsl.capability_status, "LIMITED");
  assert.equal(wsl.isolation, "production_unknown");
  const wslGate = evaluateWriteGate({
    capability_status: wsl.capability_status,
    isolation: wsl.isolation,
    managed_policy: false,
    admin_permission_bound: false,
  });
  assert.equal(wslGate.may_mutate, false);

  // Env seam alone (no target) → still production_unknown (not authorization).
  const seamEnvOnly = resolvePublicRepairCapability({
    [INTERNAL_FIXTURE_SEAM_ENV]: INTERNAL_FIXTURE_SEAM_VALUE,
  });
  assert.equal(seamEnvOnly.isolation, "production_unknown");
  assert.notEqual(seamEnvOnly.isolation, "isolated_fixture");

  // Env + disposable mkdtemp target → PREVIEW + isolated_fixture.
  const tmpOk = makeTempDir("cg-t15-seam-ok-");
  const seam = resolvePublicRepairCapability(
    { [INTERNAL_FIXTURE_SEAM_ENV]: INTERNAL_FIXTURE_SEAM_VALUE },
    process.platform,
    tmpOk,
  );
  assert.equal(seam.capability_status, "PREVIEW");
  assert.equal(seam.isolation, "isolated_fixture");
});

test("T15-P1: public CLI/MCP repair without fixture seam is WRITE_DISABLED", async () => {
  const tmp = makeTempDir("cg-t15-prod-cap-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const before = hashTargetTree(target);

  // Production-like CLI: no internal seam env.
  const prodEnv: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: "1" };
  delete prodEnv[INTERNAL_FIXTURE_SEAM_ENV];
  const cli = spawnSync(
    process.execPath,
    [cliEntry(), "repair-preview", target],
    {
      encoding: "utf8",
      env: prodEnv,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  const cliJson = JSON.parse(cli.stdout || "{}") as Record<string, unknown>;
  assert.notEqual(cli.status, 0);
  assert.equal(cliJson.error_code, "WRITE_DISABLED");
  assert.equal(cliJson.capsule, null);
  assert.equal(cliJson.authorization, null);
  assert.equal(hashTargetTree(target), before);

  // Production-like MCP: env without seam; tool JSON cannot inject PREVIEW.
  const client = new McpTestClient({
    serverEntry: mcpServerEntry(),
    env: prodEnv,
  });
  try {
    client.start();
    const mcp = (await client.callTool("changeguard_repair_preview", {
      target,
    })) as Record<string, unknown>;
    assert.equal(mcp.ok, false);
    assert.equal(mcp.error_code, "WRITE_DISABLED");
    assert.equal(mcp.capsule, null);
    assert.equal(mcp.authorization, null);
  } finally {
    await client.close();
  }

  // Harness CLI (env seam + disposable mkdtemp target) still previews.
  const harness = runCliRepairPreview(target);
  assert.equal(harness.exitCode, 0, harness.stderr);
  assert.equal(harness.result!.ok, true);
  assert.ok(harness.result!.authorization);
});

// --- T15-P1 fixture seam: env alone is never authorization ---
test("T15-P1: env seam on in-repo fixture is WRITE_DISABLED (CLI+MCP); tree unchanged", async () => {
  const repoFixture = path.join(repoRoot, "fixtures", "config-wrong-type");
  assert.equal(fs.existsSync(repoFixture), true);
  const before = hashTargetTree(repoFixture);

  const seamEnv = harnessProcessEnv();
  // CLI with env=1 against non-disposable repo fixture.
  const cli = spawnSync(
    process.execPath,
    [cliEntry(), "repair-preview", repoFixture],
    {
      encoding: "utf8",
      env: seamEnv,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  const cliJson = JSON.parse(cli.stdout || "{}") as Record<string, unknown>;
  assert.notEqual(cli.status, 0);
  assert.equal(cliJson.ok, false);
  assert.equal(cliJson.error_code, "WRITE_DISABLED");
  assert.equal(cliJson.capsule, null);
  assert.equal(cliJson.authorization, null);
  assert.equal(hashTargetTree(repoFixture), before, "repo fixture tree must not change");

  // MCP equivalence: same env + in-repo target → WRITE_DISABLED.
  const client = new McpTestClient({
    serverEntry: mcpServerEntry(),
    env: seamEnv,
  });
  try {
    client.start();
    const mcp = (await client.callTool("changeguard_repair_preview", {
      target: repoFixture,
    })) as Record<string, unknown>;
    assert.equal(mcp.ok, false);
    assert.equal(mcp.error_code, "WRITE_DISABLED");
    assert.equal(mcp.capsule, null);
    assert.equal(mcp.authorization, null);
  } finally {
    await client.close();
  }

  // Resolver: env + repo path never yields isolated_fixture.
  const cap = resolvePublicRepairCapability(seamEnv, process.platform, repoFixture);
  assert.equal(cap.isolation, "production_unknown");
  assert.equal(proveIsolatedFixtureTarget(repoFixture), false);
  assert.equal(hashTargetTree(repoFixture), before);
});

test("T15-P1: env seam + mkdtemp isolated copy still preview/apply/verify/rollback", () => {
  const tmp = makeTempDir("cg-t15-seam-iso-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const configPath = path.join(target, "config", "config.toml");
  const originalConfig = fs.readFileSync(configPath);
  const before = hashTargetTree(target);

  assert.equal(proveIsolatedFixtureTarget(target), true);

  const preview = runCliRepairPreview(target);
  assert.equal(preview.exitCode, 0, preview.stderr);
  assert.equal(preview.result!.ok, true);
  assert.ok(preview.result!.authorization);
  // preview is read-only over the target tree
  assert.equal(hashTargetTree(target), before);
  assert.ok(originalConfig.equals(fs.readFileSync(configPath)));

  const auth = preview.result!.authorization as string;
  const applied = runCliRepairApply(target, auth);
  assert.equal(applied.exitCode, 0, applied.stderr);
  assert.equal(applied.result!.ok, true);
  assert.equal(applied.result!.target_mutated, true);
  assert.notEqual(
    originalConfig.equals(fs.readFileSync(configPath)),
    true,
    "apply mutates only the isolated copy config",
  );

  const verified = runCliJson(["verify", target]);
  assert.equal(verified.exitCode, 0, verified.stderr);
  assert.equal(verified.result!.ok, true);

  const rolled = runCliJson(["rollback", target]);
  assert.equal(rolled.exitCode, 0, rolled.stderr);
  assert.equal(rolled.result!.ok, true);
  // Session ledger under .changeguard may remain; config bytes must restore.
  assert.ok(
    originalConfig.equals(fs.readFileSync(configPath)),
    "rollback restores original config bytes on the isolated copy",
  );
});

test("T15-P1: leaf/mid symlink, active ~/.codex alias, HOME dir, WSL host mount refused", () => {
  const tmp = makeTempDir("cg-t15-seam-refuse-");
  const home = path.join(tmp, "home");
  fs.mkdirSync(home, { recursive: true });
  const realCodex = path.join(tmp, "real-codex");
  fs.mkdirSync(realCodex, { recursive: true });
  fs.symlinkSync(realCodex, path.join(home, ".codex"));

  // Leaf symlink → temp: not a disposable ordinary directory.
  const realLeaf = path.join(tmp, "real-leaf");
  fs.mkdirSync(realLeaf, { recursive: true });
  const leafLink = path.join(tmp, "leaf-link");
  fs.symlinkSync(realLeaf, leafLink);
  assert.equal(proveIsolatedFixtureTarget(leafLink, home), false);
  const capLeaf = resolvePublicRepairCapability(
    { [INTERNAL_FIXTURE_SEAM_ENV]: INTERNAL_FIXTURE_SEAM_VALUE },
    process.platform,
    leafLink,
  );
  assert.equal(capLeaf.isolation, "production_unknown");

  // Intermediate symlink: temp/mid → in-repo fixture (outside trusted temp).
  // realpath of child lands in the repository, not an OS temp isolation root.
  const mid = path.join(tmp, "mid-link");
  const repoOutside = path.join(repoRoot, "fixtures", "config-wrong-type");
  fs.symlinkSync(repoOutside, mid);
  const viaMid = path.join(mid, "config");
  assert.equal(fs.existsSync(viaMid), true);
  assert.equal(proveIsolatedFixtureTarget(viaMid, home), false);

  // Active ~/.codex alias (logical) and real target refused.
  assert.equal(proveIsolatedFixtureTarget(path.join(home, ".codex"), home), false);
  assert.equal(proveIsolatedFixtureTarget(realCodex, home), false);

  // HOME ordinary / in-repo ordinary directory refused (not OS temp isolation).
  const homeOrdinary = path.join(repoRoot, "fixtures", "negative-control");
  assert.equal(proveIsolatedFixtureTarget(homeOrdinary, home), false);
  assert.equal(proveIsolatedFixtureTarget(repoRoot, home), false);

  // WSL host mount shape refused without requiring the mount to exist.
  assert.equal(proveIsolatedFixtureTarget("/mnt/c/Users/x/.codex"), false);
  assert.equal(proveIsolatedFixtureTarget("/mnt/z/Tools/fixture"), false);
  const capMnt = resolvePublicRepairCapability(
    { [INTERNAL_FIXTURE_SEAM_ENV]: INTERNAL_FIXTURE_SEAM_VALUE },
    process.platform,
    "/mnt/c/Users/x/.codex",
  );
  assert.equal(capMnt.isolation, "production_unknown");

  // Temp leaf symlink pointing at repo fixture (outside) refused.
  const tempToOutside = path.join(tmp, "to-outside");
  fs.symlinkSync(repoOutside, tempToOutside);
  assert.equal(proveIsolatedFixtureTarget(tempToOutside, home), false);

  // Positive control: plain mkdtemp under os.tmpdir() still proves.
  const ok = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t15-prove-ok-"));
  assert.equal(proveIsolatedFixtureTarget(ok, home), true);
});

test("T15-P1: preview auth on disposable target cannot apply to unproven repo fixture", () => {
  const tmp = makeTempDir("cg-t15-auth-bind-");
  const disposable = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const repoFixture = path.join(repoRoot, "fixtures", "config-wrong-type");
  const repoBefore = hashTargetTree(repoFixture);

  const preview = runCliRepairPreview(disposable);
  assert.equal(preview.exitCode, 0, preview.stderr);
  assert.ok(preview.result!.authorization);
  const auth = preview.result!.authorization as string;

  // Apply with harness env but unproven repo path → WRITE_DISABLED (capability)
  // or AUTH failure; either way no mutation and no success.
  const apply = spawnSync(
    process.execPath,
    [cliEntry(), "repair-apply", repoFixture, auth],
    {
      encoding: "utf8",
      env: harnessProcessEnv(),
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  const applyJson = JSON.parse(apply.stdout || "{}") as Record<string, unknown>;
  assert.notEqual(apply.status, 0);
  assert.equal(applyJson.ok, false);
  assert.ok(
    applyJson.error_code === "WRITE_DISABLED" ||
      applyJson.error_code === "AUTH_INVALID" ||
      applyJson.error_code === "AUTH_MALFORMED" ||
      applyJson.error_code === "TARGET_MISMATCH",
    `unexpected error_code: ${String(applyJson.error_code)}`,
  );
  assert.equal(hashTargetTree(repoFixture), repoBefore);
});

// --- T15-S11 CLI/MCP equivalence ---
test("T15-S11: CLI/MCP platform-status field equivalence", async () => {
  const cli = runCliJson(["platform-status", "--adapter=linux"]);
  assert.equal(cli.exitCode, 0, cli.stderr);
  assert.ok(cli.result);
  assert.equal(cli.result!.ok, true);
  assert.equal(cli.result!.full_support_claimed, false);
  assert.equal(cli.result!.default_status, "LIMITED");
  assertNoLeakText(cli.stdout);

  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const mcp = (await client.callTool("changeguard_platform_status", {
      adapter: "linux",
    })) as Record<string, unknown>;
    assert.equal(mcp.ok, true);
    assert.equal(mcp.full_support_claimed, false);
    assert.equal(mcp.default_status, "LIMITED");
    assert.equal(mcp.network_used, false);
    assert.equal(mcp.target_mutated, false);
    const mcpText = JSON.stringify(mcp);
    assertNoLeakText(mcpText);
  } finally {
    await client.close();
  }
});

// --- IT handoff redaction ---
test("T15: IT handoff builder rejects bypass/elevation guidance", () => {
  assert.throws(() =>
    buildITHandoff({
      policy_class: "enterprise_mdm",
      target_path_alias: "X",
      config_key: null,
      evidence_digests: [],
      admin_owned: true,
      signed: false,
      permission_bound: true,
      proposed_action: "run sudo chmod 777 on the managed file",
    }),
  );
});

// --- apply also gated ---
test("T15: applyRepair refuses LIMITED capability without allow flag", () => {
  const tmp = makeTempDir("cg-t15-apply-");
  const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
  const preview = previewRepair(target, isolatedFixtureRepairCapabilityOptions());
  assert.equal(preview.ok, true);
  const apply = applyRepair(target, {
    authorization: preview.authorization!,
    capability_status: "LIMITED",
    isolation: "isolated_fixture",
  });
  assert.equal(apply.ok, false);
  assert.equal(apply.error_code, "WRITE_DISABLED");
  assert.equal(apply.target_mutated, false);

  // Apply without capability options is also fail-closed.
  const applyDefault = applyRepair(target, {
    authorization: preview.authorization!,
  });
  assert.equal(applyDefault.ok, false);
  assert.equal(applyDefault.error_code, "WRITE_DISABLED");
});

// --- WSL capability report ---
test("T15: WSL capability report is LIMITED with host-mount refuse", () => {
  const report = wslCapabilityReport({
    configRoots: ["/mnt/c/Users/x/.codex"],
    distro_name: "Ubuntu",
  });
  assert.equal(report.status, "LIMITED");
  assert.equal(report.full_support_claimed, false);
  assert.ok(
    report.discoveries.some(
      (d) => d.refused_reason === "HOST_MOUNT_OR_REFUSED_PREFIX",
    ),
  );
});
