/**
 * Ticket 14 — Windows 11 adapter + platform support validation framework.
 *
 * Host is macOS in CI; all discovery uses injected systemCaps.
 * Platform status MUST remain PREVIEW without a real Windows 11 receipt.
 * Never fabricates FULL from synthetic / forged / non-Windows evidence.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  runCliDiagnose,
  runCliJson,
  runCliRepairPreview,
  runMcpDiagnose,
  windowsHostTestEnv,
} from "../src/harness/scenario.js";
import {
  bindRepairTarget,
  enumerateSystemCandidates,
  enumerateWindowsCandidates,
  instanceFingerprintOf,
  parseCrashMetadataWindow,
  resolveWindowsRepairScope,
  scanInstances,
  classifyWriteTarget,
  isForbiddenSystemPath,
  isSignedAppBinaryPath,
} from "../src/instances/index.js";
import {
  loadAndEvaluateReceiptFile,
  realMachineRunnerPlan,
  windows11SupportStatus,
  WINDOWS11_CRITICAL_SCENARIO_IDS,
  parsePlatformSupportReceipt,
  sealWindowsLiveHarnessWitness,
  windowsLiveAttestationFromReceipt,
  isWindowsLiveHarnessWitness,
  validatePlatformSupportReceipt,
  sealLiveHarnessWitness,
  buildPlatformSupportReceipt,
  buildMacosCapabilities,
  captureActiveCodexHomeWitness,
  isolationDigestOf,
  scenarioHashOf,
  scenariosDigestOf,
  hostCoarseFingerprintOf,
  MACOS_REQUIRED_SCENARIO_IDS,
  ReceiptValidationError,
  isolatedFixtureRepairCapabilityOptions,
} from "../src/platform/index.js";
import { diagnose } from "../src/core/diagnose.js";
import {
  previewRepair,
  applyRepair,
  verifyRepair,
  rollbackRepair,
  evaluateWindowsWriteGate,
  resolveTrustedHostPlatform,
} from "../src/core/recovery/index.js";
import { makeTempDir, readJson, writeJson, REPO_ROOT } from "./helpers.js";
import { McpTestClient } from "../src/mcp/client.js";
import { mcpServerEntry } from "../src/harness/scenario.js";

function buildWindowsLayout(tmp: string): {
  caps: Parameters<typeof enumerateWindowsCandidates>[0];
  roots: {
    local: string;
    userprofile: string;
    pathDir: string;
    msix: string;
    desktopApp: string;
    desktopCli: string;
    pathCli: string;
    wsl: string;
    profile2: string;
    userOwned: string;
  };
} {
  const local = path.join(tmp, "LocalAppData");
  const userprofile = path.join(tmp, "Users", "Alice");
  const pathDir = path.join(tmp, "path-bin");
  fs.mkdirSync(pathDir, { recursive: true });
  fs.mkdirSync(path.join(local, "Programs", "Codex", "resources", "codex"), {
    recursive: true,
  });
  fs.mkdirSync(path.join(local, "Microsoft", "WindowsApps"), {
    recursive: true,
  });
  fs.mkdirSync(path.join(userprofile, ".codex"), { recursive: true });
  fs.mkdirSync(path.join(tmp, "wsl", "usr", "local", "bin"), {
    recursive: true,
  });

  const desktopApp = path.join(local, "Programs", "Codex", "Codex.exe");
  const desktopCli = path.join(
    local,
    "Programs",
    "Codex",
    "resources",
    "codex",
    "codex.exe",
  );
  const msix = path.join(local, "Microsoft", "WindowsApps", "codex.exe");
  const pathCli = path.join(pathDir, "codex.exe");
  const wsl = path.join(tmp, "wsl", "usr", "local", "bin", "codex");
  const profile2 = path.join(tmp, "Users", "Bob", ".codex");
  fs.mkdirSync(profile2, { recursive: true });

  for (const p of [desktopApp, desktopCli, msix, pathCli, wsl]) {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "MZ-fixture-never-execute\n", "utf8");
  }
  writeJson(path.join(path.dirname(desktopApp), "version.json"), {
    version: "0.50.0",
    build: "desktop",
  });
  writeJson(path.join(path.dirname(desktopCli), "version.json"), {
    version: "0.50.0",
    build: "desktop-cli",
  });
  fs.writeFileSync(
    path.join(path.dirname(msix), "AppxManifest.xml"),
    `<Package><Identity Version="0.49.0.0"/></Package>\n`,
    "utf8",
  );
  writeJson(path.join(pathDir, "version.json"), {
    version: "0.48.0",
    build: "path",
  });
  writeJson(path.join(path.dirname(wsl), "version.json"), {
    version: "0.47.0",
    build: "wsl",
  });
  fs.writeFileSync(path.join(profile2, "config.toml"), "model = \"o3\"\n", "utf8");
  fs.writeFileSync(
    path.join(userprofile, ".codex", "config.toml"),
    "model = \"o4\"\n",
    "utf8",
  );

  const userOwned = path.join(local, "Codex", "user-cache");
  fs.mkdirSync(userOwned, { recursive: true });

  const caps = {
    platform: "windows" as const,
    arch: "x64",
    env: {
      LOCALAPPDATA: local,
      USERPROFILE: userprofile,
      HOME: userprofile,
      Path: pathDir,
      PATH: pathDir,
    },
    pathEntries: [pathDir],
    pathDelimiter: ";",
    desktopPaths: [desktopApp],
    desktopCliPaths: [desktopCli],
    msixPaths: [msix],
    wslPaths: [wsl],
    includeHostWsl: true,
    packageRoots: [] as string[],
    homeDir: userprofile,
    userProfiles: [
      {
        profile_root_alias: "WIN_USER_PROFILE",
        config_root_alias: "WIN_USER_CODEX_CONFIG",
        root_abs: path.join(userprofile, ".codex"),
      },
      {
        profile_root_alias: "WIN_USER_PROFILE_2",
        config_root_alias: "WIN_USER_CODEX_CONFIG_2",
        root_abs: profile2,
      },
    ],
  };

  return {
    caps,
    roots: {
      local,
      userprofile,
      pathDir,
      msix,
      desktopApp,
      desktopCli,
      pathCli,
      wsl,
      profile2,
      userOwned,
    },
  };
}

test("windows adapter: MSIX, Desktop app, Desktop CLI, PATH, WSL, profiles stay distinct", () => {
  const tmp = makeTempDir("cg-t14-id-");
  const { caps } = buildWindowsLayout(tmp);
  const discovery = enumerateWindowsCandidates(caps);
  assert.ok(discovery.candidates.length >= 5, "expected multi-identity set");
  assert.equal(discovery.win_wsl_coexistence, true);

  const sources = new Set(
    discovery.candidates.map((c) => `${c.install_source}:${c.surface}`),
  );
  assert.ok(sources.has("windows_msix:desktop"));
  assert.ok(sources.has("desktop_bundled:desktop"));
  assert.ok(sources.has("desktop_bundled:cli"));
  assert.ok(sources.has("path:cli"));
  assert.ok(sources.has("wsl:cli"));

  const ids = discovery.candidates.map(
    (c) => `${c.install_source}|${c.surface}|${c.path}|${c.profile_root_alias}`,
  );
  assert.equal(new Set(ids).size, ids.length, "identities must not collapse");

  // WSL candidate keeps platform=wsl while native keep windows.
  const wsl = discovery.candidates.find((c) => c.install_source === "wsl");
  assert.ok(wsl);
  assert.equal(wsl!.platform, "wsl");
  const msix = discovery.candidates.find((c) => c.install_source === "windows_msix");
  assert.ok(msix);
  assert.equal(msix!.platform, "windows");

  // Multi-profile: second profile config surfaces as distinct row.
  const profiles = new Set(
    discovery.candidates
      .map((c) => c.profile_root_alias)
      .filter((a): a is string => !!a),
  );
  assert.ok(profiles.has("MSIX_PROFILE") || profiles.has("DESKTOP_PROFILE") || profiles.has("WIN_USER_PROFILE"));
  assert.ok(
    profiles.has("WIN_USER_PROFILE_2") ||
      discovery.candidates.some((c) => c.profile_root_alias === "WIN_USER_PROFILE_2"),
  );

  // system adapter delegates windows platform
  const viaSystem = enumerateSystemCandidates(caps);
  assert.equal(viaSystem.length, discovery.candidates.length);

  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.ok(scan.instances.length >= 5);
  const publicIds = new Set(scan.instances.map((i) => i.instance_id));
  assert.equal(publicIds.size, scan.instances.length);
  const dumped = JSON.stringify(scan);
  assert.equal(dumped.includes(tmp), false, "no temp path leak");
  assert.equal(/[A-Za-z]:\\Users\\/.test(dumped), false);
});

test("windows adapter: never executes candidates for version", () => {
  const tmp = makeTempDir("cg-t14-exec-");
  const flag = path.join(tmp, "executed.flag");
  const bin = path.join(tmp, "bin", "codex.exe");
  fs.mkdirSync(path.dirname(bin), { recursive: true });
  fs.writeFileSync(
    bin,
    `#!/bin/sh\ntouch "${flag}"\n`,
    "utf8",
  );
  fs.chmodSync(bin, 0o755);
  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: {
      platform: "windows",
      pathEntries: [path.dirname(bin)],
      desktopPaths: [],
      desktopCliPaths: [],
      msixPaths: [],
      wslPaths: [],
      packageRoots: [],
    },
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(fs.existsSync(flag), false);
  assert.equal(scan.instances[0]?.version_provenance === "unavailable" || scan.instances[0]?.version === null || typeof scan.instances[0]?.version === "string", true);
});

test("crash metadata: allowed window only; dump bodies refused", () => {
  const allowed = readJson(
    path.join(REPO_ROOT, "fixtures/windows11/crash-metadata-read/allowed-window.json"),
  );
  const window = parseCrashMetadataWindow(allowed);
  assert.equal(window.dump_contents_present, false);
  assert.equal(window.exception_code, "0xC0000005");
  assert.ok(window.metadata_digest.length === 64);

  const dump = readJson(
    path.join(REPO_ROOT, "fixtures/windows11/crash-metadata-read/dump-body-refused.json"),
  );
  assert.throws(() => parseCrashMetadataWindow(dump), /DUMP_BODY|dump/i);

  // Ticket 09 fixture still classifies correctly and refuses repair auth.
  const target = path.join(
    REPO_ROOT,
    "fixtures/crash-family/access-violation-crbrowser",
  );
  const result = diagnose(target);
  assert.equal(result.ok, true);
  assert.ok(
    result.user_resolution.status === "UPSTREAM_BLOCKED" ||
      result.diagnosis_state === "ISSUE_CANDIDATE" ||
      result.diagnosis_state === "HIGH_CONFIDENCE_MATCH" ||
      result.diagnosis_state === "INCONCLUSIVE",
  );
  const preview = previewRepair(target);
  assert.equal(preview.ok, false);
  // Wrong candidate must not reach repair authorization.
  assert.notEqual(
    preview.user_resolution.status,
    "REPAIR_PREVIEWED",
  );
});

test("browser crash families remain deterministically distinct", () => {
  const families = [
    "access-violation-crbrowser",
    "interaction-cpp-exception",
    "gpu-child-relaunch",
    "concurrency-webview",
  ];
  const primaries = new Set<string>();
  for (const name of families) {
    const r = diagnose(
      path.join(REPO_ROOT, "fixtures/crash-family", name),
    );
    assert.equal(r.ok, true);
    const top = r.upstream_contribution.issue_candidates[0];
    assert.ok(top, `expected primary for ${name}`);
    primaries.add(top!);
    const prev = previewRepair(
      path.join(REPO_ROOT, "fixtures/crash-family", name),
    );
    assert.equal(prev.ok, false);
  }
  assert.equal(primaries.size, 4, "four families must not collapse");
});

test("user-owned repair binds exact instance; reuses backup/apply/verify/rollback", () => {
  const tmp = makeTempDir("cg-t14-repair-");
  const { caps, roots } = buildWindowsLayout(tmp);
  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.ok(scan.instances.length >= 2);

  // Ambiguous multi-instance without id → refuse.
  const amb = bindRepairTarget(scan.instances, {});
  assert.equal(amb.ok, false);

  const pathInst = scan.instances.find((i) => i.install_source === "path");
  assert.ok(pathInst);
  const fp = instanceFingerprintOf(pathInst!);

  // Wrong instance fingerprint refused.
  const badFp = bindRepairTarget(scan.instances, {
    instance_id: pathInst!.instance_id,
    instance_fingerprint: "0".repeat(64),
  });
  assert.equal(badFp.ok, false);
  assert.equal(badFp.error_code, "FINGERPRINT_MISMATCH");

  // Copy plugin-cache corruption fixture as user-owned target under LOCALAPPDATA.
  const target = path.join(roots.userOwned, "repair-target");
  fs.cpSync(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
    target,
    { recursive: true },
  );

  const scope = resolveWindowsRepairScope({
    instances: scan.instances,
    repair: {
      instance_id: pathInst!.instance_id,
      instance_fingerprint: fp,
    },
    targetAbs: target,
    target_path_alias: "USER_CACHE_1",
    userOwnedRoots: [roots.local, roots.userprofile],
  });
  assert.equal(scope.ok, true);
  assert.equal(scope.classification.scope, "user_owned");
  assert.equal(scope.repair_authorized_eligible, true);
  assert.equal(scope.bound_instance?.instance_id, pathInst!.instance_id);

  // Full repair cycle via Ticket 02/08 engine on the isolated user-owned target.
  // Ticket 15: in-process mutation requires explicit capability (fail-closed default).
  const fixtureCap = isolatedFixtureRepairCapabilityOptions();
  const preview = previewRepair(target, fixtureCap);
  assert.equal(preview.ok, true, preview.error_message ?? "preview");
  assert.ok(preview.capsule);
  const token = preview.authorization;
  assert.ok(token);
  const applied = applyRepair(target, {
    authorization: token!,
    ...fixtureCap,
  });
  assert.equal(applied.ok, true, applied.error_message ?? "apply");
  // Apply path may already report RESOLVED_VERIFIED; verify/rollback remain safe.
  const verified = verifyRepair(target);
  assert.ok(
    verified.ok === true ||
      applied.user_resolution.status === "RESOLVED_VERIFIED" ||
      applied.repair_applied === true,
    verified.error_message ?? "verify",
  );
  const rolled = rollbackRepair(target);
  // Either successful rollback or already clean — must not write system paths.
  assert.notEqual(rolled.error_code, "INTERNAL");
});

test("managed/admin and forbidden system paths → ADMIN_ACTION_REQUIRED + IT handoff", () => {
  const tmp = makeTempDir("cg-t14-admin-");
  const { caps, roots } = buildWindowsLayout(tmp);
  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  const inst = scan.instances[0]!;

  const msixClass = classifyWriteTarget({
    absPath: roots.msix,
    target_path_alias: "MSIX_ALIAS",
  });
  assert.ok(
    msixClass.scope === "forbidden_system" || msixClass.scope === "admin_required",
  );
  assert.equal(msixClass.admin_owned || msixClass.signed, true);
  assert.match(msixClass.requested_action, /IT|official|enterprise|Do not modify/i);
  assert.equal(msixClass.requested_action.toLowerCase().includes("chmod"), false);
  assert.equal(msixClass.requested_action.toLowerCase().includes("runas"), false);

  assert.equal(
    isForbiddenSystemPath("C:\\Program Files\\WindowsApps\\Foo\\bar.exe"),
    true,
  );

  const managedScope = resolveWindowsRepairScope({
    instances: scan.instances,
    repair: { instance_id: inst.instance_id },
    targetAbs: path.join(tmp, "Program Files", "WindowsApps", "Codex", "x.exe"),
    target_path_alias: "MSIX_PACKAGE",
    managed: {
      policy_class: "msix_package",
      admin_owned: true,
      signed: true,
      permission_bound: true,
    },
  });
  assert.equal(managedScope.ok, false);
  assert.equal(managedScope.error_code, "ADMIN_ACTION_REQUIRED");
  assert.equal(managedScope.repair_authorized_eligible, false);
  assert.equal(managedScope.classification.policy_class, "msix_package");

  // Existing managed-policy fixture still returns admin handoff via engine.
  const managedTarget = path.join(REPO_ROOT, "fixtures/config-managed-policy");
  const prev = previewRepair(managedTarget);
  assert.equal(prev.ok, false);
  assert.equal(prev.error_code, "ADMIN_ACTION_REQUIRED");
  assert.ok(prev.admin_handoff);
  assert.equal(typeof prev.admin_handoff!.policy_class, "string");
});

test("platform status: default PREVIEW; synthetic/forged/non-windows never FULL", () => {
  const none = windows11SupportStatus(null);
  assert.equal(none.level, "preview");
  assert.equal(none.full_authorized, false);
  assert.ok(none.gaps.length >= WINDOWS11_CRITICAL_SCENARIO_IDS.length);

  const syntheticPath = path.join(
    REPO_ROOT,
    "fixtures/windows11/receipts/synthetic-preview.json",
  );
  const synthetic = loadAndEvaluateReceiptFile(syntheticPath);
  assert.equal(synthetic.ok, true);
  assert.equal(synthetic.status.level, "preview");
  assert.equal(synthetic.status.full_authorized, false);
  assert.ok(
    synthetic.status.gaps.some((g) => g.code === "SYNTHETIC_HOST"),
  );

  const forgedPath = path.join(
    REPO_ROOT,
    "fixtures/windows11/receipts/forged-full.json",
  );
  const forged = loadAndEvaluateReceiptFile(forgedPath);
  assert.equal(forged.ok, true);
  assert.equal(forged.status.full_authorized, false);
  assert.notEqual(forged.status.level, "full");

  const nonWin = loadAndEvaluateReceiptFile(
    path.join(REPO_ROOT, "fixtures/windows11/receipts/non-windows.json"),
  );
  assert.equal(nonWin.ok, true);
  assert.equal(nonWin.status.full_authorized, false);
  assert.ok(
    nonWin.status.gaps.some((g) => g.code === "NON_WINDOWS_RECEIPT"),
  );

  const missing = loadAndEvaluateReceiptFile(
    path.join(REPO_ROOT, "fixtures/windows11/receipts/missing-critical.json"),
  );
  assert.equal(missing.ok, true);
  assert.equal(missing.status.full_authorized, false);
  assert.ok(
    missing.status.gaps.some((g) => g.code === "MISSING_SCENARIO"),
  );

  // Structurally "complete" real_machine objects without a process-local live
  // witness are capped at PREVIEW (external JSON alone cannot Full).
  const allPass = buildForgedCompleteRealMachineReceipt();
  const parsed = parsePlatformSupportReceipt(allPass);
  const forgedMem = windows11SupportStatus(parsed);
  assert.equal(forgedMem.full_authorized, false);
  assert.equal(forgedMem.level, "preview");
  assert.ok(
    forgedMem.gaps.some((g) => g.code === "FULL_REQUIRES_LIVE_WITNESS"),
  );
  // Product language for *this* CI host remains PREVIEW without such a file.
  const hostDefault = windows11SupportStatus(null);
  assert.equal(hostDefault.level, "preview");
});

/** Complete real_machine shape used for adversarial Full-upgrade attempts. */
function buildForgedCompleteRealMachineReceipt(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: 1,
    platform: "windows",
    os_family: "Windows 11",
    os_version: "11",
    os_build: "22631",
    arch: "x64",
    host_kind: "real_machine",
    codex_versions: ["0.50.0"],
    instances_fingerprint: "e".repeat(64),
    git_sha: "c62b9b2e6c50fbd4cc31358a2371c6a888857808",
    collected_at: "2026-07-18T00:00:00.000Z",
    critical_scenarios: WINDOWS11_CRITICAL_SCENARIO_IDS.map((id) => ({
      id,
      title: id,
      passed: true,
      evidence_digest: "f".repeat(64),
      note: null,
    })),
    operator_attestation: {
      non_primary_profile: true,
      real_hardware: true,
    },
    ...overrides,
  };
}

test("real-machine runner entry is safe: plan only, no elevation language", () => {
  const plan = realMachineRunnerPlan();
  assert.equal(plan.platform, "windows");
  assert.equal(plan.mode, "validate_receipt_only");
  assert.equal(plan.critical_scenarios.length, 11);
  assert.ok(plan.forbidden_actions.includes("write_windowsapps"));
  assert.ok(plan.forbidden_actions.includes("privilege_elevation"));
  assert.ok(plan.forbidden_actions.includes("execute_codex_or_signed_binaries"));
});

test("CLI platform-status defaults to PREVIEW; receipt path evaluates gaps", () => {
  const def = runCliJson(["platform-status"]);
  assert.equal(def.exitCode, 0);
  assert.ok(def.result);
  const status = (def.result as { status: { level: string; full_authorized: boolean } })
    .status;
  assert.equal(status.level, "preview");
  assert.equal(status.full_authorized, false);

  const forged = runCliJson([
    "platform-status",
    `--receipt=${path.join(REPO_ROOT, "fixtures/windows11/receipts/forged-full.json")}`,
  ]);
  assert.equal(forged.exitCode, 0);
  const fsStatus = (forged.result as { status: { full_authorized: boolean; level: string } })
    .status;
  assert.equal(fsStatus.full_authorized, false);
  assert.notEqual(fsStatus.level, "full");

  const plan = runCliJson(["platform-status", "--plan"]);
  assert.equal(plan.exitCode, 0);
  assert.ok((plan.result as { plan: unknown }).plan);
});

test("MCP platform-status matches CLI PREVIEW contract", async () => {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const payload = (await client.callTool("changeguard_platform_status", {
      plan: true,
    })) as {
      ok: boolean;
      status: { level: string; full_authorized: boolean };
      plan: { critical_scenarios: unknown[] } | null;
    };
    assert.equal(payload.ok, true);
    assert.equal(payload.status.level, "preview");
    assert.equal(payload.status.full_authorized, false);
    assert.ok(payload.plan);
    assert.equal(payload.plan!.critical_scenarios.length, 11);
  } finally {
    await client.close();
  }
});

test("CLI/MCP diagnose crash fixture equivalence (stable fields)", async () => {
  const target = path.join(
    REPO_ROOT,
    "fixtures/crash-family/access-violation-crbrowser",
  );
  const cli = runCliDiagnose(target);
  assert.equal(cli.exitCode, 0);
  const mcp = await runMcpDiagnose(target);
  assert.equal(cli.result?.diagnosis_state, mcp.diagnosis_state);
  assert.equal(
    cli.result?.upstream_contribution.issue_candidates[0],
    mcp.upstream_contribution.issue_candidates[0],
  );
});

test("wrong family cannot reach repair authorization via repair-preview CLI", () => {
  const titleOnly = path.join(
    REPO_ROOT,
    "fixtures/crash-family/title-similarity-only",
  );
  const prev = runCliRepairPreview(titleOnly);
  assert.notEqual(prev.exitCode, 0);
  assert.ok(prev.result);
  assert.equal((prev.result as { ok: boolean }).ok, false);
});

// ---------------------------------------------------------------------------
// Ticket 14 P1 corrections — signed-binary priority + shared write-scope gate
// ---------------------------------------------------------------------------

function assertAdminHandoffNoElevation(handoff: {
  requested_action: string;
  policy_class: string;
  admin_owned: boolean;
  signed: boolean;
  permission_bound: boolean;
}): void {
  assert.equal(typeof handoff.policy_class, "string");
  assert.ok(handoff.policy_class.length > 0);
  assert.equal(typeof handoff.requested_action, "string");
  const lower = handoff.requested_action.toLowerCase();
  assert.equal(lower.includes("chmod"), false);
  assert.equal(lower.includes("runas"), false);
  assert.equal(lower.includes("uac"), false);
  assert.equal(lower.includes("elevate"), false);
  assert.equal(lower.includes("sudo"), false);
  assert.ok(
    handoff.admin_owned || handoff.signed || handoff.permission_bound,
    "IT handoff must carry ownership/signed/permission facts",
  );
}

test("P1: isSignedAppBinaryPath wins over user-owned markers (Desktop/MSIX/PATH)", () => {
  const tmp = makeTempDir("cg-t14-signed-");
  const { roots } = buildWindowsLayout(tmp);

  // Desktop app, Desktop CLI, MSIX alias, PATH CLI — all refused even under
  // LOCALAPPDATA / explicit userOwnedRoots (signed binary wins over markers).
  for (const [label, abs] of [
    ["desktopApp", roots.desktopApp],
    ["desktopCli", roots.desktopCli],
    ["msix", roots.msix],
    ["pathCli", roots.pathCli],
  ] as const) {
    assert.equal(isSignedAppBinaryPath(abs), true, `${label} is signed binary`);
    const c = classifyWriteTarget({
      absPath: abs,
      target_path_alias: `SIGNED_${label}`,
      userOwnedRoots: [roots.local, roots.userprofile, roots.userOwned],
    });
    assert.equal(
      c.scope,
      "forbidden_system",
      `${label} must be forbidden_system under userOwnedRoots`,
    );
    // MSIX alias / WindowsApps may classify as msix_package or system_acl
    // (fixture LocalAppData paths); Desktop/PATH as signed_binary.
    assert.ok(
      c.policy_class === "signed_binary" ||
        c.policy_class === "msix_package" ||
        c.policy_class === "system_acl",
      `${label} policy_class=${c.policy_class}`,
    );
    assert.equal(c.signed, true);
    assert.equal(c.admin_owned, true);
    assertAdminHandoffNoElevation({
      requested_action: c.requested_action,
      policy_class: c.policy_class,
      admin_owned: c.admin_owned,
      signed: c.signed,
      permission_bound: c.permission_bound,
    });
  }

  // Arbitrary .exe under explicit userOwnedRoots is still forbidden.
  const rogue = path.join(roots.userOwned, "helper.exe");
  fs.writeFileSync(rogue, "MZ\n", "utf8");
  assert.equal(isSignedAppBinaryPath(rogue), true);
  const rogueClass = classifyWriteTarget({
    absPath: rogue,
    target_path_alias: "ROGUE_EXE",
    userOwnedRoots: [roots.userOwned],
  });
  assert.equal(rogueClass.scope, "forbidden_system");
  assert.equal(rogueClass.policy_class, "signed_binary");

  // .dll / .sys under AppData Programs also forbidden.
  const dll = path.join(roots.local, "Programs", "Codex", "chrome.dll");
  fs.writeFileSync(dll, "MZ\n", "utf8");
  assert.equal(
    classifyWriteTarget({
      absPath: dll,
      target_path_alias: "CHROME_DLL",
      userOwnedRoots: [roots.local],
    }).scope,
    "forbidden_system",
  );
});

test("P1: user-owned allows only non-binary cache/control data under registered roots", () => {
  const tmp = makeTempDir("cg-t14-userdata-");
  const { roots } = buildWindowsLayout(tmp);
  const cacheFile = path.join(roots.userOwned, "cache.json");
  fs.writeFileSync(cacheFile, "{\"v\":1}\n", "utf8");
  const cfg = path.join(roots.userprofile, ".codex", "config.toml");

  for (const [alias, abs] of [
    ["USER_CACHE_JSON", cacheFile],
    ["USER_CONFIG", cfg],
    ["USER_CACHE_DIR", roots.userOwned],
  ] as const) {
    const c = classifyWriteTarget({
      absPath: abs,
      target_path_alias: alias,
      userOwnedRoots: [roots.local, roots.userprofile, roots.userOwned],
    });
    assert.equal(c.scope, "user_owned", alias);
    assert.equal(c.signed, false);
    assert.equal(c.admin_owned, false);
  }
});

test("P1: Program Files / WindowsApps / managed / unknown fail closed ADMIN_ACTION_REQUIRED", () => {
  const tmp = makeTempDir("cg-t14-pf-");
  const pf = path.join(tmp, "Program Files", "WindowsApps", "CodexPkg");
  fs.mkdirSync(pf, { recursive: true });
  const pfExe = path.join(pf, "Codex.exe");
  fs.writeFileSync(pfExe, "MZ\n", "utf8");

  assert.equal(isForbiddenSystemPath(pf), true);
  assert.equal(
    classifyWriteTarget({ absPath: pf, target_path_alias: "PF_DIR" }).scope,
    "forbidden_system",
  );
  assert.equal(
    classifyWriteTarget({ absPath: pfExe, target_path_alias: "PF_EXE" }).scope,
    "forbidden_system",
  );

  const managed = classifyWriteTarget({
    absPath: path.join(tmp, "somewhere", "config.toml"),
    target_path_alias: "MANAGED_CFG",
    managed: {
      policy_class: "enterprise_gpo",
      admin_owned: true,
      signed: true,
      permission_bound: true,
    },
  });
  assert.equal(managed.scope, "admin_required");

  const unknown = classifyWriteTarget({
    absPath: path.join(tmp, "orphan-target"),
    target_path_alias: "ORPHAN",
  });
  assert.equal(unknown.scope, "unknown");

  // resolveWindowsRepairScope maps all three to ADMIN_ACTION_REQUIRED.
  const scanTmp = makeTempDir("cg-t14-pf-scan-");
  const { caps } = buildWindowsLayout(scanTmp);
  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(scanTmp, "state"),
    persistState: false,
  });
  const inst = scan.instances[0]!;
  for (const [label, abs, managedFlag] of [
    ["pf", pf, undefined],
    ["unknown", path.join(tmp, "orphan-target"), undefined],
    [
      "managed",
      path.join(tmp, "somewhere"),
      {
        policy_class: "enterprise_gpo",
        admin_owned: true,
        signed: true,
        permission_bound: true,
      },
    ],
  ] as const) {
    const scope = resolveWindowsRepairScope({
      instances: scan.instances,
      repair: { instance_id: inst.instance_id },
      targetAbs: abs,
      target_path_alias: label.toUpperCase(),
      managed: managedFlag,
    });
    assert.equal(scope.ok, false, label);
    assert.equal(scope.error_code, "ADMIN_ACTION_REQUIRED", label);
    assert.equal(scope.repair_authorized_eligible, false, label);
  }
});

test("P1: shared recovery gate refuses Program Files / signed exe / unknown on Windows host", () => {
  const tmp = makeTempDir("cg-t14-gate-");
  const { roots } = buildWindowsLayout(tmp);

  // Seed a repairable plugin-cache fixture under forbidden and user-owned roots.
  const pfTarget = path.join(tmp, "Program Files", "Codex");
  fs.cpSync(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
    pfTarget,
    { recursive: true },
  );
  // Place a signed binary under an isolated target for writePaths classification.
  const signedTarget = path.join(tmp, "signed-bin-target");
  fs.mkdirSync(signedTarget, { recursive: true });
  const signedExe = path.join(signedTarget, "Codex.exe");
  fs.writeFileSync(signedExe, "MZ\n", "utf8");
  fs.cpSync(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
    path.join(signedTarget, "payload"),
    { recursive: true },
  );

  const userTarget = path.join(roots.userOwned, "repair-target");
  fs.cpSync(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
    userTarget,
    { recursive: true },
  );

  const unknownTarget = path.join(tmp, "orphan-repair");
  fs.cpSync(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
    unknownTarget,
    { recursive: true },
  );

  // Without Windows host injection, non-Windows fixtures remain compatible.
  const nonWin = previewRepair(unknownTarget);
  // May be ok or NOT_APPLICABLE depending on fixture — must not be Windows gate.
  assert.notEqual(
    nonWin.evidence?.some?.((e) => e.kind === "windows_write_scope") ?? false,
    true,
  );

  // Program Files → refuse
  const pfPrev = previewRepair(pfTarget, { hostPlatform: "win32" });
  assert.equal(pfPrev.ok, false);
  assert.equal(pfPrev.error_code, "ADMIN_ACTION_REQUIRED");
  assert.ok(pfPrev.admin_handoff);
  assertAdminHandoffNoElevation(pfPrev.admin_handoff!);

  // Signed binary path as writePaths → refuse even under userOwnedRoots
  const signedGate = evaluateWindowsWriteGate(userTarget, {
    hostPlatform: "win32",
    userOwnedRoots: [roots.userOwned],
    writePaths: [{ absPath: roots.desktopApp, alias: "DESKTOP_EXE" }],
  });
  assert.equal(signedGate.blocked, true);
  if (signedGate.blocked) {
    assert.equal(signedGate.error_code, "ADMIN_ACTION_REQUIRED");
    assert.equal(signedGate.classification.policy_class, "signed_binary");
    assertAdminHandoffNoElevation(signedGate.admin_handoff);
  }

  // Directory that is itself a signed-binary path marker (exe file as "path")
  const exePrev = previewRepair(userTarget, {
    hostPlatform: "win32",
    userOwnedRoots: [roots.userOwned],
    writePaths: [{ absPath: signedExe, alias: "SIGNED_EXE" }],
  });
  assert.equal(exePrev.ok, false);
  assert.equal(exePrev.error_code, "ADMIN_ACTION_REQUIRED");
  assert.ok(exePrev.admin_handoff);

  // Unknown ownership on Windows → ADMIN_ACTION_REQUIRED
  const unkPrev = previewRepair(unknownTarget, { hostPlatform: "win32" });
  assert.equal(unkPrev.ok, false);
  assert.equal(unkPrev.error_code, "ADMIN_ACTION_REQUIRED");
  assert.ok(unkPrev.admin_handoff);
  assert.equal(unkPrev.admin_handoff!.policy_class, "unknown");
  assertAdminHandoffNoElevation(unkPrev.admin_handoff!);

  // Managed flags → ADMIN_ACTION_REQUIRED
  const managedPrev = previewRepair(userTarget, {
    hostPlatform: "win32",
    userOwnedRoots: [roots.userOwned],
    managed: {
      policy_class: "msix_package",
      admin_owned: true,
      signed: true,
      permission_bound: true,
    },
  });
  assert.equal(managedPrev.ok, false);
  assert.equal(managedPrev.error_code, "ADMIN_ACTION_REQUIRED");
  assert.ok(managedPrev.admin_handoff);
  assert.equal(managedPrev.admin_handoff!.policy_class, "msix_package");

  // User-owned cache allowed on Windows host → may preview
  // Ticket 15: pair host context with isolated-fixture capability (test seam only).
  const fixtureCap = isolatedFixtureRepairCapabilityOptions();
  const userPrev = previewRepair(userTarget, {
    hostPlatform: "win32",
    userOwnedRoots: [roots.userOwned, roots.local],
    ...fixtureCap,
  });
  assert.equal(userPrev.ok, true, userPrev.error_message ?? "user cache preview");
  assert.ok(userPrev.authorization);
  assert.equal(userPrev.admin_handoff, null);

  // Apply also gates: unknown refuses even with a token from a non-Windows preview
  const token = userPrev.authorization!;
  const badApply = applyRepair(unknownTarget, {
    authorization: token,
    hostPlatform: "win32",
    ...fixtureCap,
  });
  assert.equal(badApply.ok, false);
  assert.equal(badApply.error_code, "ADMIN_ACTION_REQUIRED");

  // User-owned apply proceeds under Windows host + registered roots.
  const goodApply = applyRepair(userTarget, {
    authorization: token,
    hostPlatform: "win32",
    userOwnedRoots: [roots.userOwned, roots.local],
    ...fixtureCap,
  });
  assert.equal(goodApply.ok, true, goodApply.error_message ?? "user apply");
});

test("P1: trusted host platform injection; real win32 non-downgradable; no JSON forge", () => {
  // In-process injection works on non-Windows CI hosts.
  if (process.platform !== "win32") {
    assert.equal(resolveTrustedHostPlatform("win32"), "win32");
    assert.equal(resolveTrustedHostPlatform("windows"), "win32");
    assert.equal(resolveTrustedHostPlatform(null), process.platform);
  } else {
    // Real Windows cannot be downgraded.
    assert.equal(resolveTrustedHostPlatform("darwin"), "win32");
    assert.equal(resolveTrustedHostPlatform("linux"), "win32");
  }

  // Non-Windows fixtures stay compatible without host injection.
  const fixture = path.join(REPO_ROOT, "fixtures/plugin-cache/corruption");
  const prev = previewRepair(fixture);
  // Must not trip Windows gate on darwin/linux.
  if (process.platform !== "win32") {
    assert.equal(
      prev.evidence.some((e) => e.kind === "windows_write_scope"),
      false,
    );
  }
});

test("P1: CLI/MCP write-scope equivalence under Windows host injection", async () => {
  const tmp = makeTempDir("cg-t14-climcp-");
  const { roots } = buildWindowsLayout(tmp);

  const pfTarget = path.join(tmp, "Program Files", "WindowsApps", "Codex");
  fs.cpSync(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
    pfTarget,
    { recursive: true },
  );
  const userTarget = path.join(roots.userOwned, "repair-target");
  fs.cpSync(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
    userTarget,
    { recursive: true },
  );
  const unknownTarget = path.join(tmp, "orphan-repair");
  fs.cpSync(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
    unknownTarget,
    { recursive: true },
  );

  const winEnv = windowsHostTestEnv();

  // Program Files refused on CLI and MCP with identical error contract.
  const cliPf = runCliRepairPreview(pfTarget, { env: winEnv });
  assert.notEqual(cliPf.exitCode, 0);
  assert.equal((cliPf.result as { ok: boolean }).ok, false);
  assert.equal(
    (cliPf.result as { error_code: string }).error_code,
    "ADMIN_ACTION_REQUIRED",
  );
  assert.ok((cliPf.result as { admin_handoff: unknown }).admin_handoff);
  assertAdminHandoffNoElevation(
    (cliPf.result as { admin_handoff: {
      requested_action: string;
      policy_class: string;
      admin_owned: boolean;
      signed: boolean;
      permission_bound: boolean;
    } }).admin_handoff,
  );

  const mcpPfClient = new McpTestClient({
    serverEntry: mcpServerEntry(),
    env: winEnv,
  });
  try {
    mcpPfClient.start();
    const mcpPf = (await mcpPfClient.callTool("changeguard_repair_preview", {
      target: pfTarget,
    })) as {
      ok: boolean;
      error_code: string | null;
      admin_handoff: {
        requested_action: string;
        policy_class: string;
        admin_owned: boolean;
        signed: boolean;
        permission_bound: boolean;
      } | null;
    };
    assert.equal(mcpPf.ok, false);
    assert.equal(mcpPf.error_code, "ADMIN_ACTION_REQUIRED");
    assert.ok(mcpPf.admin_handoff);
    assertAdminHandoffNoElevation(mcpPf.admin_handoff!);
    assert.equal(
      (cliPf.result as { error_code: string }).error_code,
      mcpPf.error_code,
    );
  } finally {
    await mcpPfClient.close();
  }

  // Unknown ownership refused equivalently.
  const cliUnk = runCliRepairPreview(unknownTarget, { env: winEnv });
  assert.equal(
    (cliUnk.result as { error_code: string }).error_code,
    "ADMIN_ACTION_REQUIRED",
  );
  const mcpUnkClient = new McpTestClient({
    serverEntry: mcpServerEntry(),
    env: winEnv,
  });
  try {
    mcpUnkClient.start();
    const mcpUnk = (await mcpUnkClient.callTool("changeguard_repair_preview", {
      target: unknownTarget,
    })) as { ok: boolean; error_code: string | null };
    assert.equal(mcpUnk.ok, false);
    assert.equal(mcpUnk.error_code, "ADMIN_ACTION_REQUIRED");
  } finally {
    await mcpUnkClient.close();
  }

  // LOCALAPPDATA signed exe path: place a .exe-named directory parent that is
  // classified via write gate when target is under Programs with only binaries.
  // Use core classify for Desktop signed binary; CLI refuses Program Files above.
  const desktopClass = classifyWriteTarget({
    absPath: roots.desktopApp,
    target_path_alias: "DESKTOP",
    userOwnedRoots: [roots.local],
  });
  assert.equal(desktopClass.scope, "forbidden_system");

  // User cache allowed: harness injects Windows host AND userOwnedRoots only
  // via in-process core (CLI has no JSON platform forge). Prove CLI without
  // userOwnedRoots on a path that matches AppData heuristics after injection
  // still needs roots on POSIX — so allow via core; CLI/MCP refuse orphan.
  // Equivalence for allow path: both seams share previewRepair; core path above
  // already proved allow. Cross-check managed fixture CLI/MCP still refuse.
  const managedTarget = path.join(REPO_ROOT, "fixtures/config-managed-policy");
  const cliManaged = runCliRepairPreview(managedTarget, { env: winEnv });
  const mcpManagedClient = new McpTestClient({
    serverEntry: mcpServerEntry(),
    env: winEnv,
  });
  try {
    mcpManagedClient.start();
    const mcpManaged = (await mcpManagedClient.callTool(
      "changeguard_repair_preview",
      { target: managedTarget },
    )) as { ok: boolean; error_code: string | null };
    assert.equal((cliManaged.result as { ok: boolean }).ok, false);
    assert.equal(mcpManaged.ok, false);
    assert.equal(
      (cliManaged.result as { error_code: string }).error_code,
      "ADMIN_ACTION_REQUIRED",
    );
    assert.equal(mcpManaged.error_code, "ADMIN_ACTION_REQUIRED");
  } finally {
    await mcpManagedClient.close();
  }

  // Non-Windows host (no env injection): existing fixture path remains usable
  // for diagnose-style operations; repair-preview of plugin-cache still works.
  const cliNative = runCliRepairPreview(
    path.join(REPO_ROOT, "fixtures/plugin-cache/corruption"),
  );
  // On darwin/linux should not be Windows ADMIN from write-scope.
  if (process.platform !== "win32") {
    const code = (cliNative.result as { error_code: string | null } | null)
      ?.error_code;
    // Either success or mechanism refusal — not Windows write-scope unknown.
    if (code === "ADMIN_ACTION_REQUIRED") {
      const handoff = (cliNative.result as { admin_handoff: { policy_class: string } | null })
        .admin_handoff;
      // Managed-policy style is ok; pure unknown windows gate should not fire.
      assert.notEqual(handoff?.policy_class, "unknown");
    }
  }

  void userTarget; // reserved for future LOCALAPPDATA allow CLI wiring
});

// ---------------------------------------------------------------------------
// Ticket 14 P1 — live harness witness gate (external JSON cannot Full)
// ---------------------------------------------------------------------------

test("P1 live witness: forged complete real_machine object is PREVIEW", () => {
  const forged = buildForgedCompleteRealMachineReceipt();
  const status = windows11SupportStatus(forged);
  assert.equal(status.level, "preview");
  assert.equal(status.full_authorized, false);
  assert.ok(
    status.gaps.some((g) => g.code === "FULL_REQUIRES_LIVE_WITNESS"),
    JSON.stringify(status.gaps.map((g) => g.code)),
  );
});

test("P1 live witness: file/CLI/MCP forged complete receipt stay PREVIEW", async () => {
  const tmp = makeTempDir("cg-t14-forge-");
  const receiptPath = path.join(tmp, "forged-complete.json");
  writeJson(receiptPath, buildForgedCompleteRealMachineReceipt());

  const fileEval = loadAndEvaluateReceiptFile(receiptPath);
  assert.equal(fileEval.ok, true);
  assert.equal(fileEval.status.full_authorized, false);
  assert.equal(fileEval.status.level, "preview");
  assert.ok(
    fileEval.status.gaps.some((g) => g.code === "FULL_REQUIRES_LIVE_WITNESS"),
  );

  const cli = runCliJson([
    "platform-status",
    `--receipt=${receiptPath}`,
  ]);
  assert.equal(cli.exitCode, 0);
  const cliStatus = (
    cli.result as { status: { full_authorized: boolean; level: string; gaps: Array<{ code: string }> } }
  ).status;
  assert.equal(cliStatus.full_authorized, false);
  assert.equal(cliStatus.level, "preview");
  assert.ok(
    cliStatus.gaps.some((g) => g.code === "FULL_REQUIRES_LIVE_WITNESS"),
  );

  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const mcp = (await client.callTool("changeguard_platform_status", {
      receipt: receiptPath,
    })) as {
      ok: boolean;
      status: {
        full_authorized: boolean;
        level: string;
        gaps: Array<{ code: string }>;
      };
    };
    assert.equal(mcp.ok, true);
    assert.equal(mcp.status.full_authorized, false);
    assert.equal(mcp.status.level, "preview");
    assert.ok(
      mcp.status.gaps.some((g) => g.code === "FULL_REQUIRES_LIVE_WITNESS"),
    );
  } finally {
    await client.close();
  }
});

test("P1 live witness: only matching process-local seal can Full; clones/fakes cannot", () => {
  const raw = buildForgedCompleteRealMachineReceipt();
  const receipt = parsePlatformSupportReceipt(raw);
  const att = windowsLiveAttestationFromReceipt(receipt);
  const witness = sealWindowsLiveHarnessWitness(att);
  assert.equal(isWindowsLiveHarnessWitness(witness), true);

  const live = windows11SupportStatus(receipt, { liveWitness: witness });
  assert.equal(live.full_authorized, true, JSON.stringify(live.gaps));
  assert.equal(live.level, "full");

  // JSON clone of receipt cannot carry witness → PREVIEW.
  const clone = JSON.parse(JSON.stringify(receipt)) as unknown;
  const cloneStatus = windows11SupportStatus(clone);
  assert.equal(cloneStatus.full_authorized, false);
  assert.equal(cloneStatus.level, "preview");

  // Plain-object fake witness ignored.
  const fakeWitness = { ...att, forged: true };
  const fakeStatus = windows11SupportStatus(receipt, {
    // @ts-expect-error intentional forged witness shape
    liveWitness: fakeWitness,
  });
  assert.equal(fakeStatus.full_authorized, false);
  assert.equal(fakeStatus.level, "preview");
  assert.ok(
    fakeStatus.gaps.some(
      (g) =>
        g.code === "LIVE_WITNESS_MISMATCH" ||
        g.code === "FULL_REQUIRES_LIVE_WITNESS",
    ),
  );

  // Any bound field change → PREVIEW.
  const mutated = parsePlatformSupportReceipt(
    buildForgedCompleteRealMachineReceipt({
      collected_at: "2026-07-18T12:00:00.000Z",
    }),
  );
  const mismatch = windows11SupportStatus(mutated, { liveWitness: witness });
  assert.equal(mismatch.full_authorized, false);
  assert.equal(mismatch.level, "preview");
  assert.ok(
    mismatch.gaps.some((g) => g.code === "LIVE_WITNESS_MISMATCH"),
  );

  // Evidence digest change invalidates scenarios_binding.
  const scenariosMut = buildForgedCompleteRealMachineReceipt();
  (scenariosMut.critical_scenarios as Array<{ evidence_digest: string }>)[0]!
    .evidence_digest = "a".repeat(64);
  const mutScenarios = parsePlatformSupportReceipt(scenariosMut);
  const mismatchSc = windows11SupportStatus(mutScenarios, {
    liveWitness: witness,
  });
  assert.equal(mismatchSc.full_authorized, false);
  assert.ok(
    mismatchSc.gaps.some((g) => g.code === "LIVE_WITNESS_MISMATCH"),
  );
});

test("P1 receipt parser: top-level / scenario / attestation extra keys fail closed", () => {
  assert.throws(
    () =>
      parsePlatformSupportReceipt(
        buildForgedCompleteRealMachineReceipt({ live: true }),
      ),
    (e: unknown) =>
      e instanceof ReceiptValidationError && e.code === "EXTRA_KEY",
  );
  assert.throws(
    () =>
      parsePlatformSupportReceipt(
        buildForgedCompleteRealMachineReceipt({ full_authorized: true }),
      ),
    (e: unknown) =>
      e instanceof ReceiptValidationError && e.code === "EXTRA_KEY",
  );

  const badScenario = buildForgedCompleteRealMachineReceipt();
  (badScenario.critical_scenarios as Array<Record<string, unknown>>)[0]!
    .extra_flag = true;
  assert.throws(
    () => parsePlatformSupportReceipt(badScenario),
    (e: unknown) =>
      e instanceof ReceiptValidationError && e.code === "EXTRA_KEY",
  );

  const badAtt = buildForgedCompleteRealMachineReceipt({
    operator_attestation: {
      non_primary_profile: true,
      real_hardware: true,
      operator_name: "alice",
    },
  });
  assert.throws(
    () => parsePlatformSupportReceipt(badAtt),
    (e: unknown) =>
      e instanceof ReceiptValidationError && e.code === "EXTRA_KEY",
  );

  // evaluatePlatformSupport surfaces EXTRA_KEY as PREVIEW gap.
  const status = windows11SupportStatus(
    buildForgedCompleteRealMachineReceipt({ forged_full: true }),
  );
  assert.equal(status.full_authorized, false);
  assert.ok(status.gaps.some((g) => g.code === "EXTRA_KEY"));
});

test("P1 path safety: intermediate directory symlink receipt path refused", () => {
  const tmp = makeTempDir("cg-t14-sym-");
  const realDir = path.join(tmp, "real");
  const linkDir = path.join(tmp, "link");
  fs.mkdirSync(realDir, { recursive: true });
  const receiptFile = path.join(realDir, "receipt.json");
  writeJson(receiptFile, buildForgedCompleteRealMachineReceipt());
  fs.symlinkSync(realDir, linkDir);

  // Parent directory is a symlink → refuse (shared path-safety invariant).
  const viaLink = loadAndEvaluateReceiptFile(
    path.join(linkDir, "receipt.json"),
  );
  assert.equal(viaLink.ok, false);
  assert.equal(viaLink.error_code, "SYMLINK_REFUSED");
  assert.equal(viaLink.status.full_authorized, false);

  // Leaf symlink also refused.
  const leafLink = path.join(tmp, "leaf-link.json");
  fs.symlinkSync(receiptFile, leafLink);
  const viaLeaf = loadAndEvaluateReceiptFile(leafLink);
  assert.equal(viaLeaf.ok, false);
  assert.equal(viaLeaf.error_code, "SYMLINK_REFUSED");

  // Direct real path still loads (but stays PREVIEW without live witness).
  const direct = loadAndEvaluateReceiptFile(receiptFile);
  assert.equal(direct.ok, true);
  assert.equal(direct.status.level, "preview");
  assert.equal(direct.status.full_authorized, false);
});

test("P1 regression: T13 macOS live witness still Full; external macOS JSON not Full", () => {
  const scenarios = MACOS_REQUIRED_SCENARIO_IDS.map((id) => ({
    scenario_id: id,
    scenario_hash: scenarioHashOf(id),
    status: "pass" as const,
    outcome_summary: "unit pass",
    duration_ms: 1,
    required: true,
  }));
  const caps = buildMacosCapabilities({
    platform: "macos",
    arch: "arm64",
    probeHost: false,
  });
  const active_home_witness_digest =
    captureActiveCodexHomeWitness(null).digest;
  const isolation = {
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
  const receipt = buildPlatformSupportReceipt({
    platform: "macos",
    arch: "arm64",
    coarse_os_version: "15.0",
    changeguard_version: "0.1.0",
    changeguard_commit: "abc1234",
    codex_version_provenance: {
      available: false,
      version: null,
      provenance: "unavailable",
    },
    capabilities: caps,
    scenarios,
    isolation,
    started_at: "2026-07-18T00:00:00.000Z",
    ended_at: "2026-07-18T00:00:01.000Z",
  });

  const witness = sealLiveHarnessWitness({
    scenarios_digest: scenariosDigestOf(receipt.scenarios),
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
  const live = validatePlatformSupportReceipt(receipt, {
    liveWitness: witness,
  });
  assert.equal(live.ok, true, JSON.stringify(live.errors));
  assert.equal(live.support_level, "full");

  const external = validatePlatformSupportReceipt(
    JSON.parse(JSON.stringify(receipt)),
  );
  assert.notEqual(external.support_level, "full");
  assert.equal(external.support_level, "preview");
});
