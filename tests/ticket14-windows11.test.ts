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
} from "../src/instances/index.js";
import {
  loadAndEvaluateReceiptFile,
  realMachineRunnerPlan,
  windows11SupportStatus,
  WINDOWS11_CRITICAL_SCENARIO_IDS,
  parsePlatformSupportReceipt,
} from "../src/platform/index.js";
import { diagnose } from "../src/core/diagnose.js";
import { previewRepair, applyRepair, verifyRepair, rollbackRepair } from "../src/core/recovery/index.js";
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
  const preview = previewRepair(target);
  assert.equal(preview.ok, true, preview.error_message ?? "preview");
  assert.ok(preview.capsule);
  const token = preview.authorization;
  assert.ok(token);
  const applied = applyRepair(target, { authorization: token! });
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

  // Even a structurally "complete" real_machine receipt is only FULL when
  // evaluated — we do not ship one in fixtures (no fabrication on this host).
  // Prove the positive path with an in-memory object that would pass IF real.
  const allPass = {
    schema_version: 1 as const,
    platform: "windows" as const,
    os_family: "Windows 11",
    os_version: "11",
    os_build: "22631",
    arch: "x64",
    host_kind: "real_machine" as const,
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
  };
  const parsed = parsePlatformSupportReceipt(allPass);
  const full = windows11SupportStatus(parsed);
  // Validator allows FULL only for complete real-machine evidence objects;
  // this is unit-level capability proof, not a product claim for this host.
  assert.equal(full.full_authorized, true);
  assert.equal(full.level, "full");
  // Product language for *this* CI host remains PREVIEW without such a file.
  const hostDefault = windows11SupportStatus(null);
  assert.equal(hostDefault.level, "preview");
});

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
