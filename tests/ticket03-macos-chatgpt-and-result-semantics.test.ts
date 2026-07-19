/**
 * macOS ChatGPT.app discovery + ScanResult semantics (version / health / affected).
 *
 * Covers:
 * - Official ChatGPT.app Contents/Resources/codex as desktop_bundled with plist version
 * - Desktop + same PATH path deduped to one high-confidence desktop_bundled instance
 * - Legacy Codex.app still discovered
 * - Distinct PATH install remains independent
 * - Health classification: evidence_incomplete vs healthy vs identity/budget
 * - affected_resolution_reason: no_observed_context (including single-instance)
 * - Public JSON never leaks temp absolute paths; candidates never executed
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  enumerateSystemCandidates,
  readVersionEvidence,
  resolveAffectedInstance,
  scanInstances,
} from "../src/instances/index.js";
import {
  MAX_PLIST_VERSION_META_BYTES,
  MAX_VERSION_META_BYTES,
} from "../src/instances/limits.js";
import type {
  DiscoveredCandidate,
  InstanceIdentity,
} from "../src/instances/types.js";
import { runReadOnlyHealthCheck } from "../src/hooks/health-check.js";
import { findRepoRoot } from "../src/paths.js";
import { makeTempDir, writeJson } from "./helpers.js";

const REPO = findRepoRoot(import.meta.url);
const FIXTURE_APPS = path.join(REPO, "fixtures/platform-macos/apps");

function copyTree(src: string, dest: string): void {
  fs.mkdirSync(dest, { recursive: true });
  for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, ent.name);
    const d = path.join(dest, ent.name);
    if (ent.isDirectory()) copyTree(s, d);
    else fs.copyFileSync(s, d);
  }
}

function assertNoAbsLeak(text: string, ...roots: string[]): void {
  for (const r of roots) {
    assert.equal(
      text.includes(r),
      false,
      `public output must not contain absolute path root: ${r}`,
    );
  }
  assert.equal(/\/Users\//.test(text), false, "Users path leak");
  assert.equal(/\/var\/folders\//.test(text), false, "temp path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
}

function writeExecMarkerScript(binPath: string, flagPath: string): void {
  fs.mkdirSync(path.dirname(binPath), { recursive: true });
  fs.writeFileSync(
    binPath,
    `#!/bin/sh\necho executed > "${flagPath}"\nexit 0\n`,
    "utf8",
  );
  fs.chmodSync(binPath, 0o755);
}

/**
 * XML Info.plist padded with inert keys so byte size matches real Desktop
 * bundles (~19 KiB) or deliberately exceeds the plist meta cap.
 */
function writePaddedInfoPlist(
  dest: string,
  opts: {
    version: string;
    build: string;
    targetBytes: number;
  },
): number {
  const header = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleShortVersionString</key>
  <string>${opts.version}</string>
  <key>CFBundleVersion</key>
  <string>${opts.build}</string>
  <key>CFBundleIdentifier</key>
  <string>com.openai.codex</string>
`;
  const footer = `</dict>
</plist>
`;
  const padKey = "  <key>CGPad";
  const padMid = "</key>\n  <string>";
  const padEnd = "</string>\n";
  // One pad entry skeleton without the filler body.
  const entryOverhead =
    Buffer.byteLength(padKey, "utf8") +
    Buffer.byteLength("000000", "utf8") +
    Buffer.byteLength(padMid, "utf8") +
    Buffer.byteLength(padEnd, "utf8");
  let body = header;
  let i = 0;
  while (
    Buffer.byteLength(body, "utf8") + Buffer.byteLength(footer, "utf8") <
    opts.targetBytes
  ) {
    const remaining =
      opts.targetBytes -
      Buffer.byteLength(body, "utf8") -
      Buffer.byteLength(footer, "utf8");
    const fillerLen = Math.max(1, Math.min(512, remaining - entryOverhead));
    if (fillerLen <= 0) break;
    body +=
      padKey +
      String(i).padStart(6, "0") +
      padMid +
      "x".repeat(fillerLen) +
      padEnd;
    i += 1;
    if (i > 10_000) break;
  }
  const text = body + footer;
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, text, "utf8");
  return Buffer.byteLength(text, "utf8");
}

test("ChatGPT.app desktop + same PATH path: one desktop_bundled with plist version", () => {
  const tmp = makeTempDir("cg-chatgpt-dedupe-");
  const apps = path.join(tmp, "Applications");
  const chatgptRoot = path.join(apps, "ChatGPT.app");
  copyTree(path.join(FIXTURE_APPS, "ChatGPT.app"), chatgptRoot);

  const desktopBin = path.join(
    chatgptRoot,
    "Contents",
    "Resources",
    "codex",
  );
  const execFlag = path.join(tmp, "EXECUTED.flag");
  // Overwrite fixture binary with a marker script so any execution is visible.
  writeExecMarkerScript(desktopBin, execFlag);

  // PATH entry is the exact same normalized directory as the desktop binary.
  const pathDir = path.dirname(desktopBin);
  const stateDir = path.join(tmp, "state");

  const caps = {
    platform: "macos" as const,
    arch: "arm64",
    homeDir: path.join(tmp, "home"),
    pathEntries: [pathDir],
    desktopPaths: [desktopBin],
    packageRoots: [] as string[],
    msixPaths: [] as string[],
    wslPaths: [] as string[],
  };

  const candidates = enumerateSystemCandidates(caps);
  const samePath = candidates.filter(
    (c) => path.resolve(c.path) === path.resolve(desktopBin),
  );
  assert.equal(
    samePath.length,
    1,
    `expected one candidate for ChatGPT path, got ${samePath.length}`,
  );
  assert.equal(samePath[0]!.install_source, "desktop_bundled");
  assert.equal(samePath[0]!.surface, "desktop");

  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir,
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.instances.length, 1);
  const inst = scan.instances[0]!;
  assert.equal(inst.install_source, "desktop_bundled");
  assert.equal(inst.version, "26.715.31925");
  assert.equal(inst.build, "5551");
  assert.equal(inst.version_provenance, "plist_metadata");
  assert.equal(scan.affected_resolution, "ambiguous");
  assert.equal(scan.affected_resolution_reason, "no_observed_context");

  const dumped = JSON.stringify(scan);
  assertNoAbsLeak(dumped, tmp, desktopBin, chatgptRoot);
  assert.equal(fs.existsSync(execFlag), false, "must never execute candidates");
});

test("real-size Info.plist (~20 KiB) yields version/build via plist_metadata; never executes", () => {
  // Real /Applications/ChatGPT.app Info.plist is ~19,606 bytes; the 16 KiB
  // JSON/manifest cap must not reject plists in that range (separate 64 KiB cap).
  assert.ok(MAX_PLIST_VERSION_META_BYTES > MAX_VERSION_META_BYTES);
  assert.equal(MAX_VERSION_META_BYTES, 16 * 1024);
  assert.equal(MAX_PLIST_VERSION_META_BYTES, 64 * 1024);

  const tmp = makeTempDir("cg-plist-real-size-");
  const app = path.join(tmp, "Applications", "ChatGPT.app");
  const desktopBin = path.join(app, "Contents", "Resources", "codex");
  const execFlag = path.join(tmp, "EXECUTED.flag");
  writeExecMarkerScript(desktopBin, execFlag);

  const plistPath = path.join(app, "Contents", "Info.plist");
  const targetBytes = 19_606;
  assert.ok(
    targetBytes > MAX_VERSION_META_BYTES,
    "fixture must exceed the non-plist meta cap",
  );
  assert.ok(targetBytes < MAX_PLIST_VERSION_META_BYTES);
  const written = writePaddedInfoPlist(plistPath, {
    version: "26.715.31925",
    build: "5551",
    targetBytes,
  });
  assert.ok(
    written > MAX_VERSION_META_BYTES && written < MAX_PLIST_VERSION_META_BYTES,
    `expected padded plist in (16KiB, 64KiB), got ${written}`,
  );
  // Stay near the real-machine size class (not a multi-MiB blob).
  assert.ok(written >= 19_000 && written <= 22_000, `got ${written}`);

  const caps = {
    platform: "macos" as const,
    arch: "arm64",
    homeDir: path.join(tmp, "home"),
    pathEntries: [] as string[],
    desktopPaths: [desktopBin],
    packageRoots: [] as string[],
    msixPaths: [] as string[],
    wslPaths: [] as string[],
  };

  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.instances.length, 1);
  const inst = scan.instances[0]!;
  assert.equal(inst.install_source, "desktop_bundled");
  assert.equal(inst.version, "26.715.31925");
  assert.equal(inst.build, "5551");
  assert.equal(inst.version_provenance, "plist_metadata");
  assert.equal(fs.existsSync(execFlag), false, "must never execute candidates");
  assertNoAbsLeak(JSON.stringify(scan), tmp, desktopBin, app, plistPath);

  // Direct evidence path (explicit abs under trusted root) same contract.
  const trusted: DiscoveredCandidate = {
    install_source: "desktop_bundled",
    surface: "desktop",
    path: desktopBin,
    platform: "macos",
    arch: "arm64",
    profile_root_alias: null,
    config_root_alias: null,
    path_precedence: null,
    trusted_metadata_roots: [app],
    version_metadata_abs: [plistPath],
  };
  const ev = readVersionEvidence(trusted);
  assert.equal(ev.version, "26.715.31925");
  assert.equal(ev.build, "5551");
  assert.equal(ev.provenance, "plist_metadata");
});

test("Info.plist above plist size cap is unavailable; JSON meta cap unchanged", () => {
  const tmp = makeTempDir("cg-plist-oversize-");
  const app = path.join(tmp, "Applications", "ChatGPT.app");
  const desktopBin = path.join(app, "Contents", "Resources", "codex");
  const execFlag = path.join(tmp, "EXECUTED.flag");
  writeExecMarkerScript(desktopBin, execFlag);

  const plistPath = path.join(app, "Contents", "Info.plist");
  const overBytes = MAX_PLIST_VERSION_META_BYTES + 1024;
  const written = writePaddedInfoPlist(plistPath, {
    version: "26.715.31925",
    build: "5551",
    targetBytes: overBytes,
  });
  assert.ok(
    written > MAX_PLIST_VERSION_META_BYTES,
    `expected oversize plist, got ${written}`,
  );

  const caps = {
    platform: "macos" as const,
    arch: "arm64",
    desktopPaths: [desktopBin],
    pathEntries: [] as string[],
    packageRoots: [] as string[],
    msixPaths: [] as string[],
    wslPaths: [] as string[],
  };

  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.instances.length, 1);
  assert.equal(scan.instances[0]!.version, null);
  assert.equal(scan.instances[0]!.build, null);
  assert.equal(scan.instances[0]!.version_provenance, "unavailable");
  assert.equal(fs.existsSync(execFlag), false);
  assertNoAbsLeak(JSON.stringify(scan), tmp, desktopBin, app);

  // Non-plist metadata still uses the 16 KiB cap (not the plist 64 KiB cap).
  const pathDir = path.join(tmp, "path-json");
  fs.mkdirSync(pathDir, { recursive: true });
  const pathBin = path.join(pathDir, "codex");
  writeExecMarkerScript(pathBin, path.join(tmp, "path-ran.flag"));
  const bigJson = path.join(pathDir, "version.json");
  const pad = "x".repeat(MAX_VERSION_META_BYTES + 2048);
  fs.writeFileSync(
    bigJson,
    JSON.stringify({ version: "should-not-read", build: "x", pad }),
    "utf8",
  );
  assert.ok(fs.statSync(bigJson).size > MAX_VERSION_META_BYTES);

  const jsonScan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: {
      platform: "macos",
      arch: "arm64",
      desktopPaths: [],
      pathEntries: [pathDir],
      packageRoots: [],
      msixPaths: [],
      wslPaths: [],
    },
    stateDir: path.join(tmp, "state-json"),
    persistState: false,
  });
  assert.equal(jsonScan.ok, true);
  assert.equal(jsonScan.instances.length, 1);
  assert.equal(jsonScan.instances[0]!.version, null);
  assert.equal(jsonScan.instances[0]!.version_provenance, "unavailable");
  assert.equal(fs.existsSync(path.join(tmp, "path-ran.flag")), false);
  assertNoAbsLeak(JSON.stringify(jsonScan), tmp, pathDir);
});

test("legacy Codex.app path remains registered and independent of ChatGPT.app", () => {
  const tmp = makeTempDir("cg-legacy-codex-app-");
  const apps = path.join(tmp, "Applications");
  copyTree(
    path.join(FIXTURE_APPS, "Codex.app"),
    path.join(apps, "Codex.app"),
  );
  copyTree(
    path.join(FIXTURE_APPS, "ChatGPT.app"),
    path.join(apps, "ChatGPT.app"),
  );

  const legacyBin = path.join(
    apps,
    "Codex.app",
    "Contents",
    "MacOS",
    "Codex",
  );
  const chatgptBin = path.join(
    apps,
    "ChatGPT.app",
    "Contents",
    "Resources",
    "codex",
  );
  fs.chmodSync(legacyBin, 0o755);
  fs.chmodSync(chatgptBin, 0o755);

  const caps = {
    platform: "macos" as const,
    arch: "arm64",
    homeDir: path.join(tmp, "home"),
    desktopPaths: [chatgptBin, legacyBin],
    pathEntries: [] as string[],
    packageRoots: [] as string[],
    msixPaths: [] as string[],
    wslPaths: [] as string[],
  };

  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.instances.length, 2);
  const desk = scan.instances.filter((i) => i.install_source === "desktop_bundled");
  assert.equal(desk.length, 2);
  const versions = new Set(desk.map((i) => i.version));
  assert.ok(versions.has("26.715.31925"));
  assert.ok(versions.has("0.50.0-fixture"));
  for (const i of desk) {
    assert.equal(i.version_provenance, "plist_metadata");
  }
  assertNoAbsLeak(JSON.stringify(scan), tmp, apps);
});

test("distinct PATH install stays independent from Desktop ChatGPT.app", () => {
  const tmp = makeTempDir("cg-path-independent-");
  const chatgptRoot = path.join(tmp, "Applications", "ChatGPT.app");
  copyTree(path.join(FIXTURE_APPS, "ChatGPT.app"), chatgptRoot);
  const desktopBin = path.join(
    chatgptRoot,
    "Contents",
    "Resources",
    "codex",
  );
  fs.chmodSync(desktopBin, 0o755);

  const pathDir = path.join(tmp, "other-bin");
  fs.mkdirSync(pathDir, { recursive: true });
  const pathBin = path.join(pathDir, "codex");
  const execFlag = path.join(tmp, "path-ran.flag");
  writeExecMarkerScript(pathBin, execFlag);
  writeJson(path.join(pathDir, "version.json"), {
    version: "0.60.0-path-only",
    build: "pathbuild",
  });

  const caps = {
    platform: "macos" as const,
    arch: "arm64",
    desktopPaths: [desktopBin],
    pathEntries: [pathDir],
    packageRoots: [] as string[],
    msixPaths: [] as string[],
    wslPaths: [] as string[],
  };

  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.instances.length, 2);
  const desktop = scan.instances.find(
    (i) => i.install_source === "desktop_bundled",
  );
  const pathInst = scan.instances.find((i) => i.install_source === "path");
  assert.ok(desktop);
  assert.ok(pathInst);
  assert.equal(desktop!.version, "26.715.31925");
  assert.equal(desktop!.version_provenance, "plist_metadata");
  assert.equal(pathInst!.version, "0.60.0-path-only");
  assert.equal(pathInst!.version_provenance, "version_file");
  assert.notEqual(desktop!.instance_id, pathInst!.instance_id);
  assert.equal(fs.existsSync(execFlag), false);
  assertNoAbsLeak(JSON.stringify(scan), tmp, pathDir, desktopBin);
});

test("non-Desktop PATH and package-manager evidence keeps existing source identities", () => {
  const tmp = makeTempDir("cg-path-package-independent-");
  const packageRoot = path.join(tmp, "pkg");
  const binDir = path.join(packageRoot, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, "codex"), "x", "utf8");
  writeJson(path.join(packageRoot, "package.json"), { version: "0.61.0" });

  const candidates = enumerateSystemCandidates({
    platform: "macos",
    arch: "arm64",
    desktopPaths: [],
    pathEntries: [binDir],
    packageRoots: [packageRoot],
    msixPaths: [],
    wslPaths: [],
  });

  assert.equal(candidates.length, 2);
  assert.deepEqual(
    new Set(candidates.map((candidate) => candidate.install_source)),
    new Set(["path", "package_manager"]),
  );
});

test("default macOS desktop paths include ChatGPT.app and legacy Codex.app", () => {
  // Production defaults are exact registered paths — we only assert the list
  // when desktopPaths is not injected (via path presence after filter of missing).
  // Probe with a pathKind that reports all registered paths as files.
  const registered: string[] = [];
  const caps = {
    platform: "macos" as const,
    arch: "arm64",
    homeDir: "/Users/synthetic-home-for-defaults",
    pathKind: (abs: string): "file" | "dir" | "symlink" | "missing" | "other" => {
      if (
        abs.endsWith("ChatGPT.app/Contents/Resources/codex") ||
        abs.endsWith("Codex.app/Contents/MacOS/Codex")
      ) {
        registered.push(abs);
        return "file";
      }
      // App bundle roots would be directories if probed; desktop adapter only
      // probes exact binary paths first. Treat unknown as missing.
      if (abs.endsWith(".app") || abs.includes("Contents")) return "dir";
      return "missing";
    },
    pathEntries: [] as string[],
    packageRoots: [] as string[],
    msixPaths: [] as string[],
    wslPaths: [] as string[],
  };
  const candidates = enumerateSystemCandidates(caps);
  const paths = candidates.map((c) => c.path);
  assert.ok(
    paths.some((p) => p.includes("ChatGPT.app/Contents/Resources/codex")),
    "ChatGPT.app Resources/codex must be registered",
  );
  assert.ok(
    paths.some((p) => p.includes("Codex.app/Contents/MacOS/Codex")),
    "legacy Codex.app must remain registered",
  );
  assert.ok(
    paths.some((p) =>
      p.includes(
        "Applications/ChatGPT.app/Contents/Resources/codex".replace(
          "Applications",
          "Users/synthetic-home-for-defaults/Applications",
        ),
      ) ||
      p.includes(
        "/Users/synthetic-home-for-defaults/Applications/ChatGPT.app/Contents/Resources/codex",
      ),
    ),
    "user Applications ChatGPT.app must be registered",
  );
  for (const c of candidates) {
    assert.equal(c.install_source, "desktop_bundled");
  }
});

function fakeInstance(
  overrides: Partial<InstanceIdentity> & Pick<InstanceIdentity, "instance_id">,
): InstanceIdentity {
  return {
    path_hash: "a".repeat(64),
    path_alias: "PATH_1",
    surface: "cli",
    install_source: "path",
    platform: "macos",
    arch: "arm64",
    profile_root_alias: null,
    config_root_alias: null,
    version: "1.0.0",
    build: null,
    version_provenance: "version_file",
    path_precedence: 0,
    ...overrides,
  };
}

test("health: missing version evidence => evidence_incomplete; ok may be false", () => {
  const incomplete = runReadOnlyHealthCheck([
    fakeInstance({
      instance_id: "id-missing-ver",
      version: null,
      version_provenance: "unavailable",
    }),
  ]);
  assert.equal(incomplete.ok, false);
  assert.equal(incomplete.classification, "evidence_incomplete");
  assert.equal(incomplete.classification_reason, "version_evidence_missing");
  assert.equal(incomplete.read_only, true);
  assert.equal(incomplete.bounded, true);
});

test("health: complete evidence => healthy", () => {
  const healthy = runReadOnlyHealthCheck([
    fakeInstance({ instance_id: "id-ok", version: "26.715.31925" }),
  ]);
  assert.equal(healthy.ok, true);
  assert.equal(healthy.classification, "healthy");
  assert.equal(healthy.classification_reason, "all_checks_passed");
});

test("health: identity conflict vs budget exceeded are distinct classes", () => {
  const identity = runReadOnlyHealthCheck([
    fakeInstance({ instance_id: "dup", version: "1.0.0", path_hash: "b".repeat(64) }),
    fakeInstance({ instance_id: "dup", version: "2.0.0", path_hash: "c".repeat(64) }),
  ]);
  assert.equal(identity.ok, false);
  assert.equal(identity.classification, "identity_integrity_failed");
  assert.equal(identity.classification_reason, "duplicate_instance_ids");

  // Force budget failure with a frozen clock past budget.
  const t0 = 1000;
  const budget = runReadOnlyHealthCheck(
    [fakeInstance({ instance_id: "budget-id", version: "1.0.0" })],
    {
      budgetMs: 5,
      now: (() => {
        let n = 0;
        return () => {
          n += 1;
          // First call start, second call end — exceed budget.
          return n === 1 ? t0 : t0 + 50;
        };
      })(),
    },
  );
  assert.equal(budget.ok, false);
  assert.equal(budget.classification, "budget_exceeded");
  assert.equal(budget.classification_reason, "health_check_budget_exceeded");
});

test("affected: single instance without observed context is ambiguous + no_observed_context", () => {
  const sole = fakeInstance({
    instance_id: "sole-1",
    path_hash: "d".repeat(64),
  });
  const r = resolveAffectedInstance([sole], undefined);
  assert.equal(r.resolution, "ambiguous");
  assert.equal(r.instance_id, null);
  assert.equal(r.reason, "no_observed_context");

  const rEmpty = resolveAffectedInstance([sole], {});
  assert.equal(rEmpty.resolution, "ambiguous");
  assert.equal(rEmpty.reason, "no_observed_context");
});

test("affected: no instances => none + no_instances; multi without evidence => multi_instance_insufficient_evidence", () => {
  const none = resolveAffectedInstance([], undefined);
  assert.equal(none.resolution, "none");
  assert.equal(none.reason, "no_instances");

  const a = fakeInstance({
    instance_id: "a",
    path_hash: "e".repeat(64),
  });
  const b = fakeInstance({
    instance_id: "b",
    path_hash: "f".repeat(64),
    path_alias: "PATH_2",
  });
  // Observed present but matches nothing.
  const multi = resolveAffectedInstance([a, b], {
    process_path_hash: "0".repeat(64),
  });
  assert.equal(multi.resolution, "ambiguous");
  assert.equal(multi.reason, "multi_instance_insufficient_evidence");

  const soleNoMatch = resolveAffectedInstance([a], {
    process_path_hash: "0".repeat(64),
  });
  assert.equal(soleNoMatch.resolution, "ambiguous");
  assert.equal(soleNoMatch.reason, "observed_evidence_no_match");
});

test("affected: path evidence identifies; conflicting path evidence is conflicting_observed_evidence", () => {
  const a = fakeInstance({
    instance_id: "id-a",
    path_hash: "1".repeat(64),
  });
  const b = fakeInstance({
    instance_id: "id-b",
    path_hash: "2".repeat(64),
    path_alias: "PATH_2",
  });
  const id = resolveAffectedInstance([a, b], {
    process_path_hash: "1".repeat(64),
  });
  assert.equal(id.resolution, "identified");
  assert.equal(id.instance_id, "id-a");
  assert.equal(id.reason, "identified");

  const conflict = resolveAffectedInstance([a, b], {
    process_path_hash: "1".repeat(64),
    launch_path_hash: "2".repeat(64),
  });
  assert.equal(conflict.resolution, "ambiguous");
  assert.equal(conflict.reason, "conflicting_observed_evidence");
});

test("scan result exposes affected_resolution_reason and health classification", () => {
  const tmp = makeTempDir("cg-scan-semantics-");
  const pathDir = path.join(tmp, "bin");
  fs.mkdirSync(pathDir, { recursive: true });
  fs.writeFileSync(path.join(pathDir, "codex"), "x", "utf8");
  // No version metadata → evidence incomplete when health runs.

  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: {
      platform: "macos",
      arch: "arm64",
      pathEntries: [pathDir],
      desktopPaths: [],
      packageRoots: [],
      msixPaths: [],
      wslPaths: [],
    },
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.affected_resolution, "ambiguous");
  assert.equal(scan.affected_resolution_reason, "no_observed_context");
  assert.ok(scan.health_check);
  assert.equal(scan.health_check!.classification, "evidence_incomplete");
  assert.equal(scan.health_check!.ok, false);
  assertNoAbsLeak(JSON.stringify(scan), tmp, pathDir);
});
