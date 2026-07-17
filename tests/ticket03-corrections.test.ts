/**
 * Ticket 03 correction tests — P1s + Root acceptance gaps.
 * TDD coverage for path clamping, no-follow, system adapter, packaged hook.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  enumerateSystemCandidates,
  readVersionEvidence,
  scanInstances,
} from "../src/instances/index.js";
import type { DiscoveredCandidate } from "../src/instances/types.js";
import {
  runPackagedSessionStart,
  parseHookStdin,
  resolvePluginPaths,
} from "../src/hooks/session-start-entry.js";
import { findRepoRoot } from "../src/paths.js";
import { makeTempDir, writeJson } from "./helpers.js";

const repoRoot = findRepoRoot(import.meta.url);

function buildMinimalInventory(
  tmp: string,
  opts: {
    relative_path: string;
    version_metadata_rel?: string | null;
    version?: string;
  },
): string {
  const root = path.join(tmp, "inventory");
  fs.mkdirSync(root, { recursive: true });
  const abs = path.join(root, opts.relative_path);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, "#!/bin/sh\n# placeholder\n", "utf8");
  if (opts.version) {
    writeJson(path.join(path.dirname(abs), "version.json"), {
      version: opts.version,
    });
  }
  writeJson(path.join(root, "inventory.json"), {
    schema_version: 1,
    platform: "macos",
    arch: "arm64",
    candidates: [
      {
        install_source: "path",
        surface: "cli",
        relative_path: opts.relative_path,
        path_precedence: 0,
        version_metadata_rel: opts.version_metadata_rel,
      },
    ],
    observed_context: {},
  });
  return root;
}

test("P1-1: parent-relative metadata probes do not escape inventoryRoot", () => {
  const tmp = makeTempDir("cg-t03-p1-parent-");
  const outside = path.join(tmp, "OUTSIDE");
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(
    path.join(outside, "Info.plist"),
    `<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleShortVersionString</key><string>LEAKED-OUTSIDE-9.9.9</string>
<key>CFBundleVersion</key><string>999</string>
</dict></plist>`,
    "utf8",
  );
  // Shallow candidate at inventory root so dirname + ../Info.plist would escape.
  const root = buildMinimalInventory(tmp, {
    relative_path: "codex",
    version_metadata_rel: null,
  });
  // Place outside as sibling of inventory root (../Info.plist from candidate dir).
  // inventory is tmp/inventory, candidate is tmp/inventory/codex, parent is tmp/inventory.
  // Classic escape put Info.plist at tmp/Info.plist via ../ from near=tmp/inventory.
  fs.writeFileSync(
    path.join(tmp, "Info.plist"),
    `<?xml version="1.0"?>
<plist><dict>
<key>CFBundleShortVersionString</key><string>LEAKED-OUTSIDE-9.9.9</string>
</dict></plist>`,
    "utf8",
  );
  // Also npm-style parent package.json outside inventory.
  fs.mkdirSync(path.join(tmp, "lib", "node_modules", "@openai", "codex"), {
    recursive: true,
  });
  writeJson(
    path.join(tmp, "lib", "node_modules", "@openai", "codex", "package.json"),
    { version: "NPM-LEAK-8.8.8" },
  );

  const scan = scanInstances({
    inventoryRoot: root,
    mode: "manual_scan",
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.notEqual(scan.instances[0]?.version, "LEAKED-OUTSIDE-9.9.9");
  assert.notEqual(scan.instances[0]?.version, "NPM-LEAK-8.8.8");
  // Without in-root metadata → unavailable (not leaked).
  assert.equal(scan.instances[0]?.version_provenance, "unavailable");
  assert.equal(scan.instances[0]?.version, null);
});

test("P1-1: explicit version_metadata_rel with .. is refused by inventory", () => {
  const tmp = makeTempDir("cg-t03-p1-dotdot-");
  const root = path.join(tmp, "inventory");
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "codex"), "x", "utf8");
  fs.writeFileSync(
    path.join(tmp, "Info.plist"),
    "<plist><dict><key>CFBundleShortVersionString</key><string>LEAK</string></dict></plist>",
    "utf8",
  );
  writeJson(path.join(root, "inventory.json"), {
    schema_version: 1,
    platform: "macos",
    arch: "arm64",
    candidates: [
      {
        install_source: "path",
        surface: "cli",
        relative_path: "codex",
        path_precedence: 0,
        version_metadata_rel: "../Info.plist",
      },
    ],
    observed_context: {},
  });
  const scan = scanInstances({
    inventoryRoot: root,
    mode: "manual_scan",
    persistState: false,
  });
  assert.equal(scan.ok, false);
  assert.equal(scan.error_code, "PATH_ESCAPE");
});

test("P1-2: intermediate symlink in version metadata is not followed", () => {
  const tmp = makeTempDir("cg-t03-p1-symlink-");
  const outside = path.join(tmp, "secret-outside");
  fs.mkdirSync(outside, { recursive: true });
  writeJson(path.join(outside, "secret-version.json"), {
    version: "SYMLINK-LEAK-7.7.7",
  });

  const root = path.join(tmp, "inventory");
  fs.mkdirSync(path.join(root, "bin"), { recursive: true });
  fs.writeFileSync(path.join(root, "bin", "codex"), "x", "utf8");
  // Intermediate directory symlink: inventory/meta -> outside
  fs.symlinkSync(outside, path.join(root, "meta"));
  writeJson(path.join(root, "inventory.json"), {
    schema_version: 1,
    platform: "macos",
    arch: "arm64",
    candidates: [
      {
        install_source: "path",
        surface: "cli",
        relative_path: "bin/codex",
        path_precedence: 0,
        version_metadata_rel: "meta/secret-version.json",
      },
    ],
    observed_context: {},
  });
  const scan = scanInstances({
    inventoryRoot: root,
    mode: "manual_scan",
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.notEqual(scan.instances[0]?.version, "SYMLINK-LEAK-7.7.7");
  assert.equal(scan.instances[0]?.version, null);
  assert.equal(scan.instances[0]?.version_provenance, "unavailable");
});

test("P1-2: leaf symlink version metadata is refused", () => {
  const tmp = makeTempDir("cg-t03-p1-leaf-");
  const outside = path.join(tmp, "out.json");
  writeJson(outside, { version: "LEAF-LEAK-1.1.1" });
  const root = path.join(tmp, "inventory");
  fs.mkdirSync(path.join(root, "bin"), { recursive: true });
  fs.writeFileSync(path.join(root, "bin", "codex"), "x", "utf8");
  fs.symlinkSync(outside, path.join(root, "bin", "version.json"));
  writeJson(path.join(root, "inventory.json"), {
    schema_version: 1,
    platform: "macos",
    arch: "arm64",
    candidates: [
      {
        install_source: "path",
        surface: "cli",
        relative_path: "bin/codex",
        path_precedence: 0,
        version_metadata_rel: "bin/version.json",
      },
    ],
    observed_context: {},
  });
  const scan = scanInstances({
    inventoryRoot: root,
    mode: "manual_scan",
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.notEqual(scan.instances[0]?.version, "LEAF-LEAK-1.1.1");
  assert.equal(scan.instances[0]?.version_provenance, "unavailable");
});

test("system adapter: registered roots only; no raw path disclosure; never execute", () => {
  const tmp = makeTempDir("cg-t03-sys-");
  const desktopBin = path.join(
    tmp,
    "Apps",
    "Codex.app",
    "Contents",
    "MacOS",
    "Codex",
  );
  fs.mkdirSync(path.dirname(desktopBin), { recursive: true });
  const execFlag = path.join(tmp, "EXECUTED.flag");
  fs.writeFileSync(
    desktopBin,
    `#!/bin/sh\necho ran > "${execFlag}"\n`,
    "utf8",
  );
  fs.chmodSync(desktopBin, 0o755);
  fs.writeFileSync(
    path.join(tmp, "Apps", "Codex.app", "Contents", "Info.plist"),
    `<?xml version="1.0"?>
<plist><dict>
<key>CFBundleShortVersionString</key><string>0.50.0</string>
<key>CFBundleVersion</key><string>50</string>
</dict></plist>`,
    "utf8",
  );

  const pathDir = path.join(tmp, "pathbin");
  fs.mkdirSync(pathDir, { recursive: true });
  const pathBin = path.join(pathDir, "codex");
  fs.writeFileSync(pathBin, "#!/bin/sh\nexit 0\n", "utf8");
  writeJson(path.join(pathDir, "version.json"), { version: "0.49.0" });

  const pkgRoot = path.join(tmp, "npm", "@openai", "codex");
  fs.mkdirSync(path.join(pkgRoot, "bin"), { recursive: true });
  fs.writeFileSync(path.join(pkgRoot, "bin", "codex"), "x", "utf8");
  writeJson(path.join(pkgRoot, "package.json"), { version: "0.48.0" });

  const msix = path.join(tmp, "WindowsApps", "codex.exe");
  fs.mkdirSync(path.dirname(msix), { recursive: true });
  fs.writeFileSync(msix, "MZ", "utf8");
  fs.writeFileSync(
    path.join(path.dirname(msix), "AppxManifest.xml"),
    `<Package><Identity Version="0.47.0.0"/></Package>`,
    "utf8",
  );

  const wsl = path.join(tmp, "wsl", "usr", "local", "bin", "codex");
  fs.mkdirSync(path.dirname(wsl), { recursive: true });
  fs.writeFileSync(wsl, "x", "utf8");
  writeJson(path.join(path.dirname(wsl), "version.json"), { version: "0.46.0" });

  const stateDir = path.join(tmp, "state");
  const caps = {
    platform: "macos" as const,
    arch: "arm64",
    env: { PATH: pathDir, HOME: tmp },
    pathEntries: [pathDir],
    desktopPaths: [desktopBin],
    packageRoots: [pkgRoot],
    msixPaths: [msix],
    wslPaths: [wsl],
  };

  const candidates = enumerateSystemCandidates(caps);
  assert.ok(candidates.length >= 4);
  const sources = new Set(candidates.map((c) => c.install_source));
  assert.ok(sources.has("desktop_bundled"));
  assert.ok(sources.has("path"));
  assert.ok(sources.has("package_manager"));
  assert.ok(sources.has("windows_msix") || sources.has("wsl"));

  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: caps,
    stateDir,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.primary_transition, "first_baseline");
  const dumped = JSON.stringify(scan);
  assert.equal(dumped.includes(tmp), false, "must not disclose tmp paths");
  assert.equal(dumped.includes(desktopBin), false);
  assert.equal(fs.existsSync(execFlag), false, "must never execute candidates");

  const desk = scan.instances.find((i) => i.install_source === "desktop_bundled");
  assert.ok(desk);
  assert.equal(desk!.version, "0.50.0");
  assert.equal(desk!.version_provenance, "plist_metadata");

  const pathInst = scan.instances.find((i) => i.install_source === "path");
  assert.ok(pathInst);
  assert.equal(pathInst!.version, "0.49.0");
});

test("system adapter: missing metadata yields explicit unavailable, not execution", () => {
  const tmp = makeTempDir("cg-t03-unavail-");
  const bin = path.join(tmp, "bin", "codex");
  fs.mkdirSync(path.dirname(bin), { recursive: true });
  const flag = path.join(tmp, "ran.flag");
  fs.writeFileSync(bin, `#!/bin/sh\ntouch "${flag}"\n`, "utf8");
  fs.chmodSync(bin, 0o755);
  const scan = scanInstances({
    mode: "manual_scan",
    enumeration: "system_registered",
    systemCaps: {
      platform: "linux",
      pathEntries: [path.dirname(bin)],
      desktopPaths: [],
      packageRoots: [],
      msixPaths: [],
      wslPaths: [],
    },
    stateDir: path.join(tmp, "state"),
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.instances.length, 1);
  assert.equal(scan.instances[0]!.version, null);
  assert.equal(scan.instances[0]!.version_provenance, "unavailable");
  assert.equal(fs.existsSync(flag), false);
});

test("parent metadata only via registered trusted system root", () => {
  const tmp = makeTempDir("cg-t03-trusted-");
  const app = path.join(tmp, "Codex.app");
  const bin = path.join(app, "Contents", "MacOS", "Codex");
  fs.mkdirSync(path.dirname(bin), { recursive: true });
  fs.writeFileSync(bin, "x", "utf8");
  fs.writeFileSync(
    path.join(app, "Contents", "Info.plist"),
    `<plist><dict><key>CFBundleShortVersionString</key><string>1.2.3</string></dict></plist>`,
    "utf8",
  );
  // Without trusted root, parent Info.plist must not be readable.
  const bare: DiscoveredCandidate = {
    install_source: "desktop_bundled",
    surface: "desktop",
    path: bin,
    platform: "macos",
    arch: "arm64",
    profile_root_alias: null,
    config_root_alias: null,
    path_precedence: null,
    trusted_metadata_roots: [path.dirname(bin)], // MacOS dir only — no parent
  };
  const denied = readVersionEvidence(bare);
  assert.equal(denied.version, null);

  // With app bundle registered as trusted root + explicit meta path.
  const trusted: DiscoveredCandidate = {
    ...bare,
    trusted_metadata_roots: [app],
    version_metadata_abs: [path.join(app, "Contents", "Info.plist")],
  };
  const ok = readVersionEvidence(trusted);
  assert.equal(ok.version, "1.2.3");
  assert.equal(ok.provenance, "plist_metadata");
});

test("packaged SessionStart: PLUGIN paths, silence on unchanged, state under PLUGIN_DATA", () => {
  const tmp = makeTempDir("cg-t03-hook-");
  const pluginRoot = path.join(tmp, "plugin");
  const pluginData = path.join(tmp, "plugin-data");
  const sessionCwd = path.join(tmp, "session-cwd");
  fs.mkdirSync(pluginRoot, { recursive: true });
  fs.mkdirSync(pluginData, { recursive: true });
  fs.mkdirSync(sessionCwd, { recursive: true });

  const pathDir = path.join(tmp, "bin");
  fs.mkdirSync(pathDir, { recursive: true });
  fs.writeFileSync(path.join(pathDir, "codex"), "x", "utf8");
  writeJson(path.join(pathDir, "version.json"), { version: "2.0.0" });

  const caps = {
    platform: "linux" as const,
    pathEntries: [pathDir],
    desktopPaths: [] as string[],
    packageRoots: [] as string[],
    msixPaths: [] as string[],
    wslPaths: [] as string[],
  };

  const env = {
    PLUGIN_ROOT: pluginRoot,
    PLUGIN_DATA: pluginData,
  };
  assert.deepEqual(resolvePluginPaths(env), {
    pluginRoot,
    pluginData,
  });

  const stdin = JSON.stringify({
    session_id: "s1",
    cwd: sessionCwd,
    hook_event_name: "SessionStart",
    source: "startup",
  });
  assert.equal(parseHookStdin(stdin).cwd, sessionCwd);

  const first = runPackagedSessionStart({
    env,
    stdinText: stdin,
    cwd: sessionCwd,
    systemCaps: caps,
  });
  assert.equal(first.exitCode, 0);
  assert.ok(first.result);
  assert.equal(first.result!.silent, false);
  assert.ok(first.stdout.length > 0);
  assert.ok(first.stdout.includes("additionalContext"));
  assert.equal(first.stdout.includes(sessionCwd), false);
  assert.equal(first.stdout.includes(pathDir), false);

  const stateFile = path.join(
    pluginData,
    "version-state",
    "version-fingerprint.json",
  );
  assert.ok(fs.existsSync(stateFile));
  assert.equal(fs.existsSync(path.join(sessionCwd, "state")), false);

  const second = runPackagedSessionStart({
    env,
    stdinText: stdin,
    cwd: sessionCwd,
    systemCaps: caps,
  });
  assert.equal(second.exitCode, 0);
  assert.equal(second.stdout, "");
  assert.ok(second.result?.silent);
});

test("hooks.json manifest: PLUGIN_ROOT POSIX + commandWindows contract", () => {
  const hooksPath = path.join(repoRoot, "hooks", "hooks.json");
  const raw = fs.readFileSync(hooksPath, "utf8");
  const manifest = JSON.parse(raw) as {
    hooks: {
      SessionStart: Array<{
        hooks: Array<{
          type: string;
          command: string;
          commandWindows?: string;
          timeout?: number;
        }>;
      }>;
    };
  };
  const handlers = manifest.hooks.SessionStart.flatMap((g) => g.hooks);
  assert.ok(handlers.length >= 1);
  const h = handlers[0]!;
  assert.equal(h.type, "command");
  assert.ok(h.command.includes("$PLUGIN_ROOT") || h.command.includes("${PLUGIN_ROOT}"));
  assert.ok(h.command.includes("session-start-entry"));
  assert.ok(typeof h.commandWindows === "string");
  assert.ok(h.commandWindows!.includes("%PLUGIN_ROOT%"));
  assert.ok(h.commandWindows!.includes("session-start-entry"));
  assert.equal(h.timeout, 10);
  // Must not use relative ./dist from session cwd.
  assert.equal(h.command.includes("./dist"), false);
});

test("scan-system CLI path exists and rejects missing state", () => {
  const cli = path.join(repoRoot, "bin", "changeguard.js");
  const res = spawnSync(process.execPath, [cli, "scan-system"], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", PLUGIN_DATA: "", CLAUDE_PLUGIN_DATA: "" },
  });
  // Without state dir / PLUGIN_DATA → usage error JSON, non-zero.
  assert.notEqual(res.status, 0);
  const body = JSON.parse(res.stdout);
  assert.equal(body.error_code, "USAGE");
});

test("scan-system CLI with injected state dir returns path-free ScanResult", () => {
  const tmp = makeTempDir("cg-t03-cli-sys-");
  const pathDir = path.join(tmp, "p");
  fs.mkdirSync(pathDir, { recursive: true });
  fs.writeFileSync(path.join(pathDir, "codex"), "x", "utf8");
  writeJson(path.join(pathDir, "version.json"), { version: "3.1.0" });
  const stateDir = path.join(tmp, "state");

  // Use core path for deterministic caps; CLI uses real env PATH.
  // Prove public CLI command wiring separately with empty PATH + PLUGIN_DATA.
  const res = spawnSync(
    process.execPath,
    [
      path.join(repoRoot, "bin", "changeguard.js"),
      "scan-system",
      `--state-dir=${stateDir}`,
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        NO_COLOR: "1",
        PATH: pathDir,
        Path: pathDir,
      },
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  assert.equal(res.status, 0, res.stderr);
  const body = JSON.parse(res.stdout);
  assert.equal(body.ok, true);
  assert.equal(body.mode, "manual_scan");
  assert.equal(JSON.stringify(body).includes(pathDir), false);
  assert.ok(Array.isArray(body.instances));
});

test("boundary self-test mode still passes after state-write scoping", () => {
  const res = spawnSync(
    process.execPath,
    [path.join(repoRoot, "scripts", "check-production-boundary.mjs"), "--self-test"],
    { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } },
  );
  assert.equal(res.status, 0, res.stdout + res.stderr);
  const report = JSON.parse(res.stdout);
  assert.equal(report.ok, true);
});
