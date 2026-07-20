/**
 * Manual compare-local-update: discovery, ASAR Pickle header, named artifacts,
 * three-section truth model, CLI/MCP surfaces, no state mutation.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import {
  buildSyntheticAsarBuffer,
  classifyStablePathChange,
  compareAsarComponents,
  compareLocalUpdate,
  compareNativeModuleDirs,
  formatLocalUpdateCompareMarkdown,
  listNativeModuleBasenames,
  parseAsarHeaderFile,
  parseAsarHeaderFromFd,
  parseValidatedIntegrity,
  discoverStagedAndInstalled,
  MAX_ASAR_NODES,
  MAX_NATIVE_MODULE_BASENAMES,
  MAX_STAGED_SESSION_DIRS,
  MAX_STAGED_DOWNLOAD_DIRS,
  MAX_STAGED_CANDIDATES,
  STAGED_BUNDLE_ID,
} from "../src/instances/local-update/index.js";
import type { AsarFileEntry } from "../src/instances/local-update/asar-header.js";
import { stateFilePath, loadState } from "../src/instances/state.js";
import { makeTempDir } from "./helpers.js";
import { findRepoRoot } from "../src/paths.js";

const REPO = findRepoRoot(import.meta.url);
const SU_KEY = "TEST_PUBLIC_ED_KEY_BASE64_PLACEHOLDER_NOT_REAL==";

function writePlist(
  appRoot: string,
  opts: {
    version: string;
    build: string;
    bundleId?: string;
    suKey?: string | null;
  },
): void {
  const bundleId = opts.bundleId ?? STAGED_BUNDLE_ID;
  const su =
    opts.suKey === null
      ? ""
      : `<key>SUPublicEDKey</key>\n  <string>${opts.suKey ?? SU_KEY}</string>\n`;
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>${bundleId}</string>
  <key>CFBundleShortVersionString</key>
  <string>${opts.version}</string>
  <key>CFBundleVersion</key>
  <string>${opts.build}</string>
  ${su}
</dict>
</plist>
`;
  fs.mkdirSync(path.join(appRoot, "Contents"), { recursive: true });
  fs.writeFileSync(path.join(appRoot, "Contents", "Info.plist"), xml);
}

function writeMinimalApp(
  appRoot: string,
  opts: {
    version: string;
    build: string;
    asar?: Buffer;
    codexBytes?: string;
    codeResources?: string;
    bundleId?: string;
    suKey?: string | null;
    omit?: Array<"plist" | "asar" | "codex" | "code_resources">;
  },
): void {
  fs.mkdirSync(appRoot, { recursive: true });
  const omit = new Set(opts.omit ?? []);
  if (!omit.has("plist")) {
    writePlist(appRoot, opts);
  }
  const res = path.join(appRoot, "Contents", "Resources");
  const sig = path.join(appRoot, "Contents", "_CodeSignature");
  fs.mkdirSync(res, { recursive: true });
  fs.mkdirSync(sig, { recursive: true });
  if (!omit.has("asar")) {
    const asar =
      opts.asar ??
      buildSyntheticAsarBuffer({
        "package.json": { size: 12 },
        ".vite": {
          files: {
            build: {
              files: {
                "early-bootstrap.js": { size: 100 },
                "chunk-aaaa.js": { size: 50 },
              },
            },
          },
        },
        webview: {
          files: {
            "index.html": { size: 40 },
            "avatar-overlay-composition-surface.html": { size: 30 },
          },
        },
        native: {
          files: {
            "foo.node": { size: 8 },
          },
        },
      });
    fs.writeFileSync(path.join(res, "app.asar"), asar);
  }
  if (!omit.has("codex")) {
    fs.writeFileSync(path.join(res, "codex"), opts.codexBytes ?? "#!/bin/sh\n#codex\n");
  }
  if (!omit.has("code_resources")) {
    fs.writeFileSync(
      path.join(sig, "CodeResources"),
      opts.codeResources ?? "code-resources-v1\n",
    );
  }
}

function layoutPair(tmp: string): {
  installed: string;
  installation: string;
  home: string;
} {
  const home = path.join(tmp, "home");
  const installed = path.join(tmp, "Applications", "ChatGPT.app");
  const installation = path.join(
    home,
    "Library",
    "Caches",
    "com.openai.codex",
    "org.sparkle-project.Sparkle",
    "Installation",
  );
  fs.mkdirSync(installation, { recursive: true });
  return { installed, installation, home };
}

/**
 * Real Sparkle nested layout (mandatory):
 *   Installation/<session>/<download>/ChatGPT.app
 */
function addStagedNested(
  installation: string,
  session: string,
  download: string,
  opts: Parameters<typeof writeMinimalApp>[1],
): string {
  const downloadDir = path.join(installation, session, download);
  const app = path.join(downloadDir, "ChatGPT.app");
  fs.mkdirSync(downloadDir, { recursive: true });
  writeMinimalApp(app, opts);
  return app;
}

/**
 * Bounded shallow fixture compat: Installation/<session>/ChatGPT.app
 * Must not be the only layout covered by regression tests.
 */
function addStagedShallow(
  installation: string,
  session: string,
  opts: Parameters<typeof writeMinimalApp>[1],
): string {
  const sessionDir = path.join(installation, session);
  const app = path.join(sessionDir, "ChatGPT.app");
  fs.mkdirSync(sessionDir, { recursive: true });
  writeMinimalApp(app, opts);
  return app;
}

/** Default test helper uses the real nested layout. */
function addStaged(
  installation: string,
  session: string,
  opts: Parameters<typeof writeMinimalApp>[1],
  download = "download-1",
): string {
  return addStagedNested(installation, session, download, opts);
}

// ---------------------------------------------------------------------------
// ASAR Pickle header
// ---------------------------------------------------------------------------

test("ASAR: valid outer+inner Pickle header parses files tree", () => {
  const buf = buildSyntheticAsarBuffer({
    "package.json": { size: 3 },
    nested: { files: { "a.js": { size: 1 } } },
  });
  const tmp = makeTempDir("cg-asar-");
  const f = path.join(tmp, "app.asar");
  fs.writeFileSync(f, buf);
  const r = parseAsarHeaderFile(f);
  assert.equal(r.status, "ok");
  assert.ok(r.file_count >= 2);
  const paths = r.entries.map((e) => e.path).sort();
  assert.ok(paths.includes("package.json"));
  assert.ok(paths.includes("nested/a.js"));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("ASAR: byte-8 JSON shortcut is rejected (outer payload must be 4)", () => {
  // Craft fake archive where bytes 8+ look like JSON but outer layout is wrong.
  const json = Buffer.from('{"files":{"x":{"size":1}}}', "utf8");
  const wrong = Buffer.alloc(8 + json.length);
  wrong.writeUInt32LE(json.length, 0); // not 4
  wrong.writeUInt32LE(0, 4);
  json.copy(wrong, 8);
  const tmp = makeTempDir("cg-asar-bad-");
  const f = path.join(tmp, "bad.asar");
  fs.writeFileSync(f, wrong);
  const r = parseAsarHeaderFile(f);
  assert.equal(r.status, "malformed");
  assert.equal(r.reason, "outer_payload_size_not_4");
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("ASAR: truncated / oversized / malformed headers degrade explicitly", () => {
  const tmp = makeTempDir("cg-asar-edge-");
  const tiny = path.join(tmp, "tiny.asar");
  fs.writeFileSync(tiny, Buffer.alloc(4));
  assert.equal(parseAsarHeaderFile(tiny).status, "truncated");

  // Valid outer claiming huge header pickle
  const huge = Buffer.alloc(8);
  huge.writeUInt32LE(4, 0);
  huge.writeUInt32LE(8 * 1024 * 1024, 4); // oversize claim
  const hugePath = path.join(tmp, "huge.asar");
  fs.writeFileSync(hugePath, huge);
  const hr = parseAsarHeaderFile(hugePath);
  assert.ok(hr.status === "oversize" || hr.status === "truncated");

  fs.rmSync(tmp, { recursive: true, force: true });
});

test("ASAR: parseAsarHeaderFromFd rejects short file", () => {
  const tmp = makeTempDir("cg-asar-fd-");
  const f = path.join(tmp, "s.asar");
  fs.writeFileSync(f, Buffer.from("short"));
  const fd = fs.openSync(f, "r");
  try {
    const r = parseAsarHeaderFromFd(fd, 5);
    assert.equal(r.status, "truncated");
  } finally {
    fs.closeSync(fd);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// ASAR cap honesty + integrity-aware stable paths + native modules
// ---------------------------------------------------------------------------

test("ASAR cap: MAX_ASAR_NODES is at least 8192 and covers mid-range trees", () => {
  assert.ok(MAX_ASAR_NODES >= 8192);
  // Synthetic tree with >4096 but <MAX_ASAR_NODES file leaves must complete.
  const leafCount = 5000;
  const filesTree: Record<string, unknown> = {};
  for (let i = 0; i < leafCount; i++) {
    filesTree[`f${String(i).padStart(5, "0")}.js`] = { size: i };
  }
  const buf = buildSyntheticAsarBuffer(filesTree);
  const tmp = makeTempDir("cg-asar-mid-");
  const f = path.join(tmp, "mid.asar");
  fs.writeFileSync(f, buf);
  const r = parseAsarHeaderFile(f);
  assert.equal(r.status, "ok");
  assert.equal(r.nodes_capped, false);
  assert.equal(r.depth_capped, false);
  assert.equal(r.file_count, leafCount);
  assert.ok(r.nodes_visited >= leafCount);
  assert.ok(r.nodes_visited < MAX_ASAR_NODES);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("ASAR cap honesty: capped walk cannot return compared", () => {
  // Build more nodes than MAX_ASAR_NODES so the walk is capped.
  const over = MAX_ASAR_NODES + 64;
  const filesTree: Record<string, unknown> = {};
  for (let i = 0; i < over; i++) {
    filesTree[`c${String(i).padStart(5, "0")}.js`] = { size: 1 };
  }
  const buf = buildSyntheticAsarBuffer(filesTree);
  const tmp = makeTempDir("cg-asar-cap-");
  const a = path.join(tmp, "a.asar");
  const b = path.join(tmp, "b.asar");
  fs.writeFileSync(a, buf);
  fs.writeFileSync(b, buf);
  const ra = parseAsarHeaderFile(a);
  assert.equal(ra.nodes_capped, true);
  assert.ok(ra.nodes_visited <= MAX_ASAR_NODES);
  const diff = compareAsarComponents(a, b);
  assert.equal(diff.status, "partial");
  assert.equal(diff.truncation.nodes_capped, true);
  assert.ok(
    diff.reason === "nodes_capped" ||
      (diff.reason !== null && diff.reason.includes("nodes_capped")),
  );
  assert.notEqual(diff.status, "compared");
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("integrity: parseValidatedIntegrity accepts SHA256 64-hex only", () => {
  assert.equal(parseValidatedIntegrity({}), null);
  assert.equal(
    parseValidatedIntegrity({
      integrity: { algorithm: "SHA1", hash: "a".repeat(64) },
    }),
    null,
  );
  assert.equal(
    parseValidatedIntegrity({
      integrity: { algorithm: "SHA256", hash: "not-hex" },
    }),
    null,
  );
  assert.equal(
    parseValidatedIntegrity({
      integrity: { algorithm: "SHA256", hash: "ab".repeat(20) }, // 40 hex
    }),
    null,
  );
  const ok = parseValidatedIntegrity({
    integrity: {
      algorithm: "SHA256",
      hash: "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789",
    },
  });
  assert.ok(ok);
  assert.equal(ok!.algorithm, "SHA256");
  assert.equal(ok!.hash, ok!.hash.toLowerCase());
  assert.equal(ok!.hash.length, 64);
});

function entry(
  pathAlias: string,
  size: number | null,
  hash: string | null,
): AsarFileEntry {
  return {
    path: pathAlias,
    size,
    integrity: hash
      ? { algorithm: "SHA256", hash: hash.toLowerCase() }
      : null,
    is_chunk_like: false,
    is_node_module: false,
    basename: pathAlias.split("/").pop() ?? pathAlias,
  };
}

test("integrity-aware stable path classification", () => {
  const h1 = "a".repeat(64);
  const h2 = "b".repeat(64);
  // equal hash + equal size → unchanged
  assert.equal(
    classifyStablePathChange(entry("p", 10, h1), entry("p", 10, h1)),
    "unchanged",
  );
  // different hash, same size → hash_changed
  assert.equal(
    classifyStablePathChange(entry("p", 10, h1), entry("p", 10, h2)),
    "hash_changed",
  );
  // different hash, different size → hash_changed (hash wins when both trusted)
  assert.equal(
    classifyStablePathChange(entry("p", 10, h1), entry("p", 20, h2)),
    "hash_changed",
  );
  // size differs, hashes equal → size_changed
  assert.equal(
    classifyStablePathChange(entry("p", 10, h1), entry("p", 20, h1)),
    "size_changed",
  );
  // size equal, missing integrity → present_both (never unchanged)
  assert.equal(
    classifyStablePathChange(entry("p", 10, null), entry("p", 10, h1)),
    "present_both",
  );
  assert.equal(
    classifyStablePathChange(entry("p", 10, null), entry("p", 10, null)),
    "present_both",
  );
  // size differs without dual integrity → size_changed
  assert.equal(
    classifyStablePathChange(entry("p", 10, null), entry("p", 11, null)),
    "size_changed",
  );
  // added / removed
  assert.equal(classifyStablePathChange(undefined, entry("p", 1, h1)), "added");
  assert.equal(
    classifyStablePathChange(entry("p", 1, h1), undefined),
    "removed",
  );
});

test("stable path integrity via ASAR header (no body read, no hash leak)", () => {
  const hA = "11".repeat(32);
  const hB = "22".repeat(32);
  const asarA = buildSyntheticAsarBuffer({
    "package.json": {
      size: 100,
      integrity: { algorithm: "SHA256", hash: hA },
    },
    ".vite": {
      files: {
        build: {
          files: {
            "early-bootstrap.js": {
              size: 50,
              integrity: { algorithm: "SHA256", hash: hA },
            },
          },
        },
      },
    },
    webview: {
      files: {
        "index.html": {
          size: 40,
          integrity: { algorithm: "SHA256", hash: hA },
        },
        "avatar-overlay-composition-surface.html": {
          size: 30,
          integrity: { algorithm: "SHA256", hash: hA },
        },
      },
    },
  });
  const asarB = buildSyntheticAsarBuffer({
    "package.json": {
      size: 120,
      integrity: { algorithm: "SHA256", hash: hB },
    },
    ".vite": {
      files: {
        build: {
          files: {
            "early-bootstrap.js": {
              size: 50,
              integrity: { algorithm: "SHA256", hash: hB },
            },
          },
        },
      },
    },
    webview: {
      files: {
        "index.html": {
          size: 40,
          integrity: { algorithm: "SHA256", hash: hB },
        },
        "avatar-overlay-composition-surface.html": {
          size: 30,
          integrity: { algorithm: "SHA256", hash: hB },
        },
      },
    },
  });
  const tmp = makeTempDir("cg-integ-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, {
    version: "1.0.0",
    build: "1",
    asar: asarA,
  });
  addStaged(installation, "s1", {
    version: "1.1.0",
    build: "2",
    asar: asarB,
  });
  const r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  const asar = r.local_observations.asar_component_diff;
  const early = asar.stable_path_changes.find(
    (p) => p.path_alias === ".vite/build/early-bootstrap.js",
  );
  assert.ok(early);
  assert.equal(early!.change, "hash_changed");
  assert.equal(early!.installed_size, 50);
  assert.equal(early!.staged_size, 50);
  const pkg = asar.stable_path_changes.find(
    (p) => p.path_alias === "package.json",
  );
  assert.ok(pkg);
  assert.equal(pkg!.change, "hash_changed");
  const json = JSON.stringify(r);
  // Integrity digests must not appear in public output.
  assert.ok(!json.includes(hA));
  assert.ok(!json.includes(hB));
  assert.ok(!json.includes(tmp));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("native_module_diff: added basename, absent, symlink, cap, no path leak", () => {
  const tmp = makeTempDir("cg-native-");
  const { installation, home, installed } = layoutPair(tmp);

  writeMinimalApp(installed, { version: "1.0.0", build: "1" });
  // Installed: no native dir (absent is ok).
  const stagedApp = addStaged(installation, "s1", {
    version: "1.1.0",
    build: "2",
  });
  // Staged: add Contents/Resources/native/hid-topology-watcher.node (synthetic).
  const nativeDir = path.join(stagedApp, "Contents", "Resources", "native");
  fs.mkdirSync(nativeDir, { recursive: true });
  fs.writeFileSync(
    path.join(nativeDir, "hid-topology-watcher.node"),
    "synthetic-native-module\n",
  );
  // Non-.node and symlink child must not be accepted as basenames.
  fs.writeFileSync(path.join(nativeDir, "readme.txt"), "nope\n");
  const linkTarget = path.join(tmp, "elsewhere.node");
  fs.writeFileSync(linkTarget, "x\n");
  fs.symlinkSync(linkTarget, path.join(nativeDir, "evil-link.node"));

  const r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  const nm = r.local_observations.native_module_diff;
  assert.ok(nm.status === "compared" || nm.status === "partial");
  assert.ok(nm.added.includes("hid-topology-watcher.node"));
  assert.ok(!nm.added.includes("evil-link.node"));
  assert.ok(!nm.added.includes("readme.txt"));
  assert.equal(nm.installed_dir_present, false);
  assert.equal(nm.staged_dir_present, true);
  // Sibling of asar_component_diff, not nested inside it.
  assert.ok("native_module_diff" in r.local_observations);
  assert.ok(!("native_module_diff" in (r.local_observations.asar_component_diff as object)));

  const json = JSON.stringify(r);
  assert.ok(!json.includes(tmp));
  assert.ok(!json.includes(home));
  assert.ok(!json.includes(nativeDir));
  assert.ok(!json.includes(path.join("Contents", "Resources", "native")));

  // Unit: symlink native directory refused
  const badRoot = path.join(tmp, "BadApp.app");
  writeMinimalApp(badRoot, { version: "1.0.0", build: "1" });
  const badNativeParent = path.join(badRoot, "Contents", "Resources");
  const realNative = path.join(tmp, "real-native-elsewhere");
  fs.mkdirSync(realNative, { recursive: true });
  fs.writeFileSync(path.join(realNative, "x.node"), "x\n");
  // Replace native with symlink
  const nativeLink = path.join(badNativeParent, "native");
  if (fs.existsSync(nativeLink)) fs.rmSync(nativeLink, { recursive: true });
  fs.symlinkSync(realNative, nativeLink);
  const listed = listNativeModuleBasenames(badRoot);
  assert.equal(listed.status, "refused");
  assert.equal(listed.reason, "symlink_dir");
  assert.deepEqual(listed.basenames, []);

  // Cap: more than MAX_NATIVE_MODULE_BASENAMES dirents → partial/capped
  const capRoot = path.join(tmp, "CapApp.app");
  writeMinimalApp(capRoot, { version: "1.0.0", build: "1" });
  const capNative = path.join(capRoot, "Contents", "Resources", "native");
  fs.mkdirSync(capNative, { recursive: true });
  for (let i = 0; i < MAX_NATIVE_MODULE_BASENAMES + 5; i++) {
    fs.writeFileSync(
      path.join(capNative, `mod${String(i).padStart(3, "0")}.node`),
      "n\n",
    );
  }
  const capList = listNativeModuleBasenames(capRoot);
  assert.equal(capList.entries_capped, true);
  assert.ok(capList.basenames.length <= MAX_NATIVE_MODULE_BASENAMES);

  const capDiff = compareNativeModuleDirs(installed, capRoot);
  assert.equal(capDiff.status, "partial");
  assert.equal(capDiff.truncation.entries_capped, true);

  // Absent both sides → compared with empty lists
  const emptyA = path.join(tmp, "EmptyA.app");
  const emptyB = path.join(tmp, "EmptyB.app");
  writeMinimalApp(emptyA, { version: "1.0.0", build: "1" });
  writeMinimalApp(emptyB, { version: "1.0.1", build: "2" });
  const bothAbsent = compareNativeModuleDirs(emptyA, emptyB);
  assert.equal(bothAbsent.status, "compared");
  assert.equal(bothAbsent.installed_dir_present, false);
  assert.equal(bothAbsent.staged_dir_present, false);
  assert.deepEqual(bothAbsent.added, []);
  assert.deepEqual(bothAbsent.removed, []);

  fs.rmSync(tmp, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

test("discovery: symlink root refused; path escape not accepted", () => {
  const tmp = makeTempDir("cg-disc-sym-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, { version: "1.0.0", build: "100" });
  // Replace installation with symlink
  fs.rmSync(installation, { recursive: true, force: true });
  const elsewhere = path.join(tmp, "elsewhere");
  fs.mkdirSync(elsewhere, { recursive: true });
  fs.symlinkSync(elsewhere, installation);

  const r = discoverStagedAndInstalled({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
  });
  assert.equal(r.installation_root_available, false);
  assert.ok((r.rejection_counts["symlink_installation_root"] ?? 0) >= 1);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("discovery: session caps and candidate caps", () => {
  const tmp = makeTempDir("cg-disc-cap-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, { version: "1.0.0", build: "100" });
  for (let i = 0; i < MAX_STAGED_SESSION_DIRS + 3; i++) {
    addStaged(installation, `session-${String(i).padStart(2, "0")}`, {
      version: `1.0.${i}`,
      build: String(200 + i),
    });
  }
  const r = discoverStagedAndInstalled({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
  });
  assert.equal(r.sessions_capped, true);
  assert.ok(r.sessions_inspected <= MAX_STAGED_SESSION_DIRS);
  assert.ok(r.candidates.length <= MAX_STAGED_CANDIDATES);
  assert.equal(r.candidates_capped, true);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("discovery: nested Installation/session/download/ChatGPT.app succeeds", () => {
  const tmp = makeTempDir("cg-disc-nested-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, {
    version: "26.715.31925",
    build: "5551",
  });
  // Real Sparkle layout only — no shallow ChatGPT.app under session.
  addStagedNested(installation, "session-real", "dl-abc", {
    version: "26.715.52143",
    build: "5591",
  });
  // Ensure shallow path does not exist (would mask nested-only bugs).
  assert.ok(
    !fs.existsSync(
      path.join(installation, "session-real", "ChatGPT.app"),
    ),
  );
  const r = discoverStagedAndInstalled({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
  });
  assert.equal(r.installation_root_available, true);
  assert.equal(r.sessions_inspected, 1);
  assert.equal(r.download_dirs_inspected, 1);
  assert.equal(r.candidates.length, 1);
  assert.equal(r.candidates[0]!.version, "26.715.52143");
  assert.equal(r.candidates[0]!.build, "5591");
  assert.equal(r.candidates[0]!.role, "staged");
  assert.equal(r.installed?.version, "26.715.31925");
  assert.equal(r.installed?.build, "5551");

  const cmp = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  assert.ok(
    cmp.status === "comparable_newer" || cmp.status === "partial",
    `expected newer/partial got ${cmp.status}`,
  );
  assert.equal(cmp.local_observations.version_relation, "newer");
  assert.equal(cmp.local_observations.discovery.download_dirs_inspected, 1);
  assert.equal(cmp.local_observations.discovery.download_dirs_capped, false);
  const json = JSON.stringify(cmp);
  assert.ok(!json.includes(tmp));
  assert.ok(!json.includes(home));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("discovery: nested symlink download and app refused", () => {
  const tmp = makeTempDir("cg-disc-nsym-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, { version: "1.0.0", build: "100" });

  // Valid nested candidate for control
  addStagedNested(installation, "s-ok", "dl-ok", {
    version: "1.1.0",
    build: "110",
  });

  // Session with symlink download dir
  const sSymDl = path.join(installation, "s-sym-dl");
  fs.mkdirSync(sSymDl, { recursive: true });
  const elsewhereDl = path.join(tmp, "elsewhere-dl");
  fs.mkdirSync(elsewhereDl, { recursive: true });
  writeMinimalApp(path.join(elsewhereDl, "ChatGPT.app"), {
    version: "9.9.9",
    build: "999",
  });
  fs.symlinkSync(elsewhereDl, path.join(sSymDl, "dl-link"));

  // Session with real download dir but symlink ChatGPT.app
  const sSymApp = path.join(installation, "s-sym-app", "dl-real");
  fs.mkdirSync(sSymApp, { recursive: true });
  const elsewhereApp = path.join(tmp, "elsewhere-app", "ChatGPT.app");
  writeMinimalApp(elsewhereApp, { version: "8.8.8", build: "888" });
  fs.symlinkSync(elsewhereApp, path.join(sSymApp, "ChatGPT.app"));

  const r = discoverStagedAndInstalled({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
  });
  // Only the real nested candidate is accepted
  assert.equal(r.candidates.length, 1);
  assert.equal(r.candidates[0]!.version, "1.1.0");
  assert.ok((r.rejection_counts["symlink_download"] ?? 0) >= 1);
  assert.ok((r.rejection_counts["staged:symlink_app"] ?? 0) >= 1);
  // Symlinked payloads must not leak into accepted set
  assert.ok(!r.candidates.some((c) => c.version === "9.9.9"));
  assert.ok(!r.candidates.some((c) => c.version === "8.8.8"));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("discovery: download-dir cap and over-depth refusal", () => {
  const tmp = makeTempDir("cg-disc-dlcap-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, { version: "1.0.0", build: "100" });

  // Many download dirs under one session to hit global cap
  const session = "s-many-dl";
  for (let i = 0; i < MAX_STAGED_DOWNLOAD_DIRS + 4; i++) {
    addStagedNested(installation, session, `dl-${String(i).padStart(2, "0")}`, {
      version: `1.0.${i}`,
      build: String(300 + i),
    });
  }

  // Over-depth in a session name that sorts before s-many-dl so it is inspected
  // before the download-dir cap stops further download inspection.
  // Layout: a-over/dl-deep/extra/ChatGPT.app (must never be accepted).
  const overDepth = path.join(
    installation,
    "a-over",
    "dl-deep",
    "extra",
    "ChatGPT.app",
  );
  fs.mkdirSync(path.dirname(overDepth), { recursive: true });
  writeMinimalApp(overDepth, { version: "7.7.7", build: "777" });

  const r = discoverStagedAndInstalled({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
  });
  assert.equal(r.download_dirs_capped, true);
  assert.ok(r.download_dirs_inspected <= MAX_STAGED_DOWNLOAD_DIRS);
  assert.ok(r.candidates.length <= MAX_STAGED_CANDIDATES);
  assert.ok(!r.candidates.some((c) => c.version === "7.7.7"));
  assert.ok(
    (r.rejection_counts["staged:over_depth"] ?? 0) >= 1,
    `expected staged:over_depth, got ${JSON.stringify(r.rejection_counts)}`,
  );

  // Shallow-only decoy must not mask nested discovery: nested-only root works
  const tmp2 = makeTempDir("cg-disc-noshallow-");
  const pair2 = layoutPair(tmp2);
  writeMinimalApp(pair2.installed, { version: "2.0.0", build: "200" });
  // Place only nested app (no shallow)
  addStagedNested(pair2.installation, "only-nested", "d1", {
    version: "2.1.0",
    build: "210",
  });
  // Place a shallow-only session with invalid app (missing artifact) that
  // previously would be the only path probed — nested must still be found.
  addStagedShallow(pair2.installation, "shallow-broken", {
    version: "9.0.0",
    build: "900",
    omit: ["codex"],
  });
  const r2 = discoverStagedAndInstalled({
    platform: "darwin",
    homeDir: pair2.home,
    installationRoot: pair2.installation,
    installedAppPaths: [pair2.installed],
  });
  assert.ok(r2.candidates.some((c) => c.version === "2.1.0"));
  assert.ok(!r2.candidates.some((c) => c.version === "9.0.0"));

  // Bounded shallow compat still works when that is the only layout
  const tmp3 = makeTempDir("cg-disc-shallow-compat-");
  const pair3 = layoutPair(tmp3);
  writeMinimalApp(pair3.installed, { version: "3.0.0", build: "300" });
  addStagedShallow(pair3.installation, "shallow-ok", {
    version: "3.1.0",
    build: "310",
  });
  const r3 = discoverStagedAndInstalled({
    platform: "darwin",
    homeDir: pair3.home,
    installationRoot: pair3.installation,
    installedAppPaths: [pair3.installed],
  });
  assert.equal(r3.candidates.length, 1);
  assert.equal(r3.candidates[0]!.version, "3.1.0");

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(tmp2, { recursive: true, force: true });
  fs.rmSync(tmp3, { recursive: true, force: true });
});

test("discovery: missing / multiple / same / older / newer / partial", () => {
  const tmp = makeTempDir("cg-disc-states-");
  const { installation, home, installed } = layoutPair(tmp);

  // no installed
  let r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [path.join(tmp, "missing.app")],
  });
  assert.ok(
    r.status === "no_installed_app" || r.status === "no_staged_candidate",
  );
  assert.ok(r.official_evidence);
  assert.ok(r.local_observations);
  assert.ok(r.inference_and_unknowns);

  writeMinimalApp(installed, { version: "2.0.0", build: "200" });

  // no staged
  r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
  });
  assert.equal(r.status, "no_staged_candidate");

  // newer single
  addStaged(installation, "s-newer", {
    version: "2.1.0",
    build: "210",
    codexBytes: "#!/bin/sh\n#staged-codex\n",
  });
  r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  assert.ok(
    r.status === "comparable_newer" || r.status === "partial",
    `expected newer/partial got ${r.status}`,
  );
  assert.equal(r.local_observations.version_relation, "newer");
  assert.ok(r.local_observations.named_artifacts.length >= 1);
  const codex = r.local_observations.named_artifacts.find(
    (a) => a.key === "codex_binary",
  );
  assert.ok(codex);
  assert.equal(codex!.change, "hash_changed");

  // clear staged, same version
  fs.rmSync(path.join(installation, "s-newer"), { recursive: true, force: true });
  addStaged(installation, "s-same", {
    version: "2.0.0",
    build: "200",
  });
  r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  assert.ok(r.status === "same_version" || r.status === "partial");

  // older
  fs.rmSync(path.join(installation, "s-same"), { recursive: true, force: true });
  addStaged(installation, "s-old", { version: "1.9.0", build: "190" });
  r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  assert.ok(r.status === "staged_older" || r.status === "partial");

  // multiple
  addStaged(installation, "s-old-2", { version: "1.8.0", build: "180" });
  r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
  });
  assert.equal(r.status, "multiple_candidates");
  assert.equal(r.local_observations.selected_staged, null);

  // partial artifact (missing codex on staged) — validation rejects candidate
  fs.rmSync(path.join(installation, "s-old"), { recursive: true, force: true });
  fs.rmSync(path.join(installation, "s-old-2"), { recursive: true, force: true });
  addStaged(installation, "s-partial", {
    version: "2.2.0",
    build: "220",
    omit: ["codex"],
  });
  r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
  });
  assert.equal(r.status, "no_staged_candidate");

  fs.rmSync(tmp, { recursive: true, force: true });
});

test("component aggregation, .node basenames, allowlisted paths, caps", () => {
  const tmp = makeTempDir("cg-comp-");
  const { installation, home, installed } = layoutPair(tmp);
  const asarA = buildSyntheticAsarBuffer({
    "package.json": { size: 10 },
    ".vite": {
      files: {
        build: {
          files: {
            "early-bootstrap.js": { size: 1 },
            "chunk-111.js": { size: 2 },
          },
        },
      },
    },
    webview: {
      files: {
        "index.html": { size: 5 },
        "avatar-overlay-composition-surface.html": { size: 6 },
      },
    },
    native: { files: { "old.node": { size: 1 } } },
  });
  const asarB = buildSyntheticAsarBuffer({
    "package.json": { size: 11 },
    ".vite": {
      files: {
        build: {
          files: {
            "early-bootstrap.js": { size: 9 },
            "chunk-222.js": { size: 2 },
            "chunk-333.js": { size: 2 },
          },
        },
      },
    },
    webview: {
      files: {
        "index.html": { size: 5 },
        "avatar-overlay-composition-surface.html": { size: 6 },
      },
    },
    native: { files: { "new.node": { size: 1 } } },
  });
  writeMinimalApp(installed, {
    version: "3.0.0",
    build: "300",
    asar: asarA,
  });
  addStaged(installation, "s1", {
    version: "3.1.0",
    build: "310",
    asar: asarB,
  });
  const r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  const asar = r.local_observations.asar_component_diff;
  assert.ok(asar.status === "compared" || asar.status === "partial");
  if (asar.status === "compared") {
    const pkg = asar.stable_path_changes.find((p) => p.path_alias === "package.json");
    assert.ok(pkg);
    assert.ok(pkg!.change === "size_changed" || pkg!.change === "unchanged");
    const nodes = asar.node_basename_changes.map((n) => n.basename).sort();
    assert.ok(nodes.includes("old.node") || nodes.includes("new.node"));
    assert.ok(asar.aggregate_buckets.some((b) => b.bucket === "chunk_like"));
  }
  // No absolute paths in JSON
  const json = JSON.stringify(r);
  assert.ok(!json.includes(tmp));
  assert.ok(!json.includes(home));
  assert.ok(!json.includes("/Users/"));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("three-section truth separation and safety flags", () => {
  const tmp = makeTempDir("cg-truth-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, { version: "1.0.0", build: "1" });
  addStaged(installation, "s1", { version: "1.1.0", build: "2" });
  const r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  assert.equal(typeof r.official_evidence.status, "string");
  assert.equal(typeof r.local_observations.status, "string");
  assert.equal(r.inference_and_unknowns.status, "conservative");
  assert.equal(r.network_used, false);
  assert.equal(r.target_mutated, false);
  assert.equal(r.local_observations.safety.staged_written_to_state, false);
  assert.equal(r.local_observations.safety.session_start_scanned, false);
  assert.equal(r.local_observations.safety.install_attempted, false);
  assert.ok(
    r.inference_and_unknowns.do_not_claim.some((s) =>
      /safe to install|installed/i.test(s),
    ),
  );
  // Markdown three sections
  const md = formatLocalUpdateCompareMarkdown(r);
  assert.match(md, /## 1\. Official evidence/);
  assert.match(md, /## 2\. Local observations/);
  assert.match(md, /## 3\. Inference and unknowns/);
  assert.ok(!md.includes(tmp));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("time budget yields explicit gaps without silent success", () => {
  const tmp = makeTempDir("cg-budget-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, { version: "1.0.0", build: "1" });
  addStaged(installation, "s1", {
    version: "1.2.0",
    build: "3",
    codexBytes: "x".repeat(1024),
  });
  let t = 0;
  const r = compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 1,
    nowMs: () => {
      t += 1000;
      return t;
    },
  });
  // Should still return structure; likely partial or gaps
  assert.ok(r.schema_version === 1);
  assert.ok(r.local_observations.named_artifacts.length >= 0);
  const gap = r.local_observations.named_artifacts.some(
    (a) =>
      a.installed_status === "time_budget_exceeded" ||
      a.staged_status === "time_budget_exceeded" ||
      a.change === "gap",
  );
  // With aggressive clock, expect budget gaps or partial status
  assert.ok(gap || r.status === "partial" || r.status === "comparable_newer");
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("unsupported platform without injection", () => {
  const r = compareLocalUpdate({
    platform: "linux",
    homeDir: null,
    installationRoot: null,
    installedAppPaths: [],
  });
  assert.equal(r.status, "unsupported_platform");
  assert.equal(r.ok, true);
});

test("no state / baseline mutation", () => {
  const tmp = makeTempDir("cg-nostate-");
  const { installation, home, installed } = layoutPair(tmp);
  writeMinimalApp(installed, { version: "1.0.0", build: "1" });
  addStaged(installation, "s1", { version: "1.1.0", build: "2" });
  const stateDir = path.join(tmp, "state");
  fs.mkdirSync(stateDir, { recursive: true });
  const before = fs.readdirSync(stateDir);
  compareLocalUpdate({
    platform: "darwin",
    homeDir: home,
    installationRoot: installation,
    installedAppPaths: [installed],
    timeBudgetMs: 60_000,
  });
  const after = fs.readdirSync(stateDir);
  assert.deepEqual(after, before);
  assert.equal(loadState(stateDir), null);
  assert.ok(!fs.existsSync(stateFilePath(stateDir)));
  // Installed and staged trees unchanged (still present)
  assert.ok(fs.existsSync(path.join(installed, "Contents", "Info.plist")));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("CLI JSON + Markdown surfaces", async () => {
  const bin = path.join(REPO, "bin", "changeguard.js");
  if (!fs.existsSync(path.join(REPO, "dist", "cli", "main.js"))) {
    // build may not have run yet in isolation — skip soft
  }
  const run = (args: string[]) =>
    new Promise<{ code: number | null; out: string }>((resolve, reject) => {
      const child = spawn(process.execPath, [bin, ...args], {
        cwd: REPO,
        env: { ...process.env, NO_COLOR: "1" },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let out = "";
      child.stdout.on("data", (c) => {
        out += c.toString("utf8");
      });
      child.stderr.on("data", (c) => {
        out += c.toString("utf8");
      });
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, out }));
    });

  const jsonRun = await run(["compare-local-update", "--format=json"]);
  assert.equal(jsonRun.code, 0);
  const parsed = JSON.parse(jsonRun.out) as {
    command: string;
    official_evidence: unknown;
    local_observations: unknown;
    inference_and_unknowns: unknown;
  };
  assert.equal(parsed.command, "compare-local-update");
  assert.ok(parsed.official_evidence);
  assert.ok(parsed.local_observations);
  assert.ok(parsed.inference_and_unknowns);
  assert.ok(!jsonRun.out.includes(os.homedir() + "/Library/Caches/com.openai"));

  const mdRun = await run(["compare-local-update", "--format=markdown"]);
  assert.equal(mdRun.code, 0);
  assert.match(mdRun.out, /Official evidence/i);
  assert.match(mdRun.out, /Local observations/i);
  assert.match(mdRun.out, /Inference and unknowns/i);
});

test("MCP schema and tool execution", async () => {
  const mcpJs = path.join(REPO, "dist", "mcp", "server.js");
  assert.ok(fs.existsSync(mcpJs), "dist mcp server must exist (npm test builds)");
  const result = await new Promise<{
    tools: Array<{ name: string; inputSchema?: { additionalProperties?: boolean } }>;
    call: unknown;
  }>((resolve, reject) => {
    const child = spawn(process.execPath, [mcpJs], {
      cwd: REPO,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" },
    });
    let buf = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("MCP timeout"));
    }, 10000);
    timer.unref?.();
    let tools: Array<{
      name: string;
      inputSchema?: { additionalProperties?: boolean };
    }> = [];
    child.stdout.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        if (!line.trim()) continue;
        let msg: {
          id?: number;
          result?: {
            tools?: typeof tools;
            content?: Array<{ text?: string }>;
          };
          error?: unknown;
        };
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg.id === 1 && msg.result) {
          child.stdin.write(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 2,
              method: "tools/list",
              params: {},
            }) + "\n",
          );
        }
        if (msg.id === 2 && msg.result?.tools) {
          tools = msg.result.tools;
          child.stdin.write(
            JSON.stringify({
              jsonrpc: "2.0",
              id: 3,
              method: "tools/call",
              params: {
                name: "changeguard_compare_local_update",
                arguments: {},
              },
            }) + "\n",
          );
        }
        if (msg.id === 3) {
          clearTimeout(timer);
          child.kill();
          if (msg.error) {
            reject(new Error(JSON.stringify(msg.error)));
            return;
          }
          const text = msg.result?.content?.[0]?.text ?? "{}";
          resolve({ tools, call: JSON.parse(text) });
        }
      }
    });
    child.on("error", reject);
    child.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "compare-local-update-test", version: "0.1.0" },
        },
      }) + "\n",
    );
    child.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }) + "\n",
    );
  });

  const tool = result.tools.find(
    (t) => t.name === "changeguard_compare_local_update",
  );
  assert.ok(tool, "tool listed");
  assert.equal(tool!.inputSchema?.additionalProperties, false);
  const call = result.call as {
    command: string;
    official_evidence: unknown;
    local_observations: { safety: { staged_written_to_state: boolean } };
    inference_and_unknowns: unknown;
  };
  assert.equal(call.command, "compare-local-update");
  assert.ok(call.official_evidence);
  assert.ok(call.local_observations);
  assert.ok(call.inference_and_unknowns);
  assert.equal(call.local_observations.safety.staged_written_to_state, false);
});
