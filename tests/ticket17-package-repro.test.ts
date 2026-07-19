/**
 * Ticket 17 — reproducible portable package tarball (packaging defect fix).
 *
 * Root-reproduced: identical package_content_sha256 with three different
 * tarball_sha256 values across consecutive `npm run package` runs. Cause was
 * host `tar -czf` embedding nondeterministic mtime/uid/order metadata.
 *
 * These tests exercise the pure Node 20 archiver in scripts/package-plugin.mjs
 * so two independent generations of the same tree yield identical content and
 * tarball hashes. Would fail if the archive still used wall-clock tar metadata.
 *
 * Scope: identical inputs + fixed Node toolchain; pure Node cross-platform.
 * Not claimed: byte identity across arbitrary Node/zlib versions.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { REPO_ROOT, makeTempDir } from "./helpers.js";

type PackagePluginMod = {
  sha256File: (abs: string) => string;
  sha256Tree: (root: string) => { content_sha256: string; file_count: number };
  collectArchiveEntries: (
    sourceDir: string,
    archiveRootName?: string,
  ) => { type: "dir" | "file"; name: string; mode: number; data?: Buffer }[];
  createReproducibleTar: (sourceDir: string, archiveRootName?: string) => Buffer;
  gzipReproducible: (tarBuf: Buffer) => Buffer;
  writeReproducibleTarGz: (
    sourceDir: string,
    destTgz: string,
    archiveRootName?: string,
  ) => { tarball_sha256: string; byte_length: number };
};

async function loadPackagePlugin(): Promise<PackagePluginMod> {
  const href = pathToFileURL(
    path.join(REPO_ROOT, "scripts", "package-plugin.mjs"),
  ).href;
  return import(href) as Promise<PackagePluginMod>;
}

/** Build a small synthetic package tree with mixed modes and nested paths. */
function seedSyntheticPackage(root: string): void {
  fs.mkdirSync(path.join(root, "bin"), { recursive: true });
  fs.mkdirSync(path.join(root, "docs", "nested"), { recursive: true });
  fs.mkdirSync(path.join(root, "fixtures", "a"), { recursive: true });
  fs.writeFileSync(path.join(root, "README.md"), "# repro package\n", "utf8");
  fs.writeFileSync(
    path.join(root, "package.json"),
    JSON.stringify({ private: true }) + "\n",
    "utf8",
  );
  fs.writeFileSync(
    path.join(root, "bin", "changeguard.js"),
    "#!/usr/bin/env node\nconsole.log('ok');\n",
    { encoding: "utf8", mode: 0o755 },
  );
  fs.writeFileSync(
    path.join(root, "docs", "nested", "note.md"),
    "nested\n",
    "utf8",
  );
  // File with content length not divisible by 512 (padding exercise).
  fs.writeFileSync(path.join(root, "fixtures", "a", "data.bin"), "x".repeat(600));
  // Empty file edge case
  fs.writeFileSync(path.join(root, "fixtures", "empty.txt"), "");
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** UTF-8 byte comparison for archive path order claims. */
function comparePathUtf8(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

test("Ticket17 package repro: pure archiver is byte-identical across two generations", async () => {
  const mod = await loadPackagePlugin();
  const base = makeTempDir("cg-t17-repro-");
  try {
    const pkgA = path.join(base, "pkg-a");
    const pkgB = path.join(base, "pkg-b");
    fs.mkdirSync(pkgA, { recursive: true });
    seedSyntheticPackage(pkgA);
    // Independent copy so filesystem inode/ctime differ between trees.
    fs.cpSync(pkgA, pkgB, { recursive: true });

    const contentA = mod.sha256Tree(pkgA);
    const contentB = mod.sha256Tree(pkgB);
    assert.equal(
      contentA.content_sha256,
      contentB.content_sha256,
      "synthetic package trees must have identical content hashes",
    );
    assert.equal(contentA.file_count, contentB.file_count);

    const tgzA = path.join(base, "a.tgz");
    const tgzB = path.join(base, "b.tgz");
    const metaA = mod.writeReproducibleTarGz(pkgA, tgzA, "codex-changeguard-plugin");
    // Wall-clock gap would change host-tar mtime fields; pure archiver must ignore it.
    await sleepMs(1100);
    const metaB = mod.writeReproducibleTarGz(pkgB, tgzB, "codex-changeguard-plugin");

    assert.equal(
      metaA.tarball_sha256,
      metaB.tarball_sha256,
      "tarball_sha256 must match across independent generations with identical content",
    );
    assert.equal(metaA.byte_length, metaB.byte_length);
    assert.equal(mod.sha256File(tgzA), metaA.tarball_sha256);
    assert.equal(mod.sha256File(tgzB), metaB.tarball_sha256);
    assert.equal(
      fs.readFileSync(tgzA).equals(fs.readFileSync(tgzB)),
      true,
      "tarball bytes must be identical",
    );

    // Gzip header: magic + method + flags + mtime(0) + xfl + os
    const header = fs.readFileSync(tgzA).subarray(0, 10);
    assert.equal(header[0], 0x1f);
    assert.equal(header[1], 0x8b);
    assert.equal(header[2], 0x08);
    // mtime field (bytes 4-7) must be zero for reproducibility
    assert.equal(header.readUInt32LE(4), 0, "gzip mtime must be zero");
    // OS byte at offset 9 must be normalized to 255 (unknown), not host OS (e.g. 19 on darwin)
    assert.equal(header[9], 255, "gzip OS header byte must be 255 (normalized)");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("Ticket17 package repro: file modes are fixed 0644/0755 independent of host st.mode", async () => {
  const mod = await loadPackagePlugin();
  const base = makeTempDir("cg-t17-mode-");
  try {
    const pkg = path.join(base, "pkg");
    fs.mkdirSync(pkg, { recursive: true });
    seedSyntheticPackage(pkg);
    // Host may store bin/changeguard.js as 0755; archive must still use 0644.
    const st = fs.statSync(path.join(pkg, "bin", "changeguard.js"));
    assert.ok(
      (st.mode & 0o111) !== 0 || process.platform === "win32",
      "seed should prefer executable bit on Unix hosts when supported",
    );

    const entries = mod.collectArchiveEntries(pkg, "codex-changeguard-plugin");
    for (const e of entries) {
      if (e.type === "dir") {
        assert.equal(e.mode, 0o755, `dir mode must be 0755: ${e.name}`);
      } else {
        assert.equal(e.mode, 0o644, `file mode must be 0644 (not host st.mode): ${e.name}`);
      }
    }
    const binFile = entries.find(
      (e) => e.name === "codex-changeguard-plugin/bin/changeguard.js",
    );
    assert.ok(binFile);
    assert.equal(binFile!.mode, 0o644);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("Ticket17 package repro: entry order is global UTF-8 byte-stable (a/child vs a.txt)", async () => {
  const mod = await loadPackagePlugin();
  const base = makeTempDir("cg-t17-order-");
  try {
    const pkg = path.join(base, "pkg");
    fs.mkdirSync(pkg, { recursive: true });
    seedSyntheticPackage(pkg);

    // Counterexample for shallow DFS: directory `a/` with child, plus sibling `a.txt`.
    // Global UTF-8 byte order: "…/a.txt" before "…/a" and "…/a/child" because
    // '.' (0x2e) < '/' (0x2f) after the shared prefix "a".
    fs.mkdirSync(path.join(pkg, "a"), { recursive: true });
    fs.writeFileSync(path.join(pkg, "a", "child"), "child\n", "utf8");
    fs.writeFileSync(path.join(pkg, "a.txt"), "sibling\n", "utf8");

    const entries = mod.collectArchiveEntries(pkg, "codex-changeguard-plugin");
    const names = entries.map((e) => e.name);
    const sorted = [...names].sort(comparePathUtf8);
    assert.deepEqual(
      names,
      sorted,
      "archive entry names must be globally sorted by UTF-8 bytes",
    );
    assert.equal(names[0], "codex-changeguard-plugin");

    const aTxt = "codex-changeguard-plugin/a.txt";
    const aDir = "codex-changeguard-plugin/a";
    const aChild = "codex-changeguard-plugin/a/child";
    const iTxt = names.indexOf(aTxt);
    const iDir = names.indexOf(aDir);
    const iChild = names.indexOf(aChild);
    assert.ok(iTxt >= 0, "a.txt must be present");
    assert.ok(iDir >= 0, "a/ dir must be present");
    assert.ok(iChild >= 0, "a/child must be present");
    // Shallow DFS with per-dir sort emits: a (dir), a/child, then sibling a.txt.
    // Global UTF-8 full-path order: a (prefix), then a.txt ('.' 0x2e), then a/child ('/' 0x2f).
    // The decisive gap vs shallow DFS is a.txt before a/child (not a.txt before dir a).
    assert.ok(
      iDir < iTxt,
      "UTF-8: directory path a is a proper prefix of a.txt so a precedes a.txt",
    );
    assert.ok(
      iTxt < iChild,
      "UTF-8 byte order: a.txt must precede a/child ('.' < '/'; exposes shallow DFS gap)",
    );
    assert.ok(iDir < iChild, "directory a must still precede its child a/child");
    assert.deepEqual(
      [names[iDir], names[iTxt], names[iChild]],
      [aDir, aTxt, aChild],
      "expected global order subsequence: a, a.txt, a/child",
    );

    // Directories appear before their children when the dir path is a proper prefix.
    const binIdx = names.indexOf("codex-changeguard-plugin/bin");
    const binFileIdx = names.indexOf("codex-changeguard-plugin/bin/changeguard.js");
    assert.ok(binIdx >= 0);
    assert.ok(binFileIdx > binIdx);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("Ticket17 package repro: collectArchiveEntries fails closed on symlinks", async () => {
  const mod = await loadPackagePlugin();
  const base = makeTempDir("cg-t17-symlink-");
  try {
    const pkg = path.join(base, "pkg");
    fs.mkdirSync(pkg, { recursive: true });
    fs.writeFileSync(path.join(pkg, "ok.txt"), "ok\n", "utf8");
    const target = path.join(pkg, "ok.txt");
    const link = path.join(pkg, "link.txt");
    try {
      fs.symlinkSync(target, link);
    } catch {
      // Windows without privilege: skip; other fail-closed coverage remains.
      return;
    }
    assert.throws(
      () => mod.collectArchiveEntries(pkg, "codex-changeguard-plugin"),
      /symlink/i,
    );
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("Ticket17 package repro: collectArchiveEntries fails closed on unsupported specials", async () => {
  if (process.platform === "win32") {
    // Named pipes / devices are platform-specific; skip on Windows.
    return;
  }
  const mod = await loadPackagePlugin();
  const base = makeTempDir("cg-t17-fifo-");
  try {
    const pkg = path.join(base, "pkg");
    fs.mkdirSync(pkg, { recursive: true });
    fs.writeFileSync(path.join(pkg, "ok.txt"), "ok\n", "utf8");
    const fifo = path.join(pkg, "special.fifo");
    const { spawnSync } = await import("node:child_process");
    const mk = spawnSync("mkfifo", [fifo], { encoding: "utf8" });
    if (mk.error || mk.status !== 0) {
      // mkfifo unavailable — skip special-entry case.
      return;
    }
    assert.throws(
      () => mod.collectArchiveEntries(pkg, "codex-changeguard-plugin"),
      /unsupported filesystem entry/i,
    );
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("Ticket17 package repro: host tar -czf is nondeterministic (negative control)", async () => {
  // Documents the pre-fix defect: system tar embeds wall-clock metadata.
  // Skip if tar is unavailable; the pure-archiver tests remain authoritative.
  const { spawnSync } = await import("node:child_process");
  const probe = spawnSync("tar", ["--version"], { encoding: "utf8" });
  if (probe.error || (probe.status !== 0 && probe.status !== null)) {
    // Windows or minimal environments without tar — skip negative control.
    return;
  }

  const base = makeTempDir("cg-t17-neg-");
  try {
    const release = path.join(base, "release");
    const pkg = path.join(release, "codex-changeguard-plugin");
    fs.mkdirSync(pkg, { recursive: true });
    seedSyntheticPackage(pkg);

    const t1 = path.join(base, "host1.tgz");
    const t2 = path.join(base, "host2.tgz");
    const r1 = spawnSync(
      "tar",
      ["-czf", t1, "-C", release, "codex-changeguard-plugin"],
      { encoding: "utf8" },
    );
    assert.equal(r1.status, 0, `host tar gen1 failed: ${r1.stderr}`);
    await sleepMs(1100);
    const r2 = spawnSync(
      "tar",
      ["-czf", t2, "-C", release, "codex-changeguard-plugin"],
      { encoding: "utf8" },
    );
    assert.equal(r2.status, 0, `host tar gen2 failed: ${r2.stderr}`);

    const h1 = crypto.createHash("sha256").update(fs.readFileSync(t1)).digest("hex");
    const h2 = crypto.createHash("sha256").update(fs.readFileSync(t2)).digest("hex");
    // On macOS/BSD tar this typically differs; if some platform normalizes by
    // default, the pure-archiver tests still prove the fix. Soft-assert with
    // diagnostic only when they match (unusual but not a product failure).
    if (h1 === h2) {
      // Host already deterministic — still require pure archiver path exists.
      const mod = await loadPackagePlugin();
      const pure = path.join(base, "pure.tgz");
      const meta = mod.writeReproducibleTarGz(pkg, pure, "codex-changeguard-plugin");
      assert.equal(typeof meta.tarball_sha256, "string");
      assert.equal(meta.tarball_sha256.length, 64);
    } else {
      assert.notEqual(
        h1,
        h2,
        "expected host tar nondeterminism across a 1s gap (documents pre-fix)",
      );
    }
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("Ticket17 package repro: optional system tar list/extract of pure tarball", async () => {
  // Compatibility coverage when tar is available; Windows must not require tar.
  const { spawnSync } = await import("node:child_process");
  const probe = spawnSync("tar", ["--version"], { encoding: "utf8" });
  if (probe.error || (probe.status !== 0 && probe.status !== null)) {
    return;
  }

  const mod = await loadPackagePlugin();
  const base = makeTempDir("cg-t17-extract-");
  try {
    const pkg = path.join(base, "pkg");
    fs.mkdirSync(pkg, { recursive: true });
    seedSyntheticPackage(pkg);
    const tgz = path.join(base, "pure.tgz");
    mod.writeReproducibleTarGz(pkg, tgz, "codex-changeguard-plugin");

    const list = spawnSync("tar", ["-tzf", tgz], { encoding: "utf8" });
    assert.equal(list.status, 0, `tar -tzf failed: ${list.stderr}`);
    assert.match(list.stdout, /codex-changeguard-plugin\/README\.md/);
    assert.match(list.stdout, /codex-changeguard-plugin\/bin\/changeguard\.js/);

    const out = path.join(base, "extracted");
    fs.mkdirSync(out, { recursive: true });
    const extract = spawnSync("tar", ["-xzf", tgz, "-C", out], { encoding: "utf8" });
    assert.equal(extract.status, 0, `tar -xzf failed: ${extract.stderr}`);
    const readme = path.join(out, "codex-changeguard-plugin", "README.md");
    assert.equal(fs.readFileSync(readme, "utf8"), "# repro package\n");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("Ticket17 package repro: package-plugin.mjs no longer shells out to tar -czf", () => {
  const src = fs.readFileSync(
    path.join(REPO_ROOT, "scripts", "package-plugin.mjs"),
    "utf8",
  );
  // Guard against regression to host tar packaging.
  assert.equal(
    /spawnSync\(\s*["']tar["']/.test(src),
    false,
    "package-plugin must not spawn host tar",
  );
  assert.match(src, /writeReproducibleTarGz/);
  assert.match(src, /gzipReproducible|zlib\.gzipSync/);
  assert.match(src, /reproducible_tarball/);
  assert.match(src, /gzBuf\[9\]\s*=\s*255/);
  assert.match(src, /comparePathUtf8|Buffer\.compare/);
});

test("Ticket17 package repro: two real writeReproducibleTarGz on release tree match when present", async () => {
  const packageDir = path.join(REPO_ROOT, "release", "codex-changeguard-plugin");
  if (!fs.existsSync(packageDir)) {
    // Full package not built yet; synthetic tests above remain sufficient.
    return;
  }
  const mod = await loadPackagePlugin();
  const content = mod.sha256Tree(packageDir);
  assert.ok(content.file_count > 0);

  const base = makeTempDir("cg-t17-real-");
  try {
    const t1 = path.join(base, "1.tgz");
    const t2 = path.join(base, "2.tgz");
    const m1 = mod.writeReproducibleTarGz(packageDir, t1);
    await sleepMs(200);
    const m2 = mod.writeReproducibleTarGz(packageDir, t2);
    assert.equal(m1.tarball_sha256, m2.tarball_sha256);
    assert.equal(m1.tarball_sha256.length, 64);
    const hdr = fs.readFileSync(t1).subarray(0, 10);
    assert.equal(hdr[9], 255, "release tarball gzip OS byte must be 255");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});
