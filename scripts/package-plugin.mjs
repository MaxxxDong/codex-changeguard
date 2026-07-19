/**
 * Reproducible plugin package builder (Ticket 01 + Ticket 17 S4 judge package).
 * Creates an installable artifact with compiled self-contained JS, manifest,
 * MCP config, Skill, fixtures, public docs, LICENSE, and schemas. No
 * node_modules; no runtime dependency installation. Repository-only surfaces
 * (HANDOFF.md, docs/agents, AGENTS.md, src, scripts) are excluded.
 *
 * Judge package contract (Ticket 17):
 * - Built runtime + fixtures/schemas/Skill/docs/licenses only
 * - No source maps (path leakage), caches, node_modules, secrets, Git metadata
 * - Self-contained: no repository checkout, TypeScript build, GitHub login,
 *   API key, or network required to run `node bin/changeguard.js demo`
 * - Portable `.tgz` is byte-for-byte reproducible for identical package contents
 *   (stable entry order + normalized ustar/gzip metadata; pure Node 20, no
 *   host `tar`/`gzip` timestamps or GNU-only flags)
 *
 * Output: release/codex-changeguard-plugin/ (and optional tarball).
 */
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repoRoot, "release", "codex-changeguard-plugin");
const tarballPath = path.join(repoRoot, "release", "codex-changeguard-plugin.tgz");
/** Archive root directory name inside the portable tarball. */
const ARCHIVE_ROOT_NAME = "codex-changeguard-plugin";

/** Public Markdown docs required by the plugin package surface. */
const PUBLIC_DOCS = [
  "ARCHITECTURE.md",
  "SECURITY.md",
  "TEST_PLAN.md",
  "CASE_STUDIES.md",
  "SUPPORT_MATRIX.md",
];

const TAR_BLOCK = 512;
/** Fixed mtime (Unix epoch) for every ustar header — eliminates wall-clock nondeterminism. */
const REPRO_MTIME = 0;
/** Fixed uid/gid and empty uname/gname for cross-host identical headers. */
const REPRO_UID = 0;
const REPRO_GID = 0;

function rmrf(p) {
  fs.rmSync(p, { recursive: true, force: true });
}

function mkdirp(p) {
  fs.mkdirSync(p, { recursive: true });
}

function copyFile(src, dest) {
  mkdirp(path.dirname(dest));
  fs.copyFileSync(src, dest);
}

function copyDir(src, dest) {
  mkdirp(dest);
  for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
    // Never copy VCS/cache/junk that may appear under fixtures or elsewhere.
    if (
      ent.name === ".git" ||
      ent.name === "node_modules" ||
      ent.name === ".DS_Store" ||
      ent.name === ".cache" ||
      ent.name.startsWith(".grok")
    ) {
      continue;
    }
    const s = path.join(src, ent.name);
    const d = path.join(dest, ent.name);
    if (ent.isSymbolicLink()) {
      throw new Error(`Package source must not contain symlinks: ${s}`);
    }
    if (ent.isDirectory()) copyDir(s, d);
    else if (ent.isFile()) copyFile(s, d);
  }
}

function mustExist(p, label) {
  if (!fs.existsSync(p)) {
    throw new Error(`Missing required package input: ${label} (${p})`);
  }
}

/**
 * Source READMEs are the repo bilingual entry points and keep HANDOFF.md links.
 * Packaged READMEs must not ship a broken local handoff link because
 * HANDOFF.md is intentionally repository-only. README.md remains the default
 * English entry; README.zh-CN.md ships as the bilingual package surface.
 */
function buildPublicReadme(sourceText, label = "README") {
  const lines = sourceText.split(/\r?\n/);
  const out = [];
  for (const line of lines) {
    // Drop any line with a relative HANDOFF.md Markdown link (repo-only).
    if (/\[[^\]]*\]\(\s*HANDOFF\.md(?:#[^)\s]*)?\s*\)/i.test(line)) {
      continue;
    }
    out.push(line);
  }
  let text = out.join("\n");
  if (!text.endsWith("\n")) text += "\n";
  if (/\(HANDOFF\.md(?:#[^)\s]*)?\)/i.test(text)) {
    throw new Error(
      `Public package ${label} still references HANDOFF.md after transform`,
    );
  }
  return text;
}

/**
 * Remove source maps and sourceMappingURL comments that can leak local paths.
 * Declaration maps are also stripped; runtime needs only .js (+ .d.ts optional).
 */
function stripSourceMaps(packageRoot) {
  const removed = [];
  function walk(dir, relBase = "") {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(abs, rel);
        continue;
      }
      if (!ent.isFile()) continue;
      if (ent.name.endsWith(".map") || ent.name.endsWith(".js.map") || ent.name.endsWith(".d.ts.map")) {
        fs.rmSync(abs, { force: true });
        removed.push(rel);
        continue;
      }
      if (ent.name.endsWith(".js") || ent.name.endsWith(".mjs") || ent.name.endsWith(".cjs")) {
        const text = fs.readFileSync(abs, "utf8");
        if (/sourceMappingURL\s*=/.test(text)) {
          const cleaned = text
            .replace(/\/\/[#@]\s*sourceMappingURL\s*=\s*[^\n\r]*/g, "")
            .replace(/\/\*[#@]\s*sourceMappingURL\s*=\s*[^*]*\*\//g, "");
          if (cleaned !== text) {
            fs.writeFileSync(abs, cleaned, "utf8");
          }
        }
      }
    }
  }
  walk(packageRoot);
  return removed;
}

export function sha256File(abs) {
  const h = crypto.createHash("sha256");
  h.update(fs.readFileSync(abs));
  return h.digest("hex");
}

export function sha256Tree(root) {
  const files = [];
  function walk(dir, relBase = "") {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(abs, rel);
      else if (ent.isFile()) files.push(rel);
    }
  }
  walk(root);
  files.sort();
  const h = crypto.createHash("sha256");
  for (const rel of files) {
    const abs = path.join(root, rel);
    const st = fs.statSync(abs);
    h.update(rel);
    h.update("\0");
    h.update(String(st.size));
    h.update("\0");
    h.update(fs.readFileSync(abs));
    h.update("\0");
  }
  return { content_sha256: h.digest("hex"), file_count: files.length };
}

/**
 * Encode a non-negative integer as a NUL-terminated octal field of fixed width.
 * @param {number} value
 * @param {number} length field width including trailing NUL
 */
function encodeOctal(value, length) {
  if (!Number.isFinite(value) || value < 0 || !Number.isInteger(value)) {
    throw new Error(`Invalid octal field value: ${value}`);
  }
  const s = value.toString(8);
  if (s.length > length - 1) {
    throw new Error(`Octal field overflow: ${value} needs more than ${length - 1} digits`);
  }
  return Buffer.from(s.padStart(length - 1, "0") + "\0", "ascii");
}

/**
 * Split a POSIX path into ustar name (≤100) + prefix (≤155) fields.
 * @param {string} name POSIX path using `/` separators
 * @returns {{ prefix: string, name: string }}
 */
function splitUstarName(name) {
  const nameBytes = Buffer.byteLength(name, "utf8");
  if (nameBytes <= 100) {
    return { prefix: "", name };
  }
  const parts = name.split("/");
  // Prefer the longest valid prefix so the name field stays short enough.
  for (let i = parts.length - 1; i >= 1; i--) {
    const prefix = parts.slice(0, i).join("/");
    const base = parts.slice(i).join("/");
    if (
      Buffer.byteLength(prefix, "utf8") <= 155 &&
      Buffer.byteLength(base, "utf8") <= 100 &&
      base.length > 0
    ) {
      return { prefix, name: base };
    }
  }
  throw new Error(`Path too long for ustar name/prefix fields: ${name}`);
}

/**
 * Build one 512-byte ustar header with normalized metadata.
 * @param {{ name: string, mode: number, size: number, typeflag: string, mtime?: number }} opts
 */
function writeUstarHeader(opts) {
  const { name, mode, size, typeflag, mtime = REPRO_MTIME } = opts;
  const buf = Buffer.alloc(TAR_BLOCK, 0);
  const split = splitUstarName(name);
  buf.write(split.name, 0, 100, "utf8");
  encodeOctal(mode & 0o7777, 8).copy(buf, 100);
  encodeOctal(REPRO_UID, 8).copy(buf, 108);
  encodeOctal(REPRO_GID, 8).copy(buf, 116);
  encodeOctal(size, 12).copy(buf, 124);
  encodeOctal(mtime, 12).copy(buf, 136);
  // Checksum field is spaces during calculation.
  buf.fill(0x20, 148, 156);
  buf.write(typeflag, 156, 1, "ascii");
  // linkname left zero-filled
  buf.write("ustar\0", 257, 6, "ascii");
  buf.write("00", 263, 2, "ascii");
  // uname / gname left empty (zero-filled) for host independence
  // devmajor / devminor left zero
  if (split.prefix) {
    buf.write(split.prefix, 345, 155, "utf8");
  }
  let sum = 0;
  for (let i = 0; i < TAR_BLOCK; i++) sum += buf[i];
  // Traditional tar checksum: 6 octal digits, NUL, space
  const chk = sum.toString(8).padStart(6, "0");
  buf.write(chk, 148, 6, "ascii");
  buf[154] = 0;
  buf[155] = 0x20;
  return buf;
}

/**
 * Portable archive modes independent of host st.mode.
 * All regular packaged files are invoked through Node → 0o644.
 * Directories → 0o755. Prevents Windows/Unix package-byte drift.
 * @param {"dir"|"file"} kind
 */
function normalizedMode(kind) {
  return kind === "dir" ? 0o755 : 0o644;
}

/**
 * Compare archive path names by UTF-8 byte order (not host locale / UTF-16).
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function comparePathUtf8(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/**
 * Collect package-tree entries in global UTF-8 byte-stable order.
 * Fail-closed for unsupported special filesystem entries (symlinks rejected).
 * @param {string} sourceDir absolute package directory
 * @param {string} archiveRootName root folder name inside the archive
 * @returns {{ type: "dir"|"file", name: string, mode: number, data?: Buffer }[]}
 */
export function collectArchiveEntries(sourceDir, archiveRootName = ARCHIVE_ROOT_NAME) {
  /** @type {{ type: "dir"|"file", name: string, mode: number, data?: Buffer }[]} */
  const entries = [];
  entries.push({ type: "dir", name: archiveRootName, mode: normalizedMode("dir") });

  function walk(dir, relBase) {
    const ents = fs
      .readdirSync(dir, { withFileTypes: true })
      .filter(
        (e) =>
          e.name !== ".DS_Store" &&
          e.name !== ".git" &&
          e.name !== "node_modules" &&
          !e.name.startsWith(".grok"),
      );
    for (const ent of ents) {
      const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
      const abs = path.join(dir, ent.name);
      const name = `${archiveRootName}/${rel}`;
      if (ent.isSymbolicLink()) {
        throw new Error(`Package archive must not contain symlinks: ${name}`);
      }
      if (ent.isDirectory()) {
        entries.push({ type: "dir", name, mode: normalizedMode("dir") });
        walk(abs, rel);
      } else if (ent.isFile()) {
        const data = fs.readFileSync(abs);
        entries.push({
          type: "file",
          name,
          mode: normalizedMode("file"),
          data,
        });
      } else {
        // Fail closed: sockets, FIFOs, devices, etc. must not be silently skipped.
        throw new Error(
          `Package archive must not contain unsupported filesystem entry: ${name}`,
        );
      }
    }
  }

  walk(sourceDir, "");
  // Global UTF-8 byte order (not shallow DFS). Covers a/child vs sibling a.txt:
  // byte order places "…/a.txt" before "…/a/child" because '.' (0x2e) < '/' (0x2f).
  entries.sort((a, b) => comparePathUtf8(a.name, b.name));
  return entries;
}

/**
 * Build an uncompressed ustar archive buffer with normalized metadata and
 * stable entry ordering. Byte-identical for identical file contents/modes.
 * @param {string} sourceDir
 * @param {string} [archiveRootName]
 * @returns {Buffer}
 */
export function createReproducibleTar(sourceDir, archiveRootName = ARCHIVE_ROOT_NAME) {
  const entries = collectArchiveEntries(sourceDir, archiveRootName);
  /** @type {Buffer[]} */
  const parts = [];
  for (const e of entries) {
    if (e.type === "dir") {
      parts.push(
        writeUstarHeader({
          name: e.name,
          mode: e.mode,
          size: 0,
          typeflag: "5",
          mtime: REPRO_MTIME,
        }),
      );
    } else {
      const data = e.data ?? Buffer.alloc(0);
      parts.push(
        writeUstarHeader({
          name: e.name,
          mode: e.mode,
          size: data.length,
          typeflag: "0",
          mtime: REPRO_MTIME,
        }),
      );
      parts.push(data);
      const pad = (TAR_BLOCK - (data.length % TAR_BLOCK)) % TAR_BLOCK;
      if (pad) parts.push(Buffer.alloc(pad, 0));
    }
  }
  // Two zero blocks end the archive (POSIX).
  parts.push(Buffer.alloc(TAR_BLOCK * 2, 0));
  return Buffer.concat(parts);
}

/**
 * Gzip a buffer with fixed header metadata (mtime 0, OS byte 255).
 * Node zlib may set OS from the host (e.g. 19 on darwin); normalize to 255
 * (unknown) so identical inputs + fixed Node toolchain yield stable .tgz bytes
 * across Windows/Unix. Scope is not cross-Node/zlib version identity.
 * @param {Buffer} tarBuf
 * @returns {Buffer}
 */
export function gzipReproducible(tarBuf) {
  const gzBuf = zlib.gzipSync(tarBuf, { level: 9, mtime: 0 });
  // Gzip header OS field is at offset 9 (RFC 1952). Force 255 (unknown).
  if (gzBuf.length < 10) {
    throw new Error("gzipReproducible: truncated gzip header");
  }
  gzBuf[9] = 255;
  if (gzBuf[9] !== 255) {
    throw new Error("gzipReproducible: failed to normalize OS header byte to 255");
  }
  return gzBuf;
}

/**
 * Create a portable `.tgz` that is byte-for-byte reproducible for identical
 * package contents. Pure Node — no host `tar`/`gzip` process, no GNU flags.
 * @param {string} sourceDir absolute path to the package directory
 * @param {string} destTgz absolute path of the output tarball
 * @param {string} [archiveRootName]
 * @returns {{ tarball_sha256: string, byte_length: number }}
 */
export function writeReproducibleTarGz(
  sourceDir,
  destTgz,
  archiveRootName = ARCHIVE_ROOT_NAME,
) {
  const tarBuf = createReproducibleTar(sourceDir, archiveRootName);
  const gzBuf = gzipReproducible(tarBuf);
  mkdirp(path.dirname(destTgz));
  fs.writeFileSync(destTgz, gzBuf);
  return {
    tarball_sha256: crypto.createHash("sha256").update(gzBuf).digest("hex"),
    byte_length: gzBuf.length,
  };
}

/**
 * Main packaging entry: build, assemble allowlisted tree, write reproducible tarball.
 * @returns {void}
 */
function main() {
  // 1) Build compiled JS
  const build = spawnSync("npm", ["run", "build"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: process.env,
    shell: process.platform === "win32",
  });
  if (build.status !== 0) {
    process.stderr.write(build.stdout || "");
    process.stderr.write(build.stderr || "");
    process.exit(build.status ?? 1);
  }

  // 2) Assemble package tree
  rmrf(outDir);
  mkdirp(outDir);

  const required = [
    ["dist/cli/main.js", "compiled CLI"],
    ["dist/mcp/server.js", "compiled MCP server"],
    ["dist/hooks/session-start-entry.js", "packaged SessionStart entrypoint"],
    ["dist/core/demo/run-demo.js", "compiled demo core"],
    ["bin/changeguard.js", "CLI wrapper"],
    [".codex-plugin/plugin.json", "plugin manifest"],
    [".mcp.json", "MCP config"],
    ["skills/changeguard/SKILL.md", "Skill"],
    ["hooks/hooks.json", "SessionStart hooks manifest"],
    ["package.json", "package.json"],
    ["LICENSE", "LICENSE"],
    ["README.md", "README"],
    ["README.zh-CN.md", "README (zh-CN)"],
    ["schemas/demo-receipt.schema.json", "demo receipt schema"],
    ...PUBLIC_DOCS.map((name) => [`docs/${name}`, `public doc ${name}`]),
  ];

  for (const [rel, label] of required) {
    mustExist(path.join(repoRoot, rel), label);
  }

  // Compiled self-contained JS (entire dist/)
  copyDir(path.join(repoRoot, "dist"), path.join(outDir, "dist"));
  // CLI wrapper
  copyFile(path.join(repoRoot, "bin/changeguard.js"), path.join(outDir, "bin/changeguard.js"));
  // Manifest + MCP
  copyDir(path.join(repoRoot, ".codex-plugin"), path.join(outDir, ".codex-plugin"));
  copyFile(path.join(repoRoot, ".mcp.json"), path.join(outDir, ".mcp.json"));
  // Skill
  copyDir(path.join(repoRoot, "skills"), path.join(outDir, "skills"));
  // Optional trusted SessionStart hook registration (host must trust explicitly)
  copyDir(path.join(repoRoot, "hooks"), path.join(outDir, "hooks"));
  // Fixtures + schemas
  copyDir(path.join(repoRoot, "fixtures"), path.join(outDir, "fixtures"));
  copyDir(path.join(repoRoot, "schemas"), path.join(outDir, "schemas"));
  // Public docs only (not docs/agents or other repository-internal guidance)
  for (const name of PUBLIC_DOCS) {
    copyFile(path.join(repoRoot, "docs", name), path.join(outDir, "docs", name));
  }
  // Public bilingual READMEs without repository-only handoff links
  const sourceReadme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
  fs.writeFileSync(
    path.join(outDir, "README.md"),
    buildPublicReadme(sourceReadme, "README.md"),
    "utf8",
  );
  const sourceReadmeZh = fs.readFileSync(
    path.join(repoRoot, "README.zh-CN.md"),
    "utf8",
  );
  fs.writeFileSync(
    path.join(outDir, "README.zh-CN.md"),
    buildPublicReadme(sourceReadmeZh, "README.zh-CN.md"),
    "utf8",
  );
  // AGENTS.md is repository/operator guidance — not a public runtime surface.
  copyFile(path.join(repoRoot, "package.json"), path.join(outDir, "package.json"));
  // MIT license text for the self-contained judge package
  copyFile(path.join(repoRoot, "LICENSE"), path.join(outDir, "LICENSE"));

  // Strip source maps that can leak local source paths
  const strippedMaps = stripSourceMaps(outDir);

  // Exact top-level public package surface allowlist.
  const ALLOWED_TOP_LEVEL = new Set([
    ".codex-plugin",
    ".mcp.json",
    "LICENSE",
    "README.md",
    "README.zh-CN.md",
    "bin",
    "dist",
    "docs",
    "fixtures",
    "hooks",
    "package.json",
    "schemas",
    "skills",
  ]);
  const FORBIDDEN_PACKAGED_PATHS = [
    "AGENTS.md",
    "HANDOFF.md",
    "docs/agents",
    ".scratch",
    "src",
    "scripts",
    "node_modules",
    ".git",
    ".github",
    ".env",
  ];

  const entries = fs.readdirSync(outDir).sort();
  for (const name of entries) {
    if (!ALLOWED_TOP_LEVEL.has(name)) {
      throw new Error(`Package top-level entry not on allowlist: ${name}`);
    }
  }
  // Forbidden paths must not appear anywhere in the packaged tree
  function walkRel(dir, relBase = "") {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
      const abs = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) {
        throw new Error(`Package must not contain symlinks (found ${rel})`);
      }
      for (const forbidden of FORBIDDEN_PACKAGED_PATHS) {
        if (rel === forbidden || rel.startsWith(`${forbidden}/`)) {
          throw new Error(`Package must not contain ${forbidden} (found ${rel})`);
        }
      }
      // No source maps remaining
      if (ent.isFile() && (ent.name.endsWith(".map") || /\.js\.map$/.test(ent.name))) {
        throw new Error(`Package must not contain source maps (found ${rel})`);
      }
      if (ent.isDirectory()) walkRel(abs, rel);
    }
  }
  walkRel(outDir);

  // Exact public docs tree
  const docsDir = path.join(outDir, "docs");
  const docsEntries = fs.readdirSync(docsDir).sort();
  const expectedDocs = [...PUBLIC_DOCS].sort();
  if (JSON.stringify(docsEntries) !== JSON.stringify(expectedDocs)) {
    throw new Error(
      `Package docs must be exactly ${expectedDocs.join(", ")}; got ${docsEntries.join(", ")}`,
    );
  }

  // No disposable/clone lifecycle paths
  for (const name of entries) {
    if (name.startsWith(".grok") || name.includes("grok-worker") || name.includes("grok-disposable")) {
      throw new Error(`Package must not contain clone/lifecycle path: ${name}`);
    }
  }

  // Ensure no node_modules leaked
  const nm = path.join(outDir, "node_modules");
  if (fs.existsSync(nm)) {
    throw new Error("Package must not contain node_modules");
  }

  // package.json must stay private MIT
  const packagedPkg = JSON.parse(fs.readFileSync(path.join(outDir, "package.json"), "utf8"));
  if (packagedPkg.private !== true) {
    throw new Error("Packaged package.json must keep private:true");
  }
  if (packagedPkg.license !== "MIT") {
    throw new Error("Packaged package.json must declare MIT license");
  }
  if (packagedPkg.dependencies && Object.keys(packagedPkg.dependencies).length > 0) {
    throw new Error("Packaged package.json must not declare runtime dependencies");
  }

  // Demo entrypoints must exist for judge path
  for (const rel of [
    "bin/changeguard.js",
    "dist/cli/main.js",
    "dist/core/demo/run-demo.js",
    "schemas/demo-receipt.schema.json",
    "fixtures/protected-process/incident.json",
    "fixtures/crash-family/access-violation-crbrowser/incident.json",
    "fixtures/impact-local/incident.json",
    "fixtures/official-evidence/snapshot.json",
    "LICENSE",
  ]) {
    if (!fs.existsSync(path.join(outDir, rel))) {
      throw new Error(`Judge package missing required path: ${rel}`);
    }
  }

  // Portable tarball: pure Node ustar+gzip with normalized metadata (no host tar).
  rmrf(tarballPath);
  const tarballMeta = writeReproducibleTarGz(outDir, tarballPath, ARCHIVE_ROOT_NAME);

  const treeHash = sha256Tree(outDir);
  const tarballHash = tarballMeta.tarball_sha256;

  console.log(
    JSON.stringify(
      {
        ok: true,
        outDir: path.relative(repoRoot, outDir),
        tarball: path.relative(repoRoot, tarballPath),
        package_content_sha256: treeHash.content_sha256,
        package_file_count: treeHash.file_count,
        tarball_sha256: tarballHash,
        has_node_modules: false,
        has_agents_md: false,
        has_handoff_md: false,
        has_docs_agents: false,
        has_source_maps: false,
        stripped_source_maps: strippedMaps.length,
        has_license: true,
        private: true,
        license: "MIT",
        public_docs: expectedDocs,
        entries,
        allowed_top_level: [...ALLOWED_TOP_LEVEL].sort(),
        judge_demo_entry: "node bin/changeguard.js demo",
        reproducible_tarball: true,
      },
      null,
      2,
    ),
  );
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  main();
}
