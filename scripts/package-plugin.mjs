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
 *
 * Output: release/codex-changeguard-plugin/ (and optional tarball).
 */
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repoRoot, "release", "codex-changeguard-plugin");
const tarballPath = path.join(repoRoot, "release", "codex-changeguard-plugin.tgz");

/** Public Markdown docs required by the plugin package surface. */
const PUBLIC_DOCS = [
  "ARCHITECTURE.md",
  "SECURITY.md",
  "TEST_PLAN.md",
  "CASE_STUDIES.md",
  "SUPPORT_MATRIX.md",
];

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

function sha256File(abs) {
  const h = crypto.createHash("sha256");
  h.update(fs.readFileSync(abs));
  return h.digest("hex");
}

function sha256Tree(root) {
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

// Optional portable tarball (self-contained; no network needed to unpack)
rmrf(tarballPath);
const tar = spawnSync(
  "tar",
  ["-czf", tarballPath, "-C", path.join(repoRoot, "release"), "codex-changeguard-plugin"],
  { encoding: "utf8", env: process.env },
);
if (tar.status !== 0) {
  process.stderr.write(tar.stdout || "");
  process.stderr.write(tar.stderr || "");
  throw new Error("Failed to create portable package tarball");
}

const treeHash = sha256Tree(outDir);
const tarballHash = sha256File(tarballPath);

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
    },
    null,
    2,
  ),
);
