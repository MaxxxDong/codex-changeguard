/**
 * Reproducible plugin package builder (Ticket 01).
 * Creates an installable artifact with compiled self-contained JS, manifest,
 * MCP config, Skill, fixtures, public docs, and schemas. No node_modules; no
 * runtime dependency installation. Repository-only surfaces (HANDOFF.md,
 * docs/agents, AGENTS.md, src, scripts) are excluded.
 *
 * Output: release/codex-changeguard-plugin/ (and optional tarball).
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repoRoot, "release", "codex-changeguard-plugin");

/** Public Markdown docs required by the plugin package surface. */
const PUBLIC_DOCS = [
  "ARCHITECTURE.md",
  "SECURITY.md",
  "TEST_PLAN.md",
  "CASE_STUDIES.md",
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
    const s = path.join(src, ent.name);
    const d = path.join(dest, ent.name);
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
 * Source README is the repo entry point and keeps the HANDOFF.md link.
 * The packaged README must not ship a broken local handoff link because
 * HANDOFF.md is intentionally repository-only.
 */
function buildPublicReadme(sourceText) {
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
    throw new Error("Public package README still references HANDOFF.md after transform");
  }
  return text;
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
  ["bin/changeguard.js", "CLI wrapper"],
  [".codex-plugin/plugin.json", "plugin manifest"],
  [".mcp.json", "MCP config"],
  ["skills/changeguard/SKILL.md", "Skill"],
  ["package.json", "package.json"],
  ["README.md", "README"],
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
// Fixtures + schemas
copyDir(path.join(repoRoot, "fixtures"), path.join(outDir, "fixtures"));
copyDir(path.join(repoRoot, "schemas"), path.join(outDir, "schemas"));
// Public docs only (not docs/agents or other repository-internal guidance)
for (const name of PUBLIC_DOCS) {
  copyFile(path.join(repoRoot, "docs", name), path.join(outDir, "docs", name));
}
// Public README without repository-only handoff link
const sourceReadme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
fs.writeFileSync(path.join(outDir, "README.md"), buildPublicReadme(sourceReadme), "utf8");
// AGENTS.md is repository/operator guidance — not a public runtime surface.
copyFile(path.join(repoRoot, "package.json"), path.join(outDir, "package.json"));

// Exact top-level public package surface allowlist.
const ALLOWED_TOP_LEVEL = new Set([
  ".codex-plugin",
  ".mcp.json",
  "README.md",
  "bin",
  "dist",
  "docs",
  "fixtures",
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
    for (const forbidden of FORBIDDEN_PACKAGED_PATHS) {
      if (rel === forbidden || rel.startsWith(`${forbidden}/`)) {
        throw new Error(`Package must not contain ${forbidden} (found ${rel})`);
      }
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

console.log(
  JSON.stringify(
    {
      ok: true,
      outDir: path.relative(repoRoot, outDir),
      has_node_modules: false,
      has_agents_md: false,
      has_handoff_md: false,
      has_docs_agents: false,
      public_docs: expectedDocs,
      entries,
      allowed_top_level: [...ALLOWED_TOP_LEVEL].sort(),
    },
    null,
    2,
  ),
);
