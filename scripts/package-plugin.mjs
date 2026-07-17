/**
 * Reproducible plugin package builder (Ticket 01).
 * Creates an installable artifact with compiled self-contained JS, manifest,
 * MCP config, Skill, fixtures, docs, and schemas. No node_modules; no runtime
 * dependency installation.
 *
 * Output: release/codex-changeguard-plugin/ (and optional tarball).
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repoRoot, "release", "codex-changeguard-plugin");

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
// Fixtures + schemas + docs surfaces required for judge/install
copyDir(path.join(repoRoot, "fixtures"), path.join(outDir, "fixtures"));
copyDir(path.join(repoRoot, "schemas"), path.join(outDir, "schemas"));
copyDir(path.join(repoRoot, "docs"), path.join(outDir, "docs"));
copyFile(path.join(repoRoot, "README.md"), path.join(outDir, "README.md"));
copyFile(path.join(repoRoot, "AGENTS.md"), path.join(outDir, "AGENTS.md"));
copyFile(path.join(repoRoot, "package.json"), path.join(outDir, "package.json"));

// Ensure no node_modules leaked
const nm = path.join(outDir, "node_modules");
if (fs.existsSync(nm)) {
  throw new Error("Package must not contain node_modules");
}

// Rewrite package.json bin paths stay relative; strip scripts that need devDeps if desired.
// Keep package.json as-is (private, no runtime deps).

console.log(
  JSON.stringify(
    {
      ok: true,
      outDir: path.relative(repoRoot, outDir),
      has_node_modules: false,
      entries: fs.readdirSync(outDir).sort(),
    },
    null,
    2,
  ),
);
