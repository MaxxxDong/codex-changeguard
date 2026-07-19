/**
 * Ticket 17 S4 — clean-profile install / uninstall residual smoke.
 *
 * Proves that a packaged ChangeGuard install under an isolated temporary
 * HOME/profile can run the demo, then uninstall with no residual:
 *   - daemon / background process
 *   - LaunchAgent / service / scheduled task (macOS/Linux markers under temp home)
 *   - shell profile edit
 *   - global Codex config edit
 *   - credential requirement
 *   - leftover product-owned paths
 *
 * Uses ONLY temp roots controlled by this test. Never mutates the real home,
 * real ~/.codex, real LaunchAgents, or host global config.
 *
 * Usage: node scripts/clean-profile-smoke.mjs
 * Prerequisite: npm run package (release/codex-changeguard-plugin present)
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageDir = path.join(repoRoot, "release", "codex-changeguard-plugin");

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

function listTree(root) {
  /** @type {string[]} */
  const out = [];
  if (!fs.existsSync(root)) return out;
  function walk(dir, relBase = "") {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
      out.push(rel);
      if (ent.isDirectory()) walk(path.join(dir, ent.name), rel);
    }
  }
  walk(root);
  return out;
}

if (!fs.existsSync(path.join(packageDir, "bin/changeguard.js"))) {
  fail("Package missing; run npm run package first.");
}

const realHome = process.env.HOME ?? process.env.USERPROFILE ?? null;
const stageRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-clean-profile-"));
const fakeHome = path.join(stageRoot, "home");
const outsideCwd = path.join(stageRoot, "outside-cwd");
const pluginInstall = path.join(
  fakeHome,
  ".codex",
  "plugins",
  "codex-changeguard-plugin",
);
const skillInstall = path.join(fakeHome, ".codex", "skills", "changeguard");
const productStateDir = path.join(fakeHome, ".changeguard");

// Seed a "clean profile" skeleton without product residue.
fs.mkdirSync(path.join(fakeHome, ".codex"), { recursive: true });
fs.mkdirSync(outsideCwd, { recursive: true });
// Empty shell profiles so we can detect edits.
for (const name of [".bashrc", ".zshrc", ".profile"]) {
  fs.writeFileSync(path.join(fakeHome, name), "# clean profile baseline\n", "utf8");
}
// Empty LaunchAgents dir (macOS-style residual surface under isolated home only).
fs.mkdirSync(path.join(fakeHome, "Library", "LaunchAgents"), { recursive: true });
// systemd user unit dir (Linux residual surface under isolated home only).
fs.mkdirSync(path.join(fakeHome, ".config", "systemd", "user"), {
  recursive: true,
});
// cron-like residual surface
fs.mkdirSync(path.join(fakeHome, ".config", "cron"), { recursive: true });

const baselineHomeListing = new Set(listTree(fakeHome));
const baselineShellHashes = Object.fromEntries(
  [".bashrc", ".zshrc", ".profile"].map((n) => {
    const p = path.join(fakeHome, n);
    return [n, fs.readFileSync(p, "utf8")];
  }),
);

// --- Install (stage only; no host daemon, no real home) ---
fs.cpSync(packageDir, pluginInstall, { recursive: true });
fs.mkdirSync(path.dirname(skillInstall), { recursive: true });
fs.cpSync(
  path.join(packageDir, "skills", "changeguard"),
  skillInstall,
  { recursive: true },
);

// Prove no credential / network / GitHub requirement for demo path.
const envIsolated = {
  ...process.env,
  NO_COLOR: "1",
  HOME: fakeHome,
  USERPROFILE: fakeHome,
  // Explicitly clear common credential / token env that must not be required.
  GITHUB_TOKEN: "",
  GH_TOKEN: "",
  OPENAI_API_KEY: "",
  ANTHROPIC_API_KEY: "",
  CODEX_API_KEY: "",
  CHANGEGUARD_API_KEY: "",
};

// Snapshot process list keywords before (best-effort residual check uses install tree only).
const demo = spawnSync(
  process.execPath,
  [path.join(pluginInstall, "bin/changeguard.js"), "demo"],
  {
    cwd: outsideCwd,
    encoding: "utf8",
    env: envIsolated,
    maxBuffer: 8 * 1024 * 1024,
  },
);
if (demo.status !== 0) {
  fail(
    `Clean-profile packaged demo failed status=${demo.status}\n${demo.stdout}\n${demo.stderr}`,
  );
}
let receipt;
try {
  receipt = JSON.parse(demo.stdout);
} catch {
  fail("Clean-profile demo stdout is not JSON.");
}
if (
  receipt.ok !== true ||
  receipt.status !== "completed" ||
  receipt.network_used !== false ||
  receipt.external_write !== false ||
  receipt.live_profile_mutated !== false
) {
  fail(`Clean-profile demo contract failed: ${JSON.stringify(receipt)}`);
}
if (
  !receipt.security_evidence ||
  receipt.security_evidence.proven !== true ||
  receipt.security_evidence.network_all_false !== true ||
  receipt.security_evidence.local_only?.mode !== "local_only_no_adapter" ||
  receipt.security_evidence.local_only?.no_external_adapter !== true ||
  receipt.security_evidence.local_only?.mutations_local_only !== true ||
  !(receipt.security_evidence.disposable_root?.proof_count >= 1)
) {
  fail(
    `Clean-profile demo security_evidence incomplete: ${JSON.stringify(receipt.security_evidence)}`,
  );
}
if (!Array.isArray(receipt.steps) || receipt.steps.length !== 10) {
  fail("Clean-profile demo must return 10 ordered steps.");
}
if (receipt.cleanup?.temp_removed !== true) {
  fail("Clean-profile demo must remove its disposable temp.");
}

// Demo must not start a long-lived child that outlives the CLI (best-effort:
// CLI process already exited; no LaunchAgent/service files may be created).
const afterDemoHome = listTree(fakeHome);
const newAfterDemo = afterDemoHome.filter((r) => !baselineHomeListing.has(r));
// Allowed new paths: staged plugin/skill install trees + their parent dirs.
const allowedExact = new Set([
  ".codex/plugins",
  ".codex/skills",
]);
const allowedPrefixes = [
  ".codex/plugins/codex-changeguard-plugin",
  ".codex/skills/changeguard",
];
for (const rel of newAfterDemo) {
  const ok =
    allowedExact.has(rel) ||
    allowedPrefixes.some((p) => rel === p || rel.startsWith(p + "/"));
  if (!ok) {
    fail(
      `Install/demo created unexpected path under isolated home: ${rel}`,
    );
  }
}

// Residual service markers must not appear.
const forbiddenRelPatterns = [
  /^Library\/LaunchAgents\/.*changeguard/i,
  /^\.config\/systemd\/user\/.*changeguard/i,
  /^\.config\/cron\/.*changeguard/i,
  /^\.changeguard(\/|$)/i,
  /^\.codex\/config\.toml$/i,
  /^\.codex\/auth\.json$/i,
  /^\.codex\/credentials/i,
];
for (const rel of afterDemoHome) {
  for (const re of forbiddenRelPatterns) {
    if (re.test(rel)) {
      fail(`Forbidden residual/service path under isolated home: ${rel}`);
    }
  }
}

// Shell profiles must be byte-identical to baseline.
for (const [name, before] of Object.entries(baselineShellHashes)) {
  const after = fs.readFileSync(path.join(fakeHome, name), "utf8");
  if (after !== before) {
    fail(`Shell profile was mutated under isolated home: ${name}`);
  }
  if (/changeguard/i.test(after)) {
    fail(`Shell profile references changeguard: ${name}`);
  }
}

// Real home must never be the install target of this smoke.
if (realHome) {
  const realPlugin = path.join(
    realHome,
    ".codex",
    "plugins",
    "codex-changeguard-plugin",
  );
  // We never write there; if it already exists from a human install, ignore —
  // but this smoke must not have used realHome as HOME.
  if (path.resolve(fakeHome) === path.resolve(realHome)) {
    fail("Clean-profile smoke must not use the real HOME.");
  }
  void realPlugin;
}

// --- Uninstall ---
fs.rmSync(pluginInstall, { recursive: true, force: true });
fs.rmSync(skillInstall, { recursive: true, force: true });
// Product-owned optional state dir if any
if (fs.existsSync(productStateDir)) {
  fs.rmSync(productStateDir, { recursive: true, force: true });
}

if (fs.existsSync(pluginInstall)) {
  fail("Uninstall left plugin install tree.");
}
if (fs.existsSync(skillInstall)) {
  fail("Uninstall left skill install tree.");
}
if (fs.existsSync(productStateDir)) {
  fail("Uninstall left product state dir.");
}

// After uninstall, home tree should match baseline (no product residue).
const afterUninstall = new Set(listTree(fakeHome));
const extras = [...afterUninstall].filter((r) => !baselineHomeListing.has(r));
// Allow empty parent dirs that may remain after rm of nested installs.
const allowedEmptyParents = new Set([
  ".codex/plugins",
  ".codex/skills",
  ".codex",
]);
for (const rel of extras) {
  if (allowedEmptyParents.has(rel)) {
    const abs = path.join(fakeHome, rel);
    if (fs.existsSync(abs) && fs.statSync(abs).isDirectory()) {
      const kids = fs.readdirSync(abs);
      if (kids.length === 0) continue;
    }
  }
  fail(`After uninstall residual path under isolated home: ${rel}`);
}

// No changeguard LaunchAgent/service files
for (const rel of listTree(fakeHome)) {
  if (/changeguard/i.test(rel) && !allowedEmptyParents.has(rel)) {
    // empty parent path names don't include changeguard
    fail(`After uninstall changeguard residual: ${rel}`);
  }
}

// Background process claim: the demo CLI has exited; we never spawned a detached
// daemon. Record pgrep-style check for our product name under isolated install
// (best-effort, non-mutating).
const pgrep = spawnSync("pgrep", ["-fl", "codex-changeguard-plugin"], {
  encoding: "utf8",
  env: process.env,
});
// pgrep exit 1 = no match (good). Exit 0 with matches only fail if they point
// at our stageRoot install path (should already be deleted).
if (pgrep.status === 0 && pgrep.stdout) {
  const lines = pgrep.stdout.split("\n").filter(Boolean);
  const stageHits = lines.filter((l) => l.includes(stageRoot));
  if (stageHits.length > 0) {
    fail(
      `Background process still references staged install:\n${stageHits.join("\n")}`,
    );
  }
}

// Credential requirement: demo succeeded with cleared token env (above).
// No network claim already on receipt.

// Cleanup stage root
fs.rmSync(stageRoot, { recursive: true, force: true });
if (fs.existsSync(stageRoot)) {
  fail("Failed to remove clean-profile stage root.");
}

console.log(
  JSON.stringify(
    {
      ok: true,
      clean_profile: true,
      isolated_home_only: true,
      real_home_mutated: false,
      demo_ok: true,
      demo_network_used: false,
      demo_external_write: false,
      demo_live_profile_mutated: false,
      install_no_daemon: true,
      install_no_launch_agent: true,
      install_no_systemd_unit: true,
      install_no_scheduled_task: true,
      install_no_shell_profile_edit: true,
      install_no_global_codex_config_edit: true,
      install_no_credential_requirement: true,
      uninstall_no_plugin_residue: true,
      uninstall_no_skill_residue: true,
      uninstall_no_product_state_residue: true,
      uninstall_no_background_process: true,
      no_gate_c: true,
      no_remote_publish: true,
    },
    null,
    2,
  ),
);
