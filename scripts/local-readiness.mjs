/**
 * Ticket 17 S4 — local readiness aggregator.
 *
 * Runs product-local checks only:
 *   package structure, package demo smoke, clean-profile install/uninstall
 *   residual smoke, docs/link/parity/legal surface checks, production boundary,
 *   and relevant tests.
 *
 * Must NOT create a remote, release, account, upload, registration,
 * competition submission, or real GitHub write.
 *
 * Usage: node scripts/local-readiness.mjs
 * Exit 0 only when every step passes. Emits one JSON summary to stdout.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * @typedef {{ id: string, ok: boolean, exit_code: number, detail: string }} StepResult
 */

/** @type {StepResult[]} */
const steps = [];
let failed = null;

/**
 * @param {string} id
 * @param {string[]} command
 * @param {{ cwd?: string, env?: Record<string, string | undefined>, timeoutMs?: number }} [opts]
 */
function runStep(id, command, opts = {}) {
  if (failed) {
    steps.push({
      id,
      ok: false,
      exit_code: -1,
      detail: "skipped_after_failure",
    });
    return;
  }
  const res = spawnSync(command[0], command.slice(1), {
    cwd: opts.cwd ?? repoRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", ...(opts.env ?? {}) },
    maxBuffer: 64 * 1024 * 1024,
    timeout: opts.timeoutMs ?? 30 * 60 * 1000,
    shell: process.platform === "win32" && command[0] === "npm",
  });
  const code = res.status ?? 1;
  const ok = code === 0;
  const detail = ok
    ? "ok"
    : `exit=${code}${(res.stderr || res.stdout || "").slice(0, 400)}`;
  steps.push({ id, ok, exit_code: code, detail });
  if (!ok) {
    failed = id;
    if (res.stdout) process.stderr.write(res.stdout.slice(0, 8000));
    if (res.stderr) process.stderr.write(res.stderr.slice(0, 8000));
  }
}

/** Lightweight pure docs/legal/parity checks (no network). */
function checkDocsLegalParity() {
  if (failed) {
    steps.push({
      id: "docs_legal_parity",
      ok: false,
      exit_code: -1,
      detail: "skipped_after_failure",
    });
    return;
  }
  /** @type {string[]} */
  const errors = [];
  const en = path.join(repoRoot, "README.md");
  const zh = path.join(repoRoot, "README.zh-CN.md");
  const license = path.join(repoRoot, "LICENSE");
  const pkgJson = path.join(repoRoot, "package.json");
  for (const [p, label] of [
    [en, "README.md"],
    [zh, "README.zh-CN.md"],
    [license, "LICENSE"],
    [pkgJson, "package.json"],
  ]) {
    if (!fs.existsSync(p)) errors.push(`missing:${label}`);
  }
  if (errors.length === 0) {
    const enText = fs.readFileSync(en, "utf8");
    const zhText = fs.readFileSync(zh, "utf8");
    const licText = fs.readFileSync(license, "utf8");
    const pkg = JSON.parse(fs.readFileSync(pkgJson, "utf8"));

    if (pkg.private !== true) errors.push("package_not_private");
    if (pkg.license !== "MIT") errors.push("package_license_not_mit");
    if (!/MIT License/i.test(licText)) errors.push("license_text_not_mit");

    // Packaged judge path must be documented as available (no longer "future only").
    for (const [label, text] of [
      ["README.md", enText],
      ["README.zh-CN.md", zhText],
    ]) {
      if (!/node bin\/changeguard\.js demo/.test(text)) {
        errors.push(`${label}:missing_demo_command`);
      }
      if (!text.includes("Node.js >= 20")) {
        errors.push(`${label}:missing_node20`);
      }
      if (!/npm run package:smoke/.test(text)) {
        errors.push(`${label}:missing_package_smoke`);
      }
      if (!/npm run verify:release/.test(text)) {
        errors.push(`${label}:missing_verify_release`);
      }
      if (!/local-readiness|ready:local|npm run ready:local/.test(text)) {
        errors.push(`${label}:missing_local_readiness`);
      }
      // Must not claim Gate C / public release already done.
      if (/Gate C (is )?(authorized|complete|done)/i.test(text)) {
        errors.push(`${label}:false_gate_c_claim`);
      }
      // EN/ZH both must mention clean-profile uninstall residual theme.
      if (!/clean[- ]profile|干净 Profile|干净 profile/i.test(text)) {
        errors.push(`${label}:missing_clean_profile`);
      }
    }

    // Section-level parity: both must mention key themes.
    const themes = [
      { id: "demo", en: /changeguard\.js demo/, zh: /changeguard\.js demo/ },
      { id: "mit", en: /MIT/, zh: /MIT/ },
      { id: "gate_c", en: /Gate C/, zh: /Gate C/ },
      { id: "no_network", en: /[Nn]o network|无网络/, zh: /无网络|[Nn]o network/ },
    ];
    for (const t of themes) {
      if (!t.en.test(enText)) errors.push(`en_missing_theme:${t.id}`);
      if (!t.zh.test(zhText)) errors.push(`zh_missing_theme:${t.id}`);
    }

    // Source READMEs must keep handoff links (package transform strips them).
    if (!/\[Current handoff\]\(HANDOFF\.md\)/.test(enText)) {
      errors.push("en_missing_handoff_link");
    }
    if (!/\[当前交接\]\(HANDOFF\.md\)/.test(zhText)) {
      errors.push("zh_missing_handoff_link");
    }
    // Bilingual package surface: mutual language links in source READMEs.
    if (!/\[README\.zh-CN\.md\]\(README\.zh-CN\.md\)/.test(enText)) {
      errors.push("en_missing_zh_language_link");
    }
    if (!/\[README\.md\]\(README\.md\)/.test(zhText)) {
      errors.push("zh_missing_en_language_link");
    }
  }

  const ok = errors.length === 0;
  steps.push({
    id: "docs_legal_parity",
    ok,
    exit_code: ok ? 0 : 1,
    detail: ok ? "ok" : errors.join(";"),
  });
  if (!ok) failed = "docs_legal_parity";
}

/** Package structure when release/ tree exists (after package step). */
function checkPackageStructure() {
  if (failed) {
    steps.push({
      id: "package_structure",
      ok: false,
      exit_code: -1,
      detail: "skipped_after_failure",
    });
    return;
  }
  const pkgDir = path.join(repoRoot, "release", "codex-changeguard-plugin");
  /** @type {string[]} */
  const errors = [];
  if (!fs.existsSync(pkgDir)) {
    errors.push("package_dir_missing");
  } else {
    const allowed = new Set([
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
    const top = fs.readdirSync(pkgDir).sort();
    for (const n of top) {
      if (!allowed.has(n)) errors.push(`unexpected_top:${n}`);
    }
    for (const n of allowed) {
      if (!top.includes(n)) errors.push(`missing_top:${n}`);
    }
    const required = [
      "bin/changeguard.js",
      "dist/cli/main.js",
      "dist/core/demo/run-demo.js",
      "schemas/demo-receipt.schema.json",
      "LICENSE",
      "package.json",
      "README.md",
      "README.zh-CN.md",
    ];
    for (const rel of required) {
      if (!fs.existsSync(path.join(pkgDir, rel))) errors.push(`missing:${rel}`);
    }
    // Packaged bilingual READMEs: no HANDOFF links; mutual language links resolve.
    for (const name of ["README.md", "README.zh-CN.md"]) {
      const text = fs.readFileSync(path.join(pkgDir, name), "utf8");
      if (/\[[^\]]*\]\(\s*HANDOFF\.md(?:#[^)\s]*)?\s*\)/i.test(text)) {
        errors.push(`packaged_${name}_handoff_link`);
      }
    }
    const enPkg = fs.readFileSync(path.join(pkgDir, "README.md"), "utf8");
    const zhPkg = fs.readFileSync(path.join(pkgDir, "README.zh-CN.md"), "utf8");
    if (!/\[README\.zh-CN\.md\]\(README\.zh-CN\.md\)/.test(enPkg)) {
      errors.push("packaged_en_missing_zh_link");
    }
    if (!/\[README\.md\]\(README\.md\)/.test(zhPkg)) {
      errors.push("packaged_zh_missing_en_link");
    }
    for (const [label, text] of [
      ["README.md", enPkg],
      ["README.zh-CN.md", zhPkg],
    ]) {
      if (!/node bin\/changeguard\.js demo/.test(text)) {
        errors.push(`packaged_${label}_missing_demo`);
      }
    }
    // No source maps
    function walk(dir, relBase = "") {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
        if (ent.isDirectory()) walk(path.join(dir, ent.name), rel);
        else if (ent.name.endsWith(".map")) errors.push(`source_map:${rel}`);
      }
    }
    walk(pkgDir);
    if (fs.existsSync(path.join(pkgDir, "node_modules"))) {
      errors.push("node_modules_present");
    }
    if (fs.existsSync(path.join(pkgDir, "src"))) {
      errors.push("src_present");
    }
  }
  const ok = errors.length === 0;
  steps.push({
    id: "package_structure",
    ok,
    exit_code: ok ? 0 : 1,
    detail: ok ? "ok" : errors.join(";"),
  });
  if (!ok) failed = "package_structure";
}

// Ordered local readiness steps (local only; no Gate C / remote).
runStep("typecheck", ["npm", "run", "typecheck"]);
runStep("test", ["npm", "test"]);
runStep("boundary", ["npm", "run", "check:boundary"]);
runStep("package", ["npm", "run", "package"]);
checkPackageStructure();
runStep("package_smoke", ["npm", "run", "package:smoke"]);
runStep("clean_profile_smoke", ["npm", "run", "package:clean-profile"]);
checkDocsLegalParity();
// Full release gate remains local-only (no remote). Included for readiness.
runStep("verify_release", ["npm", "run", "verify:release"]);
runStep("diff_check", ["git", "diff", "--check"]);

const ok = failed === null && steps.every((s) => s.ok);
const summary = {
  ok,
  failed_step: failed,
  local_only: true,
  gate_c: false,
  remote_publish: false,
  registration: false,
  competition_submission: false,
  real_github_write: false,
  steps,
};

console.log(JSON.stringify(summary, null, 2));
process.exit(ok ? 0 : 1);
