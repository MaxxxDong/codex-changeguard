/**
 * Real-machine isolated macOS Scenario Harness entry (Ticket 13).
 *
 * Usage:
 *   node scripts/run-macos-harness.mjs [--out=<dir>]
 *
 * Requires: darwin host and prior `npm run build` (or `npm test` compile of
 * dist-tests). The package_smoke scenario is self-contained: it always runs
 * production `npm run package` before package:smoke / packaged diagnose, so a
 * missing or stale T11-era release tree is rebuilt in-scenario.
 * Writes a path-free PlatformSupportReceipt JSON under --out (default
 * .grok-output/verification when present).
 *
 * Never touches ~/.codex or system protected roots. No sudo.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fail(msg, code = 1) {
  console.error(msg);
  process.exit(code);
}

if (process.platform !== "darwin") {
  fail("run-macos-harness requires macOS (darwin).", 2);
}

// Ensure compiled harness exists.
const harnessJs = path.join(repoRoot, "dist-tests/src/harness/macos-scenario.js");
const harnessSrcFallback = path.join(repoRoot, "dist/harness/macos-scenario.js");

function ensureBuilt() {
  if (fs.existsSync(harnessJs) || fs.existsSync(harnessSrcFallback)) return;
  const build = spawnSync("npm", ["run", "build"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: process.env,
    shell: process.platform === "win32",
  });
  if (build.status !== 0) {
    process.stderr.write(build.stdout || "");
    process.stderr.write(build.stderr || "");
    fail("build failed");
  }
  // Compile tests+src so harness (under src/harness) is available via dist-tests.
  const tsc = spawnSync(
    "npx",
    ["tsc", "-p", "tsconfig.tests.json"],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: process.env,
      shell: process.platform === "win32",
    },
  );
  if (tsc.status !== 0) {
    process.stderr.write(tsc.stdout || "");
    process.stderr.write(tsc.stderr || "");
    fail("tsc tests compile failed");
  }
}

ensureBuilt();

let outDir = null;
for (const a of process.argv.slice(2)) {
  if (a.startsWith("--out=")) {
    outDir = a.slice("--out=".length);
  } else if (a === "--help" || a === "-h") {
    console.log("Usage: node scripts/run-macos-harness.mjs [--out=<dir>]");
    process.exit(0);
  } else {
    fail(`Unknown argument: ${a}`);
  }
}

const modulePath = fs.existsSync(harnessJs)
  ? harnessJs
  : harnessSrcFallback;

if (!fs.existsSync(modulePath)) {
  fail(`Harness module missing after build: ${modulePath}`);
}

const mod = await import(pathToFileURL(modulePath).href);
const {
  runMacosScenarioHarness,
  publicHarnessSummary,
} = mod;

const result = runMacosScenarioHarness({
  outDir:
    outDir ??
    (fs.existsSync(path.join(repoRoot, ".grok-output"))
      ? path.join(repoRoot, ".grok-output", "verification")
      : undefined),
  requirePackage: true,
});

const summary = publicHarnessSummary(result);
// Public summary only — never print raw receipt_abs to stdout in CI logs if it
// embeds temp paths; still include support level and scenario table.
console.log(JSON.stringify(summary, null, 2));

// Write a path-free summary beside the receipt for inspectors.
const summaryPath = path.join(
  path.dirname(result.receipt_abs),
  "macos-platform-support-summary.json",
);
fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2) + "\n", "utf8");

process.exit(result.exit_code);
