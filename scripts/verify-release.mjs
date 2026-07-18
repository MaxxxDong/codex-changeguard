/**
 * Ticket 16 — canonical repository release / privacy / regression gate.
 *
 * Fail-closed orchestrator: ordered mandatory steps, bounded JSON summary
 * `{ok, failed_step, reason_code, steps}`, nonzero exit at first mandatory
 * failure with exact stable reason. Does not swallow failures.
 *
 * NOT the same as scripts/run-verification.sh (historical Worker log helper
 * that swallows exit codes). This script never invokes run-verification.sh.
 *
 * Usage:
 *   node scripts/verify-release.mjs
 *   node scripts/verify-release.mjs --self-test=<mode>
 *
 * Self-test modes (gate-of-gate negatives only; never production bypass):
 *   undercount | privacy_poison | missing_writer | schema_fail |
 *   package_secret | package_network | package_shell | package_daemon |
 *   package_binary | unknown_step | fixture_missing_test
 *
 * There is NO flag that makes verify:release report green while skipping a
 * mandatory step on the production path (selfTest === null).
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { MANDATORY_STEPS, REASON } from "./release-gate/reason-codes.mjs";
import {
  checkFixtureAccounting,
  FIXTURE_ACCOUNTING_ROWS,
  FIXTURE_THRESHOLDS,
} from "./release-gate/fixture-accounting.mjs";
import { checkSchemaGate, REQUIRED_SCHEMAS } from "./release-gate/schema-gate.mjs";
import { checkWritePathInventory, WRITE_PATH_INVENTORY } from "./release-gate/write-path-inventory.mjs";
import { checkInjectionMatrix } from "./release-gate/injection-matrix.mjs";
import { checkPrivacyCorpus, secretValues } from "./release-gate/privacy-corpus.mjs";
import { checkPackageAudit } from "./release-gate/package-audit.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** All self-test modes. Unknown values fail closed. */
const SELF_TEST_MODES = new Set([
  "undercount",
  "privacy_poison",
  "missing_writer",
  "schema_fail",
  "package_secret",
  "package_network",
  "package_shell",
  "package_daemon",
  "package_binary",
  "unknown_step",
  "fixture_missing_test",
]);

const PACKAGE_PLANT_MODES = new Set([
  "package_secret",
  "package_network",
  "package_shell",
  "package_daemon",
  "package_binary",
]);

/**
 * Pure-only self-tests exercise one pure step and skip all other steps so
 * gate-of-gate tests stay fast and do not recurse into npm test.
 * Production (selfTest === null) never uses this map.
 */
const PURE_SELF_TEST_STEP = Object.freeze({
  undercount: "fixture_accounting",
  fixture_missing_test: "fixture_accounting",
  privacy_poison: "privacy",
  missing_writer: "write_path",
  schema_fail: "schema",
});

/**
 * @param {string[]} argv
 * @returns {{ selfTest: string | null, jsonOnly: boolean, error: string | null }}
 */
function parseArgs(argv) {
  /** @type {{ selfTest: string | null, jsonOnly: boolean, error: string | null }} */
  const out = { selfTest: null, jsonOnly: false, error: null };
  for (const a of argv) {
    if (a.startsWith("--self-test=")) {
      const mode = a.slice("--self-test=".length);
      if (!mode || !SELF_TEST_MODES.has(mode)) {
        out.error = `unknown_self_test:${mode || "empty"}`;
        return out;
      }
      out.selfTest = mode;
    } else if (a === "--json-only") {
      out.jsonOnly = true;
    } else {
      out.error = `unknown_arg:${a}`;
      return out;
    }
  }
  return out;
}

/**
 * @param {typeof MANDATORY_STEPS[number]} step
 * @param {{ selfTest: string | null }} ctx
 */
async function runPureStep(step, ctx) {
  switch (step.pure) {
    case "schema": {
      if (ctx.selfTest === "schema_fail") {
        return checkSchemaGate(repoRoot, {
          schemas: [...REQUIRED_SCHEMAS, "definitely-missing-ticket16.schema.json"],
        });
      }
      return checkSchemaGate(repoRoot);
    }
    case "fixture_accounting": {
      if (ctx.selfTest === "undercount") {
        return checkFixtureAccounting(repoRoot, {
          rows: FIXTURE_ACCOUNTING_ROWS.filter((r) => r.bucket === "resolved_verified").slice(0, 1),
          thresholds: FIXTURE_THRESHOLDS,
        });
      }
      if (ctx.selfTest === "fixture_missing_test") {
        return checkFixtureAccounting(repoRoot, {
          rows: [
            {
              id: "poison-missing",
              bucket: "resolved_verified",
              expected_status: "RESOLVED_VERIFIED",
              fixture: "fixtures/protected-process",
              public_seam: "none",
              test_file: "tests/does-not-exist-ticket16.test.ts",
              test_name_substr: "never",
            },
          ],
          thresholds: { resolved_verified: 1, mitigation_or_upstream_blocked: 0, wrong_repair_refusal: 0 },
        });
      }
      return checkFixtureAccounting(repoRoot);
    }
    case "privacy": {
      if (ctx.selfTest === "privacy_poison") {
        const secrets = secretValues();
        return checkPrivacyCorpus(repoRoot, {
          poisonPayload: {
            transport_request: { body: secrets[0], nested: { token: secrets[0] } },
            doctor_export: secrets[1],
          },
        });
      }
      return checkPrivacyCorpus(repoRoot);
    }
    case "injection": {
      return checkInjectionMatrix(repoRoot);
    }
    case "write_path": {
      if (ctx.selfTest === "missing_writer") {
        return checkWritePathInventory(repoRoot, {
          inventory: WRITE_PATH_INVENTORY.filter((e) => e.id !== "recovery-atomic-write"),
        });
      }
      return checkWritePathInventory(repoRoot);
    }
    case "package_audit": {
      if (ctx.selfTest === "package_secret") {
        return checkPackageAudit(repoRoot, {
          plant: {
            rel: "dist/__t16_planted_secret.js",
            content: "export const x = 'cg-t16-planted-package-secret';\n",
          },
        });
      }
      if (ctx.selfTest === "package_network") {
        return checkPackageAudit(repoRoot, {
          plant: {
            rel: "dist/__t16_planted_net.js",
            content: 'import http from "node:http";\nexport const h = http;\n',
          },
        });
      }
      if (ctx.selfTest === "package_shell") {
        return checkPackageAudit(repoRoot, {
          plant: {
            rel: "dist/__t16_planted_shell.js",
            content: 'import { spawnSync } from "node:child_process";\nspawnSync("sh", ["-c", "echo x"]);\n',
          },
        });
      }
      if (ctx.selfTest === "package_daemon") {
        return checkPackageAudit(repoRoot, {
          plant: {
            rel: "dist/__t16_planted_daemon.js",
            content: "setInterval(() => {}, 1000);\n",
          },
        });
      }
      if (ctx.selfTest === "package_binary") {
        return checkPackageAudit(repoRoot, {
          plant: {
            rel: "dist/Codex.exe",
            content: "MZ" + "\0".repeat(100) + "fake-openai-binary-not-real",
          },
        });
      }
      return checkPackageAudit(repoRoot);
    }
    default:
      return {
        ok: false,
        reason_code: REASON.GATE_UNKNOWN_STEP,
        detail: `unknown_pure:${step.pure}`,
      };
  }
}

/**
 * @param {string[]} command
 * @param {string} reason
 */
function runExternal(command, reason) {
  const [cmd, ...args] = command;
  const res = spawnSync(cmd, args, {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    shell: process.platform === "win32",
    maxBuffer: 64 * 1024 * 1024,
  });
  const code = res.status ?? 1;
  return {
    ok: code === 0,
    reason_code: code === 0 ? null : reason,
    exit_code: code,
    detail: code === 0 ? "ok" : "command_failed",
  };
}

/**
 * Whether a step should be skipped during a self-test.
 * Production path (selfTest === null) always returns false — never skips.
 *
 * Pure-only modes run only the pure step under test.
 * Package-plant modes run only `package` (if needed externally) + pure package_audit.
 * Never used to green-wash production verify:release.
 *
 * @param {string | null} selfTest
 * @param {typeof MANDATORY_STEPS[number]} step
 */
function shouldSkipForSelfTest(selfTest, step) {
  if (!selfTest) return false;

  const pureTarget = PURE_SELF_TEST_STEP[selfTest];
  if (pureTarget) {
    // Only the pure step under test executes; everything else is skipped for speed.
    return !(step.kind === "pure" && step.id === pureTarget);
  }

  if (PACKAGE_PLANT_MODES.has(selfTest)) {
    // Only package build + package_audit (with isolated plant inside audit).
    if (step.id === "package") return false;
    if (step.kind === "pure" && step.pure === "package_audit") return false;
    return true;
  }

  // unknown_step handled before the loop
  return false;
}

/**
 * @param {{ selfTest: string | null }} ctx
 */
async function runGate(ctx) {
  /** @type {{ id: string, ok: boolean, reason_code: string | null, detail?: string }[]} */
  const steps = [];

  if (ctx.selfTest === "unknown_step") {
    steps.push({
      id: "unknown_forced",
      ok: false,
      reason_code: REASON.GATE_UNKNOWN_STEP,
      detail: "self_test_unknown_step",
    });
    return {
      ok: false,
      failed_step: "unknown_forced",
      reason_code: REASON.GATE_UNKNOWN_STEP,
      steps,
    };
  }

  for (const step of MANDATORY_STEPS) {
    if (ctx.selfTest && shouldSkipForSelfTest(ctx.selfTest, step)) {
      steps.push({
        id: step.id,
        ok: true,
        reason_code: null,
        detail: "self_test_skip_not_under_test",
      });
      continue;
    }

    let result;
    if (step.kind === "pure") {
      result = await runPureStep(step, ctx);
    } else if (step.kind === "npm" || step.kind === "node" || step.kind === "shell") {
      result = runExternal(step.command, step.reason);
    } else {
      result = {
        ok: false,
        reason_code: REASON.GATE_UNKNOWN_STEP,
        detail: `unknown_kind:${step.kind}`,
      };
    }

    const ok = result.ok === true;
    steps.push({
      id: step.id,
      ok,
      reason_code: ok ? null : result.reason_code ?? step.reason,
      detail: result.detail,
    });

    if (!ok) {
      return {
        ok: false,
        failed_step: step.id,
        reason_code: result.reason_code ?? step.reason,
        steps,
      };
    }
  }

  return {
    ok: true,
    failed_step: null,
    reason_code: null,
    steps,
  };
}

/**
 * Ensure package tree exists for package-plant self-tests (isolated plant still
 * copies inside checkPackageAudit). Does not skip any production step.
 */
function ensurePackageForPlantSelfTest() {
  const pkg = path.join(repoRoot, "release", "codex-changeguard-plugin");
  if (fs.existsSync(path.join(pkg, "bin/changeguard.js"))) {
    return { ok: true };
  }
  return runExternal(["npm", "run", "package"], REASON.GATE_PACKAGE);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.error) {
    const summary = {
      ok: false,
      failed_step: "orchestrator",
      reason_code: REASON.GATE_UNKNOWN_STEP,
      steps: [
        {
          id: "orchestrator",
          ok: false,
          reason_code: REASON.GATE_UNKNOWN_STEP,
          detail: args.error,
        },
      ],
    };
    console.log(JSON.stringify(summary, null, 2));
    process.exit(1);
  }

  if (args.selfTest && PACKAGE_PLANT_MODES.has(args.selfTest)) {
    const built = ensurePackageForPlantSelfTest();
    if (!built.ok) {
      const summary = {
        ok: false,
        failed_step: "package",
        reason_code: REASON.GATE_PACKAGE,
        steps: [
          {
            id: "package",
            ok: false,
            reason_code: REASON.GATE_PACKAGE,
            detail: "prebuild_for_self_test",
          },
        ],
      };
      console.log(JSON.stringify(summary, null, 2));
      process.exit(1);
    }
  }

  const summary = await runGate({ selfTest: args.selfTest });
  console.log(JSON.stringify(summary, null, 2));
  process.exit(summary.ok ? 0 : 1);
}

main().catch((err) => {
  const summary = {
    ok: false,
    failed_step: "orchestrator",
    reason_code: REASON.GATE_UNKNOWN_STEP,
    steps: [
      {
        id: "orchestrator",
        ok: false,
        reason_code: REASON.GATE_UNKNOWN_STEP,
        detail: "orchestrator_throw",
      },
    ],
  };
  console.log(JSON.stringify(summary, null, 2));
  // Do not print err stacks that might contain paths with secrets; message only
  console.error(String(err && err.message ? err.message : err));
  process.exit(1);
});
