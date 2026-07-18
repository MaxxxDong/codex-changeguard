/**
 * Real-machine isolated macOS Scenario Harness (Ticket 13).
 *
 * Invokes public CLI surfaces against disposable temp fixtures only.
 * Never touches the active ~/.codex profile, never uses sudo, never mutates
 * signed apps or protected system roots. Receipt contains no username/raw paths.
 *
 * Not imported by production CLI/MCP entrypoints (uses child_process for
 * black-box CLI invocation). Entry points: scripts/run-macos-harness.mjs,
 * tests, and package-local harness runners.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { findRepoRoot } from "../paths.js";
import {
  assertDisposableTarget,
  type DisposableTargetOptions,
  buildMacosCapabilities,
  buildPlatformSupportReceipt,
  captureActiveCodexHomeWitness,
  enumerateMacosCandidates,
  hostCoarseFingerprintOf,
  isolationDigestOf,
  readMacosCodexVersionProvenance,
  scenarioHashOf,
  scenariosDigestOf,
  sealLiveHarnessWitness,
  validatePlatformSupportReceipt,
  type PlatformSupportReceipt,
  type ScenarioOutcome,
} from "../platform/index.js";
import { INDUCE_VERIFY_FAIL_REL } from "../core/recovery/index.js";
import {
  copyFixtureToTemp,
  hashTargetTree,
  runCliJson,
  runCliDiagnose,
  runCliRepairPreview,
  runCliRepairApply,
  runCliRollback,
  cliEntry,
} from "./scenario.js";

const repoRoot = findRepoRoot(import.meta.url);

function nowIso(): string {
  return new Date().toISOString();
}

function tryRealpath(abs: string): string | null {
  try {
    return fs.realpathSync.native(abs);
  } catch {
    return null;
  }
}

/**
 * Cleanup a just-created harness path only when it is proven not to sit under
 * active Codex / protected roots (assertDisposableTarget deny classes).
 */
function safeRemoveJustCreated(
  createdAbs: string,
  home: string | null,
): void {
  const resolved = path.resolve(createdAbs);
  // Refuse cleanup when the path classifies as active/protected (or is a symlink).
  const gate = assertDisposableTarget(resolved, home, {
    requireTrustedRoot: false,
  });
  if (!gate.ok) {
    if (
      gate.code === "ACTIVE_CODEX_PROFILE_REFUSED" ||
      gate.code === "PROTECTED_ROOT_REFUSED" ||
      gate.code === "HOME_ROOT_REFUSED" ||
      gate.code === "SYMLINK_REFUSED"
    ) {
      return;
    }
  }
  try {
    const lst = fs.lstatSync(resolved);
    if (lst.isSymbolicLink()) return;
    // Re-check realpath before rm.
    const real = tryRealpath(resolved);
    if (real) {
      const realGate = assertDisposableTarget(real, home, {
        requireTrustedRoot: false,
      });
      if (
        !realGate.ok &&
        (realGate.code === "ACTIVE_CODEX_PROFILE_REFUSED" ||
          realGate.code === "PROTECTED_ROOT_REFUSED" ||
          realGate.code === "HOME_ROOT_REFUSED")
      ) {
        return;
      }
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}

/**
 * Gate-before-write for a harness output / disposable directory:
 * assert parent/canonical leaf → mkdir → re-assert; cleanup only just-created
 * paths proven outside active/protected.
 */
export function ensureDisposableDirectory(
  targetAbs: string,
  homeDir?: string | null,
  options: DisposableTargetOptions = {},
): { ok: true; real: string } | { ok: false; code: string } {
  const home =
    homeDir ??
    process.env.HOME ??
    process.env.USERPROFILE ??
    null;
  const resolved = path.resolve(targetAbs);

  const pre = assertDisposableTarget(resolved, home, {
    requireTrustedRoot: true,
    ...options,
  });
  if (!pre.ok) return pre;

  let alreadyPresent = false;
  try {
    fs.lstatSync(resolved);
    alreadyPresent = true;
  } catch {
    alreadyPresent = false;
  }

  let highestMissing: string | null = null;
  if (!alreadyPresent) {
    let cursor = resolved;
    while (cursor !== path.dirname(cursor)) {
      try {
        fs.lstatSync(cursor);
        break;
      } catch {
        highestMissing = cursor;
        cursor = path.dirname(cursor);
      }
    }
    try {
      fs.mkdirSync(resolved, { recursive: true });
    } catch {
      return { ok: false, code: "MKDIR_FAILED" };
    }
  }

  const post = assertDisposableTarget(resolved, home, {
    requireTrustedRoot: true,
    ...options,
  });
  if (!post.ok) {
    if (!alreadyPresent && highestMissing) {
      safeRemoveJustCreated(highestMissing, home);
    }
    return post;
  }
  return post;
}

/**
 * Gate-before-write mkdtemp under os.tmpdir():
 * verify os.tmpdir()/TMPDIR real paths vs active/protected/untrusted first,
 * then mkdtemp, then re-assert. Never creates under active real or alias.
 */
export function createDisposableTempRoot(
  prefix: string,
  homeDir?: string | null,
  options: DisposableTargetOptions = {},
): { ok: true; path: string; real: string } | { ok: false; code: string } {
  const home =
    homeDir ??
    process.env.HOME ??
    process.env.USERPROFILE ??
    null;

  if (
    typeof prefix !== "string" ||
    prefix.length === 0 ||
    prefix.length > 64 ||
    prefix.includes("\0") ||
    prefix.includes("..") ||
    prefix.includes(path.sep) ||
    prefix.includes("/") ||
    prefix.includes("\\")
  ) {
    return { ok: false, code: "INVALID_TARGET" };
  }

  const tmpBase = os.tmpdir();
  const bases = new Set<string>();
  bases.add(path.resolve(tmpBase));
  if (process.env.TMPDIR) bases.add(path.resolve(process.env.TMPDIR));
  if (process.env.TMP) bases.add(path.resolve(process.env.TMP));
  if (process.env.TEMP) bases.add(path.resolve(process.env.TEMP));

  for (const base of bases) {
    // Temp bases may be symlinks (macOS /tmp → /private/tmp). Check realpath.
    const baseReal = tryRealpath(base);
    if (!baseReal) {
      return { ok: false, code: "REALPATH_UNPROVABLE" };
    }
    const baseGate = assertDisposableTarget(baseReal, home, {
      requireTrustedRoot: true,
      ...options,
    });
    if (!baseGate.ok) {
      return baseGate;
    }
  }

  let root: string;
  try {
    root = fs.mkdtempSync(path.join(tmpBase, prefix));
  } catch {
    return { ok: false, code: "MKDTEMP_FAILED" };
  }

  const post = assertDisposableTarget(root, home, {
    requireTrustedRoot: true,
    ...options,
  });
  if (!post.ok) {
    safeRemoveJustCreated(root, home);
    return post;
  }
  return { ok: true, path: root, real: post.real };
}

/**
 * Create a unique disposable temp root with gate-before-write.
 * Never creates an inode under active Codex real targets or aliases.
 */
function makeDisposableRoot(prefix: string): string {
  const created = createDisposableTempRoot(prefix);
  if (!created.ok) {
    throw new Error(`Harness isolation refused temp root: ${created.code}`);
  }
  return created.path;
}

function packageVersion(): string {
  try {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"),
    ) as { version?: string };
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function gitCommitSafe(): string | null {
  try {
    const res = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    if (res.status === 0 && res.stdout) {
      const sha = res.stdout.trim();
      if (/^[0-9a-f]{7,64}$/i.test(sha)) return sha;
    }
  } catch {
    /* unavailable */
  }
  return null;
}

function assertNoLeak(text: string): void {
  if (/\/Users\//.test(text)) throw new Error("Users path leak in CLI output");
  if (/\.grok-disposable/.test(text)) {
    throw new Error("disposable path leak in CLI output");
  }
  if (/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text)) {
    throw new Error("Bearer leak in CLI output");
  }
}

/**
 * Path-free failure snippet for scenario summaries (package vs smoke vs diagnose).
 * Never embeds home/temp/disposable clone paths.
 */
function spawnFailureReason(
  phase: "package_build" | "package_smoke" | "packaged_diagnose",
  res: {
    status: number | null;
    signal?: NodeJS.Signals | null;
    stdout?: string | null;
    stderr?: string | null;
    error?: Error | null;
  },
): string {
  const label =
    phase === "package_build"
      ? "package build failed"
      : phase === "package_smoke"
        ? "package:smoke failed"
        : "packaged diagnose failed";
  const raw = [
    res.error?.message ?? "",
    res.stderr ?? "",
    res.stdout ?? "",
    res.signal ? `signal=${res.signal}` : "",
    `exit=${res.status ?? "null"}`,
  ].join("\n");
  const scrubbed = raw
    .replace(/\/Users\/[^\s"'`]+/g, "<path>")
    .replace(/\/var\/folders\/[^\s"'`]+/g, "<path>")
    .replace(/\/private\/var\/folders\/[^\s"'`]+/g, "<path>")
    .replace(/\/tmp\/[^\s"'`]+/g, "<path>")
    .replace(/\.grok-disposable\/[^\s"'`]+/g, "<path>")
    .replace(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi, "Bearer <redacted>");
  const lines = scrubbed
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !/^npm (error|err!|warn)/i.test(l));
  const detail =
    lines.find((l) =>
      /Package|missing|failed|Error|docs|SUPPORT_MATRIX|top-level|MODULE_NOT_FOUND/i.test(
        l,
      ),
    ) ??
    lines[lines.length - 1] ??
    `exit=${res.status ?? "null"}`;
  return `${label}: ${detail.slice(0, 180)}`.slice(0, 240);
}

export interface PackageSmokeScenarioOptions {
  /** When false, package:smoke failure is recorded as skipped instead of fail. */
  requirePackage?: boolean;
}

export interface PackageSmokeScenarioResult {
  status: "pass" | "fail" | "skipped";
  summary: string;
  /** Which phase failed, when status is fail/skipped for smoke. */
  failed_phase?: "package_build" | "package_smoke" | "packaged_diagnose";
}

/**
 * Self-contained package_smoke scenario body.
 *
 * Always runs production `npm run package` first, then `package:smoke`, then a
 * packaged CLI diagnose against a disposable fixture. Does not depend on test
 * order, residual release trees, or a prior manual package step. Stale T11-era
 * release artifacts (e.g. missing SUPPORT_MATRIX.md) are overwritten by the
 * rebuild. Offline only (no network).
 */
export function runPackageSmokeScenario(
  options: PackageSmokeScenarioOptions = {},
): PackageSmokeScenarioResult {
  const pkgDir = path.join(repoRoot, "release/codex-changeguard-plugin");

  // Always rebuild the production package so old/missing release cannot
  // spuriously pass (fresh clone has new tree) or fail (stale T11 tree).
  const pack = spawnSync("npm", ["run", "package"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    maxBuffer: 8 * 1024 * 1024,
  });
  if (pack.status !== 0) {
    return {
      status: "fail",
      summary: spawnFailureReason("package_build", pack),
      failed_phase: "package_build",
    };
  }
  if (!fs.existsSync(path.join(pkgDir, "bin/changeguard.js"))) {
    return {
      status: "fail",
      summary: "package build failed: package missing bin/changeguard.js after npm run package",
      failed_phase: "package_build",
    };
  }

  const smoke = spawnSync("npm", ["run", "package:smoke"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    maxBuffer: 8 * 1024 * 1024,
  });
  if (smoke.status !== 0) {
    return {
      status: options.requirePackage === false ? "skipped" : "fail",
      summary: spawnFailureReason("package_smoke", smoke),
      failed_phase: "package_smoke",
    };
  }

  // Packaged CLI diagnose on a disposable fixture (black-box, outside residual state).
  const tmp = makeDisposableRoot("cg-m13-psmoke-");
  const target = copyFixtureToTemp("fixtures/negative-control", tmp);
  const packagedCli = path.join(pkgDir, "bin/changeguard.js");
  const diag = spawnSync(process.execPath, [packagedCli, "diagnose", target], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    maxBuffer: 4 * 1024 * 1024,
  });
  if (diag.status !== 0) {
    return {
      status: "fail",
      summary: spawnFailureReason("packaged_diagnose", diag),
      failed_phase: "packaged_diagnose",
    };
  }
  assertNoLeak(diag.stdout ?? "");
  return {
    status: "pass",
    summary: "package build + package:smoke + packaged diagnose ok",
  };
}

function authFromPreview(result: Record<string, unknown>): string {
  const auth = result.authorization;
  if (typeof auth !== "string" || !auth.startsWith("cg1.")) {
    throw new Error("preview authorization missing");
  }
  return auth;
}

function buildMultiInstanceInventory(tmp: string): string {
  const root = path.join(tmp, "inventory");
  fs.mkdirSync(root, { recursive: true });
  const candidates = [
    {
      install_source: "desktop_bundled",
      surface: "desktop",
      relative_path: "apps/Codex.app/Contents/MacOS/Codex",
      version: "0.50.0",
      profile_root_alias: "DESKTOP_PROFILE",
    },
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path-bin/codex",
      version: "0.51.0",
      path_precedence: 0,
    },
    {
      install_source: "package_manager",
      surface: "cli",
      relative_path: "pkg/bin/codex",
      version: "0.49.0",
    },
  ];
  for (const c of candidates) {
    const abs = path.join(root, c.relative_path);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, "#!/bin/sh\n# fixture — never executed\n", "utf8");
    fs.writeFileSync(
      path.join(path.dirname(abs), "version.json"),
      JSON.stringify({ version: c.version, build: null }) + "\n",
      "utf8",
    );
  }
  fs.writeFileSync(
    path.join(root, "inventory.json"),
    JSON.stringify(
      {
        schema_version: 1,
        platform: "macos",
        arch: process.arch || "arm64",
        candidates: candidates.map((c) => ({
          install_source: c.install_source,
          surface: c.surface,
          relative_path: c.relative_path,
          path_precedence: "path_precedence" in c ? c.path_precedence : null,
          profile_root_alias:
            "profile_root_alias" in c ? c.profile_root_alias : null,
          config_root_alias: null,
          version_metadata_rel: path.posix.join(
            path.dirname(c.relative_path).split(path.sep).join("/"),
            "version.json",
          ),
        })),
      },
      null,
      2,
    ) + "\n",
    "utf8",
  );
  return root;
}

type ScenarioRunner = () => {
  status: "pass" | "fail" | "skipped";
  summary: string;
};

function runScenario(
  scenario_id: string,
  fixtureId: string,
  required: boolean,
  fn: ScenarioRunner,
): ScenarioOutcome {
  const t0 = performance.now();
  try {
    const out = fn();
    return {
      scenario_id,
      scenario_hash: scenarioHashOf(scenario_id, fixtureId),
      status: out.status,
      outcome_summary: out.summary.slice(0, 240),
      duration_ms: Math.round(performance.now() - t0),
      required,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "unknown_error";
    return {
      scenario_id,
      scenario_hash: scenarioHashOf(scenario_id, fixtureId),
      status: "fail",
      outcome_summary: msg.slice(0, 240),
      duration_ms: Math.round(performance.now() - t0),
      required,
    };
  }
}

export interface MacosHarnessOptions {
  /** Directory to write receipt JSON (default: under repo .grok-output if present, else temp). */
  outDir?: string;
  /** Skip package smoke when dist package is absent. */
  requirePackage?: boolean;
}

export interface MacosHarnessResult {
  receipt: PlatformSupportReceipt;
  receipt_path_alias: "PLATFORM_SUPPORT_RECEIPT";
  /** Absolute path for the runner only — not embedded in receipt. */
  receipt_abs: string;
  validation_ok: boolean;
  exit_code: number;
}

/**
 * Run the full real-machine macOS Scenario Harness on this host.
 * Refuses non-darwin platforms.
 */
export function runMacosScenarioHarness(
  options: MacosHarnessOptions = {},
): MacosHarnessResult {
  if (process.platform !== "darwin") {
    throw new Error("macos_harness_requires_darwin");
  }

  const started_at = nowIso();
  const arch = process.arch || "unknown";
  const capabilities = buildMacosCapabilities({ platform: "macos", arch });
  const hostCandidates = enumerateMacosCandidates({
    platform: "macos",
    arch,
    probeHost: true,
  });
  const codexProv = readMacosCodexVersionProvenance(hostCandidates);

  // Isolation proof: active ~/.codex must not be a harness target.
  const home = process.env.HOME ?? null;
  if (home) {
    const active = path.join(home, ".codex");
    const denied = assertDisposableTarget(active, home, {
      requireTrustedRoot: false,
    });
    if (denied.ok) {
      // Should never be ok for active profile — force fail closed.
      throw new Error("isolation_active_profile_check_broken");
    }
  }

  // Capture path-free active-home witness BEFORE any scenario mutation.
  const activeWitnessBefore = captureActiveCodexHomeWitness(home);

  const scenarios: ScenarioOutcome[] = [];

  // 1) Core read-only detection (protected-process + negative control)
  scenarios.push(
    runScenario("core_read_only_detection", "protected-process+negative", true, () => {
      const tmp = makeDisposableRoot("cg-m13-core-");
      const pos = copyFixtureToTemp("fixtures/protected-process", tmp);
      const neg = copyFixtureToTemp("fixtures/negative-control", tmp);
      const beforeP = hashTargetTree(pos);
      const beforeN = hashTargetTree(neg);
      const p = runCliDiagnose(pos);
      const n = runCliDiagnose(neg);
      assertNoLeak(p.stdout + n.stdout);
      if (p.exitCode !== 0 || !p.result?.ok) {
        return { status: "fail", summary: "positive diagnose failed" };
      }
      if (n.exitCode !== 0 || !n.result) {
        return { status: "fail", summary: "negative diagnose failed" };
      }
      if (p.result.repair_applied !== false || p.result.target_mutated !== false) {
        return { status: "fail", summary: "diagnose mutated target" };
      }
      if (p.result.network_used !== false) {
        return { status: "fail", summary: "network used" };
      }
      if (hashTargetTree(pos) !== beforeP || hashTargetTree(neg) !== beforeN) {
        return { status: "fail", summary: "target tree mutated" };
      }
      // Positive should locate component; negative stays inconclusive.
      if (p.result.diagnosis_state === "INCONCLUSIVE" && n.result.diagnosis_state !== "INCONCLUSIVE") {
        return { status: "fail", summary: "controls not separable" };
      }
      return {
        status: "pass",
        summary: `states pos=${p.result.diagnosis_state} neg=${n.result.diagnosis_state}`,
      };
    }),
  );

  // 2) Multi-instance scan
  scenarios.push(
    runScenario("multi_instance_scan", "synthetic-macos-inventory", true, () => {
      const tmp = makeDisposableRoot("cg-m13-scan-");
      const inv = buildMultiInstanceInventory(tmp);
      const check = assertDisposableTarget(inv);
      if (!check.ok) return { status: "fail", summary: check.code };
      const scan = runCliJson(["scan", inv]);
      assertNoLeak(scan.stdout);
      if (scan.exitCode !== 0 || !scan.result?.ok) {
        return { status: "fail", summary: "scan failed" };
      }
      const instances = scan.result.instances as unknown[];
      if (!Array.isArray(instances) || instances.length < 2) {
        return { status: "fail", summary: "expected multi-instance" };
      }
      if (scan.stdout.includes(inv) || /\/Users\//.test(scan.stdout)) {
        return { status: "fail", summary: "raw path leak" };
      }
      return {
        status: "pass",
        summary: `instances=${instances.length} primary=${String(scan.result.primary_transition)}`,
      };
    }),
  );

  // 3) Config repair success
  scenarios.push(
    runScenario("config_repair_success", "config-wrong-type", true, () => {
      const tmp = makeDisposableRoot("cg-m13-cfg-");
      const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
      const preview = runCliRepairPreview(target);
      assertNoLeak(preview.stdout);
      if (preview.exitCode !== 0 || !preview.result?.ok) {
        return { status: "fail", summary: "preview failed" };
      }
      const auth = authFromPreview(preview.result);
      const apply = runCliRepairApply(target, auth);
      assertNoLeak(apply.stdout);
      if (apply.exitCode !== 0 || !apply.result?.ok) {
        return { status: "fail", summary: "apply failed" };
      }
      if (apply.result.repair_applied !== true) {
        return { status: "fail", summary: "repair_applied false" };
      }
      if (apply.result.auto_rolled_back === true) {
        return { status: "fail", summary: "unexpected auto rollback" };
      }
      const status = (apply.result.user_resolution as { status?: string })?.status;
      if (status !== "RESOLVED_VERIFIED") {
        return { status: "fail", summary: `status=${status}` };
      }
      return { status: "pass", summary: "RESOLVED_VERIFIED config_set" };
    }),
  );

  // 4) Forced verification failure → auto-rollback
  scenarios.push(
    runScenario(
      "forced_verify_fail_auto_rollback",
      "config-wrong-type+induce",
      true,
      () => {
        const tmp = makeDisposableRoot("cg-m13-auto-");
        const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
        const configPath = path.join(target, "config/config.toml");
        const original = fs.readFileSync(configPath);
        const preview = runCliRepairPreview(target);
        if (preview.exitCode !== 0 || !preview.result?.ok) {
          return { status: "fail", summary: "preview failed" };
        }
        // Induce verify failure after preview (before apply).
        fs.mkdirSync(path.join(target, ".changeguard"), { recursive: true });
        fs.writeFileSync(
          path.join(target, INDUCE_VERIFY_FAIL_REL),
          "1\n",
          "utf8",
        );
        const auth = authFromPreview(preview.result);
        const apply = runCliRepairApply(target, auth);
        assertNoLeak(apply.stdout);
        if (!apply.result) return { status: "fail", summary: "no apply result" };
        if (apply.result.auto_rolled_back !== true) {
          return { status: "fail", summary: "expected auto_rolled_back" };
        }
        const after = fs.readFileSync(configPath);
        if (!after.equals(original)) {
          return { status: "fail", summary: "bytes not restored" };
        }
        const status = (apply.result.user_resolution as { status?: string })?.status;
        if (status === "RESOLVED_VERIFIED") {
          return { status: "fail", summary: "must not claim RESOLVED_VERIFIED" };
        }
        return {
          status: "pass",
          summary: `auto_rolled_back status=${status ?? "n/a"}`,
        };
      },
    ),
  );

  // 5) Explicit rollback after successful repair
  scenarios.push(
    runScenario("explicit_rollback", "config-wrong-type", true, () => {
      const tmp = makeDisposableRoot("cg-m13-rb-");
      const target = copyFixtureToTemp("fixtures/config-wrong-type", tmp);
      const configPath = path.join(target, "config/config.toml");
      const original = fs.readFileSync(configPath);
      const preview = runCliRepairPreview(target);
      if (preview.exitCode !== 0 || !preview.result?.ok) {
        return { status: "fail", summary: "preview failed" };
      }
      const apply = runCliRepairApply(target, authFromPreview(preview.result));
      if (apply.exitCode !== 0 || apply.result?.repair_applied !== true) {
        return { status: "fail", summary: "apply failed" };
      }
      const rb = runCliRollback(target);
      assertNoLeak(rb.stdout);
      if (rb.exitCode !== 0 || !rb.result?.ok) {
        return { status: "fail", summary: "rollback failed" };
      }
      const after = fs.readFileSync(configPath);
      if (!after.equals(original)) {
        return { status: "fail", summary: "rollback bytes mismatch" };
      }
      return { status: "pass", summary: "explicit rollback restored original" };
    }),
  );

  // 6) Plugin-cache repair + rollback
  scenarios.push(
    runScenario(
      "plugin_cache_repair_rollback",
      "plugin-cache/corruption",
      true,
      () => {
        const tmp = makeDisposableRoot("cg-m13-pc-");
        const target = copyFixtureToTemp(
          "fixtures/plugin-cache/corruption",
          tmp,
        );
        const cacheRel = "plugin-cache/cache/entry.js";
        const original = fs.readFileSync(path.join(target, cacheRel));
        const diag = runCliDiagnose(target);
        if (diag.exitCode !== 0 || !diag.result?.ok) {
          return { status: "fail", summary: "diagnose failed" };
        }
        const preview = runCliRepairPreview(target);
        if (preview.exitCode !== 0 || !preview.result?.ok) {
          return { status: "fail", summary: "preview failed" };
        }
        const apply = runCliRepairApply(
          target,
          authFromPreview(preview.result),
        );
        if (apply.exitCode !== 0 || apply.result?.repair_applied !== true) {
          return { status: "fail", summary: "cache apply failed" };
        }
        const mid = fs.readFileSync(path.join(target, cacheRel));
        if (mid.equals(original)) {
          return { status: "fail", summary: "cache not mutated by repair" };
        }
        const rb = runCliRollback(target);
        if (rb.exitCode !== 0 || !rb.result?.ok) {
          return { status: "fail", summary: "cache rollback failed" };
        }
        const after = fs.readFileSync(path.join(target, cacheRel));
        if (!after.equals(original)) {
          return { status: "fail", summary: "cache rollback bytes mismatch" };
        }
        return { status: "pass", summary: "plugin-cache repair+rollback ok" };
      },
    ),
  );

  // 7) KNOWN_GOOD + canary
  scenarios.push(
    runScenario("known_good_canary", "lifecycle", true, () => {
      const tmp = makeDisposableRoot("cg-m13-kg-");
      const target = copyFixtureToTemp("fixtures/lifecycle", tmp);
      // Canary loads the ledger under the default instance id unless scoped
      // elsewhere; record KNOWN_GOOD under the same instance as canary.
      const kg = runCliJson([
        "lifecycle",
        "record_known_good",
        target,
        "--instance-id=default",
        "--surface=config",
      ]);
      assertNoLeak(kg.stdout);
      if (kg.exitCode !== 0 || !kg.result?.ok) {
        return { status: "fail", summary: "record_known_good failed" };
      }
      const canary = runCliJson([
        "lifecycle",
        "canary",
        target,
        "--candidate-version=0.99.0",
        "--original-fault-absent=true",
        "--core-regressions-passed=true",
        "--canary-executed=true",
      ]);
      assertNoLeak(canary.stdout);
      if (canary.exitCode !== 0 || !canary.result?.ok) {
        return {
          status: "fail",
          summary: `canary failed code=${String(canary.result?.error_code ?? "n/a")}`,
        };
      }
      const guidance = canary.result.version_guidance;
      if (typeof guidance !== "string" || guidance.length === 0) {
        return { status: "fail", summary: "missing version_guidance" };
      }
      return {
        status: "pass",
        summary: `known_good+canary guidance=${guidance}`,
      };
    }),
  );

  // 8) Privacy refusal still allows local diagnosis (impact refuse)
  scenarios.push(
    runScenario(
      "privacy_refusal_local_diagnosis",
      "protected-process+impact-refused",
      true,
      () => {
        const tmp = makeDisposableRoot("cg-m13-priv-");
        const target = copyFixtureToTemp("fixtures/protected-process", tmp);
        const impact = runCliJson([
          "impact",
          target,
          "--disclose-refused",
        ]);
        assertNoLeak(impact.stdout);
        if (impact.exitCode !== 0 || !impact.result?.ok) {
          return { status: "fail", summary: "impact refused path failed" };
        }
        const card = impact.result.impact_card as
          | { network_used?: unknown; transport_calls?: unknown }
          | undefined;
        const refresh = impact.result.evidence_refresh as
          | { transport_calls?: unknown; observed_facts?: unknown }
          | undefined;
        if (!card || card.network_used !== false) {
          return { status: "fail", summary: "impact_card.network_used not false" };
        }
        if (card.transport_calls !== 0) {
          return { status: "fail", summary: "impact_card.transport_calls nonzero" };
        }
        if (refresh && refresh.transport_calls !== 0) {
          return { status: "fail", summary: "evidence_refresh.transport_calls nonzero" };
        }
        const facts = Array.isArray(refresh?.observed_facts)
          ? (refresh!.observed_facts as string[])
          : [];
        if (!facts.includes("transport_not_called")) {
          return { status: "fail", summary: "missing transport_not_called fact" };
        }
        const diag = runCliDiagnose(target);
        if (diag.exitCode !== 0 || !diag.result?.ok) {
          return { status: "fail", summary: "local diagnose failed after refuse" };
        }
        return {
          status: "pass",
          summary: "disclose-refused still local-ok",
        };
      },
    ),
  );

  // 9) Upstream preview zero network
  scenarios.push(
    runScenario(
      "upstream_preview_zero_network",
      "request-new-incident-cli",
      true,
      () => {
        const tmp = makeDisposableRoot("cg-m13-up-");
        const target = copyFixtureToTemp("fixtures/protected-process", tmp);
        const reqPath = path.join(repoRoot, "fixtures/upstream/request-new-incident-cli.json");
        const up = runCliJson([
          "upstream-preview",
          target,
          `--request=${reqPath}`,
          "--disclose-refused",
        ]);
        assertNoLeak(up.stdout);
        if (!up.result) return { status: "fail", summary: "no upstream result" };
        if (up.result.network_used !== false) {
          return { status: "fail", summary: "network_used true" };
        }
        if (up.result.transport_calls !== 0) {
          return { status: "fail", summary: "transport_calls nonzero" };
        }
        if (up.result.external_write !== false) {
          return { status: "fail", summary: "external_write not false" };
        }
        if (up.result.repair_authorized !== false) {
          return { status: "fail", summary: "repair_authorized not false" };
        }
        // ok may be true (PREVIEW_READY) or false (blocked) — both fine if zero network.
        return {
          status: "pass",
          summary: `upstream preview network=0 ok=${String(up.result.ok)}`,
        };
      },
    ),
  );

  // 10) Package smoke — self-contained: always production package first, then
  // package:smoke + packaged diagnose. Never depend on residual/stale release.
  scenarios.push(
    runScenario("package_smoke", "package-plugin-smoke", true, () =>
      runPackageSmokeScenario({ requirePackage: options.requirePackage }),
    ),
  );

  const ended_at = nowIso();

  // Re-capture active ~/.codex witness AFTER scenarios — must match before.
  const activeWitnessAfter = captureActiveCodexHomeWitness(home);
  // Symlink active ~/.codex is isolation_unprovable; harness must not seal Full.
  const isolationProved =
    activeWitnessBefore.isolation_provable &&
    activeWitnessAfter.isolation_provable &&
    activeWitnessBefore.digest === activeWitnessAfter.digest;
  const extraGaps: string[] = [];
  if (!isolationProved) {
    if (
      !activeWitnessBefore.isolation_provable ||
      !activeWitnessAfter.isolation_provable
    ) {
      extraGaps.push("isolation_active_codex_unprovable");
    } else {
      // Active ~/.codex changed during harness — block Full (no live witness seal).
      extraGaps.push("isolation_active_codex_unproven_or_changed");
    }
  }

  const active_home_witness_digest = activeWitnessBefore.digest;
  const isolation_digest = isolationDigestOf({
    scenario_count: scenarios.length,
    platform: "macos",
    arch,
    no_sudo: true,
    disposable_only: true,
    active_home_witness_digest,
  });

  // Isolation booleans must not be hard-coded true when isolationProved is false.
  // Schema allows false; Full requires every bit true (validated in receipt).
  // no_sudo / disposable / no_protected_write remain true by construction of
  // this harness; active-profile claims track the witness proof.
  const isolation = {
    active_codex_home_untouched: isolationProved,
    disposable_targets_only: true,
    no_sudo: true,
    no_protected_write: true,
    no_active_profile_mutation: isolationProved,
    isolation_digest,
    active_home_witness_digest,
  };

  const coarse =
    capabilities.coarse_os_version ?? "macos-unknown";
  const commit = gitCommitSafe();
  const receipt = buildPlatformSupportReceipt({
    platform: "macos",
    arch,
    coarse_os_version: coarse,
    changeguard_version: packageVersion(),
    changeguard_commit: commit,
    codex_version_provenance: codexProv,
    capabilities,
    scenarios,
    isolation,
    started_at,
    ended_at,
    extra_gaps: extraGaps,
  });

  // Final leak check on the receipt itself.
  const serialized = JSON.stringify(receipt);
  if (
    /\/Users\//.test(serialized) ||
    /\/var\/folders\//.test(serialized) ||
    /\/tmp\//.test(serialized)
  ) {
    throw new Error("receipt_contains_forbidden_paths");
  }

  // Process-local live witness: binds digests/commit/host/time from this run.
  // External JSON reload cannot reconstruct this token.
  const liveWitness = isolationProved
    ? sealLiveHarnessWitness({
        scenarios_digest: scenariosDigestOf(scenarios),
        isolation_digest,
        receipt_id: receipt.receipt_id,
        changeguard_commit: commit,
        host_fingerprint: hostCoarseFingerprintOf({
          platform: "macos",
          arch,
          coarse_os_version: coarse,
        }),
        started_at,
        ended_at,
        platform: "macos",
        arch,
      })
    : undefined;

  const validation = validatePlatformSupportReceipt(receipt, {
    liveWitness,
  });

  // Resolve output directory through the same isolation gate.
  // Default: audited repo `.grok-output/verification` when present, else mkdtemp.
  const grokOutputDir = path.join(repoRoot, ".grok-output");
  const verificationDir = path.join(grokOutputDir, "verification");
  const allowedOutRoots = [verificationDir, grokOutputDir];

  let outDir: string;
  if (options.outDir) {
    outDir = path.resolve(options.outDir);
  } else if (fs.existsSync(grokOutputDir)) {
    outDir = verificationDir;
  } else {
    outDir = makeDisposableRoot("cg-m13-out-");
  }

  // Gate-before-write: assert parent/canonical leaf, then mkdir, then re-assert.
  // Re-assert failure stops immediately and must not leave a just-created dir
  // under active/protected (cleanup only for proven non-active/non-protected).
  const finalGate = ensureDisposableDirectory(outDir, home, {
    allowedRoots: allowedOutRoots,
  });
  if (!finalGate.ok) {
    throw new Error(`harness_out_dir_refused:${finalGate.code}`);
  }

  const receiptAbs = path.join(outDir, "macos-platform-support-receipt.json");
  fs.writeFileSync(receiptAbs, JSON.stringify(receipt, null, 2) + "\n", "utf8");

  // Ensure CLI entry exists (build must have run).
  if (!fs.existsSync(cliEntry())) {
    throw new Error("cli_entry_missing_build_required");
  }

  const allRequiredPass = scenarios
    .filter((s) => s.required)
    .every((s) => s.status === "pass");
  const exit_code =
    validation.ok &&
    allRequiredPass &&
    isolationProved &&
    receipt.support_level === "full" &&
    validation.support_level === "full"
      ? 0
      : 1;

  return {
    receipt,
    receipt_path_alias: "PLATFORM_SUPPORT_RECEIPT",
    receipt_abs: receiptAbs,
    validation_ok: validation.ok,
    exit_code,
  };
}

/** Hash helper re-export for tests. */
export function harnessScenarioHash(id: string, fixture: string): string {
  return scenarioHashOf(id, fixture);
}

export function publicHarnessSummary(result: MacosHarnessResult): Record<string, unknown> {
  return {
    schema_version: 1,
    ok: result.exit_code === 0,
    support_level: result.receipt.support_level,
    receipt_id: result.receipt.receipt_id,
    receipt_path_alias: result.receipt_path_alias,
    validation_ok: result.validation_ok,
    uncovered_gaps: result.receipt.uncovered_gaps,
    scenarios: result.receipt.scenarios.map((s) => ({
      scenario_id: s.scenario_id,
      status: s.status,
      required: s.required,
      duration_ms: s.duration_ms,
    })),
    network_used: false,
    changeguard_version: result.receipt.changeguard_version,
    changeguard_commit: result.receipt.changeguard_commit,
    coarse_os_version: result.receipt.coarse_os_version,
    arch: result.receipt.arch,
  };
}
