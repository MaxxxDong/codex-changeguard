/**
 * Packaged SessionStart entrypoint for Codex plugin hooks.
 *
 * Official contract (plugin-bundled hooks):
 * - receives PLUGIN_ROOT and writable PLUGIN_DATA
 * - runs with session cwd (not plugin root)
 * - receives one JSON object on stdin
 * - uses PLUGIN_DATA for version-state persistence (never session cwd)
 * - treats cwd as observed context only
 *
 * Output:
 * - unchanged fingerprint → exit 0, no stdout
 * - changed fingerprint → valid SessionStart JSON with additionalContext
 * - never prints raw paths
 */
import fs from "node:fs";
import path from "node:path";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import type {
  HookTrustState,
  ObservedContext,
  ScanResult,
  SystemEnumerateCaps,
} from "../instances/types.js";
import { runSessionStart } from "./session-start.js";
import { REFRESH_DUE_HINT } from "../upstream/followup/limits.js";
import { sessionFollowupHintFromState } from "../upstream/followup/engine.js";

const MAX_STDIN_BYTES = 64 * 1024;

export interface HookStdinPayload {
  session_id?: string;
  cwd?: string;
  hook_event_name?: string;
  source?: string;
  model?: string;
  [key: string]: unknown;
}

export interface PackagedSessionStartEnv {
  PLUGIN_ROOT?: string;
  PLUGIN_DATA?: string;
  CLAUDE_PLUGIN_ROOT?: string;
  CLAUDE_PLUGIN_DATA?: string;
  [key: string]: string | undefined;
}

export function resolvePluginPaths(env: PackagedSessionStartEnv = process.env): {
  pluginRoot: string | null;
  pluginData: string | null;
} {
  const pluginRoot = env.PLUGIN_ROOT || env.CLAUDE_PLUGIN_ROOT || null;
  const pluginData = env.PLUGIN_DATA || env.CLAUDE_PLUGIN_DATA || null;
  return {
    pluginRoot: pluginRoot && pluginRoot.length > 0 ? pluginRoot : null,
    pluginData: pluginData && pluginData.length > 0 ? pluginData : null,
  };
}

export function parseHookStdin(raw: string): HookStdinPayload {
  if (Buffer.byteLength(raw, "utf8") > MAX_STDIN_BYTES) {
    return {};
  }
  const trimmed = raw.trim();
  if (!trimmed) return {};
  try {
    const obj = JSON.parse(trimmed) as unknown;
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return {};
    return obj as HookStdinPayload;
  } catch {
    return {};
  }
}

export function readStdinSyncBounded(maxBytes = MAX_STDIN_BYTES): string {
  try {
    const fd = 0;
    const chunks: Buffer[] = [];
    let total = 0;
    const buf = Buffer.alloc(4096);
    while (total < maxBytes) {
      let n: number;
      try {
        n = fs.readSync(fd, buf, 0, Math.min(buf.length, maxBytes - total), null);
      } catch {
        break;
      }
      if (n === 0) break;
      chunks.push(Buffer.from(buf.subarray(0, n)));
      total += n;
    }
    if (total >= maxBytes) {
      try {
        while (fs.readSync(fd, buf, 0, buf.length, null) > 0) {
          /* discard excess */
        }
      } catch {
        /* ignore */
      }
    }
    return Buffer.concat(chunks).toString("utf8");
  } catch {
    return "";
  }
}

/**
 * Format a path-free additionalContext summary for SessionStart version change.
 */
export function formatSessionStartContext(result: ScanResult): string {
  const lines = [
    "ChangeGuard version fingerprint changed.",
    `primary_transition=${result.primary_transition}`,
    `instances=${result.instances.length}`,
    `overall_fingerprint=${result.overall_fingerprint.slice(0, 16)}…`,
  ];
  if (result.health_check) {
    lines.push(
      `health_check_ok=${result.health_check.ok}`,
      `health_classification=${result.health_check.classification}`,
      `health_duration_ms=${result.health_check.duration_ms}`,
    );
  }
  lines.push(
    `affected_resolution=${result.affected_resolution}`,
    `affected_resolution_reason=${result.affected_resolution_reason}`,
  );
  for (const inst of result.instances.slice(0, 8)) {
    lines.push(
      `- ${inst.path_alias} source=${inst.install_source} version=${inst.version ?? "unavailable"} provenance=${inst.version_provenance}`,
    );
  }
  return assertNoLeakPaths(redactText(lines.join("\n")));
}

/** Path-free Ticket 12 follow-up refresh-due line (never fetches). */
export function formatFollowupRefreshHint(): string {
  return assertNoLeakPaths(
    redactText(
      `ChangeGuard follow-up: manual/local refresh is due (${REFRESH_DUE_HINT}). No network fetch.`,
    ),
  );
}

/**
 * Combine version-change and follow-up hints deterministically.
 * Order: version fingerprint block first (when present), then follow-up line.
 */
export function combineSessionStartContext(
  versionBlock: string | null,
  followupDue: boolean,
): string | null {
  const parts: string[] = [];
  if (versionBlock && versionBlock.length > 0) {
    parts.push(versionBlock);
  }
  if (followupDue) {
    parts.push(formatFollowupRefreshHint());
  }
  if (parts.length === 0) return null;
  return assertNoLeakPaths(redactText(parts.join("\n")));
}

export function buildSessionStartHookOutputFromContext(
  additionalContext: string,
): string {
  const payload = {
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext,
    },
  };
  return assertNoLeakPaths(redactText(JSON.stringify(payload)));
}

export function buildSessionStartHookOutput(result: ScanResult): string {
  return buildSessionStartHookOutputFromContext(formatSessionStartContext(result));
}

export interface RunPackagedSessionStartOptions {
  env?: PackagedSessionStartEnv;
  stdinText?: string;
  /** Observed session cwd override (tests). */
  cwd?: string;
  /** Inject system caps for tests. */
  systemCaps?: SystemEnumerateCaps;
  /** Force hook trust for tests (production packaged path is host-trusted). */
  hookTrust?: HookTrustState;
  /** Override version-fingerprint state dir (tests). */
  stateDir?: string;
  /**
   * Override follow-up state dir (tests). Production uses
   * PLUGIN_DATA/upstream-followup via resolveFollowupStateRoot.
   */
  followupStateDir?: string;
  /** Override now for follow-up due checks (tests). */
  nowMs?: number;
}

/**
 * Core packaged SessionStart runner (testable without process.exit).
 * Combines Ticket 03 version-fingerprint hints with Ticket 12 follow-up
 * refresh-due hints. Never network, never raw paths, never issue prose.
 */
export function runPackagedSessionStart(opts: RunPackagedSessionStartOptions = {}): {
  exitCode: number;
  stdout: string;
  result: ScanResult | null;
  followupDue: boolean;
} {
  const env = opts.env ?? process.env;
  const { pluginRoot, pluginData } = resolvePluginPaths(env);
  if (!pluginRoot || !pluginData) {
    // Misconfigured host: fail closed silent success so SessionStart does not break.
    return { exitCode: 0, stdout: "", result: null, followupDue: false };
  }

  const raw = opts.stdinText ?? "";
  const payload = parseHookStdin(raw);
  const cwd =
    opts.cwd ??
    (typeof payload.cwd === "string" && payload.cwd.length > 0
      ? payload.cwd
      : process.cwd());

  // cwd is observed context only — never a state or inventory root.
  void cwd;
  const observed: ObservedContext = {};

  const stateDir = opts.stateDir ?? path.join(pluginData, "version-state");
  const followupStateDir =
    opts.followupStateDir ?? path.join(pluginData, "upstream-followup");

  const hookTrust = opts.hookTrust ?? "trusted";
  const result = runSessionStart({
    hookTrust,
    enumeration: "system_registered",
    stateDir,
    systemCaps: opts.systemCaps,
    observed,
    healthBudgetMs: 10_000,
  });

  // Untrusted/skipped/failed must not become a follow-up bypass or emit hints.
  if (
    hookTrust === "untrusted" ||
    hookTrust === "skipped" ||
    hookTrust === "failed" ||
    result.hook_status === "untrusted" ||
    result.hook_status === "skipped" ||
    result.hook_status === "failed"
  ) {
    // Preserve existing non-silent error/explicit status behavior for non-trusted.
    if (!result.silent && !result.ok) {
      // Manual-path style: no packaged stdout for failed trust (silent success
      // for misconfig); untrusted still returns exit 0 with empty stdout so
      // SessionStart never breaks the host, matching prior packaged contract.
      return { exitCode: 0, stdout: "", result, followupDue: false };
    }
    return { exitCode: 0, stdout: "", result, followupDue: false };
  }

  // Trusted path only: optional follow-up refresh-due from PLUGIN_DATA state.
  let followupDue = false;
  try {
    const hint = sessionFollowupHintFromState({
      stateDir: followupStateDir,
      nowMs: opts.nowMs,
    });
    followupDue =
      hint.ok === true &&
      hint.status === "REFRESH_DUE" &&
      hint.session_hint === REFRESH_DUE_HINT;
  } catch {
    followupDue = false;
  }

  const versionChanged = result.silent !== true && result.ok === true;
  const versionBlock = versionChanged ? formatSessionStartContext(result) : null;
  const combined = combineSessionStartContext(versionBlock, followupDue);

  if (!combined) {
    // Neither version change nor follow-up due → exit 0, no stdout.
    return { exitCode: 0, stdout: "", result, followupDue: false };
  }

  const out = buildSessionStartHookOutputFromContext(combined);
  return { exitCode: 0, stdout: out + "\n", result, followupDue };
}

/** Process entry when executed as packaged hook. */
export function mainPackagedSessionStart(
  env: PackagedSessionStartEnv = process.env,
  stdinText?: string,
): never {
  const text = stdinText ?? readStdinSyncBounded();
  const { exitCode, stdout } = runPackagedSessionStart({ env, stdinText: text });
  if (stdout) process.stdout.write(stdout);
  process.exit(exitCode);
}

// Run when this module is the process entrypoint.
const isMain =
  typeof process.argv[1] === "string" &&
  (process.argv[1].endsWith(`${path.sep}session-start-entry.js`) ||
    process.argv[1].endsWith(`${path.sep}session-start-entry.ts`) ||
    process.argv[1].endsWith("/session-start-entry.js") ||
    process.argv[1].endsWith("/session-start-entry.ts"));

if (isMain) {
  mainPackagedSessionStart();
}
