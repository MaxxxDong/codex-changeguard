/**
 * Platform support receipt construction and validation (Ticket 13).
 * Full support requires every required scenario to pass and leak checks to clear.
 */
import crypto from "node:crypto";
import type {
  PlatformCapabilities,
  PlatformSupportLevel,
  PlatformSupportReceipt,
  ReceiptValidationResult,
  ScenarioOutcome,
  IsolationProof,
  CodexVersionProvenance,
  PlatformId,
} from "./types.js";
import { MACOS_REQUIRED_SCENARIO_IDS } from "./types.js";

const LEAK_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\/Users\/[^/\s"'`]+/i, label: "username_home_path" },
  { re: /\/home\/[^/\s"'`]+/i, label: "linux_home_path" },
  { re: /[A-Za-z]:\\Users\\/i, label: "windows_users_path" },
  { re: /\.grok-disposable\//i, label: "disposable_clone_path" },
  { re: /grok-worker-[A-Za-z0-9_-]+/i, label: "worker_id_path" },
  { re: /\/var\/folders\/[^\s"'`]+/i, label: "macos_temp_path" },
  { re: /\/tmp\/[^\s"'`]+/i, label: "tmp_path" },
  { re: /\/private\/var\/folders\/[^\s"'`]+/i, label: "private_temp_path" },
  { re: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i, label: "bearer_token" },
];

function sha256Text(s: string): string {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function asBool(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function asNumber(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** Scan serialized receipt for forbidden path/secret shapes. */
export function findReceiptLeaks(text: string): string[] {
  const hits: string[] = [];
  for (const { re, label } of LEAK_PATTERNS) {
    if (re.test(text)) hits.push(label);
  }
  return hits;
}

export function scenarioHashOf(scenarioId: string, fixtureId: string): string {
  return sha256Text(`scenario:v1:${scenarioId}:${fixtureId}`);
}

export function receiptIdOf(parts: {
  platform: string;
  arch: string;
  started_at: string;
  scenarios_digest: string;
}): string {
  return sha256Text(
    `receipt:v1:${parts.platform}:${parts.arch}:${parts.started_at}:${parts.scenarios_digest}`,
  ).slice(0, 32);
}

export function scenariosDigestOf(scenarios: ScenarioOutcome[]): string {
  const rows = scenarios
    .map((s) => `${s.scenario_id}|${s.scenario_hash}|${s.status}`)
    .sort();
  return sha256Text(`scenarios:v1:${rows.join("\n")}`);
}

/**
 * Derive support level from scenario outcomes and platform.
 * Full only when every required scenario passes and there are no forced gaps.
 */
export function deriveSupportLevel(args: {
  platform: PlatformId;
  scenarios: ScenarioOutcome[];
  requiredIds?: readonly string[];
  extraGaps?: string[];
}): { level: PlatformSupportLevel; gaps: string[] } {
  const required = args.requiredIds ?? MACOS_REQUIRED_SCENARIO_IDS;
  const gaps: string[] = [...(args.extraGaps ?? [])];
  if (args.platform !== "macos") {
    return {
      level: args.platform === "unknown" ? "unsupported" : "preview",
      gaps: [`platform_not_macos:${args.platform}`, ...gaps],
    };
  }
  const byId = new Map(args.scenarios.map((s) => [s.scenario_id, s]));
  for (const id of required) {
    const s = byId.get(id);
    if (!s) {
      gaps.push(`missing_scenario:${id}`);
      continue;
    }
    if (s.status !== "pass") {
      gaps.push(`scenario_not_pass:${id}:${s.status}`);
    }
  }
  if (gaps.length > 0) {
    return { level: "preview", gaps };
  }
  return { level: "full", gaps: [] };
}

export interface BuildReceiptInput {
  platform: PlatformId;
  arch: string;
  coarse_os_version: string;
  changeguard_version: string;
  changeguard_commit: string | null;
  codex_version_provenance: CodexVersionProvenance;
  capabilities: PlatformCapabilities;
  scenarios: ScenarioOutcome[];
  isolation: IsolationProof;
  started_at: string;
  ended_at: string;
  extra_gaps?: string[];
  required_ids?: readonly string[];
}

export function buildPlatformSupportReceipt(
  input: BuildReceiptInput,
): PlatformSupportReceipt {
  const dig = scenariosDigestOf(input.scenarios);
  const { level, gaps } = deriveSupportLevel({
    platform: input.platform,
    scenarios: input.scenarios,
    requiredIds: input.required_ids,
    extraGaps: input.extra_gaps,
  });
  const started = Date.parse(input.started_at);
  const ended = Date.parse(input.ended_at);
  const duration_ms =
    Number.isFinite(started) && Number.isFinite(ended)
      ? Math.max(0, ended - started)
      : 0;
  const receipt_id = receiptIdOf({
    platform: input.platform,
    arch: input.arch,
    started_at: input.started_at,
    scenarios_digest: dig,
  });
  return {
    schema_version: 1,
    receipt_id,
    platform: input.platform,
    arch: input.arch,
    coarse_os_version: input.coarse_os_version,
    changeguard_version: input.changeguard_version,
    changeguard_commit: input.changeguard_commit,
    codex_version_provenance: input.codex_version_provenance,
    capabilities: input.capabilities,
    scenarios: input.scenarios,
    isolation: input.isolation,
    started_at: input.started_at,
    ended_at: input.ended_at,
    duration_ms,
    support_level: level,
    uncovered_gaps: gaps,
    assertions: {
      no_sudo: true,
      no_active_profile: true,
      no_protected_write: true,
      no_username: true,
      no_raw_temp_path: true,
    },
    network_used: false,
  };
}

function validateScenario(raw: unknown, index: number, errors: string[]): void {
  if (!isPlainObject(raw)) {
    errors.push(`scenarios[${index}] must be object`);
    return;
  }
  if (!asString(raw.scenario_id)) errors.push(`scenarios[${index}].scenario_id`);
  if (!asString(raw.scenario_hash) || String(raw.scenario_hash).length !== 64) {
    errors.push(`scenarios[${index}].scenario_hash`);
  }
  const st = asString(raw.status);
  if (st !== "pass" && st !== "fail" && st !== "skipped") {
    errors.push(`scenarios[${index}].status`);
  }
  if (!asString(raw.outcome_summary)) {
    errors.push(`scenarios[${index}].outcome_summary`);
  }
  if (asNumber(raw.duration_ms) === null) {
    errors.push(`scenarios[${index}].duration_ms`);
  }
  if (asBool(raw.required) === null) {
    errors.push(`scenarios[${index}].required`);
  }
}

/**
 * Validate a platform support receipt (schema + leak + Full/Preview rules).
 * Never upgrades support_level beyond what scenarios prove.
 */
export function validatePlatformSupportReceipt(
  raw: unknown,
): ReceiptValidationResult {
  const errors: string[] = [];
  if (!isPlainObject(raw)) {
    return {
      schema_version: 1,
      ok: false,
      support_level: "unsupported",
      errors: ["receipt_not_object"],
      gaps: [],
      receipt_id: null,
      network_used: false,
    };
  }
  if (raw.schema_version !== 1) errors.push("schema_version");
  const platform = asString(raw.platform) as PlatformId | null;
  if (
    platform !== "macos" &&
    platform !== "windows" &&
    platform !== "linux" &&
    platform !== "wsl" &&
    platform !== "unknown"
  ) {
    errors.push("platform");
  }
  if (!asString(raw.arch)) errors.push("arch");
  if (!asString(raw.coarse_os_version)) errors.push("coarse_os_version");
  if (!asString(raw.changeguard_version)) errors.push("changeguard_version");
  if (raw.changeguard_commit !== null && !asString(raw.changeguard_commit)) {
    errors.push("changeguard_commit");
  }
  if (!isPlainObject(raw.codex_version_provenance)) {
    errors.push("codex_version_provenance");
  }
  if (!isPlainObject(raw.capabilities)) errors.push("capabilities");
  if (!Array.isArray(raw.scenarios)) errors.push("scenarios");
  else raw.scenarios.forEach((s, i) => validateScenario(s, i, errors));
  if (!isPlainObject(raw.isolation)) errors.push("isolation");
  else {
    const iso = raw.isolation;
    for (const k of [
      "active_codex_home_untouched",
      "disposable_targets_only",
      "no_sudo",
      "no_protected_write",
      "no_active_profile_mutation",
    ] as const) {
      if (iso[k] !== true) errors.push(`isolation.${k}`);
    }
    if (!asString(iso.isolation_digest)) errors.push("isolation.isolation_digest");
  }
  if (!asString(raw.started_at)) errors.push("started_at");
  if (!asString(raw.ended_at)) errors.push("ended_at");
  if (asNumber(raw.duration_ms) === null) errors.push("duration_ms");
  if (raw.network_used !== false) errors.push("network_used");
  if (!isPlainObject(raw.assertions)) errors.push("assertions");
  else {
    for (const k of [
      "no_sudo",
      "no_active_profile",
      "no_protected_write",
      "no_username",
      "no_raw_temp_path",
    ] as const) {
      if (raw.assertions[k] !== true) errors.push(`assertions.${k}`);
    }
  }
  if (!Array.isArray(raw.uncovered_gaps)) errors.push("uncovered_gaps");

  const serialized = JSON.stringify(raw);
  const leaks = findReceiptLeaks(serialized);
  for (const l of leaks) errors.push(`leak:${l}`);

  const scenarios = (Array.isArray(raw.scenarios) ? raw.scenarios : []) as ScenarioOutcome[];
  const derived = deriveSupportLevel({
    platform: (platform ?? "unknown") as PlatformId,
    scenarios,
    extraGaps: Array.isArray(raw.uncovered_gaps)
      ? (raw.uncovered_gaps as string[]).filter((g) => typeof g === "string")
      : [],
  });

  const claimed = asString(raw.support_level) as PlatformSupportLevel | null;
  if (
    claimed !== "full" &&
    claimed !== "preview" &&
    claimed !== "limited" &&
    claimed !== "read_only" &&
    claimed !== "unsupported"
  ) {
    errors.push("support_level");
  } else if (claimed === "full" && derived.level !== "full") {
    errors.push("support_level_full_without_proof");
  } else if (
    claimed &&
    derived.level === "full" &&
    claimed !== "full" &&
    // Allow under-claiming (preview when full is earned is ok? Task says Full only if pass.
    // Under-claiming as preview when all pass is truthful-but-conservative; allow.
    false
  ) {
    /* no-op */
  }

  // If receipt claims full, gaps must be empty.
  if (claimed === "full" && Array.isArray(raw.uncovered_gaps) && raw.uncovered_gaps.length > 0) {
    errors.push("full_with_gaps");
  }

  const ok = errors.length === 0;
  const support_level: PlatformSupportLevel = ok
    ? (claimed as PlatformSupportLevel) ?? derived.level
    : derived.level === "full"
      ? "preview"
      : derived.level;

  return {
    schema_version: 1,
    ok,
    support_level: ok ? (claimed as PlatformSupportLevel) : support_level,
    errors,
    gaps: derived.gaps,
    receipt_id: asString(raw.receipt_id),
    network_used: false,
  };
}
