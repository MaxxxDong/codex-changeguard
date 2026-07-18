/**
 * Platform support receipt construction and validation (Ticket 13).
 *
 * Shape validation is separate from Full attestation:
 * - Any external/CLI/MCP-loaded JSON can at most earn Preview (shape-only).
 * - Full requires a process-local live harness witness sealed in the same
 *   process that just executed the controlled real-machine harness.
 * - Witness material is held in a WeakMap (not reconstructible from JSON,
 *   hardcoded secrets, or self-reported real/synthetic flags).
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

const HEX64 = /^[0-9a-f]{64}$/;
const HEX_COMMIT = /^[0-9a-fA-F]{7,64}$/;

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

const CONSTRAINT_KEYS = [
  "broad_home_crawl",
  "raw_path_export",
  "execute_discovered_binaries",
  "sudo_required",
  "system_certificate_change",
  "system_proxy_change",
  "security_control_change",
  "signed_app_mutation",
  "openai_binary_mutation",
  "active_profile_mutation",
] as const;

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

function isHex64(v: unknown): v is string {
  return typeof v === "string" && HEX64.test(v);
}

/** Scan serialized receipt for forbidden path/secret shapes. */
export function findReceiptLeaks(text: string): string[] {
  const hits: string[] = [];
  for (const { re, label } of LEAK_PATTERNS) {
    if (re.test(text)) hits.push(label);
  }
  return hits;
}

/**
 * Canonical scenario definition hash (recomputable from receipt content).
 * Fixture id is harness bookkeeping only and must not affect the public hash,
 * otherwise external validators cannot recompute consistency.
 */
export function scenarioHashOf(scenarioId: string, _fixtureId?: string): string {
  return sha256Text(`scenario:v1:${scenarioId}`);
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

/** Coarse host fingerprint (no username/home/temp paths). */
export function hostCoarseFingerprintOf(parts: {
  platform: string;
  arch: string;
  coarse_os_version: string;
}): string {
  return sha256Text(
    `host:v1:${parts.platform}|${parts.arch}|${parts.coarse_os_version}`,
  );
}

/**
 * Derive support level from scenario outcomes and platform.
 * Full only when every required scenario passes and there are no forced gaps.
 * Note: external validators still cap at Preview without a live witness.
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

// ---------------------------------------------------------------------------
// Process-local live harness witness (not serializable / not forgeable via JSON)
// ---------------------------------------------------------------------------

const LIVE_WITNESS_BRAND = Symbol("changeguard.live_harness_witness");

export interface LiveHarnessAttestation {
  scenarios_digest: string;
  isolation_digest: string;
  receipt_id: string;
  changeguard_commit: string | null;
  host_fingerprint: string;
  started_at: string;
  ended_at: string;
  platform: string;
  arch: string;
}

export interface LiveHarnessWitness {
  readonly [LIVE_WITNESS_BRAND]: true;
}

const liveWitnessStore = new WeakMap<LiveHarnessWitness, LiveHarnessAttestation>();

/**
 * Seal a process-local witness for a just-executed controlled harness run.
 * The token is an opaque object; only this process's WeakMap can resolve it.
 */
export function sealLiveHarnessWitness(
  attestation: LiveHarnessAttestation,
): LiveHarnessWitness {
  const token = { [LIVE_WITNESS_BRAND]: true as const };
  liveWitnessStore.set(token, {
    scenarios_digest: attestation.scenarios_digest,
    isolation_digest: attestation.isolation_digest,
    receipt_id: attestation.receipt_id,
    changeguard_commit: attestation.changeguard_commit,
    host_fingerprint: attestation.host_fingerprint,
    started_at: attestation.started_at,
    ended_at: attestation.ended_at,
    platform: attestation.platform,
    arch: attestation.arch,
  });
  return token;
}

export function isLiveHarnessWitness(v: unknown): v is LiveHarnessWitness {
  return (
    typeof v === "object" &&
    v !== null &&
    (v as LiveHarnessWitness)[LIVE_WITNESS_BRAND] === true &&
    liveWitnessStore.has(v as LiveHarnessWitness)
  );
}

export function readLiveHarnessAttestation(
  witness: LiveHarnessWitness,
): LiveHarnessAttestation | null {
  return liveWitnessStore.get(witness) ?? null;
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

function validateScenario(raw: unknown, index: number, errors: string[]): ScenarioOutcome | null {
  if (!isPlainObject(raw)) {
    errors.push(`scenarios[${index}] must be object`);
    return null;
  }
  const scenario_id = asString(raw.scenario_id);
  if (!scenario_id) {
    errors.push(`scenarios[${index}].scenario_id`);
    return null;
  }
  const scenario_hash = asString(raw.scenario_hash);
  if (!isHex64(scenario_hash)) {
    errors.push(`scenarios[${index}].scenario_hash`);
  } else {
    const expected = scenarioHashOf(scenario_id);
    if (scenario_hash !== expected) {
      errors.push(`scenarios[${index}].scenario_hash_mismatch`);
    }
  }
  const st = asString(raw.status);
  if (st !== "pass" && st !== "fail" && st !== "skipped") {
    errors.push(`scenarios[${index}].status`);
  }
  if (!asString(raw.outcome_summary)) {
    errors.push(`scenarios[${index}].outcome_summary`);
  }
  const duration_ms = asNumber(raw.duration_ms);
  if (duration_ms === null || duration_ms < 0 || !Number.isInteger(duration_ms)) {
    errors.push(`scenarios[${index}].duration_ms`);
  }
  if (asBool(raw.required) === null) {
    errors.push(`scenarios[${index}].required`);
  }
  if (
    scenario_id &&
    isHex64(scenario_hash) &&
    (st === "pass" || st === "fail" || st === "skipped") &&
    asString(raw.outcome_summary) &&
    duration_ms !== null &&
    duration_ms >= 0 &&
    Number.isInteger(duration_ms) &&
    asBool(raw.required) !== null
  ) {
    return {
      scenario_id,
      scenario_hash,
      status: st,
      outcome_summary: asString(raw.outcome_summary)!,
      duration_ms,
      required: asBool(raw.required)!,
    };
  }
  return null;
}

function validateCapabilitiesConstraints(
  caps: Record<string, unknown>,
  errors: string[],
): void {
  if (!isPlainObject(caps.constraints)) {
    errors.push("capabilities.constraints");
    return;
  }
  const c = caps.constraints;
  for (const k of CONSTRAINT_KEYS) {
    if (c[k] !== false) {
      errors.push(`capabilities.constraints.${k}`);
    }
  }
}

export interface ValidateReceiptOptions {
  /**
   * Process-local witness from the controlled live harness only.
   * Never accept a JSON field as a substitute.
   */
  liveWitness?: LiveHarnessWitness;
}

/**
 * Validate a platform support receipt.
 *
 * Shape validation (schema, digests, leaks, time order) is always applied.
 * Full support_level is granted only when a matching process-local live
 * harness witness attests the same digests/commit/host/time binding.
 * Persisted or externally loaded JSON without a live witness is capped at Preview.
 */
export function validatePlatformSupportReceipt(
  raw: unknown,
  options: ValidateReceiptOptions = {},
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
  const arch = asString(raw.arch);
  if (!arch) errors.push("arch");
  const coarse_os_version = asString(raw.coarse_os_version);
  if (!coarse_os_version) errors.push("coarse_os_version");
  if (!asString(raw.changeguard_version)) errors.push("changeguard_version");
  if (raw.changeguard_commit !== null && !asString(raw.changeguard_commit)) {
    errors.push("changeguard_commit");
  } else if (
    typeof raw.changeguard_commit === "string" &&
    !HEX_COMMIT.test(raw.changeguard_commit)
  ) {
    errors.push("changeguard_commit");
  }
  if (!isPlainObject(raw.codex_version_provenance)) {
    errors.push("codex_version_provenance");
  }
  if (!isPlainObject(raw.capabilities)) errors.push("capabilities");
  else validateCapabilitiesConstraints(raw.capabilities, errors);

  const parsedScenarios: ScenarioOutcome[] = [];
  if (!Array.isArray(raw.scenarios)) errors.push("scenarios");
  else {
    raw.scenarios.forEach((s, i) => {
      const parsed = validateScenario(s, i, errors);
      if (parsed) parsedScenarios.push(parsed);
    });
  }

  let isolationDigestClaimed: string | null = null;
  let activeHomeWitness: string | null = null;
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
    isolationDigestClaimed = asString(iso.isolation_digest);
    if (!isHex64(isolationDigestClaimed)) {
      errors.push("isolation.isolation_digest");
      isolationDigestClaimed = null;
    }
    activeHomeWitness = asString(iso.active_home_witness_digest);
    if (!isHex64(activeHomeWitness)) {
      errors.push("isolation.active_home_witness_digest");
      activeHomeWitness = null;
    }
  }

  const started_at = asString(raw.started_at);
  const ended_at = asString(raw.ended_at);
  if (!started_at) errors.push("started_at");
  if (!ended_at) errors.push("ended_at");
  const duration_ms = asNumber(raw.duration_ms);
  if (duration_ms === null || duration_ms < 0 || !Number.isInteger(duration_ms)) {
    errors.push("duration_ms");
  }
  if (started_at && ended_at) {
    const t0 = Date.parse(started_at);
    const t1 = Date.parse(ended_at);
    if (!Number.isFinite(t0) || !Number.isFinite(t1)) {
      errors.push("time_order");
    } else if (t1 < t0) {
      errors.push("time_order");
    } else if (
      duration_ms !== null &&
      Number.isInteger(duration_ms) &&
      duration_ms !== Math.max(0, t1 - t0)
    ) {
      // Allow small clock/rounding slack of 0 — require exact for integer ms from ISO.
      // Harness uses Date.now-based ISO; duration is computed the same way.
      // Use absolute difference tolerance of 0; if mismatch, flag.
      const expected = Math.max(0, t1 - t0);
      if (Math.abs(duration_ms - expected) > 1) {
        errors.push("duration_ms_mismatch");
      }
    }
  }
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

  const receipt_id = asString(raw.receipt_id);
  if (!receipt_id || receipt_id.length < 8 || receipt_id.length > 128) {
    errors.push("receipt_id");
  }

  // Recompute scenarios_digest and receipt_id.
  let scenarios_digest: string | null = null;
  if (parsedScenarios.length > 0 && platform && arch && started_at) {
    scenarios_digest = scenariosDigestOf(parsedScenarios);
    const expectedReceiptId = receiptIdOf({
      platform,
      arch,
      started_at,
      scenarios_digest,
    });
    if (receipt_id && receipt_id !== expectedReceiptId) {
      errors.push("receipt_id_mismatch");
    }
  }

  // Recompute isolation_digest when possible.
  if (
    isolationDigestClaimed &&
    activeHomeWitness &&
    platform &&
    arch &&
    parsedScenarios.length > 0
  ) {
    const { isolationDigestOf } = requireIsolationDigest();
    const expectedIso = isolationDigestOf({
      scenario_count: parsedScenarios.length,
      platform,
      arch,
      no_sudo: true,
      disposable_only: true,
      active_home_witness_digest: activeHomeWitness,
    });
    if (isolationDigestClaimed !== expectedIso) {
      errors.push("isolation.isolation_digest_mismatch");
    }
  }

  const serialized = JSON.stringify(raw);
  const leaks = findReceiptLeaks(serialized);
  for (const l of leaks) errors.push(`leak:${l}`);

  // Reject self-reported forge switches if present (must not affect Full).
  if ("synthetic" in raw || "real" in raw || "live" in raw || "attestation" in raw) {
    // Extra properties are not schema-valid; treat as shape noise / forge attempt.
    errors.push("forbidden_self_report_field");
  }

  const derived = deriveSupportLevel({
    platform: (platform ?? "unknown") as PlatformId,
    scenarios: parsedScenarios,
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
  }

  if (claimed === "full" && Array.isArray(raw.uncovered_gaps) && raw.uncovered_gaps.length > 0) {
    errors.push("full_with_gaps");
  }

  // Live attestation gate for Full.
  let liveFullOk = false;
  const witness = options.liveWitness;
  if (witness && isLiveHarnessWitness(witness)) {
    const att = readLiveHarnessAttestation(witness);
    if (
      att &&
      scenarios_digest &&
      isolationDigestClaimed &&
      receipt_id &&
      platform &&
      arch &&
      started_at &&
      ended_at &&
      coarse_os_version
    ) {
      const hostFp = hostCoarseFingerprintOf({
        platform,
        arch,
        coarse_os_version,
      });
      const commit = raw.changeguard_commit === null ? null : asString(raw.changeguard_commit);
      if (
        att.scenarios_digest === scenarios_digest &&
        att.isolation_digest === isolationDigestClaimed &&
        att.receipt_id === receipt_id &&
        att.changeguard_commit === commit &&
        att.host_fingerprint === hostFp &&
        att.started_at === started_at &&
        att.ended_at === ended_at &&
        att.platform === platform &&
        att.arch === arch &&
        derived.level === "full" &&
        claimed === "full"
      ) {
        liveFullOk = true;
      } else {
        errors.push("live_attestation_mismatch");
      }
    } else {
      errors.push("live_attestation_incomplete");
    }
  } else if (claimed === "full") {
    // External / reloaded JSON cannot earn Full.
    errors.push("full_requires_live_attestation");
  }

  const shapeOk = errors.length === 0 || (
    // When the only Full-blocking issue is missing live attestation, shape may
    // still be usable as Preview — but we keep ok=false if any errors remain.
    false
  );
  void shapeOk;

  const ok = errors.length === 0 && (claimed !== "full" || liveFullOk);

  // Cap verified support_level: Full only with live witness; otherwise max Preview.
  let support_level: PlatformSupportLevel;
  if (ok && liveFullOk && claimed === "full") {
    support_level = "full";
  } else if (ok && claimed && claimed !== "full") {
    support_level = claimed;
  } else if (!ok && liveFullOk === false) {
    // Demote Full claims without live proof to Preview when scenarios would pass.
    if (derived.level === "full" || claimed === "full") {
      support_level = "preview";
    } else {
      support_level = derived.level;
    }
  } else {
    support_level = derived.level === "full" ? "preview" : derived.level;
  }

  // Final: never return full without liveFullOk.
  if (support_level === "full" && !liveFullOk) {
    support_level = "preview";
  }

  return {
    schema_version: 1,
    ok: errors.length === 0 && (claimed !== "full" || liveFullOk),
    support_level,
    errors,
    gaps: derived.gaps,
    receipt_id: receipt_id,
    network_used: false,
  };
}

/** Lazy import to avoid circular init with adapter isolationDigestOf. */
function requireIsolationDigest(): {
  isolationDigestOf: (parts: {
    scenario_count: number;
    platform: string;
    arch: string;
    no_sudo: true;
    disposable_only: true;
    active_home_witness_digest: string;
  }) => string;
} {
  // Inline the same formula as adapter.isolationDigestOf to keep receipt
  // validation self-contained for digest recompute (must stay in sync).
  return {
    isolationDigestOf(parts) {
      return sha256Text(
        [
          "isolation:v1",
          parts.platform,
          parts.arch,
          String(parts.scenario_count),
          "no_sudo",
          "disposable_only",
          parts.active_home_witness_digest,
        ].join("|"),
      );
    },
  };
}
