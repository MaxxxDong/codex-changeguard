/**
 * Registered config set/remove repair operations (Ticket 07).
 * Extends the Ticket 02 recovery DSL narrowly — one engine, registered ops only.
 */
import { sha256Buffer } from "../measure.js";
import {
  CONFIG_FAULT_OBSOLETE,
  CONFIG_FAULT_SOURCE_CONFLICT,
  CONFIG_FAULT_TYPE,
  CONFIG_OVERRIDE_ALIAS,
  CONFIG_OVERRIDE_REL,
  CONFIG_PRIMARY_ALIAS,
  CONFIG_PRIMARY_REL,
  documentIsFullyValid,
  encodeNewValueForCapsule,
  getDotted,
  parseTomlDocument,
  probeConfigControlFiles,
  redactedValueSummary,
  type ConfigFault,
  type ConfigProbeResult,
} from "../config/index.js";
import { digestObject } from "./canonical.js";
import type { RepairOperationKind } from "./types.js";

export const CONFIG_WRONG_TYPE_CAPSULE_ID = "config-wrong-type-set-v1";
export const CONFIG_OBSOLETE_CAPSULE_ID = "config-obsolete-key-remove-v1";
export const CONFIG_SOURCE_CONFLICT_CAPSULE_ID = "config-source-conflict-remove-v1";

/** Registered repairable type-fault key + replacement value (literal TOML rhs). */
export const REGISTERED_TYPE_FIX = {
  config_key: "shell_environment_policy.set",
  /** Empty string table — valid schema value. */
  new_value_toml: "{}",
  new_value_summary: "table(keys=0)",
} as const;

export interface ConfigRepairPlan {
  kind: Extract<RepairOperationKind, "config_set" | "config_remove">;
  capsule_id: string;
  target_path_alias: string;
  target_rel: string;
  config_key: string;
  old_value_type: string;
  old_value_summary: string;
  new_value: string | null;
  /** Full post-repair file bytes. */
  next_text: string;
  result_sha256: string;
  original_sha256: string;
  fault: ConfigFault;
  operation_digest: string;
  expected_pattern_count: 1;
}

export function configOperationDigest(plan: {
  kind: string;
  capsule_id: string;
  target_path_alias: string;
  config_key: string;
  new_value: string | null;
}): string {
  return digestObject({
    kind: plan.kind,
    capsule_id: plan.capsule_id,
    target_path_alias: plan.target_path_alias,
    config_key: plan.config_key,
    new_value: plan.new_value,
    description:
      plan.kind === "config_set"
        ? "Set registered config key to schema-valid value"
        : "Remove obsolete or conflicting config key",
  });
}

/**
 * Plan a registered config repair from a live probe.
 * Returns null when no registered repairable fault is present.
 */
export function planConfigRepair(targetReal: string): {
  plan: ConfigRepairPlan | null;
  probe: ConfigProbeResult;
  managed_block: boolean;
} {
  const probe = probeConfigControlFiles(targetReal);
  if (probe.managed) {
    return { plan: null, probe, managed_block: true };
  }
  if (!probe.fault) {
    return { plan: null, probe, managed_block: false };
  }
  const fault = probe.fault;

  if (fault.fault_class === CONFIG_FAULT_TYPE) {
    // Only the registered wrong-type key is repairable via config_set.
    if (
      fault.config_key === REGISTERED_TYPE_FIX.config_key ||
      fault.config_keys.includes(REGISTERED_TYPE_FIX.config_key)
    ) {
      const plan = planTypeFix(targetReal, probe, fault);
      return { plan, probe, managed_block: false };
    }
    return { plan: null, probe, managed_block: false };
  }

  if (fault.fault_class === CONFIG_FAULT_OBSOLETE) {
    const plan = planRemoveKey(
      targetReal,
      probe,
      fault,
      CONFIG_OBSOLETE_CAPSULE_ID,
      fault.path_rel === CONFIG_OVERRIDE_REL
        ? CONFIG_OVERRIDE_ALIAS
        : CONFIG_PRIMARY_ALIAS,
      fault.path_rel === CONFIG_OVERRIDE_REL
        ? CONFIG_OVERRIDE_REL
        : CONFIG_PRIMARY_REL,
    );
    return { plan, probe, managed_block: false };
  }

  if (fault.fault_class === CONFIG_FAULT_SOURCE_CONFLICT) {
    // Remove conflicting key from override (registered resolve: override loses).
    const plan = planRemoveKey(
      targetReal,
      probe,
      fault,
      CONFIG_SOURCE_CONFLICT_CAPSULE_ID,
      CONFIG_OVERRIDE_ALIAS,
      CONFIG_OVERRIDE_REL,
    );
    return { plan, probe, managed_block: false };
  }

  // Syntax errors are not auto-repaired.
  return { plan: null, probe, managed_block: false };
}

function planTypeFix(
  targetReal: string,
  probe: ConfigProbeResult,
  _fault: ConfigFault,
): ConfigRepairPlan | null {
  const doc = probe.primary;
  if (!doc || doc.path_rel !== CONFIG_PRIMARY_REL) return null;
  // Engine re-plans from live text via buildLiveConfigPlan / planTypeFixFromText.
  void targetReal;
  void _fault;
  return null;
}

/** Plan type fix from known primary file text. */
export function planTypeFixFromText(
  text: string,
  original_sha256: string,
  fault: ConfigFault,
): ConfigRepairPlan | null {
  if (
    fault.config_key !== REGISTERED_TYPE_FIX.config_key &&
    !fault.config_keys.includes(REGISTERED_TYPE_FIX.config_key)
  ) {
    return null;
  }
  const next = applySetShellEnvPolicyEmpty(text);
  if (next === null) return null;
  if (!documentIsFullyValid(next)) return null;
  const oldVal = extractOldSummary(text, REGISTERED_TYPE_FIX.config_key);
  const new_value = encodeNewValueForCapsule(
    REGISTERED_TYPE_FIX.config_key,
    REGISTERED_TYPE_FIX.new_value_toml,
  );
  const kind = "config_set" as const;
  const capsule_id = CONFIG_WRONG_TYPE_CAPSULE_ID;
  const target_path_alias = CONFIG_PRIMARY_ALIAS;
  const planBase = {
    kind,
    capsule_id,
    target_path_alias,
    config_key: REGISTERED_TYPE_FIX.config_key,
    new_value,
  };
  return {
    kind,
    capsule_id,
    target_path_alias,
    target_rel: CONFIG_PRIMARY_REL,
    config_key: REGISTERED_TYPE_FIX.config_key,
    old_value_type: oldVal.type,
    old_value_summary: oldVal.summary,
    new_value,
    next_text: next,
    result_sha256: sha256Buffer(Buffer.from(next, "utf8")),
    original_sha256,
    fault,
    operation_digest: configOperationDigest(planBase),
    expected_pattern_count: 1,
  };
}

export function planRemoveKeyFromText(
  text: string,
  original_sha256: string,
  fault: ConfigFault,
  capsule_id: string,
  target_path_alias: string,
  target_rel: string,
): ConfigRepairPlan | null {
  const key = fault.config_key;
  if (!key) return null;
  const next = removeDottedKeyFromToml(text, key);
  if (next === null) return null;
  // After remove, document should be valid when paired files considered separately.
  // For override remove of conflict key, override alone may still be valid.
  const parsed = parseTomlDocument(next);
  if (!parsed.ok && capsule_id !== CONFIG_SOURCE_CONFLICT_CAPSULE_ID) {
    return null;
  }
  const oldVal = extractOldSummary(text, key);
  const kind = "config_remove" as const;
  const planBase = {
    kind,
    capsule_id,
    target_path_alias,
    config_key: key,
    new_value: null as string | null,
  };
  return {
    kind,
    capsule_id,
    target_path_alias,
    target_rel,
    config_key: key,
    old_value_type: oldVal.type,
    old_value_summary: oldVal.summary,
    new_value: null,
    next_text: next,
    result_sha256: sha256Buffer(Buffer.from(next, "utf8")),
    original_sha256,
    fault,
    operation_digest: configOperationDigest(planBase),
    expected_pattern_count: 1,
  };
}

function planRemoveKey(
  _targetReal: string,
  _probe: ConfigProbeResult,
  fault: ConfigFault,
  capsule_id: string,
  target_path_alias: string,
  target_rel: string,
): ConfigRepairPlan | null {
  // Engine supplies text via openTargetFile; placeholder signals applicability.
  void _targetReal;
  void _probe;
  if (!fault.config_key) return null;
  // Return a stub plan marker — engine calls FromText with live bytes.
  // We encode applicability by non-null fault only; engine re-plans.
  return {
    kind: "config_remove",
    capsule_id,
    target_path_alias,
    target_rel,
    config_key: fault.config_key,
    old_value_type: "unknown",
    old_value_summary: "unknown(redacted)",
    new_value: null,
    next_text: "",
    result_sha256: "0".repeat(64),
    original_sha256: "0".repeat(64),
    fault,
    operation_digest: configOperationDigest({
      kind: "config_remove",
      capsule_id,
      target_path_alias,
      config_key: fault.config_key,
      new_value: null,
    }),
    expected_pattern_count: 1,
  };
}

/**
 * Build a complete plan from live file text given a probe fault.
 */
export function buildLiveConfigPlan(
  text: string,
  original_sha256: string,
  probe: ConfigProbeResult,
): ConfigRepairPlan | null {
  if (probe.managed || !probe.fault) return null;
  const fault = probe.fault;

  if (fault.fault_class === CONFIG_FAULT_TYPE) {
    return planTypeFixFromText(text, original_sha256, fault);
  }
  if (fault.fault_class === CONFIG_FAULT_OBSOLETE) {
    const alias =
      fault.path_rel === CONFIG_OVERRIDE_REL
        ? CONFIG_OVERRIDE_ALIAS
        : CONFIG_PRIMARY_ALIAS;
    const rel =
      fault.path_rel === CONFIG_OVERRIDE_REL
        ? CONFIG_OVERRIDE_REL
        : CONFIG_PRIMARY_REL;
    return planRemoveKeyFromText(
      text,
      original_sha256,
      fault,
      CONFIG_OBSOLETE_CAPSULE_ID,
      alias,
      rel,
    );
  }
  if (fault.fault_class === CONFIG_FAULT_SOURCE_CONFLICT) {
    return planRemoveKeyFromText(
      text,
      original_sha256,
      fault,
      CONFIG_SOURCE_CONFLICT_CAPSULE_ID,
      CONFIG_OVERRIDE_ALIAS,
      CONFIG_OVERRIDE_REL,
    );
  }
  return null;
}

function extractOldSummary(
  text: string,
  dottedKey: string,
): { type: string; summary: string } {
  const parsed = parseTomlDocument(text);
  if (!parsed.ok) {
    return { type: "unknown", summary: "unknown(redacted)" };
  }
  const v = getDotted(parsed.root, dottedKey);
  if (!v) {
    // Maybe it's a wrong-type at parent path written as scalar.
    return {
      type: "unknown",
      summary: redactedValueSummary(dottedKey, null),
    };
  }
  return {
    type: v.type,
    summary: redactedValueSummary(dottedKey, v),
  };
}

/**
 * Replace `shell_environment_policy.set = <anything>` with empty table.
 * Handles both table-form assignment under [shell_environment_policy] and
 * dotted form.
 */
export function applySetShellEnvPolicyEmpty(text: string): string | null {
  const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normalized.split("\n");
  let inSection = false;
  let replaced = false;
  const out: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const trimmed = stripComment(line).trim();

    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      const header = trimmed.slice(1, -1).trim();
      inSection = header === "shell_environment_policy";
      out.push(line);
      continue;
    }

    // Dotted assignment at top level
    if (/^shell_environment_policy\.set\s*=/.test(trimmed)) {
      out.push("shell_environment_policy.set = {}");
      replaced = true;
      continue;
    }

    if (inSection && /^set\s*=/.test(trimmed)) {
      out.push("set = {}");
      replaced = true;
      continue;
    }

    out.push(line);
  }

  if (!replaced) return null;
  let next = out.join("\n");
  if (normalized.endsWith("\n") && !next.endsWith("\n")) next += "\n";
  return next;
}

/**
 * Remove a top-level or section key line for a dotted key.
 * Supports obsolete top-level keys and simple override key removal.
 */
export function removeDottedKeyFromToml(
  text: string,
  dottedKey: string,
): string | null {
  const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normalized.split("\n");
  const parts = dottedKey.split(".");
  let inSection = false;
  let sectionName = "";
  let removed = false;
  const out: string[] = [];

  if (parts.length === 1) {
    const key = parts[0]!;
    for (const line of lines) {
      const trimmed = stripComment(line).trim();
      if (trimmed.startsWith("[")) {
        out.push(line);
        continue;
      }
      const m = trimmed.match(/^([A-Za-z0-9_-]+)\s*=/);
      if (m && m[1] === key) {
        removed = true;
        continue;
      }
      out.push(line);
    }
  } else if (parts.length === 2) {
    const section = parts[0]!;
    const key = parts[1]!;
    for (const line of lines) {
      const trimmed = stripComment(line).trim();
      if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
        sectionName = trimmed.slice(1, -1).trim();
        inSection = sectionName === section;
        out.push(line);
        continue;
      }
      // dotted form
      if (new RegExp(`^${escapeRe(section)}\\.${escapeRe(key)}\\s*=`).test(trimmed)) {
        removed = true;
        continue;
      }
      if (inSection) {
        const m = trimmed.match(/^([A-Za-z0-9_-]+)\s*=/);
        if (m && m[1] === key) {
          removed = true;
          continue;
        }
      }
      out.push(line);
    }
  } else {
    // Only depth-1 and depth-2 removals registered.
    return null;
  }

  if (!removed) return null;
  let next = out.join("\n");
  // Drop trailing excess blank lines only lightly.
  if (normalized.endsWith("\n") && !next.endsWith("\n")) next += "\n";
  return next;
}

function stripComment(line: string): string {
  let inStr: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inStr) {
      if (ch === "\\" && inStr === '"') {
        i += 1;
        continue;
      }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = ch;
      continue;
    }
    if (ch === "#") return line.slice(0, i);
  }
  return line;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Startup verification for config repairs (isolated fixture, no shell):
 * 1. original failure absent (fault class gone)
 * 2. config reload (full schema validation)
 * 3. basic registered command marker (model key present when expected)
 */
export function configStartupVerification(
  targetReal: string,
  expectedResultSha: string,
  targetRel: string,
  originalSha: string,
): {
  passed: boolean;
  original_failure_reproduces: boolean;
  core_health_passed: boolean;
  checks: { id: string; passed: boolean; detail: string }[];
  measured_sha256: string | null;
} {
  const checks: { id: string; passed: boolean; detail: string }[] = [];
  const probe = probeConfigControlFiles(targetReal);

  const original_failure_reproduces = probe.fault !== null;
  checks.push({
    id: "original_failure_absent",
    passed: !original_failure_reproduces,
    detail: original_failure_reproduces
      ? `Config fault still present: ${probe.fault?.fault_class ?? "unknown"}`
      : "Original config fault no longer present.",
  });

  // Config reload: primary (and override if present) fully valid.
  let reloadOk = true;
  if (probe.primary && !probe.primary.ok) reloadOk = false;
  if (probe.override && !probe.override.ok) reloadOk = false;
  if (probe.fault) reloadOk = false;
  checks.push({
    id: "config_reload",
    passed: reloadOk,
    detail: reloadOk
      ? "Config reload validation passed."
      : "Config reload validation failed.",
  });

  // Basic registered command: require model key string when primary exists.
  let commandOk = false;
  if (probe.primary && probe.primary.ok) {
    const model = probe.primary.flat.get("model");
    commandOk = model?.type === "string" && typeof model.value === "string";
  } else if (!probe.primary && probe.override && probe.override.ok) {
    // Override-only repair path still OK if no primary fault.
    commandOk = true;
  }
  checks.push({
    id: "registered_command",
    passed: commandOk,
    detail: commandOk
      ? "Basic registered command preconditions satisfied."
      : "Basic registered command preconditions missing.",
  });

  // Result hash of the mutated target file.
  let measured_sha256: string | null = null;
  const doc =
    targetRel === CONFIG_OVERRIDE_REL ? probe.override : probe.primary;
  if (doc) {
    measured_sha256 = doc.sha256;
  }
  checks.push({
    id: "expected_result_hash",
    passed: measured_sha256 === expectedResultSha,
    detail:
      measured_sha256 === expectedResultSha
        ? "Result hash matches capsule expectation."
        : "Result hash does not match capsule expectation.",
  });
  checks.push({
    id: "hash_changed",
    passed: measured_sha256 !== null && measured_sha256 !== originalSha,
    detail:
      measured_sha256 !== originalSha
        ? "Config hash differs from original."
        : "Config hash unchanged.",
  });

  const core_health_passed =
    reloadOk &&
    commandOk &&
    measured_sha256 === expectedResultSha &&
    measured_sha256 !== originalSha;

  const passed =
    checks.every((c) => c.passed) &&
    !original_failure_reproduces &&
    core_health_passed;

  return {
    passed,
    original_failure_reproduces,
    core_health_passed,
    checks,
    measured_sha256,
  };
}

export function isConfigCapsuleId(id: string): boolean {
  return (
    id === CONFIG_WRONG_TYPE_CAPSULE_ID ||
    id === CONFIG_OBSOLETE_CAPSULE_ID ||
    id === CONFIG_SOURCE_CONFLICT_CAPSULE_ID
  );
}

export function relForConfigAlias(alias: string): string | null {
  if (alias === CONFIG_PRIMARY_ALIAS) return CONFIG_PRIMARY_REL;
  if (alias === CONFIG_OVERRIDE_ALIAS) return CONFIG_OVERRIDE_REL;
  return null;
}

export function registeredConfigAliases(): string[] {
  return [CONFIG_PRIMARY_ALIAS, CONFIG_OVERRIDE_ALIAS];
}
