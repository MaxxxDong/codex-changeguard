/**
 * Bounded read-only probe for Codex control files under an isolated target.
 * Named candidates only; no-follow path containment; no project crawl.
 */
import { sha256Buffer } from "../measure.js";
import {
  PathSafetyError,
  readBoundedFile,
  resolveNamedCandidate,
} from "../path-safety.js";
import {
  CONFIG_MANAGED_ALIAS,
  CONFIG_MANAGED_POLICY_REL,
  CONFIG_OVERRIDE_ALIAS,
  CONFIG_OVERRIDE_REL,
  CONFIG_PRIMARY_ALIAS,
  CONFIG_PRIMARY_REL,
  MAX_CONFIG_FILE_BYTES,
  type ConfigFaultClass,
} from "./limits.js";
import {
  detectSourceConflict,
  type ConfigDocResult,
  type ConfigFault,
  validateConfigText,
} from "./validate.js";

export interface ManagedPolicyInfo {
  managed: true;
  policy_class: string;
  admin_owned: boolean;
  signed: boolean;
  permission_bound: boolean;
  path_alias: string;
  path_rel: string;
  sha256: string;
}

export interface ConfigProbeResult {
  /** True when at least one registered control file was present. */
  control_files_present: boolean;
  primary: ConfigDocResult | null;
  override: ConfigDocResult | null;
  managed: ManagedPolicyInfo | null;
  /** Highest-priority fault, if any. */
  fault: ConfigFault | null;
  measured_sha_primary: string | null;
  measured_sha_override: string | null;
  /** Paths actually opened (relative) — for harness no-project-read proofs. */
  files_read: string[];
}

/**
 * Probe registered Codex control files only.
 * Order: primary → override → managed marker.
 * Fault priority: syntax/type/obsolete on either file, then source conflict.
 */
export function probeConfigControlFiles(targetReal: string): ConfigProbeResult {
  const files_read: string[] = [];
  let primary: ConfigDocResult | null = null;
  let override: ConfigDocResult | null = null;
  let managed: ManagedPolicyInfo | null = null;
  let measured_sha_primary: string | null = null;
  let measured_sha_override: string | null = null;

  primary = readOne(targetReal, CONFIG_PRIMARY_REL, CONFIG_PRIMARY_ALIAS, files_read);
  if (primary) measured_sha_primary = primary.sha256;

  override = readOne(
    targetReal,
    CONFIG_OVERRIDE_REL,
    CONFIG_OVERRIDE_ALIAS,
    files_read,
  );
  if (override) measured_sha_override = override.sha256;

  managed = readManaged(targetReal, files_read);

  const control_files_present =
    primary !== null || override !== null || managed !== null;

  // Fault selection: single-file faults first (primary then override), then conflict.
  let fault: ConfigFault | null = null;
  if (primary && !primary.ok) {
    fault = primary.fault;
  } else if (override && !override.ok) {
    fault = override.fault;
  } else if (
    primary &&
    primary.ok &&
    override &&
    override.ok
  ) {
    fault = detectSourceConflict(primary, override);
  }

  return {
    control_files_present,
    primary,
    override,
    managed,
    fault,
    measured_sha_primary,
    measured_sha_override,
    files_read,
  };
}

function readOne(
  targetReal: string,
  rel: string,
  alias: string,
  files_read: string[],
): ConfigDocResult | null {
  let meta;
  try {
    meta = resolveNamedCandidate(targetReal, rel);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      if (e.code === "CANDIDATE_NOT_FOUND") return null;
      // Symlink / escape / invalid — rethrow as fault-like null? Fail closed as fault.
      throw e;
    }
    throw e;
  }
  if (meta.size > MAX_CONFIG_FILE_BYTES) {
    return {
      ok: false,
      path_alias: alias,
      path_rel: rel,
      sha256: "0".repeat(64),
      root: null,
      fault: {
        fault_class: "ConfigTomlSyntaxError" as ConfigFaultClass,
        config_key: "",
        config_keys: [],
        detail: "Config file exceeds size limit.",
        path_alias: alias,
        path_rel: rel,
      },
    };
  }
  const buf = readBoundedFile(meta.real, MAX_CONFIG_FILE_BYTES, meta.preOpen);
  files_read.push(rel);
  const sha = sha256Buffer(buf);
  const text = buf.toString("utf8");
  return validateConfigText(text, alias, rel, sha);
}

function readManaged(
  targetReal: string,
  files_read: string[],
): ManagedPolicyInfo | null {
  let meta;
  try {
    meta = resolveNamedCandidate(targetReal, CONFIG_MANAGED_POLICY_REL);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      if (e.code === "CANDIDATE_NOT_FOUND") return null;
      throw e;
    }
    throw e;
  }
  if (meta.size > MAX_CONFIG_FILE_BYTES) {
    throw new PathSafetyError("SIZE_LIMIT", "Managed policy exceeds size limit.");
  }
  const buf = readBoundedFile(meta.real, MAX_CONFIG_FILE_BYTES, meta.preOpen);
  files_read.push(CONFIG_MANAGED_POLICY_REL);
  const sha = sha256Buffer(buf);
  let raw: unknown;
  try {
    raw = JSON.parse(buf.toString("utf8"));
  } catch {
    // Malformed managed marker → treat as managed fail-closed (admin required).
    return {
      managed: true,
      policy_class: "unparsed_managed_marker",
      admin_owned: true,
      signed: false,
      permission_bound: true,
      path_alias: CONFIG_MANAGED_ALIAS,
      path_rel: CONFIG_MANAGED_POLICY_REL,
      sha256: sha,
    };
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return {
      managed: true,
      policy_class: "invalid_managed_marker",
      admin_owned: true,
      signed: false,
      permission_bound: true,
      path_alias: CONFIG_MANAGED_ALIAS,
      path_rel: CONFIG_MANAGED_POLICY_REL,
      sha256: sha,
    };
  }
  const o = raw as Record<string, unknown>;
  const policy_class =
    typeof o.policy_class === "string" && o.policy_class.length > 0 && o.policy_class.length <= 128
      ? o.policy_class
      : "enterprise_policy";
  return {
    managed: true,
    policy_class,
    admin_owned: o.admin_owned === true || o.admin_owned === undefined,
    signed: o.signed === true,
    permission_bound: o.permission_bound === true || o.permission_bound === undefined,
    path_alias: CONFIG_MANAGED_ALIAS,
    path_rel: CONFIG_MANAGED_POLICY_REL,
    sha256: sha,
  };
}

export function faultClassRank(c: ConfigFaultClass): number {
  switch (c) {
    case "ConfigTomlSyntaxError":
      return 0;
    case "ConfigSchemaTypeError":
      return 1;
    case "ConfigObsoleteKeyError":
      return 2;
    case "ConfigSourceConflictError":
      return 3;
    default:
      return 99;
  }
}
