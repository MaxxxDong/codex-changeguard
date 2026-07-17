/**
 * Schema validation and fault classification for Codex control config.
 * Priority when multiple issues exist: syntax > type > obsolete > source conflict
 * is applied per-file; cross-file source conflict is checked after both parse.
 */
import {
  CONFIG_FAULT_OBSOLETE,
  CONFIG_FAULT_SOURCE_CONFLICT,
  CONFIG_FAULT_SYNTAX,
  CONFIG_FAULT_TYPE,
  type ConfigFaultClass,
} from "./limits.js";
import {
  expectedTypeForKey,
  KNOWN_TOP_LEVEL_KEYS,
  OBSOLETE_CONFIG_KEYS,
  type TomlTable,
  type TomlValue,
} from "./schema.js";
import { flattenTable, getDotted, parseTomlDocument } from "./toml-parse.js";

export interface ConfigFault {
  fault_class: ConfigFaultClass;
  /** Primary affected dotted key (may be empty for pure syntax errors). */
  config_key: string;
  /** All related keys (bounded). */
  config_keys: string[];
  detail: string;
  /** Path alias of the primary fault file. */
  path_alias: string;
  /** Relative path of the primary fault file. */
  path_rel: string;
}

export interface ValidatedConfigDoc {
  ok: true;
  root: TomlTable;
  flat: Map<string, TomlValue>;
  path_alias: string;
  path_rel: string;
  sha256: string;
}

export interface InvalidConfigDoc {
  ok: false;
  fault: ConfigFault;
  path_alias: string;
  path_rel: string;
  sha256: string;
  /** Partial root when parse succeeded but schema failed. */
  root: TomlTable | null;
}

export type ConfigDocResult = ValidatedConfigDoc | InvalidConfigDoc;

/**
 * Validate a single control file's UTF-8 text.
 */
export function validateConfigText(
  text: string,
  path_alias: string,
  path_rel: string,
  sha256: string,
): ConfigDocResult {
  const parsed = parseTomlDocument(text);
  if (!parsed.ok) {
    return {
      ok: false,
      path_alias,
      path_rel,
      sha256,
      root: null,
      fault: {
        fault_class: CONFIG_FAULT_SYNTAX,
        config_key: "",
        config_keys: [],
        detail: `TOML ${parsed.error}: ${parsed.message}`,
        path_alias,
        path_rel,
      },
    };
  }

  const flat = flattenTable(parsed.root);
  if (!flat) {
    return {
      ok: false,
      path_alias,
      path_rel,
      sha256,
      root: parsed.root,
      fault: {
        fault_class: CONFIG_FAULT_SYNTAX,
        config_key: "",
        config_keys: [],
        detail: "Config table depth or structure refused.",
        path_alias,
        path_rel,
      },
    };
  }

  // Unknown top-level keys → type/schema refusal (not silent accept).
  for (const key of parsed.root.keys()) {
    if (!KNOWN_TOP_LEVEL_KEYS.has(key)) {
      return {
        ok: false,
        path_alias,
        path_rel,
        sha256,
        root: parsed.root,
        fault: {
          fault_class: CONFIG_FAULT_TYPE,
          config_key: key,
          config_keys: [key],
          detail: `Unknown top-level config key '${key}' refused.`,
          path_alias,
          path_rel,
        },
      };
    }
  }

  // Type checks on known paths.
  for (const [dotted, val] of flat) {
    // Skip pure table containers that are known parents.
    if (val.type === "table" && (dotted === "shell_environment_policy" || dotted === "features")) {
      continue;
    }
    if (OBSOLETE_CONFIG_KEYS.has(dotted)) {
      // Defer obsolete after type? Prefer type first for wrong-typed obsolete.
      // Classify obsolete keys as obsolete fault.
      continue;
    }
    const expected = expectedTypeForKey(dotted);
    if (expected === null) {
      // Nested unknown under known parent — refuse.
      const top = dotted.split(".")[0]!;
      if (KNOWN_TOP_LEVEL_KEYS.has(top)) {
        return {
          ok: false,
          path_alias,
          path_rel,
          sha256,
          root: parsed.root,
          fault: {
            fault_class: CONFIG_FAULT_TYPE,
            config_key: dotted,
            config_keys: [dotted],
            detail: `Unknown config path '${dotted}' refused.`,
            path_alias,
            path_rel,
          },
        };
      }
      continue;
    }
    if (expected === "string_table") {
      if (val.type !== "table" || !(val.value instanceof Map)) {
        return {
          ok: false,
          path_alias,
          path_rel,
          sha256,
          root: parsed.root,
          fault: {
            fault_class: CONFIG_FAULT_TYPE,
            config_key: dotted,
            config_keys: [dotted],
            detail: `Config key '${dotted}' has wrong type ${val.type}; expected string table.`,
            path_alias,
            path_rel,
          },
        };
      }
      for (const [sk, sv] of val.value as Map<string, TomlValue>) {
        if (sv.type !== "string") {
          const ck = `${dotted}.${sk}`;
          return {
            ok: false,
            path_alias,
            path_rel,
            sha256,
            root: parsed.root,
            fault: {
              fault_class: CONFIG_FAULT_TYPE,
              config_key: ck,
              config_keys: [dotted, ck],
              detail: `Config key '${ck}' has wrong type ${sv.type}; expected string.`,
              path_alias,
              path_rel,
            },
          };
        }
      }
      continue;
    }
    if (val.type !== expected) {
      return {
        ok: false,
        path_alias,
        path_rel,
        sha256,
        root: parsed.root,
        fault: {
          fault_class: CONFIG_FAULT_TYPE,
          config_key: dotted,
          config_keys: [dotted],
          detail: `Config key '${dotted}' has wrong type ${val.type}; expected ${expected}.`,
          path_alias,
          path_rel,
        },
      };
    }
  }

  // Obsolete keys (after type checks so wrong-type of known key wins first for non-obsolete).
  for (const [dotted] of flat) {
    if (OBSOLETE_CONFIG_KEYS.has(dotted)) {
      return {
        ok: false,
        path_alias,
        path_rel,
        sha256,
        root: parsed.root,
        fault: {
          fault_class: CONFIG_FAULT_OBSOLETE,
          config_key: dotted,
          config_keys: [dotted],
          detail: `Obsolete config key '${dotted}' must be removed.`,
          path_alias,
          path_rel,
        },
      };
    }
  }

  return {
    ok: true,
    root: parsed.root,
    flat,
    path_alias,
    path_rel,
    sha256,
  };
}

/**
 * Detect conflicting values for the same dotted key across primary + override.
 * Only called when both documents parse and pass single-file schema checks.
 */
export function detectSourceConflict(
  primary: ValidatedConfigDoc,
  override: ValidatedConfigDoc,
): ConfigFault | null {
  const conflicts: string[] = [];
  for (const [key, ov] of override.flat) {
    if (ov.type === "table") continue;
    const pv = primary.flat.get(key);
    if (!pv || pv.type === "table") continue;
    if (!valuesEqual(pv, ov)) {
      conflicts.push(key);
    }
  }
  if (conflicts.length === 0) return null;
  const sorted = conflicts.slice().sort();
  return {
    fault_class: CONFIG_FAULT_SOURCE_CONFLICT,
    config_key: sorted[0]!,
    config_keys: sorted.slice(0, 32),
    detail: `Conflicting configuration sources for key(s): ${sorted.slice(0, 8).join(", ")}`,
    path_alias: override.path_alias,
    path_rel: override.path_rel,
  };
}

function valuesEqual(a: TomlValue, b: TomlValue): boolean {
  if (a.type !== b.type) return false;
  if (a.type === "table" || b.type === "table") return false;
  return Object.is(a.value, b.value);
}

/** Check that a document has no faults (for post-repair verification). */
export function documentIsFullyValid(text: string): boolean {
  const r = validateConfigText(text, "x", "x", "0".repeat(64));
  return r.ok;
}

/** Read a dotted value type from a validated-or-partial root. */
export function readValue(
  root: TomlTable | null,
  dotted: string,
): TomlValue | null {
  if (!root) return null;
  return getDotted(root, dotted) ?? null;
}
