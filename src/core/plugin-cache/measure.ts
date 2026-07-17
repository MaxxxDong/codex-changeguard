/**
 * Bounded named-candidate inventory comparison for Ticket 08.
 * No cache crawl, no execution of cached code, no network/credentials.
 */
import { sha256Buffer } from "../measure.js";
import {
  PathSafetyError,
  readBoundedFile,
  resolveNamedCandidate,
} from "../path-safety.js";
import {
  MAX_PLUGIN_CACHE_FILE_BYTES,
  MAX_PLUGIN_JSON_BYTES,
  PLUGIN_BUNDLED_ENTRY_REL,
  PLUGIN_CACHE_ENTRY_ALIAS,
  PLUGIN_CACHE_ENTRY_REL,
  PLUGIN_HEALTH_REL,
  PLUGIN_INVENTORY_REL,
  PLUGIN_LOCAL_INTENT_REL,
  PLUGIN_MANIFEST_REL,
  PLUGIN_RECON_STATE_REL,
  PLUGIN_TRUSTED_ENTRY_REL,
} from "./limits.js";
import type {
  MeasuredComponent,
  PluginCacheObservation,
  PluginInventory,
  PluginManifest,
  ReconState,
} from "./types.js";

export class PluginCacheError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PluginCacheError";
    this.code = code;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function requireString(v: unknown, max: number): string | null {
  if (typeof v !== "string" || v.length === 0 || v.length > max) return null;
  return v;
}

function requireSha(v: unknown): string | null {
  if (typeof v !== "string" || !/^[a-f0-9]{64}$/.test(v)) return null;
  return v;
}

function requireInt(v: unknown, min: number, max: number): number | null {
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
    return null;
  }
  return v;
}

function readJsonCandidate(
  targetReal: string,
  rel: string,
  maxBytes: number,
): unknown {
  const meta = resolveNamedCandidate(targetReal, rel);
  if (meta.size > maxBytes) {
    throw new PluginCacheError("SIZE_LIMIT", "Plugin-cache JSON exceeds size limit.");
  }
  const buf = readBoundedFile(meta.real, maxBytes, meta.preOpen);
  try {
    return JSON.parse(buf.toString("utf8"));
  } catch {
    throw new PluginCacheError("MALFORMED_JSON", "Malformed plugin-cache JSON.");
  }
}

function measureFile(
  targetReal: string,
  rel: string,
  alias: string,
): MeasuredComponent {
  const meta = resolveNamedCandidate(targetReal, rel);
  if (meta.size > MAX_PLUGIN_CACHE_FILE_BYTES) {
    throw new PluginCacheError("SIZE_LIMIT", "Plugin-cache file exceeds size limit.");
  }
  const buf = readBoundedFile(meta.real, MAX_PLUGIN_CACHE_FILE_BYTES, meta.preOpen);
  return {
    alias,
    rel,
    measured_sha256: sha256Buffer(buf),
    size: buf.length,
  };
}

function parseInventory(raw: unknown): PluginInventory {
  if (!isPlainObject(raw) || raw.schema_version !== 1) {
    throw new PluginCacheError("MALFORMED_INVENTORY", "Inventory schema refused.");
  }
  const instance_id = requireString(raw.instance_id, 128);
  if (!instance_id || !/^[a-zA-Z0-9._:-]{1,128}$/.test(instance_id)) {
    throw new PluginCacheError("MALFORMED_INVENTORY", "Instance id refused.");
  }
  if (!isPlainObject(raw.cache_identity)) {
    throw new PluginCacheError("MALFORMED_INVENTORY", "Cache identity refused.");
  }
  const alias = requireString(raw.cache_identity.alias, 128);
  const identity_hash = requireSha(raw.cache_identity.identity_hash);
  const generation = requireInt(raw.cache_identity.generation, 0, 1_000_000);
  if (!alias || !identity_hash || generation === null) {
    throw new PluginCacheError("MALFORMED_INVENTORY", "Cache identity fields refused.");
  }
  if (typeof raw.dependency_install_failure !== "boolean") {
    throw new PluginCacheError(
      "MALFORMED_INVENTORY",
      "dependency_install_failure flag required.",
    );
  }
  if (!Array.isArray(raw.components) || raw.components.length < 1 || raw.components.length > 16) {
    throw new PluginCacheError("MALFORMED_INVENTORY", "Components refused.");
  }
  const components = raw.components.map((c) => {
    if (!isPlainObject(c)) {
      throw new PluginCacheError("MALFORMED_INVENTORY", "Component refused.");
    }
    const calias = requireString(c.alias, 128);
    const version = requireString(c.version, 64);
    const provenance = requireString(c.provenance, 32);
    if (
      !calias ||
      !version ||
      (provenance !== "bundled" &&
        provenance !== "shared_cache" &&
        provenance !== "trusted_rebuild" &&
        provenance !== "local_override")
    ) {
      throw new PluginCacheError("MALFORMED_INVENTORY", "Component fields refused.");
    }
    const declared =
      c.declared_sha256 === null || c.declared_sha256 === undefined
        ? null
        : requireSha(c.declared_sha256);
    if (c.declared_sha256 !== null && c.declared_sha256 !== undefined && !declared) {
      throw new PluginCacheError("MALFORMED_INVENTORY", "Declared hash refused.");
    }
    return {
      alias: calias,
      version,
      provenance: provenance as PluginInventory["components"][0]["provenance"],
      declared_sha256: declared,
    };
  });
  return {
    schema_version: 1,
    instance_id,
    cache_identity: { alias, identity_hash, generation },
    components,
    dependency_install_failure: raw.dependency_install_failure,
  };
}

function parseManifest(raw: unknown): PluginManifest {
  if (!isPlainObject(raw) || raw.schema_version !== 1) {
    throw new PluginCacheError("MALFORMED_MANIFEST", "Manifest schema refused.");
  }
  const required_generation = requireInt(raw.required_generation, 0, 1_000_000);
  const required_version = requireString(raw.required_version, 64);
  if (required_generation === null || !required_version) {
    throw new PluginCacheError("MALFORMED_MANIFEST", "Manifest version fields refused.");
  }
  if (!Array.isArray(raw.components) || raw.components.length < 1 || raw.components.length > 16) {
    throw new PluginCacheError("MALFORMED_MANIFEST", "Manifest components refused.");
  }
  const components = raw.components.map((c) => {
    if (!isPlainObject(c)) {
      throw new PluginCacheError("MALFORMED_MANIFEST", "Manifest component refused.");
    }
    const calias = requireString(c.alias, 128);
    const expected_sha256 = requireSha(c.expected_sha256);
    const version = requireString(c.version, 64);
    const provenance = requireString(c.provenance, 32);
    if (
      !calias ||
      !expected_sha256 ||
      !version ||
      (provenance !== "bundled" &&
        provenance !== "shared_cache" &&
        provenance !== "trusted_rebuild")
    ) {
      throw new PluginCacheError("MALFORMED_MANIFEST", "Manifest component fields refused.");
    }
    return {
      alias: calias,
      expected_sha256,
      version,
      provenance: provenance as PluginManifest["components"][0]["provenance"],
    };
  });
  if (!isPlainObject(raw.rebuild_source)) {
    throw new PluginCacheError("MALFORMED_MANIFEST", "Rebuild source refused.");
  }
  const rs = raw.rebuild_source;
  const rsAlias = requireString(rs.alias, 128);
  const rsHash = requireSha(rs.expected_sha256);
  const rsVersion = requireString(rs.version, 64);
  if (!rsAlias || !rsHash || !rsVersion || rs.verified !== true) {
    throw new PluginCacheError("MALFORMED_MANIFEST", "Rebuild source fields refused.");
  }
  return {
    schema_version: 1,
    required_generation,
    required_version,
    components,
    rebuild_source: {
      alias: rsAlias,
      verified: true,
      expected_sha256: rsHash,
      version: rsVersion,
    },
  };
}

function parseRecon(raw: unknown): ReconState {
  if (!isPlainObject(raw) || raw.schema_version !== 1) {
    throw new PluginCacheError("MALFORMED_RECON", "Recon state refused.");
  }
  if (
    typeof raw.last_cycle_overwrote_local !== "boolean" ||
    typeof raw.will_overwrite_on_next_cycle !== "boolean"
  ) {
    throw new PluginCacheError("MALFORMED_RECON", "Recon flags refused.");
  }
  let local_intent_sha256: string | null = null;
  if (raw.local_intent_sha256 !== null && raw.local_intent_sha256 !== undefined) {
    local_intent_sha256 = requireSha(raw.local_intent_sha256);
    if (!local_intent_sha256) {
      throw new PluginCacheError("MALFORMED_RECON", "Local intent hash refused.");
    }
  }
  return {
    schema_version: 1,
    last_cycle_overwrote_local: raw.last_cycle_overwrote_local,
    will_overwrite_on_next_cycle: raw.will_overwrite_on_next_cycle,
    local_intent_sha256,
  };
}

/**
 * Load bounded named plugin-cache candidates and measure component hashes.
 * Returns null when inventory is absent (not a plugin-cache target).
 */
export function observePluginCache(
  targetReal: string,
): PluginCacheObservation | null {
  // Presence gate: inventory is the named entry for this fault pack.
  try {
    resolveNamedCandidate(targetReal, PLUGIN_INVENTORY_REL);
  } catch (e) {
    if (e instanceof PathSafetyError && e.code === "CANDIDATE_NOT_FOUND") {
      return null;
    }
    if (e instanceof PathSafetyError) {
      throw new PluginCacheError(e.code, e.message);
    }
    throw e;
  }

  try {
    const inventory = parseInventory(
      readJsonCandidate(targetReal, PLUGIN_INVENTORY_REL, MAX_PLUGIN_JSON_BYTES),
    );
    const manifest = parseManifest(
      readJsonCandidate(targetReal, PLUGIN_MANIFEST_REL, MAX_PLUGIN_JSON_BYTES),
    );

    let recon: ReconState | null = null;
    try {
      recon = parseRecon(
        readJsonCandidate(targetReal, PLUGIN_RECON_STATE_REL, MAX_PLUGIN_JSON_BYTES),
      );
    } catch (e) {
      if (e instanceof PathSafetyError && e.code === "CANDIDATE_NOT_FOUND") {
        recon = null;
      } else if (e instanceof PluginCacheError) {
        throw e;
      } else if (e instanceof PathSafetyError) {
        throw new PluginCacheError(e.code, e.message);
      } else {
        throw e;
      }
    }

    const cache_entry = measureFile(
      targetReal,
      PLUGIN_CACHE_ENTRY_REL,
      PLUGIN_CACHE_ENTRY_ALIAS,
    );
    let bundled_entry: MeasuredComponent | null = null;
    try {
      bundled_entry = measureFile(
        targetReal,
        PLUGIN_BUNDLED_ENTRY_REL,
        "BUNDLED_PLUGIN_ENTRY",
      );
    } catch (e) {
      if (!(e instanceof PathSafetyError) || e.code !== "CANDIDATE_NOT_FOUND") {
        if (e instanceof PluginCacheError) throw e;
        if (e instanceof PathSafetyError) {
          throw new PluginCacheError(e.code, e.message);
        }
        throw e;
      }
    }
    const trusted_entry = measureFile(
      targetReal,
      PLUGIN_TRUSTED_ENTRY_REL,
      "TRUSTED_PLUGIN_ENTRY",
    );
    let local_intent: MeasuredComponent | null = null;
    try {
      local_intent = measureFile(
        targetReal,
        PLUGIN_LOCAL_INTENT_REL,
        "LOCAL_INTENT_ENTRY",
      );
    } catch (e) {
      if (!(e instanceof PathSafetyError) || e.code !== "CANDIDATE_NOT_FOUND") {
        if (e instanceof PluginCacheError) throw e;
        if (e instanceof PathSafetyError) {
          throw new PluginCacheError(e.code, e.message);
        }
        throw e;
      }
    }

    let health_ok: boolean | null = null;
    try {
      const healthRaw = readJsonCandidate(
        targetReal,
        PLUGIN_HEALTH_REL,
        MAX_PLUGIN_JSON_BYTES,
      );
      if (isPlainObject(healthRaw) && typeof healthRaw.ok === "boolean") {
        health_ok = healthRaw.ok;
      }
    } catch (e) {
      if (!(e instanceof PathSafetyError) || e.code !== "CANDIDATE_NOT_FOUND") {
        if (e instanceof PluginCacheError) throw e;
        if (e instanceof PathSafetyError) {
          throw new PluginCacheError(e.code, e.message);
        }
        throw e;
      }
    }

    // Cache path hash: hash of identity alias only (never absolute path).
    const cache_path_hash = inventory.cache_identity.identity_hash;

    return {
      inventory,
      manifest,
      recon,
      cache_entry,
      bundled_entry,
      trusted_entry,
      local_intent,
      health_ok,
      cache_path_hash,
      instance_id: inventory.instance_id,
    };
  } catch (e) {
    if (e instanceof PluginCacheError) throw e;
    if (e instanceof PathSafetyError) {
      throw new PluginCacheError(e.code, e.message);
    }
    throw e;
  }
}

/** True when the target looks like a plugin-cache fixture (inventory present). */
export function isPluginCacheTarget(targetReal: string): boolean {
  try {
    resolveNamedCandidate(targetReal, PLUGIN_INVENTORY_REL);
    return true;
  } catch {
    return false;
  }
}
