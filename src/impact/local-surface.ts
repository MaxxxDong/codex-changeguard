import {
  INCIDENT_FILE_NAME,
  MAX_INCIDENT_BYTES,
} from "../core/limits.js";
import { parseIncidentJson, FingerprintError } from "../core/fingerprint.js";
import {
  PathSafetyError,
  readBoundedFile,
  resolveNamedCandidate,
  resolveTargetDirectory,
} from "../core/path-safety.js";
import type { LocalSurfaceObservation } from "./types.js";

export class LocalSurfaceError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "LocalSurfaceError";
    this.code = code;
  }
}

/**
 * Observe local Codex surface facts from an isolated target's incident.json.
 * Read-only, named candidate only — reuses Ticket 01 path safety.
 */
export function observeLocalSurface(targetPath: string): LocalSurfaceObservation {
  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch (e) {
    if (e instanceof PathSafetyError) {
      throw new LocalSurfaceError(e.code, e.message);
    }
    throw new LocalSurfaceError("TARGET_ERROR", "Target refused.");
  }

  let incidentMeta;
  try {
    incidentMeta = resolveNamedCandidate(targetReal, INCIDENT_FILE_NAME);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      throw new LocalSurfaceError(e.code, e.message);
    }
    throw new LocalSurfaceError("INCIDENT_ERROR", "Incident refused.");
  }
  if (incidentMeta.size > MAX_INCIDENT_BYTES) {
    throw new LocalSurfaceError("SIZE_LIMIT", "Incident exceeds size limit.");
  }

  let buf: Buffer;
  try {
    buf = readBoundedFile(
      incidentMeta.real,
      MAX_INCIDENT_BYTES,
      incidentMeta.preOpen,
    );
  } catch (e) {
    if (e instanceof PathSafetyError) {
      throw new LocalSurfaceError(e.code, e.message);
    }
    throw new LocalSurfaceError("INCIDENT_READ", "Incident read failed.");
  }

  let fp;
  try {
    fp = parseIncidentJson(buf.toString("utf8"));
  } catch (e) {
    if (e instanceof FingerprintError) {
      throw new LocalSurfaceError(e.code, e.message);
    }
    throw new LocalSurfaceError("MALFORMED_JSON", "Malformed JSON.");
  }

  const feature_ids = fp.feature_ids ?? [];
  // Derive inventory buckets from feature_ids prefixes when present.
  const plugins = feature_ids.filter(
    (id) => id.startsWith("plugin:") || id.startsWith("plugins/"),
  );
  const skills = feature_ids.filter(
    (id) => id.startsWith("skill:") || id.startsWith("skills/"),
  );
  const mcps = feature_ids.filter(
    (id) => id.startsWith("mcp:") || id.startsWith("mcps/"),
  );
  const hooks = feature_ids.filter(
    (id) => id.startsWith("hook:") || id.startsWith("hooks/"),
  );

  const artifact_aliases = (fp.artifact_hashes ?? []).map((a) => a.path_alias);
  const runtime_surfaces = [fp.surface].filter(Boolean);

  return {
    schema_version: 1,
    codex_version: fp.codex_version,
    surface: fp.surface,
    platform_os: fp.platform.os,
    platform_arch: fp.platform.arch,
    config_keys: fp.config_keys ?? [],
    feature_ids,
    plugins,
    skills,
    mcps,
    hooks,
    artifact_aliases,
    runtime_surfaces,
  };
}

/** Build a local surface observation from explicit fields (unit tests). */
export function localSurfaceFromFields(
  partial: Partial<LocalSurfaceObservation> &
    Pick<LocalSurfaceObservation, "surface" | "platform_os">,
): LocalSurfaceObservation {
  return {
    schema_version: 1,
    codex_version: partial.codex_version ?? null,
    surface: partial.surface,
    platform_os: partial.platform_os,
    platform_arch: partial.platform_arch ?? "unknown",
    config_keys: partial.config_keys ?? [],
    feature_ids: partial.feature_ids ?? [],
    plugins: partial.plugins ?? [],
    skills: partial.skills ?? [],
    mcps: partial.mcps ?? [],
    hooks: partial.hooks ?? [],
    artifact_aliases: partial.artifact_aliases ?? [],
    runtime_surfaces: partial.runtime_surfaces ?? [partial.surface],
  };
}
