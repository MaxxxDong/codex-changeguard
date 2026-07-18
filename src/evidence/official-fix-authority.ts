/**
 * Canonical official-fix binding (Ticket 12 Phase A).
 *
 * Single authority path for follow-up candidate validation and lifecycle
 * supersession. Binds only to the immutable bundled official snapshot;
 * never trusts caller snapshot paths, free-form title tokens, URL tails,
 * digests alone, or `verified` booleans.
 *
 * Lives in the evidence domain to avoid lifecycle ↔ followup cycles.
 */
import {
  assertOfficialUrl,
  AllowlistError,
} from "./allowlist.js";
import { loadBundledSnapshot, SnapshotError } from "./snapshot.js";
import type { OfficialEvidenceItem } from "./types.js";

const SHA256_HEX = /^[a-f0-9]{64}$/;

/**
 * Closed Phase A candidate version syntax (Codex fixtures): exact three-part
 * numeric dotted version. Prerelease / free-form / hash / prose fail closed.
 */
export const PHASE_A_VERSION_RE = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;

/** Phase A measurement profile that may supersede protected-process workarounds. */
export const PHASE_A_PROTECTED_PROCESS_PROFILE_ID =
  "protected_process_shim_v1" as const;

/** Official evidence kinds eligible as upstream-fix references (closed). */
export const UPSTREAM_FIX_EVIDENCE_KINDS = Object.freeze([
  "release",
  "tag",
  "commit",
  "pr",
  "diff",
] as const);

/** Maintainer statuses eligible for upstream-fix references (closed). */
export const UPSTREAM_FIX_MAINTAINER_STATUSES = Object.freeze([
  "official",
  "maintainer",
] as const);

const FIX_KIND_SET = new Set<string>(UPSTREAM_FIX_EVIDENCE_KINDS);
const FIX_STATUS_SET = new Set<string>(UPSTREAM_FIX_MAINTAINER_STATUSES);

/** Mechanism linkage required for protected_process_shim_v1. */
export const PHASE_A_REQUIRED_SURFACE = "browser_control" as const;
export const PHASE_A_REQUIRED_ARTIFACT_ALIAS = "BROWSER_CLIENT_COPY_A" as const;

export type OfficialBindOk = {
  ok: true;
  item: OfficialEvidenceItem;
  canonical_url: string;
  bound_version: string;
};

export type OfficialBindFail = {
  ok: false;
  code: string;
  message: string;
};

export type OfficialBindResult = OfficialBindOk | OfficialBindFail;

export function isPhaseACandidateVersion(raw: string): boolean {
  return typeof raw === "string" && PHASE_A_VERSION_RE.test(raw) && raw.length <= 64;
}

/**
 * Phase A: candidate_version binds only to explicit version_range.to when both
 * are version-shaped (numeric dotted). Title / URL tail / hash / prose never bind.
 */
export function bindCandidateVersionToOfficial(
  candidate_version: string,
  item: OfficialEvidenceItem,
): { ok: true; bound_token: string } | { ok: false; code: string; message: string } {
  if (!isPhaseACandidateVersion(candidate_version)) {
    return {
      ok: false,
      code: "CANDIDATE_VERSION_UNBOUND",
      message:
        "Candidate version is not a closed Phase A version-shaped token (numeric dotted x.y.z).",
    };
  }
  const to = item.version_range?.to;
  if (typeof to !== "string" || !isPhaseACandidateVersion(to)) {
    return {
      ok: false,
      code: "CANDIDATE_VERSION_UNBOUND",
      message:
        "Official evidence item has no explicit version-shaped version_range.to for candidate binding.",
    };
  }
  if (candidate_version !== to) {
    return {
      ok: false,
      code: "CANDIDATE_VERSION_MISMATCH",
      message:
        "Requested candidate_version does not exactly match the official evidence version_range.to.",
    };
  }
  return { ok: true, bound_token: candidate_version };
}

/**
 * Base upstream-fix suitability: closed kind/status, no quarantine, registered mapper.
 * Profile mechanism policy is applied separately.
 */
export function isBaseUpstreamFixItem(item: OfficialEvidenceItem): boolean {
  if (!FIX_KIND_SET.has(item.kind)) return false;
  if (!FIX_STATUS_SET.has(item.maintainer_status)) return false;
  if (item.quarantine !== null) return false;
  if (item.structured?.has_registered_mapper !== true) return false;
  return true;
}

/**
 * Profile mechanism linkage for Phase A protected_process_shim_v1.
 * Requires browser_control in surface/component evidence and
 * BROWSER_CLIENT_COPY_A in artifact aliases.
 */
export function itemMeetsProfileMechanismPolicy(
  item: OfficialEvidenceItem,
  measurement_profile_id: string,
): boolean {
  if (measurement_profile_id !== PHASE_A_PROTECTED_PROCESS_PROFILE_ID) {
    return false;
  }
  if (!isBaseUpstreamFixItem(item)) return false;
  const surfaces = item.structured?.surfaces ?? [];
  const components = item.structured?.component_ids ?? [];
  const aliases = item.structured?.artifact_aliases ?? [];
  const hasBrowserControl =
    surfaces.includes(PHASE_A_REQUIRED_SURFACE) ||
    components.includes(PHASE_A_REQUIRED_SURFACE);
  const hasArtifactAlias = aliases.includes(PHASE_A_REQUIRED_ARTIFACT_ALIAS);
  return hasBrowserControl && hasArtifactAlias;
}

export type BindOfficialEvidenceInput = {
  official_evidence_item_digest: string;
  official_evidence_ref: string;
  /**
   * Closed measurement profile for mechanism policy.
   * Defaults to protected_process_shim_v1 (Phase A only profile).
   */
  measurement_profile_id?: string;
  /**
   * When set, also bind candidate_version to version_range.to (Phase A syntax).
   */
  candidate_version?: string;
};

/**
 * Canonical official-fix binder: exact digest + canonical URL against the
 * immutable bundled snapshot, then profile mechanism policy, then optional
 * version bind. No public snapshot_path override — production and tests use
 * the bundled fixture only.
 */
export function bindOfficialEvidenceItem(
  input: BindOfficialEvidenceInput,
): OfficialBindResult {
  const digest = input.official_evidence_item_digest;
  const ref = input.official_evidence_ref;
  const profile_id =
    typeof input.measurement_profile_id === "string" &&
    input.measurement_profile_id.length > 0
      ? input.measurement_profile_id
      : PHASE_A_PROTECTED_PROCESS_PROFILE_ID;

  if (typeof digest !== "string" || !SHA256_HEX.test(digest)) {
    return {
      ok: false,
      code: "OFFICIAL_EVIDENCE_REQUIRED",
      message: "Allowlisted official evidence item digest required (64 hex).",
    };
  }
  if (typeof ref !== "string" || ref.length === 0 || ref.length > 256) {
    return {
      ok: false,
      code: "OFFICIAL_EVIDENCE_REQUIRED",
      message: "Official evidence ref required.",
    };
  }

  // Fail closed on non-version-shaped candidate_version before snapshot bind
  // so prose titles / commit hashes never act as version authority (P1-A).
  if (
    typeof input.candidate_version === "string" &&
    !isPhaseACandidateVersion(input.candidate_version)
  ) {
    return {
      ok: false,
      code: "CANDIDATE_VERSION_UNBOUND",
      message:
        "Candidate version is not a closed Phase A version-shaped token (numeric dotted x.y.z).",
    };
  }

  let canonical_url: string;
  try {
    ({ canonical_url } = assertOfficialUrl(ref));
  } catch (e) {
    if (e instanceof AllowlistError) {
      return {
        ok: false,
        code: "OFFICIAL_EVIDENCE_REF_REFUSED",
        message: e.message,
      };
    }
    return {
      ok: false,
      code: "OFFICIAL_EVIDENCE_REF_REFUSED",
      message: "Official evidence ref refused.",
    };
  }

  let snapshot;
  try {
    // Always the immutable bundled snapshot — never a caller path.
    snapshot = loadBundledSnapshot();
  } catch (e) {
    if (e instanceof SnapshotError) {
      return {
        ok: false,
        code: "OFFICIAL_SNAPSHOT_REFUSED",
        message: e.message,
      };
    }
    return {
      ok: false,
      code: "OFFICIAL_SNAPSHOT_REFUSED",
      message: "Official evidence snapshot load failed.",
    };
  }

  const matches = snapshot.items.filter(
    (it) =>
      it.content_sha256 === digest && it.canonical_url === canonical_url,
  );
  if (matches.length === 0) {
    const byDigest = snapshot.items.filter((it) => it.content_sha256 === digest);
    const byUrl = snapshot.items.filter((it) => it.canonical_url === canonical_url);
    if (byDigest.length === 0 && byUrl.length === 0) {
      return {
        ok: false,
        code: "OFFICIAL_EVIDENCE_UNBOUND",
        message:
          "Digest and ref do not bind to any pinned official evidence item.",
      };
    }
    if (byDigest.length > 0 && byUrl.length === 0) {
      return {
        ok: false,
        code: "OFFICIAL_EVIDENCE_REF_MISMATCH",
        message: "Official evidence ref does not match digest-bound item URL.",
      };
    }
    if (byDigest.length === 0 && byUrl.length > 0) {
      return {
        ok: false,
        code: "OFFICIAL_EVIDENCE_DIGEST_MISMATCH",
        message: "Official evidence digest does not match ref-bound item.",
      };
    }
    return {
      ok: false,
      code: "OFFICIAL_EVIDENCE_MISMATCH",
      message: "Official evidence digest/ref pair does not match a single item.",
    };
  }
  if (matches.length > 1) {
    return {
      ok: false,
      code: "OFFICIAL_EVIDENCE_AMBIGUOUS",
      message: "Official evidence digest/ref matches multiple snapshot items.",
    };
  }
  const item = matches[0]!;

  if (!isBaseUpstreamFixItem(item)) {
    return {
      ok: false,
      code: "OFFICIAL_EVIDENCE_UNSUITABLE",
      message:
        "Bound evidence item is not suitable as an upstream-fix reference.",
    };
  }

  if (!itemMeetsProfileMechanismPolicy(item, profile_id)) {
    return {
      ok: false,
      code: "OFFICIAL_EVIDENCE_MECHANISM_UNRELATED",
      message:
        "Bound official evidence item is not mechanism-linked to the measurement profile; supersession refused.",
    };
  }

  let bound_version = "";
  if (typeof input.candidate_version === "string") {
    const vbind = bindCandidateVersionToOfficial(input.candidate_version, item);
    if (!vbind.ok) {
      return { ok: false, code: vbind.code, message: vbind.message };
    }
    bound_version = vbind.bound_token;
  } else {
    const to = item.version_range?.to;
    if (typeof to === "string" && isPhaseACandidateVersion(to)) {
      bound_version = to;
    }
  }

  return { ok: true, item, canonical_url, bound_version };
}

/**
 * Full supersession authority bind: digest + URL + mechanism + candidate version.
 * Used by lifecycle supersedeRecipe and follow-up candidate path.
 */
export function bindOfficialFixForSupersession(input: {
  official_evidence_item_digest: string;
  official_evidence_ref: string;
  candidate_version: string;
  measurement_profile_id?: string;
}): OfficialBindResult {
  if (
    typeof input.candidate_version !== "string" ||
    input.candidate_version.length === 0
  ) {
    return {
      ok: false,
      code: "CANDIDATE_VERSION_UNBOUND",
      message: "candidate_version required for official-fix supersession bind.",
    };
  }
  return bindOfficialEvidenceItem({
    official_evidence_item_digest: input.official_evidence_item_digest,
    official_evidence_ref: input.official_evidence_ref,
    measurement_profile_id: input.measurement_profile_id,
    candidate_version: input.candidate_version,
  });
}
