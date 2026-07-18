/**
 * Candidate-fix validation in a strict disposable target.
 * Closes T06 trust seam: caller-declared flags alone never justify
 * RECOMMEND_UPGRADE or SUPERSEDED_BY_UPSTREAM_FIX.
 *
 * Supersession requires:
 * 1. Positive registered live measurement (process-local witness) —
 *    baseline repro + candidate fault absent + core ok, bound to
 *    candidate_version / profile / artifact digests — never absence-as-success
 *    or caller booleans or persisted self-attestation JSON
 * 2. Real pinned official evidence item: digest + canonical URL both match
 *    exactly one bundled-snapshot item suitable as an upstream-fix reference
 * 3. Candidate version meaningfully bound to the official item
 *    (version_range.to or normalized release/tag version token)
 *
 * Never download/install/mutate OpenAI binaries; guidance only.
 * Never automatically uninstall a user workaround.
 */
import { runCanary, supersedeRecipe } from "../../core/lifecycle/index.js";
import { resolveTargetDirectory } from "../../core/path-safety.js";
import type { VersionGuidance } from "../../core/lifecycle/types.js";
import {
  assertOfficialUrl,
  AllowlistError,
  loadBundledSnapshot,
  SnapshotError,
} from "../../evidence/index.js";
import type { OfficialEvidenceItem } from "../../evidence/types.js";
import {
  measureWithRegisteredProfile,
  loadCandidateMeasurement,
  PROTECTED_PROCESS_SHIM_PROFILE_V1,
} from "./probes.js";
import type {
  CandidateValidationInput,
  CandidateValidationResult,
  FollowupProbeResult,
} from "./types.js";
import {
  MAX_RECIPE_ID_LEN,
  MAX_VERSION_LEN,
  UPSTREAM_FIX_EVIDENCE_KINDS,
  UPSTREAM_FIX_MAINTAINER_STATUSES,
} from "./limits.js";
import { parseCanonicalIssue, IssueUrlError } from "./issue-url.js";

const SHA256_HEX = /^[a-f0-9]{64}$/;
const FIX_KIND_SET = new Set<string>(UPSTREAM_FIX_EVIDENCE_KINDS);
const FIX_STATUS_SET = new Set<string>(UPSTREAM_FIX_MAINTAINER_STATUSES);

function isSuitableUpstreamFix(item: OfficialEvidenceItem): boolean {
  if (!FIX_KIND_SET.has(item.kind)) return false;
  if (!FIX_STATUS_SET.has(item.maintainer_status)) return false;
  if (item.quarantine !== null) return false;
  return true;
}

/**
 * Normalize a version label for binding comparison.
 * Strips common release/tag prefixes (rust-v, v, desktop-win-) and lowercases.
 */
function normalizeVersionToken(raw: string): string {
  let s = raw.trim().toLowerCase();
  // Drop trailing prerelease/build suffixes for binding against release "to".
  // Keep the core numeric-ish token.
  s = s.replace(/^rust-v/, "");
  s = s.replace(/^desktop-win-/, "");
  s = s.replace(/^notes-unmapped-/, "");
  s = s.replace(/^v/, "");
  return s;
}

/**
 * Bind requested candidate_version to a suitable official evidence item.
 * Prefer version_range.to; also accept exact normalized title/tag token match.
 * Fail closed when the official item cannot bind a candidate version.
 */
export function bindCandidateVersionToOfficial(
  candidate_version: string,
  item: OfficialEvidenceItem,
): { ok: true; bound_token: string } | { ok: false; code: string; message: string } {
  const cand = normalizeVersionToken(candidate_version);
  if (!cand) {
    return {
      ok: false,
      code: "CANDIDATE_VERSION_UNBOUND",
      message: "Candidate version cannot bind to official release token.",
    };
  }

  const tokens = new Set<string>();
  if (item.version_range?.to) {
    tokens.add(normalizeVersionToken(item.version_range.to));
  }
  // Release/tag title often embeds the version (e.g. rust-v0.50.0).
  if (typeof item.title === "string" && item.title.length > 0) {
    tokens.add(normalizeVersionToken(item.title));
  }
  // Canonical URL last path segment as a token source.
  try {
    const u = new URL(item.canonical_url);
    const seg = u.pathname.split("/").filter(Boolean).pop();
    if (seg) tokens.add(normalizeVersionToken(seg));
  } catch {
    /* ignore */
  }

  tokens.delete("");
  if (tokens.size === 0) {
    return {
      ok: false,
      code: "CANDIDATE_VERSION_UNBOUND",
      message:
        "Official evidence item has no bindable release/version token for candidate_version.",
    };
  }

  // Exact normalized token match against version_range.to / title / tag segment.
  if (tokens.has(cand)) {
    return { ok: true, bound_token: cand };
  }

  return {
    ok: false,
    code: "CANDIDATE_VERSION_MISMATCH",
    message:
      "Requested candidate_version is not meaningfully bound to the official evidence release/tag version.",
  };
}

/**
 * Bind caller digest+ref to exactly one real official-evidence snapshot item.
 * Fail closed on forge, mismatch, ambiguity, non-official URL, unsuitable kinds.
 */
export function bindOfficialEvidenceItem(input: {
  official_evidence_item_digest: string;
  official_evidence_ref: string;
  /** Optional bounded local snapshot path (tests/orchestration); validated by loadBundledSnapshot. */
  snapshot_path?: string;
}):
  | { ok: true; item: OfficialEvidenceItem; canonical_url: string }
  | { ok: false; code: string; message: string } {
  const digest = input.official_evidence_item_digest;
  const ref = input.official_evidence_ref;
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
    snapshot = loadBundledSnapshot(input.snapshot_path);
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
    // Distinguish digest-only vs ref-only for clearer fail-closed diagnostics.
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
  if (!isSuitableUpstreamFix(item)) {
    return {
      ok: false,
      code: "OFFICIAL_EVIDENCE_UNSUITABLE",
      message:
        "Bound evidence item is not suitable as an upstream-fix reference.",
    };
  }
  return { ok: true, item, canonical_url };
}

export function validateCandidateFix(
  input: CandidateValidationInput,
): CandidateValidationResult {
  const baseFail = (
    status: CandidateValidationResult["status"],
    code: string,
    message: string,
    probes: FollowupProbeResult[] = [],
    measured: {
      measured_fault_absent: boolean | null;
      measured_core_ok: boolean | null;
    } = { measured_fault_absent: null, measured_core_ok: null },
  ): CandidateValidationResult => ({
    ok: false,
    status,
    measured_fault_absent: measured.measured_fault_absent,
    measured_core_ok: measured.measured_core_ok,
    version_guidance: null,
    recipe_status: null,
    recipe_recommendable: null,
    official_evidence_item_digest: null,
    binary_downloaded: false,
    binary_installed: false,
    workaround_uninstalled: false,
    detail: message,
    probe_results: probes,
    evidence: [],
    error_code: code,
    error_message: message,
  });

  try {
    resolveTargetDirectory(input.targetPath);
  } catch {
    return baseFail("REFUSED", "INVALID_TARGET", "Isolated target refused.");
  }

  // Issue must be canonical openai/codex
  try {
    parseCanonicalIssue(input.issue_number);
  } catch (e) {
    if (e instanceof IssueUrlError) {
      return baseFail(
        e.code === "UNAUTHORIZED_REPOSITORY"
          ? "REFUSED"
          : "UNAUTHORIZED_ISSUE",
        e.code,
        e.message,
      );
    }
    return baseFail("INVALID_INPUT", "INVALID_ISSUE", "Invalid issue.");
  }

  if (
    typeof input.candidate_version !== "string" ||
    input.candidate_version.length === 0 ||
    input.candidate_version.length > MAX_VERSION_LEN
  ) {
    return baseFail("INVALID_INPUT", "INVALID_VERSION", "Invalid candidate_version.");
  }
  if (
    typeof input.recipe_id !== "string" ||
    input.recipe_id.length === 0 ||
    input.recipe_id.length > MAX_RECIPE_ID_LEN
  ) {
    return baseFail("INVALID_INPUT", "INVALID_RECIPE", "Invalid recipe_id.");
  }

  // Explicitly ignore caller-declared authority flags for decisions.
  void input.original_fault_absent;
  void input.core_regressions_passed;
  void input.verified;

  // Profile must be the closed Phase-A id (or fail closed).
  const profile_id =
    typeof input.measurement_profile_id === "string"
      ? input.measurement_profile_id
      : "";
  if (!profile_id) {
    return baseFail(
      "REFUSED",
      "UNSUPPORTED_PROFILE",
      "measurement_profile_id required (closed registered profile only).",
    );
  }

  if (
    typeof input.baselineTargetPath !== "string" ||
    input.baselineTargetPath.length === 0
  ) {
    return baseFail(
      "REFUSED",
      "BASELINE_REQUIRED",
      "baselineTargetPath required for registered live measurement.",
    );
  }

  // Adversarial: if legacy self-attestation JSON is present, refuse as authority
  // before even running live probes (content hash is not measurement authority).
  const legacy = loadCandidateMeasurement(
    input.targetPath,
    input.candidate_version,
  );
  if (legacy.error_code === "MEASUREMENT_SELF_ATTESTATION_DEPRECATED") {
    return baseFail(
      "REFUSED",
      legacy.error_code,
      legacy.detail,
      legacy.probe_results,
    );
  }

  // ── Positive measurement via closed registered live profile ──────────────
  const measured = measureWithRegisteredProfile({
    targetPath: input.targetPath,
    baselineTargetPath: input.baselineTargetPath,
    candidate_version: input.candidate_version,
    profile_id,
    nowMs: input.nowMs,
  });
  const {
    measured_fault_absent,
    measured_core_ok,
    probe_results,
    verdict,
    witness,
  } = measured;

  if (verdict === "inconclusive") {
    return baseFail(
      "REFUSED",
      measured.error_code ?? "MEASUREMENT_INCONCLUSIVE",
      measured.detail ||
        "Positive candidate measurement inconclusive; active workaround preserved.",
      probe_results,
      { measured_fault_absent, measured_core_ok },
    );
  }

  // Bind official evidence BEFORE any RECOMMEND_UPGRADE / supersession path.
  // Negative measurement may still report CANDIDATE_REGRESSED without requiring
  // a successful bind (preserve workaround); forged digests must not unlock upgrade.
  const bind =
    verdict === "positive"
      ? bindOfficialEvidenceItem({
          official_evidence_item_digest: input.official_evidence_item_digest,
          official_evidence_ref: input.official_evidence_ref,
          snapshot_path: input.snapshot_path,
        })
      : null;

  if (verdict === "positive" && bind && !bind.ok) {
    return baseFail(
      "REFUSED",
      bind.code,
      bind.message,
      probe_results,
      { measured_fault_absent, measured_core_ok },
    );
  }

  // Version binding: positive path requires candidate_version meaningfully
  // bound to the official release/tag token.
  if (verdict === "positive" && bind && bind.ok) {
    const vbind = bindCandidateVersionToOfficial(
      input.candidate_version,
      bind.item,
    );
    if (!vbind.ok) {
      return baseFail(
        "REFUSED",
        vbind.code,
        vbind.message,
        probe_results,
        { measured_fault_absent, measured_core_ok },
      );
    }
  }

  // Drive canary with MEASURED values + live witness only.
  // Public boolean path cannot recommend upgrade without witness.
  if (verdict === "positive" && !witness) {
    return baseFail(
      "REFUSED",
      "LIVE_WITNESS_REQUIRED",
      "Positive measurement missing process-local live witness.",
      probe_results,
      { measured_fault_absent, measured_core_ok },
    );
  }

  const canary = runCanary({
    targetPath: input.targetPath,
    candidate_version: input.candidate_version,
    original_fault_absent: measured_fault_absent === true,
    core_regressions_passed: measured_core_ok === true,
    canary_executed: true,
    measured_outcomes: true,
    live_measurement_witness: witness ?? undefined,
    nowMs: input.nowMs,
  });

  let version_guidance: VersionGuidance | null = canary.version_guidance;
  if (!canary.ok) {
    return {
      ok: false,
      status: "REFUSED",
      measured_fault_absent,
      measured_core_ok,
      version_guidance,
      recipe_status: null,
      recipe_recommendable: null,
      official_evidence_item_digest: null,
      binary_downloaded: false,
      binary_installed: false,
      workaround_uninstalled: false,
      detail: canary.error_message ?? "Canary refused.",
      probe_results,
      evidence: canary.evidence,
      error_code: canary.error_code ?? "CANARY_REFUSED",
      error_message: canary.error_message,
    };
  }

  if (verdict === "negative" || !measured_fault_absent || !measured_core_ok) {
    return {
      ok: true,
      status: "CANDIDATE_REGRESSED",
      measured_fault_absent,
      measured_core_ok,
      version_guidance: version_guidance ?? "HOLD_KNOWN_GOOD",
      recipe_status: "ACTIVE_WORKAROUND",
      recipe_recommendable: true,
      official_evidence_item_digest: null,
      binary_downloaded: false,
      binary_installed: false,
      workaround_uninstalled: false,
      detail:
        "Candidate fix failed measured probes; hold KNOWN_GOOD / keep workaround. No binary install; no auto-uninstall. Artifact-level disposable pair evidence only.",
      probe_results,
      evidence: [
        ...canary.evidence,
        {
          kind: "followup_candidate_regressed",
          detail: `fault_absent=${measured_fault_absent};core_ok=${measured_core_ok};profile=${profile_id}`,
          measured: true,
        },
      ],
      error_code: null,
      error_message: null,
    };
  }

  // Positive measurement + bound official evidence → supersede temporary recipe.
  if (!bind || !bind.ok) {
    return baseFail(
      "REFUSED",
      "OFFICIAL_EVIDENCE_REQUIRED",
      "Official evidence binding required before supersession.",
      probe_results,
      { measured_fault_absent, measured_core_ok },
    );
  }

  if (canary.version_guidance !== "RECOMMEND_UPGRADE") {
    return baseFail(
      "REFUSED",
      "LIVE_WITNESS_REQUIRED",
      "Canary did not obtain live-witness RECOMMEND_UPGRADE; supersession refused.",
      probe_results,
      { measured_fault_absent, measured_core_ok },
    );
  }

  const boundDigest = bind.item.content_sha256;
  const boundRef = bind.canonical_url;

  const digests = measured.public_digests;
  const digestNote =
    digests && digests.candidate_artifact_sha256
      ? `candidate_artifact=${digests.candidate_artifact_sha256.slice(0, 12)}…`
      : "candidate_artifact=unknown";

  const sup = supersedeRecipe({
    targetPath: input.targetPath,
    recipe_id: input.recipe_id,
    candidate_version: input.candidate_version,
    live_measurement_witness: witness,
    upstream: {
      ref: boundRef,
      evidence_digest: boundDigest,
      verified: true,
      measured_validation: true,
    },
    nowMs: input.nowMs,
  });

  if (!sup.ok) {
    return {
      ok: false,
      status: "REFUSED",
      measured_fault_absent,
      measured_core_ok,
      version_guidance: "RECOMMEND_UPGRADE",
      recipe_status: null,
      recipe_recommendable: null,
      official_evidence_item_digest: boundDigest,
      binary_downloaded: false,
      binary_installed: false,
      workaround_uninstalled: false,
      detail: sup.error_message ?? "Supersession refused.",
      probe_results,
      evidence: [...canary.evidence, ...sup.evidence],
      error_code: sup.error_code ?? "SUPERSESSION_REFUSED",
      error_message: sup.error_message,
    };
  }

  const recipe = sup.recipe;
  return {
    ok: true,
    status: "SUPERSEDED",
    measured_fault_absent,
    measured_core_ok,
    version_guidance: "RECOMMEND_UPGRADE",
    recipe_status: recipe?.status ?? "SUPERSEDED_BY_UPSTREAM_FIX",
    recipe_recommendable: recipe ? recipe.recommendable : false,
    official_evidence_item_digest: boundDigest,
    binary_downloaded: false,
    binary_installed: false,
    workaround_uninstalled: false,
    detail:
      `Measured candidate validation passed with live witness + bound official evidence; recipe SUPERSEDED_BY_UPSTREAM_FIX. ` +
      `Artifact-level disposable pair evidence (${digestNote}; profile=${PROTECTED_PROCESS_SHIM_PROFILE_V1}) — not cryptographic proof of an installed binary identity. Guidance only — no binary install/uninstall.`,
    probe_results,
    evidence: [
      ...canary.evidence,
      ...sup.evidence,
      {
        kind: "followup_candidate_superseded",
        detail: `recipe_id=${input.recipe_id};digest=${boundDigest.slice(0, 12)}…;url_bound=true;live_witness=true;${digestNote}`,
        measured: true,
      },
    ],
    error_code: null,
    error_message: null,
  };
}
