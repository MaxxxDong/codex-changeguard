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
 *    exactly one bundled-snapshot item suitable as an upstream-fix reference,
 *    with Phase A mechanism linkage for the measurement profile
 * 3. Candidate version exactly bound to explicit version_range.to (version-shaped)
 *
 * Never download/install/mutate OpenAI binaries; guidance only.
 * Never automatically uninstall a user workaround.
 */
import { runCanary, supersedeRecipe } from "../../core/lifecycle/index.js";
import { resolveTargetDirectory } from "../../core/path-safety.js";
import type { VersionGuidance } from "../../core/lifecycle/types.js";
import { bindOfficialEvidenceItem } from "../../evidence/official-fix-authority.js";
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
} from "./limits.js";
import { parseCanonicalIssue, IssueUrlError } from "./issue-url.js";

// Re-export canonical binders so followup public surface stays stable.
export {
  bindOfficialEvidenceItem,
  bindCandidateVersionToOfficial,
} from "../../evidence/official-fix-authority.js";

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
  // Caller-controlled snapshot_path is not a trust root (P2-1); ignore if present.
  void (input as { snapshot_path?: unknown }).snapshot_path;

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
          measurement_profile_id: profile_id,
          candidate_version: input.candidate_version,
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
      version_guidance: null,
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

  // supersedeRecipe re-runs the same canonical official binder + consumes witness.
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
      // P2-3: refused supersede must not claim RECOMMEND_UPGRADE success.
      version_guidance: null,
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
