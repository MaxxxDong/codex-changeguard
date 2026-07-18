/**
 * Candidate-fix validation in a strict disposable target.
 * Closes T06 trust seam: caller-declared flags alone never justify
 * RECOMMEND_UPGRADE or SUPERSEDED_BY_UPSTREAM_FIX.
 *
 * Supersession requires:
 * 1. Measured registered-probe / core-regression evidence (fault absent + core ok)
 * 2. Allowlisted official evidence item digest (64 hex)
 *
 * Never download/install/mutate OpenAI binaries; guidance only.
 * Never automatically uninstall a user workaround.
 */
import { runCanary, supersedeRecipe } from "../../core/lifecycle/index.js";
import { resolveTargetDirectory } from "../../core/path-safety.js";
import type { VersionGuidance } from "../../core/lifecycle/types.js";
import { measureCandidateFaultAndCore } from "./probes.js";
import type {
  CandidateValidationInput,
  CandidateValidationResult,
  FollowupProbeResult,
} from "./types.js";
import { MAX_RECIPE_ID_LEN, MAX_VERSION_LEN } from "./limits.js";
import { parseCanonicalIssue, IssueUrlError } from "./issue-url.js";

const SHA256_HEX = /^[a-f0-9]{64}$/;

export function validateCandidateFix(
  input: CandidateValidationInput,
): CandidateValidationResult {
  const baseFail = (
    status: CandidateValidationResult["status"],
    code: string,
    message: string,
    probes: FollowupProbeResult[] = [],
  ): CandidateValidationResult => ({
    ok: false,
    status,
    measured_fault_absent: null,
    measured_core_ok: null,
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
  if (
    typeof input.official_evidence_item_digest !== "string" ||
    !SHA256_HEX.test(input.official_evidence_item_digest)
  ) {
    return baseFail(
      "REFUSED",
      "OFFICIAL_EVIDENCE_REQUIRED",
      "Allowlisted official evidence item digest required (64 hex).",
    );
  }
  if (
    typeof input.official_evidence_ref !== "string" ||
    input.official_evidence_ref.length === 0 ||
    input.official_evidence_ref.length > 256
  ) {
    return baseFail(
      "REFUSED",
      "OFFICIAL_EVIDENCE_REQUIRED",
      "Official evidence ref required.",
    );
  }

  // Explicitly ignore caller-declared authority flags for decisions.
  void input.original_fault_absent;
  void input.core_regressions_passed;
  void input.verified;

  const measured = measureCandidateFaultAndCore(input.targetPath);
  const { measured_fault_absent, measured_core_ok, probe_results } = measured;

  // Drive canary with MEASURED values only (canary_executed true + measured flags).
  const canary = runCanary({
    targetPath: input.targetPath,
    candidate_version: input.candidate_version,
    original_fault_absent: measured_fault_absent,
    core_regressions_passed: measured_core_ok,
    canary_executed: true,
    measured_outcomes: true,
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
      official_evidence_item_digest: input.official_evidence_item_digest,
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

  if (!measured_fault_absent || !measured_core_ok) {
    return {
      ok: true,
      status: "CANDIDATE_REGRESSED",
      measured_fault_absent,
      measured_core_ok,
      version_guidance: version_guidance ?? "HOLD_KNOWN_GOOD",
      recipe_status: "ACTIVE_WORKAROUND",
      recipe_recommendable: true,
      official_evidence_item_digest: input.official_evidence_item_digest,
      binary_downloaded: false,
      binary_installed: false,
      workaround_uninstalled: false,
      detail:
        "Candidate fix failed measured probes; hold KNOWN_GOOD / keep workaround. No binary install; no auto-uninstall.",
      probe_results,
      evidence: [
        ...canary.evidence,
        {
          kind: "followup_candidate_regressed",
          detail: `fault_absent=${measured_fault_absent};core_ok=${measured_core_ok}`,
          measured: true,
        },
      ],
      error_code: null,
      error_message: null,
    };
  }

  // Measured pass + allowlisted official evidence digest → supersede temporary recipe.
  // verified/measured_validation are set only after independent probe measurement above;
  // caller-supplied verified=true alone never reaches this branch without measures.
  const sup = supersedeRecipe({
    targetPath: input.targetPath,
    recipe_id: input.recipe_id,
    upstream: {
      ref: input.official_evidence_ref,
      evidence_digest: input.official_evidence_item_digest,
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
      official_evidence_item_digest: input.official_evidence_item_digest,
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
    official_evidence_item_digest: input.official_evidence_item_digest,
    binary_downloaded: false,
    binary_installed: false,
    workaround_uninstalled: false,
    detail:
      "Measured candidate validation passed with official evidence digest; recipe SUPERSEDED_BY_UPSTREAM_FIX. Guidance only — no binary install/uninstall.",
    probe_results,
    evidence: [
      ...canary.evidence,
      ...sup.evidence,
      {
        kind: "followup_candidate_superseded",
        detail: `recipe_id=${input.recipe_id};digest=${input.official_evidence_item_digest.slice(0, 12)}…`,
        measured: true,
      },
    ],
    error_code: null,
    error_message: null,
  };
}
