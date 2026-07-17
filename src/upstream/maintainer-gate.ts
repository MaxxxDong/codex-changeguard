import type {
  DoctorSanitizationResult,
  DuplicateAssessment,
  MaintainerValueGateResult,
  UpstreamPreviewRequest,
  UpstreamRoute,
} from "./types.js";

/**
 * Maintainer-value gate: correct route, duplicate search, surface,
 * platform/version or explicit unknown, actual behavior, ≥1 technical signal,
 * sanitized baseline diagnostics, privacy review, reproduction quality /
 * intermittent marker, and material value over an existing Issue.
 */
export function evaluateMaintainerValueGate(input: {
  request: UpstreamPreviewRequest;
  route: UpstreamRoute;
  duplicate: DuplicateAssessment;
  doctor: DoctorSanitizationResult;
  privacy_passed: boolean;
}): MaintainerValueGateResult {
  const { request, route, duplicate, doctor, privacy_passed } = input;
  const checks: MaintainerValueGateResult["checks"] = [];

  checks.push({
    id: "route",
    passed:
      route === "GITHUB_ISSUE" ||
      route === "GITHUB_DISCUSSIONS" ||
      route === "BUGCROWD" ||
      route === "OPENAI_SUPPORT",
    detail: `Routed to ${route}.`,
  });

  checks.push({
    id: "duplicate_search",
    passed:
      route !== "GITHUB_ISSUE" || request.duplicate_search.searched === true,
    detail: request.duplicate_search.searched
      ? `Duplicate search recorded (${request.duplicate_search.candidates.length} candidates).`
      : "GitHub Issue path requires duplicate search.",
  });

  checks.push({
    id: "surface",
    passed: request.surface !== "unknown" || route !== "GITHUB_ISSUE",
    detail:
      request.surface !== "unknown"
        ? `Surface ${request.surface}.`
        : "Surface unknown on Issue path.",
  });

  const hasPlatform =
    (request.platform.os !== null && request.platform.os.length > 0) ||
    (request.platform.unknown_reason !== null &&
      request.platform.unknown_reason.length > 0);
  const hasVersion =
    (request.codex_version !== null && request.codex_version.length > 0) ||
    (request.version_unknown_reason !== null &&
      request.version_unknown_reason.length > 0);
  checks.push({
    id: "platform_version",
    passed: hasPlatform && hasVersion,
    detail:
      hasPlatform && hasVersion
        ? "Platform and version (or explicit unknown reason) present."
        : "Missing platform and/or version (or unknown reason).",
  });

  checks.push({
    id: "actual_behavior",
    passed: request.actual_behavior.trim().length > 0,
    detail: "Actual behavior described.",
  });

  checks.push({
    id: "technical_signal",
    passed: request.technical_signals.length >= 1,
    detail:
      request.technical_signals.length >= 1
        ? `${request.technical_signals.length} technical signal(s).`
        : "At least one technical signal required.",
  });

  // Baseline diagnostics: doctor included, or explicit refusal recorded with reason.
  const baselineOk =
    doctor.included ||
    doctor.refused_reasons.includes("doctor_json_not_provided") ||
    doctor.refused_reasons.length > 0;
  checks.push({
    id: "baseline_diagnostics",
    passed: baselineOk,
    detail: doctor.included
      ? `Sanitized doctor fields: ${doctor.inclusion_manifest.join(", ")}`
      : `Doctor not included (${doctor.refused_reasons.join(", ") || "none"}).`,
  });

  checks.push({
    id: "privacy_review",
    passed:
      privacy_passed &&
      request.privacy_review.secrets_redacted &&
      request.privacy_review.paths_redacted &&
      request.privacy_review.session_excluded,
    detail: privacy_passed
      ? "Privacy review flags accepted."
      : "Privacy review incomplete or failed.",
  });

  const reproOk =
    request.reproduction.quality === "reliable" ||
    request.reproduction.quality === "once" ||
    (request.reproduction.quality === "intermittent" &&
      !!request.reproduction.intermittent_marker) ||
    (request.reproduction.quality === "unknown" &&
      !!request.reproduction.intermittent_marker);
  checks.push({
    id: "reproduction_quality",
    passed: reproOk,
    detail: reproOk
      ? `Reproduction quality ${request.reproduction.quality}.`
      : "Intermittent/unknown reproduction requires an explicit marker.",
  });

  // Material value over existing Issue:
  // - NEW_INCIDENT / RELATED_NOT_SAME → new body has value
  // - EXACT_DUPLICATE zero-delta → reaction-only is correct (passes: low-noise compliance)
  // - EXACT_DUPLICATE material delta → comment has material value
  // - private/support routes → value is correct channel choice
  let materialValue = true;
  let materialDetail = "Material value over existing Issue satisfied.";
  if (route === "GITHUB_ISSUE") {
    if (duplicate.state === "EXACT_DUPLICATE" && !duplicate.evidence_delta_material) {
      materialValue = true;
      materialDetail =
        "Exact duplicate with zero Evidence Delta correctly recommends subscribe/upvote only (no low-value comment).";
    } else if (
      duplicate.state === "EXACT_DUPLICATE" &&
      duplicate.evidence_delta_material
    ) {
      materialValue = duplicate.draft_comment !== null;
      materialDetail = materialValue
        ? "Material Evidence Delta produces a structured comment preview."
        : "Material Evidence Delta missing structured comment.";
    } else if (duplicate.state === "RELATED_NOT_SAME") {
      materialValue =
        duplicate.draft_body !== null && duplicate.cross_link_issue_ids.length > 0;
      materialDetail = materialValue
        ? "Related-not-same remains separate with cross-links."
        : "Related-not-same missing body or cross-links.";
    } else {
      materialValue = duplicate.draft_body !== null;
      materialDetail = materialValue
        ? "New incident draft body present."
        : "New incident missing draft body.";
    }
  }
  checks.push({
    id: "material_value",
    passed: materialValue,
    detail: materialDetail,
  });

  const failed_ids = checks.filter((c) => !c.passed).map((c) => c.id);
  return {
    passed: failed_ids.length === 0,
    checks,
    failed_ids,
  };
}
