import {
  INCIDENT_FILE_NAME,
  MAX_ARTIFACT_BYTES,
  MAX_INCIDENT_BYTES,
  PROTECTED_ARTIFACT_REL,
  PROTECTED_AST_SIGNATURE_ID,
} from "./limits.js";
import {
  parseIncidentJson,
  recomputeLocalFactsDigest,
  FingerprintError,
} from "./fingerprint.js";
import { measureProtectedProcessAst, sha256Buffer } from "./measure.js";
import {
  PathSafetyError,
  readBoundedFile,
  resolveNamedCandidate,
  resolveTargetDirectory,
} from "./path-safety.js";
import { assertNoLeakPaths, redactText } from "./redact.js";
import type {
  DiagnosisResult,
  DiagnoseOptions,
  IncidentFingerprint,
  MeasuredEvidence,
  UserResolutionReceipt,
  UpstreamContributionReceipt,
} from "./types.js";
import crypto from "node:crypto";

function receiptId(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function baseResult(
  partial: Partial<DiagnosisResult> &
    Pick<
      DiagnosisResult,
      | "ok"
      | "diagnosis_state"
      | "user_resolution"
      | "upstream_contribution"
    >,
): DiagnosisResult {
  return {
    schema_version: 1,
    ok: partial.ok,
    diagnosis_state: partial.diagnosis_state,
    incident_fingerprint: partial.incident_fingerprint ?? null,
    user_resolution: partial.user_resolution,
    upstream_contribution: partial.upstream_contribution,
    evidence: partial.evidence ?? [],
    error_code: partial.error_code ?? null,
    error_message: partial.error_message
      ? assertNoLeakPaths(redactText(partial.error_message))
      : null,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
  };
}

function fail(
  code: string,
  message: string,
  state: DiagnosisResult["diagnosis_state"] = "INCONCLUSIVE",
): DiagnosisResult {
  return baseResult({
    ok: false,
    diagnosis_state: state,
    user_resolution: {
      status: "INCONCLUSIVE",
      summary: "Diagnosis could not complete safely.",
      receipt_id: receiptId("user"),
    },
    upstream_contribution: {
      status: "NONE",
      summary: "No upstream contribution.",
      issue_candidates: [],
      receipt_id: receiptId("upstream"),
    },
    error_code: code,
    error_message: message,
    evidence: [],
  });
}

function userReceipt(
  status: UserResolutionReceipt["status"],
  summary: string,
): UserResolutionReceipt {
  return { status, summary, receipt_id: receiptId("user") };
}

function upstreamReceipt(
  status: UpstreamContributionReceipt["status"],
  summary: string,
  issue_candidates: string[] = [],
): UpstreamContributionReceipt {
  return {
    status,
    summary,
    issue_candidates,
    receipt_id: receiptId("upstream"),
  };
}

/**
 * Shared read-only diagnosis core.
 * Reads only named incident/artifact candidates with lstat/no-follow semantics
 * and explicit byte limits. Never mutates the target, uses the network, applies
 * a repair, or claims RESOLVED_VERIFIED.
 */
export function diagnose(
  targetPath: string,
  _options: DiagnoseOptions = {},
): DiagnosisResult {
  void _options;
  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return fail(e.code, e.message);
    }
    return fail("TARGET_ERROR", "Target refused.");
  }

  // Incident candidate only — no recursive crawl.
  let incidentMeta;
  try {
    incidentMeta = resolveNamedCandidate(targetReal, INCIDENT_FILE_NAME);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return fail(e.code, e.message);
    }
    return fail("INCIDENT_ERROR", "Incident refused.");
  }
  if (incidentMeta.size > MAX_INCIDENT_BYTES) {
    return fail("SIZE_LIMIT", "Incident exceeds size limit.");
  }

  let incidentBuf: Buffer;
  try {
    incidentBuf = readBoundedFile(
      incidentMeta.real,
      MAX_INCIDENT_BYTES,
      incidentMeta.preOpen,
    );
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return fail(e.code, e.message);
    }
    return fail("INCIDENT_READ", "Incident read failed.");
  }

  let declared: IncidentFingerprint;
  try {
    declared = parseIncidentJson(incidentBuf.toString("utf8"));
  } catch (e) {
    if (e instanceof FingerprintError) {
      return fail(e.code, e.message);
    }
    return fail("MALFORMED_JSON", "Malformed JSON.");
  }

  const evidence: MeasuredEvidence[] = [
    {
      kind: "incident_loaded",
      detail: "Named incident.json candidate loaded within size bound.",
      measured: true,
    },
  ];

  // Optional protected-process artifact — named candidate only.
  let measuredArtifactSha: string | null = null;
  let measuredAstIds: string[] = [];
  let artifactPresent = false;
  let astMatched = false;

  try {
    const art = resolveNamedCandidate(targetReal, PROTECTED_ARTIFACT_REL);
    if (art.size > MAX_ARTIFACT_BYTES) {
      return fail("SIZE_LIMIT", "Artifact exceeds size limit.");
    }
    const artBuf = readBoundedFile(art.real, MAX_ARTIFACT_BYTES, art.preOpen);
    artifactPresent = true;
    measuredArtifactSha = sha256Buffer(artBuf);
    evidence.push({
      kind: "artifact_hash",
      detail: `Measured BROWSER_CLIENT_COPY_A sha256=${measuredArtifactSha}`,
      measured: true,
    });

    const ast = measureProtectedProcessAst(artBuf.toString("utf8"));
    if (ast.matched && ast.signatureId) {
      astMatched = true;
      measuredAstIds = [ast.signatureId];
      evidence.push({
        kind: "ast_signature",
        detail: `Measured AST signature ${ast.signatureId} (assignments=${ast.assignmentCount})`,
        measured: true,
      });
    } else {
      evidence.push({
        kind: "ast_signature",
        detail: "Protected-process AST pattern not present in measured bytes.",
        measured: true,
      });
    }

    // Declared hash is contextual only — never self-proof.
    const declaredHash = declared.artifact_hashes?.[0]?.sha256;
    if (declaredHash && declaredHash !== measuredArtifactSha) {
      evidence.push({
        kind: "declared_hash_mismatch",
        detail:
          "Declared artifact hash differs from independently measured bytes; declared value is contextual only.",
        measured: true,
      });
    }
  } catch (e) {
    if (e instanceof PathSafetyError) {
      if (e.code === "CANDIDATE_NOT_FOUND") {
        evidence.push({
          kind: "artifact_absent",
          detail: "Named protected-process artifact candidate not present.",
          measured: true,
        });
      } else {
        return fail(e.code, e.message);
      }
    } else {
      return fail("ARTIFACT_ERROR", "Artifact refused.");
    }
  }

  // Build output fingerprint from declared surface facts + measured evidence.
  const outFp: IncidentFingerprint = {
    ...declared,
    artifact_hashes: measuredArtifactSha
      ? [
          {
            path_alias: "BROWSER_CLIENT_COPY_A",
            sha256: measuredArtifactSha,
          },
        ]
      : declared.artifact_hashes?.length
        ? [] // do not echo unproven declared hashes as measured
        : [],
    ast_signature_ids: measuredAstIds.length
      ? measuredAstIds
      : [], // never promote declared-only AST ids
    local_facts_digest: recomputeLocalFactsDigest(
      declared,
      measuredArtifactSha,
      measuredAstIds,
    ),
  };

  // Positive path: independent hash + AST + compatible surface/error/phase.
  const signatureCompatible =
    declared.error.class === "TypeError" &&
    declared.failure_phase === "extension_handshake" &&
    (declared.surface === "browser_control" ||
      declared.feature_ids?.includes("browser_control") === true) &&
    (declared.stack_frames?.some((f) => f.file === "browser-client.mjs") ??
      false);

  if (artifactPresent && astMatched && signatureCompatible) {
    // SOURCE_COMPONENT_LOCATED only from independently measured local evidence.
    evidence.push({
      kind: "component_located",
      detail:
        "Local protected-process pattern located via measured hash and AST; Issue #32925 remains a candidate only.",
      measured: true,
    });
    return baseResult({
      ok: true,
      diagnosis_state: "SOURCE_COMPONENT_LOCATED",
      incident_fingerprint: outFp,
      user_resolution: userReceipt(
        "DIAGNOSIS_COMPLETE",
        "Affected local component located from independent measurements. No repair applied.",
      ),
      upstream_contribution: upstreamReceipt(
        "CANDIDATE_ONLY",
        "openai/codex#32925 is an issue candidate; not an official root-cause assertion.",
        ["openai/codex#32925"],
      ),
      evidence,
      error_code: null,
      error_message: null,
    });
  }

  // Declared AST id alone cannot locate a component.
  if (
    (declared.ast_signature_ids?.includes(PROTECTED_AST_SIGNATURE_ID) ??
      false) &&
    !astMatched
  ) {
    evidence.push({
      kind: "declared_only_ast_refused",
      detail:
        "Declared AST signature id is not independently measured; no component claim.",
      measured: true,
    });
  }

  // Negative / insufficient evidence → INCONCLUSIVE; never invent root cause.
  return baseResult({
    ok: true,
    diagnosis_state: "INCONCLUSIVE",
    incident_fingerprint: outFp,
    user_resolution: userReceipt(
      "INCONCLUSIVE",
      "Insufficient independent local evidence; no root cause claimed.",
    ),
    upstream_contribution: upstreamReceipt(
      "NONE",
      "No upstream contribution; evidence insufficient for candidate promotion.",
      [],
    ),
    evidence,
    error_code: null,
    error_message: null,
  });
}
