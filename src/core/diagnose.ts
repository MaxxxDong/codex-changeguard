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
import {
  classifyCrashFamily,
  shouldClassifyCrashFamily,
} from "./crash-family.js";
import { probeConfigControlFiles } from "./config/index.js";
import {
  classifyPluginCacheMechanism,
  observePluginCache,
  PluginCacheError,
} from "./plugin-cache/index.js";
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
    crash_classification: partial.crash_classification ?? null,
    model_ranking_applied: partial.model_ranking_applied ?? false,
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
  options: DiagnoseOptions = {},
): DiagnosisResult {
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

  // Ticket 08: plugin-cache inventory comparison (named candidates only).
  try {
    const obs = observePluginCache(targetReal);
    if (obs) {
      const cls = classifyPluginCacheMechanism(obs);
      evidence.push({
        kind: "plugin_cache_inventory",
        detail: `instance_id=${obs.instance_id} cache_path_hash=${obs.cache_path_hash.slice(0, 16)}… generation=${obs.inventory.cache_identity.generation}`,
        measured: true,
      });
      evidence.push({
        kind: "plugin_cache_component_hash",
        detail: `PLUGIN_CACHE_ENTRY sha256=${obs.cache_entry.measured_sha256}`,
        measured: true,
      });
      const trusted_verified =
        obs.trusted_entry.measured_sha256 ===
        obs.manifest.rebuild_source.expected_sha256;
      evidence.push({
        kind: "plugin_cache_manifest_relation",
        detail: `required_version=${obs.manifest.required_version} required_generation=${obs.manifest.required_generation} trusted_verified=${trusted_verified}`,
        measured: true,
      });
      evidence.push({
        kind: "plugin_cache_provenance",
        detail: `rebuild_source=${obs.manifest.rebuild_source.alias} sha256=${obs.trusted_entry.measured_sha256.slice(0, 16)}…`,
        measured: true,
      });

      if (cls.refused_dependency_install_conflation && cls.mechanism === null) {
        evidence.push({
          kind: "plugin_cache_not_dependency_install",
          detail: cls.reason,
          measured: true,
        });
      }

      if (cls.mechanism) {
        evidence.push({
          kind: "plugin_cache_mechanism",
          detail: `mechanism=${cls.mechanism}; ${cls.reason}`,
          measured: true,
        });
        const outFp: IncidentFingerprint = {
          ...declared,
          artifact_hashes: [
            {
              path_alias: "PLUGIN_CACHE_ENTRY",
              sha256: obs.cache_entry.measured_sha256,
            },
          ],
          ast_signature_ids: [],
          local_facts_digest: recomputeLocalFactsDigest(
            declared,
            obs.cache_entry.measured_sha256,
            [],
          ),
        };
        return baseResult({
          ok: true,
          diagnosis_state: "SOURCE_COMPONENT_LOCATED",
          incident_fingerprint: outFp,
          user_resolution: userReceipt(
            "DIAGNOSIS_COMPLETE",
            `Plugin-cache mechanism classified as ${cls.mechanism}. Not a generic dependency-install failure. No repair applied.`,
          ),
          upstream_contribution: upstreamReceipt(
            "CANDIDATE_ONLY",
            "Local plugin-cache mechanism evidence only; not an official root-cause assertion.",
            [],
          ),
          evidence,
          error_code: null,
          error_message: null,
        });
      }

      // Inventory present but no exclusive mechanism → INCONCLUSIVE (negative control path).
      const outFpNc: IncidentFingerprint = {
        ...declared,
        artifact_hashes: [
          {
            path_alias: "PLUGIN_CACHE_ENTRY",
            sha256: obs.cache_entry.measured_sha256,
          },
        ],
        ast_signature_ids: [],
        local_facts_digest: recomputeLocalFactsDigest(
          declared,
          obs.cache_entry.measured_sha256,
          [],
        ),
      };
      return baseResult({
        ok: true,
        diagnosis_state: "INCONCLUSIVE",
        incident_fingerprint: outFpNc,
        user_resolution: userReceipt(
          "INCONCLUSIVE",
          cls.refused_dependency_install_conflation
            ? "Similar symptoms present but refused plugin-cache mechanism attribution (e.g. dependency-install failure)."
            : "Plugin-cache inventory observed without exclusive mechanism evidence.",
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
  } catch (e) {
    if (e instanceof PluginCacheError) {
      return fail(e.code, e.message);
    }
    // Fall through to protected-process path for unrelated targets.
  }

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

  // Positive path: independent hash + AST + compatible surface/error/phase.
  const signatureCompatible =
    declared.error.class === "TypeError" &&
    declared.failure_phase === "extension_handshake" &&
    (declared.surface === "browser_control" ||
      declared.feature_ids?.includes("browser_control") === true) &&
    (declared.stack_frames?.some((f) => f.file === "browser-client.mjs") ??
      false);

  if (artifactPresent && astMatched && signatureCompatible) {
    const outFp: IncidentFingerprint = {
      ...declared,
      artifact_hashes: measuredArtifactSha
        ? [
            {
              path_alias: "BROWSER_CLIENT_COPY_A",
              sha256: measuredArtifactSha,
            },
          ]
        : [],
      ast_signature_ids: measuredAstIds.length ? measuredAstIds : [],
      local_facts_digest: recomputeLocalFactsDigest(
        declared,
        measuredArtifactSha,
        measuredAstIds,
        null,
      ),
    };
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

  // Ticket 07: bounded Codex control-file probe (named candidates only).
  try {
    const configProbe = probeConfigControlFiles(targetReal);
    if (configProbe.control_files_present) {
      evidence.push({
        kind: "config_probe",
        detail: `Control files read=${configProbe.files_read.length} primary=${configProbe.measured_sha_primary ? "yes" : "no"} override=${configProbe.measured_sha_override ? "yes" : "no"}`,
        measured: true,
      });
    }
    if (configProbe.fault) {
      const fault = configProbe.fault;
      evidence.push({
        kind: "config_fault",
        detail: `fault_class=${fault.fault_class} key=${fault.config_key || "(none)"}`,
        measured: true,
      });
      const measuredKeys = fault.config_keys.slice(0, 32);
      const measuredConfig = {
        fault_class: fault.fault_class,
        config_keys: measuredKeys,
        primary_sha256: configProbe.measured_sha_primary,
        override_sha256: configProbe.measured_sha_override,
      };
      const configFpBase: IncidentFingerprint = {
        ...declared,
        failure_phase: "startup",
        error: {
          class: fault.fault_class,
          normalized_message: redactText(fault.detail).slice(0, 512),
          message_digest: null,
        },
        config_keys: measuredKeys,
        artifact_hashes: measuredArtifactSha
          ? [
              {
                path_alias: "BROWSER_CLIENT_COPY_A",
                sha256: measuredArtifactSha,
              },
            ]
          : [],
        ast_signature_ids: measuredAstIds.length ? measuredAstIds : [],
        local_facts_digest: "0".repeat(64), // replaced below
      };
      const outFp: IncidentFingerprint = {
        ...configFpBase,
        local_facts_digest: recomputeLocalFactsDigest(
          configFpBase,
          measuredArtifactSha,
          measuredAstIds,
          measuredConfig,
        ),
      };
      evidence.push({
        kind: "component_located",
        detail:
          "Local Codex control configuration fault located via bounded parser/validator; no project source read.",
        measured: true,
      });
      return baseResult({
        ok: true,
        diagnosis_state: "SOURCE_COMPONENT_LOCATED",
        incident_fingerprint: outFp,
        user_resolution: userReceipt(
          "DIAGNOSIS_COMPLETE",
          `Config/startup fault classified as ${fault.fault_class}. No repair applied.`,
        ),
        upstream_contribution: upstreamReceipt(
          "CANDIDATE_ONLY",
          "openai/codex#33790 remains a user-reported pattern candidate unless official linkage exists.",
          ["openai/codex#33790"],
        ),
        evidence,
        error_code: null,
        error_message: null,
      });
    }
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return fail(e.code, e.message);
    }
    return fail("CONFIG_PROBE_ERROR", "Config probe refused.");
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
      null,
    ),
  };

  // Ticket 09 — Desktop Browser crash-family classifier (Fixture E).
  // Runs only when protected-process localization and config-fault probe
  // did not claim the component. Prefer natural-failure crash metadata;
  // never actively crash primary Codex.
  if (shouldClassifyCrashFamily(outFp)) {
    const modelIds = options.model_preferred_issue_ids ?? null;
    const classification = classifyCrashFamily(outFp, {
      model_preferred_issue_ids: modelIds,
    });

    if (classification.applicable) {
      evidence.push({
        kind: "crash_family_classification",
        detail: classification.summary,
        measured: true,
      });
      evidence.push({
        kind: "local_mechanism",
        detail: `${classification.local_mechanism.status}: ${classification.local_mechanism.summary}`,
        measured: true,
      });
      evidence.push({
        kind: "upstream_match",
        detail: `${classification.upstream_match.status}: ${classification.upstream_match.summary}`,
        measured: true,
      });
      evidence.push({
        kind: "fix_applicability",
        detail: `${classification.fix_applicability.status}: ${classification.fix_applicability.summary}`,
        measured: true,
      });
      if (classification.repair_authorization_eligible === false) {
        evidence.push({
          kind: "repair_authorization_refused",
          detail:
            "No Repair Capsule / authorization eligibility without verified fix applicability; wrong symptom-level patches blocked.",
          measured: true,
        });
      }
      for (const action of classification.refused_actions) {
        evidence.push({
          kind: "refused_action",
          detail: action,
          measured: true,
        });
      }
      for (const req of classification.next_evidence_requirements) {
        evidence.push({
          kind: "next_evidence_requirement",
          detail: req,
          measured: true,
        });
      }
      if (modelIds && modelIds.length > 0) {
        evidence.push({
          kind: "model_ranking_note",
          detail:
            "Optional model ranking may only nudge surviving candidates; hard gates and provenance are deterministic.",
          measured: true,
        });
      }

      const topIds = classification.ranked_candidates.map((c) => c.issue_id);
      const upstreamStatus =
        topIds.length > 0 ? ("CANDIDATE_ONLY" as const) : ("NONE" as const);
      const upstreamSummary =
        topIds.length > 0
          ? `Ranked Issue candidates (Top ${topIds.length}): ${topIds.join(", ")}. Not official root-cause assertions; no verified fix linkage.`
          : classification.summary;

      return baseResult({
        ok: true,
        diagnosis_state: classification.diagnosis_state,
        incident_fingerprint: outFp,
        user_resolution: userReceipt(
          classification.user_resolution_status,
          classification.summary,
        ),
        upstream_contribution: upstreamReceipt(
          upstreamStatus,
          upstreamSummary,
          topIds,
        ),
        evidence,
        error_code: null,
        error_message: null,
        crash_classification: classification,
        model_ranking_applied: Boolean(modelIds && modelIds.length > 0),
      });
    }
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
    crash_classification: null,
    model_ranking_applied: false,
  });
}
