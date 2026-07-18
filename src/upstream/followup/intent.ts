/**
 * Maintainer prose → closed intent enum only.
 * All prose is untrusted data; never shell argv, patch, path crawl, or model authority.
 */
import {
  detectInstructionLike,
  normalizeForInstructionScan,
  quarantineProse,
} from "../../evidence/quarantine.js";
import { sha256Text } from "../../evidence/canonical.js";
import type { QuarantineRecord } from "../../evidence/types.js";
import {
  MAINTAINER_INTENTS,
  MAX_PROSE,
  REGISTERED_PROBE_IDS,
} from "./limits.js";
import type {
  IntentDetectionResult,
  MaintainerIntent,
  MappedProbePlan,
  RegisteredProbeId,
} from "./types.js";

const INTENT_SET = new Set<string>(MAINTAINER_INTENTS);
const PROBE_SET = new Set<string>(REGISTERED_PROBE_IDS);

/** Keyword → intent mapping (closed enum only; prose never becomes free-form probe). */
const INTENT_PATTERNS: ReadonlyArray<{ intent: MaintainerIntent; re: RegExp }> =
  [
    {
      intent: "request_logs",
      re: /\b(logs?|log\s*file|diagnostic\s*output|stack\s*trace)\b/i,
    },
    {
      intent: "request_reproduction",
      re: /\b(repro(duce|duction)?|minimal\s*steps?|can\s+you\s+reproduce)\b/i,
    },
    {
      intent: "request_version",
      re: /\b(which\s+version|codex\s+version|version\s+info|what\s+version)\b/i,
    },
    {
      intent: "request_platform",
      re: /\b(platform|os\s+version|macos|windows|linux|architecture|arch)\b/i,
    },
    {
      intent: "request_config_probe",
      re: /\b(config(\.toml)?|configuration|settings?\s+file)\b/i,
    },
    {
      intent: "request_core_health",
      re: /\b(health\s*check|core\s*health|still\s+reproduc|does\s+it\s+still)\b/i,
    },
    {
      intent: "acknowledge_closure",
      re: /\b(closing|closed\s+as|marking\s+as\s+closed|resolved\s+upstream)\b/i,
    },
    {
      intent: "acknowledge_duplicate",
      re: /\b(duplicate\s+of|dup\s+of|already\s+tracked)\b/i,
    },
  ];

export function isMaintainerIntent(v: unknown): v is MaintainerIntent {
  return typeof v === "string" && INTENT_SET.has(v);
}

export function isRegisteredProbeId(v: unknown): v is RegisteredProbeId {
  return typeof v === "string" && PROBE_SET.has(v);
}

/**
 * Detect intents from untrusted maintainer prose.
 * Instruction-like content is quarantined; only closed enum results are returned.
 */
export function detectMaintainerIntents(
  prose: string | null | undefined,
): IntentDetectionResult {
  if (prose === null || prose === undefined || prose.length === 0) {
    return {
      intents: ["unknown_or_untrusted"],
      quarantine: null,
      instruction_like: false,
      prose_treated_as_data: true,
    };
  }
  const clipped = prose.length > MAX_PROSE ? prose.slice(0, MAX_PROSE) : prose;
  const q = quarantineProse(clipped, "body");
  const instruction_like = q.quarantine !== null;
  if (instruction_like) {
    return {
      intents: ["unknown_or_untrusted"],
      quarantine: q.quarantine,
      instruction_like: true,
      prose_treated_as_data: true,
    };
  }

  // Extra defense: detectInstructionLike on normalized form even if quarantine missed edge.
  const norm = normalizeForInstructionScan(clipped);
  const reason = detectInstructionLike(norm);
  if (reason) {
    const quarantine: QuarantineRecord = {
      quarantined: true,
      reason,
      original_sha256: sha256Text(clipped),
      placeholder: `<quarantined:body:${reason}>`,
    };
    return {
      intents: ["unknown_or_untrusted"],
      quarantine,
      instruction_like: true,
      prose_treated_as_data: true,
    };
  }

  const found = new Set<MaintainerIntent>();
  for (const p of INTENT_PATTERNS) {
    if (p.re.test(norm)) found.add(p.intent);
  }
  if (found.size === 0) {
    found.add("unknown_or_untrusted");
  }
  return {
    intents: [...found].sort(),
    quarantine: null,
    instruction_like: false,
    prose_treated_as_data: true,
  };
}

/** Map closed intents → registered probe ids only (never invent probes). */
export function mapIntentsToProbes(
  intents: readonly MaintainerIntent[],
): MappedProbePlan {
  const probe_ids = new Set<RegisteredProbeId>();
  for (const intent of intents) {
    switch (intent) {
      case "request_logs":
        probe_ids.add("log_redaction_probe");
        break;
      case "request_reproduction":
        probe_ids.add("reproduction_window_probe");
        break;
      case "request_version":
        probe_ids.add("version_fingerprint_probe");
        break;
      case "request_platform":
        probe_ids.add("platform_identity_probe");
        break;
      case "request_config_probe":
        probe_ids.add("config_control_probe");
        break;
      case "request_core_health":
        probe_ids.add("core_health_readonly");
        break;
      case "acknowledge_closure":
      case "acknowledge_duplicate":
      case "unknown_or_untrusted":
        // No probes for acknowledgement-only / untrusted.
        break;
      default: {
        const _e: never = intent;
        void _e;
      }
    }
  }
  const list = [...probe_ids].sort() as RegisteredProbeId[];
  return {
    intents: [...intents],
    probe_ids: list,
    runnable: list,
  };
}

/**
 * Explicitly refuse to pass prose into shell/argv/patch contexts.
 * Callers must never use return value for execution.
 */
export function refuseProseAsExecutable(_prose: string): never {
  throw new Error(
    "Maintainer prose is untrusted data and must never become shell argv, patch, or path crawl.",
  );
}
