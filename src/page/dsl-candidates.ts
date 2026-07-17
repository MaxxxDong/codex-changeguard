import crypto from "node:crypto";
import { sha256Text } from "../evidence/canonical.js";
import { redactText } from "../core/redact.js";
import { MAX_COMMAND_CANDIDATES, MAX_EXTRACTION_TOKEN } from "./limits.js";
import type {
  PageExtraction,
  RepairDslOpKind,
  UntrustedRepairDslCandidate,
} from "./types.js";

/**
 * Convert page commands only to bounded untrusted Repair DSL candidates.
 * Never execute, authorize, or upgrade them. Ticket 02 gates remain intact.
 */
export function pageCommandsToDslCandidates(
  extraction: PageExtraction,
): UntrustedRepairDslCandidate[] {
  const out: UntrustedRepairDslCandidate[] = [];
  const seen = new Set<string>();

  for (const item of extraction.commands_workarounds) {
    if (out.length >= MAX_COMMAND_CANDIDATES) break;
    const raw = item.value;
    const digest = sha256Text(raw);
    if (seen.has(digest)) continue;
    seen.add(digest);

    const classified = classifyCommand(raw);
    const candidate_id = crypto
      .createHash("sha256")
      .update(`page-dsl:${digest}`)
      .digest("hex")
      .slice(0, 24);

    out.push({
      schema_version: 1,
      candidate_id,
      source: "page_command",
      trust: "untrusted_page",
      status: "candidate_only",
      operation_kind: classified.kind,
      target_path_alias: classified.target_path_alias,
      raw_command_sha256: digest,
      summary: redactText(raw).slice(0, MAX_EXTRACTION_TOKEN),
      eligible_for_validation: classified.eligible_for_validation,
      refused_reasons: classified.refused_reasons,
    });
  }

  // Also scan free-form operations list.
  for (const op of extraction.operations) {
    if (out.length >= MAX_COMMAND_CANDIDATES) break;
    const digest = sha256Text(op);
    if (seen.has(digest)) continue;
    seen.add(digest);
    const classified = classifyCommand(op);
    const candidate_id = crypto
      .createHash("sha256")
      .update(`page-dsl:${digest}`)
      .digest("hex")
      .slice(0, 24);
    out.push({
      schema_version: 1,
      candidate_id,
      source: "page_command",
      trust: "untrusted_page",
      status: "candidate_only",
      operation_kind: classified.kind,
      target_path_alias: classified.target_path_alias,
      raw_command_sha256: digest,
      summary: redactText(op).slice(0, MAX_EXTRACTION_TOKEN),
      eligible_for_validation: classified.eligible_for_validation,
      refused_reasons: classified.refused_reasons,
    });
  }

  return out;
}

function classifyCommand(raw: string): {
  kind: RepairDslOpKind;
  target_path_alias: string | null;
  eligible_for_validation: boolean;
  refused_reasons: string[];
} {
  const t = raw.normalize("NFKC");
  const refused: string[] = [];

  // Hard refuse: arbitrary shell / privilege / network exfil patterns.
  if (
    /\b(sudo|rm\s+-rf|curl\b.*\|\s*(ba)?sh|powershell\s+-enc|Invoke-Expression|eval\s*\()/i.test(
      t,
    )
  ) {
    refused.push("arbitrary_or_destructive_shell");
  }
  if (/\b(exfiltrat|steal\s+token|send\s+secrets|Authorization:)\b/i.test(t)) {
    refused.push("data_exfiltration_pattern");
  }
  if (/\b(registry|reg\s+add|netsh|certutil)\b/i.test(t)) {
    refused.push("system_mutation_forbidden");
  }

  // Map known bounded patterns to MVP DSL kinds (still untrusted candidates).
  if (
    /remove\s+(?:the\s+)?(?:protected[- ]process\s+)?shim\b/i.test(t) ||
    /delete\s+globalThis\.process\b/i.test(t) ||
    /exact_block_removal/i.test(t) ||
    /remove\s+globalThis\.process\s*=/i.test(t)
  ) {
    if (refused.length > 0) {
      return {
        kind: "unknown_unsupported",
        target_path_alias: null,
        eligible_for_validation: false,
        refused_reasons: refused,
      };
    }
    return {
      kind: "exact_block_removal",
      target_path_alias: "BROWSER_CLIENT_COPY_A",
      eligible_for_validation: true,
      refused_reasons: [],
    };
  }

  if (
    /\b(?:set|unset|remove)\s+config\b/i.test(t) ||
    /\bshell_environment_policy\b/i.test(t)
  ) {
    if (refused.length > 0) {
      return {
        kind: "unknown_unsupported",
        target_path_alias: null,
        eligible_for_validation: false,
        refused_reasons: refused,
      };
    }
    const kind: RepairDslOpKind = /\b(?:unset|remove)\b/i.test(t)
      ? "config_remove"
      : "config_set";
    // Config ops are not yet Ticket 02 apply-supported; candidate only, not eligible.
    return {
      kind,
      target_path_alias: null,
      eligible_for_validation: false,
      refused_reasons: ["config_ops_not_in_ticket02_apply_path"],
    };
  }

  refused.push("unmapped_command");
  return {
    kind: "unknown_unsupported",
    target_path_alias: null,
    eligible_for_validation: false,
    refused_reasons: refused,
  };
}

/**
 * Hard boundary: candidates are never authorized apply material.
 * Callers must not pass these digests into repair-apply.
 */
export function assertCandidatesNotAuthorized(
  candidates: UntrustedRepairDslCandidate[],
): void {
  for (const c of candidates) {
    if (c.status !== "candidate_only" || c.trust !== "untrusted_page") {
      throw new Error("Page DSL candidate integrity violation.");
    }
  }
}
