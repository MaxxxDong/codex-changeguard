/**
 * Scoped evidence capsule + privacy-scanned reply draft.
 * external_write: false always; Ticket 11 owns any real write.
 */
import { sha256Canonical, sha256Text } from "../../evidence/canonical.js";
import { assertNoLeakPaths, redactText } from "../../core/redact.js";
import type { QuarantineRecord } from "../../evidence/types.js";
import { MAX_COMMENT, MAX_STRING } from "./limits.js";
import type {
  EvidenceCapsule,
  FollowupProbeResult,
  MaintainerIntent,
  ReplyDraft,
} from "./types.js";

function sanitize(s: string, max = MAX_STRING): string {
  return assertNoLeakPaths(redactText(s)).slice(0, max);
}

export function buildEvidenceCapsule(input: {
  issue_number: number;
  canonical_url: string;
  intents: MaintainerIntent[];
  probe_results: FollowupProbeResult[];
  quarantine: QuarantineRecord | null;
}): EvidenceCapsule {
  const injection = input.quarantine !== null;
  const privacy = {
    secrets_redacted: true as const,
    paths_redacted: true as const,
    session_excluded: true as const,
    injection_quarantined: injection,
    passed: !injection,
  };
  const material = {
    schema_version: 1 as const,
    issue_number: input.issue_number,
    canonical_url: input.canonical_url,
    intents: input.intents,
    probe_results: input.probe_results.map((p) => ({
      probe_id: p.probe_id,
      measured: p.measured,
      passed: p.passed,
      detail: sanitize(p.detail),
      content_digest: p.content_digest,
    })),
    privacy,
    quarantine: input.quarantine,
    external_write: false as const,
    mode: "preview_only" as const,
    locality: "local_only" as const,
    requires_ticket11_confirmation: true as const,
  };
  const capsule_id = `fec_${sha256Canonical(material).slice(0, 24)}`;
  const withId = { ...material, capsule_id, content_sha256: null as string | null };
  const content_sha256 = sha256Canonical({ ...withId, content_sha256: null });
  return {
    ...material,
    capsule_id,
    content_sha256,
  };
}

export function buildReplyDraft(input: {
  capsule: EvidenceCapsule | null;
  disposition: string;
  no_new_evidence: boolean;
  injection: boolean;
}): ReplyDraft {
  if (input.injection) {
    return {
      schema_version: 1,
      external_write: false,
      draft_comment: null,
      draft_status: "BLOCKED",
      privacy_passed: false,
      evidence_capsule_id: input.capsule?.capsule_id ?? null,
      content_digest: sha256Text("blocked"),
    };
  }
  if (input.no_new_evidence) {
    return {
      schema_version: 1,
      external_write: false,
      draft_comment: null,
      draft_status: "NO_NEW_EVIDENCE",
      privacy_passed: true,
      evidence_capsule_id: null,
      content_digest: sha256Text("no_new_evidence"),
    };
  }
  if (!input.capsule || !input.capsule.privacy.passed) {
    return {
      schema_version: 1,
      external_write: false,
      draft_comment: null,
      draft_status: "BLOCKED",
      privacy_passed: false,
      evidence_capsule_id: input.capsule?.capsule_id ?? null,
      content_digest: sha256Text("privacy_blocked"),
    };
  }
  // Disposition-only acknowledgements may have empty probes.
  if (input.capsule.probe_results.length === 0) {
    const comment = sanitize(
      `ChangeGuard local follow-up: disposition ${input.disposition} respected. No automatic reopen/comment/react.`,
      MAX_COMMENT,
    );
    return {
      schema_version: 1,
      external_write: false,
      draft_comment: comment,
      draft_status: "DISPOSITION_ONLY",
      privacy_passed: true,
      evidence_capsule_id: input.capsule.capsule_id,
      content_digest: sha256Text(comment),
    };
  }
  const lines = [
    "### Local follow-up evidence (ChangeGuard draft — not posted)",
    "",
    `Issue: #${input.capsule.issue_number}`,
    `Disposition context: ${sanitize(input.disposition)}`,
    "",
    "#### Registered probe results",
  ];
  for (const p of input.capsule.probe_results) {
    lines.push(
      `- \`${p.probe_id}\`: ${p.passed ? "ok" : "not ok"} — ${sanitize(p.detail)}`,
    );
  }
  lines.push(
    "",
    "_Facts only. Requires separate Ticket 11 preview/confirm before any GitHub write._",
  );
  const draft_comment = sanitize(lines.join("\n"), MAX_COMMENT);
  return {
    schema_version: 1,
    external_write: false,
    draft_comment,
    draft_status: "READY",
    privacy_passed: true,
    evidence_capsule_id: input.capsule.capsule_id,
    content_digest: sha256Text(draft_comment),
  };
}
