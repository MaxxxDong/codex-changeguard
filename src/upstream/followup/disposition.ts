/**
 * Deterministic upstream disposition policy.
 * Never auto-reopen, cross-post, comment, react, or argue with upstream.
 */
import type {
  DispositionPolicyResult,
  UpstreamDisposition,
} from "./types.js";
import { UPSTREAM_DISPOSITIONS } from "./limits.js";

const DISPOSITION_SET = new Set<string>(UPSTREAM_DISPOSITIONS);

export function isUpstreamDisposition(v: unknown): v is UpstreamDisposition {
  return typeof v === "string" && DISPOSITION_SET.has(v);
}

export function applyDispositionPolicy(input: {
  disposition: UpstreamDisposition;
  duplicate_of_issue?: number | null;
}): DispositionPolicyResult {
  const d = input.disposition;
  let migrate_to_issue: number | null = null;
  let user_guidance: string;

  switch (d) {
    case "needs_info":
      user_guidance =
        "Upstream needs more information. Collect a bounded evidence capsule and draft a reply; never auto-post.";
      break;
    case "cannot_reproduce":
      user_guidance =
        "Upstream cannot reproduce. Provide a minimal local reproduction window if available; do not argue or reopen.";
      break;
    case "by_design":
      user_guidance =
        "Upstream marked by-design. Respect the decision; offer local mitigation guidance only.";
      break;
    case "not_planned":
      user_guidance =
        "Upstream marked not-planned. Respect the decision; do not cross-post or reopen.";
      break;
    case "closed":
      user_guidance =
        "Upstream issue is closed. Do not auto-reopen. New material requires a new preview path if warranted.";
      break;
    case "duplicate": {
      const n = input.duplicate_of_issue;
      if (typeof n === "number" && Number.isInteger(n) && n >= 1) {
        migrate_to_issue = n;
        user_guidance = `Upstream closed as duplicate of #${n}. Migrate local subscription; do not cross-post.`;
      } else {
        user_guidance =
          "Upstream closed as duplicate. Migrate subscription when canonical target is known; do not cross-post.";
      }
      break;
    }
    case "open_active":
      user_guidance =
        "Upstream issue remains open. Follow explicit subscription only; no repository crawl.";
      break;
    default: {
      const _exhaustive: never = d;
      void _exhaustive;
      user_guidance = "Unknown disposition refused.";
    }
  }

  return {
    disposition: d,
    auto_reopen: false,
    cross_post: false,
    auto_comment: false,
    auto_react: false,
    migrate_to_issue,
    user_guidance,
    respect_upstream: true,
  };
}
