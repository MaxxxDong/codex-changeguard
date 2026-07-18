/**
 * Build ADMIN_ACTION_REQUIRED IT Handoff with Ticket 07 wire-compatible fields.
 * Never includes secrets, absolute paths, bypass, or elevation commands.
 */
import type { PlatformCapabilityStatus } from "./types.js";
import type { ITHandoff, NetworkCompareResult, OfficialReference } from "./types.js";

const ENTERPRISE_REF: OfficialReference = {
  title: "Network recommendations for ChatGPT errors on web and apps",
  url_allowlisted:
    "https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps",
};

/** Affirmative elevation/bypass recipes only — "do not bypass" remains allowed. */
const FORBIDDEN_GUIDANCE =
  /\b(sudo|chmod|chown|setfacl|takeown|runas|setuid)\b|\bdisable\s*(sip|gatekeeper|applocker|defender|security)\b|\b(bypass|circumvent)\s+(the\s+)?(policy|security|mdm|managed|admin)\b|\belevate\s+(privileges|rights|access)\b|\brun\s+as\s+admin\b/i;

export interface BuildITHandoffInput {
  policy_class: string;
  target_path_alias: string;
  config_key: string | null;
  evidence_digests: string[];
  admin_owned: boolean;
  signed: boolean;
  permission_bound: boolean;
  adapter_status?: PlatformCapabilityStatus;
  instance_id?: string | null;
  network_compare?: NetworkCompareResult | null;
  /** Optional override; must not contain elevation/bypass language. */
  proposed_action?: string;
}

export function buildITHandoff(input: BuildITHandoffInput): ITHandoff {
  const proposed =
    input.proposed_action ??
    "Contact IT/admin to update managed Codex control configuration through the approved enterprise change process. ChangeGuard will not alter signed, admin-owned, or permission-bound control files and does not provide privilege-escalation recipes.";
  if (FORBIDDEN_GUIDANCE.test(proposed)) {
    throw new Error("IT_HANDOFF_FORBIDDEN_GUIDANCE");
  }
  const flags: string[] = [];
  if (input.admin_owned) flags.push("admin_owned");
  if (input.signed) flags.push("signed");
  if (input.permission_bound) flags.push("permission_bound");

  const adapter_status = input.adapter_status ?? "LIMITED";
  const digests = input.evidence_digests.filter(
    (d) => typeof d === "string" && d.length > 0,
  );

  return {
    schema_version: 1,
    status: "ADMIN_ACTION_REQUIRED",
    policy_class: input.policy_class,
    target_path_alias: input.target_path_alias,
    config_key: input.config_key,
    requested_action: proposed,
    evidence_digests: digests,
    admin_owned: input.admin_owned,
    signed: input.signed,
    permission_bound: input.permission_bound,
    minimal_evidence: {
      digests,
      observed_flags: flags,
      adapter_status,
      instance_id: input.instance_id ?? null,
    },
    proposed_action: proposed,
    risk: "high",
    rollback:
      "Administrator restores prior managed policy or signed control configuration through the approved enterprise change process; ChangeGuard does not perform admin rollback.",
    official_reference: ENTERPRISE_REF,
    network_compare: input.network_compare ?? null,
    secrets_present: false,
    absolute_paths_present: false,
  };
}

/** Reject handoff payloads that leak paths/secrets or offer bypass commands. */
export function assertSafeHandoffText(text: string): void {
  if (FORBIDDEN_GUIDANCE.test(text)) {
    throw new Error("IT_HANDOFF_FORBIDDEN_GUIDANCE");
  }
  if (
    /\/home\/|\/Users\/|[A-Za-z]:\\|\b(Bearer|sk-|api[_-]?key|password|token)\b/i.test(
      text,
    )
  ) {
    throw new Error("IT_HANDOFF_LEAK");
  }
}
