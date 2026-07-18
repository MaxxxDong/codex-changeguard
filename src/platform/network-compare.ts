/**
 * Non-destructive network / proxy / cert / SSO / firewall comparison playbook.
 * Pure function over orchestrator-supplied observations — never opens sockets
 * and never mutates system settings.
 */
import type {
  NetworkCompareBranch,
  NetworkCompareObservation,
  NetworkCompareResult,
  OfficialReference,
} from "./types.js";

const AUTH_REF: OfficialReference = {
  title: "Troubleshooting authentication",
  url_allowlisted:
    "https://help.openai.com/en/articles/10489721-troubleshooting-authentication",
};

const NETWORK_REF: OfficialReference = {
  title: "Network recommendations for ChatGPT errors on web and apps",
  url_allowlisted:
    "https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps",
};

const CLAIMS: Record<NetworkCompareBranch, { max: string; action: string }> = {
  service_incident: {
    max: "OpenAI reported an incident affecting the surface",
    action:
      "Wait for recovery; avoid destructive local session or firewall changes.",
  },
  network_security_path: {
    max: "the network/security path caused the observed authentication failure",
    action:
      "Stabilize or disable the filtered path when authorized; allow required OpenAI domains and TCP 443; request IT SSL-inspection exemption for public OpenAI domains — do not edit firewall rules from ChangeGuard.",
  },
  auth_method_sso_mismatch: {
    max: "authentication method mismatch confirmed",
    action: "Use the original provider or required organizational SSO path.",
  },
  local_session_state: {
    max: "local session state was the differentiating factor",
    action:
      "Only after safer comparisons: sign out/in or clear affected site data per official guidance.",
  },
  unresolved_support: {
    max: "unresolved; support escalation required",
    action:
      "Collect a redacted support bundle and contact OpenAI Support or IT as appropriate.",
  },
};

/**
 * Compare supplied observations into a single branch label.
 * Never claims IP-change root cause; never returns raw IPs or headers.
 */
export function compareNetworkPaths(
  obs: NetworkCompareObservation,
): NetworkCompareResult {
  const notes: string[] = [];
  if (obs.status_page_class === "incident") {
    notes.push("status_page_class=incident");
    return result("service_incident", notes, AUTH_REF);
  }
  if (
    obs.path_a_success === false &&
    obs.path_b_success === true &&
    (obs.proxy_or_filter_active === true ||
      obs.ssl_inspection_suspected === true)
  ) {
    notes.push("path_contrast_with_filter_or_ssl_inspection");
    if (obs.network_path_id_hash) {
      notes.push(`network_path_id_hash=${obs.network_path_id_hash.slice(0, 16)}…`);
    }
    return result("network_security_path", notes, NETWORK_REF);
  }
  if (
    obs.sso_method_class &&
    obs.sso_method_class.length > 0 &&
    obs.path_a_success === false
  ) {
    notes.push(`sso_method_class=${obs.sso_method_class}`);
    return result("auth_method_sso_mismatch", notes, AUTH_REF);
  }
  if (
    obs.surface_a &&
    obs.surface_b &&
    obs.surface_a !== obs.surface_b &&
    obs.path_a_success === false &&
    obs.path_b_success === true
  ) {
    notes.push("surface_contrast_local_session");
    return result("local_session_state", notes, AUTH_REF);
  }
  notes.push("insufficient_controlled_comparison");
  return result("unresolved_support", notes, AUTH_REF);
}

function result(
  branch: NetworkCompareBranch,
  evidence_notes: string[],
  official_reference: OfficialReference | null,
): NetworkCompareResult {
  const c = CLAIMS[branch];
  return {
    schema_version: 1,
    branch,
    maximum_claim: c.max,
    safe_action: c.action,
    evidence_notes,
    network_used: false,
    settings_mutated: false,
    official_reference,
  };
}
