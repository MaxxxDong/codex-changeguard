/**
 * Ticket 15 — Linux / WSL / enterprise platform capability contracts.
 * Public results never include raw absolute paths or secrets.
 */

export type PlatformCapabilityStatus =
  | "READ_ONLY"
  | "LIMITED"
  | "PREVIEW"
  | "FULL";

export type AdapterId =
  | "unknown"
  | "macos"
  | "windows"
  | "linux"
  | "wsl"
  | "enterprise_managed";

/** Cross-OS identity domain — prevents WSL/host collapse. */
export type RuntimeDomain =
  | "native_linux"
  | "wsl_distro"
  | "windows_host"
  | "macos_host"
  | "unknown";

export type DiscoveryKind =
  | "cli_instance"
  | "config"
  | "log"
  | "user_cache"
  | "managed_policy";

export interface DiscoveryObservation {
  kind: DiscoveryKind;
  /** Alias only — never absolute path. */
  path_alias: string;
  path_hash: string;
  present: boolean;
  readable: boolean;
  /** Content digest when a regular file was read under bounds; null otherwise. */
  content_sha256: string | null;
  refused_reason: string | null;
}

export interface PlatformGap {
  id: string;
  summary: string;
  status: PlatformCapabilityStatus;
}

export interface OfficialReference {
  title: string;
  /** Allowlisted official URL only (help.openai.com / docs / status). */
  url_allowlisted: string;
}

export interface SupportReceipt {
  schema_version: 1;
  /** Hashed scenario IDs that justify a capability claim. */
  scenario_ids: string[];
  claimed_status: PlatformCapabilityStatus;
  adapter: AdapterId;
  /** Real-machine receipts are required for FULL; synthetic fixtures alone cannot. */
  real_machine: boolean;
  notes: string[];
}

export interface PlatformCapabilityReport {
  schema_version: 1;
  adapter: AdapterId;
  platform: AdapterId;
  runtime_domain: RuntimeDomain;
  status: PlatformCapabilityStatus;
  /** Mutation disabled unless status is PREVIEW/FULL and gates pass. */
  writes_enabled: boolean;
  mutation_disabled_by_default: boolean;
  discoveries: DiscoveryObservation[];
  gaps: PlatformGap[];
  support_receipt: SupportReceipt | null;
  network_used: false;
  target_mutated: false;
  /** Truthful: no real Linux/WSL host FULL receipt in this repository. */
  full_support_claimed: false;
}

export type NetworkCompareBranch =
  | "service_incident"
  | "network_security_path"
  | "auth_method_sso_mismatch"
  | "local_session_state"
  | "unresolved_support";

/** Orchestrator-supplied observation only — never opens sockets. */
export interface NetworkCompareObservation {
  status_page_class: "operational" | "incident" | "unknown";
  path_a_success: boolean | null;
  path_b_success: boolean | null;
  /** Hashed network-path id only — never public IP. */
  network_path_id_hash: string | null;
  sso_method_class: string | null;
  surface_a: string | null;
  surface_b: string | null;
  proxy_or_filter_active: boolean | null;
  ssl_inspection_suspected: boolean | null;
}

export interface NetworkCompareResult {
  schema_version: 1;
  branch: NetworkCompareBranch;
  maximum_claim: string;
  safe_action: string;
  evidence_notes: string[];
  network_used: false;
  settings_mutated: false;
  official_reference: OfficialReference | null;
}

export interface ITHandoffMinimalEvidence {
  digests: string[];
  observed_flags: string[];
  adapter_status: PlatformCapabilityStatus;
  instance_id: string | null;
}

/**
 * Full IT Handoff for ADMIN_ACTION_REQUIRED.
 * Additive over Ticket 07 AdminHandoff field names for wire compatibility.
 */
export interface ITHandoff {
  schema_version: 1;
  status: "ADMIN_ACTION_REQUIRED";
  policy_class: string;
  target_path_alias: string;
  config_key: string | null;
  /** Ticket 07 compatibility aliases. */
  requested_action: string;
  evidence_digests: string[];
  admin_owned: boolean;
  signed: boolean;
  permission_bound: boolean;
  /** Ticket 15 IT fields. */
  minimal_evidence: ITHandoffMinimalEvidence;
  proposed_action: string;
  risk: "low" | "moderate" | "high";
  rollback: string;
  official_reference: OfficialReference | null;
  network_compare: NetworkCompareResult | null;
  secrets_present: false;
  absolute_paths_present: false;
}

export interface WriteGateInput {
  capability_status: PlatformCapabilityStatus;
  /** Isolated fixture / allowlisted user-owned recovery only. */
  isolation: "isolated_fixture" | "user_owned_registered" | "production_unknown";
  managed_policy: boolean;
  admin_permission_bound: boolean;
  /**
   * LIMITED may expose only validated user-owned registered recovery when
   * explicitly allowed; READ_ONLY never mutates.
   */
  allow_limited_user_owned_recovery?: boolean;
}

export interface WriteGateResult {
  may_mutate: boolean;
  reason_code: string;
  capability_status: PlatformCapabilityStatus;
}
