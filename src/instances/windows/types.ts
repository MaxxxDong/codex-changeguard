/**
 * Windows 11 adapter types (Ticket 14).
 * Path-free public surfaces; absolute paths stay in-memory for local probes only.
 */
import type {
  DiscoveredCandidate,
  PlatformId,
  SystemEnumerateCaps,
} from "../types.js";

/** Logical environment class for an observed identity. */
export type WindowsEnvironmentClass =
  | "windows_native"
  | "wsl"
  | "unknown";

/** Write-scope classification for repair eligibility. */
export type WindowsWriteScope =
  | "user_owned"
  | "admin_required"
  | "forbidden_system"
  | "unknown";

export type WindowsInstallKind =
  | "msix_app"
  | "desktop_app"
  | "desktop_bundled_cli"
  | "path_cli"
  | "wsl_cli"
  | "package_manager_cli";

/**
 * Extended capability injection for deterministic Windows 11 tests.
 * Extends SystemEnumerateCaps without breaking existing callers.
 */
export interface WindowsEnumerateCaps extends SystemEnumerateCaps {
  /**
   * Desktop-bundled CLI absolute paths (resources/…/codex or documented layout).
   * Distinct from Desktop app binary; surface=cli, install_source=desktop_bundled.
   */
  desktopCliPaths?: string[];
  /**
   * Explicit user profile roots for multi-profile coexistence.
   * Each entry maps to a distinct profile_root_alias.
   */
  userProfiles?: WindowsProfileSpec[];
  /**
   * When true (default on platform=windows), also emit registered wslPaths
   * as independent WSL identities without collapsing with native rows.
   */
  includeHostWsl?: boolean;
}

export interface WindowsProfileSpec {
  /** Public alias only (e.g. WIN_USER_PROFILE_1). */
  profile_root_alias: string;
  /** Optional config root alias (e.g. WIN_USER_CODEX_CONFIG_1). */
  config_root_alias: string | null;
  /**
   * Absolute root for existence probes only (tests inject temp dirs).
   * Never exported on public ScanResult.
   */
  root_abs?: string;
}

export interface WindowsWriteClassification {
  scope: WindowsWriteScope;
  policy_class: string;
  /** Public path alias only — never absolute path. */
  target_path_alias: string;
  admin_owned: boolean;
  signed: boolean;
  permission_bound: boolean;
  requested_action: string;
  /** When scope is user_owned, repair may bind to this instance_id if provided. */
  bound_instance_id: string | null;
}

export interface WindowsDiscoveryResult {
  platform: PlatformId;
  candidates: DiscoveredCandidate[];
  /** Profile aliases observed (public). */
  profile_aliases: string[];
  /** Distinct install kinds discovered. */
  install_kinds: WindowsInstallKind[];
  /** True when both windows_native and wsl environment classes appear. */
  win_wsl_coexistence: boolean;
}

/** Allowed crash metadata window (no dump bodies). */
export interface WindowsCrashMetadataWindow {
  exception_code: string | null;
  faulting_module: string | null;
  faulting_symbol: string | null;
  offset_bucket: string | null;
  interaction_phase: string | null;
  page_capability: string | null;
  concurrency_context: string | null;
  gpu_child_exit_code: number | null;
  gpu_relaunch_code: number | null;
  /** Always false when dump body was present and stripped / refused. */
  dump_contents_present: false;
  /** Digest of allowed metadata fields only. */
  metadata_digest: string;
}
