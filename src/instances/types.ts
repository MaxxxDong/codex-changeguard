/**
 * Multi-instance / version-fingerprint contracts (Ticket 03).
 * Public results never include raw user paths — only hashes and aliases.
 */

export type InstallSource =
  | "desktop_bundled"
  | "path"
  | "package_manager"
  | "windows_msix"
  | "wsl"
  | "unknown";

export type InstanceSurface = "desktop" | "cli" | "unknown";

export type PlatformId = "macos" | "windows" | "linux" | "wsl" | "unknown";

export type VersionProvenance =
  | "package_json"
  | "plist_metadata"
  | "msix_manifest"
  | "version_file"
  | "fixture_declared"
  | "unavailable";

/** Classification of fingerprint delta for one or more instances. */
export type TransitionClass =
  | "first_baseline"
  | "upgrade"
  | "downgrade"
  | "unchanged"
  | "newly_discovered"
  | "removed"
  | "path_precedence_drift";

export type HookTrustState = "trusted" | "untrusted" | "skipped" | "failed";

export type AffectedResolution = "identified" | "ambiguous" | "none";

export type ScanMode = "manual_scan" | "session_start";

/** Public, path-free instance identity. */
export interface InstanceIdentity {
  instance_id: string;
  path_hash: string;
  path_alias: string;
  surface: InstanceSurface;
  install_source: InstallSource;
  platform: PlatformId;
  arch: string;
  profile_root_alias: string | null;
  config_root_alias: string | null;
  version: string | null;
  build: string | null;
  version_provenance: VersionProvenance;
  /** PATH order among path-sourced candidates; null for non-PATH. */
  path_precedence: number | null;
  /**
   * Optional cross-OS domain (Ticket 15). When present, participates in
   * instance_id material so WSL and Windows host identities never collapse.
   * Omitted from older fixture inventory rows for backward compatibility.
   */
  runtime_domain?: string | null;
}

export interface InstanceTransition {
  instance_id: string | null;
  path_alias: string | null;
  path_hash: string | null;
  class: TransitionClass;
  previous_version: string | null;
  current_version: string | null;
  previous_path_precedence: number | null;
  current_path_precedence: number | null;
}

export interface HealthCheckResult {
  ok: boolean;
  duration_ms: number;
  checks: Array<{ id: string; ok: boolean; detail: string }>;
  bounded: true;
  read_only: true;
}

export interface VersionFingerprintState {
  schema_version: 1;
  updated_at: string;
  overall_fingerprint: string;
  instances: InstanceIdentity[];
}

export interface ScanResult {
  schema_version: 1;
  ok: boolean;
  mode: ScanMode;
  fingerprint_changed: boolean;
  overall_fingerprint: string;
  previous_fingerprint: string | null;
  /** Dominant / primary transition label for the scan. */
  primary_transition: TransitionClass;
  transitions: InstanceTransition[];
  instances: InstanceIdentity[];
  affected_instance_id: string | null;
  affected_resolution: AffectedResolution;
  hook_status: HookTrustState | null;
  health_check: HealthCheckResult | null;
  /** SessionStart with no fingerprint change stays silent. */
  silent: boolean;
  state_updated: boolean;
  network_used: false;
  /** Diagnosis targets / inventory fixtures are never mutated by scan. */
  target_mutated: false;
  repair_applied: false;
  error_code: string | null;
  error_message: string | null;
  /**
   * Ticket 15 optional platform capability block (additive).
   * Present on scan-system / platform-aware paths; omitted on legacy fixtures.
   */
  platform_capability?: {
    schema_version: 1;
    adapter: string;
    status: "READ_ONLY" | "LIMITED" | "PREVIEW" | "FULL";
    writes_enabled: boolean;
    full_support_claimed: false;
    gaps: Array<{ id: string; summary: string; status: string }>;
  } | null;
}

/** Internal discovery candidate (may hold absolute paths only in-memory). */
export interface DiscoveredCandidate {
  install_source: InstallSource;
  surface: InstanceSurface;
  /** Absolute or fixture-relative path used only for local reads / hashing. */
  path: string;
  platform: PlatformId;
  arch: string;
  profile_root_alias: string | null;
  config_root_alias: string | null;
  path_precedence: number | null;
  /** Optional pre-declared version evidence (fixtures); never execute binary. */
  declared_version?: string | null;
  declared_build?: string | null;
  declared_provenance?: VersionProvenance;
  /** Relative path to version metadata file under inventory root, if any. */
  version_metadata_rel?: string | null;
  /**
   * Explicit trusted roots for metadata reads (system adapter).
   * Parent / package metadata is only readable when registered here.
   * Never derived by implicit `..` traversal from the binary path.
   */
  trusted_metadata_roots?: string[];
  /**
   * Absolute metadata file candidates already known to lie under a trusted root
   * (e.g. registered Contents/Info.plist). Still re-clamped at read time.
   */
  version_metadata_abs?: string[];
  /**
   * Ticket 15 runtime domain (native_linux | wsl_distro | windows_host | …).
   * Used in instance_id v2 material when set.
   */
  runtime_domain?: string | null;
  /** In-memory WSL distro token for domain hashing only — never exported raw. */
  wsl_distro_token?: string | null;
}

export interface ObservedContext {
  /** Match by path hash of the observed binary (preferred). */
  process_path?: string | null;
  log_path?: string | null;
  launch_path?: string | null;
  process_path_hash?: string | null;
  log_path_hash?: string | null;
  launch_path_hash?: string | null;
  process_version?: string | null;
}

export interface RepairTargetRequest {
  /** Exactly one instance id, or omit only when a single instance is observed. */
  instance_id?: string | null;
  /** Optional fingerprint corroboration. */
  instance_fingerprint?: string | null;
  /** Explicit multi-target / broadcast requests are refused. */
  instance_ids?: string[] | null;
  broadcast?: boolean | null;
}

export interface RepairTargetBinding {
  ok: boolean;
  instance: InstanceIdentity | null;
  error_code: string | null;
  error_message: string | null;
}

/** How candidates are discovered for a scan. */
export type EnumerationSource = "fixture_inventory" | "system_registered";

export interface ScanOptions {
  /**
   * Directory containing inventory.json + optional state/ and binaries.
   * Required for fixture inventory mode; optional for system enumeration
   * (state lives under stateDir / PLUGIN_DATA instead).
   */
  inventoryRoot?: string;
  /** Override state directory (default: <inventoryRoot>/state). */
  stateDir?: string;
  /** Persist new fingerprint state (default true for successful scans). */
  persistState?: boolean;
  /** Hook trust for session-start path. */
  hookTrust?: HookTrustState;
  mode?: ScanMode;
  /**
   * Candidate enumeration source.
   * - fixture_inventory (default): load inventory.json under inventoryRoot
   * - system_registered: production bounded system adapter (no home crawl)
   */
  enumeration?: EnumerationSource;
  /** Injected candidates (tests); when set, inventory/system candidates are skipped. */
  candidates?: DiscoveredCandidate[];
  observed?: ObservedContext;
  platform?: PlatformId;
  arch?: string;
  /** Clock for tests. */
  now?: () => Date;
  /** Health-check budget in ms (default 10000). */
  healthBudgetMs?: number;
  /**
   * Injectable system-enumeration capabilities (platform/env/fs).
   * Production defaults inspect only known Codex locations and PATH entries.
   */
  systemCaps?: SystemEnumerateCaps;
}

/**
 * Capability injection for deterministic macOS / Windows / Linux / WSL tests.
 * Production defaults may inspect only known Codex locations and PATH entries
 * under hard caps — never broad home traversal, never candidate execution.
 */
export interface SystemEnumerateCaps {
  platform?: PlatformId;
  arch?: string;
  /** Environment map (PATH, HOME, LOCALAPPDATA, USERPROFILE, …). */
  env?: Record<string, string | undefined>;
  /** Override PATH directory list (already split). */
  pathEntries?: string[];
  /** Explicit Desktop-bundled binary absolute paths to consider. */
  desktopPaths?: string[];
  /** Registered package-manager install roots (not broad search). */
  packageRoots?: string[];
  /** Windows MSIX / App Execution Alias candidate absolute paths. */
  msixPaths?: string[];
  /**
   * WSL registered candidate absolute paths (platform=wsl only).
   * Never used to label native Linux install_source as wsl.
   */
  wslPaths?: string[];
  /**
   * Native Linux registered CLI absolute paths (platform=linux only).
   * install_source will be path (never wsl).
   */
  linuxPaths?: string[];
  /** Cap on PATH directories inspected (default 64). */
  maxPathEntries?: number;
  /** Cap on total candidates (default MAX_INSTANCES). */
  maxCandidates?: number;
  homeDir?: string;
  pathDelimiter?: string;
  /** Injectable filesystem probes (default: real lstat, no follow). */
  pathKind?: (absPath: string) => "file" | "dir" | "symlink" | "missing" | "other";
}
