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

/**
 * Machine-readable reason for `affected_resolution` (additive, stable).
 * Never includes raw paths. Callers must not treat absence of this field
 * on legacy fixtures as an error — new ScanResult always sets it.
 */
export type AffectedResolutionReason =
  | "identified"
  | "no_instances"
  | "no_observed_context"
  | "conflicting_observed_evidence"
  | "observed_evidence_no_match"
  | "multi_instance_insufficient_evidence"
  | "version_match_ambiguous";

/**
 * Coarse health classification separate from legacy `ok`.
 * `ok` remains the all-checks-pass boolean for backward compatibility.
 * Missing version metadata alone is evidence_incomplete — not a host fault.
 */
export type HealthClassification =
  | "healthy"
  | "evidence_incomplete"
  | "identity_integrity_failed"
  | "budget_exceeded"
  | "check_failed";

export type HealthClassificationReason =
  | "all_checks_passed"
  | "version_evidence_missing"
  | "duplicate_instance_ids"
  | "health_check_budget_exceeded"
  | "instance_enumeration_failed"
  | "one_or_more_checks_failed";

export type ScanMode = "manual_scan" | "session_start";

/** Logical kind of a named installed artifact (path-free). */
export type ArtifactKind =
  | "executable"
  | "plist"
  | "asar"
  | "code_resources"
  | "manifest"
  | "metadata"
  | "other";

/**
 * Read/gap status for one named artifact measurement.
 * Oversize and refusals never produce truncated digests.
 */
export type ArtifactReadStatus =
  | "read_ok"
  | "missing"
  | "symlink_refused"
  | "out_of_root"
  | "oversize"
  | "not_file"
  | "io_error"
  /** Named target not measured because wall-clock measurement budget was exhausted. */
  | "time_budget_exceeded";

/**
 * Path-free local artifact entry. Never contains absolute paths or file bodies.
 */
export interface LocalArtifactEntry {
  /** Stable logical key (e.g. executable, info_plist, app_asar). */
  key: string;
  /** Bounded public alias (instance path_alias + key). */
  alias: string;
  kind: ArtifactKind;
  /** Hex SHA-256 when status is read_ok; otherwise null. */
  sha256: string | null;
  /** Byte size when status is read_ok; otherwise null. */
  size: number | null;
  status: ArtifactReadStatus;
}

/** Per-instance artifact baseline (persisted under state schema v2). */
export interface InstanceArtifactBaseline {
  instance_id: string;
  path_hash: string;
  path_alias: string;
  entries: LocalArtifactEntry[];
  /** Digest of sorted path-free entries for this instance. */
  baseline_digest: string;
}

export type LocalArtifactDiffStatus =
  | "first_baseline"
  | "unchanged"
  | "content_changed"
  | "partial"
  | "unavailable";

export type LocalArtifactChangeClass =
  | "added"
  | "removed"
  | "hash_changed"
  | "gap_changed";

/** One path-free artifact delta row (facts only). */
export interface LocalArtifactDiffEntry {
  instance_id: string | null;
  path_alias: string | null;
  key: string;
  alias: string;
  kind: ArtifactKind;
  change: LocalArtifactChangeClass;
  previous_sha256: string | null;
  current_sha256: string | null;
  previous_status: ArtifactReadStatus | null;
  current_status: ArtifactReadStatus | null;
  previous_size: number | null;
  current_size: number | null;
}

/**
 * Deterministic ScanResult truth surface for installed-artifact baseline/diff.
 * Separate axis from version transitions; never invents historical bytes.
 */
export interface LocalArtifactDiff {
  status: LocalArtifactDiffStatus;
  previous_baseline_digest: string | null;
  current_baseline_digest: string | null;
  added: LocalArtifactDiffEntry[];
  removed: LocalArtifactDiffEntry[];
  hash_changed: LocalArtifactDiffEntry[];
  gap_changed: LocalArtifactDiffEntry[];
  entry_counts: {
    measured: number;
    read_ok: number;
    gaps: number;
  };
  /** Bounded sorted public keys/aliases for SessionStart context. */
  keys: string[];
}

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
  /**
   * Additive machine-readable class. Interprets check failures without
   * collapsing version-evidence gaps into host/identity faults.
   */
  classification: HealthClassification;
  /** Stable reason code for the classification (path-free). */
  classification_reason: HealthClassificationReason;
}

/**
 * Version-fingerprint + artifact baseline state.
 * Written as schema_version 2; load remains backward-readable from v1
 * (v1 yields empty artifact baselines → first_baseline, never invents history).
 */
export interface VersionFingerprintState {
  schema_version: 1 | 2;
  updated_at: string;
  overall_fingerprint: string;
  instances: InstanceIdentity[];
  /**
   * Path-free artifact baselines keyed by instance. Empty array when migrating
   * from v1 or when no measurements were retained. Never invents historical rows.
   */
  artifact_baselines: InstanceArtifactBaseline[];
  /** Overall digest of artifact baselines (v2); null on pure v1 material until measured. */
  overall_artifact_digest: string | null;
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
  /**
   * Additive stable reason for affected_resolution. Always set on new results.
   * Does not change resolution semantics: no observed context stays ambiguous
   * (including the single-instance case).
   */
  affected_resolution_reason: AffectedResolutionReason;
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
   * Path-free installed-artifact baseline/diff (facts only).
   * Separate axis from primary_transition / version identity.
   */
  local_artifact_diff: LocalArtifactDiff;
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
   * Wall-clock budget (ms) for named-artifact measurement.
   * SessionStart defaults to ~4s so the 10s hook timeout retains headroom.
   * Manual scan leaves this undefined (no wall-clock cap) unless injected.
   */
  artifactTimeBudgetMs?: number;
  /** Injectable monotonic clock for artifact time-budget tests (ms). */
  artifactNowMs?: () => number;
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
  /**
   * Desktop-bundled CLI absolute paths (Ticket 14).
   * Distinct from Desktop app: surface=cli, separate identity.
   */
  desktopCliPaths?: string[];
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
  /**
   * When platform=windows, also emit registered wslPaths as independent
   * WSL identities (Ticket 14 host coexistence). Default true on windows.
   */
  includeHostWsl?: boolean;
  /**
   * Explicit multi-profile specs (Ticket 14). Aliases only on public results.
   */
  userProfiles?: Array<{
    profile_root_alias: string;
    config_root_alias: string | null;
    root_abs?: string;
  }>;
  /** Cap on PATH directories inspected (default 64). */
  maxPathEntries?: number;
  /** Cap on total candidates (default MAX_INSTANCES). */
  maxCandidates?: number;
  homeDir?: string;
  pathDelimiter?: string;
  /** Injectable filesystem probes (default: real lstat, no follow). */
  pathKind?: (absPath: string) => "file" | "dir" | "symlink" | "missing" | "other";
}
