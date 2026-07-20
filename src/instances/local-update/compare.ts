/**
 * Manual read-only spatial comparison: installed ChatGPT.app vs staged Sparkle update.
 * Never writes instance state, artifact baselines, or SessionStart state.
 * Never installs/activates/deletes/repairs either app.
 */
import path from "node:path";
import { measureNamedFile } from "../artifacts.js";
import { compareVersions } from "../compare.js";
import {
  MAX_ARTIFACT_FILE_BYTES,
  MAX_ARTIFACT_SCAN_BYTES,
} from "../limits.js";
import type { ArtifactReadStatus, LocalArtifactEntry } from "../types.js";
import { compareAsarComponents } from "./component-diff.js";
import {
  discoverStagedAndInstalled,
  type StagedDiscoveryCaps,
  type ValidatedAppBundle,
} from "./discovery.js";
import {
  DEFAULT_COMPARE_LOCAL_UPDATE_TIME_BUDGET_MS,
  MAX_INFERENCE_NOTES,
  MAX_NAMED_ARTIFACT_ROWS,
  NAMED_STAGED_ARTIFACTS,
  type NamedStagedArtifactKey,
} from "./limits.js";
import { compareNativeModuleDirs } from "./native-module-diff.js";
import { buildOfficialEvidenceSection } from "./official.js";
import type {
  LocalObservationsSection,
  LocalUpdateAppIdentity,
  LocalUpdateCompareResult,
  LocalUpdateCompareStatus,
  NamedArtifactChange,
  NamedArtifactObservation,
  NativeModuleDiff,
  VersionRelation,
} from "./types.js";

function emptyAsarSkipped(reason: string) {
  return {
    status: "skipped" as const,
    reason,
    installed_file_count: null,
    staged_file_count: null,
    stable_path_changes: [],
    node_basename_changes: [],
    aggregate_buckets: [],
    truncation: {
      stable_paths_truncated: false,
      node_basenames_truncated: false,
      buckets_truncated: false,
      nodes_capped: false,
      depth_capped: false,
    },
  };
}

function emptyNativeSkipped(reason: string): NativeModuleDiff {
  return {
    status: "skipped",
    reason,
    added: [],
    removed: [],
    truncation: { entries_capped: false },
    installed_dir_present: null,
    staged_dir_present: null,
  };
}


export interface CompareLocalUpdateOptions extends StagedDiscoveryCaps {
  timeBudgetMs?: number;
  nowMs?: () => number;
  maxFileBytes?: number;
  maxScanBytes?: number;
  /** Tests only: override bundled official snapshot path. */
  officialSnapshotPath?: string;
}

const ARTIFACT_REL: Record<NamedStagedArtifactKey, string> = {
  info_plist: path.join("Contents", "Info.plist"),
  app_asar: path.join("Contents", "Resources", "app.asar"),
  codex_binary: path.join("Contents", "Resources", "codex"),
  code_resources: path.join(
    "Contents",
    "_CodeSignature",
    "CodeResources",
  ),
};

function toPublicIdentity(
  b: ValidatedAppBundle,
  alias: string,
): LocalUpdateAppIdentity {
  return {
    alias,
    path_hash: b.path_hash,
    version: b.version,
    build: b.build,
    bundle_id: b.bundle_id,
    role: b.role,
  };
}

function versionRelation(
  installed: string | null,
  staged: string | null,
): VersionRelation {
  if (!installed || !staged) return "unknown";
  const c = compareVersions(installed, staged);
  if (c === 0) {
    // equal marketing version — still check string identity
    return installed === staged ? "same" : "incomparable";
  }
  if (c < 0) return "newer"; // staged > installed
  if (c > 0) return "older";
  return "incomparable";
}

function classifyNamedChange(
  inst: LocalArtifactEntry | null,
  stg: LocalArtifactEntry | null,
): NamedArtifactChange {
  if (!inst && !stg) return "unavailable";
  if (!inst && stg) return stg.status === "read_ok" ? "added" : "gap";
  if (inst && !stg) return inst.status === "read_ok" ? "removed" : "gap";
  if (!inst || !stg) return "unavailable";
  if (inst.status !== "read_ok" || stg.status !== "read_ok") {
    if (inst.status === stg.status && inst.status !== "read_ok") return "gap";
    return "gap";
  }
  if (inst.sha256 === stg.sha256) {
    if (inst.size === stg.size) return "unchanged";
    return "size_changed";
  }
  return "hash_changed";
}

function measureSide(
  app: ValidatedAppBundle | null,
  key: NamedStagedArtifactKey,
  alias: string,
  budget: {
    remaining: number;
    deadlineMs: number | null;
    nowMs: () => number;
  },
  maxFileBytes: number,
): LocalArtifactEntry | null {
  if (!app) return null;
  const rel = ARTIFACT_REL[key];
  const abs = path.join(app.absRoot, rel);
  return measureNamedFile(
    key,
    alias,
    abs,
    [app.absRoot],
    budget,
    maxFileBytes,
  );
}

function pickStagedCandidate(
  candidates: ValidatedAppBundle[],
  installed: ValidatedAppBundle | null,
): {
  selected: ValidatedAppBundle | null;
  reason: string | null;
  statusHint: LocalUpdateCompareStatus | null;
} {
  if (candidates.length === 0) {
    return { selected: null, reason: "no_valid_staged_candidate", statusHint: "no_staged_candidate" };
  }
  if (candidates.length > 1) {
    // Deterministic selection only when truth remains explicit: do not hide ambiguity.
    return {
      selected: null,
      reason: "multiple_valid_staged_candidates",
      statusHint: "multiple_candidates",
    };
  }
  const c = candidates[0]!;
  if (installed) {
    const rel = versionRelation(installed.version, c.version);
    if (rel === "same") {
      return {
        selected: c,
        reason: "single_candidate_same_version",
        statusHint: "same_version",
      };
    }
    if (rel === "older") {
      return {
        selected: c,
        reason: "single_candidate_older_than_installed",
        statusHint: "staged_older",
      };
    }
    if (rel === "incomparable" || rel === "unknown") {
      return {
        selected: c,
        reason: "single_candidate_version_incomparable",
        statusHint: "version_incomparable",
      };
    }
    return {
      selected: c,
      reason: "single_candidate_newer_than_installed",
      statusHint: "comparable_newer",
    };
  }
  return {
    selected: c,
    reason: "single_candidate_no_installed",
    statusHint: "no_installed_app",
  };
}

function clampNotes(notes: string[], max = MAX_INFERENCE_NOTES): string[] {
  return notes.slice(0, max);
}

function buildInference(
  status: LocalUpdateCompareStatus,
  named: NamedArtifactObservation[],
  version_relation: VersionRelation,
): LocalUpdateCompareResult["inference_and_unknowns"] {
  const implications: string[] = [];
  const unknowns: string[] = [];
  const do_not_claim = clampNotes([
    "Do not claim the staged app is installed, active, affected, repaired, or safe to install.",
    "Do not claim behavior, fixes, regressions, impact, or affected users from filenames or hashes alone.",
    "Do not treat this spatial comparison as the temporal local_artifact_diff SessionStart baseline.",
    "Do not install, activate, delete, quarantine, mutate, or repair either app from this command.",
  ]);

  if (status === "unsupported_platform") {
    implications.push(
      "Staged Sparkle Installation discovery is macOS-only in this slice; Windows/Linux report unsupported without test injection.",
    );
  }
  if (status === "no_installed_app") {
    unknowns.push("Installed ChatGPT.app was not validated at registered locations.");
  }
  if (status === "no_staged_candidate") {
    unknowns.push(
      "No valid staged ChatGPT.app was found under the allowlisted Sparkle Installation root.",
    );
  }
  if (status === "multiple_candidates") {
    implications.push(
      "Multiple valid staged candidates exist; comparison is withheld until the set is unambiguous.",
    );
    unknowns.push("Which staged session the user intends is not determined.");
  }
  if (status === "comparable_newer") {
    implications.push(
      "Staged marketing version sorts newer than installed; bytes may still differ for reasons other than release notes.",
    );
  }
  if (status === "same_version") {
    implications.push(
      "Marketing versions match; named artifact hashes may still differ (rebuild/channel noise).",
    );
  }
  if (status === "staged_older") {
    implications.push(
      "Staged marketing version sorts older than installed; not a recommended upgrade path from versions alone.",
    );
  }
  if (status === "partial") {
    unknowns.push(
      "One or more named artifacts or ASAR headers could not be fully measured; treat gaps as incomplete evidence.",
    );
  }

  const changed = named.filter(
    (n) =>
      n.change === "hash_changed" ||
      n.change === "size_changed" ||
      n.change === "added" ||
      n.change === "removed",
  );
  if (changed.length > 0) {
    implications.push(
      `${changed.length} named artifact key(s) differ between installed and staged (facts only).`,
    );
  }
  if (version_relation === "newer" || version_relation === "older") {
    unknowns.push(
      "Version ordering does not prove changelog completeness or user-visible impact.",
    );
  }
  unknowns.push(
    "Whether official remote patch notes exist outside the offline bundled snapshot is unknown.",
  );

  return {
    status: "conservative",
    implications: clampNotes(implications),
    unknowns: clampNotes(unknowns),
    do_not_claim,
  };
}

function summaryFor(
  status: LocalUpdateCompareStatus,
  installed: LocalUpdateAppIdentity | null,
  staged: LocalUpdateAppIdentity | null,
): string {
  switch (status) {
    case "unsupported_platform":
      return "Local staged-update comparison is not supported on this platform without test injection.";
    case "no_installed_app":
      return "No validated installed ChatGPT.app; staged discovery may still be reported separately.";
    case "no_staged_candidate":
      return installed
        ? `Installed ${installed.version ?? "unknown"} observed; no valid staged candidate under Sparkle Installation.`
        : "No installed app and no valid staged candidate.";
    case "multiple_candidates":
      return "Multiple valid staged ChatGPT.app candidates; comparison withheld to avoid hiding ambiguity.";
    case "same_version":
      return `Installed and staged share version ${installed?.version ?? staged?.version ?? "unknown"}; named artifacts compared spatially.`;
    case "staged_older":
      return `Staged version ${staged?.version ?? "?"} is older than installed ${installed?.version ?? "?"}.`;
    case "version_incomparable":
      return "Installed and staged versions could not be ordered; named artifacts still measured when possible.";
    case "comparable_newer":
      return `Staged version ${staged?.version ?? "?"} is newer than installed ${installed?.version ?? "?"}; spatial named-artifact comparison available.`;
    case "partial":
      return "Comparison partially completed with explicit measurement gaps.";
    case "error":
      return "Comparison failed safely without mutation.";
    default:
      return "Local staged-update comparison finished.";
  }
}

/**
 * Run the full compare-local-update pipeline (read-only).
 */
export function compareLocalUpdate(
  opts: CompareLocalUpdateOptions = {},
): LocalUpdateCompareResult {
  const discovery = discoverStagedAndInstalled(opts);

  if (!discovery.supported && discovery.installed_rejection === "unsupported_platform") {
    const official = buildOfficialEvidenceSection(null, {
      snapshotPath: opts.officialSnapshotPath,
    });
    const local_observations: LocalObservationsSection = {
      status: "unsupported_platform",
      installed: null,
      staged_candidates: [],
      selected_staged: null,
      selection_reason: "unsupported_platform",
      version_relation: "unknown",
      named_artifacts: [],
      asar_component_diff: emptyAsarSkipped("unsupported_platform"),
      native_module_diff: emptyNativeSkipped("unsupported_platform"),
      discovery: {
        platform: discovery.platform,
        staged_root_available: false,
        sessions_inspected: 0,
        sessions_capped: false,
        download_dirs_inspected: 0,
        download_dirs_capped: false,
        candidates_accepted: 0,
        candidates_capped: false,
        rejection_counts: discovery.rejection_counts,
      },
      safety: {
        network_used: false,
        target_mutated: false,
        staged_written_to_state: false,
        session_start_scanned: false,
        install_attempted: false,
      },
      notes: [
        "Default Windows/Linux result is unsupported discovery (no production Sparkle path).",
      ],
    };
    const status: LocalUpdateCompareStatus = "unsupported_platform";
    return {
      schema_version: 1,
      command: "compare-local-update",
      ok: true,
      status,
      summary: summaryFor(status, null, null),
      official_evidence: official,
      local_observations,
      inference_and_unknowns: buildInference(status, [], "unknown"),
      error_code: null,
      error_message: null,
      network_used: false,
      target_mutated: false,
      repair_applied: false,
    };
  }

  const installedPublic = discovery.installed
    ? toPublicIdentity(discovery.installed, "INSTALLED_1")
    : null;
  const stagedPublicList = discovery.candidates.map((c, i) =>
    toPublicIdentity(c, `STAGED_${i + 1}`),
  );

  const pick = pickStagedCandidate(discovery.candidates, discovery.installed);
  let status: LocalUpdateCompareStatus =
    pick.statusHint ??
    (discovery.installed ? "no_staged_candidate" : "no_installed_app");

  if (!discovery.installed && discovery.candidates.length === 0) {
    status = "no_installed_app";
  } else if (!discovery.installed && discovery.candidates.length === 1) {
    status = "no_installed_app";
  } else if (discovery.installed && discovery.candidates.length === 0) {
    status = "no_staged_candidate";
  }

  const selected = pick.selected;
  const selectedPublic = selected
    ? toPublicIdentity(
        selected,
        stagedPublicList.find((s) => s.path_hash === selected.path_hash)?.alias ??
          "STAGED_1",
      )
    : null;

  const rel = versionRelation(
    discovery.installed?.version ?? null,
    selected?.version ?? null,
  );

  // Named artifact measurement with shared time/byte budget.
  const nowMs =
    typeof opts.nowMs === "function"
      ? opts.nowMs
      : () =>
          typeof performance !== "undefined" &&
          typeof performance.now === "function"
            ? performance.now()
            : Date.now();
  const timeBudgetMs =
    typeof opts.timeBudgetMs === "number" &&
    Number.isFinite(opts.timeBudgetMs) &&
    opts.timeBudgetMs > 0
      ? opts.timeBudgetMs
      : DEFAULT_COMPARE_LOCAL_UPDATE_TIME_BUDGET_MS;
  const maxFile = opts.maxFileBytes ?? MAX_ARTIFACT_FILE_BYTES;
  const maxScan = opts.maxScanBytes ?? MAX_ARTIFACT_SCAN_BYTES;
  const startMs = nowMs();
  const budget = {
    remaining: maxScan,
    deadlineMs: startMs + timeBudgetMs,
    nowMs,
  };

  const named_artifacts: NamedArtifactObservation[] = [];
  let anyGap = false;
  let anyMeasured = false;

  if (selected && discovery.installed) {
    for (const key of NAMED_STAGED_ARTIFACTS) {
      if (named_artifacts.length >= MAX_NAMED_ARTIFACT_ROWS) break;
      const inst = measureSide(
        discovery.installed,
        key,
        `INSTALLED_1.${key}`,
        budget,
        maxFile,
      );
      const stg = measureSide(
        selected,
        key,
        `${selectedPublic?.alias ?? "STAGED_1"}.${key}`,
        budget,
        maxFile,
      );
      const change = classifyNamedChange(inst, stg);
      if (change === "gap" || change === "unavailable") anyGap = true;
      if (
        (inst && inst.status === "read_ok") ||
        (stg && stg.status === "read_ok")
      ) {
        anyMeasured = true;
      }
      named_artifacts.push({
        key,
        change,
        installed_status: (inst?.status as ArtifactReadStatus) ?? null,
        staged_status: (stg?.status as ArtifactReadStatus) ?? null,
        installed_sha256: inst?.sha256 ?? null,
        staged_sha256: stg?.sha256 ?? null,
        installed_size: inst?.size ?? null,
        staged_size: stg?.size ?? null,
      });
    }
  }

  // ASAR component diff only when both sides present and we have app roots.
  let asar_component_diff = compareAsarComponents(
    discovery.installed
      ? path.join(discovery.installed.absRoot, ARTIFACT_REL.app_asar)
      : null,
    selected ? path.join(selected.absRoot, ARTIFACT_REL.app_asar) : null,
  );
  // Bounded native-module basename observation outside ASAR (sibling section).
  let native_module_diff = compareNativeModuleDirs(
    discovery.installed?.absRoot ?? null,
    selected?.absRoot ?? null,
  );
  if (!selected || !discovery.installed) {
    const skipReason = !discovery.installed
      ? "no_installed_app"
      : "no_selected_staged";
    asar_component_diff = emptyAsarSkipped(skipReason);
    native_module_diff = emptyNativeSkipped(skipReason);
  }

  // Elevate to partial when measurements incomplete on an otherwise comparable pair.
  // Native-module partial/unavailable does not fail named artifacts, but overall
  // status remains honest when ASAR is truncated or named rows have gaps.
  if (
    (status === "comparable_newer" ||
      status === "same_version" ||
      status === "staged_older" ||
      status === "version_incomparable") &&
    (anyGap ||
      asar_component_diff.status === "partial" ||
      asar_component_diff.status === "unavailable")
  ) {
    // Keep version status if artifacts fully compared but ASAR partial — still mark partial.
    if (anyGap || !anyMeasured || asar_component_diff.status !== "compared") {
      status = "partial";
    }
  }

  const official = buildOfficialEvidenceSection(selected?.version ?? null, {
    snapshotPath: opts.officialSnapshotPath,
  });

  const notes: string[] = [
    "Spatial comparison only — not temporal local_artifact_diff baselines.",
    "Staged package is never written into instance state or SessionStart.",
  ];
  if (discovery.sessions_capped) {
    notes.push(
      `Session directory inspection capped at configured limit; additional sessions not inspected.`,
    );
  }
  if (discovery.download_dirs_capped) {
    notes.push(
      `Download directory inspection capped at configured limit; additional download dirs not inspected.`,
    );
  }
  if (discovery.candidates_capped) {
    notes.push(`Accepted staged candidates capped; additional valid apps not listed.`);
  }
  if (discovery.installed_rejection && !discovery.installed) {
    notes.push(`Installed validation: ${discovery.installed_rejection}`);
  }

  const local_observations: LocalObservationsSection = {
    status,
    installed: installedPublic,
    staged_candidates: stagedPublicList,
    selected_staged: selectedPublic,
    selection_reason: pick.reason,
    version_relation: rel,
    named_artifacts,
    asar_component_diff,
    native_module_diff,
    discovery: {
      platform: discovery.platform,
      staged_root_available: discovery.installation_root_available,
      sessions_inspected: discovery.sessions_inspected,
      sessions_capped: discovery.sessions_capped,
      download_dirs_inspected: discovery.download_dirs_inspected,
      download_dirs_capped: discovery.download_dirs_capped,
      candidates_accepted: discovery.candidates.length,
      candidates_capped: discovery.candidates_capped,
      rejection_counts: discovery.rejection_counts,
    },
    safety: {
      network_used: false,
      target_mutated: false,
      staged_written_to_state: false,
      session_start_scanned: false,
      install_attempted: false,
    },
    notes: clampNotes(notes),
  };

  return {
    schema_version: 1,
    command: "compare-local-update",
    ok: true,
    status,
    summary: summaryFor(status, installedPublic, selectedPublic),
    official_evidence: official,
    local_observations,
    inference_and_unknowns: buildInference(status, named_artifacts, rel),
    error_code: null,
    error_message: null,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
  };
}
