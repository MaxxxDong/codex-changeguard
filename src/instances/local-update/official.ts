/**
 * Official evidence section for staged local-update comparison.
 * Only reports version-bound bundled snapshot items; never infers global absence
 * from a local snapshot miss.
 */
import { loadBundledSnapshot, SnapshotError } from "../../evidence/snapshot.js";
import { compareVersions } from "../compare.js";
import { MAX_OFFICIAL_ITEM_DIGESTS } from "./limits.js";
import type { OfficialEvidenceSection } from "./types.js";

function emptySection(
  status: OfficialEvidenceSection["status"],
  label: string,
  notes: string[],
): OfficialEvidenceSection {
  return {
    status,
    label,
    snapshot_id: null,
    snapshot_content_sha256: null,
    version_bound_item_digests: [],
    version_bound_item_count: 0,
    notes,
  };
}

/**
 * True when a version_range actually binds `version` (not null-null universal).
 * Matches Ticket 04 honesty: null/unknown ranges are not universal matchers.
 */
export function versionRangeBinds(
  from: string | null,
  to: string | null,
  version: string,
): boolean {
  if (from === null && to === null) return false;
  if (from !== null && compareVersions(version, from) < 0) return false;
  if (to !== null && compareVersions(version, to) > 0) return false;
  // Require at least one bound endpoint to be non-null (already handled).
  // If only `from` is set: version >= from; if only `to`: version <= to.
  return true;
}

/**
 * Build official_evidence section for a staged (or installed) marketing version.
 * Offline bundled snapshot only — no network.
 */
export function buildOfficialEvidenceSection(
  stagedVersion: string | null,
  opts: { snapshotPath?: string } = {},
): OfficialEvidenceSection {
  if (stagedVersion === null || stagedVersion.length === 0) {
    return emptySection("not_applicable", "No staged version for binding", [
      "No staged candidate version is available to bind official evidence.",
      "Absence of a staged version does not mean official notes are globally missing.",
    ]);
  }

  try {
    const snap = loadBundledSnapshot(opts.snapshotPath);
    const digests: string[] = [];
    for (const item of snap.items) {
      const from = item.version_range?.from ?? null;
      const to = item.version_range?.to ?? null;
      if (!versionRangeBinds(from, to, stagedVersion)) continue;
      digests.push(item.content_sha256);
    }
    digests.sort();
    const truncated = digests.length > MAX_OFFICIAL_ITEM_DIGESTS;
    const shown = digests.slice(0, MAX_OFFICIAL_ITEM_DIGESTS);

    if (shown.length === 0) {
      return {
        status: "version_unbound",
        label: "Bundled official evidence not version-bound to staged version",
        snapshot_id: snap.snapshot_id,
        snapshot_content_sha256: snap.content_sha256,
        version_bound_item_digests: [],
        version_bound_item_count: 0,
        notes: [
          `Staged version ${stagedVersion} has no version-bound items in the offline bundled snapshot.`,
          "This does not prove that official patch notes are globally absent — only that this local snapshot has no bound items for that version.",
          truncated
            ? "Digest list truncated."
            : "No version-bound digests.",
        ],
      };
    }

    return {
      status: "version_bound",
      label: "Version-bound bundled official evidence present",
      snapshot_id: snap.snapshot_id,
      snapshot_content_sha256: snap.content_sha256,
      version_bound_item_digests: shown,
      version_bound_item_count: digests.length,
      notes: [
        `Found ${digests.length} version-bound official item(s) for staged version ${stagedVersion} in the offline snapshot.`,
        "Only digest identifiers are listed — prose bodies are not inlined here.",
        truncated
          ? `Digest list truncated to ${MAX_OFFICIAL_ITEM_DIGESTS}.`
          : "Digest list complete within cap.",
      ],
    };
  } catch (e) {
    const msg =
      e instanceof SnapshotError ? e.message : "Bundled snapshot unavailable.";
    return emptySection("unavailable", "Official snapshot unavailable", [
      msg,
      "Do not infer that official notes are absent worldwide from this local load failure.",
    ]);
  }
}
