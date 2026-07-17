import fs from "node:fs";
import path from "node:path";
import { sha256Canonical } from "../evidence/canonical.js";
import { findRepoRoot } from "../paths.js";
import {
  FORM_SNAPSHOT_FRESH_MS,
  OFFICIAL_FORM_BLOB_SHAS,
  OFFICIAL_FORM_SNAPSHOT_FETCHED_AT,
  OFFICIAL_FORM_SNAPSHOT_ID,
  OFFICIAL_MAIN_COMMIT,
  OFFICIAL_REPOSITORY,
} from "./limits.js";
import type {
  FormBlobRecord,
  FormSnapshotView,
  OfficialFormSnapshot,
} from "./types.js";

export class FormSnapshotError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "FormSnapshotError";
    this.code = code;
  }
}

const FORM_RECORDS: FormBlobRecord[] = [
  {
    filename: "1-codex-app.yml",
    blob_sha: OFFICIAL_FORM_BLOB_SHAS["1-codex-app.yml"],
    form: "APP",
    notes: "Codex App bug form",
  },
  {
    filename: "2-extension.yml",
    blob_sha: OFFICIAL_FORM_BLOB_SHAS["2-extension.yml"],
    form: "EXTENSION",
    notes: "Extension / IDE form",
  },
  {
    filename: "3-cli.yml",
    blob_sha: OFFICIAL_FORM_BLOB_SHAS["3-cli.yml"],
    form: "CLI",
    notes: "CLI form includes codex doctor --json",
  },
  {
    filename: "4-bug-report.yml",
    blob_sha: OFFICIAL_FORM_BLOB_SHAS["4-bug-report.yml"],
    form: "OTHER",
    notes: "Generic / other bug form",
  },
  {
    filename: "5-feature-request.yml",
    blob_sha: OFFICIAL_FORM_BLOB_SHAS["5-feature-request.yml"],
    form: "FEATURE",
    notes: "Feature request (not used for product-bug routing)",
  },
  {
    filename: "6-docs-issue.yml",
    blob_sha: OFFICIAL_FORM_BLOB_SHAS["6-docs-issue.yml"],
    form: "DOCS",
    notes: "Docs issue (not used for product-bug routing)",
  },
];

function buildBundledSnapshot(): OfficialFormSnapshot {
  const base = {
    schema_version: 1 as const,
    snapshot_id: OFFICIAL_FORM_SNAPSHOT_ID,
    fetched_at: OFFICIAL_FORM_SNAPSHOT_FETCHED_AT,
    main_commit: OFFICIAL_MAIN_COMMIT,
    repository: OFFICIAL_REPOSITORY as "openai/codex",
    forms: FORM_RECORDS,
    duplicate_guidance:
      "search_first_reaction_only_for_duplicates" as const,
    cli_form_includes_doctor_json: true as const,
    immutable_snapshot_disclaimer:
      "Immutable offline snapshot of official openai/codex issue forms verified at the recorded main commit. Not a claim that forms remain current forever; live refresh requires approved disclosure + injected official-only transport.",
  };
  const integrity_sha256 = sha256Canonical({
    schema_version: base.schema_version,
    snapshot_id: base.snapshot_id,
    fetched_at: base.fetched_at,
    main_commit: base.main_commit,
    repository: base.repository,
    forms: base.forms,
    duplicate_guidance: base.duplicate_guidance,
    cli_form_includes_doctor_json: base.cli_form_includes_doctor_json,
  });
  return { ...base, integrity_sha256 };
}

let cachedBundled: OfficialFormSnapshot | null = null;

export function bundledOfficialFormSnapshot(): OfficialFormSnapshot {
  if (cachedBundled) return cachedBundled;
  // Prefer fixture file when present (exact on-disk immutable artifact).
  try {
    const root = findRepoRoot();
    const p = path.join(
      root,
      "fixtures",
      "upstream",
      "form-snapshot-2026-07-18.json",
    );
    if (fs.existsSync(p)) {
      const raw = JSON.parse(fs.readFileSync(p, "utf8")) as unknown;
      cachedBundled = validateOfficialFormSnapshot(raw);
      return cachedBundled;
    }
  } catch {
    /* fall through to in-memory */
  }
  cachedBundled = buildBundledSnapshot();
  return cachedBundled;
}

export function validateOfficialFormSnapshot(
  raw: unknown,
): OfficialFormSnapshot {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new FormSnapshotError("SNAPSHOT_SHAPE", "Invalid form snapshot.");
  }
  const o = raw as Record<string, unknown>;
  if (o.schema_version !== 1) {
    throw new FormSnapshotError("SNAPSHOT_SCHEMA", "Unsupported snapshot schema.");
  }
  if (typeof o.snapshot_id !== "string" || o.snapshot_id.length === 0) {
    throw new FormSnapshotError("SNAPSHOT_ID", "Missing snapshot_id.");
  }
  if (typeof o.fetched_at !== "string" || Number.isNaN(Date.parse(o.fetched_at))) {
    throw new FormSnapshotError("SNAPSHOT_DATE", "Invalid fetched_at.");
  }
  if (typeof o.main_commit !== "string" || !/^[a-f0-9]{40}$/.test(o.main_commit)) {
    throw new FormSnapshotError("SNAPSHOT_COMMIT", "Invalid main_commit.");
  }
  if (o.repository !== "openai/codex") {
    throw new FormSnapshotError("SNAPSHOT_REPO", "repository must be openai/codex.");
  }
  if (!Array.isArray(o.forms) || o.forms.length === 0) {
    throw new FormSnapshotError("SNAPSHOT_FORMS", "forms must be a non-empty array.");
  }
  const forms: FormBlobRecord[] = [];
  for (const f of o.forms) {
    if (!f || typeof f !== "object") {
      throw new FormSnapshotError("FORM_SHAPE", "Invalid form record.");
    }
    const fr = f as Record<string, unknown>;
    if (typeof fr.filename !== "string" || typeof fr.blob_sha !== "string") {
      throw new FormSnapshotError("FORM_FIELDS", "Form record missing fields.");
    }
    if (!/^[a-f0-9]{40}$/.test(fr.blob_sha)) {
      throw new FormSnapshotError("FORM_BLOB", "Invalid form blob_sha.");
    }
    forms.push({
      filename: fr.filename,
      blob_sha: fr.blob_sha,
      form:
        fr.form === "APP" ||
        fr.form === "CLI" ||
        fr.form === "EXTENSION" ||
        fr.form === "OTHER" ||
        fr.form === "FEATURE" ||
        fr.form === "DOCS"
          ? fr.form
          : null,
      notes: typeof fr.notes === "string" ? fr.notes : "",
    });
  }

  const material = {
    schema_version: 1 as const,
    snapshot_id: o.snapshot_id,
    fetched_at: o.fetched_at,
    main_commit: o.main_commit,
    repository: "openai/codex" as const,
    forms,
    duplicate_guidance:
      "search_first_reaction_only_for_duplicates" as const,
    cli_form_includes_doctor_json: true as const,
  };
  const expected = sha256Canonical(material);
  if (typeof o.integrity_sha256 !== "string" || o.integrity_sha256 !== expected) {
    throw new FormSnapshotError(
      "SNAPSHOT_INTEGRITY",
      "Form snapshot integrity hash mismatch.",
    );
  }
  return {
    ...material,
    integrity_sha256: expected,
    immutable_snapshot_disclaimer:
      typeof o.immutable_snapshot_disclaimer === "string"
        ? o.immutable_snapshot_disclaimer
        : "Immutable offline snapshot; not a perpetual-currency claim.",
  };
}

export function viewFormSnapshot(
  snapshot: OfficialFormSnapshot,
  nowMs: number,
  source: FormSnapshotView["source"],
): FormSnapshotView {
  const fetched = Date.parse(snapshot.fetched_at);
  const age_ms = Math.max(0, nowMs - fetched);
  const fresh = age_ms <= FORM_SNAPSHOT_FRESH_MS;
  return {
    snapshot_id: snapshot.snapshot_id,
    fetched_at: snapshot.fetched_at,
    main_commit: snapshot.main_commit,
    integrity_sha256: snapshot.integrity_sha256,
    freshness: fresh ? "fresh" : "stale",
    stale_reason: fresh
      ? null
      : `Snapshot age ${age_ms}ms exceeds freshness window ${FORM_SNAPSHOT_FRESH_MS}ms; offline immutable snapshot is visibly stale.`,
    age_ms,
    forms: snapshot.forms,
    source,
  };
}

/** Compute integrity for fixture generation / tests. */
export function computeFormSnapshotIntegrity(
  snapshot: Omit<OfficialFormSnapshot, "integrity_sha256" | "immutable_snapshot_disclaimer"> & {
    immutable_snapshot_disclaimer?: string;
  },
): string {
  return sha256Canonical({
    schema_version: snapshot.schema_version,
    snapshot_id: snapshot.snapshot_id,
    fetched_at: snapshot.fetched_at,
    main_commit: snapshot.main_commit,
    repository: snapshot.repository,
    forms: snapshot.forms,
    duplicate_guidance: snapshot.duplicate_guidance,
    cli_form_includes_doctor_json: snapshot.cli_form_includes_doctor_json,
  });
}

export function createInMemoryBundledSnapshot(): OfficialFormSnapshot {
  return buildBundledSnapshot();
}
