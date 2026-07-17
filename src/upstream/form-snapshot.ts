import fs from "node:fs";
import path from "node:path";
import { sha256Canonical } from "../evidence/canonical.js";
import { findRepoRoot } from "../paths.js";
import {
  FORM_FILENAME_SAFE_RE,
  FORM_SNAPSHOT_FRESH_MS,
  FORM_SNAPSHOT_MAX_FUTURE_SKEW_MS,
  OFFICIAL_FORM_BLOB_SHAS,
  OFFICIAL_FORM_SNAPSHOT_FETCHED_AT,
  OFFICIAL_FORM_SNAPSHOT_ID,
  OFFICIAL_MAIN_COMMIT,
  OFFICIAL_REPOSITORY,
  REQUIRED_BUG_FORM_ROLES,
} from "./limits.js";
import type {
  FormBlobRecord,
  FormSnapshotView,
  GitHubIssueForm,
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

const SNAPSHOT_TOP_KEYS = Object.freeze([
  "schema_version",
  "snapshot_id",
  "fetched_at",
  "main_commit",
  "repository",
  "forms",
  "duplicate_guidance",
  "cli_form_includes_doctor_json",
  "integrity_sha256",
  "immutable_snapshot_disclaimer",
]);

const FORM_RECORD_KEYS = Object.freeze([
  "filename",
  "blob_sha",
  "form",
  "notes",
]);

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

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

export function validateOfficialFormSnapshot(
  raw: unknown,
  nowMs: number = Date.now(),
): OfficialFormSnapshot {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new FormSnapshotError("SNAPSHOT_SHAPE", "Invalid form snapshot.");
  }
  const o = raw as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!(SNAPSHOT_TOP_KEYS as readonly string[]).includes(k)) {
      throw new FormSnapshotError(
        "SNAPSHOT_EXTRA_FIELD",
        `Unknown form snapshot field: ${k}`,
      );
    }
  }
  if (o.schema_version !== 1) {
    throw new FormSnapshotError("SNAPSHOT_SCHEMA", "Unsupported snapshot schema.");
  }
  if (typeof o.snapshot_id !== "string" || o.snapshot_id.length === 0) {
    throw new FormSnapshotError("SNAPSHOT_ID", "Missing snapshot_id.");
  }
  if (typeof o.fetched_at !== "string" || Number.isNaN(Date.parse(o.fetched_at))) {
    throw new FormSnapshotError("SNAPSHOT_DATE", "Invalid fetched_at.");
  }
  const fetchedMs = Date.parse(o.fetched_at);
  if (fetchedMs > nowMs + FORM_SNAPSHOT_MAX_FUTURE_SKEW_MS) {
    throw new FormSnapshotError(
      "SNAPSHOT_FUTURE",
      "fetched_at is too far in the future.",
    );
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
  const seenFilenames = new Set<string>();
  const seenRoles = new Set<string>();
  for (const f of o.forms) {
    if (!isPlainObject(f)) {
      throw new FormSnapshotError("FORM_SHAPE", "Invalid form record.");
    }
    for (const k of Object.keys(f)) {
      if (!(FORM_RECORD_KEYS as readonly string[]).includes(k)) {
        throw new FormSnapshotError(
          "FORM_EXTRA_FIELD",
          `Unknown form record field: ${k}`,
        );
      }
    }
    if (typeof f.filename !== "string" || typeof f.blob_sha !== "string") {
      throw new FormSnapshotError("FORM_FIELDS", "Form record missing fields.");
    }
    if (!FORM_FILENAME_SAFE_RE.test(f.filename)) {
      throw new FormSnapshotError(
        "FORM_FILENAME",
        `Unsafe form filename: ${f.filename}`,
      );
    }
    if (seenFilenames.has(f.filename)) {
      throw new FormSnapshotError(
        "FORM_DUPLICATE_FILENAME",
        `Duplicate form filename: ${f.filename}`,
      );
    }
    seenFilenames.add(f.filename);
    if (!/^[a-f0-9]{40}$/.test(f.blob_sha)) {
      throw new FormSnapshotError("FORM_BLOB", "Invalid form blob_sha.");
    }
    const formRole: FormBlobRecord["form"] =
      f.form === "APP" ||
      f.form === "CLI" ||
      f.form === "EXTENSION" ||
      f.form === "OTHER" ||
      f.form === "FEATURE" ||
      f.form === "DOCS"
        ? f.form
        : null;
    if (
      formRole === "APP" ||
      formRole === "CLI" ||
      formRole === "EXTENSION" ||
      formRole === "OTHER"
    ) {
      if (seenRoles.has(formRole)) {
        throw new FormSnapshotError(
          "FORM_DUPLICATE_ROLE",
          `Duplicate form role: ${formRole}`,
        );
      }
      seenRoles.add(formRole);
    }
    forms.push({
      filename: f.filename,
      blob_sha: f.blob_sha,
      form: formRole,
      notes: typeof f.notes === "string" ? f.notes : "",
    });
  }

  for (const role of REQUIRED_BUG_FORM_ROLES) {
    if (!seenRoles.has(role)) {
      throw new FormSnapshotError(
        "FORM_MISSING_ROLE",
        `Snapshot missing required form role: ${role}`,
      );
    }
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
  // Future beyond skew is rejected at validation; residual future within skew → age 0.
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

/** Resolve the current filename for a GitHub issue form role from a snapshot. */
export function filenameForFormRole(
  forms: FormBlobRecord[],
  role: GitHubIssueForm,
): string | null {
  const rec = forms.find((f) => f.form === role);
  return rec ? rec.filename : null;
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
