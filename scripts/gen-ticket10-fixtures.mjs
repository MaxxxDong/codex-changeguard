/**
 * Generate Ticket 10 form-snapshot fixture with canonical integrity hash.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function sortValue(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortValue);
  const obj = value;
  const keys = Object.keys(obj).sort((a, b) => a.localeCompare(b));
  const out = {};
  for (const k of keys) out[k] = sortValue(obj[k]);
  return out;
}

function sha256Canonical(value) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(sortValue(value)), "utf8")
    .digest("hex");
}

const forms = [
  {
    filename: "1-codex-app.yml",
    blob_sha: "6e294ee27bc924fc2c68b743bad26260297d13f9",
    form: "APP",
    notes: "Codex App bug form",
  },
  {
    filename: "2-extension.yml",
    blob_sha: "599bc08b428d6328c712f526549350daf0aada79",
    form: "EXTENSION",
    notes: "Extension / IDE form",
  },
  {
    filename: "3-cli.yml",
    blob_sha: "cfd368c0ba798d4f513edd5548fd185d761ed15d",
    form: "CLI",
    notes: "CLI form includes codex doctor --json",
  },
  {
    filename: "4-bug-report.yml",
    blob_sha: "4de88414600e6100720fefa2a324ce41d759cd7f",
    form: "OTHER",
    notes: "Generic / other bug form",
  },
  {
    filename: "5-feature-request.yml",
    blob_sha: "745c347965c2e58f8e8e4437009f2c8ae0059878",
    form: "FEATURE",
    notes: "Feature request (not used for product-bug routing)",
  },
  {
    filename: "6-docs-issue.yml",
    blob_sha: "1957b6035a58950329d87d4c24e67faf98c00572",
    form: "DOCS",
    notes: "Docs issue (not used for product-bug routing)",
  },
];

const material = {
  schema_version: 1,
  snapshot_id: "official_issue_forms_2026-07-18",
  fetched_at: "2026-07-18T00:00:00.000Z",
  main_commit: "3a067484584861606ad842de5bc4ac735a865ddf",
  repository: "openai/codex",
  forms,
  duplicate_guidance: "search_first_reaction_only_for_duplicates",
  cli_form_includes_doctor_json: true,
};

const integrity = sha256Canonical(material);
const snapshot = {
  ...material,
  integrity_sha256: integrity,
  immutable_snapshot_disclaimer:
    "Immutable offline snapshot of official openai/codex issue forms verified at main commit 3a067484584861606ad842de5bc4ac735a865ddf on 2026-07-18. Not a claim that forms remain current forever; live refresh requires approved disclosure + injected official-only transport.",
};

const outDir = path.join(repoRoot, "fixtures", "upstream");
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(
  path.join(outDir, "form-snapshot-2026-07-18.json"),
  JSON.stringify(snapshot, null, 2) + "\n",
);
console.log("wrote form-snapshot integrity", integrity);
