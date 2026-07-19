/**
 * Lightweight schema structural + fixture binding gate (no new JSON-Schema runtime dep).
 * Draft 2020-12 markers, required keys, and fixture→schema presence checks.
 */

import fs from "node:fs";
import path from "node:path";

/** Required schemas shipped in the package surface. */
export const REQUIRED_SCHEMAS = Object.freeze([
  "incident-fingerprint.schema.json",
  "recovery-capsule.schema.json",
  "impact-contract.schema.json",
  "version-fingerprint-state.schema.json",
  "upstream-submission-capsule.schema.json",
  "upstream-action-receipt.schema.json",
  "followup-result.schema.json",
  "platform-support-receipt.schema.json",
  "platform-capability.schema.json",
  "it-handoff.schema.json",
  "demo-receipt.schema.json",
]);

/** Fixture files that must exist as binding evidence for schema surface. */
export const SCHEMA_FIXTURE_BINDINGS = Object.freeze([
  { fixture: "fixtures/protected-process/incident.json", kind: "incident" },
  { fixture: "fixtures/negative-control/incident.json", kind: "incident" },
  { fixture: "fixtures/upstream/form-snapshot-2026-07-18.json", kind: "form_snapshot" },
  {
    fixture: "fixtures/windows11/receipts/synthetic-preview.json",
    kind: "platform_receipt",
  },
]);

/**
 * @param {string} repoRoot
 * @param {{ schemas?: readonly string[], fixtures?: readonly typeof SCHEMA_FIXTURE_BINDINGS, schemasDir?: string }} [opts]
 */
export function checkSchemaGate(repoRoot, opts = {}) {
  const schemasDir = path.join(repoRoot, opts.schemasDir ?? "schemas");
  const required = opts.schemas ?? REQUIRED_SCHEMAS;
  const fixtures = opts.fixtures ?? SCHEMA_FIXTURE_BINDINGS;
  /** @type {string[]} */
  const errors = [];

  if (!fs.existsSync(schemasDir) || !fs.statSync(schemasDir).isDirectory()) {
    return {
      ok: false,
      reason_code: "GATE_SCHEMA",
      errors: ["schemas_dir_missing"],
      detail: "schema_gate_failed",
    };
  }

  const present = fs.readdirSync(schemasDir).filter((n) => n.endsWith(".schema.json"));
  for (const name of required) {
    const abs = path.join(schemasDir, name);
    if (!fs.existsSync(abs)) {
      errors.push(`missing_schema:${name}`);
      continue;
    }
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(abs, "utf8"));
    } catch {
      errors.push(`invalid_json:${name}`);
      continue;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      errors.push(`not_object:${name}`);
      continue;
    }
    const schema = /** @type {Record<string, unknown>} */ (parsed);
    const schemaUri = String(schema.$schema ?? "");
    if (!schemaUri.includes("2020-12")) {
      errors.push(`not_draft_2020_12:${name}`);
    }
    if (typeof schema.$id !== "string" || schema.$id.length < 8) {
      errors.push(`missing_id:${name}`);
    }
    if (schema.type !== "object" && schema.type !== undefined) {
      // allow missing type when using $ref-only roots, but we require object roots
      if (!schema.$ref) errors.push(`unexpected_type:${name}`);
    }
    // Root must be closed via additionalProperties, $ref, or a closed combinator
    // (oneOf/anyOf/allOf branches carry additionalProperties themselves).
    const hasClosedCombinator =
      Array.isArray(schema.oneOf) || Array.isArray(schema.anyOf) || Array.isArray(schema.allOf);
    if (
      schema.additionalProperties === undefined &&
      !schema.$ref &&
      !hasClosedCombinator
    ) {
      errors.push(`missing_additionalProperties:${name}`);
    }
  }

  // Extra schemas are fine; missing required is not
  for (const name of present) {
    if (!name.endsWith(".schema.json")) {
      errors.push(`unexpected_schema_name:${name}`);
    }
  }

  for (const bind of fixtures) {
    const abs = path.join(repoRoot, bind.fixture);
    if (!fs.existsSync(abs)) {
      errors.push(`missing_fixture_binding:${bind.fixture}`);
      continue;
    }
    try {
      JSON.parse(fs.readFileSync(abs, "utf8"));
    } catch {
      errors.push(`fixture_invalid_json:${bind.fixture}`);
    }
  }

  if (errors.length > 0) {
    return {
      ok: false,
      reason_code: "GATE_SCHEMA",
      errors,
      detail: "schema_gate_failed",
    };
  }
  return {
    ok: true,
    reason_code: null,
    errors: [],
    detail: "schema_gate_ok",
    schema_count: required.length,
  };
}
