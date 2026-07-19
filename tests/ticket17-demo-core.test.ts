/**
 * Ticket 17 S1 — deterministic demo core (product-local runDemo).
 * Black-box against shared core only; no CLI/MCP wiring in this slice.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  DEMO_FIXTURE_ALLOWLIST,
  DEMO_PROTECTED_ARTIFACT_REL,
  DEMO_STEP_ORDER,
  DEMO_TEMP_PREFIX,
  assertSafeDemoTree,
  copyAllowlistedFixture,
  createDemoTempRoot,
  DemoIsolationError,
  finalizeSecurityEvidence,
  proveMutationTargetDisposable,
  removeDemoTempRoot,
  runDemo,
  type DemoNetworkObservation,
  type DemoReceipt,
  type DemoStepId,
} from "../src/core/demo/index.js";
import { diagnose } from "../src/core/diagnose.js";
import { REPO_ROOT, makeTempDir } from "./helpers.js";

/** Expected deterministic family for the synthetic crash-refuse fixture. */
const DEMO_CRASH_FAMILY_ID = "access_violation_crbrowser_dom_ready";
const DEMO_CRASH_FIXTURE = path.join(
  REPO_ROOT,
  "fixtures",
  "crash-family",
  "access-violation-crbrowser",
);

const PROTECTED_ARTIFACT_SHA =
  "33af4a7ad7a4ec2d18cb928a2ef69922e69031007dd07672334c5fe45faec48f";

const STEP_ORDER: DemoStepId[] = [...DEMO_STEP_ORDER];

const SCHEMA_PATH = path.join(REPO_ROOT, "schemas", "demo-receipt.schema.json");

const REQUIRED_NETWORK_SEAMS = [
  "diagnose_main",
  "apply_main",
  "impact_baseline",
  "impact_mutated",
  "crash_diagnose",
] as const;

function sha256File(p: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

function hashTree(root: string): string {
  const h = crypto.createHash("sha256");
  const walk = (dir: string): void => {
    const entries = fs
      .readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      const rel = path.relative(root, full).split(path.sep).join("/");
      if (ent.isSymbolicLink()) {
        h.update(`L:${rel}->${fs.readlinkSync(full)}\n`);
        continue;
      }
      if (ent.isDirectory()) {
        h.update(`D:${rel}\n`);
        walk(full);
        continue;
      }
      if (ent.isFile()) {
        const buf = fs.readFileSync(full);
        h.update(`F:${rel}:${buf.length}:`);
        h.update(buf);
        h.update("\n");
      }
    }
  };
  walk(root);
  return h.digest("hex");
}

function assertNoLeakInValue(value: unknown, label = "payload"): void {
  const text = JSON.stringify(value);
  assert.equal(/\/Users\//.test(text), false, `${label}: /Users/ leak`);
  assert.equal(/\/home\//.test(text), false, `${label}: /home/ leak`);
  assert.equal(/\.grok-disposable/.test(text), false, `${label}: disposable leak`);
  assert.equal(/grok-worker-/.test(text), false, `${label}: worker id leak`);
  assert.equal(
    /\bcg1\.[A-Za-z0-9_-]+/.test(text),
    false,
    `${label}: auth token leak`,
  );
  assert.equal(
    /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text),
    false,
    `${label}: Bearer leak`,
  );
  assert.equal(
    /HOME=|USERPROFILE=|TMPDIR=\//.test(text),
    false,
    `${label}: env value leak`,
  );
  // Source shim bytes must never appear.
  assert.equal(
    text.includes("globalThis.process = __cg_shim"),
    false,
    `${label}: source leak`,
  );
}

/**
 * Structural + schema-level validation against demo-receipt.schema.json.
 * Goes beyond length checks: required keys, const booleans, steps min/max,
 * ordered ids, and security_evidence shape.
 */
function assertReceiptSchemaValid(r: DemoReceipt, label = "receipt"): void {
  assert.equal(r.schema_version, 1, `${label}: schema_version`);
  assert.ok(
    ["completed", "failed", "refused", "partial", "budget_exceeded"].includes(
      r.status,
    ),
    `${label}: status enum`,
  );
  assert.equal(typeof r.ok, "boolean");
  // ok true only when completed; completed requires proven security evidence.
  if (r.ok) {
    assert.equal(r.status, "completed", `${label}: ok implies completed`);
    assert.equal(r.security_evidence.proven, true, `${label}: ok requires proven`);
  }
  if (r.status === "completed") {
    assert.equal(r.ok, true, `${label}: completed implies ok`);
    assert.equal(r.security_evidence.proven, true);
  } else {
    assert.equal(r.ok, false, `${label}: non-completed ok false`);
  }
  assert.equal(typeof r.duration_ms, "number");
  assert.ok(r.duration_ms >= 0);
  assert.equal(r.network_used, false);
  assert.equal(r.external_write, false);
  assert.equal(r.live_profile_mutated, false);

  // Schema: steps minItems=10 maxItems=10, ordered canonical ids.
  assert.equal(r.steps.length, 10, `${label}: steps minItems/maxItems=10`);
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8")) as {
    required: string[];
    properties: {
      steps: { minItems: number; maxItems: number };
      network_used: { const: boolean };
      external_write: { const: boolean };
      live_profile_mutated: { const: boolean };
      security_evidence: {
        required: string[];
        properties: Record<string, unknown>;
      };
    };
  };
  assert.equal(schema.properties.steps.minItems, 10);
  assert.equal(schema.properties.steps.maxItems, 10);
  assert.equal(schema.properties.network_used.const, false);
  assert.equal(schema.properties.external_write.const, false);
  assert.equal(schema.properties.live_profile_mutated.const, false);
  assert.ok(
    schema.required.includes("security_evidence"),
    "schema requires security_evidence",
  );
  for (const key of schema.required) {
    assert.ok(key in r, `${label}: missing required key ${key}`);
  }
  for (let i = 0; i < STEP_ORDER.length; i++) {
    assert.equal(r.steps[i]!.id, STEP_ORDER[i], `${label}: step order ${i}`);
    assert.ok(
      ["pass", "fail", "skip", "refused"].includes(r.steps[i]!.status),
    );
    assert.equal(typeof r.steps[i]!.duration_ms, "number");
  }

  // security_evidence contract
  const se = r.security_evidence;
  assert.equal(se.schema_version, 1);
  assert.equal(typeof se.proven, "boolean");
  assert.equal(typeof se.network_all_false, "boolean");
  assert.ok(Array.isArray(se.network_observations));
  for (const o of se.network_observations) {
    assert.equal(typeof o.seam, "string");
    assert.equal(typeof o.network_used, "boolean");
    assert.equal(typeof o.value_valid, "boolean");
  }
  assert.ok(se.disposable_root);
  assert.equal(typeof se.disposable_root.proof_count, "number");
  assert.ok(Array.isArray(se.disposable_root.reason_codes));
  assert.equal(se.local_only.mode, "local_only_no_adapter");
  assert.equal(se.local_only.no_external_adapter, true);
  assert.equal(typeof se.local_only.mutations_local_only, "boolean");

  assert.ok(r.cleanup && typeof r.cleanup.attempted === "boolean");
  assert.ok(typeof r.main.resolved_verified === "boolean");
  assert.ok(typeof r.model_refusal.refused === "boolean");
  assert.ok(typeof r.crash_refusal.preview_refused === "boolean");
}

function assertProvenSecurityEvidence(r: DemoReceipt, label = "receipt"): void {
  assert.equal(r.security_evidence.proven, true, `${label}: proven`);
  assert.equal(r.security_evidence.network_all_false, true);
  assert.equal(r.network_used, false);
  assert.equal(r.external_write, false);
  assert.equal(r.live_profile_mutated, false);
  const seams = new Set(
    r.security_evidence.network_observations.map((o) => o.seam),
  );
  for (const s of REQUIRED_NETWORK_SEAMS) {
    assert.ok(seams.has(s), `${label}: missing network observation ${s}`);
  }
  for (const o of r.security_evidence.network_observations) {
    assert.equal(o.value_valid, true, `${label}: seam ${o.seam} value_valid`);
    assert.equal(o.network_used, false, `${label}: seam ${o.seam}`);
  }
  assert.ok(
    r.security_evidence.disposable_root.proof_count >= 1,
    `${label}: disposable proof_count`,
  );
  assert.ok(
    r.security_evidence.disposable_root.reason_codes.length >= 1,
    `${label}: disposable reason_codes`,
  );
  assert.equal(r.security_evidence.local_only.mutations_local_only, true);
  // Must not hardcode the three booleans as unconditional baseReceipt constants
  // without evidence machinery (source honesty).
  const runDemoSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/run-demo.ts"),
    "utf8",
  );
  assert.match(runDemoSrc, /security_evidence|finalizeSecurityEvidence|networkObservations/);
  assert.match(runDemoSrc, /recordNetwork|network_observations/);
  assert.equal(
    /network_used:\s*false,\s*\n\s*external_write:\s*false,\s*\n\s*live_profile_mutated:\s*false,/.test(
      runDemoSrc,
    ) && !/deriveSecurityBooleans|finalizeSecurityEvidence/.test(runDemoSrc),
    false,
    "security booleans must not be bare unconditional constants without evidence",
  );
}

function stepMap(r: DemoReceipt): Map<DemoStepId, DemoReceipt["steps"][0]> {
  return new Map(r.steps.map((s) => [s.id, s]));
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

test("Ticket17 demo: complete happy path ordered steps + hash restore", () => {
  const fixtureRoot = path.join(REPO_ROOT, "fixtures/protected-process");
  const beforeFixture = hashTree(fixtureRoot);

  const receipt = runDemo({
    now_ms: Date.parse("2026-07-10T12:00:00.000Z"),
  });

  assertReceiptSchemaValid(receipt, "happy");
  assertProvenSecurityEvidence(receipt, "happy");
  assertNoLeakInValue(receipt, "happy");
  assert.equal(receipt.status, "completed");
  assert.equal(receipt.ok, true);
  assert.equal(receipt.error_code, null);

  const m = stepMap(receipt);
  for (const id of STEP_ORDER) {
    assert.equal(m.get(id)!.status, "pass", `${id} must pass`);
  }

  assert.equal(receipt.main.diagnose_state, "SOURCE_COMPONENT_LOCATED");
  assert.equal(receipt.main.user_resolution_after_apply, "RESOLVED_VERIFIED");
  assert.equal(receipt.main.user_resolution_after_verify, "RESOLVED_VERIFIED");
  assert.equal(
    receipt.main.user_resolution_after_rollback,
    "MITIGATED_VERIFIED_BY_ROLLBACK",
  );
  // After rollback demo, current state is not claiming resolved.
  assert.equal(receipt.main.resolved_verified, false);
  assert.equal(receipt.main.repair_applied, true);
  assert.equal(receipt.main.auto_rolled_back, false);

  const hp = receipt.main.hash_proof;
  assert.ok(hp);
  assert.equal(hp!.path_alias, "BROWSER_CLIENT_COPY_A");
  assert.equal(hp!.original_sha256, PROTECTED_ARTIFACT_SHA);
  assert.ok(hp!.after_apply_sha256);
  assert.notEqual(hp!.after_apply_sha256, PROTECTED_ARTIFACT_SHA);
  assert.equal(hp!.after_rollback_sha256, PROTECTED_ARTIFACT_SHA);
  assert.equal(hp!.restored, true);

  assert.equal(receipt.model_refusal.refused, true);
  assert.equal(receipt.model_refusal.graph_unchanged, true);
  assert.ok(receipt.model_refusal.reasons.length >= 1);
  assert.ok(
    receipt.model_refusal.reasons.some((x) =>
      x.includes("MODEL_ADD_EDGE_REFUSED"),
    ),
  );
  assert.match(String(receipt.model_refusal.graph_sha256), /^[a-f0-9]{64}$/);

  assert.equal(receipt.crash_refusal.repair_authorization_eligible, false);
  assert.equal(receipt.crash_refusal.preview_refused, true);
  assert.ok(receipt.crash_refusal.family_id);
  assert.equal(receipt.crash_refusal.family_id, DEMO_CRASH_FAMILY_ID);
  assert.ok(
    receipt.crash_refusal.refused_actions.length > 0,
    "crash_refusal.refused_actions must be nonempty",
  );
  assert.ok(
    receipt.crash_refusal.reason_codes.length > 0,
    "crash_refusal.reason_codes must be nonempty",
  );
  assert.ok(
    receipt.crash_refusal.refused_actions.includes(
      "symptom_level_patch_authorization",
    ) ||
      receipt.crash_refusal.refused_actions.includes(
        "unverified_community_browser_crash_fix",
      ),
    "crash_refusal must include a dangerous-action refusal",
  );

  // Bind receipt crash fields to an independent diagnose() of the same fixture
  // so a hardcoded repair_authorization_eligible=false cannot false-green.
  const independentCrash = diagnose(DEMO_CRASH_FIXTURE);
  assert.equal(independentCrash.ok, true);
  assert.equal(independentCrash.network_used, false);
  const cc = independentCrash.crash_classification;
  assert.ok(cc, "independent diagnose must return crash_classification");
  assert.equal(cc.applicable, true);
  assert.equal(cc.family_id, DEMO_CRASH_FAMILY_ID);
  assert.equal(cc.repair_authorization_eligible, false);
  assert.ok(cc.refused_actions.length > 0);
  assert.equal(
    receipt.crash_refusal.family_id,
    cc.family_id,
    "receipt family_id must match independent classifier",
  );
  assert.equal(
    receipt.crash_refusal.repair_authorization_eligible,
    cc.repair_authorization_eligible,
    "receipt eligibility must match independent classifier (not a constant)",
  );
  assert.deepEqual(
    [...receipt.crash_refusal.refused_actions].sort(),
    [...cc.refused_actions].sort(),
    "receipt refused_actions must match independent classifier",
  );

  assert.equal(receipt.cleanup.attempted, true);
  assert.equal(receipt.cleanup.completed, true);
  assert.equal(receipt.cleanup.temp_removed, true);

  // Original on-disk fixture tree immutable.
  assert.equal(hashTree(fixtureRoot), beforeFixture, "fixture immutable");
  assert.equal(
    sha256File(path.join(fixtureRoot, DEMO_PROTECTED_ARTIFACT_REL)),
    PROTECTED_ARTIFACT_SHA,
  );

  // Budget ceiling
  assert.ok(receipt.duration_ms < 120_000);
});

// ---------------------------------------------------------------------------
// Model + crash isolation (already in happy path; extra unit focus)
// ---------------------------------------------------------------------------

test("Ticket17 demo: model mutation refused and graph unchanged fields stable", () => {
  const a = runDemo({ now_ms: Date.parse("2026-07-10T12:00:00.000Z") });
  const b = runDemo({ now_ms: Date.parse("2026-07-10T12:00:00.000Z") });
  assert.equal(a.status, "completed");
  assert.equal(b.status, "completed");
  assert.equal(a.model_refusal.graph_sha256, b.model_refusal.graph_sha256);
  assert.deepEqual(a.model_refusal.reasons, b.model_refusal.reasons);
  assert.equal(a.main.hash_proof!.original_sha256, b.main.hash_proof!.original_sha256);
  assert.equal(a.crash_refusal.preview_refused, true);
  assert.equal(a.crash_refusal.repair_authorization_eligible, false);
  assert.equal(a.crash_refusal.family_id, DEMO_CRASH_FAMILY_ID);
  assert.ok(a.crash_refusal.refused_actions.length > 0);
  assert.deepEqual(
    a.crash_refusal.refused_actions,
    b.crash_refusal.refused_actions,
  );
  assertNoLeakInValue(a);
  assertNoLeakInValue(b);
});

test("Ticket17 demo: crash_refuse receipt binds to independent diagnose classification", () => {
  const receipt = runDemo({
    now_ms: Date.parse("2026-07-10T12:00:00.000Z"),
  });
  assert.equal(receipt.status, "completed");
  const step = receipt.steps.find((s) => s.id === "crash_refuse");
  assert.ok(step);
  assert.equal(step!.status, "pass");

  const independent = diagnose(DEMO_CRASH_FIXTURE);
  assert.equal(independent.ok, true);
  const cc = independent.crash_classification!;
  assert.equal(cc.applicable, true);
  assert.equal(cc.family_id, DEMO_CRASH_FAMILY_ID);
  assert.equal(cc.repair_authorization_eligible, false);
  assert.ok(
    cc.refused_actions.includes("symptom_level_patch_authorization") ||
      cc.refused_actions.includes("unverified_community_browser_crash_fix"),
  );

  // Receipt must not invent eligibility when classifier would disagree.
  assert.equal(
    receipt.crash_refusal.repair_authorization_eligible,
    cc.repair_authorization_eligible,
  );
  assert.equal(receipt.crash_refusal.family_id, cc.family_id);
  assert.deepEqual(
    [...receipt.crash_refusal.refused_actions].sort(),
    [...cc.refused_actions].sort(),
  );
  assert.equal(receipt.crash_refusal.preview_refused, true);
  assert.equal(receipt.network_used, false);

  // Source must not hardcode eligibility=false after diagnose (false-green mask).
  const runDemoSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/run-demo.ts"),
    "utf8",
  );
  assert.equal(
    /crash_refusal\.repair_authorization_eligible\s*=\s*false/.test(runDemoSrc),
    false,
    "run-demo must not assign repair_authorization_eligible=false as a constant",
  );
  assert.match(
    runDemoSrc,
    /repair_authorization_eligible\s*=\s*\n?\s*cc\.repair_authorization_eligible|repair_authorization_eligible:\s*cc\.repair_authorization_eligible|cc\.repair_authorization_eligible/,
  );
  // No-op overall ternary must not reappear.
  assert.equal(
    /induce_verify_failure\s*===\s*true\s*\?\s*"completed"\s*:\s*"completed"/.test(
      runDemoSrc,
    ),
    false,
    "no-op overall ternary must be removed",
  );
});

// ---------------------------------------------------------------------------
// Leak / safety flags
// ---------------------------------------------------------------------------

test("Ticket17 demo: no network/external/live-profile/path/token leakage", () => {
  const receipt = runDemo({
    now_ms: Date.parse("2026-07-10T12:00:00.000Z"),
  });
  assertReceiptSchemaValid(receipt, "leak");
  assertProvenSecurityEvidence(receipt, "leak");
  assert.equal(receipt.network_used, false);
  assert.equal(receipt.external_write, false);
  assert.equal(receipt.live_profile_mutated, false);
  assertNoLeakInValue(receipt);
  // Receipt must not embed os.tmpdir absolute path.
  const text = JSON.stringify(receipt);
  assert.equal(text.includes(os.tmpdir()), false);
  assert.equal(text.includes(DEMO_TEMP_PREFIX), false);
  // Never proves non-mutation by hashing live home/profile.
  const runDemoSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/run-demo.ts"),
    "utf8",
  );
  assert.equal(
    /hashTree\s*\(\s*(home|live|process\.env\.HOME)/i.test(runDemoSrc),
    false,
  );
  assert.equal(
    /createHash[\s\S]{0,80}\.codex/.test(runDemoSrc),
    false,
    "must not hash live .codex profile",
  );
});

// ---------------------------------------------------------------------------
// Caller live path refusal
// ---------------------------------------------------------------------------

test("Ticket17 demo: refuse caller live ~/.codex and non-disposable paths", () => {
  const home = process.env.HOME ?? process.env.USERPROFILE;
  assert.ok(home, "home required for live-path probe");

  const live = path.join(home!, ".codex");
  // May or may not exist; either way must refuse (or if path is unprovable).
  const liveReceipt = runDemo({ targetRoot: live });
  assert.ok(
    liveReceipt.status === "refused" || liveReceipt.status === "failed",
  );
  assert.ok(
    liveReceipt.error_code === "LIVE_PROFILE_REFUSED" ||
      liveReceipt.error_code === "CALLER_TARGET_NOT_DISPOSABLE" ||
      liveReceipt.error_code === "INVALID_TARGET" ||
      liveReceipt.error_code === "TEMP_ISOLATION_UNPROVABLE" ||
      liveReceipt.error_code === "CALLER_TARGET_NOT_DISPOSABLE",
  );
  assertNoLeakInValue(liveReceipt, "live");
  // Must not report completed with resolved.
  assert.notEqual(liveReceipt.status, "completed");
  assert.equal(liveReceipt.ok, false);
  assert.equal(liveReceipt.main.resolved_verified, false);

  // Repo fixture path is not a disposable OS-temp child → refuse.
  const repoFixture = path.join(REPO_ROOT, "fixtures/protected-process");
  const repoReceipt = runDemo({ targetRoot: repoFixture });
  assert.ok(
    repoReceipt.status === "refused" || repoReceipt.status === "failed",
  );
  assert.equal(repoReceipt.error_code, "CALLER_TARGET_NOT_DISPOSABLE");
  assertNoLeakInValue(repoReceipt, "repo-fixture");
  assert.equal(repoReceipt.main.resolved_verified, false);
});

// ---------------------------------------------------------------------------
// Induced verify failure → rollback + cleanup, never resolved
// ---------------------------------------------------------------------------

test("Ticket17 demo: induced verify failure rolls back and never claims resolved", () => {
  const fixtureRoot = path.join(REPO_ROOT, "fixtures/protected-process");
  const beforeFixture = hashTree(fixtureRoot);

  const receipt = runDemo({
    induce_verify_failure: true,
    now_ms: Date.parse("2026-07-10T12:00:00.000Z"),
  });

  assertReceiptSchemaValid(receipt, "induce");
  assertProvenSecurityEvidence(receipt, "induce");
  assertNoLeakInValue(receipt, "induce");
  assert.equal(receipt.status, "completed");
  assert.equal(receipt.main.auto_rolled_back, true);
  assert.equal(receipt.main.repair_applied, false);
  assert.equal(receipt.main.resolved_verified, false);
  assert.notEqual(
    receipt.main.user_resolution_after_apply,
    "RESOLVED_VERIFIED",
  );
  assert.equal(
    receipt.main.user_resolution_after_apply,
    "REPAIR_FAILED_ROLLED_BACK",
  );
  assert.ok(receipt.main.hash_proof);
  assert.equal(
    receipt.main.hash_proof!.after_apply_sha256,
    PROTECTED_ARTIFACT_SHA,
  );
  assert.equal(receipt.main.hash_proof!.restored, true);

  const m = stepMap(receipt);
  assert.equal(m.get("apply_main")!.status, "pass");
  assert.equal(m.get("verify_main")!.status, "skip");
  assert.equal(m.get("rollback_main")!.status, "skip");
  assert.equal(m.get("model_refuse")!.status, "pass");
  assert.equal(m.get("crash_refuse")!.status, "pass");
  assert.equal(m.get("cleanup")!.status, "pass");
  assert.equal(receipt.cleanup.temp_removed, true);

  assert.equal(hashTree(fixtureRoot), beforeFixture);
});

// ---------------------------------------------------------------------------
// Schema + allowlist stability
// ---------------------------------------------------------------------------

test("Ticket17 demo: schema file and allowlist are stable product contracts", () => {
  assert.ok(fs.existsSync(SCHEMA_PATH));
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8")) as {
    required: string[];
    properties: Record<string, unknown>;
  };
  for (const k of [
    "schema_version",
    "ok",
    "status",
    "duration_ms",
    "steps",
    "main",
    "model_refusal",
    "crash_refusal",
    "network_used",
    "external_write",
    "live_profile_mutated",
    "security_evidence",
    "cleanup",
    "error_code",
    "error_message",
  ]) {
    assert.ok(schema.required.includes(k), `schema requires ${k}`);
  }
  const stepsProp = schema.properties.steps as {
    minItems: number;
    maxItems: number;
  };
  assert.equal(stepsProp.minItems, 10);
  assert.equal(stepsProp.maxItems, 10);
  assert.deepEqual(
    [...DEMO_FIXTURE_ALLOWLIST],
    [
      "fixtures/protected-process",
      "fixtures/crash-family/access-violation-crbrowser",
      "fixtures/impact-local",
    ],
  );
});

// ---------------------------------------------------------------------------
// Security-evidence fail-closed: malformed / missing / true network observations
// ---------------------------------------------------------------------------

function allRequiredStrictFalseObservations(): DemoNetworkObservation[] {
  return REQUIRED_NETWORK_SEAMS.map((seam) => ({
    seam,
    network_used: false,
    value_valid: true,
  }));
}

/** Disposable proofs that would otherwise allow proven if network is clean. */
const PROVEN_DISPOSABLE = {
  proof_count: 2,
  reason_codes: ["ISOLATE_ROOT_DISPOSABLE", "PRE_APPLY_TARGET_DISPOSABLE"],
} as const;

test("Ticket17 demo: malformed/missing/true network observations cannot yield proven:true", () => {
  // GREEN baseline: strict-false required seams + disposable proofs ⇒ proven.
  const green = finalizeSecurityEvidence(
    allRequiredStrictFalseObservations(),
    PROVEN_DISPOSABLE.proof_count,
    [...PROVEN_DISPOSABLE.reason_codes],
    true,
  );
  assert.equal(green.proven, true);
  assert.equal(green.network_all_false, true);
  for (const o of green.network_observations) {
    assert.equal(o.value_valid, true);
    assert.equal(o.network_used, false);
  }

  // RED: empty / missing required seams.
  const missing = finalizeSecurityEvidence(
    [],
    PROVEN_DISPOSABLE.proof_count,
    [...PROVEN_DISPOSABLE.reason_codes],
    true,
  );
  assert.equal(missing.proven, false);
  assert.equal(missing.network_all_false, false);

  // RED: one required seam omitted.
  const partial = finalizeSecurityEvidence(
    allRequiredStrictFalseObservations().slice(0, 3),
    PROVEN_DISPOSABLE.proof_count,
    [...PROVEN_DISPOSABLE.reason_codes],
    true,
  );
  assert.equal(partial.proven, false);
  assert.equal(partial.network_all_false, false);

  // RED: boolean true on a required seam.
  const withTrue = allRequiredStrictFalseObservations();
  withTrue[0] = { seam: "diagnose_main", network_used: true, value_valid: true };
  const trueObs = finalizeSecurityEvidence(
    withTrue,
    PROVEN_DISPOSABLE.proof_count,
    [...PROVEN_DISPOSABLE.reason_codes],
    true,
  );
  assert.equal(trueObs.proven, false);
  assert.equal(trueObs.network_all_false, false);
  assert.equal(trueObs.network_observations[0]!.network_used, true);
  assert.equal(trueObs.network_observations[0]!.value_valid, true);

  // RED: malformed runtime values (undefined/null/string/number) via value_valid=false.
  // Mirrors recordNetwork(network_used === true || network_used === false).
  for (const bad of [undefined, null, "false", 0, 1, {}, []] as unknown[]) {
    const value_valid = bad === true || bad === false;
    const obs: DemoNetworkObservation[] = allRequiredStrictFalseObservations();
    obs[1] = {
      seam: "apply_main",
      network_used: bad === true,
      value_valid,
    };
    const ev = finalizeSecurityEvidence(
      obs,
      PROVEN_DISPOSABLE.proof_count,
      [...PROVEN_DISPOSABLE.reason_codes],
      true,
    );
    assert.equal(
      ev.proven,
      false,
      `malformed ${String(bad)} must not prove`,
    );
    assert.equal(ev.network_all_false, false);
    assert.equal(ev.network_observations[1]!.value_valid, false);
  }

  // RED: duplicate-conflicting (strict false then true) fails closed.
  const conflict: DemoNetworkObservation[] = [
    ...allRequiredStrictFalseObservations(),
    { seam: "diagnose_main", network_used: true, value_valid: true },
  ];
  const conflictEv = finalizeSecurityEvidence(
    conflict,
    PROVEN_DISPOSABLE.proof_count,
    [...PROVEN_DISPOSABLE.reason_codes],
    true,
  );
  assert.equal(conflictEv.proven, false);
  assert.equal(conflictEv.network_all_false, false);

  // RED: consistent duplicate false is ok (still all strict false).
  const consistentDup: DemoNetworkObservation[] = [
    ...allRequiredStrictFalseObservations(),
    { seam: "diagnose_main", network_used: false, value_valid: true },
  ];
  const dupOk = finalizeSecurityEvidence(
    consistentDup,
    PROVEN_DISPOSABLE.proof_count,
    [...PROVEN_DISPOSABLE.reason_codes],
    true,
  );
  assert.equal(dupOk.proven, true);
  assert.equal(dupOk.network_all_false, true);

  // RED: true coerced-style observation without value_valid cannot prove
  // (legacy false-green: network_used === true mapped undefined→false).
  const coercedStyle: DemoNetworkObservation[] = allRequiredStrictFalseObservations();
  coercedStyle[2] = {
    seam: "impact_baseline",
    network_used: false, // would look offline if validity ignored
    value_valid: false, // but validity says malformed
  };
  const coerced = finalizeSecurityEvidence(
    coercedStyle,
    PROVEN_DISPOSABLE.proof_count,
    [...PROVEN_DISPOSABLE.reason_codes],
    true,
  );
  assert.equal(coerced.proven, false);
  assert.equal(coerced.network_all_false, false);
});

// ---------------------------------------------------------------------------
// TOCTOU: re-prove protectedTarget before apply/rollback mutations
// ---------------------------------------------------------------------------

/**
 * Source-order honesty: production must call proveMutationTargetDisposable
 * immediately before the happy-path applyRepair / rollbackRepair mutations
 * (no callback/test-hook seam). Best-effort recovery rollbacks elsewhere are
 * out of band; the guarded mutation site must follow its local proof.
 */
function assertMutationProofPrecedesMutationCalls(src: string): void {
  // No runtime callback surface for adversarial target swap.
  assert.equal(
    /_testHooks|RunDemoTestHooks|beforeMutationTargetProof/.test(src),
    false,
    "run-demo must not expose _testHooks / callback mutation seams",
  );
  assert.match(src, /export function proveMutationTargetDisposable/);
  assert.match(src, /PRE_APPLY_TARGET_DISPOSABLE/);
  assert.match(src, /PRE_ROLLBACK_TARGET_DISPOSABLE/);
  assert.match(src, /MUTATION_TARGET_NOT_DISPOSABLE/);

  // Apply boundary: proof must sit immediately before the sole applyRepair call.
  const applyRegionStart = src.indexOf("// --- apply_main ---");
  const verifyRegionStart = src.indexOf("// --- verify_main");
  assert.ok(applyRegionStart >= 0, "apply_main region marker present");
  assert.ok(verifyRegionStart > applyRegionStart, "verify region after apply");
  const applyRegion = src.slice(applyRegionStart, verifyRegionStart);
  const proofInApply = applyRegion.indexOf("proveMutationTargetDisposable(");
  const repairInApply = applyRegion.indexOf("applyRepair(");
  assert.ok(proofInApply >= 0, "apply region calls proveMutationTargetDisposable");
  assert.ok(repairInApply >= 0, "apply region calls applyRepair");
  assert.ok(
    proofInApply < repairInApply,
    "proveMutationTargetDisposable must precede applyRepair",
  );
  // No second applyRepair before the proof (single guarded mutation site).
  assert.equal(
    applyRegion.indexOf("applyRepair("),
    applyRegion.lastIndexOf("applyRepair("),
    "apply_main must have a single applyRepair call site",
  );

  // Rollback boundary: after the proof, the next rollbackRepair is the guarded
  // restore write. (Budget-path best-effort rollback may appear earlier.)
  const rbRegionStart = src.indexOf("// --- rollback_main");
  const modelRegionStart = src.indexOf("// --- model_refuse ---");
  assert.ok(rbRegionStart >= 0, "rollback_main region marker present");
  assert.ok(modelRegionStart > rbRegionStart, "model region after rollback");
  const rbRegion = src.slice(rbRegionStart, modelRegionStart);
  const proofInRb = rbRegion.indexOf("proveMutationTargetDisposable(");
  assert.ok(proofInRb >= 0, "rollback region calls proveMutationTargetDisposable");
  const repairAfterProof = rbRegion.indexOf("rollbackRepair(", proofInRb);
  assert.ok(
    repairAfterProof > proofInRb,
    "proveMutationTargetDisposable must precede the guarded rollbackRepair",
  );
  // Between proof and guarded rollback: no intervening applyRepair write.
  const between = rbRegion.slice(proofInRb, repairAfterProof);
  assert.equal(
    /applyRepair\(/.test(between),
    false,
    "no applyRepair between mutation proof and rollbackRepair",
  );

  // Helper must be proof-only: no mutation/callback surfaces in its body.
  const helperStart = src.indexOf(
    "export function proveMutationTargetDisposable",
  );
  assert.ok(helperStart >= 0);
  const afterHelper = src.slice(helperStart);
  const helperEndRel = afterHelper.indexOf("\nexport function ");
  const helperBody =
    helperEndRel > 0 ? afterHelper.slice(0, helperEndRel) : afterHelper.slice(0, 600);
  assert.equal(
    /callback|beforeMutation|_testHooks|writeFile|rmSync|symlinkSync|applyRepair|rollbackRepair/.test(
      helperBody,
    ),
    false,
    "proveMutationTargetDisposable must not mutate or accept callbacks",
  );
  assert.match(helperBody, /proveIsolatedFixtureTarget/);
  assert.match(helperBody, /MUTATION_TARGET_DISPOSABLE/);
  assert.match(helperBody, /MUTATION_TARGET_NOT_DISPOSABLE/);
}

test("Ticket17 demo: proveMutationTargetDisposable refuses symlink / non-disposable targets", () => {
  // Direct proof-helper adversarial cases (no runtime callback seam).
  // proveIsolatedFixtureTarget refuses symlink leaves → MUTATION_TARGET_NOT_DISPOSABLE.
  const outside = makeTempDir("cg-t17-toctou-outside-");
  const home = makeTempDir("cg-t17-toctou-home-");
  const probe = makeTempDir("cg-t17-toctou-probe-");
  try {
    // Leaf symlink pointing outside trusted disposable isolation.
    const leafLink = path.join(probe, "symlink-leaf");
    fs.symlinkSync(outside, leafLink);
    const symlinkProof = proveMutationTargetDisposable(leafLink, home);
    assert.equal(symlinkProof.ok, false);
    assert.equal(symlinkProof.reason_code, "MUTATION_TARGET_NOT_DISPOSABLE");
    // Path-free stable result: no absolute paths embedded.
    assertNoLeakInValue(symlinkProof, "toctou-symlink-proof");

    // Live profile / non-disposable path refusal.
    const liveCodex = path.join(home, ".codex");
    fs.mkdirSync(liveCodex, { recursive: true });
    const liveProof = proveMutationTargetDisposable(liveCodex, home);
    assert.equal(liveProof.ok, false);
    assert.equal(liveProof.reason_code, "MUTATION_TARGET_NOT_DISPOSABLE");
    assertNoLeakInValue(liveProof, "toctou-live-proof");

    // Positive control: real disposable mkdtemp child under OS temp proves ok.
    const disposable = createDemoTempRoot(home);
    try {
      const okProof = proveMutationTargetDisposable(disposable, home);
      assert.equal(okProof.ok, true);
      assert.equal(okProof.reason_code, "MUTATION_TARGET_DISPOSABLE");
      assertNoLeakInValue(okProof, "toctou-ok-proof");
    } finally {
      removeDemoTempRoot(disposable);
    }

    // Source honesty: production re-proves protectedTarget immediately before
    // applyRepair / rollbackRepair (source-order, no _testHooks).
    const runDemoSrc = fs.readFileSync(
      path.join(REPO_ROOT, "src/core/demo/run-demo.ts"),
      "utf8",
    );
    assertMutationProofPrecedesMutationCalls(runDemoSrc);
  } finally {
    for (const p of [outside, home, probe]) {
      try {
        fs.rmSync(p, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
  }
});

test("Ticket17 demo: mutation proof call sites precede apply/rollback (source order)", () => {
  const runDemoSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/run-demo.ts"),
    "utf8",
  );
  assertMutationProofPrecedesMutationCalls(runDemoSrc);

  // Types / options surface must not reintroduce the callback seam.
  const typesSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/types.ts"),
    "utf8",
  );
  assert.equal(
    /_testHooks|RunDemoTestHooks|beforeMutationTargetProof/.test(typesSrc),
    false,
    "RunDemoOptions must not declare _testHooks",
  );
  assert.match(typesSrc, /MutationTargetProofResult/);

  const indexSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/index.ts"),
    "utf8",
  );
  assert.equal(
    /RunDemoTestHooks/.test(indexSrc),
    false,
    "demo index must not export RunDemoTestHooks",
  );
  assert.match(indexSrc, /proveMutationTargetDisposable/);
});

// ---------------------------------------------------------------------------
// Nested symlink fail-closed on allowlisted fixture copy (RED/GREEN)
// ---------------------------------------------------------------------------

test("Ticket17 demo: copyAllowlistedFixture refuses nested symlinks (source + dest)", () => {
  const repoRoot = REPO_ROOT;
  const probeRoot = makeTempDir("cg-t17-symlink-probe-");
  const fakeFixtureRel = path.join("fixtures", "_t17-nested-symlink-probe");
  const fakeFixtureAbs = path.join(repoRoot, fakeFixtureRel);
  const outside = path.join(probeRoot, "outside-secret.txt");
  let destParent: string | null = null;

  try {
    fs.writeFileSync(outside, "OUTSIDE_SECRET_BYTES_NEVER_COPY\n", "utf8");
    // Synthetic tree under fixtures/ that is NOT on DEMO_FIXTURE_ALLOWLIST —
    // we unit-test assertSafeDemoTree + a temporary allowlist-bypass via
    // direct tree inspection + copy path internals through public APIs.
    fs.mkdirSync(fakeFixtureAbs, { recursive: true });
    fs.writeFileSync(
      path.join(fakeFixtureAbs, "safe.txt"),
      "safe\n",
      "utf8",
    );
    // Nested symlink pointing outside — must be refused without reading target.
    fs.symlinkSync(outside, path.join(fakeFixtureAbs, "nested-link"));

    // RED: assertSafeDemoTree fails closed on nested symlink.
    assert.throws(
      () => assertSafeDemoTree(fakeFixtureAbs, "source"),
      (e: unknown) =>
        e instanceof DemoIsolationError &&
        e.code === "FIXTURE_SYMLINK_REFUSED",
    );

    // RED: non-allowlisted relative path still refuses at allowlist gate.
    destParent = createDemoTempRoot();
    assert.throws(
      () =>
        copyAllowlistedFixture(
          fakeFixtureRel as never,
          destParent!,
        ),
      (e: unknown) =>
        e instanceof DemoIsolationError &&
        e.code === "FIXTURE_NOT_ALLOWLISTED",
    );

    // GREEN: real allowlisted fixtures pass safe-tree + copy + dest verify.
    for (const rel of DEMO_FIXTURE_ALLOWLIST) {
      assertSafeDemoTree(path.join(repoRoot, rel), "source");
    }
    const copied = copyAllowlistedFixture(
      "fixtures/protected-process",
      destParent!,
    );
    assertSafeDemoTree(copied, "destination");
    // Destination must not contain symlinks.
    const walkNoSymlink = (dir: string): void => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);
        assert.equal(
          ent.isSymbolicLink(),
          false,
          `dest symlink: ${ent.name}`,
        );
        if (ent.isDirectory()) walkNoSymlink(full);
      }
    };
    walkNoSymlink(copied);

    // Outside secret must never appear under dest.
    const destText = (() => {
      const acc: string[] = [];
      const walk = (d: string): void => {
        for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
          const full = path.join(d, ent.name);
          if (ent.isFile()) acc.push(fs.readFileSync(full, "utf8"));
          else if (ent.isDirectory()) walk(full);
        }
      };
      walk(copied);
      return acc.join("\n");
    })();
    assert.equal(
      destText.includes("OUTSIDE_SECRET_BYTES_NEVER_COPY"),
      false,
      "outside bytes must not be copied",
    );
  } finally {
    try {
      if (fs.existsSync(fakeFixtureAbs)) {
        fs.rmSync(fakeFixtureAbs, { recursive: true, force: true });
      }
    } catch {
      /* best-effort */
    }
    if (destParent) removeDemoTempRoot(destParent);
    try {
      fs.rmSync(probeRoot, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
});

test("Ticket17 demo: isolation refuses nested symlink planted under allowlisted fixture name (synthetic)", () => {
  // Build a disposable source tree that looks like a fixture directory with a
  // nested symlink; exercise assertSafeDemoTree + post-copy verification path
  // without polluting real allowlisted fixtures.
  const parent = createDemoTempRoot();
  const synthetic = path.join(parent, "synthetic-fixture");
  const outside = path.join(parent, "outside.bin");
  try {
    fs.mkdirSync(synthetic, { recursive: true });
    fs.writeFileSync(path.join(synthetic, "a.txt"), "a\n", "utf8");
    fs.writeFileSync(outside, "OUTSIDE\n", "utf8");
    fs.symlinkSync(outside, path.join(synthetic, "evil-link"));

    assert.throws(
      () => assertSafeDemoTree(synthetic, "source"),
      (e: unknown) =>
        e instanceof DemoIsolationError && e.code === "FIXTURE_SYMLINK_REFUSED",
    );

    // Also verify destination-side check: if a dest tree gains a symlink,
    // assertSafeDemoTree(destination) fails closed.
    const destTree = path.join(parent, "dest-tree");
    fs.mkdirSync(destTree, { recursive: true });
    fs.writeFileSync(path.join(destTree, "ok.txt"), "ok\n", "utf8");
    assertSafeDemoTree(destTree, "destination");
    fs.symlinkSync(outside, path.join(destTree, "sneaky"));
    assert.throws(
      () => assertSafeDemoTree(destTree, "destination"),
      (e: unknown) =>
        e instanceof DemoIsolationError && e.code === "FIXTURE_SYMLINK_REFUSED",
    );
  } finally {
    removeDemoTempRoot(parent);
  }
});

// ---------------------------------------------------------------------------
// Cleanup truth on early refuse
// ---------------------------------------------------------------------------

test("Ticket17 demo: early refuse still reports cleanup truth without path leak", () => {
  const receipt = runDemo({
    targetRoot: path.join(REPO_ROOT, "fixtures", "negative-control"),
  });
  assert.ok(receipt.status === "refused" || receipt.status === "failed");
  assert.equal(receipt.cleanup.attempted, true);
  // Caller-owned refuse path never creates owned temp → cleanup completed.
  assert.equal(receipt.cleanup.completed, true);
  assertNoLeakInValue(receipt, "early-refuse");
  const m = stepMap(receipt);
  assert.equal(m.get("isolate")!.status, "fail");
  assert.equal(m.get("cleanup")!.status, "pass");
});

// ---------------------------------------------------------------------------
// Temp prefix convention when ownership applies
// ---------------------------------------------------------------------------

test("Ticket17 demo: default run uses disposable temp and removes it", () => {
  // Probe that no leftover cg-demo-* is required: we only assert cleanup flag.
  // Snapshot count of cg-demo-* under tmp before/after should not grow net.
  const tmp = os.tmpdir();
  const before = fs
    .readdirSync(tmp)
    .filter((n) => n.startsWith(DEMO_TEMP_PREFIX));
  const receipt = runDemo({
    now_ms: Date.parse("2026-07-10T12:00:00.000Z"),
  });
  assert.equal(receipt.status, "completed");
  assert.equal(receipt.cleanup.temp_removed, true);
  const after = fs
    .readdirSync(tmp)
    .filter((n) => n.startsWith(DEMO_TEMP_PREFIX));
  // Net leftovers from this process should not grow (best-effort; races ok if equal).
  assert.ok(
    after.length <= before.length,
    `temp leak: before=${before.length} after=${after.length}`,
  );
});

// MakeTempDir imported for potential future extension; keep a smoke that helpers work.
test("Ticket17 demo: helpers remain available for harness composition", () => {
  const t = makeTempDir("cg-t17-help-");
  assert.ok(fs.existsSync(t));
  fs.rmSync(t, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Production-boundary least-privilege (Ticket 17 S2)
// ---------------------------------------------------------------------------

test("Ticket17 demo: production boundary refuses unneeded demo mutation APIs", () => {
  const boundary = path.join(
    REPO_ROOT,
    "scripts",
    "check-production-boundary.mjs",
  );
  const self = spawnSync(process.execPath, [boundary, "--self-test"], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    cwd: REPO_ROOT,
  });
  assert.equal(self.status, 0, self.stdout + self.stderr);

  const prod = spawnSync(process.execPath, [boundary], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    cwd: REPO_ROOT,
  });
  assert.equal(prod.status, 0, prod.stdout + prod.stderr);

  // Exact production seams: isolation owns mkdtemp/cp/rm only; run-demo owns
  // mkdir+writeFile for induce sentinel only; index/types have no fs mutations.
  const isolationSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/isolation.ts"),
    "utf8",
  );
  const runDemoSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/run-demo.ts"),
    "utf8",
  );
  const indexSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/index.ts"),
    "utf8",
  );
  const typesSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/types.ts"),
    "utf8",
  );

  assert.match(isolationSrc, /mkdtempSync/);
  assert.match(isolationSrc, /cpSync/);
  assert.match(isolationSrc, /rmSync/);
  assert.equal(
    /writeFileSync/.test(isolationSrc),
    false,
    "isolation must not writeFileSync",
  );
  assert.equal(
    /mkdirSync/.test(isolationSrc),
    false,
    "isolation must not mkdirSync",
  );

  assert.match(runDemoSrc, /writeFileSync/);
  assert.match(runDemoSrc, /mkdirSync/);
  assert.equal(/cpSync/.test(runDemoSrc), false, "run-demo must not cpSync");
  assert.equal(/rmSync/.test(runDemoSrc), false, "run-demo must not rmSync");
  assert.equal(
    /mkdtempSync/.test(runDemoSrc),
    false,
    "run-demo must not mkdtempSync",
  );

  for (const [label, src] of [
    ["index", indexSrc],
    ["types", typesSrc],
  ] as const) {
    assert.equal(
      /fs\.(writeFileSync|mkdirSync|cpSync|rmSync|mkdtempSync|renameSync)/.test(
        src,
      ),
      false,
      `${label} must not host demo mutation APIs`,
    );
  }
});
