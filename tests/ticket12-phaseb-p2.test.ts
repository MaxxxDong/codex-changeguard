/**
 * Ticket 12 Phase B — P2 hardening adversarial tests.
 * Persistence fail-closed, version syntax, snapshot_path refusal,
 * witness precheck non-mutation, request-layer authority smuggling.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  isLiveMeasurementWitness,
  LIFECYCLE_LEDGER_REL,
  readLiveMeasurementAttestation,
  runCanary,
} from "../src/core/lifecycle/index.js";
import { removeProtectedProcessBlock } from "../src/core/recovery/protected-process.js";
import {
  measureWithRegisteredProfile,
  parseFollowupRequestJson,
  PROTECTED_PROCESS_SHIM_PROFILE_V1,
  validateCandidate,
  validateCandidateFix,
} from "../src/upstream/followup/index.js";
import { copyFixtureToTemp } from "../src/harness/scenario.js";
import { makeTempDir } from "./helpers.js";

const NOW = Date.parse("2026-07-18T12:00:00.000Z");
const OFFICIAL_BOUND_VERSION = "0.50.0";
const OFFICIAL_BROWSER_DIFF_DIGEST =
  "eeb1ccc7913c4a8489c1e1de3919c4cc93bdd0de2eec87dc680c80a67aeed7d7";
const OFFICIAL_BROWSER_DIFF_URL =
  "https://github.com/openai/codex/compare/rust-v0.49.0...rust-v0.50.0";
const ARTIFACT_REL = "artifacts/browser-client.mjs";
const PROFILE = PROTECTED_PROCESS_SHIM_PROFILE_V1;

function makeBaselineCandidatePair(prefix = "cg-t12b-pair-"): {
  baseline: string;
  candidate: string;
} {
  const baseline = copyFixtureToTemp(
    "fixtures/protected-process",
    makeTempDir(`${prefix}base-`),
  );
  const candidate = copyFixtureToTemp(
    "fixtures/protected-process",
    makeTempDir(`${prefix}cand-`),
  );
  const artPath = path.join(candidate, ARTIFACT_REL);
  const src = fs.readFileSync(artPath, "utf8");
  const plan = removeProtectedProcessBlock(src);
  assert.ok(plan);
  fs.writeFileSync(artPath, plan.next, "utf8");
  return { baseline, candidate };
}

function baseValidateInput(
  candidate: string,
  baseline: string,
  overrides: Partial<{ candidate_version: string }> = {},
) {
  return {
    targetPath: candidate,
    baselineTargetPath: baseline,
    measurement_profile_id: PROFILE,
    issue_number: 500,
    candidate_version: overrides.candidate_version ?? OFFICIAL_BOUND_VERSION,
    recipe_id: "tmp-workaround-t12b",
    official_evidence_item_digest: OFFICIAL_BROWSER_DIFF_DIGEST,
    official_evidence_ref: OFFICIAL_BROWSER_DIFF_URL,
    nowMs: NOW,
  };
}

test("Ticket12 P2-2: non-version live measurement / canary cannot RECOMMEND_UPGRADE", () => {
  const { baseline, candidate } = makeBaselineCandidatePair("cg-t12b-ver-");
  for (const bad of [
    "v0.50.0",
    "0.50",
    "0.50.0-rc1",
    "latest",
    "abc",
    "1.2.3.4",
  ]) {
    const m = measureWithRegisteredProfile({
      targetPath: candidate,
      baselineTargetPath: baseline,
      candidate_version: bad,
      profile_id: PROFILE,
      nowMs: NOW,
    });
    assert.equal(m.verdict, "inconclusive", `measure ${bad}`);
    assert.equal(m.error_code, "INVALID_VERSION", `measure code ${bad}`);
    assert.equal(m.witness, null);

    const canary = runCanary({
      targetPath: candidate,
      candidate_version: bad,
      original_fault_absent: true,
      core_regressions_passed: true,
      canary_executed: true,
      measured_outcomes: true,
      nowMs: NOW,
    });
    assert.equal(canary.ok, false, `canary ${bad}`);
    assert.equal(canary.error_code, "INVALID_VERSION");
    assert.notEqual(canary.version_guidance, "RECOMMEND_UPGRADE");
  }

  const r = validateCandidateFix(
    baseValidateInput(candidate, baseline, { candidate_version: "v0.50.0" }),
  );
  assert.equal(r.ok, false);
  assert.equal(r.error_code, "INVALID_VERSION");
});

test("Ticket12 P2-3: canary ledger persistence failure fails closed", () => {
  const { baseline, candidate } = makeBaselineCandidatePair("cg-t12b-persist-");
  const seed = runCanary({
    targetPath: candidate,
    candidate_version: OFFICIAL_BOUND_VERSION,
    original_fault_absent: false,
    core_regressions_passed: false,
    canary_executed: true,
    nowMs: NOW,
  });
  assert.equal(seed.ok, true);

  const measured = measureWithRegisteredProfile({
    targetPath: candidate,
    baselineTargetPath: baseline,
    candidate_version: OFFICIAL_BOUND_VERSION,
    profile_id: PROFILE,
    nowMs: NOW + 1,
  });
  assert.equal(measured.verdict, "positive");
  assert.ok(isLiveMeasurementWitness(measured.witness));

  const lifecycleDir = path.join(candidate, ".changeguard", "lifecycle");
  try {
    fs.rmSync(lifecycleDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
  fs.mkdirSync(path.dirname(lifecycleDir), { recursive: true });
  // File where directory is required → persistence fails closed.
  fs.writeFileSync(lifecycleDir, "not-a-directory", "utf8");

  const canary = runCanary({
    targetPath: candidate,
    candidate_version: OFFICIAL_BOUND_VERSION,
    original_fault_absent: true,
    core_regressions_passed: true,
    canary_executed: true,
    measured_outcomes: true,
    live_measurement_witness: measured.witness,
    nowMs: NOW + 2,
  });
  assert.equal(canary.ok, false, "persistence failure must not ok:true");
  assert.notEqual(canary.version_guidance, "RECOMMEND_UPGRADE");
  assert.ok(typeof canary.error_code === "string" && canary.error_code.length > 0);
  // Witness not serialized as success; attestation may still be readable for retry.
  void readLiveMeasurementAttestation(measured.witness);
});

test("Ticket12 P2-4: invalid-stage/replay/binding witness does not mutate ledger", () => {
  const { baseline, candidate } = makeBaselineCandidatePair("cg-t12b-wstage-");
  const before = runCanary({
    targetPath: candidate,
    candidate_version: OFFICIAL_BOUND_VERSION,
    original_fault_absent: false,
    core_regressions_passed: false,
    canary_executed: false,
    nowMs: NOW,
  });
  assert.equal(before.ok, true);
  const ledgerAbs = path.join(candidate, LIFECYCLE_LEDGER_REL);
  const beforeBytes = fs.readFileSync(ledgerAbs);

  const measured = measureWithRegisteredProfile({
    targetPath: candidate,
    baselineTargetPath: baseline,
    candidate_version: OFFICIAL_BOUND_VERSION,
    profile_id: PROFILE,
    nowMs: NOW + 1,
  });
  assert.equal(measured.verdict, "positive");
  const w = measured.witness;
  assert.ok(isLiveMeasurementWitness(w));

  const bindFail = runCanary({
    targetPath: candidate,
    candidate_version: "0.49.0",
    original_fault_absent: true,
    core_regressions_passed: true,
    canary_executed: true,
    measured_outcomes: true,
    live_measurement_witness: w,
    nowMs: NOW + 2,
  });
  assert.equal(bindFail.ok, false);
  assert.equal(bindFail.error_code, "LIVE_WITNESS_BINDING");
  assert.notEqual(bindFail.version_guidance, "RECOMMEND_UPGRADE");
  assert.deepEqual(
    fs.readFileSync(ledgerAbs),
    beforeBytes,
    "ledger must not mutate on binding fail",
  );

  const ok = runCanary({
    targetPath: candidate,
    candidate_version: OFFICIAL_BOUND_VERSION,
    original_fault_absent: true,
    core_regressions_passed: true,
    canary_executed: true,
    measured_outcomes: true,
    live_measurement_witness: w,
    nowMs: NOW + 3,
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.version_guidance, "RECOMMEND_UPGRADE");
  const midBytes = fs.readFileSync(ledgerAbs);

  const replay = runCanary({
    targetPath: candidate,
    candidate_version: OFFICIAL_BOUND_VERSION,
    original_fault_absent: true,
    core_regressions_passed: true,
    canary_executed: true,
    measured_outcomes: true,
    live_measurement_witness: w,
    nowMs: NOW + 4,
  });
  assert.equal(replay.ok, false);
  assert.ok(
    replay.error_code === "LIVE_WITNESS_STAGE" ||
      replay.error_code === "LIVE_WITNESS_REPLAY",
  );
  assert.notEqual(replay.version_guidance, "RECOMMEND_UPGRADE");
  assert.deepEqual(
    fs.readFileSync(ledgerAbs),
    midBytes,
    "ledger must not mutate on stage/replay fail",
  );
});

test("Ticket12 P2-1: public request JSON rejects snapshot_path", () => {
  const bad = parseFollowupRequestJson(
    JSON.stringify({
      issue: 1,
      candidate_version: "0.50.0",
      recipe_id: "r1",
      official_evidence_item_digest: OFFICIAL_BROWSER_DIFF_DIGEST,
      official_evidence_ref: OFFICIAL_BROWSER_DIFF_URL,
      baseline_target: "/tmp/x",
      measurement_profile_id: PROFILE,
      snapshot_path: "/tmp/forged.json",
    }),
    "validate_candidate",
  );
  assert.equal(bad.ok, false);
  if (!bad.ok) {
    assert.ok(
      bad.code === "FORBIDDEN_FIELD" || bad.code === "EXTRA_FIELD",
      bad.code,
    );
  }
});

test("Ticket12 P2-1: smuggled snapshot_path on validateCandidateFix refused", () => {
  const { baseline, candidate } = makeBaselineCandidatePair("cg-t12b-snap-");
  const r = validateCandidateFix({
    ...baseValidateInput(candidate, baseline),
    snapshot_path: "/tmp/forged-official-snapshot.json",
  } as ReturnType<typeof baseValidateInput> & { snapshot_path: string });
  assert.equal(r.ok, false);
  assert.equal(r.error_code, "SNAPSHOT_PATH_FORBIDDEN");

  const r2 = validateCandidate({
    ...baseValidateInput(candidate, baseline),
    snapshot_path: "/tmp/forged.json",
  } as ReturnType<typeof baseValidateInput> & { snapshot_path: string });
  assert.equal(r2.ok, false);
  assert.equal(r2.error_code, "SNAPSHOT_PATH_FORBIDDEN");
});

test("Ticket12 P2: request JSON rejects witness / shell / target override keys", () => {
  for (const key of [
    "live_measurement_witness",
    "witness",
    "shell",
    "command",
    "binary_path",
    "target",
    "operation",
    "token",
  ]) {
    const body: Record<string, unknown> = { issue: 1 };
    body[key] = key === "issue" ? 1 : "evil";
    const r = parseFollowupRequestJson(JSON.stringify(body), "subscribe");
    assert.equal(r.ok, false, `key ${key}`);
  }
});
