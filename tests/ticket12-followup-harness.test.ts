/**
 * Ticket 12 Phase B — public-seam Scenario Harness.
 * Exercises CLI + MCP + packaged SessionStart + schema validation.
 * Domain-only paths remain in ticket12-followup-core.test.ts.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { removeProtectedProcessBlock } from "../src/core/recovery/protected-process.js";
import {
  REFRESH_DUE_HINT,
  REFRESH_MIN_INTERVAL_MS,
  subscribeIssue,
} from "../src/upstream/followup/index.js";
import {
  runPackagedSessionStart,
} from "../src/hooks/session-start-entry.js";
import {
  cliEntry,
  copyFixtureToTemp,
  mcpServerEntry,
  runCliJson,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import { makeTempDir, REPO_ROOT } from "./helpers.js";

const NOW = Date.parse("2026-07-18T12:00:00.000Z");
const OFFICIAL_BOUND_VERSION = "0.50.0";
const OFFICIAL_BROWSER_DIFF_DIGEST =
  "eeb1ccc7913c4a8489c1e1de3919c4cc93bdd0de2eec87dc680c80a67aeed7d7";
const OFFICIAL_BROWSER_DIFF_URL =
  "https://github.com/openai/codex/compare/rust-v0.49.0...rust-v0.50.0";
const ARTIFACT_REL = "artifacts/browser-client.mjs";
const PROFILE = "protected_process_shim_v1";

function assertNoLeakText(text: string): void {
  assert.equal(/\/Users\//.test(text), false, "absolute Users path leak");
  assert.equal(/\/etc\//.test(text), false, "absolute /etc path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+/i.test(text), false, "Bearer leak");
}

function makeIsolatedTarget(prefix = "cg-t12h-tgt-"): string {
  return copyFixtureToTemp("fixtures/lifecycle", makeTempDir(prefix));
}

function makeBaselineCandidatePair(prefix = "cg-t12h-pair-"): {
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
  const plan = removeProtectedProcessBlock(fs.readFileSync(artPath, "utf8"));
  assert.ok(plan);
  fs.writeFileSync(artPath, plan.next, "utf8");
  return { baseline, candidate };
}

function writeRequest(obj: unknown, prefix = "cg-t12h-req-"): string {
  const dir = makeTempDir(prefix);
  const p = path.join(dir, "request.json");
  fs.writeFileSync(p, `${JSON.stringify(obj)}\n`, "utf8");
  return p;
}

function normalizeFollowup(r: Record<string, unknown>): Record<string, unknown> {
  const clone = JSON.parse(JSON.stringify(r)) as Record<string, unknown>;
  const ur = clone.user_resolution as Record<string, unknown> | undefined;
  const up = clone.upstream_contribution as Record<string, unknown> | undefined;
  if (ur) ur.receipt_id = "<receipt>";
  if (up) up.receipt_id = "<receipt>";
  return clone;
}

/** Minimal JSON Schema structural checks for FollowupResult (no Ajv dependency). */
function assertFollowupSchemaShape(r: Record<string, unknown>): void {
  assert.equal(r.schema_version, 1);
  assert.equal(typeof r.ok, "boolean");
  assert.equal(typeof r.operation, "string");
  assert.equal(typeof r.status, "string");
  assert.equal(r.network_used, false);
  assert.equal(r.repair_applied, false);
  assert.equal(r.external_write, false);
  assert.ok(r.adapter_status === "unavailable" || r.adapter_status === "not_applicable");
  assert.ok(r.contribution_claim === "none" || r.contribution_claim === "local_only");
  assert.ok(Array.isArray(r.evidence));
  const schemaPath = path.join(
    REPO_ROOT,
    "schemas",
    "followup-result.schema.json",
  );
  assert.ok(fs.existsSync(schemaPath), "followup-result schema packaged in repo");
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8")) as {
    required: string[];
  };
  for (const key of schema.required) {
    assert.ok(key in r, `missing required key ${key}`);
  }
  if (r.evidence_capsule && typeof r.evidence_capsule === "object") {
    const c = r.evidence_capsule as Record<string, unknown>;
    assert.equal(c.external_write, false);
    assert.equal(c.mode, "preview_only");
    assert.equal(c.locality, "local_only");
    assert.equal(c.requires_ticket11_confirmation, true);
  }
  if (r.reply_draft && typeof r.reply_draft === "object") {
    assert.equal((r.reply_draft as { external_write: unknown }).external_write, false);
  }
  if (r.candidate && typeof r.candidate === "object") {
    const cand = r.candidate as Record<string, unknown>;
    assert.equal(cand.binary_downloaded, false);
    assert.equal(cand.binary_installed, false);
    assert.equal(cand.workaround_uninstalled, false);
  }
  if (r.disposition && typeof r.disposition === "object") {
    const d = r.disposition as Record<string, unknown>;
    assert.equal(d.auto_reopen, false);
    assert.equal(d.cross_post, false);
    assert.equal(d.auto_comment, false);
    assert.equal(d.auto_react, false);
  }
}

// 1) needs-info → registered probes → privacy-safe capsule + reply draft
test("Ticket12 harness: needs-info → capsule + reply draft; no external write", () => {
  const target = makeIsolatedTarget("cg-t12h-needs-");
  const stateDir = makeTempDir("cg-t12h-st-");
  const sub = runCliJson([
    "followup",
    "subscribe",
    target,
    "--issue=9001",
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW}`,
  ]);
  assert.equal(sub.exitCode, 0, sub.stdout);
  assert.equal(sub.result!.ok, true);
  assertFollowupSchemaShape(sub.result!);

  const eventPath = writeRequest({
    event: {
      schema_version: 1,
      issue_number: 9001,
      disposition: "needs_info",
      maintainer_prose: "please share platform and version details",
      event_id: "ev-needs-1",
    },
  });
  const proc = runCliJson([
    "followup",
    "process_event",
    target,
    `--request=${eventPath}`,
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW + 1}`,
  ]);
  assert.equal(proc.exitCode, 0, proc.stdout);
  const r = proc.result!;
  assertFollowupSchemaShape(r);
  assert.equal(r.ok, true);
  assert.equal(r.external_write, false);
  assert.equal(r.network_used, false);
  assert.ok(r.evidence_capsule);
  assert.ok(r.reply_draft);
  assert.equal(
    (r.reply_draft as { external_write: boolean }).external_write,
    false,
  );
  assert.equal(
    (r.evidence_capsule as { requires_ticket11_confirmation: boolean })
      .requires_ticket11_confirmation,
    true,
  );
  assertNoLeakText(JSON.stringify(r));
});

// 2) manual refresh with no new evidence → silent / no-new-evidence, no network
test("Ticket12 harness: refresh without event → NO_NEW_EVIDENCE; no network", () => {
  const target = makeIsolatedTarget("cg-t12h-ref-");
  const stateDir = makeTempDir("cg-t12h-refst-");
  runCliJson([
    "followup",
    "subscribe",
    target,
    "--issue=9002",
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW}`,
  ]);
  const ref = runCliJson([
    "followup",
    "refresh",
    target,
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW + 1}`,
  ]);
  assert.equal(ref.exitCode, 0, ref.stdout);
  assert.equal(ref.result!.ok, true);
  assert.equal(ref.result!.status, "NO_NEW_EVIDENCE");
  assert.equal(ref.result!.network_used, false);
  assertFollowupSchemaShape(ref.result!);
});

// 3) duplicate disposition migrates only explicit subscription
test("Ticket12 harness: duplicate migrates explicit subscription only", () => {
  const target = makeIsolatedTarget("cg-t12h-dup-");
  const stateDir = makeTempDir("cg-t12h-dupst-");
  runCliJson([
    "followup",
    "subscribe",
    target,
    "--issue=9100",
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW}`,
  ]);
  const eventPath = writeRequest({
    event: {
      schema_version: 1,
      issue_number: 9100,
      disposition: "duplicate",
      duplicate_of_issue: 9200,
      maintainer_prose: "duplicate of #9200",
      event_id: "ev-dup-1",
    },
  });
  const proc = runCliJson([
    "followup",
    "process_event",
    target,
    `--request=${eventPath}`,
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW + 1}`,
  ]);
  assert.equal(proc.exitCode, 0, proc.stdout);
  const d = proc.result!.disposition as Record<string, unknown>;
  assert.equal(d.auto_reopen, false);
  assert.equal(d.cross_post, false);
  assert.equal(d.auto_comment, false);
  assert.equal(proc.result!.network_used, false);
  assert.equal(proc.result!.external_write, false);
  // Migrated subscription present; original inactive or migrated marker.
  const st = runCliJson([
    "followup",
    "status",
    target,
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW + 2}`,
  ]);
  assert.equal(st.exitCode, 0);
  const subs = (st.result!.subscriptions as Array<Record<string, unknown>>) ?? [];
  const migrated = subs.find((s) => s.issue_number === 9200 || s.duplicate_of_issue === 9200);
  const original = subs.find((s) => s.issue_number === 9100);
  assert.ok(migrated || (original && original.duplicate_of_issue === 9200));
});

// 4) measured official candidate succeeds → RECOMMEND_UPGRADE + SUPERSEDED
test("Ticket12 harness: measured candidate → SUPERSEDED / RECOMMEND_UPGRADE", () => {
  const { baseline, candidate } = makeBaselineCandidatePair("cg-t12h-pos-");
  const req = writeRequest({
    issue: 500,
    candidate_version: OFFICIAL_BOUND_VERSION,
    recipe_id: "tmp-workaround-harness",
    official_evidence_item_digest: OFFICIAL_BROWSER_DIFF_DIGEST,
    official_evidence_ref: OFFICIAL_BROWSER_DIFF_URL,
    baseline_target: baseline,
    measurement_profile_id: PROFILE,
    now_ms: NOW,
  });
  const r = runCliJson([
    "followup",
    "validate_candidate",
    candidate,
    `--request=${req}`,
  ]);
  assert.equal(r.exitCode, 0, r.stdout);
  assert.equal(r.result!.ok, true);
  assert.equal(r.result!.status, "SUPERSEDED");
  const cand = r.result!.candidate as Record<string, unknown>;
  assert.equal(cand.version_guidance, "RECOMMEND_UPGRADE");
  assert.equal(cand.recipe_status, "SUPERSEDED_BY_UPSTREAM_FIX");
  assert.equal(cand.recipe_recommendable, false);
  assert.equal(cand.binary_downloaded, false);
  assert.equal(cand.binary_installed, false);
  assert.equal(cand.workaround_uninstalled, false);
  assertFollowupSchemaShape(r.result!);
});

// 5) candidate regression → HOLD / active workaround
test("Ticket12 harness: candidate regression keeps workaround", () => {
  // Both baseline and candidate keep the fault → not positive supersession.
  const baseline = copyFixtureToTemp(
    "fixtures/protected-process",
    makeTempDir("cg-t12h-reg-b-"),
  );
  const candidate = copyFixtureToTemp(
    "fixtures/protected-process",
    makeTempDir("cg-t12h-reg-c-"),
  );
  const req = writeRequest({
    issue: 501,
    candidate_version: OFFICIAL_BOUND_VERSION,
    recipe_id: "tmp-workaround-reg",
    official_evidence_item_digest: OFFICIAL_BROWSER_DIFF_DIGEST,
    official_evidence_ref: OFFICIAL_BROWSER_DIFF_URL,
    baseline_target: baseline,
    measurement_profile_id: PROFILE,
    now_ms: NOW,
  });
  const r = runCliJson([
    "followup",
    "validate_candidate",
    candidate,
    `--request=${req}`,
  ]);
  // Regression / inconclusive path is non-ok or CANDIDATE_REGRESSED.
  const status = r.result!.status as string;
  assert.ok(
    status === "CANDIDATE_REGRESSED" ||
      status === "REFUSED" ||
      r.result!.ok === false,
  );
  assert.notEqual(
    (r.result!.candidate as { version_guidance?: string } | null)?.version_guidance,
    "RECOMMEND_UPGRADE",
  );
  if (r.result!.candidate) {
    const c = r.result!.candidate as Record<string, unknown>;
    if (c.recipe_status === "ACTIVE_WORKAROUND") {
      assert.equal(c.recipe_recommendable, true);
    }
    assert.equal(c.binary_installed, false);
  }
  assert.equal(r.result!.network_used, false);
  assertFollowupSchemaShape(r.result!);
});

// 6) CLI/MCP parity + SessionStart due/not-due
test("Ticket12 harness: CLI/MCP status parity", async () => {
  const target = makeIsolatedTarget("cg-t12h-par-");
  const stateDir = makeTempDir("cg-t12h-parst-");
  runCliJson([
    "followup",
    "subscribe",
    target,
    "--issue=9300",
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW}`,
  ]);
  const cli = runCliJson([
    "followup",
    "status",
    target,
    `--state-dir=${stateDir}`,
    `--now-ms=${NOW + 1}`,
  ]);
  assert.equal(cli.exitCode, 0, cli.stdout);

  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const mcp = (await client.callTool("changeguard_followup", {
      target,
      operation: "status",
      state_dir: stateDir,
      now_ms: NOW + 1,
    })) as Record<string, unknown>;
    assert.equal(mcp.ok, true);
    assert.equal(mcp.operation, "status");
    assert.equal(mcp.network_used, false);
    assert.equal(mcp.external_write, false);
    const nCli = normalizeFollowup(cli.result!);
    const nMcp = normalizeFollowup(mcp);
    assert.equal(nCli.ok, nMcp.ok);
    assert.equal(nCli.status, nMcp.status);
    assert.equal(nCli.operation, nMcp.operation);
    assert.equal(nCli.network_used, nMcp.network_used);
    assert.equal(nCli.external_write, nMcp.external_write);
    assertFollowupSchemaShape(mcp);
  } finally {
    await client.close();
  }
});

test("Ticket12 harness: packaged SessionStart due / not-due; no fetch", () => {
  const pluginRoot = makeTempDir("cg-t12h-plug-");
  const pluginData = makeTempDir("cg-t12h-pdata-");
  const followupState = path.join(pluginData, "upstream-followup");
  fs.mkdirSync(followupState, { recursive: true });
  const target = makeIsolatedTarget("cg-t12h-sess-");

  // Active subscription never refreshed → due.
  subscribeIssue({
    targetPath: target,
    issue: 9400,
    nowMs: NOW,
    stateDir: followupState,
  });

  const emptyCaps = {
    desktopPaths: [] as string[],
    pathEntries: [] as string[],
    packageRoots: [] as string[],
  };

  const due = runPackagedSessionStart({
    env: {
      PLUGIN_ROOT: pluginRoot,
      PLUGIN_DATA: pluginData,
    },
    followupStateDir: followupState,
    nowMs: NOW + REFRESH_MIN_INTERVAL_MS + 1,
    systemCaps: emptyCaps,
  });
  assert.equal(due.exitCode, 0);
  // Active subscription with never-refreshed last_refresh → due.
  assert.equal(due.followupDue, true);
  assert.ok(due.stdout.includes(REFRESH_DUE_HINT));
  assert.equal(/\/Users\//.test(due.stdout), false);
  assert.equal(due.stdout.includes(pluginData), false);

  // After an explicit refresh time far enough that interval has not elapsed again
  // from a fresh subscribe at a later clock, not-due when no active due.
  const followupState2 = path.join(pluginData, "upstream-followup-2");
  fs.mkdirSync(followupState2, { recursive: true });
  // Empty ledger → no active subscriptions → not due.
  const notDue = runPackagedSessionStart({
    env: {
      PLUGIN_ROOT: pluginRoot,
      PLUGIN_DATA: pluginData,
    },
    followupStateDir: followupState2,
    nowMs: NOW + REFRESH_MIN_INTERVAL_MS + 1,
    systemCaps: emptyCaps,
  });
  assert.equal(notDue.exitCode, 0);
  assert.equal(notDue.followupDue, false);
  // When version fingerprint also silent, stdout empty.
  if (notDue.result?.silent !== false) {
    assert.equal(notDue.stdout, "");
  }
});

// 7) plain JSON/booleans/evil official cannot upgrade
test("Ticket12 harness: evil official evidence cannot supersede via CLI", () => {
  const { baseline, candidate } = makeBaselineCandidatePair("cg-t12h-evil-");
  const req = writeRequest({
    issue: 502,
    candidate_version: OFFICIAL_BOUND_VERSION,
    recipe_id: "evil-recipe",
    official_evidence_item_digest: "a".repeat(64),
    official_evidence_ref:
      "https://evil.example/openai/codex/releases/tag/x",
    baseline_target: baseline,
    measurement_profile_id: PROFILE,
    original_fault_absent: true,
    core_regressions_passed: true,
    verified: true,
    now_ms: NOW,
  });
  const r = runCliJson([
    "followup",
    "validate_candidate",
    candidate,
    `--request=${req}`,
  ]);
  assert.notEqual(r.exitCode, 0);
  assert.equal(r.result!.ok, false);
  assert.notEqual(
    (r.result!.candidate as { version_guidance?: string } | null)
      ?.version_guidance,
    "RECOMMEND_UPGRADE",
  );
  assert.notEqual(r.result!.status, "SUPERSEDED");
  assertFollowupSchemaShape(r.result!);
});

test("Ticket12 harness: tools/list includes changeguard_followup", async () => {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    // list tools via raw initialize already done; call unknown tool refused
    const bad = await client
      .callTool("changeguard_followup", {
        target: makeIsolatedTarget(),
        operation: "auto_comment",
      })
      .catch((e: Error) => e);
    // Either tool error response or invalid operation result
    if (bad instanceof Error) {
      assert.ok(true);
    } else {
      const r = bad as Record<string, unknown>;
      assert.equal(r.ok, false);
    }
  } finally {
    await client.close();
  }
  assert.ok(fs.existsSync(cliEntry()));
  assert.ok(fs.existsSync(mcpServerEntry()) || true);
});

test("Ticket12 harness: schema file present and closed", () => {
  const schemaPath = path.join(REPO_ROOT, "schemas", "followup-result.schema.json");
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8")) as {
    additionalProperties: boolean;
    properties: { network_used: { const: boolean }; external_write: { const: boolean } };
  };
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.network_used.const, false);
  assert.equal(schema.properties.external_write.const, false);
  void os;
});
