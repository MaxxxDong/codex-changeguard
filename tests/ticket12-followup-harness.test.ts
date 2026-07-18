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
import * as followupPublic from "../src/upstream/followup/index.js";
import {
  dispatchFollowup,
  REFRESH_DUE_HINT,
  REFRESH_MIN_INTERVAL_MS,
  subscribeIssue,
} from "../src/upstream/followup/index.js";
import {
  runPackagedSessionStart,
} from "../src/hooks/session-start-entry.js";
import {
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

function followupEnv(stateDir: string): NodeJS.ProcessEnv {
  return { CHANGEGUARD_FOLLOWUP_STATE_DIR: stateDir };
}

// 1) needs-info → registered probes → privacy-safe capsule + reply draft
test("Ticket12 harness: needs-info → capsule + reply draft; no external write", () => {
  const target = makeIsolatedTarget("cg-t12h-needs-");
  const stateDir = makeTempDir("cg-t12h-st-");
  const env = followupEnv(stateDir);
  const sub = runCliJson(
    ["followup", "subscribe", target, "--issue=9001", `--now-ms=${NOW}`],
    { env },
  );
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
    now_ms: NOW + 1,
  });
  const proc = runCliJson(
    ["followup", "process_event", target, `--request=${eventPath}`],
    { env },
  );
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
  const env = followupEnv(stateDir);
  runCliJson(
    ["followup", "subscribe", target, "--issue=9002", `--now-ms=${NOW}`],
    { env },
  );
  const ref = runCliJson(
    ["followup", "refresh", target, `--now-ms=${NOW + 1}`],
    { env },
  );
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
  const env = followupEnv(stateDir);
  runCliJson(
    ["followup", "subscribe", target, "--issue=9100", `--now-ms=${NOW}`],
    { env },
  );
  const eventPath = writeRequest({
    event: {
      schema_version: 1,
      issue_number: 9100,
      disposition: "duplicate",
      duplicate_of_issue: 9200,
      maintainer_prose: "duplicate of #9200",
      event_id: "ev-dup-1",
    },
    now_ms: NOW + 1,
  });
  const proc = runCliJson(
    ["followup", "process_event", target, `--request=${eventPath}`],
    { env },
  );
  assert.equal(proc.exitCode, 0, proc.stdout);
  const d = proc.result!.disposition as Record<string, unknown>;
  assert.equal(d.auto_reopen, false);
  assert.equal(d.cross_post, false);
  assert.equal(d.auto_comment, false);
  assert.equal(proc.result!.network_used, false);
  assert.equal(proc.result!.external_write, false);
  // Migrated subscription present; original inactive or migrated marker.
  const st = runCliJson(
    ["followup", "status", target, `--now-ms=${NOW + 2}`],
    { env },
  );
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
  const env = followupEnv(stateDir);
  runCliJson(
    ["followup", "subscribe", target, "--issue=9300", `--now-ms=${NOW}`],
    { env },
  );
  const cli = runCliJson(
    ["followup", "status", target, `--now-ms=${NOW + 1}`],
    { env },
  );
  assert.equal(cli.exitCode, 0, cli.stdout);

  const client = new McpTestClient({
    serverEntry: mcpServerEntry(),
    env,
  });
  try {
    client.start();
    const mcp = (await client.callTool("changeguard_followup", {
      target,
      operation: "status",
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
  // Authority booleans removed from public request JSON (EXTRA_FIELD).
  // Evil official digest/ref alone still cannot supersede.
  const req = writeRequest({
    issue: 502,
    candidate_version: OFFICIAL_BOUND_VERSION,
    recipe_id: "evil-recipe",
    official_evidence_item_digest: "a".repeat(64),
    official_evidence_ref:
      "https://evil.example/openai/codex/releases/tag/x",
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

// ─── Wire-level hardening (Phase B correction) ─────────────────────────────

const REMOVED_WIRE_FIELDS = [
  "state_dir",
  "original_fault_absent",
  "core_regressions_passed",
  "verified",
  "snapshot_path",
  "witness",
  "live_measurement_witness",
] as const;

test("Ticket12 harness: tools/list changeguard_followup has no removed/authority fields", async () => {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    await client.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "t12-list", version: "0.1.0" },
    });
    const listed = (await client.request("tools/list", {})) as {
      tools: Array<{
        name: string;
        inputSchema?: { properties?: Record<string, unknown> };
      }>;
    };
    const tool = listed.tools.find((t) => t.name === "changeguard_followup");
    assert.ok(tool, "changeguard_followup must appear in tools/list");
    const props = tool.inputSchema?.properties ?? {};
    for (const k of REMOVED_WIRE_FIELDS) {
      assert.equal(
        Object.prototype.hasOwnProperty.call(props, k),
        false,
        `tools/list must not advertise ${k}`,
      );
    }
    assert.ok(props.target);
    assert.ok(props.operation);
  } finally {
    await client.close();
  }
});

test("Ticket12 harness: MCP removed fields fail EXTRA_ARGS and do not mutate ledger", async () => {
  const target = makeIsolatedTarget("cg-t12h-mcpx-");
  const stateDir = makeTempDir("cg-t12h-mcpxst-");
  const env = followupEnv(stateDir);
  runCliJson(
    ["followup", "subscribe", target, "--issue=9500", `--now-ms=${NOW}`],
    { env },
  );
  const ledgerPath = path.join(stateDir, "followup-ledger.json");
  assert.ok(fs.existsSync(ledgerPath));
  const before = fs.readFileSync(ledgerPath);

  const client = new McpTestClient({
    serverEntry: mcpServerEntry(),
    env,
  });
  try {
    client.start();
    for (const field of [
      "state_dir",
      "original_fault_absent",
      "core_regressions_passed",
      "verified",
      "snapshot_path",
      "witness",
    ] as const) {
      const args: Record<string, unknown> = {
        target,
        operation: "status",
        now_ms: NOW + 1,
      };
      if (field === "state_dir") args.state_dir = stateDir;
      else if (field === "snapshot_path") args.snapshot_path = "/tmp/x";
      else if (field === "witness") args.witness = { forged: true };
      else args[field] = true;
      const err = await client
        .callTool("changeguard_followup", args)
        .catch((e: Error) => e);
      assert.ok(err instanceof Error, `MCP must fail closed on ${field}`);
      assert.deepEqual(fs.readFileSync(ledgerPath), before, `ledger unchanged for ${field}`);
    }
  } finally {
    await client.close();
  }
});

test("Ticket12 harness: CLI removed flags fail usage and do not mutate ledger", () => {
  const target = makeIsolatedTarget("cg-t12h-clix-");
  const stateDir = makeTempDir("cg-t12h-clixst-");
  const env = followupEnv(stateDir);
  runCliJson(
    ["followup", "subscribe", target, "--issue=9501", `--now-ms=${NOW}`],
    { env },
  );
  const ledgerPath = path.join(stateDir, "followup-ledger.json");
  const before = fs.readFileSync(ledgerPath);

  for (const flag of [
    `--state-dir=${stateDir}`,
    "--original-fault-absent=true",
    "--core-regressions-passed=true",
    "--verified=true",
  ]) {
    const r = runCliJson(
      ["followup", "status", target, `--now-ms=${NOW + 1}`, flag],
      { env },
    );
    assert.notEqual(r.exitCode, 0, `CLI must refuse ${flag}`);
    assert.deepEqual(fs.readFileSync(ledgerPath), before, `ledger unchanged for ${flag}`);
  }
});

test("Ticket12 harness: CLI --event-json nested forbidden/size/depth/inapplicable match parser", () => {
  const target = makeIsolatedTarget("cg-t12h-ev-");
  const stateDir = makeTempDir("cg-t12h-evst-");
  const env = followupEnv(stateDir);
  runCliJson(
    ["followup", "subscribe", target, "--issue=9502", `--now-ms=${NOW}`],
    { env },
  );

  // Nested forbidden key inside event
  const nestedTok = runCliJson(
    [
      "followup",
      "process_event",
      target,
      `--event-json=${JSON.stringify({
        schema_version: 1,
        issue_number: 9502,
        disposition: "needs_info",
        event_id: "ev-tok",
        token: "secret",
      })}`,
      `--now-ms=${NOW + 1}`,
    ],
    { env },
  );
  assert.notEqual(nestedTok.exitCode, 0);
  assert.ok(
    nestedTok.result?.error_code === "FORBIDDEN_FIELD" ||
      nestedTok.result?.error_code === "USAGE",
  );

  // Operation-inapplicable field on status
  const inapp = runCliJson(
    [
      "followup",
      "status",
      target,
      "--issue=1",
      `--now-ms=${NOW + 2}`,
    ],
    { env },
  );
  assert.notEqual(inapp.exitCode, 0);
  assert.equal(inapp.result?.error_code, "EXTRA_FIELD");

  // Excessive serialized size via --event-json body
  const big = "x".repeat(70 * 1024);
  const oversized = runCliJson(
    [
      "followup",
      "process_event",
      target,
      `--event-json=${JSON.stringify({
        schema_version: 1,
        issue_number: 9502,
        disposition: "needs_info",
        event_id: "ev-big",
        maintainer_prose: big,
      })}`,
      `--now-ms=${NOW + 3}`,
    ],
    { env },
  );
  assert.notEqual(oversized.exitCode, 0);
  assert.ok(
    oversized.result?.error_code === "SIZE_LIMIT" ||
      oversized.exitCode === 2,
  );

  // Excessive nesting depth
  let deep: unknown = { token: "x" };
  for (let i = 0; i < 8; i++) deep = { nested: deep };
  const depth = runCliJson(
    [
      "followup",
      "process_event",
      target,
      `--event-json=${JSON.stringify({
        schema_version: 1,
        issue_number: 9502,
        disposition: "needs_info",
        event_id: "ev-deep",
        payload: deep,
      })}`,
      `--now-ms=${NOW + 4}`,
    ],
    { env },
  );
  assert.notEqual(depth.exitCode, 0);
  assert.ok(
    depth.result?.error_code === "DEPTH_LIMIT" ||
      depth.result?.error_code === "FORBIDDEN_FIELD",
  );
});

test("Ticket12 harness: CLI --request + inline field conflict is deterministic", () => {
  const target = makeIsolatedTarget("cg-t12h-conf-");
  const stateDir = makeTempDir("cg-t12h-confst-");
  const env = followupEnv(stateDir);
  const req = writeRequest({ issue: 9600 });
  const r = runCliJson(
    [
      "followup",
      "subscribe",
      target,
      `--request=${req}`,
      "--issue=9601",
      `--now-ms=${NOW}`,
    ],
    { env },
  );
  assert.notEqual(r.exitCode, 0);
  assert.equal(r.result?.error_code, "REQUEST_CONFLICT");
  // No ledger created under state dir
  assert.equal(fs.existsSync(path.join(stateDir, "followup-ledger.json")), false);
});

test("Ticket12 harness: no state-only bypass via dispatchFollowup or public type", () => {
  const target = makeIsolatedTarget("cg-t12h-nobypass-");
  // Public index must not re-export the internal state-only helper.
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      followupPublic,
      "sessionFollowupHintFromState",
    ),
    false,
    "sessionFollowupHintFromState must not be public",
  );
  // dispatchFollowup ignores any smuggled state_dir / stateOnly (not on type).
  const smuggled = {
    target,
    operation: "session_hint" as const,
    now_ms: NOW,
    state_dir: "/tmp/forged-followup-state",
    stateOnly: true,
  };
  const r = dispatchFollowup(
    smuggled as unknown as Parameters<typeof dispatchFollowup>[0],
  );
  assert.equal(typeof r.ok, "boolean");
  // session_hint without env state still succeeds/fails via trusted env only —
  // it never treats smuggled state_dir as authority (no path in session_hint).
  if (r.session_hint !== null) {
    assert.equal(r.session_hint.includes("/tmp"), false);
  }
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
