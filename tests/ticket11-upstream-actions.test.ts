/**
 * Ticket 11 — Confirmed upstream actions Scenario Harness.
 * Controlled remote double only; production path injects no real adapter.
 * Covers success, each action preview, cancel, auth failure, invalid/expired/
 * replayed confirmation, timeout found/not-found/uncertain, duplicate existing,
 * attachment privacy, Ticket10 blocked capsule, CLI/MCP equivalence,
 * durable confirmation ledger / HMAC, cross-process replay, and
 * no target mutation / leak / network in the default path.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  previewUpstream,
} from "../src/upstream/index.js";
import {
  _resetConsumedNoncesForTests,
  claimConfirmationForExecute,
  confirmUpstreamAction,
  computeBindingSha256,
  computeConfirmationMac,
  CONFIRMATION_LEDGER_CAPACITY,
  CONFIRMATION_LEDGER_KEY_FILE,
  CONFIRMATION_LEDGER_LOCK_NAME,
  CONFIRMATION_LEDGER_LOCK_STALE_MS,
  CONFIRMATION_LEDGER_STATE_FILE,
  CONFIRMATION_TOKEN_PREFIX,
  createFakeRemoteAdapter,
  createUnavailableAdapter,
  gateCapsuleForActions,
  instrumentActionAdapter,
  mintConfirmation,
  openConfirmationLedger,
  parseConfirmationToken,
  previewUpstreamAction,
} from "../src/upstream/actions/index.js";
import { sha256Canonical } from "../src/evidence/canonical.js";
import type { UpstreamSubmissionCapsule as Capsule } from "../src/upstream/types.js";
import {
  copyFixtureToTemp,
  hashTargetTree,
  mcpServerEntry,
  runCliJson,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import { makeTempDir, REPO_ROOT } from "./helpers.js";

const FIXTURE_DIR = path.join(REPO_ROOT, "fixtures/upstream");
const ACTIONS_FIX = path.join(FIXTURE_DIR, "actions");
const PROTECTED = "fixtures/protected-process";
const NOW_FRESH = Date.parse("2026-07-18T12:00:00.000Z");
const NOW_ISO = "2026-07-18T12:00:00.000Z";

/** Shared durable ledger root for in-process + CLI child inheritance. */
const LEDGER_ROOT = makeTempDir("cg-t11-ledger-");
process.env.CHANGEGUARD_CONFIRMATION_STATE_DIR = LEDGER_ROOT;

function loadRequest(name: string): unknown {
  return JSON.parse(
    fs.readFileSync(path.join(FIXTURE_DIR, name), "utf8"),
  ) as unknown;
}

function makeCapsule(
  requestName: string,
  target: string,
): Capsule {
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest(requestName),
    nowMs: NOW_FRESH,
  });
  assert.ok(result.capsule, `expected capsule for ${requestName}`);
  return result.capsule!;
}

function writeJson(dir: string, name: string, value: unknown): string {
  const p = path.join(dir, name);
  fs.writeFileSync(p, JSON.stringify(value, null, 2), "utf8");
  return p;
}

/** Test-only: install a live exclusive lock under the ledger root. */
function forceLiveLockForTests(
  root: string,
  owner: string = crypto.randomBytes(16).toString("hex"),
  nowMs: number = Date.now(),
): string {
  const lockDir = path.join(root, CONFIRMATION_LEDGER_LOCK_NAME);
  try {
    if (fs.existsSync(lockDir)) {
      try {
        fs.unlinkSync(path.join(lockDir, "owner.json"));
      } catch {
        /* best-effort */
      }
      // Free the name via rename (production lock release pattern).
      fs.renameSync(
        lockDir,
        path.join(
          root,
          `.${CONFIRMATION_LEDGER_LOCK_NAME}.testfree.${Date.now()}`,
        ),
      );
    }
  } catch {
    /* best-effort */
  }
  fs.mkdirSync(lockDir, { recursive: false, mode: 0o700 });
  fs.writeFileSync(
    path.join(lockDir, "owner.json"),
    `${JSON.stringify({ owner, pid: process.pid, created_at_ms: nowMs })}\n`,
    { flag: "wx", mode: 0o600 },
  );
  return owner;
}

/** Test-only: install a stale lock (old created_at_ms) for reclaim tests. */
function forceStaleLockForTests(
  root: string,
  ageMs: number = CONFIRMATION_LEDGER_LOCK_STALE_MS + 5_000,
  nowMs: number = Date.now(),
): string {
  const owner = crypto.randomBytes(16).toString("hex");
  const lockDir = path.join(root, CONFIRMATION_LEDGER_LOCK_NAME);
  try {
    if (fs.existsSync(lockDir)) {
      try {
        fs.unlinkSync(path.join(lockDir, "owner.json"));
      } catch {
        /* best-effort */
      }
      fs.renameSync(
        lockDir,
        path.join(
          root,
          `.${CONFIRMATION_LEDGER_LOCK_NAME}.testfree.${Date.now()}`,
        ),
      );
    }
  } catch {
    /* best-effort */
  }
  fs.mkdirSync(lockDir, { recursive: false, mode: 0o700 });
  const created = nowMs - ageMs;
  fs.writeFileSync(
    path.join(lockDir, "owner.json"),
    `${JSON.stringify({ owner, pid: 1, created_at_ms: created })}\n`,
    { flag: "wx", mode: 0o600 },
  );
  return owner;
}

function assertNoSecrets(text: string): void {
  assert.doesNotMatch(text, /ghp_[A-Za-z0-9]+/);
  assert.doesNotMatch(text, /github_pat_/i);
  assert.doesNotMatch(text, /"cookie"\s*:/);
  assert.doesNotMatch(text, /"access_token"\s*:/);
  assert.doesNotMatch(text, /Bearer\s+[A-Za-z0-9._-]+/);
}

test("before each suite: reset durable confirmation ledger", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
});

// --- Capsule gate ---

test("gate: PREVIEW_READY open_new capsule allows create_issue", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-gate-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const gate = gateCapsuleForActions(capsule);
  assert.equal(gate.passed, true);
  assert.ok(gate.allowed_actions.includes("create_issue"));
});

test("gate: blocked/injection capsule cannot become actions", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-block-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-prompt-injection.json"),
    nowMs: NOW_FRESH,
  });
  assert.ok(result.capsule);
  assert.equal(result.capsule!.status, "PREVIEW_BLOCKED");
  const gate = gateCapsuleForActions(result.capsule);
  assert.equal(gate.passed, false);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule: result.capsule,
    action: "create_issue",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
  });
  assert.equal(preview.ok, false);
  assert.equal(preview.status, "BLOCKED_CAPSULE");
  assert.equal(preview.external_write, false);
  assert.equal(preview.confirmation_token, null);
});

test("gate: content hash tamper refused", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tamper-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const tampered = {
    ...capsule,
    capsule_content_sha256:
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  };
  const gate = gateCapsuleForActions(tampered);
  assert.equal(gate.passed, false);
  assert.ok(gate.failed_ids.includes("content_hash_mismatch"));
});

// --- Action previews (each kind) ---

test("preview: create_issue from NEW_INCIDENT capsule", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-ci-"));
  const before = hashTargetTree(target);
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({
    mode: "success",
    nowIso: NOW_ISO,
  });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "a".repeat(32),
  });
  assert.equal(preview.ok, true);
  assert.equal(preview.status, "PREVIEW_READY");
  assert.equal(preview.action, "create_issue");
  assert.ok(preview.confirmation_token?.startsWith(CONFIRMATION_TOKEN_PREFIX));
  assert.ok(preview.body_manifest?.body);
  assert.equal(preview.external_write, false);
  assert.equal(preview.network_used, false);
  assert.equal(preview.target_mutated, false);
  assert.equal(hashTargetTree(target), before);
  assertNoSecrets(JSON.stringify(preview));
});

test("preview: comment_with_delta from material delta exact dup", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-cmd-"));
  const capsule = makeCapsule("request-exact-dup-material-delta.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "comment_with_delta",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "b".repeat(32),
  });
  assert.equal(preview.ok, true);
  assert.equal(preview.action, "comment_with_delta");
  assert.ok(preview.body_manifest?.body);
  assert.match(preview.canonical_target ?? "", /9001/);
});

test("preview: react_upvote + subscribe from zero-delta exact dup", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-react-"));
  const capsule = makeCapsule("request-exact-dup-zero-delta.json", target);
  const react = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "react_upvote",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "c".repeat(32),
  });
  assert.equal(react.ok, true);
  assert.equal(react.body_manifest?.reaction, "+1");
  const sub = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "subscribe",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "d".repeat(32),
  });
  assert.equal(sub.ok, true);
  assert.equal(sub.action, "subscribe");
});

test("preview: attachment_upload with clean privacy manifest", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-att-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(ACTIONS_FIX, "attachment-manifest-clean.json"),
      "utf8",
    ),
  );
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "attachment_upload",
    attachment_manifest: manifest,
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "e".repeat(32),
  });
  assert.equal(preview.ok, true);
  assert.equal(preview.action, "attachment_upload");
  assert.ok(preview.attachment_manifest);
});

test("preview: attachment privacy failure refused", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-attp-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(ACTIONS_FIX, "attachment-manifest-privacy-fail.json"),
      "utf8",
    ),
  );
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "attachment_upload",
    attachment_manifest: manifest,
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
  });
  assert.equal(preview.ok, false);
  assert.equal(preview.status, "PRIVACY_FAILED");
  assert.equal(preview.external_write, false);
});

test("preview: wrong action for recommendation refused", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-wrong-"));
  const capsule = makeCapsule("request-exact-dup-zero-delta.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
  });
  assert.equal(preview.ok, false);
  assert.equal(preview.status, "UNSUPPORTED_ACTION");
});

// --- Confirm paths ---

test("confirm: success emits minimal Upstream Contribution Receipt", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-ok-"));
  const before = hashTargetTree(target);
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "f".repeat(32),
  });
  assert.equal(preview.ok, true);
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(confirm.ok, true);
  assert.equal(confirm.status, "EXECUTED");
  assert.equal(confirm.external_write, true);
  assert.ok(confirm.receipt);
  assert.equal(confirm.receipt!.kind, "upstream_contribution_action");
  assert.equal(confirm.receipt!.action, "create_issue");
  assert.ok(confirm.receipt!.canonical_url.startsWith("https://"));
  assert.ok(confirm.receipt!.receipt_hash);
  assert.ok(confirm.receipt!.idempotency_key.startsWith("idk_"));
  // Minimal receipt: no body / secrets / repair status
  const r = confirm.receipt as unknown as Record<string, unknown>;
  assert.equal("body" in r, false);
  assert.equal("local_repair_status" in r, false);
  assert.equal(hashTargetTree(target), before);
  assertNoSecrets(JSON.stringify(confirm));
});

test("confirm: cancellation remains pure draft", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-cancel-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "1".repeat(32),
  });
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "cancel",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(confirm.ok, true);
  assert.equal(confirm.status, "CANCELLED");
  assert.equal(confirm.external_write, false);
  assert.equal(confirm.receipt, null);
  assert.equal(confirm.network_used, false);
  // Cancelled nonce cannot be confirmed later
  const again = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(again.status, "REPLAYED_CONFIRMATION");
  assert.equal(again.external_write, false);
});

test("confirm: auth unavailable never simulates success", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-auth-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({
    mode: "auth_unavailable",
    nowIso: NOW_ISO,
  });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "2".repeat(32),
  });
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(confirm.ok, false);
  assert.ok(
    confirm.status === "AUTH_UNAVAILABLE" ||
      confirm.status === "ADAPTER_UNAVAILABLE",
  );
  assert.equal(confirm.external_write, false);
  assert.equal(confirm.receipt, null);
});

test("confirm: default unavailable adapter (production path)", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-unavail-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: null,
    nowMs: NOW_FRESH,
    nonce: "3".repeat(32),
  });
  assert.equal(preview.ok, true);
  assert.equal(preview.auth_capability.kind, "unavailable");
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: null,
    nowMs: NOW_FRESH,
  });
  assert.equal(confirm.ok, false);
  assert.equal(confirm.status, "ADAPTER_UNAVAILABLE");
  assert.equal(confirm.external_write, false);
  assert.equal(createUnavailableAdapter().getAuthCapability().authenticated, false);
});

test("confirm: expired confirmation refused", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-exp-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "4".repeat(32),
  });
  const later = NOW_FRESH + 16 * 60 * 1000;
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: later,
  });
  assert.equal(confirm.status, "EXPIRED_CONFIRMATION");
  assert.equal(confirm.external_write, false);
});

test("confirm: invalid confirmation (tampered binding) refused", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-inv-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "5".repeat(32),
  });
  // Corrupt token payload
  const bad = preview.confirmation_token!.slice(0, -4) + "XXXX";
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: bad,
    decision: "confirm",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
  });
  assert.equal(confirm.ok, false);
  assert.equal(confirm.external_write, false);
  assert.notEqual(confirm.status, "EXECUTED");
  assert.ok(
    ["INVALID_CONFIRMATION", "EXPIRED_CONFIRMATION", "REPLAYED_CONFIRMATION"].includes(
      confirm.status,
    ) ||
      confirm.error_code === "MALFORMED_CONFIRMATION" ||
      confirm.error_code === "INVALID_CONFIRMATION",
  );
});

test("confirm: replayed confirmation refused", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-replay-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "6".repeat(32),
  });
  const first = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(first.status, "EXECUTED");
  const second = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(second.status, "REPLAYED_CONFIRMATION");
  assert.equal(second.external_write, false);
});

test("confirm: duplicate existing returns receipt without re-executing twice", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-dup-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const p1 = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "7".repeat(32),
  });
  const c1 = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: p1.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(c1.status, "EXECUTED");
  // New confirmation same diagnosis/action content → same idempotency → duplicate
  const p2 = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "8".repeat(32),
  });
  assert.equal(p2.idempotency_key, p1.idempotency_key);
  const c2 = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: p2.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(c2.status, "DUPLICATE_EXISTING");
  assert.ok(c2.receipt);
  assert.equal(c2.receipt!.idempotency_key, p1.idempotency_key);
});

test("confirm: timeout found returns existing receipt (no blind retry)", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tf-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({
    mode: "timeout_found",
    nowIso: NOW_ISO,
  });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "9".repeat(32),
  });
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(confirm.status, "DUPLICATE_EXISTING");
  assert.ok(confirm.receipt);
  assert.equal(confirm.external_write, true);
});

test("confirm: timeout not_found → UNCERTAIN_NO_RETRY", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tnf-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({
    mode: "timeout_not_found",
    nowIso: NOW_ISO,
  });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "0".repeat(32),
  });
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(confirm.status, "UNCERTAIN_NO_RETRY");
  assert.equal(confirm.external_write, false);
  assert.equal(confirm.receipt, null);
});

test("confirm: timeout uncertain → UNCERTAIN_NO_RETRY", () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tu-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({
    mode: "timeout_uncertain",
    nowIso: NOW_ISO,
  });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "ab".repeat(16),
  });
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(confirm.status, "UNCERTAIN_NO_RETRY");
  assert.equal(confirm.external_write, false);
});

// --- CLI / MCP equivalence + production boundary ---

test("CLI/MCP: action preview equivalence and no network by default", async () => {
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-eq-"));
  const before = hashTargetTree(target);
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const tmp = makeTempDir("cg-t11-eqfiles-");
  const capsulePath = writeJson(tmp, "capsule.json", capsule);

  const cli = runCliJson([
    "upstream-action-preview",
    target,
    `--capsule=${capsulePath}`,
    "--action=create_issue",
  ]);
  assert.equal(cli.exitCode, 0);
  assert.ok(cli.result);
  assert.equal(cli.result!.ok, true);
  assert.equal(cli.result!.status, "PREVIEW_READY");
  assert.equal(cli.result!.external_write, false);
  assert.equal(cli.result!.network_used, false);
  assert.equal(
    (cli.result!.auth_capability as { kind: string }).kind,
    "unavailable",
  );

  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    const mcp = await client.callTool("changeguard_upstream_action_preview", {
      target,
      capsule,
      action: "create_issue",
    });
    assert.equal(mcp.ok, true);
    assert.equal(mcp.status, "PREVIEW_READY");
    assert.equal(mcp.external_write, false);
    assert.equal(mcp.network_used, false);
    assert.equal(
      (mcp.auth_capability as { kind: string }).kind,
      "unavailable",
    );
    // Same capsule binding material (idempotency depends on incident + content)
    assert.equal(mcp.action, cli.result!.action);
    assert.equal(mcp.canonical_target, cli.result!.canonical_target);
  } finally {
    await client.close();
  }

  // Confirm via CLI with production adapter → ADAPTER_UNAVAILABLE
  const token = cli.result!.confirmation_token as string;
  const conf = runCliJson([
    "upstream-action-confirm",
    target,
    `--confirmation=${token}`,
    "--decision=confirm",
  ]);
  assert.notEqual(conf.exitCode, 0);
  assert.equal(conf.result!.status, "ADAPTER_UNAVAILABLE");
  assert.equal(conf.result!.external_write, false);

  // Cancel via MCP works as pure draft.
  // MCP confirm has no now_ms and validates TTL with process wall clock; mint
  // this token with Date.now() so it is not already EXPIRED_CONFIRMATION vs fixed NOW_FRESH.
  const preview2 = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: null,
    nowMs: Date.now(),
    nonce: "cd".repeat(16),
  });
  const client2 = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    const cancel = await client2.callTool(
      "changeguard_upstream_action_confirm",
      {
        target,
        confirmation_token: preview2.confirmation_token!,
        decision: "cancel",
      },
    );
    assert.equal(cancel.status, "CANCELLED");
    assert.equal(cancel.external_write, false);
  } finally {
    await client2.close();
  }

  assert.equal(hashTargetTree(target), before);
  assertNoSecrets(cli.stdout);
});

test("binding: confirmation binds capsule hash + privacy + nonce", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-bind-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: null,
    nowMs: NOW_FRESH,
    nonce: "ef".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  const binding = parseConfirmationToken(
    preview.confirmation_token!,
    NOW_FRESH,
    { ledgerRoot: LEDGER_ROOT },
  );
  assert.equal(binding.capsule_content_sha256, capsule.capsule_content_sha256);
  assert.equal(binding.privacy.passed, true);
  assert.equal(binding.action, "create_issue");
  assert.ok(binding.binding_sha256);
  assert.ok(binding.mac);
  assert.ok(binding.idempotency_key.startsWith("idk_"));
});

// --- P1: durable ledger, HMAC, terminal uncertain, revalidation ---

test("confirm: timeout not_found marks terminal; second call never re-executes", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tnf2-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({
    mode: "timeout_not_found",
    nowIso: NOW_ISO,
  });
  const instrumented = instrumentActionAdapter(fake);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    nonce: "aa".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  const first = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(first.status, "UNCERTAIN_NO_RETRY");
  assert.equal(instrumented.executeCalls, 1);
  const second = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(second.status, "REPLAYED_CONFIRMATION");
  assert.equal(second.external_write, false);
  assert.equal(instrumented.executeCalls, 1);
});

test("confirm: timeout uncertain marks terminal; executeCalls stays 1 across calls", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tu2-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({
    mode: "timeout_uncertain",
    nowIso: NOW_ISO,
  });
  const instrumented = instrumentActionAdapter(fake);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    nonce: "bb".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  const first = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(first.status, "UNCERTAIN_NO_RETRY");
  assert.equal(instrumented.executeCalls, 1);
  const second = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(second.status, "REPLAYED_CONFIRMATION");
  assert.equal(instrumented.executeCalls, 1);
});

test("confirm: timeout query throw marks terminal_uncertain; no second execute", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tq-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const base = createFakeRemoteAdapter({
    mode: "timeout_not_found",
    nowIso: NOW_ISO,
  });
  let executeCalls = 0;
  const adapter = {
    getAuthCapability: () => base.getAuthCapability(),
    execute: (req: Parameters<typeof base.execute>[0]) => {
      executeCalls += 1;
      return base.execute(req);
    },
    queryByIdempotencyKey: () => {
      throw new Error("query boom");
    },
  };
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter,
    nowMs: NOW_FRESH,
    nonce: "cc".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  const first = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(first.status, "UNCERTAIN_NO_RETRY");
  assert.equal(executeCalls, 1);
  const second = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(second.status, "REPLAYED_CONFIRMATION");
  assert.equal(executeCalls, 1);
});

test("ledger: cross-process CLI preview+cancel shares durable ledger", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-xpc-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const tmp = makeTempDir("cg-t11-xpcfiles-");
  const capsulePath = writeJson(tmp, "capsule.json", capsule);
  const env = {
    ...process.env,
    NO_COLOR: "1",
    CHANGEGUARD_CONFIRMATION_STATE_DIR: LEDGER_ROOT,
  };
  const preview = runCliJson(
    [
      "upstream-action-preview",
      target,
      `--capsule=${capsulePath}`,
      "--action=create_issue",
    ],
    { env },
  );
  assert.equal(preview.exitCode, 0);
  assert.equal(preview.result!.status, "PREVIEW_READY");
  const token = preview.result!.confirmation_token as string;
  const cancel = runCliJson(
    [
      "upstream-action-confirm",
      target,
      `--confirmation=${token}`,
      "--decision=cancel",
    ],
    { env },
  );
  assert.equal(cancel.exitCode, 0);
  assert.equal(cancel.result!.status, "CANCELLED");
  const replay = runCliJson(
    [
      "upstream-action-confirm",
      target,
      `--confirmation=${token}`,
      "--decision=confirm",
    ],
    { env },
  );
  assert.notEqual(replay.exitCode, 0);
  assert.equal(replay.result!.status, "REPLAYED_CONFIRMATION");
  assert.equal(replay.result!.external_write, false);
});

test("ledger: offline forged token without preview registration is refused", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-forge-"));
  // Craft a binding-looking payload with only public digests (no install HMAC key).
  const partial = {
    schema_version: 1 as const,
    confirmation_id: "uac_" + "a".repeat(24),
    action: "create_issue" as const,
    canonical_target: "https://github.com/openai/codex/issues",
    body_manifest: {
      title: "x",
      body: "y",
      reaction: null,
      content_sha256: "b".repeat(64),
    },
    attachment_manifest: null,
    incident_fingerprint_digest: "c".repeat(64),
    evidence_delta_hash: null,
    capsule_content_sha256: "d".repeat(64),
    capsule_id: "forge-capsule",
    privacy: {
      passed: true,
      secrets_redacted: true,
      paths_redacted: true,
      session_excluded: true,
      injection_quarantined: false,
    },
    nonce: "dd".repeat(16),
    expires_at: new Date(NOW_FRESH + 60_000).toISOString(),
    idempotency_key: "idk_" + "e".repeat(64),
  };
  const binding_sha256 = computeBindingSha256(partial);
  const forged = {
    ...partial,
    binding_sha256,
    mac: "f".repeat(64),
  };
  const token =
    CONFIRMATION_TOKEN_PREFIX +
    Buffer.from(JSON.stringify(forged), "utf8").toString("base64url");
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: token,
    decision: "confirm",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(confirm.ok, false);
  assert.notEqual(confirm.status, "EXECUTED");
  assert.equal(confirm.external_write, false);
  assert.ok(
    confirm.status === "INVALID_CONFIRMATION" ||
      confirm.error_code === "UNREGISTERED_CONFIRMATION" ||
      confirm.error_code === "INVALID_CONFIRMATION" ||
      confirm.error_code === "MALFORMED_CONFIRMATION",
  );
});

test("confirm: non-official canonical_target refused at confirm revalidation", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-nonoff-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const ledger = openConfirmationLedger(LEDGER_ROOT);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: null,
    nowMs: NOW_FRESH,
    nonce: "ee".repeat(16),
    ledger,
  });
  assert.equal(preview.ok, true);
  const raw = JSON.parse(
    Buffer.from(
      preview.confirmation_token!.slice(CONFIRMATION_TOKEN_PREFIX.length),
      "base64url",
    ).toString("utf8"),
  ) as Record<string, unknown>;
  // Build a new binding with non-official target + fresh nonce so we can register it.
  const nonce = "11".repeat(16);
  const partial = {
    schema_version: 1 as const,
    confirmation_id: "uac_" + "1".repeat(24),
    action: "create_issue" as const,
    canonical_target: "https://evil.example/openai/codex/issues",
    body_manifest: raw.body_manifest as {
      title: string | null;
      body: string | null;
      reaction: string | null;
      content_sha256: string;
    },
    attachment_manifest: null,
    incident_fingerprint_digest: raw.incident_fingerprint_digest as string,
    evidence_delta_hash: raw.evidence_delta_hash as string | null,
    capsule_content_sha256: raw.capsule_content_sha256 as string,
    capsule_id: raw.capsule_id as string,
    privacy: raw.privacy as {
      passed: true;
      secrets_redacted: true;
      paths_redacted: true;
      session_excluded: true;
      injection_quarantined: false;
    },
    nonce,
    expires_at: raw.expires_at as string,
    idempotency_key: raw.idempotency_key as string,
  };
  const binding_sha256 = computeBindingSha256(partial);
  const key = ledger.loadOrCreateHmacKey();
  const mac = computeConfirmationMac(key, { ...partial, binding_sha256 });
  ledger.register(
    {
      nonce,
      confirmation_id: partial.confirmation_id,
      binding_sha256,
      expires_at: partial.expires_at,
      registered_at_ms: NOW_FRESH,
      action: partial.action,
      canonical_target: partial.canonical_target,
      idempotency_key: partial.idempotency_key,
    },
    NOW_FRESH,
  );
  const token =
    CONFIRMATION_TOKEN_PREFIX +
    Buffer.from(
      JSON.stringify({ ...partial, binding_sha256, mac }),
      "utf8",
    ).toString("base64url");
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: token,
    decision: "confirm",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    ledger,
  });
  assert.equal(confirm.ok, false);
  assert.equal(confirm.external_write, false);
  assert.notEqual(confirm.status, "EXECUTED");
  assert.equal(confirm.status, "INVALID_CONFIRMATION");
});

test("confirm: tampered body content_sha256 refused", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tbody-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const ledger = openConfirmationLedger(LEDGER_ROOT);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "22".repeat(16),
    ledger,
  });
  assert.equal(preview.ok, true);
  const raw = JSON.parse(
    Buffer.from(
      preview.confirmation_token!.slice(CONFIRMATION_TOKEN_PREFIX.length),
      "base64url",
    ).toString("utf8"),
  ) as Record<string, unknown>;
  const body = {
    ...(raw.body_manifest as Record<string, unknown>),
    body: "TAMPERED BODY TEXT",
    // Leave stale content_sha256 so revalidation fails.
  };
  const partial = {
    schema_version: 1 as const,
    confirmation_id: raw.confirmation_id as string,
    action: "create_issue" as const,
    canonical_target: raw.canonical_target as string,
    body_manifest: body as {
      title: string | null;
      body: string | null;
      reaction: string | null;
      content_sha256: string;
    },
    attachment_manifest: null,
    incident_fingerprint_digest: raw.incident_fingerprint_digest as string,
    evidence_delta_hash: raw.evidence_delta_hash as string | null,
    capsule_content_sha256: raw.capsule_content_sha256 as string,
    capsule_id: raw.capsule_id as string,
    privacy: raw.privacy as {
      passed: true;
      secrets_redacted: true;
      paths_redacted: true;
      session_excluded: true;
      injection_quarantined: false;
    },
    nonce: raw.nonce as string,
    expires_at: raw.expires_at as string,
    idempotency_key: raw.idempotency_key as string,
  };
  const binding_sha256 = computeBindingSha256(partial);
  const key = ledger.loadOrCreateHmacKey();
  const mac = computeConfirmationMac(key, { ...partial, binding_sha256 });
  // Update ledger binding hash so HMAC+registration pass; body digest must still fail.
  const docPath = path.join(LEDGER_ROOT, CONFIRMATION_LEDGER_STATE_FILE);
  const doc = JSON.parse(fs.readFileSync(docPath, "utf8")) as {
    entries: Array<Record<string, unknown>>;
  };
  const ent = doc.entries.find((e) => e.nonce === partial.nonce);
  assert.ok(ent);
  ent!.binding_sha256 = binding_sha256;
  fs.writeFileSync(docPath, JSON.stringify(doc, null, 2) + "\n", "utf8");
  const token =
    CONFIRMATION_TOKEN_PREFIX +
    Buffer.from(
      JSON.stringify({ ...partial, binding_sha256, mac }),
      "utf8",
    ).toString("base64url");
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: token,
    decision: "confirm",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    ledger,
  });
  assert.equal(confirm.ok, false);
  assert.equal(confirm.external_write, false);
  assert.notEqual(confirm.status, "EXECUTED");
});

test("confirm: tampered attachment manifest refused", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-tatt-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const ledger = openConfirmationLedger(LEDGER_ROOT);
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(ACTIONS_FIX, "attachment-manifest-clean.json"),
      "utf8",
    ),
  );
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "attachment_upload",
    attachment_manifest: manifest,
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "33".repeat(16),
    ledger,
  });
  assert.equal(preview.ok, true);
  const raw = JSON.parse(
    Buffer.from(
      preview.confirmation_token!.slice(CONFIRMATION_TOKEN_PREFIX.length),
      "base64url",
    ).toString("utf8"),
  ) as Record<string, unknown>;
  const att = raw.attachment_manifest as {
    schema_version: 1;
    entries: Array<Record<string, unknown>>;
    manifest_sha256: string;
  };
  // Tamper entry name while leaving manifest_sha256 stale.
  att.entries = att.entries.map((e) => ({ ...e, name: "tampered.txt" }));
  const partial = {
    schema_version: 1 as const,
    confirmation_id: raw.confirmation_id as string,
    action: "attachment_upload" as const,
    canonical_target: raw.canonical_target as string,
    body_manifest: raw.body_manifest as {
      title: string | null;
      body: string | null;
      reaction: string | null;
      content_sha256: string;
    },
    attachment_manifest: att as never,
    incident_fingerprint_digest: raw.incident_fingerprint_digest as string,
    evidence_delta_hash: raw.evidence_delta_hash as string | null,
    capsule_content_sha256: raw.capsule_content_sha256 as string,
    capsule_id: raw.capsule_id as string,
    privacy: raw.privacy as {
      passed: true;
      secrets_redacted: true;
      paths_redacted: true;
      session_excluded: true;
      injection_quarantined: false;
    },
    nonce: raw.nonce as string,
    expires_at: raw.expires_at as string,
    idempotency_key: raw.idempotency_key as string,
  };
  const binding_sha256 = computeBindingSha256(partial);
  const key = ledger.loadOrCreateHmacKey();
  const mac = computeConfirmationMac(key, { ...partial, binding_sha256 });
  const docPath = path.join(LEDGER_ROOT, CONFIRMATION_LEDGER_STATE_FILE);
  const doc = JSON.parse(fs.readFileSync(docPath, "utf8")) as {
    entries: Array<Record<string, unknown>>;
  };
  const ent = doc.entries.find((e) => e.nonce === partial.nonce);
  assert.ok(ent);
  ent!.binding_sha256 = binding_sha256;
  fs.writeFileSync(docPath, JSON.stringify(doc, null, 2) + "\n", "utf8");
  const token =
    CONFIRMATION_TOKEN_PREFIX +
    Buffer.from(
      JSON.stringify({ ...partial, binding_sha256, mac }),
      "utf8",
    ).toString("base64url");
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: token,
    decision: "confirm",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    ledger,
  });
  assert.equal(confirm.ok, false);
  assert.equal(confirm.external_write, false);
  assert.notEqual(confirm.status, "EXECUTED");
});

test("ledger: symlink key file refused", () => {
  const root = makeTempDir("cg-t11-sym-");
  fs.mkdirSync(root, { recursive: true });
  const outside = path.join(makeTempDir("cg-t11-sym-out-"), "key");
  fs.writeFileSync(outside, "ab".repeat(32), "utf8");
  fs.symlinkSync(outside, path.join(root, CONFIRMATION_LEDGER_KEY_FILE));
  const ledger = openConfirmationLedger(root);
  assert.throws(() => ledger.loadOrCreateHmacKey(), /Symlink|refused/i);
});

test("ledger: oversize state file refused", () => {
  const root = makeTempDir("cg-t11-over-");
  fs.mkdirSync(root, { recursive: true });
  // Create a huge ledger file (> CONFIRMATION_LEDGER_MAX_BYTES is 512KiB).
  const huge = path.join(root, CONFIRMATION_LEDGER_STATE_FILE);
  fs.writeFileSync(huge, "x".repeat(600 * 1024), "utf8");
  const ledger = openConfirmationLedger(root);
  assert.throws(() => ledger.getEntry("aa".repeat(16), NOW_FRESH), /size|refused|SIZE/i);
});

test("ledger: TTL expiry drops registered nonce (parse EXPIRED or unregistered)", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-ttl-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: null,
    nowMs: NOW_FRESH,
    nonce: "44".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(preview.ok, true);
  const later = NOW_FRESH + 16 * 60 * 1000;
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: later,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(confirm.status, "EXPIRED_CONFIRMATION");
  assert.equal(confirm.external_write, false);
});

test("ledger: capacity bound refuses excess registered nonces", () => {
  const root = makeTempDir("cg-t11-cap-");
  const ledger = openConfirmationLedger(root);
  const expires_at = new Date(NOW_FRESH + 60_000).toISOString();
  for (let i = 0; i < CONFIRMATION_LEDGER_CAPACITY; i++) {
    const nonce = i.toString(16).padStart(32, "0");
    ledger.register(
      {
        nonce,
        confirmation_id: `uac_${i.toString(16).padStart(24, "0")}`,
        binding_sha256: "a".repeat(64),
        expires_at,
        registered_at_ms: NOW_FRESH + i,
        action: "create_issue",
        canonical_target: "https://github.com/openai/codex/issues",
        idempotency_key: `idk_${i.toString(16).padStart(64, "0")}`,
      },
      NOW_FRESH + i,
    );
  }
  assert.throws(
    () =>
      ledger.register(
        {
          nonce: "f".repeat(32),
          confirmation_id: "uac_" + "f".repeat(24),
          binding_sha256: "b".repeat(64),
          expires_at,
          registered_at_ms: NOW_FRESH + 9999,
          action: "create_issue",
          canonical_target: "https://github.com/openai/codex/issues",
          idempotency_key: "idk_" + "b".repeat(64),
        },
        NOW_FRESH + 9999,
      ),
    /capacity/i,
  );
});

test("mint without ledger context is not a public write bypass", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  assert.throws(
    () =>
      mintConfirmation({
        action: "create_issue",
        canonical_target: "https://github.com/openai/codex/issues",
        body_manifest: {
          title: "t",
          body: "b",
          reaction: null,
          content_sha256: sha256Canonical({
            title: "t",
            body: "b",
            reaction: null,
            action: "create_issue",
          }),
        },
        attachment_manifest: null,
        incident_fingerprint_digest: "a".repeat(64),
        evidence_delta_hash: null,
        capsule_content_sha256: "b".repeat(64),
        capsule_id: "x",
        privacy: {
          passed: true,
          secrets_redacted: true,
          paths_redacted: true,
          session_excluded: true,
          injection_quarantined: false,
        },
        idempotency_key: "idk_" + "c".repeat(64),
        ledger: null as never,
      }),
    /ledger/i,
  );
});

test("hmac key never appears in token, receipt, or confirm result", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-keyhide-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const ledger = openConfirmationLedger(LEDGER_ROOT);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: fake,
    nowMs: NOW_FRESH,
    nonce: "55".repeat(16),
    ledger,
  });
  const keyHex = ledger.loadOrCreateHmacKey().toString("hex");
  assert.equal(preview.confirmation_token!.includes(keyHex), false);
  assert.equal(JSON.stringify(preview).includes(keyHex), false);
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: fake,
    nowMs: NOW_FRESH,
    ledger,
  });
  assert.equal(confirm.status, "EXECUTED");
  assert.equal(JSON.stringify(confirm).includes(keyHex), false);
  assert.equal(JSON.stringify(confirm.receipt).includes(keyHex), false);
});

// --- P1 r3: exclusive in_flight claim, crash-safety, lock reclaim ---

test("claim: concurrent Promise confirm executeCalls strictly 1", async () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-conc-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const instrumented = instrumentActionAdapter(fake);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    nonce: "66".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  const token = preview.confirmation_token!;
  const results = await Promise.all([
    Promise.resolve().then(() =>
      confirmUpstreamAction({
        targetPath: target,
        confirmation_token: token,
        decision: "confirm",
        adapter: instrumented,
        nowMs: NOW_FRESH,
        ledgerRoot: LEDGER_ROOT,
      }),
    ),
    Promise.resolve().then(() =>
      confirmUpstreamAction({
        targetPath: target,
        confirmation_token: token,
        decision: "confirm",
        adapter: instrumented,
        nowMs: NOW_FRESH,
        ledgerRoot: LEDGER_ROOT,
      }),
    ),
  ]);
  const executed = results.filter((r) => r.status === "EXECUTED");
  const blocked = results.filter(
    (r) =>
      r.status === "REPLAYED_CONFIRMATION" ||
      r.status === "IN_FLIGHT_NO_RETRY",
  );
  assert.equal(executed.length, 1);
  assert.equal(blocked.length, 1);
  assert.equal(instrumented.executeCalls, 1);
  assert.equal(executed[0]!.external_write, true);
  assert.equal(blocked[0]!.external_write, false);
});

test("claim: dual-process concurrent confirm only one EXECUTED", async () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-dual-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO }),
    nowMs: NOW_FRESH,
    nonce: "77".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  const token = preview.confirmation_token!;
  const outDir = makeTempDir("cg-t11-dual-out-");
  const outA = path.join(outDir, "a.json");
  const outB = path.join(outDir, "b.json");
  const actionsEntry = path.join(
    REPO_ROOT,
    "dist",
    "upstream",
    "actions",
    "index.js",
  );
  assert.ok(
    fs.existsSync(actionsEntry),
    "dist actions entry must exist (npm test builds first)",
  );

  function spawnConfirm(outPath: string) {
    const script = `
import { confirmUpstreamAction, createFakeRemoteAdapter } from ${JSON.stringify(actionsEntry)};
import fs from "node:fs";
const r = confirmUpstreamAction({
  targetPath: ${JSON.stringify(target)},
  confirmation_token: ${JSON.stringify(token)},
  decision: "confirm",
  adapter: createFakeRemoteAdapter({ mode: "success", nowIso: ${JSON.stringify(NOW_ISO)} }),
  nowMs: ${NOW_FRESH},
  ledgerRoot: ${JSON.stringify(LEDGER_ROOT)},
});
fs.writeFileSync(${JSON.stringify(outPath)}, JSON.stringify({
  status: r.status,
  external_write: r.external_write,
  ok: r.ok,
}));
`;
    return spawn(process.execPath, ["--input-type=module", "-e", script], {
      env: {
        ...process.env,
        NO_COLOR: "1",
        CHANGEGUARD_CONFIRMATION_STATE_DIR: LEDGER_ROOT,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
  }

  const childA = spawnConfirm(outA);
  const childB = spawnConfirm(outB);
  const [codeA, codeB] = await Promise.all([
    new Promise<number>((resolve) => {
      childA.on("close", (c) => resolve(c ?? 1));
    }),
    new Promise<number>((resolve) => {
      childB.on("close", (c) => resolve(c ?? 1));
    }),
  ]);
  assert.equal(codeA, 0, "child A exit");
  assert.equal(codeB, 0, "child B exit");
  const ra = JSON.parse(fs.readFileSync(outA, "utf8")) as {
    status: string;
    external_write: boolean;
  };
  const rb = JSON.parse(fs.readFileSync(outB, "utf8")) as {
    status: string;
    external_write: boolean;
  };
  const statuses = [ra.status, rb.status].sort();
  const executed = [ra, rb].filter((r) => r.status === "EXECUTED");
  const blocked = [ra, rb].filter(
    (r) =>
      r.status === "REPLAYED_CONFIRMATION" ||
      r.status === "IN_FLIGHT_NO_RETRY",
  );
  assert.equal(
    executed.length,
    1,
    `expected one EXECUTED, got ${statuses.join(",")}`,
  );
  assert.equal(blocked.length, 1);
  assert.equal(executed[0]!.external_write, true);
  assert.equal(blocked[0]!.external_write, false);
});

test("claim: execute throw → UNCERTAIN_NO_RETRY; second confirm never executes", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-throw-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  let executeCalls = 0;
  const adapter = {
    getAuthCapability: () => ({
      kind: "gh_authenticated" as const,
      detail: "test",
      authenticated: true,
    }),
    execute: () => {
      executeCalls += 1;
      throw new Error("adapter boom after claim");
    },
    queryByIdempotencyKey: () => ({
      outcome: "uncertain" as const,
      receipt: null,
      error_code: null,
      error_message: null,
    }),
  };
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter,
    nowMs: NOW_FRESH,
    nonce: "88".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  const first = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(first.status, "UNCERTAIN_NO_RETRY");
  assert.equal(first.external_write, false);
  assert.equal(executeCalls, 1);
  const entry = openConfirmationLedger(LEDGER_ROOT).getEntry(
    "88".repeat(16),
    NOW_FRESH,
  );
  assert.ok(entry);
  assert.ok(
    entry!.status === "terminal_uncertain" || entry!.status === "in_flight",
  );
  const second = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.ok(
    second.status === "REPLAYED_CONFIRMATION" ||
      second.status === "IN_FLIGHT_NO_RETRY",
  );
  assert.equal(second.external_write, false);
  assert.equal(executeCalls, 1);
});

test("claim: crash after claim (in_flight) second confirm never executes", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-crash-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const instrumented = instrumentActionAdapter(fake);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    nonce: "99".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  // Simulate process crash after exclusive claim, before/during execute.
  const claim = claimConfirmationForExecute(
    "99".repeat(16),
    LEDGER_ROOT,
    NOW_FRESH,
  );
  assert.equal(claim.ok, true);
  const mid = openConfirmationLedger(LEDGER_ROOT).getEntry(
    "99".repeat(16),
    NOW_FRESH,
  );
  assert.equal(mid!.status, "in_flight");
  const again = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.ok(
    again.status === "IN_FLIGHT_NO_RETRY" ||
      again.status === "REPLAYED_CONFIRMATION",
  );
  assert.equal(again.external_write, false);
  assert.equal(instrumented.executeCalls, 0);
});

test("claim: incomplete success receipt stays terminal; no second execute", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-incomp-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  let executeCalls = 0;
  const adapter = {
    getAuthCapability: () => ({
      kind: "gh_authenticated" as const,
      detail: "test",
      authenticated: true,
    }),
    execute: () => {
      executeCalls += 1;
      return {
        outcome: "success" as const,
        canonical_url: null,
        remote_receipt_id: null,
        timestamp: null,
        existing_idempotency_key: null,
        error_code: null,
        error_message: null,
      };
    },
    queryByIdempotencyKey: () => ({
      outcome: "uncertain" as const,
      receipt: null,
      error_code: null,
      error_message: null,
    }),
  };
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter,
    nowMs: NOW_FRESH,
    nonce: "ab".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  const first = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(first.status, "UNCERTAIN_NO_RETRY");
  assert.equal(executeCalls, 1);
  const second = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.ok(
    second.status === "REPLAYED_CONFIRMATION" ||
      second.status === "IN_FLIGHT_NO_RETRY",
  );
  assert.equal(executeCalls, 1);
});

test("claim: markConsumed failure leaves in_flight; still no second execute", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-markfail-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const instrumented = instrumentActionAdapter(fake);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    nonce: "cd".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  // Claim + simulate mark path by forcing in_flight after a "successful" remote
  // without consume (crash between remote write and markConsumed).
  const claim = claimConfirmationForExecute(
    "cd".repeat(16),
    LEDGER_ROOT,
    NOW_FRESH,
  );
  assert.equal(claim.ok, true);
  // Leave as in_flight (markConsumed never ran). Replay must not execute.
  const again = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.ok(
    again.status === "IN_FLIGHT_NO_RETRY" ||
      again.status === "REPLAYED_CONFIRMATION",
  );
  assert.equal(instrumented.executeCalls, 0);
  const ent = openConfirmationLedger(LEDGER_ROOT).getEntry(
    "cd".repeat(16),
    NOW_FRESH,
  );
  assert.equal(ent!.status, "in_flight");
});

test("lock: stale lock is reclaimed safely; claim proceeds", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  forceStaleLockForTests(
    LEDGER_ROOT,
    CONFIRMATION_LEDGER_LOCK_STALE_MS + 10_000,
    Date.now(),
  );
  const lockPath = path.join(LEDGER_ROOT, CONFIRMATION_LEDGER_LOCK_NAME);
  assert.ok(fs.existsSync(lockPath));
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-stale-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const instrumented = instrumentActionAdapter(fake);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    nonce: "ef".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  // preview's register reclaims stale lock; confirm must also succeed.
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.equal(confirm.status, "EXECUTED");
  assert.equal(instrumented.executeCalls, 1);
});

test("lock: live lock is refused fail-closed (no execute)", () => {
  _resetConsumedNoncesForTests(LEDGER_ROOT);
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-livelock-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const fake = createFakeRemoteAdapter({ mode: "success", nowIso: NOW_ISO });
  const instrumented = instrumentActionAdapter(fake);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    nonce: "10".repeat(16),
    ledgerRoot: LEDGER_ROOT,
  });
  // Install a live lock held by a fake owner; claim must fail closed.
  forceLiveLockForTests(LEDGER_ROOT, "aa".repeat(16), Date.now());
  const confirm = confirmUpstreamAction({
    targetPath: target,
    confirmation_token: preview.confirmation_token!,
    decision: "confirm",
    adapter: instrumented,
    nowMs: NOW_FRESH,
    ledgerRoot: LEDGER_ROOT,
  });
  assert.ok(
    confirm.status === "IN_FLIGHT_NO_RETRY" ||
      confirm.status === "INVALID_CONFIRMATION" ||
      confirm.status === "REPLAYED_CONFIRMATION",
  );
  assert.equal(confirm.external_write, false);
  assert.equal(instrumented.executeCalls, 0);
  // Cleanup live lock so later tests are not blocked.
  try {
    const lockDir = path.join(LEDGER_ROOT, CONFIRMATION_LEDGER_LOCK_NAME);
    try {
      fs.unlinkSync(path.join(lockDir, "owner.json"));
    } catch {
      /* best-effort */
    }
    fs.renameSync(
      lockDir,
      path.join(
        LEDGER_ROOT,
        `.${CONFIRMATION_LEDGER_LOCK_NAME}.testfree.${Date.now()}`,
      ),
    );
  } catch {
    /* best-effort */
  }
});

test("ledger: in_flight is recognized; prune never demotes to registered", () => {
  const root = makeTempDir("cg-t11-inflight-schema-");
  const ledger = openConfirmationLedger(root);
  const expires_at = new Date(NOW_FRESH + 60_000).toISOString();
  const nonce = "12".repeat(16);
  ledger.register(
    {
      nonce,
      confirmation_id: "uac_" + "2".repeat(24),
      binding_sha256: "a".repeat(64),
      expires_at,
      registered_at_ms: NOW_FRESH,
      action: "create_issue",
      canonical_target: "https://github.com/openai/codex/issues",
      idempotency_key: "idk_" + "a".repeat(64),
    },
    NOW_FRESH,
  );
  const claim = ledger.claimForExecute(nonce, { nowMs: NOW_FRESH });
  assert.equal(claim.ok, true);
  const mid = ledger.getEntry(nonce, NOW_FRESH);
  assert.equal(mid!.status, "in_flight");
  // Capacity pressure with many consumed entries must not rewrite in_flight → registered.
  for (let i = 0; i < CONFIRMATION_LEDGER_CAPACITY; i++) {
    const n = (i + 1).toString(16).padStart(32, "0");
    try {
      ledger.register(
        {
          nonce: n,
          confirmation_id: `uac_${i.toString(16).padStart(24, "0")}`,
          binding_sha256: "b".repeat(64),
          expires_at,
          registered_at_ms: NOW_FRESH + i + 1,
          action: "create_issue",
          canonical_target: "https://github.com/openai/codex/issues",
          idempotency_key: `idk_${i.toString(16).padStart(64, "0")}`,
        },
        NOW_FRESH + i + 1,
      );
      ledger.markConsumed(n, NOW_FRESH + i + 1);
    } catch {
      /* capacity may refuse further registered — acceptable */
    }
  }
  const still = ledger.getEntry(nonce, NOW_FRESH);
  assert.ok(still, "unexpired in_flight must survive capacity pressure");
  assert.equal(still!.status, "in_flight");
  assert.notEqual(still!.status, "registered");
});
