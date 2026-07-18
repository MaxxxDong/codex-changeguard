/**
 * Ticket 11 — Confirmed upstream actions Scenario Harness.
 * Controlled remote double only; production path injects no real adapter.
 * Covers success, each action preview, cancel, auth failure, invalid/expired/
 * replayed confirmation, timeout found/not-found/uncertain, duplicate existing,
 * attachment privacy, Ticket10 blocked capsule, CLI/MCP equivalence, and
 * no target mutation / leak / network in the default path.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  previewUpstream,
} from "../src/upstream/index.js";
import {
  _resetConsumedNoncesForTests,
  confirmUpstreamAction,
  createFakeRemoteAdapter,
  createUnavailableAdapter,
  gateCapsuleForActions,
  parseConfirmationToken,
  previewUpstreamAction,
  CONFIRMATION_TOKEN_PREFIX,
} from "../src/upstream/actions/index.js";
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

function assertNoSecrets(text: string): void {
  assert.doesNotMatch(text, /ghp_[A-Za-z0-9]+/);
  assert.doesNotMatch(text, /github_pat_/i);
  assert.doesNotMatch(text, /"cookie"\s*:/);
  assert.doesNotMatch(text, /"access_token"\s*:/);
  assert.doesNotMatch(text, /Bearer\s+[A-Za-z0-9._-]+/);
}

test("before each suite: reset nonces", () => {
  _resetConsumedNoncesForTests();
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

  // Cancel via MCP works as pure draft
  const preview2 = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: null,
    nowMs: NOW_FRESH,
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
  _resetConsumedNoncesForTests();
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t11-bind-"));
  const capsule = makeCapsule("request-new-incident-cli.json", target);
  const preview = previewUpstreamAction({
    targetPath: target,
    capsule,
    action: "create_issue",
    adapter: null,
    nowMs: NOW_FRESH,
    nonce: "ef".repeat(16),
  });
  const binding = parseConfirmationToken(
    preview.confirmation_token!,
    NOW_FRESH,
  );
  assert.equal(binding.capsule_content_sha256, capsule.capsule_content_sha256);
  assert.equal(binding.privacy.passed, true);
  assert.equal(binding.action, "create_issue");
  assert.ok(binding.binding_sha256);
  assert.ok(binding.idempotency_key.startsWith("idk_"));
});
