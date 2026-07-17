/**
 * Ticket 10 — Upstream Submission Capsule (preview-only) Scenario Harness.
 * Covers routing, forms, duplicates, doctor sanitization, snapshot freshness,
 * transport rules, adversarial input, CLI/MCP equivalence, no leaks/writes.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  ALLOWED_REQUEST_KEYS,
  FORBIDDEN_UPSTREAM_KEYS,
  MAX_UPSTREAM_REQUEST_BYTES,
  OFFICIAL_FORM_BLOB_SHAS,
  OFFICIAL_MAIN_COMMIT,
  assessDuplicate,
  bundledOfficialFormSnapshot,
  createFakeFormTransport,
  formTransportPermitted,
  instrumentUpstreamTransport,
  mapGitHubIssueForm,
  parseUpstreamRequest,
  previewUpstream,
  routeUpstream,
  sanitizeDoctorJson,
  validateOfficialFormSnapshot,
  viewFormSnapshot,
  UpstreamRequestError,
} from "../src/upstream/index.js";
import {
  copyFixtureToTemp,
  hashTargetTree,
  mcpServerEntry,
  runCliJson,
} from "../src/harness/scenario.js";
import { McpTestClient } from "../src/mcp/client.js";
import { makeTempDir, REPO_ROOT } from "./helpers.js";

const FIXTURE_DIR = path.join(REPO_ROOT, "fixtures/upstream");
const PROTECTED = "fixtures/protected-process";
// Snapshot verified for 2026-07-18 — use that as "now" so bundled is fresh.
const NOW_FRESH = Date.parse("2026-07-18T12:00:00.000Z");
const NOW_STALE = Date.parse("2026-08-01T00:00:00.000Z");

function loadRequest(name: string): unknown {
  return JSON.parse(
    fs.readFileSync(path.join(FIXTURE_DIR, name), "utf8"),
  ) as unknown;
}

function runCliUpstream(
  target: string,
  requestPath: string,
  extra: string[] = [],
): {
  exitCode: number;
  stdout: string;
  result: Record<string, unknown> | null;
} {
  return runCliJson([
    "upstream-preview",
    target,
    `--request=${requestPath}`,
    ...extra,
  ]);
}

async function runMcpUpstream(
  target: string,
  request: unknown,
  disclosure_decision?: string,
): Promise<Record<string, unknown>> {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    const args: Record<string, unknown> = { target, request };
    if (disclosure_decision) args.disclosure_decision = disclosure_decision;
    return await client.callTool("changeguard_upstream_preview", args);
  } finally {
    await client.close();
  }
}

function assertNoSubmission(result: {
  external_write: boolean;
  repair_authorized: boolean;
  submission_status: string;
  network_used: boolean;
  capsule: {
    external_write: boolean;
    mode: string;
    locality: string;
    requires_ticket11_confirmation?: boolean;
    status?: string;
  } | null;
}): void {
  assert.equal(result.external_write, false);
  assert.equal(result.repair_authorized, false);
  assert.equal(result.submission_status, "none");
  assert.equal(result.network_used, false);
  if (result.capsule) {
    assert.equal(result.capsule.external_write, false);
    assert.equal(result.capsule.mode, "preview_only");
    assert.equal(result.capsule.locality, "local_only");
    assert.equal(result.capsule.requires_ticket11_confirmation, true);
    assert.notEqual(result.capsule.status, "SUBMITTED");
    assert.notEqual(result.capsule.status, "POSTED");
  }
}

// --- Routing ---

test("routes: security → BUGCROWD never public issue draft", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-sec-"));
  const before = hashTargetTree(target);
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-security-bugcrowd.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.ok, true);
  assert.ok(result.capsule);
  assert.equal(result.capsule!.route, "BUGCROWD");
  assert.equal(result.capsule!.status, "ROUTED_PRIVATE");
  assert.equal(result.capsule!.github_issue_form, null);
  assert.equal(result.capsule!.duplicate.draft_body, null);
  assert.equal(result.capsule!.duplicate.draft_comment, null);
  assert.equal(result.capsule!.duplicate.recommendation, "private_report");
  assert.ok(result.capsule!.private_report_guidance);
  assert.match(
    result.capsule!.private_report_guidance!,
    /Bugcrowd/i,
  );
  assertNoSubmission(result);
  assert.equal(hashTargetTree(target), before);
});

test("routes: account/billing → OPENAI_SUPPORT", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-acct-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-account-support.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.route, "OPENAI_SUPPORT");
  assert.equal(result.capsule!.duplicate.recommendation, "contact_support");
  assert.equal(result.capsule!.duplicate.draft_body, null);
  assert.ok(result.capsule!.support_guidance);
  assertNoSubmission(result);
});

test("routes: product support → GITHUB_DISCUSSIONS", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-disc-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-support-discussions.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.route, "GITHUB_DISCUSSIONS");
  assert.equal(result.capsule!.duplicate.recommendation, "open_discussion");
  assert.ok(result.capsule!.discussion_guidance);
  assertNoSubmission(result);
});

test("routes: product bug → GITHUB_ISSUE", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-issue-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-new-incident-cli.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.route, "GITHUB_ISSUE");
  assert.equal(result.capsule!.status, "PREVIEW_READY");
  assert.equal(result.capsule!.duplicate.state, "NEW_INCIDENT");
  assert.ok(result.capsule!.duplicate.draft_body);
  assertNoSubmission(result);
});

// --- Form mapping ---

test("forms: APP / CLI / EXTENSION / OTHER mapping", () => {
  assert.deepEqual(mapGitHubIssueForm("app"), {
    form: "APP",
    filename: "1-codex-app.yml",
  });
  assert.deepEqual(mapGitHubIssueForm("desktop"), {
    form: "APP",
    filename: "1-codex-app.yml",
  });
  assert.deepEqual(mapGitHubIssueForm("cli"), {
    form: "CLI",
    filename: "3-cli.yml",
  });
  assert.deepEqual(mapGitHubIssueForm("extension"), {
    form: "EXTENSION",
    filename: "2-extension.yml",
  });
  assert.deepEqual(mapGitHubIssueForm("browser_control"), {
    form: "EXTENSION",
    filename: "2-extension.yml",
  });
  assert.deepEqual(mapGitHubIssueForm("other"), {
    form: "OTHER",
    filename: "4-bug-report.yml",
  });

  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-forms-"));
  for (const [file, form, filename] of [
    ["request-app-form.json", "APP", "1-codex-app.yml"],
    ["request-new-incident-cli.json", "CLI", "3-cli.yml"],
    ["request-extension-form.json", "EXTENSION", "2-extension.yml"],
    ["request-other-form.json", "OTHER", "4-bug-report.yml"],
  ] as const) {
    const r = previewUpstream({
      targetPath: target,
      request: loadRequest(file),
      nowMs: NOW_FRESH,
    });
    assert.equal(r.capsule!.github_issue_form, form, file);
    assert.equal(r.capsule!.form_filename, filename, file);
  }
});

// --- Duplicates ---

test("exact duplicate zero Evidence Delta: subscribe/upvote only, no body/comment", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-dup0-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-exact-dup-zero-delta.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.duplicate.state, "EXACT_DUPLICATE");
  assert.equal(result.capsule!.duplicate.evidence_delta_material, false);
  assert.equal(result.capsule!.duplicate.recommendation, "subscribe_or_upvote");
  assert.equal(result.capsule!.duplicate.draft_body, null);
  assert.equal(result.capsule!.duplicate.draft_comment, null);
  assert.equal(result.capsule!.draft_title, null);
  assert.equal(result.capsule!.duplicate.matched_issue_id, "openai/codex#9001");
  assert.equal(result.capsule!.maintainer_value_gate.passed, true);
  assertNoSubmission(result);
});

test("exact duplicate material Evidence Delta: structured comment preview", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-dupm-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-exact-dup-material-delta.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.duplicate.state, "EXACT_DUPLICATE");
  assert.equal(result.capsule!.duplicate.evidence_delta_material, true);
  assert.equal(result.capsule!.duplicate.recommendation, "comment_with_delta");
  assert.equal(result.capsule!.duplicate.draft_body, null);
  assert.ok(result.capsule!.duplicate.draft_comment);
  assert.match(result.capsule!.duplicate.draft_comment!, /Evidence Delta/i);
  assert.match(result.capsule!.duplicate.draft_comment!, /platform_version|Linux/i);
  assert.ok(result.capsule!.duplicate.evidence_delta_hash);
  assertNoSubmission(result);
});

test("related-not-same: separate body with cross-links", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-rel-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-related-not-same.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.duplicate.state, "RELATED_NOT_SAME");
  assert.equal(result.capsule!.duplicate.recommendation, "cross_link_related");
  assert.ok(result.capsule!.duplicate.draft_body);
  assert.ok(
    result.capsule!.duplicate.cross_link_issue_ids.includes("openai/codex#8800"),
  );
  // Separated labels preserved.
  assert.ok(result.capsule!.observed_facts.length > 0);
  assert.ok(result.capsule!.user_reports.length > 0);
  assert.ok(result.capsule!.hypotheses.length > 0);
});

test("new incident: open_new with body", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-new-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-new-incident-cli.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.duplicate.state, "NEW_INCIDENT");
  assert.equal(result.capsule!.duplicate.recommendation, "open_new");
  assert.ok(result.capsule!.duplicate.draft_body);
  assert.match(
    result.capsule!.duplicate.draft_body!,
    /Observed facts|Technical signals/i,
  );
  // Exact technical error preserved (no secret redaction needed).
  assert.ok(
    result.capsule!.error_strings.some((e) =>
      e.includes("protected global process binding"),
    ),
  );
});

// --- Maintainer gate + facts separation ---

test("maintainer-value gate requires all checklist fields", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-gate-"));
  const good = loadRequest("request-new-incident-cli.json") as Record<
    string,
    unknown
  >;
  const bad = {
    ...good,
    technical_signals: [],
    privacy_review: {
      secrets_redacted: false,
      paths_redacted: false,
      session_excluded: false,
    },
  };
  const result = previewUpstream({
    targetPath: target,
    request: bad,
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.status, "GATE_FAILED");
  assert.equal(result.capsule!.maintainer_value_gate.passed, false);
  assert.ok(
    result.capsule!.maintainer_value_gate.failed_ids.includes(
      "technical_signal",
    ),
  );
  assert.ok(
    result.capsule!.maintainer_value_gate.failed_ids.includes("privacy_review"),
  );
});

// --- Doctor ---

test("doctor sanitization: inclusion manifest, secret/path redaction", () => {
  const clean = sanitizeDoctorJson(
    JSON.parse(
      fs.readFileSync(path.join(FIXTURE_DIR, "doctor-clean.json"), "utf8"),
    ),
  );
  assert.equal(clean.included, true);
  assert.ok(clean.inclusion_manifest.includes("codex_version"));
  assert.ok(clean.sanitized_summary);

  const secrets = sanitizeDoctorJson(
    JSON.parse(
      fs.readFileSync(path.join(FIXTURE_DIR, "doctor-secrets.json"), "utf8"),
    ),
  );
  assert.equal(secrets.included, true);
  const summaryText = JSON.stringify(secrets.sanitized_summary);
  assert.doesNotMatch(summaryText, /sk-abcdefghijklmnopqrstuvwxyz/);
  assert.doesNotMatch(summaryText, /\/Users\/alice/);
  assert.ok(
    summaryText.includes("<redacted-secret>") ||
      summaryText.includes("<redacted-path>") ||
      secrets.secrets_redacted ||
      secrets.paths_redacted,
  );

  // Forbidden key fails closed.
  assert.throws(
    () => sanitizeDoctorJson({ schema_version: 1, access_token: "tok" }),
    (e: unknown) => e instanceof Error && /privacy|sensitive|FORBIDDEN/i.test(e.message),
  );
});

test("doctor is orchestrator-supplied only; never executes codex", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-doc-"));
  const req = loadRequest("request-new-incident-cli.json") as Record<
    string,
    unknown
  >;
  req.doctor_json = {
    schema_version: 1,
    codex_version: "0.50.0",
    os: "macos",
    arch: "arm64",
    status: "ok",
    summary: "from orchestrator",
  };
  const result = previewUpstream({
    targetPath: target,
    request: req,
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.doctor_inclusion.included, true);
  assert.ok(
    result.capsule!.doctor_inclusion.inclusion_manifest.length > 0,
  );
  assert.equal(result.network_used, false);
});

// --- Form snapshot ---

test("immutable form snapshot: commit, blob SHAs, integrity, CLI doctor field", () => {
  const snap = bundledOfficialFormSnapshot();
  assert.equal(snap.main_commit, OFFICIAL_MAIN_COMMIT);
  assert.equal(snap.cli_form_includes_doctor_json, true);
  assert.equal(
    snap.duplicate_guidance,
    "search_first_reaction_only_for_duplicates",
  );
  for (const [filename, sha] of Object.entries(OFFICIAL_FORM_BLOB_SHAS)) {
    const rec = snap.forms.find((f) => f.filename === filename);
    assert.ok(rec, filename);
    assert.equal(rec!.blob_sha, sha);
  }
  // Integrity fail-closed.
  assert.throws(() =>
    validateOfficialFormSnapshot({
      ...snap,
      integrity_sha256: "0".repeat(64),
    }),
  );
  // Fresh vs stale.
  const fresh = viewFormSnapshot(snap, NOW_FRESH, "bundled_immutable");
  assert.equal(fresh.freshness, "fresh");
  assert.equal(fresh.stale_reason, null);
  const stale = viewFormSnapshot(snap, NOW_STALE, "bundled_immutable");
  assert.equal(stale.freshness, "stale");
  assert.ok(stale.stale_reason);
});

test("stale snapshot visible when now is beyond freshness window", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-stale-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-new-incident-cli.json"),
    nowMs: NOW_STALE,
  });
  assert.equal(result.capsule!.form_snapshot.freshness, "stale");
  assert.ok(result.capsule!.form_snapshot.stale_reason);
  assert.equal(
    result.capsule!.form_snapshot.main_commit,
    OFFICIAL_MAIN_COMMIT,
  );
});

// --- Transport ---

test("approved fake form transport refreshes; refused/zero transport does not", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-tr-"));
  const snap = bundledOfficialFormSnapshot();
  const fake = instrumentUpstreamTransport(createFakeFormTransport(snap));

  const approved = previewUpstream({
    targetPath: target,
    request: loadRequest("request-new-incident-cli.json"),
    disclosure_decision: "approved",
    transport: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(approved.transport_calls, 1);
  assert.equal(fake.callCount, 1);
  assert.equal(
    approved.capsule!.form_snapshot.source,
    "transport_refresh",
  );
  assert.deepEqual(fake.calls[0]!.allowed_repositories, ["openai/codex"]);
  assert.ok(
    fake.calls[0]!.allowed_hosts.includes("github.com"),
  );

  const refused = previewUpstream({
    targetPath: target,
    request: loadRequest("request-new-incident-cli.json"),
    disclosure_decision: "refused",
    transport: fake,
    nowMs: NOW_FRESH,
  });
  assert.equal(refused.transport_calls, 0);
  assert.equal(fake.callCount, 1); // unchanged

  const zero = previewUpstream({
    targetPath: target,
    request: loadRequest("request-new-incident-cli.json"),
    disclosure_decision: "approved",
    transport: null,
    nowMs: NOW_FRESH,
  });
  assert.equal(zero.transport_calls, 0);
  assert.equal(zero.capsule!.form_snapshot.source, "bundled_immutable");
  assert.equal(formTransportPermitted("approved", false), false);
  assert.equal(formTransportPermitted("approved", true), true);
  assert.equal(formTransportPermitted("refused", true), false);
});

// --- Adversarial ---

test("prompt injection quarantined; no public draft upgrade", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-inj-"));
  const result = previewUpstream({
    targetPath: target,
    request: loadRequest("request-prompt-injection.json"),
    nowMs: NOW_FRESH,
  });
  assert.equal(result.capsule!.privacy_review.injection_quarantined, true);
  assert.ok(result.capsule!.privacy_review.quarantine?.quarantined);
  assert.equal(result.capsule!.status, "PREVIEW_BLOCKED");
  assert.equal(result.external_write, false);
  assert.equal(result.repair_authorized, false);
});

test("malformed / oversized / extra fields fail closed", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-adv-"));

  const malformed = previewUpstream({
    targetPath: target,
    request: "{not-json",
  });
  assert.equal(malformed.ok, false);
  assert.ok(
    malformed.error_code === "MALFORMED_JSON" ||
      malformed.error_code === "REQUEST_ERROR",
  );

  const extra = previewUpstream({
    targetPath: target,
    request: {
      ...(loadRequest("request-new-incident-cli.json") as object),
      evil_extra: true,
    },
  });
  assert.equal(extra.ok, false);
  assert.equal(extra.error_code, "EXTRA_FIELD");

  const withToken = previewUpstream({
    targetPath: target,
    request: {
      ...(loadRequest("request-new-incident-cli.json") as object),
      access_token: "secret",
    },
  });
  assert.equal(withToken.ok, false);
  assert.equal(withToken.error_code, "FORBIDDEN_PRIVACY_FIELD");

  // Oversized request.
  const big = {
    ...(loadRequest("request-new-incident-cli.json") as object),
    actual_behavior: "x".repeat(MAX_UPSTREAM_REQUEST_BYTES),
  };
  const over = previewUpstream({ targetPath: target, request: big });
  assert.equal(over.ok, false);
  assert.ok(
    over.error_code === "SIZE_LIMIT" || over.error_code === "STRING_LIMIT",
  );

  assert.ok(ALLOWED_REQUEST_KEYS.includes("case_kind"));
  assert.ok(FORBIDDEN_UPSTREAM_KEYS.includes("cookie"));
});

test("full-width secret shapes are redacted in free text", () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-fw-"));
  const req = loadRequest("request-new-incident-cli.json") as Record<
    string,
    unknown
  >;
  // Full-width colon form — NFKC should normalize then redact.
  req.actual_behavior =
    "failure with api_key：sk-abcdefghijklmnopqrstuvwxyz path /Users/max/secret";
  const result = previewUpstream({
    targetPath: target,
    request: req,
    nowMs: NOW_FRESH,
  });
  assert.equal(result.ok, true);
  const blob = JSON.stringify(result.capsule);
  assert.doesNotMatch(blob, /sk-abcdefghijklmnopqrstuvwxyz/);
  assert.doesNotMatch(blob, /\/Users\/max\/secret/);
});

// --- CLI / MCP equivalence ---

test("CLI/MCP upstream-preview stable-field equivalence; target unchanged", async () => {
  const target = copyFixtureToTemp(PROTECTED, makeTempDir("cg-t10-eq-"));
  const before = hashTargetTree(target);
  const requestPath = path.join(FIXTURE_DIR, "request-new-incident-cli.json");
  const request = loadRequest("request-new-incident-cli.json");

  const cli = runCliUpstream(target, requestPath, ["--disclose-refused"]);
  assert.equal(cli.exitCode, 0, cli.stdout);
  assert.ok(cli.result);

  const mcp = await runMcpUpstream(target, request, "refused");

  const pick = (r: Record<string, unknown>) => {
    const c = r.capsule as Record<string, unknown>;
    return {
      ok: r.ok,
      route: c.route,
      form: c.github_issue_form,
      dup: (c.duplicate as Record<string, unknown>).state,
      status: c.status,
      external_write: c.external_write,
      mode: c.mode,
      transport_calls: r.transport_calls,
      submission_status: r.submission_status,
    };
  };
  assert.deepEqual(pick(cli.result!), pick(mcp));
  assert.equal(hashTargetTree(target), before, "target must not mutate");
});

test("production boundary: no SUBMITTED/POSTED; package schema exists", () => {
  const schemaPath = path.join(
    REPO_ROOT,
    "schemas/upstream-submission-capsule.schema.json",
  );
  assert.ok(fs.existsSync(schemaPath));
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8")) as {
    properties: { mode: { const: string }; external_write: { const: boolean } };
  };
  assert.equal(schema.properties.mode.const, "preview_only");
  assert.equal(schema.properties.external_write.const, false);

  // Contract helpers.
  const r = routeUpstream("validated_security_vulnerability");
  assert.equal(r.route, "BUGCROWD");
  assert.equal(r.public_issue_draft_forbidden, true);

  assert.throws(
    () => parseUpstreamRequest({ schema_version: 2, case_kind: "codex_product_bug" }),
    (e: unknown) => e instanceof UpstreamRequestError,
  );
});

test("assessDuplicate unit: zero material forces null bodies", () => {
  const { request } = parseUpstreamRequest(
    loadRequest("request-exact-dup-zero-delta.json"),
  );
  const d = assessDuplicate(request, "GITHUB_ISSUE");
  assert.equal(d.state, "EXACT_DUPLICATE");
  assert.equal(d.draft_body, null);
  assert.equal(d.draft_comment, null);
  assert.equal(d.recommendation, "subscribe_or_upvote");
});
