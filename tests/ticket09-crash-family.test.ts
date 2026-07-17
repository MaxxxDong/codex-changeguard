/**
 * Ticket 09 — Windows Desktop Browser crash-family classifier.
 * Scenario Harness (CLI/MCP public seams) + focused adversarial classifiers.
 * TDD surface for Fixture E families and negative controls.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  classifyCrashFamily,
  CRASH_FAMILY_CATALOG,
  diagnose,
  normalizeExceptionCode,
  normalizeModuleName,
  normalizeOffsetBucket,
} from "../src/core/index.js";
import { parseIncidentJson } from "../src/core/fingerprint.js";
import { MAX_INCIDENT_BYTES } from "../src/core/limits.js";
import {
  copyFixtureToTemp,
  hashTargetTree,
  runCliDiagnose,
  runCliRepairPreview,
  runMcpDiagnose,
} from "../src/harness/scenario.js";
import { baseIncident, makeTempDir, writeJson, REPO_ROOT } from "./helpers.js";

const CRASH_ROOT = "fixtures/crash-family";

const FAMILY_FIXTURES = {
  access: `${CRASH_ROOT}/access-violation-crbrowser`,
  interaction: `${CRASH_ROOT}/interaction-cpp-exception`,
  gpu: `${CRASH_ROOT}/gpu-child-relaunch`,
  concurrency: `${CRASH_ROOT}/concurrency-webview`,
  macos: `${CRASH_ROOT}/macos-negative`,
  titleOnly: `${CRASH_ROOT}/title-similarity-only`,
  ambiguous: `${CRASH_ROOT}/ambiguous-evidence`,
  noIsolation: `${CRASH_ROOT}/no-isolation-stop`,
} as const;

const ALLOWED_CRASH_USER = new Set([
  "INCONCLUSIVE",
  "DIAGNOSIS_COMPLETE",
  "INSUFFICIENT_LOCAL_FACTS",
  "UPSTREAM_BLOCKED",
]);

type Diag = NonNullable<ReturnType<typeof runCliDiagnose>["result"]> & {
  crash_classification?: {
    ranked_candidates: Array<{
      issue_id: string;
      family_id: string;
      rank: number;
      score: number;
      hard_gated: boolean;
    }>;
    rejected_candidates: Array<{
      issue_id: string;
      hard_gated: boolean;
      gate_reasons: string[];
    }>;
    local_mechanism: { status: string };
    upstream_match: { status: string };
    fix_applicability: { status: string };
    repair_authorization_eligible: boolean;
    next_evidence_requirements: string[];
    refused_actions: string[];
    family_id: string | null;
  } | null;
};

function assertReadOnlyBoundary(result: Diag): void {
  assert.equal(result.network_used, false);
  assert.equal(result.target_mutated, false);
  assert.equal(result.repair_applied, false);
  assert.notEqual(result.diagnosis_state, "RESOLVED_VERIFIED");
  assert.notEqual(result.diagnosis_state, "SAFE_FIX_AVAILABLE");
  assert.notEqual(result.diagnosis_state, "LOCAL_REPRO_CONFIRMED");
  assert.notEqual(result.diagnosis_state, "FIX_COMMIT_LINKED");
  assert.ok(ALLOWED_CRASH_USER.has(result.user_resolution.status));
  if (result.crash_classification) {
    assert.equal(result.crash_classification.repair_authorization_eligible, false);
    assert.equal(
      result.crash_classification.fix_applicability.status,
      "blocked",
    );
  }
}

function assertNoLeakText(text: string): void {
  assert.equal(/\/Users\//.test(text), false, "absolute Users path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(/\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text), false);
  assert.equal(
    /\b(?:api[_-]?key|password|secret)\s*[:=]\s*\S+/i.test(text),
    false,
  );
}

function topIds(result: Diag): string[] {
  return result.upstream_contribution.issue_candidates;
}

function assertTop3Contains(result: Diag, issueId: string): void {
  const ids = topIds(result);
  assert.ok(ids.length <= 3, `Top list longer than 3: ${ids.join(",")}`);
  assert.ok(
    ids.includes(issueId),
    `expected ${issueId} in Top 3, got [${ids.join(", ")}] state=${result.diagnosis_state}`,
  );
  assert.ok(
    result.diagnosis_state === "ISSUE_CANDIDATE" ||
      result.diagnosis_state === "HIGH_CONFIDENCE_MATCH",
    `unexpected state ${result.diagnosis_state}`,
  );
  assert.equal(result.user_resolution.status, "UPSTREAM_BLOCKED");
}

function fixtureTemp(fixtureRel: string): string {
  return copyFixtureToTemp(fixtureRel, makeTempDir("cg-t09-"));
}

function assertCliMcpCrashEquiv(
  cli: Diag,
  mcp: Awaited<ReturnType<typeof runMcpDiagnose>> & Diag,
): void {
  assert.equal(cli.ok, mcp.ok);
  assert.equal(cli.diagnosis_state, mcp.diagnosis_state);
  assert.equal(cli.user_resolution.status, mcp.user_resolution.status);
  assert.equal(cli.user_resolution.summary, mcp.user_resolution.summary);
  assert.equal(cli.upstream_contribution.status, mcp.upstream_contribution.status);
  assert.deepEqual(
    cli.upstream_contribution.issue_candidates,
    mcp.upstream_contribution.issue_candidates,
  );
  assert.deepEqual(cli.incident_fingerprint, mcp.incident_fingerprint);
  assert.equal(
    cli.crash_classification?.family_id ?? null,
    mcp.crash_classification?.family_id ?? null,
  );
  assert.deepEqual(
    cli.crash_classification?.ranked_candidates.map((c) => c.issue_id) ?? [],
    mcp.crash_classification?.ranked_candidates.map((c) => c.issue_id) ?? [],
  );
  assert.notEqual(cli.user_resolution.receipt_id, cli.upstream_contribution.receipt_id);
  assert.notEqual(mcp.user_resolution.receipt_id, mcp.upstream_contribution.receipt_id);
}

// --- Positive families: correct Issue in Top 3, distinct candidates ---

test("0xC0000005 / CrBrowserMain / chrome.dll+offset ranks openai/codex#32683 Top 3", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.access);
  const before = hashTargetTree(tmp);
  const { exitCode, result, stdout } = runCliDiagnose(tmp);
  assert.equal(exitCode, 0);
  assert.ok(result);
  const r = result as Diag;
  assertReadOnlyBoundary(r);
  assertNoLeakText(stdout);
  assertTop3Contains(r, "openai/codex#32683");
  assert.equal(r.crash_classification?.family_id, "access_violation_crbrowser_dom_ready");
  // Other families must not outrank the canonical one.
  assert.equal(topIds(r)[0], "openai/codex#32683");
  // T09-TOP3-MECHANISM-BLEED: GPU / complex-page families must not survive on
  // shared neutral_dom_ready / in_app_browser soft signals alone.
  assert.ok(
    !topIds(r).includes("openai/codex#32094"),
    `Top 3 must exclude GPU family #32094 without GPU codes; got [${topIds(r).join(", ")}]`,
  );
  assert.ok(
    !topIds(r).includes("openai/codex#33762"),
    `Top 3 must exclude complex-page #33762 without concrete page capability; got [${topIds(r).join(", ")}]`,
  );
  assert.equal(hashTargetTree(tmp), before);
});

test("0xc06d007f interaction family ranks openai/codex#33710 Top 3", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.interaction);
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  const r = result as Diag;
  assertReadOnlyBoundary(r);
  assertTop3Contains(r, "openai/codex#33710");
  assert.equal(topIds(r)[0], "openai/codex#33710");
  assert.notEqual(topIds(r)[0], "openai/codex#32683");
});

test("GPU 101457950 -> 18 media family ranks openai/codex#32094 Top 3", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.gpu);
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  const r = result as Diag;
  assertReadOnlyBoundary(r);
  assertTop3Contains(r, "openai/codex#32094");
  assert.equal(topIds(r)[0], "openai/codex#32094");
});

test("concurrency / WebView attach family ranks openai/codex#33202 Top 3", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.concurrency);
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  const r = result as Diag;
  assertReadOnlyBoundary(r);
  assertTop3Contains(r, "openai/codex#33202");
  assert.equal(topIds(r)[0], "openai/codex#33202");
});

test("distinct crash families rank different primary candidates", () => {
  const primaries = [
    FAMILY_FIXTURES.access,
    FAMILY_FIXTURES.interaction,
    FAMILY_FIXTURES.gpu,
    FAMILY_FIXTURES.concurrency,
  ].map((fx) => {
    const { result } = runCliDiagnose(fixtureTemp(fx));
    assert.ok(result);
    return topIds(result as Diag)[0];
  });
  assert.deepEqual(primaries, [
    "openai/codex#32683",
    "openai/codex#33710",
    "openai/codex#32094",
    "openai/codex#33202",
  ]);
  assert.equal(new Set(primaries).size, 4);
});

// --- Negative controls ---

test("macOS / different-module negative control hard-gates Windows families", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.macos);
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  const r = result as Diag;
  assertReadOnlyBoundary(r);
  assert.equal(r.diagnosis_state, "INCONCLUSIVE");
  assert.equal(r.user_resolution.status, "INCONCLUSIVE");
  assert.deepEqual(topIds(r), []);
  const rejected = r.crash_classification?.rejected_candidates ?? [];
  assert.ok(rejected.length > 0);
  for (const c of rejected) {
    if (c.issue_id.startsWith("openai/codex#")) {
      assert.equal(c.hard_gated, true, `${c.issue_id} should be hard-gated on macOS`);
      assert.ok(
        c.gate_reasons.some((g) => g.startsWith("platform_incompatible")),
        `${c.issue_id} missing platform gate`,
      );
    }
  }
});

test("title / generic click-open Browser crash similarity cannot create high confidence", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.titleOnly);
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  const r = result as Diag;
  assertReadOnlyBoundary(r);
  assert.equal(r.diagnosis_state, "INCONCLUSIVE");
  assert.notEqual(r.diagnosis_state, "HIGH_CONFIDENCE_MATCH");
  assert.deepEqual(topIds(r), []);
  assert.ok(
    r.user_resolution.summary.toLowerCase().includes("title") ||
      r.user_resolution.summary.toLowerCase().includes("insufficient") ||
      r.user_resolution.summary.toLowerCase().includes("symptom"),
  );
});

test("ambiguous evidence returns INCONCLUSIVE with next evidence requirements", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.ambiguous);
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  const r = result as Diag;
  assertReadOnlyBoundary(r);
  assert.equal(r.diagnosis_state, "INCONCLUSIVE");
  assert.equal(r.user_resolution.status, "INCONCLUSIVE");
  assert.ok(
    (r.crash_classification?.next_evidence_requirements.length ?? 0) > 0,
  );
});

test("no-isolation + active probe stop refuses primary-instance crash", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.noIsolation);
  const before = hashTargetTree(tmp);
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  const r = result as Diag;
  assertReadOnlyBoundary(r);
  assert.equal(r.diagnosis_state, "INCONCLUSIVE");
  assert.equal(r.user_resolution.status, "INCONCLUSIVE");
  assert.deepEqual(topIds(r), []);
  const refused = r.crash_classification?.refused_actions ?? [];
  assert.ok(refused.includes("active_crash_probe_without_isolation"));
  assert.ok(refused.includes("primary_codex_instance_crash"));
  assert.ok(
    (r.crash_classification?.next_evidence_requirements ?? []).some((s) =>
      s.toLowerCase().includes("isolat"),
    ),
  );
  assert.equal(hashTargetTree(tmp), before);
});

// --- Axes, gates, repair refusal ---

test("local_mechanism / upstream_match / fix_applicability stay separate; no repair auth", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.access);
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  const r = result as Diag;
  const cc = r.crash_classification!;
  assert.ok(cc.local_mechanism.status === "supported" || cc.local_mechanism.status === "candidate");
  assert.equal(cc.upstream_match.status, "candidate");
  assert.equal(cc.fix_applicability.status, "blocked");
  assert.equal(cc.repair_authorization_eligible, false);
  assert.ok(cc.refused_actions.includes("symptom_level_patch_authorization"));
});

test("repair-preview on crash fixture never enters authorization (wrong fix blocked)", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.access);
  const before = hashTargetTree(tmp);
  const preview = runCliRepairPreview(tmp);
  assert.ok(preview.result);
  const pr = preview.result as {
    ok: boolean;
    authorization: string | null;
    user_resolution: { status: string };
    capsule: unknown;
  };
  assert.equal(pr.ok, false);
  assert.equal(pr.authorization, null);
  assert.equal(pr.capsule, null);
  assert.notEqual(pr.user_resolution.status, "REPAIR_PREVIEWED");
  assert.notEqual(pr.user_resolution.status, "RESOLVED_VERIFIED");
  assert.equal(hashTargetTree(tmp), before);
});

test("model preferred ranking cannot override hard gates or invent provenance", () => {
  const raw = fs.readFileSync(
    path.join(REPO_ROOT, FAMILY_FIXTURES.macos, "incident.json"),
    "utf8",
  );
  const fp = parseIncidentJson(raw);
  // Model tries to force a Windows family onto macOS evidence.
  const classification = classifyCrashFamily(fp, {
    model_preferred_issue_ids: [
      "openai/codex#32683",
      "openai/codex#33710",
      "openai/codex#32094",
    ],
  });
  assert.equal(classification.ranked_candidates.length, 0);
  assert.ok(
    classification.rejected_candidates.every(
      (c) => c.hard_gated || c.score < 0.55,
    ),
  );
  assert.equal(classification.repair_authorization_eligible, false);
  assert.equal(classification.fix_applicability.status, "blocked");
});

test("model preference cannot promote title-only incident to high confidence", () => {
  const raw = fs.readFileSync(
    path.join(REPO_ROOT, FAMILY_FIXTURES.titleOnly, "incident.json"),
    "utf8",
  );
  const fp = parseIncidentJson(raw);
  const classification = classifyCrashFamily(fp, {
    model_preferred_issue_ids: ["openai/codex#32683"],
  });
  assert.notEqual(classification.diagnosis_state, "HIGH_CONFIDENCE_MATCH");
  assert.equal(classification.ranked_candidates.length, 0);
});

test("incompatible mechanism hard-gates wrong family (exception mismatch)", () => {
  const raw = fs.readFileSync(
    path.join(REPO_ROOT, FAMILY_FIXTURES.access, "incident.json"),
    "utf8",
  );
  const fp = parseIncidentJson(raw);
  const classification = classifyCrashFamily(fp);
  const interaction = classification.rejected_candidates.find(
    (c) => c.issue_id === "openai/codex#33710",
  );
  assert.ok(interaction);
  assert.equal(interaction!.hard_gated, true);
  assert.ok(
    interaction!.gate_reasons.some((g) => g.startsWith("exception_mismatch")),
  );
});

test("defining-mechanism gate: absent GPU codes hard-gates openai/codex#32094", () => {
  const raw = fs.readFileSync(
    path.join(REPO_ROOT, FAMILY_FIXTURES.access, "incident.json"),
    "utf8",
  );
  const fp = parseIncidentJson(raw);
  const classification = classifyCrashFamily(fp);
  assert.ok(
    !classification.ranked_candidates.some((c) => c.issue_id === "openai/codex#32094"),
  );
  const gpu = classification.rejected_candidates.find(
    (c) => c.issue_id === "openai/codex#32094",
  );
  assert.ok(gpu);
  assert.equal(gpu!.hard_gated, true);
  assert.ok(
    gpu!.gate_reasons.some(
      (g) =>
        g === "gpu_exit_required" ||
        g === "gpu_relaunch_required" ||
        g.startsWith("exception_conflict:"),
    ),
    `expected GPU defining-mechanism gate reasons, got ${gpu!.gate_reasons.join(",")}`,
  );
});

test("defining-mechanism gate: absent concrete page capability hard-gates openai/codex#33762", () => {
  const raw = fs.readFileSync(
    path.join(REPO_ROOT, FAMILY_FIXTURES.access, "incident.json"),
    "utf8",
  );
  const fp = parseIncidentJson(raw);
  const classification = classifyCrashFamily(fp);
  assert.ok(
    !classification.ranked_candidates.some((c) => c.issue_id === "openai/codex#33762"),
  );
  const complex = classification.rejected_candidates.find(
    (c) => c.issue_id === "openai/codex#33762",
  );
  assert.ok(complex);
  assert.equal(complex!.hard_gated, true);
  assert.ok(
    complex!.gate_reasons.some((g) => g.startsWith("page_capability_required:")),
    `expected page_capability_required, got ${complex!.gate_reasons.join(",")}`,
  );
});

test("model preference cannot resurrect no-mechanism GPU/complex candidates", () => {
  const raw = fs.readFileSync(
    path.join(REPO_ROOT, FAMILY_FIXTURES.access, "incident.json"),
    "utf8",
  );
  const fp = parseIncidentJson(raw);
  const classification = classifyCrashFamily(fp, {
    model_preferred_issue_ids: [
      "openai/codex#32094",
      "openai/codex#33762",
    ],
  });
  const rankedIds = classification.ranked_candidates.map((c) => c.issue_id);
  assert.ok(rankedIds.includes("openai/codex#32683"));
  assert.ok(!rankedIds.includes("openai/codex#32094"));
  assert.ok(!rankedIds.includes("openai/codex#33762"));
  for (const id of ["openai/codex#32094", "openai/codex#33762"]) {
    const rejected = classification.rejected_candidates.find((c) => c.issue_id === id);
    assert.ok(rejected);
    assert.equal(rejected!.hard_gated, true);
  }
});

test("adversarial: no-mechanism candidate excluded when only shared soft signals match", () => {
  // Synthetic: Windows desktop AV signature without GPU codes or complex page.
  // Competing families that only share phase/component must not enter Top 3.
  const dir = makeTempDir("cg-t09-nomech-");
  writeJson(
    path.join(dir, "incident.json"),
    baseIncident({
      surface: "desktop",
      platform: { os: "windows", arch: "x64", sandbox_class: null },
      failure_phase: "navigation",
      error: {
        class: "NativeCrash",
        normalized_message: "browser crash after neutral page opens",
        message_digest:
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      },
      feature_ids: ["in_app_browser"],
      crash_metadata: {
        exception_code: "0xC0000005",
        faulting_module: "chrome.dll",
        faulting_symbol: "CrBrowserMain",
        offset_bucket: "0x2e08f46",
        gpu_child_exit_code: null,
        gpu_relaunch_code: null,
        interaction_phase: "neutral_dom_ready",
        page_capability: "neutral",
        concurrency_context: "single",
        concurrent_side_chats: 1,
        component: "in_app_browser",
        isolation_available: true,
        natural_failure_only: true,
        active_probe_requested: false,
        dump_contents_present: false,
      },
    }),
  );
  const classification = classifyCrashFamily(parseIncidentJson(
    fs.readFileSync(path.join(dir, "incident.json"), "utf8"),
  ));
  const rankedIds = classification.ranked_candidates.map((c) => c.issue_id);
  assert.ok(rankedIds.includes("openai/codex#32683"));
  assert.ok(!rankedIds.includes("openai/codex#32094"));
  assert.ok(!rankedIds.includes("openai/codex#33762"));
  assert.ok(
    classification.ranked_candidates.every((c) => c.hard_gated === false),
  );
  // Direct gate evidence on rejected no-mechanism families.
  const gpu = classification.rejected_candidates.find(
    (c) => c.issue_id === "openai/codex#32094",
  );
  const complex = classification.rejected_candidates.find(
    (c) => c.issue_id === "openai/codex#33762",
  );
  assert.equal(gpu?.hard_gated, true);
  assert.equal(complex?.hard_gated, true);
});

// --- CLI / MCP equivalence ---

test("CLI/MCP stable-field equivalence on crash-family positive fixture", async () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.access);
  const cli = runCliDiagnose(tmp);
  assert.equal(cli.exitCode, 0);
  assert.ok(cli.result);
  const mcp = (await runMcpDiagnose(tmp)) as Diag;
  assertCliMcpCrashEquiv(cli.result as Diag, mcp);
  assertReadOnlyBoundary(cli.result as Diag);
  assertReadOnlyBoundary(mcp);
});

test("CLI/MCP equivalence on macOS negative and title-only controls", async () => {
  for (const fx of [FAMILY_FIXTURES.macos, FAMILY_FIXTURES.titleOnly]) {
    const tmp = fixtureTemp(fx);
    const cli = runCliDiagnose(tmp);
    assert.ok(cli.result);
    const mcp = (await runMcpDiagnose(tmp)) as Diag;
    assertCliMcpCrashEquiv(cli.result as Diag, mcp);
  }
});

// --- Adversarial parse / bounds / redaction ---

test("malformed crash_metadata extra key refused", () => {
  const dir = makeTempDir("cg-t09-extra-");
  writeJson(
    path.join(dir, "incident.json"),
    baseIncident({
      surface: "desktop",
      platform: { os: "windows", arch: "x64", sandbox_class: null },
      failure_phase: "navigation",
      error: {
        class: "NativeCrash",
        normalized_message: "browser crash",
        message_digest:
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      },
      feature_ids: ["in_app_browser"],
      crash_metadata: {
        exception_code: "0xC0000005",
        faulting_module: "chrome.dll",
        faulting_symbol: "CrBrowserMain",
        offset_bucket: "0x2e08f46",
        gpu_child_exit_code: null,
        gpu_relaunch_code: null,
        interaction_phase: "neutral_dom_ready",
        page_capability: "neutral",
        concurrency_context: "single",
        concurrent_side_chats: 1,
        component: "in_app_browser",
        isolation_available: true,
        natural_failure_only: true,
        active_probe_requested: false,
        dump_contents_present: false,
        dump_body_base64: "AAAA", // forbidden
      },
    }),
  );
  const r = diagnose(dir);
  assert.equal(r.ok, false);
  assert.equal(r.error_code, "MALFORMED_INCIDENT");
});

test("oversized incident refused", () => {
  const dir = makeTempDir("cg-t09-size-");
  const big = baseIncident({
    surface: "desktop",
    platform: { os: "windows", arch: "x64", sandbox_class: null },
    error: {
      class: "NativeCrash",
      normalized_message: "x".repeat(MAX_INCIDENT_BYTES + 100),
      message_digest:
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    },
  });
  // Write raw oversized file bypassing field limits via huge padding key would fail parse;
  // size limit is on file bytes — write a huge buffer.
  const pad = "x".repeat(MAX_INCIDENT_BYTES + 32);
  fs.writeFileSync(
    path.join(dir, "incident.json"),
    JSON.stringify(big).slice(0, 100) + pad,
    "utf8",
  );
  const r = diagnose(dir);
  assert.equal(r.ok, false);
  assert.ok(
    r.error_code === "SIZE_LIMIT" || r.error_code === "MALFORMED_JSON",
  );
});

test("absolute path in crash module field is redacted on output", () => {
  const dir = makeTempDir("cg-t09-path-");
  writeJson(
    path.join(dir, "incident.json"),
    baseIncident({
      surface: "desktop",
      platform: { os: "windows", arch: "x64", sandbox_class: null },
      failure_phase: "navigation",
      error: {
        class: "NativeCrash",
        normalized_message: "browser crash with path",
        message_digest:
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      },
      feature_ids: ["in_app_browser"],
      crash_metadata: {
        exception_code: "0xC0000005",
        faulting_module: "C:\\\\Users\\\\alice\\\\AppData\\\\chrome.dll",
        faulting_symbol: "CrBrowserMain",
        offset_bucket: "0x2e08f46",
        gpu_child_exit_code: null,
        gpu_relaunch_code: null,
        interaction_phase: "neutral_dom_ready",
        page_capability: "neutral",
        concurrency_context: "single",
        concurrent_side_chats: 1,
        component: "in_app_browser",
        isolation_available: true,
        natural_failure_only: true,
        active_probe_requested: false,
        dump_contents_present: false,
      },
    }),
  );
  const { exitCode, stdout, result } = runCliDiagnose(dir);
  assert.equal(exitCode, 0);
  assert.ok(result);
  assertNoLeakText(stdout);
  // Redaction may replace path segments; raw username path must not appear.
  assert.equal(/C:\\\\Users\\\\alice/i.test(stdout), false);
  assert.equal(/\/Users\/alice/i.test(stdout), false);
});

test("dump_contents_present flags refused dump parse/export without blocking metadata path", () => {
  const dir = makeTempDir("cg-t09-dump-");
  writeJson(
    path.join(dir, "incident.json"),
    baseIncident({
      surface: "desktop",
      platform: { os: "windows", arch: "x64", sandbox_class: null },
      failure_phase: "navigation",
      error: {
        class: "NativeCrash",
        normalized_message: "browser crash dump present",
        message_digest:
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01",
      },
      feature_ids: ["in_app_browser"],
      crash_metadata: {
        exception_code: "0xC0000005",
        faulting_module: "chrome.dll",
        faulting_symbol: "CrBrowserMain",
        offset_bucket: "0x2e08f46",
        gpu_child_exit_code: null,
        gpu_relaunch_code: null,
        interaction_phase: "neutral_dom_ready",
        page_capability: "neutral",
        concurrency_context: "single",
        concurrent_side_chats: 1,
        component: "in_app_browser",
        isolation_available: true,
        natural_failure_only: true,
        active_probe_requested: false,
        dump_contents_present: true,
      },
    }),
  );
  const r = diagnose(dir) as Diag;
  assert.equal(r.ok, true);
  assert.ok(
    r.crash_classification?.refused_actions.includes("dump_contents_parse_export"),
  );
  // Still may rank from metadata; never claims dump-based proof.
  assert.equal(r.crash_classification?.repair_authorization_eligible, false);
});

// --- Normalization unit checks ---

test("exception/offset/module normalization is deterministic", () => {
  assert.equal(normalizeExceptionCode("0xC0000005"), "0xc0000005");
  assert.equal(normalizeExceptionCode("C0000005"), "0xc0000005");
  assert.equal(normalizeOffsetBucket("2e08f46"), "0x2e08f46");
  assert.equal(normalizeModuleName("C:\\\\Windows\\\\System32\\\\chrome.dll"), "chrome.dll");
  assert.equal(normalizeModuleName("ChatGPT.exe"), "chatgpt.exe");
});

test("catalog has expected Fixture E issue ids", () => {
  const ids = CRASH_FAMILY_CATALOG.map((c) => c.issue_id);
  for (const id of [
    "openai/codex#32683",
    "openai/codex#33710",
    "openai/codex#32094",
    "openai/codex#33202",
  ]) {
    assert.ok(ids.includes(id), `missing ${id}`);
  }
  assert.ok(CRASH_FAMILY_CATALOG.every((c) => c.fix_linked === false));
  assert.ok(CRASH_FAMILY_CATALOG.every((c) => c.safe_fix_applicable === false));
});

// --- Prior-ticket regression (Tickets 01–04 public diagnose) ---

test("prior-ticket regression: protected-process still SOURCE_COMPONENT_LOCATED", () => {
  const tmp = fixtureTemp("fixtures/protected-process");
  const before = hashTargetTree(tmp);
  const { exitCode, result } = runCliDiagnose(tmp);
  assert.equal(exitCode, 0);
  assert.ok(result);
  assert.equal(result.diagnosis_state, "SOURCE_COMPONENT_LOCATED");
  assert.deepEqual(result.upstream_contribution.issue_candidates, [
    "openai/codex#32925",
  ]);
  assert.equal(result.user_resolution.status, "DIAGNOSIS_COMPLETE");
  // Crash classifier must not hijack protected-process positive path.
  assert.equal(
    (result as Diag).crash_classification ?? null,
    null,
  );
  assert.equal(hashTargetTree(tmp), before);
});

test("prior-ticket regression: negative-control remains INCONCLUSIVE", () => {
  const tmp = fixtureTemp("fixtures/negative-control");
  const { result } = runCliDiagnose(tmp);
  assert.ok(result);
  assert.equal(result.diagnosis_state, "INCONCLUSIVE");
  assert.equal(result.user_resolution.status, "INCONCLUSIVE");
  assert.deepEqual(result.upstream_contribution.issue_candidates, []);
});

test("shared-core diagnose() matches CLI on access-violation family", () => {
  const tmp = fixtureTemp(FAMILY_FIXTURES.access);
  const core = diagnose(tmp) as Diag;
  const cli = runCliDiagnose(tmp).result as Diag;
  assert.equal(core.diagnosis_state, cli.diagnosis_state);
  assert.equal(core.user_resolution.status, cli.user_resolution.status);
  assert.deepEqual(
    core.upstream_contribution.issue_candidates,
    cli.upstream_contribution.issue_candidates,
  );
  assert.equal(core.crash_classification?.family_id, cli.crash_classification?.family_id);
});
