/**
 * ChangeGuard Rescue CLI — public seams share one core with MCP.
 * Commands:
 *   changeguard diagnose <isolated-target>
 *   changeguard impact <isolated-target> [--disclose-approved|--disclose-refused]
 *   changeguard analyze-page <isolated-target> --envelope=<page.json> [--disclose-approved|--disclose-refused]
 *   changeguard upstream-preview <isolated-target> --request=<request.json> [--disclose-approved|--disclose-refused]
 *   changeguard upstream-action-preview <isolated-target> --capsule=<capsule.json> --action=<kind> [--attachments=<manifest.json>]
 *   changeguard upstream-action-confirm <isolated-target> --confirmation=<ua1.…|path> --decision=confirm|cancel
 *   changeguard repair-preview <isolated-target>
 *   changeguard repair-apply <isolated-target> <authorization-token>
 *   changeguard verify <isolated-target>
 *   changeguard rollback <isolated-target>
 *   changeguard scan <inventory-root>          (fixture inventory adapter)
 *   changeguard scan-system                    (production registered system adapter)
 *   changeguard session-start <inventory-root> [--hook-trust=…]  (manual fixture path)
 *   changeguard lifecycle <operation> <isolated-target> [--key=value …]
 *   changeguard followup <operation> <isolated-target> [--request=<request.json>] …
 *   changeguard platform-status [--probe-host=true|false] [--receipt=<path>] [--plan] [--adapter=<id>]
 *   changeguard platform-receipt-validate <receipt.json>
 *   changeguard demo [--budget-ms=<positive-int>]
 *
 * Ticket 11 production seams inject no real gh/browser adapter (capability unavailable).
 * Ticket 12 follow-up is local-only (no network/daemon; external_write:false; no live witness serialization).
 * Ticket 13 platform seams are read-only (no harness spawn; Full only with real-machine receipt).
 * Ticket 14 Windows support remains PREVIEW without a real Windows 11 host receipt.
 * Ticket 15 Linux/WSL capability matrix is Limited/Read-only without a real-machine receipt.
 * Ticket 17 demo is product-local: shared runDemo core only; disposable OS-temp; no network/live profile.
 */
import fs from "node:fs";
import { diagnose } from "../core/diagnose.js";
import {
  DEMO_DEFAULT_BUDGET_MS,
  demoSkippedSteps,
  runDemo,
  surfaceSecurityEvidence,
  type DemoReceipt,
} from "../core/demo/index.js";
import {
  applyRepair,
  previewRepair,
  rollbackRepair,
  verifyRepair,
} from "../core/recovery/index.js";
import {
  dispatchLifecycle,
  type LifecycleDispatchArgs,
} from "../core/lifecycle/index.js";
import type { LifecycleResult } from "../core/lifecycle/types.js";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import { assessImpact } from "../impact/assess.js";
import type { DiagnosisResult } from "../core/types.js";
import type { RepairResult } from "../core/recovery/types.js";
import type { DisclosureDecision } from "../evidence/types.js";
import type { ImpactAssessmentResult } from "../impact/types.js";
import { scanInstances } from "../instances/scan.js";
import { unavailableLocalArtifactDiff } from "../instances/artifact-diff.js";
import type { HookTrustState, ScanResult } from "../instances/types.js";
import { runSessionStart } from "../hooks/session-start.js";
import { analyzePage } from "../page/analyze.js";
import type {
  PageAnalysisResult,
  PageDisclosureDecision,
} from "../page/types.js";
import { MAX_PAGE_ENVELOPE_BYTES } from "../page/limits.js";
import { previewUpstream } from "../upstream/preview.js";
import type {
  DisclosureDecision as UpstreamDisclosureDecision,
  UpstreamPreviewResult,
} from "../upstream/types.js";
import { MAX_UPSTREAM_REQUEST_BYTES } from "../upstream/limits.js";
import {
  confirmUpstreamAction,
  previewUpstreamAction,
  MAX_ACTION_REQUEST_BYTES,
  MAX_CONFIRMATION_BYTES,
  type ActionConfirmResult,
  type ActionPreviewResult,
} from "../upstream/actions/index.js";
import {
  platformStatus,
  resolvePublicRepairCapability,
  validatePlatformSupportReceipt,
  loadAndEvaluateReceiptFile,
  realMachineRunnerPlan,
  windows11SupportStatus,
  type AdapterId,
  type PlatformStatusResult,
  type ReceiptValidationResult,
} from "../platform/index.js";
import {
  dispatchFollowup,
  isFollowupOperation,
  parseFollowupRequestJson,
  parseFollowupWireBody,
  MAX_FOLLOWUP_REQUEST_BYTES,
  type FollowupResult,
} from "../upstream/followup/index.js";
import type { FollowupDispatchArgs } from "../upstream/followup/dispatch.js";

const PLATFORM_ADAPTERS = new Set<AdapterId>([
  "unknown",
  "macos",
  "windows",
  "linux",
  "wsl",
  "enterprise_managed",
]);

function printJson(value: unknown, exitCode: number): never {
  const text = assertNoLeakPaths(redactText(JSON.stringify(value, null, 2)));
  process.stdout.write(text + "\n");
  process.exit(exitCode);
}

function usageDiagnosis(): DiagnosisResult {
  return {
    schema_version: 1,
    ok: false,
    diagnosis_state: "INCONCLUSIVE",
    incident_fingerprint: null,
    user_resolution: {
      status: "INCONCLUSIVE",
      summary: "Invalid arguments.",
      receipt_id: "cli_usage_user",
    },
    upstream_contribution: {
      status: "NONE",
      summary: "No upstream contribution.",
      issue_candidates: [],
      receipt_id: "cli_usage_upstream",
    },
    evidence: [],
    error_code: "USAGE",
    error_message:
      "Usage: changeguard diagnose|impact|analyze-page|upstream-preview|upstream-action-preview|upstream-action-confirm|repair-preview|repair-apply|verify|rollback|scan|scan-system|session-start|lifecycle|followup|platform-status|platform-receipt-validate …",
    network_used: false,
    target_mutated: false,
    repair_applied: false,
  };
}

function actionPreviewUsageError(): never {
  const result: ActionPreviewResult = {
    schema_version: 1,
    ok: false,
    status: "INVALID_INPUT",
    action: null,
    canonical_target: null,
    body_manifest: null,
    attachment_manifest: null,
    privacy: null,
    incident_fingerprint_digest: null,
    evidence_delta_hash: null,
    capsule_content_sha256: null,
    capsule_id: null,
    confirmation_token: null,
    confirmation: null,
    idempotency_key: null,
    auth_capability: {
      kind: "unavailable",
      detail: "Usage error.",
      authenticated: false,
    },
    local_incident: null,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    repair_authorized: false,
    external_write: false,
    error_code: "USAGE",
    error_message:
      "Usage: changeguard upstream-action-preview <isolated-target> --capsule=<capsule.json> --action=<kind> [--attachments=<manifest.json>]",
  };
  printJson(result, 2);
}

function actionConfirmUsageError(): never {
  const result: ActionConfirmResult = {
    schema_version: 1,
    ok: false,
    status: "INVALID_CONFIRMATION",
    action: null,
    decision: null,
    receipt: null,
    idempotency_key: null,
    auth_capability: {
      kind: "unavailable",
      detail: "Usage error.",
      authenticated: false,
    },
    confirmation_id: null,
    local_incident: null,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    repair_authorized: false,
    external_write: false,
    error_code: "USAGE",
    error_message:
      "Usage: changeguard upstream-action-confirm <isolated-target> --confirmation=<ua1.…|path> --decision=confirm|cancel",
  };
  printJson(result, 2);
}

/**
 * Unified platform-status (Tickets 13 + 14 + 15).
 * - Always includes macOS/host capability fields from platformStatus.
 * - Always includes Windows support evaluation under `status` (default PREVIEW).
 * - Always includes Ticket 15 capability matrix under `reports` / `default_status`.
 * - --adapter=<id> filters the capability matrix (does not upgrade Full).
 * - --receipt=<path> evaluates a Windows support receipt file (never fabricates Full).
 * - --plan includes the Windows real-machine runner plan.
 * - --probe-host controls host install probing for capabilities.
 */
function runPlatformStatus(rest: string[]): void {
  let probeHost = true;
  let receiptPath: string | null = null;
  let showPlan = false;
  let adapter: AdapterId | undefined;
  const usage =
    "Usage: changeguard platform-status [--probe-host=true|false] [--receipt=<path>] [--plan] [--adapter=<id>]";
  for (const a of rest) {
    if (a === "--probe-host=false" || a === "--probe-host=0") {
      probeHost = false;
      continue;
    }
    if (a === "--probe-host=true" || a === "--probe-host=1") {
      probeHost = true;
      continue;
    }
    if (a.startsWith("--receipt=")) {
      receiptPath = a.slice("--receipt=".length);
      if (!receiptPath) {
        printJson(
          {
            schema_version: 1,
            ok: false,
            error_code: "USAGE",
            error_message: "Empty --receipt= path.",
            network_used: false,
            target_mutated: false,
            repair_applied: false,
          },
          2,
        );
      }
      continue;
    }
    if (a === "--plan") {
      showPlan = true;
      continue;
    }
    if (a.startsWith("--adapter=")) {
      const v = a.slice("--adapter=".length) as AdapterId;
      if (!PLATFORM_ADAPTERS.has(v)) {
        printJson(
          {
            schema_version: 1,
            ok: false,
            error_code: "USAGE",
            error_message: usage,
            network_used: false,
            target_mutated: false,
            repair_applied: false,
          },
          2,
        );
      }
      adapter = v;
      continue;
    }
    if (a.startsWith("-")) {
      printJson(
        {
          schema_version: 1,
          ok: false,
          error_code: "USAGE",
          error_message: usage,
          network_used: false,
          target_mutated: false,
          repair_applied: false,
        },
        2,
      );
    }
    printJson(
      {
        schema_version: 1,
        ok: false,
        error_code: "USAGE",
        error_message: usage,
        network_used: false,
        target_mutated: false,
        repair_applied: false,
      },
      2,
    );
  }

  const base: PlatformStatusResult = platformStatus({
    probeHost,
    ...(adapter ? { adapter } : {}),
  });
  let winStatus = windows11SupportStatus(null);
  let loadOk = true;
  let error_code: string | null = base.error_code;
  let error_message: string | null = base.error_message;

  if (receiptPath) {
    const loaded = loadAndEvaluateReceiptFile(receiptPath);
    winStatus = loaded.status;
    loadOk = loaded.ok;
    if (!loaded.ok) {
      error_code = loaded.error_code;
      error_message = loaded.error_message;
    }
  }

  printJson(
    {
      ...base,
      ok: base.ok && loadOk,
      status: winStatus,
      plan: showPlan ? realMachineRunnerPlan() : null,
      error_code,
      error_message,
    },
    // Exit 0 when evaluation succeeded (including honest PREVIEW).
    // Nonzero only on load/parse failure of a provided receipt path.
    loadOk ? (base.ok ? 0 : 1) : 1,
  );
}

function runPlatformReceiptValidate(rest: string[]): void {
  if (rest.length !== 1 || isFlag(rest[0]!)) {
    printJson(
      {
        schema_version: 1,
        ok: false,
        support_level: "unsupported",
        errors: ["USAGE"],
        gaps: [],
        receipt_id: null,
        network_used: false,
        error_code: "USAGE",
        error_message:
          "Usage: changeguard platform-receipt-validate <receipt.json>",
      },
      2,
    );
  }
  const receiptPath = rest[0]!;
  try {
    if (!fs.existsSync(receiptPath)) {
      const result: ReceiptValidationResult = {
        schema_version: 1,
        ok: false,
        support_level: "unsupported",
        errors: ["RECEIPT_NOT_FOUND"],
        gaps: [],
        receipt_id: null,
        network_used: false,
      };
      printJson(result, 1);
    }
    const raw = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    const result = validatePlatformSupportReceipt(raw);
    printJson(result, result.ok ? 0 : 1);
  } catch {
    const result: ReceiptValidationResult = {
      schema_version: 1,
      ok: false,
      support_level: "unsupported",
      errors: ["RECEIPT_PARSE"],
      gaps: [],
      receipt_id: null,
      network_used: false,
    };
    printJson(result, 1);
  }
}


function upstreamUsageError(): never {
  const result: UpstreamPreviewResult = {
    schema_version: 1,
    ok: false,
    capsule: null,
    disclosure_decision: "not_requested",
    disclosure_manifest: {
      schema_version: 1,
      manifest_id: "cli_usage",
      fields: [],
      purpose: "usage",
      destinations: [],
    },
    transport_calls: 0,
    local_incident: null,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    repair_authorized: false,
    external_write: false,
    submission_status: "none",
    error_code: "USAGE",
    error_message:
      "Usage: changeguard upstream-preview <isolated-target> --request=<upstream-request.json> [--disclose-approved|--disclose-refused]",
  };
  printJson(result, 2);
}

function pageUsageError(): never {
  const result: PageAnalysisResult = {
    schema_version: 1,
    ok: false,
    page_evidence: null,
    comparison: null,
    disclosure_decision: "not_requested",
    disclosure_manifest: {
      schema_version: 1,
      manifest_id: "cli_usage",
      fields: [],
      purpose: "usage",
      destinations: [],
    },
    transport_calls: 0,
    observed_facts: [],
    user_reports: [],
    hypotheses: [],
    local_incident: null,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    repair_authorized: false,
    error_code: "USAGE",
    error_message:
      "Usage: changeguard analyze-page <isolated-target> --envelope=<page-envelope.json> [--disclose-approved|--disclose-refused]",
  };
  printJson(result, 2);
}

function scanUsageError(
  kind: "scan" | "session-start" | "scan-system",
): never {
  const result: ScanResult = {
    schema_version: 1,
    ok: false,
    mode: kind === "session-start" ? "session_start" : "manual_scan",
    fingerprint_changed: false,
    overall_fingerprint: "",
    previous_fingerprint: null,
    primary_transition: "unchanged",
    transitions: [],
    instances: [],
    affected_instance_id: null,
    affected_resolution: "none",
    affected_resolution_reason: "no_instances",
    hook_status: kind === "session-start" ? "failed" : null,
    health_check: null,
    silent: false,
    state_updated: false,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    error_code: "USAGE",
    error_message:
      kind === "scan"
        ? "Usage: changeguard scan <inventory-root>"
        : kind === "scan-system"
          ? "Usage: changeguard scan-system [--state-dir=<dir>]"
          : "Usage: changeguard session-start <inventory-root> [--hook-trust=trusted|untrusted|skipped|failed]",
    local_artifact_diff: unavailableLocalArtifactDiff(),
  };
  printJson(result, 2);
}

function isFlag(s: string): boolean {
  return s.startsWith("-");
}

/** Demo usage — never embeds paths, tokens, or live targets. Schema-valid. */
function demoUsageError(): never {
  const result: DemoReceipt = {
    schema_version: 1,
    ok: false,
    status: "failed",
    duration_ms: 0,
    // Canonical 10 ordered steps (schema minItems=10), all skipped/refused.
    steps: demoSkippedSteps("INVALID_ARGS", "refused"),
    main: {
      diagnose_state: null,
      user_resolution_after_apply: null,
      user_resolution_after_verify: null,
      user_resolution_after_rollback: null,
      resolved_verified: false,
      repair_applied: false,
      auto_rolled_back: false,
      hash_proof: null,
    },
    model_refusal: {
      refused: false,
      reasons: [],
      graph_unchanged: false,
      graph_sha256: null,
    },
    crash_refusal: {
      family_id: null,
      diagnosis_state: null,
      repair_authorization_eligible: false,
      preview_refused: false,
      refused_actions: [],
      reason_codes: [],
    },
    network_used: false,
    external_write: false,
    live_profile_mutated: false,
    // Unproven: no demo run occurred; never ok:true with empty evidence.
    security_evidence: surfaceSecurityEvidence(),
    cleanup: {
      attempted: false,
      completed: false,
      temp_removed: false,
    },
    error_code: "INVALID_ARGS",
    error_message:
      "Usage: changeguard demo [--budget-ms=<positive-int>]. No positional targets; product-local disposable demo only.",
  };
  printJson(result, 2);
}

/**
 * Parse demo CLI flags. No positionals. Optional --budget-ms=N only.
 * Rejects unknown flags, bare --budget-ms, non-positive / non-integer budgets.
 */
function parseDemoArgs(
  rest: string[],
): { budget_ms?: number } | null {
  let budget_ms: number | undefined;
  for (const a of rest) {
    if (a.startsWith("--budget-ms=")) {
      const raw = a.slice("--budget-ms=".length);
      if (!/^\d+$/.test(raw)) return null;
      const n = Number(raw);
      if (!Number.isInteger(n) || n <= 0 || n > DEMO_DEFAULT_BUDGET_MS * 2) {
        return null;
      }
      budget_ms = n;
      continue;
    }
    // Reject unknown flags, bare --budget-ms, positionals, induce/target controls.
    return null;
  }
  return budget_ms === undefined ? {} : { budget_ms };
}

function runDemoCli(rest: string[]): void {
  const parsed = parseDemoArgs(rest);
  if (!parsed) {
    demoUsageError();
  }
  const receipt = runDemo(
    parsed.budget_ms !== undefined ? { budget_ms: parsed.budget_ms } : {},
  );
  printJson(receipt, receipt.ok ? 0 : 1);
}

function parseHookTrust(args: string[]): HookTrustState {
  for (const a of args) {
    if (a.startsWith("--hook-trust=")) {
      const v = a.slice("--hook-trust=".length);
      if (
        v === "trusted" ||
        v === "untrusted" ||
        v === "skipped" ||
        v === "failed"
      ) {
        return v;
      }
      scanUsageError("session-start");
    }
  }
  return "trusted";
}

function parseStateDir(args: string[]): string | undefined {
  for (const a of args) {
    if (a.startsWith("--state-dir=")) {
      const v = a.slice("--state-dir=".length);
      if (v.length > 0) return v;
    }
  }
  return undefined;
}

function runScan(inventoryRoot: string): void {
  try {
    const result = scanInstances({
      inventoryRoot,
      mode: "manual_scan",
      enumeration: "fixture_inventory",
    });
    printJson(result, result.ok ? 0 : 1);
  } catch {
    printJson(
      {
        schema_version: 1,
        ok: false,
        mode: "manual_scan",
        error_code: "INTERNAL",
        error_message: "Scan failed.",
        network_used: false,
        target_mutated: false,
        repair_applied: false,
      },
      1,
    );
  }
}

function runScanSystem(stateDir?: string): void {
  try {
    // Prefer explicit --state-dir, then PLUGIN_DATA, else a temp-safe refusal with USAGE.
    const pluginData =
      process.env.PLUGIN_DATA || process.env.CLAUDE_PLUGIN_DATA || null;
    const resolvedState =
      stateDir ??
      (pluginData ? `${pluginData.replace(/[/\\]$/, "")}/version-state` : null);
    if (!resolvedState) {
      scanUsageError("scan-system");
    }
    const result = scanInstances({
      mode: "manual_scan",
      enumeration: "system_registered",
      stateDir: resolvedState,
    });
    printJson(result, result.ok ? 0 : 1);
  } catch {
    printJson(
      {
        schema_version: 1,
        ok: false,
        mode: "manual_scan",
        error_code: "INTERNAL",
        error_message: "Scan failed.",
        network_used: false,
        target_mutated: false,
        repair_applied: false,
      },
      1,
    );
  }
}

function runSession(inventoryRoot: string, hookTrust: HookTrustState): void {
  try {
    const result = runSessionStart({
      inventoryRoot,
      enumeration: "fixture_inventory",
      hookTrust,
    });
    // Manual CLI path always emits structured JSON for inspectability.
    // Packaged hook silence is owned by session-start-entry (no stdout when silent).
    printJson(result, result.ok || result.silent ? 0 : 1);
  } catch {
    printJson(
      {
        schema_version: 1,
        ok: false,
        mode: "session_start",
        hook_status: "failed",
        error_code: "HOOK_FAILED",
        error_message: "SessionStart hook failed; use manual scan.",
        network_used: false,
        target_mutated: false,
        repair_applied: false,
      },
      1,
    );
  }
}

function parseImpactArgs(rest: string[]): {
  target: string;
  disclosure_decision: DisclosureDecision;
} | null {
  if (rest.length === 0) return null;
  let disclosure_decision: DisclosureDecision = "not_requested";
  const positional: string[] = [];
  for (const a of rest) {
    if (a === "--disclose-approved") {
      disclosure_decision = "approved";
      continue;
    }
    if (a === "--disclose-refused") {
      disclosure_decision = "refused";
      continue;
    }
    if (a.startsWith("-")) {
      return null;
    }
    positional.push(a);
  }
  if (positional.length !== 1) return null;
  return { target: positional[0]!, disclosure_decision };
}

function runImpact(
  target: string,
  disclosure_decision: DisclosureDecision,
): void {
  try {
    // CLI never injects a live network transport. Approved without transport
    // falls back to the timestamped immutable snapshot with stale labels.
    const result: ImpactAssessmentResult = assessImpact({
      targetPath: target,
      disclosure_decision,
      transport: null,
    });
    printJson(result, result.ok ? 0 : 1);
  } catch {
    printJson(
      {
        schema_version: 1,
        ok: false,
        error_code: "INTERNAL",
        error_message: "Impact assessment failed.",
        network_used: false,
        target_mutated: false,
        repair_applied: false,
      },
      1,
    );
  }
}

function parseAnalyzePageArgs(rest: string[]): {
  target: string;
  envelopePath: string;
  disclosure_decision: PageDisclosureDecision;
} | null {
  if (rest.length === 0) return null;
  let disclosure_decision: PageDisclosureDecision = "not_requested";
  let envelopePath: string | null = null;
  const positional: string[] = [];
  for (const a of rest) {
    if (a === "--disclose-approved") {
      disclosure_decision = "approved";
      continue;
    }
    if (a === "--disclose-refused") {
      disclosure_decision = "refused";
      continue;
    }
    if (a.startsWith("--envelope=")) {
      const v = a.slice("--envelope=".length);
      if (v.length === 0) return null;
      envelopePath = v;
      continue;
    }
    if (a.startsWith("-")) {
      return null;
    }
    positional.push(a);
  }
  if (positional.length !== 1 || !envelopePath) return null;
  return { target: positional[0]!, envelopePath, disclosure_decision };
}

function parseUpstreamPreviewArgs(rest: string[]): {
  target: string;
  requestPath: string;
  disclosure_decision: UpstreamDisclosureDecision;
} | null {
  if (rest.length === 0) return null;
  let disclosure_decision: UpstreamDisclosureDecision = "not_requested";
  let requestPath: string | null = null;
  const positional: string[] = [];
  for (const a of rest) {
    if (a === "--disclose-approved") {
      disclosure_decision = "approved";
      continue;
    }
    if (a === "--disclose-refused") {
      disclosure_decision = "refused";
      continue;
    }
    if (a.startsWith("--request=")) {
      const v = a.slice("--request=".length);
      if (v.length === 0) return null;
      requestPath = v;
      continue;
    }
    if (a.startsWith("-")) {
      return null;
    }
    positional.push(a);
  }
  if (positional.length !== 1 || !requestPath) return null;
  return { target: positional[0]!, requestPath, disclosure_decision };
}

function runUpstreamPreview(
  target: string,
  requestPath: string,
  disclosure_decision: UpstreamDisclosureDecision,
): void {
  try {
    if (!fs.existsSync(requestPath)) {
      printJson(
        {
          schema_version: 1,
          ok: false,
          capsule: null,
          disclosure_decision,
          transport_calls: 0,
          network_used: false,
          target_mutated: false,
          repair_applied: false,
          repair_authorized: false,
          external_write: false,
          submission_status: "none",
          error_code: "REQUEST_NOT_FOUND",
          error_message: "Upstream request file not found.",
        },
        1,
      );
    }
    const raw = fs.readFileSync(requestPath, "utf8");
    if (Buffer.byteLength(raw, "utf8") > MAX_UPSTREAM_REQUEST_BYTES) {
      printJson(
        {
          schema_version: 1,
          ok: false,
          capsule: null,
          disclosure_decision,
          transport_calls: 0,
          network_used: false,
          target_mutated: false,
          repair_applied: false,
          repair_authorized: false,
          external_write: false,
          submission_status: "none",
          error_code: "SIZE_LIMIT",
          error_message: "Upstream request exceeds size limit.",
        },
        1,
      );
    }
    let request: unknown;
    try {
      request = JSON.parse(raw);
    } catch {
      printJson(
        {
          schema_version: 1,
          ok: false,
          capsule: null,
          disclosure_decision,
          transport_calls: 0,
          network_used: false,
          target_mutated: false,
          repair_applied: false,
          repair_authorized: false,
          external_write: false,
          submission_status: "none",
          error_code: "MALFORMED_JSON",
          error_message: "Upstream request JSON is malformed.",
        },
        1,
      );
    }
    // CLI never injects a live network transport.
    const result: UpstreamPreviewResult = previewUpstream({
      targetPath: target,
      request,
      disclosure_decision,
      transport: null,
    });
    printJson(result, result.ok ? 0 : 1);
  } catch {
    printJson(
      {
        schema_version: 1,
        ok: false,
        error_code: "INTERNAL",
        error_message: "Upstream preview failed.",
        network_used: false,
        target_mutated: false,
        repair_applied: false,
        repair_authorized: false,
        external_write: false,
        submission_status: "none",
      },
      1,
    );
  }
}

function parseUpstreamActionPreviewArgs(args: string[]): {
  target: string;
  capsulePath: string;
  action: string;
  attachmentsPath: string | null;
} | null {
  const positional: string[] = [];
  let capsulePath: string | null = null;
  let action: string | null = null;
  let attachmentsPath: string | null = null;
  for (const a of args) {
    if (a.startsWith("--capsule=")) {
      const v = a.slice("--capsule=".length);
      if (v.length === 0) return null;
      capsulePath = v;
      continue;
    }
    if (a.startsWith("--action=")) {
      const v = a.slice("--action=".length);
      if (v.length === 0) return null;
      action = v;
      continue;
    }
    if (a.startsWith("--attachments=")) {
      const v = a.slice("--attachments=".length);
      if (v.length === 0) return null;
      attachmentsPath = v;
      continue;
    }
    if (a.startsWith("-")) return null;
    positional.push(a);
  }
  if (positional.length !== 1 || !capsulePath || !action) return null;
  return {
    target: positional[0]!,
    capsulePath,
    action,
    attachmentsPath,
  };
}

function parseUpstreamActionConfirmArgs(args: string[]): {
  target: string;
  confirmation: string;
  decision: string;
} | null {
  const positional: string[] = [];
  let confirmation: string | null = null;
  let decision: string | null = null;
  for (const a of args) {
    if (a.startsWith("--confirmation=")) {
      const v = a.slice("--confirmation=".length);
      if (v.length === 0) return null;
      confirmation = v;
      continue;
    }
    if (a.startsWith("--decision=")) {
      const v = a.slice("--decision=".length);
      if (v.length === 0) return null;
      decision = v;
      continue;
    }
    if (a.startsWith("-")) return null;
    positional.push(a);
  }
  if (positional.length !== 1 || !confirmation || !decision) return null;
  return {
    target: positional[0]!,
    confirmation,
    decision,
  };
}

function runUpstreamActionPreview(parsed: {
  target: string;
  capsulePath: string;
  action: string;
  attachmentsPath: string | null;
}): void {
  try {
    if (!fs.existsSync(parsed.capsulePath)) {
      printJson(
        {
          schema_version: 1,
          ok: false,
          status: "INVALID_INPUT",
          error_code: "CAPSULE_NOT_FOUND",
          error_message: "Capsule file not found.",
          network_used: false,
          target_mutated: false,
          external_write: false,
        },
        1,
      );
    }
    const raw = fs.readFileSync(parsed.capsulePath, "utf8");
    if (Buffer.byteLength(raw, "utf8") > MAX_ACTION_REQUEST_BYTES) {
      printJson(
        {
          schema_version: 1,
          ok: false,
          status: "INVALID_INPUT",
          error_code: "SIZE_LIMIT",
          error_message: "Capsule exceeds size limit.",
          network_used: false,
          external_write: false,
        },
        1,
      );
    }
    let capsule: unknown;
    try {
      capsule = JSON.parse(raw);
    } catch {
      printJson(
        {
          schema_version: 1,
          ok: false,
          status: "INVALID_INPUT",
          error_code: "MALFORMED_JSON",
          error_message: "Capsule JSON is malformed.",
          network_used: false,
          external_write: false,
        },
        1,
      );
    }
    let attachment_manifest: unknown = undefined;
    if (parsed.attachmentsPath) {
      if (!fs.existsSync(parsed.attachmentsPath)) {
        printJson(
          {
            schema_version: 1,
            ok: false,
            status: "INVALID_INPUT",
            error_code: "ATTACHMENTS_NOT_FOUND",
            error_message: "Attachments file not found.",
            network_used: false,
            external_write: false,
          },
          1,
        );
      }
      const araw = fs.readFileSync(parsed.attachmentsPath, "utf8");
      if (Buffer.byteLength(araw, "utf8") > MAX_ACTION_REQUEST_BYTES) {
        printJson(
          {
            schema_version: 1,
            ok: false,
            status: "INVALID_INPUT",
            error_code: "SIZE_LIMIT",
            error_message: "Attachments exceed size limit.",
            network_used: false,
            external_write: false,
          },
          1,
        );
      }
      try {
        attachment_manifest = JSON.parse(araw);
      } catch {
        printJson(
          {
            schema_version: 1,
            ok: false,
            status: "INVALID_INPUT",
            error_code: "MALFORMED_JSON",
            error_message: "Attachments JSON is malformed.",
            network_used: false,
            external_write: false,
          },
          1,
        );
      }
    }
    // Production: no real adapter — capability unavailable; never simulates write.
    const result: ActionPreviewResult = previewUpstreamAction({
      targetPath: parsed.target,
      capsule,
      action: parsed.action,
      attachment_manifest,
      adapter: null,
    });
    printJson(result, result.ok ? 0 : 1);
  } catch {
    printJson(
      {
        schema_version: 1,
        ok: false,
        status: "INVALID_INPUT",
        error_code: "INTERNAL",
        error_message: "Upstream action preview failed.",
        network_used: false,
        external_write: false,
      },
      1,
    );
  }
}

function runUpstreamActionConfirm(parsed: {
  target: string;
  confirmation: string;
  decision: string;
}): void {
  try {
    let token = parsed.confirmation;
    // Allow file path to token (when value is a readable path and not ua1.…).
    if (!token.startsWith("ua1.") && fs.existsSync(token)) {
      const raw = fs.readFileSync(token, "utf8").trim();
      if (Buffer.byteLength(raw, "utf8") > MAX_CONFIRMATION_BYTES) {
        printJson(
          {
            schema_version: 1,
            ok: false,
            status: "INVALID_CONFIRMATION",
            error_code: "SIZE_LIMIT",
            error_message: "Confirmation exceeds size limit.",
            network_used: false,
            external_write: false,
          },
          1,
        );
      }
      token = raw;
    }
    // Production: no real adapter — never requests tokens or simulates success.
    const result: ActionConfirmResult = confirmUpstreamAction({
      targetPath: parsed.target,
      confirmation_token: token,
      decision: parsed.decision,
      adapter: null,
    });
    printJson(result, result.ok ? 0 : 1);
  } catch {
    printJson(
      {
        schema_version: 1,
        ok: false,
        status: "FAILED",
        error_code: "INTERNAL",
        error_message: "Upstream action confirm failed.",
        network_used: false,
        external_write: false,
      },
      1,
    );
  }
}

function runAnalyzePage(
  target: string,
  envelopePath: string,
  disclosure_decision: PageDisclosureDecision,
): void {
  try {
    // Read orchestrator-supplied envelope only; never scrape browser state.
    let raw: string;
    try {
      const st = fs.statSync(envelopePath);
      if (!st.isFile() || st.size > MAX_PAGE_ENVELOPE_BYTES) {
        printJson(
          {
            schema_version: 1,
            ok: false,
            error_code: "ENVELOPE_SIZE",
            error_message: "Page envelope file missing or exceeds size limit.",
            network_used: false,
            target_mutated: false,
            repair_applied: false,
            repair_authorized: false,
            transport_calls: 0,
          },
          1,
        );
      }
      raw = fs.readFileSync(envelopePath, "utf8");
    } catch {
      printJson(
        {
          schema_version: 1,
          ok: false,
          error_code: "ENVELOPE_READ",
          error_message: "Could not read page envelope file.",
          network_used: false,
          target_mutated: false,
          repair_applied: false,
          repair_authorized: false,
          transport_calls: 0,
        },
        1,
      );
    }
    // CLI never injects a live page transport — no hidden network.
    const result: PageAnalysisResult = analyzePage({
      targetPath: target,
      envelope: raw,
      disclosure_decision,
      transport: null,
    });
    printJson(result, result.ok ? 0 : 1);
  } catch {
    printJson(
      {
        schema_version: 1,
        ok: false,
        error_code: "INTERNAL",
        error_message: "Page analysis failed.",
        network_used: false,
        target_mutated: false,
        repair_applied: false,
        repair_authorized: false,
        transport_calls: 0,
      },
      1,
    );
  }
}

/**
 * Parse `lifecycle <operation> <target> [--key=value]`.
 * Nested A/B observations use `--control-json=` / `--treatment-json=`.
 */
function runLifecycleCli(rest: string[]): void {
  const positional = rest.filter((a) => !a.startsWith("-"));
  const flags = rest.filter((a) => a.startsWith("-"));
  if (positional.length !== 2) {
    printJson(usageDiagnosis(), 2);
  }
  const [operation, target] = positional;
  const args: LifecycleDispatchArgs = {
    target: target!,
    operation: operation!,
  };
  for (const f of flags) {
    const eq = f.indexOf("=");
    if (!f.startsWith("--") || eq < 0) {
      printJson(usageDiagnosis(), 2);
    }
    const key = f.slice(2, eq);
    const raw = f.slice(eq + 1);
    switch (key) {
      case "instance-id":
        args.instance_id = raw;
        break;
      case "surface":
        args.surface = raw;
        break;
      case "source-rel":
        args.source_rel = raw;
        break;
      case "checkpoint-id":
        args.checkpoint_id = raw;
        break;
      case "now-ms":
        args.now_ms = Number(raw);
        break;
      case "timestamp-only":
        args.timestamp_only = raw === "true" || raw === "1";
        break;
      case "control-json":
        try {
          args.control = JSON.parse(raw) as unknown;
        } catch {
          printJson(usageDiagnosis(), 2);
        }
        break;
      case "treatment-json":
        try {
          args.treatment = JSON.parse(raw) as unknown;
        } catch {
          printJson(usageDiagnosis(), 2);
        }
        break;
      case "official-source":
        args.official_source = raw;
        break;
      case "version-pin":
        args.version_pin = raw;
        break;
      case "provenance":
        args.provenance = raw;
        break;
      case "signed-history":
        args.signed_history_available = raw === "true" || raw === "1";
        break;
      case "lawful-media":
        args.lawful_media_available = raw === "true" || raw === "1";
        break;
      case "candidate-version":
        args.candidate_version = raw;
        break;
      case "original-fault-absent":
        args.original_fault_absent = raw === "true" || raw === "1";
        break;
      case "core-regressions-passed":
        args.core_regressions_passed = raw === "true" || raw === "1";
        break;
      case "canary-executed":
        args.canary_executed = raw === "true" || raw === "1";
        break;
      case "recipe-id":
        args.recipe_id = raw;
        break;
      case "upstream-ref":
        args.upstream_ref = raw;
        break;
      case "upstream-evidence-digest":
        args.upstream_evidence_digest = raw;
        break;
      case "upstream-verified":
        args.upstream_verified = raw === "true" || raw === "1";
        break;
      default:
        printJson(usageDiagnosis(), 2);
    }
  }
  const result: LifecycleResult = dispatchLifecycle(args);
  printJson(result, result.ok ? 0 : 1);
}

/**
 * Parse `followup <operation> <target> [--request=<json>] [--key=value]`.
 * Target and operation are positional and never overridden by request JSON.
 * Inline flags and --request both pass through the canonical wire parser.
 * Mixing --request with inline request fields is refused (REQUEST_CONFLICT).
 * State is resolved from CHANGEGUARD_FOLLOWUP_STATE_DIR / PLUGIN_DATA / XDG only.
 */
function followupUsageError(): never {
  const result: FollowupResult = {
    schema_version: 1,
    ok: false,
    operation: "status",
    status: "INVALID_INPUT",
    user_resolution: {
      status: "INCONCLUSIVE",
      summary: "Invalid follow-up arguments.",
      receipt_id: "cli_followup_usage",
    },
    upstream_contribution: {
      status: "NONE",
      summary: "No upstream contribution.",
      issue_candidates: [],
      receipt_id: "cli_followup_usage_up",
    },
    subscription: null,
    subscriptions: null,
    disposition: null,
    intents: null,
    probe_plan: null,
    evidence_capsule: null,
    reply_draft: null,
    candidate: null,
    ledger: null,
    session_hint: null,
    evidence: [],
    error_code: "USAGE",
    error_message:
      "Usage: changeguard followup <operation> <isolated-target> [--request=<request.json>] [--issue=…] [--candidate-version=…] …",
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    external_write: false,
    adapter_status: "not_applicable",
    contribution_claim: "none",
  };
  printJson(result, 2);
}

function followupParseFail(
  operation: string,
  code: string,
  message: string,
  exitCode = 1,
): never {
  printJson(
    {
      schema_version: 1,
      ok: false,
      operation,
      status: "INVALID_INPUT",
      error_code: code,
      error_message: message,
      network_used: false,
      target_mutated: false,
      repair_applied: false,
      external_write: false,
      adapter_status: "not_applicable",
      contribution_claim: "none",
    },
    exitCode,
  );
}

/** CLI flag keys that contribute to the request body (not --request itself). */
const FOLLOWUP_INLINE_BODY_FLAGS = new Set([
  "issue",
  "event-json",
  "candidate-version",
  "recipe-id",
  "official-evidence-item-digest",
  "official-evidence-ref",
  "baseline-target",
  "measurement-profile-id",
  "now-ms",
]);

function runFollowupCli(rest: string[]): void {
  const positional = rest.filter((a) => !a.startsWith("-"));
  const flags = rest.filter((a) => a.startsWith("-"));
  if (positional.length !== 2) {
    followupUsageError();
  }
  const [operation, target] = positional;
  if (!operation || !target || !isFollowupOperation(operation)) {
    followupUsageError();
  }

  let requestPath: string | null = null;
  const inlineBody: Record<string, unknown> = {};
  let hasInlineBody = false;

  for (const f of flags) {
    const eq = f.indexOf("=");
    if (!f.startsWith("--") || eq < 0) {
      followupUsageError();
    }
    const key = f.slice(2, eq);
    const raw = f.slice(eq + 1);
    switch (key) {
      case "request":
        if (raw.length === 0) followupUsageError();
        requestPath = raw;
        break;
      case "issue":
        if (raw.length === 0) followupUsageError();
        inlineBody.issue = raw;
        hasInlineBody = true;
        break;
      case "event-json": {
        let eventParsed: unknown;
        try {
          eventParsed = JSON.parse(raw) as unknown;
        } catch {
          followupUsageError();
        }
        inlineBody.event = eventParsed;
        hasInlineBody = true;
        break;
      }
      case "candidate-version":
        if (raw.length === 0) followupUsageError();
        inlineBody.candidate_version = raw;
        hasInlineBody = true;
        break;
      case "recipe-id":
        if (raw.length === 0) followupUsageError();
        inlineBody.recipe_id = raw;
        hasInlineBody = true;
        break;
      case "official-evidence-item-digest":
        if (raw.length === 0) followupUsageError();
        inlineBody.official_evidence_item_digest = raw;
        hasInlineBody = true;
        break;
      case "official-evidence-ref":
        if (raw.length === 0) followupUsageError();
        inlineBody.official_evidence_ref = raw;
        hasInlineBody = true;
        break;
      case "baseline-target":
        if (raw.length === 0) followupUsageError();
        inlineBody.baseline_target = raw;
        hasInlineBody = true;
        break;
      case "measurement-profile-id":
        if (raw.length === 0) followupUsageError();
        inlineBody.measurement_profile_id = raw;
        hasInlineBody = true;
        break;
      case "now-ms": {
        const n = Number(raw);
        if (!Number.isFinite(n)) followupUsageError();
        inlineBody.now_ms = n;
        hasInlineBody = true;
        break;
      }
      // Removed public flags — refuse closed (no silent ignore).
      case "state-dir":
      case "original-fault-absent":
      case "core-regressions-passed":
      case "verified":
        followupUsageError();
        break;
      default:
        // Unknown flags, including removed surfaces, fail usage.
        if (FOLLOWUP_INLINE_BODY_FLAGS.has(key)) {
          followupUsageError();
        }
        followupUsageError();
    }
  }

  if (requestPath && hasInlineBody) {
    followupParseFail(
      operation,
      "REQUEST_CONFLICT",
      "Do not mix --request with inline follow-up fields; use exactly one source.",
    );
  }

  let bodyFields: Partial<FollowupDispatchArgs> = {};
  if (requestPath) {
    if (!fs.existsSync(requestPath)) {
      followupParseFail(
        operation,
        "REQUEST_NOT_FOUND",
        "Follow-up request file not found.",
      );
    }
    const raw = fs.readFileSync(requestPath, "utf8");
    if (Buffer.byteLength(raw, "utf8") > MAX_FOLLOWUP_REQUEST_BYTES) {
      followupParseFail(
        operation,
        "SIZE_LIMIT",
        "Follow-up request exceeds size limit.",
      );
    }
    const parsed = parseFollowupRequestJson(raw, operation);
    if (!parsed.ok) {
      followupParseFail(operation, parsed.code, parsed.message);
    }
    bodyFields = parsed.fields;
  } else if (hasInlineBody) {
    const parsed = parseFollowupWireBody(inlineBody, operation);
    if (!parsed.ok) {
      followupParseFail(operation, parsed.code, parsed.message);
    }
    bodyFields = parsed.fields;
  }

  const args: FollowupDispatchArgs = {
    target,
    operation,
    ...bodyFields,
  };
  const result: FollowupResult = dispatchFollowup(args);
  printJson(result, result.ok ? 0 : 1);
}

export function runCli(argv: string[]): void {
  const args = argv.slice(2);
  if (args.length === 0) {
    printJson(usageDiagnosis(), 2);
  }
  const [cmd, ...rest] = args;

  try {
    if (cmd === "diagnose") {
      if (rest.length !== 1 || isFlag(rest[0]!)) {
        printJson(usageDiagnosis(), 2);
      }
      const result = diagnose(rest[0]!);
      printJson(result, result.ok ? 0 : 1);
    }

    if (cmd === "impact") {
      const parsed = parseImpactArgs(rest);
      if (!parsed) {
        printJson(usageDiagnosis(), 2);
      }
      runImpact(parsed.target, parsed.disclosure_decision);
      return;
    }

    if (cmd === "analyze-page") {
      const parsed = parseAnalyzePageArgs(rest);
      if (!parsed) {
        pageUsageError();
      }
      runAnalyzePage(
        parsed.target,
        parsed.envelopePath,
        parsed.disclosure_decision,
      );
      return;
    }

    if (cmd === "upstream-preview") {
      const parsed = parseUpstreamPreviewArgs(rest);
      if (!parsed) {
        upstreamUsageError();
      }
      runUpstreamPreview(
        parsed.target,
        parsed.requestPath,
        parsed.disclosure_decision,
      );
      return;
    }

    if (cmd === "upstream-action-preview") {
      const parsed = parseUpstreamActionPreviewArgs(rest);
      if (!parsed) {
        actionPreviewUsageError();
      }
      runUpstreamActionPreview(parsed);
      return;
    }

    if (cmd === "upstream-action-confirm") {
      const parsed = parseUpstreamActionConfirmArgs(rest);
      if (!parsed) {
        actionConfirmUsageError();
      }
      runUpstreamActionConfirm(parsed);
      return;
    }

    if (cmd === "repair-preview") {
      if (rest.length !== 1 || isFlag(rest[0]!)) {
        printJson(usageDiagnosis(), 2);
      }
      // Production: host-derived capability + production_unknown (fail-closed).
      // Env CHANGEGUARD_INTERNAL_FIXTURE_SEAM=1 alone is not authorization;
      // exact target must also prove disposable isolation (mkdtemp under OS temp).
      const target = rest[0]!;
      const result: RepairResult = previewRepair(
        target,
        resolvePublicRepairCapability(process.env, process.platform, target),
      );
      printJson(result, result.ok ? 0 : 1);
    }

    if (cmd === "repair-apply") {
      if (rest.length !== 2 || isFlag(rest[0]!) || isFlag(rest[1]!)) {
        printJson(usageDiagnosis(), 2);
      }
      // Same exact-target capability binding as preview — authorization from
      // a disposable preview cannot upgrade an unproven apply target.
      const target = rest[0]!;
      const result: RepairResult = applyRepair(target, {
        authorization: rest[1]!,
        ...resolvePublicRepairCapability(process.env, process.platform, target),
      });
      printJson(result, result.ok ? 0 : 1);
    }

    if (cmd === "verify") {
      if (rest.length !== 1 || isFlag(rest[0]!)) {
        printJson(usageDiagnosis(), 2);
      }
      const result: RepairResult = verifyRepair(rest[0]!);
      printJson(result, result.ok ? 0 : 1);
    }

    if (cmd === "rollback") {
      if (rest.length !== 1 || isFlag(rest[0]!)) {
        printJson(usageDiagnosis(), 2);
      }
      const result: RepairResult = rollbackRepair(rest[0]!);
      printJson(result, result.ok ? 0 : 1);
    }

    if (cmd === "scan") {
      if (rest.length !== 1 || isFlag(rest[0]!)) scanUsageError("scan");
      runScan(rest[0]!);
      return;
    }

    if (cmd === "scan-system") {
      const flags = rest.filter((a) => a.startsWith("-"));
      const positional = rest.filter((a) => !a.startsWith("-"));
      if (positional.length !== 0) scanUsageError("scan-system");
      for (const f of flags) {
        if (!f.startsWith("--state-dir=")) scanUsageError("scan-system");
      }
      runScanSystem(parseStateDir(flags));
      return;
    }

    if (cmd === "session-start") {
      const positional = rest.filter((a) => !a.startsWith("-"));
      const flags = rest.filter((a) => a.startsWith("-"));
      if (positional.length !== 1) scanUsageError("session-start");
      for (const f of flags) {
        if (!f.startsWith("--hook-trust=")) scanUsageError("session-start");
      }
      const trust = parseHookTrust(flags);
      runSession(positional[0]!, trust);
      return;
    }

    if (cmd === "lifecycle") {
      runLifecycleCli(rest);
      return;
    }

    if (cmd === "followup") {
      runFollowupCli(rest);
      return;
    }

    if (cmd === "platform-status") {
      runPlatformStatus(rest);
      return;
    }

    if (cmd === "platform-receipt-validate") {
      runPlatformReceiptValidate(rest);
      return;
    }

    if (cmd === "demo") {
      runDemoCli(rest);
      return;
    }

    printJson(usageDiagnosis(), 2);
  } catch {
    const result: DiagnosisResult = {
      schema_version: 1,
      ok: false,
      diagnosis_state: "INCONCLUSIVE",
      incident_fingerprint: null,
      user_resolution: {
        status: "INCONCLUSIVE",
        summary: "Command failed safely.",
        receipt_id: "cli_error_user",
      },
      upstream_contribution: {
        status: "NONE",
        summary: "No upstream contribution.",
        issue_candidates: [],
        receipt_id: "cli_error_upstream",
      },
      evidence: [],
      error_code: "INTERNAL",
      error_message: "Command failed.",
      network_used: false,
      target_mutated: false,
      repair_applied: false,
    };
    printJson(result, 1);
  }
}

runCli(process.argv);
