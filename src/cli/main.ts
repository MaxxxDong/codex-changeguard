/**
 * ChangeGuard Rescue CLI — public seams share one core with MCP.
 * Commands:
 *   changeguard diagnose <isolated-target>
 *   changeguard impact <isolated-target> [--disclose-approved|--disclose-refused]
 *   changeguard analyze-page <isolated-target> --envelope=<page.json> [--disclose-approved|--disclose-refused]
 *   changeguard upstream-preview <isolated-target> --request=<request.json> [--disclose-approved|--disclose-refused]
 *   changeguard repair-preview <isolated-target>
 *   changeguard repair-apply <isolated-target> <authorization-token>
 *   changeguard verify <isolated-target>
 *   changeguard rollback <isolated-target>
 *   changeguard scan <inventory-root>          (fixture inventory adapter)
 *   changeguard scan-system                    (production registered system adapter)
 *   changeguard platform-status [--receipt=<path>]  (Ticket 14 support level; default PREVIEW)
 *   changeguard session-start <inventory-root> [--hook-trust=…]  (manual fixture path)
 *   changeguard lifecycle <operation> <isolated-target> [--key=value …]
 */
import fs from "node:fs";
import { diagnose } from "../core/diagnose.js";
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
  loadAndEvaluateReceiptFile,
  realMachineRunnerPlan,
  windows11SupportStatus,
} from "../platform/index.js";

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
      "Usage: changeguard diagnose|impact|analyze-page|upstream-preview|repair-preview|repair-apply|verify|rollback|scan|scan-system|platform-status|session-start|lifecycle …",
    network_used: false,
    target_mutated: false,
    repair_applied: false,
  };
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
  };
  printJson(result, 2);
}

function isFlag(s: string): boolean {
  return s.startsWith("-");
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

    if (cmd === "repair-preview") {
      if (rest.length !== 1 || isFlag(rest[0]!)) {
        printJson(usageDiagnosis(), 2);
      }
      const result: RepairResult = previewRepair(rest[0]!);
      printJson(result, result.ok ? 0 : 1);
    }

    if (cmd === "repair-apply") {
      if (rest.length !== 2 || isFlag(rest[0]!) || isFlag(rest[1]!)) {
        printJson(usageDiagnosis(), 2);
      }
      const result: RepairResult = applyRepair(rest[0]!, {
        authorization: rest[1]!,
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

    if (cmd === "platform-status") {
      const flags = rest.filter((a) => a.startsWith("-"));
      const positional = rest.filter((a) => !a.startsWith("-"));
      if (positional.length !== 0) {
        printJson(
          {
            schema_version: 1,
            ok: false,
            error_code: "USAGE",
            error_message:
              "Usage: changeguard platform-status [--receipt=<path>] [--plan]",
            network_used: false,
            target_mutated: false,
            repair_applied: false,
          },
          2,
        );
      }
      let receiptPath: string | null = null;
      let showPlan = false;
      for (const f of flags) {
        if (f.startsWith("--receipt=")) {
          receiptPath = f.slice("--receipt=".length);
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
        } else if (f === "--plan") {
          showPlan = true;
        } else {
          printJson(
            {
              schema_version: 1,
              ok: false,
              error_code: "USAGE",
              error_message:
                "Usage: changeguard platform-status [--receipt=<path>] [--plan]",
              network_used: false,
              target_mutated: false,
              repair_applied: false,
            },
            2,
          );
        }
      }
      if (showPlan) {
        printJson(
          {
            schema_version: 1,
            ok: true,
            plan: realMachineRunnerPlan(),
            status: windows11SupportStatus(null),
            network_used: false,
            target_mutated: false,
            repair_applied: false,
          },
          0,
        );
      }
      if (receiptPath) {
        const loaded = loadAndEvaluateReceiptFile(receiptPath);
        printJson(
          {
            schema_version: 1,
            ok: loaded.ok,
            status: loaded.status,
            error_code: loaded.error_code,
            error_message: loaded.error_message,
            network_used: false,
            target_mutated: false,
            repair_applied: false,
          },
          // Exit 0 when evaluation succeeded (including honest PREVIEW).
          // Nonzero only on load/parse failure.
          loaded.ok ? 0 : 1,
        );
      }
      // No receipt: honest PREVIEW default (never fabricate FULL).
      const status = windows11SupportStatus(null);
      printJson(
        {
          schema_version: 1,
          ok: true,
          status,
          network_used: false,
          target_mutated: false,
          repair_applied: false,
        },
        0,
      );
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
