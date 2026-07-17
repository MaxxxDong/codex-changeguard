/**
 * ChangeGuard Rescue CLI — public seams share one core with MCP.
 * Commands:
 *   changeguard diagnose <isolated-target>
 *   changeguard impact <isolated-target> [--disclose-approved|--disclose-refused]
 *   changeguard repair-preview <isolated-target>
 *   changeguard repair-apply <isolated-target> <authorization-token>
 *   changeguard verify <isolated-target>
 *   changeguard rollback <isolated-target>
 *   changeguard scan <inventory-root>          (fixture inventory adapter)
 *   changeguard scan-system                    (production registered system adapter)
 *   changeguard session-start <inventory-root> [--hook-trust=…]  (manual fixture path)
 */
import { diagnose } from "../core/diagnose.js";
import {
  applyRepair,
  previewRepair,
  rollbackRepair,
  verifyRepair,
} from "../core/recovery/index.js";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import { assessImpact } from "../impact/assess.js";
import type { DiagnosisResult } from "../core/types.js";
import type { RepairResult } from "../core/recovery/types.js";
import type { DisclosureDecision } from "../evidence/types.js";
import type { ImpactAssessmentResult } from "../impact/types.js";
import { scanInstances } from "../instances/scan.js";
import type { HookTrustState, ScanResult } from "../instances/types.js";
import { runSessionStart } from "../hooks/session-start.js";

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
      "Usage: changeguard diagnose|impact|repair-preview|repair-apply|verify|rollback|scan|scan-system|session-start …",
    network_used: false,
    target_mutated: false,
    repair_applied: false,
  };
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
