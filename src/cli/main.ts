/**
 * ChangeGuard Rescue CLI — public seams share one core with MCP.
 * Commands:
 *   changeguard diagnose <isolated-target>
 *   changeguard repair-preview <isolated-target>
 *   changeguard repair-apply <isolated-target> <authorization-binding>
 *   changeguard verify <isolated-target>
 *   changeguard rollback <isolated-target>
 */
import { diagnose } from "../core/diagnose.js";
import {
  applyRepair,
  previewRepair,
  rollbackRepair,
  verifyRepair,
} from "../core/recovery/index.js";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import type { DiagnosisResult } from "../core/types.js";
import type { RepairResult } from "../core/recovery/types.js";

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
      "Usage: changeguard diagnose|repair-preview|repair-apply|verify|rollback <isolated-target> [authorization]",
    network_used: false,
    target_mutated: false,
    repair_applied: false,
  };
}

function isFlag(s: string): boolean {
  return s.startsWith("-");
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
