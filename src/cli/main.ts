/**
 * ChangeGuard Rescue CLI — public seam: `changeguard diagnose <isolated-target>`
 * One shared core with MCP. Generic path-free errors.
 */
import { diagnose } from "../core/diagnose.js";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import type { DiagnosisResult } from "../core/types.js";

function printResult(result: DiagnosisResult, exitCode: number): never {
  const text = assertNoLeakPaths(redactText(JSON.stringify(result, null, 2)));
  process.stdout.write(text + "\n");
  process.exit(exitCode);
}

function usageError(): never {
  const result: DiagnosisResult = {
    schema_version: 1,
    ok: false,
    diagnosis_state: "INCONCLUSIVE",
    incident_fingerprint: null,
    user_resolution: {
      status: "INCONCLUSIVE",
      summary: "Invalid arguments.",
      receipt_id: "cli_usage",
    },
    upstream_contribution: {
      status: "NONE",
      summary: "No upstream contribution.",
      issue_candidates: [],
      receipt_id: "cli_usage",
    },
    evidence: [],
    error_code: "USAGE",
    error_message:
      "Usage: changeguard diagnose <isolated-target-directory>",
    network_used: false,
    target_mutated: false,
    repair_applied: false,
  };
  printResult(result, 2);
}

export function runCli(argv: string[]): void {
  // argv: node entry ...  OR bin forwards to this module with process.argv
  const args = argv.slice(2);
  if (args.length === 0) {
    usageError();
  }
  const [cmd, ...rest] = args;
  if (cmd !== "diagnose") {
    usageError();
  }
  if (rest.length !== 1) {
    usageError();
  }
  const target = rest[0]!;
  // Reject unknown flags / extra options
  if (target.startsWith("-")) {
    usageError();
  }

  try {
    const result = diagnose(target);
    const exit = result.ok ? 0 : 1;
    printResult(result, exit);
  } catch (err) {
    const result: DiagnosisResult = {
      schema_version: 1,
      ok: false,
      diagnosis_state: "INCONCLUSIVE",
      incident_fingerprint: null,
      user_resolution: {
        status: "INCONCLUSIVE",
        summary: "Diagnosis failed safely.",
        receipt_id: "cli_error",
      },
      upstream_contribution: {
        status: "NONE",
        summary: "No upstream contribution.",
        issue_candidates: [],
        receipt_id: "cli_error",
      },
      evidence: [],
      error_code: "INTERNAL",
      error_message: "Diagnosis failed.",
      network_used: false,
      target_mutated: false,
      repair_applied: false,
    };
    void err;
    printResult(result, 1);
  }
}

runCli(process.argv);
