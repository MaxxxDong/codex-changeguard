/**
 * Future real-machine Windows 11 Scenario Harness runner entry (Ticket 14).
 *
 * Safe on every host (including Windows):
 * - never executes Codex / signed app binaries
 * - never writes WindowsApps, Program Files, registry policy, or system security settings
 * - never elevates privileges
 * - only loads/validates a receipt JSON and evaluates PREVIEW/FULL
 * - never seals a live harness witness (external JSON alone cannot Full)
 *
 * Real scenario execution remains operator-driven; this entry is the
 * load/validate/evaluate seam for future automation. A future controlled
 * in-process Windows harness may call sealWindowsLiveHarnessWitness after
 * a real run — production CLI/MCP and this plan do not.
 */
import path from "node:path";
import {
  PathSafetyError,
  readAbsoluteRegularFile,
} from "../../core/path-safety.js";
import { WINDOWS11_CRITICAL_SCENARIOS } from "./critical-scenarios.js";
import { parsePlatformSupportReceipt } from "./receipt.js";
import { windows11SupportStatus } from "./status.js";
import type { PlatformSupportStatus } from "./types.js";

const MAX_RECEIPT_BYTES = 256 * 1024;

export interface RealMachineRunnerPlan {
  schema_version: 1;
  platform: "windows";
  mode: "validate_receipt_only";
  critical_scenarios: Array<{ id: string; title: string }>;
  forbidden_actions: string[];
  notes: string[];
}

/** Static plan describing what a real-machine run must cover. */
export function realMachineRunnerPlan(): RealMachineRunnerPlan {
  return {
    schema_version: 1,
    platform: "windows",
    mode: "validate_receipt_only",
    critical_scenarios: WINDOWS11_CRITICAL_SCENARIOS.map((s) => ({
      id: s.id,
      title: s.title,
    })),
    forbidden_actions: [
      "execute_codex_or_signed_binaries",
      "write_windowsapps",
      "write_program_files",
      "write_registry_policy",
      "modify_system_security_settings",
      "privilege_elevation",
      "dump_body_collection",
      "broad_home_crawl",
    ],
    notes: [
      "This entry validates operator-supplied receipts only.",
      "FULL requires host_kind=real_machine on Windows 11 with all critical scenarios passed AND a process-local live harness witness.",
      "External JSON / file / CLI / MCP alone cannot authorize FULL (capped at PREVIEW).",
      "Synthetic and cross_platform_ci receipts remain PREVIEW.",
      "No live witness is sealed by this validate-receipt-only runner.",
    ],
  };
}

export interface LoadReceiptResult {
  ok: boolean;
  status: PlatformSupportStatus;
  error_code: string | null;
  error_message: string | null;
}

function pathSafetyToLoadError(e: PathSafetyError): {
  error_code: string;
  error_message: string;
} {
  switch (e.code) {
    case "SYMLINK_ESCAPE":
      return {
        error_code: "SYMLINK_REFUSED",
        error_message: "Symlink receipt path refused.",
      };
    case "TARGET_NOT_FOUND":
    case "CANDIDATE_NOT_FOUND":
      return {
        error_code: "NOT_FOUND",
        error_message: "Receipt file not found.",
      };
    case "SIZE_LIMIT":
      return {
        error_code: "SIZE_LIMIT",
        error_message: "Receipt file exceeds size limit.",
      };
    case "INVALID_TARGET":
    case "INVALID_CANDIDATE":
    case "INVALID_PATH":
      return {
        error_code: "NOT_A_FILE",
        error_message: "Receipt path is not a regular file.",
      };
    case "TOCTOU":
      return {
        error_code: "TOCTOU",
        error_message: "Receipt path refused (path changed during read).",
      };
    default:
      return {
        error_code: e.code || "PATH_REFUSED",
        error_message: e.message || "Receipt path refused.",
      };
  }
}

/**
 * Load a receipt file (JSON) and evaluate Windows 11 support status.
 * Read-only; reuses path-safety invariants (parent not symlink, no leaf
 * symlink segments, regular file, size limit). External file loads never
 * receive a live witness — status remains at most PREVIEW.
 */
export function loadAndEvaluateReceiptFile(
  receiptPath: string,
  options?: { now?: () => Date },
): LoadReceiptResult {
  if (typeof receiptPath !== "string" || receiptPath.length === 0) {
    const status = windows11SupportStatus(null, options);
    return {
      ok: false,
      status,
      error_code: "INVALID_PATH",
      error_message: "Receipt path is required.",
    };
  }
  // Normalize for stable error surfaces; actual open uses path-safety.
  void path.resolve(receiptPath);

  let text: string;
  try {
    text = readAbsoluteRegularFile(receiptPath, MAX_RECEIPT_BYTES).toString(
      "utf8",
    );
  } catch (e) {
    const status = windows11SupportStatus(null, options);
    if (e instanceof PathSafetyError) {
      const mapped = pathSafetyToLoadError(e);
      return {
        ok: false,
        status,
        error_code: mapped.error_code,
        error_message: mapped.error_message,
      };
    }
    return {
      ok: false,
      status,
      error_code: "READ_ERROR",
      error_message: "Failed to read receipt file.",
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(text) as unknown;
  } catch {
    const status = windows11SupportStatus(null, options);
    return {
      ok: false,
      status,
      error_code: "INVALID_JSON",
      error_message: "Receipt is not valid JSON.",
    };
  }
  // Structural parse first so callers get clear errors; status also re-validates.
  // Never pass a liveWitness here — file/CLI/MCP cannot upgrade to Full.
  try {
    parsePlatformSupportReceipt(json);
  } catch (e) {
    const status = windows11SupportStatus(null, options);
    return {
      ok: false,
      status,
      error_code:
        e instanceof Error && "code" in e
          ? String((e as { code: string }).code)
          : "INVALID_RECEIPT",
      error_message:
        e instanceof Error ? e.message : "Receipt validation failed.",
    };
  }
  const status = windows11SupportStatus(json, options);
  return {
    ok: true,
    status,
    error_code: null,
    error_message: null,
  };
}
