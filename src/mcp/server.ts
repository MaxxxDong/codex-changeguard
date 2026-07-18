/**
 * ChangeGuard MCP server — shared core with Rescue CLI.
 * Tools: diagnose (read-only) + Ticket 02 recovery tools (authorized mutation
 * only under an isolated target via registered recovery operations) + Ticket 03
 * multi-instance scan / SessionStart tools (state writes only under PLUGIN_DATA)
 * + Ticket 05 untrusted page-evidence analysis (orchestrator-supplied envelope)
 * + Ticket 06 lifecycle (KNOWN_GOOD / retention / A-B / canary / supersession)
 * + Ticket 10 upstream draft preview (local-only capsule; never external write)
 * + Ticket 11 confirmed upstream action preview/confirm (no real adapter by default)
 * + Ticket 13 platform status / receipt validation (macOS capabilities; no harness spawn)
 * + Ticket 14 Windows 11 support status (PREVIEW without real-machine host receipt)
 * + Ticket 15 Linux/WSL/enterprise capability matrix (Limited/Read-only without real-machine receipt).
 *
 * Wire protocol: newline-delimited JSON-RPC 2.0 over stdio.
 * Request frames are accumulated as bounded bytes (not unbounded readline).
 */
import { diagnose } from "../core/diagnose.js";
import { MAX_MCP_REQUEST_BYTES } from "../core/limits.js";
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
import type { DiagnosisResult } from "../core/types.js";
import type { RepairResult } from "../core/recovery/types.js";
import { assessImpact } from "../impact/assess.js";
import type { ImpactAssessmentResult } from "../impact/types.js";
import type { DisclosureDecision } from "../evidence/types.js";
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

const PLATFORM_ADAPTERS = new Set<AdapterId>([
  "unknown",
  "macos",
  "windows",
  "linux",
  "wsl",
  "enterprise_managed",
]);

const TOOL_DIAGNOSE = "changeguard_diagnose";
const TOOL_IMPACT = "changeguard_impact";
const TOOL_ANALYZE_PAGE = "changeguard_analyze_page";
const TOOL_UPSTREAM_PREVIEW = "changeguard_upstream_preview";
const TOOL_UPSTREAM_ACTION_PREVIEW = "changeguard_upstream_action_preview";
const TOOL_UPSTREAM_ACTION_CONFIRM = "changeguard_upstream_action_confirm";
const TOOL_REPAIR_PREVIEW = "changeguard_repair_preview";
const TOOL_REPAIR_APPLY = "changeguard_repair_apply";
const TOOL_VERIFY = "changeguard_verify";
const TOOL_ROLLBACK = "changeguard_rollback";
const TOOL_SCAN = "changeguard_scan";
const TOOL_SCAN_SYSTEM = "changeguard_scan_system";
const TOOL_SESSION = "changeguard_session_start";
const TOOL_LIFECYCLE = "changeguard_lifecycle";
const TOOL_PLATFORM_STATUS = "changeguard_platform_status";
const TOOL_PLATFORM_RECEIPT = "changeguard_platform_receipt_validate";

const KNOWN_TOOLS = new Set([
  TOOL_DIAGNOSE,
  TOOL_IMPACT,
  TOOL_ANALYZE_PAGE,
  TOOL_UPSTREAM_PREVIEW,
  TOOL_UPSTREAM_ACTION_PREVIEW,
  TOOL_UPSTREAM_ACTION_CONFIRM,
  TOOL_REPAIR_PREVIEW,
  TOOL_REPAIR_APPLY,
  TOOL_VERIFY,
  TOOL_ROLLBACK,
  TOOL_SCAN,
  TOOL_SCAN_SYSTEM,
  TOOL_SESSION,
  TOOL_LIFECYCLE,
  TOOL_PLATFORM_STATUS,
  TOOL_PLATFORM_RECEIPT,
]);

/** Extra top-level tools/call params beyond name/arguments are refused. */
const TOOLS_CALL_TOP_KEYS = new Set(["name", "arguments"]);

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
}

function safeJson(value: unknown): string {
  return assertNoLeakPaths(redactText(JSON.stringify(value)));
}

function send(msg: unknown): void {
  process.stdout.write(safeJson(msg) + "\n");
}

function errorResponse(
  id: string | number | null | undefined,
  code: number,
  message: string,
): void {
  send({
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code, message: assertNoLeakPaths(redactText(message)) },
  });
}

function resultResponse(
  id: string | number | null | undefined,
  result: unknown,
): void {
  send({ jsonrpc: "2.0", id: id ?? null, result });
}

function toolSchemas() {
  const targetProp = {
    type: "string",
    description: "Absolute or relative path to an isolated fixture/target directory.",
  };
  return [
    {
      name: TOOL_DIAGNOSE,
      description:
        "Read-only ChangeGuard diagnosis of an isolated target directory. Returns DiagnosisResult / IncidentFingerprint. Never mutates the target or uses the network.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target"],
        properties: { target: targetProp },
      },
    },
    {
      name: TOOL_IMPACT,
      description:
        "Read-only official-evidence Impact Card for an isolated target. Builds a disclosure manifest first; refused disclosure uses the local snapshot and never calls transport. No network sockets in-process.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target"],
        properties: {
          target: targetProp,
          disclosure_decision: {
            type: "string",
            enum: ["approved", "refused", "not_requested"],
            description:
              "Disclosure authorization. Default not_requested. Approved without an injected transport uses the stale snapshot fallback.",
          },
        },
      },
    },
    {
      name: TOOL_ANALYZE_PAGE,
      description:
        "Analyze an orchestrator-supplied untrusted page-evidence envelope against a local isolated target fingerprint. Quarantines prompt injection; converts page commands only to candidate-only Repair DSL (never authorize/apply). Never reads cookies/storage/tokens. Production never injects page transport.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target", "envelope"],
        properties: {
          target: targetProp,
          envelope: {
            type: "object",
            description:
              "Bounded page-evidence envelope: schema_version, url, page_mode, visible_title?, visible_text, metadata?. No cookies/tokens/storage/request fields.",
          },
          disclosure_decision: {
            type: "string",
            enum: ["approved", "refused", "not_requested"],
            description:
              "Disclosure for optional public page transport. Default not_requested. Production MCP never injects transport (transport_calls: 0).",
          },
        },
      },
    },
    {
      name: TOOL_UPSTREAM_PREVIEW,
      description:
        "Generate a local-only Upstream Submission Capsule (preview). Routes among GitHub Issue / Discussions / Bugcrowd / OpenAI Support; deduplicates; sanitizes optional doctor JSON; never performs external write, reaction, upload, or token/auth. Production never injects form transport.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target", "request"],
        properties: {
          target: targetProp,
          request: {
            type: "object",
            description:
              "Bounded upstream preview request (case_kind, surface, platform, actual_behavior, technical_signals, reproduction, observed_facts, duplicate_search, evidence_delta, optional doctor_json, privacy_review). additionalProperties false; no tokens/cookies/session.",
          },
          disclosure_decision: {
            type: "string",
            enum: ["approved", "refused", "not_requested"],
            description:
              "Disclosure for optional official form refresh. Default not_requested. Production MCP never injects transport (transport_calls: 0).",
          },
        },
      },
    },
    {
      name: TOOL_UPSTREAM_ACTION_PREVIEW,
      description:
        "Ticket 11: separately preview one confirmed upstream action (create_issue, comment_with_delta, react_upvote, subscribe, attachment_upload) bound to a valid Ticket 10 PREVIEW_READY capsule. Emits a one-shot confirmation binding. Production injects no real adapter; never requests tokens/cookies/session.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target", "capsule", "action"],
        properties: {
          target: targetProp,
          capsule: {
            type: "object",
            description:
              "Ticket 10 UpstreamSubmissionCapsule. Only PREVIEW_READY capsules with valid integrity/privacy/recommendation may become actions.",
          },
          action: {
            type: "string",
            enum: [
              "create_issue",
              "comment_with_delta",
              "react_upvote",
              "subscribe",
              "attachment_upload",
            ],
            description: "Separately previewed action kind.",
          },
          attachment_manifest: {
            type: "object",
            description:
              "Optional attachment manifest (required for attachment_upload). Privacy flags must all be true; no tokens/paths.",
          },
        },
      },
    },
    {
      name: TOOL_UPSTREAM_ACTION_CONFIRM,
      description:
        "Ticket 11: confirm or cancel a one-shot upstream action confirmation. Cancellation/auth unavailable remain pure draft and never simulate success. Production injects no real gh/browser adapter (ADAPTER_UNAVAILABLE). Host may inject adapter outside this server.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target", "confirmation_token", "decision"],
        properties: {
          target: targetProp,
          confirmation_token: {
            type: "string",
            description:
              "One-shot confirmation token from upstream-action-preview (ua1.…). Not an access token.",
          },
          decision: {
            type: "string",
            enum: ["confirm", "cancel"],
            description: "User decision for this exact bound action.",
          },
        },
      },
    },
    {
      name: TOOL_REPAIR_PREVIEW,
      description:
        "Preview a bounded Repair Capsule for an isolated protected-process target. No mutation.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target"],
        properties: { target: targetProp },
      },
    },
    {
      name: TOOL_REPAIR_APPLY,
      description:
        "Apply one experimental repair after exact scope-bound authorization. Auto-rolls back on verification failure.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target", "authorization"],
        properties: {
          target: targetProp,
          authorization: {
            type: "string",
            description:
              "Self-contained authorization token from repair-preview (cg1.…).",
          },
        },
      },
    },
    {
      name: TOOL_VERIFY,
      description:
        "Verify that the original failure no longer reproduces and core health checks pass.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target"],
        properties: { target: targetProp },
      },
    },
    {
      name: TOOL_ROLLBACK,
      description:
        "Explicit rollback restoring exact original bytes from the verified backup.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target"],
        properties: { target: targetProp },
      },
    },
    {
      name: TOOL_SCAN,
      description:
        "Deterministic multi-instance / version-fingerprint scan over an isolated inventory fixture. Returns ScanResult. Never executes discovered binaries for version, never exposes raw paths, never uses the network.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target"],
        properties: {
          target: {
            type: "string",
            description:
              "Absolute or relative path to an isolated inventory root (inventory.json).",
          },
        },
      },
    },
    {
      name: TOOL_SCAN_SYSTEM,
      description:
        "Production registered system adapter: enumerates bounded known Codex candidates (Desktop, PATH, package roots, MSIX, WSL) without executing them. Returns ScanResult with hashes/aliases only. Requires state_dir (or PLUGIN_DATA).",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["state_dir"],
        properties: {
          state_dir: {
            type: "string",
            description:
              "Writable ChangeGuard state directory (typically under PLUGIN_DATA). Never the session cwd.",
          },
        },
      },
    },
    {
      name: TOOL_SESSION,
      description:
        "Trusted SessionStart equivalent over an isolated inventory fixture: silent when fingerprint unchanged; otherwise bounded read-only health check. Hook trust must be explicit. Packaged SessionStart uses the dedicated PLUGIN_ROOT entrypoint.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target"],
        properties: {
          target: {
            type: "string",
            description: "Isolated inventory root for SessionStart scan.",
          },
          hook_trust: {
            type: "string",
            enum: ["trusted", "untrusted", "skipped", "failed"],
            description: "Hook trust state (default trusted).",
          },
        },
      },
    },
    {
      name: TOOL_LIFECYCLE,
      description:
        "Ticket 06 KNOWN_GOOD / retention / A/B update-regression / exact-instance surface rollback / CLI-Desktop version preview / canary / supersession. Mutations only under the isolated target ChangeGuard lifecycle state.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["target", "operation"],
        properties: {
          target: targetProp,
          operation: {
            type: "string",
            description:
              "status|record_repair_backup|record_successful_start|record_known_good|apply_retention|assess_update_regression|rollback_surface|cli_version_rollback_preview|desktop_version_rollback_preview|canary|supersede_recipe",
          },
          instance_id: { type: "string" },
          surface: { type: "string" },
          source_rel: { type: "string" },
          checkpoint_id: { type: "string" },
          now_ms: { type: "number" },
          timestamp_only: { type: "boolean" },
          control: { type: "object" },
          treatment: { type: "object" },
          official_source: {
            type: "string",
            enum: [
              "official_npm",
              "official_installer",
              "homebrew_cask_official",
              "untrusted",
              "absent",
            ],
          },
          version_pin: { type: "string" },
          provenance: {
            type: "string",
            enum: ["trusted_official", "untrusted", "absent"],
          },
          signed_history_available: { type: "boolean" },
          lawful_media_available: { type: "boolean" },
          candidate_version: { type: "string" },
          original_fault_absent: { type: "boolean" },
          core_regressions_passed: { type: "boolean" },
          canary_executed: { type: "boolean" },
          recipe_id: { type: "string" },
          upstream_ref: { type: "string" },
          upstream_evidence_digest: { type: "string" },
          upstream_verified: { type: "boolean" },
        },
      },
    },
    {
      name: TOOL_PLATFORM_STATUS,
      description:
        "Unified platform status (Tickets 13+14+15): read-only host capabilities (macOS adapter when on darwin), Windows 11 support evaluation under `status` (default PREVIEW), and Linux/WSL/enterprise capability matrix under `reports` (Limited/Read-only without real-machine receipt). Optional macOS harness receipt object, optional Windows receipt file path, optional runner plan, optional adapter filter. Never mutates host, never executes binaries, never fabricates Full from synthetic evidence.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          probe_host: {
            type: "boolean",
            description:
              "When true (default), probe registered Desktop/PATH candidates without executing them.",
          },
          adapter: {
            type: "string",
            enum: [
              "unknown",
              "macos",
              "windows",
              "linux",
              "wsl",
              "enterprise_managed",
            ],
            description:
              "Optional Ticket 15 capability-matrix adapter filter. Does not upgrade Full.",
          },
          receipt: {
            description:
              "Optional macOS harness receipt object (Ticket 13 verified_support_level) or Windows support receipt file path string (Ticket 14).",
            oneOf: [
              {
                type: "object",
                description:
                  "macOS Scenario Harness receipt object for verified_support_level.",
              },
              {
                type: "string",
                description:
                  "Path to a Windows platform-support receipt JSON file.",
              },
            ],
          },
          plan: {
            type: "boolean",
            description:
              "When true, include the Windows real-machine runner plan (scenario IDs + forbidden actions).",
          },
        },
      },
    },
    {
      name: TOOL_PLATFORM_RECEIPT,
      description:
        "Validate a macOS platform support Scenario Harness receipt (schema, leak checks, Full-only-with-proof). Read-only; no network. Windows file-path receipts use changeguard_platform_status with receipt path.",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["receipt"],
        properties: {
          receipt: {
            type: "object",
            description: "macOS PlatformSupportReceipt JSON object.",
          },
        },
      },
    },
  ];
}

function requireObjectArgs(args: unknown): Record<string, unknown> {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw Object.assign(new Error("Invalid tool arguments."), {
      code: "INVALID_ARGS",
    });
  }
  return args as Record<string, unknown>;
}

function requireTarget(a: Record<string, unknown>): string {
  if (typeof a.target !== "string" || a.target.length === 0) {
    throw Object.assign(new Error("Invalid target."), { code: "INVALID_TARGET" });
  }
  return a.target;
}

function handleToolsCall(params: unknown): {
  payload:
    | DiagnosisResult
    | ImpactAssessmentResult
    | PageAnalysisResult
    | UpstreamPreviewResult
    | ActionPreviewResult
    | ActionConfirmResult
    | RepairResult
    | ScanResult
    | LifecycleResult
    | PlatformStatusResult
    | ReceiptValidationResult
    | (PlatformStatusResult & {
        status: unknown;
        plan: unknown;
      });
  ok: boolean;
} {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    throw Object.assign(new Error("Malformed MCP params."), {
      code: "MALFORMED_MCP",
    });
  }
  const p = params as Record<string, unknown>;
  for (const k of Object.keys(p)) {
    if (!TOOLS_CALL_TOP_KEYS.has(k)) {
      throw Object.assign(new Error("Unknown or extra tool params."), {
        code: "EXTRA_PARAMS",
      });
    }
  }
  if (typeof p.name !== "string" || !KNOWN_TOOLS.has(p.name)) {
    throw Object.assign(new Error("Unknown tool."), { code: "UNKNOWN_TOOL" });
  }
  const a = requireObjectArgs(p.arguments);

  if (p.name === TOOL_DIAGNOSE) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "target")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    const payload = diagnose(requireTarget(a));
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_IMPACT) {
    const allowed = new Set(["target", "disclosure_decision"]);
    for (const k of Object.keys(a)) {
      if (!allowed.has(k)) {
        throw Object.assign(new Error("Unknown or extra arguments."), {
          code: "EXTRA_ARGS",
        });
      }
    }
    const target = requireTarget(a);
    let disclosure_decision: DisclosureDecision = "not_requested";
    if (a.disclosure_decision !== undefined) {
      if (
        a.disclosure_decision !== "approved" &&
        a.disclosure_decision !== "refused" &&
        a.disclosure_decision !== "not_requested"
      ) {
        throw Object.assign(new Error("Invalid disclosure_decision."), {
          code: "INVALID_ARGS",
        });
      }
      disclosure_decision = a.disclosure_decision;
    }
    // MCP never injects a live transport — snapshot/stale path only.
    const payload = assessImpact({
      targetPath: target,
      disclosure_decision,
      transport: null,
    });
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_ANALYZE_PAGE) {
    const allowed = new Set(["target", "envelope", "disclosure_decision"]);
    for (const k of Object.keys(a)) {
      if (!allowed.has(k)) {
        throw Object.assign(new Error("Unknown or extra arguments."), {
          code: "EXTRA_ARGS",
        });
      }
    }
    const target = requireTarget(a);
    if (a.envelope === undefined || a.envelope === null) {
      throw Object.assign(new Error("Invalid envelope."), {
        code: "INVALID_ARGS",
      });
    }
    // Bound serialized envelope size before analysis.
    let envelopeSerialized: string;
    try {
      envelopeSerialized = JSON.stringify(a.envelope);
    } catch {
      throw Object.assign(new Error("Invalid envelope."), {
        code: "INVALID_ARGS",
      });
    }
    if (Buffer.byteLength(envelopeSerialized, "utf8") > MAX_PAGE_ENVELOPE_BYTES) {
      throw Object.assign(new Error("Page envelope exceeds size limit."), {
        code: "SIZE_LIMIT",
      });
    }
    let disclosure_decision: PageDisclosureDecision = "not_requested";
    if (a.disclosure_decision !== undefined) {
      if (
        a.disclosure_decision !== "approved" &&
        a.disclosure_decision !== "refused" &&
        a.disclosure_decision !== "not_requested"
      ) {
        throw Object.assign(new Error("Invalid disclosure_decision."), {
          code: "INVALID_ARGS",
        });
      }
      disclosure_decision = a.disclosure_decision;
    }
    // MCP never injects a live page transport — no hidden network.
    const payload = analyzePage({
      targetPath: target,
      envelope: a.envelope,
      disclosure_decision,
      transport: null,
    });
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_UPSTREAM_PREVIEW) {
    const allowed = new Set(["target", "request", "disclosure_decision"]);
    for (const k of Object.keys(a)) {
      if (!allowed.has(k)) {
        throw Object.assign(new Error("Unknown or extra arguments."), {
          code: "EXTRA_ARGS",
        });
      }
    }
    const target = requireTarget(a);
    if (a.request === undefined || a.request === null) {
      throw Object.assign(new Error("Invalid request."), {
        code: "INVALID_ARGS",
      });
    }
    let requestSerialized: string;
    try {
      requestSerialized = JSON.stringify(a.request);
    } catch {
      throw Object.assign(new Error("Invalid request."), {
        code: "INVALID_ARGS",
      });
    }
    if (
      Buffer.byteLength(requestSerialized, "utf8") > MAX_UPSTREAM_REQUEST_BYTES
    ) {
      throw Object.assign(new Error("Upstream request exceeds size limit."), {
        code: "SIZE_LIMIT",
      });
    }
    let disclosure_decision: UpstreamDisclosureDecision = "not_requested";
    if (a.disclosure_decision !== undefined) {
      if (
        a.disclosure_decision !== "approved" &&
        a.disclosure_decision !== "refused" &&
        a.disclosure_decision !== "not_requested"
      ) {
        throw Object.assign(new Error("Invalid disclosure_decision."), {
          code: "INVALID_ARGS",
        });
      }
      disclosure_decision = a.disclosure_decision;
    }
    // MCP never injects a live form transport — no hidden network / no external write.
    const payload: UpstreamPreviewResult = previewUpstream({
      targetPath: target,
      request: a.request,
      disclosure_decision,
      transport: null,
    });
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_UPSTREAM_ACTION_PREVIEW) {
    const allowed = new Set([
      "target",
      "capsule",
      "action",
      "attachment_manifest",
    ]);
    for (const k of Object.keys(a)) {
      if (!allowed.has(k)) {
        throw Object.assign(new Error("Unknown or extra arguments."), {
          code: "EXTRA_ARGS",
        });
      }
    }
    const target = requireTarget(a);
    if (a.capsule === undefined || a.capsule === null) {
      throw Object.assign(new Error("Invalid capsule."), {
        code: "INVALID_ARGS",
      });
    }
    let capsuleSerialized: string;
    try {
      capsuleSerialized = JSON.stringify(a.capsule);
    } catch {
      throw Object.assign(new Error("Invalid capsule."), {
        code: "INVALID_ARGS",
      });
    }
    if (
      Buffer.byteLength(capsuleSerialized, "utf8") > MAX_ACTION_REQUEST_BYTES
    ) {
      throw Object.assign(new Error("Capsule exceeds size limit."), {
        code: "SIZE_LIMIT",
      });
    }
    if (typeof a.action !== "string") {
      throw Object.assign(new Error("Invalid action."), {
        code: "INVALID_ARGS",
      });
    }
    // MCP never injects a real gh/browser adapter — capability unavailable by default.
    const payload: ActionPreviewResult = previewUpstreamAction({
      targetPath: target,
      capsule: a.capsule,
      action: a.action,
      attachment_manifest: a.attachment_manifest,
      adapter: null,
    });
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_UPSTREAM_ACTION_CONFIRM) {
    const allowed = new Set(["target", "confirmation_token", "decision"]);
    for (const k of Object.keys(a)) {
      if (!allowed.has(k)) {
        throw Object.assign(new Error("Unknown or extra arguments."), {
          code: "EXTRA_ARGS",
        });
      }
    }
    const target = requireTarget(a);
    if (
      typeof a.confirmation_token !== "string" ||
      a.confirmation_token.length === 0
    ) {
      throw Object.assign(new Error("Invalid confirmation_token."), {
        code: "INVALID_ARGS",
      });
    }
    if (
      Buffer.byteLength(a.confirmation_token, "utf8") > MAX_CONFIRMATION_BYTES
    ) {
      throw Object.assign(new Error("Confirmation token exceeds size limit."), {
        code: "SIZE_LIMIT",
      });
    }
    if (a.decision !== "confirm" && a.decision !== "cancel") {
      throw Object.assign(new Error("Invalid decision."), {
        code: "INVALID_ARGS",
      });
    }
    // MCP never injects a real adapter — cancel works; confirm → ADAPTER_UNAVAILABLE.
    const payload: ActionConfirmResult = confirmUpstreamAction({
      targetPath: target,
      confirmation_token: a.confirmation_token,
      decision: a.decision,
      adapter: null,
    });
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_REPAIR_PREVIEW) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "target")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    // Same host-derived capability binding as CLI (user JSON cannot inject PREVIEW).
    const payload = previewRepair(
      requireTarget(a),
      resolvePublicRepairCapability(),
    );
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_REPAIR_APPLY) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "target" && k !== "authorization")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    if (typeof a.authorization !== "string" || a.authorization.length === 0) {
      throw Object.assign(new Error("Invalid authorization."), {
        code: "INVALID_ARGS",
      });
    }
    const payload = applyRepair(requireTarget(a), {
      authorization: a.authorization,
      ...resolvePublicRepairCapability(),
    });
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_VERIFY) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "target")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    const payload = verifyRepair(requireTarget(a));
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_ROLLBACK) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "target")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    const payload = rollbackRepair(requireTarget(a));
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_SCAN) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "target")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    if (typeof a.target !== "string" || a.target.length === 0) {
      throw Object.assign(new Error("Invalid target."), {
        code: "INVALID_TARGET",
      });
    }
    const payload = scanInstances({
      inventoryRoot: a.target,
      mode: "manual_scan",
      enumeration: "fixture_inventory",
    });
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_SCAN_SYSTEM) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "state_dir")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    if (typeof a.state_dir !== "string" || a.state_dir.length === 0) {
      throw Object.assign(new Error("Invalid state_dir."), {
        code: "INVALID_ARGS",
      });
    }
    const payload = scanInstances({
      mode: "manual_scan",
      enumeration: "system_registered",
      stateDir: a.state_dir,
    });
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_SESSION) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "target" && k !== "hook_trust")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    if (typeof a.target !== "string" || a.target.length === 0) {
      throw Object.assign(new Error("Invalid target."), {
        code: "INVALID_TARGET",
      });
    }
    let hookTrust: HookTrustState = "trusted";
    if (a.hook_trust !== undefined) {
      if (
        a.hook_trust !== "trusted" &&
        a.hook_trust !== "untrusted" &&
        a.hook_trust !== "skipped" &&
        a.hook_trust !== "failed"
      ) {
        throw Object.assign(new Error("Invalid hook_trust."), {
          code: "INVALID_ARGS",
        });
      }
      hookTrust = a.hook_trust;
    }
    const payload = runSessionStart({
      inventoryRoot: a.target,
      enumeration: "fixture_inventory",
      hookTrust,
    });
    // SessionStart silent no-change is a successful empty outcome.
    const ok = payload.ok || payload.silent === true;
    return { payload, ok };
  }

  if (p.name === TOOL_LIFECYCLE) {
    const allowed = new Set([
      "target",
      "operation",
      "instance_id",
      "surface",
      "source_rel",
      "checkpoint_id",
      "now_ms",
      "timestamp_only",
      "control",
      "treatment",
      "official_source",
      "version_pin",
      "provenance",
      "signed_history_available",
      "lawful_media_available",
      "candidate_version",
      "original_fault_absent",
      "core_regressions_passed",
      "canary_executed",
      "recipe_id",
      "upstream_ref",
      "upstream_evidence_digest",
      "upstream_verified",
    ]);
    for (const k of Object.keys(a)) {
      if (!allowed.has(k)) {
        throw Object.assign(new Error("Unknown or extra arguments."), {
          code: "EXTRA_ARGS",
        });
      }
    }
    if (typeof a.target !== "string" || a.target.length === 0) {
      throw Object.assign(new Error("Invalid target."), {
        code: "INVALID_TARGET",
      });
    }
    if (typeof a.operation !== "string" || a.operation.length === 0) {
      throw Object.assign(new Error("Invalid operation."), {
        code: "INVALID_ARGS",
      });
    }
    const dispatchArgs: LifecycleDispatchArgs = {
      target: a.target,
      operation: a.operation,
    };
    if (typeof a.instance_id === "string") dispatchArgs.instance_id = a.instance_id;
    if (typeof a.surface === "string") dispatchArgs.surface = a.surface;
    if (typeof a.source_rel === "string") dispatchArgs.source_rel = a.source_rel;
    if (typeof a.checkpoint_id === "string") {
      dispatchArgs.checkpoint_id = a.checkpoint_id;
    }
    if (typeof a.now_ms === "number") dispatchArgs.now_ms = a.now_ms;
    if (typeof a.timestamp_only === "boolean") {
      dispatchArgs.timestamp_only = a.timestamp_only;
    }
    if (a.control !== undefined) dispatchArgs.control = a.control;
    if (a.treatment !== undefined) dispatchArgs.treatment = a.treatment;
    if (typeof a.official_source === "string") {
      dispatchArgs.official_source = a.official_source;
    }
    if (typeof a.version_pin === "string") dispatchArgs.version_pin = a.version_pin;
    if (typeof a.provenance === "string") dispatchArgs.provenance = a.provenance;
    if (typeof a.signed_history_available === "boolean") {
      dispatchArgs.signed_history_available = a.signed_history_available;
    }
    if (typeof a.lawful_media_available === "boolean") {
      dispatchArgs.lawful_media_available = a.lawful_media_available;
    }
    if (typeof a.candidate_version === "string") {
      dispatchArgs.candidate_version = a.candidate_version;
    }
    if (typeof a.original_fault_absent === "boolean") {
      dispatchArgs.original_fault_absent = a.original_fault_absent;
    }
    if (typeof a.core_regressions_passed === "boolean") {
      dispatchArgs.core_regressions_passed = a.core_regressions_passed;
    }
    if (typeof a.canary_executed === "boolean") {
      dispatchArgs.canary_executed = a.canary_executed;
    }
    if (typeof a.recipe_id === "string") dispatchArgs.recipe_id = a.recipe_id;
    if (typeof a.upstream_ref === "string") {
      dispatchArgs.upstream_ref = a.upstream_ref;
    }
    if (typeof a.upstream_evidence_digest === "string") {
      dispatchArgs.upstream_evidence_digest = a.upstream_evidence_digest;
    }
    if (typeof a.upstream_verified === "boolean") {
      dispatchArgs.upstream_verified = a.upstream_verified;
    }
    const payload = dispatchLifecycle(dispatchArgs);
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_PLATFORM_STATUS) {
    const allowed = new Set(["probe_host", "receipt", "plan", "adapter"]);
    for (const k of Object.keys(a)) {
      if (!allowed.has(k)) {
        throw Object.assign(new Error("Unknown or extra arguments."), {
          code: "EXTRA_ARGS",
        });
      }
    }
    let probeHost = true;
    if (a.probe_host !== undefined) {
      if (typeof a.probe_host !== "boolean") {
        throw Object.assign(new Error("Invalid probe_host."), {
          code: "INVALID_ARGS",
        });
      }
      probeHost = a.probe_host;
    }
    if (a.plan !== undefined && typeof a.plan !== "boolean") {
      throw Object.assign(new Error("Invalid plan."), {
        code: "INVALID_ARGS",
      });
    }
    const includePlan = a.plan === true;

    let adapter: AdapterId | undefined;
    if (a.adapter !== undefined) {
      if (typeof a.adapter !== "string" || !PLATFORM_ADAPTERS.has(a.adapter as AdapterId)) {
        throw Object.assign(new Error("Invalid adapter."), {
          code: "INVALID_ARGS",
        });
      }
      adapter = a.adapter as AdapterId;
    }

    // receipt: string path → Windows support receipt; object → macOS harness receipt.
    let macosReceipt: unknown = undefined;
    let winStatus = windows11SupportStatus(null);
    let loadOk = true;
    let error_code: string | null = null;
    let error_message: string | null = null;

    if (typeof a.receipt === "string") {
      if (a.receipt.length === 0) {
        throw Object.assign(new Error("Invalid receipt path."), {
          code: "INVALID_ARGS",
        });
      }
      const loaded = loadAndEvaluateReceiptFile(a.receipt);
      winStatus = loaded.status;
      loadOk = loaded.ok;
      error_code = loaded.error_code;
      error_message = loaded.error_message;
    } else if (a.receipt !== undefined) {
      if (
        a.receipt === null ||
        typeof a.receipt !== "object" ||
        Array.isArray(a.receipt)
      ) {
        throw Object.assign(new Error("Invalid receipt."), {
          code: "INVALID_ARGS",
        });
      }
      macosReceipt = a.receipt;
    }

    const base = platformStatus({
      probeHost,
      receipt: macosReceipt,
      ...(adapter ? { adapter } : {}),
    });
    const payload = {
      ...base,
      ok: base.ok && loadOk,
      status: winStatus,
      plan: includePlan ? realMachineRunnerPlan() : null,
      error_code: error_code ?? base.error_code,
      error_message: error_message ?? base.error_message,
    };
    return { payload, ok: payload.ok };
  }

  if (p.name === TOOL_PLATFORM_RECEIPT) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "receipt")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    if (a.receipt === undefined || a.receipt === null) {
      throw Object.assign(new Error("Invalid receipt."), {
        code: "INVALID_ARGS",
      });
    }
    const payload = validatePlatformSupportReceipt(a.receipt);
    return { payload, ok: payload.ok };
  }

  throw Object.assign(new Error("Unknown tool."), { code: "UNKNOWN_TOOL" });
}

function handleMessage(raw: string): void {
  if (Buffer.byteLength(raw, "utf8") > MAX_MCP_REQUEST_BYTES) {
    errorResponse(null, -32600, "Request exceeds size limit.");
    return;
  }
  let msg: JsonRpcRequest;
  try {
    msg = JSON.parse(raw) as JsonRpcRequest;
  } catch {
    errorResponse(null, -32700, "Parse error.");
    return;
  }
  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    errorResponse(msg.id ?? null, -32600, "Invalid Request.");
    return;
  }

  try {
    switch (msg.method) {
      case "initialize":
        resultResponse(msg.id, {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "changeguard", version: "0.1.0" },
        });
        return;
      case "notifications/initialized":
      case "initialized":
        return;
      case "tools/list":
        resultResponse(msg.id, { tools: toolSchemas() });
        return;
      case "tools/call": {
        const { payload, ok } = handleToolsCall(msg.params);
        resultResponse(msg.id, {
          content: [
            {
              type: "text",
              text: safeJson(payload),
            },
          ],
          structuredContent: payload,
          isError: !ok,
        });
        return;
      }
      case "ping":
        resultResponse(msg.id, {});
        return;
      default:
        errorResponse(msg.id ?? null, -32601, "Method not found.");
    }
  } catch (e) {
    const message =
      e && typeof e === "object" && "message" in e
        ? String((e as { message: unknown }).message)
        : "Tool call failed.";
    errorResponse(msg.id ?? null, -32000, message || "Tool call failed.");
  }
}

/**
 * Byte-oriented NDJSON frame accumulator.
 * Enforces MAX_MCP_REQUEST_BYTES before retaining more than the bound or
 * calling JSON.parse. On overflow: emit one bounded JSON-RPC error, discard
 * until newline, then recover for subsequent valid frames.
 */
export class NdjsonFrameAccumulator {
  private buf = Buffer.alloc(0);
  private discarding = false;
  private overflowEmitted = false;
  readonly maxBytes: number;
  private readonly onFrame: (frameUtf8: string) => void;
  private readonly onOverflow: () => void;

  constructor(
    maxBytes: number,
    onFrame: (frameUtf8: string) => void,
    onOverflow: () => void,
  ) {
    this.maxBytes = maxBytes;
    this.onFrame = onFrame;
    this.onOverflow = onOverflow;
  }

  get retainedBytes(): number {
    return this.buf.length;
  }

  push(chunk: Buffer): void {
    if (!Buffer.isBuffer(chunk) || chunk.length === 0) return;

    let data = chunk;
    while (data.length > 0) {
      if (this.discarding) {
        const nl = data.indexOf(0x0a);
        if (nl < 0) {
          return;
        }
        data = data.subarray(nl + 1);
        this.discarding = false;
        this.overflowEmitted = false;
        this.buf = Buffer.alloc(0);
        continue;
      }

      if (this.buf.length === this.maxBytes) {
        if (data[0] === 0x0a) {
          const frameBuf = this.buf;
          this.buf = Buffer.alloc(0);
          data = data.subarray(1);
          if (frameBuf.length > 0) {
            this.onFrame(frameBuf.toString("utf8"));
          }
          continue;
        }
        this.emitOverflowAndDiscard(data);
        data = Buffer.alloc(0);
        continue;
      }

      if (this.buf.length > this.maxBytes) {
        this.emitOverflowAndDiscard(data);
        data = Buffer.alloc(0);
        continue;
      }

      const room = this.maxBytes - this.buf.length;
      const take = Math.min(room, data.length);
      const slice = data.subarray(0, take);
      const nlInSlice = slice.indexOf(0x0a);

      if (nlInSlice >= 0) {
        const frameBuf = Buffer.concat([this.buf, slice.subarray(0, nlInSlice)]);
        this.buf = Buffer.alloc(0);
        data = data.subarray(nlInSlice + 1);
        if (frameBuf.length > 0) {
          this.onFrame(frameBuf.toString("utf8"));
        }
        continue;
      }

      this.buf = Buffer.concat([this.buf, slice]);
      data = data.subarray(take);
    }
  }

  private emitOverflowAndDiscard(rest: Buffer): void {
    if (!this.overflowEmitted) {
      this.onOverflow();
      this.overflowEmitted = true;
    }
    this.buf = Buffer.alloc(0);
    this.discarding = true;
    const nl = rest.indexOf(0x0a);
    if (nl >= 0) {
      this.discarding = false;
      this.overflowEmitted = false;
      const after = rest.subarray(nl + 1);
      if (after.length > 0) {
        this.push(after);
      }
    }
  }
}

export function startMcpServer(
  input: NodeJS.ReadableStream = process.stdin,
): NdjsonFrameAccumulator {
  const acc = new NdjsonFrameAccumulator(
    MAX_MCP_REQUEST_BYTES,
    (frame) => {
      handleMessage(frame);
    },
    () => {
      errorResponse(null, -32600, "Request exceeds size limit.");
    },
  );

  input.on("data", (chunk: Buffer | string) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
    acc.push(buf);
  });
  input.on("end", () => {
    process.exit(0);
  });
  return acc;
}

const entryArg = process.argv[1] ?? "";
if (
  /[/\\]mcp[/\\]server\.(js|ts)$/.test(entryArg) ||
  entryArg.endsWith("mcp/server.js") ||
  entryArg.endsWith("mcp\\server.js")
) {
  startMcpServer();
}
