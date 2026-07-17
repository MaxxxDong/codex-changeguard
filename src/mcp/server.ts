/**
 * ChangeGuard MCP server — shared core with Rescue CLI.
 * Tools: diagnose (read-only) + Ticket 02 recovery tools (authorized mutation
 * only under an isolated target via registered recovery operations).
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
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import type { DiagnosisResult } from "../core/types.js";
import type { RepairResult } from "../core/recovery/types.js";

const TOOL_DIAGNOSE = "changeguard_diagnose";
const TOOL_REPAIR_PREVIEW = "changeguard_repair_preview";
const TOOL_REPAIR_APPLY = "changeguard_repair_apply";
const TOOL_VERIFY = "changeguard_verify";
const TOOL_ROLLBACK = "changeguard_rollback";

const KNOWN_TOOLS = new Set([
  TOOL_DIAGNOSE,
  TOOL_REPAIR_PREVIEW,
  TOOL_REPAIR_APPLY,
  TOOL_VERIFY,
  TOOL_ROLLBACK,
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
            description: "Exact authorization_binding from repair-preview.",
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
  payload: DiagnosisResult | RepairResult;
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

  if (p.name === TOOL_REPAIR_PREVIEW) {
    const keys = Object.keys(a);
    if (keys.some((k) => k !== "target")) {
      throw Object.assign(new Error("Unknown or extra arguments."), {
        code: "EXTRA_ARGS",
      });
    }
    const payload = previewRepair(requireTarget(a));
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
