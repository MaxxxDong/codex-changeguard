/**
 * Read-only MCP server exposing changeguard_diagnose.
 * Shares the same core as the Rescue CLI. No network. No target mutation.
 *
 * Wire protocol: newline-delimited JSON-RPC 2.0 over stdio.
 * Request frames are accumulated as bounded bytes (not unbounded readline).
 */
import { diagnose } from "../core/diagnose.js";
import { MAX_MCP_REQUEST_BYTES } from "../core/limits.js";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import type { DiagnosisResult } from "../core/types.js";

const TOOL_NAME = "changeguard_diagnose";
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

function toolSchema() {
  return {
    name: TOOL_NAME,
    description:
      "Read-only ChangeGuard diagnosis of an isolated target directory. Returns DiagnosisResult / IncidentFingerprint. Never mutates the target or uses the network.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["target"],
      properties: {
        target: {
          type: "string",
          description: "Absolute or relative path to an isolated fixture/target directory.",
        },
      },
    },
  };
}

function handleToolsCall(params: unknown): DiagnosisResult {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    throw Object.assign(new Error("Malformed MCP params."), {
      code: "MALFORMED_MCP",
    });
  }
  const p = params as Record<string, unknown>;
  // Reject extra top-level keys; only name + arguments allowed.
  for (const k of Object.keys(p)) {
    if (!TOOLS_CALL_TOP_KEYS.has(k)) {
      throw Object.assign(new Error("Unknown or extra tool params."), {
        code: "EXTRA_PARAMS",
      });
    }
  }
  if (p.name !== TOOL_NAME) {
    throw Object.assign(new Error("Unknown tool."), { code: "UNKNOWN_TOOL" });
  }
  const args = p.arguments;
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw Object.assign(new Error("Invalid tool arguments."), {
      code: "INVALID_ARGS",
    });
  }
  const a = args as Record<string, unknown>;
  const keys = Object.keys(a);
  if (keys.some((k) => k !== "target")) {
    throw Object.assign(new Error("Unknown or extra arguments."), {
      code: "EXTRA_ARGS",
    });
  }
  if (typeof a.target !== "string" || a.target.length === 0) {
    throw Object.assign(new Error("Invalid target."), { code: "INVALID_TARGET" });
  }
  return diagnose(a.target);
}

function handleMessage(raw: string): void {
  // Bound is already enforced by the frame accumulator before parse.
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
        // notification — no response required
        return;
      case "tools/list":
        resultResponse(msg.id, { tools: [toolSchema()] });
        return;
      case "tools/call": {
        const diagnosis = handleToolsCall(msg.params);
        resultResponse(msg.id, {
          content: [
            {
              type: "text",
              text: safeJson(diagnosis),
            },
          ],
          structuredContent: diagnosis,
          isError: !diagnosis.ok,
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
    // Never leak raw exception stacks or absolute paths.
    errorResponse(msg.id ?? null, -32000, message || "Tool call failed.");
  }
}

/**
 * Byte-oriented NDJSON frame accumulator.
 * Enforces MAX_MCP_REQUEST_BYTES before retaining more than the bound or
 * calling JSON.parse. On overflow: emit one bounded JSON-RPC error, discard
 * until newline, then recover for subsequent valid frames.
 * Preserves correct UTF-8 handling across partial chunks and multiple frames.
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

  /** Expose current retained byte length (for tests). */
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
          // Still no newline — drop this chunk, keep discarding.
          return;
        }
        // Resume after the newline that ends the oversized frame.
        data = data.subarray(nl + 1);
        this.discarding = false;
        this.overflowEmitted = false;
        this.buf = Buffer.alloc(0);
        continue;
      }

      // Inclusive bound: payload of length <= maxBytes is accepted.
      // When payload is already exactly maxBytes, only a newline may complete
      // the frame; any other next byte is overflow. Retained bytes stay bounded.
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
        // Defensive: never retain past the inclusive bound.
        this.emitOverflowAndDiscard(data);
        data = Buffer.alloc(0);
        continue;
      }

      const room = this.maxBytes - this.buf.length;
      const take = Math.min(room, data.length);
      const slice = data.subarray(0, take);
      const nlInSlice = slice.indexOf(0x0a);

      if (nlInSlice >= 0) {
        // Complete frame within inclusive bound (frame length <= maxBytes).
        const frameBuf = Buffer.concat([this.buf, slice.subarray(0, nlInSlice)]);
        this.buf = Buffer.alloc(0);
        data = data.subarray(nlInSlice + 1);
        // Skip empty frames (blank lines).
        if (frameBuf.length > 0) {
          this.onFrame(frameBuf.toString("utf8"));
        }
        continue;
      }

      // No newline in the accepted payload slice.
      this.buf = Buffer.concat([this.buf, slice]);
      data = data.subarray(take);
      // Loop again: if more bytes remain, the exact-bound branch decides
      // newline-accept vs overflow without unbounded accumulation.
    }
  }

  private emitOverflowAndDiscard(rest: Buffer): void {
    if (!this.overflowEmitted) {
      this.onOverflow();
      this.overflowEmitted = true;
    }
    this.buf = Buffer.alloc(0);
    this.discarding = true;
    // Continue discarding rest from current push if it contains a newline.
    const nl = rest.indexOf(0x0a);
    if (nl >= 0) {
      this.discarding = false;
      this.overflowEmitted = false;
      // Process remainder after newline via a recursive push.
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

/** Only auto-start when executed as the MCP server entry (not when imported by tests). */
const entryArg = process.argv[1] ?? "";
if (
  /[/\\]mcp[/\\]server\.(js|ts)$/.test(entryArg) ||
  entryArg.endsWith("mcp/server.js") ||
  entryArg.endsWith("mcp\\server.js")
) {
  startMcpServer();
}
