/**
 * Read-only MCP server exposing changeguard_diagnose.
 * Shares the same core as the Rescue CLI. No network. No target mutation.
 *
 * Wire protocol: newline-delimited JSON-RPC 2.0 over stdio.
 */
import readline from "node:readline";
import { diagnose } from "../core/diagnose.js";
import { MAX_MCP_REQUEST_BYTES } from "../core/limits.js";
import { assertNoLeakPaths, redactText } from "../core/redact.js";
import type { DiagnosisResult } from "../core/types.js";

const TOOL_NAME = "changeguard_diagnose";

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
  if (!params || typeof params !== "object") {
    throw Object.assign(new Error("Malformed MCP params."), {
      code: "MALFORMED_MCP",
    });
  }
  const p = params as Record<string, unknown>;
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

export function startMcpServer(): void {
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });
  rl.on("line", (line) => {
    if (line.trim().length === 0) return;
    handleMessage(line);
  });
  rl.on("close", () => {
    process.exit(0);
  });
}

startMcpServer();
