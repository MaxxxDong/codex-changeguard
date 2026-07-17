/**
 * Minimal MCP stdio test client.
 * Handles partial stdout chunks and clears timers promptly.
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface McpClientOptions {
  serverEntry?: string;
  timeoutMs?: number;
}

export class McpTestClient {
  private child: ChildProcessWithoutNullStreams | null = null;
  private nextId = 1;
  private pending = new Map<
    number,
    {
      resolve: (v: unknown) => void;
      reject: (e: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();
  private readonly timeoutMs: number;
  private readonly serverEntry: string;
  /** Accumulates partial stdout chunks until a full NDJSON line is available. */
  private partialStdout = "";
  private initialized = false;

  constructor(opts: McpClientOptions = {}) {
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    const here = path.dirname(fileURLToPath(import.meta.url));
    this.serverEntry =
      opts.serverEntry ?? path.join(here, "server.js");
  }

  start(): void {
    if (this.child) return;
    this.child = spawn(process.execPath, [this.serverEntry], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" },
    });
    // Handle partial stdout chunks manually so incomplete frames wait for more data.
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => {
      this.partialStdout += chunk;
      let idx: number;
      while ((idx = this.partialStdout.indexOf("\n")) >= 0) {
        const line = this.partialStdout.slice(0, idx);
        this.partialStdout = this.partialStdout.slice(idx + 1);
        if (line.trim().length > 0) this.onLine(line);
      }
    });
    this.child.stderr.on("data", () => {
      /* discard — must not surface absolute paths in tests */
    });
    this.child.on("error", (err) => {
      this.failAll(err);
    });
    this.child.on("exit", () => {
      this.failAll(new Error("MCP server exited."));
    });
  }

  private onLine(line: string): void {
    let msg: { id?: number; result?: unknown; error?: unknown };
    try {
      msg = JSON.parse(line) as {
        id?: number;
        result?: unknown;
        error?: unknown;
      };
    } catch {
      return;
    }
    if (typeof msg.id !== "number") return;
    const p = this.pending.get(msg.id);
    if (!p) return;
    clearTimeout(p.timer);
    this.pending.delete(msg.id);
    if (msg.error) {
      p.reject(
        new Error(
          typeof msg.error === "object" &&
            msg.error &&
            "message" in msg.error
            ? String((msg.error as { message: unknown }).message)
            : "MCP error",
        ),
      );
    } else {
      p.resolve(msg.result);
    }
  }

  private failAll(err: Error): void {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }

  async request(method: string, params?: unknown): Promise<unknown> {
    if (!this.child) this.start();
    const id = this.nextId++;
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params: params ?? {},
    });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("MCP request timeout."));
      }, this.timeoutMs);
      // Unref so open timers do not keep the process alive after tests.
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer });
      this.child!.stdin.write(payload + "\n");
    });
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.child) this.start();
    if (this.initialized) return;
    await this.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "changeguard-test", version: "0.1.0" },
    });
    this.child!.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }) + "\n",
    );
    this.initialized = true;
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    await this.ensureInitialized();
    const result = (await this.request("tools/call", {
      name,
      arguments: args,
    })) as {
      structuredContent?: unknown;
      content?: Array<{ type: string; text: string }>;
      isError?: boolean;
    };
    if (result.structuredContent && typeof result.structuredContent === "object") {
      return result.structuredContent as Record<string, unknown>;
    }
    const text = result.content?.find((c) => c.type === "text")?.text;
    if (!text) {
      throw new Error("MCP response missing structured payload.");
    }
    return JSON.parse(text) as Record<string, unknown>;
  }

  async diagnose(target: string): Promise<DiagnosisViaMcp> {
    return (await this.callTool("changeguard_diagnose", {
      target,
    })) as DiagnosisViaMcp;
  }

  async repairPreview(target: string): Promise<RepairViaMcp> {
    return (await this.callTool("changeguard_repair_preview", {
      target,
    })) as RepairViaMcp;
  }

  async repairApply(
    target: string,
    authorization: string,
  ): Promise<RepairViaMcp> {
    return (await this.callTool("changeguard_repair_apply", {
      target,
      authorization,
    })) as RepairViaMcp;
  }

  async verify(target: string): Promise<RepairViaMcp> {
    return (await this.callTool("changeguard_verify", {
      target,
    })) as RepairViaMcp;
  }

  async rollback(target: string): Promise<RepairViaMcp> {
    return (await this.callTool("changeguard_rollback", {
      target,
    })) as RepairViaMcp;
  }

  /** Clear timers promptly and close the child. */
  async close(): Promise<void> {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error("MCP client closed."));
    }
    this.pending.clear();
    this.partialStdout = "";
    this.initialized = false;
    if (this.child) {
      this.child.stdin.end();
      this.child.kill("SIGTERM");
      this.child = null;
    }
  }
}

export type DiagnosisViaMcp = {
  schema_version: 1;
  ok: boolean;
  diagnosis_state: string;
  incident_fingerprint: unknown;
  user_resolution: {
    status: string;
    summary: string;
    receipt_id: string;
  };
  upstream_contribution: {
    status: string;
    summary: string;
    issue_candidates: string[];
    receipt_id: string;
  };
  evidence: Array<{ kind: string; detail: string; measured: boolean }>;
  error_code: string | null;
  error_message: string | null;
  network_used: false;
  target_mutated: false;
  repair_applied: false;
};

export type RepairViaMcp = {
  schema_version: 1;
  ok: boolean;
  operation: string;
  capsule: {
    authorization_binding: string;
    original_sha256: string;
    expected_pattern_count: number;
    target_path_alias: string;
    [key: string]: unknown;
  } | null;
  /** Self-contained authorization token from preview (null on non-preview). */
  authorization: string | null;
  user_resolution: {
    status: string;
    summary: string;
    receipt_id: string;
  };
  upstream_contribution: {
    status: string;
    summary: string;
    issue_candidates: string[];
    receipt_id: string;
  };
  evidence: Array<{ kind: string; detail: string; measured: boolean }>;
  error_code: string | null;
  error_message: string | null;
  network_used: false;
  target_mutated: boolean;
  repair_applied: boolean;
  auto_rolled_back: boolean;
  verification: unknown;
  backup: unknown;
  resulting_sha256: string | null;
  contribution_claim: string;
};
