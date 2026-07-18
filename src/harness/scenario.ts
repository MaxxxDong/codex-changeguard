/**
 * Scenario Harness — highest approved black-box seam.
 * Invokes public CLI/MCP surfaces and owns whole-target before/after hashing.
 * The diagnosis core does not own recursive target hashing.
 */
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { McpTestClient } from "../mcp/client.js";
import { findRepoRoot } from "../paths.js";
import type { DiagnosisResult } from "../core/types.js";

const repoRoot = findRepoRoot(import.meta.url);

export function cliEntry(): string {
  return path.join(repoRoot, "bin", "changeguard.js");
}

export function mcpServerEntry(): string {
  return path.join(repoRoot, "dist", "mcp", "server.js");
}

/** Deterministic whole-tree hash for isolated targets (harness-owned). */
export function hashTargetTree(root: string): string {
  const h = crypto.createHash("sha256");
  const walk = (dir: string): void => {
    const entries = fs
      .readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      const rel = path.relative(root, full).split(path.sep).join("/");
      if (ent.isSymbolicLink()) {
        const link = fs.readlinkSync(full);
        h.update(`L:${rel}->${link}\n`);
        continue;
      }
      if (ent.isDirectory()) {
        h.update(`D:${rel}\n`);
        walk(full);
        continue;
      }
      if (ent.isFile()) {
        const buf = fs.readFileSync(full);
        h.update(`F:${rel}:${buf.length}:`);
        h.update(buf);
        h.update("\n");
      }
    }
  };
  walk(root);
  return h.digest("hex");
}

export function runCliDiagnose(target: string): {
  exitCode: number;
  stdout: string;
  stderr: string;
  result: DiagnosisResult | null;
} {
  return runCliJson(["diagnose", target]) as {
    exitCode: number;
    stdout: string;
    stderr: string;
    result: DiagnosisResult | null;
  };
}

/** Invoke Rescue CLI and parse JSON stdout (shared by diagnose + recovery). */
export function runCliJson(
  args: string[],
  opts?: { env?: NodeJS.ProcessEnv },
): {
  exitCode: number;
  stdout: string;
  stderr: string;
  result: Record<string, unknown> | null;
} {
  const res = spawnSync(process.execPath, [cliEntry(), ...args], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", ...(opts?.env ?? {}) },
    maxBuffer: 4 * 1024 * 1024,
  });
  let result: Record<string, unknown> | null = null;
  try {
    result = JSON.parse(res.stdout) as Record<string, unknown>;
  } catch {
    result = null;
  }
  return {
    exitCode: res.status ?? 1,
    stdout: res.stdout ?? "",
    stderr: res.stderr ?? "",
    result,
  };
}

export function runCliRepairPreview(target: string) {
  return runCliJson(["repair-preview", target]);
}

export function runCliRepairApply(target: string, authorization: string) {
  return runCliJson(["repair-apply", target, authorization]);
}

export function runCliVerify(target: string) {
  return runCliJson(["verify", target]);
}

export function runCliRollback(target: string) {
  return runCliJson(["rollback", target]);
}

export function runCliScan(inventoryRoot: string): {
  exitCode: number;
  stdout: string;
  stderr: string;
  result: unknown;
} {
  return runCliJson(["scan", inventoryRoot]);
}

export function runCliSessionStart(
  inventoryRoot: string,
  hookTrust: "trusted" | "untrusted" | "skipped" | "failed" = "trusted",
): {
  exitCode: number;
  stdout: string;
  stderr: string;
  result: unknown;
  durationMs: number;
} {
  const t0 = performance.now();
  const out = runCliJson([
    "session-start",
    inventoryRoot,
    `--hook-trust=${hookTrust}`,
  ]);
  return {
    ...out,
    durationMs: performance.now() - t0,
  };
}

export async function runMcpDiagnose(target: string): Promise<DiagnosisResult> {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const result = await client.diagnose(target);
    return result as DiagnosisResult;
  } finally {
    await client.close();
  }
}

export async function runMcpScan(target: string): Promise<unknown> {
  const client = new McpTestClient({ serverEntry: mcpServerEntry() });
  try {
    client.start();
    const result = await client.callTool("changeguard_scan", { target });
    return result;
  } finally {
    await client.close();
  }
}

export function copyFixtureToTemp(
  fixtureRel: string,
  tempRoot: string,
): string {
  const src = path.join(repoRoot, fixtureRel);
  const dest = path.join(tempRoot, path.basename(fixtureRel));
  fs.cpSync(src, dest, { recursive: true });
  return dest;
}

export function repoPath(...parts: string[]): string {
  return path.join(repoRoot, ...parts);
}
