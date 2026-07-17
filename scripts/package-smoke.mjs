/**
 * Black-box package smoke: launch CLI and MCP from the packaged artifact
 * while the caller's current directory is outside the repository.
 * Runs with only Node and the package files after build/package.
 */
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageDir = path.join(repoRoot, "release", "codex-changeguard-plugin");

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

if (!fs.existsSync(path.join(packageDir, "bin/changeguard.js"))) {
  fail("Package missing; run npm run package first.");
}
if (fs.existsSync(path.join(packageDir, "node_modules"))) {
  fail("Package must not contain node_modules.");
}

const outside = fs.mkdtempSync(path.join(os.tmpdir(), "cg-smoke-cwd-"));
const fixtureSrc = path.join(packageDir, "fixtures", "protected-process");
const fixtureDest = path.join(outside, "protected-process");
fs.cpSync(fixtureSrc, fixtureDest, { recursive: true });

// CLI smoke from outside cwd
const cli = spawnSync(
  process.execPath,
  [path.join(packageDir, "bin/changeguard.js"), "diagnose", fixtureDest],
  {
    cwd: outside,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  },
);
if (cli.status !== 0) {
  fail(`CLI smoke failed status=${cli.status}\n${cli.stdout}\n${cli.stderr}`);
}
const cliResult = JSON.parse(cli.stdout);
if (cliResult.diagnosis_state !== "SOURCE_COMPONENT_LOCATED") {
  fail(`CLI unexpected state: ${cliResult.diagnosis_state}`);
}
if (cliResult.network_used !== false || cliResult.repair_applied !== false) {
  fail("CLI boundary markers failed");
}

// MCP smoke from outside cwd
const serverEntry = path.join(packageDir, "dist/mcp/server.js");
const mcpResult = await new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [serverEntry], {
    cwd: outside,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, NO_COLOR: "1" },
  });
  let buf = "";
  const timer = setTimeout(() => {
    child.kill();
    reject(new Error("MCP smoke timeout"));
  }, 10000);
  timer.unref?.();

  child.stdout.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (!line.trim()) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id === 1 && msg.result) {
        // initialized — send tools/call
        child.stdin.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
              name: "changeguard_diagnose",
              arguments: { target: fixtureDest },
            },
          }) + "\n",
        );
      }
      if (msg.id === 2) {
        clearTimeout(timer);
        child.kill();
        if (msg.error) {
          reject(new Error(JSON.stringify(msg.error)));
          return;
        }
        resolve(msg.result?.structuredContent ?? JSON.parse(msg.result?.content?.[0]?.text ?? "null"));
      }
    }
  });
  child.on("error", reject);
  child.stdin.write(
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "package-smoke", version: "0.1.0" },
      },
    }) + "\n",
  );
  child.stdin.write(
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n",
  );
});

if (!mcpResult || mcpResult.diagnosis_state !== "SOURCE_COMPONENT_LOCATED") {
  fail(`MCP unexpected: ${JSON.stringify(mcpResult)}`);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      outside_cwd: true,
      cli_state: cliResult.diagnosis_state,
      mcp_state: mcpResult.diagnosis_state,
      package_dir: packageDir,
      no_node_modules: true,
    },
    null,
    2,
  ),
);
