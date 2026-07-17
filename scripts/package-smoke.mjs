/**
 * Black-box package smoke: launch CLI and MCP from the packaged artifact
 * while the caller's current directory is outside the repository.
 * Runs with only Node and the package files after build/package.
 *
 * Launches the MCP server via the packaged `.mcp.json` surface (same contract
 * a plugin host would use): validate allowed server config, resolve `cwd: "."`
 * relative to the package root, and spawn `command` + `args`.
 */
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageDir = path.join(repoRoot, "release", "codex-changeguard-plugin");

/** Exact public top-level allowlist for the packaged plugin artifact. */
const ALLOWED_TOP_LEVEL = new Set([
  ".codex-plugin",
  ".mcp.json",
  "README.md",
  "bin",
  "dist",
  "docs",
  "fixtures",
  "package.json",
  "schemas",
  "skills",
]);

const FORBIDDEN_TOP_LEVEL = [
  "AGENTS.md",
  ".scratch",
  "src",
  "scripts",
  "node_modules",
];

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

if (!fs.existsSync(path.join(packageDir, "bin/changeguard.js"))) {
  fail("Package missing; run npm run package first.");
}

// Exact package surface assertions
const top = fs.readdirSync(packageDir).sort();
for (const name of top) {
  if (!ALLOWED_TOP_LEVEL.has(name)) {
    fail(`Unexpected top-level package entry: ${name}`);
  }
  if (name.startsWith(".grok") || name.includes("grok-worker") || name.includes("grok-disposable")) {
    fail(`Package must not contain clone/lifecycle path: ${name}`);
  }
}
for (const name of FORBIDDEN_TOP_LEVEL) {
  if (fs.existsSync(path.join(packageDir, name))) {
    fail(`Package must not contain ${name}`);
  }
}
if (fs.existsSync(path.join(packageDir, "node_modules"))) {
  fail("Package must not contain node_modules.");
}
if (fs.existsSync(path.join(packageDir, "AGENTS.md"))) {
  fail("Package must not contain AGENTS.md.");
}

// Read and validate packaged .mcp.json (plugin host surface)
const mcpConfigPath = path.join(packageDir, ".mcp.json");
if (!fs.existsSync(mcpConfigPath)) {
  fail("Packaged .mcp.json missing.");
}
let mcpConfig;
try {
  mcpConfig = JSON.parse(fs.readFileSync(mcpConfigPath, "utf8"));
} catch {
  fail("Packaged .mcp.json is not valid JSON.");
}
const servers = mcpConfig?.mcpServers;
if (!servers || typeof servers !== "object" || Array.isArray(servers)) {
  fail("Packaged .mcp.json must declare mcpServers object.");
}
const serverNames = Object.keys(servers);
if (serverNames.length !== 1 || serverNames[0] !== "changeguard") {
  fail(`Packaged .mcp.json must declare only mcpServers.changeguard; got ${serverNames.join(",")}`);
}
const server = servers.changeguard;
if (!server || typeof server !== "object" || Array.isArray(server)) {
  fail("Invalid changeguard server config.");
}
const allowedServerKeys = new Set(["command", "args", "cwd", "env"]);
for (const k of Object.keys(server)) {
  if (!allowedServerKeys.has(k)) {
    fail(`Unexpected MCP server key: ${k}`);
  }
}
if (server.command !== "node") {
  fail(`MCP command must be node; got ${server.command}`);
}
if (!Array.isArray(server.args) || server.args.length < 1) {
  fail("MCP args must be a non-empty array.");
}
for (const a of server.args) {
  if (typeof a !== "string") fail("MCP args must be strings.");
  if (path.isAbsolute(a)) fail(`MCP args must not be absolute paths: ${a}`);
}
if (server.cwd !== undefined && server.cwd !== ".") {
  fail(`MCP cwd must be "." when present; got ${JSON.stringify(server.cwd)}`);
}
if (server.env !== undefined) {
  if (!server.env || typeof server.env !== "object" || Array.isArray(server.env)) {
    fail("MCP env must be an object when present.");
  }
  // Ticket 01: empty env only (no secrets).
  if (Object.keys(server.env).length !== 0) {
    fail("MCP env must be empty for Ticket 01 package surface.");
  }
}

// Resolve cwd: "." relative to package root as a plugin host would.
const mcpCwd = path.resolve(packageDir, server.cwd ?? ".");
if (mcpCwd !== path.resolve(packageDir)) {
  fail("Resolved MCP cwd must be the package root.");
}
const mcpArgs = server.args.map((a) => a); // relative args; resolved against mcpCwd by node spawn
const mcpCommand = server.command === "node" ? process.execPath : server.command;

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

// MCP smoke: launch via packaged .mcp.json command+args with package-root cwd;
// caller process cwd remains outside the repo.
const mcpResult = await new Promise((resolve, reject) => {
  const child = spawn(mcpCommand, mcpArgs, {
    cwd: mcpCwd,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, NO_COLOR: "1" },
  });
  // Keep caller-side fixture path absolute so server (running under package cwd)
  // still reaches the outside-cwd target.
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

// Confirm caller cwd was outside the package/repo during smoke.
if (path.resolve(outside) === path.resolve(packageDir)) {
  fail("Smoke cwd must be outside package dir.");
}

console.log(
  JSON.stringify(
    {
      ok: true,
      outside_cwd: true,
      mcp_from_packaged_mcp_json: true,
      mcp_command: server.command,
      mcp_args: server.args,
      mcp_cwd_resolved_to_package_root: true,
      cli_state: cliResult.diagnosis_state,
      mcp_state: mcpResult.diagnosis_state,
      package_dir: packageDir,
      package_top_level: top,
      no_node_modules: true,
      no_agents_md: true,
    },
    null,
    2,
  ),
);
