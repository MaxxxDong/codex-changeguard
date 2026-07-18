/**
 * Black-box package smoke: launch CLI and MCP from the packaged artifact
 * while the caller's current directory is outside the repository.
 * Runs with only Node and the package files after build/package.
 *
 * Launches the MCP server via the packaged `.mcp.json` surface (same contract
 * a plugin host would use): validate allowed server config, resolve `cwd: "."`
 * relative to the package root, and spawn `command` + `args`.
 *
 * Also enforces the public package surface: exact top-level allowlist, forbidden
 * repository-only paths, exact public docs set, and no broken local Markdown links.
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
  "hooks",
  "package.json",
  "schemas",
  "skills",
]);

/** Paths that must never appear in the packaged tree (repo-only / build-only). */
const FORBIDDEN_PACKAGED_PATHS = [
  "AGENTS.md",
  "HANDOFF.md",
  "docs/agents",
  ".scratch",
  "src",
  "scripts",
  "node_modules",
];

/** Exact public docs Markdown set for the package. */
const PUBLIC_DOCS = [
  "ARCHITECTURE.md",
  "CASE_STUDIES.md",
  "SECURITY.md",
  "SUPPORT_MATRIX.md",
  "TEST_PLAN.md",
];

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

function walkPackageRel(dir, relBase, onEntry) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
    const abs = path.join(dir, ent.name);
    onEntry(rel, abs, ent);
    if (ent.isDirectory()) walkPackageRel(abs, rel, onEntry);
  }
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
if (JSON.stringify(top) !== JSON.stringify([...ALLOWED_TOP_LEVEL].sort())) {
  fail(
    `Package top-level contract mismatch.\nExpected: ${[...ALLOWED_TOP_LEVEL].sort().join(", ")}\nGot: ${top.join(", ")}`,
  );
}

// Forbidden repository-only / build-only paths must not appear anywhere
const packagedRels = [];
walkPackageRel(packageDir, "", (rel) => {
  packagedRels.push(rel);
  for (const forbidden of FORBIDDEN_PACKAGED_PATHS) {
    if (rel === forbidden || rel.startsWith(`${forbidden}/`)) {
      fail(`Package must not contain ${forbidden} (found ${rel})`);
    }
  }
});
for (const forbidden of FORBIDDEN_PACKAGED_PATHS) {
  if (fs.existsSync(path.join(packageDir, forbidden))) {
    fail(`Package must not contain ${forbidden}.`);
  }
}

// Exact public docs tree (four Markdown files only; no docs/agents)
const docsDir = path.join(packageDir, "docs");
if (!fs.existsSync(docsDir) || !fs.statSync(docsDir).isDirectory()) {
  fail("Packaged docs/ directory missing.");
}
const docsEntries = fs.readdirSync(docsDir).sort();
const expectedDocs = [...PUBLIC_DOCS].sort();
if (JSON.stringify(docsEntries) !== JSON.stringify(expectedDocs)) {
  fail(
    `Packaged docs must be exactly ${expectedDocs.join(", ")}; got ${docsEntries.join(", ")}`,
  );
}
for (const name of docsEntries) {
  const st = fs.statSync(path.join(docsDir, name));
  if (!st.isFile() || !name.endsWith(".md")) {
    fail(`Packaged docs entry must be a Markdown file: ${name}`);
  }
}

// Packaged README must not keep a local relative link to repository-only HANDOFF.md.
// Prose may mention the name as an excluded surface; broken/missing link targets are
// caught by the general Markdown link walk below.
const packagedReadme = fs.readFileSync(path.join(packageDir, "README.md"), "utf8");
if (/\[[^\]]*\]\(\s*HANDOFF\.md(?:#[^)\s]*)?\s*\)/i.test(packagedReadme)) {
  fail("Packaged README must not contain a local link to HANDOFF.md.");
}

// Source repo README must still keep the handoff link (package transform only).
const sourceReadme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
if (!/\[Current handoff\]\(HANDOFF\.md\)/.test(sourceReadme)) {
  fail("Source README must retain the Current handoff -> HANDOFF.md link.");
}

// Local relative Markdown links in packaged .md files must resolve to existing targets.
const MD_LINK_RE = /\[([^\]]*)\]\(([^)]+)\)/g;
const brokenLinks = [];
walkPackageRel(packageDir, "", (rel, abs, ent) => {
  if (!ent.isFile() || !rel.endsWith(".md")) return;
  const text = fs.readFileSync(abs, "utf8");
  let m;
  while ((m = MD_LINK_RE.exec(text)) !== null) {
    const hrefRaw = m[2].trim();
    // Strip optional title: url "title" or url 'title'
    const href = hrefRaw.replace(/\s+["'][^"']*["']\s*$/, "").trim();
    if (!href) continue;
    if (href.startsWith("#")) continue;
    if (/^[a-z][a-z0-9+.-]*:/i.test(href)) continue; // scheme (http, https, mailto, ...)
    if (href.startsWith("/")) continue; // absolute path (not a package-local relative link)
    const bare = href.split("#")[0];
    if (!bare) continue;
    const target = path.resolve(path.dirname(abs), bare);
    const packageRootResolved = path.resolve(packageDir);
    if (
      target !== packageRootResolved &&
      !target.startsWith(packageRootResolved + path.sep)
    ) {
      brokenLinks.push({ file: rel, href, reason: "escapes package root" });
      continue;
    }
    if (!fs.existsSync(target)) {
      brokenLinks.push({ file: rel, href, reason: "missing target" });
    }
  }
});
if (brokenLinks.length > 0) {
  fail(
    `Packaged Markdown has broken local relative links:\n${brokenLinks
      .map((b) => `  ${b.file}: (${b.href}) — ${b.reason}`)
      .join("\n")}`,
  );
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

// Ticket 04: packaged official-evidence snapshot asset must exist and parse.
const snapshotPath = path.join(packageDir, "fixtures", "official-evidence", "snapshot.json");
if (!fs.existsSync(snapshotPath)) {
  fail("Package missing fixtures/official-evidence/snapshot.json");
}
let snapshot;
try {
  snapshot = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
} catch {
  fail("Packaged official-evidence snapshot is not valid JSON.");
}
if (snapshot.schema_version !== 1 || typeof snapshot.content_sha256 !== "string") {
  fail("Packaged official-evidence snapshot missing schema_version/content_sha256.");
}
if (!Array.isArray(snapshot.items) || snapshot.items.length < 1) {
  fail("Packaged official-evidence snapshot must contain items.");
}
if (typeof snapshot.fetched_at !== "string" || !snapshot.immutable) {
  fail("Packaged official-evidence snapshot must be immutable with fetched_at.");
}

// Ticket 04: impact-local fixture + CLI/MCP impact equivalence (disclose-refused).
const impactSrc = path.join(packageDir, "fixtures", "impact-local");
if (!fs.existsSync(path.join(impactSrc, "incident.json"))) {
  fail("Package missing fixtures/impact-local/incident.json");
}
const impactDest = path.join(outside, "impact-local");
fs.cpSync(impactSrc, impactDest, { recursive: true });

const cliImpact = spawnSync(
  process.execPath,
  [
    path.join(packageDir, "bin/changeguard.js"),
    "impact",
    impactDest,
    "--disclose-refused",
  ],
  {
    cwd: outside,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  },
);
if (cliImpact.status !== 0) {
  fail(
    `CLI impact smoke failed status=${cliImpact.status}\n${cliImpact.stdout}\n${cliImpact.stderr}`,
  );
}
const cliImpactResult = JSON.parse(cliImpact.stdout);
if (!cliImpactResult.ok || !cliImpactResult.impact_card) {
  fail(`CLI impact unexpected: ${cliImpact.stdout.slice(0, 400)}`);
}
if (cliImpactResult.impact_card.transport_calls !== 0) {
  fail("CLI impact disclose-refused must set transport_calls: 0");
}
if (cliImpactResult.impact_card.network_used !== false) {
  fail("CLI impact network_used must be false");
}
if (cliImpactResult.impact_card.disclosure_decision !== "refused") {
  fail("CLI impact disclosure_decision must be refused");
}
if (
  typeof cliImpactResult.impact_card.snapshot_content_sha256 !== "string" ||
  cliImpactResult.impact_card.snapshot_content_sha256.length !== 64
) {
  fail("CLI impact must return snapshot_content_sha256");
}

const mcpImpactResult = await new Promise((resolve, reject) => {
  const child = spawn(mcpCommand, mcpArgs, {
    cwd: mcpCwd,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, NO_COLOR: "1" },
  });
  let buf = "";
  const timer = setTimeout(() => {
    child.kill();
    reject(new Error("MCP impact smoke timeout"));
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
              name: "changeguard_impact",
              arguments: {
                target: impactDest,
                disclosure_decision: "refused",
              },
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
        resolve(
          msg.result?.structuredContent ??
            JSON.parse(msg.result?.content?.[0]?.text ?? "null"),
        );
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
        clientInfo: { name: "package-smoke-impact", version: "0.1.0" },
      },
    }) + "\n",
  );
  child.stdin.write(
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) +
      "\n",
  );
});

if (!mcpImpactResult || !mcpImpactResult.ok || !mcpImpactResult.impact_card) {
  fail(`MCP impact unexpected: ${JSON.stringify(mcpImpactResult)}`);
}
if (mcpImpactResult.impact_card.transport_calls !== 0) {
  fail("MCP impact disclose-refused must set transport_calls: 0");
}
if (
  mcpImpactResult.impact_card.snapshot_content_sha256 !==
  cliImpactResult.impact_card.snapshot_content_sha256
) {
  fail("CLI/MCP impact snapshot_content_sha256 must match");
}
if (
  mcpImpactResult.impact_card.disclosure_decision !==
  cliImpactResult.impact_card.disclosure_decision
) {
  fail("CLI/MCP impact disclosure_decision must match");
}

// Ticket 05: page-evidence analyze-page CLI/MCP equivalence (disclose-refused).
// Require all page fixtures in the package, especially the adversarial injection case
// (must be present and not skipped by packaging filters).
const requiredPageFixtures = [
  "valid-protected-process.json",
  "prompt-injection.json",
  "wrong-platform.json",
  "unsupported-assertion.json",
  "logged-page-clean.json",
  "chatgpt-session.json",
];
for (const name of requiredPageFixtures) {
  const p = path.join(packageDir, "fixtures", "page-evidence", name);
  if (!fs.existsSync(p)) {
    fail(`Package missing fixtures/page-evidence/${name}`);
  }
}
const pageEnvelopeSrc = path.join(
  packageDir,
  "fixtures",
  "page-evidence",
  "valid-protected-process.json",
);
if (!fs.existsSync(pageEnvelopeSrc)) {
  fail("Package missing fixtures/page-evidence/valid-protected-process.json");
}
const pageTargetSrc = path.join(packageDir, "fixtures", "protected-process");
const pageTargetDest = path.join(outside, "page-protected-process");
fs.cpSync(pageTargetSrc, pageTargetDest, { recursive: true });
const pageEnvelopeDest = path.join(outside, "page-envelope.json");
fs.copyFileSync(pageEnvelopeSrc, pageEnvelopeDest);

const cliPage = spawnSync(
  process.execPath,
  [
    path.join(packageDir, "bin/changeguard.js"),
    "analyze-page",
    pageTargetDest,
    `--envelope=${pageEnvelopeDest}`,
    "--disclose-refused",
  ],
  {
    cwd: outside,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  },
);
if (cliPage.status !== 0) {
  fail(
    `CLI analyze-page smoke failed status=${cliPage.status}\n${cliPage.stdout}\n${cliPage.stderr}`,
  );
}
const cliPageResult = JSON.parse(cliPage.stdout);
if (!cliPageResult.ok || !cliPageResult.page_evidence || !cliPageResult.comparison) {
  fail(`CLI analyze-page unexpected: ${cliPage.stdout.slice(0, 400)}`);
}
if (cliPageResult.transport_calls !== 0) {
  fail("CLI analyze-page disclose-refused must set transport_calls: 0");
}
if (cliPageResult.network_used !== false) {
  fail("CLI analyze-page network_used must be false");
}
if (cliPageResult.repair_authorized !== false) {
  fail("CLI analyze-page repair_authorized must be false");
}
if (cliPageResult.target_mutated !== false) {
  fail("CLI analyze-page target_mutated must be false");
}
if (cliPageResult.comparison.applicability !== "applicable_candidate") {
  fail(
    `CLI analyze-page expected applicable_candidate; got ${cliPageResult.comparison.applicability}`,
  );
}

const pageEnvelopeObj = JSON.parse(fs.readFileSync(pageEnvelopeDest, "utf8"));
const mcpPageResult = await new Promise((resolve, reject) => {
  const child = spawn(mcpCommand, mcpArgs, {
    cwd: mcpCwd,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, NO_COLOR: "1" },
  });
  let buf = "";
  const timer = setTimeout(() => {
    child.kill();
    reject(new Error("MCP analyze-page smoke timeout"));
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
              name: "changeguard_analyze_page",
              arguments: {
                target: pageTargetDest,
                envelope: pageEnvelopeObj,
                disclosure_decision: "refused",
              },
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
        resolve(
          msg.result?.structuredContent ??
            JSON.parse(msg.result?.content?.[0]?.text ?? "null"),
        );
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
        clientInfo: { name: "package-smoke-page", version: "0.1.0" },
      },
    }) + "\n",
  );
  child.stdin.write(
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) +
      "\n",
  );
});

if (!mcpPageResult || !mcpPageResult.ok || !mcpPageResult.comparison) {
  fail(`MCP analyze-page unexpected: ${JSON.stringify(mcpPageResult)}`);
}
if (mcpPageResult.transport_calls !== 0) {
  fail("MCP analyze-page refuse must set transport_calls: 0");
}
if (
  mcpPageResult.comparison.applicability !==
  cliPageResult.comparison.applicability
) {
  fail("CLI/MCP analyze-page applicability must match");
}
if (
  mcpPageResult.page_evidence?.content_sha256 !==
  cliPageResult.page_evidence?.content_sha256
) {
  fail("CLI/MCP analyze-page content_sha256 must match");
}

// Hook manifest discovery + entrypoint existence (packaged SessionStart contract).
const hooksManifestPath = path.join(packageDir, "hooks", "hooks.json");
if (!fs.existsSync(hooksManifestPath)) {
  fail("Packaged hooks/hooks.json missing.");
}
let hooksManifest;
try {
  hooksManifest = JSON.parse(fs.readFileSync(hooksManifestPath, "utf8"));
} catch {
  fail("Packaged hooks/hooks.json is not valid JSON.");
}
const sessionStart = hooksManifest?.hooks?.SessionStart;
if (!Array.isArray(sessionStart) || sessionStart.length < 1) {
  fail("hooks.json must declare SessionStart hooks.");
}
const hookHandlers = sessionStart.flatMap((g) =>
  Array.isArray(g?.hooks) ? g.hooks : [],
);
if (hookHandlers.length < 1) {
  fail("SessionStart must declare at least one command handler.");
}
const handler = hookHandlers[0];
if (handler.type !== "command" || typeof handler.command !== "string") {
  fail("SessionStart handler must be type=command with command string.");
}
if (!handler.command.includes("$PLUGIN_ROOT") && !handler.command.includes("${PLUGIN_ROOT}")) {
  fail("SessionStart command must reference PLUGIN_ROOT (POSIX).");
}
if (typeof handler.commandWindows !== "string" || !handler.commandWindows.includes("%PLUGIN_ROOT%")) {
  fail("SessionStart must declare commandWindows with %PLUGIN_ROOT%.");
}
if (handler.timeout !== 10) {
  fail(`SessionStart timeout must be 10 seconds; got ${handler.timeout}`);
}
const entryRel = "dist/hooks/session-start-entry.js";
const entryAbs = path.join(packageDir, entryRel);
if (!fs.existsSync(entryAbs)) {
  fail(`Packaged SessionStart entrypoint missing: ${entryRel}`);
}

// Arbitrary-cwd hook smoke: MODULE_NOT_FOUND must not occur when cwd ≠ package root.
const pluginData = fs.mkdtempSync(path.join(os.tmpdir(), "cg-plugin-data-"));
const hookCwd = fs.mkdtempSync(path.join(os.tmpdir(), "cg-session-cwd-"));
const hookEnv = {
  ...process.env,
  NO_COLOR: "1",
  PLUGIN_ROOT: packageDir,
  PLUGIN_DATA: pluginData,
};
const hookInput = JSON.stringify({
  session_id: "smoke-session",
  cwd: hookCwd,
  hook_event_name: "SessionStart",
  source: "startup",
});
const hook1 = spawnSync(process.execPath, [entryAbs], {
  cwd: hookCwd,
  encoding: "utf8",
  env: hookEnv,
  input: hookInput,
  maxBuffer: 2 * 1024 * 1024,
});
if (hook1.status !== 0) {
  fail(
    `Packaged SessionStart first run failed status=${hook1.status}\nstdout=${hook1.stdout}\nstderr=${hook1.stderr}`,
  );
}
if (/MODULE_NOT_FOUND|Cannot find module/i.test(hook1.stderr || "")) {
  fail("Packaged SessionStart must not MODULE_NOT_FOUND from session cwd.");
}
// First baseline is a change → may emit additionalContext JSON; must not leak paths.
if (hook1.stdout && (hook1.stdout.includes(hookCwd) || hook1.stdout.includes(packageDir))) {
  fail("SessionStart stdout must not disclose raw plugin/session paths.");
}
// Second run with same system view: unchanged → exit 0, no stdout.
const hook2 = spawnSync(process.execPath, [entryAbs], {
  cwd: hookCwd,
  encoding: "utf8",
  env: hookEnv,
  input: hookInput,
  maxBuffer: 2 * 1024 * 1024,
});
if (hook2.status !== 0) {
  fail(`Unchanged SessionStart must exit 0; got ${hook2.status}\n${hook2.stderr}`);
}
if ((hook2.stdout || "") !== "") {
  fail(`Unchanged SessionStart must emit no stdout; got ${JSON.stringify(hook2.stdout)}`);
}
// State must live under PLUGIN_DATA, not session cwd.
const stateFile = path.join(pluginData, "version-state", "version-fingerprint.json");
if (!fs.existsSync(stateFile)) {
  fail("SessionStart must persist version state under PLUGIN_DATA.");
}
const cwdListing = fs.readdirSync(hookCwd);
if (cwdListing.includes("state") || cwdListing.includes("version-fingerprint.json")) {
  fail("SessionStart must not write state into session cwd.");
}

// Ticket 10: packaged upstream-preview from outside repo cwd (no network).
const upstreamReadySrc = path.join(
  packageDir,
  "fixtures",
  "upstream",
  "request-new-incident-cli.json",
);
const upstreamBlockedSrc = path.join(
  packageDir,
  "fixtures",
  "upstream",
  "request-prompt-injection.json",
);
if (!fs.existsSync(upstreamReadySrc) || !fs.existsSync(upstreamBlockedSrc)) {
  fail("Package missing Ticket 10 upstream request fixtures.");
}
const readyReqPath = path.join(outside, "upstream-ready.json");
const blockedReqPath = path.join(outside, "upstream-blocked.json");
fs.copyFileSync(upstreamReadySrc, readyReqPath);
fs.copyFileSync(upstreamBlockedSrc, blockedReqPath);

const readyUp = spawnSync(
  process.execPath,
  [
    path.join(packageDir, "bin/changeguard.js"),
    "upstream-preview",
    fixtureDest,
    `--request=${readyReqPath}`,
    "--disclose-refused",
  ],
  {
    cwd: outside,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  },
);
if (readyUp.status !== 0) {
  fail(
    `Packaged upstream-preview PREVIEW_READY must exit 0; status=${readyUp.status}\n${readyUp.stdout}\n${readyUp.stderr}`,
  );
}
let readyUpResult;
try {
  readyUpResult = JSON.parse(readyUp.stdout);
} catch {
  fail("Packaged upstream-preview PREVIEW_READY stdout is not JSON.");
}
if (
  !readyUpResult.ok ||
  readyUpResult.capsule?.status !== "PREVIEW_READY" ||
  readyUpResult.external_write !== false ||
  readyUpResult.network_used !== false ||
  readyUpResult.submission_status !== "none"
) {
  fail(
    `Packaged upstream-preview PREVIEW_READY contract failed: ${JSON.stringify(readyUpResult)}`,
  );
}

const blockedUp = spawnSync(
  process.execPath,
  [
    path.join(packageDir, "bin/changeguard.js"),
    "upstream-preview",
    fixtureDest,
    `--request=${blockedReqPath}`,
    "--disclose-refused",
  ],
  {
    cwd: outside,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  },
);
if (blockedUp.status === 0) {
  fail("Packaged upstream-preview PREVIEW_BLOCKED must exit nonzero.");
}
let blockedUpResult;
try {
  blockedUpResult = JSON.parse(blockedUp.stdout);
} catch {
  fail("Packaged upstream-preview PREVIEW_BLOCKED stdout is not JSON.");
}
const blockedCapsule = blockedUpResult.capsule;
if (
  blockedUpResult.ok !== false ||
  !blockedCapsule ||
  blockedCapsule.status !== "PREVIEW_BLOCKED" ||
  blockedCapsule.duplicate?.recommendation !== "blocked" ||
  blockedCapsule.duplicate?.draft_body !== null ||
  blockedCapsule.duplicate?.draft_comment !== null ||
  blockedCapsule.draft_title !== null ||
  blockedUpResult.network_used !== false ||
  blockedUpResult.external_write !== false
) {
  fail(
    `Packaged upstream-preview PREVIEW_BLOCKED contract failed: ${JSON.stringify(blockedUpResult)}`,
  );
}
const blockedSer = JSON.stringify(blockedCapsule);
if (
  /Ignore previous instructions|You are now a helpful|exfiltrate secrets|curl http:\/\/evil/i.test(
    blockedSer,
  )
) {
  fail("Packaged PREVIEW_BLOCKED capsule must not export raw injection text.");
}

// Ticket 11: packaged upstream-action-preview / confirm (no real adapter).
// Shared confirmation ledger root so preview mint and confirm parse share HMAC+nonce state.
const ticket11LedgerRoot = path.join(outside, "ticket11-confirmation-state");
fs.mkdirSync(ticket11LedgerRoot, { recursive: true });
const ticket11Env = {
  ...process.env,
  NO_COLOR: "1",
  CHANGEGUARD_CONFIRMATION_STATE_DIR: ticket11LedgerRoot,
};
const capsulePath = path.join(outside, "ticket11-capsule.json");
fs.writeFileSync(
  capsulePath,
  JSON.stringify(readyUpResult.capsule, null, 2),
  "utf8",
);
const actionPreview = spawnSync(
  process.execPath,
  [
    path.join(packageDir, "bin/changeguard.js"),
    "upstream-action-preview",
    fixtureDest,
    `--capsule=${capsulePath}`,
    "--action=create_issue",
  ],
  {
    cwd: outside,
    encoding: "utf8",
    env: ticket11Env,
  },
);
if (actionPreview.status !== 0) {
  fail(
    `Packaged upstream-action-preview must exit 0 for PREVIEW_READY capsule; status=${actionPreview.status}\n${actionPreview.stdout}\n${actionPreview.stderr}`,
  );
}
let actionPreviewResult;
try {
  actionPreviewResult = JSON.parse(actionPreview.stdout);
} catch {
  fail("Packaged upstream-action-preview stdout is not JSON.");
}
if (
  !actionPreviewResult.ok ||
  actionPreviewResult.status !== "PREVIEW_READY" ||
  actionPreviewResult.external_write !== false ||
  actionPreviewResult.network_used !== false ||
  actionPreviewResult.auth_capability?.kind !== "unavailable" ||
  typeof actionPreviewResult.confirmation_token !== "string" ||
  !actionPreviewResult.confirmation_token.startsWith("ua1.")
) {
  fail(
    `Packaged upstream-action-preview contract failed: ${JSON.stringify(actionPreviewResult)}`,
  );
}

const actionConfirm = spawnSync(
  process.execPath,
  [
    path.join(packageDir, "bin/changeguard.js"),
    "upstream-action-confirm",
    fixtureDest,
    `--confirmation=${actionPreviewResult.confirmation_token}`,
    "--decision=confirm",
  ],
  {
    cwd: outside,
    encoding: "utf8",
    env: ticket11Env,
  },
);
if (actionConfirm.status === 0) {
  fail(
    "Packaged upstream-action-confirm without real adapter must exit nonzero (never simulate success).",
  );
}
let actionConfirmResult;
try {
  actionConfirmResult = JSON.parse(actionConfirm.stdout);
} catch {
  fail("Packaged upstream-action-confirm stdout is not JSON.");
}
if (
  actionConfirmResult.ok !== false ||
  actionConfirmResult.status !== "ADAPTER_UNAVAILABLE" ||
  actionConfirmResult.external_write !== false ||
  actionConfirmResult.receipt !== null
) {
  fail(
    `Packaged upstream-action-confirm must stay pure draft: ${JSON.stringify(actionConfirmResult)}`,
  );
}

// Blocked Ticket 10 capsule cannot become actions.
const blockedCapsulePath = path.join(outside, "ticket11-blocked-capsule.json");
fs.writeFileSync(
  blockedCapsulePath,
  JSON.stringify(blockedCapsule, null, 2),
  "utf8",
);
const blockedAction = spawnSync(
  process.execPath,
  [
    path.join(packageDir, "bin/changeguard.js"),
    "upstream-action-preview",
    fixtureDest,
    `--capsule=${blockedCapsulePath}`,
    "--action=create_issue",
  ],
  {
    cwd: outside,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  },
);
if (blockedAction.status === 0) {
  fail("Blocked capsule upstream-action-preview must exit nonzero.");
}
let blockedActionResult;
try {
  blockedActionResult = JSON.parse(blockedAction.stdout);
} catch {
  fail("Blocked capsule upstream-action-preview stdout is not JSON.");
}
if (
  blockedActionResult.ok !== false ||
  blockedActionResult.status !== "BLOCKED_CAPSULE" ||
  blockedActionResult.external_write !== false
) {
  fail(
    `Blocked capsule must not become actions: ${JSON.stringify(blockedActionResult)}`,
  );
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
      public_docs: docsEntries,
      no_node_modules: true,
      no_agents_md: true,
      no_handoff_md: true,
      no_docs_agents: true,
      local_markdown_links_ok: true,
      forbidden_paths_absent: FORBIDDEN_PACKAGED_PATHS,
      session_start_entrypoint: entryRel,
      session_start_command_uses_plugin_root: true,
      session_start_command_windows: handler.commandWindows,
      session_start_timeout: handler.timeout,
      session_start_arbitrary_cwd_ok: true,
      session_start_unchanged_no_stdout: true,
      session_start_state_under_plugin_data: true,
      ticket10_upstream_preview_ready_exit_0: true,
      ticket10_upstream_preview_blocked_nonzero: true,
      ticket10_upstream_preview_no_network: true,
      ticket11_action_preview_ready_exit_0: true,
      ticket11_action_confirm_adapter_unavailable: true,
      ticket11_blocked_capsule_refused: true,
      ticket11_no_real_adapter: true,
    },
    null,
    2,
  ),
);
