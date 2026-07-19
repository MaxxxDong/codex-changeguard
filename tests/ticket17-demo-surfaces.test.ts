/**
 * Ticket 17 S2 — CLI / MCP / Skill demo surfaces.
 * Black-box against public Rescue CLI + MCP; shared runDemo only.
 * Does not claim full Ticket 17 product closeout.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { McpTestClient } from "../src/mcp/client.js";
import {
  mcpServerEntry,
  runCliJson,
} from "../src/harness/scenario.js";
import { REPO_ROOT } from "./helpers.js";
import {
  DEMO_STEP_ORDER,
  runDemo,
  type DemoReceipt,
} from "../src/core/demo/index.js";

const SKILL_PATH = path.join(REPO_ROOT, "skills", "changeguard", "SKILL.md");
const DEMO_SCHEMA_PATH = path.join(
  REPO_ROOT,
  "schemas",
  "demo-receipt.schema.json",
);

function assertNoLeakText(text: string, label = "text"): void {
  assert.equal(/\/Users\//.test(text), false, `${label}: /Users/ leak`);
  assert.equal(/\/home\//.test(text), false, `${label}: /home/ leak`);
  assert.equal(/\.grok-disposable/.test(text), false, `${label}: disposable leak`);
  assert.equal(/grok-worker-/.test(text), false, `${label}: worker id leak`);
  assert.equal(
    /\bcg1\.[A-Za-z0-9_-]+/.test(text),
    false,
    `${label}: auth token leak`,
  );
  assert.equal(
    /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(text),
    false,
    `${label}: Bearer leak`,
  );
  assert.equal(
    /HOME=|USERPROFILE=|TMPDIR=\//.test(text),
    false,
    `${label}: env value leak`,
  );
  assert.equal(
    text.includes("globalThis.process = __cg_shim"),
    false,
    `${label}: source leak`,
  );
  assert.equal(text.includes(os.tmpdir()), false, `${label}: tmpdir leak`);
}

function assertSecurityBooleans(r: Record<string, unknown>, label: string): void {
  assert.equal(r.network_used, false, `${label}: network_used`);
  assert.equal(r.external_write, false, `${label}: external_write`);
  assert.equal(r.live_profile_mutated, false, `${label}: live_profile_mutated`);
  const se = r.security_evidence as Record<string, unknown> | undefined;
  assert.ok(se, `${label}: security_evidence present`);
  assert.equal(typeof se.proven, "boolean", `${label}: proven type`);
  if (r.ok === true) {
    assert.equal(se.proven, true, `${label}: ok requires proven evidence`);
  }
}

/**
 * Schema-level validation for public demo responses (including INVALID_ARGS).
 * Asserts steps.minItems=10, ordered ids, required keys from schema file.
 */
function assertDemoReceiptSchemaLevel(
  r: Record<string, unknown>,
  label: string,
): void {
  const schema = JSON.parse(fs.readFileSync(DEMO_SCHEMA_PATH, "utf8")) as {
    required: string[];
    properties: {
      steps: { minItems: number; maxItems: number };
    };
  };
  assert.equal(schema.properties.steps.minItems, 10);
  assert.equal(schema.properties.steps.maxItems, 10);
  for (const key of schema.required) {
    assert.ok(key in r, `${label}: missing required ${key}`);
  }
  assert.ok(Array.isArray(r.steps), `${label}: steps array`);
  const steps = r.steps as Array<Record<string, unknown>>;
  assert.equal(steps.length, 10, `${label}: steps length === schema minItems`);
  for (let i = 0; i < DEMO_STEP_ORDER.length; i++) {
    assert.equal(
      steps[i]?.id,
      DEMO_STEP_ORDER[i],
      `${label}: step[${i}] id`,
    );
    assert.ok(
      ["pass", "fail", "skip", "refused"].includes(String(steps[i]?.status)),
      `${label}: step status`,
    );
  }
  assert.equal(r.network_used, false);
  assert.equal(r.external_write, false);
  assert.equal(r.live_profile_mutated, false);
  assert.ok(r.security_evidence, `${label}: security_evidence`);
}

function assertCrashRefusalBound(
  r: Record<string, unknown>,
  label: string,
): void {
  const crash = r.crash_refusal as Record<string, unknown> | undefined;
  assert.ok(crash, `${label}: crash_refusal present`);
  assert.equal(
    crash.repair_authorization_eligible,
    false,
    `${label}: repair_authorization_eligible`,
  );
  assert.equal(crash.preview_refused, true, `${label}: preview_refused`);
  assert.equal(
    typeof crash.family_id,
    "string",
    `${label}: family_id type`,
  );
  assert.ok(
    typeof crash.family_id === "string" && crash.family_id.length > 0,
    `${label}: family_id nonempty`,
  );
  assert.ok(
    Array.isArray(crash.refused_actions) &&
      (crash.refused_actions as unknown[]).length > 0,
    `${label}: refused_actions nonempty`,
  );
  assert.ok(
    Array.isArray(crash.reason_codes) &&
      (crash.reason_codes as unknown[]).length > 0,
    `${label}: reason_codes nonempty`,
  );
  const refused = crash.refused_actions as string[];
  assert.ok(
    refused.includes("symptom_level_patch_authorization") ||
      refused.includes("unverified_community_browser_crash_fix"),
    `${label}: dangerous-action refusal present`,
  );
}

/**
 * Normalize DemoReceipt for CLI/MCP stable-field equivalence.
 * Strips nondeterministic timing and keeps ordered step ids/statuses/reason_codes
 * plus security booleans and lifecycle outcomes.
 */
function stableDemoFields(r: Record<string, unknown>): unknown {
  const steps = Array.isArray(r.steps)
    ? (r.steps as Array<Record<string, unknown>>).map((s) => ({
        id: s.id,
        status: s.status,
        reason_code: s.reason_code,
      }))
    : [];
  return {
    schema_version: r.schema_version,
    ok: r.ok,
    status: r.status,
    steps,
    main: r.main,
    model_refusal: r.model_refusal,
    crash_refusal: r.crash_refusal,
    network_used: r.network_used,
    external_write: r.external_write,
    live_profile_mutated: r.live_profile_mutated,
    security_evidence: r.security_evidence,
    cleanup: r.cleanup,
    error_code: r.error_code,
    // error_message may be null on success; keep for fail-path equivalence.
    error_message: r.error_message,
  };
}

/**
 * Raw MCP tools/call that preserves isError (callTool only returns structured content).
 * Replicates initialize handshake used by McpTestClient.ensureInitialized.
 */
async function runMcpDemo(
  args: Record<string, unknown> = {},
): Promise<{
  payload: Record<string, unknown> | null;
  isError: boolean | undefined;
  rawText: string;
  error: unknown;
}> {
  const client = new McpTestClient({
    serverEntry: mcpServerEntry(),
    timeoutMs: 120_000,
  });
  try {
    client.start();
    await client.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "t17-demo-test", version: "0.1.0" },
    });
    // Match client ensureInitialized: send initialized notification.
    (
      client as unknown as {
        child: { stdin: { write: (s: string) => void } } | null;
      }
    ).child?.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }) + "\n",
    );
    const result = (await client.request("tools/call", {
      name: "changeguard_demo",
      arguments: args,
    })) as {
      structuredContent?: unknown;
      content?: Array<{ type: string; text: string }>;
      isError?: boolean;
    };
    const textPart = result.content?.find((c) => c.type === "text")?.text;
    const payload =
      result.structuredContent && typeof result.structuredContent === "object"
        ? (result.structuredContent as Record<string, unknown>)
        : textPart
          ? (JSON.parse(textPart) as Record<string, unknown>)
          : null;
    const rawText = textPart ?? JSON.stringify(payload ?? {});
    return { payload, isError: result.isError, rawText, error: null };
  } catch (e) {
    return {
      payload: null,
      isError: true,
      rawText: e instanceof Error ? e.message : String(e),
      error: e,
    };
  } finally {
    await client.close();
  }
}

// ---------------------------------------------------------------------------
// CLI success + arg validation
// ---------------------------------------------------------------------------

test("Ticket17 surfaces: CLI demo default success exit 0 + receipt.ok", () => {
  const { exitCode, result, stdout } = runCliJson(["demo"]);
  assert.equal(exitCode, 0);
  assert.ok(result);
  assert.equal(result.ok, true);
  assert.equal(result.status, "completed");
  assert.equal(result.schema_version, 1);
  assertSecurityBooleans(result, "cli-success");
  assertCrashRefusalBound(result, "cli-success");
  assert.equal(Array.isArray(result.steps), true);
  assert.equal((result.steps as unknown[]).length, 10);
  assert.equal(
    (result.cleanup as { temp_removed?: boolean }).temp_removed,
    true,
  );
  assertNoLeakText(stdout, "cli-stdout");
  assertNoLeakText(JSON.stringify(result), "cli-result");
});

test("Ticket17 surfaces: CLI rejects malformed budget and extra args without side effects", () => {
  const tmp = os.tmpdir();
  const before = fs
    .readdirSync(tmp)
    .filter((n) => n.startsWith("cg-demo-"));

  const cases: string[][] = [
    ["demo", "--budget-ms=not-a-number"],
    ["demo", "--budget-ms=0"],
    ["demo", "--budget-ms=-1"],
    ["demo", "--budget-ms"],
    ["demo", "--unknown"],
    ["demo", "some-path"],
    ["demo", "--target=/tmp/x"],
    ["demo", "--induce-verify-failure"],
    ["demo", "--budget-ms=1", "extra"],
  ];
  for (const args of cases) {
    const { exitCode, result, stdout } = runCliJson(args);
    assert.notEqual(exitCode, 0, `expected nonzero for ${args.join(" ")}`);
    assert.ok(result);
    assert.equal(result.ok, false, `ok false for ${args.join(" ")}`);
    // Usage failures must not claim completed happy path.
    assert.notEqual(result.status, "completed");
    // No successful step story on pure parse refuse.
    if (result.error_code === "INVALID_ARGS") {
      // Schema-valid: minItems=10 ordered steps (skipped/refused), not empty.
      assertDemoReceiptSchemaLevel(result, `cli-invalid:${args.join(" ")}`);
      const steps = result.steps as Array<{ status: string; reason_code: string | null }>;
      assert.ok(
        steps.every(
          (s) => s.status === "skip" || s.status === "refused",
        ),
        `INVALID_ARGS steps must be skip/refused for ${args.join(" ")}`,
      );
      assert.equal(
        (result.cleanup as { attempted?: boolean }).attempted,
        false,
      );
      assert.equal(result.ok, false);
      const se = result.security_evidence as { proven?: boolean };
      assert.equal(se.proven, false, "INVALID_ARGS must not claim proven");
    }
    assertNoLeakText(stdout, `cli-bad:${args.join(" ")}`);
  }

  const after = fs
    .readdirSync(tmp)
    .filter((n) => n.startsWith("cg-demo-"));
  assert.ok(
    after.length <= before.length,
    `demo side-effect temp leak on bad args: before=${before.length} after=${after.length}`,
  );
});

test("Ticket17 surfaces: CLI accepts bounded budget-ms", () => {
  const { exitCode, result, stdout } = runCliJson([
    "demo",
    "--budget-ms=120000",
  ]);
  assert.equal(exitCode, 0);
  assert.equal(result?.ok, true);
  assert.equal(result?.status, "completed");
  assertNoLeakText(stdout, "cli-budget");
});

// ---------------------------------------------------------------------------
// MCP success + strict schema
// ---------------------------------------------------------------------------

test("Ticket17 surfaces: MCP changeguard_demo success", async () => {
  const { payload, isError, rawText, error } = await runMcpDemo({});
  assert.equal(error, null, String(error));
  assert.ok(payload);
  assert.equal(payload.ok, true);
  assert.equal(payload.status, "completed");
  assert.equal(isError, false);
  assertSecurityBooleans(payload, "mcp-success");
  assertCrashRefusalBound(payload, "mcp-success");
  assertNoLeakText(rawText, "mcp-raw");
  assertNoLeakText(JSON.stringify(payload), "mcp-payload");
});

test("Ticket17 surfaces: MCP strict unknown-field refusal", async () => {
  const client = new McpTestClient({
    serverEntry: mcpServerEntry(),
    timeoutMs: 30_000,
  });
  try {
    client.start();
    await client.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "t17-demo-test", version: "0.1.0" },
    });
    let refused = false;
    try {
      await client.request("tools/call", {
        name: "changeguard_demo",
        arguments: { target: "/tmp/evil", induce_verify_failure: true },
      });
    } catch (e) {
      refused = true;
      const msg = e instanceof Error ? e.message : String(e);
      assert.match(msg, /Unknown or extra|extra arguments|EXTRA/i);
      assertNoLeakText(msg, "mcp-extra-err");
    }
    assert.equal(refused, true, "unknown fields must refuse");

    // Invalid budget
    let badBudget = false;
    try {
      await client.request("tools/call", {
        name: "changeguard_demo",
        arguments: { budget_ms: 0 },
      });
    } catch {
      badBudget = true;
    }
    assert.equal(badBudget, true, "budget_ms=0 must refuse");
  } finally {
    await client.close();
  }
});

// ---------------------------------------------------------------------------
// CLI / MCP stable-field equivalence
// ---------------------------------------------------------------------------

test("Ticket17 surfaces: CLI/MCP stable-field equivalence", async () => {
  const cli = runCliJson(["demo"]);
  assert.equal(cli.exitCode, 0);
  assert.ok(cli.result);

  const mcp = await runMcpDemo({});
  assert.equal(mcp.error, null);
  assert.ok(mcp.payload);
  assert.equal(mcp.isError, false);

  const a = stableDemoFields(cli.result);
  const b = stableDemoFields(mcp.payload);
  assert.deepEqual(a, b);

  // Security booleans present on both
  assertSecurityBooleans(cli.result, "eq-cli");
  assertSecurityBooleans(mcp.payload, "eq-mcp");
  assertCrashRefusalBound(cli.result, "eq-cli");
  assertCrashRefusalBound(mcp.payload, "eq-mcp");

  // Ordered step outcomes
  const cliSteps = cli.result.steps as Array<{ id: string; status: string }>;
  const mcpSteps = mcp.payload.steps as Array<{ id: string; status: string }>;
  assert.deepEqual(
    cliSteps.map((s) => s.id),
    mcpSteps.map((s) => s.id),
  );
  assert.deepEqual(
    cliSteps.map((s) => s.status),
    mcpSteps.map((s) => s.status),
  );
});

// ---------------------------------------------------------------------------
// Internal induce seam not a surface control
// ---------------------------------------------------------------------------

test("Ticket17 surfaces: induce_verify_failure is internal-only (not CLI/MCP args)", () => {
  // Core still supports induce for tests.
  const induced = runDemo({ induce_verify_failure: true }) as DemoReceipt;
  assert.equal(induced.ok, true); // story completes with rollback path
  assert.equal(induced.main.resolved_verified, false);
  assert.equal(induced.main.auto_rolled_back, true);

  // Surfaces reject induce / target controls.
  const cli = runCliJson(["demo", "--induce_verify_failure=true"]);
  assert.notEqual(cli.exitCode, 0);
  assert.equal(cli.result?.ok, false);
  assert.equal(cli.result?.error_code, "INVALID_ARGS");
  assert.ok(cli.result);
  assertDemoReceiptSchemaLevel(cli.result!, "cli-induce-invalid");
});

test("Ticket17 surfaces: no _testHooks field/control on RunDemoOptions/CLI/MCP", () => {
  // Callback test-hook surface must not exist on options or public surfaces.
  const typesSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/core/demo/types.ts"),
    "utf8",
  );
  assert.equal(
    /_testHooks|RunDemoTestHooks|beforeMutationTargetProof/.test(typesSrc),
    false,
    "RunDemoOptions must not declare _testHooks",
  );

  const cliSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/cli/main.ts"),
    "utf8",
  );
  const mcpSrc = fs.readFileSync(
    path.join(REPO_ROOT, "src/mcp/server.ts"),
    "utf8",
  );
  for (const [label, src] of [
    ["cli", cliSrc],
    ["mcp", mcpSrc],
  ] as const) {
    assert.equal(
      /_testHooks|RunDemoTestHooks|beforeMutationTargetProof/.test(src),
      false,
      `${label}: must not reference test-hook controls`,
    );
  }

  // Unknown / hook-like flags still fail closed as INVALID_ARGS (schema-valid).
  const cli = runCliJson(["demo", "--_testHooks=1"]);
  assert.notEqual(cli.exitCode, 0);
  assert.equal(cli.result?.ok, false);
  assert.equal(cli.result?.error_code, "INVALID_ARGS");
  assert.ok(cli.result);
  assertDemoReceiptSchemaLevel(cli.result!, "cli-testhooks-invalid");

  // Schema still requires value_valid on network observations when present.
  const schema = JSON.parse(fs.readFileSync(DEMO_SCHEMA_PATH, "utf8")) as {
    properties: {
      security_evidence: {
        properties: {
          network_observations: {
            items: { required: string[] };
          };
        };
      };
    };
  };
  assert.ok(
    schema.properties.security_evidence.properties.network_observations.items.required.includes(
      "value_valid",
    ),
    "schema requires value_valid on network observations",
  );
});

test("Ticket17 surfaces: INVALID_ARGS DemoReceipt is schema-valid (minItems=10)", () => {
  const { exitCode, result } = runCliJson(["demo", "--unknown-flag"]);
  assert.notEqual(exitCode, 0);
  assert.ok(result);
  assert.equal(result.error_code, "INVALID_ARGS");
  assertDemoReceiptSchemaLevel(result, "invalid-args-schema");
  // Schema file itself requires steps.minItems=10 (not just a length assert).
  const schema = JSON.parse(fs.readFileSync(DEMO_SCHEMA_PATH, "utf8")) as {
    properties: { steps: { minItems: number; maxItems: number } };
    required: string[];
  };
  assert.equal(schema.properties.steps.minItems, 10);
  assert.equal(schema.properties.steps.maxItems, 10);
  assert.ok(schema.required.includes("security_evidence"));
  assert.ok(schema.required.includes("steps"));
});

// ---------------------------------------------------------------------------
// Skill documentation contract
// ---------------------------------------------------------------------------

test("Ticket17 surfaces: Skill documents /changeguard demo judge contract", () => {
  const text = fs.readFileSync(SKILL_PATH, "utf8");
  assert.match(text, /\/changeguard demo/);
  assert.match(text, /changeguard_demo/);
  assert.match(text, /runDemo/);
  assert.match(text, /deterministic|no model|no-model|no network/i);
  assert.match(text, /disposable/i);
  assert.match(text, /rollback/i);
  assert.match(text, /cleanup/i);
  assert.match(text, /model.?refus/i);
  assert.match(text, /crash.?refus/i);
  assert.match(text, /Gate C|publication|registration/i);
  // Must forbid shell workarounds — not prescribe them as the primary path.
  assert.match(text, /no shell workaround|shell workarounds or/i);
  assert.equal(/bash -c demo|curl .*demo/i.test(text), false);
});

// ---------------------------------------------------------------------------
// tools/list advertises demo with strict schema
// ---------------------------------------------------------------------------

test("Ticket17 surfaces: MCP tools/list includes changeguard_demo strict schema", async () => {
  const client = new McpTestClient({
    serverEntry: mcpServerEntry(),
    timeoutMs: 15_000,
  });
  try {
    client.start();
    await client.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "t17-demo-test", version: "0.1.0" },
    });
    const listed = (await client.request("tools/list", {})) as {
      tools?: Array<{ name: string; inputSchema?: Record<string, unknown> }>;
    };
    const tool = listed.tools?.find((t) => t.name === "changeguard_demo");
    assert.ok(tool, "changeguard_demo listed");
    assert.equal(tool!.inputSchema?.additionalProperties, false);
    const props = tool!.inputSchema?.properties as
      | Record<string, unknown>
      | undefined;
    assert.ok(props);
    assert.ok("budget_ms" in props!);
    assert.equal("target" in props!, false);
    assert.equal("induce_verify_failure" in props!, false);
  } finally {
    await client.close();
  }
});
