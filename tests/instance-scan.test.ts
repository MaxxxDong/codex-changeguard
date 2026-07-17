/**
 * Ticket 03 — multi-instance / version detection Scenario Harness.
 * Covers baseline, unchanged, upgrade, downgrade, PATH drift, hooks,
 * manual fallback, actual-instance evidence, ambiguous refusal, duration,
 * and raw-path non-disclosure.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  runCliScan,
  runCliSessionStart,
  runMcpScan,
} from "../src/harness/scenario.js";
import {
  bindRepairTarget,
  instanceFingerprintOf,
  pathHashOf,
  scanInstances,
} from "../src/instances/index.js";
import { runSessionStart } from "../src/hooks/session-start.js";
import type { ScanResult } from "../src/instances/types.js";
import { makeTempDir, writeJson } from "./helpers.js";

function assertNoRawPathLeak(text: string, inventoryRoot: string): void {
  assert.equal(/\/Users\//.test(text), false, "Users path leak");
  assert.equal(/\/home\//.test(text), false, "home path leak");
  assert.equal(/\.grok-disposable/.test(text), false, "disposable path leak");
  assert.equal(
    text.includes(inventoryRoot),
    false,
    "inventory root must not appear in public output",
  );
  // Windows-ish raw paths
  assert.equal(/[A-Za-z]:\\Users\\/.test(text), false, "Windows Users leak");
}

interface CandSpec {
  install_source:
    | "desktop_bundled"
    | "path"
    | "package_manager"
    | "windows_msix"
    | "wsl";
  surface: "desktop" | "cli";
  relative_path: string;
  version: string;
  build?: string;
  path_precedence?: number;
  profile_root_alias?: string;
  config_root_alias?: string;
}

function buildInventory(
  tmp: string,
  candidates: CandSpec[],
  observed?: Record<string, unknown>,
): string {
  const root = path.join(tmp, "inventory");
  fs.mkdirSync(root, { recursive: true });
  for (const c of candidates) {
    const abs = path.join(root, c.relative_path);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    // Placeholder binary bytes — never executed for version.
    fs.writeFileSync(abs, "#!/bin/sh\n# fixture binary placeholder\n", "utf8");
    // Metadata beside binary so version is read without execution.
    writeJson(path.join(path.dirname(abs), "version.json"), {
      version: c.version,
      build: c.build ?? null,
    });
  }
  writeJson(path.join(root, "inventory.json"), {
    schema_version: 1,
    platform: "macos",
    arch: "arm64",
    candidates: candidates.map((c) => ({
      install_source: c.install_source,
      surface: c.surface,
      relative_path: c.relative_path,
      path_precedence: c.path_precedence,
      profile_root_alias: c.profile_root_alias ?? null,
      config_root_alias: c.config_root_alias ?? null,
      // Prefer metadata file over declared to exercise non-exec path.
      version_metadata_rel: path.posix.join(
        path.dirname(c.relative_path).split(path.sep).join("/"),
        "version.json",
      ),
    })),
    observed_context: observed ?? {},
  });
  return root;
}

function asScan(result: unknown): ScanResult {
  assert.ok(result && typeof result === "object");
  return result as ScanResult;
}

test("first baseline establishes state without claiming upgrade", () => {
  const tmp = makeTempDir("cg-t03-base-");
  const root = buildInventory(tmp, [
    {
      install_source: "desktop_bundled",
      surface: "desktop",
      relative_path: "desktop/Codex.app/Contents/MacOS/Codex",
      version: "0.40.0",
      profile_root_alias: "DESKTOP_PROFILE",
    },
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path/bin/codex",
      version: "0.40.0",
      path_precedence: 0,
    },
    {
      install_source: "package_manager",
      surface: "cli",
      relative_path: "pkg/bin/codex",
      version: "0.39.0",
    },
    {
      install_source: "windows_msix",
      surface: "desktop",
      relative_path: "msix/Codex/Codex.exe",
      version: "0.40.1",
    },
    {
      install_source: "wsl",
      surface: "cli",
      relative_path: "wsl/usr/local/bin/codex",
      version: "0.40.0",
    },
  ]);

  const { exitCode, result, stdout } = runCliScan(root);
  const scan = asScan(result);
  assert.equal(exitCode, 0);
  assert.equal(scan.ok, true);
  assert.equal(scan.primary_transition, "first_baseline");
  assert.equal(scan.fingerprint_changed, true);
  assert.equal(scan.state_updated, true);
  assert.equal(scan.instances.length, 5);
  const sources = new Set(scan.instances.map((i) => i.install_source));
  assert.ok(sources.has("desktop_bundled"));
  assert.ok(sources.has("path"));
  assert.ok(sources.has("package_manager"));
  assert.ok(sources.has("windows_msix"));
  assert.ok(sources.has("wsl"));
  // Never collapse multi-instance.
  assert.equal(new Set(scan.instances.map((i) => i.instance_id)).size, 5);
  // No raw paths in public output.
  assertNoRawPathLeak(stdout, root);
  for (const inst of scan.instances) {
    assert.ok(inst.path_hash && /^[a-f0-9]{64}$/.test(inst.path_hash));
    assert.ok(inst.path_alias);
    assert.ok(!inst.path_alias.includes("/"));
    assert.ok(inst.version_provenance === "version_file");
  }
  assert.equal(scan.network_used, false);
  assert.equal(scan.target_mutated, false);
  assert.ok(
    fs.existsSync(path.join(root, "state", "version-fingerprint.json")),
  );
});

test("unchanged fingerprint is silent on SessionStart and under 10s", () => {
  const tmp = makeTempDir("cg-t03-unchanged-");
  const root = buildInventory(tmp, [
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path/bin/codex",
      version: "0.41.0",
      path_precedence: 0,
    },
  ]);
  // Establish baseline.
  const first = asScan(runCliScan(root).result);
  assert.equal(first.primary_transition, "first_baseline");

  const session = runCliSessionStart(root, "trusted");
  const scan = asScan(session.result);
  assert.equal(session.exitCode, 0);
  assert.equal(scan.silent, true);
  assert.equal(scan.fingerprint_changed, false);
  assert.equal(scan.primary_transition, "unchanged");
  assert.equal(scan.health_check, null);
  assert.equal(scan.state_updated, false);
  assert.ok(
    session.durationMs < 10_000,
    `SessionStart no-change must be <10s, got ${session.durationMs}`,
  );
  assertNoRawPathLeak(session.stdout, root);
});

test("multi-instance upgrade classifies upgrade without picking newest as affected by default", () => {
  const tmp = makeTempDir("cg-t03-upgrade-");
  const root = buildInventory(tmp, [
    {
      install_source: "desktop_bundled",
      surface: "desktop",
      relative_path: "desktop/Codex",
      version: "0.40.0",
    },
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path/bin/codex",
      version: "0.40.0",
      path_precedence: 0,
    },
  ]);
  asScan(runCliScan(root).result);

  // Upgrade only PATH instance.
  writeJson(path.join(root, "path/bin/version.json"), {
    version: "0.50.0",
    build: null,
  });
  // Bump desktop slightly less so PATH is newer — still must not auto-select it.
  writeJson(path.join(root, "desktop/version.json"), {
    version: "0.41.0",
    build: null,
  });

  const scan = asScan(runCliScan(root).result);
  assert.equal(scan.primary_transition, "upgrade");
  assert.ok(scan.transitions.some((t) => t.class === "upgrade"));
  assert.equal(scan.instances.length, 2);
  // Without observed context, multi-instance remains ambiguous.
  assert.equal(scan.affected_resolution, "ambiguous");
  assert.equal(scan.affected_instance_id, null);
  // Newest must not be auto-bound for repair.
  const binding = bindRepairTarget(scan.instances, {}, {
    affected_resolution: scan.affected_resolution,
    affected_instance_id: scan.affected_instance_id,
  });
  assert.equal(binding.ok, false);
  assert.equal(binding.error_code, "AMBIGUOUS_TARGET");
});

test("downgrade is classified as downgrade", () => {
  const tmp = makeTempDir("cg-t03-down-");
  const root = buildInventory(tmp, [
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path/bin/codex",
      version: "0.50.0",
      path_precedence: 0,
    },
  ]);
  asScan(runCliScan(root).result);
  writeJson(path.join(root, "path/bin/version.json"), {
    version: "0.40.0",
    build: null,
  });
  const scan = asScan(runCliScan(root).result);
  assert.equal(scan.primary_transition, "downgrade");
  assert.ok(scan.transitions.some((t) => t.class === "downgrade"));
});

test("PATH precedence drift is detected without collapsing instances", () => {
  const tmp = makeTempDir("cg-t03-path-");
  const root = buildInventory(tmp, [
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path-a/codex",
      version: "0.40.0",
      path_precedence: 0,
    },
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path-b/codex",
      version: "0.40.0",
      path_precedence: 1,
    },
  ]);
  asScan(runCliScan(root).result);

  // Swap precedence in inventory.
  const inv = JSON.parse(
    fs.readFileSync(path.join(root, "inventory.json"), "utf8"),
  ) as {
    candidates: Array<{ relative_path: string; path_precedence: number }>;
  };
  for (const c of inv.candidates) {
    if (c.relative_path === "path-a/codex") c.path_precedence = 1;
    if (c.relative_path === "path-b/codex") c.path_precedence = 0;
  }
  writeJson(path.join(root, "inventory.json"), inv);

  const scan = asScan(runCliScan(root).result);
  assert.ok(
    scan.transitions.some((t) => t.class === "path_precedence_drift"),
    JSON.stringify(scan.transitions),
  );
  assert.equal(scan.instances.length, 2);
  assert.equal(new Set(scan.instances.map((i) => i.instance_id)).size, 2);
});

test("untrusted and failed hooks are explicit; manual scan remains equivalent", async () => {
  const tmp = makeTempDir("cg-t03-hook-");
  const root = buildInventory(tmp, [
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path/bin/codex",
      version: "0.42.0",
      path_precedence: 0,
    },
  ]);

  const untrusted = asScan(runCliSessionStart(root, "untrusted").result);
  assert.equal(untrusted.hook_status, "untrusted");
  assert.equal(untrusted.ok, false);
  assert.equal(untrusted.error_code, "HOOK_UNTRUSTED");
  assert.equal(untrusted.state_updated, false);

  const skipped = asScan(runCliSessionStart(root, "skipped").result);
  assert.equal(skipped.hook_status, "skipped");
  assert.equal(skipped.error_code, "HOOK_SKIPPED");

  const failed = asScan(runCliSessionStart(root, "failed").result);
  assert.equal(failed.hook_status, "failed");
  assert.equal(failed.error_code, "HOOK_FAILED");

  // Manual fallback works and is equivalent to trusted scan core.
  const manual = asScan(runCliScan(root).result);
  assert.equal(manual.ok, true);
  assert.equal(manual.mode, "manual_scan");
  assert.equal(manual.primary_transition, "first_baseline");

  const mcp = asScan(await runMcpScan(root));
  assert.equal(mcp.ok, true);
  // After manual baseline, MCP scan of same root should be unchanged.
  assert.equal(mcp.primary_transition, "unchanged");
  assert.equal(mcp.fingerprint_changed, false);
  assert.deepEqual(
    manual.instances.map((i) => i.instance_id).sort(),
    // first manual wrote state; mcp second pass — instances still match identity
    mcp.instances.map((i) => i.instance_id).sort(),
  );
});

test("SessionStart on change runs health check under 10 seconds", () => {
  const tmp = makeTempDir("cg-t03-health-");
  const root = buildInventory(tmp, [
    {
      install_source: "path",
      surface: "cli",
      relative_path: "path/bin/codex",
      version: "0.40.0",
      path_precedence: 0,
    },
  ]);
  asScan(runCliScan(root).result);
  writeJson(path.join(root, "path/bin/version.json"), {
    version: "0.55.0",
    build: "deadbeef",
  });

  const t0 = performance.now();
  const session = runSessionStart({
    inventoryRoot: root,
    hookTrust: "trusted",
  });
  const elapsed = performance.now() - t0;
  assert.equal(session.ok, true);
  assert.equal(session.silent, false);
  assert.equal(session.fingerprint_changed, true);
  assert.ok(session.health_check);
  assert.equal(session.health_check!.read_only, true);
  assert.equal(session.health_check!.bounded, true);
  assert.ok(session.health_check!.duration_ms < 10_000);
  assert.ok(elapsed < 10_000, `changed SessionStart took ${elapsed}ms`);
  assert.ok(session.health_check!.ok);
});

test("actual-instance evidence identifies the failing install; never highest version", () => {
  const tmp = makeTempDir("cg-t03-affected-");
  const root = buildInventory(
    tmp,
    [
      {
        install_source: "desktop_bundled",
        surface: "desktop",
        relative_path: "desktop/Codex",
        version: "0.99.0", // higher
      },
      {
        install_source: "path",
        surface: "cli",
        relative_path: "path/bin/codex",
        version: "0.40.0", // lower, but actually failing
        path_precedence: 0,
      },
    ],
    { process_path_rel: "path/bin/codex" },
  );
  const scan = asScan(
    scanInstances({ inventoryRoot: root, mode: "manual_scan" }),
  );
  assert.equal(scan.affected_resolution, "identified");
  assert.ok(scan.affected_instance_id);
  const affected = scan.instances.find(
    (i) => i.instance_id === scan.affected_instance_id,
  );
  assert.ok(affected);
  assert.equal(affected!.install_source, "path");
  assert.equal(affected!.version, "0.40.0");
  // Highest version is desktop — must not be selected.
  assert.notEqual(affected!.version, "0.99.0");

  const binding = bindRepairTarget(
    scan.instances,
    { instance_id: scan.affected_instance_id },
    {
      affected_resolution: scan.affected_resolution,
      affected_instance_id: scan.affected_instance_id,
    },
  );
  assert.equal(binding.ok, true);
  assert.equal(binding.instance?.install_source, "path");
});

test("ambiguous multi-instance refuses repair binding and broadcast", () => {
  const tmp = makeTempDir("cg-t03-ambig-");
  const root = buildInventory(tmp, [
    {
      install_source: "path",
      surface: "cli",
      relative_path: "a/codex",
      version: "0.40.0",
      path_precedence: 0,
    },
    {
      install_source: "path",
      surface: "cli",
      relative_path: "b/codex",
      version: "0.41.0",
      path_precedence: 1,
    },
  ]);
  const scan = asScan(
    scanInstances({ inventoryRoot: root, mode: "manual_scan" }),
  );
  assert.equal(scan.affected_resolution, "ambiguous");

  const noId = bindRepairTarget(scan.instances, {}, {
    affected_resolution: "ambiguous",
    affected_instance_id: null,
  });
  assert.equal(noId.ok, false);
  assert.equal(noId.error_code, "AMBIGUOUS_TARGET");

  const broadcast = bindRepairTarget(scan.instances, {
    broadcast: true,
    instance_id: scan.instances[0]!.instance_id,
  });
  assert.equal(broadcast.ok, false);
  assert.equal(broadcast.error_code, "BROADCAST_REFUSED");

  const multi = bindRepairTarget(scan.instances, {
    instance_ids: scan.instances.map((i) => i.instance_id),
  });
  assert.equal(multi.ok, false);
  assert.equal(multi.error_code, "BROADCAST_REFUSED");

  // Exact one id + matching fingerprint is accepted.
  const one = scan.instances[0]!;
  const ok = bindRepairTarget(scan.instances, {
    instance_id: one.instance_id,
    instance_fingerprint: instanceFingerprintOf(one),
  });
  assert.equal(ok.ok, true);
});

test("CLI and MCP scan results are consistent for stable fields", async () => {
  const tmp = makeTempDir("cg-t03-eq-");
  const root = buildInventory(tmp, [
    {
      install_source: "package_manager",
      surface: "cli",
      relative_path: "npm/bin/codex",
      version: "0.44.0",
    },
    {
      install_source: "wsl",
      surface: "cli",
      relative_path: "wsl/bin/codex",
      version: "0.44.0",
    },
  ]);
  // Use core twice with persistState false for pure equivalence, then public seams.
  const a = scanInstances({
    inventoryRoot: root,
    mode: "manual_scan",
    persistState: false,
  });
  const b = scanInstances({
    inventoryRoot: root,
    mode: "manual_scan",
    persistState: false,
  });
  assert.equal(a.overall_fingerprint, b.overall_fingerprint);
  assert.deepEqual(
    a.instances.map((i) => i.instance_id).sort(),
    b.instances.map((i) => i.instance_id).sort(),
  );

  const cli = asScan(runCliScan(root).result);
  // Fresh MCP against same state after CLI baseline → unchanged
  const mcp = asScan(await runMcpScan(root));
  assert.equal(cli.instances.length, mcp.instances.length);
  assert.deepEqual(
    cli.instances.map((i) => i.path_hash).sort(),
    mcp.instances.map((i) => i.path_hash).sort(),
  );
  assert.equal(mcp.fingerprint_changed, false);
});

test("version evidence never requires executing candidates; path hashes stay stable", () => {
  const tmp = makeTempDir("cg-t03-meta-");
  const root = buildInventory(tmp, [
    {
      install_source: "desktop_bundled",
      surface: "desktop",
      relative_path: "App/Codex",
      version: "1.2.3",
      build: "abc",
    },
  ]);
  // Corrupt the placeholder "binary" — still must not execute; metadata wins.
  fs.writeFileSync(
    path.join(root, "App/Codex"),
    "not-a-real-binary\n",
    "utf8",
  );
  writeJson(path.join(root, "App/version.json"), {
    version: "1.2.3",
    build: "abc",
  });
  const scan = scanInstances({
    inventoryRoot: root,
    mode: "manual_scan",
    persistState: false,
  });
  assert.equal(scan.ok, true);
  assert.equal(scan.instances[0]!.version, "1.2.3");
  assert.equal(scan.instances[0]!.version_provenance, "version_file");
  const expectedHash = pathHashOf(path.join(root, "App/Codex"));
  assert.equal(scan.instances[0]!.path_hash, expectedHash);
});

test("state refuses symlink state file", () => {
  const tmp = makeTempDir("cg-t03-symlink-");
  const root = buildInventory(tmp, [
    {
      install_source: "path",
      surface: "cli",
      relative_path: "bin/codex",
      version: "0.1.0",
      path_precedence: 0,
    },
  ]);
  const stateDir = path.join(root, "state");
  fs.mkdirSync(stateDir, { recursive: true });
  const target = path.join(tmp, "evil.json");
  fs.writeFileSync(target, "{}", "utf8");
  fs.symlinkSync(target, path.join(stateDir, "version-fingerprint.json"));
  const scan = scanInstances({ inventoryRoot: root, mode: "manual_scan" });
  assert.equal(scan.ok, false);
  assert.equal(scan.error_code, "SYMLINK_REFUSED");
});
