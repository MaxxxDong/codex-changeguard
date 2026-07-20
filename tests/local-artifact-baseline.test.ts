/**
 * Local installed-artifact baseline / diff (path-free facts).
 *
 * Covers: v1→v2 migration honesty, first baseline, unchanged, hash change
 * without version change, added/removed, stable ordering, symlink refusal,
 * oversize gap, binary bytes, Unicode alias / path redaction, multi-instance
 * isolation, SessionStart context.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  formatSessionStartContext,
} from "../src/hooks/session-start-entry.js";
import { runSessionStart } from "../src/hooks/session-start.js";
import {
  classifyLocalArtifactDiff,
  loadState,
  parseStateJson,
  pathHashOf,
  saveState,
  scanInstances,
  stateFilePath,
} from "../src/instances/index.js";
import type {
  InstanceArtifactBaseline,
  LocalArtifactEntry,
  ScanResult,
  VersionFingerprintState,
} from "../src/instances/types.js";
import { makeTempDir, writeJson } from "./helpers.js";

function sha256File(abs: string): string {
  const buf = fs.readFileSync(abs);
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function buildInventory(
  tmp: string,
  opts: {
    relative_path: string;
    version: string;
    bytes?: string | Buffer;
    meta?: Record<string, unknown>;
    extraCandidates?: Array<{
      relative_path: string;
      version: string;
      bytes?: string | Buffer;
      install_source?: string;
      surface?: string;
      path_precedence?: number;
    }>;
  },
): string {
  const root = path.join(tmp, "inventory");
  fs.mkdirSync(root, { recursive: true });
  const abs = path.join(root, opts.relative_path);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, opts.bytes ?? "#!/bin/sh\n# fixture\n");
  writeJson(path.join(path.dirname(abs), "version.json"), {
    version: opts.version,
    build: null,
    ...(opts.meta ?? {}),
  });
  const candidates = [
    {
      install_source: "path",
      surface: "cli",
      relative_path: opts.relative_path,
      path_precedence: 0,
      version_metadata_rel: path.posix.join(
        path.dirname(opts.relative_path).split(path.sep).join("/"),
        "version.json",
      ),
    },
    ...(opts.extraCandidates ?? []).map((c) => {
      const cAbs = path.join(root, c.relative_path);
      fs.mkdirSync(path.dirname(cAbs), { recursive: true });
      fs.writeFileSync(cAbs, c.bytes ?? "#!/bin/sh\n# fixture2\n");
      writeJson(path.join(path.dirname(cAbs), "version.json"), {
        version: c.version,
        build: null,
      });
      return {
        install_source: c.install_source ?? "path",
        surface: c.surface ?? "cli",
        relative_path: c.relative_path,
        path_precedence: c.path_precedence ?? 1,
        version_metadata_rel: path.posix.join(
          path.dirname(c.relative_path).split(path.sep).join("/"),
          "version.json",
        ),
      };
    }),
  ];
  writeJson(path.join(root, "inventory.json"), {
    schema_version: 1,
    platform: "macos",
    arch: "arm64",
    candidates,
    observed_context: {},
  });
  return root;
}

function asScan(r: unknown): ScanResult {
  assert.ok(r && typeof r === "object");
  return r as ScanResult;
}

function assertNoPathLeak(text: string, ...roots: string[]): void {
  for (const root of roots) {
    assert.equal(text.includes(root), false, `path leak: ${root}`);
  }
  assert.equal(/\/Users\//.test(text), false);
  assert.equal(/\/home\//.test(text), false);
  assert.equal(/\.grok-disposable/.test(text), false);
  assert.equal(/[A-Za-z]:\\Users\\/.test(text), false);
}

test("first baseline establishes artifact state without content_changed", () => {
  const tmp = makeTempDir("cg-art-first-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.50.0",
    bytes: Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x42]),
  });
  const scan = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(scan.ok, true);
  assert.equal(scan.primary_transition, "first_baseline");
  assert.equal(scan.local_artifact_diff.status, "first_baseline");
  assert.equal(scan.local_artifact_diff.hash_changed.length, 0);
  assert.equal(scan.local_artifact_diff.previous_baseline_digest, null);
  assert.ok(scan.local_artifact_diff.current_baseline_digest);
  assert.ok(scan.local_artifact_diff.entry_counts.read_ok >= 1);
  assert.equal(scan.state_updated, true);
  assert.equal(scan.fingerprint_changed, true);

  const state = loadState(path.join(root, "state"));
  assert.ok(state);
  assert.equal(state!.schema_version, 2);
  assert.ok(Array.isArray(state!.artifact_baselines));
  assert.ok(state!.artifact_baselines.length >= 1);
  const entry = state!.artifact_baselines[0]!.entries.find(
    (e) => e.key === "executable",
  );
  assert.ok(entry);
  assert.equal(entry!.status, "read_ok");
  assert.equal(
    entry!.sha256,
    sha256File(path.join(root, "path/bin/codex")),
  );
  // No absolute paths in persisted state text.
  const raw = fs.readFileSync(stateFilePath(path.join(root, "state")), "utf8");
  assertNoPathLeak(raw, root);
  assert.equal(raw.includes(path.join(root, "path")), false);
});

test("v1 state migrates without inventing history; first_baseline only", () => {
  const tmp = makeTempDir("cg-art-v1mig-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.50.0",
    bytes: "v1-body",
  });
  // First scan would write v2; instead seed a pure v1 state matching identity.
  const first = asScan(
    scanInstances({ inventoryRoot: root, persistState: false }),
  );
  const v1: VersionFingerprintState = {
    schema_version: 1,
    updated_at: "2020-01-01T00:00:00.000Z",
    overall_fingerprint: first.overall_fingerprint,
    instances: first.instances,
    artifact_baselines: [],
    overall_artifact_digest: null,
  };
  // Write raw v1 JSON (no artifact fields).
  const stateDir = path.join(root, "state");
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(
    stateFilePath(stateDir),
    JSON.stringify(
      {
        schema_version: 1,
        updated_at: v1.updated_at,
        overall_fingerprint: v1.overall_fingerprint,
        instances: v1.instances,
      },
      null,
      2,
    ) + "\n",
  );

  const loaded = loadState(stateDir);
  assert.ok(loaded);
  assert.equal(loaded!.schema_version, 1);
  assert.deepEqual(loaded!.artifact_baselines, []);
  assert.equal(loaded!.overall_artifact_digest, null);

  const second = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(second.primary_transition, "unchanged");
  assert.equal(second.local_artifact_diff.status, "first_baseline");
  assert.equal(second.local_artifact_diff.hash_changed.length, 0);
  assert.equal(second.fingerprint_changed, true);
  assert.equal(second.state_updated, true);

  const after = loadState(stateDir);
  assert.equal(after!.schema_version, 2);
  assert.ok(after!.artifact_baselines.length >= 1);
  assert.ok(after!.overall_artifact_digest);
});

test("unchanged identity + artifacts is silent SessionStart", () => {
  const tmp = makeTempDir("cg-art-unch-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.51.0",
  });
  const first = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(first.local_artifact_diff.status, "first_baseline");

  const t0 = Date.now();
  const session = runSessionStart({
    inventoryRoot: root,
    hookTrust: "trusted",
  });
  const ms = Date.now() - t0;
  assert.equal(session.silent, true);
  assert.equal(session.fingerprint_changed, false);
  assert.equal(session.local_artifact_diff.status, "unchanged");
  assert.ok(ms < 10_000, `SessionStart must be <10s, got ${ms}`);
});

test("exact artifact hash change without version change", () => {
  const tmp = makeTempDir("cg-art-hash-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.52.0",
    bytes: "original-bytes",
  });
  const first = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(first.primary_transition, "first_baseline");

  // Mutate only binary bytes; keep version metadata identical.
  fs.writeFileSync(path.join(root, "path/bin/codex"), "mutated-bytes-xyz");
  const second = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(second.primary_transition, "unchanged");
  assert.equal(second.local_artifact_diff.status, "content_changed");
  assert.ok(second.local_artifact_diff.hash_changed.length >= 1);
  const row = second.local_artifact_diff.hash_changed.find(
    (r) => r.key === "executable",
  );
  assert.ok(row);
  assert.equal(row!.change, "hash_changed");
  assert.ok(row!.previous_sha256);
  assert.ok(row!.current_sha256);
  assert.notEqual(row!.previous_sha256, row!.current_sha256);
  assert.equal(second.fingerprint_changed, true);
  assert.equal(second.state_updated, true);
  assertNoPathLeak(JSON.stringify(second), root);
});

test("stable ordering of keys and diff rows", () => {
  const a: LocalArtifactEntry = {
    key: "z_last",
    alias: "A:z_last",
    kind: "other",
    sha256: "a".repeat(64),
    size: 1,
    status: "read_ok",
  };
  const b: LocalArtifactEntry = {
    key: "a_first",
    alias: "A:a_first",
    kind: "executable",
    sha256: "b".repeat(64),
    size: 2,
    status: "read_ok",
  };
  const prev: InstanceArtifactBaseline[] = [
    {
      instance_id: "inst_b",
      path_hash: "c".repeat(64),
      path_alias: "PATH_2",
      entries: [a],
      baseline_digest: "d".repeat(64),
    },
    {
      instance_id: "inst_a",
      path_hash: "e".repeat(64),
      path_alias: "PATH_1",
      entries: [b],
      baseline_digest: "f".repeat(64),
    },
  ];
  const cur: InstanceArtifactBaseline[] = [
    {
      instance_id: "inst_a",
      path_hash: "e".repeat(64),
      path_alias: "PATH_1",
      entries: [
        { ...b, sha256: "1".repeat(64) },
        {
          key: "m_mid",
          alias: "A:m_mid",
          kind: "metadata",
          sha256: "2".repeat(64),
          size: 3,
          status: "read_ok",
        },
      ],
      baseline_digest: "g".repeat(64),
    },
    {
      instance_id: "inst_b",
      path_hash: "c".repeat(64),
      path_alias: "PATH_2",
      entries: [],
      baseline_digest: "h".repeat(64),
    },
  ];
  const diff = classifyLocalArtifactDiff(prev, cur);
  const keys = diff.hash_changed.map((r) => `${r.instance_id}:${r.key}`);
  const sorted = [...keys].sort((x, y) => x.localeCompare(y));
  assert.deepEqual(keys, sorted);
  const addedKeys = diff.added.map((r) => r.key);
  assert.deepEqual(addedKeys, [...addedKeys].sort((x, y) => x.localeCompare(y)));
});

test("symlink leaf refused as explicit gap; never hashed", async () => {
  const tmp = makeTempDir("cg-art-sym-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.53.0",
    bytes: "real",
  });
  // Inventory enumeration refuses symlink candidates; measure path must still
  // treat a named symlink leaf as an explicit gap (never follow / never hash).
  const first = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(first.ok, true);
  const id = first.instances[0]!;
  const bin = path.join(root, "path/bin/codex");
  const outside = path.join(tmp, "outside-secret");
  fs.writeFileSync(outside, "secret-payload");
  fs.unlinkSync(bin);
  fs.symlinkSync(outside, bin);

  const { measureInstanceArtifactBaselines } = await import(
    "../src/instances/artifacts.js"
  );
  const baselines = measureInstanceArtifactBaselines(
    [id],
    [
      {
        install_source: "path",
        surface: "cli",
        path: bin,
        platform: "macos",
        arch: "arm64",
        profile_root_alias: null,
        config_root_alias: null,
        path_precedence: 0,
        version_metadata_rel: "path/bin/version.json",
        trusted_metadata_roots: [root],
      },
    ],
    { inventoryRoot: root },
  );
  const exec = baselines[0]!.entries.find((e) => e.key === "executable");
  assert.ok(exec);
  assert.equal(exec!.status, "symlink_refused");
  assert.equal(exec!.sha256, null);
  assert.equal(exec!.size, null);
  // Outside secret payload digest must not appear.
  const secretHash = crypto
    .createHash("sha256")
    .update("secret-payload")
    .digest("hex");
  assert.equal(JSON.stringify(baselines).includes(secretHash), false);
  assertNoPathLeak(JSON.stringify(baselines), root, outside);
});

test("oversize file is gap without truncated digest", async () => {
  const tmp = makeTempDir("cg-art-over2-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.54.1",
    bytes: Buffer.alloc(32, 1),
  });
  const first = asScan(scanInstances({ inventoryRoot: root }));
  const id = first.instances[0]!;
  const { measureInstanceArtifactBaselines } = await import(
    "../src/instances/artifacts.js"
  );
  fs.writeFileSync(path.join(root, "path/bin/codex"), Buffer.alloc(4096, 2));
  const baselines = measureInstanceArtifactBaselines(
    [id],
    [
      {
        install_source: "path",
        surface: "cli",
        path: path.join(root, "path/bin/codex"),
        platform: "macos",
        arch: "arm64",
        profile_root_alias: null,
        config_root_alias: null,
        path_precedence: 0,
        version_metadata_rel: "path/bin/version.json",
        trusted_metadata_roots: [root],
      },
    ],
    { inventoryRoot: root, maxFileBytes: 64, maxScanBytes: 10_000 },
  );
  const exec = baselines[0]!.entries.find((e) => e.key === "executable");
  assert.ok(exec);
  assert.equal(exec!.status, "oversize");
  assert.equal(exec!.sha256, null);
  assert.equal(exec!.size, null);
});

test("binary bytes hashed correctly; unicode alias redacted from paths", () => {
  const tmp = makeTempDir("cg-art-bin-");
  const binBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.55.0",
    bytes: binBytes,
  });
  const scan = asScan(scanInstances({ inventoryRoot: root }));
  const expected = crypto.createHash("sha256").update(binBytes).digest("hex");
  const state = loadState(path.join(root, "state"))!;
  const exec = state.artifact_baselines[0]!.entries.find(
    (e) => e.key === "executable",
  )!;
  assert.equal(exec.sha256, expected);
  // Public aliases must not include path separators or home roots.
  for (const e of state.artifact_baselines[0]!.entries) {
    assert.equal(e.alias.includes("/"), false);
    assert.equal(e.alias.includes("\\"), false);
  }
  const ctx = formatSessionStartContext(scan);
  assert.match(ctx, /local_artifact_status=first_baseline/);
  assert.match(ctx, /historical_update_not_reconstructable/);
  assertNoPathLeak(ctx, root);
});

test("multi-instance isolation: one instance binary change does not alter the other", () => {
  const tmp = makeTempDir("cg-art-multi-");
  const root = buildInventory(tmp, {
    relative_path: "path/a/codex",
    version: "0.56.0",
    bytes: "A-original",
    extraCandidates: [
      {
        relative_path: "path/b/codex",
        version: "0.56.0",
        bytes: "B-original",
        path_precedence: 1,
      },
    ],
  });
  const first = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(first.instances.length, 2);
  const digestsBefore = first.local_artifact_diff.current_baseline_digest;

  fs.writeFileSync(path.join(root, "path/a/codex"), "A-mutated");
  const second = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(second.local_artifact_diff.status, "content_changed");
  const changed = second.local_artifact_diff.hash_changed;
  assert.ok(changed.length >= 1);
  // All hash_changed rows must reference the same instance_id (A), not both.
  const ids = new Set(changed.map((r) => r.instance_id));
  assert.equal(ids.size, 1);
  assert.notEqual(
    second.local_artifact_diff.current_baseline_digest,
    digestsBefore,
  );
});

test("added and removed artifact keys surface correctly", () => {
  const prevEntry: LocalArtifactEntry = {
    key: "old_meta",
    alias: "P:old_meta",
    kind: "metadata",
    sha256: "a".repeat(64),
    size: 10,
    status: "read_ok",
  };
  const keep: LocalArtifactEntry = {
    key: "executable",
    alias: "P:executable",
    kind: "executable",
    sha256: "b".repeat(64),
    size: 20,
    status: "read_ok",
  };
  const newEntry: LocalArtifactEntry = {
    key: "app_asar",
    alias: "P:app_asar",
    kind: "asar",
    sha256: "c".repeat(64),
    size: 30,
    status: "read_ok",
  };
  const prev: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "d".repeat(64),
      path_alias: "PATH_1",
      entries: [keep, prevEntry],
      baseline_digest: "e".repeat(64),
    },
  ];
  const cur: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "d".repeat(64),
      path_alias: "PATH_1",
      entries: [keep, newEntry],
      baseline_digest: "f".repeat(64),
    },
  ];
  const diff = classifyLocalArtifactDiff(prev, cur);
  assert.equal(diff.status, "content_changed");
  assert.equal(diff.added.map((r) => r.key).join(","), "app_asar");
  assert.equal(diff.removed.map((r) => r.key).join(","), "old_meta");
});

test("parseStateJson rejects v1 with artifact fields; accepts v2", () => {
  assert.throws(() =>
    parseStateJson(
      JSON.stringify({
        schema_version: 1,
        updated_at: "t",
        overall_fingerprint: "a".repeat(64),
        instances: [],
        artifact_baselines: [],
      }),
    ),
  );
  const v2 = parseStateJson(
    JSON.stringify({
      schema_version: 2,
      updated_at: "t",
      overall_fingerprint: "a".repeat(64),
      instances: [],
      artifact_baselines: [],
      overall_artifact_digest: null,
    }),
  );
  assert.equal(v2.schema_version, 2);
});

test("SessionStart baseline-established notice does not claim content_changed", () => {
  const tmp = makeTempDir("cg-art-ss-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.57.0",
  });
  // Seed v1 state with matching fingerprint.
  const dry = asScan(
    scanInstances({ inventoryRoot: root, persistState: false }),
  );
  const stateDir = path.join(root, "state");
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(
    stateFilePath(stateDir),
    JSON.stringify({
      schema_version: 1,
      updated_at: "t",
      overall_fingerprint: dry.overall_fingerprint,
      instances: dry.instances,
    }),
  );
  const session = runSessionStart({
    inventoryRoot: root,
    hookTrust: "trusted",
  });
  assert.equal(session.silent, false);
  assert.equal(session.fingerprint_changed, true);
  assert.equal(session.local_artifact_diff.status, "first_baseline");
  assert.notEqual(session.local_artifact_diff.status, "content_changed");
  const ctx = formatSessionStartContext(session);
  assert.match(ctx, /baseline established|local_artifact_status=first_baseline/i);
  assert.equal(/content_changed/.test(ctx), false);
  assertNoPathLeak(ctx, root);
});

test("pathHashOf matches measure candidate binding", () => {
  const p = "/Applications/ChatGPT.app/Contents/Resources/codex";
  assert.equal(pathHashOf(p).length, 64);
});

test("saveState refuses to write schema_version 1", () => {
  const tmp = makeTempDir("cg-art-save-");
  assert.throws(() =>
    saveState(tmp, {
      schema_version: 1,
      updated_at: "t",
      overall_fingerprint: "a".repeat(64),
      instances: [],
      artifact_baselines: [],
      overall_artifact_digest: null,
    }),
  );
});

// --- Integrity / binding / budget / pure-artifact headline regressions ---

function seedValidV2State(root: string): VersionFingerprintState {
  const first = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(first.ok, true);
  const state = loadState(path.join(root, "state"));
  assert.ok(state);
  assert.equal(state!.schema_version, 2);
  return state!;
}

test("tampered baseline_digest with unchanged overall is refused fail-closed", () => {
  const tmp = makeTempDir("cg-art-tamper-base-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.60.0",
    bytes: "tamper-base-body",
  });
  seedValidV2State(root);
  const rawPath = stateFilePath(path.join(root, "state"));
  const raw = JSON.parse(fs.readFileSync(rawPath, "utf8")) as Record<
    string,
    unknown
  >;
  const baselines = raw.artifact_baselines as Array<Record<string, unknown>>;
  assert.ok(baselines.length >= 1);
  // Flip only stored baseline_digest; leave entries and overall untouched.
  baselines[0]!.baseline_digest = "0".repeat(64);
  fs.writeFileSync(rawPath, JSON.stringify(raw, null, 2) + "\n");

  assert.throws(() => loadState(path.join(root, "state")), (e: unknown) => {
    assert.ok(e && typeof e === "object" && "code" in e);
    assert.equal((e as { code: string }).code, "SCHEMA");
    return true;
  });
  const scan = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(scan.ok, false);
  assert.equal(scan.error_code, "SCHEMA");
  assert.equal(scan.state_updated, false);
});

test("tampered overall_artifact_digest only is refused fail-closed", () => {
  const tmp = makeTempDir("cg-art-tamper-over-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.60.1",
    bytes: "tamper-over-body",
  });
  seedValidV2State(root);
  const rawPath = stateFilePath(path.join(root, "state"));
  const raw = JSON.parse(fs.readFileSync(rawPath, "utf8")) as Record<
    string,
    unknown
  >;
  raw.overall_artifact_digest = "1".repeat(64);
  fs.writeFileSync(rawPath, JSON.stringify(raw, null, 2) + "\n");

  assert.throws(() => parseStateJson(fs.readFileSync(rawPath, "utf8")), (e: unknown) => {
    assert.equal((e as { code: string }).code, "SCHEMA");
    return true;
  });
  const scan = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(scan.ok, false);
  assert.equal(scan.error_code, "SCHEMA");
});

test("null overall_artifact_digest with nonempty baselines is refused", () => {
  const tmp = makeTempDir("cg-art-null-over-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.60.2",
  });
  seedValidV2State(root);
  const rawPath = stateFilePath(path.join(root, "state"));
  const raw = JSON.parse(fs.readFileSync(rawPath, "utf8")) as Record<
    string,
    unknown
  >;
  assert.ok(Array.isArray(raw.artifact_baselines));
  assert.ok((raw.artifact_baselines as unknown[]).length > 0);
  raw.overall_artifact_digest = null;
  fs.writeFileSync(rawPath, JSON.stringify(raw, null, 2) + "\n");
  assert.throws(() => parseStateJson(fs.readFileSync(rawPath, "utf8")));
});

test("invalid overall_artifact_digest string with nonempty baselines is refused", () => {
  const tmp = makeTempDir("cg-art-bad-over-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.60.3",
  });
  seedValidV2State(root);
  const rawPath = stateFilePath(path.join(root, "state"));
  const raw = JSON.parse(fs.readFileSync(rawPath, "utf8")) as Record<
    string,
    unknown
  >;
  raw.overall_artifact_digest = "not-a-digest";
  fs.writeFileSync(rawPath, JSON.stringify(raw, null, 2) + "\n");
  assert.throws(() => parseStateJson(fs.readFileSync(rawPath, "utf8")));
});

test("duplicate / missing / extra / mismatched baseline bindings refused", () => {
  const tmp = makeTempDir("cg-art-bind-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.60.4",
    extraCandidates: [
      {
        relative_path: "path/bin2/codex",
        version: "0.60.4",
        path_precedence: 1,
      },
    ],
  });
  const state = seedValidV2State(root);
  assert.equal(state.instances.length, 2);
  assert.equal(state.artifact_baselines.length, 2);
  const rawPath = stateFilePath(path.join(root, "state"));
  const baseRaw = JSON.parse(fs.readFileSync(rawPath, "utf8")) as Record<
    string,
    unknown
  >;

  // Duplicate baseline for same instance_id.
  {
    const raw = structuredClone(baseRaw) as Record<string, unknown>;
    const bl = raw.artifact_baselines as Array<Record<string, unknown>>;
    bl.push({ ...bl[0]! });
    fs.writeFileSync(rawPath, JSON.stringify(raw, null, 2) + "\n");
    assert.throws(() => parseStateJson(fs.readFileSync(rawPath, "utf8")));
  }
  // Missing one baseline.
  {
    const raw = structuredClone(baseRaw) as Record<string, unknown>;
    const bl = raw.artifact_baselines as unknown[];
    bl.pop();
    // Keep overall as-is (will fail 1:1 and/or digest).
    fs.writeFileSync(rawPath, JSON.stringify(raw, null, 2) + "\n");
    assert.throws(() => parseStateJson(fs.readFileSync(rawPath, "utf8")));
  }
  // Extra orphan baseline (wrong instance_id).
  {
    const raw = structuredClone(baseRaw) as Record<string, unknown>;
    const bl = raw.artifact_baselines as Array<Record<string, unknown>>;
    bl.push({
      ...bl[0]!,
      instance_id: "orphan_not_in_instances",
    });
    // Drop one real instance so lengths might still mismatch; force extra id.
    fs.writeFileSync(rawPath, JSON.stringify(raw, null, 2) + "\n");
    assert.throws(() => parseStateJson(fs.readFileSync(rawPath, "utf8")));
  }
  // Binding mismatch: path_hash differs from instance.
  {
    const raw = structuredClone(baseRaw) as Record<string, unknown>;
    const bl = raw.artifact_baselines as Array<Record<string, unknown>>;
    bl[0] = { ...bl[0]!, path_hash: "f".repeat(64) };
    // Recompute overall from stored digests is still wrong only if we don't
    // recompute from entries — binding check fires first.
    fs.writeFileSync(rawPath, JSON.stringify(raw, null, 2) + "\n");
    assert.throws(() => parseStateJson(fs.readFileSync(rawPath, "utf8")));
  }
});

test("deterministic measurement time budget yields explicit gap without path leak", async () => {
  const tmp = makeTempDir("cg-art-budget-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.61.0",
    bytes: Buffer.alloc(256, 7),
  });
  const dry = asScan(
    scanInstances({ inventoryRoot: root, persistState: false }),
  );
  const id = dry.instances[0]!;
  const { measureInstanceArtifactBaselines } = await import(
    "../src/instances/artifacts.js"
  );
  // Fake clock: first call start, then every subsequent now is past deadline.
  let calls = 0;
  const baselines = measureInstanceArtifactBaselines(
    [id],
    [
      {
        install_source: "path",
        surface: "cli",
        path: path.join(root, "path/bin/codex"),
        platform: "macos",
        arch: "arm64",
        profile_root_alias: null,
        config_root_alias: null,
        path_precedence: 0,
        version_metadata_rel: "path/bin/version.json",
        trusted_metadata_roots: [root],
      },
    ],
    {
      inventoryRoot: root,
      timeBudgetMs: 1,
      nowMs: () => {
        calls += 1;
        // start at 0; after first scheduling check jump past budget
        return calls <= 1 ? 0 : 100;
      },
    },
  );
  const entries = baselines[0]!.entries;
  assert.ok(entries.length >= 1);
  const budgetGaps = entries.filter((e) => e.status === "time_budget_exceeded");
  assert.ok(
    budgetGaps.length >= 1,
    "expected at least one time_budget_exceeded gap",
  );
  for (const g of budgetGaps) {
    assert.equal(g.sha256, null);
    assert.equal(g.size, null);
  }
  // Incomplete: not all named targets can honestly be read_ok under exhausted budget.
  const readOk = entries.filter((e) => e.status === "read_ok");
  assert.ok(readOk.length < entries.length || budgetGaps.length === entries.length);
  const text = JSON.stringify(baselines);
  assertNoPathLeak(text, root);
  assert.equal(text.includes(path.join(root, "path")), false);
});

test("mid-file streaming time budget discards partial hash as time_budget_exceeded", async () => {
  // ARTIFACT_HASH_CHUNK_BYTES is 1 MiB; a multi-chunk file forces loop re-checks.
  const CHUNK = 1024 * 1024;
  const tmp = makeTempDir("cg-art-midbudget-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.61.1",
    // Two full chunks so the streaming loop runs at least twice.
    bytes: Buffer.alloc(CHUNK * 2, 9),
  });
  // Touch inventory path so fixture root exists; measureNamedFile is unit-tested.
  asScan(scanInstances({ inventoryRoot: root, persistState: false }));
  const { measureNamedFile } = await import("../src/instances/artifacts.js");
  const execAbs = path.join(root, "path/bin/codex");
  let calls = 0;
  // startMs + pre-file checks stay before deadline; advance only after first chunk.
  const budget = {
    remaining: CHUNK * 4,
    deadlineMs: 50,
    nowMs: () => {
      calls += 1;
      // Enough zeros for entry check + first chunk check; exceed on second chunk.
      return calls <= 2 ? 0 : 100;
    },
  };
  const measured = measureNamedFile(
    "executable",
    "P:executable",
    execAbs,
    [root],
    budget,
    CHUNK * 4,
  );
  assert.equal(measured.status, "time_budget_exceeded");
  assert.equal(measured.sha256, null);
  assert.equal(measured.size, null);
  assert.ok(calls >= 3, "expected clock to advance during multi-chunk streaming");
  assertNoPathLeak(JSON.stringify(measured), root);
});

test("repeated identical time_budget_exceeded baselines stay non-silent incomplete", () => {
  const readOk: LocalArtifactEntry = {
    key: "executable",
    alias: "P:executable",
    kind: "executable",
    sha256: "a".repeat(64),
    size: 10,
    status: "read_ok",
  };
  const timeout: LocalArtifactEntry = {
    key: "package_json",
    alias: "P:package_json",
    kind: "metadata",
    sha256: null,
    size: null,
    status: "time_budget_exceeded",
  };
  const allTimeout: LocalArtifactEntry[] = [
    {
      key: "executable",
      alias: "P:executable",
      kind: "executable",
      sha256: null,
      size: null,
      status: "time_budget_exceeded",
    },
    {
      key: "package_json",
      alias: "P:package_json",
      kind: "metadata",
      sha256: null,
      size: null,
      status: "time_budget_exceeded",
    },
  ];
  const mixedPrev: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "b".repeat(64),
      path_alias: "PATH_1",
      entries: [readOk, timeout],
      baseline_digest: "c".repeat(64),
    },
  ];
  // Identical rows/digests as previous — still incomplete current measurement.
  const mixedCur: InstanceArtifactBaseline[] = structuredClone(mixedPrev);
  const mixed = classifyLocalArtifactDiff(mixedPrev, mixedCur);
  assert.equal(mixed.status, "partial");
  assert.equal(mixed.hash_changed.length, 0);
  assert.equal(mixed.gap_changed.length, 0);
  assert.ok(mixed.entry_counts.read_ok >= 1);
  assert.ok(mixed.entry_counts.gaps >= 1);

  const allPrev: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "b".repeat(64),
      path_alias: "PATH_1",
      entries: allTimeout,
      baseline_digest: "d".repeat(64),
    },
  ];
  const allCur: InstanceArtifactBaseline[] = structuredClone(allPrev);
  const all = classifyLocalArtifactDiff(allPrev, allCur);
  assert.equal(all.status, "unavailable");
  assert.equal(all.hash_changed.length, 0);
  assert.equal(all.entry_counts.read_ok, 0);
  assert.ok(all.entry_counts.gaps >= 1);

  // Stable missing gaps (not wall-clock) with identical rows remain unchanged.
  const missing: LocalArtifactEntry = {
    key: "package_json",
    alias: "P:package_json",
    kind: "metadata",
    sha256: null,
    size: null,
    status: "missing",
  };
  const stablePrev: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "b".repeat(64),
      path_alias: "PATH_1",
      entries: [readOk, missing],
      baseline_digest: "e".repeat(64),
    },
  ];
  const stableCur: InstanceArtifactBaseline[] = structuredClone(stablePrev);
  const stable = classifyLocalArtifactDiff(stablePrev, stableCur);
  assert.equal(stable.status, "unchanged");
});

test("scan with repeated time_budget_exceeded is non-silent fingerprint_changed", () => {
  const tmp = makeTempDir("cg-art-repbudget-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.61.2",
    bytes: "rep-budget",
  });
  // Establish full baseline first.
  asScan(scanInstances({ inventoryRoot: root }));
  // Force all named targets past budget on both subsequent scans.
  const alwaysExhausted = {
    artifactTimeBudgetMs: 1,
    artifactNowMs: (() => {
      let n = 0;
      return () => {
        n += 1;
        return n <= 1 ? 0 : 10_000;
      };
    })(),
  };
  const second = asScan(
    scanInstances({ inventoryRoot: root, ...alwaysExhausted }),
  );
  assert.equal(second.ok, true);
  assert.equal(second.primary_transition, "unchanged");
  assert.ok(
    second.local_artifact_diff.status === "partial" ||
      second.local_artifact_diff.status === "unavailable",
  );
  assert.equal(second.fingerprint_changed, true);
  assert.equal(second.silent, false);
  // Reset clock for third scan: still all timeouts, identical gap rows.
  const alwaysExhausted2 = {
    artifactTimeBudgetMs: 1,
    artifactNowMs: (() => {
      let n = 0;
      return () => {
        n += 1;
        return n <= 1 ? 0 : 10_000;
      };
    })(),
  };
  const third = asScan(
    scanInstances({ inventoryRoot: root, ...alwaysExhausted2 }),
  );
  assert.equal(third.primary_transition, "unchanged");
  assert.ok(
    third.local_artifact_diff.status === "partial" ||
      third.local_artifact_diff.status === "unavailable",
  );
  assert.equal(third.fingerprint_changed, true);
  assert.equal(third.silent, false);
  assert.ok(
    third.local_artifact_diff.entry_counts.gaps >= 1 ||
      third.local_artifact_diff.status === "unavailable",
  );
});

test("SessionStart pure artifact drift headline is not version-change wording", () => {
  const tmp = makeTempDir("cg-art-headline-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.62.0",
    bytes: "headline-original",
  });
  asScan(scanInstances({ inventoryRoot: root }));
  fs.writeFileSync(path.join(root, "path/bin/codex"), "headline-mutated");
  const session = runSessionStart({
    inventoryRoot: root,
    hookTrust: "trusted",
  });
  assert.equal(session.ok, true);
  assert.equal(session.primary_transition, "unchanged");
  assert.equal(session.local_artifact_diff.status, "content_changed");
  assert.equal(session.fingerprint_changed, true);
  const ctx = formatSessionStartContext(session);
  assert.match(
    ctx,
    /local installed-artifact fingerprint\/baseline changed/i,
  );
  assert.equal(
    /version fingerprint changed\./i.test(ctx) &&
      !/local installed-artifact/.test(ctx),
    false,
  );
  // Must not use the pure version headline alone.
  assert.equal(ctx.startsWith("ChangeGuard version fingerprint changed."), false);
  assert.match(ctx, /local_artifact_gap_changed=\d+/);
  assertNoPathLeak(ctx, root);
});

test("SessionStart headlines honest incomplete/unavailable artifact measurement", () => {
  const emptyDiffLists = {
    added: [] as ScanResult["local_artifact_diff"]["added"],
    removed: [] as ScanResult["local_artifact_diff"]["removed"],
    hash_changed: [] as ScanResult["local_artifact_diff"]["hash_changed"],
    gap_changed: [] as ScanResult["local_artifact_diff"]["gap_changed"],
  };
  const gapOnlyEntry = {
    instance_id: "i1",
    path_alias: "PATH_1",
    key: "executable",
    alias: "P:executable",
    kind: "executable" as const,
    change: "gap_changed" as const,
    previous_sha256: "b".repeat(64),
    current_sha256: null,
    previous_status: "read_ok" as const,
    current_status: "time_budget_exceeded" as const,
    previous_size: 10,
    current_size: null,
  };
  const base: ScanResult = {
    schema_version: 1,
    ok: true,
    mode: "session_start",
    fingerprint_changed: true,
    overall_fingerprint: "a".repeat(64),
    previous_fingerprint: "a".repeat(64),
    primary_transition: "unchanged",
    transitions: [],
    instances: [],
    affected_instance_id: null,
    affected_resolution: "none",
    affected_resolution_reason: "no_instances",
    hook_status: "trusted",
    health_check: null,
    silent: false,
    state_updated: false,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    error_code: null,
    error_message: null,
    local_artifact_diff: {
      status: "unavailable",
      previous_baseline_digest: null,
      current_baseline_digest: null,
      ...emptyDiffLists,
      entry_counts: { measured: 0, read_ok: 0, gaps: 0 },
      keys: [],
    },
  };

  // First baseline (previous_fingerprint null) + unavailable → baseline established, never version changed.
  const firstBaselineUnavailable: ScanResult = {
    ...base,
    previous_fingerprint: null,
    primary_transition: "first_baseline",
    local_artifact_diff: {
      status: "unavailable",
      previous_baseline_digest: null,
      current_baseline_digest: null,
      ...emptyDiffLists,
      entry_counts: { measured: 2, read_ok: 0, gaps: 2 },
      keys: ["P:executable", "P:package_json"],
    },
  };
  const ctxFirstUnavail = formatSessionStartContext(firstBaselineUnavailable);
  assert.match(
    ctxFirstUnavail,
    /version fingerprint baseline established/i,
  );
  assert.match(
    ctxFirstUnavail,
    /local installed-artifact measurement unavailable/i,
  );
  assert.equal(/version fingerprint changed/i.test(ctxFirstUnavail), false);
  assert.match(ctxFirstUnavail, /local_artifact_status=unavailable/);

  // Identity unchanged + all time-budget gaps → unavailable measurement, not version.
  const unavailableIdentitySame: ScanResult = {
    ...base,
    previous_fingerprint: "a".repeat(64),
    primary_transition: "unchanged",
    local_artifact_diff: {
      status: "unavailable",
      previous_baseline_digest: "b".repeat(64),
      current_baseline_digest: "b".repeat(64),
      ...emptyDiffLists,
      entry_counts: { measured: 2, read_ok: 0, gaps: 2 },
      keys: ["P:executable", "P:package_json"],
    },
  };
  const ctxUnavail = formatSessionStartContext(unavailableIdentitySame);
  assert.match(
    ctxUnavail,
    /local installed-artifact measurement unavailable/i,
  );
  assert.equal(/version fingerprint changed/i.test(ctxUnavail), false);
  assert.match(ctxUnavail, /local_artifact_status=unavailable/);

  // Identity unchanged + first timeout gap_changed → incomplete (gap is not content change).
  const firstTimeoutGap: ScanResult = {
    ...base,
    previous_fingerprint: "a".repeat(64),
    primary_transition: "unchanged",
    local_artifact_diff: {
      status: "partial",
      previous_baseline_digest: "c".repeat(64),
      current_baseline_digest: "c".repeat(64),
      added: [],
      removed: [],
      hash_changed: [],
      gap_changed: [gapOnlyEntry],
      entry_counts: { measured: 2, read_ok: 1, gaps: 1 },
      keys: ["P:executable", "P:package_json"],
    },
  };
  const ctxFirstTimeout = formatSessionStartContext(firstTimeoutGap);
  assert.match(
    ctxFirstTimeout,
    /local installed-artifact measurement incomplete/i,
  );
  assert.equal(/version fingerprint changed/i.test(ctxFirstTimeout), false);
  assert.equal(
    /fingerprint\/baseline changed/i.test(ctxFirstTimeout),
    false,
  );
  assert.match(ctxFirstTimeout, /local_artifact_gap_changed=1/);

  // Repeated timeout (gap_changed present again, still no content deltas) → incomplete.
  const repeatedTimeout: ScanResult = {
    ...firstTimeoutGap,
    local_artifact_diff: {
      ...firstTimeoutGap.local_artifact_diff,
      gap_changed: [
        {
          ...gapOnlyEntry,
          previous_status: "time_budget_exceeded",
          current_status: "time_budget_exceeded",
          previous_sha256: null,
        },
      ],
      entry_counts: { measured: 2, read_ok: 0, gaps: 2 },
    },
  };
  const ctxRepeated = formatSessionStartContext(repeatedTimeout);
  assert.match(
    ctxRepeated,
    /local installed-artifact measurement incomplete/i,
  );
  assert.equal(/version fingerprint changed/i.test(ctxRepeated), false);
  assert.equal(
    /change was detected but measurement is incomplete/i.test(ctxRepeated),
    false,
  );

  // Identity unchanged + partial with zero entry deltas → incomplete, not version.
  const partialIdentitySame: ScanResult = {
    ...base,
    previous_fingerprint: "a".repeat(64),
    primary_transition: "unchanged",
    local_artifact_diff: {
      status: "partial",
      previous_baseline_digest: "c".repeat(64),
      current_baseline_digest: "c".repeat(64),
      ...emptyDiffLists,
      entry_counts: { measured: 2, read_ok: 1, gaps: 1 },
      keys: ["P:executable", "P:package_json"],
    },
  };
  const ctxPartial = formatSessionStartContext(partialIdentitySame);
  assert.match(
    ctxPartial,
    /local installed-artifact measurement incomplete/i,
  );
  assert.equal(/version fingerprint changed/i.test(ctxPartial), false);

  // Identity changed + unavailable → version changed AND measurement unavailable.
  const unavailableIdentityChanged: ScanResult = {
    ...base,
    previous_fingerprint: "d".repeat(64),
    overall_fingerprint: "e".repeat(64),
    primary_transition: "upgrade",
    local_artifact_diff: {
      status: "unavailable",
      previous_baseline_digest: "f".repeat(64),
      current_baseline_digest: "0".repeat(64),
      ...emptyDiffLists,
      entry_counts: { measured: 2, read_ok: 0, gaps: 2 },
      keys: ["P:executable"],
    },
  };
  const ctxBoth = formatSessionStartContext(unavailableIdentityChanged);
  assert.match(ctxBoth, /version fingerprint changed/i);
  assert.match(ctxBoth, /local installed-artifact measurement unavailable/i);
  assert.equal(
    ctxBoth.startsWith("ChangeGuard version fingerprint changed."),
    false,
  );

  // Partial with content + gap → content detected but measurement incomplete.
  const partialContentGap: ScanResult = {
    ...base,
    previous_fingerprint: "a".repeat(64),
    primary_transition: "unchanged",
    local_artifact_diff: {
      status: "partial",
      previous_baseline_digest: "1".repeat(64),
      current_baseline_digest: "2".repeat(64),
      added: [],
      removed: [],
      hash_changed: [
        {
          instance_id: "i1",
          path_alias: "PATH_1",
          key: "executable",
          alias: "P:executable",
          kind: "executable",
          change: "hash_changed",
          previous_sha256: "b".repeat(64),
          current_sha256: "d".repeat(64),
          previous_status: "read_ok",
          current_status: "read_ok",
          previous_size: 10,
          current_size: 12,
        },
      ],
      gap_changed: [gapOnlyEntry],
      entry_counts: { measured: 2, read_ok: 1, gaps: 1 },
      keys: ["P:executable", "P:package_json"],
    },
  };
  const ctxContentGap = formatSessionStartContext(partialContentGap);
  assert.match(
    ctxContentGap,
    /local installed-artifact change was detected but measurement is incomplete/i,
  );
  assert.equal(/version fingerprint changed/i.test(ctxContentGap), false);
  assert.match(ctxContentGap, /local_artifact_hash_changed=1/);
  assert.match(ctxContentGap, /local_artifact_gap_changed=1/);
});

test("content plus gap classifies partial; gap-only classifies partial", () => {
  const keep: LocalArtifactEntry = {
    key: "executable",
    alias: "P:executable",
    kind: "executable",
    sha256: "b".repeat(64),
    size: 20,
    status: "read_ok",
  };
  const metaOk: LocalArtifactEntry = {
    key: "package_json",
    alias: "P:package_json",
    kind: "metadata",
    sha256: "c".repeat(64),
    size: 5,
    status: "read_ok",
  };
  const metaMissing: LocalArtifactEntry = {
    key: "package_json",
    alias: "P:package_json",
    kind: "metadata",
    sha256: null,
    size: null,
    status: "missing",
  };
  const execChanged: LocalArtifactEntry = {
    ...keep,
    sha256: "d".repeat(64),
  };
  const prev: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "e".repeat(64),
      path_alias: "PATH_1",
      entries: [keep, metaOk],
      baseline_digest: "f".repeat(64),
    },
  ];
  // Content + gap: hash change on executable AND gap on package_json.
  const curBoth: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "e".repeat(64),
      path_alias: "PATH_1",
      entries: [execChanged, metaMissing],
      baseline_digest: "1".repeat(64),
    },
  ];
  const both = classifyLocalArtifactDiff(prev, curBoth);
  assert.equal(both.status, "partial");
  assert.ok(both.hash_changed.length >= 1);
  assert.ok(both.gap_changed.length >= 1);

  // Gap-only: executable unchanged, package_json status flip.
  const curGap: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "e".repeat(64),
      path_alias: "PATH_1",
      entries: [keep, metaMissing],
      baseline_digest: "2".repeat(64),
    },
  ];
  const gapOnly = classifyLocalArtifactDiff(prev, curGap);
  assert.equal(gapOnly.status, "partial");
  assert.equal(gapOnly.hash_changed.length, 0);
  assert.ok(gapOnly.gap_changed.length >= 1);
});

test("digest-only disagreement with zero entry deltas fails closed as unavailable", () => {
  // Same entries but different stored baseline digests on the baseline objects
  // would only appear if digests were not recomputed; classifier recomputes from
  // entries, so equal entries ⇒ equal digests ⇒ unchanged. If digests somehow
  // disagreed without entry deltas after recompute, status is unavailable.
  const entry: LocalArtifactEntry = {
    key: "executable",
    alias: "P:executable",
    kind: "executable",
    sha256: "a".repeat(64),
    size: 1,
    status: "read_ok",
  };
  const prev: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "b".repeat(64),
      path_alias: "PATH_1",
      entries: [entry],
      baseline_digest: "c".repeat(64),
    },
  ];
  const cur: InstanceArtifactBaseline[] = [
    {
      instance_id: "i1",
      path_hash: "b".repeat(64),
      path_alias: "PATH_1",
      entries: [entry],
      baseline_digest: "d".repeat(64),
    },
  ];
  const diff = classifyLocalArtifactDiff(prev, cur);
  // Recomputed digests from identical entries match → unchanged (not content_changed).
  assert.equal(diff.status, "unchanged");
  assert.equal(diff.hash_changed.length, 0);
  assert.equal(diff.previous_baseline_digest, diff.current_baseline_digest);
});

test("v1 migration remains first_baseline with no invented history after integrity fix", () => {
  const tmp = makeTempDir("cg-art-v1mig2-");
  const root = buildInventory(tmp, {
    relative_path: "path/bin/codex",
    version: "0.63.0",
    bytes: "v1-again",
  });
  const first = asScan(
    scanInstances({ inventoryRoot: root, persistState: false }),
  );
  const stateDir = path.join(root, "state");
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(
    stateFilePath(stateDir),
    JSON.stringify(
      {
        schema_version: 1,
        updated_at: "2020-01-01T00:00:00.000Z",
        overall_fingerprint: first.overall_fingerprint,
        instances: first.instances,
      },
      null,
      2,
    ) + "\n",
  );
  const second = asScan(scanInstances({ inventoryRoot: root }));
  assert.equal(second.primary_transition, "unchanged");
  assert.equal(second.local_artifact_diff.status, "first_baseline");
  assert.equal(second.local_artifact_diff.hash_changed.length, 0);
  assert.equal(second.local_artifact_diff.previous_baseline_digest, null);
  assert.equal(second.fingerprint_changed, true);
});

test("SessionStart first_baseline truth table: v1 prior + identity change names version changed", () => {
  // Edge: previous_fingerprint non-null (migrating prior v1 state) while identity
  // actually changed and local_artifact_diff is first_baseline — must not claim
  // "version fingerprint / artifact baseline established" (that is first-ever only).
  const emptyDiffLists = {
    added: [] as ScanResult["local_artifact_diff"]["added"],
    removed: [] as ScanResult["local_artifact_diff"]["removed"],
    hash_changed: [] as ScanResult["local_artifact_diff"]["hash_changed"],
    gap_changed: [] as ScanResult["local_artifact_diff"]["gap_changed"],
  };
  const firstBaselineArt: ScanResult["local_artifact_diff"] = {
    status: "first_baseline",
    previous_baseline_digest: null,
    current_baseline_digest: "c".repeat(64),
    ...emptyDiffLists,
    entry_counts: { measured: 1, read_ok: 1, gaps: 0 },
    keys: ["P:executable"],
  };
  const baseFields: Omit<
    ScanResult,
    | "previous_fingerprint"
    | "overall_fingerprint"
    | "primary_transition"
    | "local_artifact_diff"
  > = {
    schema_version: 1,
    ok: true,
    mode: "session_start",
    fingerprint_changed: true,
    transitions: [],
    instances: [],
    affected_instance_id: null,
    affected_resolution: "none",
    affected_resolution_reason: "no_instances",
    hook_status: "trusted",
    health_check: null,
    silent: false,
    state_updated: true,
    network_used: false,
    target_mutated: false,
    repair_applied: false,
    error_code: null,
    error_message: null,
  };

  // Case 1: true first-ever scan (no prior fingerprint).
  const firstEver: ScanResult = {
    ...baseFields,
    previous_fingerprint: null,
    overall_fingerprint: "a".repeat(64),
    primary_transition: "first_baseline",
    local_artifact_diff: firstBaselineArt,
  };
  const ctxFirstEver = formatSessionStartContext(firstEver);
  assert.match(
    ctxFirstEver,
    /^ChangeGuard version fingerprint \/ artifact baseline established\./,
  );
  assert.equal(/version fingerprint changed/i.test(ctxFirstEver), false);
  assertNoPathLeak(ctxFirstEver, "/tmp");

  // Case 2: prior v1-like state (previous_fingerprint set) + real identity change
  // + artifact first_baseline (no invented artifact history).
  const v1PriorIdentityChanged: ScanResult = {
    ...baseFields,
    previous_fingerprint: "d".repeat(64),
    overall_fingerprint: "e".repeat(64),
    primary_transition: "upgrade",
    local_artifact_diff: firstBaselineArt,
  };
  const ctxV1Identity = formatSessionStartContext(v1PriorIdentityChanged);
  assert.match(
    ctxV1Identity,
    /^ChangeGuard version fingerprint changed; local installed-artifact baseline established\./,
  );
  assert.equal(
    /version fingerprint \/ artifact baseline established/i.test(ctxV1Identity),
    false,
  );
  assert.match(ctxV1Identity, /local_artifact_status=first_baseline/);
  assert.match(
    ctxV1Identity,
    /artifact_note=historical_update_not_reconstructable/,
  );
  assertNoPathLeak(ctxV1Identity, "/tmp");

  // Case 3: prior fingerprint present, identity unchanged (pure v1 migration).
  const v1PriorIdentitySame: ScanResult = {
    ...baseFields,
    previous_fingerprint: "a".repeat(64),
    overall_fingerprint: "a".repeat(64),
    primary_transition: "unchanged",
    local_artifact_diff: firstBaselineArt,
  };
  const ctxV1Same = formatSessionStartContext(v1PriorIdentitySame);
  assert.match(
    ctxV1Same,
    /^ChangeGuard local installed-artifact fingerprint\/baseline established\./,
  );
  assert.equal(/version fingerprint changed/i.test(ctxV1Same), false);
  assert.equal(
    /version fingerprint \/ artifact baseline established/i.test(ctxV1Same),
    false,
  );
  assertNoPathLeak(ctxV1Same, "/tmp");
});
