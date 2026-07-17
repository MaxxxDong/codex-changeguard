import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { findRepoRoot } from "../src/paths.js";

export const REPO_ROOT = findRepoRoot(import.meta.url);

export function makeTempDir(prefix = "cg-"): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n", "utf8");
}

export function readJson(file: string): unknown {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** Minimal valid incident for negative / mutation tests. */
export function baseIncident(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    schema_version: 1,
    codex_version: null,
    build_sha: null,
    surface: "app_server",
    platform: { os: "macos", arch: "arm64", sandbox_class: null },
    failure_phase: "startup",
    error: {
      class: "SyntaxError",
      normalized_message: "unrelated fixture syntax failure",
      message_digest:
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    stack_frames: [],
    config_keys: [],
    feature_ids: [],
    artifact_hashes: [],
    ast_signature_ids: [],
    local_facts_digest:
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ...overrides,
  };
}
