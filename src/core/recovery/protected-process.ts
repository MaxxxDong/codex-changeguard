/**
 * Registered protected-process experimental repair (exact block removal).
 * Operates only on the named BROWSER_CLIENT_COPY_A artifact under an isolated target.
 */
import {
  MAX_ARTIFACT_BYTES,
  PROTECTED_ARTIFACT_REL,
  PROTECTED_AST_SIGNATURE_ID,
} from "../limits.js";
import { measureProtectedProcessAst, sha256Buffer } from "../measure.js";
import { digestObject, sha256Text } from "./canonical.js";

/** Canonical description of the registered operation (no source bytes). */
export const PROTECTED_PROCESS_OP = {
  kind: "exact_block_removal" as const,
  target_path_alias: "BROWSER_CLIENT_COPY_A",
  artifact_rel: PROTECTED_ARTIFACT_REL,
  expected_pattern_count: 1,
  signature_id: PROTECTED_AST_SIGNATURE_ID,
  description:
    "Remove the exact three-statement protected-process shim block; leave surrounding fixture content.",
};

export function operationDigest(): string {
  return digestObject({
    kind: PROTECTED_PROCESS_OP.kind,
    target_path_alias: PROTECTED_PROCESS_OP.target_path_alias,
    expected_pattern_count: PROTECTED_PROCESS_OP.expected_pattern_count,
    signature_id: PROTECTED_PROCESS_OP.signature_id,
    description: PROTECTED_PROCESS_OP.description,
  });
}

/**
 * Locate and remove exactly one protected-process shim block from source text.
 * Uses the same structural tokenizer as diagnosis — comments/strings/regex cannot spoof.
 * Returns null when pattern count is not exactly one.
 */
export function removeProtectedProcessBlock(source: string): {
  next: string;
  original_pattern_count: number;
  result_pattern_count: number;
  result_sha256: string;
} | null {
  const measured = measureProtectedProcessAst(source);
  if (!measured.matched || measured.blockCount !== 1) {
    return null;
  }
  // Structural removal: find the three assignment statements by line scan with
  // the same token match, then rewrite source without those statements.
  // Prefer exact statement-text removal of the known three lines when present
  // as contiguous statements (fixture and same-shape targets).
  const next = stripShimStatements(source);
  if (next === null) {
    return null;
  }
  const after = measureProtectedProcessAst(next);
  return {
    next,
    original_pattern_count: measured.blockCount,
    result_pattern_count: after.blockCount,
    result_sha256: sha256Buffer(Buffer.from(next, "utf8")),
  };
}

/**
 * Strip the three shim assignment statements while preserving other content.
 * Fails closed when the exact contiguous block is not present as statements.
 */
function stripShimStatements(source: string): string | null {
  // Match the exact three-statement block as written by the positive fixture
  // and any target that uses the same structural form with an identifier shim.
  // We operate on logical lines after normalizing newlines.
  const normalized = source.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normalized.split("\n");

  // Find index of `globalThis.process = <id>;`
  let start = -1;
  let shimId: string | null = null;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i]!.match(/^\s*globalThis\.process\s*=\s*([A-Za-z_$][\w$]*)\s*;\s*$/);
    if (m) {
      start = i;
      shimId = m[1]!;
      break;
    }
  }
  if (start < 0 || !shimId) return null;
  if (start + 2 >= lines.length) return null;

  const line2 = lines[start + 1]!;
  const line3 = lines[start + 2]!;
  const re2 =
    /^\s*globalThis\.global\s*=\s*globalThis\.global\s*\?\?\s*globalThis\s*;\s*$/;
  const re3 = new RegExp(
    `^\\s*globalThis\\.global\\.process\\s*=\\s*${escapeRegExp(shimId)}\\s*;\\s*$`,
  );
  if (!re2.test(line2) || !re3.test(line3)) {
    return null;
  }

  // Confirm structural measure still sees exactly one block before stripping.
  const before = measureProtectedProcessAst(normalized);
  if (!before.matched || before.blockCount !== 1) return null;

  const outLines = [
    ...lines.slice(0, start),
    ...lines.slice(start + 3),
  ];
  // Drop a now-unused `const <shimId> = Object.create(null);` immediately above
  // when present (fixture cleanup). Optional — only when adjacent.
  if (outLines.length > 0 && start > 0) {
    const prevIdx = start - 1;
    // After removal, previous line is still at prevIdx in original; in outLines
    // it remains at start-1.
    const prev = outLines[start - 1] ?? "";
    const unused = new RegExp(
      `^\\s*const\\s+${escapeRegExp(shimId)}\\s*=\\s*Object\\.create\\(null\\)\\s*;\\s*$`,
    );
    if (unused.test(prev)) {
      outLines.splice(start - 1, 1);
      void prevIdx;
    }
  }

  // Insert a single comment marker that is not a structural match.
  const insertAt = Math.min(start > 0 ? start - 1 : 0, outLines.length);
  // Prefer placing the repair note near the original site without spoofing AST.
  const note =
    "// ChangeGuard authorized repair: protected-process shim block removed.";
  // Find a good insertion point: after remaining comments near original start.
  let insert = 0;
  for (let i = 0; i < outLines.length; i++) {
    const t = outLines[i]!.trim();
    if (t.startsWith("//") || t.length === 0) {
      insert = i + 1;
      continue;
    }
    break;
  }
  outLines.splice(insert, 0, note);
  void insertAt;

  let next = outLines.join("\n");
  if (!next.endsWith("\n") && source.endsWith("\n")) {
    next += "\n";
  }
  const after = measureProtectedProcessAst(next);
  if (after.matched || after.blockCount !== 0) {
    return null;
  }
  // Core health: marker export must remain when it was present.
  if (
    /\bexport\s+const\s+marker\b/.test(normalized) &&
    !/\bexport\s+const\s+marker\b/.test(next)
  ) {
    return null;
  }
  return next;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Core health checks on repaired (or current) artifact bytes.
 * No network, no shell — structural + size only.
 */
export function coreHealthChecks(source: string): {
  passed: boolean;
  checks: { id: string; passed: boolean; detail: string }[];
} {
  const checks: { id: string; passed: boolean; detail: string }[] = [];
  const nonEmpty = source.length > 0 && source.length <= MAX_ARTIFACT_BYTES;
  checks.push({
    id: "size_bound",
    passed: nonEmpty,
    detail: nonEmpty ? "Artifact size within bounds." : "Artifact size invalid.",
  });
  const hasMarker = /\bexport\s+const\s+marker\b/.test(source);
  checks.push({
    id: "marker_export",
    passed: hasMarker,
    detail: hasMarker
      ? "Fixture marker export present."
      : "Fixture marker export missing.",
  });
  const noShim = !measureProtectedProcessAst(source).matched;
  checks.push({
    id: "no_protected_shim",
    passed: noShim,
    detail: noShim
      ? "Protected-process shim absent."
      : "Protected-process shim still present.",
  });
  // Lightweight syntax gate: balanced braces/parens and no NUL.
  const noNul = !source.includes("\0");
  checks.push({
    id: "no_nul",
    passed: noNul,
    detail: noNul ? "No NUL bytes." : "NUL bytes present.",
  });
  const balance = balancedDelimiters(source);
  checks.push({
    id: "delimiter_balance",
    passed: balance,
    detail: balance ? "Delimiters balanced." : "Unbalanced delimiters.",
  });
  return {
    passed: checks.every((c) => c.passed),
    checks,
  };
}

function balancedDelimiters(source: string): boolean {
  // Skip strings/comments roughly for health only (not a full parser).
  let paren = 0;
  let brace = 0;
  let bracket = 0;
  let i = 0;
  const n = source.length;
  while (i < n) {
    const ch = source[i]!;
    if (ch === "/" && source[i + 1] === "/") {
      i += 2;
      while (i < n && source[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && source[i + 1] === "*") {
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      const q = ch;
      i += 1;
      while (i < n) {
        if (source[i] === "\\") {
          i += 2;
          continue;
        }
        if (source[i] === q) {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === "(") paren += 1;
    else if (ch === ")") paren -= 1;
    else if (ch === "{") brace += 1;
    else if (ch === "}") brace -= 1;
    else if (ch === "[") bracket += 1;
    else if (ch === "]") bracket -= 1;
    if (paren < 0 || brace < 0 || bracket < 0) return false;
    i += 1;
  }
  return paren === 0 && brace === 0 && bracket === 0;
}

export function preHandshakeFailureStillPresent(source: string): boolean {
  // Original failure mechanism: protected-process shim redefinition present.
  return measureProtectedProcessAst(source).matched;
}

export function artifactPathAlias(): string {
  return PROTECTED_PROCESS_OP.target_path_alias;
}

export function artifactRel(): string {
  return PROTECTED_PROCESS_OP.artifact_rel;
}

/** Stable invalidation material for capsule binding. */
export function invalidationMaterial(input: {
  original_sha256: string;
  expected_pattern_count: number;
  scope_digest: string;
  operation_digest: string;
  capsule_id: string;
  mode: string;
  authorization_tier: string;
}): string {
  return digestObject({
    v: 1,
    ...input,
  });
}

export function authorizationBinding(input: {
  capsule_id: string;
  scope_digest: string;
  original_sha256: string;
  expected_pattern_count: number;
  operation_digest: string;
  invalidation_digest: string;
  trust_tier: string;
  authorization_tier: string;
  mode: string;
  target_path_alias: string;
  expires_at: string;
}): string {
  return digestObject({
    kind: "changeguard_repair_authorization_v1",
    ...input,
  });
}

/** Expiry: 1 hour from preview time (UTC ISO). */
export function defaultExpiryIso(nowMs = Date.now()): string {
  return new Date(nowMs + 60 * 60 * 1000).toISOString();
}

export function isExpired(expiresAt: string, nowMs = Date.now()): boolean {
  const t = Date.parse(expiresAt);
  if (!Number.isFinite(t)) return true;
  return nowMs >= t;
}

export function hashForLog(sha: string): string {
  // Never required, but keep helpers path-free.
  return sha256Text(sha).slice(0, 16);
}
