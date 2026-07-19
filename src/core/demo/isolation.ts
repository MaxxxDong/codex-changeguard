/**
 * Strict disposable isolation for Ticket 17 demo core.
 * Creates OS-temp children (prefix cg-demo-), copies only allowlisted fixtures,
 * and never touches live ~/.codex. All public outputs use path aliases only.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { findRepoRoot } from "../../paths.js";
import {
  assertDisposableTarget,
  listTrustedDisposableRoots,
} from "../../platform/macos/adapter.js";
import {
  canonicalDisposablePathsEqual,
  proveIsolatedFixtureTarget,
} from "../../platform/capability.js";
import {
  DEMO_FIXTURE_ALLOWLIST,
  DEMO_TEMP_PREFIX,
  type DemoFixtureRel,
} from "./types.js";

export class DemoIsolationError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "DemoIsolationError";
    this.code = code;
  }
}

function tryRealpath(p: string): string | null {
  try {
    return fs.realpathSync.native(p);
  } catch {
    try {
      return fs.realpathSync(p);
    } catch {
      return null;
    }
  }
}

/** Refuse active Codex profile roots (logical + real). */
function isLiveCodexPath(candidate: string, homeDir?: string | null): boolean {
  const home =
    homeDir ?? process.env.HOME ?? process.env.USERPROFILE ?? null;
  if (!home || home.length === 0) return false;
  const active = path.resolve(path.join(home, ".codex"));
  const activeReal = tryRealpath(active) ?? active;
  const cand = path.resolve(candidate);
  const candReal = tryRealpath(cand) ?? cand;
  const under = (root: string, target: string): boolean => {
    if (canonicalDisposablePathsEqual(root, target)) return true;
    const rel = path.relative(root, target);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  };
  return under(active, cand) || under(activeReal, candReal);
}

/**
 * Create a unique disposable demo root under OS temp (prefix cg-demo-).
 * Proves isolation after create: strict trusted-root child, not live profile.
 */
export function createDemoTempRoot(homeDir?: string | null): string {
  const tmpBase = os.tmpdir();
  const baseGate = assertDisposableTarget(tmpBase, homeDir, {
    requireTrustedRoot: true,
  });
  if (!baseGate.ok) {
    throw new DemoIsolationError(
      "TEMP_ROOT_REFUSED",
      "OS temp root is not a trusted disposable root.",
    );
  }

  let root: string;
  try {
    root = fs.mkdtempSync(path.join(tmpBase, DEMO_TEMP_PREFIX));
  } catch {
    throw new DemoIsolationError(
      "TEMP_CREATE_FAILED",
      "Failed to create disposable demo temp directory.",
    );
  }

  if (!proveIsolatedFixtureTarget(root, homeDir)) {
    try {
      fs.rmSync(root, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
    throw new DemoIsolationError(
      "TEMP_ISOLATION_UNPROVABLE",
      "Created temp path failed isolation proof.",
    );
  }

  if (isLiveCodexPath(root, homeDir)) {
    try {
      fs.rmSync(root, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
    throw new DemoIsolationError(
      "LIVE_PROFILE_REFUSED",
      "Demo temp resolved under live Codex profile.",
    );
  }

  // Refuse equality with trusted roots (must be a child).
  const trusted = listTrustedDisposableRoots();
  const real = tryRealpath(root) ?? path.resolve(root);
  for (const t of trusted) {
    if (canonicalDisposablePathsEqual(real, t)) {
      try {
        fs.rmSync(root, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
      throw new DemoIsolationError(
        "TEMP_ROOT_EQUALITY_REFUSED",
        "Demo temp must be a strict child of a trusted root.",
      );
    }
  }

  return root;
}

/**
 * Validate a caller-supplied root: must already exist and prove disposable
 * isolation. Live ~/.codex and non-temp targets are refused.
 */
export function assertCallerDemoRoot(
  targetRoot: string,
  homeDir?: string | null,
): string {
  if (
    typeof targetRoot !== "string" ||
    targetRoot.length === 0 ||
    targetRoot.length > 4096 ||
    targetRoot.includes("\0")
  ) {
    throw new DemoIsolationError("INVALID_TARGET", "Caller target refused.");
  }
  if (isLiveCodexPath(targetRoot, homeDir)) {
    throw new DemoIsolationError(
      "LIVE_PROFILE_REFUSED",
      "Live Codex profile paths are refused.",
    );
  }
  if (!proveIsolatedFixtureTarget(targetRoot, homeDir)) {
    throw new DemoIsolationError(
      "CALLER_TARGET_NOT_DISPOSABLE",
      "Caller target is outside strict disposable isolation.",
    );
  }
  const real = tryRealpath(targetRoot) ?? path.resolve(targetRoot);
  return real;
}

function isAllowlistedFixture(rel: string): rel is DemoFixtureRel {
  return (DEMO_FIXTURE_ALLOWLIST as readonly string[]).includes(rel);
}

/**
 * Recursively inspect a tree without following symlinks.
 * Fail closed on any symlink or non-regular/non-directory filesystem object.
 * Used before allowlisted fixture copy and to verify the copied destination.
 */
export function assertSafeDemoTree(
  root: string,
  role: "source" | "destination" = "source",
): void {
  if (
    typeof root !== "string" ||
    root.length === 0 ||
    root.length > 4096 ||
    root.includes("\0")
  ) {
    throw new DemoIsolationError(
      "FIXTURE_INVALID",
      `Demo ${role} tree path refused.`,
    );
  }

  let rootStat: fs.Stats;
  try {
    rootStat = fs.lstatSync(root);
  } catch {
    throw new DemoIsolationError(
      "FIXTURE_NOT_FOUND",
      `Demo ${role} tree missing.`,
    );
  }
  if (rootStat.isSymbolicLink()) {
    throw new DemoIsolationError(
      "FIXTURE_SYMLINK_REFUSED",
      `Demo ${role} tree root must not be a symlink.`,
    );
  }
  if (!rootStat.isDirectory()) {
    throw new DemoIsolationError(
      "FIXTURE_INVALID",
      `Demo ${role} tree root must be a directory.`,
    );
  }

  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      // withFileTypes uses lstat-style metadata; do not follow links.
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      throw new DemoIsolationError(
        "FIXTURE_INVALID",
        `Demo ${role} tree unreadable.`,
      );
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      // Dirent may report symlink before file/dir; refuse immediately.
      if (ent.isSymbolicLink()) {
        throw new DemoIsolationError(
          "FIXTURE_SYMLINK_REFUSED",
          `Demo ${role} tree contains a nested symlink.`,
        );
      }
      // Double-check with lstat (no follow) — refuse races / specials.
      let st: fs.Stats;
      try {
        st = fs.lstatSync(full);
      } catch {
        throw new DemoIsolationError(
          "FIXTURE_INVALID",
          `Demo ${role} tree entry unreadable.`,
        );
      }
      if (st.isSymbolicLink()) {
        throw new DemoIsolationError(
          "FIXTURE_SYMLINK_REFUSED",
          `Demo ${role} tree contains a nested symlink.`,
        );
      }
      if (st.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!st.isFile()) {
        throw new DemoIsolationError(
          "FIXTURE_INVALID",
          `Demo ${role} tree contains a non-regular filesystem object.`,
        );
      }
    }
  }
}

/**
 * Copy one allowlisted synthetic fixture into destParent as a basename child.
 * Source is always under the repository root; never copies arbitrary paths.
 * Nested symlinks and non-regular objects are refused before and after copy.
 */
export function copyAllowlistedFixture(
  fixtureRel: DemoFixtureRel | string,
  destParent: string,
  homeDir?: string | null,
): string {
  if (!isAllowlistedFixture(fixtureRel)) {
    throw new DemoIsolationError(
      "FIXTURE_NOT_ALLOWLISTED",
      "Fixture is not on the demo allowlist.",
    );
  }
  if (!proveIsolatedFixtureTarget(destParent, homeDir)) {
    throw new DemoIsolationError(
      "DEST_NOT_DISPOSABLE",
      "Fixture destination is not disposable.",
    );
  }
  if (isLiveCodexPath(destParent, homeDir)) {
    throw new DemoIsolationError(
      "LIVE_PROFILE_REFUSED",
      "Live Codex profile paths are refused.",
    );
  }

  const repoRoot = findRepoRoot(import.meta.url);
  const src = path.join(repoRoot, fixtureRel);
  // Fail closed on nested symlinks / specials before any copy (no follow).
  assertSafeDemoTree(src, "source");

  const dest = path.join(destParent, path.basename(fixtureRel));
  if (fs.existsSync(dest)) {
    throw new DemoIsolationError(
      "DEST_EXISTS",
      "Fixture destination already exists.",
    );
  }
  try {
    fs.cpSync(src, dest, {
      recursive: true,
      // Do not follow symlinks out of the fixture tree.
      dereference: false,
      errorOnExist: true,
    });
  } catch (e) {
    if (e instanceof DemoIsolationError) throw e;
    throw new DemoIsolationError(
      "FIXTURE_COPY_FAILED",
      "Failed to copy allowlisted fixture.",
    );
  }

  // Destination must also be free of symlinks / specials before return.
  try {
    assertSafeDemoTree(dest, "destination");
  } catch (e) {
    try {
      fs.rmSync(dest, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
    throw e;
  }

  if (!proveIsolatedFixtureTarget(dest, homeDir)) {
    try {
      fs.rmSync(dest, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
    throw new DemoIsolationError(
      "FIXTURE_DEST_ISOLATION_UNPROVABLE",
      "Copied fixture failed isolation proof.",
    );
  }
  return dest;
}

/** Best-effort recursive remove; returns whether the path is gone. */
export function removeDemoTempRoot(root: string | null | undefined): boolean {
  if (!root || typeof root !== "string" || root.length === 0) return true;
  // Never remove trusted roots themselves or live profile.
  const real = tryRealpath(root) ?? path.resolve(root);
  const trusted = listTrustedDisposableRoots();
  for (const t of trusted) {
    if (canonicalDisposablePathsEqual(real, t)) {
      return false;
    }
  }
  if (isLiveCodexPath(root)) {
    return false;
  }
  try {
    fs.rmSync(root, { recursive: true, force: true });
  } catch {
    /* continue to existence check */
  }
  return !fs.existsSync(root);
}

/** SHA-256 hex of a file under an isolated target (relative path only). */
export function hashRelativeFile(
  targetRoot: string,
  rel: string,
): string | null {
  if (
    typeof rel !== "string" ||
    rel.length === 0 ||
    path.isAbsolute(rel) ||
    rel.includes("\0") ||
    rel.includes("..")
  ) {
    return null;
  }
  const full = path.join(targetRoot, rel);
  try {
    const buf = fs.readFileSync(full);
    return crypto.createHash("sha256").update(buf).digest("hex");
  } catch {
    return null;
  }
}
