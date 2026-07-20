/**
 * Bounded path-free observation of direct `.node` basenames under
 * Contents/Resources/native (outside ASAR).
 *
 * Rules:
 * - Exact relative dir Contents/Resources/native under validated app roots
 * - Directory may be absent
 * - If present: real non-symlink direct directory; no recursion
 * - Direct children only; deterministic sort; hard cap
 * - Symlink children refused/skipped; only regular files ending in `.node`
 * - Public output: capped added/removed basenames + status/cap truth only
 */
import fs from "node:fs";
import path from "node:path";
import { assertRealDirectory, isInsideRoot } from "../path-bounded.js";
import {
  MAX_NATIVE_MODULE_BASENAMES,
  NATIVE_MODULE_DIR_REL,
} from "./limits.js";
import type { NativeModuleDiff } from "./types.js";

function emptyNative(
  status: NativeModuleDiff["status"],
  reason: string | null,
  extras: Partial<NativeModuleDiff> = {},
): NativeModuleDiff {
  return {
    status,
    reason,
    added: [],
    removed: [],
    truncation: { entries_capped: false },
    installed_dir_present: null,
    staged_dir_present: null,
    ...extras,
  };
}

/**
 * List direct regular-file `.node` basenames under appRoot/Contents/Resources/native.
 * Internal absolute paths are never returned.
 */
export function listNativeModuleBasenames(appRootAbs: string): {
  status: "ok" | "absent" | "refused" | "capped";
  reason: string | null;
  basenames: string[];
  dir_present: boolean;
  entries_capped: boolean;
} {
  let root: string;
  try {
    root = assertRealDirectory(appRootAbs);
  } catch {
    return {
      status: "refused",
      reason: "app_root_invalid",
      basenames: [],
      dir_present: false,
      entries_capped: false,
    };
  }

  const relParts = NATIVE_MODULE_DIR_REL.split("/");
  let cursor = root;
  for (const part of relParts) {
    cursor = path.join(cursor, part);
    if (!isInsideRoot(root, cursor)) {
      return {
        status: "refused",
        reason: "path_escape",
        basenames: [],
        dir_present: false,
        entries_capped: false,
      };
    }
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(cursor);
    } catch {
      return {
        status: "absent",
        reason: "dir_absent",
        basenames: [],
        dir_present: false,
        entries_capped: false,
      };
    }
    if (lst.isSymbolicLink()) {
      return {
        status: "refused",
        reason: "symlink_dir",
        basenames: [],
        dir_present: false,
        entries_capped: false,
      };
    }
    if (!lst.isDirectory()) {
      return {
        status: "refused",
        reason: "not_directory",
        basenames: [],
        dir_present: false,
        entries_capped: false,
      };
    }
  }

  let names: string[];
  try {
    names = fs.readdirSync(cursor);
  } catch {
    return {
      status: "refused",
      reason: "readdir_failed",
      basenames: [],
      dir_present: true,
      entries_capped: false,
    };
  }

  // Deterministic order before hard cap on inspected dirents.
  names = names.slice().sort((a, b) => a.localeCompare(b));
  const entries_capped = names.length > MAX_NATIVE_MODULE_BASENAMES;
  const limited = names.slice(0, MAX_NATIVE_MODULE_BASENAMES);
  const accepted: string[] = [];

  for (const name of limited) {
    if (
      typeof name !== "string" ||
      name.length === 0 ||
      name === "." ||
      name === ".." ||
      name.includes("\0") ||
      name.includes("/") ||
      name.includes("\\") ||
      !name.endsWith(".node")
    ) {
      continue;
    }
    const child = path.join(cursor, name);
    if (!isInsideRoot(root, child)) continue;
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(child);
    } catch {
      continue;
    }
    // Symlink children refused/skipped (not accepted as .node basenames).
    if (lst.isSymbolicLink()) continue;
    if (!lst.isFile()) continue;
    accepted.push(name);
  }

  return {
    status: entries_capped ? "capped" : "ok",
    reason: entries_capped ? "entries_capped" : null,
    basenames: accepted,
    dir_present: true,
    entries_capped,
  };
}

function setOf(names: string[]): Set<string> {
  return new Set(names);
}

/**
 * Compare installed vs staged native module basenames (path-free).
 * Degrades explicitly on refuse/cap; never fails named-artifact comparison.
 */
export function compareNativeModuleDirs(
  installedAppRoot: string | null,
  stagedAppRoot: string | null,
): NativeModuleDiff {
  if (!installedAppRoot && !stagedAppRoot) {
    return emptyNative("unavailable", "no_app_roots");
  }
  if (!installedAppRoot || !stagedAppRoot) {
    return emptyNative("partial", "one_side_missing_app");
  }

  try {
    const inst = listNativeModuleBasenames(installedAppRoot);
    const stg = listNativeModuleBasenames(stagedAppRoot);

    const instSet = setOf(inst.basenames);
    const stgSet = setOf(stg.basenames);
    const added = [...stgSet]
      .filter((n) => !instSet.has(n))
      .sort((a, b) => a.localeCompare(b))
      .slice(0, MAX_NATIVE_MODULE_BASENAMES);
    const removed = [...instSet]
      .filter((n) => !stgSet.has(n))
      .sort((a, b) => a.localeCompare(b))
      .slice(0, MAX_NATIVE_MODULE_BASENAMES);

    const eitherRefused =
      inst.status === "refused" || stg.status === "refused";
    const eitherCapped =
      inst.entries_capped ||
      stg.entries_capped ||
      inst.status === "capped" ||
      stg.status === "capped";

    if (eitherRefused) {
      return {
        status: "partial",
        reason: `side_refused:${inst.reason ?? "ok"}/${stg.reason ?? "ok"}`,
        added,
        removed,
        truncation: { entries_capped: eitherCapped },
        installed_dir_present: inst.dir_present,
        staged_dir_present: stg.dir_present,
      };
    }

    if (eitherCapped) {
      return {
        status: "partial",
        reason: "entries_capped",
        added,
        removed,
        truncation: { entries_capped: true },
        installed_dir_present: inst.dir_present,
        staged_dir_present: stg.dir_present,
      };
    }

    // Both sides ok or absent (absent is a valid complete observation).
    return {
      status: "compared",
      reason: null,
      added,
      removed,
      truncation: { entries_capped: false },
      installed_dir_present: inst.dir_present,
      staged_dir_present: stg.dir_present,
    };
  } catch {
    return emptyNative("unavailable", "native_compare_exception");
  }
}
