/**
 * Windows write / discovery policy (Ticket 14).
 * Bounded allowlists and hard-forbidden system zones.
 * Never guides privilege elevation or registry policy mutation.
 */
import path from "node:path";
import type {
  WindowsWriteClassification,
  WindowsWriteScope,
} from "./types.js";

/** Normalized forbidden path markers (lowercase, both separators). */
const FORBIDDEN_MARKERS = [
  "windowsapps",
  "program files",
  "program files (x86)",
  "programdata\\microsoft\\windows\\start menu",
  "programdata/microsoft/windows/start menu",
  "\\windows\\system32",
  "/windows/system32",
  "\\windows\\syswow64",
  "/windows/syswow64",
] as const;

const FORBIDDEN_BASENAMES = new Set([
  "codex.exe",
  "chatgpt.exe",
  "chrome.dll",
  "appxmanifest.xml",
]);

/**
 * Classify whether a candidate absolute path is a hard-forbidden system zone.
 * Used for repair refusal — discovery may still lstat App Execution Alias.
 */
export function isForbiddenSystemPath(absPath: string): boolean {
  const n = absPath.split(path.sep).join("\\").toLowerCase();
  for (const m of FORBIDDEN_MARKERS) {
    if (n.includes(m)) {
      // Allow LOCALAPPDATA\Microsoft\WindowsApps alias for existence only —
      // write classification still forbids mutation (see classifyWriteTarget).
      if (
        m === "windowsapps" &&
        (n.includes("\\appdata\\local\\microsoft\\windowsapps") ||
          n.includes("/appdata/local/microsoft/windowsapps"))
      ) {
        // Alias location: not Program Files\WindowsApps package store.
        // Still forbidden for writes; flag via dedicated helper.
        continue;
      }
      return true;
    }
  }
  // Package store under Program Files\WindowsApps
  if (n.includes("\\program files\\windowsapps") || n.includes("/program files/windowsapps")) {
    return true;
  }
  return false;
}

/** True when path is the user-local App Execution Alias directory. */
export function isMsixAliasPath(absPath: string): boolean {
  const n = absPath.split(path.sep).join("\\").toLowerCase();
  return (
    n.includes("\\appdata\\local\\microsoft\\windowsapps") ||
    n.includes("/appdata/local/microsoft/windowsapps")
  );
}

/** True when path looks like a signed Desktop/MSIX application binary. */
export function isSignedAppBinaryPath(absPath: string): boolean {
  const base = path.basename(absPath).toLowerCase();
  if (FORBIDDEN_BASENAMES.has(base) && base.endsWith(".exe")) return true;
  if (base.endsWith(".dll") || base.endsWith(".sys")) return true;
  return false;
}

/**
 * User-owned roots for Windows repair (relative markers).
 * Real ACL checks are host-specific; tests inject owned roots.
 */
export function isUnderUserOwnedMarkers(
  absPath: string,
  userRoots: string[] = [],
): boolean {
  const resolved = path.resolve(absPath);
  for (const root of userRoots) {
    const r = path.resolve(root);
    const rel = path.relative(r, resolved);
    if (rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel))) {
      return true;
    }
  }
  const n = resolved.split(path.sep).join("\\").toLowerCase();
  // Heuristic markers only for classification language — production repair
  // still requires isolated target roots via Ticket 02 engine.
  if (n.includes("\\appdata\\local\\") || n.includes("\\appdata\\roaming\\")) {
    if (isMsixAliasPath(resolved) || isForbiddenSystemPath(resolved)) {
      return false;
    }
    return true;
  }
  if (n.includes("\\.codex\\") || n.includes("/.codex/")) return true;
  if (n.includes("\\users\\") && n.includes("\\appdata\\")) {
    if (isMsixAliasPath(resolved) || isForbiddenSystemPath(resolved)) {
      return false;
    }
    return true;
  }
  return false;
}

export interface ClassifyWriteOptions {
  /** Absolute candidate path (in-memory only). */
  absPath: string;
  /** Public alias for the target. */
  target_path_alias: string;
  /** Injected user-owned roots (tests / explicit registration). */
  userOwnedRoots?: string[];
  /** Managed policy / admin ownership flags from fixture probe. */
  managed?: {
    policy_class: string;
    admin_owned: boolean;
    signed: boolean;
    permission_bound: boolean;
  };
  bound_instance_id?: string | null;
}

/**
 * Classify a write target for repair eligibility.
 * ADMIN paths never receive chmod/elevation/bypass guidance.
 */
export function classifyWriteTarget(
  opts: ClassifyWriteOptions,
): WindowsWriteClassification {
  const abs = path.resolve(opts.absPath);
  const alias = opts.target_path_alias;

  if (opts.managed) {
    return {
      scope: "admin_required",
      policy_class: opts.managed.policy_class,
      target_path_alias: alias,
      admin_owned: opts.managed.admin_owned,
      signed: opts.managed.signed,
      permission_bound: opts.managed.permission_bound,
      requested_action:
        "Contact IT/admin to update managed Codex control configuration through approved enterprise change process.",
      bound_instance_id: null,
    };
  }

  if (isMsixAliasPath(abs) || isForbiddenSystemPath(abs)) {
    return {
      scope: "forbidden_system",
      policy_class: isMsixAliasPath(abs) ? "msix_package" : "system_acl",
      target_path_alias: alias,
      admin_owned: true,
      signed: true,
      permission_bound: true,
      requested_action:
        "Do not modify WindowsApps, Program Files, or signed package binaries. Use official install/update channels or enterprise change process.",
      bound_instance_id: null,
    };
  }

  if (isSignedAppBinaryPath(abs) && !isUnderUserOwnedMarkers(abs, opts.userOwnedRoots ?? [])) {
    return {
      scope: "forbidden_system",
      policy_class: "signed_binary",
      target_path_alias: alias,
      admin_owned: true,
      signed: true,
      permission_bound: true,
      requested_action:
        "Signed application binaries are not local repair targets; use official install sources only.",
      bound_instance_id: null,
    };
  }

  if (isUnderUserOwnedMarkers(abs, opts.userOwnedRoots ?? [])) {
    return {
      scope: "user_owned",
      policy_class: "user_profile",
      target_path_alias: alias,
      admin_owned: false,
      signed: false,
      permission_bound: false,
      requested_action:
        "User-owned cache/control files may be repaired only after scope-bound authorization with backup, atomic apply, verify, and rollback.",
      bound_instance_id: opts.bound_instance_id ?? null,
    };
  }

  return {
    scope: "unknown" as WindowsWriteScope,
    policy_class: "unknown",
    target_path_alias: alias,
    admin_owned: false,
    signed: false,
    permission_bound: true,
    requested_action:
      "Target ownership is unclear; refuse local mutation and collect bounded evidence for IT handoff if managed.",
    bound_instance_id: null,
  };
}

/** Map write scope to recovery error code language. */
export function writeScopeToErrorCode(
  scope: WindowsWriteScope,
): "ADMIN_ACTION_REQUIRED" | "REPAIR_REFUSED" | null {
  if (scope === "admin_required" || scope === "forbidden_system") {
    return "ADMIN_ACTION_REQUIRED";
  }
  if (scope === "unknown") return "REPAIR_REFUSED";
  return null;
}
