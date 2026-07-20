/**
 * Bounded macOS Sparkle staged-update discovery.
 *
 * Production root (exact):
 *   $HOME/Library/Caches/com.openai.codex/org.sparkle-project.Sparkle/Installation
 *
 * Traversal (exactly two directory levels under Installation, plus optional shallow compat):
 *   allowlisted root
 *     → direct session directories only (bounded, symlink-refused)
 *       → direct download directories only (bounded, symlink-refused)
 *         → exact direct child ChatGPT.app only
 *   Optional bounded compat: session/ChatGPT.app (direct child) is also accepted.
 *
 * No recursive walk, no depth beyond those levels, no wildcard app names.
 * Caps: 8 session dirs, 16 download dirs (global), 4 accepted candidates.
 * Never follows symlinks for root/session/download/app/required artifacts.
 */
import fs from "node:fs";
import path from "node:path";
import {
  assertRealDirectory,
  BoundedPathError,
  isInsideRoot,
  readRelativeUnderRoot,
  resolveRegularFileUnderRoot,
} from "../path-bounded.js";
import { pathHashOf } from "../identity.js";
import { MAX_PLIST_VERSION_META_BYTES } from "../limits.js";
import {
  MAX_DOWNLOAD_DIR_NAME,
  MAX_SESSION_DIR_NAME,
  MAX_STAGED_CANDIDATES,
  MAX_STAGED_DOWNLOAD_DIRS,
  MAX_STAGED_SESSION_DIRS,
  REQUIRED_APP_REL_FILES,
  SPARKLE_INSTALLATION_REL,
  STAGED_APP_BASENAME,
  STAGED_BUNDLE_ID,
} from "./limits.js";

export interface StagedDiscoveryCaps {
  /** Override platform detection (tests). */
  platform?: NodeJS.Platform | string;
  /** Override home directory (tests). */
  homeDir?: string | null;
  /** Inject exact Installation root (tests only). */
  installationRoot?: string | null;
  /** Inject installed app roots (absolute). Empty = use production defaults. */
  installedAppPaths?: string[] | null;
  env?: NodeJS.ProcessEnv;
}

export interface ValidatedAppBundle {
  /** Absolute path — internal only; never export. */
  absRoot: string;
  path_hash: string;
  version: string;
  build: string;
  bundle_id: string;
  su_public_ed_key: string | null;
  role: "installed" | "staged";
  /** Session dir basename for staged (alias material); null for installed. */
  session_token: string | null;
}

export interface StagedDiscoveryResult {
  platform: string;
  supported: boolean;
  installation_root_available: boolean;
  sessions_inspected: number;
  sessions_capped: boolean;
  download_dirs_inspected: number;
  download_dirs_capped: boolean;
  candidates: ValidatedAppBundle[];
  candidates_capped: boolean;
  rejection_counts: Record<string, number>;
  installed: ValidatedAppBundle | null;
  installed_rejection: string | null;
}

function bump(counts: Record<string, number>, reason: string): void {
  counts[reason] = (counts[reason] ?? 0) + 1;
}

function detectPlatform(caps: StagedDiscoveryCaps): string {
  if (caps.platform) return String(caps.platform);
  return process.platform;
}

function homeOf(caps: StagedDiscoveryCaps): string | null {
  if (caps.homeDir !== undefined) return caps.homeDir;
  const env = caps.env ?? process.env;
  const h = env.HOME || env.USERPROFILE || null;
  return h && h.length > 0 ? h : null;
}

function productionInstallationRoot(caps: StagedDiscoveryCaps): string | null {
  if (caps.installationRoot !== undefined && caps.installationRoot !== null) {
    return path.resolve(caps.installationRoot);
  }
  const home = homeOf(caps);
  if (!home) return null;
  return path.join(home, ...SPARKLE_INSTALLATION_REL);
}

function productionInstalledAppPaths(caps: StagedDiscoveryCaps): string[] {
  if (Array.isArray(caps.installedAppPaths)) {
    return caps.installedAppPaths.map((p) => path.resolve(p));
  }
  const out: string[] = ["/Applications/ChatGPT.app"];
  const home = homeOf(caps);
  if (home) {
    out.push(path.join(home, "Applications", "ChatGPT.app"));
  }
  return out;
}

function parsePlistField(text: string, key: string): string | null {
  const re = new RegExp(
    `<key>${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}<\\/key>\\s*<string>([^<]+)<\\/string>`,
  );
  const m = text.match(re);
  if (!m?.[1]) return null;
  const v = m[1].trim();
  return v.length > 0 && v.length <= 256 ? v : null;
}

/**
 * Validate a ChatGPT.app bundle under an allowed parent root (or as its own root).
 * Refuses symlink root/app/required artifacts; requires exact relative files and bundle id.
 */
export function validateAppBundle(
  appAbs: string,
  role: "installed" | "staged",
  opts: {
    session_token?: string | null;
    /** When set, app must be inside this real parent directory. */
    parentRoot?: string | null;
    /** Required SUPublicEDKey match (for staged vs installed). */
    requireSuKey?: string | null;
  } = {},
): { ok: true; bundle: ValidatedAppBundle } | { ok: false; reason: string } {
  const resolved = path.resolve(appAbs);
  if (path.basename(resolved) !== STAGED_APP_BASENAME) {
    return { ok: false, reason: "wrong_app_basename" };
  }

  let appRoot: string;
  try {
    appRoot = assertRealDirectory(resolved);
  } catch (e) {
    if (e instanceof BoundedPathError) {
      if (e.code === "SYMLINK_ESCAPE") return { ok: false, reason: "symlink_app" };
      return { ok: false, reason: "app_not_directory" };
    }
    return { ok: false, reason: "app_not_directory" };
  }

  if (opts.parentRoot) {
    let parent: string;
    try {
      parent = assertRealDirectory(opts.parentRoot);
    } catch {
      return { ok: false, reason: "parent_root_invalid" };
    }
    if (!isInsideRoot(parent, appRoot) || path.dirname(appRoot) !== parent) {
      return { ok: false, reason: "app_not_direct_child" };
    }
  }

  for (const rel of REQUIRED_APP_REL_FILES) {
    try {
      resolveRegularFileUnderRoot(appRoot, rel.split("/").join(path.sep));
    } catch (e) {
      if (e instanceof BoundedPathError) {
        if (e.code === "SYMLINK_ESCAPE") {
          return { ok: false, reason: `symlink_artifact:${rel}` };
        }
        if (e.code === "NOT_FOUND") {
          return { ok: false, reason: `missing_artifact:${rel}` };
        }
        return { ok: false, reason: `artifact_refused:${rel}` };
      }
      return { ok: false, reason: `artifact_refused:${rel}` };
    }
  }

  const plistText = readRelativeUnderRoot(
    appRoot,
    path.join("Contents", "Info.plist"),
    MAX_PLIST_VERSION_META_BYTES,
  );
  if (plistText === null) {
    return { ok: false, reason: "plist_unreadable" };
  }

  const bundle_id = parsePlistField(plistText, "CFBundleIdentifier");
  if (bundle_id !== STAGED_BUNDLE_ID) {
    return { ok: false, reason: "bundle_id_mismatch" };
  }
  const version = parsePlistField(plistText, "CFBundleShortVersionString");
  const build = parsePlistField(plistText, "CFBundleVersion");
  if (!version || !build) {
    return { ok: false, reason: "version_fields_missing" };
  }
  const suKey = parsePlistField(plistText, "SUPublicEDKey");
  if (opts.requireSuKey !== undefined && opts.requireSuKey !== null) {
    if (!suKey || suKey !== opts.requireSuKey) {
      return { ok: false, reason: "su_public_ed_key_mismatch" };
    }
  }

  return {
    ok: true,
    bundle: {
      absRoot: appRoot,
      path_hash: pathHashOf(appRoot),
      version,
      build,
      bundle_id,
      su_public_ed_key: suKey,
      role,
      session_token: opts.session_token ?? null,
    },
  };
}

function isSafeDirName(name: string, maxLen: number): boolean {
  return (
    typeof name === "string" &&
    name.length > 0 &&
    name.length <= maxLen &&
    name !== "." &&
    name !== ".." &&
    !name.includes("\0") &&
    !name.includes("/") &&
    !name.includes("\\")
  );
}

function tryAcceptStagedApp(
  appAbs: string,
  parentAbs: string,
  sessionName: string,
  installed: ValidatedAppBundle | null,
  candidates: ValidatedAppBundle[],
  rejection_counts: Record<string, number>,
  state: { candidates_capped: boolean },
): void {
  if (candidates.length >= MAX_STAGED_CANDIDATES) {
    state.candidates_capped = true;
    return;
  }
  // Spec: staged SUPublicEDKey must match installed when installed is known.
  // Without an installed baseline key, authenticity cannot be verified → reject.
  const requireKey = installed?.su_public_ed_key ?? null;
  if (installed && !requireKey) {
    bump(rejection_counts, "staged:su_public_ed_key_no_installed_baseline");
    return;
  }
  const v = validateAppBundle(appAbs, "staged", {
    session_token: sessionName.slice(0, 32),
    parentRoot: parentAbs,
    requireSuKey: requireKey,
  });
  if (!v.ok) {
    bump(rejection_counts, `staged:${v.reason}`);
    return;
  }
  // When no installed app, still require a nonempty staged key (updater authenticity material).
  if (!installed && !v.bundle.su_public_ed_key) {
    bump(rejection_counts, "staged:su_public_ed_key_missing");
    return;
  }
  candidates.push(v.bundle);
  if (candidates.length >= MAX_STAGED_CANDIDATES) {
    state.candidates_capped = true;
  }
}

/**
 * Discover installed ChatGPT.app (first valid production candidate) and staged apps.
 *
 * Staged layout (mandatory real path):
 *   Installation/<session>/<download>/ChatGPT.app
 * Bounded fixture compat:
 *   Installation/<session>/ChatGPT.app
 */
export function discoverStagedAndInstalled(
  caps: StagedDiscoveryCaps = {},
): StagedDiscoveryResult {
  const platform = detectPlatform(caps);
  const rejection_counts: Record<string, number> = {};

  if (platform !== "darwin" && platform !== "macos") {
    // Non-macOS: no production discovery unless tests inject roots.
    const hasInject =
      (caps.installationRoot !== undefined && caps.installationRoot !== null) ||
      (Array.isArray(caps.installedAppPaths) && caps.installedAppPaths.length > 0);
    if (!hasInject) {
      const plat =
        platform === "win32"
          ? "windows"
          : platform === "linux"
            ? "linux"
            : platform;
      return {
        platform: plat,
        supported: false,
        installation_root_available: false,
        sessions_inspected: 0,
        sessions_capped: false,
        download_dirs_inspected: 0,
        download_dirs_capped: false,
        candidates: [],
        candidates_capped: false,
        rejection_counts: { unsupported_platform: 1 },
        installed: null,
        installed_rejection: "unsupported_platform",
      };
    }
  }

  // Installed app
  let installed: ValidatedAppBundle | null = null;
  let installed_rejection: string | null = null;
  const installPaths = productionInstalledAppPaths(caps);
  for (const p of installPaths) {
    const v = validateAppBundle(p, "installed");
    if (v.ok) {
      installed = v.bundle;
      break;
    }
    installed_rejection = v.reason;
    bump(rejection_counts, `installed:${v.reason}`);
  }
  if (!installed && installPaths.length === 0) {
    installed_rejection = "no_installed_path";
  }

  // Staged discovery
  const installRoot = productionInstallationRoot(caps);
  let installation_root_available = false;
  let sessions_inspected = 0;
  let sessions_capped = false;
  let download_dirs_inspected = 0;
  let download_dirs_capped = false;
  const candidates: ValidatedAppBundle[] = [];
  const candidateState = { candidates_capped: false };

  if (!installRoot) {
    bump(rejection_counts, "no_installation_root");
  } else {
    let root: string | null = null;
    try {
      root = assertRealDirectory(installRoot);
      installation_root_available = true;
    } catch (e) {
      if (e instanceof BoundedPathError && e.code === "SYMLINK_ESCAPE") {
        bump(rejection_counts, "symlink_installation_root");
      } else {
        bump(rejection_counts, "installation_root_missing");
      }
      root = null;
    }

    if (root) {
      let sessionNames: string[] = [];
      try {
        sessionNames = fs.readdirSync(root);
      } catch {
        bump(rejection_counts, "installation_readdir_failed");
        sessionNames = [];
      }
      // Deterministic order.
      sessionNames = [...sessionNames].sort((a, b) => a.localeCompare(b));

      for (const sessionName of sessionNames) {
        if (sessions_inspected >= MAX_STAGED_SESSION_DIRS) {
          sessions_capped = true;
          break;
        }
        if (!isSafeDirName(sessionName, MAX_SESSION_DIR_NAME)) {
          bump(rejection_counts, "session_name_invalid");
          continue;
        }
        const sessionAbs = path.join(root, sessionName);
        let sessionSt: fs.Stats;
        try {
          sessionSt = fs.lstatSync(sessionAbs);
        } catch {
          bump(rejection_counts, "session_lstat_failed");
          continue;
        }
        if (sessionSt.isSymbolicLink()) {
          bump(rejection_counts, "symlink_session");
          sessions_inspected += 1;
          continue;
        }
        if (!sessionSt.isDirectory()) {
          bump(rejection_counts, "session_not_directory");
          continue;
        }
        sessions_inspected += 1;

        // Bounded fixture compat: session/ChatGPT.app (direct child).
        // Real Sparkle layout uses session/download/ChatGPT.app below.
        const shallowAppAbs = path.join(sessionAbs, STAGED_APP_BASENAME);
        try {
          const shallowSt = fs.lstatSync(shallowAppAbs);
          if (shallowSt.isSymbolicLink()) {
            bump(rejection_counts, "staged:symlink_app");
          } else if (shallowSt.isDirectory()) {
            tryAcceptStagedApp(
              shallowAppAbs,
              sessionAbs,
              sessionName,
              installed,
              candidates,
              rejection_counts,
              candidateState,
            );
          } else {
            bump(rejection_counts, "staged:app_not_directory");
          }
        } catch {
          // No shallow app — expected for real nested layout.
        }

        // Nested layout: session → download dirs → ChatGPT.app
        // Skip further download inspection once the global download-dir cap is hit,
        // but keep counting remaining sessions for honesty.
        if (download_dirs_capped) {
          continue;
        }

        let downloadNames: string[] = [];
        try {
          downloadNames = fs.readdirSync(sessionAbs);
        } catch {
          bump(rejection_counts, "session_readdir_failed");
          downloadNames = [];
        }
        downloadNames = [...downloadNames].sort((a, b) => a.localeCompare(b));

        for (const downloadName of downloadNames) {
          // Skip the app basename itself (handled as shallow compat above).
          if (downloadName === STAGED_APP_BASENAME) {
            continue;
          }
          if (download_dirs_inspected >= MAX_STAGED_DOWNLOAD_DIRS) {
            download_dirs_capped = true;
            break;
          }
          if (!isSafeDirName(downloadName, MAX_DOWNLOAD_DIR_NAME)) {
            bump(rejection_counts, "download_name_invalid");
            continue;
          }
          const downloadAbs = path.join(sessionAbs, downloadName);
          let downloadSt: fs.Stats;
          try {
            downloadSt = fs.lstatSync(downloadAbs);
          } catch {
            bump(rejection_counts, "download_lstat_failed");
            continue;
          }
          if (downloadSt.isSymbolicLink()) {
            bump(rejection_counts, "symlink_download");
            download_dirs_inspected += 1;
            continue;
          }
          if (!downloadSt.isDirectory()) {
            // Non-directory siblings (files, etc.) are not download dirs — skip silently.
            continue;
          }
          download_dirs_inspected += 1;

          // Only exact direct child ChatGPT.app — no deeper walk.
          // Over-depth trees (download/extra/ChatGPT.app) are never probed.
          const nestedAppAbs = path.join(downloadAbs, STAGED_APP_BASENAME);
          try {
            const appSt = fs.lstatSync(nestedAppAbs);
            if (appSt.isSymbolicLink()) {
              bump(rejection_counts, "staged:symlink_app");
              continue;
            }
            if (!appSt.isDirectory()) {
              bump(rejection_counts, "staged:app_not_directory");
              continue;
            }
          } catch {
            // No ChatGPT.app under this download dir. Detect over-depth decoys
            // only when a single immediate child dir exists that is not the app
            // and contains ChatGPT.app — refuse without accepting.
            try {
              const childNames = fs.readdirSync(downloadAbs);
              for (const child of childNames) {
                if (!isSafeDirName(child, MAX_DOWNLOAD_DIR_NAME)) continue;
                const deeper = path.join(downloadAbs, child, STAGED_APP_BASENAME);
                try {
                  const deeperSt = fs.lstatSync(deeper);
                  if (deeperSt.isDirectory() || deeperSt.isSymbolicLink()) {
                    bump(rejection_counts, "staged:over_depth");
                    break;
                  }
                } catch {
                  // no deeper app
                }
              }
            } catch {
              // ignore readdir failures for empty/missing
            }
            bump(rejection_counts, "staged:app_not_directory");
            continue;
          }

          tryAcceptStagedApp(
            nestedAppAbs,
            downloadAbs,
            sessionName,
            installed,
            candidates,
            rejection_counts,
            candidateState,
          );
        }
      }
    }
  }

  return {
    platform:
      platform === "darwin"
        ? "macos"
        : platform === "win32"
          ? "windows"
          : platform === "linux"
            ? "linux"
            : String(platform),
    supported: true,
    installation_root_available,
    sessions_inspected,
    sessions_capped,
    download_dirs_inspected,
    download_dirs_capped,
    candidates,
    candidates_capped: candidateState.candidates_capped,
    rejection_counts,
    installed,
    installed_rejection,
  };
}
