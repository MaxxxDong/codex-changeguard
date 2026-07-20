/**
 * Bounds for manual staged local-update comparison (path-free, read-only).
 * Separate from SessionStart temporal artifact baselines.
 */

/** Cap inspected Sparkle session directories under the Installation root. */
export const MAX_STAGED_SESSION_DIRS = 8;
/**
 * Cap inspected download directories under session dirs (global across sessions).
 * Real Sparkle layout: Installation/<session>/<download>/ChatGPT.app.
 */
export const MAX_STAGED_DOWNLOAD_DIRS = 16;
/** Cap accepted valid staged app candidates after validation. */
export const MAX_STAGED_CANDIDATES = 4;
/** Max recursion depth when walking ASAR header JSON tree. */
export const MAX_ASAR_TREE_DEPTH = 24;
/**
 * Max total nodes visited in ASAR header JSON.
 * Conservative bound above real ChatGPT.app headers (~6.4k nodes).
 */
export const MAX_ASAR_NODES = 8192;
/** Max path segment length in ASAR header. */
export const MAX_ASAR_PATH_SEGMENT = 256;
/** Max full path string length in ASAR header. */
export const MAX_ASAR_PATH_LEN = 512;
/** Max ASAR outer header-pickle size (bytes) we will read. */
export const MAX_ASAR_HEADER_PICKLE_BYTES = 4 * 1024 * 1024;
/** Max inner JSON string byte length. */
export const MAX_ASAR_HEADER_JSON_BYTES = 3 * 1024 * 1024;
/** Cap public component arrays (stable paths, .node basenames, buckets). */
export const MAX_COMPONENT_ARRAY = 32;
/**
 * Cap direct `.node` basenames inspected under Contents/Resources/native
 * (outside ASAR; path-free basename observation only).
 */
export const MAX_NATIVE_MODULE_BASENAMES = 32;
/** Relative native-module directory under a validated ChatGPT.app root. */
export const NATIVE_MODULE_DIR_REL = "Contents/Resources/native" as const;
/** Cap named artifact comparison rows returned. */
export const MAX_NAMED_ARTIFACT_ROWS = 8;
/** Cap official evidence item digests listed when version-bound. */
export const MAX_OFFICIAL_ITEM_DIGESTS = 16;
/** Cap inference / unknown note strings. */
export const MAX_INFERENCE_NOTES = 24;
/** Cap inspected session dir name length. */
export const MAX_SESSION_DIR_NAME = 128;
/** Cap inspected download dir name length (same bound as session). */
export const MAX_DOWNLOAD_DIR_NAME = 128;
/** Required staged macOS bundle identifier. */
export const STAGED_BUNDLE_ID = "com.openai.codex";
/**
 * Exact staged app basename.
 * Accepted only as a direct child of a download directory
 * (or, for bounded fixture compat, as a direct child of a session directory).
 */
export const STAGED_APP_BASENAME = "ChatGPT.app";
/** Relative Sparkle Installation root under $HOME (POSIX). */
export const SPARKLE_INSTALLATION_REL = [
  "Library",
  "Caches",
  "com.openai.codex",
  "org.sparkle-project.Sparkle",
  "Installation",
] as const;

/** Exact named artifacts compared (stable keys). */
export const NAMED_STAGED_ARTIFACTS = [
  "info_plist",
  "app_asar",
  "codex_binary",
  "code_resources",
] as const;

export type NamedStagedArtifactKey = (typeof NAMED_STAGED_ARTIFACTS)[number];

/** Stable same-path component allowlist inside ASAR (when present). */
export const ASAR_STABLE_PATH_ALLOWLIST = [
  ".vite/build/early-bootstrap.js",
  "package.json",
  "webview/avatar-overlay-composition-surface.html",
  "webview/index.html",
] as const;

/**
 * Default wall-clock budget for named-artifact hashing in this manual command.
 * Reuses the SessionStart-scale budget invariant (not a second unbounded hasher).
 */
export const DEFAULT_COMPARE_LOCAL_UPDATE_TIME_BUDGET_MS = 8000;

/** Required relative files inside a staged/installed ChatGPT.app (POSIX). */
export const REQUIRED_APP_REL_FILES = [
  "Contents/Info.plist",
  "Contents/Resources/app.asar",
  "Contents/Resources/codex",
  "Contents/_CodeSignature/CodeResources",
] as const;
