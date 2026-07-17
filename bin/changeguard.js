#!/usr/bin/env node
/**
 * Repository / distribution wrapper for the ChangeGuard Rescue CLI.
 * One exact entry path: dist/cli/main.js (built self-contained JavaScript).
 */
import { pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const entry = join(here, "..", "dist", "cli", "main.js");

try {
  await import(pathToFileURL(entry).href);
} catch (err) {
  const message =
    err && typeof err === "object" && "code" in err && err.code === "ERR_MODULE_NOT_FOUND"
      ? "ChangeGuard CLI is not built. Run: npm run build"
      : "ChangeGuard CLI failed to start.";
  console.error(message);
  process.exit(1);
}
