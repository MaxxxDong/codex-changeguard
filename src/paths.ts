import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Walk up from a file URL/path until package.json name is codex-changeguard. */
export function findRepoRoot(fromUrlOrPath: string = import.meta.url): string {
  let dir = fromUrlOrPath.startsWith("file:")
    ? path.dirname(fileURLToPath(fromUrlOrPath))
    : path.dirname(fromUrlOrPath);
  for (let i = 0; i < 12; i++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(candidate, "utf8")) as {
          name?: string;
        };
        if (pkg.name === "codex-changeguard") {
          return dir;
        }
      } catch {
        /* continue */
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("Repository root not found.");
}
