/**
 * Standalone CLI read-only hash proof (Ticket 01).
 * Hashes isolated target before/after `changeguard diagnose`; expects equality.
 */
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function hashTree(root) {
  const h = crypto.createHash("sha256");
  const walk = (dir) => {
    for (const ent of fs
      .readdirSync(dir, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, ent.name);
      const rel = path.relative(root, full).split(path.sep).join("/");
      if (ent.isSymbolicLink()) {
        h.update(`L:${rel}->${fs.readlinkSync(full)}\n`);
      } else if (ent.isDirectory()) {
        h.update(`D:${rel}\n`);
        walk(full);
      } else if (ent.isFile()) {
        const buf = fs.readFileSync(full);
        h.update(`F:${rel}:${buf.length}:`);
        h.update(buf);
        h.update("\n");
      }
    }
  };
  walk(root);
  return h.digest("hex");
}

function prove(fixtureRel) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cg-proof-"));
  const dest = path.join(tmp, path.basename(fixtureRel));
  fs.cpSync(path.join(repoRoot, fixtureRel), dest, { recursive: true });
  const before = hashTree(dest);
  const res = spawnSync(
    process.execPath,
    [path.join(repoRoot, "bin/changeguard.js"), "diagnose", dest],
    { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } },
  );
  const after = hashTree(dest);
  const result = JSON.parse(res.stdout);
  const ok =
    before === after &&
    result.network_used === false &&
    result.target_mutated === false &&
    result.repair_applied === false &&
    result.diagnosis_state !== "RESOLVED_VERIFIED";
  return {
    fixture: fixtureRel,
    exitCode: res.status,
    before,
    after,
    unchanged: before === after,
    diagnosis_state: result.diagnosis_state,
    ok,
  };
}

const reports = [
  prove("fixtures/protected-process"),
  prove("fixtures/negative-control"),
];
const allOk = reports.every((r) => r.ok && r.exitCode === 0);
console.log(JSON.stringify({ allOk, reports }, null, 2));
process.exit(allOk ? 0 : 1);
