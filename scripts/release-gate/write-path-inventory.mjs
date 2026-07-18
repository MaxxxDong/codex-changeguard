/**
 * Production write-path inventory (Ticket 16).
 *
 * Every production writer is classified as repair | state | ledger.
 * Repair paths require the full contract markers in source.
 * State/ledger paths must NOT be falsely forced into a repair contract.
 * Inventory is bound to the production-boundary allowlist and real files.
 */

import fs from "node:fs";
import path from "node:path";

/**
 * Canonical production writers. Harness-only writers (e.g. macos-scenario)
 * are intentionally excluded.
 */
export const WRITE_PATH_INVENTORY = Object.freeze([
  {
    id: "recovery-atomic-write",
    class: "repair",
    rel: "src/core/recovery/atomic-write.ts",
    required_markers: [
      "createVerifiedBackup",
      "atomicReplaceFile",
      "restoreFromBackup",
    ],
    /** Companion engine that forbids RESOLVED_VERIFIED on verify failure */
    companion_rel: "src/core/recovery/engine.ts",
    companion_markers: [
      "RESOLVED_VERIFIED is impossible",
      "auto_rollback",
      "createVerifiedBackup",
    ],
    boundary_bind: "recovery",
  },
  {
    id: "instance-fingerprint-state",
    class: "state",
    rel: "src/instances/state.ts",
    required_markers: ["writeFileSync", "renameSync"],
    // State writes are ChangeGuard-owned; no repair backup/rollback contract.
    forbid_false_repair_claim: true,
    boundary_bind: "state_allowlist",
  },
  {
    id: "upstream-confirmation-ledger",
    class: "ledger",
    rel: "src/upstream/actions/ledger.ts",
    required_markers: ["writeFileSync", "renameSync"],
    forbid_false_repair_claim: true,
    boundary_bind: "state_allowlist",
  },
  {
    id: "followup-ledger",
    class: "ledger",
    rel: "src/upstream/followup/ledger.ts",
    required_markers: ["writeFileSync", "renameSync"],
    forbid_false_repair_claim: true,
    boundary_bind: "state_allowlist",
  },
  {
    id: "lifecycle-ledger",
    class: "ledger",
    rel: "src/core/lifecycle/ledger.ts",
    required_markers: ["KNOWN_GOOD", "checkpoint"],
    forbid_false_repair_claim: true,
    boundary_bind: "lifecycle",
  },
]);

/** Mirrors scripts/check-production-boundary.mjs DEFAULT_STATE_WRITE_ALLOWLIST. */
export const BOUNDARY_STATE_WRITE_ALLOWLIST = Object.freeze([
  "src/instances/state.ts",
  "src/upstream/actions/ledger.ts",
  "src/upstream/followup/ledger.ts",
]);

export const BOUNDARY_RECOVERY_WRITE_PATH = "src/core/recovery/atomic-write.ts";

/**
 * @param {string} repoRoot
 * @param {{ inventory?: readonly typeof WRITE_PATH_INVENTORY, stateAllowlist?: readonly string[], recoveryPath?: string }} [opts]
 */
export function checkWritePathInventory(repoRoot, opts = {}) {
  const inventory = opts.inventory ?? WRITE_PATH_INVENTORY;
  const stateAllowlist = new Set(opts.stateAllowlist ?? BOUNDARY_STATE_WRITE_ALLOWLIST);
  const recoveryPath = opts.recoveryPath ?? BOUNDARY_RECOVERY_WRITE_PATH;
  /** @type {string[]} */
  const errors = [];

  const inventoryRels = new Set(inventory.map((e) => e.rel));

  // Drift: every state allowlist path must appear as state or ledger in inventory
  for (const rel of stateAllowlist) {
    const entry = inventory.find((e) => e.rel === rel);
    if (!entry) {
      errors.push(`missing_inventory_for_allowlist:${rel}`);
      continue;
    }
    if (entry.class !== "state" && entry.class !== "ledger") {
      errors.push(`allowlist_not_state_or_ledger:${rel}`);
    }
  }

  // Recovery path must be inventory repair class
  const recoveryEntry = inventory.find((e) => e.rel === recoveryPath);
  if (!recoveryEntry) {
    errors.push(`missing_recovery_inventory:${recoveryPath}`);
  } else if (recoveryEntry.class !== "repair") {
    errors.push(`recovery_not_repair_class:${recoveryPath}`);
  }

  for (const entry of inventory) {
    const abs = path.join(repoRoot, entry.rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
      errors.push(`missing_writer:${entry.id}`);
      continue;
    }
    const text = fs.readFileSync(abs, "utf8");
    for (const m of entry.required_markers) {
      if (!text.includes(m)) {
        errors.push(`missing_marker:${entry.id}:${m}`);
      }
    }
    if (entry.companion_rel) {
      const cAbs = path.join(repoRoot, entry.companion_rel);
      if (!fs.existsSync(cAbs)) {
        errors.push(`missing_companion:${entry.id}`);
      } else {
        const cText = fs.readFileSync(cAbs, "utf8");
        for (const m of entry.companion_markers ?? []) {
          if (!cText.includes(m)) {
            errors.push(`missing_companion_marker:${entry.id}:${m}`);
          }
        }
      }
    }
    if (entry.class === "repair") {
      // Repair must prove cannot yield RESOLVED_VERIFIED on failure via companion/engine
      const engineAbs = path.join(repoRoot, entry.companion_rel ?? "src/core/recovery/engine.ts");
      if (fs.existsSync(engineAbs)) {
        const eng = fs.readFileSync(engineAbs, "utf8");
        if (!eng.includes("RESOLVED_VERIFIED is impossible")) {
          errors.push(`repair_missing_resolved_block:${entry.id}`);
        }
      }
    }
    if (entry.boundary_bind === "state_allowlist" && !stateAllowlist.has(entry.rel)) {
      errors.push(`not_on_boundary_allowlist:${entry.id}`);
    }
    if (entry.boundary_bind === "recovery" && entry.rel !== recoveryPath) {
      errors.push(`recovery_path_mismatch:${entry.id}`);
    }
  }

  // Detect unregistered production writers under known write surfaces
  const scanRoots = [
    "src/core/recovery",
    "src/instances",
    "src/upstream/actions",
    "src/upstream/followup",
    "src/core/lifecycle",
  ];
  for (const root of scanRoots) {
    const absRoot = path.join(repoRoot, root);
    if (!fs.existsSync(absRoot)) continue;
    walkTsFiles(absRoot, repoRoot, (relFromRepo, abs) => {
      if (relFromRepo.includes("/harness/")) return;
      const text = fs.readFileSync(abs, "utf8");
      if (inventoryRels.has(relFromRepo)) return;
      if (relFromRepo === "src/core/recovery/engine.ts") return;
      if (relFromRepo.endsWith("/index.ts")) return;
      if (relFromRepo.endsWith("/types.ts") || relFromRepo.endsWith("/constants.ts")) return;
      if (relFromRepo === "src/core/lifecycle/engine.ts") return;
      if (relFromRepo === "src/core/lifecycle/dispatch.ts") return;
      if (relFromRepo === "src/core/lifecycle/live-measurement.ts") return;
      if (/fs\.(writeFileSync|writeSync|renameSync)/.test(text)) {
        errors.push(`unregistered_writer:${relFromRepo}`);
      }
    });
  }

  if (errors.length > 0) {
    return {
      ok: false,
      reason_code: "GATE_WRITE_PATH",
      errors,
      detail: "write_path_inventory_failed",
    };
  }
  return {
    ok: true,
    reason_code: null,
    errors: [],
    detail: "write_path_inventory_ok",
    count: inventory.length,
  };
}

/**
 * @param {string} dir
 * @param {string} repoRoot
 * @param {(rel: string, abs: string) => void} fn
 */
function walkTsFiles(dir, repoRoot, fn) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, ent.name);
    if (ent.isDirectory()) walkTsFiles(abs, repoRoot, fn);
    else if (ent.isFile() && ent.name.endsWith(".ts")) {
      const rel = path.relative(repoRoot, abs).split(path.sep).join("/");
      fn(rel, abs);
    }
  }
}
