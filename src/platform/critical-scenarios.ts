/**
 * Canonical Windows 11 critical Scenario Harness matrix (Ticket 14).
 * Missing any ID blocks FULL elevation.
 */
import type { Windows11CriticalScenarioId } from "./types.js";

export interface CriticalScenarioDefinition {
  id: Windows11CriticalScenarioId;
  title: string;
  description: string;
}

/** Ordered matrix — Full requires every entry present and passed. */
export const WINDOWS11_CRITICAL_SCENARIOS: readonly CriticalScenarioDefinition[] =
  [
    {
      id: "W11-S01",
      title: "Multi-identity scan without collapse",
      description:
        "scan-system enumerates at least two install identities (e.g. MSIX+PATH or Desktop+PATH) as distinct instance rows.",
    },
    {
      id: "W11-S02",
      title: "Windows + WSL coexistence",
      description:
        "Windows-native and WSL CLI identities remain independent; ambiguous repair binding is refused.",
    },
    {
      id: "W11-S03",
      title: "Crash metadata classification",
      description:
        "Read-only crash metadata classifies one Browser crash family with correct Top-3 candidate.",
    },
    {
      id: "W11-S04",
      title: "Cross-family repair refusal",
      description:
        "Title-similarity / wrong-family evidence cannot reach repair authorization.",
    },
    {
      id: "W11-S05",
      title: "User-owned repair verified",
      description:
        "User-owned cache/control: preview → apply → verify → RESOLVED_VERIFIED with hash receipts.",
    },
    {
      id: "W11-S06",
      title: "Induced verification auto-rollback",
      description:
        "Induced verification failure restores exact original bytes; RESOLVED_VERIFIED impossible.",
    },
    {
      id: "W11-S07",
      title: "Explicit rollback",
      description:
        "Explicit rollback reaches MITIGATED_VERIFIED_BY_ROLLBACK with original hash match.",
    },
    {
      id: "W11-S08",
      title: "Managed/admin handoff",
      description:
        "Managed/ACL/MSIX package targets yield ADMIN_ACTION_REQUIRED + IT handoff without elevation guidance.",
    },
    {
      id: "W11-S09",
      title: "SessionStart Windows hook",
      description:
        "SessionStart commandWindows: silent on unchanged fingerprint; changed path stays read-only under 10s.",
    },
    {
      id: "W11-S10",
      title: "CLI/MCP equivalence and boundary",
      description:
        "CLI/MCP stable-field equivalence; production boundary checks green.",
    },
    {
      id: "W11-S11",
      title: "No forbidden writes",
      description:
        "No writes to WindowsApps, Program Files, registry policy, or signed app binaries.",
    },
  ] as const;

export const WINDOWS11_CRITICAL_SCENARIO_IDS: readonly Windows11CriticalScenarioId[] =
  WINDOWS11_CRITICAL_SCENARIOS.map((s) => s.id);

export function isCriticalScenarioId(
  value: string,
): value is Windows11CriticalScenarioId {
  return (WINDOWS11_CRITICAL_SCENARIO_IDS as readonly string[]).includes(value);
}
