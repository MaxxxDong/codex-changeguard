/**
 * Support-status upgrade evidence. Synthetic fixtures alone cannot claim FULL.
 */
import type { AdapterId, SupportReceipt } from "./types.js";

export interface SupportReceiptValidation {
  ok: boolean;
  reason_code: string;
}

export function validateSupportReceipt(
  receipt: SupportReceipt,
  expectedAdapter: AdapterId,
): SupportReceiptValidation {
  if (receipt.schema_version !== 1) {
    return { ok: false, reason_code: "BAD_SCHEMA" };
  }
  if (receipt.adapter !== expectedAdapter) {
    return { ok: false, reason_code: "ADAPTER_MISMATCH" };
  }
  if (!Array.isArray(receipt.scenario_ids) || receipt.scenario_ids.length === 0) {
    return { ok: false, reason_code: "NO_SCENARIOS" };
  }
  if (receipt.claimed_status === "FULL" && receipt.real_machine !== true) {
    return { ok: false, reason_code: "FULL_REQUIRES_REAL_MACHINE" };
  }
  return { ok: true, reason_code: "OK" };
}

/** Synthetic harness receipts used in tests — never claim FULL. */
export function syntheticLimitedReceipt(
  adapter: AdapterId,
  scenarioIds: string[],
): SupportReceipt {
  return {
    schema_version: 1,
    scenario_ids: scenarioIds,
    claimed_status: "LIMITED",
    adapter,
    real_machine: false,
    notes: [
      "Synthetic Scenario Harness only; Full support not claimed.",
    ],
  };
}
