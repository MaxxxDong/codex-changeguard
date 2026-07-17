import { sha256Text } from "./canonical.js";
import { MAX_EVIDENCE_BODY, MAX_EVIDENCE_TITLE } from "./limits.js";
import type { QuarantineRecord } from "./types.js";

/**
 * Instruction-like / executable patterns in untrusted upstream prose.
 * Detection only — never execute, interpolate as instructions, or accept patches.
 */
const INSTRUCTION_PATTERNS: ReadonlyArray<{ id: string; re: RegExp }> = [
  { id: "ignore_instructions", re: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i },
  { id: "system_role", re: /\b(system|developer)\s*:\s*/i },
  { id: "you_are_now", re: /\byou\s+are\s+now\b/i },
  { id: "shell_fence", re: /```(?:bash|sh|zsh|shell|powershell|cmd|ps1)\b/i },
  { id: "sudo", re: /\bsudo\s+\S+/i },
  { id: "destructive_rm", re: /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*|--force)\b/i },
  { id: "curl_pipe", re: /\bcurl\b[^|\n]*\|\s*(?:ba)?sh\b/i },
  { id: "apply_patch", re: /\bapply\s+this\s+patch\b/i },
  { id: "run_command", re: /\b(?:run|execute)\s+this\s+command\b/i },
  { id: "eval_code", re: /\beval\s*\(/i },
  { id: "exfil", re: /\b(?:exfiltrat|steal\s+token|send\s+secrets)\b/i },
];

export function detectInstructionLike(text: string): string | null {
  for (const p of INSTRUCTION_PATTERNS) {
    if (p.re.test(text)) return p.id;
  }
  return null;
}

export function quarantineProse(
  text: string | null | undefined,
  field: "title" | "body" | "content",
): { safe_text: string; quarantine: QuarantineRecord | null } {
  if (text === null || text === undefined || text.length === 0) {
    return { safe_text: "", quarantine: null };
  }
  const max = field === "title" ? MAX_EVIDENCE_TITLE : MAX_EVIDENCE_BODY;
  const clipped = text.length > max ? text.slice(0, max) : text;
  const reason = detectInstructionLike(clipped);
  if (!reason) {
    // Still treat free-form prose as untrusted data: strip CR and bound, never execute.
    const safe = clipped.replace(/\r/g, "").replace(/\0/g, "");
    return { safe_text: safe, quarantine: null };
  }
  const original_sha256 = sha256Text(clipped);
  return {
    safe_text: `<quarantined:${field}:${reason}>`,
    quarantine: {
      quarantined: true,
      reason,
      original_sha256,
      placeholder: `<quarantined:${field}:${reason}>`,
    },
  };
}

/**
 * Merge quarantine records; first non-null wins for primary reason, all reasons recorded in hash set via caller.
 */
export function mergeQuarantine(
  ...records: Array<QuarantineRecord | null>
): QuarantineRecord | null {
  for (const r of records) {
    if (r) return r;
  }
  return null;
}

/** Refuse to treat quarantined or prose text as executable instructions. */
export function assertNotExecutable(_text: string): void {
  // Explicit no-op boundary: callers must never eval/spawn from evidence prose.
  void _text;
}
