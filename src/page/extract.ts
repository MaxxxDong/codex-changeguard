import {
  detectInstructionLike,
  quarantineProse,
} from "../evidence/quarantine.js";
import { redactText } from "../core/redact.js";
import {
  MAX_CITED_SOURCES,
  MAX_COMMAND_CANDIDATES,
  MAX_EXTRACTION_ITEMS,
  MAX_EXTRACTION_TOKEN,
} from "./limits.js";
import type {
  LabeledExtractionItem,
  PageEvidenceEnvelope,
  PageExtraction,
} from "./types.js";
import type { QuarantineRecord } from "../evidence/types.js";

function clipToken(s: string): string {
  const t = redactText(s).trim();
  if (t.length <= MAX_EXTRACTION_TOKEN) return t;
  return t.slice(0, MAX_EXTRACTION_TOKEN);
}

function pushItem(
  arr: LabeledExtractionItem[],
  item: LabeledExtractionItem,
): void {
  if (arr.length >= MAX_EXTRACTION_ITEMS) return;
  if (!item.value) return;
  arr.push(item);
}

function uniquePush(arr: string[], value: string, max: number): void {
  const v = clipToken(value);
  if (!v || arr.includes(v) || arr.length >= max) return;
  arr.push(v);
}

/**
 * Extract labeled page facts, claims, commands, and inferences from untrusted text.
 * All values remain trust: untrusted_page. Instruction-like content is quarantined.
 */
export function extractPageContent(envelope: PageEvidenceEnvelope): {
  extraction: PageExtraction;
  quarantine: QuarantineRecord | null;
  injection_quarantined: boolean;
  safe_visible_text: string;
} {
  const titleQ = quarantineProse(envelope.visible_title, "title");
  const bodyQ = quarantineProse(envelope.visible_text, "body");
  const quarantine = bodyQ.quarantine ?? titleQ.quarantine;
  const injection_quarantined = quarantine !== null;

  // Analyze original (bounded) text for structured extraction, but never treat
  // it as instructions. Safe text is used only for non-instruction fields.
  const textForScan = `${envelope.visible_title}\n${envelope.visible_text}`;
  const nfkcText = textForScan.normalize("NFKC");

  const observed_facts: LabeledExtractionItem[] = [];
  const author_claims: LabeledExtractionItem[] = [];
  const commands_workarounds: LabeledExtractionItem[] = [];
  const inferences: LabeledExtractionItem[] = [];

  const symptoms: string[] = [];
  let platform: string | null = null;
  let surface: string | null = null;
  const versions: string[] = [];
  const errors: string[] = [];
  const stack_symbols: string[] = [];
  let failure_phase: string | null = null;
  const operations: string[] = [];
  const cited_sources: string[] = [];
  const conclusions: string[] = [];

  // Platform markers
  if (/\bwindows(?:\s*11)?\b/i.test(nfkcText) || /\bwin32\b/i.test(nfkcText)) {
    platform = "windows";
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "platform",
      value: "windows",
      trust: "untrusted_page",
    });
  } else if (/\bmacos\b|\bmac\s*os\b|\bdarwin\b/i.test(nfkcText)) {
    platform = "macos";
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "platform",
      value: "macos",
      trust: "untrusted_page",
    });
  } else if (/\blinux\b|\bubuntu\b|\bwsl\b/i.test(nfkcText)) {
    platform = "linux";
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "platform",
      value: "linux",
      trust: "untrusted_page",
    });
  }

  // Surface markers
  if (
    /\bbrowser[_ ]?control\b|\bin-app browser\b|\bcodex browser\b/i.test(nfkcText)
  ) {
    surface = "browser_control";
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "surface",
      value: "browser_control",
      trust: "untrusted_page",
    });
  } else if (/\bcodex\s+cli\b|\bsurface:\s*cli\b/i.test(nfkcText)) {
    surface = "cli";
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "surface",
      value: "cli",
      trust: "untrusted_page",
    });
  } else if (/\bcodex\s+desktop\b|\bsurface:\s*desktop\b/i.test(nfkcText)) {
    surface = "desktop";
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "surface",
      value: "desktop",
      trust: "untrusted_page",
    });
  } else if (
    /\bchatgpt\b|\bsession expired\b|\baccount\b.*\blogin\b/i.test(nfkcText) &&
    !/\bcodex\b/i.test(nfkcText)
  ) {
    surface = "chatgpt_account";
    pushItem(author_claims, {
      kind: "author_claim",
      field: "surface",
      value: "chatgpt_account",
      trust: "untrusted_page",
    });
  }

  // Versions
  for (const m of nfkcText.matchAll(
    /\b(?:codex|rust-)?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\b/gi,
  )) {
    uniquePush(versions, m[1] ?? m[0]!, MAX_EXTRACTION_ITEMS);
  }
  for (const v of versions) {
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "version",
      value: v,
      trust: "untrusted_page",
    });
  }

  // Error classes / messages
  const errorPatterns: RegExp[] = [
    /\bTypeError\b[^\n]{0,120}/gi,
    /\bReferenceError\b[^\n]{0,120}/gi,
    /\bError:\s*[^\n]{0,120}/gi,
    /\b0x[cC][0-9a-fA-F]{7}\b/g,
    /\bprotected global process binding rejected assignment\b/gi,
    /\bsession expired\b/gi,
  ];
  for (const re of errorPatterns) {
    for (const m of nfkcText.matchAll(re)) {
      uniquePush(errors, m[0]!, MAX_EXTRACTION_ITEMS);
    }
  }
  for (const e of errors) {
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "error",
      value: e,
      trust: "untrusted_page",
    });
  }

  // Stack symbols
  const stackPatterns: RegExp[] = [
    /\bchrome\.dll\+[0-9a-fx]+/gi,
    /\bCrBrowserMain\b/g,
    /\bjs\.global-process-shim-redefinition\.v1\b/g,
    /\bmodule_initialization\b/g,
    /\bbrowser-client\.mjs\b/gi,
  ];
  for (const re of stackPatterns) {
    for (const m of nfkcText.matchAll(re)) {
      uniquePush(stack_symbols, m[0]!, MAX_EXTRACTION_ITEMS);
    }
  }
  for (const s of stack_symbols) {
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "stack_symbol",
      value: s,
      trust: "untrusted_page",
    });
  }

  // Failure phase
  if (/\bbefore (?:extension )?handshake\b|\bextension_handshake\b/i.test(nfkcText)) {
    failure_phase = "extension_handshake";
  } else if (/\bat startup\b|\bfailure_phase:\s*startup\b/i.test(nfkcText)) {
    failure_phase = "startup";
  } else if (/\bafter DOM-ready\b|\bnavigation\b/i.test(nfkcText)) {
    failure_phase = "navigation";
  }
  if (failure_phase) {
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "failure_phase",
      value: failure_phase,
      trust: "untrusted_page",
    });
  }

  // Symptoms
  if (
    /\bcrash(?:es|ed|ing)?\b/i.test(nfkcText) ||
    /\bfails? to start\b/i.test(nfkcText) ||
    /\bhangs?\b/i.test(nfkcText) ||
    /\brejected assignment\b/i.test(nfkcText)
  ) {
    const symptom = clipToken(
      nfkcText
        .split(/\n/)
        .map((l) => l.trim())
        .find(
          (l) =>
            /crash|fail|hang|rejected assignment|error/i.test(l) &&
            l.length > 8 &&
            l.length < 200,
        ) ?? "failure_reported",
    );
    uniquePush(symptoms, symptom, MAX_EXTRACTION_ITEMS);
    pushItem(author_claims, {
      kind: "author_claim",
      field: "symptom",
      value: symptom,
      trust: "untrusted_page",
    });
  }

  // Cited sources (URLs / issue refs)
  for (const m of nfkcText.matchAll(
    /https?:\/\/[^\s)\]>'"]+/gi,
  )) {
    uniquePush(cited_sources, m[0]!, MAX_CITED_SOURCES);
  }
  for (const m of nfkcText.matchAll(/#(\d{3,6})\b/g)) {
    uniquePush(cited_sources, `issue:${m[1]}`, MAX_CITED_SOURCES);
  }
  for (const c of cited_sources) {
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "cited_source",
      value: c,
      trust: "untrusted_page",
    });
  }

  // Commands / workarounds (code fences and shell-like lines)
  const commandBlocks: string[] = [];
  for (const m of nfkcText.matchAll(
    /```(?:bash|sh|zsh|shell|powershell|cmd|ps1)?\s*\n([\s\S]*?)```/gi,
  )) {
    const body = (m[1] ?? "").trim();
    if (body) commandBlocks.push(body.slice(0, MAX_EXTRACTION_TOKEN * 2));
  }
  for (const line of nfkcText.split(/\n/)) {
    const t = line.trim();
    if (
      /^(?:sudo\s+|rm\s+|curl\s+|npm\s+|npx\s+|codex\s+|export\s+|setx\s+)/i.test(
        t,
      ) ||
      /^\$\s+\S+/.test(t)
    ) {
      commandBlocks.push(t.slice(0, MAX_EXTRACTION_TOKEN * 2));
    }
    if (
      /workaround|fix:|patch:|remove the shim|delete globalThis\.process/i.test(
        t,
      )
    ) {
      commandBlocks.push(t.slice(0, MAX_EXTRACTION_TOKEN * 2));
    }
  }
  let cmdCount = 0;
  for (const cmd of commandBlocks) {
    if (cmdCount >= MAX_COMMAND_CANDIDATES) break;
    // Still record even if instruction-like — as command_workaround data only.
    const summary = clipToken(cmd);
    uniquePush(operations, summary, MAX_EXTRACTION_ITEMS);
    pushItem(commands_workarounds, {
      kind: "command_workaround",
      field: "operation",
      value: summary,
      trust: "untrusted_page",
    });
    cmdCount++;
  }

  // Author conclusions / inferences
  for (const line of nfkcText.split(/\n/)) {
    const t = line.trim();
    if (
      /^(?:root cause|conclusion|this is (?:because|caused)|the fix is|clearly)/i.test(
        t,
      ) ||
      /\bmust be\b.*\b(bug|cause|issue)\b/i.test(t)
    ) {
      const c = clipToken(t);
      uniquePush(conclusions, c, MAX_EXTRACTION_ITEMS);
      pushItem(author_claims, {
        kind: "author_claim",
        field: "conclusion",
        value: c,
        trust: "untrusted_page",
      });
      pushItem(inferences, {
        kind: "inference",
        field: "conclusion",
        value: c,
        trust: "untrusted_page",
      });
    }
  }

  // If body was quarantined for injection, record that as an observed system fact
  // about the page content — not as an instruction.
  if (injection_quarantined) {
    const reason = detectInstructionLike(envelope.visible_text) ??
      detectInstructionLike(envelope.visible_title) ??
      "instruction_like";
    pushItem(observed_facts, {
      kind: "observed_fact",
      field: "other",
      value: `quarantined:${reason}`,
      trust: "untrusted_page",
    });
  }

  return {
    extraction: {
      observed_facts,
      author_claims,
      commands_workarounds,
      inferences,
      symptoms,
      platform,
      surface,
      versions,
      errors,
      stack_symbols,
      failure_phase,
      operations,
      cited_sources,
      conclusions,
    },
    quarantine,
    injection_quarantined,
    safe_visible_text: bodyQ.safe_text,
  };
}
