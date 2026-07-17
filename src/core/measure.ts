import crypto from "node:crypto";
import { PROTECTED_AST_SIGNATURE_ID } from "./limits.js";

export function sha256Buffer(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/**
 * Minimal deterministic JS tokenizer for structural signature measurement.
 * Skips comments, string/template contents, and regex literals so
 * comment/string/regex spoofing cannot match.
 *
 * Production-self-contained: no runtime parser dependency.
 */

type TokKind =
  | "ident"
  | "punct"
  | "op"
  | "number"
  | "string"
  | "template"
  | "eof";

interface Tok {
  kind: TokKind;
  value: string;
}

/** Keywords after which `/` starts a regex literal, not division. */
const REGEX_AFTER_KEYWORDS = new Set([
  "return",
  "throw",
  "case",
  "else",
  "typeof",
  "void",
  "delete",
  "await",
  "new",
  "in",
  "of",
  "instanceof",
  "yield",
  "do",
]);

function isIdentStart(ch: string): boolean {
  return /[A-Za-z_$]/.test(ch);
}

function isIdentCont(ch: string): boolean {
  return /[A-Za-z0-9_$]/.test(ch);
}

/**
 * Conservative previous-token test: true → `/` may start a regex literal.
 * Fail closed on residual ambiguity by preferring regex-literal skip
 * (avoids promoting spoof text into a false structural match).
 */
function slashStartsRegex(prev: Tok | undefined): boolean {
  if (!prev || prev.kind === "eof") return true;
  if (prev.kind === "number" || prev.kind === "string" || prev.kind === "template") {
    return false;
  }
  if (prev.kind === "ident") {
    return REGEX_AFTER_KEYWORDS.has(prev.value);
  }
  if (prev.kind === "op") {
    // Comparison / logical / nullish ops introduce an expression → regex.
    return true;
  }
  if (prev.kind === "punct") {
    // After primary expression tail, `/` is division.
    if (prev.value === ")" || prev.value === "]" || prev.value === "}") {
      return false;
    }
    // After assignment, comma, semicolon, open groups, operators → regex.
    return true;
  }
  // Unknown prior kind — fail closed: treat as regex so spoof text is skipped.
  return true;
}

/**
 * Consume a JavaScript regex literal body starting at `i` (index of `/`).
 * Handles escapes and character classes. Returns index after optional flags,
 * or -1 if the span cannot be closed safely (caller should not promote).
 */
function skipRegexLiteral(text: string, i: number): number {
  const n = text.length;
  if (text[i] !== "/") return -1;
  let j = i + 1;
  let inClass = false;
  while (j < n) {
    const ch = text[j]!;
    if (ch === "\\") {
      j += 2;
      continue;
    }
    if (ch === "[" && !inClass) {
      inClass = true;
      j += 1;
      continue;
    }
    if (ch === "]" && inClass) {
      inClass = false;
      j += 1;
      continue;
    }
    if (ch === "/" && !inClass) {
      j += 1;
      // Optional flags
      while (j < n && /[a-zA-Z]/.test(text[j]!)) j += 1;
      return j;
    }
    // Unterminated regex on newline — fail closed (do not invent tokens).
    if (ch === "\n") return -1;
    j += 1;
  }
  return -1;
}

/**
 * Tokenize source, omitting comments entirely, collapsing string/template
 * contents to a single placeholder token, and skipping regex literals so
 * structural comparison never sees comment/string/regex text.
 */
export function tokenizeJsIgnoringCommentsAndStrings(source: string): Tok[] {
  const text = source.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const tokens: Tok[] = [];
  let i = 0;
  const n = text.length;

  const push = (kind: TokKind, value: string): void => {
    tokens.push({ kind, value });
  };

  const lastTok = (): Tok | undefined =>
    tokens.length > 0 ? tokens[tokens.length - 1] : undefined;

  while (i < n) {
    const ch = text[i]!;

    // Whitespace
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\f" || ch === "\v") {
      i += 1;
      continue;
    }

    // Line comment
    if (ch === "/" && text[i + 1] === "/") {
      i += 2;
      while (i < n && text[i] !== "\n") i += 1;
      continue;
    }

    // Block comment
    if (ch === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < n && !(text[i] === "*" && text[i + 1] === "/")) i += 1;
      if (i < n) i += 2;
      continue;
    }

    // Regex literal (before treating `/` as division / punct)
    if (ch === "/" && slashStartsRegex(lastTok())) {
      const end = skipRegexLiteral(text, i);
      if (end >= 0) {
        // Omit regex body entirely (like comments); no structural tokens.
        i = end;
        continue;
      }
      // Ambiguous / unclosed: fail closed — skip the `/` without emitting a
      // punct that could glue spoof text into a false match stream.
      i += 1;
      continue;
    }

    // String literals '...' or "..."
    if (ch === "'" || ch === '"') {
      const quote = ch;
      i += 1;
      while (i < n) {
        if (text[i] === "\\") {
          i += 2;
          continue;
        }
        if (text[i] === quote) {
          i += 1;
          break;
        }
        i += 1;
      }
      push("string", '""');
      continue;
    }

    // Template literals `...` (including ${} nests at a shallow level)
    if (ch === "`") {
      i += 1;
      let depth = 0;
      while (i < n) {
        if (text[i] === "\\") {
          i += 2;
          continue;
        }
        if (text[i] === "`" && depth === 0) {
          i += 1;
          break;
        }
        if (text[i] === "$" && text[i + 1] === "{") {
          depth += 1;
          i += 2;
          continue;
        }
        if (text[i] === "}" && depth > 0) {
          depth -= 1;
          i += 1;
          continue;
        }
        i += 1;
      }
      push("template", "``");
      continue;
    }

    // Numbers (simple)
    if (/[0-9]/.test(ch) || (ch === "." && /[0-9]/.test(text[i + 1] ?? ""))) {
      let j = i + 1;
      while (j < n && /[0-9.A-Za-zxXn_]/.test(text[j]!)) j += 1;
      push("number", text.slice(i, j));
      i = j;
      continue;
    }

    // Identifiers / keywords
    if (isIdentStart(ch)) {
      let j = i + 1;
      while (j < n && isIdentCont(text[j]!)) j += 1;
      push("ident", text.slice(i, j));
      i = j;
      continue;
    }

    // Multi-char operators of interest
    if (ch === "?" && text[i + 1] === "?") {
      push("op", "??");
      i += 2;
      continue;
    }
    if (ch === "=" && text[i + 1] === "=") {
      // == or === — treat as op, not assignment
      if (text[i + 2] === "=") {
        push("op", "===");
        i += 3;
      } else {
        push("op", "==");
        i += 2;
      }
      continue;
    }
    if (ch === "!" && text[i + 1] === "=") {
      if (text[i + 2] === "=") {
        push("op", "!==");
        i += 3;
      } else {
        push("op", "!=");
        i += 2;
      }
      continue;
    }

    // Single punctuation / operators (including `/` as division when not regex)
    if ("=.;(){}[],:+-*/%<>!&|^~?".includes(ch)) {
      push("punct", ch);
      i += 1;
      continue;
    }

    // Unknown character — skip (fail closed for matching later)
    i += 1;
  }

  push("eof", "");
  return tokens;
}

function tokEq(t: Tok | undefined, kind: TokKind, value?: string): boolean {
  if (!t || t.kind !== kind) return false;
  if (value !== undefined && t.value !== value) return false;
  return true;
}

/**
 * Match one protected-process shim block starting at token index `start`.
 *
 * Exact three-statement shape (real protected-process shim):
 *   globalThis.process = <shimExpr> ;
 *   globalThis.global = globalThis.global ?? globalThis ;
 *   globalThis.global.process = <sameShimExpr> ;
 *
 * <shimExpr> is a simple identifier, and both assignments must use the same
 * identifier. Returns the index after the block, or -1 if no match.
 */
function matchProtectedBlock(tokens: Tok[], start: number): number {
  let i = start;

  // 1) globalThis . process = <id> ;
  if (!tokEq(tokens[i], "ident", "globalThis")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", ".")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident", "process")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", "=")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident") || !tokens[i]) return -1;
  const shim = tokens[i]!.value;
  i += 1;
  if (!tokEq(tokens[i], "punct", ";")) return -1;
  i += 1;

  // 2) globalThis . global = globalThis . global ?? globalThis ;
  if (!tokEq(tokens[i], "ident", "globalThis")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", ".")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident", "global")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", "=")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident", "globalThis")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", ".")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident", "global")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "op", "??")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident", "globalThis")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", ";")) return -1;
  i += 1;

  // 3) globalThis . global . process = <same id> ;
  if (!tokEq(tokens[i], "ident", "globalThis")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", ".")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident", "global")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", ".")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident", "process")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", "=")) return -1;
  i += 1;
  if (!tokEq(tokens[i], "ident", shim)) return -1;
  i += 1;
  if (!tokEq(tokens[i], "punct", ";")) return -1;
  i += 1;

  return i;
}

/**
 * Independently detect the protected-process shim structural signature from
 * bytes. A hash or AST id merely declared in incident JSON never proves itself.
 *
 * Requires exactly one target block per file. Zero or more than one is not a
 * match. Comments, strings/templates, and regex literals cannot contribute matches.
 */
export function measureProtectedProcessAst(source: string): {
  matched: boolean;
  signatureId: string | null;
  assignmentCount: number;
  blockCount: number;
} {
  const tokens = tokenizeJsIgnoringCommentsAndStrings(source);
  const blockStarts: number[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const end = matchProtectedBlock(tokens, i);
    if (end >= 0) {
      blockStarts.push(i);
      // Advance past matched block to avoid overlapping recount of the same block.
      // Still allow non-overlapping second blocks to be found later.
      i = end - 1;
    }
  }
  const blockCount = blockStarts.length;
  // Exactly one target block required.
  const matched = blockCount === 1;
  return {
    matched,
    signatureId: matched ? PROTECTED_AST_SIGNATURE_ID : null,
    // Three statements in the matched block (for evidence detail).
    assignmentCount: matched ? 3 : 0,
    blockCount,
  };
}
