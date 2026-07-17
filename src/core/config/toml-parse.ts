/**
 * Bounded deterministic TOML subset parser for Codex control files.
 * Fail-closed on unknown structure; does not execute or import anything.
 */
import {
  MAX_CONFIG_DOCUMENT_KEYS,
  MAX_CONFIG_TABLE_DEPTH,
  MAX_CONFIG_VALUE_CHARS,
} from "./limits.js";
import type { TomlTable, TomlValue } from "./schema.js";

export class TomlParseError extends Error {
  readonly code = "TOML_SYNTAX";
  constructor(message = "Invalid TOML syntax.") {
    super(message);
    this.name = "TomlParseError";
  }
}

export interface ParseResult {
  ok: true;
  root: TomlTable;
  keyCount: number;
}

export interface ParseFail {
  ok: false;
  error: "syntax" | "oversized" | "depth" | "unknown_structure";
  message: string;
}

/**
 * Parse a restricted TOML document into a table.
 * Supports: comments, bare/quoted keys, strings, booleans, integers, floats,
 * [tables], dotted keys, and simple inline tables `{ k = v }`.
 */
export function parseTomlDocument(text: string): ParseResult | ParseFail {
  if (typeof text !== "string") {
    return { ok: false, error: "syntax", message: "Invalid TOML input." };
  }
  if (text.includes("\0")) {
    return { ok: false, error: "syntax", message: "NUL byte in TOML." };
  }
  // Refuse multi-line basic strings / literal strings / arrays-of-tables for MVP.
  if (text.includes('"""') || text.includes("'''")) {
    return {
      ok: false,
      error: "unknown_structure",
      message: "Multi-line TOML strings are not supported.",
    };
  }
  if (text.includes("[[")) {
    return {
      ok: false,
      error: "unknown_structure",
      message: "Array-of-tables is not supported.",
    };
  }

  const root: TomlTable = new Map();
  let current: TomlTable = root;
  let currentPath: string[] = [];
  let keyCount = 0;
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");

  for (let li = 0; li < lines.length; li++) {
    let line = lines[li]!;
    const hash = indexOfUnquoted(line, "#");
    if (hash >= 0) line = line.slice(0, hash);
    line = line.trim();
    if (line.length === 0) continue;

    if (line.startsWith("[")) {
      if (!line.endsWith("]")) {
        return { ok: false, error: "syntax", message: "Malformed table header." };
      }
      const inner = line.slice(1, -1).trim();
      if (inner.length === 0 || inner.includes("[") || inner.includes("]")) {
        return { ok: false, error: "syntax", message: "Malformed table header." };
      }
      const parts = splitDottedKey(inner);
      if (!parts) {
        return { ok: false, error: "syntax", message: "Invalid table path." };
      }
      if (parts.length > MAX_CONFIG_TABLE_DEPTH) {
        return { ok: false, error: "depth", message: "Table depth exceeded." };
      }
      const ensured = ensureTablePath(root, parts);
      if (!ensured.ok) return ensured;
      current = ensured.table;
      currentPath = parts;
      continue;
    }

    const eq = indexOfUnquoted(line, "=");
    if (eq < 0) {
      return { ok: false, error: "syntax", message: "Expected key = value." };
    }
    const keyRaw = line.slice(0, eq).trim();
    const valRaw = line.slice(eq + 1).trim();
    if (!keyRaw || !valRaw) {
      return { ok: false, error: "syntax", message: "Empty key or value." };
    }
    const keyParts = splitDottedKey(keyRaw);
    if (!keyParts || keyParts.length === 0) {
      return { ok: false, error: "syntax", message: "Invalid key." };
    }
    const parsedVal = parseValue(valRaw);
    if (!parsedVal.ok) return parsedVal;

    keyCount += 1;
    if (keyCount > MAX_CONFIG_DOCUMENT_KEYS) {
      return { ok: false, error: "oversized", message: "Too many config keys." };
    }

    // Dotted assignment relative to current table.
    if (keyParts.length === 1) {
      if (current.has(keyParts[0]!)) {
        return {
          ok: false,
          error: "syntax",
          message: "Duplicate key.",
        };
      }
      current.set(keyParts[0]!, parsedVal.value);
    } else {
      const parentParts = keyParts.slice(0, -1);
      const leaf = keyParts[keyParts.length - 1]!;
      const fullDepth = currentPath.length + parentParts.length;
      if (fullDepth > MAX_CONFIG_TABLE_DEPTH) {
        return { ok: false, error: "depth", message: "Table depth exceeded." };
      }
      const ensured = ensureTablePath(current, parentParts);
      if (!ensured.ok) return ensured;
      if (ensured.table.has(leaf)) {
        return { ok: false, error: "syntax", message: "Duplicate key." };
      }
      ensured.table.set(leaf, parsedVal.value);
    }
  }

  return { ok: true, root, keyCount };
}

function splitDottedKey(raw: string): string[] | null {
  const parts: string[] = [];
  let i = 0;
  const s = raw.trim();
  while (i < s.length) {
    while (i < s.length && s[i] === " ") i += 1;
    if (i >= s.length) break;
    if (s[i] === '"' || s[i] === "'") {
      const q = s[i]!;
      i += 1;
      let buf = "";
      while (i < s.length && s[i] !== q) {
        if (s[i] === "\\" && q === '"') {
          i += 1;
          if (i >= s.length) return null;
          buf += s[i];
          i += 1;
          continue;
        }
        buf += s[i];
        i += 1;
      }
      if (i >= s.length || s[i] !== q) return null;
      i += 1;
      if (buf.length === 0 || buf.length > 128) return null;
      parts.push(buf);
    } else {
      let buf = "";
      while (i < s.length && s[i] !== "." && s[i] !== " ") {
        const ch = s[i]!;
        if (!/[A-Za-z0-9_-]/.test(ch)) return null;
        buf += ch;
        i += 1;
      }
      if (buf.length === 0 || buf.length > 128) return null;
      parts.push(buf);
    }
    while (i < s.length && s[i] === " ") i += 1;
    if (i < s.length) {
      if (s[i] !== ".") return null;
      i += 1;
    }
  }
  return parts.length > 0 ? parts : null;
}

function ensureTablePath(
  root: TomlTable,
  parts: string[],
): { ok: true; table: TomlTable } | ParseFail {
  let cursor: TomlTable = root;
  for (const p of parts) {
    const existing = cursor.get(p);
    if (!existing) {
      const child: TomlTable = new Map();
      cursor.set(p, { type: "table", value: child });
      cursor = child;
      continue;
    }
    if (existing.type !== "table" || !(existing.value instanceof Map)) {
      return {
        ok: false,
        error: "syntax",
        message: "Key path conflicts with non-table value.",
      };
    }
    cursor = existing.value as TomlTable;
  }
  return { ok: true, table: cursor };
}

function parseValue(
  raw: string,
): { ok: true; value: TomlValue } | ParseFail {
  const s = raw.trim();
  if (s === "true") return { ok: true, value: { type: "boolean", value: true } };
  if (s === "false") return { ok: true, value: { type: "boolean", value: false } };

  if (s.startsWith("{")) {
    return parseInlineTable(s);
  }
  if (s.startsWith("[")) {
    return {
      ok: false,
      error: "unknown_structure",
      message: "TOML arrays are not supported in control config.",
    };
  }

  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    const inner = unquoteString(s);
    if (inner === null) {
      return { ok: false, error: "syntax", message: "Invalid string." };
    }
    if (inner.length > MAX_CONFIG_VALUE_CHARS) {
      return { ok: false, error: "oversized", message: "String value too long." };
    }
    return { ok: true, value: { type: "string", value: inner } };
  }

  // Integer / float
  if (/^[+-]?\d+$/.test(s)) {
    const n = Number(s);
    if (!Number.isSafeInteger(n)) {
      return { ok: false, error: "syntax", message: "Integer out of range." };
    }
    return { ok: true, value: { type: "integer", value: n } };
  }
  if (/^[+-]?\d+\.\d+$/.test(s)) {
    const n = Number(s);
    if (!Number.isFinite(n)) {
      return { ok: false, error: "syntax", message: "Invalid float." };
    }
    return { ok: true, value: { type: "float", value: n } };
  }

  // Bare strings refused — require quotes for strings.
  return { ok: false, error: "syntax", message: "Unrecognized value." };
}

function parseInlineTable(
  s: string,
): { ok: true; value: TomlValue } | ParseFail {
  if (!s.startsWith("{") || !s.endsWith("}")) {
    return { ok: false, error: "syntax", message: "Invalid inline table." };
  }
  const inner = s.slice(1, -1).trim();
  const table: TomlTable = new Map();
  if (inner.length === 0) {
    return { ok: true, value: { type: "table", value: table } };
  }
  // Split on commas not inside quotes.
  const parts: string[] = [];
  let buf = "";
  let inStr: string | null = null;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]!;
    if (inStr) {
      buf += ch;
      if (ch === "\\" && inStr === '"') {
        i += 1;
        if (i < inner.length) buf += inner[i];
        continue;
      }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = ch;
      buf += ch;
      continue;
    }
    if (ch === ",") {
      parts.push(buf.trim());
      buf = "";
      continue;
    }
    buf += ch;
  }
  if (inStr) {
    return { ok: false, error: "syntax", message: "Unterminated string in inline table." };
  }
  if (buf.trim()) parts.push(buf.trim());

  for (const part of parts) {
    const eq = indexOfUnquoted(part, "=");
    if (eq < 0) {
      return { ok: false, error: "syntax", message: "Invalid inline table entry." };
    }
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    const keyParts = splitDottedKey(k);
    if (!keyParts || keyParts.length !== 1) {
      return {
        ok: false,
        error: "unknown_structure",
        message: "Nested dotted keys in inline tables are not supported.",
      };
    }
    if (table.has(keyParts[0]!)) {
      return { ok: false, error: "syntax", message: "Duplicate inline table key." };
    }
    const pv = parseValue(v);
    if (!pv.ok) return pv;
    // Refuse nested inline tables / arrays for depth control.
    if (pv.value.type === "table" || pv.value.type === "array") {
      return {
        ok: false,
        error: "unknown_structure",
        message: "Nested inline tables are not supported.",
      };
    }
    table.set(keyParts[0]!, pv.value);
  }
  return { ok: true, value: { type: "table", value: table } };
}

function unquoteString(s: string): string | null {
  if (s.length < 2) return null;
  const q = s[0];
  if ((q !== '"' && q !== "'") || s[s.length - 1] !== q) return null;
  if (q === "'") {
    // Literal string — no escapes except no nested quote.
    return s.slice(1, -1);
  }
  let out = "";
  for (let i = 1; i < s.length - 1; i++) {
    const ch = s[i]!;
    if (ch === "\\") {
      i += 1;
      if (i >= s.length - 1) return null;
      const n = s[i]!;
      if (n === "n") out += "\n";
      else if (n === "t") out += "\t";
      else if (n === "r") out += "\r";
      else if (n === '"' || n === "\\") out += n;
      else return null;
      continue;
    }
    if (ch === '"') return null;
    out += ch;
  }
  return out;
}

function indexOfUnquoted(s: string, ch: string): number {
  let inStr: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (inStr) {
      if (c === "\\" && inStr === '"') {
        i += 1;
        continue;
      }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = c;
      continue;
    }
    if (c === ch) return i;
  }
  return -1;
}

/** Flatten table to dotted key → value for validation. */
export function flattenTable(
  table: TomlTable,
  prefix = "",
  out: Map<string, TomlValue> = new Map(),
  depth = 0,
): Map<string, TomlValue> | null {
  if (depth > MAX_CONFIG_TABLE_DEPTH) return null;
  for (const [k, v] of table) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v.type === "table" && v.value instanceof Map) {
      out.set(path, v);
      const nested = flattenTable(v.value as TomlTable, path, out, depth + 1);
      if (!nested) return null;
    } else {
      out.set(path, v);
    }
  }
  return out;
}

export function getDotted(
  table: TomlTable,
  dotted: string,
): TomlValue | undefined {
  const parts = dotted.split(".");
  let cursor: TomlTable | null = table;
  let last: TomlValue | undefined;
  for (let i = 0; i < parts.length; i++) {
    if (!cursor) return undefined;
    last = cursor.get(parts[i]!);
    if (!last) return undefined;
    if (i === parts.length - 1) return last;
    if (last.type === "table" && last.value instanceof Map) {
      cursor = last.value as TomlTable;
    } else {
      return undefined;
    }
  }
  return last;
}
