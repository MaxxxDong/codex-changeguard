/**
 * ChangeGuard-owned confirmation ledger: durable one-shot nonce registry.
 * Atomic replace, symlink-safe, bounded capacity + TTL. No daemon, network,
 * or writes into the diagnosis target. State lives under plugin data / injectible root.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  CONFIRMATION_LEDGER_CAPACITY,
  CONFIRMATION_LEDGER_DIR_MODE,
  CONFIRMATION_LEDGER_FILE_MODE,
  CONFIRMATION_LEDGER_KEY_BYTES,
  CONFIRMATION_LEDGER_KEY_FILE,
  CONFIRMATION_LEDGER_MAX_BYTES,
  CONFIRMATION_LEDGER_STATE_FILE,
  CONFIRMATION_TTL_MS,
} from "./limits.js";

export type LedgerEntryStatus =
  | "registered"
  | "consumed"
  | "terminal_uncertain";

export interface LedgerEntry {
  nonce: string;
  status: LedgerEntryStatus;
  confirmation_id: string;
  binding_sha256: string;
  expires_at: string;
  registered_at_ms: number;
  updated_at_ms: number;
  action: string;
  canonical_target: string;
  idempotency_key: string;
}

interface LedgerDocument {
  schema_version: 1;
  entries: LedgerEntry[];
  updated_at_ms: number;
}

export type LedgerErrorCode =
  | "LEDGER_IO"
  | "LEDGER_SCHEMA"
  | "LEDGER_SYMLINK"
  | "LEDGER_CAPACITY"
  | "LEDGER_NOT_REGISTERED"
  | "LEDGER_TERMINAL"
  | "LEDGER_SIZE"
  | "LEDGER_ROOT";

export class LedgerError extends Error {
  readonly code: LedgerErrorCode;
  constructor(code: LedgerErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "LedgerError";
  }
}

const NONCE_HEX = /^[a-f0-9]{32}$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;

/** Resolve ChangeGuard-owned confirmation state root (never target project). */
export function resolveConfirmationStateRoot(override?: string | null): string {
  if (typeof override === "string" && override.length > 0) {
    return path.resolve(override);
  }
  const forced = process.env.CHANGEGUARD_CONFIRMATION_STATE_DIR;
  if (typeof forced === "string" && forced.length > 0) {
    return path.resolve(forced);
  }
  const plugin = process.env.PLUGIN_DATA || process.env.CLAUDE_PLUGIN_DATA;
  if (typeof plugin === "string" && plugin.length > 0) {
    return path.join(path.resolve(plugin), "upstream-actions");
  }
  const xdg = process.env.XDG_STATE_HOME;
  if (typeof xdg === "string" && xdg.length > 0) {
    return path.join(
      path.resolve(xdg),
      "codex-changeguard",
      "upstream-actions",
    );
  }
  const home = process.env.HOME || process.env.USERPROFILE;
  if (typeof home !== "string" || home.length === 0) {
    throw new LedgerError(
      "LEDGER_ROOT",
      "No confirmation state root (set CHANGEGUARD_CONFIRMATION_STATE_DIR or PLUGIN_DATA).",
    );
  }
  return path.join(
    path.resolve(home),
    ".local",
    "state",
    "codex-changeguard",
    "upstream-actions",
  );
}

function openReadFlags(): number {
  const base = fs.constants.O_RDONLY;
  const nofollow =
    "O_NOFOLLOW" in fs.constants
      ? (fs.constants as NodeJS.Dict<number>).O_NOFOLLOW
      : undefined;
  if (typeof nofollow === "number") return base | nofollow;
  return base;
}

function assertDirSafe(abs: string): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(abs);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === "ENOENT") {
      throw new LedgerError("LEDGER_IO", "Ledger path missing.");
    }
    throw new LedgerError("LEDGER_IO", "Ledger path refused.");
  }
  if (st.isSymbolicLink()) {
    throw new LedgerError("LEDGER_SYMLINK", "Symlink ledger path refused.");
  }
  if (!st.isDirectory()) {
    throw new LedgerError("LEDGER_IO", "Ledger root is not a directory.");
  }
}

function assertFileNotSymlink(abs: string): fs.Stats | null {
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink()) {
      throw new LedgerError("LEDGER_SYMLINK", "Symlink ledger file refused.");
    }
    return st;
  } catch (e) {
    if (e instanceof LedgerError) throw e;
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === "ENOENT") return null;
    throw new LedgerError("LEDGER_IO", "Ledger file path refused.");
  }
}

function ensureRoot(root: string): void {
  if (fs.existsSync(root)) {
    assertDirSafe(root);
    return;
  }
  fs.mkdirSync(root, { recursive: true, mode: CONFIRMATION_LEDGER_DIR_MODE });
  assertDirSafe(root);
}

function readBoundedFile(abs: string, maxBytes: number): Buffer {
  const pre = assertFileNotSymlink(abs);
  if (!pre) {
    throw new LedgerError("LEDGER_IO", "Ledger file missing.");
  }
  if (!pre.isFile()) {
    throw new LedgerError("LEDGER_IO", "Ledger path is not a file.");
  }
  if (pre.size > maxBytes) {
    throw new LedgerError("LEDGER_SIZE", "Ledger file exceeds size limit.");
  }
  let fd: number;
  try {
    fd = fs.openSync(abs, openReadFlags());
  } catch {
    throw new LedgerError("LEDGER_IO", "Ledger read open failed.");
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) {
      throw new LedgerError("LEDGER_SIZE", "Ledger file refused.");
    }
    if (st.dev !== pre.dev || st.ino !== pre.ino || st.size !== pre.size) {
      throw new LedgerError("LEDGER_IO", "Ledger TOCTOU refused.");
    }
    const buf = Buffer.alloc(st.size);
    let offset = 0;
    while (offset < st.size) {
      const n = fs.readSync(fd, buf, offset, st.size - offset, offset);
      if (n === 0) break;
      offset += n;
    }
    return buf.subarray(0, offset);
  } finally {
    fs.closeSync(fd);
  }
}

function atomicWriteFile(root: string, fileName: string, bytes: Buffer): void {
  ensureRoot(root);
  if (bytes.length > CONFIRMATION_LEDGER_MAX_BYTES) {
    throw new LedgerError("LEDGER_SIZE", "Ledger payload exceeds size limit.");
  }
  const dest = path.join(root, fileName);
  const existing = assertFileNotSymlink(dest);
  if (existing && !existing.isFile()) {
    throw new LedgerError("LEDGER_IO", "Ledger dest refused.");
  }
  const tmp = path.join(
    root,
    `.${fileName}.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString("hex")}`,
  );
  try {
    fs.writeFileSync(tmp, bytes, {
      encoding: undefined,
      flag: "wx",
      mode: CONFIRMATION_LEDGER_FILE_MODE,
    });
    fs.renameSync(tmp, dest);
  } catch (e) {
    try {
      if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    } catch {
      /* best-effort */
    }
    if (e instanceof LedgerError) throw e;
    throw new LedgerError("LEDGER_IO", "Atomic ledger write failed.");
  }
  const finalStat = assertFileNotSymlink(dest);
  if (!finalStat || !finalStat.isFile()) {
    throw new LedgerError("LEDGER_IO", "Ledger post-write refused.");
  }
}

function emptyDoc(nowMs: number): LedgerDocument {
  return { schema_version: 1, entries: [], updated_at_ms: nowMs };
}

function parseDoc(raw: unknown, nowMs: number): LedgerDocument {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new LedgerError("LEDGER_SCHEMA", "Ledger JSON refused.");
  }
  const o = raw as Record<string, unknown>;
  if (o.schema_version !== 1) {
    throw new LedgerError("LEDGER_SCHEMA", "Ledger schema_version refused.");
  }
  if (!Array.isArray(o.entries)) {
    throw new LedgerError("LEDGER_SCHEMA", "Ledger entries refused.");
  }
  if (o.entries.length > CONFIRMATION_LEDGER_CAPACITY * 2) {
    throw new LedgerError("LEDGER_SIZE", "Ledger entry count refused.");
  }
  const entries: LedgerEntry[] = [];
  for (const ent of o.entries) {
    if (ent === null || typeof ent !== "object" || Array.isArray(ent)) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger entry refused.");
    }
    const e = ent as Record<string, unknown>;
    if (typeof e.nonce !== "string" || !NONCE_HEX.test(e.nonce)) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger nonce refused.");
    }
    if (
      e.status !== "registered" &&
      e.status !== "consumed" &&
      e.status !== "terminal_uncertain"
    ) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger status refused.");
    }
    if (typeof e.confirmation_id !== "string" || e.confirmation_id.length === 0) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger confirmation_id refused.");
    }
    if (typeof e.binding_sha256 !== "string" || !SHA256_HEX.test(e.binding_sha256)) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger binding_sha256 refused.");
    }
    if (typeof e.expires_at !== "string") {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger expires_at refused.");
    }
    if (typeof e.registered_at_ms !== "number" || !Number.isFinite(e.registered_at_ms)) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger registered_at_ms refused.");
    }
    if (typeof e.updated_at_ms !== "number" || !Number.isFinite(e.updated_at_ms)) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger updated_at_ms refused.");
    }
    if (typeof e.action !== "string" || e.action.length === 0) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger action refused.");
    }
    if (typeof e.canonical_target !== "string" || e.canonical_target.length === 0) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger canonical_target refused.");
    }
    if (typeof e.idempotency_key !== "string" || e.idempotency_key.length === 0) {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger idempotency_key refused.");
    }
    entries.push({
      nonce: e.nonce,
      status: e.status,
      confirmation_id: e.confirmation_id,
      binding_sha256: e.binding_sha256,
      expires_at: e.expires_at,
      registered_at_ms: e.registered_at_ms,
      updated_at_ms: e.updated_at_ms,
      action: e.action,
      canonical_target: e.canonical_target,
      idempotency_key: e.idempotency_key,
    });
  }
  const updated =
    typeof o.updated_at_ms === "number" && Number.isFinite(o.updated_at_ms)
      ? o.updated_at_ms
      : nowMs;
  return { schema_version: 1, entries, updated_at_ms: updated };
}

function isExpired(entry: LedgerEntry, nowMs: number): boolean {
  const exp = Date.parse(entry.expires_at);
  if (!Number.isFinite(exp)) return true;
  return exp <= nowMs;
}

function prune(doc: LedgerDocument, nowMs: number): LedgerDocument {
  const live = doc.entries.filter((e) => !isExpired(e, nowMs));
  // Prefer keeping registered; drop oldest terminal/consumed when over capacity.
  if (live.length <= CONFIRMATION_LEDGER_CAPACITY) {
    return { schema_version: 1, entries: live, updated_at_ms: nowMs };
  }
  const registered = live.filter((e) => e.status === "registered");
  const terminal = live
    .filter((e) => e.status !== "registered")
    .sort((a, b) => a.updated_at_ms - b.updated_at_ms);
  const room = Math.max(0, CONFIRMATION_LEDGER_CAPACITY - registered.length);
  const keptTerminal = terminal.slice(Math.max(0, terminal.length - room));
  const merged = [...registered, ...keptTerminal].sort(
    (a, b) => a.registered_at_ms - b.registered_at_ms,
  );
  return {
    schema_version: 1,
    entries: merged.slice(0, CONFIRMATION_LEDGER_CAPACITY),
    updated_at_ms: nowMs,
  };
}

export class ConfirmationLedger {
  readonly root: string;

  constructor(root: string) {
    this.root = path.resolve(root);
  }

  /** Load or create install-local HMAC key (never logged/exported). */
  loadOrCreateHmacKey(): Buffer {
    ensureRoot(this.root);
    const keyPath = path.join(this.root, CONFIRMATION_LEDGER_KEY_FILE);
    const existing = assertFileNotSymlink(keyPath);
    if (existing) {
      if (!existing.isFile()) {
        throw new LedgerError("LEDGER_IO", "HMAC key path refused.");
      }
      if (existing.size > 128) {
        throw new LedgerError("LEDGER_SIZE", "HMAC key file too large.");
      }
      const buf = readBoundedFile(keyPath, 128);
      // Stored as hex of CONFIRMATION_LEDGER_KEY_BYTES.
      const hex = buf.toString("utf8").trim();
      if (!/^[a-f0-9]+$/i.test(hex) || hex.length !== CONFIRMATION_LEDGER_KEY_BYTES * 2) {
        throw new LedgerError("LEDGER_SCHEMA", "HMAC key material refused.");
      }
      return Buffer.from(hex, "hex");
    }
    const key = crypto.randomBytes(CONFIRMATION_LEDGER_KEY_BYTES);
    atomicWriteFile(
      this.root,
      CONFIRMATION_LEDGER_KEY_FILE,
      Buffer.from(key.toString("hex"), "utf8"),
    );
    return key;
  }

  private loadDoc(nowMs: number): LedgerDocument {
    ensureRoot(this.root);
    const file = path.join(this.root, CONFIRMATION_LEDGER_STATE_FILE);
    const st = assertFileNotSymlink(file);
    if (!st) return emptyDoc(nowMs);
    const buf = readBoundedFile(file, CONFIRMATION_LEDGER_MAX_BYTES);
    let raw: unknown;
    try {
      raw = JSON.parse(buf.toString("utf8"));
    } catch {
      throw new LedgerError("LEDGER_SCHEMA", "Ledger JSON malformed.");
    }
    return prune(parseDoc(raw, nowMs), nowMs);
  }

  private saveDoc(doc: LedgerDocument, nowMs: number): void {
    const pruned = prune(doc, nowMs);
    if (pruned.entries.length > CONFIRMATION_LEDGER_CAPACITY) {
      throw new LedgerError("LEDGER_CAPACITY", "Ledger capacity exceeded.");
    }
    const payload = Buffer.from(
      `${JSON.stringify({ ...pruned, updated_at_ms: nowMs }, null, 2)}\n`,
      "utf8",
    );
    atomicWriteFile(this.root, CONFIRMATION_LEDGER_STATE_FILE, payload);
  }

  getEntry(nonce: string, nowMs: number = Date.now()): LedgerEntry | null {
    if (!NONCE_HEX.test(nonce)) return null;
    const doc = this.loadDoc(nowMs);
    const hit = doc.entries.find((e) => e.nonce === nonce) ?? null;
    if (!hit) return null;
    if (isExpired(hit, nowMs)) return null;
    return hit;
  }

  /**
   * Register a freshly minted confirmation. Fails if nonce already present
   * (non-expired) or capacity cannot accept another registered entry.
   */
  register(
    entry: Omit<LedgerEntry, "status" | "updated_at_ms"> & {
      status?: "registered";
    },
    nowMs: number = Date.now(),
  ): void {
    if (!NONCE_HEX.test(entry.nonce)) {
      throw new LedgerError("LEDGER_SCHEMA", "Register nonce refused.");
    }
    const doc = this.loadDoc(nowMs);
    if (doc.entries.some((e) => e.nonce === entry.nonce && !isExpired(e, nowMs))) {
      throw new LedgerError("LEDGER_SCHEMA", "Nonce already registered.");
    }
    const registeredCount = doc.entries.filter(
      (e) => e.status === "registered" && !isExpired(e, nowMs),
    ).length;
    if (registeredCount >= CONFIRMATION_LEDGER_CAPACITY) {
      throw new LedgerError(
        "LEDGER_CAPACITY",
        "Confirmation ledger at capacity for registered nonces.",
      );
    }
    // Drop any expired slot for this nonce then append.
    const entries = doc.entries.filter((e) => e.nonce !== entry.nonce);
    entries.push({
      nonce: entry.nonce,
      status: "registered",
      confirmation_id: entry.confirmation_id,
      binding_sha256: entry.binding_sha256,
      expires_at: entry.expires_at,
      registered_at_ms: entry.registered_at_ms,
      updated_at_ms: nowMs,
      action: entry.action,
      canonical_target: entry.canonical_target,
      idempotency_key: entry.idempotency_key,
    });
    this.saveDoc({ schema_version: 1, entries, updated_at_ms: nowMs }, nowMs);
  }

  private transition(
    nonce: string,
    status: "consumed" | "terminal_uncertain",
    nowMs: number,
  ): void {
    if (!NONCE_HEX.test(nonce)) {
      throw new LedgerError("LEDGER_SCHEMA", "Nonce refused.");
    }
    const doc = this.loadDoc(nowMs);
    const idx = doc.entries.findIndex((e) => e.nonce === nonce);
    if (idx < 0) {
      throw new LedgerError(
        "LEDGER_NOT_REGISTERED",
        "Nonce not registered in confirmation ledger.",
      );
    }
    const cur = doc.entries[idx]!;
    if (isExpired(cur, nowMs)) {
      throw new LedgerError("LEDGER_NOT_REGISTERED", "Nonce expired.");
    }
    if (cur.status === "consumed" || cur.status === "terminal_uncertain") {
      // Idempotent mark — already terminal.
      return;
    }
    const next = [...doc.entries];
    next[idx] = { ...cur, status, updated_at_ms: nowMs };
    this.saveDoc(
      { schema_version: 1, entries: next, updated_at_ms: nowMs },
      nowMs,
    );
  }

  markConsumed(nonce: string, nowMs: number = Date.now()): void {
    this.transition(nonce, "consumed", nowMs);
  }

  markTerminalUncertain(nonce: string, nowMs: number = Date.now()): void {
    this.transition(nonce, "terminal_uncertain", nowMs);
  }

  /** True when nonce is consumed or terminal_uncertain (replay refuse). */
  isTerminal(nonce: string, nowMs: number = Date.now()): boolean {
    const e = this.getEntry(nonce, nowMs);
    if (!e) return false;
    return e.status === "consumed" || e.status === "terminal_uncertain";
  }

  /** Wipe ledger state files under this root (tests only). */
  resetForTests(): void {
    ensureRoot(this.root);
    for (const name of [
      CONFIRMATION_LEDGER_STATE_FILE,
      CONFIRMATION_LEDGER_KEY_FILE,
    ]) {
      const p = path.join(this.root, name);
      try {
        const st = fs.lstatSync(p);
        if (st.isSymbolicLink()) {
          throw new LedgerError("LEDGER_SYMLINK", "Symlink reset refused.");
        }
        if (st.isFile()) fs.unlinkSync(p);
      } catch (e) {
        if (e instanceof LedgerError) throw e;
        const err = e as NodeJS.ErrnoException;
        if (err && err.code !== "ENOENT") {
          throw new LedgerError("LEDGER_IO", "Ledger reset failed.");
        }
      }
    }
  }
}

export function openConfirmationLedger(
  root?: string | null,
): ConfirmationLedger {
  return new ConfirmationLedger(resolveConfirmationStateRoot(root));
}

/** Test helper: open + full wipe of entries/key under root. */
export function _resetConfirmationLedgerForTests(
  root?: string | null,
): ConfirmationLedger {
  const ledger = openConfirmationLedger(root);
  ledger.resetForTests();
  return ledger;
}

/** Default TTL helper for registration expiry ISO. */
export function defaultExpiresAtIso(
  nowMs: number,
  ttlMs: number = CONFIRMATION_TTL_MS,
): string {
  return new Date(nowMs + ttlMs).toISOString();
}
