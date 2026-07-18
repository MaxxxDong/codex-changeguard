/**
 * ChangeGuard-owned confirmation ledger: durable one-shot nonce registry.
 * Atomic replace, symlink-safe, bounded capacity + TTL. No daemon, network,
 * or writes into the diagnosis target. State lives under plugin data / injectible root.
 *
 * Cross-process exclusive claim: registered → in_flight CAS under an atomic
 * mkdir lock (no flock / child_process). Crash after claim leaves in_flight
 * (safe terminal: never re-execute).
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
  CONFIRMATION_LEDGER_LOCK_NAME,
  CONFIRMATION_LEDGER_LOCK_POLL_MS,
  CONFIRMATION_LEDGER_LOCK_STALE_MS,
  CONFIRMATION_LEDGER_LOCK_WAIT_MS,
  CONFIRMATION_LEDGER_MAX_BYTES,
  CONFIRMATION_LEDGER_OWNER_BYTES,
  CONFIRMATION_LEDGER_STATE_FILE,
  CONFIRMATION_TTL_MS,
} from "./limits.js";

export type LedgerEntryStatus =
  | "registered"
  | "in_flight"
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
  | "LEDGER_ROOT"
  | "LEDGER_LOCK";

export class LedgerError extends Error {
  readonly code: LedgerErrorCode;
  constructor(code: LedgerErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "LedgerError";
  }
}

/** Result of exclusive claim CAS (registered → in_flight). */
export type ClaimForExecuteResult =
  | { ok: true; entry: LedgerEntry }
  | {
      ok: false;
      reason:
        | "not_registered"
        | "expired"
        | "in_flight"
        | "consumed"
        | "terminal_uncertain"
        | "invalid_status"
        | "binding_mismatch"
        | "lock_busy"
        | "io";
    };

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
      e.status !== "in_flight" &&
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

/**
 * Drop only expired entries. Never demote in_flight → registered.
 * Capacity: prefer keep registered + in_flight; drop oldest consumed/terminal.
 */
function prune(doc: LedgerDocument, nowMs: number): LedgerDocument {
  const live = doc.entries.filter((e) => !isExpired(e, nowMs));
  if (live.length <= CONFIRMATION_LEDGER_CAPACITY) {
    return { schema_version: 1, entries: live, updated_at_ms: nowMs };
  }
  const priority = live.filter(
    (e) => e.status === "registered" || e.status === "in_flight",
  );
  const droppable = live
    .filter(
      (e) => e.status === "consumed" || e.status === "terminal_uncertain",
    )
    .sort((a, b) => a.updated_at_ms - b.updated_at_ms);

  if (priority.length >= CONFIRMATION_LEDGER_CAPACITY) {
    // Keep all unexpired in_flight; fill remainder with newest registered.
    const inFlight = priority.filter((e) => e.status === "in_flight");
    const registered = priority
      .filter((e) => e.status === "registered")
      .sort((a, b) => b.registered_at_ms - a.registered_at_ms);
    const room = Math.max(0, CONFIRMATION_LEDGER_CAPACITY - inFlight.length);
    const keptReg = registered.slice(0, room);
    const merged = [...inFlight, ...keptReg].sort(
      (a, b) => a.registered_at_ms - b.registered_at_ms,
    );
    return {
      schema_version: 1,
      entries: merged.slice(0, CONFIRMATION_LEDGER_CAPACITY),
      updated_at_ms: nowMs,
    };
  }

  const room = CONFIRMATION_LEDGER_CAPACITY - priority.length;
  const keptDroppable = droppable.slice(
    Math.max(0, droppable.length - room),
  );
  const merged = [...priority, ...keptDroppable].sort(
    (a, b) => a.registered_at_ms - b.registered_at_ms,
  );
  return {
    schema_version: 1,
    entries: merged.slice(0, CONFIRMATION_LEDGER_CAPACITY),
    updated_at_ms: nowMs,
  };
}

// --- exclusive lock (atomic mkdir; owner token; stale reclaim; fail-closed) ---

interface LockOwnerDoc {
  owner: string;
  pid: number;
  created_at_ms: number;
}

function lockDirPath(root: string): string {
  return path.join(root, CONFIRMATION_LEDGER_LOCK_NAME);
}

function lockOwnerPath(lockDir: string): string {
  return path.join(lockDir, "owner.json");
}

function sleepMs(ms: number): void {
  if (ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      /* spin fallback */
    }
  }
}

function readLockMeta(
  lockDir: string,
): { owner: string; created_at_ms: number; ageAnchorMs: number } | null {
  try {
    const st = fs.lstatSync(lockDir);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      return null;
    }
    const op = lockOwnerPath(lockDir);
    const ost = fs.lstatSync(op);
    if (ost.isSymbolicLink() || !ost.isFile()) {
      return null;
    }
    if (ost.size > 4096) return null;
    const raw = JSON.parse(fs.readFileSync(op, "utf8")) as Record<
      string,
      unknown
    >;
    if (typeof raw.owner !== "string" || !/^[a-f0-9]{16,64}$/i.test(raw.owner)) {
      return null;
    }
    if (typeof raw.created_at_ms !== "number" || !Number.isFinite(raw.created_at_ms)) {
      return null;
    }
    // Prefer owner created_at; also consider dir/file mtime for crash mid-write.
    const ageAnchorMs = Math.min(raw.created_at_ms, st.mtimeMs, ost.mtimeMs);
    return {
      owner: raw.owner.toLowerCase(),
      created_at_ms: raw.created_at_ms,
      ageAnchorMs,
    };
  } catch {
    return null;
  }
}

/**
 * Free a lock directory name without rmdir/rm (boundary forbids those).
 * Unlink owner file when present, then rename the dir to a unique tomb so the
 * canonical lock path is available for the next exclusive mkdir.
 */
function releaseLockDir(lockDir: string, root: string, kind: string): void {
  try {
    const op = lockOwnerPath(lockDir);
    try {
      const st = fs.lstatSync(op);
      if (!st.isSymbolicLink() && st.isFile()) fs.unlinkSync(op);
    } catch {
      /* best-effort */
    }
  } catch {
    /* best-effort */
  }
  const tomb = path.join(
    root,
    `.${CONFIRMATION_LEDGER_LOCK_NAME}.${kind}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString("hex")}`,
  );
  try {
    fs.renameSync(lockDir, tomb);
  } catch {
    /* concurrent reclaim / already gone */
  }
  // Best-effort: if tomb is empty of files, leave the empty dir (no rmdir API).
  try {
    const op2 = lockOwnerPath(tomb);
    const st2 = fs.lstatSync(op2);
    if (!st2.isSymbolicLink() && st2.isFile()) fs.unlinkSync(op2);
  } catch {
    /* already unlinked or absent */
  }
}

/**
 * Attempt to reclaim a stale lock via atomic rename of the lock dir.
 * Live locks (age < STALE) are never reclaimed.
 */
function tryReclaimStaleLock(root: string, nowMs: number): boolean {
  const lockDir = lockDirPath(root);
  let st: fs.Stats;
  try {
    st = fs.lstatSync(lockDir);
  } catch {
    return false;
  }
  if (st.isSymbolicLink()) {
    throw new LedgerError("LEDGER_SYMLINK", "Symlink ledger lock refused.");
  }
  if (!st.isDirectory()) {
    // Unexpected non-dir lock path — fail closed for reclaim.
    return false;
  }
  const meta = readLockMeta(lockDir);
  // Prefer created_at from owner doc; mtime is a secondary crash-safe anchor.
  const ageAnchor = meta?.ageAnchorMs ?? st.mtimeMs;
  if (nowMs - ageAnchor < CONFIRMATION_LEDGER_LOCK_STALE_MS) {
    return false; // live lock
  }
  const before = lockDirPath(root);
  releaseLockDir(lockDir, root, "stale");
  // Success when canonical lock path is no longer present (or is a different inode).
  try {
    fs.lstatSync(before);
    return false;
  } catch {
    return true;
  }
}

function tryAcquireLockOnce(
  root: string,
  owner: string,
  nowMs: number,
): boolean {
  ensureRoot(root);
  const lockDir = lockDirPath(root);
  try {
    fs.mkdirSync(lockDir, { mode: CONFIRMATION_LEDGER_DIR_MODE });
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === "EEXIST") return false;
    throw new LedgerError("LEDGER_IO", "Lock mkdir failed.");
  }
  try {
    const st = fs.lstatSync(lockDir);
    if (st.isSymbolicLink() || !st.isDirectory()) {
      throw new LedgerError("LEDGER_SYMLINK", "Lock path refused.");
    }
  } catch (e) {
    if (e instanceof LedgerError) throw e;
    throw new LedgerError("LEDGER_IO", "Lock path stat failed.");
  }
  const doc: LockOwnerDoc = {
    owner,
    pid: process.pid,
    created_at_ms: nowMs,
  };
  const bytes = Buffer.from(`${JSON.stringify(doc)}\n`, "utf8");
  try {
    fs.writeFileSync(lockOwnerPath(lockDir), bytes, {
      flag: "wx",
      mode: CONFIRMATION_LEDGER_FILE_MODE,
    });
  } catch {
    releaseLockDir(lockDir, root, "abort");
    return false;
  }
  return true;
}

function acquireExclusiveLock(root: string, nowMs: number): string {
  const owner = crypto
    .randomBytes(CONFIRMATION_LEDGER_OWNER_BYTES)
    .toString("hex");
  const deadline = nowMs + CONFIRMATION_LEDGER_LOCK_WAIT_MS;
  let attemptNow = nowMs;
  while (true) {
    if (tryAcquireLockOnce(root, owner, attemptNow)) {
      return owner;
    }
    // Live lock: try stale reclaim then re-acquire.
    try {
      if (tryReclaimStaleLock(root, attemptNow)) {
        if (tryAcquireLockOnce(root, owner, attemptNow)) {
          return owner;
        }
      }
    } catch (e) {
      if (e instanceof LedgerError) throw e;
    }
    if (attemptNow >= deadline) {
      throw new LedgerError(
        "LEDGER_LOCK",
        "Confirmation ledger lock busy (fail-closed).",
      );
    }
    const remaining = deadline - attemptNow;
    sleepMs(Math.min(CONFIRMATION_LEDGER_LOCK_POLL_MS, remaining));
    attemptNow = Date.now();
  }
}

function releaseExclusiveLock(root: string, owner: string): void {
  const lockDir = lockDirPath(root);
  const meta = readLockMeta(lockDir);
  if (!meta || meta.owner !== owner.toLowerCase()) {
    // Not ours — never remove another holder's lock.
    return;
  }
  releaseLockDir(lockDir, root, "release");
}

export class ConfirmationLedger {
  readonly root: string;

  constructor(root: string) {
    this.root = path.resolve(root);
  }

  /**
   * Run fn under exclusive cross-process ledger lock.
   * Fail-closed on lock timeout / symlink / IO.
   */
  withExclusiveLock<T>(fn: () => T, nowMs: number = Date.now()): T {
    const owner = acquireExclusiveLock(this.root, nowMs);
    try {
      return fn();
    } finally {
      releaseExclusiveLock(this.root, owner);
    }
  }

  /** Load or create install-local HMAC key (never logged/exported). */
  loadOrCreateHmacKey(): Buffer {
    return this.withExclusiveLock(() => {
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
        const hex = buf.toString("utf8").trim();
        if (
          !/^[a-f0-9]+$/i.test(hex) ||
          hex.length !== CONFIRMATION_LEDGER_KEY_BYTES * 2
        ) {
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
    });
  }

  private loadDocUnlocked(nowMs: number): LedgerDocument {
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

  private saveDocUnlocked(doc: LedgerDocument, nowMs: number): void {
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
    // Read path: atomic rename means readers see consistent documents.
    const doc = this.loadDocUnlocked(nowMs);
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
    this.withExclusiveLock(() => {
      const doc = this.loadDocUnlocked(nowMs);
      if (
        doc.entries.some((e) => e.nonce === entry.nonce && !isExpired(e, nowMs))
      ) {
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
      this.saveDocUnlocked(
        { schema_version: 1, entries, updated_at_ms: nowMs },
        nowMs,
      );
    }, nowMs);
  }

  /**
   * Exclusive CAS: registered → in_flight under ledger lock.
   * Only a successful claim may proceed to adapter.execute.
   * Concurrent losers get ok:false with reason in_flight / terminal.
   */
  claimForExecute(
    nonce: string,
    opts?: { binding_sha256?: string; nowMs?: number },
  ): ClaimForExecuteResult {
    const nowMs = opts?.nowMs ?? Date.now();
    if (!NONCE_HEX.test(nonce)) {
      return { ok: false, reason: "not_registered" };
    }
    try {
      return this.withExclusiveLock(() => {
        const doc = this.loadDocUnlocked(nowMs);
        const idx = doc.entries.findIndex((e) => e.nonce === nonce);
        if (idx < 0) {
          return { ok: false, reason: "not_registered" };
        }
        const cur = doc.entries[idx]!;
        if (isExpired(cur, nowMs)) {
          return { ok: false, reason: "expired" };
        }
        if (
          opts?.binding_sha256 &&
          opts.binding_sha256 !== cur.binding_sha256
        ) {
          return { ok: false, reason: "binding_mismatch" };
        }
        if (cur.status === "in_flight") {
          return { ok: false, reason: "in_flight" };
        }
        if (cur.status === "consumed") {
          return { ok: false, reason: "consumed" };
        }
        if (cur.status === "terminal_uncertain") {
          return { ok: false, reason: "terminal_uncertain" };
        }
        if (cur.status !== "registered") {
          return { ok: false, reason: "invalid_status" };
        }
        const nextEntry: LedgerEntry = {
          ...cur,
          status: "in_flight",
          updated_at_ms: nowMs,
        };
        const next = [...doc.entries];
        next[idx] = nextEntry;
        this.saveDocUnlocked(
          { schema_version: 1, entries: next, updated_at_ms: nowMs },
          nowMs,
        );
        return { ok: true, entry: nextEntry };
      }, nowMs);
    } catch (e) {
      if (e instanceof LedgerError && e.code === "LEDGER_LOCK") {
        return { ok: false, reason: "lock_busy" };
      }
      if (e instanceof LedgerError) {
        return { ok: false, reason: "io" };
      }
      return { ok: false, reason: "io" };
    }
  }

  private transition(
    nonce: string,
    status: "consumed" | "terminal_uncertain",
    nowMs: number,
  ): void {
    if (!NONCE_HEX.test(nonce)) {
      throw new LedgerError("LEDGER_SCHEMA", "Nonce refused.");
    }
    this.withExclusiveLock(() => {
      const doc = this.loadDocUnlocked(nowMs);
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
      // Allow registered → terminal (cancel / pre-execute) and
      // in_flight → terminal (post-claim success / uncertain). Never reverse.
      if (cur.status !== "registered" && cur.status !== "in_flight") {
        throw new LedgerError("LEDGER_TERMINAL", "Ledger entry not transitionable.");
      }
      const next = [...doc.entries];
      next[idx] = { ...cur, status, updated_at_ms: nowMs };
      this.saveDocUnlocked(
        { schema_version: 1, entries: next, updated_at_ms: nowMs },
        nowMs,
      );
    }, nowMs);
  }

  markConsumed(nonce: string, nowMs: number = Date.now()): void {
    this.transition(nonce, "consumed", nowMs);
  }

  markTerminalUncertain(nonce: string, nowMs: number = Date.now()): void {
    this.transition(nonce, "terminal_uncertain", nowMs);
  }

  /**
   * True when nonce is consumed, terminal_uncertain, or in_flight
   * (exclusive claim held / crash-safe terminal — no second execute).
   */
  isTerminal(nonce: string, nowMs: number = Date.now()): boolean {
    const e = this.getEntry(nonce, nowMs);
    if (!e) return false;
    return (
      e.status === "consumed" ||
      e.status === "terminal_uncertain" ||
      e.status === "in_flight"
    );
  }

  /** Wipe ledger state files under this root (tests only). */
  resetForTests(): void {
    ensureRoot(this.root);
    // Free any leftover lock name first (test isolation; no rmdir).
    try {
      const lockDir = lockDirPath(this.root);
      try {
        fs.lstatSync(lockDir);
        releaseLockDir(lockDir, this.root, "reset");
      } catch {
        /* absent */
      }
    } catch {
      /* best-effort */
    }
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
