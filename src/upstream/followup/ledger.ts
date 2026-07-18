/**
 * Fail-closed subscription / follow-up ledger under ChangeGuard-owned state.
 * Strict schema, no symlink following, size/cap controls, corruption refusal.
 * No secrets, tokens, raw session material, or unnecessary absolute paths.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  FOLLOWUP_LEDGER_CAPACITY,
  FOLLOWUP_LEDGER_DIR_MODE,
  FOLLOWUP_LEDGER_FILE_MODE,
  FOLLOWUP_LEDGER_MAX_BYTES,
  FOLLOWUP_LEDGER_STATE_FILE,
  MAX_EVENTS_PER_ISSUE,
  MAX_SUBSCRIPTIONS,
  UPSTREAM_DISPOSITIONS,
} from "./limits.js";
import type {
  FollowupEventRecord,
  FollowupLedger,
  SubscriptionRecord,
  UpstreamDisposition,
} from "./types.js";
import { sha256Text } from "../../evidence/canonical.js";

export type FollowupLedgerErrorCode =
  | "LEDGER_IO"
  | "LEDGER_SCHEMA"
  | "LEDGER_SYMLINK"
  | "LEDGER_CAPACITY"
  | "LEDGER_SIZE"
  | "LEDGER_ROOT"
  | "LEDGER_CORRUPT"
  | "LEDGER_DIGEST";

export class FollowupLedgerError extends Error {
  readonly code: FollowupLedgerErrorCode;
  constructor(code: FollowupLedgerErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "FollowupLedgerError";
  }
}

const DISPOSITION_SET = new Set<string>(UPSTREAM_DISPOSITIONS);
const SHA256_HEX = /^[a-f0-9]{64}$/;

const SUB_KEYS = [
  "issue_number",
  "canonical_url",
  "subscribed_at_ms",
  "last_refresh_at_ms",
  "last_event_digest",
  "last_disposition",
  "duplicate_of_issue",
  "active",
] as const;

const EVENT_KEYS = [
  "event_id",
  "issue_number",
  "disposition",
  "event_digest",
  "processed_at_ms",
  "intents",
  "probe_ids",
  "evidence_capsule_id",
  "reply_draft_digest",
] as const;

const LEDGER_KEYS = [
  "schema_version",
  "subscriptions",
  "events",
  "updated_at_ms",
  "ledger_digest",
] as const;

/** Resolve ChangeGuard-owned follow-up state root (never target project). */
export function resolveFollowupStateRoot(override?: string | null): string {
  if (typeof override === "string" && override.length > 0) {
    return path.resolve(override);
  }
  const forced = process.env.CHANGEGUARD_FOLLOWUP_STATE_DIR;
  if (typeof forced === "string" && forced.length > 0) {
    return path.resolve(forced);
  }
  const plugin = process.env.PLUGIN_DATA || process.env.CLAUDE_PLUGIN_DATA;
  if (typeof plugin === "string" && plugin.length > 0) {
    return path.join(path.resolve(plugin), "upstream-followup");
  }
  const xdg = process.env.XDG_STATE_HOME;
  if (typeof xdg === "string" && xdg.length > 0) {
    return path.join(
      path.resolve(xdg),
      "codex-changeguard",
      "upstream-followup",
    );
  }
  const home = process.env.HOME || process.env.USERPROFILE;
  if (typeof home !== "string" || home.length === 0) {
    throw new FollowupLedgerError(
      "LEDGER_ROOT",
      "No follow-up state root (set CHANGEGUARD_FOLLOWUP_STATE_DIR or PLUGIN_DATA).",
    );
  }
  return path.join(
    path.resolve(home),
    ".local",
    "state",
    "codex-changeguard",
    "upstream-followup",
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
      throw new FollowupLedgerError("LEDGER_IO", "Ledger path missing.");
    }
    throw new FollowupLedgerError("LEDGER_IO", "Ledger path refused.");
  }
  if (st.isSymbolicLink()) {
    throw new FollowupLedgerError("LEDGER_SYMLINK", "Symlink ledger path refused.");
  }
  if (!st.isDirectory()) {
    throw new FollowupLedgerError("LEDGER_IO", "Ledger root is not a directory.");
  }
}

function assertFileNotSymlink(abs: string): fs.Stats | null {
  try {
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink()) {
      throw new FollowupLedgerError("LEDGER_SYMLINK", "Symlink ledger file refused.");
    }
    return st;
  } catch (e) {
    if (e instanceof FollowupLedgerError) throw e;
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === "ENOENT") return null;
    throw new FollowupLedgerError("LEDGER_IO", "Ledger file path refused.");
  }
}

function ensureRoot(root: string): void {
  if (fs.existsSync(root)) {
    assertDirSafe(root);
    return;
  }
  fs.mkdirSync(root, { recursive: true, mode: FOLLOWUP_LEDGER_DIR_MODE });
  assertDirSafe(root);
}

function readBoundedFile(abs: string, maxBytes: number): Buffer {
  const pre = assertFileNotSymlink(abs);
  if (!pre) {
    throw new FollowupLedgerError("LEDGER_IO", "Ledger file missing.");
  }
  if (!pre.isFile()) {
    throw new FollowupLedgerError("LEDGER_IO", "Ledger path is not a file.");
  }
  if (pre.size > maxBytes) {
    throw new FollowupLedgerError("LEDGER_SIZE", "Ledger file exceeds size limit.");
  }
  let fd: number;
  try {
    fd = fs.openSync(abs, openReadFlags());
  } catch {
    throw new FollowupLedgerError("LEDGER_IO", "Ledger read open failed.");
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) {
      throw new FollowupLedgerError("LEDGER_SIZE", "Ledger file refused.");
    }
    if (st.dev !== pre.dev || st.ino !== pre.ino || st.size !== pre.size) {
      throw new FollowupLedgerError("LEDGER_IO", "Ledger TOCTOU refused.");
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
  if (bytes.length > FOLLOWUP_LEDGER_MAX_BYTES) {
    throw new FollowupLedgerError("LEDGER_SIZE", "Ledger payload exceeds size limit.");
  }
  const dest = path.join(root, fileName);
  const existing = assertFileNotSymlink(dest);
  if (existing && !existing.isFile()) {
    throw new FollowupLedgerError("LEDGER_IO", "Ledger dest refused.");
  }
  const tmp = path.join(
    root,
    `.${fileName}.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString("hex")}`,
  );
  try {
    fs.writeFileSync(tmp, bytes, {
      encoding: undefined,
      flag: "wx",
      mode: FOLLOWUP_LEDGER_FILE_MODE,
    });
    fs.renameSync(tmp, dest);
  } catch (e) {
    try {
      if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    } catch {
      /* best-effort */
    }
    if (e instanceof FollowupLedgerError) throw e;
    throw new FollowupLedgerError("LEDGER_IO", "Atomic ledger write failed.");
  }
  const finalStat = assertFileNotSymlink(dest);
  if (!finalStat || !finalStat.isFile()) {
    throw new FollowupLedgerError("LEDGER_IO", "Ledger post-write refused.");
  }
}

function exactKeys(obj: Record<string, unknown>, keys: readonly string[]): boolean {
  const got = Object.keys(obj).sort();
  const exp = [...keys].sort();
  if (got.length !== exp.length) return false;
  for (let i = 0; i < exp.length; i++) {
    if (got[i] !== exp[i]) return false;
  }
  return true;
}

function ledgerDigestMaterial(ledger: Omit<FollowupLedger, "ledger_digest">): string {
  return sha256Text(
    JSON.stringify({
      schema_version: ledger.schema_version,
      subscriptions: ledger.subscriptions,
      events: ledger.events,
      updated_at_ms: ledger.updated_at_ms,
    }),
  );
}

export function sealLedger(ledger: Omit<FollowupLedger, "ledger_digest">): FollowupLedger {
  return {
    ...ledger,
    ledger_digest: ledgerDigestMaterial(ledger),
  };
}

export function emptyFollowupLedger(nowMs: number): FollowupLedger {
  return sealLedger({
    schema_version: 1,
    subscriptions: [],
    events: [],
    updated_at_ms: nowMs,
  });
}

function parseSubscription(raw: unknown): SubscriptionRecord {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription refused.");
  }
  const o = raw as Record<string, unknown>;
  if (!exactKeys(o, SUB_KEYS)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription keys refused.");
  }
  if (typeof o.issue_number !== "number" || !Number.isInteger(o.issue_number) || o.issue_number < 1) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription issue_number refused.");
  }
  if (typeof o.canonical_url !== "string" || o.canonical_url.length === 0 || o.canonical_url.length > 256) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription canonical_url refused.");
  }
  if (typeof o.subscribed_at_ms !== "number" || !Number.isFinite(o.subscribed_at_ms)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription subscribed_at_ms refused.");
  }
  if (
    o.last_refresh_at_ms !== null &&
    (typeof o.last_refresh_at_ms !== "number" || !Number.isFinite(o.last_refresh_at_ms))
  ) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription last_refresh_at_ms refused.");
  }
  if (
    o.last_event_digest !== null &&
    (typeof o.last_event_digest !== "string" || !SHA256_HEX.test(o.last_event_digest))
  ) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription last_event_digest refused.");
  }
  if (
    o.last_disposition !== null &&
    (typeof o.last_disposition !== "string" || !DISPOSITION_SET.has(o.last_disposition))
  ) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription last_disposition refused.");
  }
  if (
    o.duplicate_of_issue !== null &&
    (typeof o.duplicate_of_issue !== "number" ||
      !Number.isInteger(o.duplicate_of_issue) ||
      o.duplicate_of_issue < 1)
  ) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription duplicate_of_issue refused.");
  }
  if (typeof o.active !== "boolean") {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Subscription active refused.");
  }
  return {
    issue_number: o.issue_number,
    canonical_url: o.canonical_url,
    subscribed_at_ms: o.subscribed_at_ms,
    last_refresh_at_ms: o.last_refresh_at_ms as number | null,
    last_event_digest: o.last_event_digest as string | null,
    last_disposition: o.last_disposition as UpstreamDisposition | null,
    duplicate_of_issue: o.duplicate_of_issue as number | null,
    active: o.active,
  };
}

function parseEvent(raw: unknown): FollowupEventRecord {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event refused.");
  }
  const o = raw as Record<string, unknown>;
  if (!exactKeys(o, EVENT_KEYS)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event keys refused.");
  }
  if (typeof o.event_id !== "string" || o.event_id.length === 0 || o.event_id.length > 128) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event event_id refused.");
  }
  if (typeof o.issue_number !== "number" || !Number.isInteger(o.issue_number) || o.issue_number < 1) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event issue_number refused.");
  }
  if (typeof o.disposition !== "string" || !DISPOSITION_SET.has(o.disposition)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event disposition refused.");
  }
  if (typeof o.event_digest !== "string" || !SHA256_HEX.test(o.event_digest)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event event_digest refused.");
  }
  if (typeof o.processed_at_ms !== "number" || !Number.isFinite(o.processed_at_ms)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event processed_at_ms refused.");
  }
  if (!Array.isArray(o.intents) || o.intents.length > 16) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event intents refused.");
  }
  if (!Array.isArray(o.probe_ids) || o.probe_ids.length > 16) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event probe_ids refused.");
  }
  if (
    o.evidence_capsule_id !== null &&
    (typeof o.evidence_capsule_id !== "string" || o.evidence_capsule_id.length > 128)
  ) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event evidence_capsule_id refused.");
  }
  if (
    o.reply_draft_digest !== null &&
    (typeof o.reply_draft_digest !== "string" || !SHA256_HEX.test(o.reply_draft_digest))
  ) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Event reply_draft_digest refused.");
  }
  return {
    event_id: o.event_id,
    issue_number: o.issue_number,
    disposition: o.disposition as UpstreamDisposition,
    event_digest: o.event_digest,
    processed_at_ms: o.processed_at_ms,
    intents: o.intents as FollowupEventRecord["intents"],
    probe_ids: o.probe_ids as FollowupEventRecord["probe_ids"],
    evidence_capsule_id: o.evidence_capsule_id as string | null,
    reply_draft_digest: o.reply_draft_digest as string | null,
  };
}

function parseLedger(raw: unknown): FollowupLedger {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Ledger JSON refused.");
  }
  const o = raw as Record<string, unknown>;
  if (!exactKeys(o, LEDGER_KEYS)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Ledger keys refused.");
  }
  if (o.schema_version !== 1) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Ledger schema_version refused.");
  }
  if (!Array.isArray(o.subscriptions) || o.subscriptions.length > MAX_SUBSCRIPTIONS * 2) {
    throw new FollowupLedgerError("LEDGER_SIZE", "Ledger subscriptions refused.");
  }
  if (!Array.isArray(o.events) || o.events.length > FOLLOWUP_LEDGER_CAPACITY * 4) {
    throw new FollowupLedgerError("LEDGER_SIZE", "Ledger events refused.");
  }
  if (typeof o.updated_at_ms !== "number" || !Number.isFinite(o.updated_at_ms)) {
    throw new FollowupLedgerError("LEDGER_SCHEMA", "Ledger updated_at_ms refused.");
  }
  if (typeof o.ledger_digest !== "string" || !SHA256_HEX.test(o.ledger_digest)) {
    throw new FollowupLedgerError("LEDGER_DIGEST", "Ledger digest refused.");
  }
  const subscriptions = o.subscriptions.map(parseSubscription);
  const events = o.events.map(parseEvent);
  const sealed = sealLedger({
    schema_version: 1,
    subscriptions,
    events,
    updated_at_ms: o.updated_at_ms,
  });
  if (sealed.ledger_digest !== o.ledger_digest) {
    throw new FollowupLedgerError("LEDGER_CORRUPT", "Ledger digest mismatch.");
  }
  return sealed;
}

function prune(ledger: FollowupLedger, nowMs: number): FollowupLedger {
  // Cap subscriptions
  let subs = ledger.subscriptions.filter((s) => s.active);
  if (subs.length > MAX_SUBSCRIPTIONS) {
    throw new FollowupLedgerError("LEDGER_CAPACITY", "Active subscription capacity exceeded.");
  }
  // Keep inactive recent for audit, but cap total
  const inactive = ledger.subscriptions
    .filter((s) => !s.active)
    .sort((a, b) => b.subscribed_at_ms - a.subscribed_at_ms)
    .slice(0, Math.max(0, MAX_SUBSCRIPTIONS - subs.length));
  subs = [...subs, ...inactive].slice(0, MAX_SUBSCRIPTIONS);

  // Cap events: keep newest; also per-issue cap
  const byIssue = new Map<number, FollowupEventRecord[]>();
  const sorted = [...ledger.events].sort((a, b) => b.processed_at_ms - a.processed_at_ms);
  const kept: FollowupEventRecord[] = [];
  for (const e of sorted) {
    const list = byIssue.get(e.issue_number) ?? [];
    if (list.length >= MAX_EVENTS_PER_ISSUE) continue;
    if (kept.length >= FOLLOWUP_LEDGER_CAPACITY) break;
    list.push(e);
    byIssue.set(e.issue_number, list);
    kept.push(e);
  }
  return sealLedger({
    schema_version: 1,
    subscriptions: subs,
    events: kept,
    updated_at_ms: nowMs,
  });
}

export function loadFollowupLedger(root: string, nowMs: number): FollowupLedger {
  ensureRoot(root);
  const abs = path.join(root, FOLLOWUP_LEDGER_STATE_FILE);
  const st = assertFileNotSymlink(abs);
  if (!st) {
    return emptyFollowupLedger(nowMs);
  }
  const buf = readBoundedFile(abs, FOLLOWUP_LEDGER_MAX_BYTES);
  let parsed: unknown;
  try {
    parsed = JSON.parse(buf.toString("utf8"));
  } catch {
    throw new FollowupLedgerError("LEDGER_CORRUPT", "Ledger JSON parse failed.");
  }
  return parseLedger(parsed);
}

export function saveFollowupLedger(root: string, ledger: FollowupLedger, nowMs: number): FollowupLedger {
  const pruned = prune(ledger, nowMs);
  const sealed = sealLedger({
    schema_version: 1,
    subscriptions: pruned.subscriptions,
    events: pruned.events,
    updated_at_ms: nowMs,
  });
  const bytes = Buffer.from(`${JSON.stringify(sealed, null, 2)}\n`, "utf8");
  atomicWriteFile(root, FOLLOWUP_LEDGER_STATE_FILE, bytes);
  return sealed;
}

export function findSubscription(
  ledger: FollowupLedger,
  issue_number: number,
): SubscriptionRecord | null {
  return ledger.subscriptions.find((s) => s.issue_number === issue_number && s.active) ?? null;
}

export function upsertSubscription(
  ledger: FollowupLedger,
  sub: SubscriptionRecord,
  nowMs: number,
): FollowupLedger {
  const others = ledger.subscriptions.filter((s) => s.issue_number !== sub.issue_number);
  const next = sealLedger({
    schema_version: 1,
    subscriptions: [...others, sub],
    events: ledger.events,
    updated_at_ms: nowMs,
  });
  if (next.subscriptions.filter((s) => s.active).length > MAX_SUBSCRIPTIONS) {
    throw new FollowupLedgerError("LEDGER_CAPACITY", "Subscription capacity exceeded.");
  }
  return next;
}

export function appendEvent(
  ledger: FollowupLedger,
  event: FollowupEventRecord,
  nowMs: number,
): FollowupLedger {
  // Idempotent: same event_id or same digest for issue → no duplicate append
  const dup = ledger.events.find(
    (e) =>
      e.event_id === event.event_id ||
      (e.issue_number === event.issue_number && e.event_digest === event.event_digest),
  );
  if (dup) {
    return ledger;
  }
  return sealLedger({
    schema_version: 1,
    subscriptions: ledger.subscriptions,
    events: [...ledger.events, event],
    updated_at_ms: nowMs,
  });
}
