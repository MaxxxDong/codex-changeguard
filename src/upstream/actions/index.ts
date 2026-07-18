/** Ticket 11 confirmed upstream actions — namespaced public surface. */

export type {
  ActionConfirmResult,
  ActionConfirmStatus,
  ActionConfirmationBinding,
  ActionPreviewResult,
  ActionPreviewStatus,
  AdapterExecuteOutcome,
  AdapterExecuteRequest,
  AdapterExecuteResult,
  AdapterQueryOutcome,
  AdapterQueryResult,
  AttachmentManifest,
  AttachmentManifestEntry,
  AuthCapabilityKind,
  AuthCapabilityReport,
  BodyManifest,
  CapsuleGateCheck,
  CapsuleGateResult,
  ConfirmDecision,
  PrivacyBinding,
  UpstreamActionAdapter,
  UpstreamActionKind,
  UpstreamActionReceipt,
} from "./types.js";

export {
  CONFIRMATION_TOKEN_PREFIX,
  CONFIRMATION_TTL_MS,
  CONFIRMATION_LEDGER_CAPACITY,
  CONFIRMATION_LEDGER_KEY_FILE,
  CONFIRMATION_LEDGER_STATE_FILE,
  FORBIDDEN_ACTION_KEYS,
  MAX_ACTION_REQUEST_BYTES,
  MAX_ATTACHMENTS,
  MAX_CONFIRMATION_BYTES,
  OFFICIAL_CANONICAL_HOSTS,
  OFFICIAL_REPOSITORY,
  UPSTREAM_ACTION_KINDS,
} from "./limits.js";

export {
  createUnavailableAdapter,
  instrumentActionAdapter,
} from "./adapter.js";

export {
  createFakeRemoteAdapter,
} from "./fake-remote.js";
export type { FakeRemoteAdapter, FakeRemoteMode, FakeRemoteOptions } from "./fake-remote.js";

export {
  gateCapsuleForActions,
  recomputeCapsuleContentSha256,
  allowedActionsForRecommendation,
  isActionAllowed,
} from "./capsule-gate.js";

export {
  computeIdempotencyKey,
  incidentFingerprintDigest,
  receiptHash,
} from "./idempotency.js";

export {
  mintConfirmation,
  parseConfirmationToken,
  consumeConfirmationNonce,
  markConfirmationTerminalUncertain,
  computeBindingSha256,
  computeConfirmationMac,
  revalidateConfirmationBinding,
  ConfirmationError,
  openConfirmationLedger,
  _resetConsumedNoncesForTests,
  _resetConfirmationLedgerForTests,
} from "./confirmation.js";
export type {
  ConfirmationErrorCode,
  MintConfirmationInput,
  ParseConfirmationOptions,
} from "./confirmation.js";
export { ConfirmationLedger } from "./confirmation.js";

export {
  resolveConfirmationStateRoot,
  LedgerError,
} from "./ledger.js";
export type { LedgerEntry, LedgerEntryStatus, LedgerErrorCode } from "./ledger.js";

export {
  buildBodyManifest,
  parseAttachmentManifest,
  resolveCanonicalTarget,
  isOfficialCanonicalTarget,
  ManifestError,
} from "./manifest.js";

export { previewUpstreamAction } from "./preview.js";
export type { ActionPreviewOptions } from "./preview.js";

export { confirmUpstreamAction } from "./confirm.js";
export type { ActionConfirmOptions } from "./confirm.js";
