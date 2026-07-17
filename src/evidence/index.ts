export type {
  DisclosureDecision,
  DisclosureField,
  DisclosureManifest,
  EvidenceKind,
  EvidenceRefreshResult,
  EvidenceSourceMode,
  EvidenceState,
  LocalDisclosureContext,
  MaintainerStatus,
  OfficialEvidenceItem,
  OfficialEvidenceSnapshot,
  OfficialStructuredPayload,
  OfficialTransport,
  OfficialTransportRequest,
  OfficialTransportResponse,
  QuarantineRecord,
  RawOfficialTransportItem,
  StaleRisk,
  TransportCallLog,
  TrustClass,
  SourceClass,
  VersionRange,
} from "./types.js";

export {
  buildDisclosureManifest,
  buildTransportRequest,
  disclosureFieldNames,
  disclosureSendableFieldNames,
  sanitizeSendableLocalFields,
} from "./disclosure.js";
export {
  assertOfficialUrl,
  assertOriginAllowlist,
  officialAllowlists,
  isAllowedHost,
  isAllowedRepository,
  isAllowedOrigin,
  AllowlistError,
} from "./allowlist.js";
export {
  detectInstructionLike,
  normalizeForInstructionScan,
  quarantineProse,
  assertNotExecutable,
} from "./quarantine.js";
export {
  createFakeTransport,
  createFailingTransport,
  instrumentTransport,
} from "./transport.js";
export {
  parseSnapshotJson,
  loadBundledSnapshot,
  buildSnapshotFromItems,
  defaultBundledSnapshotPath,
  snapshotFingerprint,
  SnapshotError,
} from "./snapshot.js";
export { refreshOfficialEvidence, validateTransportFetchedAt } from "./refresh.js";
export type { RefreshOptions } from "./refresh.js";
export { canonicalStringify, sha256Canonical, sha256Text } from "./canonical.js";
export {
  computeItemContentSha256,
  computeSnapshotContentSha256,
} from "./item-hash.js";
export {
  OFFICIAL_HOSTS,
  OFFICIAL_REPOSITORIES,
  OFFICIAL_ORIGINS,
  MAX_EVIDENCE_ITEMS,
  STALE_HIGH_SECONDS,
  MAX_FETCHED_AT_FUTURE_SKEW_SECONDS,
} from "./limits.js";
