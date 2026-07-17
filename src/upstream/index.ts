export type {
  CapsuleStatus,
  CaseKind,
  DisclosureDecision,
  DoctorSanitizationResult,
  DuplicateAssessment,
  DuplicateCandidate,
  DuplicateRecommendation,
  DuplicateSearch,
  DuplicateState,
  EvidenceDelta,
  EvidenceDeltaItem,
  EvidenceDeltaKind,
  FormBlobRecord,
  FormSnapshotView,
  GitHubIssueForm,
  MaintainerValueGateCheck,
  MaintainerValueGateResult,
  OfficialFormSnapshot,
  PlatformInfo,
  PrivacyReviewInput,
  ProductSurfaceHint,
  ReproductionInfo,
  ReproductionQuality,
  UpstreamDisclosureField,
  UpstreamDisclosureManifest,
  UpstreamFormTransport,
  UpstreamFormTransportRequest,
  UpstreamFormTransportResponse,
  UpstreamPreviewRequest,
  UpstreamPreviewResult,
  UpstreamRoute,
  UpstreamSubmissionCapsule,
} from "./types.js";

export {
  MAX_UPSTREAM_REQUEST_BYTES,
  MAX_DOCTOR_JSON_BYTES,
  MAX_STRING,
  MAX_TITLE,
  OFFICIAL_FORM_SNAPSHOT_ID,
  OFFICIAL_FORM_SNAPSHOT_FETCHED_AT,
  OFFICIAL_MAIN_COMMIT,
  OFFICIAL_FORM_BLOB_SHAS,
  OFFICIAL_HOSTS,
  OFFICIAL_REPOSITORY,
  FORBIDDEN_UPSTREAM_KEYS,
  ALLOWED_REQUEST_KEYS,
  FORM_SNAPSHOT_FRESH_MS,
  FORM_SNAPSHOT_MAX_FUTURE_SKEW_MS,
  FORM_FILENAME_SAFE_RE,
  REQUIRED_BUG_FORM_ROLES,
} from "./limits.js";

export { routeUpstream, mapGitHubIssueForm, applyFormMap } from "./routing.js";
export type { RouteDecision } from "./routing.js";
export { assessDuplicate } from "./duplicate.js";
export { sanitizeDoctorJson, DoctorError } from "./doctor.js";
export {
  bundledOfficialFormSnapshot,
  validateOfficialFormSnapshot,
  viewFormSnapshot,
  computeFormSnapshotIntegrity,
  createInMemoryBundledSnapshot,
  filenameForFormRole,
  FormSnapshotError,
} from "./form-snapshot.js";
export {
  buildUpstreamDisclosureManifest,
  formTransportPermitted,
  formTransportRequestPayload,
} from "./disclosure.js";
export {
  createFakeFormTransport,
  createFailingFormTransport,
  instrumentUpstreamTransport,
} from "./transport.js";
export type { UpstreamTransportCallLog } from "./transport.js";
export { evaluateMaintainerValueGate } from "./maintainer-gate.js";
export { parseUpstreamRequest, UpstreamRequestError } from "./request.js";
export { previewUpstream } from "./preview.js";
export type { UpstreamPreviewOptions } from "./preview.js";
