/** Ticket 12 maintainer follow-up / upstream-fix closure — public surface. */

export type {
  CanonicalIssueRef,
  CandidateValidationInput,
  CandidateValidationResult,
  DispositionPolicyResult,
  EvidenceCapsule,
  FollowupDispatchArgs,
  FollowupEventRecord,
  FollowupLedger,
  FollowupOperation,
  FollowupProbeResult,
  FollowupResult,
  FollowupStatus,
  IntentDetectionResult,
  MaintainerIntent,
  MappedProbePlan,
  ProcessEventInput,
  RefreshInput,
  RegisteredProbeId,
  ReplyDraft,
  SessionHintInput,
  StatusInput,
  SubscribeInput,
  SubscriptionRecord,
  UnsubscribeInput,
  UpstreamDisposition,
} from "./types.js";

export {
  MAX_FOLLOWUP_REQUEST_BYTES,
  MAX_SUBSCRIPTIONS,
  REFRESH_DUE_HINT,
  REFRESH_MIN_INTERVAL_MS,
  FOLLOWUP_LEDGER_STATE_FILE,
  FOLLOWUP_LEDGER_CAPACITY,
  FOLLOWUP_LEDGER_LOCK_NAME,
  FOLLOWUP_LEDGER_LOCK_STALE_MS,
  FOLLOWUP_LEDGER_LOCK_WAIT_MS,
  CANDIDATE_MEASUREMENT_REL,
  FORBIDDEN_FOLLOWUP_KEYS,
  MAINTAINER_INTENTS,
  UPSTREAM_DISPOSITIONS,
  REGISTERED_PROBE_IDS,
  OFFICIAL_HOST,
  OFFICIAL_REPOSITORY,
} from "./limits.js";

export {
  parseCanonicalIssue,
  parseIssueNumber,
  isCanonicalIssueUrl,
  IssueUrlError,
} from "./issue-url.js";

export {
  applyDispositionPolicy,
  isUpstreamDisposition,
} from "./disposition.js";

export {
  detectMaintainerIntents,
  mapIntentsToProbes,
  isMaintainerIntent,
  isRegisteredProbeId,
  refuseProseAsExecutable,
} from "./intent.js";

export {
  runRegisteredProbe,
  runRegisteredProbes,
  measureCandidateFaultAndCore,
  measureWithRegisteredProfile,
  loadCandidateMeasurement,
  PROTECTED_PROCESS_SHIM_PROFILE_V1,
} from "./probes.js";
export type {
  CandidateMeasurementResult,
  CandidateMeasurementVerdict,
} from "./probes.js";

export {
  resolveFollowupStateRoot,
  loadFollowupLedger,
  saveFollowupLedger,
  emptyFollowupLedger,
  FollowupLedgerError,
  findSubscription,
  withFollowupLedgerTransaction,
} from "./ledger.js";
export type { FollowupLedgerErrorCode } from "./ledger.js";

export { buildEvidenceCapsule, buildReplyDraft } from "./capsule.js";

export {
  validateCandidateFix,
  bindOfficialEvidenceItem,
  bindCandidateVersionToOfficial,
} from "./candidate.js";

export {
  subscribeIssue,
  unsubscribeIssue,
  followupStatus,
  sessionFollowupHint,
  refreshFollowup,
  processFollowupEvent,
  validateCandidate,
} from "./engine.js";

export { dispatchFollowup, isFollowupOperation } from "./dispatch.js";

export {
  parseFollowupRequestJson,
  parseFollowupWireBody,
  refuseForbiddenFollowupKeys,
  MAX_FOLLOWUP_REQUEST_DEPTH,
} from "./request.js";
