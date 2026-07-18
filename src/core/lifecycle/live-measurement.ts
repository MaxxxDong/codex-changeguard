/**
 * Ticket 12 live measurement authority (process-local).
 *
 * Positive upgrade / supersession require a process-local opaque witness minted
 * only by the closed registered profile runner below. Caller JSON, booleans,
 * digests, persisted receipts, and plain objects never self-prove.
 *
 * No public seal(attestation) / arbitrary registration — mint is private.
 */
import crypto from "node:crypto";
import {
  MAX_ARTIFACT_BYTES,
  PROTECTED_ARTIFACT_REL,
} from "../limits.js";
import { sha256Buffer } from "../measure.js";
import {
  PathSafetyError,
  resolveNamedCandidate,
  readBoundedFile,
  resolveTargetDirectory,
} from "../path-safety.js";
import {
  artifactRel,
  coreHealthChecks,
  preHandshakeFailureStillPresent,
} from "../recovery/protected-process.js";
import { sha256Text } from "../recovery/canonical.js";
import { proveIsolatedFixtureTarget } from "../../platform/capability.js";

/** Closed Phase-A profile id. Unknown profiles fail closed. */
export const PROTECTED_PROCESS_SHIM_PROFILE_V1 = "protected_process_shim_v1" as const;
export type RegisteredMeasurementProfileId = typeof PROTECTED_PROCESS_SHIM_PROFILE_V1;

const LIVE_WITNESS_BRAND = Symbol.for("changeguard.live_measurement_witness.v1");

export type LiveMeasurementStage = "fresh" | "canary_recorded" | "consumed";

export interface LiveMeasurementAttestation {
  profile_id: RegisteredMeasurementProfileId;
  candidate_version: string;
  baseline_artifact_sha256: string;
  candidate_artifact_sha256: string;
  baseline_isolation_digest: string;
  candidate_isolation_digest: string;
  /** Ordered probe digests (baseline fault, candidate fault, candidate core). */
  probe_digests: readonly string[];
  baseline_fault_present: true;
  candidate_fault_present: false;
  candidate_core_ok: true;
  /** Process-local anti-replay material — never exported in public results. */
  nonce: string;
  measured_at_ms: number;
  stage: LiveMeasurementStage;
}

export interface LiveMeasurementWitness {
  readonly [LIVE_WITNESS_BRAND]: true;
}

/**
 * Private store record. Exact canonical target identity stays here only —
 * never copied into public LiveMeasurementAttestation / results / evidence.
 */
interface AttestationState extends LiveMeasurementAttestation {
  stage: LiveMeasurementStage;
  /**
   * Exact canonical candidate root (realpath) proven during registered live
   * measurement isolation. Used solely for process-local target binding.
   */
  measured_candidate_target_real: string;
}

const liveMeasurementStore = new WeakMap<object, AttestationState>();

function isWitnessObject(v: unknown): v is LiveMeasurementWitness {
  return (
    typeof v === "object" &&
    v !== null &&
    (v as LiveMeasurementWitness)[LIVE_WITNESS_BRAND] === true &&
    liveMeasurementStore.has(v as object)
  );
}

/** Type guard: process-local branded witness only (JSON clones fail). */
export function isLiveMeasurementWitness(v: unknown): v is LiveMeasurementWitness {
  return isWitnessObject(v);
}

/**
 * Read attestation only for a live witness still in the process store.
 * Never accepts plain objects / JSON clones.
 */
export function readLiveMeasurementAttestation(
  witness: unknown,
): LiveMeasurementAttestation | null {
  if (!isWitnessObject(witness)) return null;
  const st = liveMeasurementStore.get(witness as object);
  if (!st) return null;
  return {
    profile_id: st.profile_id,
    candidate_version: st.candidate_version,
    baseline_artifact_sha256: st.baseline_artifact_sha256,
    candidate_artifact_sha256: st.candidate_artifact_sha256,
    baseline_isolation_digest: st.baseline_isolation_digest,
    candidate_isolation_digest: st.candidate_isolation_digest,
    probe_digests: [...st.probe_digests],
    baseline_fault_present: true,
    candidate_fault_present: false,
    candidate_core_ok: true,
    nonce: st.nonce,
    measured_at_ms: st.measured_at_ms,
    stage: st.stage,
  };
}

function mintWitness(state: AttestationState): LiveMeasurementWitness {
  const token = { [LIVE_WITNESS_BRAND]: true as const };
  liveMeasurementStore.set(token, state);
  return token;
}

function digestOf(material: unknown): string {
  return sha256Text(JSON.stringify(material));
}

/**
 * Path-free isolation proof digest. Absolute roots never appear in public
 * digests; binds role + measured artifact content only after proveIsolatedFixtureTarget.
 */
function isolationProofDigest(
  role: "baseline" | "candidate",
  artifactSha256: string,
): string {
  return digestOf({
    schema: "t12_isolation_proof_v1",
    role,
    disposable_isolated: true,
    artifact_content_sha256: artifactSha256,
  });
}

function readArtifactBytes(targetPath: string):
  | { ok: true; bytes: Buffer; sha256: string }
  | { ok: false; code: string; message: string } {
  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch (e) {
    const code = e instanceof PathSafetyError ? e.code : "INVALID_TARGET";
    return { ok: false, code, message: "Isolated target refused." };
  }

  // Fixed registered artifact path — never caller-provided relative path.
  const rel = artifactRel();
  if (rel !== PROTECTED_ARTIFACT_REL) {
    return {
      ok: false,
      code: "ARTIFACT_CONTRACT",
      message: "Registered artifact path contract mismatch.",
    };
  }

  let meta: ReturnType<typeof resolveNamedCandidate>;
  try {
    meta = resolveNamedCandidate(targetReal, rel);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      if (e.code === "SYMLINK_ESCAPE") {
        return {
          ok: false,
          code: "ARTIFACT_SYMLINK",
          message: "Symlinked measurement artifact refused.",
        };
      }
      if (e.code === "CANDIDATE_NOT_FOUND") {
        return {
          ok: false,
          code: "ARTIFACT_ABSENT",
          message: "Registered measurement artifact absent.",
        };
      }
      return {
        ok: false,
        code: "ARTIFACT_PATH",
        message: `Measurement artifact path refused: ${e.code}`,
      };
    }
    return { ok: false, code: "ARTIFACT_PATH", message: "Measurement artifact path refused." };
  }

  if (meta.size > MAX_ARTIFACT_BYTES) {
    return {
      ok: false,
      code: "ARTIFACT_SIZE",
      message: "Measurement artifact exceeds size limit.",
    };
  }

  try {
    const bytes = readBoundedFile(meta.real, MAX_ARTIFACT_BYTES, meta.preOpen);
    return { ok: true, bytes, sha256: sha256Buffer(bytes) };
  } catch (e) {
    const code = e instanceof PathSafetyError ? e.code : "ARTIFACT_READ";
    return {
      ok: false,
      code: code === "SYMLINK_ESCAPE" ? "ARTIFACT_SYMLINK" : "ARTIFACT_READ",
      message: `Measurement artifact unreadable: ${code}`,
    };
  }
}

export type LiveMeasurementVerdict = "positive" | "negative" | "inconclusive";

export interface RegisteredLiveMeasurementResult {
  verdict: LiveMeasurementVerdict;
  profile_id: string | null;
  candidate_version: string | null;
  measured_fault_absent: boolean | null;
  measured_core_ok: boolean | null;
  baseline_fault_reproduced: boolean | null;
  /** Present only on positive path; process-local, never serializable authority. */
  witness: LiveMeasurementWitness | null;
  /** Path-free digests safe for public evidence (no roots/nonce/witness). */
  public_digests: {
    baseline_artifact_sha256: string | null;
    candidate_artifact_sha256: string | null;
    baseline_isolation_digest: string | null;
    candidate_isolation_digest: string | null;
    probe_digests: string[];
  };
  detail: string;
  error_code: string | null;
  /**
   * Explicit: artifact-level candidate evidence under disposable roots —
   * not cryptographic proof of an installed binary identity.
   */
  evidence_scope: "artifact_level_disposable_pair";
}

function inconclusive(
  code: string,
  detail: string,
  partial: Partial<RegisteredLiveMeasurementResult> = {},
): RegisteredLiveMeasurementResult {
  return {
    verdict: "inconclusive",
    profile_id: partial.profile_id ?? null,
    candidate_version: partial.candidate_version ?? null,
    measured_fault_absent: partial.measured_fault_absent ?? null,
    measured_core_ok: partial.measured_core_ok ?? null,
    baseline_fault_reproduced: partial.baseline_fault_reproduced ?? null,
    witness: null,
    public_digests: partial.public_digests ?? {
      baseline_artifact_sha256: null,
      candidate_artifact_sha256: null,
      baseline_isolation_digest: null,
      candidate_isolation_digest: null,
      probe_digests: [],
    },
    detail,
    error_code: code,
    evidence_scope: "artifact_level_disposable_pair",
  };
}

function negative(
  detail: string,
  fields: {
    profile_id: string;
    candidate_version: string;
    measured_fault_absent: boolean;
    measured_core_ok: boolean;
    baseline_fault_reproduced: true;
    public_digests: RegisteredLiveMeasurementResult["public_digests"];
  },
): RegisteredLiveMeasurementResult {
  return {
    verdict: "negative",
    profile_id: fields.profile_id,
    candidate_version: fields.candidate_version,
    measured_fault_absent: fields.measured_fault_absent,
    measured_core_ok: fields.measured_core_ok,
    baseline_fault_reproduced: true,
    witness: null,
    public_digests: fields.public_digests,
    detail,
    error_code: null,
    evidence_scope: "artifact_level_disposable_pair",
  };
}

export interface RegisteredMeasurementInput {
  /** Disposable candidate root (measured for fault-absent + core health). */
  targetPath: string;
  /** Separate disposable baseline root (must reproduce original fault). */
  baselineTargetPath: string;
  candidate_version: string;
  /** Closed profile id — only protected_process_shim_v1 in Phase A. */
  profile_id: string;
  nowMs?: number;
}

/**
 * Closed production-capable registered profile runner (Phase A).
 * Executes fixed T02 measurement primitives in-process on isolated disposable
 * baseline/candidate artifact pairs. Mints a process-local witness only on the
 * full positive path. Never mutates artifacts, never shells/networks, never
 * touches the active profile.
 */
export function runRegisteredLiveMeasurement(
  input: RegisteredMeasurementInput,
): RegisteredLiveMeasurementResult {
  const profile = input.profile_id;
  if (profile !== PROTECTED_PROCESS_SHIM_PROFILE_V1) {
    return inconclusive(
      "UNSUPPORTED_PROFILE",
      `Unsupported or unknown measurement profile refused: ${typeof profile === "string" ? profile.slice(0, 64) : "invalid"}.`,
    );
  }

  const candidate_version = input.candidate_version;
  if (
    typeof candidate_version !== "string" ||
    candidate_version.length === 0 ||
    candidate_version.length > 64
  ) {
    return inconclusive("INVALID_VERSION", "Invalid candidate_version.");
  }

  if (
    typeof input.targetPath !== "string" ||
    typeof input.baselineTargetPath !== "string" ||
    input.targetPath.length === 0 ||
    input.baselineTargetPath.length === 0
  ) {
    return inconclusive(
      "INVALID_TARGET",
      "Baseline and candidate disposable targets required.",
    );
  }

  // Prove both roots are real, distinct, disposable isolated targets.
  if (!proveIsolatedFixtureTarget(input.baselineTargetPath)) {
    return inconclusive(
      "BASELINE_ISOLATION_REFUSED",
      "Baseline target failed disposable isolation proof (active/protected/symlink/non-disposable refused).",
    );
  }
  if (!proveIsolatedFixtureTarget(input.targetPath)) {
    return inconclusive(
      "CANDIDATE_ISOLATION_REFUSED",
      "Candidate target failed disposable isolation proof (active/protected/symlink/non-disposable refused).",
    );
  }

  let baselineReal: string;
  let candidateReal: string;
  try {
    baselineReal = resolveTargetDirectory(input.baselineTargetPath).targetReal;
    candidateReal = resolveTargetDirectory(input.targetPath).targetReal;
  } catch {
    return inconclusive("INVALID_TARGET", "Isolated target refused.");
  }

  if (baselineReal === candidateReal) {
    return inconclusive(
      "ROOT_EQUALITY_REFUSED",
      "Baseline and candidate roots must be distinct disposable targets.",
    );
  }

  const baselineArt = readArtifactBytes(input.baselineTargetPath);
  if (!baselineArt.ok) {
    return inconclusive(
      baselineArt.code.startsWith("ARTIFACT")
        ? `BASELINE_${baselineArt.code}`
        : baselineArt.code,
      `Baseline: ${baselineArt.message}`,
    );
  }
  const candidateArt = readArtifactBytes(input.targetPath);
  if (!candidateArt.ok) {
    return inconclusive(
      candidateArt.code.startsWith("ARTIFACT")
        ? `CANDIDATE_${candidateArt.code}`
        : candidateArt.code,
      `Candidate: ${candidateArt.message}`,
    );
  }

  const baselineSource = baselineArt.bytes.toString("utf8");
  const candidateSource = candidateArt.bytes.toString("utf8");

  // In-process T02 primitives only — no shell/network.
  const baselineFault = preHandshakeFailureStillPresent(baselineSource);
  const candidateFault = preHandshakeFailureStillPresent(candidateSource);
  const core = coreHealthChecks(candidateSource);

  const probe_digests = [
    digestOf({
      probe: "baseline_pre_handshake_fault",
      present: baselineFault,
      artifact_sha256: baselineArt.sha256,
    }),
    digestOf({
      probe: "candidate_pre_handshake_fault",
      present: candidateFault,
      artifact_sha256: candidateArt.sha256,
    }),
    digestOf({
      probe: "candidate_core_health",
      passed: core.passed,
      checks: core.checks.map((c) => ({ id: c.id, passed: c.passed })),
      artifact_sha256: candidateArt.sha256,
    }),
  ];

  const baseline_isolation_digest = isolationProofDigest(
    "baseline",
    baselineArt.sha256,
  );
  const candidate_isolation_digest = isolationProofDigest(
    "candidate",
    candidateArt.sha256,
  );

  const public_digests = {
    baseline_artifact_sha256: baselineArt.sha256,
    candidate_artifact_sha256: candidateArt.sha256,
    baseline_isolation_digest,
    candidate_isolation_digest,
    probe_digests: [...probe_digests],
  };

  // Baseline not reproduced → inconclusive (cannot prove fix).
  if (baselineFault !== true) {
    return inconclusive(
      "MEASUREMENT_BASELINE_MISSING",
      "Baseline fault was not positively reproduced; cannot prove fix.",
      {
        profile_id: profile,
        candidate_version,
        baseline_fault_reproduced: false,
        measured_fault_absent: candidateFault === false,
        measured_core_ok: core.passed,
        public_digests,
      },
    );
  }

  const measured_fault_absent = candidateFault === false;
  const measured_core_ok = core.passed === true;

  // Candidate still faulty or core check failure → measured negative.
  if (!measured_fault_absent || !measured_core_ok) {
    return negative(
      `Measured negative (CANDIDATE_REGRESSED): fault_absent=${measured_fault_absent};core_ok=${measured_core_ok}. Artifact-level disposable pair evidence only — not installed-binary identity.`,
      {
        profile_id: profile,
        candidate_version,
        measured_fault_absent,
        measured_core_ok,
        baseline_fault_reproduced: true,
        public_digests,
      },
    );
  }

  const nowMs =
    typeof input.nowMs === "number" && Number.isFinite(input.nowMs)
      ? Math.trunc(input.nowMs)
      : Date.now();
  const nonce = crypto.randomBytes(16).toString("hex");

  const state: AttestationState = {
    profile_id: PROTECTED_PROCESS_SHIM_PROFILE_V1,
    candidate_version,
    baseline_artifact_sha256: baselineArt.sha256,
    candidate_artifact_sha256: candidateArt.sha256,
    baseline_isolation_digest,
    candidate_isolation_digest,
    probe_digests,
    baseline_fault_present: true,
    candidate_fault_present: false,
    candidate_core_ok: true,
    nonce,
    measured_at_ms: nowMs,
    stage: "fresh",
    // Exact realpath from isolation proof — never exported publicly.
    measured_candidate_target_real: candidateReal,
  };

  const witness = mintWitness(state);

  return {
    verdict: "positive",
    profile_id: profile,
    candidate_version,
    measured_fault_absent: true,
    measured_core_ok: true,
    baseline_fault_reproduced: true,
    witness,
    public_digests,
    detail:
      "Positive registered live measurement (protected_process_shim_v1): baseline fault reproduced, candidate fault absent, candidate core health passed. Artifact-level candidate evidence under disposable roots — not cryptographic proof of an installed binary identity.",
    error_code: null,
    evidence_scope: "artifact_level_disposable_pair",
  };
}

export type WitnessAuthorityErrorCode =
  | "LIVE_WITNESS_REQUIRED"
  | "LIVE_WITNESS_INVALID"
  | "LIVE_WITNESS_STAGE"
  | "LIVE_WITNESS_BINDING"
  | "LIVE_WITNESS_REPLAY";

export interface WitnessAuthorityOk {
  ok: true;
  attestation: LiveMeasurementAttestation;
}

export interface WitnessAuthorityFail {
  ok: false;
  code: WitnessAuthorityErrorCode;
  message: string;
}

function publicAttestationView(st: AttestationState): LiveMeasurementAttestation {
  return {
    profile_id: st.profile_id,
    candidate_version: st.candidate_version,
    baseline_artifact_sha256: st.baseline_artifact_sha256,
    candidate_artifact_sha256: st.candidate_artifact_sha256,
    baseline_isolation_digest: st.baseline_isolation_digest,
    candidate_isolation_digest: st.candidate_isolation_digest,
    probe_digests: [...st.probe_digests],
    baseline_fault_present: true,
    candidate_fault_present: false,
    candidate_core_ok: true,
    nonce: st.nonce,
    measured_at_ms: st.measured_at_ms,
    stage: st.stage,
  };
}

function bindingMatch(
  st: AttestationState,
  expected: {
    candidate_version: string;
    profile_id?: string;
    /** Exact canonical target realpath for this operation (required). */
    target_real: string;
  },
): boolean {
  if (st.candidate_version !== expected.candidate_version) return false;
  if (
    expected.profile_id !== undefined &&
    st.profile_id !== expected.profile_id
  ) {
    return false;
  }
  if (st.profile_id !== PROTECTED_PROCESS_SHIM_PROFILE_V1) return false;
  if (st.baseline_fault_present !== true) return false;
  if (st.candidate_fault_present !== false) return false;
  if (st.candidate_core_ok !== true) return false;
  // Exact target identity: witness measured under A never authorizes B.
  if (
    typeof expected.target_real !== "string" ||
    expected.target_real.length === 0 ||
    st.measured_candidate_target_real !== expected.target_real
  ) {
    return false;
  }
  return true;
}

/**
 * Record canary under live measurement authority.
 * Advances fresh → canary_recorded only when the caller has already established
 * the successful measured-canary branch (executed + fault absent + core ok)
 * and target/version/profile bind. Plain objects / clones / failed canaries
 * never reach this mutator with authority; stage is not advanced on mismatch.
 */
export function recordCanaryWithLiveWitness(
  witness: unknown,
  expected: {
    candidate_version: string;
    profile_id?: string;
    target_real: string;
  },
): WitnessAuthorityOk | WitnessAuthorityFail {
  if (!isWitnessObject(witness)) {
    return {
      ok: false,
      code: "LIVE_WITNESS_REQUIRED",
      message:
        "Process-local live measurement witness required; caller booleans/JSON cannot authorize RECOMMEND_UPGRADE.",
    };
  }
  const st = liveMeasurementStore.get(witness as object);
  if (!st) {
    return {
      ok: false,
      code: "LIVE_WITNESS_INVALID",
      message: "Live measurement witness not recognized in this process.",
    };
  }
  if (st.stage === "consumed") {
    return {
      ok: false,
      code: "LIVE_WITNESS_REPLAY",
      message: "Live measurement witness already consumed; replay refused.",
    };
  }
  if (st.stage !== "fresh") {
    return {
      ok: false,
      code: "LIVE_WITNESS_STAGE",
      message: `Live measurement witness stage refused for canary: ${st.stage}.`,
    };
  }
  if (!bindingMatch(st, expected)) {
    return {
      ok: false,
      code: "LIVE_WITNESS_BINDING",
      message: "Live measurement witness binding mismatch for canary.",
    };
  }
  st.stage = "canary_recorded";
  return {
    ok: true,
    attestation: publicAttestationView(st),
  };
}

/**
 * Consume witness for supersession.
 * Requires stage canary_recorded, exact target binding, then consumed (one-shot).
 * Target/version/profile mismatch fails closed without consuming the witness.
 */
export function consumeWitnessForSupersede(
  witness: unknown,
  expected: {
    candidate_version: string;
    profile_id?: string;
    target_real: string;
  },
): WitnessAuthorityOk | WitnessAuthorityFail {
  if (!isWitnessObject(witness)) {
    return {
      ok: false,
      code: "LIVE_WITNESS_REQUIRED",
      message:
        "Process-local live measurement witness required; verified/measured booleans cannot authorize supersession.",
    };
  }
  const st = liveMeasurementStore.get(witness as object);
  if (!st) {
    return {
      ok: false,
      code: "LIVE_WITNESS_INVALID",
      message: "Live measurement witness not recognized in this process.",
    };
  }
  if (st.stage === "consumed") {
    return {
      ok: false,
      code: "LIVE_WITNESS_REPLAY",
      message: "Live measurement witness already consumed; replay refused.",
    };
  }
  if (st.stage !== "canary_recorded") {
    return {
      ok: false,
      code: "LIVE_WITNESS_STAGE",
      message: `Live measurement witness stage refused for supersession: ${st.stage}.`,
    };
  }
  if (!bindingMatch(st, expected)) {
    return {
      ok: false,
      code: "LIVE_WITNESS_BINDING",
      message: "Live measurement witness binding mismatch for supersession.",
    };
  }
  st.stage = "consumed";
  return {
    ok: true,
    attestation: publicAttestationView(st),
  };
}
