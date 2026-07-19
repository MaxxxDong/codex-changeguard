/**
 * Unified privacy zero-leak corpus (Ticket 16).
 *
 * Proves external_disclosure_count === 0 across instrumented outbound seams.
 * Stdout redaction alone is NOT sufficient — scans payload JSON, transport
 * requests, capsule/doctor export shapes.
 *
 * Each secret class is injected through every relevant sendable scalar/list
 * field on an approved instrumented transport path; each resulting request is
 * scanned. Failure output never prints secret corpus values (hashes/labels only).
 *
 * Required product module/API absence or incompatible shape fails GATE_PRIVACY
 * (fail-closed; no silent optional catch-and-continue).
 */

import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import path from "node:path";

/** Synthetic secret labels — actual values live only inside this module for scan. */
const SECRETS = Object.freeze({
  token: ["cg-t16-", "token-AAAA1111BBBB2222CCCC3333"].join(""),
  bearer: "Bearer cg-t16-sk-live-XYZNOTREAL0001",
  // High-confidence GitHub PAT shapes (synthetic; never live credentials).
  ghp: ["gh", "p_", "cgT16GitHubPatNOTREAL0001ABCDEF"].join(""),
  githubPat: [
    "github",
    "_pat_",
    "11CGT16NOTREAL_abcdefghijklmnopqrstuvwx",
  ].join(""),
  cookie: "Cookie: session_id=cg-t16-cookie-value-DEADBEEF",
  setCookie: "Set-Cookie: cg_sess=cg-t16-setcookie-FF00AA; Path=/",
  password: ["password=", "cg-t16-hunter-NOTREAL"].join(""),
  otp: "one-time-code=847291",
  otpAlt: "otp=847291",
  envDump: [
    "process.env={HOME:/Users/cg-t16-user,",
    "API_",
    "KEY=",
    "cg-t16-env-secret-KEY99,PATH:/usr/bin}",
  ].join(""),
  posixPath: "/Users/cg-t16-user/.codex/auth.json",
  winPath: "C:\\Users\\cg-t16-user\\AppData\\Roaming\\Codex\\secrets.txt",
  uncPath: "\\\\server\\share\\cg-t16\\session.rollout",
  sessionRollout:
    "session_rollout_content=COMPLETE_ROLLOUT_BODY_cg-t16-session-payload-NOEXPORT",
  projectSource: "export const secretKey = 'cg-t16-project-source-leak';",
  nestedJson: JSON.stringify({
    nested: {
      token: ["cg-t16-nested-", "token-ZZ99"].join(""),
      cookie: "cg-t16-nested-cookie",
      env: { API_KEY: ["cg-t16-nested-", "env"].join("") },
    },
  }),
  fullWidth: "ＡＰＩ＿ＫＥＹ＝ｃｇｔ１６ｆｕｌｌｗｉｄｔｈｓｅｃｒｅｔ",
});

/** Root-confirmed outbound smuggle payloads (exact reproductions). */
const ROOT_SMUGGLE = Object.freeze([
  SECRETS.cookie,
  SECRETS.otp,
  SECRETS.sessionRollout,
]);

/** Labels for reporting (never the raw values). */
export const PRIVACY_CORPUS_LABELS = Object.freeze(Object.keys(SECRETS));

/** Sendable scalar fields on OfficialTransportRequest / local_context. */
const SENDABLE_SCALARS = Object.freeze([
  "codex_version",
  "surface",
  "platform_os",
  "platform_arch",
  "error_class",
]);

/** Sendable list fields. */
const SENDABLE_LISTS = Object.freeze(["config_keys", "feature_ids"]);

function digestLabel(label) {
  return crypto.createHash("sha256").update(label).digest("hex").slice(0, 12);
}

/**
 * Values that must never appear in outbound instrumented payloads.
 * @returns {string[]}
 */
export function secretValues() {
  return Object.values(SECRETS);
}

/**
 * Build a multi-class adversarial free-text blob for injection into seams.
 * Callers should feed this into local context fields that go through redaction
 * or must be device-only.
 */
export function buildAdversarialCorpusText() {
  return [
    SECRETS.token,
    SECRETS.bearer,
    SECRETS.ghp,
    SECRETS.githubPat,
    SECRETS.cookie,
    SECRETS.setCookie,
    SECRETS.password,
    SECRETS.otp,
    SECRETS.otpAlt,
    SECRETS.envDump,
    SECRETS.posixPath,
    SECRETS.winPath,
    SECRETS.uncPath,
    SECRETS.sessionRollout,
    SECRETS.projectSource,
    SECRETS.nestedJson,
    SECRETS.fullWidth,
  ].join(" | ");
}

/**
 * Scan any JSON-serializable payload for secret substrings.
 * @param {unknown} payload
 * @param {string[]} secrets
 * @returns {{ leaks: { label_digest: string, seam: string }[], external_disclosure_count: number }}
 */
export function scanPayloadForSecrets(payload, secrets = secretValues(), seam = "payload") {
  const text = stableStringify(payload);
  /** @type {{ label_digest: string, seam: string }[]} */
  const leaks = [];
  const labels = Object.entries(SECRETS);
  for (const [label, value] of labels) {
    if (value && text.includes(value)) {
      leaks.push({ label_digest: digestLabel(label), seam });
    }
  }
  // Also catch NFKC-normalized full-width secret after normalization
  const nfkc = text.normalize("NFKC");
  const nfkcSecret = SECRETS.fullWidth.normalize("NFKC");
  if (nfkc.includes(nfkcSecret) && !leaks.some((l) => l.label_digest === digestLabel("fullWidth"))) {
    if (nfkc.includes("cgt16fullwidthsecret") || nfkc.includes(nfkcSecret)) {
      if (nfkc.includes("cgt16fullwidthsecret")) {
        leaks.push({ label_digest: digestLabel("fullWidth"), seam: `${seam}:nfkc` });
      }
    }
  }
  // Generic env dump / session markers
  for (const marker of [
    "cg-t16-env-secret-KEY99",
    "COMPLETE_ROLLOUT_BODY_cg-t16",
    "cg-t16-project-source-leak",
    "cg-t16-nested-token-ZZ99",
    "cg-t16-cookie-value-DEADBEEF",
    "cg-t16-setcookie-FF00AA",
    "cg-t16-hunter-NOTREAL",
    "cg-t16-sk-live-XYZNOTREAL0001",
    "cg-t16-token-AAAA1111BBBB2222CCCC3333",
    SECRETS.ghp,
    SECRETS.githubPat,
    "/Users/cg-t16-user",
    "C:\\\\Users\\\\cg-t16-user",
    "\\\\server\\\\share\\\\cg-t16",
  ]) {
    if (text.includes(marker) || nfkc.includes(marker)) {
      leaks.push({ label_digest: digestLabel(marker.slice(0, 16)), seam });
    }
  }
  // de-dupe
  const seen = new Set();
  const unique = [];
  for (const l of leaks) {
    const k = `${l.seam}:${l.label_digest}`;
    if (seen.has(k)) continue;
    seen.add(k);
    unique.push(l);
  }
  return {
    leaks: unique,
    external_disclosure_count: unique.length,
  };
}

function stableStringify(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Bounded base local context with only legitimate identifier tokens.
 */
function cleanBaseContext() {
  return {
    codex_version: "0.50.0",
    surface: "browser_control",
    platform_os: "macos",
    platform_arch: "arm64",
    config_keys: ["shell_environment_policy.set"],
    feature_ids: ["browser"],
    error_class: "Error",
  };
}

/**
 * Load a required dist module; fail closed with GATE_PRIVACY detail label.
 * @param {string} repoRoot
 * @param {string} relDist path under dist/
 * @param {string} detailLabel
 */
async function loadRequiredDist(repoRoot, relDist, detailLabel) {
  const abs = path.join(repoRoot, relDist);
  try {
    return await import(pathToFileURL(abs).href);
  } catch {
    return {
      __privacy_load_error: true,
      detail: detailLabel,
    };
  }
}

/**
 * Run the privacy gate using product modules from dist/ (compiled).
 * Fail closed if dist is missing (typecheck/build must precede pure steps when
 * ordered after typecheck; verify-release runs pure steps after tests/build).
 *
 * @param {string} repoRoot
 * @param {{ poisonPayload?: unknown }} [opts]
 * Product modules are always required on the non-poison path (fail-closed).
 * There is no skipProduct / optional-product mode that can green-wash proofs.
 */
export async function checkPrivacyCorpus(repoRoot, opts = {}) {
  /** @type {{ label_digest: string, seam: string }[]} */
  let allLeaks = [];
  let external_disclosure_count = 0;

  // 1) Poisoned payload self-check path for negative tests
  if (opts.poisonPayload !== undefined) {
    const scan = scanPayloadForSecrets(opts.poisonPayload, secretValues(), "poison");
    allLeaks = scan.leaks;
    external_disclosure_count = scan.external_disclosure_count;
    return failOrOk(allLeaks, external_disclosure_count, "poison_mode");
  }

  // 2) Static corpus: redactText must not leave raw secrets (product redactor)
  const redactLoad = await loadRequiredDist(
    repoRoot,
    "dist/core/redact.js",
    "privacy_dist_redact_unavailable",
  );
  if (redactLoad.__privacy_load_error) {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count: -1,
      leaks: [],
      detail: redactLoad.detail,
    };
  }
  const redactText = redactLoad.redactText;
  const nfkc = redactLoad.nfkc;
  if (typeof redactText !== "function" || typeof nfkc !== "function") {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count: -1,
      leaks: [],
      detail: "privacy_redact_api_incompatible",
    };
  }

  const corpus = buildAdversarialCorpusText();
  const redacted = redactText(corpus);

  // Redactor must strip credential-shaped + absolute path forms (stdout seam).
  // Free-text markers that are not credential-shaped (bare synthetic token ids,
  // OTP digits, session-rollout, project-source) are proven absent from
  // *outbound* transport/capsule below — not required to vanish from redactText.
  const mustRedactLabels = [
    "bearer",
    "ghp",
    "githubPat",
    "cookie",
    "setCookie",
    "password",
    "posixPath",
    "winPath",
    "uncPath",
    "fullWidth",
  ];
  for (const label of mustRedactLabels) {
    const value = SECRETS[label];
    if (value && redacted.includes(value)) {
      allLeaks.push({ label_digest: digestLabel(label), seam: "redact_raw_remain" });
    }
  }
  if (redacted.includes("/Users/cg-t16-user")) {
    allLeaks.push({ label_digest: digestLabel("posixPath"), seam: "redact_path" });
  }
  if (redacted.includes("C:\\Users\\cg-t16-user")) {
    allLeaks.push({ label_digest: digestLabel("winPath"), seam: "redact_win" });
  }
  if (redacted.includes("\\\\server\\share\\cg-t16")) {
    allLeaks.push({ label_digest: digestLabel("uncPath"), seam: "redact_unc" });
  }
  const redactedNfkc = nfkc(redacted);
  if (redactedNfkc.includes("cgt16fullwidthsecret")) {
    allLeaks.push({ label_digest: digestLabel("fullWidth"), seam: "redact_fullwidth" });
  }
  if (redacted.includes("cg-t16-env-secret-KEY99")) {
    allLeaks.push({ label_digest: digestLabel("envDump"), seam: "redact_env" });
  }

  // 3) Required evidence modules — fail closed if missing/incompatible
  const discLoad = await loadRequiredDist(
    repoRoot,
    "dist/evidence/disclosure.js",
    "privacy_dist_disclosure_unavailable",
  );
  if (discLoad.__privacy_load_error) {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count: -1,
      leaks: [],
      detail: discLoad.detail,
    };
  }
  const buildDisclosureManifest = discLoad.buildDisclosureManifest;
  const buildTransportRequest = discLoad.buildTransportRequest;
  const sanitizeSendableLocalFields = discLoad.sanitizeSendableLocalFields;
  const isSendableDisclosureToken = discLoad.isSendableDisclosureToken;
  if (
    typeof buildDisclosureManifest !== "function" ||
    typeof buildTransportRequest !== "function" ||
    typeof sanitizeSendableLocalFields !== "function" ||
    typeof isSendableDisclosureToken !== "function"
  ) {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count: -1,
      leaks: [],
      detail: "privacy_disclosure_api_incompatible",
    };
  }

  const refreshLoad = await loadRequiredDist(
    repoRoot,
    "dist/evidence/refresh.js",
    "privacy_dist_refresh_unavailable",
  );
  if (refreshLoad.__privacy_load_error) {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count: -1,
      leaks: [],
      detail: refreshLoad.detail,
    };
  }
  const refreshOfficialEvidence = refreshLoad.refreshOfficialEvidence;
  if (typeof refreshOfficialEvidence !== "function") {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count: -1,
      leaks: [],
      detail: "privacy_refresh_api_incompatible",
    };
  }

  const transportLoad = await loadRequiredDist(
    repoRoot,
    "dist/evidence/transport.js",
    "privacy_dist_transport_unavailable",
  );
  if (transportLoad.__privacy_load_error) {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count: -1,
      leaks: [],
      detail: transportLoad.detail,
    };
  }
  const createFakeTransport = transportLoad.createFakeTransport;
  const instrumentTransport = transportLoad.instrumentTransport;
  if (typeof createFakeTransport !== "function" || typeof instrumentTransport !== "function") {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count: -1,
      leaks: [],
      detail: "privacy_transport_api_incompatible",
    };
  }

  const snapshotPath = path.join(repoRoot, "fixtures/official-evidence/snapshot.json");
  const corpusEntries = Object.entries(SECRETS);

  // --- Product token invariant: every secret class rejected as sendable token ---
  // isSendableDisclosureToken is required above (fail-closed); no optional skip.
  for (const [label, value] of corpusEntries) {
    if (isSendableDisclosureToken(value)) {
      allLeaks.push({
        label_digest: digestLabel(label),
        seam: "sendable_token_accepted",
      });
    }
  }
  for (const smuggle of ROOT_SMUGGLE) {
    if (isSendableDisclosureToken(smuggle)) {
      allLeaks.push({
        label_digest: digestLabel("root_smuggle"),
        seam: "sendable_token_root",
      });
    }
  }

  // --- Direct buildTransportRequest: inject each secret into every scalar/list field ---
  {
    const base = cleanBaseContext();
    for (const [label, value] of corpusEntries) {
      for (const field of SENDABLE_SCALARS) {
        const local_context = { ...base, [field]: value };
        const sendable = sanitizeSendableLocalFields(local_context);
        const scanSendable = scanPayloadForSecrets(
          sendable,
          secretValues(),
          `sanitize_scalar:${field}`,
        );
        allLeaks.push(...scanSendable.leaks);
        // Field must be omitted (not present with corpus value)
        if (sendable[field] !== undefined && stableStringify(sendable[field]).includes(value)) {
          allLeaks.push({
            label_digest: digestLabel(label),
            seam: `sanitize_scalar_leak:${field}`,
          });
        }
        const manifest = buildDisclosureManifest(local_context);
        const outbound = buildTransportRequest(manifest, local_context);
        const oScan = scanPayloadForSecrets(
          outbound,
          secretValues(),
          `outbound_scalar:${field}`,
        );
        allLeaks.push(...oScan.leaks);
      }
      for (const field of SENDABLE_LISTS) {
        const local_context = { ...base, [field]: [value, "safe.id"] };
        const sendable = sanitizeSendableLocalFields(local_context);
        const scanSendable = scanPayloadForSecrets(
          sendable,
          secretValues(),
          `sanitize_list:${field}`,
        );
        allLeaks.push(...scanSendable.leaks);
        if (Array.isArray(sendable[field])) {
          for (const item of sendable[field]) {
            if (typeof item === "string" && item.includes(value)) {
              allLeaks.push({
                label_digest: digestLabel(label),
                seam: `sanitize_list_leak:${field}`,
              });
            }
          }
        }
        const manifest = buildDisclosureManifest(local_context);
        const outbound = buildTransportRequest(manifest, local_context);
        const oScan = scanPayloadForSecrets(
          outbound,
          secretValues(),
          `outbound_list:${field}`,
        );
        allLeaks.push(...oScan.leaks);
      }
    }

    // Exact Root reproductions on error_class
    for (const smuggle of ROOT_SMUGGLE) {
      const local_context = { ...base, error_class: smuggle };
      const manifest = buildDisclosureManifest(local_context);
      const outbound = buildTransportRequest(manifest, local_context);
      const text = stableStringify(outbound);
      if (text.includes(smuggle)) {
        allLeaks.push({
          label_digest: digestLabel("root_error_class"),
          seam: "outbound_root_smuggle",
        });
      }
      // Distinctive substrings must not appear either
      for (const marker of [
        "cg-t16-cookie-value-DEADBEEF",
        "847291",
        "COMPLETE_ROLLOUT_BODY_cg-t16",
      ]) {
        if (text.includes(marker)) {
          allLeaks.push({
            label_digest: digestLabel(marker.slice(0, 16)),
            seam: "outbound_root_marker",
          });
        }
      }
      // error_class must be omitted entirely when smuggled
      if (outbound.error_class !== undefined) {
        allLeaks.push({
          label_digest: digestLabel("root_error_class_present"),
          seam: "outbound_root_field_present",
        });
      }
    }
  }

  // --- Refusal path: zero transport calls ---
  {
    const fake = instrumentTransport(
      createFakeTransport({
        fetched_at: "2026-07-10T00:00:00.000Z",
        items: [],
      }),
    );
    const poisonedLocal = {
      ...cleanBaseContext(),
      error_class: SECRETS.cookie,
      config_keys: [SECRETS.otp, SECRETS.sessionRollout],
      feature_ids: [SECRETS.projectSource],
      _device_only_blob: corpus,
    };
    const refresh = refreshOfficialEvidence({
      disclosure_decision: "refused",
      transport: fake,
      snapshot_path: snapshotPath,
      now_ms: Date.parse("2026-07-11T00:00:00.000Z"),
      local_context: poisonedLocal,
    });
    if (refresh.transport_calls !== 0 || fake.callCount !== 0 || refresh.transport_request !== null) {
      allLeaks.push({
        label_digest: digestLabel("transport_refuse"),
        seam: "transport_refuse_nonzero",
      });
    }
    const scan = scanPayloadForSecrets(
      { request: refresh.transport_request, refresh },
      secretValues(),
      "transport_refuse",
    );
    allLeaks.push(...scan.leaks);
  }

  // --- Approved path: inject full corpus via every sendable field (instrumented) ---
  {
    // Matrix: for each secret, approved refresh with that secret in error_class
    // and list fields — request must never contain corpus.
    for (const [label, value] of corpusEntries) {
      const fake = instrumentTransport(
        createFakeTransport({
          fetched_at: "2026-07-10T11:00:00.000Z",
          items: [],
        }),
      );
      const local_context = {
        codex_version: value,
        surface: value,
        platform_os: value,
        platform_arch: value,
        config_keys: [value],
        feature_ids: [value],
        error_class: value,
      };
      const refresh = refreshOfficialEvidence({
        disclosure_decision: "approved",
        transport: fake,
        snapshot_path: snapshotPath,
        now_ms: Date.parse("2026-07-11T00:00:00.000Z"),
        local_context,
      });
      const req =
        refresh.transport_request ?? (fake.callCount > 0 ? fake.calls[0] : null);
      const reqScan = scanPayloadForSecrets(
        req,
        secretValues(),
        `transport_approved:${label}`,
      );
      allLeaks.push(...reqScan.leaks);
      // Also scan fake call log
      if (fake.calls && fake.calls.length > 0) {
        for (let i = 0; i < fake.calls.length; i++) {
          const cScan = scanPayloadForSecrets(
            fake.calls[i],
            secretValues(),
            `transport_call:${label}`,
          );
          allLeaks.push(...cScan.leaks);
        }
      }
    }

    // Clean legitimate approved path still works and has zero secrets
    {
      const fake = instrumentTransport(
        createFakeTransport({
          fetched_at: "2026-07-10T11:00:00.000Z",
          items: [],
        }),
      );
      const local_context = cleanBaseContext();
      const refresh = refreshOfficialEvidence({
        disclosure_decision: "approved",
        transport: fake,
        snapshot_path: snapshotPath,
        now_ms: Date.parse("2026-07-11T00:00:00.000Z"),
        local_context,
      });
      const req =
        refresh.transport_request ?? (fake.callCount > 0 ? fake.calls[0] : null);
      const reqScan = scanPayloadForSecrets(req, secretValues(), "transport_approved_clean");
      allLeaks.push(...reqScan.leaks);
      // Capsule-like envelope must not embed corpus
      const capsuleLike = {
        transport_request: req,
        privacy_review: {
          secrets_redacted: true,
          paths_redacted: true,
          session_excluded: true,
        },
      };
      const cScan = scanPayloadForSecrets(capsuleLike, secretValues(), "capsule_export");
      allLeaks.push(...cScan.leaks);
    }
  }

  // --- Doctor sanitization: required module; forbidden keys + allowlisted free-text ---
  {
    const doctorLoad = await loadRequiredDist(
      repoRoot,
      "dist/upstream/doctor.js",
      "privacy_dist_doctor_unavailable",
    );
    if (doctorLoad.__privacy_load_error) {
      return {
        ok: false,
        reason_code: "GATE_PRIVACY",
        external_disclosure_count: -1,
        leaks: allLeaks.map((l) => ({
          label_digest: l.label_digest,
          seam: l.seam,
        })),
        detail: doctorLoad.detail,
      };
    }
    const sanitizeDoctorJson = doctorLoad.sanitizeDoctorJson;
    if (typeof sanitizeDoctorJson !== "function") {
      return {
        ok: false,
        reason_code: "GATE_PRIVACY",
        external_disclosure_count: -1,
        leaks: [],
        detail: "privacy_doctor_api_incompatible",
      };
    }

    // Forbidden keys: must throw / refuse, never emit secrets
    const forbiddenPayloads = [
      { token: SECRETS.token },
      { cookie: SECRETS.cookie },
      { session: SECRETS.sessionRollout },
      { env: SECRETS.envDump },
      { password: SECRETS.password },
      { access_token: SECRETS.bearer },
    ];
    for (const payload of forbiddenPayloads) {
      let doctorOut;
      try {
        doctorOut = sanitizeDoctorJson(payload);
        // If it returns without throw, scan output — secrets must be absent
        const dScan = scanPayloadForSecrets(doctorOut, secretValues(), "doctor_forbidden_key");
        allLeaks.push(...dScan.leaks);
      } catch (err) {
        // Expected fail-closed; error message must not contain corpus values
        const msg = err && typeof err === "object" && "message" in err ? String(err.message) : String(err);
        const eScan = scanPayloadForSecrets(msg, secretValues(), "doctor_error_msg");
        allLeaks.push(...eScan.leaks);
      }
    }

    // Allowlisted free-text fields with sensitive values — must redact.
    // Inject credential/path/OTP/session shapes that product redaction handles;
    // bare synthetic token ids without key= form are proven on transport only.
    const freeTextDoctor = {
      schema_version: 1,
      codex_version: "0.50.0",
      summary: [
        SECRETS.cookie,
        SECRETS.bearer,
        SECRETS.password,
        SECRETS.otp,
        SECRETS.sessionRollout,
        SECRETS.posixPath,
        SECRETS.winPath,
        SECRETS.envDump,
        SECRETS.fullWidth,
      ].join(" | "),
      status: SECRETS.cookie,
      checks: [SECRETS.otp, SECRETS.sessionRollout, SECRETS.posixPath],
      platform: SECRETS.envDump,
    };
    let doctorFree;
    try {
      doctorFree = sanitizeDoctorJson(freeTextDoctor);
    } catch (err) {
      // Fail-closed reject is acceptable; still scan error text
      const msg = err && typeof err === "object" && "message" in err ? String(err.message) : String(err);
      const eScan = scanPayloadForSecrets(msg, secretValues(), "doctor_freetext_error");
      allLeaks.push(...eScan.leaks);
      doctorFree = { blocked: true };
    }
    const freeScan = scanPayloadForSecrets(doctorFree, secretValues(), "doctor_export");
    allLeaks.push(...freeScan.leaks);
    // Distinctive markers in doctor export
    const freeText = stableStringify(doctorFree);
    for (const marker of [
      "cg-t16-cookie-value-DEADBEEF",
      "COMPLETE_ROLLOUT_BODY_cg-t16",
      "cg-t16-project-source-leak",
      "/Users/cg-t16-user",
      "cg-t16-env-secret-KEY99",
    ]) {
      if (freeText.includes(marker)) {
        allLeaks.push({
          label_digest: digestLabel(marker.slice(0, 16)),
          seam: "doctor_export_marker",
        });
      }
    }
  }

  // de-dupe
  const seen = new Set();
  const unique = [];
  for (const l of allLeaks) {
    const k = `${l.seam}:${l.label_digest}`;
    if (seen.has(k)) continue;
    seen.add(k);
    unique.push(l);
  }
  external_disclosure_count = unique.length;
  return failOrOk(unique, external_disclosure_count, "privacy_corpus");
}

function failOrOk(leaks, external_disclosure_count, detail) {
  if (external_disclosure_count !== 0) {
    return {
      ok: false,
      reason_code: "GATE_PRIVACY",
      external_disclosure_count,
      // Never include secret values — digests and seams only
      leaks: leaks.map((l) => ({ label_digest: l.label_digest, seam: l.seam })),
      detail: `${detail}_failed`,
    };
  }
  return {
    ok: true,
    reason_code: null,
    external_disclosure_count: 0,
    leaks: [],
    detail: `${detail}_ok`,
  };
}
