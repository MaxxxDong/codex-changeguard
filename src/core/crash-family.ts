/**
 * Ticket 09 — Windows Desktop in-app Browser crash-family classifier.
 *
 * Deterministic gates separate exception/process/timing/page/concurrency
 * families. Title similarity alone cannot produce high confidence or
 * root-cause attribution. Optional model ranking cannot override hard gates
 * or invent provenance. No dump contents; natural-failure metadata preferred.
 * Without isolation, active crash probes are refused.
 */

import type {
  AxisAssessment,
  CrashClassificationResult,
  CrashMetadata,
  IncidentFingerprint,
  RankedIssueCandidate,
} from "./types.js";

/** Registered upstream issue catalog for Fixture E families (open at snapshot). */
export interface CrashFamilyCatalogEntry {
  issue_id: string;
  family_id: string;
  /** Hard-required OS values; empty means any. */
  platforms: Array<"windows" | "macos" | "linux" | "unknown">;
  /** Compatible surfaces; empty means any desktop-ish. */
  surfaces: Array<IncidentFingerprint["surface"]>;
  exception_codes: string[];
  /** Normalized module basenames (lowercase). */
  modules: string[];
  /** Faulting symbols (case-sensitive match after trim). */
  symbols: string[];
  /** Offset buckets as normalized hex (lowercase, no leading zeros pad). */
  offset_buckets: string[];
  interaction_phases: NonNullable<CrashMetadata["interaction_phase"]>[];
  page_capabilities: NonNullable<CrashMetadata["page_capability"]>[];
  concurrency_contexts: NonNullable<CrashMetadata["concurrency_context"]>[];
  gpu_child_exit_codes: number[];
  gpu_relaunch_codes: number[];
  components: string[];
  /** Lexical title tokens used only for recall, never high confidence alone. */
  title_tokens: string[];
  /** Verified Issue/PR/commit/release fix linkage present? Always false for MVP catalog. */
  fix_linked: boolean;
  /** Safe local repair applicability for authorization eligibility. Always false here. */
  safe_fix_applicable: boolean;
}

/**
 * Canonical Fixture E catalog. Order is stable for deterministic ranking ties.
 * All entries are open user-reported Issues without verified fix linkage.
 */
export const CRASH_FAMILY_CATALOG: readonly CrashFamilyCatalogEntry[] = [
  {
    issue_id: "openai/codex#32683",
    family_id: "access_violation_crbrowser_dom_ready",
    platforms: ["windows"],
    surfaces: ["desktop", "browser_control"],
    exception_codes: ["0xc0000005"],
    modules: ["chrome.dll"],
    symbols: ["CrBrowserMain"],
    offset_buckets: ["0x2e08f46"],
    interaction_phases: ["neutral_dom_ready"],
    page_capabilities: ["neutral"],
    concurrency_contexts: ["single", "unknown"],
    gpu_child_exit_codes: [],
    gpu_relaunch_codes: [],
    components: ["in_app_browser", "chromium_browser_main"],
    title_tokens: ["browser", "crash", "desktop", "windows", "dom"],
    fix_linked: false,
    safe_fix_applicable: false,
  },
  {
    issue_id: "openai/codex#33710",
    family_id: "cpp_exception_interaction",
    platforms: ["windows"],
    surfaces: ["desktop", "browser_control"],
    exception_codes: ["0xc06d007f"],
    modules: ["chatgpt.exe", "codex.exe"],
    symbols: [],
    offset_buckets: [],
    interaction_phases: ["link_click", "button_click"],
    page_capabilities: ["neutral", "unknown"],
    concurrency_contexts: ["single", "unknown"],
    gpu_child_exit_codes: [],
    gpu_relaunch_codes: [],
    components: ["in_app_browser", "desktop_shell"],
    title_tokens: ["browser", "crash", "click", "link", "windows"],
    fix_linked: false,
    safe_fix_applicable: false,
  },
  {
    issue_id: "openai/codex#32094",
    family_id: "gpu_child_relaunch_media",
    platforms: ["windows"],
    surfaces: ["desktop", "browser_control"],
    exception_codes: [],
    modules: [],
    symbols: [],
    offset_buckets: [],
    interaction_phases: ["media_canvas", "neutral_dom_ready", "unknown"],
    page_capabilities: ["media", "canvas"],
    concurrency_contexts: ["single", "unknown"],
    gpu_child_exit_codes: [101457950],
    gpu_relaunch_codes: [18],
    components: ["gpu_process", "in_app_browser"],
    title_tokens: ["browser", "crash", "gpu", "media", "canvas"],
    fix_linked: false,
    safe_fix_applicable: false,
  },
  {
    issue_id: "openai/codex#33202",
    family_id: "concurrency_webview_attach",
    platforms: ["windows"],
    surfaces: ["desktop", "browser_control"],
    exception_codes: [],
    modules: [],
    symbols: [],
    offset_buckets: [],
    interaction_phases: ["webview_attach"],
    page_capabilities: ["neutral", "unknown"],
    concurrency_contexts: ["multi_side_chat"],
    gpu_child_exit_codes: [],
    gpu_relaunch_codes: [],
    components: ["in_app_browser", "webview"],
    title_tokens: ["browser", "crash", "side", "chat", "webview", "concurrent"],
    fix_linked: false,
    safe_fix_applicable: false,
  },
  {
    issue_id: "openai/codex#33762",
    family_id: "complex_page_silent_exit",
    platforms: ["windows"],
    surfaces: ["desktop", "browser_control"],
    exception_codes: [],
    modules: [],
    symbols: [],
    offset_buckets: [],
    interaction_phases: ["unknown", "neutral_dom_ready"],
    page_capabilities: ["complex_login"],
    concurrency_contexts: ["single", "unknown"],
    gpu_child_exit_codes: [],
    gpu_relaunch_codes: [],
    components: ["in_app_browser", "bundled_plugin"],
    title_tokens: ["browser", "crash", "login", "cloudflare", "disable"],
    fix_linked: false,
    safe_fix_applicable: false,
  },
] as const;

const CANDIDATE_THRESHOLD = 0.55;
const HIGH_CONFIDENCE_THRESHOLD = 0.82;

export function normalizeExceptionCode(code: string | null | undefined): string | null {
  if (code === null || code === undefined) return null;
  const t = code.trim().toLowerCase();
  if (!t) return null;
  // Accept 0x… or bare hex; normalize to 0x-prefixed lowercase.
  if (/^0x[0-9a-f]+$/.test(t)) return t;
  if (/^[0-9a-f]+$/.test(t)) return `0x${t}`;
  return t;
}

export function normalizeOffsetBucket(
  offset: string | null | undefined,
): string | null {
  if (offset === null || offset === undefined) return null;
  const t = offset.trim().toLowerCase();
  if (!t) return null;
  if (/^0x[0-9a-f]+$/.test(t)) return t;
  if (/^[0-9a-f]+$/.test(t)) return `0x${t}`;
  return t;
}

export function normalizeModuleName(mod: string | null | undefined): string | null {
  if (mod === null || mod === undefined) return null;
  const base = mod.trim().toLowerCase().replace(/\\/g, "/").split("/").pop() ?? "";
  return base || null;
}

function axis(
  status: AxisAssessment["status"],
  summary: string,
  score: number | null = null,
): AxisAssessment {
  return { status, summary, score };
}

function hasStructuralSignal(meta: CrashMetadata | null | undefined): boolean {
  if (!meta) return false;
  return Boolean(
    normalizeExceptionCode(meta.exception_code) ||
      normalizeModuleName(meta.faulting_module) ||
      (meta.faulting_symbol && meta.faulting_symbol.trim()) ||
      normalizeOffsetBucket(meta.offset_bucket) ||
      meta.gpu_child_exit_code !== null ||
      meta.gpu_relaunch_code !== null ||
      (meta.concurrency_context && meta.concurrency_context !== "unknown") ||
      (meta.interaction_phase && meta.interaction_phase !== "unknown") ||
      (meta.page_capability &&
        meta.page_capability !== "unknown" &&
        meta.page_capability !== "neutral"),
  );
}

function isBrowserishSurface(surface: IncidentFingerprint["surface"]): boolean {
  return surface === "desktop" || surface === "browser_control";
}

function isBrowserCrashIncident(fp: IncidentFingerprint): boolean {
  const meta = fp.crash_metadata;
  if (meta) return true;
  // Lightweight detection from error class / features when metadata omitted.
  const cls = fp.error.class.toLowerCase();
  if (cls.includes("access_violation") || cls.includes("native_crash")) return true;
  if (fp.feature_ids?.includes("in_app_browser") === true) return true;
  if (
    fp.error.normalized_message.toLowerCase().includes("browser") &&
    fp.error.normalized_message.toLowerCase().includes("crash")
  ) {
    return true;
  }
  return false;
}

interface ScoredCandidate {
  entry: CrashFamilyCatalogEntry;
  score: number;
  hard_gated: boolean;
  gate_reasons: string[];
  structural_hits: number;
  title_only: boolean;
}

function scoreCandidate(
  entry: CrashFamilyCatalogEntry,
  fp: IncidentFingerprint,
  meta: CrashMetadata | null,
  modelPreferred: string[] | null,
): ScoredCandidate {
  const gate_reasons: string[] = [];
  let hard_gated = false;

  // Platform hard gate
  if (entry.platforms.length > 0 && !entry.platforms.includes(fp.platform.os)) {
    hard_gated = true;
    gate_reasons.push(
      `platform_incompatible:${fp.platform.os}!=${entry.platforms.join("|")}`,
    );
  }

  // Surface hard gate
  if (entry.surfaces.length > 0 && !entry.surfaces.includes(fp.surface)) {
    hard_gated = true;
    gate_reasons.push(`surface_incompatible:${fp.surface}`);
  }

  const exc = normalizeExceptionCode(meta?.exception_code ?? null);
  const mod = normalizeModuleName(meta?.faulting_module ?? null);
  const sym = meta?.faulting_symbol?.trim() ?? null;
  const off = normalizeOffsetBucket(meta?.offset_bucket ?? null);
  const phase = meta?.interaction_phase ?? null;
  const pageCap = meta?.page_capability ?? null;
  const conc = meta?.concurrency_context ?? null;
  const gpuExit = meta?.gpu_child_exit_code ?? null;
  const gpuRel = meta?.gpu_relaunch_code ?? null;
  const component = meta?.component?.trim().toLowerCase() ?? null;

  // Mechanism hard gates: when candidate requires a specific exception and
  // the incident provides a *different* non-null exception, hard-gate out.
  if (entry.exception_codes.length > 0 && exc) {
    if (!entry.exception_codes.includes(exc)) {
      hard_gated = true;
      gate_reasons.push(`exception_mismatch:${exc}`);
    }
  }

  // GPU family: if incident has GPU codes that don't match required ones.
  if (entry.gpu_child_exit_codes.length > 0 && gpuExit !== null) {
    if (!entry.gpu_child_exit_codes.includes(gpuExit)) {
      hard_gated = true;
      gate_reasons.push(`gpu_exit_mismatch:${gpuExit}`);
    }
  }
  if (entry.gpu_relaunch_codes.length > 0 && gpuRel !== null) {
    if (!entry.gpu_relaunch_codes.includes(gpuRel)) {
      hard_gated = true;
      gate_reasons.push(`gpu_relaunch_mismatch:${gpuRel}`);
    }
  }

  // Concurrency hard gate when candidate requires multi and incident is single
  // with structural multi signal absent — only hard when entry requires multi
  // and incident explicitly declares single with no multi signal.
  if (
    entry.concurrency_contexts.length === 1 &&
    entry.concurrency_contexts[0] === "multi_side_chat" &&
    conc === "single"
  ) {
    hard_gated = true;
    gate_reasons.push("concurrency_mismatch:single");
  }

  // Interaction hard gate: if entry requires specific phases and incident has
  // a concrete different phase, gate out.
  if (
    entry.interaction_phases.length > 0 &&
    phase &&
    phase !== "unknown" &&
    !entry.interaction_phases.includes(phase)
  ) {
    // Only hard-gate when both sides are concrete and non-overlapping.
    hard_gated = true;
    gate_reasons.push(`interaction_mismatch:${phase}`);
  }

  // Module hard gate when both present and incompatible
  if (entry.modules.length > 0 && mod) {
    if (!entry.modules.includes(mod)) {
      hard_gated = true;
      gate_reasons.push(`module_mismatch:${mod}`);
    }
  }

  if (hard_gated) {
    return {
      entry,
      score: 0,
      hard_gated: true,
      gate_reasons,
      structural_hits: 0,
      title_only: false,
    };
  }

  // Architecture-aligned score components (weights from docs/ARCHITECTURE.md §5).
  let score = 0;
  let structural_hits = 0;

  // 0.28 exact_or_structural_signature
  let structural = 0;
  if (exc && entry.exception_codes.includes(exc)) {
    structural += 0.12;
    structural_hits += 1;
  }
  if (sym && entry.symbols.some((s) => s === sym)) {
    structural += 0.08;
    structural_hits += 1;
  }
  if (mod && entry.modules.includes(mod)) {
    structural += 0.04;
    structural_hits += 1;
  }
  if (off && entry.offset_buckets.includes(off)) {
    structural += 0.04;
    structural_hits += 1;
  }
  if (
    gpuExit !== null &&
    entry.gpu_child_exit_codes.includes(gpuExit) &&
    gpuRel !== null &&
    entry.gpu_relaunch_codes.includes(gpuRel)
  ) {
    structural += 0.2;
    structural_hits += 2;
  } else if (
    gpuExit !== null &&
    entry.gpu_child_exit_codes.includes(gpuExit)
  ) {
    structural += 0.1;
    structural_hits += 1;
  }
  score += Math.min(0.28, structural);

  // 0.14 platform_arch
  if (entry.platforms.includes(fp.platform.os)) score += 0.14;

  // 0.12 version_range — unknown version gets partial credit only
  if (fp.codex_version) score += 0.08;
  else score += 0.04;

  // 0.12 surface_component
  if (entry.surfaces.includes(fp.surface)) score += 0.08;
  if (component && entry.components.includes(component)) {
    score += 0.04;
    structural_hits += 1;
  } else if (
    meta?.component === null ||
    meta?.component === undefined ||
    entry.components.length === 0
  ) {
    score += 0.02;
  }

  // 0.10 stack_symbol (already partially in structural; residual)
  if (sym && entry.symbols.includes(sym)) score += 0.04;

  // 0.08 config_feature_keys
  if (fp.feature_ids?.includes("in_app_browser")) score += 0.06;
  else if (isBrowserishSurface(fp.surface)) score += 0.03;

  // 0.10 failure_phase / interaction
  if (phase && entry.interaction_phases.includes(phase)) {
    score += 0.08;
    structural_hits += 1;
  } else if (
    fp.failure_phase === "navigation" ||
    fp.failure_phase === "tab_discovery" ||
    fp.failure_phase === "extension_handshake"
  ) {
    score += 0.03;
  }

  // page capability
  if (pageCap && entry.page_capabilities.includes(pageCap)) {
    score += 0.06;
    structural_hits += 1;
  }

  // concurrency
  if (conc && entry.concurrency_contexts.includes(conc)) {
    if (conc === "multi_side_chat") {
      score += 0.12;
      structural_hits += 1;
    } else {
      score += 0.03;
    }
  }

  // 0.06 upstream_linkage — catalog entries are open issues only
  score += entry.fix_linked ? 0.06 : 0.02;

  // Title / symptom lexical recall — capped and never sufficient alone.
  const titleBlob = [
    fp.error.normalized_message,
    fp.error.class,
    ...(fp.feature_ids ?? []),
  ]
    .join(" ")
    .toLowerCase();
  let titleHits = 0;
  for (const tok of entry.title_tokens) {
    if (titleBlob.includes(tok.toLowerCase())) titleHits += 1;
  }
  const titleBoost = Math.min(0.12, titleHits * 0.02);
  score += titleBoost;

  const title_only = structural_hits === 0 && titleBoost > 0;

  // Title-only path cannot exceed below-candidate band.
  if (title_only) {
    score = Math.min(score, CANDIDATE_THRESHOLD - 0.01);
  }

  // Model preference may only rerank *surviving* candidates within a tiny band;
  // it cannot resurrect hard-gated or invent score past gates.
  if (modelPreferred && modelPreferred.includes(entry.issue_id) && !title_only) {
    score = Math.min(0.95, score + 0.03);
  }

  // Cap at 0.99; high confidence still needs structural + platform gates below.
  score = Math.min(0.99, Math.round(score * 1000) / 1000);

  return {
    entry,
    score,
    hard_gated: false,
    gate_reasons,
    structural_hits,
    title_only,
  };
}

function localMechanismAssessment(
  fp: IncidentFingerprint,
  meta: CrashMetadata | null,
  best: ScoredCandidate | null,
): AxisAssessment {
  if (!hasStructuralSignal(meta) && !isBrowserCrashIncident(fp)) {
    return axis("unknown", "No crash structural signals observed.", 0);
  }
  if (!meta) {
    return axis(
      "unknown",
      "Browser crash symptom noted but sanitized crash_metadata absent.",
      0.2,
    );
  }
  if (best && !best.hard_gated && best.structural_hits >= 2) {
    return axis(
      "supported",
      `Local mechanism signals align with family ${best.entry.family_id}.`,
      best.score,
    );
  }
  if (best && !best.hard_gated && best.structural_hits >= 1) {
    return axis(
      "candidate",
      `Partial local mechanism signals for family ${best.entry.family_id}.`,
      best.score,
    );
  }
  if (best?.title_only) {
    return axis(
      "unsupported",
      "Only title/symptom similarity; no structural crash mechanism match.",
      best.score,
    );
  }
  return axis(
    "unknown",
    "Crash metadata present but no compatible local mechanism family.",
    0.3,
  );
}

function upstreamMatchAssessment(best: ScoredCandidate | null): AxisAssessment {
  if (!best || best.hard_gated) {
    return axis("unsupported", "No compatible upstream Issue after hard gates.", 0);
  }
  if (best.title_only || best.score < CANDIDATE_THRESHOLD) {
    return axis(
      "unsupported",
      "Title/symptom similarity alone cannot establish upstream match.",
      best.score,
    );
  }
  if (best.score >= HIGH_CONFIDENCE_THRESHOLD && best.structural_hits >= 2) {
    return axis(
      "candidate",
      `${best.entry.issue_id} is a high-confidence pattern match; still not official root-cause proof.`,
      best.score,
    );
  }
  return axis(
    "candidate",
    `${best.entry.issue_id} is an Issue candidate (user-reported; not official root cause).`,
    best.score,
  );
}

function fixApplicabilityAssessment(
  best: ScoredCandidate | null,
): AxisAssessment {
  if (!best || best.hard_gated || best.score < CANDIDATE_THRESHOLD) {
    return axis(
      "blocked",
      "No applicable verified fix; wrong or unproven patches must not enter authorization.",
      0,
    );
  }
  if (!best.entry.fix_linked || !best.entry.safe_fix_applicable) {
    return axis(
      "blocked",
      `${best.entry.issue_id} has no verified Issue/PR/commit/release fix linkage; Repair Capsule authorization refused.`,
      0,
    );
  }
  return axis(
    "supported",
    "Verified fix linkage and safe applicability evidence present.",
    1,
  );
}

export interface ClassifyCrashFamilyOptions {
  /**
   * Optional model rerank preference (issue ids). May only nudge surviving
   * candidates; cannot bypass hard gates or invent provenance.
   */
  model_preferred_issue_ids?: string[] | null;
}

/**
 * Classify a desktop browser crash incident into ranked Issue candidates.
 * Pure and deterministic. Never claims official root cause or invents fixes.
 */
export function classifyCrashFamily(
  fp: IncidentFingerprint,
  options: ClassifyCrashFamilyOptions = {},
): CrashClassificationResult {
  const meta = fp.crash_metadata ?? null;
  const modelPreferred = options.model_preferred_issue_ids ?? null;

  const next_evidence_requirements: string[] = [];
  const refused_actions: string[] = [];

  // Active probe without isolation — hard stop (do not crash primary instance).
  if (meta?.active_probe_requested === true && meta.isolation_available !== true) {
    refused_actions.push(
      "active_crash_probe_without_isolation",
      "primary_codex_instance_crash",
    );
    next_evidence_requirements.push(
      "Provide a disposable isolated profile/process before any active Browser crash probe.",
      "Prefer existing Event Viewer / Crashpad metadata and natural-failure logs.",
      "Do not crash the user's primary Codex instance.",
    );
    return {
      applicable: true,
      diagnosis_state: "INCONCLUSIVE",
      user_resolution_status: "INCONCLUSIVE",
      ranked_candidates: [],
      rejected_candidates: CRASH_FAMILY_CATALOG.map((e) => ({
        issue_id: e.issue_id,
        family_id: e.family_id,
        rank: 0,
        score: 0,
        local_mechanism: axis("unknown", "Classification stopped: no isolation.", null),
        upstream_match: axis("unknown", "Not evaluated without isolation safety.", null),
        fix_applicability: axis("blocked", "Repair authorization ineligible.", 0),
        hard_gated: true,
        gate_reasons: ["no_isolation_active_probe_stop"],
      })),
      local_mechanism: axis(
        "unknown",
        "Stopped: active crash probe requested without disposable isolation.",
        null,
      ),
      upstream_match: axis("unknown", "Not ranked without isolation safety gate.", null),
      fix_applicability: axis(
        "blocked",
        "No Repair Capsule eligibility without isolation and applicability evidence.",
        0,
      ),
      repair_authorization_eligible: false,
      next_evidence_requirements,
      refused_actions,
      family_id: null,
      summary:
        "Active Browser crash probe refused without disposable isolation; use existing crash metadata only.",
    };
  }

  // Refuse dump contents path (never parse/export dumps in MVP).
  if (meta?.dump_contents_present === true) {
    refused_actions.push("dump_contents_parse_export");
    next_evidence_requirements.push(
      "Remove dump body contents; provide sanitized exception/module/symbol/offset metadata only.",
    );
  }

  if (!isBrowserCrashIncident(fp)) {
    return {
      applicable: false,
      diagnosis_state: "INCONCLUSIVE",
      user_resolution_status: "INCONCLUSIVE",
      ranked_candidates: [],
      rejected_candidates: [],
      local_mechanism: axis("unknown", "Not a browser-crash-family incident.", null),
      upstream_match: axis("unknown", "Classifier not applicable.", null),
      fix_applicability: axis("blocked", "Not applicable.", 0),
      repair_authorization_eligible: false,
      next_evidence_requirements: [],
      refused_actions: [],
      family_id: null,
      summary: "Crash-family classifier not applicable.",
    };
  }

  // Prefer natural-failure metadata; never require active crash of primary instance.
  if (meta?.isolation_available !== true) {
    refused_actions.push("active_primary_instance_crash_probe");
  }

  const scored = CRASH_FAMILY_CATALOG.map((entry) =>
    scoreCandidate(entry, fp, meta, modelPreferred),
  );

  // Sort: hard_gated last, then score desc, then stable issue_id.
  const ordered = scored.slice().sort((a, b) => {
    if (a.hard_gated !== b.hard_gated) return a.hard_gated ? 1 : -1;
    if (b.score !== a.score) return b.score - a.score;
    return a.entry.issue_id.localeCompare(b.entry.issue_id);
  });

  // Candidate promotion requires score threshold AND enough structural hits.
  // A lone generic component/title match must not rank an Issue into Top 3.
  const survivors = ordered.filter(
    (s) =>
      !s.hard_gated &&
      s.score >= CANDIDATE_THRESHOLD &&
      !s.title_only &&
      s.structural_hits >= 2,
  );
  const rejected = ordered.filter(
    (s) =>
      s.hard_gated ||
      s.score < CANDIDATE_THRESHOLD ||
      s.title_only ||
      s.structural_hits < 2,
  );

  const toRanked = (
    s: ScoredCandidate,
    rank: number,
  ): RankedIssueCandidate => {
    const local = localMechanismAssessment(fp, meta, s);
    const up = s.hard_gated
      ? axis("unsupported", `Hard-gated: ${s.gate_reasons.join(",")}`, 0)
      : s.title_only
        ? axis(
            "unsupported",
            "Title similarity only; cannot attribute root cause.",
            s.score,
          )
        : s.score >= CANDIDATE_THRESHOLD
          ? axis(
              "candidate",
              `${s.entry.issue_id} survives deterministic gates (score=${s.score}).`,
              s.score,
            )
          : axis("unsupported", `Below candidate threshold (${s.score}).`, s.score);
    const fix = fixApplicabilityAssessment(s.hard_gated ? null : s);
    return {
      issue_id: s.entry.issue_id,
      family_id: s.entry.family_id,
      rank,
      score: s.score,
      local_mechanism: local,
      upstream_match: up,
      fix_applicability: fix,
      hard_gated: s.hard_gated,
      gate_reasons: s.gate_reasons,
    };
  };

  const ranked_candidates = survivors.slice(0, 3).map((s, i) => toRanked(s, i + 1));
  const rejected_candidates = rejected.map((s) => toRanked(s, 0));

  const best = survivors[0] ?? null;
  const local_mechanism = localMechanismAssessment(fp, meta, best);
  const upstream_match = upstreamMatchAssessment(best);
  const fix_applicability = fixApplicabilityAssessment(best);

  // Ambiguous: multiple survivors with near-tied scores and different families.
  const ambiguous =
    survivors.length >= 2 &&
    Math.abs(survivors[0]!.score - survivors[1]!.score) < 0.05 &&
    survivors[0]!.structural_hits === survivors[1]!.structural_hits;

  // Insufficient structural evidence
  const insufficient =
    !hasStructuralSignal(meta) ||
    (survivors.length === 0 && !best);

  let diagnosis_state: CrashClassificationResult["diagnosis_state"] = "INCONCLUSIVE";
  let user_resolution_status: CrashClassificationResult["user_resolution_status"] =
    "INCONCLUSIVE";
  let summary: string;

  if (insufficient && !best) {
    diagnosis_state = "INCONCLUSIVE";
    user_resolution_status = "INCONCLUSIVE";
    summary =
      "Insufficient crash structural evidence; title/symptom similarity cannot establish root cause.";
    next_evidence_requirements.push(
      "Capture Windows exception code, faulting module/symbol/offset bucket from Event Viewer or Crashpad metadata.",
      "Record interaction phase (neutral DOM-ready vs click), page capability, and concurrent side-chat count.",
      "Prefer natural-failure logs; only use disposable isolated profile for active probes.",
    );
  } else if (ambiguous) {
    diagnosis_state = "INCONCLUSIVE";
    user_resolution_status = "INCONCLUSIVE";
    summary =
      "Ambiguous crash evidence: multiple families remain compatible; collect differentiating signals.";
    next_evidence_requirements.push(
      "Differentiate exception code vs GPU exit codes vs concurrency-controlled reproduction.",
      "Run a safe neutral-page probe only in disposable isolation; keep a no-Browser control separate.",
    );
    // Keep candidates for recall but do not claim a single family.
  } else if (best) {
    const high =
      best.score >= HIGH_CONFIDENCE_THRESHOLD && best.structural_hits >= 2;
    diagnosis_state = high ? "HIGH_CONFIDENCE_MATCH" : "ISSUE_CANDIDATE";
    // No verifiable fix → UPSTREAM_BLOCKED (never invent repair eligibility).
    if (!best.entry.fix_linked || !best.entry.safe_fix_applicable) {
      user_resolution_status = "UPSTREAM_BLOCKED";
      summary = `Matched crash family ${best.entry.family_id} → ${best.entry.issue_id} (candidate only). No verified fix linkage; upstream blocked for local repair authorization.`;
      next_evidence_requirements.push(
        `Watch ${best.entry.issue_id} for verified PR/commit/release fix linkage.`,
        "Keep mitigation (external Chrome / disable in-app Browser) as exposure reduction only — not root-cause proof.",
        "Do not authorize symptom-level community patches without isolated repro, negative control, and applicability evidence.",
      );
    } else {
      user_resolution_status = "DIAGNOSIS_COMPLETE";
      summary = `Matched crash family ${best.entry.family_id} with applicable fix evidence.`;
    }
  } else {
    diagnosis_state = "INCONCLUSIVE";
    user_resolution_status = "INCONCLUSIVE";
    summary =
      "Browser crash signals observed but no catalog family survived hard gates.";
    next_evidence_requirements.push(
      "Confirm platform is Windows for Fixture E families, or collect macOS-specific crash signatures under a different pack.",
      "Provide exception/module/symbol or GPU/concurrency differentiators.",
    );
  }

  // Symptom-level patch refusal always.
  refused_actions.push(
    "symptom_level_patch_authorization",
    "unverified_community_browser_crash_fix",
  );

  return {
    applicable: true,
    diagnosis_state,
    user_resolution_status,
    ranked_candidates,
    rejected_candidates,
    local_mechanism,
    upstream_match,
    fix_applicability,
    repair_authorization_eligible: false,
    next_evidence_requirements,
    refused_actions: [...new Set(refused_actions)],
    family_id: best && !ambiguous ? best.entry.family_id : null,
    summary,
  };
}

/** True when incident should be routed through the crash-family path. */
export function shouldClassifyCrashFamily(fp: IncidentFingerprint): boolean {
  if (fp.crash_metadata) return true;
  return isBrowserCrashIncident(fp);
}
