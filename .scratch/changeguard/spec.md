# Codex ChangeGuard Product Specification

**Status:** ready-for-agent
**Tracker:** local Markdown
**License decision:** MIT
**Publication state:** private local repository until separate Gate C authorization

## Problem Statement

Codex ships frequently across Desktop, CLI, browser, Plugin, Skill, MCP, Hook, and platform-specific runtime surfaces. After an update, users often cannot tell which installed instance changed, what the update affected, whether a new failure matches an upstream defect, or which recovery step is safe. Existing support material is fragmented across release notes, documentation, GitHub Issues, pull requests, commits, community posts, local logs, and configuration state. Symptom-level search frequently returns plausible but incompatible fixes, while manual experimentation can corrupt a working profile or leak sensitive local data.

Users need a product inside Codex that aims to restore usability rather than merely explain or guess. It must distinguish verified mechanism evidence from similarity, execute only bounded and reversible repairs, prove the outcome, retain a usable rollback path, and stop honestly when the evidence is insufficient or the defect is upstream.

OpenAI maintainers simultaneously need fewer duplicate, underspecified, misrouted, and privacy-unsafe reports. When a user problem cannot be fully resolved locally—or when a locally resolved problem exposes a reproducible Codex defect—the diagnostic evidence should be converted into a concise, correctly routed, deduplicated, reproducible upstream contribution without creating a parallel incident database or silently acting as the user.

## Solution

ChangeGuard is an independent, open-source Codex fault-diagnosis and repair Plugin. Its first objective is to restore the user's Codex environment. Its second objective is to convert already-collected, privacy-reviewed evidence into low-noise upstream collaboration that reduces maintainer workload.

The primary experience lives inside Codex and follows a work-order flow:

1. Detect the active Codex instance, version transition, affected surface, and local failure signature.
2. Locate compatible official changes, existing Issues, platform evidence, and deterministic local intersections.
3. Diagnose with allowlisted probes and at most three evidence-backed mechanisms.
4. Present one bounded Repair Capsule containing target, preconditions, exact changes, backup, risk, verification, rollback, and disclosure.
5. Execute only after the authorization required by the repair tier.
6. Verify the original failure and core health checks; automatically roll back a failed repair.
7. Return a user-resolution outcome and a separate upstream-contribution outcome.

Read-only local diagnosis is automatic. External evidence refresh sends only a displayed, sanitized disclosure manifest. Bundled, reviewed repairs may execute after one bounded confirmation. New official, maintainer, community, or model-derived repairs must first pass isolated reproduction, negative control, backup, atomic-change, verification, and rollback tests; a proven candidate may then run once as an explicitly authorized experimental repair. High-risk or non-reversible actions remain guidance-only.

ChangeGuard does not claim official OpenAI affiliation. It does not replace OpenAI Support, GitHub Discussions, the OpenAI Bugcrowd program, or the canonical `openai/codex` Issue tracker. It routes evidence to the appropriate channel and never creates, comments, reacts, uploads, closes, or reopens on behalf of a user without a separate preview and confirmation.

## User Stories

1. As a Codex user, I want ChangeGuard to detect which Codex instance is actually failing, so that I do not repair the wrong installation.
2. As a Codex user, I want Desktop-bundled, PATH, package-manager, Windows MSIX, and WSL installations listed separately, so that version conflicts are visible.
3. As a Codex user, I want a post-update health check to run only when a version fingerprint changes, so that normal sessions remain quiet.
4. As a Codex user, I want the post-update health check to finish quickly and remain read-only, so that starting Codex is not disrupted.
5. As a Codex user, I want first installation distinguished from upgrade and downgrade, so that ChangeGuard does not invent a change event.
6. As a Codex user, I want an update card explaining relevant changes, so that I understand what may affect my environment.
7. As a Codex user, I want unknown new changes labeled `UNMAPPED_CHANGE`, so that broad version support does not become false certainty.
8. As a Codex user, I want diagnosis based on mechanisms, capabilities, signatures, and probes rather than a narrow version allowlist, so that frequent releases remain supportable.
9. As a Codex user, I want `/changeguard diagnose` to collect safe facts before asking questions, so that I do not repeat information the product can inspect.
10. As a Codex user, I want `/changeguard diagnose <URL>` to evaluate a report or proposed fix I found online, so that I can determine whether it applies locally.
11. As a Codex user, I want web content treated as untrusted input, so that prompt injection cannot control the diagnostic or repair engine.
12. As a Codex user, I want exact errors, stack symbols, schemas, AST signatures, hashes, and failure phases compared, so that similar symptoms are not treated as the same defect.
13. As a Codex user, I want ChangeGuard to distinguish local mechanism evidence, upstream match evidence, and fix applicability, so that one confidence score cannot hide uncertainty.
14. As a Codex user, I want model hypotheses separated from observed facts, so that plausible explanations are not presented as confirmed causes.
15. As a Codex user, I want counter-evidence preserved, so that a failed hypothesis lowers confidence instead of disappearing.
16. As a Codex user, I want quick and deep diagnosis modes, so that I can choose between a short health check and a bounded investigation.
17. As a Codex user, I want experimental diagnosis to require explicit opt-in, so that risky probes do not run unexpectedly.
18. As a Codex user, I want diagnostic search limited to a small number of evidence-backed mechanisms, so that ChangeGuard does not perform patch roulette.
19. As a Codex user, I want ChangeGuard to stop when evidence or safe isolation is exhausted, so that it does not force a repair.
20. As a Codex user, I want a Repair Capsule to show the exact target, preconditions, mutation, backup, verification, rollback, and risk, so that one confirmation is informed and bounded.
21. As a Codex user, I want the Repair Capsule invalidated when a target hash, scope, dependency, or permission changes, so that stale authorization cannot be reused.
22. As a Codex user, I want low-risk reviewed repairs to execute after one bounded confirmation, so that the product can actually solve problems.
23. As a Codex user, I want community and model-derived repairs isolated and tested before they are offered, so that unverified advice cannot mutate my environment.
24. As a Codex user, I want failed verification to trigger automatic rollback, so that an unsuccessful repair does not leave a worse state.
25. As a Codex user, I want `/changeguard verify` to reproduce the original failure condition safely and check core health, so that success is demonstrated rather than inferred.
26. As a Codex user, I want dangerous crash probes run only in an isolated profile or fixture, so that my active work is protected.
27. As a Codex user, I want ChangeGuard to avoid crashing my primary Codex instance, so that diagnosis cannot destroy the session being used for recovery.
28. As a Codex user, I want exact backups preserved for at least seven days and three successful starts, so that ordinary repairs remain reversible.
29. As a Codex user, I want the last three healthy Codex-control checkpoints retained as `KNOWN_GOOD`, so that update regressions have a reliable recovery target.
30. As a Codex user, I want `/changeguard rollback` to restore only the affected instance and control surface, so that unrelated installations remain unchanged.
31. As a Codex user, I want official package-source version pinning used for CLI rollback, so that ChangeGuard does not distribute OpenAI binaries.
32. As a Codex Desktop user, I want rollback offered only when an official signed prior installer or lawful local media exists, so that binary provenance remains trustworthy.
33. As a Codex user, I want rollback reported as mitigation rather than a root-cause fix, so that the outcome remains accurate.
34. As a Codex user, I want new releases canary-tested against the original failure before upgrading from `KNOWN_GOOD`, so that the regression is not reintroduced.
35. As a Codex user, I want status results such as `RESOLVED_VERIFIED`, `MITIGATED_VERIFIED`, `UPSTREAM_BLOCKED`, and `INCONCLUSIVE` to have strict meanings, so that wording cannot overstate success.
36. As a Codex user, I want an `ADMIN_ACTION_REQUIRED` outcome for managed environments, so that ChangeGuard does not bypass enterprise policy.
37. As an enterprise user, I want an IT Handoff containing minimal evidence, requested action, official references, and rollback, so that administrators can act safely.
38. As a privacy-conscious user, I want local collection limited to required Codex facts, so that project source and unrelated personal data remain untouched.
39. As a privacy-conscious user, I want tokens, cookies, passwords, one-time codes, complete sessions, and terminal history always excluded, so that they cannot be exported accidentally.
40. As a privacy-conscious user, I want to see the exact disclosure manifest before external search, so that I know what will leave my device.
41. As a privacy-conscious user, I want external search to use sanitized fingerprints rather than raw logs, so that evidence retrieval does not require broad disclosure.
42. As a privacy-conscious user, I want raw diagnostic material deleted after the diagnosis unless I explicitly export it, so that temporary evidence does not accumulate.
43. As a privacy-conscious user, I want zero product telemetry by default, so that usage and incident data do not become a hidden service.
44. As a Codex user, I want the main result card to lead with restored status, exact changes, verification, rollback, and remaining risk, so that I can act without reading an investigation transcript.
45. As a Codex user, I want detailed evidence, version diffs, and Issue matches available in expandable sections, so that auditability does not overwhelm the primary action.
46. As a Codex user, I want a lightweight rescue CLI when Codex cannot start, so that registered local checks and rollback remain reachable.
47. As a Codex user, I want the rescue CLI to share the same deterministic core as the Plugin, so that it does not become a second source of truth.
48. As a Codex user, I want the product to support any model available in Codex through capability checks, so that support is not hardcoded to two named releases.
49. As a Codex user, I want the actual model used recorded and never silently switched, so that the reasoning provenance is auditable.
50. As a Codex user, I want deterministic code to own evidence, hashes, probes, mutations, verification, and safety gates, so that a model cannot bypass controls.
51. As a Codex user, I want a model to help synthesize evidence and propose minimal experiments, so that difficult problems benefit from semantic reasoning.
52. As an OpenAI maintainer, I want ChangeGuard to search existing Issues before proposing a new one, so that duplicate load is reduced.
53. As an OpenAI maintainer, I want exact duplicates with no new evidence to produce only a suggested reaction or subscription, so that Issues do not collect low-value comments.
54. As an OpenAI maintainer, I want a comment proposed only when it contains a material Evidence Delta, so that each notification adds actionable information.
55. As an OpenAI maintainer, I want related-but-distinct mechanisms filed separately and cross-linked, so that incompatible defects are not merged by symptom.
56. As an OpenAI maintainer, I want reports routed to the current App, CLI, Extension, Other Bug, Discussions, Bugcrowd, or Support channel, so that the right team receives them.
57. As an OpenAI maintainer, I want current official Issue forms fetched at submission time, so that required fields remain compatible with evolving templates.
58. As an OpenAI maintainer, I want `codex doctor --json` included when supported and privacy-reviewed, so that reports carry standard diagnostics.
59. As an OpenAI maintainer, I want every proposed report to pass a maintainer-value gate, so that symptom-only and privacy-unsafe submissions are blocked.
60. As an OpenAI maintainer, I want facts, user reports, and hypotheses separated in the draft, so that uncertain claims are immediately recognizable.
61. As an OpenAI maintainer, I want exact errors and commands preserved without translation while explanatory prose can be bilingual, so that technical signals remain searchable.
62. As an OpenAI maintainer, I want the user's subscription tier requested rather than inferred when the official form requires it, so that reports contain accurate account context.
63. As an OpenAI maintainer, I want submission attempts to be idempotent, so that timeouts cannot create duplicate Issues or comments.
64. As an OpenAI maintainer, I want a resolved local defect reported only when it is a reproducible untracked Codex defect with useful evidence, so that local success does not hide a product regression or create noise.
65. As an OpenAI maintainer, I want ChangeGuard to help users answer follow-up evidence requests and validate candidate releases, so that reports can reach closure.
66. As an OpenAI maintainer, I want upstream closure and duplicate decisions respected, so that ChangeGuard does not reopen or cross-post against maintainer guidance.
67. As an OpenAI maintainer, I want verified official fixes to supersede temporary ChangeGuard workarounds, so that the community tool does not create a permanent fork.
68. As a Codex user, I want every Issue, comment, reaction, attachment, close, or reopen action previewed and separately confirmed, so that ChangeGuard never speaks for me silently.
69. As a Codex user, I want an upstream contribution receipt separate from the repair receipt, so that local recovery and external publication remain distinct truths.
70. As a community contributor, I want a successful experimental repair converted into a sanitized recipe contribution package, so that it can be reviewed without exposing OpenAI or user files.
71. As a community contributor, I want recipes expressed as bounded DSL actions with positive and negative fixtures, so that review and regression testing are deterministic.
72. As a community contributor, I want official fixes linked and obsolete recipes marked `SUPERSEDED_BY_UPSTREAM_FIX`, so that users stop applying expired patches.
73. As a competition judge, I want `/changeguard demo` to run a complete protected-process fixture safely within five minutes, so that the product can be evaluated without a broken real installation.
74. As a competition judge, I want the demo to show a model hypothesis being refuted by a deterministic probe, so that the safety boundary is visible.
75. As a competition judge, I want a secondary Windows crash-family scenario to reject an unsafe symptom-level patch, so that precision is demonstrated as well as repair.
76. As a competition judge, I want the primary demo to work without GitHub login or an additional API key, so that evaluation is reproducible.
77. As a competition judge, I want platform support labeled Full, Preview, Limited, or Read-only based on real-machine evidence, so that unsupported claims are avoided.
78. As a project maintainer, I want success measured by verified recovery, low false attribution, deduplication, evidence quality, and zero privacy leaks rather than Issue volume, so that incentives align with users and OpenAI.
79. As a project maintainer, I want the public product clearly identified as independent and unofficial, so that users do not confuse it with OpenAI support.
80. As a project maintainer, I want the repository released under MIT only after Gate C authorization, so that licensing and publication are explicit decisions.

## Implementation Decisions

### Product Boundary and Outcomes

- ChangeGuard is a Codex Plugin, not a generic ChatGPT or OpenAI account-support product.
- The primary outcome is user recovery. Upstream collaboration is a secondary outcome produced from diagnostic evidence and must not block local recovery.
- The user-resolution state machine includes `RESOLVED_VERIFIED`, `MITIGATED_VERIFIED`, `MITIGATED_VERIFIED_BY_ROLLBACK`, `UPSTREAM_BLOCKED`, `INCONCLUSIVE`, and `ADMIN_ACTION_REQUIRED`.
- Only `RESOLVED_VERIFIED` may state that the original problem is fixed. Mitigation states must say that usability was restored without claiming root-cause resolution.
- Version guidance is separately represented as `RECOMMEND_UPGRADE`, `UPGRADE_CANARY_AVAILABLE`, `HOLD_KNOWN_GOOD`, or `GENERAL_UPDATE_ONLY`.
- Every run emits two independent receipts: a User Resolution Outcome and an Upstream Contribution Outcome.

### Component Model

- The primary product is one Codex Plugin with a Skill orchestrator, a local MCP server, a trusted optional `SessionStart` Hook, structured Codex result cards, and a bundled rescue CLI.
- The Skill owns user interaction and orchestration. The MCP server exposes registered facts, probes, repairs, and verification operations rather than arbitrary shell execution.
- The Hook performs only bounded local version-change detection and a lightweight read-only health check. There is no daemon, hidden network activity, or continuous logging.
- The rescue CLI reuses the same core modules and registered operations. It provides local diagnosis and rollback when Codex cannot start; it is not a full model diagnosis path without Codex connectivity.
- An independent Inspector may be added later only as an optional read-only view over the same contracts. It must not duplicate decision logic.
- The implementation uses TypeScript and Node.js. Release artifacts are self-contained JavaScript modules and do not perform runtime package installation.
- Node.js 20 or newer is the baseline. Platform-specific binaries may be introduced only if a capability cannot be implemented safely through the shared TypeScript core.
- Persistent state uses versioned JSON or JSONL receipts and snapshots. No daemon database is required.

### Evidence and Model Boundary

- The Incident Fingerprint records distinct installed instance, surface, platform, architecture, version, failure phase, normalized error, component, structural signatures, and provenance.
- The Change-to-Local Graph contains only deterministic edges from official evidence or observed probes. A model cannot add or upgrade deterministic edges.
- Evidence has source URL or local origin, fetch time, relevant version, state, content hash, and snapshot identifier.
- Diagnosis maintains separate `local_mechanism`, `upstream_match`, and `fix_applicability` assessments. No aggregate score may override a failed safety or applicability gate.
- Candidate Issue retrieval uses compatible surface/platform/version gates, structural signatures, lexical retrieval, and optional model reranking. High-confidence attribution requires a structural or reproducible signal.
- Models may synthesize evidence, identify contradictions, rank compatible candidates, design minimal experiments, propose DSL candidates, and explain outcomes.
- Models may not mutate evidence, invent provenance, raise confidence past deterministic gates, invoke arbitrary shell, execute repairs directly, or ignore refuting probes.
- The product records the model actually used and supports current or future Codex models through capabilities rather than a hardcoded model-name allowlist. GPT-5.6 is the primary competition development and demonstration model, not the only supported model.

### Diagnosis Modes and Stop Rules

- Quick diagnosis targets approximately two minutes. Deep diagnosis targets approximately fifteen minutes. Experimental diagnosis is explicitly opt-in and bounded by the declared Repair Capsule.
- A diagnosis keeps no more than three evidence-backed mechanism candidates.
- It stops when candidates are falsified, required isolation or rollback is unavailable, permissions exceed the supported boundary, upstream is confirmed without an applicable fix, or two distinct mechanism-level repair attempts fail.
- A stopped diagnosis may reopen only when a new release, new upstream evidence, or materially different local evidence appears.
- Dangerous crash reproduction runs only in a disposable fixture or isolated profile/process. Existing crash metadata and natural failure logs are preferred when safe isolation is unavailable.

### Authorization and Repair DSL

- Read-only local collection and allowlisted probes run within the active diagnosis without repeated prompts.
- External retrieval requires one diagnosis-scoped approval of the displayed disclosure manifest.
- Each repair is represented by one Repair Capsule containing target instance, preconditions, exact operations, authorization tier, backup, expected effect, verification, rollback, and expiry conditions.
- Any target hash, match count, dependency, scope, or permission change invalidates the Capsule and requires a new preview and authorization.
- Bundled reviewed repairs may execute after one bounded confirmation.
- New official, maintainer, community, or model-derived repairs must pass isolated reproduction, negative control, backup, atomic replacement, smoke verification, and rollback validation before they can be offered as an experimental one-off repair.
- Failed verification automatically invokes rollback and prevents a resolved outcome.
- The MVP DSL allows bounded configuration set/remove, exact replacement with hash and match-count guards, verified resource copy, rename-to-quarantine, backup restoration, registered probe invocation, registered process restart, and opening an official update path.
- The MVP DSL forbids arbitrary shell or PowerShell, arbitrary scripts, recursive deletion, arbitrary registry writes, security-control disablement, system proxy/certificate/auth changes, unlisted targets, and replacement of signed application binaries.

### Backup, Rollback, and Update Lifecycle

- Normal repair backups remain for at least seven days and three successful starts.
- The latest three healthy configuration, Plugin, Skill, MCP, and Hook checkpoints remain available as `KNOWN_GOOD` beyond ordinary backup expiry. Users may explicitly retain more.
- OpenAI application binaries are never archived or redistributed by ChangeGuard.
- CLI rollback uses the official installation source and an explicit version pin when available.
- Desktop rollback is offered only through an official signed previous installer/history or lawful user-provided media.
- Update regression claims require controlled A/B evidence rather than timing alone.
- After rollback, ChangeGuard tracks the canonical upstream issue and candidate fix. A later version is canary-tested in isolation before recommending upgrade.
- A verified upstream fix supersedes the workaround. The old recipe becomes `SUPERSEDED_BY_UPSTREAM_FIX` and is no longer recommended for new environments.

### Version, Instance, and Platform Coverage

- ChangeGuard maintains a reachable release, tag, diff, Issue, pull request, commit, and fix index rather than supporting only a small rolling window of versions.
- Compatibility is expressed by mechanism, capability, platform, component, structural signatures, and semantic preconditions. Version remains one signal, not the primary allowlist.
- The adapter layer enumerates installations, profiles, configuration roots, log roots, caches, crash metadata, registered restart/quarantine/rollback/update capabilities, and permission boundaries.
- A Repair Capsule targets exactly one observed instance and never broadcasts across installations.
- Unknown adapters permit read-only generic diagnosis but disable mutation.
- macOS is the first full supported path. Windows 11 becomes Full only after a real-machine end-to-end loop; until then it is Preview. Linux and WSL provide generic CLI diagnosis with limited Desktop repair.
- Enterprise-managed policy, certificate, proxy, SSO, firewall, and signed package boundaries remain read-only. Required administrator work produces an IT Handoff rather than a bypass.

### Local Data and Privacy

- Default collection includes version/build fingerprints, configuration keys/types/schema rather than sensitive values, Plugin/Skill/MCP/Hook inventory and hashes, redacted failure windows, crash metadata without dump contents, and coarse resource metrics.
- Full configuration values, large log windows, cache-source snippets, crash dumps, network/browser request details, and project control files require specific disclosure and authorization.
- Ordinary project source, project data, Git history, unrelated terminal history, browser cookies/storage, full session rollouts, and secrets are outside the default collection boundary.
- Project-level inspection is limited to relevant Codex control files and requires exact disclosure. Ordinary application-code defects route back to the normal Codex workflow.
- External queries contain only a sanitized fingerprint and the displayed disclosure fields.
- Raw diagnostic data is removed after the diagnosis unless the user explicitly exports a sanitized package.
- ChangeGuard collects no telemetry, account identifier, device identifier, usage statistics, diagnosis statistics, or repair statistics. Metrics are derived from fixtures and explicit local tests.

### Upstream Collaboration

- Official documentation, releases, Issues, pull requests, and commits are preferred over maintainer posts, quality community sources, and the broader web, in that order.
- A versioned official snapshot supports reproducible retrieval. Each diagnosis refreshes live official evidence when available and labels snapshot age; there is no always-on crawler or full web mirror.
- The canonical public incident page is the applicable `openai/codex` Issue. ChangeGuard does not create a cloud incident database or parallel support forum.
- Upstream routing first distinguishes product bug, support question, validated security vulnerability, and account/billing/private case. It then chooses the current App, CLI, Extension, Other Bug, Discussions, Bugcrowd, or OpenAI Support path.
- Exact duplicates with no Evidence Delta produce only a suggested reaction/subscription. A structured comment is proposed only for materially new evidence such as a platform/version, exact crash signature, minimal reproduction, fix validation, or rollback result.
- Related-but-distinct mechanisms remain separate and cross-linked. Symptom similarity alone cannot merge incidents.
- Current official Issue forms are fetched at submission time and mapped from the richer internal record. A timestamped snapshot is used only when live retrieval is unavailable and is clearly labeled stale.
- `codex doctor --json` is collected when supported, then sanitized and shown to the user before inclusion.
- The maintainer-value gate requires correct routing, duplicate search, product surface, platform and version or reason unknown, actual behavior, at least one technical signal, baseline diagnostics, privacy review, reproduction quality or a clear intermittent marker, and material value over an existing Issue.
- The submission adapter uses an authenticated `gh` or visible browser session without requesting or storing a token.
- Create, comment, reaction, attachment, close, reopen, and follow-up actions are separately previewed and confirmed.
- Submission idempotency uses canonical target, Incident Fingerprint, and Evidence Delta hash. After an ambiguous timeout the adapter queries current state before retrying; uncertain state stops rather than duplicates.
- OpenAI maintainer requests can trigger a new bounded local evidence Capsule and response draft. ChangeGuard never silently replies or commits the user to follow-up work.
- Duplicate, cannot-reproduce, by-design, not-planned, and closed decisions are respected. New interaction requires a material Evidence Delta and user confirmation.
- Validated security vulnerabilities are routed privately to OpenAI's Bugcrowd program and never rendered as public Issue drafts.

### Product Identity and Governance

- Public materials state that ChangeGuard is an independent community project and is not an OpenAI product, official support channel, or certification.
- Names, branding, and interface design must not imply official ownership.
- Issue volume, comment volume, and reaction volume are not success metrics.
- Primary metrics are verified recovery rate, time to verified recovery, false repair/attribution rate, rollback reliability, duplicate avoidance, report reproducibility, accepted Evidence Delta, and zero secret/private-data leakage.
- The source will be released under the MIT License only after separate Gate C publication authorization.
- Public releases include the Plugin, MCP server, rescue CLI, DSL, reviewed recipes, tests, and sanitized synthetic fixtures. They exclude OpenAI binaries, private logs, full configuration, crash dumps, browser-client payloads, and user session data.

### Core Fault Packs and Demonstration

- The first four supported fault packs are browser/runtime compatibility, configuration/startup, bundled Plugin cache/version skew/reconciliation, and the Codex Desktop browser crash family.
- Network/authentication diagnosis is included only when it directly affects Codex. Generic ChatGPT session-expiry and account support remain outside the product boundary.
- The flagship fixture reproduces the protected `process` property failure in an isolated Codex-like profile, proves failure before browser discovery/handshake, differentiates positive and negative controls, applies a validated experimental repair to a disposable copy, verifies recovery, and proves rollback.
- The secondary Windows crash-family fixture shows that similar browser crashes map to distinct candidates and rejects an unsafe patch when applicability evidence is missing.
- `/changeguard demo` runs the real fixture path within five minutes without GitHub login, additional API key, rebuilding the product, or modifying the judge's live Codex installation.

## Testing Decisions

- The primary and highest test seam is one black-box Scenario Harness that invokes the public ChangeGuard command surface and observes user-visible outcomes plus the isolated target filesystem.
- The Scenario Harness exercises `/changeguard demo`, `/changeguard diagnose <fixture-or-URL>`, `/changeguard verify`, `/changeguard rollback`, and `/changeguard upstream` through the same Skill, MCP, shared core, and rescue-CLI contracts used by the product.
- Good tests assert externally observable behavior: terminal state, result card, actual target mutation or restoration, verification result, disclosure manifest, receipt, upstream routing decision, and absence of forbidden disclosure. Tests do not assert private helper calls or duplicate each module's implementation.
- Contract-level tests are retained only where the black-box seam cannot efficiently isolate a safety invariant: JSON Schema validation, platform adapter capability contracts, Repair DSL parsing, and cryptographic/hash preconditions.
- At least two positive fixtures must reach `RESOLVED_VERIFIED` through a complete repair and verification loop.
- At least two fixtures must reach a verified mitigation or `UPSTREAM_BLOCKED` outcome without overstating resolution.
- At least three similar-symptom negative controls must reject the wrong mechanism or repair.
- The protected-process positive and negative fixtures must be deterministically separable; failure to separate them is a release blocker.
- Browser crash-family fixtures must distinguish incompatible stack/signature families even when user-facing symptoms overlap.
- Every write-path fixture validates preconditions, backup, atomic mutation, success verification, and actual rollback. A failed verification must make `RESOLVED_VERIFIED` impossible.
- Privacy adversarial tests include tokens, environment values, usernames, absolute paths, cookies, session content, malicious Issue text, and prompt injection. Forbidden external disclosure count must remain zero.
- Submission tests cover exact duplicate, material Evidence Delta, related-but-distinct incident, new incident, Discussions routing, Bugcrowd routing, Support routing, stale form snapshot, authenticated and unauthenticated adapter states, timeout idempotency, and explicit user cancellation.
- Version tests cover first install, update, downgrade, multiple concurrent installations, PATH precedence drift, unknown new versions, stale cache reconciliation, `KNOWN_GOOD`, rollback, canary upgrade, and official-fix supersession.
- Platform support claims require fresh real-machine Scenario Harness receipts. Windows remains Preview until a full Windows 11 path succeeds outside a synthetic fixture.
- The competition acceptance path completes the protected-process fixture in approximately two minutes after installation and the full judge flow in five minutes without modifying the primary Codex profile.
- Install, schema, fixture, CLI, Plugin, MCP, Hook, recovery, upstream, and privacy checks are run from one repository-level verification command before a release checkpoint.

## Out of Scope

- Generic ChatGPT usage support, prompt quality, model-answer quality, billing, refunds, subscription appeals, or account recovery.
- Debugging ordinary user application code, data, tests, or deployment failures unrelated to Codex itself.
- General operating-system, hardware, antivirus, proxy, certificate, firewall, or enterprise-policy repair.
- Bypassing administrative controls, managed policy, security controls, authentication, signed packages, or platform protection.
- Arbitrary shell execution, arbitrary registry modification, recursive deletion, system certificate/proxy changes, or replacement/distribution of signed OpenAI binaries.
- Automatic Issue creation, comments, reactions, uploads, closure, reopening, or maintainer replies without user preview and confirmation.
- A ChangeGuard cloud service, telemetry pipeline, public incident mirror, full GitHub mirror, background daemon, or continuous crawler.
- Reverse engineering proprietary opaque binaries, redistributing OpenAI code/assets, bypassing access controls, or claiming support for opaque mechanisms without behavioral evidence.
- A general third-party Plugin or Skill debugger except where version skew or reconciliation directly affects Codex runtime behavior.
- Permanent support for temporary monkey patches after an applicable official fix has been verified.
- Public repository publication, competition registration, upload, or submission before separate Gate C authorization.

## Further Notes

- Product constitution: ChangeGuard restores user usability first and turns verified diagnostic evidence into privacy-preserving, low-noise upstream collaboration second. It does not impersonate official support, substitute guesses for verification, execute unauthorized mutations, or transform user data into telemetry.
- The local repository is independent from the competition portfolio. Competition research, Gate decisions, registration, and submission status remain canonical in the portfolio repository.
- Current official Issue forms instruct users to search first and generally react to an existing Issue rather than add a redundant comment. ChangeGuard's duplicate behavior intentionally follows that guidance.
- Existing architecture and case-study documents are evidence inputs, but this specification is the canonical statement of the product behavior approved during the requirements review. Implementation documents must be reconciled when they still contain the earlier blanket preview-only policy.
- The first implementation order is: trusted execution base; protected-process vertical demo; multi-version/multi-instance/`KNOWN_GOOD` rollback; four core fault packs; upstream collaboration; cross-platform real validation; competition packaging and public-release readiness.
