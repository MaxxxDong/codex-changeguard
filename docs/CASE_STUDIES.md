# Real-world Diagnosis Case Studies

Evidence snapshot: 2026-07-17. These cases test whether ChangeGuard can turn a community report into a bounded diagnosis without treating forum replies or GitHub Issue titles as root-cause proof.

## Case 1 — repeated ChatGPT “session expired”

Community source: [LINUX DO topic 2605367](https://linux.do/t/topic/2605367)

### Evidence actually present

- Product surface: ChatGPT, otherwise unspecified.
- Exact user-visible symptom: “session expired”.
- One reply asks whether the public IP is stable and suggests that switching proxy nodes can trigger another login.
- No app/browser version, operating system, sign-in method, timestamp, response code, status-page correlation, or controlled reproduction is provided.

The IP explanation is plausible as a network-path hypothesis, but the thread does not prove it. OpenAI's official guidance says VPNs, proxies, browser extensions, firewalls, and other network controls can block authentication requests; it does not establish that every IP change invalidates a ChatGPT session.

### ChangeGuard localization path

1. Record the exact timestamp, product surface, app/browser version, OS, sign-in method, and whether one or multiple accounts are affected.
2. Check [OpenAI Status](https://status.openai.com/) before changing local state. At this evidence snapshot, the official status API reported all systems operational and no current authentication incident.
3. Compare web versus desktop app on the same network. This separates an app-local session store from an account/network-wide failure.
4. Compare the current network with one controlled alternative such as a cellular hotspot. Record only a hashed network-path identifier; never collect the public IP itself for model export.
5. Repeat once with VPN/proxy/security filtering disabled when the user is authorized to do so. Check whether OpenAI domains and WebSocket traffic over TCP 443 are allowed and whether SSL inspection is interfering.
6. Preserve only URL origin, timestamp, redirect count, and HTTP/status class from a user-approved diagnostic capture. Drop headers, cookies, bodies, tokens, account IDs, and query secrets.
7. Verify that the user selects the original authentication method or required organizational SSO path.
8. Only after the safer comparisons, sign out/in or clear ChatGPT site data according to official guidance. This is remediation, not a diagnostic first step, because it destroys the previous local session state.

### Resolution matrix

| Supported branch | Evidence needed | Safe action | Maximum claim |
|---|---|---|---|
| Service incident | matching time/surface on OpenAI Status | wait for recovery; avoid destructive local changes | OpenAI reported an incident affecting the surface |
| VPN/proxy/security path | failure on filtered path and success on a controlled alternative | stabilize/disable the path; allow required domains and TCP 443; exempt public OpenAI domains from SSL inspection | the network/security path caused the observed authentication failure |
| Auth method/SSO mismatch | exact official error or success using the original/required method | use the original provider or required SSO | authentication method mismatch confirmed |
| Browser/app local state | same account works on another surface/network; fresh local session fixes only the affected surface | update app, sign out/in, then clear affected site data if needed | local session state was the differentiating factor |
| Account-side or unknown | failure persists across surfaces and controlled networks with no status incident | collect a redacted support bundle and contact OpenAI Support | unresolved; support escalation required |

Official references:

- [Troubleshooting authentication](https://help.openai.com/en/articles/10489721-troubleshooting-authentication)
- [Why can't I log in to ChatGPT?](https://help.openai.com/en/articles/7426629-why-cant-i-log-in-to-chatgpt)
- [Network recommendations for ChatGPT errors on web and apps](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps)

### Product-scope decision

This is an adjacent authentication/network diagnostic, not a Codex update-impact fixture. It demonstrates refusal of false precision and can ship as a small playbook after the Codex crash classifier. It should not expand the MVP into a general ChatGPT support bot.

## Case 2 — Windows Codex/ChatGPT app exits around in-app Browser use

Community source: [LINUX DO topic 2576892](https://linux.do/t/topic/2576892)

### Evidence actually present

- Windows 11 and the newer ChatGPT/Codex desktop app.
- Tasks sometimes terminate the whole application.
- The original author reports that disabling the in-app Browser and using the Chrome extension stopped the observed crashes.
- One reply proposes disk I/O pressure and moving the project to SSD, without measurements.
- Another user later identifies SecureLink as the cause of that user's separate failure; this does not prove SecureLink caused the original report.

The forum provides a useful mitigation but not enough evidence for a single root cause.

### Upstream candidate map

All public Issues below were open at the 2026-07-17 evidence snapshot. A public Issue in the official repository is still a report, not an official fix, unless a verified PR/commit/release link is present.

| Candidate | Distinguishing evidence | Match to the forum report |
|---|---|---|
| [openai/codex#32683](https://github.com/openai/codex/issues/32683) | neutral page; DOM-ready then crash in 1–5 seconds; repeated `0xC0000005`; `CrBrowserMain`; `chrome.dll+0x2e08f46` | strongest generic candidate if the same native signature is found |
| [openai/codex#33710](https://github.com/openai/codex/issues/33710) | click/link interaction; `ChatGPT.exe`; exception `0xc06d007f` | candidate only if Event Viewer has this exception and interaction timing |
| [openai/codex#32094](https://github.com/openai/codex/issues/32094) | media/canvas page; GPU child exit `101457950`; relaunch failure `18` | candidate only for the GPU/media signature; the Issue references internal browser-team tracking but remains publicly open |
| [openai/codex#33202](https://github.com/openai/codex/issues/33202) | several concurrent side chats; exit immediately after Browser WebView/debugger attachment | candidate when concurrency is the controlled differentiator |
| [openai/codex#33762](https://github.com/openai/codex/issues/33762) | complex login/Cloudflare pages; silent exit; Browser disable state is re-enabled during bundled-plugin reconciliation | adjacent candidate for complex-page failures and an ineffective disable workaround |

### ChangeGuard localization path

1. Fingerprint Windows build, desktop package version, bundled CLI version, Chromium version, Browser plugin version, install method, and concurrent side-chat count.
2. Read only the final redacted lifecycle window around `IAB_LIFECYCLE`, WebView attachment, DOM-ready, child-process exit, and application termination. Do not upload full logs by default.
3. Read Event Viewer crash metadata: exception code, faulting process/module, timestamp, and AppX event. Do not read unrelated event bodies.
4. Read Crashpad metadata and hash a user-selected dump, but do not parse or export process-memory contents in the MVP.
5. Run a user-approved neutral-page probe once with the in-app Browser and once with external Chrome/no Browser. Stop after a crash; never loop a destructive reproducer.
6. Fork the candidate set using exact exception/process/timing/page/concurrency evidence. Title similarity contributes retrieval recall but cannot override these gates.
7. Test SecureLink, VPN/fake-IP, GPU/media, concurrency, and storage-pressure hypotheses independently. Each needs a controlled A/B result and a matching local signal; one passing mitigation cannot validate the others.
8. Search Issue comments, linked PRs, commits, and releases. Until a public linkage is verified, report `ISSUE_CANDIDATE` or `LOCAL_REPRO_CONFIRMED`, not `FIX_COMMIT_LINKED`.

### Current safe resolution

- Immediate mitigation: avoid the in-app Browser and use external Chrome for browsing. This reduces exposure but is not a source-level fix.
- If the Browser disable setting is rewritten on restart, verify the persisted configuration and startup reconciliation before promising that the mitigation is durable.
- If SecureLink or another security product is suspected, use a single authorized A/B test and inspect its own block log. Do not uninstall security software based on a forum reply.
- If the native signature matches an open Issue and no released fix is linked, preserve the redacted repro pack, keep the workaround, and watch for an official release.

## What the product can honestly promise

ChangeGuard can automatically find these forum posts and GitHub candidates, but search is only the retrieval stage. Precision comes from matching the user's local version, platform, surface, failure phase, exception/process signature, and controlled reproduction. When those fields are absent, the correct product result is a short diagnostic plan and `INCONCLUSIVE`, not a confident answer copied from the most similar thread.
