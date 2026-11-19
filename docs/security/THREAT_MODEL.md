# SentinelGate — Threat model and abuse-case register

Status: initial review for defensive pilot. Architecture reference: docs/superpowers/designs/2026-11-19-enterprise-sentinelgate.md.

## Assets and trust

- Admin credentials and sessions; device tokens, extension local bridge tokens; policy versions and approvals; endpoint integrity; security event metadata; quarantine directory; employee privacy; vendor credentials for future integrations.
- Untrusted inputs: all HTTP request bodies, browser page contents and URLs, file names/extensions, user-selected uploads, downloaded archives, endpoints with local admin access, proxy/network traffic, logs and third-party agent skills.
- Attackers: internet attacker reaching an exposed service, malicious local user, malware running as a user, compromised admin workstation, compromised device token, malicious website and supply-chain attacker.

## Threats (prioritized, not claims of exploitation)

| ID | Boundary / threat | Pilot exposure | Required mitigation / proof |
|---|---|---|---|
| T01 | Admin brute force, session theft, account takeover | One bootstrap admin; no production SSO/RBAC | IdP + MFA, rate limiting, session expiry/revocation; invalid/valid login tests |
| T02 | Device token copied and used for event poisoning | Bearer token per device stored in local JSON | Managed enrollment, rotation/revocation, device binding, event input tests |
| T03 | Unauthorized or mistaken mass policy change | Console policy written by single admin | RBAC, two-person approval for high-impact rules, canary, rollback, immutable audit |
| T04 | Browser bypass through unmanaged browsers/native apps | MV3 browser-only controls | Managed browser/MDM plus verified OS security plane; publish coverage matrix |
| T05 | Upload via fetch/XHR/clipboard/native processes evades controls | File input/drop heuristics only | Purview Endpoint DLP or approved OS-level control; explicit negative coverage tests |
| T06 | Download finishes before browser cancellation | Best-effort downloads API + post-download watcher | Defender real-time protection, controlled download tests; do not claim prevention |
| T07 | Malicious webpage spoofs extension messages or triggers policy errors | Page and content-script are separate trust zones | Validate sender/origin, minimize privileges, fuzz invalid messages |
| T08 | Local bridge token exposure or replay | Loopback token in agent config/browser storage | Rotate token, constrain origins to managed extensions, local ACLs, replay and origin tests |
| T09 | Event flood or malformed inputs cause memory/storage exhaustion | SQLite pilot and queued JSONL | Input limits, rate limits, storage quotas, retention and malformed-input tests |
| T10 | Duplicate or missing security events during network partition | At-least-once queue can duplicate | Stable event IDs, server dedup, durable bounded retry, offline fault injection |
| T11 | Malicious or stale cached policy persists | Cached policy and limited freshness metadata | Signed/verifiable expiry-aware cache, explicit stale state and recovery tests |
| T12 | Quarantine file mishandling corrupts legitimate data | Moves restricted file types locally | Reversible quarantine, ACLs, safe restore, collision checks, false-positive tests |
| T13 | Agent/extension tampering or untrusted update | No production signing/self-defense | Signed release, controlled updater/rollback, MDM deployment, tamper reporting |
| T14 | Overcollection and unauthorized employee monitoring | Metadata events retained indefinitely | Documented notice, least privilege, purpose limitation, purge/export and audit |
| T15 | Dependency or agent skill supply-chain compromise | Third-party dev framework added | Pinned gitlink+lock, source review, no runtime dependency, manual plugin install |

## Verification matrix

Before enforcement release: show malicious AND legitimate sample behavior in a disposable Windows VM; separate Chrome/Edge/other-browser/native-app results. Test disconnect, stale policy, restart, reboot, upgrades, non-admin user, local-admin user, corrupted config, concurrent events, clock skew and quota exhaustion. Attach test artifact URLs and host/OS/browser versions. These tests are requirements, not results already obtained.

## Security and privacy posture

No keylogging, screenshots, stealth activity, interception of personal accounts, capture of credentials, or content scraping is part of the product. Security incidents contain the smallest useful metadata. A policy that harms ordinary permitted business activity is a security defect and must have a rollback path.
