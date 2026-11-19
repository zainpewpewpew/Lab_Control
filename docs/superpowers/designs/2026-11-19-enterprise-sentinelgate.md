# SentinelGate Enterprise Security Platform — Design baseline

Date: 2026-11-19. Status: preliminary architecture and risk boundary for engineering review; NOT a production approval.

## Problem and outcomes

An enterprise CISO needs managed Windows endpoints to prevent access to forbidden destinations, reduce malicious downloads, manage risky upload flows, and provide auditable policy decisions with minimal employee privacy intrusion. An MVP already exists in console/server.py, agent/agent.py and extension/. This document distinguishes present behavior from required enterprise security controls.

Success outcomes: auditable security policies, demonstrable enforcement in explicitly tested channels, legitimate business workflow continuity, secure enrollment, manageable false positives, incident export and explicit exception governance. Neither the current MVP nor this design is a replacement for full EDR/DLP.

## System context and trust boundaries

Boundary A: CISO/browser -> management API. Pilot: cookie + CSRF + SQLite on a Python HTTP server; target: corporate IdP SSO, RBAC, MFA, short sessions and independent immutable audit. Restrict admin interfaces to company management network.

Boundary B: management API -> endpoint agent. Pilot: individual bearer tokens and TLS for remote hosts; target: device-bound authenticated enrollment, token/certificate rotation, revocation, server identity pinning where appropriate, minimal device policy scope, signed policy snapshots and robust replay controls.

Boundary C: Windows agent -> OS filesystem. Pilot: scans Downloads after a file appears and may move a disallowed extension into agent-local quarantine. Target: Windows Service identity, OS permissions, durable recovery, signed code/config, safe quarantine semantics and independently validated endpoint enforcement (Defender/WDAC/MDM). Never claim all Windows I/O flows are observed.

Boundary D: browser extension -> webpage. Pilot: MV3 network domain blocklist, downloads API cancellation, content script file-picker/drop detection. Web pages are untrusted; content scripts and page JavaScript are separate worlds; native apps, arbitrary JS upload transports and unmanaged browsers are outside control. Target: managed deployment, verified extension permissions, testable destination restrictions and integration with actual Endpoint DLP.

Boundary E: events -> central storage. Pilot: bounded metadata and SQLite event rows without retention control. Target: policy-versioned events, stable idempotency keys, bounded retry queue, retention/pseudonymization, access controls, forensic export with access audit, retention purge and external security monitoring.

## Logical architecture

Corporate IdP / authorized CISO
   -> management API (RBAC / policy approval / audit / retention)
   -> versioned scoped policies (groups, users, devices, browser profile)
   -> authenticated Windows endpoint agent + managed Chromium extension
   -> supported policy decisions (allow / monitor / block) and controlled exceptions
   -> reliable security metadata events -> centralized SIEM

Separate defensive integrations: Microsoft Defender for Endpoint (malware, network protection), Microsoft Purview Endpoint DLP (content-aware upload restrictions), Intune/MDM (managed extensions, application controls), WDAC/App Control for Business (executables). These are recommended external enforcement planes; no such integration is implemented by this design.

## Non-functional requirements

- Security: deny unauthenticated admin access; verify authorization on every policy mutation, use minimum privilege, secure bootstrap and revoke compromised device identities.
- Safety: default MONITOR for new policy, canary releases and rollback path; critical business services allowlisted only by approved change.
- Reliability: offline policy clearly marked as stale; bounded queue, retry with deduplication; no silent loss of high-severity event data.
- Performance: policy evaluation bounded and predictable; avoid blocking interactive Windows workloads on management API latency.
- Privacy: collect only what supports security decisions, not content or surveillance; role-restricted incident access, retention duration and employee disclosure.
- Audit: every policy change captures actor, old/new policy hash, timestamp, scope, approval and rationale; logs are append-only in durable storage.
- Operational integrity: signed releases, secure updater and rollback, tested alerting, backup/restore, change control and emergency exceptions.

## Policy model — target (not yet implemented)

policy_id, version, scope, mode, rule_type, action, exceptions, expires_at, author, approver, signed_hash, rollback_to. Rules must distinguish website domains, downloadable artifact types, approved cloud destinations, and content-aware DLP classifications. A filename extension alone is NOT sensitive-data classification. Policy decisions record rule_id, version and outcome in events.

## Security decision semantics

- Monitor mode: observe only; no blocking or moving files.
- Enforce mode: block only explicitly supported, tested channels; never silently infer OS-wide enforcement.
- Management API unavailable: use an authenticated cached policy only within documented lifetime and expose stale status; require an approved emergency override.
- Enrolment/identity compromised: support immediate device revocation without relying solely on restarting agent.
- Browser extension absent/disabled: report a coverage gap where detectible; do not claim blocking continued.
- Privacy sensitive event: redact before queueing; do not store passwords, file bytes, clipboard contents or full page queries.

## Options considered

1. Expand current Python/extension pilot as universal DLP: rejected, because browser APIs and a file watcher do not cover native Windows upload/download or malware analysis.
2. Build a custom kernel/network interception stack now: rejected for the MVP; high code-signing, reliability, Windows security engineering and privacy burden.
3. Recommended: evolve the management/analytics/orchestration platform first, integrate established enforcement planes and validate each rule type with controlled tests. Keep present browser/Downloads controls clearly labelled pilot.

## First implementation milestone acceptance

- The engineering dependency is a pinned submodule, not an application dependency.
- CI runs Windows and Linux tests, JS syntax checks and checks Git submodule provenance.
- Agents have documented Superpowers workflow plus a SentinelGate threat review skill.
- Design and task-level plan link code and tests and name explicit gaps.
- Changes do not alter active endpoint enforcement or secretly collect employee data.

## Open questions requiring CISO approval before enterprise pilot

Management identity provider; approved retention period and region; number of endpoints and network segmentation; target browser coverage; which native apps require protection; Microsoft licensing and connectors; legal basis and employee notice; outage behavior per risk tier; authorized break-glass owners; deployment/signing/rollback procedure.
