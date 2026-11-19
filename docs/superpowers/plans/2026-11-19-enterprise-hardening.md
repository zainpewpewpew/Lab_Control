# SentinelGate Enterprise Hardening — Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (preferred with independent spec/code review) or superpowers:executing-plans; perform tasks through TDD and fresh verification.

**Goal:** Evolve an auditable Windows endpoint-security management pilot toward an enterprise-controlled platform without misrepresenting browser-only protections as full Endpoint DLP.

**Architecture:** Preserve the current small Python/SQLite management API, Python Windows pilot agent and Chromium MV3 extension while strengthening identity, policy lifecycle, telemetry and deployment boundaries behind defined interfaces. Integrate verified enterprise enforcement providers for malware and content-aware DLP rather than pretending browser scripts are universal controls.

**Tech Stack:** Python 3.11+ management and tests; existing Python agent; Chrome/Edge MV3 JS; SQLite for pilot, future migration to managed DB; external enterprise integrations by approved design.

**Spec:** docs/superpowers/designs/2026-11-19-enterprise-sentinelgate.md

## Global constraints

- First-run default mode remains monitor; high-impact enforce requires explicit authorization.
- Do not collect file contents, passwords, screenshots, keystrokes or browsing history.
- Do not expand extension permissions without threat and privacy review.
- Do not claim OS-wide upload protection without actual OS integration.
- Keep no-runtime-dependency rule for Superpowers.
- Each task requires negative tests and legitimate-path tests plus rollback evidence.

## Review focus

1. Offline laptop with stale policy -> visible stale state and documented safe behavior.
2. Misconfigured admin/enrolment token -> reject without leaking secrets.
3. Malformed or duplicate telemetry -> bounded processing and deduplicated storage.
4. Browser extension missing or disabled -> report limited coverage; never false positive active status.
5. False-positive block on an allowed business workflow -> reversible exception with expiry and audited owner.

---

### Task 0: Development pipeline and pinned Superpowers dependency

**Files:** .gitmodules, superpowers.lock.json, AGENTS.md, CLAUDE.md, scripts/, tests/test_superpowers_integration.py, .github/workflows/ci.yml.
- [x] Select the reviewed upstream source commit and lock metadata.
- [x] Implement automated metadata tests (valid, invalid URL, invalid SHA, mismatch).
- [x] Implement verifier that compares gitlink + actual checkout in CI.
- [x] Add Windows/macOS installation helpers and official plugin instructions.
- [ ] Confirm GitHub Actions Windows/Linux run green and fresh CLI auto-triggers brainstorming; preserve evidence.

### Task 1: Identity and authorization (separate PR)

**Files:** console/server.py, tests/test_integration.py, new auth module if approved.
- [ ] RED: wrong password burst is rate-limited; real admin valid sign-in still succeeds.
- [ ] RED: read-only actor cannot mutate policy; unauthorized device cannot read policies.
- [ ] GREEN: implement approved SSO/RBAC abstraction, rate limits and session revocation.
- [ ] REFACTOR: separate identity module and remove duplicated authorization checks.
- [ ] Review: credential safety, session expiry, cookie flags, SSO outage path and audit log.

### Task 2: Secure device lifecycle (separate PR)

**Files:** console/server.py, agent/agent.py, tests/test_integration.py, new tests/test_enrollment.py.
- [ ] RED: revoked token cannot heartbeat, fetch policy or submit events.
- [ ] RED: device ID cannot be spoofed in requests; rotation invalidates old token.
- [ ] GREEN: implement device registry state, token rotation/revocation and admin audit.
- [ ] Review: enrollment authorization, renewal, recovery when device is offline.

### Task 3: Versioned policy changes and rollback

**Files:** console/server.py, console/static/app.js, agent/agent.py, tests/test_policy_lifecycle.py.
- [ ] RED: unaudited/malformed high-impact policy rejected.
- [ ] RED: canary-scoped policy does not apply to unrelated endpoint.
- [ ] RED: expired rule falls back to documented safe policy; rollback restores previous version.
- [ ] GREEN: policy ID/version/scope/status/approver and immutable history.
- [ ] Review: out-of-order sync, policy tampering and false-positive handling.

### Task 4: Telemetry integrity, privacy and retention

**Files:** console/server.py, agent/agent.py, tests/test_telemetry.py.
- [ ] RED: replayed event ID stored only once; malformed/oversized batch rejected.
- [ ] RED: queue survives failed POST; bounded backpressure protects disk.
- [ ] RED: prescribed retention purge removes events and records audit metadata.
- [ ] GREEN: idempotency key, durable send acknowledgement and retention control.
- [ ] Review: PII minimization, access permissions, overflow resilience and legal requirements.

### Task 5: Windows agent packaging and safe quarantine

**Files:** agent/agent.py, installer/ (new after approved design), tests/test_quarantine.py.
- [ ] RED: file changing while scanning is not moved prematurely.
- [ ] RED: collisions, symlinks, access-denied errors, malicious filenames and restore preserve user data.
- [ ] GREEN: service wrapper, least privilege, signed artifacts, safe restore, tamper-evident updates.
- [ ] Review: Windows VM matrix, reboot/service recovery and explicit policy gaps.

### Task 6: Browser managed enforcement and coverage report

**Files:** extension/, tests/browser/ (approved harness), console device coverage view.
- [ ] RED: allowed domain/upload remains usable; disallowed supported channel blocked.
- [ ] RED: missing extension or non-managed profile is shown as uncovered, not protected.
- [ ] GREEN: managed deployment requirements, permission minimization and measured enforcement.
- [ ] Review: Chrome/Edge manifest permissions, browser-version compatibility, bypasses and false positives.

### Task 7: Verified enterprise security-provider integration

**Files:** integrations/ (new), docs/security/ (updated), tests/integrations/ (new).
- [ ] Design and approve official provider APIs, licensing, least-privileged scopes and failure modes.
- [ ] RED: revoked integration secret, API throttling and provider outage are handled safely.
- [ ] GREEN: ingest MDE endpoint posture and Purview/Intune enforcement coverage with audited mapping.
- [ ] Verify: no unsupported malware/DLP prevention claims and no secret exposure.

### Task 8: Production release readiness

**Files:** .github/workflows/, docs/security/RELEASE_GATES.md, runbooks/ (new).
- [ ] Verify Windows packaging, code signing, upgrade/rollback, vulnerability testing and SOC runbooks.
- [ ] Run performance/load and failure injection in staging on test endpoints.
- [ ] Attach approvals, document residual risk, and keep product marked Pilot until every gate is evidenced.

Do not execute future tasks merely because they are listed. Each requires an approved task-specific design, failing tests, and review prior to production-facing merge.
