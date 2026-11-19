---
name: sentinelgate-security-review
description: Use when reviewing or changing SentinelGate authentication, policy decisions, file handling, telemetry, Windows agent operations, or browser permissions. Adds domain-specific evidence gates after Superpowers process skills.
---

# SentinelGate Security Review

This project skill complements (does not replace) upstream Superpowers. Read AGENTS.md, docs/security/THREAT_MODEL.md, the current code, and the task's approved design/plan.

1. Name the assets, trust boundary, principal, authorization check and data stored/returned.
2. Identify adversarial input: malformed requests, compromised endpoint, malicious webpage, local-admin tampering, leaked tokens, offline agent, false positives.
3. State exactly where existing enforcement works and where it does not. Browser file-picker handling is not Windows-wide DLP. Post-download quarantine is not antivirus prevention.
4. Check secrecy, data minimization, employee notice, retention, role access, and logs for credentials or file content.
5. Require failing negative tests AND permitted-path tests; include offline and rollback where relevant.
6. Produce severity-ranked findings with file/line references, a regression test, and remediation owner. No vague "secure" or "production ready" claims.
7. Gate any broad policy enablement, additional browser permissions, privileges or data collection on explicit CISO sign-off.
8. Run or cite fresh verification commands before reporting completion. Disclose unavailable Windows/browser integration tests.

Review output format: Scope; Observed evidence; Critical/High/Medium findings; Coverage gaps; Tests; Rollback; Decision (pilot only / review required / blocked).
