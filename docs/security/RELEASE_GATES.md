# Enterprise release gates — SentinelGate

Status: MVP / pilot only. All enterprise release gates below are unfulfilled unless separately evidenced by deployment-specific tests and CISO sign-off. Passing automated tests is necessary but NOT sufficient.

## Gate 0 — Repo and developer supply chain

- Reviewed Superpowers commit pinned in both gitlink and lockfile; verify on Windows/Linux.
- Agent plugin installed independently and verified in a fresh session before relying on skill automation.
- PR includes design, plan, TDD red/green evidence, independent review and risk analysis.
- Workflow CI green on Linux and Windows; no secret or employee data committed.

## Gate 1 — Identity, authorization and audit

- Enterprise SSO/MFA/RBAC and least privilege; no shared all-powerful default account.
- Device enrollment requires approvals; tokens/certs rotate and revoke.
- Authorized policy lifecycle uses version, actor, approval, canary and rollback.
- Tamper-resistant admin and event audit with retention policy.

## Gate 2 — Enforcement coverage and safety

- Document exact browser and native-app coverage; test allow and deny behavior.
- Enforced policies are managed (MDM/Intune where appropriate); unmanaged extension is not considered hardened protection.
- Verified malware and sensitive-data controls delegated to supported EDR/DLP providers or independently audited equivalent.
- False-positive restore and emergency exceptions documented and exercised; no blanket enforcement from unapproved policy.

## Gate 3 — Software delivery

- Signed Windows installer/service and controlled automatic updates with rollback.
- Hardening of filesystem/registry/config ACL, bootstrap, service privileges and error handling.
- Performance, reconnect, power-loss recovery and failover tests; restore drill.
- Vulnerability assessment, penetration test and external review of third-party components.

## Gate 4 — Operations, compliance and privacy

- Legal/employee notice and collection minimization approved.
- Alert severity and SOC response owners defined; incident playbooks tested.
- Retention, deletion, audit export, backups and disaster recovery verified.
- Production rollout authorized by CISO, IT operations, privacy/legal and service owners.

## Mandatory evidence template

For every gate item: reviewer, date, environment (Windows version, browser version, agent hash), test command, observed result, artifact link, defects, exception expiry and approver. Mark unknown as NOT VERIFIED, not PASS.

## Current automated evidence

At integration time the original four Python integration tests and four new metadata validation tests were run in a Linux Python environment; this does not validate Windows deployment, GitHub Actions remote CI, upstream plugin activation, DLP effectiveness or enterprise threat prevention. Those remain open.
