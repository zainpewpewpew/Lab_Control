# SentinelGate change review

## User impact and threat boundary
- What user/system problem is solved?
- Which boundaries change: browser, Windows agent, CISO API, policy, authentication, telemetry?
- Is the feature monitor-only, browser best-effort, or genuinely OS-enforced? Supply evidence.

## Superpowers workflow evidence
- Design/spec: link
- Implementation plan: link
- RED test observed failing (command + failure excerpt):
- GREEN/full suite observed passing (command + result):
- Independent review (critical/important findings and resolutions):

## Security and privacy
- Authorization model and abuse scenarios:
- Secret/token handling:
- Data collected, minimization, retention, and access controls:
- Offline/failure behavior, canary and rollback:
- New dependencies, permissions, or network endpoints:

## Test matrix and deployment
- Windows real-device check:
- Chrome and Edge managed-policy check:
- CI result:
- Known limitations:
- CISO/engineering owner sign-off for production-affecting enforcement:

Checklist: No claim of production-ready EDR/DLP without independent evaluation.
