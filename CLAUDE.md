# SentinelGate Enterprise — Claude Code Project Instructions

Read AGENTS.md first. Read docs/superpowers/INTEGRATION.md before changing agent workflows and docs/security/THREAT_MODEL.md before changing any trust boundary.

## Install and use Superpowers

Official Claude Code marketplace (run inside Claude Code):

~~~text
/plugin install superpowers@claude-plugins-official
~~~

Use scripts/setup-superpowers.ps1 on Windows or scripts/setup-superpowers.sh on macOS/Linux to fetch and verify the reviewed upstream SUBMODULE. The plugin installation is separate and requires installation into Claude Code; merely cloning this repository does not activate any Superpowers skills.

Follow the official Superpowers workflow: brainstorming, writing-plans, using-git-worktrees, test-driven-development, systematic-debugging, requesting-code-review, verification-before-completion, finishing-a-development-branch. Do not invent command names or pretend a skill was invoked when unavailable.

## Product-specific safeguards

- CISO console, Windows agent, and browser extension are the three security-sensitive components.
- Do not broaden browser extension permissions or add TLS-interception, credential collection, stealth persistence, or employee surveillance without a separately approved design, threat model, and tests.
- Treat policy changes as versioned security decisions with authorization, rollback, and explicit audit logging.
- Enforce minimal collection: domains/metadata only. Do not ingest file contents or passwords.
- Do not equate browser content-script upload interception with OS-wide DLP; do not call post-download quarantine antivirus.
- Keep pilot safety defaults: monitor first, enforce only when intentionally configured.
- Tests and security review are required before deployment; CI passing alone is not sign-off.
