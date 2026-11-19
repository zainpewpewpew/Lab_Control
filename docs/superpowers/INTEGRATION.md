# Superpowers Integration — SentinelGate engineering

## Why it is in this repository

Superpowers (obra/superpowers, MIT license) is an agentic software-development methodology, NOT a Windows endpoint security agent, antivirus signature engine, browser filter or DLP driver. It belongs exclusively in the development toolchain. Security enforcement continues to be implemented in SentinelGate components and/or verified enterprise security products.

Reviewed source: https://github.com/obra/superpowers
Pinned upstream commit: 22f0b463e7a5e579904dd6211a520321035526f7
Upstream version reported at pin: 7.0.2
Manifest: superpowers.lock.json ; gitlink: tools/superpowers ; review script: scripts/verify_superpowers.py
Do not copy upstream skill files into the application runtime or add the Superpowers plugin as a Windows endpoint dependency.

## Checkout and installation

A normal Git clone may leave submodules uninitialized. Run from the SentinelGate repository root:

Windows PowerShell:
~~~powershell
.\scripts\setup-superpowers.ps1
~~~

macOS or Linux shell:
~~~bash
bash scripts/setup-superpowers.sh
~~~

The scripts run git submodule update --init --checkout -- tools/superpowers, then check that the gitlink, lockfile and checkout agree. They do NOT silently install the plugin into a coding agent, enable any third-party executable hooks, or install software on employee devices.

For Claude Code (inside the CLI, according to upstream README):
~~~text
/plugin install superpowers@claude-plugins-official
~~~

For Codex app/CLI, install Superpowers through its official Plugins catalog (Codex CLI: /plugins, search Superpowers). For OpenCode V2 (>= 2.0.4), follow upstream docs/README.opencode.md and use its native git-backed plugin setting. Install separately for each coding harness; a Git submodule on disk is not an active agent bootstrap.

In enterprise environments opt out of the optional logo/version visual-companion telemetry by setting SUPERPOWERS_DISABLE_TELEMETRY=1 in the coding-agent process environment. Installation scripts set that variable for their own process only; configure it in the actual agent-launch environment if needed.

## Prove the skill system is actually active

1. Start a FRESH session after installing the official plugin.
2. Give the neutral test request "Let's make a react todo list".
3. Verify the agent invokes brainstorming BEFORE writing code.
4. If no skill fires, diagnose the plugin installation in that coding harness; possession of tools/superpowers alone is insufficient.
5. Record a short verification note with harness/version and skill invocation in your PR. Never claim invocation without actual evidence.

## Mapping official skills to SentinelGate changes

| Change point | Official Superpowers skill | Artifact or evidence |
|---|---|---|
| New capability | brainstorming | problem, threat boundary, alternatives, approved design in docs/superpowers/designs/ |
| Ready design | writing-plans | small executable tasks and tests in docs/superpowers/plans/ |
| Starting implementation | using-git-worktrees | isolated workspace + passing baseline |
| Each behavior change | test-driven-development | RED -> GREEN -> REFACTOR evidence |
| Complex defect | systematic-debugging | reproducible root cause and regression |
| Parallel changes | dispatching-parallel-agents / subagent-driven-development | independent task + spec/code review; no shared dirty files |
| End of each task | requesting-code-review / receiving-code-review | severity-ranked findings and fixes |
| Before any success claim | verification-before-completion | fresh full commands and outputs |
| Before integration | finishing-a-development-branch | reviewed PR, test evidence, merge decision |

The local sentinelgate-security-review skill adds domain-specific gates, without modifying upstream Superpowers core. The normal Superpowers process skills remain authoritative for development flow.

## Non-negotiable SentinelGate policies

- No automatic pushing of enforcement rules to every employee device from an unreviewed AI suggestion.
- Any increase in browser permissions, OS privilege, telemetry collection, or policy failure-closed behavior requires an explicit threat model and approval.
- Always test permitted use cases alongside blocked cases; the product must not destroy employee work due to false positives.
- A red/green test of an HTML file-picker cannot establish native-app or OS-wide upload protection.
- Never add direct credentials to git, CI logs, event payloads or prompt context.
- Do not introduce new dependencies without reviewing provenance, license, maintenance and update path.

## Updating the pinned submodule

In a clean local worktree:
1. Read upstream release notes, LICENSE, skills changed and breaking changes. Obtain approval for an upgrade.
2. Update the checked-out tools/superpowers revision to the reviewed full commit SHA.
3. Update superpowers.lock.json revision and version at pin in the SAME commit as the gitlink change.
4. Run scripts/verify_superpowers.py --require-checkout, full tests, review the gitlink diff and CI.
5. Merge only after peer review. Do not use unpinned git clone or latest branch in release workflow.

## Source / attribution

Upstream MIT: https://github.com/obra/superpowers/blob/main/LICENSE
Project-specific guidance is SentinelGate-owned and is not submitted upstream. Superpowers is for development, not the production endpoint agent.
