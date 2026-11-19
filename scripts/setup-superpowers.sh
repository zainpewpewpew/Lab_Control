#!/usr/bin/env bash
# SentinelGate developer setup on macOS/Linux; plugin installation remains a separate step.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
git submodule update --init --checkout -- tools/superpowers
python3 scripts/verify_superpowers.py --require-checkout
export SUPERPOWERS_DISABLE_TELEMETRY=1
printf '%s\n' \
  'Pinned Superpowers source checkout verified.' \
  'Claude Code plugin: /plugin install superpowers@claude-plugins-official' \
  'Codex plugin: /plugins ; search Superpowers and install' \
  'Start a new agent session; verify brainstorming auto-triggers before feature work.'
