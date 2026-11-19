# SentinelGate developer setup on Windows; does not install the plugin in Claude/Codex automatically.
param([switch]$VerifyOnly)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $root
try {
    if (-not $VerifyOnly) {
        & git submodule update --init --checkout -- tools/superpowers
        if ($LASTEXITCODE -ne 0) { throw "Failed to checkout the pinned Superpowers submodule" }
    }
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        & py -3 scripts/verify_superpowers.py --require-checkout
    } else {
        & python scripts/verify_superpowers.py --require-checkout
    }
    if ($LASTEXITCODE -ne 0) { throw "Superpowers verification failed" }
    $env:SUPERPOWERS_DISABLE_TELEMETRY = "1"
    Write-Host "Pinned Superpowers source checkout verified."
    Write-Host "Install the plugin separately inside Claude Code: /plugin install superpowers@claude-plugins-official"
    Write-Host "Or install Superpowers inside Codex via /plugins (search Superpowers)."
    Write-Host "Begin a fresh coding-agent session and verify brainstorming auto-triggers before coding."
} finally {
    Pop-Location
}
