# EMERGENCY LOCAL UNINSTALL. Breaks the tamper seal and is auditable at the console.
# Prefer the signed 'uninstall' command from the CISO console instead. Only use this when
# the console is unreachable and physical admin access to the endpoint is available.
#
# Elevated PowerShell required.
param(
  [string]$InstallDir    = "C:\Program Files\CadenceSec",
  [string]$DataDir       = "C:\ProgramData\CadenceSec",
  [string]$ServiceName   = "CadenceSecAgent",
  [string]$WatchdogTask  = "CadenceSecWatchdog",
  [switch]$KeepData
)
$ErrorActionPreference = 'Stop'
$p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run elevated (Administrator)."
}

Write-Warning "You are removing CadenceSec locally. This breaks the tamper seal; the last heartbeat may or may not have reached the console."
$ans = Read-Host "Type UNINSTALL to continue"
if ($ans -ne 'UNINSTALL') { Write-Host "Aborted."; return }

schtasks.exe /Delete /TN $WatchdogTask /F 2>$null | Out-Null
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  sc.exe stop   $ServiceName | Out-Null
  Start-Sleep -Seconds 3
  sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 2
}
if (Test-Path $InstallDir) {
  icacls $InstallDir /reset /T /C /Q | Out-Null
  Remove-Item -Recurse -Force $InstallDir
}
if (-not $KeepData -and (Test-Path $DataDir)) {
  icacls $DataDir /reset /T /C /Q | Out-Null
  Remove-Item -Recurse -Force $DataDir
}
Write-Host "CadenceSec removed locally. Notify the CISO so the device record can be retired at the console."
