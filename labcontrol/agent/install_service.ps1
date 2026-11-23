# CadenceSec agent installer with anti-tamper hardening.
# Elevated PowerShell required. Target: Windows 10/11 x64 company-owned laptops.
# Disclosure precondition: employee has signed the Monitoring Policy. Do NOT install covertly.
#
# Two modes:
#   (A) Single-file binary (recommended): build dulu di mana saja via `build.ps1`,
#       lalu panggil installer dengan `-AgentExe`. Zero Python di endpoint.
#       Example:
#         .\install_service.ps1 -AgentExe .\agent.exe `
#           -ServerUrl https://console.your.corp:8443 -EnrollSecret 'xxx' -Employee 'nama'
#
#   (B) Python mode (fallback): agent.py dijalankan oleh venv di endpoint.
#       Butuh Python 3.11 x64 terinstall di `C:\Program Files\Python311\`.
#         .\install_service.ps1 -ServerUrl https://... -EnrollSecret 'xxx' -Employee 'nama'
param(
  [Parameter(Mandatory=$true)][string]$ServerUrl,
  [Parameter(Mandatory=$true)][string]$EnrollSecret,
  [string]$Employee        = $env:USERNAME,
  [string]$AgentExe        = "",
  [string]$CaCert          = "",
  [string]$PythonExe       = "C:\Program Files\Python311\python.exe",
  [string]$InstallDir      = "C:\Program Files\CadenceSec",
  [string]$DataDir         = "C:\ProgramData\CadenceSec",
  [string]$ServiceName     = "CadenceSecAgent",
  [string]$ServiceDisplay  = "CadenceSec Endpoint Protection",
  [string]$WatchdogTask    = "CadenceSecWatchdog",
  [int]$WatchdogMinutes    = 2
)
$ErrorActionPreference = 'Stop'
function Require-Admin {
  $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run elevated (Administrator)."
  }
}
Require-Admin

$useExe = $false
if ($AgentExe -ne "") {
  if (-not (Test-Path $AgentExe)) { throw "Agent executable tidak ditemukan: $AgentExe" }
  $useExe = $true
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir    | Out-Null

# Ship the self-signed console cert next to the agent, so httpx pins TLS
# verification to this one CA without touching the OS trust store.
if ($CaCert -ne "") {
  if (-not (Test-Path $CaCert)) { throw "Console cert tidak ditemukan: $CaCert" }
  Copy-Item -Force $CaCert "$DataDir\console-cert.pem"
}

if ($useExe) {
  Copy-Item -Force $AgentExe "$InstallDir\agent.exe"
  $binary   = "$InstallDir\agent.exe"
  $enrollBin = $binary
  $runBin    = $binary
} else {
  if (-not (Test-Path $PythonExe)) { throw "Python 3.11 x64 tidak ada di $PythonExe. Pakai -AgentExe atau install Python." }
  Copy-Item -Force "$PSScriptRoot\agent.py"         "$InstallDir\agent.py"
  Copy-Item -Force "$PSScriptRoot\requirements.txt" "$InstallDir\requirements.txt"
  & $PythonExe -m venv "$InstallDir\venv"
  $venvPy = "$InstallDir\venv\Scripts\python.exe"
  & $venvPy -m pip install --upgrade pip
  & $venvPy -m pip install -r "$InstallDir\requirements.txt"
  $enrollBin = "`"$venvPy`" `"$InstallDir\agent.py`""
  $runBin    = "`"$venvPy`" `"$InstallDir\agent.py`" run"
}

# One-time enrollment (writes config + keypair to %ProgramData%\CadenceSec\).
if ($useExe) {
  & $binary enroll --server-url $ServerUrl --enroll-secret $EnrollSecret --employee $Employee
} else {
  $argList = @("`"$InstallDir\agent.py`"", "enroll",
               "--server-url", $ServerUrl,
               "--enroll-secret", $EnrollSecret,
               "--employee", $Employee)
  & $venvPy @argList
}

# Register (or replace) the service.
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  sc.exe stop   $ServiceName | Out-Null
  Start-Sleep -Seconds 2
  sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 2
}
if ($useExe) {
  $binPath = "`"$binary`" run"
} else {
  $binPath = "`"$venvPy`" `"$InstallDir\agent.py`" run"
}
sc.exe create $ServiceName binPath= $binPath start= auto obj= LocalSystem DisplayName= "$ServiceDisplay" | Out-Null
sc.exe description $ServiceName "Endpoint telemetry and policy enforcement, operated by the IT Security team per the signed Employee Monitoring Policy." | Out-Null
sc.exe failure     $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

# --- Anti-tamper hardening ---
# Use well-known SIDs so ACL lines work on every Windows locale (ID, ES, JA, ...).
# *S-1-5-18  = SYSTEM
# *S-1-5-32-544 = Administrators
# *S-1-5-32-545 = Users

# 1. Install dir ACL: Users=ReadExecute, Admins/SYSTEM=Full. Deny write/delete/attr for Users.
icacls $InstallDir /inheritance:r | Out-Null
icacls $InstallDir /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
icacls $InstallDir /deny  "*S-1-5-32-545:(OI)(CI)(DE,WD,AD,WDAC,WO)" | Out-Null

# 2. Data dir ACL: SYSTEM/Admins full; Users denied entirely (telemetry + token kept private).
icacls $DataDir /inheritance:r | Out-Null
icacls $DataDir /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
icacls $DataDir /deny  "*S-1-5-32-545:(OI)(CI)F" | Out-Null

# 3. Service SDDL: Authenticated Users query-only; no Stop/Pause/Config/Delete for non-admin.
$svcSddl = "D:(A;;CCLCRPRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
sc.exe sdset $ServiceName $svcSddl | Out-Null

# 4. Watchdog scheduled task: SYSTEM, every N minutes, start service if stopped.
$wdCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"if ((Get-Service -Name '$ServiceName' -ErrorAction SilentlyContinue).Status -ne 'Running') { Start-Service -Name '$ServiceName' }`""
schtasks.exe /Delete /TN $WatchdogTask /F 2>$null | Out-Null
schtasks.exe /Create /TN $WatchdogTask /SC MINUTE /MO $WatchdogMinutes /RL HIGHEST /RU SYSTEM /TR $wdCmd /F | Out-Null

$taskPath = "$env:SystemRoot\System32\Tasks\$WatchdogTask"
if (Test-Path $taskPath) {
  icacls $taskPath /inheritance:r | Out-Null
  icacls $taskPath /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
}

# 5. Lock the service registry key so standard users cannot read secret paths.
# Use SIDs directly so this works on every Windows locale.
$svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (Test-Path $svcRegPath) {
  $sidSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $sidUsers  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
  $acl = Get-Acl $svcRegPath
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($r in @($acl.Access)) { $acl.RemoveAccessRule($r) | Out-Null }
  $rules = @(
    (New-Object System.Security.AccessControl.RegistryAccessRule($sidSystem,"FullControl","ContainerInherit","None","Allow")),
    (New-Object System.Security.AccessControl.RegistryAccessRule($sidAdmins,"FullControl","ContainerInherit","None","Allow")),
    (New-Object System.Security.AccessControl.RegistryAccessRule($sidUsers,"ReadKey","None","None","Allow"))
  )
  foreach ($r in $rules) { $acl.AddAccessRule($r) }
  Set-Acl $svcRegPath $acl
}

# 6. Start.
sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 2
$st = (Get-Service -Name $ServiceName).Status
$mode = if ($useExe) { "single-file exe" } else { "python venv" }

Write-Host ""
Write-Host "CadenceSec agent installed ($mode mode)."
Write-Host "  Service   : $ServiceName ($ServiceDisplay) — status: $st"
Write-Host "  Watchdog  : $WatchdogTask (every $WatchdogMinutes min as SYSTEM)"
Write-Host "  Install   : $InstallDir   (Users ACL: ReadExecute, deny write/delete)"
Write-Host "  Data      : $DataDir      (Users ACL: denied)"
Write-Host "  Logs      : $DataDir\agent.log"
Write-Host "  Config    : $DataDir\config.json (SYSTEM only)"
Write-Host ""
Write-Host "Standard users cannot stop, delete, or modify the agent or its data."
Write-Host "Removal: signed 'uninstall' command from the CISO console (preferred), OR"
Write-Host "run admin_emergency_uninstall.ps1 locally as Administrator (breaks tamper seal — logged)."
