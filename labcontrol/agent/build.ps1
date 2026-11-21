# Build LabControl agent.exe on Windows (10/11 x64).
# Produces: dist\agent.exe (single-file, all deps embedded, no Python required to install).
#
# Usage (non-elevated is fine; elevation only needed when installing the built .exe):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\build.ps1 -PythonExe "C:\Program Files\Python311\python.exe"
#
# When done, pick up dist\agent.exe and hand it to install_service.ps1 via -AgentExe.
param(
  [string]$PythonExe = "C:\Program Files\Python311\python.exe",
  [string]$OutDir    = "$PSScriptRoot\dist"
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $PythonExe)) { throw "Python 3.11 x64 tidak ada di $PythonExe." }

$build = Join-Path $PSScriptRoot 'buildvenv'
if (Test-Path $build) { Remove-Item -Recurse -Force $build }
& $PythonExe -m venv $build
$py = Join-Path $build 'Scripts\python.exe'

& $py -m pip install --upgrade pip
& $py -m pip install -r "$PSScriptRoot\requirements.txt"
& $py -m pip install pyinstaller==6.10.0

Push-Location $PSScriptRoot
try {
  # Clean previous builds so we always produce a fresh, deterministic artifact.
  if (Test-Path "$PSScriptRoot\build") { Remove-Item -Recurse -Force "$PSScriptRoot\build" }
  if (Test-Path "$PSScriptRoot\dist")  { Remove-Item -Recurse -Force "$PSScriptRoot\dist"  }
  & $py -m PyInstaller agent.spec --noconfirm --clean
} finally {
  Pop-Location
}

$exe = Join-Path $OutDir 'agent.exe'
if (-not (Test-Path $exe)) { throw "Build gagal: agent.exe tidak terbentuk." }
$size = [math]::Round((Get-Item $exe).Length / 1MB, 2)
Write-Host ""
Write-Host "Built: $exe  ($size MB)"
Write-Host "Next: .\install_service.ps1 -AgentExe '$exe' -ServerUrl ... -EnrollSecret ..."
