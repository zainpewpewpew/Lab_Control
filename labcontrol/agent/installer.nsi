; NSIS installer for CadenceSec Windows Agent.
; Produces a single self-contained setup.exe that:
;   - Requests elevation (UAC)
;   - Prompts for console URL, enroll secret, employee name
;   - Extracts agent.exe + install_service.ps1 to %TEMP%
;   - Runs install_service.ps1 which does the hardening + service registration
;   - Cleans up temp files
;
; Build (on Windows or via makensis on macOS/Linux):
;   makensis /DAGENT_EXE="dist\agent.exe" /DINSTALL_PS1="install_service.ps1" installer.nsi
;
; Expects (in same dir as the .nsi, or supplied via /D flags):
;   dist\agent.exe
;   install_service.ps1
;   admin_emergency_uninstall.ps1 (optional, bundled as recovery tool)
;   console-cert.pem (optional, auto-imported when present)

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!ifndef AGENT_EXE
  !define AGENT_EXE "dist\agent.exe"
!endif
!ifndef INSTALL_PS1
  !define INSTALL_PS1 "install_service.ps1"
!endif
!ifndef VERSION
  !define VERSION "0.1.0"
!endif

Name "CadenceSec Agent ${VERSION}"
OutFile "CadenceSec-Agent-Setup-${VERSION}.exe"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName"     "CadenceSec Endpoint Protection"
VIAddVersionKey "ProductVersion"  "${VERSION}"
VIAddVersionKey "FileVersion"     "${VERSION}.0"
VIAddVersionKey "CompanyName"     "CadenceSec"
VIAddVersionKey "FileDescription" "CadenceSec Agent installer"
VIAddVersionKey "LegalCopyright"  "CadenceSec"
Unicode true
RequestExecutionLevel admin
InstallDir "$PROGRAMFILES64\CadenceSec"
ShowInstDetails show
ShowUninstDetails show

Var ServerUrl
Var EnrollSecret
Var EmployeeName
Var Dlg
Var LblUrl
Var EdtUrl
Var LblSec
Var EdtSec
Var LblEmp
Var EdtEmp

!define MUI_ABORTWARNING
!define MUI_ICON   "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

!insertmacro MUI_PAGE_WELCOME
Page custom EnrollmentPage EnrollmentPageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Function EnrollmentPage
  !insertmacro MUI_HEADER_TEXT "CadenceSec enrollment" "Isi URL console dan enroll secret yang diberikan CISO."
  nsDialogs::Create 1018
  Pop $Dlg
  ${If} $Dlg == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 12u "Console URL (https://host:port):"
  Pop $LblUrl
  ${NSD_CreateText} 0 14u 100% 12u "https://192.168.1.10:8443"
  Pop $EdtUrl

  ${NSD_CreateLabel} 0 34u 100% 12u "Enroll secret (shared pre-key dari CISO):"
  Pop $LblSec
  ${NSD_CreatePassword} 0 48u 100% 12u ""
  Pop $EdtSec

  ${NSD_CreateLabel} 0 68u 100% 12u "Employee tag (nama atau username):"
  Pop $LblEmp
  ${NSD_CreateText} 0 82u 100% 12u "$USERNAME"
  Pop $EdtEmp

  ${NSD_CreateLabel} 0 110u 100% 20u "Install membutuhkan hak Administrator dan akan menginstall service CadenceSec Endpoint Protection beserta watchdog. Kebijakan Monitoring Policy wajib sudah ditandatangani."

  nsDialogs::Show
FunctionEnd

Function EnrollmentPageLeave
  ${NSD_GetText} $EdtUrl $ServerUrl
  ${NSD_GetText} $EdtSec $EnrollSecret
  ${NSD_GetText} $EdtEmp $EmployeeName

  StrCpy $0 $ServerUrl 8
  ${If} $0 != "https://"
    MessageBox MB_ICONEXCLAMATION "Console URL harus dimulai https://"
    Abort
  ${EndIf}

  StrLen $0 $EnrollSecret
  ${If} $0 < 8
    MessageBox MB_ICONEXCLAMATION "Enroll secret tidak valid (minimal 8 karakter)."
    Abort
  ${EndIf}

  StrLen $0 $EmployeeName
  ${If} $0 < 1
    MessageBox MB_ICONEXCLAMATION "Employee tag kosong."
    Abort
  ${EndIf}
FunctionEnd

Section "Install"
  SetOutPath "$TEMP\CadenceSecSetup"
  File "/oname=agent.exe" "${AGENT_EXE}"
  File "${INSTALL_PS1}"
  File /nonfatal "admin_emergency_uninstall.ps1"
  File /nonfatal "console-cert.pem"

  ${If} ${FileExists} "$TEMP\CadenceSecSetup\console-cert.pem"
    DetailPrint "Importing console certificate to Trusted Root…"
    nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Certificate -FilePath \"$TEMP\CadenceSecSetup\console-cert.pem\" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null"'
    Pop $0
  ${EndIf}

  StrCpy $2 ""
  ${If} ${FileExists} "$TEMP\CadenceSecSetup\console-cert.pem"
    StrCpy $2 ' -CaCert "$TEMP\CadenceSecSetup\console-cert.pem"'
  ${EndIf}

  DetailPrint "Running install_service.ps1 (service + hardening)…"
  StrCpy $0 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$TEMP\CadenceSecSetup\install_service.ps1" -AgentExe "$TEMP\CadenceSecSetup\agent.exe" -ServerUrl "$ServerUrl" -EnrollSecret "$EnrollSecret" -Employee "$EmployeeName"$2'
  nsExec::ExecToLog $0
  Pop $1
  ${If} $1 != 0
    MessageBox MB_ICONSTOP "Install gagal (exit code $1). Baca detail di jendela ini, lalu tutup."
    Abort
  ${EndIf}

  CreateDirectory "$INSTDIR"
  CopyFiles /SILENT "$TEMP\CadenceSecSetup\admin_emergency_uninstall.ps1" "$INSTDIR\admin_emergency_uninstall.ps1"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CadenceSecAgent" "DisplayName"      "CadenceSec Endpoint Protection"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CadenceSecAgent" "DisplayVersion"  "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CadenceSecAgent" "Publisher"       "CadenceSec"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CadenceSecAgent" "UninstallString" "$INSTDIR\Uninstall.exe"

  RMDir /r "$TEMP\CadenceSecSetup"
SectionEnd

Section "Uninstall"
  DetailPrint "Running admin_emergency_uninstall.ps1 (break tamper seal)…"
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "echo UNINSTALL | & \"$INSTDIR\admin_emergency_uninstall.ps1\""'
  Pop $0
  Delete "$INSTDIR\Uninstall.exe"
  RMDir  "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CadenceSecAgent"
SectionEnd
