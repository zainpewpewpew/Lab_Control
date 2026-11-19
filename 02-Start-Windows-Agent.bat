@echo off
setlocal
cd /d "%~dp0"
if not exist agent\agent-config.json (
  echo Missing agent\agent-config.json.
  echo Use the CISO Console Endpoints page to register and copy configuration.
  pause
  exit /b 1
)
where py >NUL 2>&1
if errorlevel 1 (
  echo Python Launcher not found. Install Python 3.10 or newer.
  pause
  exit /b 1
)
echo Starting SentinelGate Endpoint Agent on 127.0.0.1:8898
py -3 agent\agent.py
pause
