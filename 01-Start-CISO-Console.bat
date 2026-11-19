@echo off
setlocal
cd /d "%~dp0"
where py >NUL 2>&1
if errorlevel 1 (
  echo Python Launcher not found. Install Python 3.10 or newer and enable py launcher.
  pause
  exit /b 1
)
echo Starting SentinelGate CISO Console at http://127.0.0.1:8899
py -3 console\server.py
pause
