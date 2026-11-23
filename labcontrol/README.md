# CadenceSec

Transparent employee-endpoint monitoring + policy enforcement + signed remote command, self-hosted. Nol lisensi berbayar.

## Legal (wajib baca sebelum deploy)
- Hanya untuk laptop milik perusahaan (bukan BYOD pribadi tanpa consent tertulis).
- Terdokumentasi di kontrak kerja atau Employee Monitoring Policy yang ditandatangani karyawan.
- Sesuai UU PDP No. 27/2022: tujuan, basis hukum, retensi, hak subjek data.
- Agent **tidak** melakukan: keystroke logging, screen capture, file-content exfiltration, webcam/mic, password harvesting. Scope sengaja dibatasi.
- Pasang login banner Windows yang memberi tahu karyawan bahwa device dimonitor.

## Komponen
```
labcontrol/
├── console/            # FastAPI + SQLite + SSE backend (self-host 1 VM)
│   ├── server.py
│   ├── requirements.txt
│   ├── state/          # DB + signing key (dibuat otomatis)
│   └── web/index.html  # dashboard HTML (dipakai juga oleh ciso-app)
├── agent/              # Anti-tamper Python agent, Windows service + watchdog
│   ├── agent.py
│   ├── requirements.txt
│   ├── install_service.ps1              # install + ACL hardening + watchdog
│   └── admin_emergency_uninstall.ps1    # last-resort local removal (admin only)
├── ciso-app/           # Native Electron desktop app (Mac/Windows/Linux)
│   ├── main.js         # main process: menu, tray, notifications, settings
│   ├── preload.js      # SSE → native notification bridge
│   ├── setup.html      # first-run server URL dialog
│   ├── assets/tray.png
│   ├── package.json
│   └── README.md
└── deploy/
    ├── .env.example
    ├── docker-compose.yml
    └── Dockerfile
```

## Arsitektur
```
[Windows endpoint]                 [Console VM (CISO)]
agent.py  ──bearer token──►  /agent/enroll
          ──bearer token──►  /agent/heartbeat ──► SQLite + SSE broadcast
          ◄── signed cmds   command queue  ◄──  /admin/commands
          ──result──────►   /agent/command-result
                                              │
                                              ├─► Telegram bot
                                              └─► Web dashboard (SSE live)
```
- Transport: HTTPS, TLS 1.2+.
- Auth agent: random bearer token issued on enroll, SHA-256 hash disimpan server.
- Auth command: Ed25519 signature dari console private key; agent verify dengan public key yang disimpan saat enroll. Nonce anti-replay (500 terakhir).
- Agent offline-safe: event di-buffer ke `events.jsonl`, replay saat online.

## Deploy console
Pilih salah satu:

### Opsi 1 - Python langsung
```bash
cd labcontrol/console
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

export CS_ADMIN_USER=admin
export CS_ADMIN_PASSWORD='$(openssl rand -base64 24)'
export CS_SESSION_SECRET=$(openssl rand -hex 32)
export CS_ENROLL_SECRET=$(openssl rand -hex 32)
export CS_TELEGRAM_TOKEN='123456:AA...'       # opsional
export CS_TELEGRAM_CHAT_ID='-1001234567890'   # opsional

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=labcontrol"

uvicorn server:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile key.pem --ssl-certfile cert.pem
```
Buka `https://<ip-vm>:8443` di browser. Login pakai `CS_ADMIN_USER` / `CS_ADMIN_PASSWORD`.

### Opsi 2 - Docker Compose
```bash
cp deploy/.env.example deploy/.env
# isi .env; letakkan key.pem/cert.pem di deploy/certs/
cd deploy && docker compose up -d
```

Simpan `CS_ENROLL_SECRET` baik-baik — itu kunci untuk install agent di tiap endpoint. Rotasi dengan restart console + re-enroll agent lama.

## CISO desktop app (Mac/Windows/Linux)
Native window wrapper; tidak perlu buka browser lagi.

```bash
cd labcontrol/ciso-app
npm install
npm start        # dev mode

# installer native
npm run dist:mac   # → dist/*.dmg
npm run dist:win   # → dist/*.exe (NSIS)
```
First run: isi URL console di dialog Server Settings. Credential CISO di-input saat
login web (SameSite cookie). Fitur: menu bar native, system tray dengan badge unread,
notifikasi OS untuk event severity >= ambang (default 4). Ambang dan URL bisa diubah
via menu `File → Server Settings…` atau `Cmd/Ctrl+,`.

## Deploy agent (per laptop karyawan)
Prasyarat: Python 3.11 x64 terinstall di `C:\Program Files\Python311\python.exe` (atau pass `-PythonExe`).

Elevated PowerShell:
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
cd \path\to\labcontrol\agent
.\install_service.ps1 `
  -ServerUrl https://console.your.corp:8443 `
  -EnrollSecret 'secret-dari-console' `
  -Employee 'firstname.lastname'
```
Script:
1. Copy `agent.py` + deps ke `C:\Program Files\CadenceSec\`.
2. Buat venv dan install requirements.
3. Enroll device → simpan `device_id`, bearer token, console public key ke `C:\ProgramData\CadenceSec\config.json`.
4. Daftarkan Windows service `CadenceSecAgent` (auto-start, restart on failure).

### Anti-tamper yang dipasang install_service.ps1
- Service berjalan sebagai `LocalSystem`.
- ACL `C:\Program Files\CadenceSec\`: Users = ReadExecute, **deny** Write/Delete/ModifyPerms. Admin+SYSTEM = Full.
- ACL `C:\ProgramData\CadenceSec\`: Users = **deny all**. Admin+SYSTEM = Full. Config, token, key, log, event buffer tak bisa dibaca atau dihapus user biasa.
- Service security descriptor via `sc.exe sdset`: Authenticated Users hanya query status, tidak bisa Stop/Pause/ChangeConfig/Delete. Audit on fail.
- Registry service key `HKLM\SYSTEM\CurrentControlSet\Services\CadenceSecAgent`: Users = ReadKey saja (tidak bisa lihat `ImagePath` detail).
- Watchdog scheduled task `CadenceSecWatchdog` jalan tiap 2 menit sebagai SYSTEM, start service jika berhenti. Task file sendiri di-ACL agar user biasa tak bisa lihat atau edit.
- Service failure action: auto-restart 3x dengan backoff 5s/10s/30s.

### Siapa yang bisa stop/uninstall
| Aktor | Bisa stop | Bisa uninstall |
|---|---|---|
| Karyawan (Standard User) | Tidak | Tidak |
| Karyawan (Local Admin pada laptopnya sendiri) | Ya (akan di-restart watchdog ≤2 menit; auditable) | Ya (butuh kill service + task + hapus dir — meninggalkan jejak di event log + console) |
| CISO via console (signed `uninstall` command) | Ya | Ya, bersih, tercatat di tabel `commands` |
| Admin fisik via `admin_emergency_uninstall.ps1` | Ya | Ya, break tamper seal, terlihat di audit |

Local Admin tidak bisa dicegah secara absolut tanpa sertifikat MS untuk PPL atau driver kernel. Mitigasi praktis: **karyawan dikonfigurasi sebagai Standard User** di laptop perusahaan. CISO/IT menyimpan kredensial admin terpisah.

### Uninstall jalur resmi (dari console)
1. CISO login desktop app atau web.
2. Pilih device → tombol "Uninstall" (tambahkan sendiri di toolbar, atau via API):
```
POST /admin/commands
{ "device_id": "dev_...", "action": "uninstall", "args": {} }
```
3. Agent terima di heartbeat berikutnya, verify Ed25519 sig + nonce.
4. Agent spawn detached reaper → stop service, delete service, delete watchdog task, hapus dir Install + Data, lalu `os._exit(0)`.
5. Event `agent_uninstall` sev 8 terbroadcast sebelum exit.

### Uninstall jalur darurat (fisik)
`admin_emergency_uninstall.ps1` di `labcontrol/agent/`. Harus elevated, perlu ketik `UNINSTALL` eksplisit, akan reset ACL + hapus service/task/dir. Gunakan hanya jika console unreachable.

## Yang dilihat CISO
- Daftar device (hostname, employee, last seen).
- Live event feed via Server-Sent Events: process started/ended, logon/logoff, USB plug/unplug, net connect, policy hit, command result, agent start/stop.
- Severity 0–10. Rule engine built-in: `process-blocklist-hit (sev 5)`, `usb-mass-storage-plug (sev 3)`, `logon-after-hours (sev 2)`, `agent-tamper (sev 8)`. Match → kirim ke Telegram bot.
- Command buttons: lock, logoff, reboot, shutdown, run cmd, kill process, collect proc list.
- Policy editor JSON per device:
```json
{
  "process_blocklist": ["mimikatz.exe", "procdump.exe", "teamviewer.exe"],
  "usb_block": true,
  "allow_personal_email": false
}
```

## Yang agent TIDAK lakukan
- Keystrokes
- Screen capture / screenshot periodic
- Webcam / microphone
- Browser history detail (cuma domain via net_connect PID)
- File content copy
- Password / credential harvest

Kalau di kemudian hari butuh salah satu di atas, harus ada consent tegas tertulis tiap karyawan dan DPO sign-off sesuai UU PDP.

## Rotasi secret & disaster recovery
- `CS_ENROLL_SECRET`: ganti di env + restart console. Agent lama tetap jalan (pakai bearer token). Agent baru butuh secret baru.
- `CS_SESSION_SECRET`: ganti → semua sesi admin logout.
- Signing key console di `console/state/signing.key` (Ed25519). Hilang = semua agent tolak command (nggak bisa verify). Backup file ini ke secret manager perusahaan.
- DB: `console/state/cadencesec.db`. Backup rutin.

## Threat model singkat
| Vector | Mitigasi |
|---|---|
| Replay command | Nonce 128-bit + window 500 nonce di state agent |
| MITM | TLS, pinning console pubkey optional (manual) |
| Agent token leak | Token per-device, SHA-256 di DB, rotasi via re-enroll |
| Admin console compromise | HTTPS only, HttpOnly SameSite=Strict cookie, scrypt verify equivalent |
| DoS via event flood | `MAX_EVENTS_PER_HEARTBEAT=200`, `MAX_EVENT_BYTES=256KB` |
| Insider CISO abuse | Audit trail di tabel `events` + `commands`, retensi policy |

## Roadmap v1
- mTLS per device (ganti bearer dengan client cert).
- WebSocket (ganti SSE) untuk bidirectional push command tanpa heartbeat polling.
- ETW File Access telemetry via `pywintrace`.
- GeoIP lookup di console untuk `net_connect` events.
- Backfill compliance report (CIS, PCI) seperti Wazuh.
- macOS + Linux agent (osquery binding).
- Anti-tamper: ACL deny-write di `C:\Program Files\CadenceSec\`, SHA-256 integrity check per startup, alert `agent_tamper` kalau mismatch.

## Transfer (nilai per-operator)
| Variabel | Lokasi | Catatan |
|---|---|---|
| `CS_ADMIN_USER / PASSWORD` | env console | Credential CISO untuk login dashboard |
| `CS_ENROLL_SECRET` | env console | Shared pre-key untuk install agent |
| `CS_TELEGRAM_TOKEN / CHAT_ID` | env console | Dari @BotFather, chat_id dari /getUpdates |
| `ServerUrl` | argumen install_service.ps1 | URL HTTPS console yang reachable dari endpoint |
| `cert.pem/key.pem` | `deploy/certs/` atau console dir | Self-signed OK di LAN, Let's Encrypt untuk WAN |
| Alert rules | tabel `alert_rules` | Edit via API `POST /admin/alert-rules` atau SQL langsung |
