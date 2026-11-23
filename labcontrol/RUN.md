# CadenceSec — Panduan Menjalankan

Dokumen ini adalah urutan konkret menjalankan CadenceSec untuk pilot dua laptop (Mac CISO + Windows user) setelah kedua file deliverable dibangun. Tiga komponen harus hidup berurutan: console, CISO app, agent.

## Prasyarat yang sudah selesai

- `labcontrol/dist/CadenceSec-0.1.0.dmg` (CISO Mac app, 91 MB) sudah di-build.
- `labcontrol/dist/CadenceSec-Agent-Setup.exe` (Windows agent installer, 22 MB) sudah di-build via GitHub Actions.
- `labcontrol/console/.env` berisi `CS_ADMIN_USER`, `CS_ADMIN_PASSWORD`, `CS_SESSION_SECRET`, `CS_ENROLL_SECRET`. File ini sensitif dan sudah di-gitignore — jangan commit.
- `labcontrol/console/state/cert.pem` + `key.pem` sudah di-generate dengan SAN yang mencakup `127.0.0.1`, `localhost`, dan IP LAN Mac CISO (misal `192.168.0.140`).
- Karyawan sudah tanda-tangan Employee Monitoring Policy dan DPIA sesuai UU PDP 27/2022.

Catatan jaringan: console `https://<IP-LAN-Mac>:8443` hanya reachable di jaringan yang sama. Pastikan Mac CISO dan Windows user di satu Wi-Fi/LAN.

## 1. Jalankan console di Mac CISO

Dari terminal:

```bash
cd "/Users/rizkyasepsutrisna/DATA E/FREELANCE/Proyek Instagram/Lab_Control/labcontrol/console"
nohup ./start.sh > state/console.log 2>&1 &
disown
```

Cek hidup:

```bash
curl -k https://127.0.0.1:8443/health
```

Harus balas `{"ok":true,"ts":...}`. Log jalan di `labcontrol/console/state/console.log`.

Stop console:

```bash
pkill -f "server:app"
```

Jika mau console auto-start setiap Mac boot, pasang launchd agent (file `~/Library/LaunchAgents/com.labcontrol.console.plist` yang panggil `start.sh`); minta dibuatkan bila perlu.

## 2. Install CISO app di Mac CISO

1. Double-click `labcontrol/dist/CadenceSec-0.1.0.dmg`.
2. Drag ikon `CadenceSec.app` ke folder `Applications`.
3. Jalankan dari Launchpad. Pertama kali Gatekeeper akan menolak karena app belum di-code-sign: klik kanan pada ikon → **Open** → **Open** di dialog peringatan. Ini hanya sekali per app.
4. Buka menu `File → Server Settings…` (atau `Cmd+,`). Isi:
   - **Console URL:** `https://192.168.0.140:8443` (ganti ke IP LAN Mac Anda; cek dengan `ipconfig getifaddr en0`).
   - **Severity threshold:** default `4` untuk notifikasi macOS.
5. Login dengan `admin` dan password dari `labcontrol/console/.env` baris `CS_ADMIN_PASSWORD`.
6. Pada koneksi pertama, app menampilkan fingerprint SHA-256 sertifikat console dan memintanya di-pin (TOFU). Setujui. Pin disimpan di Electron userData; mismatch di koneksi berikutnya akan hard-fail dan hanya bisa di-reset dari Server Settings.

## 3. Deploy agent di laptop Windows user

Lakukan ini setelah console hidup dan jaringan sudah satu LAN.

1. Transfer `CadenceSec-Agent-Setup.exe` dari Mac ke laptop Windows user (USB, SMB share, atau SCP).
2. Double-click file. UAC prompt muncul — pilih **Yes** untuk elevated.
3. Wizard NSIS menanyakan tiga field:
   - **Console URL:** `https://192.168.0.140:8443` (nilai sama dengan di CISO app).
   - **Enroll secret:** nilai dari `labcontrol/console/.env` baris `CS_ENROLL_SECRET`.
   - **Employee tag:** nama atau username karyawan, bebas, untuk label di dashboard.
4. Klik **Install**. Installer akan:
   - Ekstrak `agent.exe` ke `C:\Program Files\CadenceSec\`.
   - Jalankan `install_service.ps1`: enroll ke console, register service `CadenceSecAgent` sebagai `LocalSystem`, pasang ACL hardening (install dir deny-write bagi Users, data dir deny-all bagi Users), set SDDL service (Authenticated Users query-only), register scheduled task `CadenceSecWatchdog` tiap 2 menit sebagai SYSTEM, lock registry key service.
   - Start service.
5. Device muncul di CISO app ≤30 detik. Nama host, employee tag, dan timestamp `last_seen` terlihat di tab Devices.

Verifikasi dari laptop Windows (opsional, elevated PowerShell):

```powershell
Get-Service CadenceSecAgent
Get-ScheduledTask CadenceSecWatchdog
Get-Content C:\ProgramData\CadenceSec\agent.log -Tail 20
```

## Operasi harian dari CISO app

- **Live event feed** (SSE) menampilkan proses, logon, USB plug, net_connect, dan command result real-time.
- **Command buttons** yang tersedia: `lock_workstation`, `shutdown`, `reboot`, `logoff`, `kill_process`, `collect_proclist`, `collect_usb_list`, `collect_net_list`, `uninstall`, `self_test`. `run_cmd` sengaja dihapus pada audit remediation karena risiko SYSTEM-level RCE fleet-wide tidak sepadan.
- **Policy editor JSON** per device: field `process_blocklist` (array nama exe lower-case), `usb_block`, `allow_personal_email`. Setiap perubahan tercatat ke tabel `policy_history` dengan `updated_by`, `version`, dan `updated_at` — bisa di-query `GET /admin/policy/<device_id>/history` untuk audit DPIA.
- **Alert rules** terseed otomatis: `process-blocklist-hit (sev 5)`, `usb-mass-storage-plug (sev 3)`, `logon-after-hours (sev 2)`, `agent-tamper (sev 8)`. Match → notifikasi OS di CISO app + Telegram bila `CS_TELEGRAM_TOKEN`/`CS_TELEGRAM_CHAT_ID` di-set.

## Uninstall agent

Jalur resmi: dari CISO app kirim signed command `uninstall`. Agent verifikasi signature Ed25519 + nonce + `issued_at` (reject bila > 24 jam), lalu spawn reaper yang stop service, hapus scheduled task, bersihkan `C:\Program Files\CadenceSec\` dan `C:\ProgramData\CadenceSec\`, kemudian copy `agent.log` terakhir ke `C:\Windows\Logs\CadenceSec-uninstall-<timestamp>.log` untuk forensik.

Jalur darurat (console tidak reachable): di laptop Windows, elevated PowerShell:

```powershell
cd 'C:\Program Files\CadenceSec'
.\admin_emergency_uninstall.ps1
# wajib ketik: UNINSTALL
```

Ini merusak tamper seal dan akan terbaca di event log.

## Troubleshooting

- **Device tak muncul di CISO app setelah install.** Cek `C:\ProgramData\CadenceSec\agent.log`. Umumnya sertifikat console belum dipercaya di Windows — installer coba `Import-Certificate` otomatis bila `console-cert.pem` di-bundle. Jika tidak, copy manual `labcontrol/console/state/cert.pem` ke laptop lalu di PowerShell admin: `Import-Certificate -FilePath .\cert.pem -CertStoreLocation Cert:\LocalMachine\Root`.
- **Agent reject semua command ("bad signature").** Signing key di `labcontrol/console/state/signing.key` sudah pernah hilang atau diganti. Device public key dari enroll lama tidak lagi cocok. Fix: uninstall agent lewat `admin_emergency_uninstall.ps1` lalu install ulang untuk re-enroll.
- **Agent tak heartbeat setelah laptop user pindah jaringan.** `ServerUrl` yang disimpan agent berupa IP LAN. Untuk pilot, jaga kedua laptop di satu LAN. Untuk produksi, pasang DDNS/hostname publik + port-forward 8443 di router, regen `cert.pem` dengan SAN berisi hostname itu, rebuild + reinstall agent.
- **Console mati sementara.** Agent buffer event ke `C:\ProgramData\CadenceSec\events.jsonl` (cap 8 MiB, rotasi otomatis). Saat console hidup lagi, event tersisa di-sync di heartbeat berikutnya.

## Rotasi secret

- Ganti `CS_ENROLL_SECRET`: edit `labcontrol/console/.env`, restart console. Agent yang sudah terdaftar tidak terpengaruh (pakai bearer token). Hanya enroll berikutnya butuh secret baru.
- Ganti `CS_ADMIN_PASSWORD`: edit `.env`, restart console. Semua sesi admin logout.
- Ganti `CS_SESSION_SECRET`: edit `.env`, restart console. Cookie session invalid; admin login ulang.
- **Jangan** ganti/kehilangan `labcontrol/console/state/signing.key`. Hilang = seluruh armada tolak command. Backup ke secret manager perusahaan.

## File yang sensitif dan tak boleh di-commit

Sudah tercover `.gitignore`, tapi untuk diingat:

- `labcontrol/console/.env` — berisi admin password + enroll secret + session secret.
- `labcontrol/console/state/` — berisi `cadencesec.db`, `signing.key`, `key.pem`, `cert.pem`.
- `labcontrol/agent/dist/` dan `labcontrol/agent/*.exe` — hasil build lokal.
- `labcontrol/dist/` — DMG + Setup.exe + QUICKSTART.
