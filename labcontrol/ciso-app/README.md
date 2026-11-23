# CadenceSec CISO Desktop App

Native Mac/Windows/Linux shell untuk CISO console. Membungkus dashboard FastAPI
dalam window native dengan menu bar, system tray, dan notifikasi OS.

## Prasyarat
- Node.js 20 LTS atau 22 LTS
- Console `labcontrol/console/` sudah jalan dan reachable via HTTPS

## Jalankan (development)
```bash
cd labcontrol/ciso-app
npm install
npm start
```
Pada first run akan muncul Server Settings. Isi URL console (contoh `https://console.your.corp:8443`), ambang notifikasi, lalu Save.

## Package (installer native)
```bash
# macOS (produce .dmg di dist/)
npm run dist:mac

# Windows (produce NSIS installer di dist/)
npm run dist:win
```
Untuk Mac notarization + Windows code signing, isi env `CSC_LINK`, `CSC_KEY_PASSWORD`,
`APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD` sesuai docs electron-builder, lalu rerun.

## Fitur native
- **Settings persisten**: `~/Library/Application Support/CadenceSec/config.json` (macOS),
  `%APPDATA%\CadenceSec\config.json` (Windows).
- **System tray**: dot icon di menu bar dengan unread counter.
- **Native notification**: tiap event SSE dengan `severity >= notifyMinSeverity` muncul
  sebagai notifikasi OS. Klik notifikasi → fokus ke window.
- **Reload Console**: `Cmd/Ctrl+R`.
- **Server Settings**: `Cmd/Ctrl+,` kapan saja untuk pindah server atau ganti threshold.
- **Dock badge** (macOS) dan tray title text sync dengan unread.
- **Close to tray**: tombol close hanya menyembunyikan window; quit via menu atau tray.
- **Self-signed TLS**: diterima **hanya** untuk host yang sama dengan `serverUrl`. Cert
  mismatch = koneksi ditolak.

## Keamanan
- `contextIsolation: true`, `nodeIntegration: false`, `sandbox: false` (perlu akses
  `ipcRenderer` di preload).
- Preload tidak expose Node API ke renderer selain `window.lc.*`.
- Preload mem-patch `EventSource` untuk forward event SSE dashboard ke main process
  demi notifikasi native, tanpa mengubah logika dashboard asli.

## Troubleshooting
- "Cannot reach console" → cek firewall, cek `serverUrl`, pastikan `uvicorn` jalan,
  cek cert valid (self-signed harus persis serverUrl).
- Tray icon tak muncul di Linux → butuh `libappindicator3-1` atau `libayatana-appindicator3-1`.
- Notification tidak muncul di Windows → set app ID via Settings → System → Notifications.
