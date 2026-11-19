# SentinelGate Enterprise — Windows Security Control Center (MVP / Pilot)

**Defensive, transparent Windows endpoint pilot** for corporate IT/CISO teams. Includes a central CISO Console, Windows Endpoint Agent, and Chrome / Microsoft Edge MV3 browser extension.

**Pilot only. NOT a production-grade EDR, antivirus, secure web gateway, or content-aware DLP.** Use it in an authorized test environment before enterprise rollout.

## Implemented in this package

| Feature | Implementation | Boundary |
|---|---|---|
| Central CISO dashboard | Login, last-24h event summary, endpoints, last heartbeat, recent security events | Local pilot server; not yet SSO/RBAC |
| Website blocklist | Browser extension uses `chrome.declarativeNetRequest` to block configured domains and subdomains | Enforced only in Chrome / Edge with extension installed and enabled |
| Restricted browser downloads | Browser `downloads` API attempts to cancel transfers by filename / URL extension | Best effort, may race with download; not malware analysis |
| Restricted browser uploads | Content script checks `<input type=file>`, file picker changes, drag/drop, and form submission by domain, extension, size | Cannot comprehensively intercept arbitrary JavaScript uploads, clipboard, all browser APIs, or native applications |
| Windows Downloads monitoring | Agent watches current user's Downloads folder, logs restricted file types, moves them to local quarantine folder | **Post-download**, not real-time AV and not all user/app folders |
| Central policy | Enforce or monitor; domain and file-extension lists; upload size limit | Last-known policy stays cached when central server temporarily unreachable |
| Endpoint telemetry | Device identity, event type, action, domain, extension, file size, policy reason | No keystrokes, screen captures, browsing history, or document contents |
| Endpoint registration | CISO generates unique bearer token per device | Token copied manually; no cert enrollment or MDM yet |

## Requirements

- Windows 10/11, Python **3.10 or newer**, Chrome or Microsoft Edge.
- Admin/test PC runs central server. For same-PC pilot, console and agent can run on one Windows machine.
- Managed browser extension must be installed manually for a lab pilot, **force-installed via your device management system in production**.

## Quick start — one Windows test PC

1. Extract ZIP into a folder accessible to your account (e.g. `C:\SentinelGate-Pilot`).
2. Run `01-Start-CISO-Console.bat` (or `py -3 console\server.py`).
3. Open **http://127.0.0.1:8899**. The initial admin username is `admin`. The **first-run random password** is in `console\state\bootstrap-admin.txt` (restrict access and delete after storing in a password manager).
4. In **Endpoints** choose **Register endpoint**, assign a test device name, then copy the full JSON configuration.
5. Paste it into a new file `agent\agent-config.json`. The value `bridge_token` is shared between the local extension and local Windows agent; treat it as a secret.
6. Run `02-Start-Windows-Agent.bat` (or `py -3 agent\agent.py`).
7. Open `edge://extensions/` or `chrome://extensions/` → Developer mode → **Load unpacked** → select the `extension` directory. In extension **Options**, paste the `bridge_token` from `agent-config.json`.
8. In console **Web Protection**, add `example.invalid` as a blocked domain. Set mode **Enforce** and save. Extension sync takes up to roughly one minute after the Windows agent has synchronized. Navigate to `https://example.invalid/` to verify blocking.
9. Test upload policy on a **test site you own** using a dummy `.key` or `.sql` test file. Do **not** use sensitive production data as test material.
10. Test monitoring with dummy files in your own Windows Downloads folder. Files moved by agent are held in `agent\state\quarantine` with randomized names (no automatic deletion).

**Important:** On first run, the agent ignores existing files in Downloads; it only processes new stable files after launch. Agent intentionally starts in monitor mode if no policy cache exists. Policy is synced from console on connection.

## Multiple Windows endpoints / LAN pilot

For an endpoint on another machine, the central console must have a reachable **HTTPS address and a trusted TLS certificate**. The console refuses a non-loopback bind unless passed `--tls-cert` and `--tls-key`.

Example on central management host (requires you to supply a certificate and key):

```powershell
py -3 console\server.py --host 0.0.0.0 --port 8899 --tls-cert C:\certs\console.crt --tls-key C:\certs\console.key
```

Open the console via `https://your-management-host.example:8899` so the generated `server_url` points to a trusted, reachable hostname. Do not expose the pilot server to the public internet; restrict network access to authorized corporate IP ranges. Client TLS verification is **enabled**; no insecure skip-verify switch is provided.

## Policy semantics

- `blocked_domains`: browser website domain blocklist. Exact hostname and subdomains.
- `blocked_upload_domains`: content-script upload blocklist by page hostname.
- `blocked_download_extensions`: Chrome/Edge download cancellation + Windows Downloads post-download quarantine.
- `blocked_upload_extensions`: file-picker / form upload controls by extension.
- `max_upload_mb`: max size of an individual file sent through the supported browser flows.
- `mode` = `monitor`: record matching actions without intentionally blocking; = `enforce`: enforce supported browser rules and quarantine restricted extensions in Downloads.

## Security & privacy constraints

- This is a **visible corporate security product**. Tell employees which categories of security events are logged, document the company security policy, define retention and access rights, and comply with local privacy and labor regulations.
- Does not collect clipboard contents, keystrokes, screenshots, file bodies, passwords, query strings, or full browsing history.
- Agent, extension, and console are not hardened against tampering by local administrators. The extension can be disabled unless deployed using managed-browser policy.
- Local bridge listens on `127.0.0.1:8898`, requires a token, and accepts the `chrome-extension://` origin. Central console uses session cookies, CSRF token, salted PBKDF2 hashing, and separate per-device API tokens. Initial admin setup is a bootstrap mechanism only.
- Local quarantine is **not** Windows Defender quarantine. The agent does not classify files as malware.
- Agent stores a last-known policy cache and a plaintext JSONL queue containing security metadata only. Apply Windows ACL protections to both data folders and configuration secrets. Event queue retries may create duplicates after network interruptions.
- Console SQLite events are currently retained indefinitely. Configure a retention period and encryption/backup policy before production deployment.
- **No production rollout without**: AD/Entra SSO + RBAC, signing, code integrity, Windows Service with recovery, managed extension deployment, hardened enrollment and certificate rotation, validated secure updates, external audit log storage, secure retention, structured admin policy approval, compliance review, and security testing.

## Enterprise architecture recommendation

1. Microsoft Defender for Endpoint + Network Protection for malware/phishing protection and web content filtering across supported browsers and nonbrowser processes.
2. Microsoft Purview Endpoint DLP for sensitive-data classification and restrictions on risky cloud uploads, clipboard and restricted app activities.
3. Microsoft Intune for managed deployment, browser extensions, device control, and Windows Defender settings.
4. App Control for Business / AppLocker for restricting unknown executable programs and scripts.
5. SentinelGate dashboard as a policy workflow and incident reporting layer **only after production integration and hardening**.

Official references:

- https://learn.microsoft.com/defender-endpoint/network-protection
- https://learn.microsoft.com/en-us/defender-endpoint/web-content-filtering
- https://learn.microsoft.com/en-us/purview/dlp-configure-endpoint-settings
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol
- https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest

## Package structure

```
SentinelGate-Enterprise-MVP/
  01-Start-CISO-Console.bat
  02-Start-Windows-Agent.bat
  console/server.py
  console/static/{index.html,styles.css,app.js}
  agent/agent.py
  agent/agent-config.example.json
  extension/{manifest.json,background.js,content.js,options.html,options.js}
  tests/test_integration.py
```

Run tests using `py -3 -m unittest discover -s tests -v` from the package root.

## Build / licensing

This is a working **source-code pilot** and Windows launcher scripts, **not** a compiled `.exe` / `.msi`, Windows driver, signed Windows service, or production DLP product. No external Python package dependencies are required. For production, package and sign Windows binaries only after architecture review, formal testing and hardening.
