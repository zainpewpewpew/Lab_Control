// CadenceSec CISO desktop console (Electron main process).
// Wraps the FastAPI console in a native Mac/Windows window with:
//   - persistent server URL + session
//   - native application menu
//   - system tray with unread-alert badge
//   - OS-level notifications on severity >= 4 events
//   - first-run server setup page
//
// Build: npm install && npm start
// Package: npm run dist:mac | npm run dist:win

const { app, BrowserWindow, Menu, Tray, Notification, ipcMain, shell, dialog, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');

const USER_DATA = app.getPath('userData');
const CONFIG_FILE = path.join(USER_DATA, 'config.json');
let mainWindow = null;
let tray = null;
let unread = 0;
let config = loadConfig();

function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8')); }
  catch { return { serverUrl: '', notifyMinSeverity: 4, startMinimized: false, pinnedFingerprint: '' }; }
}
function saveConfig() {
  fs.mkdirSync(USER_DATA, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
}

function normalizeFingerprint(fp) {
  return (fp || '').toUpperCase().replace(/[^0-9A-F]/g, '');
}

function trayIconPath() {
  // Simple 16x16 PNG tray icon bundled; fallback to a 1x1 transparent image.
  const p = path.join(__dirname, 'assets', 'tray.png');
  return fs.existsSync(p) ? p : null;
}

function buildMenu() {
  const isMac = process.platform === 'darwin';
  const template = [
    ...(isMac ? [{ label: app.name, submenu: [
      { role: 'about' }, { type: 'separator' },
      { label: 'Server Settings…', accelerator: 'Cmd+,', click: openSettings },
      { type: 'separator' },
      { role: 'services' }, { type: 'separator' },
      { role: 'hide' }, { role: 'hideOthers' }, { role: 'unhide' }, { type: 'separator' },
      { role: 'quit' },
    ]}] : []),
    { label: 'File', submenu: [
      { label: 'Server Settings…', accelerator: 'CmdOrCtrl+,', click: openSettings },
      { label: 'Reload Console', accelerator: 'CmdOrCtrl+R', click: () => mainWindow?.reload() },
      { type: 'separator' },
      isMac ? { role: 'close' } : { role: 'quit' },
    ]},
    // Standard Edit menu — required for Cmd+C / Cmd+V / Cmd+X / Cmd+A
    // shortcuts to route to the focused webContents on macOS. Without it,
    // the renderer's <input> fields silently swallow paste requests.
    { label: 'Edit', submenu: [
      { role: 'undo' },
      { role: 'redo' },
      { type: 'separator' },
      { role: 'cut' },
      { role: 'copy' },
      { role: 'paste' },
      ...(isMac ? [
        { role: 'pasteAndMatchStyle' },
        { role: 'delete' },
        { role: 'selectAll' },
      ] : [
        { role: 'delete' },
        { type: 'separator' },
        { role: 'selectAll' },
      ]),
    ]},
    { label: 'View', submenu: [
      { role: 'toggleDevTools' }, { role: 'resetZoom' },
      { role: 'zoomIn' }, { role: 'zoomOut' }, { type: 'separator' },
      { role: 'togglefullscreen' },
    ]},
    { label: 'Window', submenu: [{ role: 'minimize' }, ...(isMac ? [{ role: 'front' }] : [])] },
    { label: 'Help', submenu: [
      { label: 'Open Logs Folder', click: () => shell.openPath(USER_DATA) },
      { label: 'CadenceSec Docs', click: () => shell.openExternal('https://cadencesec.local/docs') },
    ]},
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function buildTray() {
  const iconPath = trayIconPath();
  const icon = iconPath ? nativeImage.createFromPath(iconPath) : nativeImage.createEmpty();
  tray = new Tray(icon);
  tray.setToolTip('CadenceSec CISO');
  updateTray();
  tray.on('click', () => { showMain(); });
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open console', click: showMain },
    { label: 'Clear badge', click: () => { unread = 0; updateTray(); } },
    { label: 'Server settings…', click: openSettings },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.isQuitting = true; app.quit(); } },
  ]));
}

function updateTray() {
  if (!tray) return;
  tray.setTitle(unread > 0 ? `  ${unread}` : '');
  if (process.platform === 'darwin') app.dock?.setBadge(unread > 0 ? String(unread) : '');
}

function showMain() {
  if (!mainWindow) return createMainWindow();
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function openSettings() {
  const win = new BrowserWindow({
    width: 480, height: 340, resizable: false, modal: !!mainWindow, parent: mainWindow,
    title: 'CadenceSec — Server Settings',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true },
  });
  win.loadFile(path.join(__dirname, 'setup.html'));
  win.webContents.on('did-finish-load', () => {
    win.webContents.send('settings:current', config);
  });
  const handler = (e, newCfg) => {
    const serverChanged = newCfg.serverUrl && newCfg.serverUrl !== config.serverUrl;
    config = { ...config, ...newCfg };
    if (serverChanged || newCfg.clearPin) config.pinnedFingerprint = '';
    saveConfig();
    win.close();
    if (mainWindow) mainWindow.loadURL(config.serverUrl);
    else createMainWindow();
  };
  ipcMain.once('settings:save', handler);
  win.on('closed', () => ipcMain.removeListener('settings:save', handler));
}

function createMainWindow() {
  if (!config.serverUrl) { openSettings(); return; }
  mainWindow = new BrowserWindow({
    width: 1400, height: 900, minWidth: 1000, minHeight: 640,
    title: 'CadenceSec — CISO Console',
    backgroundColor: '#0b1020',
    show: !config.startMinimized,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  mainWindow.loadURL(config.serverUrl);
  mainWindow.webContents.on('did-fail-load', (_e, code, desc, url) => {
    dialog.showMessageBox(mainWindow, {
      type: 'error', title: 'Cannot reach console',
      message: `Failed to load ${url}\n${desc} (${code})`,
      buttons: ['Open settings', 'Retry', 'Quit'],
    }).then(r => {
      if (r.response === 0) openSettings();
      else if (r.response === 1) mainWindow.reload();
      else app.quit();
    });
  });
  mainWindow.webContents.on('certificate-error', (e, url, _err, cert, callback) => {
    // Pin by SHA-256 fingerprint for the configured console URL only.
    // First-run TOFU: no pinned fingerprint → store the current cert's and accept once.
    if (!url.startsWith(config.serverUrl)) return callback(false);
    const seen = normalizeFingerprint(cert && cert.fingerprint);
    const pinned = normalizeFingerprint(config.pinnedFingerprint);
    if (!seen) return callback(false);
    if (!pinned) {
      config.pinnedFingerprint = seen;
      saveConfig();
      e.preventDefault(); return callback(true);
    }
    if (pinned === seen) { e.preventDefault(); return callback(true); }
    dialog.showErrorBox(
      'CadenceSec — certificate changed',
      'Pinned fingerprint:\n' + pinned + '\n\nServer presented:\n' + seen +
      '\n\nConnection refused. If this change is intentional, clear the pinned fingerprint from Server Settings.'
    );
    callback(false);
  });
  mainWindow.on('close', (e) => {
    if (!app.isQuitting) { e.preventDefault(); mainWindow.hide(); }
  });
}

ipcMain.on('alert:event', (_e, payload) => {
  const sev = payload?.severity ?? 0;
  const minSev = config.notifyMinSeverity ?? 4;
  if (sev < minSev) return;
  unread += 1;
  updateTray();
  if (Notification.isSupported()) {
    new Notification({
      title: `CadenceSec alert — sev ${sev}`,
      body: `${payload.kind} · ${payload.hostname || payload.device_id}\n${truncate(JSON.stringify(payload.data || {}), 160)}`,
      urgency: sev >= 7 ? 'critical' : 'normal',
      silent: false,
    }).on('click', () => { showMain(); unread = 0; updateTray(); })
      .show();
  }
});

ipcMain.on('alert:clear-badge', () => { unread = 0; updateTray(); });

function truncate(s, n) { return s.length > n ? s.slice(0, n - 1) + '…' : s; }

app.whenReady().then(() => {
  buildMenu();
  buildTray();
  if (!config.serverUrl) openSettings();
  else createMainWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
    else showMain();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => { app.isQuitting = true; });
