// Preload: runs in the renderer with contextIsolation ON.
// Exposes:
//   window.cs.settings.save({serverUrl, notifyMinSeverity, startMinimized})
//   window.cs.settings.onCurrent(cb)
//   window.cs.clearBadge()
// And wraps EventSource so every incoming SSE event is also forwarded to the main process
// for native OS notifications on severity >= notifyMinSeverity.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cs', {
  settings: {
    save: (cfg) => ipcRenderer.send('settings:save', cfg),
    onCurrent: (cb) => ipcRenderer.on('settings:current', (_e, cfg) => cb(cfg)),
  },
  clearBadge: () => ipcRenderer.send('alert:clear-badge'),
});

// Patch EventSource so the dashboard page's /admin/stream also notifies main.
const RealEventSource = window.EventSource;
if (RealEventSource) {
  window.EventSource = function PatchedEventSource(url, opts) {
    const es = new RealEventSource(url, opts);
    const origAdd = es.addEventListener.bind(es);
    es.addEventListener = (type, listener, options) => {
      if (type === 'message') {
        const wrapped = (ev) => {
          try {
            const payload = JSON.parse(ev.data);
            ipcRenderer.send('alert:event', payload);
          } catch (_) { /* ignore */ }
          listener(ev);
        };
        return origAdd(type, wrapped, options);
      }
      return origAdd(type, listener, options);
    };
    const origSetter = Object.getOwnPropertyDescriptor(RealEventSource.prototype, 'onmessage');
    Object.defineProperty(es, 'onmessage', {
      set(fn) {
        es.addEventListener('message', fn);
      },
      get() { return null; },
    });
    return es;
  };
}
