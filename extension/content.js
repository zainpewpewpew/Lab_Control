// Browser-level pilot DLP. Known limitation: not a replacement for OS-level Endpoint DLP.
(() => {
  let policy = {mode:'monitor', blocked_upload_domains:[],blocked_upload_extensions:[],max_upload_mb:50};
  const hasDomain = (host,list) => (list||[]).some(d => host === d || host.endsWith('.'+d));
  const extension = filename => String(filename||'').split('.').pop().toLowerCase();
  function notice(message) {
    let box = document.getElementById('sentinelgate-policy-notice');
    if (!box) {
      box = document.createElement('div'); box.id = 'sentinelgate-policy-notice';
      box.style.cssText = 'all:initial!important;position:fixed!important;z-index:2147483647!important;top:18px!important;right:18px!important;max-width:380px!important;padding:16px 20px!important;background:#10243b!important;color:white!important;border:1px solid #4b9cdd!important;border-radius:11px!important;box-shadow:0 12px 32px #0005!important;font:14px/1.5 system-ui!important;';
      (document.documentElement||document.body).appendChild(box);
    }
    box.textContent='🛡 SentinelGate: '+message;
    setTimeout(()=>{if(box.isConnected)box.remove();},5200);
  }
  function emit(result) {
    chrome.runtime.sendMessage({kind:'event',event:{kind:'upload',action:policy.mode==='enforce'?'blocked':'observed',domain:location.hostname,extension:result.ext,size:result.size,reason:result.reason}}).catch(()=>{});
  }
  function findViolation(files) {
    if (!files || !files.length) return null;
    for (const file of files) {
      const ext = extension(file.name);
      const maxBytes = Number(policy.max_upload_mb||50) * 1024 * 1024;
      if (hasDomain(location.hostname,policy.blocked_upload_domains)) return {ext,size:file.size,reason:'Upload forbidden to this destination'};
      if ((policy.blocked_upload_extensions||[]).includes(ext)) return {ext,size:file.size,reason:'Sensitive / restricted file extension'};
      if (file.size > maxBytes) return {ext,size:file.size,reason:'Upload exceeds company size policy'};
    }
    return null;
  }
  document.addEventListener('change', event => {
    const field=event.target;
    if (!(field instanceof HTMLInputElement) || field.type !== 'file') return;
    const blocked=findViolation(field.files);
    if (!blocked) return;
    emit(blocked);
    if (policy.mode !== 'enforce') return;
    field.value='';
    event.stopImmediatePropagation();
    notice('Upload ditolak — '+blocked.reason);
  },true);
  document.addEventListener('drop', event => {
    const files=event.dataTransfer?.files;
    const blocked=findViolation(files);
    if (!blocked) return;
    emit(blocked);
    if (policy.mode !== 'enforce') return;
    event.preventDefault();event.stopImmediatePropagation();
    notice('Drop file ditolak — '+blocked.reason);
  },true);
  document.addEventListener('submit', event => {
    const form=event.target;
    if (!(form instanceof HTMLFormElement)) return;
    for (const input of form.querySelectorAll('input[type="file"]')) {
      const blocked=findViolation(input.files);
      if (!blocked) continue;
      emit(blocked);
      if (policy.mode === 'enforce') {
        event.preventDefault();event.stopImmediatePropagation();
        notice('Upload ditolak — '+blocked.reason);
      }
      break;
    }
  },true);
  chrome.storage.local.get(['policy']).then(result=>{if(result.policy)policy=result.policy;}).catch(()=>{});
  chrome.storage.onChanged.addListener((changes,area)=>{if(area==='local' && changes.policy?.newValue)policy=changes.policy.newValue;});
})();
