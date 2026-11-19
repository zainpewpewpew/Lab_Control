// SentinelGate pilot extension: only security metadata is reported, never file bytes or page text.
const BRIDGE = 'http://127.0.0.1:8898';
const EMPTY_POLICY = {mode:'monitor', blocked_domains:[], blocked_upload_domains:[], blocked_download_extensions:[], blocked_upload_extensions:[], max_upload_mb:50};
let policy = EMPTY_POLICY;
let bridgeToken = '';
let processedDownloads = new Set();

function hasDomain(host, domainList) {
  const h = String(host || '').toLowerCase();
  return (domainList || []).some(d => h === d || h.endsWith('.' + d));
}
function fileExtension(path) {
  const name = String(path || '').split(/[\\/]/).pop().split('?')[0].split('#')[0];
  const dot = name.lastIndexOf('.');
  return dot === -1 ? '' : name.slice(dot + 1).toLowerCase();
}
async function postEvent(event) {
  if (!bridgeToken) return;
  try {
    await fetch(BRIDGE + '/api/event', {
      method: 'POST',
      headers: {'Content-Type':'application/json','X-Sentinel-Bridge':bridgeToken},
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(4000)
    });
  } catch (err) { console.debug('SentinelGate event queue unavailable', String(err)); }
}
async function refreshPolicy() {
  const saved = await chrome.storage.local.get(['bridgeToken','policy']);
  bridgeToken = saved.bridgeToken || '';
  if (saved.policy && typeof saved.policy === 'object') policy = saved.policy;
  if (!bridgeToken) { await chrome.action.setBadgeText({text:'SET'}); return; }
  try {
    const resp = await fetch(BRIDGE + '/api/policy', {headers:{'X-Sentinel-Bridge':bridgeToken}, signal:AbortSignal.timeout(4500)});
    if (!resp.ok) throw new Error('Bridge HTTP ' + resp.status);
    const body = await resp.json();
    if (!body.policy || !['monitor','enforce'].includes(body.policy.mode)) throw new Error('Invalid policy');
    policy = body.policy;
    await chrome.storage.local.set({policy,policySyncedAt:Date.now()});
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const newRules = (policy.mode === 'enforce' ? policy.blocked_domains : []).slice(0,700).map((domain,index) => ({
      id: index+1, priority:1, action:{type:'block'}, condition:{urlFilter:'||'+domain+'^'}
    }));
    await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:existing.map(r=>r.id),addRules:newRules});
    await chrome.action.setBadgeText({text:policy.mode === 'enforce' ? 'ON' : 'MON'});
    await chrome.action.setBadgeBackgroundColor({color:'#0b9e78'});
  } catch (err) {
    // Keep last enforced rules and cached policy when the agent goes offline.
    await chrome.action.setBadgeText({text:'CACHE'});
    await chrome.action.setBadgeBackgroundColor({color:'#d38b2e'});
    console.warn('SentinelGate: cached enforcement active if previously provisioned',String(err));
  }
}
chrome.runtime.onInstalled.addListener(async () => {
  chrome.alarms.create('sentinel-refresh', {periodInMinutes:1});
  await refreshPolicy();
});
chrome.runtime.onStartup.addListener(async () => {
  chrome.alarms.create('sentinel-refresh', {periodInMinutes:1});
  await refreshPolicy();
});
chrome.alarms.onAlarm.addListener(a => { if (a.name === 'sentinel-refresh') refreshPolicy(); });
chrome.runtime.onMessage.addListener((msg,sender,reply) => {
  if (!msg || typeof msg !== 'object') return;
  if (msg.kind === 'refresh') { refreshPolicy().then(()=>reply({ok:true})).catch(()=>reply({ok:false})); return true; }
  if (msg.kind === 'getPolicy') { reply({policy}); return; }
  if (msg.kind === 'event' && sender.tab && ['upload','web','download'].includes(msg.event?.kind)) {
    postEvent(msg.event); reply({queued:true}); return;
  }
});
chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;
  try {
    const host = new URL(details.url).hostname;
    if (hasDomain(host,policy.blocked_domains)) {
      postEvent({kind:'web',action:policy.mode === 'enforce' ? 'blocked' : 'observed',domain:host,reason:'Restricted website domain'});
    }
  } catch {}
});
async function inspectDownload(item) {
  if (processedDownloads.has(item.id)) return;
  const extension = fileExtension(item.filename) || fileExtension(item.url);
  if (!policy.blocked_download_extensions?.includes(extension)) return;
  processedDownloads.add(item.id);
  const host = (() => {try{return new URL(item.url).hostname}catch{return ''}})();
  if (policy.mode === 'enforce') {
    try { await chrome.downloads.cancel(item.id); } catch (e) { console.warn('Cancel failed',e); }
  }
  await postEvent({kind:'download',action:policy.mode === 'enforce'?'blocked':'observed',domain:host,extension,size:item.totalBytes > 0 ? item.totalBytes : 0,reason:'Restricted download extension'});
  if (processedDownloads.size > 1500) processedDownloads = new Set();
}
chrome.downloads.onCreated.addListener(item => { inspectDownload(item); });
chrome.downloads.onChanged.addListener(delta => {
  if (delta.filename?.current && !processedDownloads.has(delta.id)) {
    chrome.downloads.search({id:delta.id}).then(items=>{if(items[0]) inspectDownload(items[0]);}).catch(()=>{});
  }
});
refreshPolicy();
