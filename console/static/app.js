'use strict';
let csrf = '';
let policy = null;
let events = [];
let devices = [];
let toastTimer;
const $ = id => document.getElementById(id);
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const friendlyDate = str => str ? new Date(str).toLocaleString('id-ID',{dateStyle:'short',timeStyle:'medium'}) : 'Never';
const lines = id => $(id).value.split(/\r?\n|,/).map(s=>s.trim().replace(/^\./,'')).filter(Boolean);
const setLines = (id,arr) => $(id).value=(arr||[]).join('\n');
function toast(msg,bad=false) {
  const node=$('toast'); node.textContent=msg;node.className='toast'+(bad?' bad':'');
  clearTimeout(toastTimer);toastTimer=setTimeout(()=>node.classList.add('hidden'),3800);
}
async function api(path,{method='GET',data=null,admin=true}={}) {
  const opt={method,credentials:'same-origin',headers:{}};
  if(data!==null){opt.body=JSON.stringify(data);opt.headers['Content-Type']='application/json';}
  if(method!=='GET' && admin && csrf)opt.headers['X-CSRF-Token']=csrf;
  const response=await fetch(path,opt);
  let result={};try{result=await response.json()}catch{}
  if(!response.ok)throw new Error(result.error||`HTTP ${response.status}`);
  return result;
}
function loggedIn(value){$('login').classList.toggle('hidden',value);$('app').classList.toggle('hidden',!value);}
function setView(name){
  for(const panel of document.querySelectorAll('.view'))panel.classList.toggle('hidden',panel.id!==`view-${name}`);
  for(const tab of document.querySelectorAll('.nav button'))tab.classList.toggle('active',tab.dataset.view===name);
  $('section-crumb').textContent=({overview:'Overview',incidents:'Security Events',web:'Web Protection',dlp:'Data Loss Prevention',devices:'Endpoints'})[name]||name;
  window.scrollTo({top:0,behavior:'smooth'});
}
function labelBadge(value){return `<span class="tag ${escapeHtml(value)}">${escapeHtml(value||'unknown').toUpperCase()}</span>`;}
function emptyRow(colspan, msg='No events recorded yet') {return `<tr><td colspan="${colspan}" class="empty">${escapeHtml(msg)}</td></tr>`;}
function eventRow(ev,compact=false){
  const kind=escapeHtml(ev.kind||'other'), domain=escapeHtml(ev.domain||'—'), ext=escapeHtml(ev.extension||'—');
  const destination=ev.domain?domain:(ev.extension?'.'+ext:'—');
  if(compact) return `<tr><td>${escapeHtml(friendlyDate(ev.created))}</td><td>${escapeHtml(ev.device_id)}</td><td><span class="tag">${kind.toUpperCase()}</span></td><td>${destination}</td><td>${labelBadge(ev.action)}</td></tr>`;
  return `<tr><td>${escapeHtml(friendlyDate(ev.created))}</td><td>${escapeHtml(ev.device_id)}</td><td><span class="tag">${kind.toUpperCase()}</span></td><td>${domain}</td><td>${ext}</td><td title="${escapeHtml(ev.reason)}">${escapeHtml(ev.reason||'—')}</td><td>${labelBadge(ev.action)}</td></tr>`;
}
function renderEvents(){
  $('nav-event-count').textContent=events.length;
  $('recent-events').innerHTML=events.slice(0,7).map(e=>eventRow(e,true)).join('')||emptyRow(5);
  const match=$('event-filter').value.trim().toLowerCase(), kind=$('event-kind').value;
  const filtered=events.filter(ev=>(!kind||ev.kind===kind) && (!match||[ev.device_id,ev.domain,ev.reason,ev.extension].join(' ').toLowerCase().includes(match)));
  $('all-events').innerHTML=filtered.map(e=>eventRow(e)).join('')||emptyRow(7,'No events match your filters');
}
function renderDevices(){
  const cutoff=Date.now()-5*60*1000;
  $('devices-table').innerHTML=devices.map(d=>{
    const online=d.last_seen&&new Date(d.last_seen).getTime()>=cutoff;
    return `<tr><td><b>${escapeHtml(d.name)}</b></td><td>${escapeHtml(d.device_id)}</td><td>${escapeHtml(friendlyDate(d.created))}</td><td>${escapeHtml(friendlyDate(d.last_seen))}</td><td>${labelBadge(online?'online':'offline')}</td></tr>`;
  }).join('')||emptyRow(5,'No enrolled Windows endpoints');
}
function renderSummary(s){
  $('m-online').textContent=s.online_devices;$('m-total').textContent=s.total_devices;
  $('m-blocked').textContent=s.blocked_24h;$('m-uploads').textContent=s.uploads_blocked;
  $('m-downloads').textContent=s.downloads_blocked;
  const all=s.by_kind||[],max=Math.max(1,...all.map(x=>x.total));
  $('activity-chart').innerHTML=all.length?all.map(a=>`<div class="chart-row"><span class="chart-label">${escapeHtml(a.kind)}</span><div class="chart-track"><div class="chart-bar" style="width:${Math.min(100,100*a.total/max)}%"></div></div><span class="chart-count">${a.total}</span></div>`).join(''):'<div class="empty">Belum ada security event dalam 24 jam.</div>';
}
function renderPolicy(){
  setLines('blocked-domains',policy.blocked_domains);setLines('download-ext',policy.blocked_download_extensions);
  setLines('upload-ext',policy.blocked_upload_extensions);setLines('upload-domains',policy.blocked_upload_domains);
  $('upload-max').value=policy.max_upload_mb;
  $('mode-web').value=policy.mode;$('mode-dlp').value=policy.mode;
}
async function loadAll(){
  const [summary,eventsResult,devicesResult,policyResult]=await Promise.all([
    api('/api/admin/summary'),api('/api/admin/events'),api('/api/admin/devices'),api('/api/admin/policy')
  ]);
  events=eventsResult.events;devices=devicesResult.devices;policy=policyResult.policy;
  renderSummary(summary);renderEvents();renderDevices();renderPolicy();
}
async function savePolicy(section){
  if(!policy)return;
  const next={...policy};
  if(section==='web'){
    next.blocked_domains=lines('blocked-domains');next.mode=$('mode-web').value;
  } else {
    next.blocked_download_extensions=lines('download-ext');next.blocked_upload_extensions=lines('upload-ext');
    next.blocked_upload_domains=lines('upload-domains');next.max_upload_mb=Number($('upload-max').value);
    next.mode=$('mode-dlp').value;
  }
  try{const r=await api('/api/admin/policy',{method:'POST',data:next});policy=r.policy;renderPolicy();toast('Policy saved. Endpoints will receive it on their next sync.');}
  catch(err){toast(err.message,true);}
}
$('login-form').addEventListener('submit',async e=>{
  e.preventDefault();$('login-error').textContent='';
  try {const r=await api('/api/admin/login',{method:'POST',data:{username:$('login-username').value,password:$('login-password').value},admin:false});csrf=r.csrf;loggedIn(true);await loadAll();}
  catch(err){$('login-error').textContent=err.message;}
});
$('logout').addEventListener('click',async()=>{try{await api('/api/admin/logout',{method:'POST',data:{}})}catch{}csrf='';loggedIn(false);$('login-password').value='';});
$('nav').addEventListener('click',e=>{const b=e.target.closest('[data-view]');if(b)setView(b.dataset.view);});
document.querySelectorAll('[data-jump]').forEach(b=>b.addEventListener('click',()=>setView(b.dataset.jump)));
$('refresh').addEventListener('click',()=>loadAll().then(()=>toast('Data refreshed')).catch(e=>toast(e.message,true)));
$('reload-events').addEventListener('click',()=>loadAll().then(()=>toast('Events refreshed')).catch(e=>toast(e.message,true)));
$('event-filter').addEventListener('input',renderEvents);$('event-kind').addEventListener('change',renderEvents);
$('save-web').addEventListener('click',()=>savePolicy('web'));
$('save-dlp').addEventListener('click',()=>savePolicy('dlp'));
$('new-device').addEventListener('click',()=>{$('enroll-modal').classList.remove('hidden');$('enroll-form').classList.remove('hidden');$('enroll-output').classList.add('hidden');});
$('close-modal').addEventListener('click',()=>$('enroll-modal').classList.add('hidden'));
$('enroll-modal').addEventListener('click',e=>{if(e.target.id==='enroll-modal')$('enroll-modal').classList.add('hidden')});
$('enroll-form').addEventListener('submit',async e=>{
  e.preventDefault();try{
    const result=await api('/api/admin/enroll',{method:'POST',data:{name:$('device-name').value}});
    const bytes=new Uint8Array(32);crypto.getRandomValues(bytes);
    const bridgeToken=Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
    const cfg={server_url:location.origin,device_id:result.device_id,device_token:result.device_token,bridge_token:bridgeToken,downloads_dir:'%USERPROFILE%\\Downloads',poll_seconds:15};
    $('enroll-config').textContent=JSON.stringify(cfg,null,2);
    $('enroll-form').classList.add('hidden');$('enroll-output').classList.remove('hidden');
    const r=await api('/api/admin/devices');devices=r.devices;renderDevices();toast('Device registered. Save endpoint credentials securely.');
  }catch(err){toast(err.message,true)}
});
$('copy-config').addEventListener('click',async()=>{
  try{await navigator.clipboard.writeText($('enroll-config').textContent);toast('Endpoint configuration copied.');}
  catch{toast('Clipboard not available. Select and copy JSON manually.',true)}
});
async function start(){
  try{const r=await api('/api/admin/me');csrf=r.csrf;loggedIn(true);await loadAll();}
  catch{loggedIn(false);}
  setInterval(async()=>{if(!csrf||document.visibilityState==='hidden')return;
    try{
      const [sum,ev,dv]=await Promise.all([api('/api/admin/summary'),api('/api/admin/events'),api('/api/admin/devices')]);
      events=ev.events;devices=dv.devices;renderSummary(sum);renderEvents();renderDevices();
    }catch{}
  },15000);
}
start();
