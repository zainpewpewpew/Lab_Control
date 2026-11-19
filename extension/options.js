const token = document.getElementById('token');
const status = document.getElementById('status');
chrome.storage.local.get('bridgeToken').then(result=>token.value=result.bridgeToken||'');
document.getElementById('save').addEventListener('click',async()=>{
  const value=token.value.trim();
  if(value.length<16){status.textContent='Token terlalu pendek.';return;}
  await chrome.storage.local.set({bridgeToken:value});
  try {await chrome.runtime.sendMessage({kind:'refresh'}); status.textContent='Disimpan. Periksa badge ON/MON/CACHE pada ekstensi.';}
  catch{status.textContent='Disimpan; restart browser jika sinkronisasi belum berjalan.';}
});
