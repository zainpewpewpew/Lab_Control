"""SentinelGate Enterprise MVP Windows agent. No keystroke, screen, or file-content collection."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'state'
QUEUE = DATA / 'events.jsonl'
CACHE = DATA / 'policy.json'
LOCK = threading.RLock()
POLICY = {'mode':'monitor','blocked_domains':[],'blocked_upload_domains':[], 'blocked_download_extensions':[], 'blocked_upload_extensions':[],'max_upload_mb':50,'version':1}
CONFIG = {}


def save_json(path, obj):
    tmp = path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(obj,indent=2), encoding='utf-8')
    tmp.replace(path)

def api(path, body=None):
    url = CONFIG['server_url'].rstrip('/')+path
    data = json.dumps(body).encode() if body is not None else None
    headers = {'Authorization':'Bearer '+CONFIG['device_token']}
    if data is not None: headers['Content-Type']='application/json'
    req = urllib.request.Request(url,data=data,headers=headers,method='POST' if data is not None else 'GET')
    with urllib.request.urlopen(req,timeout=8) as response:
        if response.status >= 300: raise RuntimeError('Server HTTP '+str(response.status))
        return json.loads(response.read(128*1024))

def append_event(event):
    safe = {}
    for k in ('kind','action','domain','extension','reason'):
        if k in event: safe[k] = str(event[k])[:260]
    safe['size']=max(0,min(int(event.get('size',0) or 0),2**40))
    with LOCK:
        with QUEUE.open('a',encoding='utf-8') as fp:
            fp.write(json.dumps(safe)+'\n')

def flush_events():
    with LOCK:
        if not QUEUE.exists(): return
        lines = QUEUE.read_text(encoding='utf-8').splitlines()
        if not lines: return
        batch = [json.loads(x) for x in lines[:50] if x.strip()]
        api('/api/agent/events', {'events':batch})
        QUEUE.write_text('\n'.join(lines[50:])+ ('\n' if len(lines)>50 else ''), encoding='utf-8')

def sync_loop():
    global POLICY
    while True:
        try:
            result = api('/api/agent/policy')
            new_policy = result['policy']
            if isinstance(new_policy,dict) and new_policy.get('mode') in ('monitor','enforce'):
                with LOCK:
                    POLICY = new_policy
                    save_json(CACHE,POLICY)
            api('/api/agent/heartbeat',{'platform':'Windows','agent_version':'0.1'})
            flush_events()
        except (OSError,ValueError,KeyError,urllib.error.URLError) as exc:
            print('[AGENT] Console connection failed; cached policy retained:',exc)
        time.sleep(max(5,min(int(CONFIG.get('poll_seconds',15)),300)))

def download_monitor():
    folder = Path(os.path.expandvars(CONFIG.get('downloads_dir','%USERPROFILE%\\Downloads'))).expanduser()
    folder.mkdir(parents=True,exist_ok=True)
    quarantine = DATA / 'quarantine'
    quarantine.mkdir(exist_ok=True)
    previous = {}  # existing entries at startup are intentionally not processed
    try:
        for f in folder.iterdir():
            if f.is_file():
                s=f.stat()
                previous[str(f)] = (s.st_size,s.st_mtime,100)
    except OSError: pass
    print('[AGENT] Monitoring download folder:',folder)
    while True:
        current={}
        try:
            for file in folder.iterdir():
                if not file.is_file() or file.is_symlink() or file.suffix.lower() in ('.crdownload','.part','.tmp'):
                    continue
                s = file.stat()
                key = str(file)
                old = previous.get(key)
                stable = old[2]+1 if old and old[:2] == (s.st_size,s.st_mtime) else 0
                current[key] = (s.st_size,s.st_mtime,stable)
                if stable != 2: continue
                ext = file.suffix.lower().lstrip('.')
                with LOCK: policy = dict(POLICY)
                if ext not in policy.get('blocked_download_extensions',[]): continue
                event={'kind':'download','extension':ext,'size':s.st_size,'domain':'', 'reason':'Restricted extension found in Downloads'}
                if policy.get('mode')=='monitor':
                    event['action']='observed'
                else:
                    try:
                        destination = quarantine / (secrets.token_hex(12)+'.'+ext)
                        shutil.move(str(file), str(destination))
                        current.pop(key,None)
                        event['action']='quarantined'
                        event['reason']='Post-download quarantine (not antivirus detection)'
                    except OSError as exc:
                        event['action']='error'
                        event['reason']='Quarantine failed: '+str(exc)[:120]
                append_event(event)
        except OSError as exc:
            print('[AGENT] Downloads monitor error:',exc)
        previous=current
        time.sleep(2)

class BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def origin(self):
        origin = self.headers.get('Origin','')
        if origin.startswith('chrome-extension://') and len(origin)<130 and all(c.isalnum() or c in '-:/' for c in origin):
            return origin
        return ''

    def respond(self,status,obj):
        data=json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        allowed=self.origin()
        if allowed: self.send_header('Access-Control-Allow-Origin',allowed)
        self.send_header('Vary','Origin')
        self.send_header('Content-Length',str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        return bool(self.origin()) and secrets.compare_digest(self.headers.get('X-Sentinel-Bridge',''),CONFIG['bridge_token'])

    def do_OPTIONS(self):
        if not self.origin(): return self.respond(403,{'error':'Extension origin required'})
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin',self.origin())
        self.send_header('Access-Control-Allow-Headers','content-type,x-sentinel-bridge')
        self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS')
        self.send_header('Access-Control-Max-Age','600')
        self.send_header('Content-Length','0')
        self.end_headers()

    def do_GET(self):
        if not self.authorized(): return self.respond(401,{'error':'Bridge authorization required'})
        if self.path == '/api/policy':
            with LOCK: policy = dict(POLICY)
            return self.respond(200,{'policy':policy})
        self.respond(404,{'error':'Not found'})

    def do_POST(self):
        if not self.authorized(): return self.respond(401,{'error':'Bridge authorization required'})
        if self.path != '/api/event': return self.respond(404,{'error':'Not found'})
        try:
            length = int(self.headers.get('Content-Length','0'))
            if not 0 < length <= 4096: raise ValueError('Invalid request length')
            value = json.loads(self.rfile.read(length))
            if not isinstance(value,dict): raise ValueError('Object required')
            if value.get('kind') not in ('web','upload','download','agent') or value.get('action') not in ('blocked','observed','error'):
                raise ValueError('Invalid event type')
            append_event(value)
        except (ValueError, TypeError) as exc:
            return self.respond(400,{'error':str(exc)})
        self.respond(202,{'queued':True})

def main():
    global CONFIG,POLICY
    parser=argparse.ArgumentParser(description='SentinelGate Windows endpoint agent')
    parser.add_argument('--config',default=str(ROOT/'agent-config.json'))
    args=parser.parse_args()
    path=Path(args.config)
    if not path.is_file(): sys.exit('Missing agent-config.json. Copy agent-config.example.json and fill enrollment values.')
    CONFIG=json.loads(path.read_text(encoding='utf-8'))
    for key in ('server_url','device_id','device_token','bridge_token'):
        if not isinstance(CONFIG.get(key),str) or len(CONFIG[key])<8:
            sys.exit('Missing or invalid agent configuration field: '+key)
    p=urllib.parse.urlsplit(CONFIG['server_url'])
    if p.scheme!='https' and not (p.scheme=='http' and p.hostname in ('127.0.0.1','localhost')):
        sys.exit('Remote console requires HTTPS and a trusted certificate')
    if p.username or p.password or p.query or p.fragment:
        sys.exit('Invalid server_url')
    DATA.mkdir(exist_ok=True)
    if CACHE.exists():
        try:
            POLICY=json.loads(CACHE.read_text(encoding='utf-8'))
        except (OSError,ValueError): pass
    threading.Thread(target=sync_loop,daemon=True).start()
    threading.Thread(target=download_monitor,daemon=True).start()
    srv=ThreadingHTTPServer(('127.0.0.1',8898),BridgeHandler)
    print('[AGENT] Chrome / Edge bridge running on http://127.0.0.1:8898')
    try: srv.serve_forever(poll_interval=.3)
    except KeyboardInterrupt: pass
    finally: srv.server_close()

if __name__ == '__main__': main()
