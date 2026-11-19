"""SentinelGate Enterprise MVP - central CISO console (Python 3.10+, standard library)."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import http.cookies
import json
import os
import re
import secrets
import sqlite3
import ssl
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
STATE = ROOT / 'state'
DB_FILE = STATE / 'sentinelgate.db'
STATIC = ROOT / 'static'
MAX_BODY = 128 * 1024

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

@contextmanager
def connect():
    db = sqlite3.connect(DB_FILE, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA journal_mode=WAL')
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def hash_secret(secret):
    return hashlib.sha256(secret.encode()).hexdigest()

def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 240_000).hex()

DEFAULT_POLICY = {
    'version': 1,
    'mode': 'monitor',
    'blocked_domains': ['example.invalid'],
    'blocked_upload_domains': ['file.io', 'transfer.sh'],
    'blocked_download_extensions': ['exe', 'msi', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'hta'],
    'blocked_upload_extensions': ['key', 'pem', 'pfx', 'env', 'sql', 'db'],
    'max_upload_mb': 50,
}

def validate_policy(body):
    if not isinstance(body, dict):
        raise ValueError('Policy must be a JSON object')
    policy = {'version': 1}
    policy['mode'] = body.get('mode')
    if policy['mode'] not in ('monitor', 'enforce'):
        raise ValueError('mode must be monitor or enforce')
    for field in ('blocked_domains', 'blocked_upload_domains', 'blocked_download_extensions', 'blocked_upload_extensions'):
        values = body.get(field)
        if not isinstance(values, list) or len(values) > 700:
            raise ValueError(field + ' must be an array with at most 700 items')
        cleaned = []
        for value in values:
            if not isinstance(value, str):
                raise ValueError(field + ' entries must be strings')
            value = value.strip().lower().lstrip('.')
            if field.endswith('domains'):
                if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', value) or '..' in value or '.' not in value:
                    raise ValueError('Invalid domain: ' + value[:80])
            elif not re.fullmatch(r'[a-z0-9]{1,12}', value):
                raise ValueError('Invalid extension: ' + value[:80])
            cleaned.append(value)
        policy[field] = sorted(set(cleaned))
    size = body.get('max_upload_mb')
    if type(size) is not int or not 1 <= size <= 2048:
        raise ValueError('max_upload_mb must be between 1 and 2048')
    policy['max_upload_mb'] = size
    return policy

def initialize():
    STATE.mkdir(exist_ok=True)
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY CHECK(id=1), salt TEXT, passhash TEXT);
        CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, csrf TEXT, expires TEXT);
        CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, name TEXT, token_hash TEXT UNIQUE, last_seen TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, kind TEXT, action TEXT, domain TEXT, extension TEXT, size INTEGER, reason TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT);
        CREATE INDEX IF NOT EXISTS events_created ON events(created);
        ''')
        if not db.execute('SELECT id FROM auth WHERE id=1').fetchone():
            pw = os.getenv('SENTINEL_ADMIN_PASSWORD') or secrets.token_urlsafe(18)
            if len(pw) < 12:
                raise ValueError('SENTINEL_ADMIN_PASSWORD must contain at least 12 characters')
            salt = secrets.token_hex(16)
            db.execute('INSERT INTO auth VALUES (1,?,?)', (salt, password_hash(pw, salt)))
            (STATE / 'bootstrap-admin.txt').write_text('URL: http://127.0.0.1:8899\nUser: admin\nPassword: ' + pw + '\n', encoding='utf-8')
            try: (STATE / 'bootstrap-admin.txt').chmod(0o600)
            except OSError: pass
            print('FIRST RUN: Admin credential stored in console/state/bootstrap-admin.txt (restrict access).')
        if not db.execute("SELECT key FROM config WHERE key='policy'").fetchone():
            db.execute("INSERT INTO config(key,value) VALUES('policy',?)", (json.dumps(DEFAULT_POLICY),))

def policy_read():
    with connect() as db:
        row = db.execute("SELECT value FROM config WHERE key='policy'").fetchone()
    return json.loads(row['value'])

class Handler(BaseHTTPRequestHandler):
    server_version = 'SentinelGate/0.1'

    def log_message(self, fmt, *args):
        print('%s %s' % (self.address_string(), fmt % args))

    def json_response(self, status, data, cookies=None):
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
        if cookies:
            self.send_header('Set-Cookie', cookies)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def payload(self):
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= length <= MAX_BODY:
                raise ValueError('Invalid payload size')
            if not self.headers.get('Content-Type','').split(';')[0].strip() == 'application/json':
                raise ValueError('Content-Type must be application/json')
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError('Invalid JSON payload') from exc

    def current_session(self):
        try:
            jar = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            token = jar['sg_session'].value
        except (KeyError, http.cookies.CookieError):
            return None
        with connect() as db:
            row = db.execute('SELECT csrf FROM sessions WHERE token_hash=? AND expires>?', (hash_secret(token), now())).fetchone()
        return dict(row) if row else None

    def require_admin(self, write=False):
        session = self.current_session()
        if not session:
            self.json_response(401, {'error':'Login required'})
            return False
        if write and not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
            self.json_response(403, {'error':'Invalid CSRF token'})
            return False
        return True

    def agent_id(self):
        header = self.headers.get('Authorization','')
        if not header.startswith('Bearer '):
            return None
        token = header[7:]
        if len(token) > 256:
            return None
        with connect() as db:
            row = db.execute('SELECT device_id FROM devices WHERE token_hash=?', (hash_secret(token),)).fetchone()
        return row['device_id'] if row else None

    def serve_asset(self, path):
        if path == '/': path = '/index.html'
        requested = (STATIC / path.removeprefix('/')).resolve()
        if not requested.is_relative_to(STATIC.resolve()) or not requested.is_file():
            self.json_response(404, {'error':'Not found'})
            return
        data = requested.read_bytes()
        media = 'text/html; charset=utf-8' if requested.suffix == '.html' else ('text/css; charset=utf-8' if requested.suffix == '.css' else 'text/javascript; charset=utf-8')
        self.send_response(200)
        self.send_header('Content-Type',media)
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/api/health':
            return self.json_response(200, {'status':'ok','product':'SentinelGate Enterprise MVP'})
        if path == '/api/agent/policy':
            device = self.agent_id()
            if not device: return self.json_response(401, {'error':'Invalid device token'})
            return self.json_response(200, {'policy':policy_read(), 'fetched_at':now()})
        if path == '/api/admin/me':
            session = self.current_session()
            return self.json_response(200 if session else 401, {'user':'admin','csrf':session['csrf']} if session else {'error':'Login required'})
        if path.startswith('/api/admin/'):
            if not self.require_admin(): return
            with connect() as db:
                if path == '/api/admin/policy':
                    return self.json_response(200, {'policy':policy_read()})
                if path == '/api/admin/devices':
                    rows = db.execute('SELECT device_id,name,last_seen,created FROM devices ORDER BY created DESC').fetchall()
                    return self.json_response(200, {'devices':[dict(r) for r in rows]})
                if path == '/api/admin/events':
                    rows = db.execute('SELECT id,device_id,kind,action,domain,extension,size,reason,created FROM events ORDER BY id DESC LIMIT 250').fetchall()
                    return self.json_response(200, {'events':[dict(r) for r in rows]})
                if path == '/api/admin/summary':
                    since = (datetime.now(timezone.utc)-timedelta(hours=24)).isoformat(timespec='seconds')
                    stats = db.execute("SELECT COUNT(*) total, SUM(CASE WHEN action IN ('blocked','quarantined') THEN 1 ELSE 0 END) blocked, SUM(CASE WHEN kind='upload' AND action IN ('blocked','quarantined') THEN 1 ELSE 0 END) uploads, SUM(CASE WHEN kind='download' AND action IN ('blocked','quarantined') THEN 1 ELSE 0 END) downloads FROM events WHERE created>=?", (since,)).fetchone()
                    total = db.execute('SELECT COUNT(*) total FROM devices').fetchone()['total']
                    active_since = (datetime.now(timezone.utc)-timedelta(minutes=5)).isoformat(timespec='seconds')
                    online = db.execute('SELECT COUNT(*) total FROM devices WHERE last_seen>=?',(active_since,)).fetchone()['total']
                    bykind = db.execute('SELECT kind,COUNT(*) total FROM events WHERE created>=? GROUP BY kind',(since,)).fetchall()
                    return self.json_response(200, {'total_devices':total,'online_devices':online,'events_24h':stats['total'] or 0,'blocked_24h':stats['blocked'] or 0,'uploads_blocked':stats['uploads'] or 0,'downloads_blocked':stats['downloads'] or 0,'by_kind':[dict(r) for r in bykind]})
            return self.json_response(404, {'error':'API not found'})
        if path.startswith('/api/'):
            return self.json_response(404, {'error':'API not found'})
        self.serve_asset(path)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ('/api/admin/login','/api/admin/logout','/api/admin/policy','/api/admin/enroll','/api/agent/heartbeat','/api/agent/events'):
            return self.json_response(404, {'error':'API not found'})
        try:
            body = self.payload()
            if not isinstance(body, dict):
                raise ValueError('JSON object required')
        except ValueError as exc:
            return self.json_response(400, {'error':str(exc)})
        if path == '/api/admin/login':
            user, password = body.get('username',''), body.get('password','')
            with connect() as db:
                auth = db.execute('SELECT salt,passhash FROM auth WHERE id=1').fetchone()
                ok = user == 'admin' and isinstance(password,str) and hmac.compare_digest(password_hash(password,auth['salt']),auth['passhash'])
                if not ok: return self.json_response(401, {'error':'Invalid credentials'})
                token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
                expires = (datetime.now(timezone.utc)+timedelta(hours=8)).isoformat(timespec='seconds')
                db.execute('INSERT INTO sessions VALUES (?,?,?)',(hash_secret(token),csrf,expires))
                db.commit()
            secure = '; Secure' if isinstance(self.connection,ssl.SSLSocket) else ''
            return self.json_response(200, {'user':'admin','csrf':csrf}, 'sg_session='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+secure)
        if path.startswith('/api/admin/'):
            if not self.require_admin(write=True): return
            if path == '/api/admin/logout':
                jar = http.cookies.SimpleCookie(self.headers.get('Cookie',''))
                if 'sg_session' in jar:
                    with connect() as db:
                        db.execute('DELETE FROM sessions WHERE token_hash=?',(hash_secret(jar['sg_session'].value),))
                        db.commit()
                return self.json_response(200, {'ok':True}, 'sg_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            if path == '/api/admin/policy':
                try: policy = validate_policy(body)
                except ValueError as exc: return self.json_response(400, {'error':str(exc)})
                with connect() as db:
                    db.execute("UPDATE config SET value=? WHERE key='policy'",(json.dumps(policy),))
                    db.commit()
                return self.json_response(200,{'policy':policy})
            if path == '/api/admin/enroll':
                name = str(body.get('name','')).strip()
                if not 1 <= len(name) <= 80:
                    return self.json_response(400, {'error':'Device name required (1-80 chars)'})
                device_id = 'dev-'+secrets.token_hex(6)
                token = secrets.token_urlsafe(32)
                with connect() as db:
                    db.execute('INSERT INTO devices (device_id,name,token_hash,created) VALUES (?,?,?,?)',(device_id,name,hash_secret(token),now()))
                    db.commit()
                return self.json_response(201, {'device_id':device_id, 'device_token':token, 'warning':'Copy token now; it is shown only once'})
        device = self.agent_id()
        if not device:
            return self.json_response(401, {'error':'Invalid device token'})
        with connect() as db:
            db.execute('UPDATE devices SET last_seen=? WHERE device_id=?',(now(),device))
            db.commit()
            if path == '/api/agent/heartbeat':
                return self.json_response(200, {'ok':True})
            if path == '/api/agent/events':
                events = body.get('events',[])
                if not isinstance(events,list) or len(events) > 50:
                    return self.json_response(400, {'error':'events must be an array (<=50)'})
                for ev in events:
                    if not isinstance(ev,dict): continue
                    kind = str(ev.get('kind','other'))[:32]
                    action = str(ev.get('action','observed'))[:32]
                    if kind not in ('web','upload','download','agent','other') or action not in ('blocked','observed','quarantined','error'):
                        continue
                    db.execute('INSERT INTO events(device_id,kind,action,domain,extension,size,reason,created) VALUES (?,?,?,?,?,?,?,?)', (device,kind,action,str(ev.get('domain',''))[:253],str(ev.get('extension',''))[:24],min(max(int(ev.get('size') or 0),0),2**40),str(ev.get('reason',''))[:200],now()))
                db.commit()
                return self.json_response(200, {'ok':True})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host',default='127.0.0.1')
    ap.add_argument('--port',type=int,default=8899)
    ap.add_argument('--tls-cert')
    ap.add_argument('--tls-key')
    args = ap.parse_args()
    if args.host not in ('127.0.0.1','::1','localhost') and not (args.tls_cert and args.tls_key):
        ap.error('Non-loopback console requires TLS certificate and key')
    initialize()
    srv = ThreadingHTTPServer((args.host,args.port),Handler)
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert,args.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket,server_side=True)
    print(f'SentinelGate CISO Console: {"https" if args.tls_cert else "http"}://{args.host}:{args.port}')
    try: srv.serve_forever(poll_interval=.3)
    except KeyboardInterrupt: pass
    finally: srv.server_close()

if __name__=='__main__': main()
