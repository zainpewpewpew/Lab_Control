"""LabControl console: CISO-facing endpoint-monitoring server.

Single-file FastAPI app.
Run: uvicorn server:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
Transfer: set LC_ADMIN_PASSWORD, LC_SIGNING_KEY, LC_TELEGRAM_TOKEN, LC_TELEGRAM_CHAT_ID in env.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
STATE = ROOT / 'state'
STATE.mkdir(exist_ok=True)
DB_FILE = STATE / 'labcontrol.db'
KEY_FILE = STATE / 'signing.key'
WEB_DIR = ROOT / 'web'

ADMIN_USER = os.environ.get('LC_ADMIN_USER', 'admin')
ADMIN_PASSWORD = os.environ.get('LC_ADMIN_PASSWORD') or ''
SESSION_SECRET = os.environ.get('LC_SESSION_SECRET') or secrets.token_hex(32)
TELEGRAM_TOKEN = os.environ.get('LC_TELEGRAM_TOKEN', '')
TELEGRAM_CHAT = os.environ.get('LC_TELEGRAM_CHAT_ID', '')
ENROLL_SECRET = os.environ.get('LC_ENROLL_SECRET') or ''
MAX_EVENT_BYTES = 256 * 1024
MAX_EVENTS_PER_HEARTBEAT = 200

if not ADMIN_PASSWORD:
    raise SystemExit('Set LC_ADMIN_PASSWORD env var before starting the console.')
if not ENROLL_SECRET:
    raise SystemExit('Set LC_ENROLL_SECRET env var (shared enrollment pre-key).')

signer = URLSafeSerializer(SESSION_SECRET, salt='labcontrol-session')


# Per-IP rate limiting (in-memory; sufficient for single-worker pilot).
_rate_state: dict[str, list[float]] = {}


def rate_limit_check(key: str, max_hits: int, window_sec: int) -> bool:
    now = time.time()
    hits = [t for t in _rate_state.get(key, []) if now - t < window_sec]
    if len(hits) >= max_hits:
        _rate_state[key] = hits
        return False
    hits.append(now)
    _rate_state[key] = hits
    return True


def client_ip(request: Request) -> str:
    return (request.client.host if request.client else 'unknown') or 'unknown'


def hash_password(pw: str, salt: bytes) -> bytes:
    return hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


@contextmanager
def db():
    conn = sqlite3.connect(DB_FILE, isolation_level=None, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        yield conn
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    employee TEXT,
    os_build TEXT,
    pubkey BLOB NOT NULL,
    token_hash BLOB NOT NULL,
    enrolled_at INTEGER NOT NULL,
    last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    severity INTEGER NOT NULL DEFAULT 0,
    data TEXT NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_device_ts ON events(device_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE TABLE IF NOT EXISTS commands(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    action TEXT NOT NULL,
    args TEXT NOT NULL,
    nonce TEXT NOT NULL,
    signature BLOB NOT NULL,
    delivered_at INTEGER,
    result TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS policy(
    device_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_history_device_ts ON policy_history(device_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS alert_rules(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    match_kind TEXT NOT NULL,
    match_substr TEXT NOT NULL DEFAULT '',
    min_severity INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1
);
"""


def load_signing_key() -> Ed25519PrivateKey:
    if KEY_FILE.exists():
        raw = KEY_FILE.read_bytes()
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    KEY_FILE.write_bytes(raw)
    os.chmod(KEY_FILE, 0o600)
    return key


SIGNING_KEY: Ed25519PrivateKey = load_signing_key()


def sign_command(device_id: str, action: str, args: dict[str, Any], nonce: str, issued_at: int) -> bytes:
    payload = json.dumps(
        {'device_id': device_id, 'action': action, 'args': args, 'nonce': nonce, 'issued_at': issued_at},
        sort_keys=True, separators=(',', ':')
    ).encode()
    return SIGNING_KEY.sign(payload)


def console_pubkey_b64() -> str:
    pub = SIGNING_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(pub).decode()


event_subscribers: set[asyncio.Queue[str]] = set()


async def broadcast_event(payload: dict[str, Any]) -> None:
    data = json.dumps(payload, default=str)
    stale = []
    for q in list(event_subscribers):
        try:
            q.put_nowait(data)
        except asyncio.QueueFull:
            stale.append(q)
    for q in stale:
        event_subscribers.discard(q)


async def telegram_send(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        return
    url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    body = {'chat_id': TELEGRAM_CHAT, 'text': text[:3800], 'parse_mode': 'HTML'}
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            await client.post(url, json=body)
    except httpx.HTTPError:
        pass


async def evaluate_alerts(device_id: str, kind: str, severity: int, data: dict[str, Any]) -> None:
    with db() as conn:
        rules = conn.execute(
            'SELECT name, match_kind, match_substr, min_severity FROM alert_rules WHERE enabled=1'
        ).fetchall()
    serialized = json.dumps(data, default=str).lower()
    for r in rules:
        if r['match_kind'] and r['match_kind'] != kind:
            continue
        if r['min_severity'] > severity:
            continue
        sub = (r['match_substr'] or '').lower()
        if sub and sub not in serialized:
            continue
        text = (
            f"<b>LabControl alert</b>\n"
            f"Rule: {r['name']}\n"
            f"Device: {device_id}\n"
            f"Kind: {kind}\n"
            f"Severity: {severity}\n"
            f"Data: <code>{json.dumps(data, default=str)[:900]}</code>"
        )
        # Fire-and-forget: a slow Telegram API must not stall the agent heartbeat.
        asyncio.create_task(telegram_send(text))


class EnrollReq(BaseModel):
    enroll_secret: str = Field(min_length=8, max_length=256)
    hostname: str = Field(min_length=1, max_length=255)
    employee: str | None = Field(default=None, max_length=255)
    os_build: str | None = Field(default=None, max_length=255)
    pubkey: str = Field(min_length=20, max_length=200)


class Event(BaseModel):
    ts: int
    kind: str = Field(min_length=1, max_length=64)
    severity: int = Field(ge=0, le=10)
    data: dict[str, Any] = Field(default_factory=dict)


class Heartbeat(BaseModel):
    events: list[Event] = Field(default_factory=list)


class CommandCreate(BaseModel):
    device_id: str
    action: str = Field(pattern=r'^[a-z_][a-z0-9_]{0,31}$')
    args: dict[str, Any] = Field(default_factory=dict)


class CommandResult(BaseModel):
    command_id: int
    ok: bool
    output: str = Field(default='', max_length=16000)


class AlertRuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    match_kind: str = Field(default='', max_length=64)
    match_substr: str = Field(default='', max_length=200)
    min_severity: int = Field(ge=0, le=10, default=0)
    enabled: bool = True


async def admin_required(request: Request) -> str:
    token = request.cookies.get('lc_sess')
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'login required')
    try:
        data = signer.loads(token)
    except BadSignature:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'bad session')
    if data.get('u') != ADMIN_USER or time.time() - data.get('t', 0) > 43200:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'session expired')
    return data['u']


async def agent_required(request: Request) -> sqlite3.Row:
    auth = request.headers.get('authorization', '')
    if not auth.lower().startswith('bearer '):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'bearer token required')
    device_id = request.headers.get('x-device-id', '')
    if not device_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'x-device-id required')
    token = auth.split(None, 1)[1].strip()
    with db() as conn:
        row = conn.execute(
            'SELECT device_id, hostname, employee, token_hash FROM devices WHERE device_id=?',
            (device_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'unknown device')
    expected = row['token_hash']
    candidate = hashlib.sha256(token.encode()).digest()
    if not hmac.compare_digest(expected, candidate):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'bad token')
    return row


@asynccontextmanager
async def lifespan(app: FastAPI):
    with db() as conn:
        conn.executescript(SCHEMA)
        cnt = conn.execute('SELECT COUNT(*) c FROM alert_rules').fetchone()['c']
        if cnt == 0:
            seed = [
                ('process-blocklist-hit', 'process_block', '', 5),
                ('usb-mass-storage-plug', 'usb_plug', 'mass storage', 3),
                ('logon-after-hours', 'logon', '', 2),
                ('agent-tamper', 'agent_tamper', '', 8),
            ]
            now = int(time.time())
            conn.executemany(
                'INSERT INTO alert_rules(name, match_kind, match_substr, min_severity) VALUES(?,?,?,?)',
                seed,
            )
    yield


app = FastAPI(title='LabControl Console', lifespan=lifespan)


@app.get('/', response_class=HTMLResponse)
async def index():
    return (WEB_DIR / 'index.html').read_text(encoding='utf-8')


app.mount('/static', StaticFiles(directory=str(WEB_DIR)), name='static')


@app.post('/admin/login')
async def admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    if not rate_limit_check('login:' + client_ip(request), max_hits=10, window_sec=300):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, 'too many login attempts; retry in 5 min')
    if not (constant_time_eq(username, ADMIN_USER) and constant_time_eq(password, ADMIN_PASSWORD)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'bad credentials')
    token = signer.dumps({'u': ADMIN_USER, 't': int(time.time())})
    resp = JSONResponse({'ok': True})
    resp.set_cookie('lc_sess', token, httponly=True, samesite='strict', secure=True, max_age=43200)
    return resp


@app.post('/admin/logout')
async def admin_logout():
    resp = JSONResponse({'ok': True})
    resp.delete_cookie('lc_sess')
    return resp


@app.get('/admin/me')
async def admin_me(user: str = Depends(admin_required)):
    return {'user': user, 'pubkey': console_pubkey_b64()}


@app.get('/admin/devices')
async def list_devices(user: str = Depends(admin_required)):
    with db() as conn:
        rows = conn.execute(
            'SELECT device_id, hostname, employee, os_build, enrolled_at, last_seen FROM devices ORDER BY last_seen DESC NULLS LAST'
        ).fetchall()
    return [dict(r) for r in rows]


@app.get('/admin/events')
async def list_events(
    user: str = Depends(admin_required),
    device_id: str | None = None,
    limit: int = 200,
):
    limit = max(1, min(limit, 1000))
    with db() as conn:
        if device_id:
            rows = conn.execute(
                'SELECT id, device_id, ts, kind, severity, data FROM events WHERE device_id=? ORDER BY id DESC LIMIT ?',
                (device_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT id, device_id, ts, kind, severity, data FROM events ORDER BY id DESC LIMIT ?',
                (limit,),
            ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d['data'] = json.loads(d['data'])
        out.append(d)
    return out


ALLOWED_ACTIONS = {'lock_workstation', 'shutdown', 'reboot', 'logoff',
                   'kill_process', 'collect_proclist', 'uninstall', 'self_test',
                   'collect_usb_list', 'collect_net_list'}


@app.post('/admin/commands')
async def create_command(cmd: CommandCreate, user: str = Depends(admin_required)):
    if cmd.action not in ALLOWED_ACTIONS:
        raise HTTPException(400, f'action must be one of {sorted(ALLOWED_ACTIONS)}')
    nonce = secrets.token_hex(16)
    issued_at = int(time.time())
    sig = sign_command(cmd.device_id, cmd.action, cmd.args, nonce, issued_at)
    with db() as conn:
        exists = conn.execute('SELECT 1 FROM devices WHERE device_id=?', (cmd.device_id,)).fetchone()
        if not exists:
            raise HTTPException(404, 'device not found')
        cur = conn.execute(
            'INSERT INTO commands(device_id, created_at, action, args, nonce, signature) VALUES(?,?,?,?,?,?)',
            (cmd.device_id, issued_at, cmd.action, json.dumps(cmd.args), nonce, sig),
        )
        cmd_id = cur.lastrowid
    return {'ok': True, 'command_id': cmd_id}


@app.get('/admin/policy/{device_id}')
async def get_policy(device_id: str, user: str = Depends(admin_required)):
    with db() as conn:
        row = conn.execute('SELECT version, updated_at, body FROM policy WHERE device_id=?', (device_id,)).fetchone()
    if not row:
        return {'version': 0, 'body': {'process_blocklist': [], 'usb_block': False, 'allow_personal_email': True}}
    return {'version': row['version'], 'updated_at': row['updated_at'], 'body': json.loads(row['body'])}


@app.put('/admin/policy/{device_id}')
async def put_policy(device_id: str, body: dict[str, Any], user: str = Depends(admin_required)):
    with db() as conn:
        exists = conn.execute('SELECT 1 FROM devices WHERE device_id=?', (device_id,)).fetchone()
        if not exists:
            raise HTTPException(404, 'device not found')
        row = conn.execute('SELECT version FROM policy WHERE device_id=?', (device_id,)).fetchone()
        v = (row['version'] + 1) if row else 1
        now = int(time.time())
        body_json = json.dumps(body)
        conn.execute(
            'INSERT INTO policy_history(device_id, version, updated_at, updated_by, body) VALUES(?,?,?,?,?)',
            (device_id, v, now, user, body_json),
        )
        conn.execute(
            'INSERT INTO policy(device_id, version, updated_at, body) VALUES(?,?,?,?) '
            'ON CONFLICT(device_id) DO UPDATE SET version=excluded.version, updated_at=excluded.updated_at, body=excluded.body',
            (device_id, v, now, body_json),
        )
    return {'ok': True, 'version': v}


@app.get('/admin/policy/{device_id}/history')
async def policy_history(device_id: str, user: str = Depends(admin_required), limit: int = 50):
    limit = max(1, min(limit, 500))
    with db() as conn:
        rows = conn.execute(
            'SELECT version, updated_at, updated_by, body FROM policy_history '
            'WHERE device_id=? ORDER BY id DESC LIMIT ?',
            (device_id, limit),
        ).fetchall()
    return [
        {'version': r['version'], 'updated_at': r['updated_at'], 'updated_by': r['updated_by'], 'body': json.loads(r['body'])}
        for r in rows
    ]


@app.get('/admin/alert-rules')
async def list_rules(user: str = Depends(admin_required)):
    with db() as conn:
        rows = conn.execute(
            'SELECT id, name, match_kind, match_substr, min_severity, enabled FROM alert_rules ORDER BY id'
        ).fetchall()
    return [dict(r) for r in rows]


@app.post('/admin/alert-rules')
async def create_rule(r: AlertRuleIn, user: str = Depends(admin_required)):
    with db() as conn:
        cur = conn.execute(
            'INSERT INTO alert_rules(name, match_kind, match_substr, min_severity, enabled) VALUES(?,?,?,?,?)',
            (r.name, r.match_kind, r.match_substr, r.min_severity, 1 if r.enabled else 0),
        )
    return {'ok': True, 'id': cur.lastrowid}


@app.delete('/admin/alert-rules/{rule_id}')
async def delete_rule(rule_id: int, user: str = Depends(admin_required)):
    with db() as conn:
        conn.execute('DELETE FROM alert_rules WHERE id=?', (rule_id,))
    return {'ok': True}


@app.get('/admin/stream')
async def admin_stream(request: Request, user: str = Depends(admin_required)):
    q: asyncio.Queue[str] = asyncio.Queue(maxsize=512)
    event_subscribers.add(q)

    async def gen():
        try:
            yield b': connected\n\n'
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=20)
                    yield f'data: {data}\n\n'.encode()
                except asyncio.TimeoutError:
                    yield b': keepalive\n\n'
        finally:
            event_subscribers.discard(q)

    return StreamingResponse(gen(), media_type='text/event-stream', headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})


@app.post('/agent/enroll')
async def agent_enroll(request: Request, req: EnrollReq):
    if not rate_limit_check('enroll:' + client_ip(request), max_hits=5, window_sec=3600):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, 'enrollment rate limited; retry in 1 hour')
    if not hmac.compare_digest(req.enroll_secret.encode(), ENROLL_SECRET.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'bad enroll secret')
    try:
        pub_bytes = base64.b64decode(req.pubkey)
        Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception:
        raise HTTPException(400, 'invalid pubkey')
    device_id = 'dev_' + secrets.token_hex(12)
    token = secrets.token_urlsafe(40)
    token_hash = hashlib.sha256(token.encode()).digest()
    now = int(time.time())
    with db() as conn:
        conn.execute(
            'INSERT INTO devices(device_id, hostname, employee, os_build, pubkey, token_hash, enrolled_at, last_seen) '
            'VALUES(?,?,?,?,?,?,?,?)',
            (device_id, req.hostname, req.employee, req.os_build, pub_bytes, token_hash, now, now),
        )
    return {
        'device_id': device_id,
        'token': token,
        'console_pubkey': console_pubkey_b64(),
        'heartbeat_sec': 30,
        'telemetry_sec': 60,
    }


@app.post('/agent/heartbeat')
async def agent_heartbeat(hb: Heartbeat, device: sqlite3.Row = Depends(agent_required)):
    if len(hb.events) > MAX_EVENTS_PER_HEARTBEAT:
        raise HTTPException(413, 'too many events')
    now = int(time.time())
    with db() as conn:
        conn.execute('UPDATE devices SET last_seen=? WHERE device_id=?', (now, device['device_id']))
        rows = []
        for e in hb.events:
            raw = json.dumps(e.data, default=str)
            if len(raw) > MAX_EVENT_BYTES:
                continue
            rows.append((device['device_id'], e.ts, e.kind, e.severity, raw))
        if rows:
            conn.executemany(
                'INSERT INTO events(device_id, ts, kind, severity, data) VALUES(?,?,?,?,?)', rows
            )
        cmd_rows = conn.execute(
            'SELECT id, action, args, nonce, signature, created_at FROM commands '
            'WHERE device_id=? AND delivered_at IS NULL ORDER BY id LIMIT 20',
            (device['device_id'],),
        ).fetchall()
        if cmd_rows:
            ids = [r['id'] for r in cmd_rows]
            conn.execute(
                f'UPDATE commands SET delivered_at=? WHERE id IN ({",".join("?" * len(ids))})',
                (now, *ids),
            )
        policy_row = conn.execute(
            'SELECT version, body FROM policy WHERE device_id=?', (device['device_id'],)
        ).fetchone()

    for e in hb.events:
        payload = {
            'device_id': device['device_id'],
            'hostname': device['hostname'],
            'ts': e.ts,
            'kind': e.kind,
            'severity': e.severity,
            'data': e.data,
        }
        await broadcast_event(payload)
        await evaluate_alerts(device['device_id'], e.kind, e.severity, e.data)

    commands = []
    for r in cmd_rows:
        commands.append({
            'id': r['id'],
            'action': r['action'],
            'args': json.loads(r['args']),
            'nonce': r['nonce'],
            'signature': base64.b64encode(r['signature']).decode(),
            'issued_at': r['created_at'],
        })
    policy = {
        'version': policy_row['version'] if policy_row else 0,
        'body': json.loads(policy_row['body']) if policy_row else
                {'process_blocklist': [], 'usb_block': False, 'allow_personal_email': True},
    }
    return {'ok': True, 'commands': commands, 'policy': policy}


@app.post('/agent/command-result')
async def agent_command_result(res: CommandResult, device: sqlite3.Row = Depends(agent_required)):
    with db() as conn:
        row = conn.execute(
            'SELECT device_id FROM commands WHERE id=?', (res.command_id,)
        ).fetchone()
        if not row or row['device_id'] != device['device_id']:
            raise HTTPException(404, 'command not found for this device')
        conn.execute(
            'UPDATE commands SET result=? WHERE id=?',
            (json.dumps({'ok': res.ok, 'output': res.output[:16000]}), res.command_id),
        )
    await broadcast_event({
        'device_id': device['device_id'],
        'hostname': device['hostname'],
        'ts': int(time.time()),
        'kind': 'command_result',
        'severity': 0 if res.ok else 4,
        'data': {'command_id': res.command_id, 'ok': res.ok, 'output_head': res.output[:400]},
    })
    return {'ok': True}


@app.get('/agent/policy')
async def agent_policy(device: sqlite3.Row = Depends(agent_required)):
    with db() as conn:
        row = conn.execute(
            'SELECT version, body FROM policy WHERE device_id=?', (device['device_id'],)
        ).fetchone()
    if not row:
        return {'version': 0, 'body': {'process_blocklist': [], 'usb_block': False, 'allow_personal_email': True}}
    return {'version': row['version'], 'body': json.loads(row['body'])}


@app.get('/health')
async def health():
    return {'ok': True, 'ts': int(time.time())}
