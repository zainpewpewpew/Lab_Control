"""LabControl endpoint agent (Windows 10/11).

Transparent monitoring + policy enforcement + signed remote command executor.
No keystroke capture, no screen capture, no file-content exfiltration.
Config: %ProgramData%\\LabControl\\config.json (created by install_service.ps1 after first enroll).
Run as Windows Service via install_service.ps1, or foreground with --once for testing.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import json
import logging
import logging.handlers
import os
import platform
import queue
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import psutil
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

IS_WINDOWS = platform.system() == 'Windows'
if IS_WINDOWS:
    DATA_DIR = Path(os.environ.get('ProgramData', r'C:\\ProgramData')) / 'LabControl'
else:
    DATA_DIR = Path(os.environ.get('LABCONTROL_DATA', str(Path.home() / '.labcontrol')))

DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = DATA_DIR / 'config.json'
KEY_FILE = DATA_DIR / 'device.key'
STATE_FILE = DATA_DIR / 'state.json'
LOG_FILE = DATA_DIR / 'agent.log'
QUEUE_FILE = DATA_DIR / 'events.jsonl'

log = logging.getLogger('labcontrol')


def setup_log() -> None:
    log.setLevel(logging.INFO)
    h = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding='utf-8')
    h.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    log.addHandler(h)
    if sys.stdout and sys.stdout.isatty():
        s = logging.StreamHandler()
        s.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        log.addHandler(s)


def load_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        raise SystemExit(f'Config missing: {CONFIG_FILE}. Run install_service.ps1 to enroll.')
    return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))


def load_state() -> dict[str, Any]:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}


def save_state(state: dict[str, Any]) -> None:
    tmp = STATE_FILE.with_suffix('.tmp')
    tmp.write_text(json.dumps(state), encoding='utf-8')
    tmp.replace(STATE_FILE)


def load_device_key() -> Ed25519PrivateKey:
    if KEY_FILE.exists():
        return Ed25519PrivateKey.from_private_bytes(KEY_FILE.read_bytes())
    k = Ed25519PrivateKey.generate()
    KEY_FILE.write_bytes(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    if not IS_WINDOWS:
        os.chmod(KEY_FILE, 0o600)
    return k


def device_pubkey_b64(k: Ed25519PrivateKey) -> str:
    return base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def enroll(server_url: str, enroll_secret: str, employee: str | None) -> None:
    key = load_device_key()
    hostname = socket.gethostname()
    os_build = f'{platform.system()} {platform.release()} {platform.version()}'
    payload = {
        'enroll_secret': enroll_secret,
        'hostname': hostname,
        'employee': employee or '',
        'os_build': os_build,
        'pubkey': device_pubkey_b64(key),
    }
    with httpx.Client(timeout=15) as client:
        r = client.post(server_url.rstrip('/') + '/agent/enroll', json=payload)
    if r.status_code != 200:
        raise SystemExit(f'enroll failed: {r.status_code} {r.text}')
    data = r.json()
    cfg = {
        'server_url': server_url.rstrip('/'),
        'device_id': data['device_id'],
        'token': data['token'],
        'console_pubkey': data['console_pubkey'],
        'heartbeat_sec': int(data.get('heartbeat_sec', 30)),
        'telemetry_sec': int(data.get('telemetry_sec', 60)),
    }
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding='utf-8')
    print(f'Enrolled: device_id={data["device_id"]}')


class EventSink:
    """Persistent event buffer; events survive restarts until flushed to console."""

    MAX_FILE_BYTES = 8 * 1024 * 1024  # 8 MB hard cap on the on-disk queue

    def __init__(self, path: Path, cap: int = 10000):
        self.path = path
        self.cap = cap
        self.lock = threading.Lock()
        self.q: queue.Queue[dict[str, Any]] = queue.Queue()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding='utf-8').splitlines()
        except Exception:
            return
        # Drop oldest if the file already exceeded cap (survives across restarts).
        tail = lines[-self.cap:]
        for line in tail:
            if line.strip():
                try:
                    self.q.put(json.loads(line))
                except Exception:
                    continue

    def push(self, kind: str, severity: int, data: dict[str, Any]) -> None:
        if self.q.qsize() >= self.cap:
            with contextlib.suppress(queue.Empty):
                self.q.get_nowait()
        evt = {'ts': int(time.time()), 'kind': kind, 'severity': severity, 'data': data}
        self.q.put(evt)
        self._append(evt)

    def _append(self, evt: dict[str, Any]) -> None:
        with self.lock:
            with self.path.open('a', encoding='utf-8') as f:
                f.write(json.dumps(evt) + '\n')
            try:
                if self.path.stat().st_size > self.MAX_FILE_BYTES:
                    self._rotate_locked()
            except OSError:
                pass

    def _rotate_locked(self) -> None:
        tmp = self.path.with_suffix('.tmp')
        with tmp.open('w', encoding='utf-8') as f:
            for item in list(self.q.queue):
                f.write(json.dumps(item) + '\n')
        tmp.replace(self.path)

    def drain(self, max_n: int = 200) -> list[dict[str, Any]]:
        out = []
        while len(out) < max_n:
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                break
        return out

    def requeue(self, items: list[dict[str, Any]]) -> None:
        for e in items:
            self.q.put(e)

    def rewrite_from_queue(self) -> None:
        with self.lock:
            tmp = self.path.with_suffix('.tmp')
            with tmp.open('w', encoding='utf-8') as f:
                for item in list(self.q.queue):
                    f.write(json.dumps(item) + '\n')
            tmp.replace(self.path)


class Collector(threading.Thread):
    def __init__(self, sink: EventSink, policy_ref: dict[str, Any], interval: int):
        super().__init__(daemon=True, name='collector')
        self.sink = sink
        self.policy_ref = policy_ref
        self.interval = interval
        self.stop_flag = threading.Event()
        self.seen_pids: set[int] = set()
        self.seen_logons: set[str] = set()
        self.seen_usb: set[str] = set()
        self.seen_nets: set[tuple] = set()
        self._first_pass = True

    def stop(self) -> None:
        self.stop_flag.set()

    def run(self) -> None:
        while not self.stop_flag.is_set():
            try:
                self._tick()
            except Exception as exc:
                log.exception('collector tick error: %s', exc)
            self.stop_flag.wait(self.interval)

    def _tick(self) -> None:
        self._scan_processes()
        self._scan_logons()
        self._scan_usb()
        self._scan_connections()
        self._first_pass = False

    def _scan_processes(self) -> None:
        pids_now: set[int] = set()
        new_procs = []
        block = {s.lower() for s in self.policy_ref.get('process_blocklist', [])}
        for p in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'create_time']):
            try:
                info = p.info
                pid = info['pid']
                pids_now.add(pid)
                if pid in self.seen_pids:
                    continue
                name = (info.get('name') or '').lower()
                row = {
                    'pid': pid,
                    'name': info.get('name') or '',
                    'user': info.get('username') or '',
                    'exe': info.get('exe') or '',
                    'cmdline': (info.get('cmdline') or [])[:12],
                    'started': int(info.get('create_time') or 0),
                }
                new_procs.append(row)
                if name in block:
                    self.sink.push('process_block', 6, row)
                    with contextlib.suppress(Exception):
                        psutil.Process(pid).kill()
                        self.sink.push('process_killed', 6, {'pid': pid, 'name': name})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not self._first_pass and new_procs:
            self.sink.push('process_started', 1, {'procs': new_procs})
        ended = self.seen_pids - pids_now
        if not self._first_pass and ended:
            self.sink.push('process_ended', 0, {'pids': sorted(ended)[:200]})
        self.seen_pids = pids_now

    def _scan_logons(self) -> None:
        try:
            users = psutil.users()
        except Exception:
            return
        current = {f"{u.name}@{u.host or ''}|{int(u.started or 0)}" for u in users}
        if self._first_pass:
            self.seen_logons = current
            return
        for key in current - self.seen_logons:
            name, _, started = key.partition('|')
            self.sink.push('logon', 2, {'user': name.split('@', 1)[0], 'started': int(started or 0)})
        for key in self.seen_logons - current:
            name, _, _ = key.partition('|')
            self.sink.push('logoff', 1, {'user': name.split('@', 1)[0]})
        self.seen_logons = current

    def _scan_usb(self) -> None:
        if not IS_WINDOWS:
            return
        try:
            out = subprocess.check_output(
                ['wmic', 'path', 'Win32_PnPEntity', 'where', "PNPDeviceID like 'USB%'",
                 'get', 'PNPDeviceID,Name', '/format:csv'],
                stderr=subprocess.DEVNULL, timeout=8,
            ).decode(errors='ignore')
        except Exception:
            return
        current = set()
        parsed: dict[str, str] = {}
        for line in out.splitlines():
            line = line.strip()
            if not line or line.lower().startswith('node') or ',' not in line:
                continue
            parts = line.split(',')
            if len(parts) < 3:
                continue
            name, pnp = parts[-2].strip(), parts[-1].strip()
            if not pnp:
                continue
            current.add(pnp)
            parsed[pnp] = name
        if self._first_pass:
            self.seen_usb = current
            return
        for pnp in current - self.seen_usb:
            name = parsed.get(pnp, '')
            sev = 3 if 'mass storage' in name.lower() or 'disk' in name.lower() else 1
            self.sink.push('usb_plug', sev, {'pnp': pnp, 'name': name})
            if self.policy_ref.get('usb_block') and sev >= 3:
                self._block_usb(pnp)
        for pnp in self.seen_usb - current:
            self.sink.push('usb_unplug', 0, {'pnp': pnp})
        self.seen_usb = current

    def _block_usb(self, pnp: str) -> None:
        try:
            subprocess.run(
                ['pnputil', '/disable-device', pnp],
                check=False, capture_output=True, timeout=10,
            )
            self.sink.push('usb_blocked', 4, {'pnp': pnp})
        except Exception as exc:
            self.sink.push('usb_block_fail', 5, {'pnp': pnp, 'err': str(exc)})

    def _scan_connections(self) -> None:
        try:
            conns = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, OSError):
            return
        snap: set[tuple] = set()
        new_rows: list[dict[str, Any]] = []
        for c in conns:
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue
            key = (c.pid or 0, c.raddr.ip, c.raddr.port)
            snap.add(key)
            if not self._first_pass and key not in self.seen_nets:
                row = {'pid': c.pid, 'remote_ip': c.raddr.ip, 'remote_port': c.raddr.port}
                with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                    row['proc'] = psutil.Process(c.pid).name() if c.pid else ''
                new_rows.append(row)
        if new_rows:
            self.sink.push('net_connect', 1, {'conns': new_rows[:50]})
        self.seen_nets = snap


class CommandRunner:
    def __init__(self, console_pub: Ed25519PublicKey, device_id: str, sink: EventSink, state: dict[str, Any]):
        self.console_pub = console_pub
        self.device_id = device_id
        self.sink = sink
        self.state = state
        self.state.setdefault('seen_nonces', [])

    MAX_COMMAND_AGE_SEC = 86400  # replay-window cap even if state.json is wiped

    def _verify(self, cmd: dict[str, Any]) -> bool:
        if cmd['nonce'] in self.state['seen_nonces']:
            return False
        issued_at = int(cmd.get('issued_at') or 0)
        if issued_at <= 0:
            return False
        age = int(time.time()) - issued_at
        if age > self.MAX_COMMAND_AGE_SEC or age < -300:
            return False
        payload = json.dumps(
            {'device_id': self.device_id, 'action': cmd['action'], 'args': cmd['args'],
             'nonce': cmd['nonce'], 'issued_at': issued_at},
            sort_keys=True, separators=(',', ':'),
        ).encode()
        try:
            self.console_pub.verify(base64.b64decode(cmd['signature']), payload)
        except InvalidSignature:
            return False
        self.state['seen_nonces'].append(cmd['nonce'])
        self.state['seen_nonces'] = self.state['seen_nonces'][-500:]
        save_state(self.state)
        return True

    def run(self, cmd: dict[str, Any]) -> tuple[bool, str]:
        if not self._verify(cmd):
            self.sink.push('command_rejected', 7, {'id': cmd['id'], 'action': cmd['action']})
            return False, 'signature invalid or nonce replayed'
        action = cmd['action']
        args = cmd.get('args') or {}
        try:
            if action == 'lock_workstation':
                return self._lock()
            if action == 'shutdown':
                return self._power('shutdown')
            if action == 'reboot':
                return self._power('reboot')
            if action == 'logoff':
                return self._power('logoff')
            if action == 'collect_proclist':
                return self._collect_proclist()
            if action == 'kill_process':
                return self._kill_process(int(args.get('pid') or 0))
            if action == 'uninstall':
                return self._uninstall()
            if action == 'self_test':
                return True, f'alive pid={os.getpid()} host={socket.gethostname()}'
            if action == 'collect_usb_list':
                return self._collect_usb_list()
            if action == 'collect_net_list':
                return self._collect_net_list()
            return False, f'unknown action {action}'
        except Exception as exc:
            return False, f'exception: {exc!r}'

    def _lock(self) -> tuple[bool, str]:
        if IS_WINDOWS:
            ok = bool(ctypes.windll.user32.LockWorkStation())
            return ok, 'locked' if ok else 'LockWorkStation returned 0'
        return False, 'lock_workstation only supported on Windows'

    def _power(self, mode: str) -> tuple[bool, str]:
        if IS_WINDOWS:
            arg = {'shutdown': '/s', 'reboot': '/r', 'logoff': '/l'}[mode]
            proc = subprocess.run(['shutdown', arg, '/t', '15', '/c', f'LabControl {mode} issued by CISO'],
                                  capture_output=True, text=True)
            return proc.returncode == 0, (proc.stdout + proc.stderr).strip() or f'{mode} scheduled'
        return False, f'{mode} only supported on Windows'

    def _collect_proclist(self) -> tuple[bool, str]:
        rows = []
        for p in psutil.process_iter(['pid', 'name', 'username', 'exe']):
            with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                rows.append(p.info)
        self.sink.push('proclist_snapshot', 0, {'count': len(rows), 'procs': rows[:1000]})
        return True, f'{len(rows)} procs captured'

    def _kill_process(self, pid: int) -> tuple[bool, str]:
        if pid <= 0:
            return False, 'pid required'
        try:
            p = psutil.Process(pid)
            name = p.name()
            p.kill()
            return True, f'killed pid={pid} name={name}'
        except psutil.NoSuchProcess:
            return False, 'no such pid'
        except psutil.AccessDenied:
            return False, 'access denied'

    def _collect_usb_list(self) -> tuple[bool, str]:
        if not IS_WINDOWS:
            return False, 'windows only'
        try:
            out = subprocess.check_output(
                ['wmic', 'path', 'Win32_PnPEntity', 'where', "PNPDeviceID like 'USB%'",
                 'get', 'PNPDeviceID,Name', '/format:csv'],
                stderr=subprocess.DEVNULL, timeout=10,
            ).decode(errors='ignore')
        except Exception as exc:
            return False, f'wmic failed: {exc}'
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.lower().startswith('node') or ',' not in line:
                continue
            parts = line.split(',')
            if len(parts) >= 3:
                rows.append({'name': parts[-2].strip(), 'pnp': parts[-1].strip()})
        self.sink.push('usb_snapshot', 0, {'count': len(rows), 'items': rows[:400]})
        return True, f'{len(rows)} usb devices'

    def _collect_net_list(self) -> tuple[bool, str]:
        rows = []
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                    continue
                item = {'pid': c.pid, 'remote_ip': c.raddr.ip, 'remote_port': c.raddr.port}
                with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                    item['proc'] = psutil.Process(c.pid).name() if c.pid else ''
                rows.append(item)
        except (psutil.AccessDenied, OSError) as exc:
            return False, f'net_connections failed: {exc}'
        self.sink.push('net_snapshot', 0, {'count': len(rows), 'items': rows[:1000]})
        return True, f'{len(rows)} established connections'

    def _uninstall(self) -> tuple[bool, str]:
        """Self-uninstall triggered by signed CISO command only.

        Agent spawns a detached shell that waits for us to exit, then stops the
        service, deletes it, removes install dir, and wipes %ProgramData%.
        We log event, cleanly return, then main loop stops the service via SCM.
        """
        if not IS_WINDOWS:
            try:
                for p in [CONFIG_FILE, KEY_FILE, STATE_FILE, QUEUE_FILE, LOG_FILE]:
                    with contextlib.suppress(Exception):
                        p.unlink()
            except Exception as exc:
                return False, f'cleanup error: {exc}'
            return True, 'non-windows local files removed; re-enroll required'

        install_dir = Path(r'C:\\Program Files\\LabControl')
        data_dir = Path(r'C:\\ProgramData\\LabControl')
        # Preserve the last agent.log for post-incident forensics before the reaper wipes DataDir.
        archive = Path(r'C:\\Windows\\Logs\\LabControl-uninstall-' + time.strftime('%Y%m%d-%H%M%S') + '.log')
        try:
            if LOG_FILE.exists():
                archive.parent.mkdir(parents=True, exist_ok=True)
                archive.write_bytes(LOG_FILE.read_bytes())
        except Exception as exc:
            log.warning('log archive failed: %s', exc)
        reaper = (
            'cmd.exe /c "ping 127.0.0.1 -n 8 > NUL & '
            'sc.exe stop LabControlAgent & '
            'sc.exe delete LabControlAgent & '
            'schtasks /Delete /TN LabControlWatchdog /F & '
            f'rmdir /s /q \"{install_dir}\" & '
            f'rmdir /s /q \"{data_dir}\""'
        )
        try:
            subprocess.Popen(
                reaper, shell=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        except Exception as exc:
            return False, f'reaper spawn failed: {exc}'
        self.sink.push('agent_uninstall', 8, {'reason': 'signed_command'})
        threading.Thread(target=lambda: (time.sleep(2), os._exit(0)), daemon=True).start()
        return True, 'uninstall scheduled; agent exiting in 2s'


class AgentLoop:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.sink = EventSink(QUEUE_FILE)
        self.state = load_state()
        self.policy = self.state.get('policy') or {
            'version': 0, 'body': {'process_blocklist': [], 'usb_block': False, 'allow_personal_email': True}
        }
        console_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(cfg['console_pubkey']))
        self.runner = CommandRunner(console_pub, cfg['device_id'], self.sink, self.state)
        self.collector = Collector(self.sink, self.policy['body'], cfg.get('telemetry_sec', 60))
        self.stop_flag = threading.Event()

    def stop(self) -> None:
        self.stop_flag.set()
        self.collector.stop()

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg['server_url'],
            headers={'Authorization': f'Bearer {self.cfg["token"]}', 'X-Device-Id': self.cfg['device_id']},
            timeout=15,
        )

    def _heartbeat(self, client: httpx.Client) -> None:
        batch = self.sink.drain(200)
        try:
            r = client.post('/agent/heartbeat', json={'events': batch})
        except httpx.HTTPError as exc:
            log.warning('heartbeat network error: %s', exc)
            self.sink.requeue(batch)
            return
        if r.status_code != 200:
            log.warning('heartbeat http %s %s', r.status_code, r.text[:200])
            self.sink.requeue(batch)
            return
        body = r.json()
        self.sink.rewrite_from_queue()
        pol = body.get('policy') or {}
        if pol and pol.get('version', 0) >= self.policy.get('version', 0):
            new_body = pol.get('body') or self.policy['body']
            if new_body != self.policy['body']:
                self.collector.policy_ref.clear()
                self.collector.policy_ref.update(new_body)
                log.info('policy updated to version %s', pol.get('version'))
            self.policy = pol
            self.state['policy'] = pol
            save_state(self.state)
        for cmd in body.get('commands') or []:
            ok, out = self.runner.run(cmd)
            log.info('command %s(%s) → ok=%s', cmd['action'], cmd['id'], ok)
            with contextlib.suppress(httpx.HTTPError):
                client.post('/agent/command-result',
                            json={'command_id': cmd['id'], 'ok': ok, 'output': out})

    def run(self) -> None:
        self.sink.push('agent_start', 0, {
            'hostname': socket.gethostname(),
            'os': platform.platform(),
            'pid': os.getpid(),
        })
        self.collector.start()
        hb = self.cfg.get('heartbeat_sec', 30)
        with self._client() as client:
            while not self.stop_flag.is_set():
                try:
                    self._heartbeat(client)
                except Exception as exc:
                    log.exception('heartbeat error: %s', exc)
                self.stop_flag.wait(hb)
        self.sink.push('agent_stop', 0, {'pid': os.getpid()})
        with contextlib.suppress(Exception), self._client() as client:
            self._heartbeat(client)


def cmd_run(args: argparse.Namespace) -> None:
    setup_log()
    cfg = load_config()
    loop = AgentLoop(cfg)
    if args.once:
        loop.collector.start()
        time.sleep(2)
        with loop._client() as c:
            loop._heartbeat(c)
        loop.collector.stop()
        return
    try:
        loop.run()
    except KeyboardInterrupt:
        loop.stop()


def cmd_enroll(args: argparse.Namespace) -> None:
    enroll(args.server_url, args.enroll_secret, args.employee)


def main() -> None:
    p = argparse.ArgumentParser(prog='labcontrol-agent')
    sub = p.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run', help='Run agent loop (foreground)')
    r.add_argument('--once', action='store_true', help='Single tick then exit (debug)')
    r.set_defaults(func=cmd_run)
    e = sub.add_parser('enroll', help='Enroll this device against the console')
    e.add_argument('--server-url', required=True)
    e.add_argument('--enroll-secret', required=True)
    e.add_argument('--employee', default=None)
    e.set_defaults(func=cmd_enroll)
    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
