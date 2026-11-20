#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""sentinel-uid: penjaga hak (root) untuk UI standalone ZySentinel.

Tujuan defensif: sentinel-ui (akun tanpa hak, menghadap jaringan) hanya meneruskan. Seluruh
keputusan ada di sini: login akun Linux lewat PAM (hanya root dan grup sudo/wheel), TOTP opsional,
penguncian brute force per akun dan per IP, sesi terikat (User-Agent + prefiks IP), token CSRF per
sesi, allowlist metode, gerbang lisensi platform, dan catatan audit. Metode plugin dipanggil hanya
setelah semua pemeriksaan lolos dan tidak pernah dari input yang belum divalidasi.

Protokol: socket unix (0660 root:zysui), satu baris JSON per permintaan dan per jawaban, panjang terbatas.
"""
import base64
import ctypes
import ctypes.util
import grp
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import re
import secrets
import socket
import socketserver
import struct
import sys
import threading
import time

BASE = os.environ.get('ZYS_UI_BASE', '/www/server/sentinel')
ETC_UI = os.path.join(BASE, 'etc', 'ui')
SOCK = os.environ.get('ZYS_UI_SOCK', '/run/sentinel/ui.sock')
AUDIT_LOG = os.path.join(BASE, 'log', 'ui-audit.log')
MAX_LINE = 1 << 20
SESSION_MAX = 8 * 3600
SESSION_IDLE = 30 * 60
LOGIN_MIN_SECONDS = 0.6
FAIL_LIMIT = 5
FAIL_WINDOW = 15 * 60
BAN_AFTER_IP_FAILS = 10

# Metode yang tetap boleh bila lisensi tidak mengizinkan platform (halaman aktivasi saja).
LICENSE_ONLY = frozenset((
    'get_license', 'get_plans', 'license_activate', 'license_checkout', 'license_cancel',
    'license_refresh', 'license_deactivate', 'license_dev_challenge', 'license_dev_activate',
    'get_lang_setting', 'set_lang_setting', 'get_terms_and_policy', 'get_adapter_info',
))
METHOD_RE = re.compile(r'^[a-z][a-z0-9_]{1,63}$')


def now():
    return time.time()


def sha(s):
    return hashlib.sha256(s.encode('utf-8', 'replace')).hexdigest()


# --------------------------------------------------------------------------- #
# konfigurasi                                                                  #
# --------------------------------------------------------------------------- #
def load_conf():
    conf = {'groups': ['sudo', 'wheel'], 'allow_root': True, 'pam_service': 'zysentinel'}
    try:
        with open(os.path.join(ETC_UI, 'ui.conf')) as f:
            data = json.load(f)
        if isinstance(data.get('groups'), list):
            conf['groups'] = [str(g) for g in data['groups'] if re.match(r'^[A-Za-z0-9_.-]{1,32}$', str(g))]
        if 'allow_root' in data:
            conf['allow_root'] = bool(data['allow_root'])
        if re.match(r'^[A-Za-z0-9_-]{1,32}$', str(data.get('pam_service', ''))):
            conf['pam_service'] = data['pam_service']
    except Exception:
        pass
    return conf


# --------------------------------------------------------------------------- #
# PAM lewat ctypes (tanpa dependensi)                                          #
# --------------------------------------------------------------------------- #
class _PamMessage(ctypes.Structure):
    _fields_ = [('msg_style', ctypes.c_int), ('msg', ctypes.c_char_p)]


class _PamResponse(ctypes.Structure):
    _fields_ = [('resp', ctypes.c_char_p), ('resp_retcode', ctypes.c_int)]


_CONV_FUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(_PamMessage)),
                              ctypes.POINTER(ctypes.POINTER(_PamResponse)), ctypes.c_void_p)


class _PamConv(ctypes.Structure):
    _fields_ = [('conv', _CONV_FUNC), ('appdata_ptr', ctypes.c_void_p)]


def pam_authenticate(username, password, service='zysentinel'):
    """True bila PAM menerima pasangan akun/sandi. Gagal tertutup pada setiap galat."""
    if not username or not password or '\x00' in username or '\x00' in password or len(password) > 512:
        return False
    libname = ctypes.util.find_library('pam')
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    if not libname:
        return False
    pam = ctypes.CDLL(libname)
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    pam.pam_start.restype = ctypes.c_int
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_PamConv), ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pw = password.encode('utf-8')

    @_CONV_FUNC
    def conv(n, msg, resp, _app):
        arr = libc.calloc(n, ctypes.sizeof(_PamResponse))
        if not arr:
            return 5  # PAM_BUF_ERR
        resp[0] = ctypes.cast(arr, ctypes.POINTER(_PamResponse))
        for i in range(n):
            style = msg[i].contents.msg_style
            if style in (1, 2):  # PAM_PROMPT_ECHO_OFF / ON
                resp[0][i].resp = ctypes.cast(libc.strdup(pw), ctypes.c_char_p)
                resp[0][i].resp_retcode = 0
        return 0

    handle = ctypes.c_void_p()
    cv = _PamConv(conv, 0)
    if pam.pam_start(service.encode(), username.encode(), ctypes.byref(cv), ctypes.byref(handle)) != 0:
        return False
    try:
        if pam.pam_authenticate(handle, 0) != 0:
            return False
        return pam.pam_acct_mgmt(handle, 0) == 0
    finally:
        pam.pam_end(handle, 0)


def user_allowed(username, conf):
    """Hanya root (bila diizinkan) dan anggota grup administrasi. Akun lain ditolak sebelum PAM."""
    if not re.match(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$', username or ''):
        return False
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return False
    if pw.pw_uid == 0:
        return bool(conf.get('allow_root', True))
    for gname in conf.get('groups', []):
        try:
            g = grp.getgrnam(gname)
        except KeyError:
            continue
        if username in g.gr_mem or pw.pw_gid == g.gr_gid:
            return True
    return False


# --------------------------------------------------------------------------- #
# TOTP (RFC 6238) dengan anti-replay                                           #
# --------------------------------------------------------------------------- #
def totp_code(secret_b32, step):
    key = base64.b32decode(secret_b32.strip().replace(' ', '').upper() + '=' * (-len(secret_b32.strip()) % 8))
    h = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return '%06d' % ((struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_secret_path(user):
    return os.path.join(ETC_UI, 'totp', user + '.key')


def totp_secret(user):
    try:
        with open(totp_secret_path(user)) as f:
            s = f.read().strip()
        return s or None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# penguncian brute force                                                       #
# --------------------------------------------------------------------------- #
class Lockout(object):
    def __init__(self, ban_cb=None):
        self.lock = threading.Lock()
        self.fails = {}
        self.ban_cb = ban_cb

    def _prune(self, key):
        lst = [t for t in self.fails.get(key, []) if now() - t < FAIL_WINDOW]
        self.fails[key] = lst
        return lst

    def locked(self, user, ip):
        with self.lock:
            return len(self._prune('u:' + user)) >= FAIL_LIMIT or len(self._prune('i:' + ip)) >= FAIL_LIMIT

    def fail(self, user, ip):
        with self.lock:
            self._prune('u:' + user).append(now())
            lst = self._prune('i:' + ip)
            lst.append(now())
            ban = len(lst) >= BAN_AFTER_IP_FAILS
        if ban and self.ban_cb:
            try:
                self.ban_cb(ip)
            except Exception:
                pass

    def ok(self, user, ip):
        with self.lock:
            self.fails.pop('u:' + user, None)


# --------------------------------------------------------------------------- #
# sesi                                                                         #
# --------------------------------------------------------------------------- #
def ip_prefix(ip):
    try:
        a = ipaddress.ip_address(ip)
        return str(ipaddress.ip_network('%s/%d' % (ip, 24 if a.version == 4 else 64), strict=False))
    except ValueError:
        return ''


class Sessions(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {}

    def create(self, user, ip, ua):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            # sesi kedaluwarsa dibuang saat ada login baru (tidak menumpuk di memori)
            for h in [h for h, v in self.data.items() if now() - v['born'] > SESSION_MAX or now() - v['seen'] > SESSION_IDLE]:
                self.data.pop(h, None)
            self.data[sha(tok)] = {'user': user, 'ip': ip_prefix(ip), 'ua': sha(ua or ''), 'csrf': secrets.token_urlsafe(32),
                                   'born': now(), 'seen': now()}
        return tok

    def get(self, tok, ip, ua):
        if not tok or len(tok) > 128:
            return None
        h = sha(tok)
        with self.lock:
            s = self.data.get(h)
            if not s:
                return None
            if now() - s['born'] > SESSION_MAX or now() - s['seen'] > SESSION_IDLE or \
                    s['ua'] != sha(ua or '') or s['ip'] != ip_prefix(ip):
                self.data.pop(h, None)
                return None
            s['seen'] = now()
            return dict(s)

    def drop(self, tok):
        with self.lock:
            self.data.pop(sha(tok or ''), None)


# --------------------------------------------------------------------------- #
# audit                                                                        #
# --------------------------------------------------------------------------- #
_audit_lock = threading.Lock()


def audit(user, ip, what, result):
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        line = '%s user=%s ip=%s %s result=%s\n' % (time.strftime('%Y-%m-%dT%H:%M:%S%z'), re.sub(r'[^\w.@-]', '?', str(user))[:32],
                                                    re.sub(r'[^0-9a-fA-F:.]', '?', str(ip))[:45], re.sub(r'[^\w =.:-]', '?', what)[:120], result)
        with _audit_lock:
            fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, 'a') as f:
                f.write(line)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# inti                                                                         #
# --------------------------------------------------------------------------- #
class DictObj(dict):
    """Pengganti objek `get` milik aaPanel: akses kunci via atribut; kunci tak ada = AttributeError."""
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k)


class Core(object):
    def __init__(self, auth=None, allowlist=None, plugin=None, ban=None):
        self.conf = load_conf()
        self.auth = auth or (lambda u, p: pam_authenticate(u, p, self.conf['pam_service']))
        self.sessions = Sessions()
        self.lockout = Lockout(ban or self._ban)
        self.totp_used = {}
        self._plugin = plugin
        self._plug_lock = threading.Lock()
        self.allowlist = allowlist if allowlist is not None else self._load_allowlist()

    # -- pembantu
    def _ban(self, ip):
        ctl = os.path.join(BASE, 'bin', 'guardctl')
        if os.path.isfile(ctl) and ip_prefix(ip):
            os.spawnv(os.P_NOWAIT, ctl, [ctl, 'ban', ip])

    def _load_allowlist(self):
        for cand in (os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ui-allowlist.json'),
                     os.path.join(BASE, 'ui', 'ui-allowlist.json'), os.path.join(BASE, 'bin', 'ui-allowlist.json')):
            try:
                with open(cand) as f:
                    data = json.load(f)
                return frozenset(m for m in data if METHOD_RE.match(m))
            except Exception:
                continue
        return frozenset()

    def plugin(self):
        with self._plug_lock:
            if self._plugin is None:
                for cand in (os.path.join(BASE, 'ui'), os.path.dirname(os.path.abspath(__file__))):
                    if os.path.isfile(os.path.join(cand, 'sentinel_main.py')):
                        sys.path.insert(0, cand)
                        break
                import sentinel_main
                self._plugin = sentinel_main.sentinel_main()
            return self._plugin

    @staticmethod
    def msg(ok, text, **extra):
        r = {'status': bool(ok), 'msg': text}
        r.update(extra)
        return r

    def platform_ok(self):
        """Lisensi mengizinkan platform ini? Standalone bebas di semua paket sejak 20 Nov 2026; platform tak dikenal ditolak."""
        try:
            import sentinel_license as lic
            from adapters import get_panel_adapter
            nama = get_panel_adapter().get_panel_info().to_dict().get('name', 'standalone')
            return bool(lic.platform_izin(nama)[0])
        except Exception:
            return False

    # -- operasi
    def login(self, req):
        t0 = now()
        user = str(req.get('user', ''))[:64]
        ip = str(req.get('ip', ''))
        ua = str(req.get('ua', ''))[:256]
        res = self._login(req, user, ip, ua)
        # waktu respons konstan: tidak membedakan akun tak ada, sandi salah, atau grup tak diizinkan
        rest = LOGIN_MIN_SECONDS - (now() - t0)
        if rest > 0:
            time.sleep(rest)
        return res

    def _login(self, req, user, ip, ua):
        gagal = self.msg(False, 'Login gagal', code='bad_login')
        if not ip_prefix(ip):
            return gagal
        ukey = user.strip().lower()      # kunci per akun tidak bisa dihindari dengan ganti huruf besar/kecil atau spasi
        if self.lockout.locked(ukey, ip):
            audit(user, ip, 'login', 'locked')
            return self.msg(False, 'Terlalu banyak percobaan gagal, coba lagi nanti', code='locked')
        password = str(req.get('password', ''))
        ok = False
        try:
            ok = user_allowed(user, self.conf) and bool(self.auth(user, password))
        except Exception:
            ok = False
        if ok:
            sec = totp_secret(user)
            if sec:
                ok = self._check_totp(user, sec, str(req.get('otp', '')).strip())
                if not ok:
                    self.lockout.fail(ukey, ip)
                    audit(user, ip, 'login', 'bad_otp')
                    return self.msg(False, 'Login gagal', code='bad_login' if req.get('otp') else 'need_otp')
        if not ok:
            self.lockout.fail(ukey, ip)
            audit(user, ip, 'login', 'fail')
            return gagal
        self.lockout.ok(ukey, ip)
        tok = self.sessions.create(user, ip, ua)
        audit(user, ip, 'login', 'ok')
        return self.msg(True, 'ok', token=tok, user=user, max_age=SESSION_MAX)

    def _check_totp(self, user, secret, otp):
        if not re.match(r'^\d{6}$', otp):
            return False
        step = int(now() // 30)
        for s in (step - 1, step, step + 1):
            try:
                good = totp_code(secret, s)
            except Exception:
                return False
            if hmac.compare_digest(good, otp):
                with threading.Lock():
                    if self.totp_used.get(user, -1) >= s:
                        return False
                    self.totp_used[user] = s
                return True
        return False

    def session(self, req):
        s = self.sessions.get(req.get('sid'), str(req.get('ip', '')), str(req.get('ua', '')))
        if not s:
            return self.msg(False, 'Sesi tidak sah', code='no_session')
        return self.msg(True, 'ok', user=s['user'], csrf=s['csrf'], licensed=self.platform_ok())

    def logout(self, req):
        s = self.sessions.get(req.get('sid'), str(req.get('ip', '')), str(req.get('ua', '')))
        if s:
            audit(s['user'], req.get('ip', ''), 'logout', 'ok')
        self.sessions.drop(req.get('sid'))
        return self.msg(True, 'ok')

    def call(self, req):
        ip = str(req.get('ip', ''))
        s = self.sessions.get(req.get('sid'), ip, str(req.get('ua', '')))
        if not s:
            return self.msg(False, 'Akses ditolak: sesi tidak terotentikasi, silakan login ulang', code='no_session')
        csrf = str(req.get('csrf', ''))
        if not csrf or not hmac.compare_digest(csrf, s['csrf']):
            audit(s['user'], ip, 'call', 'bad_csrf')
            return self.msg(False, 'Akses ditolak: sesi panel tidak valid, muat ulang halaman lalu coba lagi', code='bad_csrf')
        origin = str(req.get('origin', '')).strip().lower()
        host = str(req.get('host', '')).strip().lower()
        if not host or not origin or origin.split('://', 1)[-1].split('/', 1)[0] != host:
            audit(s['user'], ip, 'call', 'bad_origin')
            return self.msg(False, 'Akses ditolak: permintaan berasal dari alamat situs yang berbeda dengan panel', code='bad_origin')
        method = str(req.get('method', ''))
        if not METHOD_RE.match(method) or method not in self.allowlist:
            audit(s['user'], ip, 'call %s' % method[:40], 'not_allowed')
            return self.msg(False, 'Metode tidak diizinkan', code='not_allowed')
        if method not in LICENSE_ONLY and not self.platform_ok():
            return self._upgrade()
        params = req.get('params')
        if not isinstance(params, dict):
            params = {}
        get = DictObj({str(k)[:64]: v for k, v in params.items()
                       if isinstance(v, (str, int, float, bool, list, dict, type(None)))})
        try:
            import adapters.standalone_public as public
        except Exception:
            public = None
        try:
            plug = self.plugin()
            fn = getattr(plug, method, None)
            if not callable(fn):
                return self.msg(False, 'Metode tidak diizinkan', code='not_allowed')
            if public:
                public.set_request_context(s['user'], s['csrf'], ip)
            res = fn(get)
        except Exception as e:
            audit(s['user'], ip, 'call %s' % method, 'error')
            return self.msg(False, 'Galat internal: %s' % type(e).__name__)
        finally:
            if public:
                public.clear_request_context()
        if not method.startswith('get_'):
            audit(s['user'], ip, 'call %s' % method, 'ok' if isinstance(res, dict) and res.get('status') else 'fail')
        return res

    def _upgrade(self):
        res = self.msg(False, 'Fitur ini membutuhkan paket Pro atau lebih tinggi. Klik Upgrade untuk membukanya.')
        res['upgrade'] = {'feature': 'platform_standalone', 'plan': 'pro', 'current': 'free'}
        return res

    def handle(self, req):
        op = req.get('op')
        if op == 'health':
            return self.msg(True, 'ok')
        if op == 'login':
            return self.login(req)
        if op == 'session':
            return self.session(req)
        if op == 'logout':
            return self.logout(req)
        if op == 'call':
            return self.call(req)
        return self.msg(False, 'op tidak dikenal')


class Handler(socketserver.StreamRequestHandler):
    core = None

    def handle(self):
        try:
            self.request.settimeout(300)
            line = self.rfile.readline(MAX_LINE + 1)
            if not line or len(line) > MAX_LINE:
                return
            req = json.loads(line.decode('utf-8'))
            if not isinstance(req, dict):
                return
            res = self.core.handle(req)
        except Exception:
            res = {'status': False, 'msg': 'permintaan tidak valid'}
        try:
            self.wfile.write((json.dumps(res, ensure_ascii=False, default=str) + '\n').encode('utf-8'))
        except Exception:
            pass


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 64


def serve(core, sock_path=SOCK, group='zysui'):
    d = os.path.dirname(sock_path)
    os.makedirs(d, exist_ok=True)
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass
    Handler.core = core
    old = os.umask(0o117)
    try:
        srv = Server(sock_path, Handler)
    finally:
        os.umask(old)
    try:
        os.chown(sock_path, 0, grp.getgrnam(group).gr_gid)
        os.chmod(sock_path, 0o660)
    except KeyError:
        os.chmod(sock_path, 0o600)
    srv.serve_forever()


if __name__ == '__main__':
    if os.geteuid() != 0 and not os.environ.get('ZYS_UI_TEST'):
        sys.exit('sentinel-uid harus berjalan sebagai root')
    serve(Core())
