#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""sentinel-ui: pintu HTTPS untuk UI standalone ZySentinel (berjalan sebagai akun tanpa hak `zysui`).

Tujuan defensif: hanya TLS, aset statis, batas laju per IP, header keamanan, dan batas ukuran request.
Tidak pernah memegang hak root dan tidak memutuskan apa pun: login, sesi, CSRF, allowlist metode, dan
gerbang lisensi semuanya diputuskan sentinel-uid lewat socket unix. Bila proses ini disusupi, penyerang
tetap butuh sesi sah dari login sungguhan untuk memanggil metode plugin.
"""
import hashlib
import json
import mimetypes
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

BASE = os.environ.get('ZYS_UI_BASE', '/www/server/sentinel')
SOCK = os.environ.get('ZYS_UI_SOCK', '/run/sentinel/ui.sock')
HERE = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.environ.get('ZYS_UI_DIR') or ('/usr/share/zysentinel-ui' if os.path.isdir('/usr/share/zysentinel-ui') else HERE)
# TLS dan allow.txt di luar $BASE (etc/ dikunci 0700 root oleh installer; akun zysui tidak bisa menembusnya)
ETC_UI = os.environ.get('ZYS_UI_ETC') or os.path.join(BASE, 'etc', 'ui')
PORT = int(os.environ.get('ZYS_UI_PORT', '18491'))
BIND = os.environ.get('ZYS_UI_BIND', '0.0.0.0')
COOKIE = '__Host-zys_ui'
MAX_BODY = 1 << 20
LOGIN_MAX_BODY = 4096
READ_TIMEOUT = 15
MAX_CONN = 64
RATE_LOGIN = (5, 60)      # 5 per menit per IP
RATE_API = (30, 1)        # 30 per detik per IP

# Aset yang boleh dilayani (daftar tetap; path lain = 404). Kunci = path URL, nilai = berkas di ui/ui/assets.
ASSETS = {
    '/assets/jquery.min.js': 'jquery.min.js',
    '/assets/layer/layer.js': 'layer/layer.js',
    '/assets/layer/theme/default/layer.css': 'layer/theme/default/layer.css',
    '/assets/layer/theme/default/icon.png': 'layer/theme/default/icon.png',
    '/assets/layer/theme/default/icon-ext.png': 'layer/theme/default/icon-ext.png',
    '/assets/layer/theme/default/loading-0.gif': 'layer/theme/default/loading-0.gif',
    '/assets/layer/theme/default/loading-1.gif': 'layer/theme/default/loading-1.gif',
    '/assets/layer/theme/default/loading-2.gif': 'layer/theme/default/loading-2.gif',
    '/assets/layui/layui-icon.css': 'layui/layui-icon.css',
    '/assets/layui/font/iconfont.woff2': 'layui/font/iconfont.woff2',
    '/assets/layui/font/iconfont.woff': 'layui/font/iconfont.woff',
    '/assets/layui/font/iconfont.ttf': 'layui/font/iconfont.ttf',
    '/assets/shim.js': 'shim.js',
    '/assets/login.js': 'login.js',
    '/assets/app.css': 'app.css',
    '/static/js/echarts.min.js': 'echarts.min.js',
    '/static/vite/data/world.json': 'world.json',
    '/static/img/soft_ico/ico-sentinel.png': 'ico-sentinel.png',
    '/favicon.ico': 'ico-sentinel.png',
}

_rate_lock = threading.Lock()
_rate = {}
_conn = threading.BoundedSemaphore(MAX_CONN)
_allow = None


def allowed_ip(ip):
    """Daftar IP yang diizinkan (opsional): etc/ui/allow.txt, satu IP/CIDR per baris. Kosong/tak ada = semua."""
    global _allow
    import ipaddress
    try:
        mt = os.stat(os.path.join(ETC_UI, 'allow.txt')).st_mtime
    except OSError:
        return True
    if _allow is None or _allow[0] != mt:
        nets = []
        with open(os.path.join(ETC_UI, 'allow.txt')) as f:
            for ln in f:
                ln = ln.split('#', 1)[0].strip()
                if ln:
                    try:
                        nets.append(ipaddress.ip_network(ln, strict=False))
                    except ValueError:
                        pass
        _allow = (mt, nets)
    if not _allow[1]:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _allow[1])


def rate_ok(kind, ip, limit):
    n, per = limit
    k = (kind, ip)
    t = time.time()
    with _rate_lock:
        lst = [x for x in _rate.get(k, []) if t - x < per]
        if len(lst) >= n:
            _rate[k] = lst
            return False
        lst.append(t)
        _rate[k] = lst
        if len(_rate) > 20000:
            for kk in [kk for kk, v in _rate.items() if not v or t - v[-1] > 120]:
                _rate.pop(kk, None)
    return True


def uid_call(req, timeout=300):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(SOCK)
        s.sendall((json.dumps(req) + '\n').encode('utf-8'))
        buf = b''
        while not buf.endswith(b'\n'):
            ch = s.recv(65536)
            if not ch:
                break
            buf += ch
            if len(buf) > (32 << 20):
                raise ValueError('jawaban terlalu besar')
        return json.loads(buf.decode('utf-8'))
    finally:
        s.close()


def read_asset(rel):
    for root in (os.path.join(UI_DIR, 'ui', 'assets'), os.path.join(UI_DIR, 'assets')):
        p = os.path.realpath(os.path.join(root, rel))
        if p.startswith(os.path.realpath(root) + os.sep) and os.path.isfile(p):
            with open(p, 'rb') as f:
                return f.read()
    return None


def read_ui_file(name):
    for cand in (os.path.join(UI_DIR, 'ui', name), os.path.join(UI_DIR, name)):
        if os.path.isfile(cand):
            with open(cand, 'rb') as f:
                return f.read().decode('utf-8')
    return ''


class Handler(BaseHTTPRequestHandler):
    server_version = 'zysentinel-ui'
    sys_version = ''
    protocol_version = 'HTTP/1.1'
    _consumed = False
    _body = None

    def log_message(self, fmt, *a):
        pass

    # -- pembantu
    def ip(self):
        return self.client_address[0]

    def common_headers(self, nonce=None):
        h = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Cross-Origin-Opener-Policy': 'same-origin',
            # index.html (fragmen dasbor) memakai skrip dan gaya inline serta atribut onclick; sumber lain tetap 'self' saja.
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                                       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        }
        return h

    def send(self, code, body=b'', ctype='application/json; charset=utf-8', extra=None, nostore=True):
        if isinstance(body, str):
            body = body.encode('utf-8')
        if self.command == 'POST' and not self._consumed:
            self.close_connection = True      # isi POST tidak dibaca (ditolak/404/terlalu besar): jangan pakai ulang koneksi
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        if self.close_connection:
            self.send_header('Connection', 'close')
        self.send_header('Content-Length', str(len(body)))
        for k, v in self.common_headers().items():
            self.send_header(k, v)
        if nostore:
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Pragma', 'no-cache')
        else:
            # aset: selalu divalidasi ulang (ETag). Dulu max-age=3600 membuat browser memakai login.js/css lama selama sejam
            # setelah pembaruan; kini perubahan langsung berlaku dan yang tidak berubah cukup 304.
            self.send_header('Cache-Control', 'no-cache')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def jsend(self, obj, code=200, extra=None):
        self.send(code, json.dumps(obj, ensure_ascii=False, default=str), extra=extra)

    def cookie_sid(self):
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == COOKIE:
                return v[:128]
        return ''

    def body(self, limit=MAX_BODY):
        """Isi request (dibaca sekali). None bila Content-Length tak valid/terlalu besar: isi TIDAK dibaca dan koneksi ditutup."""
        if self._consumed:
            return self._body
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = -1
        if n < 0 or n > limit:
            self._body = None
            return None
        self._body = self.rfile.read(n) if n else b''
        self._consumed = True
        return self._body

    def handle_one_request(self):
        # keep-alive: sisa isi POST yang tidak dibaca akan terbaca sebagai request berikutnya (desinkronisasi). Setiap
        # request mulai dari keadaan bersih; send() menutup koneksi bila isi POST belum dibaca.
        self._consumed = False
        self._body = None
        super().handle_one_request()

    def base_req(self, op):
        return {'op': op, 'ip': self.ip(), 'ua': self.headers.get('User-Agent', '')[:256], 'sid': self.cookie_sid()}

    def gate(self):
        if not allowed_ip(self.ip()):
            self.send(403, b'forbidden', 'text/plain')
            return False
        return True

    # -- GET
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.gate():
            return
        path = urlsplit(self.path).path
        if path == '/healthz':
            try:
                r = uid_call({'op': 'health'}, 3)
                ok = bool(r.get('status'))
            except Exception:
                ok = False
            return self.send(200 if ok else 503, 'ok' if ok else 'uid down', 'text/plain')
        if path in ASSETS:
            data = read_asset(ASSETS[path])
            if data is None:
                return self.send(404, b'not found', 'text/plain')
            ct = mimetypes.guess_type(ASSETS[path])[0] or 'application/octet-stream'
            if path.endswith('.json'):
                ct = 'application/json'
            etag = '"%s"' % hashlib.sha256(data).hexdigest()[:32]
            if self.headers.get('If-None-Match') == etag:
                return self.send(304, b'', ct, extra={'ETag': etag}, nostore=False)
            return self.send(200, data, ct, extra={'ETag': etag}, nostore=False)
        if path == '/':
            return self.page()
        self.send(404, b'not found', 'text/plain')

    def page(self):
        if not rate_ok('page', self.ip(), RATE_API):
            return self.send(429, b'too many requests', 'text/plain')
        shell = read_ui_file('shell.html')
        try:
            r = uid_call(dict(self.base_req('session')), 10)
        except Exception:
            return self.send(503, 'Layanan sentinel-uid tidak berjalan.', 'text/plain; charset=utf-8')
        if r.get('status'):
            app = read_ui_file('index.html')
            page = shell.replace('<!--ZYS:MODE-->', 'app').replace('<!--ZYS:CSRF-->', r['csrf']).replace('<!--ZYS:APP-->', app)
            page = page.replace('<!--ZYS:LICENSED-->', '1' if r.get('licensed') else '0')
        else:
            page = shell.replace('<!--ZYS:MODE-->', 'login').replace('<!--ZYS:CSRF-->', '').replace('<!--ZYS:APP-->', '')
            page = page.replace('<!--ZYS:LICENSED-->', '0')
        self.send(200, page, 'text/html; charset=utf-8')

    # -- POST
    def do_POST(self):
        if not self.gate():
            return
        u = urlsplit(self.path)
        if u.path == '/api/login':
            return self.login()
        if u.path == '/api/logout':
            return self.logout()
        if u.path == '/plugin':
            return self.plugin(parse_qs(u.query))
        self.send(404, b'not found', 'text/plain')

    def same_origin(self):
        host = (self.headers.get('Host') or '').lower()
        origin = (self.headers.get('Origin') or '').lower()
        if not origin:
            ref = (self.headers.get('Referer') or '').lower()
            origin = ref
        return bool(host and origin and origin.split('://', 1)[-1].split('/', 1)[0] == host)

    def login(self):
        if not rate_ok('login', self.ip(), RATE_LOGIN):
            return self.jsend({'status': False, 'msg': 'Terlalu banyak percobaan, coba lagi nanti', 'code': 'locked'}, 429)
        # form login kecil: isi dibatasi 4 KB (bukan 1 MB), wajib JSON, asal sama (anti login CSRF)
        raw = self.body(limit=LOGIN_MAX_BODY)
        if raw is None or not self.same_origin():
            return self.jsend({'status': False, 'msg': 'permintaan ditolak'}, 400)
        if (self.headers.get('Content-Type') or '').split(';')[0].strip().lower() != 'application/json':
            return self.jsend({'status': False, 'msg': 'permintaan ditolak'}, 415)
        try:
            d = json.loads(raw.decode('utf-8'))
        except Exception:
            return self.jsend({'status': False, 'msg': 'permintaan ditolak'}, 400)
        # bentuk dikunci: objek dengan nilai teks saja (tipe lain = daftar/objek/angka ditolak, bukan dipaksa jadi teks)
        if not isinstance(d, dict) or any(not isinstance(d.get(k, ''), str) for k in ('user', 'password', 'otp')) or set(d) - {'user', 'password', 'otp'}:
            return self.jsend({'status': False, 'msg': 'permintaan ditolak'}, 400)
        req = self.base_req('login')
        req.update({'user': d.get('user', '')[:64], 'password': d.get('password', '')[:512], 'otp': d.get('otp', '')[:8]})
        try:
            r = uid_call(req, 30)
        except Exception:
            return self.jsend({'status': False, 'msg': 'Layanan login tidak tersedia'}, 503)
        if not r.get('status'):
            return self.jsend({'status': False, 'msg': r.get('msg', 'Login gagal'), 'code': r.get('code', 'bad_login')})
        cookie = '%s=%s; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d' % (COOKIE, r['token'], int(r.get('max_age', 28800)))
        self.jsend({'status': True, 'msg': 'ok'}, extra={'Set-Cookie': cookie})

    def logout(self):
        self.body()
        if not self.same_origin():
            return self.jsend({'status': False, 'msg': 'permintaan ditolak'}, 400)
        try:
            uid_call(self.base_req('logout'), 10)
        except Exception:
            pass
        # Clear-Site-Data: browser membuang cache, cookie, dan penyimpanan origin ini (tidak ada sisa halaman/token yang bisa
        # dibuka lagi lewat tombol kembali atau cache). Cookie sesi juga dikadaluarsakan eksplisit untuk browser yang abai.
        self.jsend({'status': True, 'msg': 'ok'}, extra={
            'Set-Cookie': '%s=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT' % COOKIE,
            'Clear-Site-Data': '"cache", "cookies", "storage"'})

    def plugin(self, q):
        if not rate_ok('api', self.ip(), RATE_API):
            return self.jsend({'status': False, 'msg': 'Terlalu banyak permintaan'}, 429)
        raw = self.body()
        if raw is None:
            return self.jsend({'status': False, 'msg': 'permintaan terlalu besar'}, 413)
        method = (q.get('s') or [''])[0]
        if (q.get('name') or [''])[0] != 'sentinel' or not re.match(r'^[a-z][a-z0-9_]{1,63}$', method):
            return self.jsend({'status': False, 'msg': 'Metode tidak diizinkan'}, 400)
        params = {k: (v[0] if len(v) == 1 else v) for k, v in parse_qs(raw.decode('utf-8', 'replace'), keep_blank_values=True).items()}
        req = self.base_req('call')
        req.update({'method': method, 'params': params, 'csrf': self.headers.get('x-http-token') or self.headers.get('X-Http-Token') or '',
                    'origin': self.headers.get('Origin') or self.headers.get('Referer') or '', 'host': self.headers.get('Host') or ''})
        try:
            r = uid_call(req)
        except Exception:
            return self.jsend({'status': False, 'msg': 'Layanan sentinel-uid tidak tersedia'}, 503)
        code = 401 if isinstance(r, dict) and r.get('code') == 'no_session' else 200
        self.jsend(r, code)

    def handle(self):
        if not _conn.acquire(blocking=False):
            return
        try:
            self.request.settimeout(READ_TIMEOUT)
            super().handle()
        finally:
            _conn.release()


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # klien putus/handshake gagal/permintaan rusak itu biasa di port publik; jangan banjiri jurnal dengan traceback
        pass


def make_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
    ctx.load_cert_chain(os.path.join(ETC_UI, 'tls.crt'), os.path.join(ETC_UI, 'tls.key'))
    return ctx


def main():
    srv = QuietServer((BIND, PORT), Handler)
    # handshake di thread penangan (bukan di accept) agar klien lambat tidak menahan penerimaan koneksi lain
    srv.socket = make_context().wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    srv.serve_forever()


if __name__ == '__main__':
    main()
