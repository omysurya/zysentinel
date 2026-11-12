# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Pengganti modul `public` milik aaPanel untuk mode standalone (tanpa panel).

sentinel_main memakai lima fungsi dari `public`: returnMsg, M('sites'), WriteLog,
get_local_ip, dan get_csrf_sess_html_token_value. Modul ini menyediakannya dengan
bentuk keluaran yang sama, sehingga UI dan seluruh metode plugin berjalan identik
di dalam aaPanel maupun di UI standalone.

Konteks permintaan (sesi, token CSRF) diisi oleh sentinel-uid setelah login PAM,
sesi, CSRF, dan Origin lolos. Tanpa konteks, token CSRF kosong, sehingga
pemeriksaan di `_enforce_security_guard` tetap fail-closed.
"""
import os
import socket
import threading
import time

LOG_FILE = '/www/server/sentinel/log/panel.log'

_ctx = threading.local()


def set_request_context(user='', csrf='', ip=''):
    """Dipanggil sentinel-uid sebelum memanggil metode plugin (satu thread = satu permintaan)."""
    _ctx.v = {'user': user, 'csrf': csrf, 'ip': ip}


def clear_request_context():
    _ctx.v = None


def get_request_context():
    return getattr(_ctx, 'v', None)


def returnMsg(status, msg):
    return {'status': bool(status), 'msg': msg}


def get_csrf_sess_html_token_value():
    c = get_request_context()
    return (c or {}).get('csrf', '')


def WriteLog(tp, msg, *args):
    """Catatan operasi ke berkas log sentinel (pengganti log operasi panel)."""
    try:
        if args:
            msg = msg % args
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        c = get_request_context() or {}
        with open(LOG_FILE, 'a') as f:
            f.write('%s [%s] %s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), tp,
                                        c.get('user', '-'), str(msg).replace('\n', ' ')[:500]))
    except Exception:
        pass


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.0.2.1', 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


class _Query(object):
    """Subset kueri `public.M('sites').field(..).select()` yang dipakai plugin, dari vhost nyata."""

    def __init__(self, table):
        self._table = table
        self._fields = None

    def field(self, f):
        self._fields = [x.strip() for x in str(f).split(',') if x.strip()]
        return self

    def select(self):
        if self._table != 'sites':
            return []
        try:
            from adapters.panel.standalone import StandaloneAdapter
            vhosts = StandaloneAdapter().get_vhosts()
        except Exception:
            return []
        rows = []
        for v in vhosts:
            row = {'name': v.domain, 'path': v.docroot, 'status': '1'}
            if self._fields:
                row = {k: row.get(k, '') for k in self._fields}
            rows.append(row)
        return rows


def M(table):
    return _Query(table)
