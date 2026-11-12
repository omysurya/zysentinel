#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Buka port UI ZySentinel di firewall milik host (firewalld, ufw, CSF) supaya UI bisa dijangkau dari jaringan.

Firewall ZySentinel sendiri (rantai SENTINEL) sudah mengizinkan port UI, tetapi firewall bawaan host/panel (firewalld di
CyberPanel dan AlmaLinux, ufw di Ubuntu, CSF di cPanel) memfilter lebih dulu: tanpa aturan di sana, UI menjawab dari
localhost tetapi dari browser admin halaman hanya "loading" lalu kosong karena paketnya dijatuhkan.

Aturan dasar:
  * Hanya menyentuh manajer firewall yang AKTIF; yang terpasang tapi mati dilewati.
  * Idempoten dan tidak mengganggu: tidak memuat ulang firewall (tidak memutus koneksi lain), aturan permanen + runtime.
  * Hanya mencabut aturan yang kita buat sendiri (dicatat di berkas status); aturan milik admin yang sudah ada dibiarkan.

Pemakaian: hostfw.py {open|close|sync|status} [port]
  sync = open bila UI aktif (/etc/zysentinel-ui/enabled ada), close bila tidak.
Keluar 0 bila berhasil atau tidak ada manajer aktif; 1 bila ada manajer aktif yang gagal diubah.
"""
import json
import os
import re
import shutil
import subprocess
import sys

DEFAULT_PORT = int(os.environ.get('ZYS_UI_PORT', '18491'))
UI_ETC = os.environ.get('ZYS_UI_ETC', '/etc/zysentinel-ui')
STATE = os.environ.get('ZYS_HOSTFW_STATE', '/www/server/sentinel/etc/hostfw.json')
CSF_CONF = os.environ.get('ZYS_CSF_CONF', '/etc/csf/csf.conf')
COMMENT = 'ZySentinel UI'


def _run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except Exception as e:
        return 127, str(e)


def _load():
    try:
        with open(STATE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save(d):
    try:
        os.makedirs(os.path.dirname(STATE), mode=0o700, exist_ok=True)
        tmp = STATE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE)
    except OSError:
        pass


# ------------------------------------------------------------------ firewalld
def firewalld_active():
    if not shutil.which('firewall-cmd'):
        return False
    rc, out = _run(['firewall-cmd', '--state'], 15)
    return rc == 0 and 'running' in out


def _fwd_has(port, permanent):
    cmd = ['firewall-cmd'] + (['--permanent'] if permanent else []) + ['--query-port=%d/tcp' % port]
    rc, out = _run(cmd, 15)
    return rc == 0 and 'yes' in out


def firewalld_open(port):
    """Mengembalikan (ok, diubah)."""
    changed = False
    for permanent in (True, False):
        if not _fwd_has(port, permanent):
            cmd = ['firewall-cmd'] + (['--permanent'] if permanent else []) + ['--add-port=%d/tcp' % port]
            rc, _ = _run(cmd, 30)
            if rc != 0:
                return False, changed
            changed = True
    return True, changed


def firewalld_close(port):
    ok = True
    for permanent in (True, False):
        if _fwd_has(port, permanent):
            cmd = ['firewall-cmd'] + (['--permanent'] if permanent else []) + ['--remove-port=%d/tcp' % port]
            ok = _run(cmd, 30)[0] == 0 and ok
    return ok


# ------------------------------------------------------------------ ufw
def ufw_active():
    if not shutil.which('ufw'):
        return False
    rc, out = _run(['ufw', 'status'], 15)
    return rc == 0 and re.search(r'^Status:\s*active', out, re.M) is not None


def _ufw_has(port):
    rc, out = _run(['ufw', 'status'], 15)
    return rc == 0 and re.search(r'^%d(/tcp)?\s+ALLOW' % port, out, re.M) is not None


def ufw_open(port):
    if _ufw_has(port):
        return True, False
    rc, _ = _run(['ufw', 'allow', '%d/tcp' % port, 'comment', COMMENT], 30)
    return rc == 0, rc == 0


def ufw_close(port):
    if not _ufw_has(port):
        return True
    return _run(['ufw', 'delete', 'allow', '%d/tcp' % port], 30)[0] == 0


# ------------------------------------------------------------------ CSF (ConfigServer, umum di cPanel)
def csf_active():
    return bool(shutil.which('csf')) and os.path.isfile(CSF_CONF)


_CSF_RE = re.compile(r'^(TCP_IN\s*=\s*")([^"]*)(")', re.M)


def _csf_ports():
    try:
        with open(CSF_CONF) as f:
            m = _CSF_RE.search(f.read())
    except OSError:
        return None
    return [p for p in m.group(2).split(',') if p] if m else None


def _csf_write(ports):
    with open(CSF_CONF) as f:
        s = f.read()
    bak = CSF_CONF + '.zys-orig'
    if not os.path.exists(bak):
        shutil.copy2(CSF_CONF, bak)
    s = _CSF_RE.sub(lambda m: m.group(1) + ','.join(ports) + m.group(3), s, count=1)
    tmp = CSF_CONF + '.zys-tmp'
    with open(tmp, 'w') as f:
        f.write(s)
    shutil.copymode(CSF_CONF, tmp)
    os.replace(tmp, CSF_CONF)
    return _run(['csf', '-r'], 180)[0] == 0


def csf_open(port):
    ports = _csf_ports()
    if ports is None:
        return False, False
    if str(port) in ports:
        return True, False
    return _csf_write(ports + [str(port)]), True


def _csf_drop_backup():
    """Cadangan csf.conf hanya berguna selama port kita masih ada; setelah dicabut hanya menjadi berkas sisa."""
    try:
        os.remove(CSF_CONF + '.zys-orig')
    except OSError:
        pass


def csf_close(port):
    ports = _csf_ports()
    if ports is None:
        return True
    if str(port) not in ports:
        _csf_drop_backup()
        return True
    ok = _csf_write([p for p in ports if p != str(port)])
    if ok:
        _csf_drop_backup()
    return ok


MANAGERS = (('firewalld', firewalld_active, firewalld_open, firewalld_close),
            ('ufw', ufw_active, ufw_open, ufw_close),
            ('csf', csf_active, csf_open, csf_close))


def open_port(port):
    """Buka di setiap manajer aktif. Mengembalikan (jumlah_manajer_aktif, daftar_gagal)."""
    st = _load()
    aktif, gagal = 0, []
    for nama, active, op, _ in MANAGERS:
        if not active():
            continue
        aktif += 1
        ok, changed = op(port)
        if not ok:
            gagal.append(nama)
            continue
        if changed:                                   # catat hanya aturan buatan kita
            lst = st.setdefault(nama, [])
            if port not in lst:
                lst.append(port)
        print('hostfw: %s: port %d/tcp %s' % (nama, port, 'dibuka' if changed else 'sudah terbuka'))
    _save(st)
    return aktif, gagal


def close_port(port):
    """Cabut hanya aturan yang kita buat sendiri."""
    st = _load()
    gagal = []
    for nama, active, _, cl in MANAGERS:
        if port not in st.get(nama, []) or not active():
            continue
        if cl(port):
            st[nama].remove(port)
            print('hostfw: %s: port %d/tcp dicabut' % (nama, port))
        else:
            gagal.append(nama)
    _save(st)
    return gagal


def status(port):
    for nama, active, _, _ in MANAGERS:
        if active():
            print('%s: aktif, port %d %s' % (nama, port, 'tercatat dibuka oleh ZySentinel' if port in _load().get(nama, []) else 'tidak dicatat'))


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'status'
    try:
        port = int(argv[2]) if len(argv) > 2 else DEFAULT_PORT
    except ValueError:
        print('port tidak valid', file=sys.stderr)
        return 2
    if not 1 <= port <= 65535:
        print('port di luar rentang', file=sys.stderr)
        return 2
    if cmd == 'sync':
        cmd = 'open' if os.path.exists(os.path.join(UI_ETC, 'enabled')) else 'close'
    if cmd == 'open':
        aktif, gagal = open_port(port)
        if not aktif:
            print('hostfw: tidak ada firewall host yang aktif (firewalld/ufw/csf); tidak ada yang perlu dibuka')
        if gagal:
            print('hostfw: GAGAL membuka port %d di: %s (buka manual)' % (port, ', '.join(gagal)), file=sys.stderr)
        return 1 if gagal else 0
    if cmd == 'close':
        gagal = close_port(port)
        if gagal:
            print('hostfw: GAGAL mencabut port %d di: %s' % (port, ', '.join(gagal)), file=sys.stderr)
        return 1 if gagal else 0
    if cmd == 'status':
        status(port)
        return 0
    print('pakai: hostfw.py {open|close|sync|status} [port]', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
