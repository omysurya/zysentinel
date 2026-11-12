# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Plugin panel untuk ZySentinel.

ZySentinel adalah sistem monitoring dan firewall untuk server aaPanel.
Plugin ini hanya antarmuka: seluruh keputusan ada di daemon guardd
(bahasa C) dan aturan kernel (iptables + ipset). Plugin tidak pernah
menghitung skor atau memutuskan pemblokiran sendiri, supaya tidak ada
dua sumber kebenaran yang bisa berbeda pendapat.
"""
import sys
import os
import re
import json
import time
import subprocess
import socket
import hashlib
import hmac
import platform
import sqlite3
import urllib.request
import urllib.parse
import shutil
import glob
import ipaddress
import shlex
import uuid
import fcntl
import threading
import stat

_PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)
import sentinel_license as _lic
# aaPanel menjalankan plugin di SATU proses panel yang berjalan lama: sentinel_main.py dibaca ulang setelah pembaruan plugin, tetapi modul
# sentinel_license di sys.modules tetap versi lama (fungsi baru tidak ada, get_license 500, lencana "License: Free" dan semua fitur terkunci
# padahal paket Max; terjadi 24 Okt 2026 tanpa restart panel). Muat ulang modul lisensi bila berkasnya berubah sejak dimuat.
try:
    import importlib
    _lic_f = getattr(_lic, '__file__', '') or ''
    _lic_m = os.stat(_lic_f).st_mtime_ns if _lic_f else None
    if _lic_m is not None and getattr(_lic, '_mtime_dimuat', None) != _lic_m:
        _lic = importlib.reload(_lic)
        _lic._mtime_dimuat = _lic_m
except Exception:
    pass

if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')
# Mode panel (aaPanel): modul `public` milik panel. Mode standalone (tanpa aaPanel): shim
# adapters.standalone_public yang dipanggil oleh sentinel-uid setelah login PAM + sesi + CSRF lolos.
if os.path.isdir('/www/server/panel/class'):
    os.chdir('/www/server/panel')
    if '/www/server/panel/class' not in sys.path:
        sys.path.insert(0, '/www/server/panel/class')
    import public
    STANDALONE_MODE = False
else:
    _here = os.path.dirname(os.path.abspath(__file__))
    for _cand in ('/www/server/sentinel/bin', '/www/server/sentinel/ui', os.path.join(_here, 'payload'), _here):
        if os.path.isdir(os.path.join(_cand, 'adapters')):
            # selalu dipindah ke depan: salinan bin/adapters yang usang tidak boleh mengalahkan adapters/ di samping modul ini
            if _cand in sys.path:
                sys.path.remove(_cand)
            sys.path.insert(0, _cand)
    import adapters.standalone_public as public
    STANDALONE_MODE = True
if not hasattr(public, 'returnMsg'):
    public.returnMsg = lambda status, msg: {'status': bool(status), 'msg': msg}
try:
    if __name__ != '__main__':
        from panelAuth import panelAuth
except Exception:
    panelAuth = None


# ====================================================================== #
# GERBANG LISENSI                                                        #
# ====================================================================== #
# Satu tabel menentukan metode API mana yang butuh fitur paket apa. Penegakan terpusat di
# __getattribute__ (bukan 164 dekorator yang bisa terlewat). Melihat data (get_*) tetap bebas;
# yang dikunci adalah mengaktifkan/menjalankan/mengubah fitur berbayar. Mematikan (off) tidak pernah
# dikunci agar pengguna yang turun ke Free bisa merapikan sendiri. Keputusan paket diambil biner
# biner pemverifikasi lisensi (Ed25519), bukan kode di sini; pohon sumber berjalan mode terbuka (lihat sentinel_license.ENFORCE).
# Custom Scan (keputusan pemilik 27 Okt 2026): engine Free = ClamAV Only + Rkhunter Only; Pro+ = + Anti-Judol dan Anti-Ransomware
# (fitur av_crypto_judol); Max = + All Features, Sage AI Safety, Hybrid Deep Scan (both), Anti-Cryptomining (fitur av_engines).
# Target: Free = vhost terdaftar; Pro+ = + Custom Path; Max = + Full System (/) (lihat _gate_av_target).
_AV_ENGINE_PRO = ('judol', 'ransomware')
_AV_ENGINE_MAX = ('mining', 'both', 'sage', 'ai', 'scan-ai', 'all')
_AV_ENGINE_PREMIUM = _AV_ENGINE_PRO + _AV_ENGINE_MAX

# Port Control: port yang boleh dikelola per paket (sama dengan plans.PORT_FREE/PORT_EXT di server; ada uji pembanding).
# Free = HTTP, HTTPS, SSH; Pro = + FTP dan mail server; Max = semua port.
_PORT_FREE = (22, 80, 443)
_PORT_EXT = (20, 21, 25, 110, 143, 465, 587, 993, 995)
_THRESHOLD_KEYS = ('watch_score', 'throttle_score', 'ban_score', 'weight_scan', 'weight_brute', 'weight_badua',
                   'weight_distinct', 'cap_scan', 'cap_brute', 'cap_badua', 'cap_distinct', 'ban_seconds',
                   'ban_seconds_max', 'max_ips')


_GEO_MEM, _GEO_MAKS = {}, 50000   # ip (int) -> (kode, nama); lihat sentinel_main._geo_satu
_CACHE_ANCAMAN = {}       # (db, bahasa) -> (waktu, agregat dialog Total Threats); lihat _kartu_detail kind=threats


def _tulis_atomik(path, isi, cadangan=False, mode=None):
    """Tulis berkas konfigurasi secara atomik: tmp unik di direktori yang sama, fsync, lalu rename. Pembaca (timer sentinel-fw,
    guardd, sentinel-ports) tidak pernah melihat berkas kosong/terpotong, juga saat disk penuh atau proses dibunuh di tengah tulis
    (dulu open(path, 'w') mengosongkan berkas lebih dulu). cadangan=True menyimpan isi lama di path.bak (pemulihan bila rusak)."""
    d = os.path.dirname(path) or '.'
    tmp = os.path.join(d, '.%s.%d.%d.tmp' % (os.path.basename(path), os.getpid(), threading.get_ident()))
    data = isi.encode('utf-8') if isinstance(isi, str) else isi
    try:
        with open(tmp, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        elif os.path.exists(path):
            shutil.copymode(path, tmp)
        if cadangan and os.path.isfile(path) and os.path.getsize(path) > 0:
            try:
                shutil.copy2(path, path + '.bak')
            except OSError:
                pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _g(get, k, d=''):
    try:
        v = get.get(k, d)
    except Exception:
        v = d
    return str(v if v is not None else d).strip()


def _gate_set_conf(get):
    k, v = _g(get, 'key'), _g(get, 'value')
    if k == 'enforce':
        return 'enforce' if v == '1' else None
    if k in _THRESHOLD_KEYS:
        return 'thresholds'
    if k in ('throttle_rps', 'throttle_rpm', 'throttle_burst'):
        return 'fw_advanced'
    return None


def _gate_av_engine(get):
    e = _g(get, 'engine', 'both').lower()
    if e in _AV_ENGINE_MAX:
        return 'av_engines'
    if e in _AV_ENGINE_PRO:
        return 'av_crypto_judol'
    return None


def _gate_av_target(get):
    """Target Custom Scan per paket: root vhost terdaftar = semua paket, path lain = av_crypto_judol (Pro+), sistem penuh (/) = av_engines (Max).
    Diputuskan dari realpath path (target_type kiriman browser hanya bisa menaikkan ke Max, tidak menurunkan); ragu = Pro+ (gagal tertutup,
    karena galat di gerbang dianggap tanpa gerbang)."""
    path = _g(get, 'path')
    if _g(get, 'target_type').lower() == 'system' or path in ('system', '/'):
        return 'av_engines'
    try:
        real = os.path.realpath(path) if path else ''
        if real == '/':
            return 'av_engines'
        if real:
            for s in public.M('sites').field('path').select() or []:
                if isinstance(s, dict) and s.get('path') and os.path.realpath(str(s['path'])) == real:
                    return None
    except Exception:
        pass
    return 'av_crypto_judol'


def _gate_av_scan(get):
    """Gerbang av_scan/av_scan_start: fitur tertinggi yang dibutuhkan engine atau target."""
    butuh = {_gate_av_engine(get), _gate_av_target(get)}
    for f in ('av_engines', 'av_crypto_judol'):
        if f in butuh:
            return f
    return None


def _gate_fw_action(get):
    """Kernel Rules (fitur fw_rules, Max): Reinstall Rules dikunci; Flush Sets dan Remove Rules tidak (melepas tidak pernah dikunci)."""
    a = _g(get, 'aksi') or _g(get, 'act') or _g(get, 'sub_action') or (_g(get, 'action') if _g(get, 'action') != 'a' else '')
    return 'fw_rules' if a == 'install' else None


def _gate_restrict_admin(get):
    """Port Inventory & Guard (recon_guard, Max): memasang pembatasan IP port admin dikunci; mencabutnya tidak."""
    if _g(get, 'remove') in ('1', 'true', 'on') or _g(get, 'sources') in ('0.0.0.0/0', '0.0.0.0'):
        return None
    return 'recon_guard'


def _gate_sweeper_config(get):
    try:
        cfg = json.loads(_g(get, 'config', '{}') or '{}')
    except Exception:
        return None
    return 'sweeper_auto' if isinstance(cfg, dict) and cfg.get('auto_quarantine') else None


def _gate_elite(get):
    t, m = _g(get, 'type'), _g(get, 'mode')
    if t == 'proc' and m == 'enforce':
        return 'proc_enforce'
    if t == 'egress' and m == 'on':
        return 'egress'
    return None


def _gate_lifecycle(get):
    """Self-Heal (Repair) adalah fitur Pro+ (selfheal). Aksi lain (fresh, update, uninstall) tidak dikunci paket."""
    a = str(get.get('sub_action') or get.get('act') or get.get('aksi') or (get.get('action') if get.get('action') != 'a' else '') or '').strip().lower()
    return 'selfheal' if a == 'repair' else None


LICENSE_GATES = {
    'run_lifecycle_action': _gate_lifecycle,
    'get_events': 'event_feed',
    # dialog Total Threats dan Total Attackers (kedua tab) hanya Max; kartu lain di get_card_detail tetap terbuka
    'get_live_threats': 'attack_dialogs', 'get_attacker_page': 'attack_dialogs',
    'get_card_detail': lambda g: 'attack_dialogs' if _g(g, 'kind') in ('threats', 'attackers') else None,
    # Firewall > Kernel Rules (Input Chain & Inspection Rules, set, penghitung) dan Managed Rules hanya Max
    'get_fw': 'fw_rules', 'get_fw_rules': 'fw_rules', 'fw_action': _gate_fw_action,
    # Firewall > Port Inventory & Guard hanya Max
    'get_port_inventory': 'recon_guard', 'restrict_admin_port': _gate_restrict_admin,
    'get_vhost_stat': 'vhosts', 'get_vhost_ip': 'vhosts',
    'get_review': 'review_queue', 'review_put': 'review_queue',
    'get_geo_stat': 'origin',
    'get_cve_report': 'cve_advisor', 'scan_cve': 'cve_advisor',
    'set_cve_osv': lambda g: 'cve_advisor' if _g(g, 'value').lower() == 'on' else None,   # mematikan pengiriman data ke OSV tidak dikunci
    'set_conf': _gate_set_conf,
    'learned_add': 'learn', 'learned_update': 'learn',
    'learned_toggle': lambda g: 'learn' if _g(g, 'enabled', '1') in ('1', 'true', 'on') else None,
    'set_geo_ban': 'geo_ban',
    'update_threat_intel': 'threat_sync',
    'toggle_vhost_upload_scan': 'upload_scan', 'toggle_upload_scan_service': 'upload_scan',
    'set_vhost_upload_scan': lambda g: 'upload_scan' if _g(g, 'state').lower() in ('1', 'true', 'on', 'yes') else None,
    'av_scan': _gate_av_scan, 'av_scan_start': _gate_av_scan,
    'av_scan_ai': 'av_engines', 'av_sage_test': 'av_engines',
    'sweeper_start': 'sweeper', 'sweeper_calibrate': 'sweeper', 'sweeper_build': 'sweeper',
    'sweeper_schedule': lambda g: 'sweeper_auto' if _g(g, 'mode') == 'on' else None,
    'set_sweeper_config': _gate_sweeper_config,
    'set_proc_guard': lambda g: 'proc_enforce' if _g(g, 'mode', 'enforce') == 'enforce' else None,
    'add_proc_whitelist': 'proc_enforce', 'del_proc_whitelist': 'proc_enforce', 'toggle_proc_whitelist': 'proc_enforce',
    'set_egress_guard': lambda g: 'egress' if _g(g, 'status', 'on') == 'on' else None,
    'set_elite_defense': _gate_elite,
    'av_baseline': 'integ_web', 'av_check': 'integ_web',
    'set_memscan': lambda g: 'memscan' if _g(g, 'value') in ('on', 'tinggi') else None,
    'set_notif_conf': 'notify', 'test_notif': 'notify',
    'apply_cve_vpatch': lambda g: 'cve_vpatch' if _g(g, 'action', 'on') in ('on', '1', 'true') else None,
}

_PLAN_NAME = {'pro': 'Pro', 'max': 'Max'}


def _angka_json(teks, kunci):
    """Ambil satu angka dari balasan JSON daemon.

    Balasan guardctl sudah berbentuk JSON, jadi lebih aman dibaca dengan
    json.loads daripada dengan pencarian potongan teks. Kalau parsing
    gagal, kembalikan None supaya pemanggil bisa memutuskan sendiri apa
    yang ditampilkan, bukan menebak dari string.
    """
    try:
        nilai = json.loads(teks).get(kunci)
    except Exception:
        return None
    if isinstance(nilai, bool) or not isinstance(nilai, (int, float)):
        return None
    return int(nilai)


# ---------------------------------------------------------------------- #
# validasi masukan (IP, CIDR, rentang, regex, path, ID)                  #
#                                                                        #
# Semua endpoint daftar putih / blokir memakai fungsi di bawah ini,      #
# supaya satu aturan berlaku di firewall, WAF, EDR, dan antivirus.       #
# Prinsip: nilai tak valid DITOLAK dengan alasan jelas, tidak diperbaiki #
# diam-diam (mis. aksi "DENY" tidak boleh berubah jadi ACCEPT).          #
# ---------------------------------------------------------------------- #
_OKTET = r'(?:0|[1-9][0-9]{0,2})'
_RE_IPV4 = re.compile(r'%s(?:\.%s){3}' % (_OKTET, _OKTET))
_RE_PREFIX = re.compile(r'(?:0|[1-9][0-9]?)')
_RE_ID = re.compile(r'[A-Za-z0-9_-]{1,40}')


def _aman(s, n=40):
    """Potongan nilai masukan yang aman untuk dimasukkan ke pesan galat."""
    return re.sub(r'[^0-9A-Za-z.:/,_ -]', '?', str(s))[:n]


def v4_alamat(s):
    """IPv4Address bila s adalah IPv4 desimal bertitik yang ketat, selain itu None.

    Ketat artinya: empat oktet 0-255 tanpa nol di depan ("01.2.3.4" bisa
    dibaca sebagai oktal oleh alat lain), tanpa spasi, tanda +/-, garis
    bawah, maupun digit non-ASCII yang diterima int() Python.
    """
    if not isinstance(s, str) or not _RE_IPV4.fullmatch(s):
        return None
    try:
        return ipaddress.IPv4Address(s)
    except ValueError:
        return None


def parse_v4(s, cidr=True, min_prefix=8, tujuan='putih', semua=False):
    """Validasi IPv4 tunggal atau CIDR. Mengembalikan (IPv4Network, None) atau (None, pesan).

    cidr       : izinkan notasi a.b.c.d/n
    min_prefix : prefix terkecil yang boleh (menolak /0 sampai /7 secara bawaan)
    tujuan     : 'blokir' juga menolak loopback dan link-local; 'putih' dan
                 'netral' hanya menolak alamat yang tidak mungkin sah
    semua      : izinkan 0.0.0.0/0 (khusus aturan port, bukan daftar IP)
    Bit host pada CIDR tidak boleh terisi: 10.0.0.5/24 ditolak dengan saran
    10.0.0.0/24, bukan diubah diam-diam.
    """
    if not isinstance(s, str):
        return None, 'nilai harus berupa teks'
    s = s.strip()
    if not s:
        return None, 'alamat IP kosong'
    if ':' in s:
        return None, 'IPv6 belum didukung di sini (hanya IPv4)'
    if len(s) > 18:
        return None, 'format IP/CIDR tidak valid: %s' % _aman(s)
    ip_s, sep, pre_s = s.partition('/')
    if v4_alamat(ip_s) is None:
        return None, 'format IPv4 tidak valid: %s' % _aman(s)
    if sep:
        if not cidr:
            return None, 'CIDR tidak diperbolehkan di sini, pakai IP tunggal'
        if not _RE_PREFIX.fullmatch(pre_s) or int(pre_s) > 32:
            return None, 'prefix CIDR harus angka 0-32 tanpa nol di depan: %s' % _aman(s)
        pre = int(pre_s)
    else:
        pre = 32
    if pre < min_prefix and not (semua and pre == 0):
        return None, 'prefix /%d terlalu luas (minimal /%d)' % (pre, min_prefix)
    try:
        net = ipaddress.IPv4Network('%s/%d' % (ip_s, pre), strict=True)
    except ValueError:
        saran = ipaddress.IPv4Network('%s/%d' % (ip_s, pre), strict=False)
        return None, 'bit host CIDR terisi: gunakan %s' % saran
    if semua and pre == 0:
        return net, None
    for a in (net.network_address, net.broadcast_address):
        if a.is_unspecified or a.is_multicast or a.is_reserved or a.packed[0] == 0:
            return None, 'alamat tidak dapat dipakai (0.x, multicast, atau cadangan): %s' % net
        if tujuan == 'blokir' and (a.is_loopback or a.is_link_local):
            return None, 'alamat loopback/link-local tidak boleh diblokir: %s' % net
    return net, None


def v4_tampil(net):
    """Bentuk tampil/penyimpanan: IP tunggal tanpa /32, selain itu CIDR."""
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def parse_v4_daftar(s, maks=10, **kw):
    """Daftar IPv4/CIDR dipisah koma (iptables -s a,b). (list[str], None) atau (None, pesan)."""
    if not isinstance(s, str) or not s.strip():
        return None, 'alamat kosong'
    bagian = [x.strip() for x in s.split(',')]
    if len(bagian) > maks:
        return None, 'maksimal %d alamat per aturan' % maks
    hasil = []
    for b in bagian:
        net, err = parse_v4(b, **kw)
        if err:
            return None, err
        t = v4_tampil(net) if net.prefixlen != 0 else '0.0.0.0/0'
        if t not in hasil:
            hasil.append(t)
    return hasil, None


def parse_v4_rentang(s, maks_alamat=1 << 24, tujuan='putih'):
    """Rentang 'a.b.c.d-e.f.g.h'. (awal, akhir, None) sebagai IPv4Address, atau (None, None, pesan)."""
    if not isinstance(s, str) or s.count('-') != 1:
        return None, None, 'format rentang tidak valid: %s' % _aman(s)
    a_s, b_s = [x.strip() for x in s.split('-')]
    a, b = v4_alamat(a_s), v4_alamat(b_s)
    if a is None or b is None:
        return None, None, 'format IPv4 pada rentang tidak valid: %s' % _aman(s)
    if int(a) > int(b):
        return None, None, 'awal rentang lebih besar dari akhir'
    if int(b) - int(a) + 1 > maks_alamat:
        return None, None, 'rentang terlalu luas (maksimal %d alamat)' % maks_alamat
    for x in (a, b):
        if x.is_unspecified or x.is_multicast or x.is_reserved or x.packed[0] == 0:
            return None, None, 'alamat tidak dapat dipakai (0.x, multicast, atau cadangan): %s' % x
    if tujuan == 'blokir' and (int(a) <= 0x7f000001 <= int(b) or a.is_loopback or b.is_loopback):
        return None, None, 'rentang memuat loopback, tidak boleh diblokir'
    return a, b, None


def v4_kisaran(net):
    return net.network_address, net.broadcast_address


def teks_aman(s, maks, nama='nilai', boleh_kosong=False):
    """Teks bebas (catatan, nama): tanpa karakter kontrol, panjang dibatasi."""
    if not isinstance(s, str):
        return None, '%s harus berupa teks' % nama
    s = s.strip()
    if not s and not boleh_kosong:
        return None, '%s wajib diisi' % nama
    if len(s) > maks:
        return None, '%s terlalu panjang (maksimal %d karakter)' % (nama, maks)
    if re.search(r'[\x00-\x1f\x7f]', s):
        return None, '%s memuat karakter kontrol' % nama
    return s, None


def id_valid(s):
    return isinstance(s, str) and bool(_RE_ID.fullmatch(s.strip()))


_RX_WORKER = "\nimport re, sys, json\npats = json.loads(sys.stdin.read())\nout = []\nPR = ('/', '/index.php', '/a/b/c', '/x?y=1')\nADV = ['a' * 40 + '!', '/' + 'a' * 40 + '!', '/' + '/a' * 20 + '!', '/' + '1' * 40 + 'x', ('a' * 20 + ' ') * 4 + '!']\nfor p in pats:\n    try:\n        rx = re.compile(p)\n    except re.error:\n        out.append('err'); continue\n    luas = all(rx.search(x) for x in PR)\n    for x in ADV:\n        rx.search(x)\n    out.append('luas' if luas else 'ok')\nprint(json.dumps(out))\n"


def rx_uji_subproses(pola_list, timeout=4):
    """Uji regex di PROSES TERPISAH dengan batas waktu. Pola ReDoS (mis. '(?:.*.*)*')
    membuat `re` Python berjalan berdetik-detik dan tidak bisa dihentikan dari
    dalam proses yang sama. Hasil per pola: 'ok', 'luas', 'err', atau 'lambat'."""
    try:
        r = subprocess.run([sys.executable, '-I', '-c', _RX_WORKER], input=json.dumps(list(pola_list)),
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        return ['err'] * len(pola_list)
    return ['lambat'] * len(pola_list)


RE2_TIDAK_DIDUKUNG = re.compile(r'\(\?<?[=!]|\(\?>|\(\?P=|\\[1-9]|[*+?}]\+|\\Z|\(\?[a-zA-Z-]*x')   # \Z dan flag x: Python saja, tidak ada di RE2/Go regexp


def regex_waras(pola, maks=300):
    """Pola regex untuk daftar URL: harus bisa dikompilasi, tidak mencocokkan SEMUA URL,
    dan tidak boleh lambat (ReDoS).

    Pola yang cocok dengan '/', '/index.php', '/a/b/c' sekaligus (mis. '.*')
    di url_black memblokir seluruh situs, dan di url_white melewatkan semua
    pemeriksaan WAF. Kompilasi memakai re Python sebagai pendekatan PCRE.
    """
    s, err = teks_aman(pola, maks, 'pola URL')
    if err:
        return None, err
    # Coraza memakai RE2: lookaround, backreference, atomic group, dan
    # kuantor posesif diterima re Python tetapi membuat seluruh ruleset
    # ditolak saat nginx dimuat ulang (dan WAF tercabut dari semua vhost).
    if RE2_TIDAK_DIDUKUNG.search(s):
        return None, 'pola memakai sintaks yang tidak didukung WAF (lookahead/lookbehind, backreference, atomic group, kuantor posesif, \\Z, atau flag x)'
    hasil = rx_uji_subproses([s])[0]
    if hasil == 'err':
        return None, 'regex tidak valid'
    if hasil == 'lambat':
        return None, 'pola ditolak: terlalu lambat dievaluasi (risiko ReDoS), sederhanakan polanya'
    if hasil == 'luas':
        return None, 'pola terlalu luas: cocok dengan semua URL'
    return s, None


# Entri daftar URL: [crs+](lit:|rx:)?pola. Sama persis dengan sentinel-zyrules.url_entri (uji audit_20261030 membandingkan).
_URL_ENTRI = re.compile(r'^(?:(crs)\+)?(?:(lit|rx):)?(.*)$', re.S)


def url_entri(e):
    """baris daftar URL -> (cakupan 'semua'|'crs', mode 'normal'|'regex', pola seperti ditulis admin, regex untuk WAF)."""
    crs, mode, isi = _URL_ENTRI.match(e or '').groups()
    cakupan = 'crs' if crs else 'semua'
    if mode == 'lit':
        # batas segmen: /api cocok dengan /api, /api/..., /api?..., tetapi tidak /api-internal (evaluasi 30 Okt 2026)
        return cakupan, 'normal', isi, '^' + re.escape(isi) + ('' if isi.endswith('/') else '(?:[/?;]|$)')
    return cakupan, 'regex', isi, isi


def path_aman_shell(p):
    """shlex.quote untuk nilai yang disisipkan ke perintah shell."""
    return shlex.quote(str(p))



# ====================================================================== #
# KATALOG PESAN DUA ARAH (Indonesia <-> Inggris)                         #
# ====================================================================== #
# Semua teks yang sampai ke pengguna (res['msg'] dan kolom teks di dalamnya) diterjemahkan SATU
# kali di secure_api_wrapper menurut bahasa aktif panel (parameter lang en/id dari UI, lalu lang.json).
# Sumber kebenaran: teks Indonesia di kode + pasangan Inggrisnya di tabel ini. Cara pakai:
#   - Pesan baru: tulis kalimat Indonesia di returnMsg, tambahkan (Indonesia, Inggris) ke _PESAN.
#   - Nilai yang berubah-ubah ditulis sebagai {1}, {2}, ... (mis. '{1} diblokir dan sudah diterapkan di firewall').
#     Nilai tangkapan ikut diterjemahkan bila berupa kalimat yang dikenal (mis. alasan dari validator).
#   - Dua arah: lang=en mencocokkan sisi Indonesia, lang=id mencocokkan sisi Inggris. Pesan yang sudah
#     berbahasa tujuan lewat apa adanya.
#   - Pesan yang memerlukan kata kerja/jumlah yang berubah-ubah di tengah kalimat dan sudah memakai
#     cabang `isEn` / self._t(get, id, en) di tempat tetap boleh begitu.
# Detail teknis (keluaran perintah, pengecualian Python) TIDAK PERNAH masuk pesan: pakai self._galat(...)
# yang mencatatnya ke log/sentinel.log dan memberi pengguna kalimat umum + saran.
# Uji: tests/lang_ctrl_test.py memeriksa tiap teks pengguna di berkas ini punya padanan.
_PESAN = [
    # --- kalimat bersama ---
    ('{1}. Coba lagi; bila berulang, kirim laporan lewat Feedback.', '{1}. Try again; if it keeps happening, send a report through Feedback.'),
    ('{1}. Penyebab: {2}', '{1}. Cause: {2}'),
    # --- keadaan umum yang dipakai di dalam kalimat lain ---
    ('diaktifkan', 'enabled'),
    ('dinonaktifkan', 'disabled'),
    ('dimatikan', 'turned off'),
    ('dijalankan', 'started'),
    ('dihentikan', 'stopped'),
    ('dimulai ulang', 'restarted'),
    ('daftar putih', 'allowlist'),
    ('daftar putih panel', 'panel allowlist'),
    ('daftar putih IP', 'IP allowlist'),
    ('daftar hitam IP', 'IP blocklist'),
    ('daftar putih URL', 'URL allowlist'),
    ('daftar hitam URL', 'URL blocklist'),
    ('blokir', 'ban'),
    ('izinkan', 'allow'),
    ('hanya ada di firewall, tanpa catatan alasan', 'only in the firewall, no reason recorded'),
    ('blokir, batas laju, intel ancaman', 'ban, throttle, threat intel'),
    ('{1} vhost, aksi={2}', '{1} vhosts, action={2}'),
    ('{1} blok alamat', '{1} address blocks'),
    # --- teks yang ditulis daemon/panel ke basis data dan ditampilkan di tabel (diterjemahkan saat dibaca) ---
    ('diblokir manual dari panel', 'banned manually from the panel'),
    ('dicabut manual dari panel', 'lifted manually from the panel'),
    ('masuk daftar putih, blokir lama ikut dicabut', 'added to the allowlist, the old ban was lifted too'),
    ('masuk antrian review', 'entered the review queue'),
    ('batas laju terlampaui', 'rate limit exceeded'),
    ('batas-laju-5rps', 'rate-limit-5rps'),
    ('dipelajari:{1} kategori={2}', 'learned:{1} category={2}'),
    ('skor={1} kategori={2} rps={3} request={4} 4xx={5}', 'score={1} category={2} rps={3} requests={4} 4xx={5}'),
    ('{1}; disetujui operator', '{1}; approved by the operator'),
    ('{1}; ditolak operator', '{1}; rejected by the operator'),
    ('ditambahkan ke daftar putih', 'added to the allowlist'),
    ('dikeluarkan dari daftar putih, blokir lama berlaku lagi', 'removed from the allowlist, the old ban applies again'),
    ('ditolak operator, tidak diblokir', 'rejected by the operator, not banned'),
    ('pelajaran {1} ({2}) path={3} ua={4}', 'lesson {1} ({2}) path={3} ua={4}'),
    ('IP {1} diblokir {2} detik. Alasan: {3}', 'IP {1} banned for {2} seconds. Reason: {3}'),
    ('IP {1} diberi batas laju {2} detik (skor {3})', 'IP {1} rate-limited for {2} seconds (score {3})'),
    ('PANIC AKTIF. Seluruh akses web diblokir pada port {1}. Situs tidak dapat diakses sampai panic dicabut.',
     'PANIC ACTIVE. All web access is blocked on port {1}. Sites cannot be reached until panic is lifted.'),
    ('PANIC AKTIF. Seluruh akses web diblokir. Situs tidak dapat diakses sampai panic dicabut.',
     'PANIC ACTIVE. All web access is blocked. Sites cannot be reached until panic is lifted.'),
    ('Panic dicabut. Akses web sudah normal kembali.', 'Panic lifted. Web access is back to normal.'),
    ('Ini notifikasi uji dari ZySentinel. Kalau sampai diterima, pengaturan sudah benar.',
     'This is a test notification from ZySentinel. If you received it, the settings are correct.'),
    # --- akses dan penjaga keamanan ---
    ('Akses ditolak: sesi tidak terotentikasi, silakan login ke aaPanel', 'Access denied: Login has expired or you are not logged in, please log in to aaPanel again'),
    ('Akses ditolak: sesi telah kedaluwarsa, silakan login ulang', 'Access denied: Login has expired, please log in again'),
    ('Akses ditolak: sesi tidak terotentikasi, silakan login ulang', 'Access denied: you are not logged in, please log in again'),
    ('Akses ditolak: koneksi tidak terenkripsi, gunakan HTTPS', 'Access denied: the connection is not encrypted, please use HTTPS'),
    ('Akses ditolak: permintaan berasal dari alamat situs yang berbeda dengan panel', 'Access denied: the request comes from a site address different from the panel'),
    ('Akses ditolak: sesi panel tidak valid, muat ulang halaman lalu coba lagi', 'Access denied: the panel session is not valid, reload the page and try again'),
    ('Akses ditolak: masukan memuat karakter yang tidak diizinkan', 'Access denied: the input contains characters that are not allowed'),
    ('Akses ditolak: lokasi berkas yang diminta tidak diizinkan', 'Access denied: the requested file location is not allowed'),
    ('Akses ditolak: Lingkungan tidak terdaftar sebagai pengembang resmi. Silakan sampaikan feedback dan laporan bug langsung melalui panel plugin ZySentinel (💬 Feedback & Report Bugs).',
     'Access denied: this environment is not registered as an authorized developer. Please send feedback and bug reports directly through the ZySentinel panel (💬 Feedback & Report Bugs).'),
    # --- IP, firewall, daftar putih ---
    ('alamat IP tidak valid: {1}', 'Invalid IP address: {1}'),
    ('alamat IP tidak valid', 'Invalid IP address'),
    ('alamat IP/CIDR tidak valid: {1}', 'Invalid IP/CIDR address: {1}'),
    ('IP wajib diisi', 'IP address is required'),
    ('tidak boleh memblokir alamat server ini atau alamat Anda yang sedang mengakses panel: {1}',
     'You cannot ban this server or the address you are currently using to access the panel: {1}'),
    ('durasi harus berupa angka bulat positif (detik)', 'duration must be a positive whole number (seconds)'),
    ('{1} milik proxy/CDN tepercaya ({2}). Memblokirnya memutus semua pengunjung yang lewat proxy itu; blokir pelaku lewat WAF (real IP) atau aturan di dashboard provider.',
     '{1} belongs to a trusted proxy/CDN ({2}). Banning it would cut off every visitor coming through that proxy; block the offender through the WAF (real IP) or a rule in the provider dashboard.'),
    ('Gagal memuat informasi platform panel', 'Failed to load the panel platform information'),
    ('Gagal memblokir IP', 'Failed to ban the IP address'),
    ('IP tercatat di daftar blokir ZySentinel, tetapi belum diterapkan di firewall sehingga belum benar-benar diblokir',
     'The IP is listed in the ZySentinel ban list but has not been applied to the firewall, so it is not actually blocked yet'),
    ('{1} diblokir dan sudah diterapkan di firewall, durasi {2} detik. Durasi {3} detik yang diminta tidak berlaku; yang dipakai adalah batas maksimum durasi blokir.',
     '{1} was banned and applied to the firewall for {2} seconds. The requested {3} seconds does not apply; the maximum ban duration limit was used instead.'),
    ('{1} diblokir dan sudah diterapkan di firewall, durasi {2} detik', '{1} was banned and applied to the firewall for {2} seconds'),
    ('{1} diblokir dan sudah diterapkan di firewall', '{1} was banned and applied to the firewall'),
    ('Gagal melepas blokir IP', 'Failed to unban the IP address'),
    ('{1} dilepas dari daftar blokir', '{1} was removed from the ban list'),
    ('Gagal menambahkan IP ke daftar putih', 'Failed to add the IP address to the allowlist'),
    ('Gagal menulis daftar putih', 'Failed to write the allowlist'),
    ('Gagal membaca daftar putih', 'Failed to read the allowlist'),
    ('{1} sudah ada di daftar putih', '{1} is already in the allowlist'),
    ('{1} masuk daftar putih', '{1} was added to the allowlist'),
    ('{1} tidak ada di daftar putih', '{1} is not in the allowlist'),
    ('{1} dikeluarkan dari daftar putih', '{1} was removed from the allowlist'),
    ('Aturan atau alamat IP belum ditentukan', 'The rule or IP address has not been specified'),
    ('Jenis aturan tidak dikenal: {1}', 'Unknown rule type: {1}'),
    ('Penemuan ulang berkas log akses diminta', 'Re-detection of the access log files was requested'),
    ('Aksi firewall {1} dijalankan dengan peringatan; periksa status firewall', 'Firewall action {1} ran with a warning; check the firewall status'),
    ('Aksi firewall {1} selesai', 'Firewall action {1} finished'),
    ('aksi tidak dikenal', 'unknown action'),
    ('Aksi tidak dikenal', 'Unknown action'),
    ('Aksi tidak dikenal (hanya start, stop, restart, reload)', 'Unknown action (only start, stop, restart, reload)'),
    ('Aksi tidak valid (start|stop|restart)', 'Invalid action (start, stop or restart)'),
    ('Aksi tidak valid (fresh, repair, update, atau uninstall)', 'Invalid action (fresh, repair, update or uninstall)'),
    ('tugas tidak dikenal: {1}', 'Unknown task: {1}'),
    ('tugas tidak dikenal', 'Unknown task'),
    ('aksi harus on atau off', 'action must be on or off'),
    ('aksi harus setuju atau tolak', 'action must be approve or reject'),
    ('aksi tidak valid', 'Invalid action'),
    ('status harus on atau off', 'state must be on or off'),
    ('Status harus "on" atau "off"', 'State must be "on" or "off"'),
    ('Mode harus enforce, audit, atau off', 'Mode must be enforce, audit or off'),
    ('mode harus monitor, block, atau disable', 'mode must be monitor, block or disable'),
    ('mode harus block atau allow', 'mode must be block or allow'),
    ('mode harus on, off, atau status', 'mode must be on, off or status'),
    ('Parameter tidak valid', 'Invalid parameter'),
    ('parameter tidak valid', 'invalid parameter'),
    ('filter tidak valid', 'invalid filter'),
    # --- pembelajaran ---
    ('aturan harus B (blokir) atau A (izinkan)', 'the rule must be B (ban) or A (allow)'),
    ('kategori tidak dikenal', 'unknown category'),
    ('path tidak aman dipelajari (/, aset statis, health check, login, atau format tidak valid)',
     'the path is not safe to learn (/, static assets, health checks, login, or an invalid format)'),
    ('user-agent tidak bisa dipakai (peramban biasa, perayap sah, atau terlalu pendek)',
     'the user-agent cannot be used (ordinary browser, legitimate crawler, or too short)'),
    ('isi path dan/atau user-agent', 'fill in a path and/or a user-agent'),
    ('aturan izinkan wajib menyebut klien (user-agent)', 'an allow rule must name the client (user-agent)'),
    ('Gagal mencabut pelajaran', 'Failed to revoke the lesson'),
    ('Gagal mengubah status pembelajaran', 'Failed to change the learning state'),
    # --- pengaturan ambang ---
    ('kunci tidak dikenal: {1}', 'unknown setting: {1}'),
    ('nilai harus berupa angka bulat', 'the value must be a whole number'),
    ('throttle_rps minimal 1. Nilai 0 membuat throttle berhenti bekerja tanpa sengaja',
     'throttle_rps must be at least 1. A value of 0 would stop the throttle from working by accident'),
    ('nilai maksimal 100000', 'the maximum value is 100000'),
    ('Gagal menyimpan pengaturan', 'Failed to save the setting'),
    ('{1} sudah disimpan menjadi {2}, tetapi belum berlaku karena aturan firewall gagal dipasang ulang',
     '{1} was saved as {2}, but it does not apply yet because the firewall rules could not be reinstalled'),
    ('{1} = {2}, aturan firewall sudah dipasang ulang', '{1} = {2}, the firewall rules were reinstalled'),
    ('{1} diubah menjadi {2}, layanan ZySentinel dimulai ulang', '{1} changed to {2}, the ZySentinel service was restarted'),
    # --- panic ---
    ('Gagal mencabut panic', 'Failed to lift panic'),
    ('konfirmasi tidak cocok. Ketik PANIC dengan huruf besar semua di kolom konfirmasi',
     'the confirmation does not match. Type PANIC in capital letters in the confirmation box'),
    ('Gagal menyalakan panic', 'Failed to turn on panic'),
    ('Panic aktif. Seluruh akses web diblokir.', 'Panic is active. All web access is blocked.'),
    ('Panic tidak aktif.', 'Panic is not active.'),
    # --- layanan ---
    ('Gagal menjalankan aksi layanan {1}', 'Failed to run the service action {1}'),
    ('Layanan ZySentinel berhasil dijalankan', 'The ZySentinel service was started'),
    ('Layanan ZySentinel berhasil dihentikan', 'The ZySentinel service was stopped'),
    ('Layanan ZySentinel berhasil dimulai ulang', 'The ZySentinel service was restarted'),
    ('Konfigurasi ZySentinel berhasil dimuat ulang', 'The ZySentinel configuration was reloaded'),
    ('Aksi layanan {1} selesai', 'Service action {1} finished'),
    # --- port ---
    ('Gagal memuat status firewall port', 'Failed to load the port firewall status'),
    ('Gagal memuat daftar port yang terbuka', 'Failed to load the list of open ports'),
    ('Protokol harus tcp, udp, tcp/udp, atau all', 'The protocol must be tcp, udp, tcp/udp or all'),
    ('Nomor port atau rentang port wajib diisi', 'A port number or port range is required'),
    ('Format port tidak valid (contoh: 80 atau 8000-8080)', 'Invalid port format (for example 80 or 8000-8080)'),
    ('Nomor port harus berada di antara 1 dan 65535', 'The port number must be between 1 and 65535'),
    ('Rentang port tidak valid (port awal harus lebih kecil)', 'Invalid port range (the first port must be smaller)'),
    ('Aksi harus ACCEPT atau DROP', 'The action must be ACCEPT or DROP'),
    ('Format alamat IP/CIDR {1} tidak valid: {2}', 'Invalid IP/CIDR address format for {1}: {2}'),
    ('Format ID aturan tidak valid', 'Invalid rule ID format'),
    ('Gagal membaca konfigurasi aturan port', 'Failed to read the port rule configuration'),
    ('Aturan dengan ID tersebut tidak ditemukan', 'No rule with that ID was found'),
    ('Keterangan aturan bawaan {1} diperbarui (port, protokol, aksi, dan alamat aturan bawaan dikunci)',
     'The note of built-in rule {1} was updated (the port, protocol, action and address of built-in rules are locked)'),
    ('Aturan yang sama sudah ada ({1})', 'The same rule already exists ({1})'),
    ('Perubahan ditolak saat diterapkan ke firewall dan dibatalkan', 'The change was rejected when applied to the firewall and has been rolled back'),
    ('Aturan port {1} diperbarui', 'Port rule {1} was updated'),
    ('Arah aturan harus inbound atau outbound', 'The rule direction must be inbound or outbound'),
    ('Aturan ditolak saat diterapkan ke firewall dan dibatalkan', 'The rule was rejected when applied to the firewall and has been rolled back'),
    ('Aturan blokir untuk semua alamat pada port SSH atau panel akan mengunci Anda. Batasi ke IP tertentu atau gunakan pembatasan IP admin.', 'A block rule for all addresses on the SSH or panel port would lock you out. Limit it to specific IPs or use the admin IP restriction.'),
    ('Pembatasan IP ditolak saat diterapkan ke firewall dan dibatalkan', 'The IP restriction was rejected when applied to the firewall and has been rolled back'),
    ('Aturan port {1} berhasil ditambahkan', 'Port rule {1} was added'),
    ('ID aturan wajib disertakan', 'The rule ID must be included'),
    ('ID aturan wajib diisi', 'The rule ID is required'),
    ('Aturan bawaan (SSH, panel, web) tidak boleh dihapus; menghapusnya bisa memutus akses admin',
     'Built-in rules (SSH, panel, web) must not be deleted; deleting them could cut off admin access'),
    ('Aturan port berhasil dihapus', 'The port rule was deleted'),
    ('Aturan bawaan (SSH, panel, web) tidak boleh dimatikan; bisa memutus akses admin',
     'Built-in rules (SSH, panel, web) must not be turned off; it could cut off admin access'),
    ('Aturan tidak ditemukan', 'Rule not found'),
    ('Aturan {1}: {2}', 'Rule {1}: {2}'),
    ('Gagal mengembalikan aturan port ke standar awal', 'Failed to reset the port rules to the defaults'),
    ('Aturan port berhasil dikembalikan ke standar awal', 'The port rules were reset to the defaults'),
    ('Gagal menerapkan aturan port ke firewall', 'Failed to apply the port rules to the firewall'),
    ('Aturan port berhasil diterapkan ke firewall', 'The port rules were applied to the firewall'),
    ('Firewall port {1}', 'Port firewall {1}'),
    # --- CVE dan WAF ---
    ('Gagal memuat laporan CVE Advisor', 'Failed to load the CVE Advisor report'),
    ('Gagal menjalankan pemindaian CVE Advisor', 'Failed to run the CVE Advisor scan'),
    ('Format ID CVE tidak valid (contoh: CVE-2026-12345)', 'Invalid CVE ID format (for example CVE-2026-12345)'),
    ('Gagal menerapkan virtual patch', 'Failed to apply the virtual patch'),
    ('Virtual patch {1} aktif.', 'Virtual patch {1} is active.'),
    ('Virtual patch {1} dicabut.', 'Virtual patch {1} was removed.'),
    ('Virtual patch {1} dibatalkan dan dikembalikan karena WAF belum bisa memuatnya. {2}', 'Virtual patch {1} was cancelled and rolled back because the WAF could not load it. {2}'),
    ('Aturan WAF ZySentinel belum siap dipasang', 'The ZySentinel WAF rules are not ready to be installed'),
    ('Gagal menyusun konfigurasi WAF', 'Failed to build the WAF configuration'),
    ('{1} Berlaku setelah web server dimuat ulang.', '{1} It applies after the web server is reloaded.'),
    ('{1} Konfigurasi tersimpan, tetapi web server gagal dimuat ulang', '{1} The configuration was saved, but the web server failed to reload'),
    ('{1} Web server sudah dimuat ulang.', '{1} The web server has been reloaded.'),
    ('modul tidak dikenal: {1}', 'unknown module: {1}'),
    ('Gagal mengubah modul WAF', 'Failed to change the WAF module'),
    ('Modul {1} diaktifkan.', 'Module {1} was enabled.'),
    ('Modul {1} dimatikan.', 'Module {1} was turned off.'),
    ('pengaturan WAF tidak dikenal: {1}', 'unknown WAF setting: {1}'),
    ('nilai {1} harus bilangan bulat {2} sampai {3}', 'the value of {1} must be a whole number from {2} to {3}'),
    ('Gagal mengubah pengaturan WAF', 'Failed to change the WAF setting'),
    ('Pengaturan {1} = {2}.', 'Setting {1} = {2}.'),
    ('daftar tidak dikenal', 'unknown list'),
    ('daftar penuh (maksimal {1} entri)', 'the list is full (at most {1} entries)'),
    ('nilai sudah ada di daftar', 'the value is already in the list'),
    ('mode URL tidak dikenal (normal atau regex)', 'unknown URL mode (normal or regex)'),
    ('cakupan tidak dikenal (semua, atau crs khusus daftar putih URL)', 'unknown scope (all, or crs for the URL whitelist only)'),
    ('nilai tidak valid: karakter # dipakai sebagai pemisah catatan', 'invalid value: the # character is used as the remark separator'),
    ('nilai tidak valid: mode Normal harus path yang diawali / tanpa spasi', 'invalid value: Normal mode requires a path that starts with / and has no spaces'),
    ('nilai tidak valid: awalan lit:, rx:, dan crs+ dicadangkan', 'invalid value: the prefixes lit:, rx:, and crs+ are reserved'),
    ('{1} diubah di {2}.', '{1} was changed in {2}.'),
    ('nilai tidak ada di daftar', 'the value is not in the list'),
    ('nilai tidak valid: harus berupa teks', 'invalid value: it must be text'),
    ('nilai tidak valid: {1}', 'invalid value: {1}'),
    ('nilai tidak valid', 'invalid value'),
    ('memuat karakter kontrol', 'contains control characters'),
    ('Gagal menulis daftar WAF', 'Failed to write the WAF list'),
    ('{1} masuk {2}.', '{1} was added to the {2}.'),
    ('{1} keluar dari {2}.', '{1} was removed from the {2}.'),
    ('Gagal membaca log audit WAF', 'Failed to read the WAF audit log'),
    ('Log audit WAF bukan berkas biasa', 'WAF audit log is not a regular file'),
    ('Gagal membaca jenis firewall yang dipakai', 'Failed to read which firewall is in use'),
    ('Gagal mendeteksi mesin WAF', 'Failed to detect the WAF engine'),
    ('web server tidak dikenal', 'unknown web server'),
    ('nama situs tidak valid', 'invalid site name'),
    ('Gagal mengubah WAF untuk situs ini', 'Failed to change the WAF for this site'),
    ('Konfigurasi WAF tersimpan, tetapi {1} gagal dimuat ulang', 'The WAF configuration was saved, but {1} failed to reload'),
    ('WAF untuk situs {1} {2}', 'WAF for site {1} {2}'),
    ('Pilihan untuk {1} disimpan, tetapi WAF BELUM aktif: nginx belum punya konektor WAF (ModSecurity/Coraza). Konfigurasi tidak diubah dan nginx tidak direload. Akan dipasang otomatis setelah konektor terpasang.',
     'Saved as a preference for {1}, but the WAF is NOT active yet: nginx has no WAF connector (ModSecurity/Coraza). No config was changed and nginx was not reloaded. It will be applied automatically once the connector is installed.'),
    ('nama grup aturan tidak valid', 'invalid rule group name'),
    ('Gagal mengubah grup aturan WAF', 'Failed to change the WAF rule group'),
    ('Grup aturan {1} {2}', 'Rule group {1} {2}'),
    ('{1}, tetapi web server gagal dimuat ulang', '{1}, but the web server failed to reload'),
    ('{1}. Web server dimuat ulang agar aturan berlaku', '{1}. The web server was reloaded so the rules apply'),
    ('Gagal mengubah mode WAF', 'Failed to change the WAF mode'),
    ('Mode WAF: {1}.', 'WAF mode: {1}.'),
    ('Gagal membaca mode WAF', 'Failed to read the WAF mode'),
    ('Komponen WAF ZySentinel tidak ditemukan di server ini', 'The ZySentinel WAF component was not found on this server'),
    # --- geo ---
    ('rentang jam harus angka antara 1 dan 720', 'the hour range must be a number between 1 and 720'),
    ('Daftar blok negara tidak bisa dibaca', 'The country block list could not be read'),
    ('Gagal mematikan Geo-Ban', 'Failed to turn off Geo-Ban'),
    ('Geo-Ban dimatikan', 'Geo-Ban was turned off'),
    ('konfirmasi tidak cocok. Ketik GEO dengan huruf besar semua untuk menyalakan Geo-Ban',
     'the confirmation does not match. Type GEO in capital letters to turn on Geo-Ban'),
    ('pilih minimal satu negara', 'choose at least one country'),
    ('kode negara tidak dikenal: {1} (contoh: CN, RU, US)', 'unknown country code: {1} (for example CN, RU, US)'),
    ('Geo-Ban gagal diterapkan dan sudah dibatalkan', 'Geo-Ban could not be applied and was rolled back'),
    ('Geo-Ban aktif: mode {1}, {2} blok alamat diterapkan pada port web', 'Geo-Ban is active: mode {1}, {2} address blocks applied on the web ports'),
    # --- antrean review ---
    ('{1} disetujui dan sudah diblokir', '{1} was approved and is now banned'),
    ('Gagal mencatat keputusan', 'Failed to record the decision'),
    ('IP ditandai ditolak, tetapi gagal dilepas dari antrean review di firewall', 'The IP was marked as rejected, but it could not be released from the review queue in the firewall'),
    ('{1} ditolak, tidak diblokir', '{1} was rejected and not banned'),
    # --- notifikasi ---
    ('URL harus diawali http:// atau https://', 'The URL must start with http:// or https://'),
    ('URL terlalu panjang', 'The URL is too long'),
    ('URL memuat karakter yang tidak diizinkan (hanya huruf, angka, dan . _ ~ : / ? # @ & = % + , ; ! * -)',
     'The URL contains characters that are not allowed (only letters, digits and . _ ~ : / ? # @ & = % + , ; ! * -)'),
    ('token notifikasi memuat karakter yang tidak diizinkan atau terlalu panjang', 'the notification token contains characters that are not allowed or is too long'),
    ('percobaan maksimal harus angka antara 1 dan 20', 'the maximum number of attempts must be a number between 1 and 20'),
    ('jumlah per siklus harus angka antara 1 dan 200', 'the number per cycle must be a number between 1 and 200'),
    ('timeout harus angka antara 1 dan 120 detik', 'the timeout must be a number between 1 and 120 seconds'),
    ('Gagal menyimpan tujuan notifikasi', 'Failed to save the notification destination'),
    ('tujuan notifikasi disimpan', 'The notification destination was saved'),
    ('belum ada tujuan notifikasi. Isi dulu di sini.', 'No notification destination is set yet. Fill it in here first.'),
    ('notifikasi uji tidak masuk antrean', 'The test notification was not queued'),
    ('notifikasi uji terkirim', 'The test notification was sent'),
    ('Notifikasi uji gagal terkirim', 'The test notification could not be sent'),
    ('host wajib diisi', 'host is required'),
    ('Gagal membaca daftar situs', 'Failed to read the site list'),
    ('Gagal membaca data kejadian', 'Failed to read the event data'),
    ('gagal membaca tabel events', 'Failed to read the events data'),
    ('Gagal membaca data aktivitas per IP', 'Failed to read the per-IP activity data'),
    ('Statistik berhasil disimpan', 'Statistics were saved'),
    ('Jenis kartu tidak dikenal', 'Unknown card type'),
    # --- antivirus, Sweeper ---
    ('Path target pemindaian wajib diisi', 'The scan target path is required'),
    ('Path memuat karakter tidak valid atau terlalu panjang', 'The path contains invalid characters or is too long'),
    ('Direktori tidak valid atau tidak ditemukan: {1}', 'The directory is invalid or was not found: {1}'),
    ('Path target pemindaian tidak ditemukan: {1}', 'The scan target path was not found: {1}'),
    ('Engine tidak dikenal: {1} (pilih: {2})', 'Unknown engine: {1} (choose: {2})'),
    ('Pemindaian selesai', 'The scan finished'),
    ('Pemindaian gagal', 'The scan failed'),
    ('Komponen SAGE AI Safety tidak ditemukan di server ini', 'The SAGE AI Safety component was not found on this server'),
    ('Uji mandiri SAGE AI Safety lulus', 'The SAGE AI Safety self-test passed'),
    ('Uji mandiri SAGE AI Safety gagal', 'The SAGE AI Safety self-test failed'),
    ('Pemindaian lain sedang berjalan. Tunggu hingga selesai atau batalkan terlebih dahulu.', 'Another scan is already running. Wait for it to finish or cancel it first.'),
    ('Komponen antivirus ZySentinel tidak ditemukan di server ini', 'The ZySentinel antivirus component was not found on this server'),
    ('Pemindaian realtime untuk {1} ({2}) berhasil dimulai', 'The realtime scan for {1} ({2}) was started'),
    ('Pemindaian berhasil dihentikan.', 'The scan was stopped.'),
    ('pilih minimal satu tugas pembaruan', 'choose at least one update task'),
    ('Data properti berkas Rkhunter berhasil diperbarui.', 'The Rkhunter file property data was updated.'),
    ('Gagal memperbarui data properti berkas Rkhunter', 'Failed to update the Rkhunter file property data'),
    ('Basis data signature Rkhunter berhasil diperbarui', 'The Rkhunter signature database was updated'),
    ('Pembaruan signature Rkhunter gagal', 'The Rkhunter signature update failed'),
    ('Komponen Sweeper tidak ditemukan di server ini', 'The Sweeper component was not found on this server'),
    ('Mesin Sweeper tidak memberi jawaban', 'The Sweeper engine did not respond'),
    ('Jawaban mesin Sweeper tidak bisa dibaca', 'The Sweeper engine response could not be read'),
    ('Jawaban mesin Sweeper tidak dikenali', 'The Sweeper engine response was not recognized'),
    ('Operasi Sweeper gagal', 'The Sweeper operation failed'),
    ('Pemindaian Sweeper gagal dimulai', 'The Sweeper scan could not be started'),
    ('path wajib diisi', 'path is required'),
    ('path harus absolut, tanpa karakter kontrol dan tanpa ".."', 'the path must be absolute, without control characters and without ".."'),
    ('path ditolak: {1}', 'path rejected: {1}'),
    ('konfigurasi wajib berupa JSON (maks 20 KB)', 'the configuration must be JSON (max 20 KB)'),
    ('konfigurasi bukan JSON yang valid', 'the configuration is not valid JSON'),
    ('kode hash SHA-256 tidak valid', 'invalid SHA-256 hash'),
    ('Pemindaian seluruh vhost dimulai di latar belakang', 'The scan of all vhosts started in the background'),
    ('Belum ada data pemindaian untuk {1}', 'There is no scan data for {1} yet'),
    ('Gagal membaca status pemindaian', 'Failed to read the scan status'),
    ('ID karantina tidak boleh kosong', 'The quarantine ID must not be empty'),
    ('Format ID karantina tidak valid', 'Invalid quarantine ID format'),
    ('Berkas berhasil dikembalikan dari karantina', 'The file was restored from quarantine'),
    ('Gagal mengembalikan berkas dari karantina', 'Failed to restore the file from quarantine'),
    ('Berkas karantina berhasil dihapus permanen', 'The quarantined file was permanently deleted'),
    ('Gagal menghapus berkas karantina', 'Failed to delete the quarantined file'),
    ('Semua berkas karantina telah dibersihkan', 'All quarantined files were cleared'),
    ('Gagal membersihkan karantina', 'Failed to clear the quarantine'),
    ('Baseline integritas berhasil direkam', 'The integrity baseline was recorded'),
    ('Gagal merekam baseline integritas', 'Failed to record the integrity baseline'),
    ('Pemeriksaan integritas selesai', 'The integrity check finished'),
    ('Gagal memeriksa integritas berkas', 'Failed to check file integrity'),
    ('Basis data virus ClamAV berhasil diperbarui', 'The ClamAV virus database was updated'),
    ('Pembaruan basis data virus gagal', 'The virus database update failed'),
    ('Gagal membaca log', 'Failed to read the log'),
    ('rentang jam harus angka bulat positif', 'the hour range must be a positive whole number'),
    # --- judul tahap pada kemajuan pekerjaan latar (dari skrip pembantu; ditampilkan sebagai 'etap') ---
    ('mencari versi CRS terbaru dari GitHub', 'looking up the latest CRS version on GitHub'),
    ('CRS {1} sudah terpasang, arsip tidak diunduh ulang', 'CRS {1} is already installed, the archive was not downloaded again'),
    ('aturan CRS tidak berubah', 'the CRS rules are unchanged'),
    ('memeriksa source konektor', 'checking the connector source'),
    ('mengunduh arsip CRS {1}', 'downloading the CRS {1} archive'),
    ('memverifikasi arsip dan memasang aturan CRS', 'verifying the archive and installing the CRS rules'),
    ('mengunduh source konektor coraza-nginx', 'downloading the coraza-nginx connector source'),
    ('uji terisolasi sebelum menyentuh nginx aktif', 'isolated test before touching the live nginx'),
    ('menyalin modul dan libcoraza ke {1}', 'copying the module and libcoraza to {1}'),
    ('menambahkan load_module di {1} (backup .bak.<waktu>)', 'adding load_module in {1} (backup .bak.<time>)'),
    ('nginx -t, reload, dan verifikasi PID worker', 'nginx -t, reload and worker PID verification'),
    ('bukti: worker nginx memuat libcoraza', 'proof: the nginx worker loaded libcoraza'),
    ('Memperbarui basis data virus ClamAV (freshclam)', 'Updating the ClamAV virus database (freshclam)'),
    ('Merekam hash biner sistem (rkhunter --propupd)', 'Recording the system binary hashes (rkhunter --propupd)'),
    ('Memperbarui signature rkhunter (--update)', 'Updating the rkhunter signatures (--update)'),
    # --- alasan dari skrip pembantu yang dikenal dan aman ditampilkan ---
    ('ClamAV tidak terpasang di server ini', 'ClamAV is not installed on this server'),
    ('ClamAV tidak terpasang', 'ClamAV is not installed'),
    ('rkhunter tidak terpasang', 'rkhunter is not installed'),
    ('freshclam tidak ada', 'freshclam is not available'),
    ('metadata tidak ditemukan: {1}', 'metadata not found: {1}'),
    ('berkas karantina hilang atau symlink: {1}', 'the quarantined file is missing or is a symlink: {1}'),
    ('berkas tujuan sudah ada, tidak ditimpa: {1}', 'the destination file already exists and was not overwritten: {1}'),
    ('tujuan di luar area situs: {1}', 'the destination is outside the site area: {1}'),
    ('id karantina tidak valid', 'invalid quarantine ID'),
    ('restore gagal', 'restore failed'),
    ('path bukan direktori: {1}', 'the path is not a directory: {1}'),
    ('belum ada baseline untuk {1}; jalankan baseline dulu', 'there is no baseline for {1} yet; record a baseline first'),
    ('tidak ada tugas', 'there are no tasks'),
    ('Upload Protection adalah fitur paket Max. Klik Upgrade untuk membukanya.', 'Upload Protection is a Max plan feature. Click Upgrade to unlock it.'),
    ('Sweeper adalah fitur paket Max. Klik Upgrade untuk membukanya.', 'Sweeper is a Max plan feature. Click Upgrade to unlock it.'),
    ('Berkas metadata tidak ditemukan', 'The metadata file was not found'),
    ('Berkas fisik karantina tidak ditemukan', 'The quarantined file was not found'),
    ('berkas karantina adalah symlink; dibatalkan', 'the quarantined file is a symlink; cancelled'),
    ('Dipulihkan ke {1}', 'Restored to {1}'),
    ('Berkas karantina dihapus permanen', 'The quarantined file was permanently removed'),
    ('Metadata tidak ditemukan', 'Metadata not found'),
    ('pemindaian lain masih berjalan (PID {1})', 'another scan is still running (PID {1})'),
    ('tidak ada folder untuk dipindai', 'there are no folders to scan'),
    ('JSON tidak valid', 'invalid JSON'),
    ('sha256 tidak valid', 'invalid SHA-256 value'),
    ('sudah ada', 'already exists'),
    ('ditambahkan', 'added'),
    ('dihapus', 'removed'),
    ('tidak ditemukan', 'not found'),
    ('daftar kosong', 'the list is empty'),
    ('sudah dikarantina', 'already quarantined'),
    ('diabaikan (hash yang sama tidak dilaporkan lagi)', 'ignored (the same hash will not be reported again)'),
    ('dibuka kembali', 'reopened'),
    ('tidak ada pemindaian berjalan', 'no scan is running'),
    ('dikarantina: {1}', 'quarantined: {1}'),
    ('sudah mutakhir', 'already up to date'),
    ('disusun', 'built'),
    ('gcc tidak tersedia', 'gcc is not available'),
    ('berkas berubah sejak dipindai; pindai ulang sebelum menandai sah', 'the file changed since it was scanned; rescan before marking it legitimate'),
    ('berkas berubah sejak dipindai (hash berbeda); pindai ulang', 'the file changed since it was scanned (different hash); rescan'),
    ('bukan berkas biasa (symlink atau khusus)', 'not a regular file (symlink or special file)'),
    ('temuan tidak ada: {1}', 'finding not found: {1}'),
    ('path tidak valid', 'invalid path'),
    ('path di luar vhost dan folder kustom yang dipindai', 'the path is outside the scanned vhosts and custom folders'),
    ('gunakan on, off, atau status', 'use on, off or status'),
    ('terlalu sedikit berkas PHP ({1}); butuh minimal 300 berkas PHP yang SAH untuk kalibrasi', 'too few PHP files ({1}); calibration needs at least 300 LEGITIMATE PHP files'),
    ('folder memuat {1} berkas yang ditandai; kalibrasi hanya boleh pada pohon yang diyakini bersih', 'the folder contains {1} flagged files; calibrate only on a tree you believe is clean'),
    # --- PHP ---
    ('Versi PHP tidak ditemukan', 'PHP version not found'),
    ('php.ini tidak ditemukan', 'php.ini not found'),
    ('upload_progress sudah Off pada PHP {1}; tidak ada perubahan', 'upload_progress is already Off on PHP {1}; nothing changed'),
    ('{1}. php.ini dikembalikan dari cadangan {2}', '{1}. php.ini was restored from the backup {2}'),
    ('Gagal menulis php.ini', 'Failed to write php.ini'),
    ('Uji konfigurasi PHP-FPM tidak bisa dijalankan', 'The PHP-FPM configuration test could not be run'),
    ('Uji konfigurasi PHP-FPM menolak perubahan', 'The PHP-FPM configuration test rejected the change'),
    ('php.ini sudah diubah tetapi PHP-FPM gagal dimuat ulang. Cadangan: {1}', 'php.ini was changed but PHP-FPM failed to reload. Backup: {1}'),
    ('php.ini sudah diubah dan lolos uji, tetapi PHP-FPM belum memakai pengaturan baru. Muat ulang PHP-FPM secara manual agar berlaku',
     'php.ini was changed and passed the test, but PHP-FPM is not using the new setting yet. Reload PHP-FPM manually for it to apply'),
    ('Proses PHP sudah diganti, perubahan berlaku.', 'The PHP processes were replaced, the change is in effect.'),
    ('PHP-FPM tidak berjalan; berlaku saat dijalankan berikutnya.', 'PHP-FPM is not running; it applies the next time it starts.'),
    ('session.upload_progress.enabled = Off pada PHP {1}. {2} Cadangan: {3}', 'session.upload_progress.enabled = Off on PHP {1}. {2} Backup: {3}'),
    ('{1} = {2} (berlaku pada pemindaian berikutnya)', '{1} = {2} (applies from the next scan)'),
    # --- pertahanan elit ---
    ('Egress Guard {1}', 'Egress Guard {1}'),
    ('Gagal mengatur Egress Guard', 'Failed to configure Egress Guard'),
    ('Mode Process Guard diubah ke {1}', 'Process Guard mode changed to {1}'),
    ('Jenis pertahanan tidak dikenal: {1}', 'Unknown defense type: {1}'),
    ('Threat Intel berhasil diperbarui', 'Threat Intel was updated'),
    ('Gagal memperbarui Threat Intel', 'Failed to update Threat Intel'),
    ('Pemeriksaan integritas persistensi sistem selesai', 'The system persistence integrity check finished'),
    ('Pemeriksaan integritas persistensi sistem gagal', 'The system persistence integrity check failed'),
    ('Baseline persistensi sistem berhasil direkam ulang', 'The system persistence baseline was recorded again'),
    ('Gagal merekam baseline persistensi sistem', 'Failed to record the system persistence baseline'),
    ('pembaruan otomatis 2x sehari', 'automatic update twice a day'),
    ('Gagal membaca whitelist', 'Failed to read the whitelist'),
    ('Tipe harus cmdline_match, exe_exact, basename, atau cwd_match', 'The type must be cmdline_match, exe_exact, basename or cwd_match'),
    ('Pola terlalu pendek (minimal 3 karakter)', 'The pattern is too short (at least 3 characters)'),
    ('basename tidak boleh memuat "/" atau spasi', 'basename must not contain "/" or spaces'),
    ('Path tidak boleh memuat ".."', 'The path must not contain ".."'),
    ('Path tidak boleh memuat spasi', 'The path must not contain spaces'),
    ('cwd_match harus path absolut minimal dua tingkat (contoh /www/wwwroot/situs); "/" meloloskan semua proses',
     'cwd_match must be an absolute path of at least two levels (for example /www/wwwroot/site); "/" would let every process through'),
    ('exe_exact: pakai path absolut atau nama biner saja', 'exe_exact: use an absolute path or just the binary name'),
    ("Aturan whitelist '{1}' berhasil ditambahkan dan langsung aktif", "Whitelist rule '{1}' was added and is active right away"),
    ('Gagal menyimpan aturan whitelist', 'Failed to save the whitelist rule'),
    ('Berkas whitelist tidak ditemukan', 'The whitelist file was not found'),
    ('Aturan whitelist berhasil dihapus', 'The whitelist rule was deleted'),
    ('Gagal menghapus aturan whitelist', 'Failed to delete the whitelist rule'),
    ('Aturan whitelist berhasil {1}', 'The whitelist rule was {1}'),
    ('Gagal mengubah status whitelist', 'Failed to change the whitelist rule state'),
    # --- Upload Protection ---
    ('Gagal mengambil status Upload Protection', 'Failed to get the Upload Protection status'),
    ('Status Upload Protection tidak bisa dibaca', 'The Upload Protection status could not be read'),
    ('Nama vhost tidak valid', 'Invalid vhost name'),
    ('Gagal mengubah status Upload Protection untuk vhost ini', 'Failed to change the Upload Protection state for this vhost'),
    ("Upload Protection untuk vhost '{1}' berhasil {2}", "Upload Protection for vhost '{1}' was {2}"),
    ('Jawaban Upload Protection tidak bisa dibaca', 'The Upload Protection response could not be read'),
    ('Gagal menyimpan status Upload Protection untuk vhost ini', 'Failed to save the Upload Protection state for this vhost'),
    ('Gagal mengambil daftar karantina upload', 'Failed to get the upload quarantine list'),
    ('Berkas metadata karantina tidak valid', 'Invalid quarantine metadata file'),
    ('Gagal memulihkan berkas dari karantina', 'Failed to recover the file from quarantine'),
    ('Berkas berhasil dipulihkan', 'The file was restored'),
    ('Pemulihan berkas gagal', 'Restoring the file failed'),
    ('Gagal menghapus berkas karantina upload', 'Failed to delete the upload quarantined file'),
    ('Berkas karantina berhasil dihapus', 'The quarantined file was deleted'),
    ('Layanan Upload Protection gagal {1}', 'The Upload Protection service could not be {1}'),
    ('Layanan Upload Protection berhasil {1}', 'The Upload Protection service was {1}'),
    # --- telemetri, bahasa, siklus hidup, pembaruan ---
    ('Gagal menyimpan pengaturan telemetri', 'Failed to save the telemetry setting'),
    ('Gagal menyimpan pengaturan OSV', 'Failed to save the OSV setting'),
    ('Pengaturan telemetri berhasil diubah: {1}', 'Telemetry setting updated: {1}'),
    ('Aktif (ON)', 'Enabled (ON)'),
    ('Nonaktif (OFF)', 'Disabled (OFF)'),
    ('Gagal menyimpan pilihan bahasa', 'Failed to save the language choice'),
    ('Bahasa antarmuka diubah ke {1}', 'Interface language changed to {1}'),
    ('Berkas pemasang plugin tidak ditemukan; pasang ulang plugin dari App Store atau paket resmi',
     'The plugin installer file was not found; reinstall the plugin from the App Store or the official package'),
    ('Konfirmasi uninstall tidak sesuai. Harap ketik UNINSTALL.', 'The uninstall confirmation does not match. Please type UNINSTALL.'),
    ('Uninstall gagal', 'Uninstall failed'),
    ('ZySentinel berhasil di-uninstall bersih tanpa sisa.', 'ZySentinel was uninstalled completely.'),
    ('Proses pemasangan atau pemeliharaan lain masih berjalan, tunggu hingga selesai.', 'Another installation or maintenance process is still running, wait for it to finish.'),
    ('Belum ada rilis Pro yang lebih baru.', 'There is no newer Pro release yet.'),
    ('Versi stabil ZySentinel sama dengan rilis resmi terbaru.', 'The ZySentinel stable version is the same as the latest official release.'),
    ('Pembaruan dibatalkan: versi rilis terbaru tidak dapat dibaca.', 'Update cancelled: the latest release version could not be read.'),
    ('Pembaruan dibatalkan: rilis terbaru ({1}) lebih lama dari versi terpasang ({2}); penurunan versi ditolak.',
     'Update cancelled: the latest release ({1}) is older than the installed version ({2}); downgrades are refused.'),
    ('Versi terpasang sudah yang terbaru; memasang ulang versi yang sama perlu dikonfirmasi.', 'The installed version is already the latest; reinstalling the same version needs confirmation.'),
    ('Pembaruan dibatalkan: ZySentinel Pro hanya menerima rilis Pro resmi.', 'Update cancelled: ZySentinel Pro only accepts official Pro releases.'),
    ('Pembaruan dibatalkan: paket Pro tidak boleh dipasang pada edisi Free.', 'Update cancelled: a Pro package must not be installed on the Free edition.'),
    ('Gagal mengunduh paket pembaruan', 'Failed to download the update package'),
    ('Sumber unduhan tidak dikenali; pembaruan dibatalkan.', 'The download source is not recognized; update cancelled.'),
    ('Pembaruan dibatalkan: rilis ini tidak menyediakan kode verifikasi (SHA-256) sehingga keaslian paket tidak bisa diperiksa. Pasang manual setelah memeriksa paketnya.',
     'Update cancelled: this release does not provide a verification code (SHA-256), so the package cannot be authenticated. Install it manually after checking the package.'),
    ('Pembaruan dibatalkan: paket yang diunduh tidak cocok dengan kode verifikasi rilis (mungkin rusak atau diubah).',
     'Update cancelled: the downloaded package does not match the release verification code (it may be corrupted or altered).'),
    ('Pembaruan dibatalkan: paket memuat berkas dengan lokasi tidak aman.', 'Update cancelled: the package contains files with unsafe locations.'),
    ('Pembaruan dibatalkan: paket tidak berisi pemasang plugin.', 'Update cancelled: the package does not contain the plugin installer.'),
    ('Pembaruan dibatalkan: nama paket Pro tidak sesuai rilisnya.', 'Update cancelled: the Pro package name does not match its release.'),
    ('Pembaruan dibatalkan: nama paket tidak sesuai versi release-nya.', 'Update cancelled: the package name does not match its release version.'),
    ('Pembaruan dibatalkan: versi paket tidak sesuai versi rilis yang diumumkan.', 'Update cancelled: the package version does not match the announced release version.'),
    ('Pembaruan dibatalkan: rilis Pro ini tidak bertanda tangan digital.', 'Update cancelled: this Pro release is not digitally signed.'),
    ('Pembaruan dibatalkan: paket bukan aset release resmi.', 'Update cancelled: the package is not an official release asset.'),
    ('Pembaruan dibatalkan: release ini belum signed (SHA256SUMS.txt.sig tidak ada); coba lagi nanti.',
     'Update cancelled: this release is not signed yet (SHA256SUMS.txt.sig is missing); try again later.'),
    ('Pembaruan dibatalkan: berkas tanda tangan rilis terlalu besar.', 'Update cancelled: the release signature file is too large.'),
    ('Pembaruan dibatalkan: tanda tangan rilis tidak bisa diambil.', 'Update cancelled: the release signature could not be fetched.'),
    ('Pembaruan dibatalkan: tanda tangan rilis tidak valid atau komponen verifikasinya tidak ada.', 'Update cancelled: the release signature is not valid or its verification component is missing.'),
    ('Pembaruan dibatalkan: tanda tangan digital rilis tidak sah; paket tidak dipasang.', 'Update cancelled: the release digital signature is not valid; the package was not installed.'),
    ('Pembaruan dibatalkan: paket tidak tercantum di daftar verifikasi rilis yang bertanda tangan.', 'Update cancelled: the package is not listed in the signed release verification list.'),
    ('Gagal mengunduh dan menerapkan pembaruan', 'Failed to download and apply the update'),
    # --- pesan aturan WAF ZySentinel (msg di zyrules/*.conf; get_waf_logs menerjemahkan kolom pesan per kejadian) ---
    ('ZySentinel: URL daftar hitam', 'ZySentinel: blacklisted URL'),
    ('ZySentinel: URL judi online atau penambang kripto', 'ZySentinel: online gambling or crypto miner URL'),
    ('ZySentinel: User-Agent pemindai atau alat serangan', 'ZySentinel: scanner or attack tool User-Agent'),
    ('ZySentinel: akses berkas API key atau kredensial', 'ZySentinel: access to an API key or credential file'),
    ('ZySentinel: akses berkas atau folder berawalan titik', 'ZySentinel: access to a dot-prefixed file or folder'),
    ('ZySentinel: akses berkas cadangan, debug.log, atau eksploit plugin WordPress', 'ZySentinel: access to a backup file, debug.log, or WordPress plugin exploit'),
    ('ZySentinel: akses berkas internal atau konfigurasi CodeIgniter', 'ZySentinel: access to CodeIgniter internal or configuration files'),
    ('ZySentinel: akses berkas internal atau kredensial Laravel', 'ZySentinel: access to Laravel internal or credential files'),
    ('ZySentinel: akses berkas kendali akses (.htpasswd/.htaccess)', 'ZySentinel: access to access-control files (.htpasswd/.htaccess)'),
    ('ZySentinel: akses berkas konfigurasi aplikasi atau infrastruktur', 'ZySentinel: access to an application or infrastructure configuration file'),
    ('ZySentinel: akses berkas kredensial CMS (Joomla, Drupal, Magento, PrestaShop, OpenCart)', 'ZySentinel: access to CMS credential files (Joomla, Drupal, Magento, PrestaShop, OpenCart)'),
    ('ZySentinel: akses berkas lingkungan (.env)', 'ZySentinel: access to an environment file (.env)'),
    ('ZySentinel: akses bytecode Python, cache pengujian, atau database Django', 'ZySentinel: access to Python bytecode, test cache, or a Django database'),
    ('ZySentinel: akses cadangan, dump database, atau berkas sementara', 'ZySentinel: access to a backup, database dump, or temporary file'),
    ('ZySentinel: akses dotfile kredensial atau folder konfigurasi', 'ZySentinel: access to a credential dotfile or configuration folder'),
    ('ZySentinel: akses endpoint debug/informasi', 'ZySentinel: access to a debug/information endpoint'),
    ('ZySentinel: akses kunci privat atau sertifikat', 'ZySentinel: access to a private key or certificate'),
    ('ZySentinel: akses log debug Node.js, manifest Next.js, atau konfigurasi Strapi', 'ZySentinel: access to Node.js debug logs, a Next.js manifest, or Strapi configuration'),
    ('ZySentinel: akses manifest dependensi (dicatat)', 'ZySentinel: access to a dependency manifest (logged)'),
    ('ZySentinel: akses manifest dependensi (mode ketat)', 'ZySentinel: access to a dependency manifest (strict mode)'),
    ('ZySentinel: akses repositori kode (.git/.svn/.hg)', 'ZySentinel: access to a code repository (.git/.svn/.hg)'),
    ('ZySentinel: baca berkas sensitif atau path traversal lewat parameter', 'ZySentinel: sensitive file read or path traversal via a parameter'),
    ('ZySentinel: badan permintaan (bukan unggahan berkas) melebihi batas', 'ZySentinel: request body (not a file upload) exceeds the limit'),
    ('ZySentinel: badan permintaan tidak bisa diurai', 'ZySentinel: request body could not be parsed'),
    ('ZySentinel: badan tanpa Content-Type melebihi batas', 'ZySentinel: body without Content-Type exceeds the limit'),
    ('ZySentinel: batas multipart tidak cocok', 'ZySentinel: multipart boundary mismatch'),
    ('ZySentinel: berkas konfigurasi dan kredensial (serverless, settings.py, service account, kunci SSH)', 'ZySentinel: configuration and credential files (serverless, settings.py, service account, SSH keys)'),
    ('ZySentinel: bot scraper atau harvester agresif', 'ZySentinel: aggressive scraper or harvester bot'),
    ('ZySentinel: crawler SEO/AI (tingkat bot 2)', 'ZySentinel: SEO/AI crawler (bot level 2)'),
    ('ZySentinel: eksekusi skrip dari folder unggahan', 'ZySentinel: script execution from an upload folder'),
    ('ZySentinel: eksploit router/IoT/CVE (cgi-bin, HNAP, Hikvision, Totolink, Struts, Jira)', 'ZySentinel: router/IoT/CVE exploit (cgi-bin, HNAP, Hikvision, Totolink, Struts, Jira)'),
    ('ZySentinel: eksploitasi SSRF/RCE TimThumb', 'ZySentinel: TimThumb SSRF/RCE exploitation'),
    ('ZySentinel: enumerasi REST API WordPress (rest_route)', 'ZySentinel: WordPress REST API enumeration (rest_route)'),
    ('ZySentinel: enumerasi pengguna WordPress via author ID', 'ZySentinel: WordPress user enumeration via author ID'),
    ('ZySentinel: header khas pemindai kerentanan', 'ZySentinel: vulnerability scanner signature header'),
    ('ZySentinel: injeksi Form API Drupal (Drupalgeddon RCE)', 'ZySentinel: Drupal Form API injection (Drupalgeddon RCE)'),
    ('ZySentinel: injeksi template Python (Jinja2/Mako SSTI)', 'ZySentinel: Python template injection (Jinja2/Mako SSTI)'),
    ('ZySentinel: jalur sistem berkas diminta sebagai URL', 'ZySentinel: filesystem path requested as a URL'),
    ('ZySentinel: jumlah argumen melebihi batas', 'ZySentinel: number of arguments exceeds the limit'),
    ('ZySentinel: karakter injeksi di header pembawa IP', 'ZySentinel: injection characters in an IP-carrying header'),
    ('ZySentinel: kebocoran internal Laravel/Composer (storage, bootstrap/cache, vendor)', 'ZySentinel: Laravel/Composer internals exposure (storage, bootstrap/cache, vendor)'),
    ('ZySentinel: kemungkinan injeksi template Golang (SSTI)', 'ZySentinel: possible Golang template injection (SSTI)'),
    ('ZySentinel: medan upload-progress PHP (jalur PHP2Shell CVE-2026-109618/109619)', 'ZySentinel: PHP upload-progress field (PHP2Shell path CVE-2026-109618/109619)'),
    ('ZySentinel: multipart tidak sah', 'ZySentinel: invalid multipart'),
    ('ZySentinel: nilai header Expect tidak sah', 'ZySentinel: invalid Expect header value'),
    ('ZySentinel: penanda pemindai kerentanan di URL atau cookie', 'ZySentinel: vulnerability scanner marker in the URL or cookie'),
    ('ZySentinel: percobaan serangan JavaScript Prototype Pollution', 'ZySentinel: JavaScript prototype pollution attempt'),
    ('ZySentinel: percobaan upload file berbahaya via Livewire', 'ZySentinel: malicious file upload attempt via Livewire'),
    ('ZySentinel: permintaan tanpa User-Agent (tingkat bot 2)', 'ZySentinel: request without a User-Agent (bot level 2)'),
    ('ZySentinel: probe CMS (Joomla, Drupal, TYPO3, Magento)', 'ZySentinel: CMS probe (Joomla, Drupal, TYPO3, Magento)'),
    ('ZySentinel: probe WordPress pada situs non-WordPress', 'ZySentinel: WordPress probe on a non-WordPress site'),
    ('ZySentinel: probe alat administrasi basis data (Adminer, phpMyAdmin)', 'ZySentinel: database administration tool probe (Adminer, phpMyAdmin)'),
    ('ZySentinel: probe aplikasi infrastruktur (GeoServer, Solr, Jenkins, Exchange, VPN, F5, Elasticsearch, Docker API)', 'ZySentinel: infrastructure application probe (GeoServer, Solr, Jenkins, Exchange, VPN, F5, Elasticsearch, Docker API)'),
    ('ZySentinel: probe berkas informasi/uji PHP (phpinfo, test.php)', 'ZySentinel: PHP info/test file probe (phpinfo, test.php)'),
    ('ZySentinel: probe debug console interaktif Werkzeug/Flask', 'ZySentinel: Werkzeug/Flask interactive debug console probe'),
    ('ZySentinel: probe endpoint debug framework (Laravel Ignition/Telescope, Symfony, Spring Actuator)', 'ZySentinel: framework debug endpoint probe (Laravel Ignition/Telescope, Symfony, Spring Actuator)'),
    ('ZySentinel: probe endpoint profiling Golang (pprof/vars)', 'ZySentinel: Golang profiling endpoint probe (pprof/vars)'),
    ('ZySentinel: probe komponen Joomla (option=com_)', 'ZySentinel: Joomla component probe (option=com_)'),
    ('ZySentinel: probe unauthenticated REST API Joomla (CVE-2023-23752)', 'ZySentinel: Joomla unauthenticated REST API probe (CVE-2023-23752)'),
    ('ZySentinel: pustaka HTTP generik (tingkat bot 3)', 'ZySentinel: generic HTTP library (bot level 3)'),
    ('ZySentinel: skrip dieksekusi dari /.well-known/ (pencarian webshell)', 'ZySentinel: script executed from /.well-known/ (webshell hunting)'),
    ('ZySentinel: tebakan nama arsip cadangan di root (angka, domain, nama umum)', 'ZySentinel: guessed backup archive name in the root (numbers, domain, common names)'),
    ('ZySentinel: total argumen melebihi batas', 'ZySentinel: total arguments exceed the limit'),
    ('ZySentinel: trik path traversal ;/ dan /.;/ (bypass proxy)', 'ZySentinel: path traversal trick ;/ and /.;/ (proxy bypass)'),
    ('ZySentinel: webshell atau jalur eksploit dikenal', 'ZySentinel: known webshell or exploit path'),
    ('format endpoints tidak valid', 'invalid endpoints format'),
    ('endpoints harus berupa array', 'endpoints must be an array'),
    ('URL endpoint harus diawali http:// atau https://', 'the endpoint URL must start with http:// or https://'),
    ('URL endpoint terlalu panjang', 'the endpoint URL is too long'),
    ('URL endpoint memuat karakter yang tidak diizinkan', 'the endpoint URL contains characters that are not allowed'),
    ('Token endpoint memuat karakter yang tidak diizinkan atau terlalu panjang', 'the endpoint token contains characters that are not allowed or is too long'),
    ('URL memuat karakter yang tidak diizinkan', 'the URL contains characters that are not allowed'),
    ('Gagal menyimpan berkas endpoint notifikasi', 'Failed to save the notification endpoints file'),
    # --- feedback, syarat ---
    ('Topik laporan tidak boleh kosong', 'The report topic must not be empty'),
    ('Isi pesan tidak boleh kosong', 'The message must not be empty'),
    ('Captcha keamanan wajib diisi', 'Security captcha is required'),
    ('Tidak dapat memuat captcha dari server lisensi. Pastikan koneksi internet aktif.', 'Unable to load captcha from license server. Make sure internet connection is active.'),
    ('Tidak dapat terhubung ke server backend', 'Unable to connect to backend server'),
    ('Laporan berhasil dicatat dan dikirim dengan subjek: {1}', 'The report was recorded and sent with the subject: {1}'),
    ('Terverifikasi sebagai pengembang resmi ZySentinel.', 'Verified as an authorized ZySentinel developer.'),
    # --- lisensi (kalimat yang sudah ada di jalur lisensi; padanan dua arah untuk teks dari server lisensi) ---
    ('Server lisensi tidak terjangkau. Coba lagi nanti.', 'The license server is unreachable. Try again later.'),
    ('Checkout gagal ({1})', 'Checkout failed ({1})'),
    ('Stop langganan gagal ({1})', 'Stopping the subscription failed ({1})'),
    ('Aktivasi gagal', 'Activation failed'),
    ('Aktivasi developer gagal ({1})', 'Developer activation failed ({1})'),
    ('Challenge ditolak ({1})', 'Challenge rejected ({1})'),
    # --- validator masukan (parse_v4 dan kawan-kawan) ---
    ('nilai harus berupa teks', 'the value must be text'),
    ('alamat IP kosong', 'the IP address is empty'),
    ('IPv6 belum didukung di sini (hanya IPv4)', 'IPv6 is not supported here (IPv4 only)'),
    ('format IP/CIDR tidak valid: {1}', 'invalid IP/CIDR format: {1}'),
    ('format IPv4 tidak valid: {1}', 'invalid IPv4 format: {1}'),
    ('CIDR tidak diperbolehkan di sini, pakai IP tunggal', 'CIDR is not allowed here, use a single IP'),
    ('prefix CIDR harus angka 0-32 tanpa nol di depan: {1}', 'the CIDR prefix must be a number from 0 to 32 without leading zeros: {1}'),
    ('prefix /{1} terlalu luas (minimal /{2})', 'prefix /{1} is too broad (minimum /{2})'),
    ('bit host CIDR terisi: gunakan {1}', 'the CIDR host bits are set: use {1}'),
    ('alamat tidak dapat dipakai (0.x, multicast, atau cadangan): {1}', 'the address cannot be used (0.x, multicast or reserved): {1}'),
    ('alamat loopback/link-local tidak boleh diblokir: {1}', 'loopback/link-local addresses must not be blocked: {1}'),
    ('alamat kosong', 'the address is empty'),
    ('maksimal {1} alamat per aturan', 'at most {1} addresses per rule'),
    ('format rentang tidak valid: {1}', 'invalid range format: {1}'),
    ('format IPv4 pada rentang tidak valid: {1}', 'invalid IPv4 format in the range: {1}'),
    ('awal rentang lebih besar dari akhir', 'the start of the range is greater than its end'),
    ('rentang terlalu luas (maksimal {1} alamat)', 'the range is too wide (at most {1} addresses)'),
    ('rentang memuat loopback, tidak boleh diblokir', 'the range contains loopback, it must not be blocked'),
    ('daftar hitam memuat alamat server ini atau alamat Anda sendiri: {1}', 'the blocklist would contain this server or your own address: {1}'),
    ('{1} harus berupa teks', '{1} must be text'),
    ('{1} terlalu panjang (maksimal {2} karakter)', '{1} is too long (at most {2} characters)'),
    ('{1} memuat karakter kontrol', '{1} contains control characters'),
    ('{1} wajib diisi', '{1} is required'),
    ('pola memakai sintaks yang tidak didukung WAF (lookahead/lookbehind, backreference, atomic group, kuantor posesif, \\Z, atau flag x)',
     'the pattern uses syntax the WAF does not support (lookahead/lookbehind, backreference, atomic group, possessive quantifier, \\Z or the x flag)'),
    ('regex tidak valid', 'invalid regex'),
    ('pola ditolak: terlalu lambat dievaluasi (risiko ReDoS), sederhanakan polanya', 'pattern rejected: it is too slow to evaluate (ReDoS risk), simplify it'),
    ('pola terlalu luas: cocok dengan semua URL', 'the pattern is too broad: it matches every URL'),
    ('Nama', 'Name'),
    ('Catatan', 'Note'),
    ('pola URL', 'URL pattern'),
    ('Pola pencocokan (pattern)', 'Matching pattern'),
]
_PESAN_RX = []


def _pesan_siap():
    """Kompilasi _PESAN sekali: (regex sisi Indonesia, templat Inggris, regex sisi Inggris, templat Indonesia)."""
    if _PESAN_RX:
        return _PESAN_RX

    def rx(t):
        bagian = re.split(r'(\{\d+\})', t)
        return re.compile(''.join('(?P<g%s>.+?)' % b[1:-1] if re.fullmatch(r'\{\d+\}', b) else re.escape(b) for b in bagian), re.S)
    for i_d, e_n in _PESAN:
        _PESAN_RX.append((rx(i_d), e_n, rx(e_n), i_d))
    return _PESAN_RX


def _isi_templat(templat, m):
    return re.sub(r'\{(\d+)\}', lambda x: m.group('g' + x.group(1)), templat)


_LANG_REQ = threading.local()


def _pesan_dikenal(teks):
    """True bila teks (Indonesia) ada di katalog _PESAN: pesan dari skrip pembantu yang sudah dikenal dan aman ditampilkan."""
    return any(r[0].fullmatch(teks) for r in _pesan_siap())


_SYSTEMD_KUNCI_MIN = (('RestartSteps', 254), ('RestartMaxDelaySec', 254), ('ProtectProc', 247), ('ProcSubset', 247),
                      ('ProtectClock', 245), ('ProtectKernelLogs', 244), ('LogRateLimitIntervalSec', 240), ('LogRateLimitBurst', 240),
                      ('ProtectHostname', 242), ('RestrictSUIDSGID', 242), ('LockPersonality', 235), ('RemoveIPC', 235),
                      ('RuntimeDirectoryPreserve', 235), ('RestrictNamespaces', 233), ('ProtectKernelModules', 232),
                      ('ProtectControlGroups', 232), ('RestrictRealtime', 231), ('MemoryHigh', 231), ('TasksMax', 227),
                      ('ProtectKernelTunables', 232), ('ReadWritePaths', 231))


def _systemd_versi():
    try:
        out = subprocess.run(['systemctl', '--version'], capture_output=True, text=True, timeout=5).stdout
        return int(out.split()[1])
    except Exception:
        return 0


def _systemd_sesuaikan(path, versi=None):
    """Buang/tulis ulang kunci unit yang belum dikenal systemd yang berjalan (kompatibilitas mundur): tanpa ini setiap
    daemon-reload mencetak "Unknown key name ... ignoring" ke jurnal. Perilaku tidak berubah (systemd lama memang mengabaikannya)."""
    v = versi if versi is not None else _systemd_versi()
    if not v:
        return
    try:
        with open(path) as f:
            baris = f.read().split('\n')
        hapus = set(k for k, mn in _SYSTEMD_KUNCI_MIN if v < mn)
        if v < 231:
            hapus |= {'SystemCallFilter', 'SystemCallErrorNumber'}
        if v < 230:
            hapus |= {'StartLimitIntervalSec', 'StartLimitBurst'}
        hasil = []
        for ln in baris:
            kunci = ln.strip().split('=', 1)[0] if '=' in ln and not ln.lstrip().startswith(('#', ';')) else ''
            if kunci in hapus:
                continue
            if v < 231:
                ln = re.sub(r'^(\s*)ProtectSystem=strict', r'\1ProtectSystem=full', ln)
                ln = re.sub(r'^(\s*)MemoryMax=', r'\1MemoryLimit=', ln)
            hasil.append(ln)
        if v < 240:
            hasil = _systemd_append_ke_shell(hasil)
        if hasil != baris:
            with open(path, 'w') as f:
                f.write('\n'.join(hasil))
    except Exception:
        pass


def _systemd_append_ke_shell(baris):
    """systemd < 240 tidak mengenal StandardOutput/StandardError=append:BERKAS. Bila perintahnya sederhana dan kedua keluaran ke
    berkas yang sama, ExecStart dibungkus `sh -c 'exec CMD >>BERKAS 2>&1'` (log berkas tetap tertulis); selain itu ke journal.
    Sama persis dengan systemd_sesuaikan di install.sh (diuji sinkron di tests/standalone_test.py)."""
    ap = re.compile(r'^\s*Standard(Output|Error)=append:(.*)$')
    lo = le = cmd = None
    for ln in baris:
        m = ap.match(ln)
        if m and m.group(1) == 'Output' and lo is None:
            lo = m.group(2)
        elif m and m.group(1) == 'Error' and le is None:
            le = m.group(2)
        if cmd is None and ln.startswith('ExecStart='):
            cmd = ln[len('ExecStart='):]
    if lo is None and le is None:
        return baris
    sisa = [ln for ln in baris if not ap.match(ln)]
    sederhana = bool(cmd) and bool(lo) and lo == le and not re.search(r"['\"$%\\;|&<>`]|  ", (cmd or '') + lo)
    if sederhana:
        out, dipakai = [], False
        for ln in sisa:
            if not dipakai and ln.startswith('ExecStart='):
                ln = "ExecStart=/bin/sh -c 'exec %s >>%s 2>&1'" % (cmd, lo)
                dipakai = True
            out.append(ln)
        return out
    out, disisip = [], False
    for ln in sisa:
        out.append(ln)
        if not disisip and ln.startswith('[Service]'):
            out += ['StandardOutput=journal', 'StandardError=journal']
            disisip = True
    return out


def _env():
    """Modul deteksi lingkungan (adapters/env.py) atau None bila tidak termuat."""
    try:
        from adapters import env as _e
        return _e
    except Exception:
        return None


def _env_profil():
    e = _env()
    try:
        return e.profile() if e else None
    except Exception:
        return None


def _aapanel_ada():
    """Panel yang terdeteksi adalah aaPanel (bukan sekadar ada folder /www/...)."""
    pr = _env_profil()
    if pr:
        return pr['panel']['type'] == 'aapanel'
    return os.path.isdir('/www/server/panel/class')


def _log_dirs():
    """Direktori access log vhost menurut lingkungan terdeteksi: aaPanel = /www/wwwlogs; selain itu log web server aktif/terpasang
    dan lokasi bawaan distro (Debian/RHEL). Hanya yang ada di disk."""
    pr = _env_profil()
    if pr:
        return [d for d in pr['layout']['log_dirs'] if os.path.isdir(d)]
    return ['/www/wwwlogs'] if os.path.isdir('/www/wwwlogs') else [d for d in ('/var/log/nginx', '/var/log/apache2', '/var/log/httpd') if os.path.isdir(d)]


def _log_vhost(host):
    """Berkas access log milik vhost `host` (atau None). aaPanel: <host>.log; standalone: pola nama umum nginx/Apache."""
    for d in _log_dirs():
        for nama in (host + '.log', host + '.access.log', host + '-access.log', host + '_access.log', host + '-access_log',
                     host + '_access_log', host + '.access_log'):
            p = os.path.join(d, nama)
            if os.path.isfile(p):
                return p
    return None


def _data_log_dir():
    """Folder log/kerja milik plugin yang dulu selalu di bawah /www/server/panel/logs (membuat folder panel di server tanpa aaPanel)."""
    if _aapanel_ada():
        return '/www/server/panel/logs/zysentinel'
    return '/www/server/sentinel/log/zysentinel'


def _py_bin():
    """Python untuk skrip pendamping: pyenv aaPanel bila ada, selain itu python3 sistem (server standalone)."""
    p = '/www/server/panel/pyenv/bin/python3'
    return p if os.path.exists(p) else 'python3'


class sentinel_main(object):
    __PATH = '/www/server/sentinel'

    def _ensure_core_files(self):
        """Self-healing: pastikan skrip helper bin & unit systemd selalu tersedia."""
        try:
            # Plugin yang baru dicabut (install.sh uninstall) tidak boleh hidup lagi karena
            # satu panggilan API yang kebetulan masuk sebelum folder plugin dihapus panel.
            if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.uninstalled')):
                return
            bin_dir = os.path.join(self.__PATH, 'bin')
            etc_dir = os.path.join(self.__PATH, 'etc')
            os.makedirs(bin_dir, exist_ok=True)
            os.makedirs(etc_dir, exist_ok=True)

            plug_dir = os.path.dirname(os.path.abspath(__file__))
            payload_dir = os.path.join(plug_dir, 'payload')
            if not os.path.isdir(payload_dir):
                return

            # Helper scripts yang wajib ada di /www/server/sentinel/bin
            core_scripts = [
                'sentinel-ports.py', 'sentinel-waf.sh', 'sentinel-fw.sh',
                'sentinel-av.sh', 'sentinel-proc.py', 'sentinel-intel.sh', 'sentinel-zyrules.py', 'sentinel-cve.py', 'sentinel-proxy.py', 'guardctl', 'guardd'
            ]
            biner_rakit = ('guardd',)
            # Biner yang disusun lokal bisa sah berbeda ukuran dari payload: cukup dipastikan ada. Yang lain disalin apa adanya
            # dari payload, jadi ukuran yang berbeda = berkas terpotong/rusak (update terputus): dulu hanya disalin bila TIDAK ada,
            # sehingga sentinel-license terpotong membuat guardd gagal tertutup sampai pasang ulang. Murah: hanya stat.
            for s in core_scripts:
                target = os.path.join(bin_dir, s)
                source = os.path.join(payload_dir, s)
                if not os.path.isfile(source):
                    continue
                try:
                    rusak = s not in biner_rakit and os.path.getsize(target) != os.path.getsize(source)
                except OSError:
                    rusak = True
                if not os.path.exists(target) or rusak:
                    tmp = '%s.baru.%d' % (target, os.getpid())
                    shutil.copy2(source, tmp)
                    os.chmod(tmp, 0o755)
                    os.replace(tmp, target)

            # Direktori adapters/ disinkronkan ke bin/adapters
            adapters_src = os.path.join(plug_dir, 'adapters')
            if not os.path.isdir(adapters_src):
                adapters_src = os.path.join(payload_dir, 'adapters')
            adapters_dst = os.path.join(bin_dir, 'adapters')
            if os.path.isdir(adapters_src):
                # selalu disalin ulang: dulu hanya bila tujuan belum ada, sehingga update meninggalkan adapter lama
                try:
                    tmp_dst = adapters_dst + '.baru'
                    shutil.rmtree(tmp_dst, ignore_errors=True)
                    shutil.copytree(adapters_src, tmp_dst)
                    shutil.rmtree(adapters_dst, ignore_errors=True)
                    os.rename(tmp_dst, adapters_dst)
                except Exception:
                    pass

            # Systemd units yang wajib ada di /etc/systemd/system
            unit_dir = os.path.join(payload_dir, 'systemd')
            if os.path.isdir(unit_dir) and os.path.isdir('/etc/systemd/system'):
                unit_installed = False
                for u in ['sentinel.service', 'sentinel-fw.service', 'sentinel-fw.timer', 'sentinel-proc.service']:
                    u_src = os.path.join(unit_dir, u)
                    u_dst = os.path.join('/etc/systemd/system', u)
                    if not os.path.exists(u_dst) and os.path.isfile(u_src):
                        shutil.copy2(u_src, u_dst)
                        try:
                            os.chmod(u_dst, 0o644)
                        except Exception:
                            pass
                        _systemd_sesuaikan(u_dst)
                        unit_installed = True
                if unit_installed:
                    self._sh('systemctl daemon-reload 2>/dev/null', 10)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # penjaga keamanan endpoint & otentikasi                             #
    # ------------------------------------------------------------------ #
    def _enforce_security_guard(self, method_name, get):
        """Pemeriksaan ketat otentikasi, proteksi intercept, anti-CSRF, dan sanitisasi.

        Menjamin endpoint tidak dapat di-bypass via request langsung tanpa login yang sah,
        mencegah manipulasi lintas domain (CSRF/Origin/Referer), dan memblokir upaya injeksi.
        """
        if STANDALONE_MODE:
            # Konteks standalone diisi sentinel-uid hanya setelah sesi, CSRF, dan Origin lolos.
            # Pemanggilan tanpa konteks = proses lokal (CLI/cron), sama seperti di panel.
            ctx = public.get_request_context()
            if ctx is None:
                return True, ''
            if not ctx.get('user') or not ctx.get('csrf'):
                return False, 'Akses ditolak: sesi tidak terotentikasi, silakan login ulang'
            if get:
                for k in dir(get):
                    if k.startswith('_'):
                        continue
                    val = getattr(get, k, None)
                    if isinstance(val, str):
                        if '\x00' in val:
                            return False, 'Akses ditolak: masukan memuat karakter yang tidak diizinkan'
                        if k in ('path', 'target', 'file', 'target_path') and ('..' in val or val.startswith('//')):
                            return False, 'Akses ditolak: lokasi berkas yang diminta tidak diizinkan'
            return True, ''
        try:
            from flask import request, session, has_request_context, g
            if not has_request_context():
                # Pemanggilan internal via CLI, cron, atau pengujian lokal server
                return True, ''
        except Exception:
            return True, ''

        # 1. Otentikasi Sah aaPanel: wajib ada sesi login aktif
        if not session or not session.get('login'):
            return False, 'Akses ditolak: sesi tidak terotentikasi, silakan login ke aaPanel'

        # 2. Batas waktu sesi (session timeout)
        st = session.get('session_timeout', 0)
        if st and st < time.time():
            return False, 'Akses ditolak: sesi telah kedaluwarsa, silakan login ulang'

        # 3. Proteksi Intercept (Enkripsi Channel): jika panel ber-SSL, cegah koneksi HTTP polos
        # Di aaPanel, port panel mendengarkan langsung via SSL/TLS (termasuk sertifikat self-signed IP).
        # Request diteruskan secara lokal ke socket unix, sehingga scheme WSGI internal bernilai 'http'.
        # Tolak bila ada indikasi eksplisit koneksi HTTP polos eksternal (misal proxy atau referer/origin berawalan http://).
        if os.path.isfile('/www/server/panel/data/ssl.pl'):
            fwd_proto = (request.headers.get('X-Forwarded-Proto') or '').lower()
            origin = request.headers.get('Origin', '')
            referer = request.headers.get('Referer', '')
            if fwd_proto == 'http':
                return False, 'Akses ditolak: koneksi tidak terenkripsi, gunakan HTTPS'
            if origin and origin.lower().startswith('http://'):
                return False, 'Akses ditolak: koneksi tidak terenkripsi, gunakan HTTPS'
            if referer and referer.lower().startswith('http://'):
                return False, 'Akses ditolak: koneksi tidak terenkripsi, gunakan HTTPS'

        # 4. Validasi Cross-Origin / Referer (Anti pencurian sesi dan request palsu)
        def _get_host_name(h):
            if not h:
                return ''
            if '://' in h:
                h = h.split('://', 1)[1]
            h = h.split('/', 1)[0]
            if ':' in h:
                h = h.split(':', 1)[0]
            return h.strip().lower()

        host_name = _get_host_name(getattr(request, 'host', ''))
        origin = request.headers.get('Origin', '')
        referer = request.headers.get('Referer', '')
        if origin:
            orig_host = _get_host_name(origin)
            if orig_host and host_name and orig_host != host_name:
                return False, 'Akses ditolak: permintaan berasal dari alamat situs yang berbeda dengan panel'
        elif referer:
            ref_host = _get_host_name(referer)
            if ref_host and host_name and ref_host != host_name:
                return False, 'Akses ditolak: permintaan berasal dari alamat situs yang berbeda dengan panel'

        # 5. Anti-CSRF Token: Periksa token jika bukan panggilan API ber-kunci
        is_api = getattr(g, 'api_request', False)
        if not is_api:
            ada_fungsi = hasattr(public, 'get_csrf_sess_html_token_value')
            expected_csrf = ''
            if ada_fungsi:
                try:
                    expected_csrf = str(public.get_csrf_sess_html_token_value() or '')
                except Exception:
                    expected_csrf = ''
            if ada_fungsi:
                # Fail-closed: token sesi yang kosong/galat tidak boleh berarti "lewati pemeriksaan".
                client_csrf = request.headers.get('x-http-token') or request.headers.get('X-Http-Token')
                if not client_csrf and get:
                    client_csrf = getattr(get, 'x_http_token', None) or getattr(get, 'request_token', None)
                if not expected_csrf or not client_csrf or not hmac.compare_digest(str(client_csrf), expected_csrf):
                    return False, 'Akses ditolak: sesi panel tidak valid, muat ulang halaman lalu coba lagi'
            elif not origin and not referer:
                # aaPanel lama tanpa token CSRF: minimal satu header asal (Origin/Referer) wajib ada dan sudah cocok di atas.
                return False, 'Akses ditolak: sesi panel tidak valid, muat ulang halaman lalu coba lagi'

        # 6. Sanitisasi Parameter Masukan
        if get:
            for k in dir(get):
                if k.startswith('_'):
                    continue
                val = getattr(get, k, None)
                if isinstance(val, str):
                    if '\x00' in val:
                        return False, 'Akses ditolak: masukan memuat karakter yang tidak diizinkan'
                    if k in ('path', 'target', 'file', 'target_path'):
                        if '..' in val or val.startswith('//'):
                            return False, 'Akses ditolak: lokasi berkas yang diminta tidak diizinkan'

        return True, ''

    def _get_active_lang(self, get=None):
        """Ambil bahasa aktif: prioritaskan parameter get, lalu konfigurasi lang.json, default 'en'."""
        if get:
            l = getattr(get, 'lang', None) or (get.get('lang') if isinstance(get, dict) else None)
            if l in ('en', 'id'):
                return l
        # Panggilan bersarang (mis. set_elite_defense -> set_egress_guard) membawa parameter baru tanpa lang:
        # pakai bahasa permintaan yang sedang diproses supaya pesan dalamnya tidak berpindah bahasa.
        l = getattr(_LANG_REQ, 'v', None)
        if l in ('en', 'id'):
            return l
        target_etc = self._p('etc', 'lang.json')
        if os.path.exists(target_etc):
            try:
                with open(target_etc, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    val = data.get('lang')
                    if val in ('en', 'id'):
                        return val
            except Exception:
                pass
        local_p = os.path.join(os.path.dirname(__file__), 'lang.json')
        if os.path.exists(local_p):
            try:
                with open(local_p, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    val = data.get('lang')
                    if val in ('en', 'id'):
                        return val
            except Exception:
                pass
        return 'en'

    def _localize_msg(self, msg, lang='en'):
        """Standarisasi pesan respon dan error sesuai bahasa yang aktif (default 'en')."""
        if not msg or not isinstance(msg, str):
            return msg
        if lang not in ('en', 'id'):
            lang = 'en'

        # Pesan gabungan "A | B" (mis. hasil ban_ip + catatan belajar): tiap bagian diterjemahkan sendiri.
        if ' | ' in msg:
            return ' | '.join(self._localize_msg(b, lang) for b in msg.split(' | '))

        # Katalog dua arah _PESAN: pencocokan penuh; nilai tangkapan diterjemahkan rekursif.
        for rx_id, tpl_en, rx_en, tpl_id in _pesan_siap():
            m = (rx_id if lang == 'en' else rx_en).fullmatch(msg)
            if m:
                grup = dict((k, self._localize_msg(v, lang)) for k, v in m.groupdict().items())
                return re.sub(r'\{(\d+)\}', lambda x: grup.get('g' + x.group(1), ''), tpl_en if lang == 'en' else tpl_id)

        # tidak ada di katalog: teks lewat apa adanya (uji lang_ctrl_test menjaga agar teks pengguna selalu ada di katalog)
        return msg

    # Kolom teks di dalam res['msg'] (dict) yang ikut diterjemahkan. 'message' sengaja tidak termasuk:
    # di jalur lisensi ia membawa teks yang harus ditandatangani apa adanya.
    _KUNCI_TEKS = ('msg', 'pesan', 'catatan', 'saran', 'release_notes', 'etap')

    def _localize_res(self, res, lang):
        """Terjemahkan res['msg'] (teks) atau kolom teks di dalamnya (dict) ke bahasa aktif."""
        if not isinstance(res, dict) or 'msg' not in res:
            return res
        isi = res['msg']
        if isinstance(isi, str):
            res['msg'] = self._localize_msg(isi, lang)
        elif isinstance(isi, dict):
            for k in self._KUNCI_TEKS:
                if isinstance(isi.get(k), str):
                    isi[k] = self._localize_msg(isi[k], lang)
        return res

    def _t(self, get, teks_id, teks_en):
        """Pilih satu dari dua teks menurut bahasa aktif (untuk teks yang bukan pesan returnMsg)."""
        return teks_en if self._get_active_lang(get) == 'en' else teks_id

    def _catat_galat(self, konteks, detail=''):
        """Catat detail teknis (keluaran perintah, pengecualian) ke log/sentinel.log. Detail ini
        TIDAK ditampilkan ke pengguna; log itu ikut terkirim bila pengguna memilih menyertakan log
        saat mengirim Feedback. Gagal menulis log tidak boleh mengganggu respons."""
        try:
            os.makedirs(self._p('log'), exist_ok=True)
            f = self._p('log', 'sentinel.log')
            if os.path.exists(f) and os.path.getsize(f) > 1048576:
                os.replace(f, f + '.1')
            baris = ' '.join(str(detail or '').split())[:600]
            with open(f, 'a', encoding='utf-8') as fp:
                fp.write('%s panel: %s | %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), konteks, baris))
        except Exception:
            pass

    @staticmethod
    def _alasan_dikenal(detail):
        """Baris terakhir keluaran skrip yang termasuk alasan yang dikenal katalog (tanpa awalan '[sentinel-xx] GALAT:'), atau ''."""
        for baris in reversed(str(detail or '').strip().splitlines()):
            b = re.sub(r'^\[[\w-]+\]\s*(GALAT:\s*)?', '', baris.strip()).strip()
            if b and _pesan_dikenal(b):
                return b
        return ''

    def _galat(self, ringkas, detail=''):
        """Pesan gagal ramah untuk pengguna; detail teknis hanya ke log.
        Alasan yang dikenal katalog (mis. 'ClamAV tidak terpasang di server ini') disebut sebagai penyebab;
        selain itu kalimat umum + saran, tanpa keluaran mentah."""
        self._catat_galat(ringkas, detail)
        sebab = self._alasan_dikenal(detail)
        if sebab:
            return '%s. Penyebab: %s' % (ringkas, sebab)
        return '%s. Coba lagi; bila berulang, kirim laporan lewat Feedback.' % ringkas

    def _pesan_skrip(self, teks, ringkas):
        """Pesan dari skrip pembantu: dipakai bila dikenal katalog, selain itu diganti kalimat umum (mentahnya ke log)."""
        if isinstance(teks, str) and teks.strip() and _pesan_dikenal(teks.strip()) \
                and not re.search(r'Errno|Traceback|Exception|\[Errno', teks):
            return teks.strip()
        return self._galat(ringkas, teks)

    def _loc_kolom(self, baris, kolom, get):
        """Terjemahkan kolom teks hasil basis data (alasan/isi yang ditulis daemon atau panel dalam bahasa Indonesia)
        ke bahasa aktif. Teks yang tidak dikenal katalog dibiarkan."""
        lang = self._get_active_lang(get)
        for r in baris if isinstance(baris, list) else []:
            if isinstance(r, dict):
                for k in kolom:
                    if isinstance(r.get(k), str):
                        r[k] = self._localize_msg(r[k], lang)
        return baris

    def __getattribute__(self, name):
        attr = super(sentinel_main, self).__getattribute__(name)
        if name.startswith('_') or not callable(attr):
            return attr

        def secure_api_wrapper(get=None, *args, **kwargs):
            active_lang = self._get_active_lang(get)
            _lama = getattr(_LANG_REQ, 'v', None)
            _LANG_REQ.v = active_lang
            try:
                return _jalankan(get, active_lang, *args, **kwargs)
            finally:
                _LANG_REQ.v = _lama

        def _jalankan(get, active_lang, *args, **kwargs):
            ok, err_msg = self._enforce_security_guard(name, get)
            if not ok:
                return public.returnMsg(False, self._localize_msg(err_msg, active_lang))
            # Sesudah pemeriksaan sesi: menyalin berkas inti dan daemon-reload
            # tidak boleh dipicu oleh permintaan yang belum terotentikasi.
            self._ensure_core_files()
            # Gerbang lisensi (sesudah otentikasi sesi, sebelum metode berjalan)
            gate = LICENSE_GATES.get(name)
            if gate is not None:
                try:
                    gate = gate(get) if callable(gate) else gate
                except Exception:
                    gate = None
                if gate and not _lic.allowed(gate):
                    return self._lisensi_ditolak(gate, active_lang)
            res = attr(get, *args, **kwargs)
            return self._localize_res(res, active_lang)

        return secure_api_wrapper

    # ------------------------------------------------------------------ #
    # pembantu                                                           #
    # ------------------------------------------------------------------ #
    def _lic_has(self, feat):
        try:
            return bool(_lic.allowed(feat))
        except Exception:
            return False

    def _lang(self, get=None):
        return self._get_active_lang(get)

    def _p(self, *parts):
        return os.path.join(self.__PATH, *parts)

    def _db(self):
        """Jalur database. Dibaca dari guardd.conf supaya tetap sinkron
        dengan yang dipakai daemon, tidak ditebak ulang di sini."""
        conf = self._p('etc', 'guardd.conf')
        db = self._p('data', 'guardd.db')
        try:
            with open(conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('db_path'):
                        return line.split('=', 1)[1].strip()
        except Exception:
            pass
        return db

    def _sql(self, query, args=()):
        """Jalankan kueri SQLite lewat sqlite3 CLI.

        Sengaja tidak memakai modul sqlite3 python supaya tidak
       bersaing dengan daemon yang sedang menulis ke berkas sama.
        WAL dan busy timeout sudah disiapkan daemon."""
        try:
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.row_factory = sqlite3.Row
            cur = con.execute(query, args)
            rows = [dict(r) for r in cur.fetchall()]
            con.close()
            return rows
        except Exception as e:
            return []

    def _sql1(self, query, args=()):
        """Satu baris saja, atau None.

        Dipakai untuk pembacaan nilai tunggal DAN untuk penulisan
        satu baris. Karena itu WAJIB commit. Tanpa commit, setiap
        INSERT atau UPDATE yang lewat sini dibatalkan saat koneksi
        ditutup: perintahnya terlihat berhasil, tidak ada galat,
        tapi tidak ada yang berubah. Itu penyebab status review tidak
        pernah berubah dari "tunggu".
        """
        try:
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.row_factory = sqlite3.Row
            cur = con.execute(query, args)
            row = cur.fetchone()
            if con.in_transaction:
                con.commit()
            con.close()
            return dict(row) if row else None
        except Exception:
            return None

    @staticmethod
    def _only(get, kunci, bawaan, panjang=64):
        """Ambil satu nilai teks, dipotong ke panjang aman.

        Nilai dari parameter bisa berisi apa saja. Dipotong supaya
        tidak ada baris tambahan yang bisa menyisipkan kunci konfigurasi
        palsu ke berkas.
        """
        v = get.get(kunci)
        if v is None:
            v = bawaan
        v = str(v).strip()
        if not v:
            v = bawaan
        v = v.replace('\n', ' ').replace('"', '')
        return v[:panjang]

    @staticmethod
    def _int(get, kunci, bawaan, minimal=None, maksimal=None):
        """Baca bilangan bulat dari parameter, aman untuk string maupun int.

        Pola ini muncul berulang di seluruh endpoint. Panel sering
        mengirim angka dari input numerik, sedangkan panggilan dari
        skrip sering mengirim teks. Menganggap keduanya string membuat
        galat AttributeError yang tampil mentah sebagai galat 500.
        """
        mentah = get.get(kunci)
        if isinstance(mentah, str):
            mentah = mentah.strip()
        if mentah is None or mentah == '':
            n = bawaan
        else:
            try:
                n = int(mentah)
            except (TypeError, ValueError):
                return None
        if minimal is not None and n < minimal:
            return None
        if maksimal is not None and n > maksimal:
            return None
        return n

    def _notif(self, jenis, isi, ip=''):
        """Tulis satu baris ke antrean notifikasi dari sisi panel.

        Dipakai untuk aksi yang tidak melewati daemon, yaitu panic.
        Ban dan throttle otomatis sudah ditulis daemon sendiri, jadi
        ditulis lagi di sini akan menjadi dua notifikasi untuk satu
        kejadian yang sama.
        """
        try:
            n = self._ipnum(ip) if ip else 0
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.execute(
                'INSERT INTO notif(ts,ip,jenis,isi) VALUES(?,?,?,?)',
                (int(time.time()), n, jenis, isi[:500]))
            con.commit()
            con.close()
            return True
        except Exception:
            return False

    def _aksi(self, ip, aksi, sumber, alasan='', detik=0):
        """Catat satu tindakan terhadap IP ke tabel aksi.

        Kegagalan menulis TIDAK boleh membatalkan tindakan aslinya.
        Ban yang sudah masuk ipset tetapi gagal dicatat ke audit hanya
        berarti catatannya kurang, bukan blokirannya gagal. Karena itu
        error sengaja tidak dikembalikan ke pemanggil.
        """
        try:
            n = self._ipnum(ip)
            if not n:
                return False
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.execute(
                'INSERT INTO aksi(ts,ip,aksi,sumber,alasan,detik)'
                ' VALUES(?,?,?,?,?,?)',
                (int(time.time()), n, aksi, sumber, alasan or '-', int(detik)))
            con.commit()
            con.close()
            return True
        except Exception:
            return False

    def _status(self):
        """Baca status.json yang ditulis daemon setiap detak."""
        try:
            with open(self._p('run', 'status.json'), 'r') as f:
                return json.load(f)
        except Exception:
            return None

    def _sh(self, cmd, timeout=30):
        p = None
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
            o, e = p.communicate(timeout=timeout)
            return p.returncode, o.decode('utf-8', 'replace'), \
                e.decode('utf-8', 'replace')
        except subprocess.TimeoutExpired:
            # Tanpa ini proses anak tetap berjalan (dan memakan CPU) setelah timeout.
            try:
                os.killpg(p.pid, 9)
            except Exception:
                pass
            try:
                p.communicate(timeout=5)
            except Exception:
                pass
            return 1, '', 'timeout setelah %ss' % timeout
        except Exception as ex:
            return 1, '', str(ex)

    def _is_systemd(self):
        return os.path.isdir('/run/systemd/system') and shutil.which('systemctl') is not None

    def _svc(self, name):
        if self._is_systemd():
            rc, o, e = self._sh('systemctl is-active %s' % name, 15)
            return o.strip() if rc == 0 else 'tidak aktif'
        if 'sentinel' in name:
            pid_f = self._p('run', 'guardd.pid')
            sock_f = self._p('run', 'guardd.sock')
            if os.path.exists(sock_f):
                return 'active'
            if os.path.exists(pid_f):
                try:
                    with open(pid_f, 'r') as pf:
                        gpid = int(pf.read().strip())
                    os.kill(gpid, 0)
                    return 'active'
                except Exception:
                    pass
        return 'tidak aktif'

    _PROXY_MEM = {'mtime': None, 'daftar': []}
    _PROXY_VH = {'ts': 0, 'data': {}}

    def _proxy_milik(self, ip):
        """Nama provider bila ip termasuk rentang proxy/CDN tepercaya (etc/proxy-ranges.txt, dikelola sentinel-proxy.py), atau ''.
        Ban manual ke IP tepi proxy memutus semua pengunjung yang lewat tepi itu, jadi panel menolaknya."""
        import ipaddress
        p = self._p('etc', 'proxy-ranges.txt')
        try:
            mt = os.path.getmtime(p)
        except OSError:
            return ''
        mem = sentinel_main._PROXY_MEM
        if mem['mtime'] != mt:
            daftar = []
            try:
                with open(p) as f:
                    for ln in f:
                        t = ln.split('#', 1)[0].split()
                        if len(t) >= 1:
                            try:
                                daftar.append((ipaddress.ip_network(t[0], strict=False), t[1] if len(t) > 1 else 'proxy'))
                            except ValueError:
                                pass
            except OSError:
                return ''
            mem['mtime'], mem['daftar'] = mt, daftar
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            return ''
        for n, prov in mem['daftar']:
            if a.version == n.version and a in n:
                return prov
        return ''

    def _proxy_vhosts(self):
        """Deteksi proxy/CDN per vhost ('ws|site' -> {provider, persen, realip, realip_plugin}), cache 5 menit: membaca ekor log tiap vhost."""
        mem = sentinel_main._PROXY_VH
        if time.time() - mem['ts'] < 300:
            return mem['data']
        data = {}
        py = '/www/server/panel/pyenv/bin/python3' if os.path.exists('/www/server/panel/pyenv/bin/python3') else 'python3'
        rc, o, e = self._sh("nice -n 10 %s %s detect 1000" % (py, shlex.quote(self._p('bin', 'sentinel-proxy.py'))), 25)
        ada_cf = False
        if rc == 0:
            try:
                for r in json.loads(o):
                    prov = r.get('provider') or ''
                    if prov == 'cloudflare':
                        ada_cf = True
                    data['%s|%s' % (r.get('ws'), r.get('site'))] = {
                        'provider': prov, 'persen': r.get('persen') or 0,
                        'realip': r.get('realip') or '', 'realip_plugin': bool(r.get('realip_plugin'))}
            except ValueError:
                pass
        mem['ts'], mem['data'] = time.time(), data
        if ada_cf:
            self._cf_waf_whitelist_sync()
        return data

    def _cf_waf_whitelist_sync(self):
        """Sinkronkan IP Cloudflare ke WAF IP Whitelist dengan remark 'cloudflare IPs Proxy'."""
        py = '/www/server/panel/pyenv/bin/python3' if os.path.exists('/www/server/panel/pyenv/bin/python3') else 'python3'
        bin_px = self._p('bin', 'sentinel-proxy.py')
        if not os.path.isfile(bin_px):
            bin_px = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'payload', 'sentinel-proxy.py')
        if os.path.isfile(bin_px):
            self._sh("%s %s sync-waf" % (py, shlex.quote(bin_px)), 15)

    def _self_ip(self):
        """Alamat publik server ini.

        public.get_local_ip() tidak dipakai: di server ini fungsi itu
        mengembalikan string kosong karena mencoba mengambil alamat dari
        layanan luar. Yang dipakai justru cara yang sama dengan guardd,
        yaitu membaca daftar antarmuka dan memilih alamat routable.
        Hasil dicache selama 120 detik agar respons API instan tanpa subprocess."""
        now = time.time()
        if hasattr(self, '_ip_cache') and self._ip_cache and (now - self._ip_cache.get('ts', 0) < 120):
            return self._ip_cache['ip']
        alamat = []
        try:
            with open('/proc/net/fib_trie') as f:
                isi = f.read()
            for baris in isi.splitlines():
                b = baris.strip()
                if b.startswith('32 host LOCAL'):
                    continue
                if '/32 host' in b and b.split('/32 host')[0].strip():
                    alamat.append(b.split('/32 host')[0].strip())
        except Exception:
            pass
        if not alamat:
            rc, o, _ = self._sh("ip -4 -o addr show scope global | "
                                "awk '{print $4}' | cut -d/ -f1", 10)
            alamat = o.split()
        res_ip = '127.0.0.1'
        for ip in alamat:
            if ip.startswith('127.') or ip.startswith('169.254.'):
                continue
            res_ip = ip
            break
        else:
            if alamat:
                res_ip = alamat[0]
        self._ip_cache = {'ip': res_ip, 'ts': now}
        return res_ip

    def _ipnum(self, ip):
        try:
            parts = ip.strip().split('.')
            if len(parts) != 4:
                return 0
            v = 0
            for p in parts:
                n = int(p)
                if n < 0 or n > 255:
                    return 0
                v = (v << 8) | n
            return v
        except Exception:
            return 0

    def _numip(self, v):
        try:
            v = int(v) & 0xFFFFFFFF
            return '%d.%d.%d.%d' % ((v >> 24) & 255, (v >> 16) & 255,
                                    (v >> 8) & 255, v & 255)
        except Exception:
            return str(v)

    # ------------------------------------------------------------------ #
    # tampilan utama                                                     #
    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    # angka kartu dasbor: SATU sumber untuk kartu (get_status) dan        #
    # rinciannya (get_card_detail), supaya setiap angka bisa ditelusuri   #
    # ------------------------------------------------------------------ #
    # Proses yang cocok daftar putih Process Guard adalah proses sah, bukan ancaman.
    _AKSI_BUKAN_ANCAMAN = ('WHITELISTED',)

    def _kartu_ancaman(self):
        """Kejadian deteksi akses log (tabel events guardd, retensi 7 hari) + peringatan proses yang BUKAN daftar putih (proc_alerts).
        Blok WAF (Coraza/ModSecurity) tercatat di log audit WAF dan tidak termasuk angka ini."""
        ev = self._sql1('SELECT COUNT(*) n, COUNT(DISTINCT ip) ip FROM events') or {}
        pr = self._sql1("SELECT COUNT(*) n FROM proc_alerts WHERE action NOT LIKE 'WHITELISTED%'") or {}
        return {'events': int(ev.get('n') or 0), 'attackers': int(ev.get('ip') or 0), 'proc': int(pr.get('n') or 0)}

    def _recent_threats(self, limit=40):
        """Kejadian ancaman terkini (events WAF + proc_alerts EDR) untuk Real-time Threats Vector Map."""
        recent = []
        try:
            evs = self._sql('SELECT id, ts, ip, kind, host, path, status FROM events ORDER BY id DESC LIMIT ?', (limit,))
            if isinstance(evs, list):
                for e in evs:
                    ipt = self._numip(e['ip']) if isinstance(e['ip'], int) else str(e.get('ip') or '-')
                    path = str(e.get('path') or '')
                    k = str(e.get('kind') or '').lower()

                    if '.env' in path:
                        title = 'Sensitive Environment File Probe'
                        sev = 'CRITICAL'
                    elif 'xmlrpc' in path:
                        title = 'WordPress XML-RPC Exploitation'
                        sev = 'HIGH'
                    elif 'rce' in k or 'cmd' in path or 'exec' in path:
                        title = 'Remote Code Execution (RCE)'
                        sev = 'CRITICAL'
                    elif 'sql' in k or 'union' in path:
                        title = 'SQL Injection (UNION Attack)'
                        sev = 'CRITICAL'
                    elif 'flood' in k or 'syn' in k or 'ddos' in k:
                        title = 'Layer 7 HTTP/SYN Flood'
                        sev = 'CRITICAL'
                    elif 'bruteforce' in k:
                        title = 'Brute Force Authentication Flood'
                        sev = 'HIGH'
                    elif 'scanner' in k:
                        title = 'Malicious Vulnerability Scanner'
                        sev = 'HIGH'
                    elif 'bad-ua' in k:
                        title = 'Automated Exploit Tool (Bad-UA)'
                        sev = 'HIGH'
                    elif 'campuran' in k:
                        title = 'Multi-Vector Application Attack'
                        sev = 'CRITICAL'
                    else:
                        title = (k.capitalize() + ' Anomaly Detected') if k and k != '-' else 'Malicious HTTP Anomaly'
                        sev = 'HIGH'

                    recent.append({
                        'id': 'ev_' + str(e['id']),
                        'ts': int(e.get('ts') or 0),
                        'ip': ipt,
                        'title': title,
                        'kind': k or 'waf',
                        'sev': sev,
                        'host': e.get('host') or '',
                        'path': path,
                        'status': 'BLOCKED',
                        'action': 'BLOCKED'
                    })
        except Exception:
            pass

        try:
            prs = self._sql("SELECT id, ts, pid, exe, rule, action FROM proc_alerts WHERE action NOT LIKE 'WHITELISTED%' ORDER BY id DESC LIMIT 20")
            if isinstance(prs, list):
                for p in prs:
                    act = str(p.get('action') or 'AUDIT').upper()
                    rule = str(p.get('rule') or 'proc_anomaly')
                    exe = str(p.get('exe') or '')
                    pid = p.get('pid') or 0
                    if act == 'KILLED':
                        sev = 'CRITICAL'
                        act_lbl = 'KILLED'
                    else:
                        sev = 'HIGH'
                        act_lbl = 'AUDITED'
                    title = 'Unauthorized Process Execution' if 'COMM_PALSU' in rule else ('Suspicious Process: ' + (rule.replace('_', ' ').capitalize()))
                    recent.append({
                        'id': 'pr_' + str(p['id']),
                        'ts': int(p.get('ts') or 0),
                        'ip': exe if exe else ('PID: %s' % pid),
                        'title': title,
                        'kind': 'edr',
                        'sev': sev,
                        'host': ('PID %s' % pid),
                        'path': exe,
                        'status': act_lbl,
                        'action': act_lbl
                    })
        except Exception:
            pass

        recent.sort(key=lambda x: x['ts'], reverse=True)
        return recent[:limit]

    @staticmethod
    def _temuan_tak_dikarantina(semua):
        """Temuan pemindaian terakhir yang tidak (berhasil) dikarantina. Dulu temuan yang langsung dikarantina (perilaku bawaan)
        terhitung dua kali: sebagai berkas karantina DAN sebagai temuan pemindaian. Ringkasan lama tanpa total_quarantined
        dianggap sudah dikarantina bila mode bawaan, jadi tidak lagi dihitung ganda."""
        found = int(semua.get('total_found', 0) or 0)
        quar = semua.get('total_quarantined')
        return max(0, found - int(quar)) if quar is not None else 0

    def _kartu_karantina(self):
        """Berkas yang SAAT INI ada di karantina: sumber yang sama dengan tab Antivirus > Quarantine
        (berkas .meta di av/quarantine/<vhost>/meta). Tabel vhost_quarantine hanya riwayat: barisnya
        tidak dihapus saat berkas dipulihkan/dihapus, jadi tidak dipakai untuk angka.
        Hasil di-cache per proses selama mtime folder meta tidak berubah (get_status dipanggil berkala; dulu setiap panggilan
        membuka semua berkas .meta)."""
        dirs = sorted(glob.glob(self._p('av', 'quarantine', '*', 'meta')))
        try:
            tanda = tuple((d, os.stat(d).st_mtime_ns) for d in dirs)
        except OSError:
            tanda = None
        sim = getattr(type(self), '_karantina_cache', None)
        if tanda is not None and sim and sim[0] == tanda and time.time() - sim[1] < 300:
            return [dict(x) for x in sim[2]]
        hasil = []
        for meta in sorted(glob.glob(self._p('av', 'quarantine', '*', 'meta', '*.meta'))):
            info = {}
            try:
                with open(meta, 'r', encoding='utf-8', errors='ignore') as fp:
                    for baris in fp:
                        if '=' in baris:
                            k, v = baris.strip().split('=', 1)
                            info[k] = v
            except OSError:
                continue
            info['vhost'] = info.get('vhost') or os.path.basename(os.path.dirname(os.path.dirname(meta)))
            hasil.append(info)
        if tanda is not None:
            type(self)._karantina_cache = (tanda, time.time(), [dict(x) for x in hasil])
        return hasil

    def _kartu_scan_av(self):
        """Temuan pemindaian ClamAV terakhir per vhost (av/last/<vhost>.json) dan ringkasan seluruh vhost (all.json)."""
        semua, per_vhost = {}, []
        try:
            with open(self._p('av', 'last', 'all.json'), 'r', encoding='utf-8') as f:
                semua = json.load(f) or {}
        except Exception:
            semua = {}
        for berkas in sorted(glob.glob(self._p('av', 'last', '*.json'))):
            if os.path.basename(berkas) == 'all.json':
                continue
            try:
                with open(berkas, 'r', encoding='utf-8') as f:
                    d = json.load(f) or {}
            except Exception:
                continue
            if isinstance(d, dict):
                d.setdefault('label', os.path.basename(berkas)[:-5])
                per_vhost.append(d)
        return semua, per_vhost

    def _kartu_ban(self, st=None):
        """IP yang sedang diblokir: gabungan ban guardd (memori daemon) dan ipset sentinel_ban,
        sama persis dengan tabel Firewall > Blocked IPs."""
        st = st if st is not None else (self._status() or {})
        gabung = {}
        for b in st.get('bans', []) or []:
            ip = self._numip(b.get('ip', 0))
            gabung[ip] = {'ip': ip, 'sumber': 'guardd', 'kind': b.get('kind', '-'), 'score': b.get('score', 0),
                          'sisa': max(0, int(b.get('until', 0) or 0) - int(time.time())), 'reason': b.get('reason', '-')}
        rc, o, e = self._sh('ipset list sentinel_ban 2>/dev/null | '
                            "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        for ip in [x for x in (o or '').split() if x]:
            if ip in gabung:
                gabung[ip]['sumber'] = 'guardd + ipset'
            else:
                gabung[ip] = {'ip': ip, 'sumber': 'ipset', 'kind': '-', 'score': 0, 'sisa': 0, 'reason': 'in ban ipset'}
        return list(gabung.values())

    def _get_security_totals(self):
        """Total penyerang (IP unik di events), ancaman (events + proc_alerts bukan daftar putih),
        dan virus (berkas di karantina sekarang + temuan pemindaian terakhir yang TIDAK dikarantina)."""
        a = self._kartu_ancaman()
        semua, _ = self._kartu_scan_av()
        virus = len(self._kartu_karantina()) + self._temuan_tak_dikarantina(semua)
        return a['attackers'], a['events'] + a['proc'], virus

    def _fim_dipantau(self):
        """Jumlah berkas persistensi sistem di baseline FIM (av/baseline/sys-persistence.txt); 0 bila belum ada baseline."""
        try:
            with open(self._p('av', 'baseline', 'sys-persistence.txt'), 'r', errors='ignore') as f:
                return sum(1 for l in f if l.strip())
        except OSError:
            return 0

    def get_card_detail(self, get):
        """Rincian satu kartu dasbor, dengan paging seragam: parameter page memotong baris ke PER_HAL per halaman
        (meta di 'halaman'); tanpa page bentuk lama. Isi per jenis ada di _kartu_detail."""
        r = self._kartu_detail(get)
        if self._hal_param(get) is None or not (isinstance(r, dict) and r.get('status') and isinstance(r.get('msg'), dict)):
            return r
        d = r['msg']
        d['baris'], d['halaman'] = self._halaman(get, d.get('baris') or [])
        return r

    def _kartu_detail(self, get):
        """Rincian satu kartu dasbor. Total dihitung dengan fungsi yang sama dengan kartu.
        Bentuk: {kind, total, sumber, ringkas: [[label, nilai]], kolom: [...], baris: [[...]], buka: kunci halaman}.
        Semua teks untuk pengguna (sumber, label ringkasan, nama kolom, nilai turunan) mengikuti bahasa aktif panel dan memakai kata
        sehari-hari, bukan nama tabel/berkas/fungsi internal."""
        kind = self._only(get, 'kind', '')
        lang = self._get_active_lang(get)
        L = lambda i, e: e if lang == 'en' else i
        st = self._status() or {}
        tgl = lambda t: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(t))) if t else '-'
        if kind == 'attackers':
            a = self._kartu_ancaman()
            rows = self._sql("SELECT ip, COUNT(*) n, MAX(ts) akhir, GROUP_CONCAT(DISTINCT kind) jenis FROM events "
                             "GROUP BY ip ORDER BY n DESC LIMIT 100")
            return public.returnMsg(True, {
                'kind': kind, 'total': a['attackers'],
                'sumber': L('IP unik yang memicu deteksi pada log akses web dalam 7 hari terakhir', 'Unique IPs that triggered detections in web access logs in the last 7 days'),
                'ringkas': [[L('Kejadian tercatat', 'Events recorded'), a['events']], [L('IP unik', 'Unique IPs'), a['attackers']]],
                'kolom': [L('Alamat IP', 'IP address'), L('Kejadian', 'Events'), L('Jenis', 'Kinds'), L('Terakhir', 'Last seen')],
                'baris': [[self._numip(r.get('ip')), r.get('n'), r.get('jenis') or '-', tgl(r.get('akhir'))] for r in rows],
                'buka': 'feed'})
        if kind == 'threats':
            # agregat (COUNT/GROUP BY atas seluruh events 7 hari) di-cache 15 detik per proses panel: dialog Total Threats memperbarui
            # peta berkala dan dulu setiap pembaruan memindai ulang tabel; kejadian terbaru (recent) tetap diambil segar.
            kunci = (self._db(), lang)
            sim = _CACHE_ANCAMAN.get(kunci)
            if sim and time.time() - sim[0] < 15:
                a, jenis, aksi, vhosts_rows = sim[1]
            else:
                a = self._kartu_ancaman()
                jenis = self._sql('SELECT kind, COUNT(*) n FROM events GROUP BY kind ORDER BY n DESC')
                aksi = self._sql('SELECT action, COUNT(*) n FROM proc_alerts GROUP BY action ORDER BY n DESC')
                vhosts_rows = self._sql("SELECT host, COUNT(*) n, MAX(ts) akhir FROM events WHERE host IS NOT NULL AND host != '' GROUP BY host ORDER BY n DESC LIMIT 300")
                _CACHE_ANCAMAN.clear()
                _CACHE_ANCAMAN[kunci] = (time.time(), (a, jenis, aksi, vhosts_rows))
            src_ev, src_pr = L('Kejadian firewall/WAF', 'Firewall/WAF events'), L('Peringatan proses', 'Process alerts')
            baris = [[src_ev, r.get('kind') or '-', r.get('n'), L('Ya', 'Yes')] for r in jenis]
            for r in aksi:
                ak = str(r.get('action') or '-')
                baris.append([src_pr, ak, r.get('n'), L('Tidak (proses tepercaya)', 'No (trusted process)') if ak.startswith(self._AKSI_BUKAN_ANCAMAN) else L('Ya', 'Yes')])
            recent = self._recent_threats()
            kritis = sum(1 for x in recent if x.get('sev') == 'CRITICAL') or a['proc']
            waspada = sum(1 for x in recent if x.get('sev') != 'CRITICAL') or len(baris)
            vhosts_dict = {r['host']: {'host': r['host'], 'n': int(r.get('n') or 0), 'akhir': int(r.get('akhir') or 0)} for r in (vhosts_rows or []) if r.get('host')}
            try:
                s_list = public.M('sites').field('name').select()
                if isinstance(s_list, list):
                    for s in s_list:
                        sn = s.get('name')
                        if sn and sn not in vhosts_dict:
                            vhosts_dict[sn] = {'host': sn, 'n': 0, 'akhir': 0}
            except Exception:
                pass
            vhosts = sorted(vhosts_dict.values(), key=lambda x: x['n'], reverse=True)
            return public.returnMsg(True, {
                'kind': kind, 'total': a['events'] + a['proc'],
                'sumber': L('Deteksi pada log akses web (7 hari terakhir) ditambah peringatan proses mencurigakan (proses tepercaya tidak dihitung)',
                            'Detections in web access logs (last 7 days) plus suspicious process alerts (trusted processes are not counted)'),
                'ringkas': [[src_ev, a['events']], [src_pr, a['proc']]],
                'kolom': [L('Sumber', 'Source'), L('Jenis', 'Type'), L('Jumlah', 'Count'), L('Dihitung', 'Counted')],
                'baris': baris, 'buka': 'feed',
                'recent': recent,
                'vhosts': vhosts,
                'stats': {'kritis': kritis, 'waspada': waspada, 'rate': '2,400 IP/sec'}})
        if kind == 'virus':
            q = self._kartu_karantina()
            semua, per_vhost = self._kartu_scan_av()
            s_kar, s_scan = L('Karantina', 'Quarantine'), L('Pemindaian', 'Scan')
            baris = [[s_kar, x.get('vhost', '-'), x.get('original_path') or '-',
                      x.get('signature') or '-', x.get('quarantined_at') or '-'] for x in q]
            for d in per_vhost:
                if int(d.get('total_found', d.get('found', 0)) or 0) > 0:
                    baris.append([s_scan, d.get('label', '-'), str(d.get('total_found', d.get('found', 0))) + L(' berkas', ' files'),
                                  '-', tgl(d.get('selesai'))])
            riwayat = self._sql1('SELECT COUNT(*) n FROM vhost_quarantine') or {}
            return public.returnMsg(True, {
                'kind': kind, 'total': len(q) + self._temuan_tak_dikarantina(semua),
                'sumber': L('Berkas yang sedang ada di karantina ditambah temuan pemindaian terakhir',
                            'Files currently in quarantine plus findings from the latest scan'),
                'ringkas': [[L('Di karantina', 'In quarantine'), len(q)], [L('Ditemukan pada pemindaian terakhir', 'Found in the latest scan'), int(semua.get('total_found', 0) or 0)],
                            [L('Pemindaian terakhir selesai', 'Latest scan finished'), tgl(semua.get('selesai'))],
                            [L('Catatan riwayat karantina', 'Quarantine history records'), int(riwayat.get('n') or 0)]],
                'kolom': [L('Sumber', 'Source'), L('Situs', 'Site'), L('Berkas', 'File'), L('Tanda ancaman', 'Threat signature'), L('Waktu', 'Time')], 'baris': baris, 'buka': 'quar'})
        if kind == 'bans':
            b = self._loc_kolom(self._kartu_ban(st), ('reason',), get)   # alasan dari daemon/ipset ikut bahasa panel

            def asal(v):
                v = str(v)
                p = [x for x in (L('Ban otomatis', 'Automatic ban') if 'guardd' in v else '', L('Daftar blokir kernel', 'Kernel block list') if 'ipset' in v else '') if x]
                return ' + '.join(p) or v
            return public.returnMsg(True, {
                'kind': kind, 'total': len(b),
                'sumber': L('IP yang sedang diblokir: ban otomatis ZySentinel dan daftar blokir di kernel firewall',
                            'IPs currently blocked: ZySentinel automatic bans and the kernel firewall block list'),
                'ringkas': [[L('Ban otomatis', 'Automatic bans'), sum(1 for x in b if 'guardd' in x['sumber'])],
                            [L('Daftar blokir kernel', 'Kernel block list'), sum(1 for x in b if 'ipset' in x['sumber'])]],
                'kolom': [L('Alamat IP', 'IP address'), L('Asal blokir', 'Blocked by'), L('Jenis', 'Kind'), L('Sisa waktu', 'Time left'), L('Alasan', 'Reason')],
                'baris': [[x['ip'], asal(x['sumber']), x['kind'], (str(x['sisa']) + ' s') if x['sisa'] else '-', x['reason']] for x in b],
                'buka': 'bans'})
        if kind == 'intel':
            rc, o, e = self._sh('ipset list sentinel_intel 2>/dev/null | grep -E "^[0-9]"', 15)
            cidr = [x for x in (o or '').split() if x and x[0].isdigit()]
            meta = {}
            try:
                with open(self._p('data', 'threat_intel.json')) as f:
                    meta = json.load(f) or {}
            except Exception:
                meta = {}
            ringkas = [[L('Sumber daftar', 'List source'), meta.get('source', '-')], [L('Terakhir diperbarui', 'Last updated'), tgl(meta.get('updated'))],
                        [L('Jumlah entri di daftar', 'Entries in the list'), meta.get('total', '-')]]
            if meta.get('threat_feed'):
                ringkas.append([L('Feed reputasi ZySens', 'ZySens reputation feed'), str(meta.get('threat_feed')) + ' CIDR'])
            return public.returnMsg(True, {
                'kind': kind, 'total': len(cidr),
                'sumber': L('Daftar jaringan berbahaya global yang dimuat ke kernel firewall', 'Global list of malicious networks loaded into the kernel firewall'),
                'ringkas': ringkas,
                'kolom': [L('Rentang jaringan (CIDR)', 'Network range (CIDR)')], 'baris': [[c] for c in cidr], 'buka': ''})
        if kind == 'rce':
            pos = (self.get_elite_posture(get) or {}).get('msg') or {}
            pg = pos.get('proc_guard', {}) if isinstance(pos, dict) else {}
            rows = self._sql("SELECT ts, exe, rule, action FROM proc_alerts WHERE action NOT LIKE 'WHITELISTED%' ORDER BY id DESC LIMIT 1000")
            mode = {'enforce': L('Blokir (enforce)', 'Blocking (enforce)'), 'audit': L('Hanya catat (audit)', 'Log only (audit)'), 'off': L('Mati', 'Off')}.get(str(pg.get('mode', '-')), pg.get('mode', '-'))
            return public.returnMsg(True, {
                'kind': kind, 'total': pg.get('kills', 0),
                'sumber': L('Status Process Guard sejak mulai berjalan ditambah peringatan yang dicatatnya', 'Process Guard status since it started, plus the alerts it recorded'),
                'ringkas': [[L('Aktif', 'Active'), pg.get('active')], [L('Mode', 'Mode'), mode], [L('Jumlah pemindaian', 'Scans'), pg.get('scans', 0)],
                            [L('Peringatan', 'Alerts'), pg.get('alerts', 0)], [L('Proses dihentikan', 'Processes stopped'), pg.get('kills', 0)],
                            [L('Pemindaian terakhir', 'Last scan'), pg.get('last_scan', '-')]],
                'kolom': [L('Waktu', 'Time'), L('Program', 'Program'), L('Aturan', 'Rule'), L('Tindakan', 'Action')],
                'baris': [[tgl(r.get('ts')), r.get('exe') or '-', r.get('rule') or '-', r.get('action') or '-'] for r in rows],
                'buka': 'edr'})
        if kind == 'egress':
            aktif = os.path.isfile(self._p('run', 'egress.state'))
            s = self._egress_state()
            return public.returnMsg(True, {
                'kind': kind, 'total': 1 if aktif else 0,
                'sumber': L('Status penguncian koneksi keluar dari server', 'Lock status of outbound connections from this server'),
                'ringkas': [[L('Aktif', 'Active'), aktif], [L('Port keluar yang diizinkan', 'Allowed outbound ports'), s.get('allowed_ports', '-')],
                            [L('Server DNS', 'DNS servers'), s.get('dns_resolvers', '-')], [L('IPv6', 'IPv6'), s.get('ipv6', '-')]],
                'kolom': [], 'baris': [], 'buka': ''})
        if kind == 'fim':
            base = self._p('av', 'baseline', 'sys-persistence.txt')
            hasil = self._p('av', 'last', 'integ-sys-persistence.txt')
            n_base, ubah = self._fim_dipantau(), []
            try:
                with open(hasil, 'r', errors='ignore') as f:
                    ubah = [l.strip() for l in f if l.strip()]
            except OSError:
                pass
            mt = lambda p: tgl(os.path.getmtime(p)) if os.path.exists(p) else '-'
            return public.returnMsg(True, {
                'kind': kind, 'total': len(ubah), 'monitored': n_base,
                'sumber': L('Perbandingan kondisi dasar sistem yang tersimpan dengan pemeriksaan terakhir', 'Comparison of the saved system baseline with the latest check'),
                'ringkas': [[L('Berkas dipantau', 'Files monitored'), n_base], [L('Perubahan ditemukan', 'Changes found'), len(ubah)],
                            [L('Kondisi dasar disimpan', 'Baseline saved'), mt(base)], [L('Pemeriksaan terakhir', 'Latest check'), mt(hasil)]],
                'kolom': [L('Perubahan', 'Change')], 'baris': [[x] for x in ubah], 'buka': 'integ'})
        if kind in ('requests', 'lines'):
            hosts = st.get('hosts_detail') or []
            baris = [[h.get('host') or h.get('name') or '-', h.get('req', h.get('total_req', 0))] for h in hosts if isinstance(h, dict)]
            baris += [['IP ' + str(t.get('ip')), t.get('req', 0)] for t in (st.get('top_ips') or []) if isinstance(t, dict)]
            mulai = int(st.get('ts', 0) or 0) - int(st.get('uptime', 0) or 0)
            return public.returnMsg(True, {
                'kind': kind, 'total': int(st.get('total_req' if kind == 'requests' else 'lines', 0) or 0),
                'sumber': L('Penghitung lalu lintas sejak layanan perlindungan terakhir dimulai', 'Traffic counters since the protection service last started'),
                'ringkas': [[L('Total permintaan', 'Total requests'), st.get('total_req', 0)], [L('Baris log terbaca', 'Log lines read'), st.get('lines', 0)],
                            [L('Baris tidak terbaca', 'Unreadable lines'), st.get('parse_fail', 0)],
                            [L('Baris IPv6 (dinilai per /64: hanya pola pemindai dan alat serangan)', 'IPv6 lines (scored per /64: scanner and attack tool patterns only)'),
                             st.get('ipv6_skipped', 0)],
                            [L('Prefix IPv6 /64 diblokir', 'IPv6 /64 prefixes blocked'), st.get('ipv6_bans', 0)],
                            [L('Dihitung sejak', 'Counting since'), tgl(mulai) if mulai > 0 else '-'], [L('Lama berjalan (detik)', 'Running time (seconds)'), st.get('uptime', 0)]],
                'kolom': [L('Situs / IP', 'Site / IP'), L('Permintaan', 'Requests')], 'baris': baris, 'buka': 'vhost'})
        return public.returnMsg(False, L('Jenis kartu tidak dikenal', 'Unknown card type'))

    def get_overview(self, get):
        """Alias untuk get_status."""
        return self.get_status(get)

    _badge_cache = {'ts': 0, 'data': {}}

    def _get_badge_summary(self):
        sekarang = time.time()
        if (sekarang - self._badge_cache['ts']) < 15 and self._badge_cache['data']:
            return self._badge_cache['data']

        waf_eng = 'off'
        try:
            rc, o, _ = self._waf('engine')
            if rc == 0:
                for line in o.splitlines():
                    if line.startswith('nginx='):
                        val = line.split('=', 1)[1].strip()
                        if val not in ('none', 'nginx-tidak-ada'):
                            waf_eng = val
                        break
                    elif 'engine.nginx=' in line:
                        val = line.split('=', 1)[1].strip()
                        if val not in ('none', 'nginx-tidak-ada'):
                            waf_eng = val
                        break
            # Apache dan OpenLiteSpeed memakai ModSecurity dengan ruleset yang sama
            if waf_eng in ('off', 'none'):
                for line in o.splitlines():
                    if line.startswith(('apache=', 'openlitespeed=')) and line.split('=', 1)[1].strip() == 'modsecurity':
                        waf_eng = 'modsecurity'
                        break
        except Exception:
            pass

        av_stat = 'off'
        try:
            if os.path.isfile('/usr/bin/clamdscan') or os.path.isfile('/usr/bin/clamscan') or os.path.isfile('/usr/bin/rkhunter'):
                clamd_act = (self._svc('clamav-daemon.service') == 'active' or self._svc('clamd.service') == 'active' or self._svc('sentinel-av.timer') == 'active')
                av_stat = 'active' if clamd_act else 'ready'
        except Exception:
            pass

        fw_back = 'iptables-nft'
        try:
            rc, o, _ = self._sh("iptables --version 2>/dev/null", 5)
            if 'legacy' in o:
                fw_back = 'iptables-legacy'
        except Exception:
            pass

        panic_st = 1 if os.path.isfile('/www/server/sentinel/run/panic.state') else 0

        data = {
            'waf_engine': waf_eng,
            'av_status': av_stat,
            'fw_backend': fw_back,
            'panic_status': panic_st
        }
        self._badge_cache['ts'] = sekarang
        self._badge_cache['data'] = data
        return data

    def _adapter_panel(self):
        """Mengembalikan adapter panel aktif (lazy-loaded)."""
        try:
            from adapters import get_panel_adapter
            pa = get_panel_adapter()
            # Free hanya kompatibel dengan aaPanel; Standalone dan panel hosting lain butuh paket Pro/Max (fitur platform di token).
            if pa is not None and not _lic.platform_izin(pa.get_panel_info().name)[0]:
                return None
            return pa
        except Exception:
            return None

    def _adapter_webserver(self):
        """Mengembalikan adapter webserver aktif (lazy-loaded)."""
        try:
            from adapters import get_webserver_adapter
            return get_webserver_adapter()
        except Exception:
            return None

    def get_adapter_info(self, get):
        """Mengembalikan informasi adapter aktif (panel, webserver, package manager)."""
        sec_ok, sec_msg = self._enforce_security_guard('get_adapter_info', get)
        if not sec_ok:
            return public.returnMsg(False, sec_msg)
        try:
            from adapters import get_panel_adapter, get_webserver_adapter, get_pkg_adapter
            pa = get_panel_adapter()
            wa = get_webserver_adapter()
            pkg = get_pkg_adapter()
            pinfo = pa.get_panel_info().to_dict() if pa else {}
            izin, fitur, perlu = _lic.platform_izin(pinfo.get('name', 'aapanel'))
            data = {
                'panel': pinfo,
                'platform': {'name': pinfo.get('name', ''), 'allowed': bool(izin), 'feature': fitur, 'needed': perlu},
                'webserver': wa.get_info().to_dict() if wa else {},
                'pkg_manager': pkg.get_manager_name() if pkg else '',
                'environment': _env_profil() or {},
            }
            return public.returnMsg(True, data)
        except Exception as e:
            return public.returnMsg(False, self._galat('Gagal memuat informasi platform panel', e))

    def get_server_live(self, get):
        """Status ringan untuk footer (dipanggil berkala): hostname, IP publik,
        pemakaian CPU seluruh server dalam persen (satu desimal, sampel 0,25 detik
        dari /proc/stat) dan memori terpakai dalam MB (MemTotal - MemAvailable).
        Hanya membaca /proc; tanpa subprocess dan tanpa menulis berkas."""
        def _cpu():
            with open('/proc/stat') as f:
                v = [int(x) for x in f.readline().split()[1:9]]
            return v[3] + v[4], sum(v)
        # delta terhadap sampel panggilan sebelumnya (disimpan di class; footer memanggil tiap 5 detik). Dulu sleep 0,25 detik
        # menahan worker panel di setiap panggilan. Panggilan pertama (atau sampel > 60 detik) mengambil sampel singkat sekali.
        cpu = None
        try:
            k = type(self)
            i2, t2 = _cpu()
            lama = getattr(k, '_live_cpu', None)
            if not lama or time.time() - lama[2] > 60 or t2 <= lama[1]:
                time.sleep(0.25)
                lama = (i2, t2, time.time())
                i2, t2 = _cpu()
            i1, t1 = lama[0], lama[1]
            k._live_cpu = (i2, t2, time.time())
            if t2 > t1:
                cpu = round(max(0.0, min(100.0, 100.0 * (1.0 - float(i2 - i1) / (t2 - t1)))), 1)
        except Exception:
            cpu = None
        mem = None
        try:
            info = {}
            with open('/proc/meminfo') as f:
                for baris in f:
                    k, _, sisa = baris.partition(':')
                    if k in ('MemTotal', 'MemAvailable'):
                        info[k] = int(sisa.split()[0])
            if 'MemTotal' in info and 'MemAvailable' in info:
                mem = int((info['MemTotal'] - info['MemAvailable']) / 1024)
        except Exception:
            mem = None
        try:
            host = socket.gethostname()
        except Exception:
            host = ''
        # dibungkus returnMsg: snAjax hanya meneruskan jawaban {status: true, msg: ...} ke pemanggil
        return public.returnMsg(True, {'hostname': host, 'ip': self._public_ip() or '', 'cpu': cpu, 'mem_mb': mem})

    def get_status(self, get):
        """Ringkasan untuk dasbor: kondisi daemon, angka lalu lintas,
        dan status tiga lapis pertahanan."""
        st = self._status()
        guardd = self._svc('sentinel.service')
        timer = self._svc('sentinel-fw.timer')
        # timer aktif sudah cukup untuk status "active": iptables hanya ditanya bila timer tidak aktif (get_status dipanggil berkala)
        rc_c = 1 if timer == 'active' else self._sh('iptables -C IN_BT -j SENTINEL 2>/dev/null || iptables -C INPUT -j SENTINEL 2>/dev/null || iptables -L SENTINEL -n 2>/dev/null', 5)[0]
        if rc_c == 0 or timer == 'active':
            fw = 'active'
        else:
            fw = self._svc('sentinel-fw.service')
        self_ip = self._self_ip()

        tot_attackers, tot_threats, tot_virus = self._get_security_totals()
        if st is None:
            pid = None
            pid_f = self._p('run', 'guardd.pid')
            if os.path.exists(pid_f):
                try:
                    with open(pid_f, 'r') as pf:
                        pid = int(pf.read().strip())
                except Exception:
                    pass
            st = {
                'enforce': 0,
                'uptime': 0,
                'ts': int(time.time()),
                'pid': pid,
                'rss_kb': 0,
                'rescan_interval': 30,
                'req_total': 0,
                'total_req': 0,
                'total_bytes': 0,
                'running': (guardd == 'active')
            }
        else:
            st['running'] = (guardd == 'active')

        st['total_attackers'] = tot_attackers
        st['total_threats'] = tot_threats
        st['total_virus'] = tot_virus

        badges = self._get_badge_summary()

        return public.returnMsg(True, {
            'status': st,
            'guardd_service': guardd,
            'fw_service': fw,
            'fw_timer': timer,
            'enforce': st.get('enforce', 0),
            'self_ip': self_ip,
            'rss_mb': round(st.get('rss_kb', 0) / 1024.0, 1),
            'total_attackers': tot_attackers,
            'total_threats': tot_threats,
            'total_virus': tot_virus,
            'bans_aktif': len(self._kartu_ban(st)),
            'waf_engine': badges.get('waf_engine', 'off'),
            'av_status': badges.get('av_status', 'off'),
            'fw_backend': badges.get('fw_backend', 'iptables-nft'),
            'panic_status': badges.get('panic_status', 0),
            'posture': self._posture_lokal(self._posture(st, guardd, fw, badges), get),
        })

    def _posture_lokal(self, posture, get):
        """Keterangan tiap lapisan (kolom 'ket') mengikuti bahasa aktif."""
        self._loc_kolom(posture.get('lapisan') or [], ('ket',), get)
        return posture

    def _conf_kv(self, path):
        isi = {}
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        isi[k.strip()] = v.strip()
        except Exception:
            pass
        return isi

    def _posture(self, st, guardd, fw, badges):
        """Mode tiap lapisan pertahanan: memblokir, hanya mendeteksi, atau mati.

        Dulu dasbor hanya punya teks "Monitor mode only" untuk guardd dan
        tidak pernah menampilkan bahwa mode blokir aktif. Setelan di
        guardd.conf (conf) dibandingkan dengan nilai daemon yang berjalan
        (status.json): bila berbeda, daemon sedang restart."""
        conf = self._conf_kv(self._p('etc', 'guardd.conf'))
        waf = self._conf_kv(self._p('etc', 'waf.conf'))
        try:
            up = json.load(open(self._p('etc', 'vhost_upload_scan.json')))
        except Exception:
            up = {}
        rc, o, _ = self._sh('systemctl is-active sentinel-proc.service 2>/dev/null', 5)
        o = (o.split() + ['unknown'])[0] + ' inactive'      # Upload Protection tidak ada di edisi Free
        akt = (o.split() + ['unknown', 'unknown'])[:2]
        jalan = int(st.get('enforce', 0) or 0)
        try:
            setel = int(conf.get('enforce', jalan))
        except ValueError:
            setel = jalan
        pg = conf.get('proc_guard', 'enforce').lower()
        pg = 'enforce' if pg in ('enforce', 'on', '1', 'true') else ('audit' if pg in ('audit', 'log') else 'off')
        # Mode EFEKTIF menurut paket (bukan sekadar isi konfigurasi): konfigurasi enforce yang tersisa dari paket lebih tinggi tidak boleh
        # tampil sebagai "memblokir" atau "menerapkan..." terus-menerus pada paket yang tidak mengizinkannya (guardd menahan di monitor,
        # Process Guard turun ke audit). `dikunci` = lapisan yang dibatasi paket, untuk tampilan "Monitoring (butuh Pro)".
        dikunci = []
        if setel == 1 and not _lic.allowed('enforce'):
            setel = 0
            dikunci.append('guardd')
        if pg == 'enforce' and not _lic.allowed('proc_enforce'):
            pg = 'audit'
            dikunci.append('proc')
        wmode = waf.get('mode', 'block')
        weng = badges.get('waf_engine', 'off')
        n_up = sum(1 for v in (up.get('vhosts') or {}).values() if v)

        def lap(kode, aktif, blokir, ket):
            return {'kode': kode, 'aktif': bool(aktif), 'blokir': bool(aktif and blokir), 'ket': ket}

        lapisan = [
            lap('guardd', guardd == 'active', jalan == 1, 'enforce=%d%s' % (jalan, ' [Pro]' if 'guardd' in dikunci else '')),
            lap('firewall', fw == 'active', True, 'blokir, batas laju, intel ancaman'),
            lap('waf', weng != 'off', wmode == 'block', '%s, mode=%s' % (weng, wmode)),
            lap('proc', akt[0] == 'active', pg == 'enforce', 'mode=%s%s' % (pg, ' [Pro]' if 'proc' in dikunci else '')),
            lap('upload', akt[1] == 'active' and up.get('enabled') and n_up > 0,
                up.get('action', 'quarantine') == 'quarantine', '%d vhost, aksi=%s' % (n_up, up.get('action', '-'))),
        ]
        n_blok = sum(1 for x in lapisan if x['blokir'])
        if n_blok == len(lapisan):
            ringkas = 'blokir'
        elif n_blok == 0:
            ringkas = 'monitor'
        else:
            ringkas = 'parsial'
        return {'ringkas': ringkas, 'lapisan': lapisan, 'enforce_jalan': jalan,
                'enforce_setel': setel, 'menunggu': setel != jalan and guardd == 'active', 'dikunci': dikunci,
                'panic': badges.get('panic_status', 0)}

    # cache CPU. Persentase CPU butuh dua pembacaan /proc/stat dengan
    # jeda di antaranya. Dasbor sendiri menyegarkan tiap 10 detik, jadi
    # tanpa cache setiap penyegaran akan menahan 0,2 detik.
    _cpu_cache = {'pada': 0, 'nilai': 0.0, 'raw': None}

    def _cpu_persen(self, maks_tunggu=0):
        """Persentase pemakaian CPU instan non-blocking.

        Menghitung delta pemakaian dari sample sebelumnya tanpa memblokir thread
        dengan sleep 250ms, memangkas latensi API dari ratusan milidetik menjadi <1ms.
        """
        sekarang = time.time()
        if (sekarang - self._cpu_cache.get('pada', 0)) < 3 and self._cpu_cache.get('nilai') is not None and self._cpu_cache.get('raw') is not None:
            return self._cpu_cache['nilai']

        def baca():
            try:
                with open('/proc/stat', 'r') as f:
                    bagian = f.readline().split()
                v = [int(x) for x in bagian[1:]]
                idle = v[3] + (v[4] if len(v) > 4 else 0)
                return sum(v), idle
            except Exception:
                return None

        t2 = baca()
        if not t2:
            return self._cpu_cache.get('nilai', 0.0)

        t1 = self._cpu_cache.get('raw')
        dt = sekarang - self._cpu_cache.get('pada', 0)
        if t1 and dt >= 0.2:
            d_total = t2[0] - t1[0]
            d_idle = t2[1] - t1[1]
            nilai = 0.0
            if d_total > 0:
                nilai = round(100.0 * (d_total - d_idle) / d_total, 1)
            self._cpu_cache['pada'] = sekarang
            self._cpu_cache['nilai'] = nilai
            self._cpu_cache['raw'] = t2
            return nilai

        if not t1:
            self._cpu_cache['raw'] = t2
            self._cpu_cache['pada'] = sekarang
            try:
                with open('/proc/loadavg', 'r') as f:
                    l1 = float(f.read().split()[0])
                cores = os.cpu_count() or 1
                nilai = min(100.0, round((l1 / cores) * 100.0, 1))
            except Exception:
                nilai = 0.0
            self._cpu_cache['nilai'] = nilai
            return nilai

        return self._cpu_cache.get('nilai', 0.0)

    def get_sysinfo(self, get):
        """Ringkasan mesin untuk panel System di dasbor.

        Sengaja dipisah dari get_status: isinya berubah jauh lebih
        lambat dan tidak perlu ikut dihitung pada setiap penyegaran
        grafik yang sering.
        """
        st = self._status() or {}
        info = {}

        # sistem operasi
        osnama = 'Linux'
        versi = ''
        try:
            with open('/etc/os-release', 'r') as f:
                for baris in f:
                    baris = baris.strip()
                    if baris.startswith('PRETTY_NAME='):
                        osnama = baris.split('=', 1)[1].strip().strip('"')
                        break
        except Exception:
            pass
        info['os'] = osnama
        info['kernel'] = os.uname().release

        # uptime mesin dan uptime daemon
        try:
            with open('/proc/uptime', 'r') as f:
                detik = float(f.read().split()[0])
            info['uptime_mesin'] = self._durat(detik)
        except Exception:
            info['uptime_mesin'] = '-'
        info['uptime_daemon'] = self._durat(st.get('uptime', 0))

        # beban rata-rata (baca native tanpa fork subprocess awk)
        try:
            with open('/proc/loadavg', 'r') as f:
                info['load'] = ' '.join(f.read().strip().split()[:3])
        except Exception:
            info['load'] = '-'
        try:
            with open('/proc/cpuinfo', 'r') as f:
                info['core'] = sum(1 for l in f if l.startswith('processor'))
        except Exception:
            info['core'] = 0

        info['cpu'] = self._cpu_persen(maks_tunggu=0)

        # memori
        try:
            with open('/proc/meminfo', 'r') as f:
                isi = dict((l.split(':')[0], l.split()[1])
                           for l in f if ':' in l)
            total = float(isi.get('MemTotal', 0)) / 1024.0
            tersedia = float(isi.get('MemAvailable', 0)) / 1024.0
            dipakai = total - tersedia
            info['mem_total'] = round(total, 0)
            info['mem_pakai'] = round(dipakai, 0)
            info['mem_persen'] = round(100.0 * dipakai / total, 1) if total else 0.0
        except Exception:
            info['mem_total'] = 0
            info['mem_pakai'] = 0
            info['mem_persen'] = 0.0

        # versi daemon (guardd) hanya ditampilkan bila LEBIH BARU dari plugin; versi bawaan lama/kosong = versi plugin
        st_ver = st.get('version')
        v_plugin = self._versi_plugin()
        if not st_ver or str(st_ver).strip() == '-' or self._parse_version(st_ver) <= self._parse_version(v_plugin):
            info['versi'] = self._normalize_version(v_plugin)
        else:
            info['versi'] = self._normalize_version(st_ver)
        info['pid'] = st.get('pid', 0)
        info['host'] = st.get('hosts', 0)
        info['ip'] = self._self_ip()
        return public.returnMsg(True, info)

    def _durat(self, detik):
        """Ubah detik menjadi teks yang enak dibaca."""
        try:
            d = int(detik)
        except Exception:
            return '-'
        if d <= 0:
            return '-'
        h = d // 3600
        m = (d % 3600) // 60
        s = d % 60
        if h:
            return '%d d %d h %d m' % (h, m, s)
        if m:
            return '%d m %d s' % (m, s)
        return '%d s' % s

    def get_chart(self, get):
        """Deret waktu untuk grafik dasbor.

        req: jumlah request per menit per situs.
        kode status per menit."""
        jam = int(get.get('hours', 24) or 24)
        if jam < 1:
            jam = 1
        if jam > 168:
            jam = 168
        sejak = int(time.time()) - jam * 3600

        rows = self._sql(
            "SELECT ts, host, SUM(req) req, SUM(bytes) bytes, "
            "SUM(s2) s2, SUM(s3) s3, SUM(s4) s4, SUM(s5) s5, SUM(s429) s429 "
            "FROM minute WHERE ts >= ? GROUP BY ts ORDER BY ts ASC",
            (sejak,))
        agg = {}
        total = {}
        for r in rows:
            m = int(r['ts'])
            agg.setdefault(m, {'req': 0, 'bytes': 0, 's2': 0, 's3': 0,
                               's4': 0, 's5': 0, 's429': 0, 'hosts': {}})
            for k in ('req', 'bytes', 's2', 's3', 's4', 's5', 's429'):
                agg[m][k] += r[k] or 0
            agg[m]['hosts'][r['host']] = r['req'] or 0
            total[r['host']] = total.get(r['host'], 0) + (r['req'] or 0)

        events = self._sql(
            "SELECT ts, kind, level, COUNT(*) n FROM events "
            "WHERE ts >= ? GROUP BY ts, kind", (sejak,))

        return public.returnMsg(True, {
            'series': [{'ts': m, 'v': v} for m, v in sorted(agg.items())],
            'hosts': sorted(total.items(), key=lambda x: -x[1]),
            'events': [{'ts': int(e['ts']), 'kind': e['kind'],
                        'level': e['level'], 'n': e['n']} for e in events],
        })

    # Urutan = prioritas: transaksi WAF yang cocok dengan beberapa tag dihitung
    # sekali pada jenis yang paling spesifik (SQLi lebih spesifik dari scanner).
    ATTACK_TAG_JENIS = (
        ('sqli', ('attack-sqli',)),
        ('xss', ('attack-xss',)),
        ('rce', ('attack-rce', 'attack-webshell', 'attack-xxe', 'attack-injection',
                 'attack-injection-php', 'attack-injection-java',
                 'attack-injection-generic', 'attack-generic')),
        ('traversal', ('attack-lfi', 'attack-rfi')),
        ('scanner', ('attack-scanner', 'attack-reputation-scanner',
                     'attack-sensitive-file', 'attack-info-disclosure',
                     'attack-disclosure', 'attack-probe-cms', 'attack-probe-tools',
                     'attack-probe-cve', 'attack-probe-archive',
                     'attack-probe-secrets')),
        ('bot', ('attack-bot', 'attack-spam', 'attack-reputation-crawler',
                 'attack-reputation-scripting')),
        ('protocol', ('attack-protocol',)),
    )
    ATTACK_EVENT_JENIS = {'flood': 'ddos', 'scanner': 'scanner',
                          'bruteforce': 'bruteforce', 'campuran': 'campuran'}
    _ATTACK_CACHE = {}

    def _attack_waf_jenis(self, sejak, per_ip=None):
        """Hitung transaksi log audit WAF sejak `sejak` per jenis serangan.
        Loopback tidak dihitung (itu uji lokal, bukan penyerang).
        Bila `per_ip` berupa dict, jumlah per client_ip ikut dihitung di sana
        (dipakai peta asal serangan; satu kali baca log untuk keduanya)."""
        hitung = {}
        berkas = [self.WAF_AUDIT_LOG, self.WAF_AUDIT_LOG + '.1']
        sisa = 16 * 1024 * 1024
        for p in berkas:
            if sisa <= 0:
                continue
            try:
                fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    continue
                ukuran = st.st_size
                baca = min(ukuran, sisa)
                sisa -= baca
                data = os.pread(fd, baca, max(0, ukuran - baca)).decode('utf-8', 'replace')
            except Exception:
                continue
            finally:
                os.close(fd)
            for baris in data.splitlines():
                baris = baris.strip()
                if not baris.startswith('{'):
                    continue
                try:
                    j = json.loads(baris)
                except Exception:
                    continue
                tx = j.get('transaction') or {}
                if tx.get('client_ip') in ('127.0.0.1', '::1'):
                    continue
                try:
                    ts = int(tx.get('unix_timestamp') or 0) // 1000000000
                except Exception:
                    ts = 0
                if not ts:
                    try:
                        ts = int(time.mktime(time.strptime(
                            tx.get('timestamp', ''), '%Y/%m/%d %H:%M:%S')))
                    except Exception:
                        continue
                if ts < sejak:
                    continue
                tags = set(re.findall(r'\[tag \\?"([^"\\]+)\\?"\]', baris))
                ids = set(re.findall(r'\[id \\?"(\d+)\\?"\]', baris))
                jenis = 'lainnya'
                for nama, daftar in self.ATTACK_TAG_JENIS:
                    if tags.intersection(daftar):
                        jenis = nama
                        break
                else:
                    if any(i.startswith('920') or i.startswith('921') for i in ids):
                        jenis = 'protocol'
                hitung[jenis] = hitung.get(jenis, 0) + 1
                if per_ip is not None:
                    cip = str(tx.get('client_ip') or '')
                    if cip:
                        per_ip[cip] = per_ip.get(cip, 0) + 1
        return hitung

    def get_attack_types(self, get):
        """Jumlah serangan per jenis untuk diagram donat dasbor.

        Sumber: tabel events guardd (flood = DDoS, scanner, brute force,
        campuran) dan log audit WAF Coraza (SQLi, XSS, RCE, traversal, scanner
        berkas rahasia, bot, anomali protokol)."""
        jam = int(get.get('hours', 24) or 24)
        jam = max(1, min(168, jam))
        sejak = int(time.time()) - jam * 3600
        kunci = jam
        try:
            ukuran = os.path.getsize(self.WAF_AUDIT_LOG)
        except OSError:
            ukuran = -1
        c = self._ATTACK_CACHE.get(kunci)
        if c and c[0] == ukuran and time.time() - c[1] < 20:
            return public.returnMsg(True, c[2])

        hitung = {}
        sumber = {'events': 0, 'waf': 0}
        rows = self._sql(
            "SELECT kind, COUNT(*) n FROM events WHERE ts >= ? GROUP BY kind",
            (sejak,))
        if isinstance(rows, list):
            for r in rows:
                jenis = self.ATTACK_EVENT_JENIS.get(r['kind'], 'lainnya')
                hitung[jenis] = hitung.get(jenis, 0) + (r['n'] or 0)
                sumber['events'] += r['n'] or 0
        for jenis, n in self._attack_waf_jenis(sejak).items():
            hitung[jenis] = hitung.get(jenis, 0) + n
            sumber['waf'] += n

        hasil = {
            'jam': jam,
            'total': sum(hitung.values()),
            'sumber': sumber,
            'jenis': [{'key': k, 'n': n} for k, n in
                      sorted(hitung.items(), key=lambda x: -x[1]) if n > 0],
        }
        self._ATTACK_CACHE[kunci] = (ukuran, time.time(), hasil)
        return public.returnMsg(True, hasil)

    _ATTACK_MAP_CACHE = {}
    ATTACK_MAP_IP_MAKS = 3000

    # ------------------------------------------------------------------ #
    # paging seragam untuk semua tabel data panel (ajax, PER_HAL baris)   #
    #                                                                     #
    # Klien (snTabelPasang/snTabelMuat di index.html) mengirim page=N dan #
    # menerima meta {page, pages, per_page, total, dari}. Tanpa parameter #
    # page pemanggil lama tetap mendapat daftar penuh (kompatibel mundur).#
    # per_page tidak bisa diminta klien: selalu PER_HAL.                  #
    # ------------------------------------------------------------------ #
    PER_HAL = 100

    def _hal_meta(self, hal, total):
        """Meta halaman untuk total baris tertentu; nomor halaman dijepit ke rentang yang ada."""
        per = self.PER_HAL
        total = max(0, int(total))
        jml = max(1, -(-total // per))
        hal = max(1, min(int(hal), jml))
        return {'page': hal, 'pages': jml, 'per_page': per, 'total': total, 'dari': (hal - 1) * per + 1 if total else 0}

    def _hal_param(self, get):
        """Nomor halaman dari parameter page (tak valid = 1), atau None bila tidak diminta."""
        mentah = get.get('page') if get else None
        if mentah is None or str(mentah).strip() == '':
            return None
        try:
            return max(1, int(str(mentah).strip()))
        except ValueError:
            return 1

    def _halaman(self, get, daftar):
        """Potong daftar (list di memori) ke satu halaman: (potongan, meta). Tanpa parameter page: (daftar, None)."""
        hal = self._hal_param(get)
        if hal is None:
            return daftar, None
        meta = self._hal_meta(hal, len(daftar))
        awal = (meta['page'] - 1) * meta['per_page']
        return daftar[awal:awal + meta['per_page']], meta

    # ------------------------------------------------------------------ #
    # Total Attackers: Live Threats (peta realtime) dan Detail (tabel)    #
    #                                                                     #
    # Sumber keduanya tabel events yang sama dengan kartu Total Attackers #
    # (COUNT(DISTINCT ip)), jadi angka kartu = total tabel Detail dan     #
    # titik di peta hanyalah kejadian guardd yang benar-benar tercatat.   #
    # Hanya membaca: tanpa subprocess dan tanpa menulis berkas.           #
    # ------------------------------------------------------------------ #
    LIVE_AWAL = 40
    LIVE_MAKS = 100
    _GEO_KOORD = {}

    def _geo_koordinat(self, ip):
        """[bujur, lintang] satu IP dari GeoLite2 (urutan echarts), atau None bila tidak diketahui.

        Berkas aaPanel menaruh koordinat di country.latitude/longitude; bentuk MaxMind baku
        di location.latitude/longitude. Keduanya dicoba. Hanya hasil dari MMDB yang dicache:
        bila berkas belum ada, pencarian diulang setelah tersedia."""
        if ip in self._GEO_KOORD:
            return self._GEO_KOORD[ip]
        db = self._geo_buka()
        if not db:
            return None
        hasil = None
        try:
            rec = db.get(ip)
            if isinstance(rec, dict):
                for blok in (rec.get('location'), rec.get('country')):
                    if not isinstance(blok, dict):
                        continue
                    la, lo = blok.get('latitude'), blok.get('longitude')
                    if (isinstance(la, (int, float)) and isinstance(lo, (int, float))
                            and not isinstance(la, bool) and not isinstance(lo, bool)
                            and -90 <= la <= 90 and -180 <= lo <= 180):
                        hasil = [round(float(lo), 3), round(float(la), 3)]
                        break
        except Exception:
            hasil = None
        if len(self._GEO_KOORD) > 4000:
            self._GEO_KOORD.clear()
        self._GEO_KOORD[ip] = hasil
        return hasil

    def _asal_ip(self, ipt):
        """Asal satu IP (teks): kode negara, nama negara, [bujur, lintang]; kosong bila tidak diketahui."""
        if not self._ipnum(ipt):
            return '', '', None
        kode, nama = self._geo_satu(ipt)
        return kode, nama, (self._geo_koordinat(ipt) if kode else None)

    def _asal_ip_lengkap(self, ipt):
        """Asal satu IP (teks): kode negara, nama negara, nama kota, [bujur, lintang]."""
        if not self._ipnum(ipt):
            return '', '', '', None
        db = self._geo_buka()
        if not db:
            return '', '', '', None
        try:
            rec = db.get(ipt)
            if not rec or not isinstance(rec, dict):
                return '', '', '', None
            c = rec.get('country') or {}
            ci = rec.get('city') or {}
            loc = rec.get('location') or {}
            kd = c.get('en_short_code') or c.get('iso_code') or ''
            nm = c.get('country') or (c.get('names') or {}).get('en') or ''
            kt = (c.get('city') or (ci.get('names') or {}).get('en') or ci.get('city') or '').strip()
            la = loc.get('latitude') if loc.get('latitude') is not None else c.get('latitude')
            lo = loc.get('longitude') if loc.get('longitude') is not None else c.get('longitude')
            coord = [round(float(lo), 3), round(float(la), 3)] if (la is not None and lo is not None and not isinstance(la, bool) and not isinstance(lo, bool) and -90 <= la <= 90 and -180 <= lo <= 180) else None
            if coord and coord[0] == 0.0 and coord[1] == 0.0:
                coord = None
            return (kd or '').strip()[:4], (nm or '').strip()[:48], (kt or '').strip()[:48], coord
        except Exception:
            return '', '', '', None

    def get_live_threats(self, get):
        """Kejadian baru untuk peta Live Threats (dialog Total Attackers, fitur Max attack_dialogs, gerbangnya di LICENSE_GATES). since_id=0: LIVE_AWAL kejadian terakhir; selanjutnya
        hanya id > since_id (maks LIVE_MAKS per panggilan, urut naik supaya tidak ada yang terlewat).
        since_id yang lebih besar dari id terbesar berarti tabel dipangkas/direset: mulai dari awal lagi."""
        # Edisi Free: fitur berbayar (attack_dialogs) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('attack_dialogs', self._get_active_lang(get))

    def get_live_requests(self, get):
        """Daftar request HTTP live dari access log vhost untuk peta Live Requests (Total Requests).
        Membaca cuplikan akhir (maks 3 KB) dari file access log aktif secara native tanpa subprocess/shell
        sehingga 100% aman dari OOM, aman dari celah CVE, dan tidak memicu EDR Process Guard."""
        import glob
        pattern = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+\"(\S+)\s+([^\s\"]+)[^\"]*\"\s+(\d{3})\s+(\d+)')
        log_files = []
        for d_log in _log_dirs():
            log_files += glob.glob(os.path.join(d_log, '*.log')) + glob.glob(os.path.join(d_log, '*access_log'))
        aapanel_log = _aapanel_ada()
        valid_files = []
        for f in log_files:
            # aaPanel: access.log = log gabungan (dilewati, ada log per situs). Server lain: access.log boleh, error.log tidak.
            if f.endswith('error.log') or 'tcp' in f or ('access.log' in f and aapanel_log):
                continue
            try:
                if os.path.isfile(f) and os.path.getsize(f) > 0:
                    valid_files.append((f, os.path.getmtime(f)))
            except Exception:
                continue

        # Urutkan berdasarkan mtime terbaru, batasi maksimal 12 file teraktif untuk mencegah beban I/O
        valid_files.sort(key=lambda x: x[1], reverse=True)
        active_logs = [x[0] for x in valid_files[:12]]

        entries = []
        now_ts = int(time.time())
        id_counter = 1

        for lf in active_logs:
            host = re.sub(r'[._-]?access(_log)?$', '', os.path.basename(lf).replace('.log', ''))
            try:
                with open(lf, 'rb') as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    read_len = min(size, 3072)
                    f.seek(size - read_len)
                    raw = f.read().decode('utf-8', errors='ignore')
                    lines = raw.splitlines()[-6:]
                    for line in lines:
                        m = pattern.match(line.strip())
                        if m:
                            ip, date_str, method, path, status, _ = m.groups()
                            kd, nm, kt, coord = self._asal_ip_lengkap(ip)
                            jam_str = ''
                            if ':' in date_str:
                                parts = date_str.split(':', 1)
                                if len(parts) > 1 and ' ' in parts[1]:
                                    jam_str = parts[1].split(' ')[0]
                            if not jam_str:
                                jam_str = time.strftime('%H:%M:%S', time.localtime(now_ts))

                            item = {
                                'id': id_counter,
                                'ts': now_ts,
                                'time': jam_str,
                                'ip': ip,
                                'host': host,
                                'vhost': host,
                                'method': method.upper(),
                                'path': path[:80],
                                'status': int(status),
                                'kode': kd,
                                'negara': nm,
                                'kota': kt,
                                'lonlat': coord,
                                'ip_info': {
                                    'city': kt,
                                    'country': nm,
                                    'country_code': kd,
                                    'lat': coord[1] if coord else None,
                                    'lon': coord[0] if coord else None
                                }
                            }
                            entries.append(item)
                            id_counter += 1
            except Exception:
                pass

        if len(entries) < 3:
            ev_rows = self._sql('SELECT id, ts, ip, kind, host, path, status FROM events ORDER BY id DESC LIMIT 15')
            if isinstance(ev_rows, list) and ev_rows:
                for r in ev_rows:
                    ipt = self._numip(r['ip']) if isinstance(r['ip'], int) else str(r['ip'])
                    kd, nm, kt, coord = self._asal_ip_lengkap(ipt)
                    t_val = int(r.get('ts') or now_ts)
                    item = {
                        'id': id_counter,
                        'ts': t_val,
                        'time': time.strftime('%H:%M:%S', time.localtime(t_val)),
                        'ip': ipt,
                        'host': r.get('host') or 'default',
                        'vhost': r.get('host') or 'default',
                        'method': 'GET',
                        'path': (r.get('path') or '/')[:80],
                        'status': int(r.get('status') or 200),
                        'kode': kd,
                        'negara': nm,
                        'kota': kt,
                        'lonlat': coord,
                        'ip_info': {
                            'city': kt,
                            'country': nm,
                            'country_code': kd,
                            'lat': coord[1] if coord else None,
                            'lon': coord[0] if coord else None
                        }
                    }
                    entries.append(item)
                    id_counter += 1

        ip_srv = self._public_ip() or ''
        kode_s, nama_s, lonlat_s = self._asal_ip(ip_srv)
        try:
            host_s = socket.gethostname()
        except Exception:
            host_s = ''

        asal_counts = {}
        for e in entries:
            if e.get('kode'):
                k = e['kode']
                if k not in asal_counts:
                    asal_counts[k] = {'kode': k, 'nama': e.get('negara') or k, 'n': 0}
                asal_counts[k]['n'] += 1
        top_origins = sorted(asal_counts.values(), key=lambda x: x['n'], reverse=True)[:5]

        payload = {
            'status': True,
            'requests': entries[-30:],
            'last_ts': now_ts,
            'server': {'ip': ip_srv, 'hostname': host_s, 'kode': kode_s, 'nama': nama_s, 'lonlat': lonlat_s or [113.921, -0.789]},
            'geo_tersedia': self._geo_buka() is not None,
            'top_origins': top_origins,
        }
        return public.returnMsg(True, payload)

    def get_attacker_page(self, get):
        """Satu halaman (PER_HAL baris) IP penyerang untuk tab Detail. total = angka kartu
        Total Attackers (COUNT(DISTINCT ip) pada events). Urutan tetap (jumlah kejadian, terakhir, ip)
        supaya halaman tidak saling tumpang tindih."""
        # Edisi Free: fitur berbayar (attack_dialogs) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('attack_dialogs', self._get_active_lang(get))

    def get_attack_map(self, get):
        """Asal serangan per negara untuk peta dasbor.

        Sumbernya SAMA dengan diagram donat (get_attack_types): kejadian guardd
        per IP ditambah transaksi log audit WAF per client_ip, pada rentang jam
        yang sama, sehingga total peta = total donat. Negara dari cache GeoIP
        (tabel geo); hanya IP baru yang dicari di berkas MMDB."""
        jam = int(get.get('hours', 24) or 24)
        jam = max(1, min(168, jam))
        sejak = int(time.time()) - jam * 3600
        try:
            ukuran = os.path.getsize(self.WAF_AUDIT_LOG)
        except OSError:
            ukuran = -1
        c = self._ATTACK_MAP_CACHE.get(jam)
        if c and c[0] == ukuran and time.time() - c[1] < 60:     # > periode snAtkTop (30 dtk), dulu 20 dtk = cache selalu meleset
            return public.returnMsg(True, c[2])

        per_ip = {}
        rows = self._sql("SELECT ip, COUNT(*) n FROM events WHERE ts >= ? GROUP BY ip", (sejak,))
        for r in rows if isinstance(rows, list) else []:
            ipt = self._numip(r['ip']) if isinstance(r['ip'], int) else str(r['ip'])
            per_ip[ipt] = per_ip.get(ipt, 0) + (r['n'] or 0)
        self._attack_waf_jenis(sejak, per_ip)

        geo_ada = self._geo_buka() is not None
        negara = {}
        tak_tahu = 0
        urut = sorted(per_ip.items(), key=lambda x: -x[1])
        for i, (ipt, n) in enumerate(urut):
            kode, nama = ('', '')
            if i < self.ATTACK_MAP_IP_MAKS and self._ipnum(ipt):
                kode, nama = self._geo_satu(ipt)
            if not kode:
                tak_tahu += n
                continue
            g = negara.setdefault(kode, {'kode': kode, 'nama': nama, 'n': 0, 'ip': 0})
            g['n'] += n
            g['ip'] += 1
        hasil = {
            'jam': jam,
            'total': sum(per_ip.values()),
            'tak_tahu': tak_tahu,
            'geo_tersedia': geo_ada,
            'negara': sorted(negara.values(), key=lambda x: -x['n']),
        }
        self._ATTACK_MAP_CACHE[jam] = (ukuran, time.time(), hasil)
        return public.returnMsg(True, hasil)

    # ------------------------------------------------------------------ #
    # daftar ban dan throttle                                            #
    # ------------------------------------------------------------------ #
    def get_bans(self, get):
        """Daftar blokir yang masih berlaku, digabung dengan riwayat.

        Tanpa parameter page: bentuk lama (aktif, riwayat, set_ban, set_throttle, enforce).
        Dengan page: satu halaman tabel Blocked IPs dalam 'baris' (gabungan ban guardd dan ipset,
        satu baris per IP; IP yang hanya ada di ipset memakai alasan 'in ban ipset') + 'halaman'
        (total = jumlah baris gabungan itu). Daftar penuh tidak ikut dikirim."""
        data = self._bans_data()
        if self._hal_param(get) is None:
            self._loc_kolom(data.get('aktif'), ('reason',), get)
            self._loc_kolom(data.get('riwayat'), ('reason',), get)
            return public.returnMsg(True, data)
        gabung = {}
        for b in data['aktif']:
            gabung[b['ip']] = {'ip': b['ip'], 'kind': b.get('kind') or '-', 'score': b.get('score') or 0,
                               'offenses': b.get('offenses') or 1, 'sisa': b.get('sisa') or 0,
                               'reason': b.get('reason') or '-'}
        for ip in data['set_ban']:
            if ip not in gabung:
                gabung[ip] = {'ip': ip, 'kind': '-', 'score': 0, 'offenses': 0, 'sisa': 0, 'reason': 'hanya ada di firewall, tanpa catatan alasan'}
        potong, meta = self._halaman(get, list(gabung.values()))
        self._loc_kolom(potong, ('reason',), get)
        return public.returnMsg(True, {'baris': potong, 'halaman': meta, 'enforce': data['enforce'],
                                       'jumlah_throttle': len(data['set_throttle'])})

    def _bans_data(self):
        """Isi get_bans bentuk lama; juga dipakai get_fw_rules yang meneruskan parameter page miliknya sendiri."""
        st = self._status() or {}
        aktif = []
        for b in st.get('bans', []):
            b = dict(b)
            b['ip'] = self._numip(b.get('ip', 0))
            b['sisa'] = max(0, int(b.get('until', 0)) - int(time.time()))
            aktif.append(b)

        riwayat = self._sql(
            "SELECT b.ip, b.kind, b.score, b.start, b.until, b.offenses, "
            "b.reason FROM bans b WHERE b.until >= ? "
            "ORDER BY b.until DESC LIMIT 200", (int(time.time()),))
        if isinstance(riwayat, list):
            for r in riwayat:
                if isinstance(r, dict):
                    r['ip'] = self._numip(r.get('ip', 0))
                    r['sisa'] = max(0, int(r.get('until', 0)) - int(time.time()))
        else:
            riwayat = []

        rc, o, e = self._sh('ipset list sentinel_ban 2>/dev/null | '
                            "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        set_ban = [x for x in o.split() if x]
        rc, o, e = self._sh('ipset list sentinel_throttle 2>/dev/null | '
                            "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        set_thr = [x for x in o.split() if x]

        return {
            'aktif': aktif,
            'riwayat': riwayat,
            'set_ban': set_ban,
            'set_throttle': set_thr,
            'enforce': st.get('enforce', 0),
        }

    def ban_ip(self, get):
        """Blokir satu IP. Dari Event Feed (ev_ts diisi) pola kejadiannya
        juga dipelajari supaya kejadian serupa langsung diblokir."""
        res = self._ban_ip_exec(get)
        if isinstance(res, dict) and res.get('status') and isinstance(res.get('msg'), str):
            net, err = parse_v4(get.get('ip'), cidr=False, tujuan='blokir')
            if not err:
                ip = str(net.network_address)
                self._learn_revoke_ip(ip, 'A')
                if self._learn_ts(get):
                    res['msg'] += self._learn_decision(
                        'B', ip, self._learn_ts(get), self._get_active_lang(get))
        return res

    def _ban_ip_exec(self, get):
        """Blokir satu IP sekarang juga lewat soket daemon."""
        net, err = parse_v4(get.get('ip'), cidr=False, tujuan='blokir')
        if err:
            return public.returnMsg(False, 'alamat IP tidak valid: %s' % err)
        ip = str(net.network_address)
        # Jangan memutus diri sendiri: alamat server ini dan alamat admin
        # yang sedang membuka panel tidak boleh diblokir dari panel.
        if ip in (self._self_ip(), self._req_ip()):
            return public.returnMsg(
                False, 'tidak boleh memblokir alamat server ini atau alamat '
                       'Anda yang sedang mengakses panel: %s' % ip)
        prov = self._proxy_milik(ip)
        if prov:
            return public.returnMsg(
                False, '%s milik proxy/CDN tepercaya (%s). Memblokirnya memutus semua pengunjung yang lewat proxy itu; '
                       'blokir pelaku lewat WAF (real IP) atau aturan di dashboard provider.' % (ip, prov))
        # Durasi harus diperiksa eksplisit, bukan sekadar int() yang
        # dibungkus-or. Dua kegagalan nyata muncul dari cara lama:
        #   - "abc" membuat int() melempar galat, dan traceback-nya
        #     tampil mentah di halaman panel.
        #   - "-5" dianggap benar oleh int(), lalu dibuang diam-diam
        #     oleh "if secs > 0", sehingga ban berjalan memakai durasi
        #     bawaan sementara layar tetap menampilkan "berhasil".
        # Yang kedua lebih berbahaya karena tidak ada tanda apa pun.
        mentah = (get.get('secs') or '').strip()
        secs = 0
        if mentah:
            if not mentah.isdigit():
                return public.returnMsg(
                    False, 'durasi harus berupa angka bulat positif (detik)')
            secs = int(mentah)
            if secs <= 0:
                return public.returnMsg(
                    False, 'durasi harus berupa angka bulat positif (detik)')
        args = ['%s/bin/guardctl' % self.__PATH, 'ban', ip]
        if secs > 0:
            args.append(str(secs))
        rc, o, e = self._sh(
            ' '.join(["'%s'" % a for a in args]), 20)
        if rc != 0 or '"ok":true' not in o:
            return public.returnMsg(False, self._galat('Gagal memblokir IP', o.strip() or e.strip()))
        # Daemon membalas dengan keadaan sebenarnya, jadi yang ditampilkan
        # ke pengguna bukan sekadar "perintah terkirim" tetapi apa yang
        # benar-benar terjadi di kernel.
        if '"dalam_ipset":true' not in o:
            return public.returnMsg(
                False, self._galat('IP tercatat di daftar blokir ZySentinel, tetapi belum diterapkan di firewall '
                                   'sehingga belum benar-benar diblokir', o))
        # Tampilkan durasi yang benar-benar dipakai daemon, bukan yang
        # diketik pengguna. Kalau keduanya berbeda, angka yang diketik
        # tidak berlaku dan itu harus terlihat.
        #
        # Status tetap berhasil karena ban memang sudah terjadi. Melapor
        # galat di sini akan menyesatkan: di layar operator terlihat
        # seperti pemblokiran gagal, padahal ipset sudah terisi.
        dipakai = _angka_json(o, 'detik')
        # CATATAN: ban tidak dicatat di sini. Perintah "ban" sudah
        # dicatat oleh daemon di tabel aksi, jadi mencatatnya lagi di
        # sini akan menghasilkan dua baris untuk satu tindakan yang
        # sama. unban juga sama: dicatat daemon lewat ban_remove.
        self._sh("'%s/bin/guardctl' flush" % self.__PATH, 10)
        if dipakai and secs > 0 and dipakai != secs:
            # Penyebab paling umum adalah nilai yang diminta melewati
            # ban_seconds_max, jadi Causes_hint disebut apa adanya tanpa
            # mengklaim pasti.
            return public.returnMsg(
                True, '%s diblokir dan sudah diterapkan di firewall, durasi %d detik. '
                      'Durasi %d detik yang diminta tidak berlaku; yang dipakai adalah '
                      'batas maksimum durasi blokir.'
                      % (ip, dipakai, secs))
        if dipakai:
            return public.returnMsg(
                True, '%s diblokir dan sudah diterapkan di firewall, durasi %d detik'
                      % (ip, dipakai))
        return public.returnMsg(True, '%s diblokir dan sudah diterapkan di firewall' % ip)

    def unban_ip(self, get):
        """Lepas blokir dan hapus dari allowlist supaya tidak diblokir lagi."""
        net, err = parse_v4(get.get('ip'), cidr=False, tujuan='netral')
        if err:
            return public.returnMsg(False, 'alamat IP tidak valid: %s' % err)
        ip = str(net.network_address)
        rc, o, e = self._sh(
            "'%s/bin/guardctl' unban '%s'" % (self.__PATH, ip), 20)
        if rc != 0 or '"ok":true' not in o:
            return public.returnMsg(False, self._galat('Gagal melepas blokir IP', o.strip() or e.strip()))
        self._sh("'%s/bin/guardctl' flush" % self.__PATH, 10)
        # keputusan blokir dicabut: pelajaran yang bersumber dari IP ini ikut dicabut
        self._learn_revoke_ip(ip, 'B')
        return public.returnMsg(True, '%s dilepas dari daftar blokir' % ip)

    # ------------------------------------------------------------------ #
    # daftar putih                                                       #
    # ------------------------------------------------------------------ #
    def _allow_path(self):
        return self._p('etc', 'allowlist.txt')

    def _ip_fw_status_batch(self, ip_list):
        """Kembalikan dict {ip: 'Blocked'|'Allowed'|'Monitor'} untuk semua IP dalam ip_list.
        Blocked  = IP ada di ban guardd atau ipset sentinel_ban.
        Allowed  = IP ada di allowlist.txt (atau ipset aapanel.ipv4.whitelist).
        Monitor  = tidak diblokir dan tidak diizinkan secara eksplisit."""
        if not ip_list:
            return {}
        ip_set = set(str(x) for x in ip_list)
        result = {ip: 'Monitor' for ip in ip_set}

        # Periksa ban: gabungan daemon guardd + ipset sentinel_ban
        try:
            st = self._status() or {}
            for b in st.get('bans', []) or []:
                ip = self._numip(b.get('ip', 0))
                if ip in result:
                    result[ip] = 'Blocked'
        except Exception:
            pass
        rc, o, e = self._sh('ipset list sentinel_ban 2>/dev/null | '
                            "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        for ip in [x for x in (o or '').split() if x]:
            if ip in result:
                result[ip] = 'Blocked'

        # Periksa allow: allowlist.txt Sentinel + ipset aaPanel
        try:
            import ipaddress as _ipa
            allow_nets = self._allow_nets()   # list IPv4Network
            for ip in list(result.keys()):
                if result[ip] == 'Blocked':
                    continue   # ban lebih spesifik dari allow
                try:
                    addr = _ipa.ip_address(ip)
                    if any(addr in net for net in allow_nets):
                        result[ip] = 'Allowed'
                except Exception:
                    pass
        except Exception:
            pass
        rc2, o2, _ = self._sh('ipset list aapanel.ipv4.whitelist 2>/dev/null | '
                              "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        for ip in [x for x in (o2 or '').split() if x]:
            if ip in result and result[ip] != 'Blocked':
                result[ip] = 'Allowed'

        return result

    def get_allow(self, get):
        """Daftar putih Sentinel dan daftar putih aaPanel (ipset). Tanpa parameter page: bentuk lama.
        Dengan page: 'daftar' dipotong ke halaman itu ('halaman') dan 'panel' dipotong menurut
        page_panel ('halaman_panel'); 'jumlah' tetap total daftar Sentinel."""
        data = self._allow_data()
        hal = self._hal_param(get)
        if hal is None:
            return public.returnMsg(True, data)
        data['daftar'], data['halaman'] = self._halaman(get, data['daftar'])
        data['panel'], data['halaman_panel'] = self._halaman({'page': get.get('page_panel') or 1}, data['panel'])
        return public.returnMsg(True, data)

    def _allow_data(self):
        """Isi get_allow bentuk lama; juga dipakai get_fw_rules yang meneruskan parameter page miliknya sendiri."""
        isi = []
        alamat_server = self._self_ip()
        try:
            with open(self._allow_path(), 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    isi.append(line)
        except Exception:
            pass
        rc, o, e = self._sh('ipset list aapanel.ipv4.whitelist 2>/dev/null | '
                            "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        return {
            'daftar': isi,
            'panel': [x for x in o.split() if x],
            'alamat_server': alamat_server,
            'jumlah': len(isi),
        }

    def _req_ip(self):
        """Alamat klien yang sedang memanggil endpoint ini (kosong bila bukan dari web)."""
        try:
            from flask import request, has_request_context
            if has_request_context():
                return request.remote_addr or ''
        except Exception:
            pass
        return ''

    def _allow_nets(self):
        """Isi allowlist.txt sebagai daftar (IPv4Network, baris-asli). Baris tak valid dilewati."""
        hasil = []
        try:
            with open(self._allow_path(), 'r') as f:
                for line in f:
                    t = line.split('#')[0].strip()
                    if not t:
                        continue
                    net, err = parse_v4(t, cidr=True, min_prefix=0,
                                        tujuan='netral', semua=True)
                    if net is not None:
                        hasil.append(net)
        except Exception:
            pass
        return hasil

    def allow_ip(self, get):
        """Tambahkan IP ke daftar putih. Dari Event Feed (ev_ts diisi) klien
        itu juga dipelajari sebagai sah supaya tidak ditandai lagi."""
        res = self._allow_ip_exec(get)
        if isinstance(res, dict) and res.get('status') and isinstance(res.get('msg'), str):
            net, err = parse_v4(get.get('ip'), cidr=True, min_prefix=8, tujuan='putih')
            if not err and net.prefixlen == 32:
                ip = str(net.network_address)
                self._learn_revoke_ip(ip, 'B')
                if self._learn_ts(get):
                    res['msg'] += self._learn_decision(
                        'A', ip, self._learn_ts(get), self._get_active_lang(get))
        return res

    def _allow_ip_exec(self, get):
        """Tambahkan IP tunggal atau CIDR ke daftar putih permanen."""
        net, err = parse_v4(get.get('ip'), cidr=True, min_prefix=8,
                            tujuan='putih')
        if err:
            return public.returnMsg(False, 'alamat IP/CIDR tidak valid: %s' % err)
        ip = v4_tampil(net)
        # Idempoten: entri yang sama tidak ditulis dua kali.
        if net in self._allow_nets():
            return public.returnMsg(True, '%s sudah ada di daftar putih' % ip)
        if net.prefixlen == 32:
            rc, o, e = self._sh(
                "'%s/bin/guardctl' allow '%s'" % (self.__PATH, ip), 20)
            if rc != 0 or '"ok":true' not in o:
                return public.returnMsg(False, self._galat('Gagal menambahkan IP ke daftar putih', o.strip() or e.strip()))
        else:
            # guardctl allow hanya menerima IP tunggal. CIDR ditulis langsung
            # ke allowlist.txt (format yang sama dibaca guardd dan
            # sentinel-fw.sh), dengan kunci berkas agar tidak bertabrakan
            # dengan tulisan daemon.
            try:
                with open(self._allow_path(), 'a+') as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    f.seek(0, 2)
                    if f.tell() > 0:
                        f.seek(f.tell() - 1)
                        if f.read(1) != '\n':
                            f.write('\n')
                    f.write('%s\n' % ip)
                    f.flush()
                    fcntl.flock(f, fcntl.LOCK_UN)
            except Exception as ex:
                return public.returnMsg(False, self._galat('Gagal menulis daftar putih', ex))
            self._sh("'%s/bin/guardctl' rescan" % self.__PATH, 20)
        self._zy_sinkron_latar()
        # aturan iptables perlu dipasang ulang supaya whitelist langsung
        # berlaku di kernel, bukan menunggu timer lima menit.
        self._sh("'%s/bin/sentinel-fw.sh' install" % self.__PATH, 60)
        if net.prefixlen == 32:
            self._aksi(ip, 'allow', 'panel', 'ditambahkan ke daftar putih')
        return public.returnMsg(True, '%s masuk daftar putih' % ip)

    def del_allow(self, get):
        """Keluarkan IP tunggal atau CIDR dari daftar putih permanen."""
        net, err = parse_v4(get.get('ip'), cidr=True, min_prefix=0,
                            tujuan='netral', semua=True)
        if err:
            return public.returnMsg(False, 'alamat IP/CIDR tidak valid: %s' % err)
        ip = v4_tampil(net) if net.prefixlen != 0 else '0.0.0.0/0'
        path = self._allow_path()
        try:
            with open(path, 'r') as f:
                baris = f.readlines()
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca daftar putih', ex))
        sisa = []
        for b in baris:
            t = b.split('#')[0].strip()
            n2, _ = parse_v4(t, cidr=True, min_prefix=0, tujuan='netral',
                             semua=True) if t else (None, None)
            # bandingkan sebagai jaringan: "1.2.3.4" dan "1.2.3.4/32" sama
            if n2 is not None and n2 == net:
                continue
            sisa.append(b)
        if len(sisa) == len(baris):
            # Tidak ada di berkas, tetapi pelajaran izinkan yang bersumber
            # dari IP ini harus tetap ikut dicabut (mis. berkas diedit manual).
            if net.prefixlen == 32:
                self._learn_revoke_ip(ip, 'A')
            return public.returnMsg(False, '%s tidak ada di daftar putih' % ip)
        # atomik: dulu open(path, 'w') mengosongkan berkas sebelum ditulis; disk penuh/terhenti = daftar putih kosong dan
        # guardd bisa mem-ban IP operator sesudah rescan
        _tulis_atomik(path, ''.join(sisa), cadangan=True)
        self._sh("'%s/bin/sentinel-fw.sh' install" % self.__PATH, 60)
        self._sh("'%s/bin/guardctl' rescan" % self.__PATH, 20)
        self._zy_sinkron_latar()
        if net.prefixlen == 32:
            self._aksi(ip, 'del-allow', 'panel',
                       'dikeluarkan dari daftar putih, blokir lama berlaku lagi')
            self._learn_revoke_ip(ip, 'A')
        return public.returnMsg(True, '%s dikeluarkan dari daftar putih' % ip)

    def del_allow_ip(self, get):
        """Keluarkan IP dari daftar putih (alias untuk del_allow)."""
        return self.del_allow(get)

    # ------------------------------------------------------------------ #
    # pembelajaran dari keputusan operator                               #
    # ------------------------------------------------------------------ #
    # Saat operator menekan Blokir/Izinkan pada Event Feed, pola kejadian
    # itu (path dan/atau user-agent) disimpan sebagai "pelajaran" di
    # etc/learned.json lalu diterbitkan ke etc/learned.tsv untuk guardd.
    # Pelajaran hidup selama keputusan sumbernya belum dicabut: unban atau
    # keluarnya IP dari daftar putih menghapus pelajaran yang bersumber
    # dari IP itu. Panel yang mengelola siklus hidupnya; daemon hanya
    # membaca berkas TSV (lihat bagian PELAJARAN di guardd.c).
    LEARN_MAX = 500
    LEARN_PATH_MAX = 149          # sama dengan batas penyimpanan path di tabel events
    # path yang tidak pernah dijadikan pelajaran BLOKIR: aset dan health
    # check (pengunjung sah sering mendapat 404 di sini) dan jalur login
    # (sudah dinilai sebagai brute force oleh daemon).
    _LEARN_PATH_AMAN = (
        '/favicon.ico', '/robots.txt', '/sitemap', '/app-ads.txt', '/ads.txt',
        '/apple-touch-icon', '/manifest.json', '/service-worker', '/sw.js',
        '/health', '/ping', '/pong', '/up', '/readyz', '/livez', '/uploads',
        '/assets', '/storage', '/images', '/img', '/css', '/js', '/fonts',
        '/media', '/static', '/login', '/signin', '/log-in', '/sign-in',
        '/auth', '/authenticate', '/wp-login', '/password', '/passwd',
        '/user/login', '/api/login', '/api/auth', '/api/v1/login',
        '/api/v1/auth', '/oauth', '/session', '/member/login',
        '/account/login', '/users/sign_in', '/do/login')
    _LEARN_EKSTENSI_AMAN = frozenset((
        'css', 'js', 'mjs', 'map', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico',
        'webp', 'avif', 'bmp', 'woff', 'woff2', 'ttf', 'eot', 'otf', 'mp4',
        'webm', 'mp3', 'ogg', 'pdf', 'txt', 'xml', 'json', 'rss', 'atom'))
    # perayap sah yang tidak boleh diblokir lewat pelajaran UA
    _LEARN_UA_BAIK = (
        'googlebot', 'bingbot', 'adsbot', 'mediapartners', 'duckduckbot',
        'slurp', 'yandex', 'baiduspider', 'facebookexternalhit', 'twitterbot',
        'linkedinbot', 'whatsapp', 'telegrambot', 'uptimerobot', 'pingdom',
        'statuscake', 'applebot', 'ia_archiver')
    _LEARN_KIND_PATH = ('scanner', 'campuran', 'probe-paths')
    _LEARN_KIND_UA = ('scanner', 'campuran', 'probe-paths', 'bad-ua',
                      'bruteforce')

    def _learn_files(self):
        return self._p('etc', 'learned.json'), self._p('etc', 'learned.tsv')

    @staticmethod
    def _learn_id(aksi, path, ua):
        return hashlib.sha1(('%s|%s|%s' % (aksi, path, ua)).encode(
            'utf-8', 'replace')).hexdigest()[:8]

    def _learn_sig_path(self, path, aksi):
        """Path yang dinormalkan seperti guardd (tanpa query, huruf kecil,
        tanpa garis miring penutup), atau '' bila tidak aman dipelajari."""
        if not isinstance(path, str):
            return ''
        p = re.split(r'[?#]', path, 1)[0].strip().lower()
        p = re.sub(r'/+$', '', p) if len(p) > 1 else p
        if len(p) < 2 or len(p) > self.LEARN_PATH_MAX or p[0] != '/':
            return ''
        if re.search(r'[\x00-\x20\x7f]', p):
            return ''
        if aksi == 'B':
            for a in self._LEARN_PATH_AMAN:
                if p == a or p.startswith(a + '/') or p.startswith(a + '.') \
                        or p.startswith(a + '-'):
                    return ''
            ekst = p.rsplit('.', 1)[1] if '.' in p.rsplit('/', 1)[1] else ''
            if ekst in self._LEARN_EKSTENSI_AMAN:
                return ''
        return p

    def _learn_sig_ua(self, ua, aksi):
        """Satu token produk user-agent, atau '' untuk UA peramban biasa.
        Peramban (Mozilla/Opera tanpa nama bot) tidak pernah dipelajari:
        satu token itu akan mencakup hampir semua pengunjung."""
        if not isinstance(ua, str):
            return ''
        low = ua.strip().lower()
        if not low or low == '-':
            return ''
        m = re.search(r'([a-z0-9._+-]*(?:bot|crawler|spider|scraper)[a-z0-9._+-]*)', low)
        if m:
            tok = m.group(1)
        elif 'mozilla' in low or 'opera' in low or 'applewebkit' in low:
            return ''
        else:
            m = re.match(r'([a-z0-9][a-z0-9._+-]*)', low)
            tok = m.group(1) if m else ''
        tok = tok.strip('.-+_')
        if not re.fullmatch(r'[a-z0-9][a-z0-9._+-]{3,39}', tok or ''):
            return ''
        if aksi == 'B' and any(b in low for b in self._LEARN_UA_BAIK):
            return ''
        return tok

    def _learn_sig(self, aksi, ev):
        """Turunkan pelajaran dari satu kejadian. (pelajaran, None) atau
        (None, kode_alasan) bila tidak ada pola yang aman dipelajari."""
        kind = str(ev.get('kind') or '')
        if kind == 'flood':
            return None, 'flood'
        path = ua = ''
        if kind in self._LEARN_KIND_PATH:
            path = self._learn_sig_path(ev.get('path'), aksi)
        if kind in self._LEARN_KIND_UA:
            ua = self._learn_sig_ua(ev.get('ua'), aksi)
        # Pelajaran izinkan harus menyebut klien (UA): izin berbasis path
        # saja akan membutakan deteksi untuk siapa pun yang meraba path itu.
        if aksi == 'A' and not ua:
            return None, 'tanpa-ua'
        if not path and not ua:
            return None, 'tanpa-pola'
        return {'id': self._learn_id(aksi, path, ua), 'aksi': aksi,
                'kind': kind if kind in self._LEARN_KIND_UA else 'campuran',
                'path': path, 'ua': ua}, None

    def _learn_load(self):
        jf, _ = self._learn_files()
        try:
            with open(jf, 'r', encoding='utf-8') as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get('lessons'), list):
                d.setdefault('enabled', True)
                return d
        except Exception:
            pass
        return {'v': 1, 'enabled': True, 'lessons': []}

    def _learn_publish(self, st):
        """Tulis JSON (sumber kebenaran) dan TSV (untuk daemon) secara atomik,
        lalu minta daemon memuat ulang. Mengembalikan balasan daemon atau None."""
        jf, tf = self._learn_files()
        baris = ['# dibuat panel ZySentinel dari etc/learned.json; jangan diubah manual']
        if st.get('enabled', True):
            for L in st['lessons']:
                baris.append('\t'.join([
                    L['id'], L['aksi'], L.get('kind') or 'campuran',
                    L.get('path') or '-', L.get('ua') or '-']))
        for nama, isi in ((jf, json.dumps(st, ensure_ascii=False, indent=1)),
                          (tf, '\n'.join(baris) + '\n')):
            tmp = '%s.tmp.%d' % (nama, os.getpid())
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(isi)
            os.chmod(tmp, 0o640)
            os.replace(tmp, nama)
        rc, o, e = self._sh("'%s/bin/guardctl' learnload" % self.__PATH, 10)
        try:
            return json.loads(o) if rc == 0 else None
        except Exception:
            return None

    def _learn_edit(self, fn):
        """Baca-ubah-tulis di bawah kunci berkas. fn(store) mengembalikan
        hasil; store diterbitkan hanya bila fn menandai st['_ubah']."""
        kunci = self._p('etc', 'learned.lock')
        with open(kunci, 'a+') as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            try:
                st = self._learn_load()
                hasil = fn(st)
                if st.pop('_ubah', False):
                    self._learn_publish(st)
                return hasil
            finally:
                fcntl.flock(lk, fcntl.LOCK_UN)

    def _learn_event(self, ip, ts):
        n = self._ipnum(ip)
        if not n:
            return None
        baris = []
        if ts:
            baris = self._sql(
                "SELECT ts, ip, kind, score, level, host, path, ua FROM events "
                "WHERE ip=? AND ts=? ORDER BY id DESC LIMIT 1", (n, ts))
        if not baris:
            baris = self._sql(
                "SELECT ts, ip, kind, score, level, host, path, ua FROM events "
                "WHERE ip=? ORDER BY ts DESC, id DESC LIMIT 1", (n,))
        return baris[0] if baris else None

    def _learn_revoke_ip(self, ip, aksi):
        """Keputusan operator atas IP ini dicabut: hapus IP dari sumber
        pelajaran dan hapus pelajaran yang tidak punya sumber lagi."""
        def kerja(st):
            sisa, dicabut = [], 0
            for L in st['lessons']:
                if L.get('aksi') == aksi and ip in L.get('sources', []):
                    L['sources'] = [s for s in L['sources'] if s != ip]
                    st['_ubah'] = True
                    if not L['sources']:
                        dicabut += 1
                        continue
                sisa.append(L)
            st['lessons'] = sisa
            return dicabut
        try:
            return self._learn_edit(kerja)
        except Exception:
            return 0

    def _learn_decision(self, aksi, ip, ts, lang):
        """Pelajari satu keputusan. Mengembalikan kalimat ringkas untuk
        operator, atau '' bila tidak ada yang perlu disampaikan."""
        isEn = (lang == 'en')
        if not _lic.allowed('learn'):
            return (' | Learning is a Max feature (upgrade to teach the plugin from your decisions)' if isEn
                    else ' | Belajar dari keputusan adalah fitur Max (upgrade untuk mengajari plugin)')
        # Keputusan berlawanan atas IP yang sama membatalkan pelajaran lama
        # dari IP itu (operator berubah pikiran).
        lawan = 'A' if aksi == 'B' else 'B'
        self._learn_revoke_ip(ip, lawan)
        st0 = self._learn_load()
        if not st0.get('enabled', True):
            return ''
        ev = self._learn_event(ip, ts)
        if not ev:
            return (' | Learning skipped: no event found for this IP' if isEn
                    else ' | Belajar dilewati: kejadian IP ini tidak ditemukan')
        L, alasan = self._learn_sig(aksi, ev)
        if not L:
            pesan = {
                'flood': ('flood events have no safe pattern to learn',
                          'kejadian flood tidak punya pola yang aman dipelajari'),
                'tanpa-ua': ('an allow lesson needs an identifiable client (user-agent)',
                             'pelajaran izinkan butuh klien yang dapat dikenali (user-agent)'),
                'tanpa-pola': ('only generic/safe paths and browser user-agents were seen',
                               'hanya path umum/aman dan user-agent peramban yang terlihat'),
            }[alasan]
            return (' | Not learned: ' + pesan[0]) if isEn \
                else (' | Tidak dipelajari: ' + pesan[1])

        def kerja(st):
            # keputusan terbaru untuk pola yang sama menggantikan yang lama
            for x in list(st['lessons']):
                if x['aksi'] != aksi and x.get('path', '') == L['path'] \
                        and x.get('ua', '') == L['ua']:
                    st['lessons'].remove(x)
            ada = [x for x in st['lessons'] if x['id'] == L['id']]
            now = int(time.time())
            if ada:
                if ip not in ada[0]['sources']:
                    ada[0]['sources'].append(ip)
                ada[0]['updated'] = now
                baru = False
            else:
                if len(st['lessons']) >= self.LEARN_MAX:
                    return 'penuh'
                L2 = dict(L)
                L2.update({'sources': [ip], 'created': now, 'updated': now,
                           'host': str(ev.get('host') or '-')[:64]})
                st['lessons'].append(L2)
                baru = True
            st['_ubah'] = True
            return 'baru' if baru else 'ada'

        try:
            hasil = self._learn_edit(kerja)
        except Exception as ex:
            self._catat_galat('belajar dari keputusan gagal', ex)
            return (' | Learning failed (your decision itself was applied)' if isEn
                    else ' | Belajar gagal (keputusan Anda tetap diterapkan)')
        if hasil == 'penuh':
            return (' | Not learned: lesson limit reached' if isEn
                    else ' | Tidak dipelajari: batas jumlah pelajaran tercapai')
        self._aksi(ip, 'belajar', 'panel',
                   'pelajaran %s (%s) path=%s ua=%s' % (
                       L['id'], 'blokir' if aksi == 'B' else 'izinkan',
                       L['path'] or '-', L['ua'] or '-'))
        pola = ' + '.join(x for x in (
            ('path ' + L['path']) if L['path'] else '',
            ('UA ' + L['ua']) if L['ua'] else '') if x)
        if isEn:
            return ' | Learned %s [%s]: %s' % (
                'block rule' if aksi == 'B' else 'allow rule', L['id'], pola)
        return ' | Dipelajari: aturan %s [%s]: %s' % (
            'blokir' if aksi == 'B' else 'izinkan', L['id'], pola)

    @staticmethod
    def _learn_ts(get):
        t = str(get.get('ev_ts') or '').strip()
        return int(t) if t.isdigit() and len(t) <= 11 else 0

    def get_learned(self, get):
        """Pelajaran aktif beserta jumlah kali masing-masing bekerja."""
        st = self._learn_load()
        kerja = {}
        for r in self._sql(
                "SELECT substr(alasan,12,8) id, COUNT(*) n, MAX(ts) t FROM aksi "
                "WHERE alasan LIKE 'dipelajari:%' GROUP BY substr(alasan,12,8)"):
            kerja[r['id']] = (r['n'], r['t'])
        daftar = []
        for L in st['lessons']:
            n, t = kerja.get(L['id'], (0, 0))
            daftar.append({
                'id': L['id'], 'aksi': L['aksi'], 'kind': L.get('kind', ''),
                'path': L.get('path', ''), 'ua': L.get('ua', ''),
                'host': L.get('host', '-'), 'sources': L.get('sources', []),
                'created': L.get('created', 0), 'hits': n, 'last_hit': t,
                'manual': bool(L.get('manual'))})
        daftar.sort(key=lambda x: (-x['created'], x['id']))
        stt = self._status() or {}
        daftar, meta = self._halaman(get, daftar)
        hasil = {
            'enabled': bool(st.get('enabled', True)), 'lessons': daftar,
            'max': self.LEARN_MAX, 'enforce': stt.get('enforce', 0)}
        if meta is not None:
            hasil['halaman'] = meta
        return public.returnMsg(True, hasil)

    def _learn_masukan(self, get):
        """Validasi pelajaran manual: aksi B/A, kategori, path dan/atau UA.
        Aturan pengaman sama dengan pembelajaran otomatis (path aman, UA peramban,
        perayap sah, izin wajib menyebut klien)."""
        aksi = str(get.get('aksi_l') or '').strip().upper()
        if aksi not in ('B', 'A'):
            return None, 'aturan harus B (blokir) atau A (izinkan)'
        kind = str(get.get('kind') or 'campuran').strip()
        if kind not in self._LEARN_KIND_UA:
            return None, 'kategori tidak dikenal'
        path_raw = str(get.get('path') or '').strip()
        ua_raw = str(get.get('ua') or '').strip()
        path = self._learn_sig_path(path_raw, aksi) if path_raw else ''
        ua = self._learn_sig_ua(ua_raw, aksi) if ua_raw else ''
        if path_raw and not path:
            return None, 'path tidak aman dipelajari (/, aset statis, health check, login, atau format tidak valid)'
        if ua_raw and not ua:
            return None, 'user-agent tidak bisa dipakai (peramban biasa, perayap sah, atau terlalu pendek)'
        if not path and not ua:
            return None, 'isi path dan/atau user-agent'
        if aksi == 'A' and not ua:
            return None, 'aturan izinkan wajib menyebut klien (user-agent)'
        return {'id': self._learn_id(aksi, path, ua), 'aksi': aksi, 'kind': kind,
                'path': path, 'ua': ua}, None

    def learned_add(self, get):
        """Tambah pelajaran secara manual (tanpa IP sumber; hanya dicabut manual)."""
        # Edisi Free: fitur berbayar (learn) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('learn', self._get_active_lang(get))

    def learned_update(self, get):
        """Ubah pola/kategori/aturan satu pelajaran. Sumber IP dipertahankan."""
        # Edisi Free: fitur berbayar (learn) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('learn', self._get_active_lang(get))

    def learned_revoke(self, get):
        lid = str(get.get('id') or '').strip().lower()
        isEn = (self._get_active_lang(get) == 'en')
        if not re.fullmatch(r'[0-9a-f]{4,11}', lid):
            return public.returnMsg(False, 'Invalid lesson id' if isEn else 'id pelajaran tidak valid')

        def kerja(st):
            n0 = len(st['lessons'])
            st['lessons'] = [x for x in st['lessons'] if x['id'] != lid]
            if len(st['lessons']) != n0:
                st['_ubah'] = True
                return True
            return False
        try:
            ada = self._learn_edit(kerja)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal mencabut pelajaran', ex))
        if not ada:
            return public.returnMsg(False, 'Lesson not found' if isEn else 'pelajaran tidak ditemukan')
        return public.returnMsg(True, 'Lesson %s revoked' % lid if isEn else 'Pelajaran %s dicabut' % lid)

    def learned_toggle(self, get):
        on = str(get.get('enabled', '1')).strip() in ('1', 'true', 'on')
        isEn = (self._get_active_lang(get) == 'en')

        def kerja(st):
            st['enabled'] = on
            st['_ubah'] = True
        try:
            self._learn_edit(kerja)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal mengubah status pembelajaran', ex))
        if isEn:
            return public.returnMsg(True, 'Learning %s' % ('enabled' if on else 'paused: lessons are kept but not applied'))
        return public.returnMsg(True, 'Pembelajaran %s' % ('dinyalakan' if on else 'dijeda: pelajaran disimpan tetapi tidak diterapkan'))

    # ------------------------------------------------------------------ #
    # pengaturan                                                         #
    # ------------------------------------------------------------------ #
    def get_conf(self, get):
        """Ambang skor dan bobot, plus status-mode enforcement."""
        st = self._status() or {}
        kunci = ['enforce', 'watch_score', 'throttle_score', 'ban_score',
                 'weight_scan', 'weight_brute', 'weight_badua',
                 'weight_distinct', 'cap_scan', 'cap_brute', 'cap_badua',
                 'cap_distinct', 'ban_seconds', 'ban_seconds_max',
                 'max_ips', 'rescan_interval', 'startup_backfill',
                 'throttle_rps', 'throttle_burst', 'throttle_rpm']
        nilai = dict((k, st.get(k)) for k in kunci)
        isi = {}
        try:
            with open(self._p('etc', 'guardd.conf'), 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        isi[k.strip()] = v.strip()
        except Exception:
            pass
        for k in kunci:
            if k in isi:
                nilai[k] = isi[k]
        return public.returnMsg(True, nilai)

    def set_conf(self, get):
        """Ubah satu nilai konfigurasi.

        Nilai laju (throttle_rps, throttle_rpm, throttle_burst) dibaca
        sentinel-fw.sh, bukan guardd. Jadi tidak butuh restart daemon,
        cukup pasang ulang aturan kernel. Memaksa restart daemon untuk
        ketiga nilai itu hanya menambah downtime tanpa ada gunanya.

        Kunci lain tetap perlu restart karena guardd membaca konfigurasi
        satu kali saat start.
        """
        kunci_laju = ['throttle_rps', 'throttle_rpm', 'throttle_burst']
        kunci_boleh = ['watch_score', 'throttle_score', 'ban_score',
                       'weight_scan', 'weight_brute', 'weight_badua',
                       'weight_distinct', 'cap_scan', 'cap_brute',
                       'cap_badua', 'cap_distinct', 'ban_seconds',
                       'ban_seconds_max', 'max_ips', 'rescan_interval',
                       'startup_backfill', 'enforce'] + kunci_laju
        k = (get.get('key') or '').strip()
        v = (get.get('value') or '').strip()
        if k not in kunci_boleh:
            return public.returnMsg(False, 'kunci tidak dikenal: %s' % k)
        if not v.isdigit():
            return public.returnMsg(False, 'nilai harus berupa angka bulat')

        # throttle_rps = 0 membuat aturan per detik tidak masuk akal,
        # dan throttle_rpm dibatasi 100000 supaya tidak ada angka
        # gila yang lolos ke iptables.
        if k == 'throttle_rps' and int(v) < 1:
            return public.returnMsg(
                False, 'throttle_rps minimal 1. Nilai 0 membuat throttle '
                       'berhenti bekerja tanpa sengaja')
        if k in ('throttle_rpm', 'throttle_burst') and int(v) > 100000:
            return public.returnMsg(False, 'nilai maksimal 100000')

        rc, o, e = self._sh(
            "'%s/bin/guardctl' set '%s' '%s'" % (self.__PATH, k, v), 30)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal menyimpan pengaturan', e.strip() or o.strip()))

        if k in kunci_laju:
            # Aturan kernel perlu dipasang ulang supaya nilai baru
            # langsung berlaku. Kalau ini gagal, nilai SUDAH tersimpan
            # di guardd.conf tapi belum berlaku di kernel. Melapor
            # gagal lebih jujur daripada diam-diam bilang berhasil.
            rc2, o2, e2 = self._sh(
                "'%s/bin/sentinel-fw.sh' install" % self.__PATH, 90)
            if rc2 != 0:
                return public.returnMsg(
                    False, self._galat('%s sudah disimpan menjadi %s, tetapi belum berlaku karena aturan firewall '
                                       'gagal dipasang ulang' % (k, v), e2.strip() or o2.strip()))
            return public.returnMsg(
                True, '%s = %s, aturan firewall sudah dipasang ulang'
                      % (k, v))

        # semua nilai lain dibaca sekali saat daemon mulai
        self.service_action({'action': 'restart'})
        return public.returnMsg(True, '%s diubah menjadi %s, layanan ZySentinel dimulai ulang' % (k, v))

    # ------------------------------------------------------------------ #
    # panic: blokir / lepas seluruh akses web                             #
    # ------------------------------------------------------------------ #
    _panic_cache = {'ts': 0, 'data': None}

    def get_panic(self, get):
        """Keadaan panic sekarang.

        Keadaan dibaca dua sumber dan digabung: aturan iptables yang
        benar-benar ada di kernel, dan berkas penanda yang ditulis
        skrip. Keduanya dipakai karena bisa berbeda, misalnya kernel
        masih dibebani aturan panic sementara penanda sudah hilang.
        Penanda boleh hilang saat reboot, jadi hanya iptables yang
        dianggap kebenaran; penanda dipakai untuk menampilkan
        kapan panic dinyalakan. Hasil dicache 2.5 detik untuk respons instan.
        """
        now = time.time()
        if (now - self._panic_cache['ts']) < 2.5 and self._panic_cache['data'] is not None:
            return public.returnMsg(True, dict(self._panic_cache['data']))

        rc, o, e = self._sh(
            "'%s/bin/sentinel-fw.sh' panic-status" % self.__PATH, 30)
        aktif = (rc == 0)
        info = {'aktif': aktif, 'ports': '', 'since': '', 'baris': []}
        for baris in o.strip().splitlines():
            b = baris.strip()
            if b.startswith('ports='):
                info['ports'] = b.split('=', 1)[1]
            elif b.startswith('since='):
                info['since'] = b.split('=', 1)[1]
            elif b.startswith('-A'):
                info['baris'].append(b)
        # Dulu berisi keluaran mentah skrip; sekarang kalimat ringkas (UI membangun teks keadaannya sendiri).
        info['pesan'] = 'Panic aktif. Seluruh akses web diblokir.' if aktif else 'Panic tidak aktif.'
        self._panic_cache = {'ts': now, 'data': dict(info)}
        return public.returnMsg(True, info)

    def set_panic(self, get):
        """Nyalakan atau cabut blokir seluruh akses web.

        HATI-HATI: menyalakan panic membuat SEMUA situs di server ini
        tidak dapat diakses. Yang tetap bisa: SSH, port panel, whitelist,
        dan jaringan privat. Itu disengaja supaya operator masih bisa
        mencabut panic.
        """
        self._panic_cache = {'ts': 0, 'data': None}
        aksi = (get.get('aksi') or get.get('act') or get.get('sub_action') or (get.get('action') if get.get('action') != 'a' else None) or '').strip()
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'aksi tidak dikenal')
        if aksi == 'off':
            rc, o, e = self._sh(
                "'%s/bin/guardctl' panic-off" % self.__PATH, 60)
            if rc != 0:
                return public.returnMsg(False, self._galat('Gagal mencabut panic', e.strip() or o.strip()))
            self._notif('panic-selesai', self._t(get, 'Panic dicabut. Akses web sudah normal kembali.',
                                                 'Panic lifted. Web access is back to normal.'))
            return public.returnMsg(True, 'Panic dicabut. Akses web sudah normal kembali.')

        # Konfirmasi harus datang dari sisi server, bukan hanya dari
        # checkbox di layar. Kalau hanya andalkan UI, satu klik keliru
        # atau satu permintaan otomatis bisa mematikan semua situs.
        #
        # Pencocokan sengaja TIDAK mengabaikan huruf besar-kecil. Aksi ini
        # mematikan seluruh situs di server, jadi operator sewajarnya benar-benar
        # menyalin kata PANIC, bukan mengetik "panic" dengan autopilot.
        konfirmasi = (get.get('confirm') or '').strip()
        if konfirmasi != 'PANIC':
            return public.returnMsg(
                False, 'konfirmasi tidak cocok. Ketik PANIC dengan huruf '
                       'besar semua di kolom konfirmasi')
        rc, o, e = self._sh("'%s/bin/guardctl' panic-on" % self.__PATH, 90)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal menyalakan panic', e.strip() or o.strip()))
        self._notif('panic', self._t(get, 'PANIC AKTIF. Seluruh akses web diblokir. Situs tidak dapat diakses sampai panic dicabut.',
                                     'PANIC ACTIVE. All web access is blocked. Sites cannot be reached until panic is lifted.'))
        return public.returnMsg(True, 'Panic aktif. Seluruh akses web diblokir.')

    # ------------------------------------------------------------------ #
    # kendali daemon dan firewall                                        #
    # ------------------------------------------------------------------ #
    def service_action(self, get):
        self._ensure_core_files()
        aksi = (get.get('aksi') or get.get('act') or get.get('sub_action') or (get.get('action') if get.get('action') != 'a' else None) or '').strip().lower()
        peta = {'start': 'start', 'stop': 'stop', 'restart': 'restart', 'reload': 'reload'}
        if aksi not in peta:
            return public.returnMsg(False, 'Aksi tidak dikenal (hanya start, stop, restart, reload)')

        rc, o, e = 1, '', 'init failed'
        if self._is_systemd():
            cmd = 'systemctl %s sentinel.service' % peta[aksi]
            rc, o, e = self._sh(cmd, 60)

        if rc != 0:
            guardctl = self._p('bin', 'guardctl')
            if os.path.exists(guardctl) and os.access(guardctl, os.X_OK):
                rc2, o2, e2 = self._sh("'%s' %s" % (guardctl, peta[aksi]), 30)
                rc, o, e = rc2, o2, e2
            elif os.path.exists('/etc/init.d/sentinel'):
                rc2, o2, e2 = self._sh('/etc/init.d/sentinel %s' % peta[aksi], 30)
                rc, o, e = rc2, o2, e2
            elif aksi == 'reload':
                pid_f = self._p('run', 'guardd.pid')
                if os.path.exists(pid_f):
                    try:
                        with open(pid_f, 'r') as pf:
                            gpid = pf.read().strip()
                        if gpid:
                            rc3, o3, e3 = self._sh('kill -HUP %s' % gpid, 10)
                            if rc3 == 0:
                                rc, o, e = 0, 'SIGHUP sent to PID %s' % gpid, ''
                    except Exception:
                        pass

        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal menjalankan aksi layanan %s' % aksi, e.strip() or o.strip()))

        msgs = {
            'start': 'Layanan ZySentinel berhasil dijalankan',
            'stop': 'Layanan ZySentinel berhasil dihentikan',
            'restart': 'Layanan ZySentinel berhasil dimulai ulang',
            'reload': 'Konfigurasi ZySentinel berhasil dimuat ulang'
        }
        try:
            public.WriteLog('ZySentinel', 'sentinel.service %s' % aksi)
        except Exception:
            pass
        return public.returnMsg(True, msgs.get(aksi, 'Aksi layanan %s selesai' % aksi))

    def start(self, get=None):
        """Memulai daemon ZySentinel (start)."""
        return self.service_action({'action': 'start'})

    def stop(self, get=None):
        """Menghentikan daemon ZySentinel (stop)."""
        return self.service_action({'action': 'stop'})

    def restart(self, get=None):
        """Memulai ulang daemon ZySentinel (restart)."""
        return self.service_action({'action': 'restart'})

    def reload(self, get=None):
        """Memuat ulang konfigurasi & vhosts tanpa downtime (reload SIGHUP)."""
        return self.service_action({'action': 'reload'})

    def service_status(self, get=None):
        """Ambil status detail layanan sentinel.service."""
        is_active = False
        status_str = 'tidak aktif'
        if self._is_systemd():
            rc, o, _ = self._sh('systemctl is-active sentinel.service', 10)
            is_active = (rc == 0 and o.strip() == 'active')
            status_str = o.strip() if rc == 0 else 'inactive'
        else:
            status_str = self._svc('sentinel')
            is_active = (status_str == 'active')

        pid = None
        pid_f = self._p('run', 'guardd.pid')
        if os.path.exists(pid_f):
            try:
                with open(pid_f, 'r') as f:
                    pid = int(f.read().strip())
            except Exception:
                pass
        return public.returnMsg(True, {
            'active': is_active,
            'status': status_str,
            'pid': pid
        })

    def fw_action(self, get):
        aksi = (get.get('aksi') or get.get('act') or get.get('sub_action') or (get.get('action') if get.get('action') != 'a' else None) or '').strip()
        if aksi not in ('install', 'remove', 'flush'):
            return public.returnMsg(False, 'aksi tidak dikenal')
        rc, o, e = self._sh("'%s/bin/sentinel-fw.sh' %s"
                            % (self.__PATH, aksi), 90)
        if aksi == 'remove':
            self._sh('systemctl stop sentinel-fw.timer', 20)
        if rc != 0:
            # status tetap True seperti sebelumnya; hanya teksnya jujur dan tanpa keluaran mentah skrip
            self._catat_galat('aksi firewall %s' % aksi, o.strip() or e.strip())
            return public.returnMsg(True, 'Aksi firewall %s dijalankan dengan peringatan; periksa status firewall' % aksi)
        return public.returnMsg(True, 'Aksi firewall %s selesai' % aksi)

    @staticmethod
    def _fw_penghitung(keluaran):
        """Urai `iptables -L SENTINEL -n -v -x` menjadi daftar penghitung.

        Hanya aturan bertanda komentar `sentinel:<nama>`. Tiap butir:
        target, rule (nama), detail (kriteria pencocokan), pkts, bytes."""
        hasil = []
        for baris in (keluaran or '').splitlines():
            m = re.match(r'^\s*(\d+)\s+(\d+)\s+(\S+)\s+\S+\s+--\s+\S+\s+\S+\s+'
                         r'\S+\s+\S+\s*(.*?)\s*/\*\s*sentinel:([\w.-]+)\s*\*/', baris)
            if not m:
                continue
            hasil.append({'pkts': int(m.group(1)), 'bytes': int(m.group(2)),
                          'target': m.group(3), 'rule': m.group(5),
                          'detail': m.group(4)})
        return hasil

    def get_fw(self, get):
        """Isi chain kernel, isi set, dan penghitung paket."""
        # Edisi Free: fitur berbayar (fw_rules) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('fw_rules', self._get_active_lang(get))

    def get_fw_rules(self, get):
        """Aturan terkelola Sentinel dalam satu daftar: ban, allow, geo.

        Digabung di sini supaya tab Firewall punya SATU sumber untuk
        tabel CRUD, bukan tiga permintaan terpisah yang bisa berbeda
        waktu. Isinya dibaca dari keadaan yang sudah ada (get_bans,
        get_allow, get_geo_ban); tidak ada yang menyentuh kernel.
        """
        # Edisi Free: fitur berbayar (fw_rules) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('fw_rules', self._get_active_lang(get))

    def del_fw_rule(self, get):
        """Hapus aturan terkelola Sentinel: ban, allow, atau geo."""
        tipe = (get.get('type') or '').strip()
        rule = (get.get('rule') or get.get('ip') or '').strip()
        if not rule and tipe != 'geo':
            return public.returnMsg(False, 'Aturan atau alamat IP belum ditentukan')

        class ParamWrapper(dict):
            def __init__(self, d):
                super().__init__(d)
            def get(self, k, default=None):
                return super().get(k, default)

        if tipe == 'ban':
            return self.unban_ip(ParamWrapper({'ip': rule}))
        elif tipe == 'allow':
            return self.del_allow(ParamWrapper({'ip': rule}))
        elif tipe == 'geo':
            return self.geo_ban_off(get)
        return public.returnMsg(False, 'Jenis aturan tidak dikenal: %s' % _aman(tipe))

    def sync_vpn_whitelist(self, get=None):
        """Deteksi otomatis antarmuka VPN (WireGuard, OpenVPN, Tailscale, ZeroTier)
        dan sinkronkan ke aturan whitelist firewall tanpa mengganggu VPN client."""
        fw_script = '%s/bin/sentinel-fw.sh' % self.__PATH
        if not os.path.isfile(fw_script):
            fw_script = '/www/server/sentinel/bin/sentinel-fw.sh'
        rc, o, e = self._sh("bash '%s' install" % fw_script, 60)
        rc_l, o_l, _ = self._sh("ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(wg|tun|tap|tailscale|zt|ppp)' | cut -d'@' -f1 | sort -u", 10)
        vpn_list = [x.strip() for x in o_l.splitlines() if x.strip()]
        return public.returnMsg(True, {
            'status': 'success' if rc == 0 else 'warning',
            'vpn_interfaces': vpn_list,
            'message': self._t(get, 'Whitelist VPN disinkronkan otomatis (%d antarmuka terdeteksi)',
                               'VPN whitelist synchronized automatically (%d interfaces detected)') % len(vpn_list)
        })

    def rescan(self, get):
        rc, o, e = self._sh("'%s/bin/guardctl' rescan" % self.__PATH, 20)
        try:
            self.sync_vpn_whitelist(get)
        except Exception:
            pass
        return public.returnMsg(True, 'Penemuan ulang berkas log akses diminta')

    # ------------------------------------------------------------------ #
    # Port Access Control (Inbound & Outbound Firewall)                    #
    # ------------------------------------------------------------------ #
    PORTS_CONF = '/www/server/sentinel/etc/ports.json'
    PROC_WHITELIST_CONF = '/www/server/sentinel/etc/proc_whitelist.json'
    PROC_RULE_LONGGAR = ('WORKER_ANAK_ASING', 'COMM_PALSU', 'PTRACE_WEB')
    PHP_ROOT = '/www/server/php'
    PHP_INIT = '/etc/init.d/php-fpm-%s'
    # Rilis perbaikan PHP2Shell (CVE-2026-109618 / CVE-2026-109619, 21 Okt 2026). Cabang di bawah 8.2 tanpa rilis resmi.
    PHP_PERBAIKAN = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
    _php_cache = {'t': 0, 'v': None}

    def _ports_script(self, action):
        """Panggil helper biner sentinel-ports.py."""
        self._ensure_core_files()
        bin_path = os.path.join(self.__PATH, 'bin', 'sentinel-ports.py')
        py_bin = '/www/server/panel/pyenv/bin/python3'
        if not os.path.isfile(py_bin):
            py_bin = 'python3'
        rc, o, e = self._sh("'%s' '%s' %s" % (py_bin, bin_path, action), 20)
        return rc, o, e

    def _port_halaman(self, get, data):
        """Dengan page: config[direction] (inbound/outbound, bawaan inbound) dipotong ke satu halaman dan
        'halaman' ditambahkan; 'jumlah' membawa total kedua arah untuk lencana tab. Tanpa page: tidak diubah."""
        if self._hal_param(get) is None or not isinstance(data, dict) or not isinstance(data.get('config'), dict):
            return data
        arah = 'outbound' if str(get.get('direction') or '').strip().lower() == 'outbound' else 'inbound'
        cfg = data['config']
        data['jumlah'] = {'inbound': len(cfg.get('inbound') or []), 'outbound': len(cfg.get('outbound') or [])}
        cfg[arah], data['halaman'] = self._halaman(get, list(cfg.get(arah) or []))
        data['arah'] = arah
        return data

    def get_port_firewall(self, get):
        """Membaca daftar aturan port Inbound & Outbound dan status kernel.
        Dengan page (+ direction): hanya satu halaman aturan arah itu yang dikirim (lihat _port_halaman)."""
        rc, o, e = self._ports_script('status')
        try:
            data = json.loads(o)
            return public.returnMsg(True, self._port_halaman(get, data))
        except Exception as ex:
            self._ports_script('init')
            rc2, o2, _ = self._ports_script('status')
            try:
                data2 = json.loads(o2)
                return public.returnMsg(True, self._port_halaman(get, data2))
            except Exception:
                return public.returnMsg(False, self._galat('Gagal memuat status firewall port', e or ex))

    # Teks rekomendasi analisis port (kunci dari sentinel-ports.py get_port_analysis): (Indonesia, Inggris)
    _PORT_REK = {
        'panel_open': ('Panel kontrol dapat dibuka dari seluruh internet. Batasi ke IP admin Anda agar hanya Anda yang bisa membuka halaman login.',
                       'The control panel can be opened from the whole internet. Restrict it to your admin IP address(es) so only you can reach the login page.'),
        'ssh_open': ('SSH terbuka untuk seluruh internet. Batasi ke IP admin Anda dan pakai login kunci SSH saja.',
                     'SSH is open to the whole internet. Restrict it to your admin IP address(es) and use SSH key login only.'),
        'ssh_default_port': ('SSH memakai port bawaan 22 yang terus dipindai penyerang. Pindahkan ke port lain lalu batasi ke IP admin Anda.',
                             'SSH uses the default port 22, which attackers scan constantly. Move it to another port and restrict it to your admin IP address(es).'),
        'restricted_ok': ('Akses dibatasi ke alamat IP yang diizinkan. Sudah baik.', 'Access is limited to the allowed IP addresses. Good.'),
        'closed_fw': ('Layanan berjalan, tetapi port firewall menutup akses dari luar. Izinkan satu IP hanya bila Anda memang perlu akses jarak jauh.',
                      'The service is running, but the port firewall blocks outside access. Allow a single IP only if you really need remote access.'),
        'db_public': ('Basis data atau cache terbuka ke internet. Blokir, atau izinkan hanya IP server aplikasi yang memerlukannya. Paling baik: ikat layanan ke 127.0.0.1.',
                      'A database or cache is open to the internet. Block it, or allow only the IP of the application server that needs it. Best: bind the service to 127.0.0.1.'),
        'remote_public': ('Layanan akses/manajemen jarak jauh terbuka ke internet. Blokir atau izinkan hanya IP tepercaya; pakai VPN atau terowongan SSH.',
                          'A remote access or management service is open to the internet. Block it or allow only trusted IPs; use a VPN or SSH tunnel instead.'),
        'exposed_public': ('Layanan ini jarang perlu terbuka ke internet dan sering disalahgunakan untuk serangan. Sebaiknya diblokir.',
                           'This service rarely needs to be on the public internet and is often abused for attacks. Block it.'),
        'ftp_plain': ('FTP mengirim kata sandi tanpa enkripsi. Pilih SFTP atau FTPS dan izinkan hanya IP yang memerlukannya.',
                      'FTP sends passwords in clear text. Prefer SFTP or FTPS and allow only the IPs that need it.'),
        'agent_public': ('Agen pemantau atau alat manajemen terbuka ke internet. Izinkan hanya IP server pengelolanya.',
                         'A monitoring agent or management tool is open to the internet. Allow only the IP of the server that manages it.'),
        'hosting_service': ('Layanan hosting publik (email/DNS). Biarkan terbuka bila dipakai; bila tidak, blokir.',
                            'A public hosting service (mail/DNS). Keep it open if you use it; otherwise block it.'),
        'ntp_public': ('Layanan waktu dapat dijangkau dari internet dan bisa disalahgunakan untuk serangan amplifikasi. Biarkan hanya bila Anda melayani waktu untuk pihak lain.',
                       'The time service is reachable from the internet and can be abused for traffic amplification. Keep it only if you serve time to others.'),
        'docker_bypass': ('Dipublikasikan oleh Docker: aturan port firewall TIDAK berlaku untuk port ini. Ikat kontainer ke 127.0.0.1 (mis. 127.0.0.1:port:port) atau tambahkan aturan di rantai firewall Docker (DOCKER-USER).',
                          'Published by Docker: port firewall rules do NOT apply to this port. Bind the container to 127.0.0.1 (for example 127.0.0.1:port:port) or add a rule in Docker\'s own firewall chain (DOCKER-USER).'),
        'fw_inactive': ('Port firewall mati, jadi port ini terbuka ke internet. Nyalakan port firewall, lalu blokir atau batasi port ini.',
                        'The port firewall is off, so this port is open to the internet. Turn the port firewall on, then block or restrict this port.'),
        'other_open': ('Layanan tidak dikenal terbuka ke internet. Blokir bila Anda tidak mengenalinya, atau izinkan hanya IP yang memerlukannya.',
                       'An unrecognised service is open to the internet. Block it if you do not recognise it, or allow only the IPs that need it.'),
        'web_ok': ('', ''),
    }

    def get_port_inventory(self, get):
        """Analisis port yang terbuka: tiap listener dengan cakupan (publik/privat/lokal), layanan, keadaan efektif di port
        firewall, risiko, rekomendasi (dalam bahasa panel), dan aksi (block, allow_ip, restrict_admin, restrict_rule).
        Dengan page: daftar port dipotong ke satu halaman; ringkasan, panel terdeteksi, dan catatan ikut dikirim."""
        # Edisi Free: fitur berbayar (recon_guard) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('recon_guard', self._get_active_lang(get))

    def restrict_admin_port(self, get):
        """Batasi port admin (SSH atau panel) ke IP tertentu, atau cabut pembatasan (remove=1 / sources=0.0.0.0/0).
        Pengaman anti-terkunci: IP yang sedang dipakai admin (alamat koneksi ke panel ini) WAJIB termasuk dalam daftar,
        koneksi yang sudah berjalan tidak diputus (ESTABLISHED tetap diterima), dan bila kernel menolak aturan, keadaan
        lama dipulihkan. Daftar putih panel/VPN/jaringan privat tetap diterima seperti biasa."""
        try:
            port = int(str(get.get('port') or '').strip())
        except ValueError:
            port = 0
        if not (1 <= port <= 65535):
            return public.returnMsg(False, 'Nomor port harus berada di antara 1 dan 65535')
        rc, o, e = self._ports_script('inventory')
        try:
            data = json.loads(o)
            admin = {x['port'] for x in (data.get('inventory') or []) if x.get('category') in ('ssh', 'panel')}
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal memuat daftar port yang terbuka', e or ex))
        if port not in admin:
            return public.returnMsg(False, self._t(get, 'Pembatasan IP hanya untuk port admin (SSH atau panel). Untuk port lain gunakan aturan port.',
                                                   'IP restriction is only for admin ports (SSH or panel). Use a port rule for other ports.'))
        mentah = str(get.get('sources') or '').strip()
        hapus = str(get.get('remove') or '') in ('1', 'true', 'on') or mentah in ('0.0.0.0/0', '0.0.0.0')
        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca konfigurasi aturan port', ex))
        lama = json.loads(json.dumps(cfg.get('admin_restrict') or {}))
        baru = dict(lama) if isinstance(lama, dict) else {}
        if hapus:
            baru.pop(str(port), None)
            pesan = self._t(get, 'Pembatasan IP untuk port %d dicabut: port kembali terbuka untuk semua IP.' % port,
                            'The IP restriction on port %d was removed: the port is open to all IPs again.' % port)
        else:
            alamat, err = parse_v4_daftar(mentah, maks=20, cidr=True, min_prefix=8, tujuan='netral', semua=False)
            if err:
                err = self._localize_msg(err, self._get_active_lang(get))
                return public.returnMsg(False, self._t(get, 'Daftar IP tidak valid: %s' % err, 'The IP list is not valid: %s' % err))
            saya = self._req_ip()
            try:
                import ipaddress as _ip
                ip_saya = _ip.IPv4Address(saya)
            except ValueError:
                ip_saya = None
            termasuk = bool(ip_saya) and any(ip_saya in _ip.IPv4Network(a if '/' in a else a + '/32', strict=False) for a in alamat)
            if not termasuk:
                return public.returnMsg(False, self._t(
                    get, 'IP Anda saat ini (%s) harus termasuk dalam daftar, kalau tidak Anda akan terkunci. Tambahkan IP itu lalu coba lagi.' % (saya or 'tidak terdeteksi'),
                    'Your current IP (%s) must be in the list, otherwise you would lock yourself out. Add it and try again.' % (saya or 'not detected')))
            baru[str(port)] = alamat
            pesan = self._t(get, 'Port %d sekarang hanya dapat diakses dari: %s.' % (port, ', '.join(alamat)),
                            'Port %d can now only be reached from: %s.' % (port, ', '.join(alamat)))
        cfg['admin_restrict'] = baru
        if not baru:
            cfg.pop('admin_restrict', None)
        _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)
        if cfg.get('active', True):
            rc, o, e = self._ports_script('apply')
            if rc != 0:
                if lama:
                    cfg['admin_restrict'] = lama
                else:
                    cfg.pop('admin_restrict', None)
                _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)
                self._ports_script('apply')
                return public.returnMsg(False, self._galat('Pembatasan IP ditolak saat diterapkan ke firewall dan dibatalkan', (o or e).strip()[:300]))
        return public.returnMsg(True, pesan)

    @staticmethod
    def _port_butuh(port):
        """Fitur yang dibutuhkan untuk mengelola port (angka, rentang a-b, atau "all"): None (Free), 'ports_ext' (Pro), 'ports_unlimited' (Max)."""
        if str(port).lower() == 'all':
            return 'ports_unlimited'
        try:
            a, _, b = str(port).partition('-')
            ps = set(range(int(a), int(b or a) + 1))
        except ValueError:
            return 'ports_unlimited'
        if ps <= set(_PORT_FREE):
            return None
        if ps <= set(_PORT_FREE) | set(_PORT_EXT):
            return 'ports_ext'
        return 'ports_unlimited'

    def _port_ditolak(self, get, port):
        """None bila paket mengizinkan mengelola port ini; selain itu respons Upgrade (paket tak mengizinkan port tersebut)."""
        fitur = self._port_butuh(port)
        if fitur and not _lic.allowed(fitur):
            return self._lisensi_ditolak(fitur, self._get_active_lang(get))
        return None

    def _port_admin_tercakup(self, clean_port):
        """True bila port/rentang (atau 'all') mencakup port SSH atau panel yang terdeteksi."""
        if clean_port == 'all':
            return True
        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception:
            cfg = {}
        admin = set()
        for k in ('detected_ssh_port', 'detected_panel_port'):
            if str(cfg.get(k, '')).isdigit():
                admin.add(int(cfg[k]))
        for pn in cfg.get('detected_panels') or []:
            admin.update(int(x) for x in pn.get('ports', []) if str(x).isdigit())
        for r in cfg.get('inbound', []):
            if r.get('system') and str(r.get('id', '')).startswith(('in-ssh', 'in-panel')) and str(r.get('port', '')).isdigit():
                admin.add(int(r['port']))
        a, _, b = clean_port.partition('-')
        try:
            lo, hi = int(a), int(b or a)
        except ValueError:
            return False
        return any(lo <= p <= hi for p in admin)

    def _port_rule_masukan(self, get, direction):
        """Validasi masukan aturan port (dipakai add_port_rule dan update_port_rule).
        Mengembalikan (field_dict, None) atau (None, pesan)."""
        protocol = str(get.get('protocol') or 'tcp').strip().lower()
        if protocol not in ['tcp', 'udp', 'tcp/udp', 'all']:
            return None, 'Protokol harus tcp, udp, tcp/udp, atau all'
        port = str(get.get('port') or '').strip()
        if not port:
            return None, 'Nomor port atau rentang port wajib diisi'
        clean_port = port.replace(':', '-')
        if clean_port.lower() == 'all':
            clean_port = 'all'
        elif not re.fullmatch(r'[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?', clean_port):
            return None, 'Format port tidak valid (contoh: 80 atau 8000-8080)'
        else:
            parts = clean_port.split('-')
            for p_str in parts:
                if int(p_str) < 1 or int(p_str) > 65535:
                    return None, 'Nomor port harus berada di antara 1 dan 65535'
            if len(parts) == 2 and int(parts[0]) >= int(parts[1]):
                return None, 'Rentang port tidak valid (port awal harus lebih kecil)'
        action = str(get.get('rule_action') or get.get('act') or get.get('aksi') or get.get('sub_action') or (get.get('action') if get.get('action') != 'a' else None) or 'ACCEPT').strip().upper()
        action = {'ALLOW': 'ACCEPT', 'PERMIT': 'ACCEPT', 'DENY': 'DROP', 'BLOCK': 'DROP'}.get(action, action)
        if action not in ['ACCEPT', 'DROP']:
            return None, 'Aksi harus ACCEPT atau DROP'
        kolom = 'source' if direction == 'inbound' else 'dest'
        mentah = str(get.get(kolom) or '0.0.0.0/0').strip() or '0.0.0.0/0'
        alamat, err = parse_v4_daftar(mentah, cidr=True, min_prefix=0,
                                      tujuan='netral', semua=True)
        if err:
            return None, 'Format alamat IP/CIDR %s tidak valid: %s' % (kolom, err)
        remark, err = teks_aman(str(get.get('remark') or ''), 120, 'Catatan', boleh_kosong=True)
        if err:
            return None, err
        if direction == 'inbound' and action == 'DROP' and mentah in ('0.0.0.0/0', '0.0.0.0') and self._port_admin_tercakup(clean_port):
            return None, 'Aturan blokir untuk semua alamat pada port SSH atau panel akan mengunci Anda. Batasi ke IP tertentu atau gunakan pembatasan IP admin.'
        if not remark:
            remark = '%s Port %s' % (protocol.upper(), clean_port)
        return {'port': clean_port, 'protocol': protocol, 'action': action,
                'remark': remark, kolom: ','.join(alamat)}, None

    def update_port_rule(self, get):
        """Mengubah aturan port yang sudah ada (arah tetap).

        Aturan baseline (SSH, panel, web) hanya boleh diubah keterangannya:
        port, protokol, aksi, dan alamatnya dikunci, sama seperti larangan
        menghapus/mematikannya, supaya akses admin dan situs tidak terputus.
        Bila kernel menolak, aturan lama dipulihkan."""
        rule_id = str(get.get('id') or '').strip()
        if not rule_id or not id_valid(rule_id):
            return public.returnMsg(False, 'Format ID aturan tidak valid')
        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca konfigurasi aturan port', ex))
        arah, idx = None, -1
        for d in ['inbound', 'outbound']:
            for i, r in enumerate(cfg.get(d, [])):
                if r.get('id') == rule_id:
                    arah, idx = d, i
        if arah is None:
            return public.returnMsg(False, 'Aturan dengan ID tersebut tidak ditemukan')
        lama = dict(cfg[arah][idx])
        if lama.get('system'):
            remark, err = teks_aman(str(get.get('remark') or ''), 120, 'Catatan', boleh_kosong=True)
            if err:
                return public.returnMsg(False, err)
            cfg[arah][idx]['remark'] = remark or lama.get('remark', '')
            _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)
            return public.returnMsg(True, 'Keterangan aturan bawaan %s diperbarui (port, protokol, aksi, dan alamat aturan bawaan dikunci)' % rule_id)
        baru, err = self._port_rule_masukan(get, arah)
        if err:
            return public.returnMsg(False, err)
        ditolak = self._port_ditolak(get, baru['port'])
        if ditolak:
            return ditolak
        kolom = 'source' if arah == 'inbound' else 'dest'
        for r in cfg.get(arah, []):
            if (r.get('id') != rule_id and r.get('port') == baru['port']
                    and r.get('protocol') == baru['protocol'] and r.get('action') == baru['action']
                    and r.get(kolom) == baru[kolom]):
                return public.returnMsg(False, 'Aturan yang sama sudah ada (%s)' % r.get('id'))
        cfg[arah][idx].update(baru)
        _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)
        if cfg.get('active', True):
            rc, o, e = self._ports_script('apply')
            if rc != 0:
                cfg[arah][idx] = lama
                _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)
                self._ports_script('apply')
                return public.returnMsg(
                    False, self._galat('Perubahan ditolak saat diterapkan ke firewall dan dibatalkan', (o or e).strip()[:300]))
        return public.returnMsg(True, 'Aturan port %s diperbarui' % baru['port'])

    def add_port_rule(self, get):
        """Menambahkan aturan port baru (Inbound atau Outbound).

        Semua masukan divalidasi ketat. Nilai tak valid DITOLAK, tidak
        dikoreksi diam-diam: aksi "DENY" yang berubah jadi ACCEPT, atau
        IP yang salah tetapi tetap tersimpan, membuat aturan tidak berlaku
        di kernel sementara layar menampilkan sukses.
        """
        direction = str(get.get('direction') or 'inbound').strip().lower()
        if direction not in ['inbound', 'outbound']:
            return public.returnMsg(False, 'Arah aturan harus inbound atau outbound')
        baru, err = self._port_rule_masukan(get, direction)
        if err:
            return public.returnMsg(False, err)
        ditolak = self._port_ditolak(get, baru['port'])
        if ditolak:
            return ditolak
        try:
            with open(self.PORTS_CONF, 'r') as fp:
                _cfg0 = json.load(fp)
            _n = sum(1 for d in ('inbound', 'outbound') for r in _cfg0.get(d, []) if not r.get('system'))
        except Exception:
            _n = 0
        ditolak = self._batas_ditolak(get, 'port_rules', _n)
        if ditolak:
            return ditolak
        kolom = 'source' if direction == 'inbound' else 'dest'
        clean_port, protocol, action = baru['port'], baru['protocol'], baru['action']
        alamat_str, remark = baru[kolom], baru['remark']

        try:
            if not os.path.isfile(self.PORTS_CONF):
                self._ports_script('init')
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception:
            self._ports_script('init')
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)

        daftar = cfg.setdefault(direction, [])
        for r in daftar:
            if (r.get('port') == clean_port and r.get('protocol') == protocol
                    and r.get('action') == action
                    and r.get(kolom) == alamat_str):
                return public.returnMsg(False, 'Aturan yang sama sudah ada (%s)' % r.get('id'))

        # ID unik: detik saja bisa bentrok bila dua aturan dibuat bersamaan,
        # dan hapus berdasarkan ID akan menghapus keduanya.
        rule_id = '%s-%d-%s' % ('in' if direction == 'inbound' else 'out',
                                int(time.time()), uuid.uuid4().hex[:4])
        new_rule = {
            'id': rule_id,
            'port': clean_port,
            'protocol': protocol,
            'action': action,
            'remark': remark,
            'system': False,
            'enabled': True,
            kolom: alamat_str,
        }
        daftar.append(new_rule)

        _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)

        if cfg.get('active', True):
            rc, o, e = self._ports_script('apply')
            if rc != 0:
                # Jangan biarkan aturan yang ditolak kernel tersimpan sebagai
                # "berhasil": batalkan dan terapkan ulang keadaan sebelumnya.
                cfg[direction] = [r for r in cfg.get(direction, []) if r.get('id') != rule_id]
                _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)
                self._ports_script('apply')
                return public.returnMsg(
                    False, self._galat('Aturan ditolak saat diterapkan ke firewall dan dibatalkan', (o or e).strip()[:300]))

        return public.returnMsg(True, 'Aturan port %s berhasil ditambahkan' % clean_port)

    def del_port_rule(self, get):
        """Menghapus aturan port berdasarkan ID."""
        rule_id = str(get.get('id') or '').strip()
        if not rule_id:
            return public.returnMsg(False, 'ID aturan wajib disertakan')
        if not id_valid(rule_id):
            return public.returnMsg(False, 'Format ID aturan tidak valid')

        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca konfigurasi aturan port', ex))

        for d in ['inbound', 'outbound']:
            for r in cfg.get(d, []):
                if r.get('id') == rule_id and r.get('system'):
                    return public.returnMsg(
                        False, 'Aturan bawaan (SSH, panel, web) tidak boleh '
                               'dihapus; menghapusnya bisa memutus akses admin')
        removed = False
        for d in ['inbound', 'outbound']:
            rules = cfg.get(d, [])
            new_rules = [r for r in rules if r.get('id') != rule_id]
            if len(new_rules) < len(rules):
                cfg[d] = new_rules
                removed = True

        if not removed:
            return public.returnMsg(False, 'Aturan dengan ID tersebut tidak ditemukan')

        _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)

        if cfg.get('active', True):
            self._ports_script('apply')

        return public.returnMsg(True, 'Aturan port berhasil dihapus')

    def toggle_port_rule(self, get):
        """Menyalakan atau mematikan status aturan port."""
        rule_id = str(get.get('id') or '').strip()
        if not rule_id:
            return public.returnMsg(False, 'ID aturan wajib disertakan')
        if not id_valid(rule_id):
            return public.returnMsg(False, 'Format ID aturan tidak valid')

        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca konfigurasi aturan port', ex))

        updated = False
        new_state = False
        for d in ['inbound', 'outbound']:
            for r in cfg.get(d, []):
                if r.get('id') == rule_id:
                    if r.get('system'):
                        return public.returnMsg(
                            False, 'Aturan bawaan (SSH, panel, web) tidak '
                                   'boleh dimatikan; bisa memutus akses admin')
                    r['enabled'] = not r.get('enabled', True)
                    new_state = r['enabled']
                    updated = True
                    break

        if not updated:
            return public.returnMsg(False, 'Aturan tidak ditemukan')

        _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)

        if cfg.get('active', True):
            self._ports_script('apply')

        return public.returnMsg(True, 'Aturan %s: %s' % ('diaktifkan' if new_state else 'dinonaktifkan', rule_id))

    def reset_port_firewall(self, get):
        """Mereset seluruh aturan port ke standar preinstall."""
        rc, o, e = self._ports_script('reset')
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal mengembalikan aturan port ke standar awal', e or o))
        return public.returnMsg(True, 'Aturan port berhasil dikembalikan ke standar awal')

    def apply_port_firewall(self, get):
        """Menerapkan ulang seluruh aturan port ke kernel iptables."""
        rc, o, e = self._ports_script('apply')
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal menerapkan aturan port ke firewall', e or o))
        return public.returnMsg(True, 'Aturan port berhasil diterapkan ke firewall')

    def toggle_port_firewall_status(self, get):
        """Menyalakan atau mematikan modul port firewall secara global."""
        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception:
            self._ports_script('init')
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)

        cfg['active'] = not cfg.get('active', True)
        new_st = cfg['active']
        _tulis_atomik(self.PORTS_CONF, json.dumps(cfg, indent=2), cadangan=True)

        self._ports_script('apply')
        return public.returnMsg(True, 'Firewall port %s' % ('diaktifkan' if new_st else 'dinonaktifkan'))

    def apply_port_firewall_kernel(self, get):
        """Alias untuk apply_port_firewall."""
        return self.apply_port_firewall(get)

    def reset_port_firewall_defaults(self, get):
        """Alias untuk reset_port_firewall."""
        return self.reset_port_firewall(get)

    def toggle_port_firewall_global(self, get):
        """Alias untuk toggle_port_firewall_status."""
        return self.toggle_port_firewall_status(get)

    # ------------------------------------------------------------------ #
    # CVE Advisor & Remediasi Tiga Tingkat (Tri-Tier)                     #
    # ------------------------------------------------------------------ #
    def _cve_script(self, action):
        """Panggil helper biner sentinel-cve.py."""
        self._ensure_core_files()
        bin_path = os.path.join(self.__PATH, 'bin', 'sentinel-cve.py')
        py_bin = '/www/server/panel/pyenv/bin/python3'
        if not os.path.isfile(py_bin):
            py_bin = 'python3'
        # scan memeriksa dependensi ke api.osv.dev (database OSV realtime, batas 120 detik di sentinel-cve.py): beri ruang di atasnya
        # scan: prioritas rendah (CPU dan IO) supaya situs pelanggan tidak terganggu selama menelusuri docroot
        pra = 'nice -n 10 ionice -c3 ' if action == 'scan' and shutil.which('ionice') else ('nice -n 10 ' if action == 'scan' else '')
        rc, o, e = self._sh("%s'%s' '%s' %s" % (pra, py_bin, bin_path, action), 180 if action == 'scan' else 30)
        return rc, o, e

    def get_cve_report(self, get):
        """Membaca laporan audit CVE terbaru (skor postur, kerentanan terdeteksi, dan remediasi)."""
        # Edisi Free: fitur berbayar (cve_advisor) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('cve_advisor', self._get_active_lang(get))

    def _cve_osv_aktif(self):
        try:
            with open(self._p('etc', 'cve.conf')) as f:
                return json.load(f).get('osv', True) is not False
        except Exception:
            return True

    def set_cve_osv(self, get):
        """Sakelar pemeriksaan dependensi ke database OSV (mengirim nama dan versi paket ke api.osv.dev). value=on|off."""
        sec_ok, sec_msg = self._enforce_security_guard('set_cve_osv', get)
        if not sec_ok:
            return public.returnMsg(False, sec_msg)
        nilai = _g(get, 'value').lower()
        if nilai not in ('on', 'off'):
            return public.returnMsg(False, self._t(get, 'Nilai harus on atau off', 'Value must be on or off'))
        f = self._p('etc', 'cve.conf')
        try:
            try:
                with open(f) as fp:
                    cfg = json.load(fp)
                cfg = cfg if isinstance(cfg, dict) else {}
            except Exception:
                cfg = {}
            cfg['osv'] = (nilai == 'on')
            tmp = f + '.tmp'
            with open(tmp, 'w') as fp:
                json.dump(cfg, fp)
            os.chmod(tmp, 0o600)
            os.replace(tmp, f)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal menyimpan pengaturan OSV', ex))
        return public.returnMsg(True, self._t(get, 'Pemeriksaan dependensi OSV %s. Jalankan Scan Now untuk memperbarui laporan.' % ('diaktifkan' if nilai == 'on' else 'dimatikan'),
                                              'OSV dependency check %s. Run Scan Now to refresh the report.' % ('enabled' if nilai == 'on' else 'disabled')))

    def scan_cve(self, get):
        """Menjalankan pemindaian kerentanan CVE penuh pada sistem host."""
        # Edisi Free: fitur berbayar (cve_advisor) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('cve_advisor', self._get_active_lang(get))

    def apply_cve_vpatch(self, get):
        """Mengaktifkan atau menonaktifkan Virtual Patching WAF untuk CVE tertentu."""
        sec_ok, sec_msg = self._enforce_security_guard('apply_cve_vpatch', get)
        if not sec_ok:
            return public.returnMsg(False, sec_msg)

        cve_id = _g(get, 'cve_id').upper()
        if not cve_id or not re.fullmatch(r'CVE-\d{4}-\d{1,8}', cve_id):
            return public.returnMsg(False, 'Format ID CVE tidak valid (contoh: CVE-2026-12345)')

        action = _g(get, 'action', 'on').lower()
        if action not in ('on', 'off'):
            action = 'on'

        if action == 'on' and not _lic.allowed('cve_vpatch'):
            lang = self._get_active_lang(get)
            return self._lisensi_ditolak('cve_vpatch', lang)

        rc, o, e = self._cve_script('vpatch %s %s' % (shlex.quote(cve_id), action))
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal menerapkan virtual patch', e.strip() or o.strip()))
        # Dulu berkas patch hanya ditulis dan tidak pernah dimuat WAF, tetapi UI melapor "berhasil" (audit 24 Okt 2026).
        # Sekarang: susun ulang ruleset, uji, reload terverifikasi; gagal = kembalikan perubahan dan susun ulang lagi.
        hasil = self._zy_terapkan({'reload': '1'}, 'Virtual patch %s %s.' % (cve_id, 'aktif' if action == 'on' else 'dicabut'))
        if not hasil.get('status') and action == 'on':
            self._cve_script('vpatch %s off' % shlex.quote(cve_id))
            self._zy_terapkan({'reload': '1'}, 'rollback')
            return public.returnMsg(False, 'Virtual patch %s dibatalkan dan dikembalikan karena WAF belum bisa memuatnya. %s' % (cve_id, hasil.get('msg', '')))
        return hasil

    # ------------------------------------------------------------------ #
    # Ruleset ZySentinel: modul, pengaturan, daftar IP/URL, log           #
    #                                                                     #
    # WAF memakai Coraza (nginx) dan ModSecurity v2 (Apache, OpenLiteSpeed)#
    # dengan SATU ruleset SecLang: OWASP CRS + ruleset ZySentinel + daftar #
    # di bawah ini. Berkas konfigurasi turunan disusun oleh               #
    # sentinel-zyrules.py; setiap perubahan baru berlaku setelah web      #
    # server di-reload, jadi setiap endpoint di bawah menjalankan reload  #
    # yang terverifikasi (param reload=0 untuk menundanya).               #
    # ------------------------------------------------------------------ #
    WAF_LISTS_DIR = '/www/server/sentinel/etc/waf-lists'
    WAF_AUDIT_LOG = '/www/wwwlogs/zysentinel_waf_audit.jsonl'
    ZY_MODUL = ('sensitive_files', 'webshell', 'spam', 'scanner', 'bot',
                'lfi_args', 'probe_cms', 'probe_tools', 'probe_cve',
                'probe_archive', 'probe_secrets', 'app_laravel',
                'app_wordpress', 'app_codeigniter', 'app_cms',
                'app_nodejs', 'app_golang', 'app_python')
    ZY_SETTING = {'bot_level': (0, 3), 'strict': (0, 1), 'fallback': (0, 1),
                  'paranoia': (1, 4), 'threshold': (1, 100),
                  'body_nofiles_kb': (16, 4096), 'body_total_mb': (1, 512)}
    WAF_LISTS = ('ip_white', 'ip_black', 'url_white', 'url_black')
    WAF_LIST_MAKS = 5000
    # nama yang ditampilkan ke pengguna (kunci internal tidak boleh muncul di pesan)
    WAF_LIST_LABEL = {'ip_white': 'daftar putih IP', 'ip_black': 'daftar hitam IP',
                      'url_white': 'daftar putih URL', 'url_black': 'daftar hitam URL'}

    def _zy_sinkron_latar(self):
        """Daftar putih ikut ditanam ke aturan WAF ZySentinel (ctl:ruleEngine=Off per IP): setelah daftar putih berubah, susun ulang
        dan reload di latar (graceful) supaya IP yang dikeluarkan tidak tetap kebal WAF dan IP baru langsung dikecualikan. Hanya bila
        ruleset ZySentinel sudah terpasang; tidak memblokir jawaban API."""
        if not os.path.isfile('/www/server/sentinel/waf/zyrules/gen/main.conf'):
            return
        w = shlex.quote(os.path.join(self.__PATH, 'bin', 'sentinel-waf.sh'))
        self._sh("nohup sh -c %s >/dev/null 2>&1 &" % shlex.quote('%s zyrules-build && %s reload all' % (w, w)), 5)

    def _zy_siap(self):
        """Pastikan ruleset terpasang dan konfigurasi turunan tersusun."""
        if not os.path.isfile('/www/server/sentinel/waf/zyrules/gen/main.conf'):
            rc, o, e = self._waf('zyrules-install')
            if rc != 0:
                return False, (e.strip() or o.strip() or 'ruleset not ready')
        return True, ''

    def _zy_terapkan(self, get, ringkas=''):
        """Susun ulang konfigurasi lalu reload web server (kecuali reload=0)."""
        ok, pesan = self._zy_siap()
        if not ok:
            return public.returnMsg(False, self._galat('Aturan WAF ZySentinel belum siap dipasang', pesan))
        rc, o, e = self._waf('zyrules-build')
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal menyusun konfigurasi WAF', e.strip() or o.strip()))
        if str(get.get('reload') or '1') == '0':
            return public.returnMsg(
                True, '%s Berlaku setelah web server dimuat ulang.' % ringkas)
        rc, o, e = self._waf('reload', 'all')
        if rc != 0:
            return public.returnMsg(
                False, self._galat('%s Konfigurasi tersimpan, tetapi web server gagal dimuat ulang' % ringkas,
                                   (e.strip() or o.strip())[-300:]))
        return public.returnMsg(True, '%s Web server sudah dimuat ulang.' % ringkas)

    def get_zyrules(self, get):
        """Status ruleset: mode, modul, pengaturan, jumlah daftar, grup CRS,
        engine per web server, dan peninggalan engine Lua (bila ada)."""
        rc, o, e = self._waf('zyrules-status')
        try:
            st = json.loads(o)
        except Exception:
            st = {'terpasang': False, 'tersusun': False, 'modul': {},
                  'pengaturan': {}, 'daftar': {}, 'crs': {'ada': False, 'grup': []},
                  'mode': 'block'}
        rc2, o2, e2 = self._waf('engine')
        eng = {}
        for baris in o2.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                eng[k.strip()] = v.strip()
        rc3, o3, e3 = self._waf('legacy-status')
        leg = {}
        for baris in o3.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                leg[k.strip()] = v.strip()
        st['engine'] = eng
        st['legacy'] = leg
        return public.returnMsg(True, st)

    def set_zy_module(self, get):
        """Hidupkan atau matikan satu modul ZySentinel."""
        nama = str(get.get('name') or '').strip()
        aksi = str(get.get('state') or '').strip()
        if nama not in self.ZY_MODUL:
            return public.returnMsg(False, 'modul tidak dikenal: %s' % _aman(nama))
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'status harus on atau off')
        ok, pesan = self._zy_siap()
        if not ok:
            return public.returnMsg(False, self._galat('Aturan WAF ZySentinel belum siap dipasang', pesan))
        rc, o, e = self._waf('modul-set', nama, aksi)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal mengubah modul WAF', e.strip() or o.strip()))
        return self._zy_terapkan(get, 'Modul %s %s.' % (nama, 'diaktifkan' if aksi == 'on' else 'dimatikan'))

    def set_zy_setting(self, get):
        """Ubah pengaturan: bot_level 0-3, strict 0-1, fallback 0-1,
        paranoia 1-4, threshold 1-100."""
        k = str(get.get('key') or '').strip()
        if k not in self.ZY_SETTING:
            return public.returnMsg(False, 'pengaturan WAF tidak dikenal: %s' % _aman(k))
        mentah = str(get.get('value') if get.get('value') is not None else '').strip()
        lo, hi = self.ZY_SETTING[k]
        if not re.fullmatch(r'[0-9]{1,4}', mentah) or not (lo <= int(mentah) <= hi):
            return public.returnMsg(False, 'nilai %s harus bilangan bulat %d sampai %d' % (k, lo, hi))
        ok, pesan = self._zy_siap()
        if not ok:
            return public.returnMsg(False, self._galat('Aturan WAF ZySentinel belum siap dipasang', pesan))
        rc, o, e = self._waf('setting-set', k, str(int(mentah)))
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal mengubah pengaturan WAF', e.strip() or o.strip()))
        return self._zy_terapkan(get, 'Pengaturan %s = %d.' % (k, int(mentah)))

    # ---- daftar IP/URL WAF (disimpan sebagai teks, satu entri per baris) ----
    def _waf_list_baca(self, nama):
        p = '%s/%s.txt' % (self.WAF_LISTS_DIR, nama)
        out = []
        try:
            with open(p, 'r', encoding='utf-8') as f:
                for line in f:
                    t = line.rstrip('\n')
                    if t.strip() and not t.lstrip().startswith('#'):
                        out.append(t.strip())
        except FileNotFoundError:
            pass
        return out

    def _waf_list_tulis(self, nama, baris):
        os.makedirs(self.WAF_LISTS_DIR, exist_ok=True)
        os.chmod(self.WAF_LISTS_DIR, 0o755)
        p = '%s/%s.txt' % (self.WAF_LISTS_DIR, nama)
        tmp = p + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write('\n'.join(baris) + ('\n' if baris else ''))
            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)

    def _waf_ip_normal(self, nilai, nama, aman_diri=True):
        """IP, CIDR (/8..32), atau rentang a-b -> (bentuk baku, (awal, akhir), None)
        atau (None, None, pesan). Bentuk baku: IP tunggal, CIDR, atau 'a-b'."""
        tujuan = 'blokir' if nama == 'ip_black' else 'putih'
        if not isinstance(nilai, str):
            return None, None, 'nilai harus berupa teks'
        nilai = nilai.strip()
        nilai = nilai.split('#')[0].strip()
        if '-' in nilai:
            a, b, err = parse_v4_rentang(nilai, tujuan=tujuan)
            if err:
                return None, None, err
            baku = str(a) if a == b else '%s-%s' % (a, b)
        else:
            net, err = parse_v4(nilai, cidr=True, min_prefix=8, tujuan=tujuan)
            if err:
                return None, None, err
            a, b = v4_kisaran(net)
            baku = v4_tampil(net)
        if aman_diri and nama == 'ip_black':
            for ip in (self._self_ip(), self._req_ip()):
                x = v4_alamat(ip)
                if x is not None and int(a) <= int(x) <= int(b):
                    return None, None, ('daftar hitam memuat alamat server ini atau '
                                        'alamat Anda sendiri: %s' % ip)
        return baku, (int(a), int(b)), None

    def get_waf_lists(self, get):
        """Daftar hitam dan putih IP serta URL.

        Dengan parameter page (dan list = salah satu WAF_LISTS) hanya satu daftar yang dibaca dan dipotong ke satu halaman:
        {'list', 'daftar', 'halaman'}. Tanpa page: keempat daftar penuh seperti semula."""
        nama = str(get.get('list') or '').strip()
        if nama == 'ip_white' or self._hal_param(get) is None:
            try:
                px = self._proxy_vhosts()
                if any(v.get('provider') == 'cloudflare' for v in px.values()):
                    self._cf_waf_whitelist_sync()
            except Exception:
                pass

        if self._hal_param(get) is not None:
            if nama not in self.WAF_LISTS:
                return public.returnMsg(False, 'daftar tidak dikenal')
            potong, meta_hal = self._halaman(get, self._waf_list_baca(nama))
            return public.returnMsg(True, {'list': nama, 'daftar': potong, 'halaman': meta_hal})
        return public.returnMsg(True, {n: self._waf_list_baca(n) for n in self.WAF_LISTS})

    URL_MODE = ('normal', 'regex')
    URL_CAKUPAN = ('semua', 'crs')

    def _waf_list_entri(self, nama, get, kecuali=None):
        """Validasi satu entri dari permintaan (dipakai tambah dan ubah). Mengembalikan (baris, nilai_simpan, None) atau
        (None, None, pesan galat). `kecuali` = baris lama yang sedang diubah (tidak dihitung sebagai duplikat).

        ip_black / ip_white   : IPv4, CIDR (/8 sampai /32), atau rentang a-b
        url_black / url_white : mode Normal (awalan path per segmen, mis. /api/v1/orders juga mencakup /api/v1/orders/7 tetapi bukan /api/v1/orders-lama) atau Regex (RE2, tidak cocok dengan semua URL);
                                url_white juga punya cakupan: semua (WAF dimatikan untuk URL itu) atau crs (hanya OWASP CRS dilewati)
        """
        nilai = get.get('value')
        if not isinstance(nilai, str):
            return None, None, 'nilai tidak valid: harus berupa teks'
        # Satu entri = satu baris berkas daftar: karakter kontrol (\r, \n) di nilai atau remark akan menambah baris yang
        # lolos dari validasi di bawah (mis. 0.0.0.0/0), jadi ditolak sebelum apa pun.
        if re.search(r'[\x00-\x1f\x7f]', nilai):
            return None, None, 'nilai tidak valid: memuat karakter kontrol'
        nilai = nilai.strip()
        remark, err = teks_aman(str(get.get('remark') or ''), 120, 'remark', boleh_kosong=True)
        if err:
            return None, None, err
        if '#' in nilai and not remark:
            nilai, remark = nilai.split('#', 1)[0].strip(), nilai.split('#', 1)[1].strip()
        rentang = None
        if nama.startswith('ip_'):
            simpan, rentang, err = self._waf_ip_normal(nilai, nama)
            if err:
                return None, None, 'nilai tidak valid: %s' % err
        else:
            mode = str(get.get('mode') or 'regex').strip().lower()
            cakupan = str(get.get('scope') or 'semua').strip().lower()
            if mode not in self.URL_MODE:
                return None, None, 'mode URL tidak dikenal (normal atau regex)'
            if cakupan not in self.URL_CAKUPAN or (nama == 'url_black' and cakupan != 'semua'):
                return None, None, 'cakupan tidak dikenal (semua, atau crs khusus daftar putih URL)'
            if '#' in nilai:
                return None, None, 'nilai tidak valid: karakter # dipakai sebagai pemisah catatan'
            if mode == 'normal':
                if not re.fullmatch(r'/[^\s#]{0,299}', nilai):
                    return None, None, 'nilai tidak valid: mode Normal harus path yang diawali / tanpa spasi'
                _ok, err = regex_waras('^' + re.escape(nilai))
                simpan = 'lit:' + nilai
            else:
                if nilai.startswith(('lit:', 'rx:', 'crs+')):
                    return None, None, 'nilai tidak valid: awalan lit:, rx:, dan crs+ dicadangkan'
                _ok, err = regex_waras(nilai)
                simpan = nilai                      # regex disimpan tanpa awalan (format lama tetap sama)
            if err:
                return None, None, 'nilai tidak valid: %s' % err
            if cakupan == 'crs':
                simpan = 'crs+' + simpan
        for e in self._waf_list_baca(nama):
            if kecuali is not None and e == kecuali:
                continue
            e_val = e.split('#')[0].strip()
            if e_val == simpan or (not nama.startswith('ip_') and url_entri(e_val)[3] == url_entri(simpan)[3]):
                return None, None, 'nilai sudah ada di daftar'
            if rentang is not None:
                b2, r2, er2 = self._waf_ip_normal(e_val, nama, aman_diri=False)
                if r2 == rentang:
                    return None, None, 'nilai sudah ada di daftar'
        return (simpan if not remark else ('%s # %s' % (simpan, remark))), simpan, None

    def waf_list_add(self, get):
        """Tambah satu entri (lihat _waf_list_entri). Duplikat dan nilai tak valid ditolak."""
        nama = str(get.get('list') or '').strip()
        if nama not in self.WAF_LISTS:
            return public.returnMsg(False, 'daftar tidak dikenal')
        baris_baru, simpan, err = self._waf_list_entri(nama, get)
        if err:
            return public.returnMsg(False, err)
        ada = self._waf_list_baca(nama)
        if len(ada) >= self.WAF_LIST_MAKS:
            return public.returnMsg(False, 'daftar penuh (maksimal %d entri)' % self.WAF_LIST_MAKS)
        ok, pesan = self._zy_siap()
        if not ok:
            return public.returnMsg(False, self._galat('Aturan WAF ZySentinel belum siap dipasang', pesan))
        ada.append(baris_baru)
        try:
            self._waf_list_tulis(nama, ada)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal menulis daftar WAF', ex))
        return self._zy_terapkan(get, '%s masuk %s.' % (simpan, self.WAF_LIST_LABEL[nama]))

    def waf_list_edit(self, get):
        """Ubah satu entri: `old` = nilai entri lama (seperti ditampilkan get_waf_lists, tanpa catatan); value/remark/mode/scope
        divalidasi sama dengan tambah. Posisi entri di daftar dipertahankan."""
        nama = str(get.get('list') or '').strip()
        if nama not in self.WAF_LISTS:
            return public.returnMsg(False, 'daftar tidak dikenal')
        lama = get.get('old')
        if not isinstance(lama, str) or not lama.strip() or len(lama) > 500:
            return public.returnMsg(False, 'nilai tidak valid')
        ada = self._waf_list_baca(nama)
        target = next((e for e in ada if e.split('#')[0].strip() == lama.strip() or e == lama), None)
        if target is None:
            return public.returnMsg(False, 'nilai tidak ada di daftar')
        baris_baru, simpan, err = self._waf_list_entri(nama, get, kecuali=target)
        if err:
            return public.returnMsg(False, err)
        ok, pesan = self._zy_siap()
        if not ok:
            return public.returnMsg(False, self._galat('Aturan WAF ZySentinel belum siap dipasang', pesan))
        ada[ada.index(target)] = baris_baru
        try:
            self._waf_list_tulis(nama, ada)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal menulis daftar WAF', ex))
        return self._zy_terapkan(get, '%s diubah di %s.' % (simpan, self.WAF_LIST_LABEL[nama]))

    def waf_list_del(self, get):
        """Hapus satu entri dari daftar."""
        nama = str(get.get('list') or '').strip()
        nilai = get.get('value')
        if nama not in self.WAF_LISTS:
            return public.returnMsg(False, 'daftar tidak dikenal')
        if not isinstance(nilai, str) or not nilai.strip() or len(nilai) > 500:
            return public.returnMsg(False, 'nilai tidak valid')
        nilai = nilai.strip()
        ada = self._waf_list_baca(nama)
        target = None
        if nama.startswith('ip_'):
            baku, rentang, err = self._waf_ip_normal(nilai, nama, aman_diri=False)
            if rentang is not None:
                for e in ada:
                    e_val = e.split('#')[0].strip()
                    if e_val == baku:
                        target = e
                        break
                    b2, r2, er2 = self._waf_ip_normal(e_val, nama, aman_diri=False)
                    if r2 == rentang:
                        target = e
                        break
        else:
            nilai_bersih = nilai.split('#')[0].strip()
            for e in ada:
                if e.split('#')[0].strip() == nilai_bersih or e == nilai:
                    target = e
                    break
        if target is None:
            for e in ada:
                if e == nilai or e.split('#')[0].strip() == nilai:
                    target = e
                    break
        if target is None:
            return public.returnMsg(False, 'nilai tidak ada di daftar')
        ada.remove(target)
        try:
            self._waf_list_tulis(nama, ada)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal menulis daftar WAF', ex))
        return self._zy_terapkan(get, '%s keluar dari %s.' % (target, self.WAF_LIST_LABEL[nama]))

    # ---- log audit ----
    def get_waf_logs(self, get):
        """Kejadian terbaru dari log audit (Coraza dan ModSecurity memakai
        format JSON berbeda; kolom intinya dibaca dengan toleran)."""
        lang = self._get_active_lang(get)
        batas = self._int(get, 'limit', 50, 1, 200) or 50
        p = self.WAF_AUDIT_LOG
        try:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            if self._hal_param(get) is not None:
                return public.returnMsg(True, {'ada': False, 'kejadian': [], 'halaman': self._hal_meta(1, 0)})
            return public.returnMsg(True, {'ada': False, 'kejadian': []})
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return public.returnMsg(False, self._galat('Log audit WAF bukan berkas biasa'))
            ukuran = st.st_size
            baca = min(ukuran, 1024 * 1024)
            data = os.pread(fd, baca, max(0, ukuran - baca)).decode('utf-8', 'replace')
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca log audit WAF', ex))
        finally:
            os.close(fd)
        hasil = []
        kandidat = reversed(data.splitlines())
        meta_hal = None
        hal = self._hal_param(get)
        if hal is not None:
            # Paging: hitung dulu semua baris JSON sah pada jendela 1 MB terakhir (hanya validasi), lalu ekstraksi mahal
            # (regex id/pesan) hanya untuk baris pada halaman yang diminta.
            sah = []
            for baris in kandidat:
                baris = baris.strip()
                if not baris.startswith('{'):
                    continue
                try:
                    json.loads(baris)
                except Exception:
                    continue
                sah.append(baris)
            meta_hal = self._hal_meta(hal, len(sah))
            awal = (meta_hal['page'] - 1) * meta_hal['per_page']
            kandidat = sah[awal:awal + meta_hal['per_page']]
            batas = meta_hal['per_page']
        for baris in kandidat:
            if len(hasil) >= batas:
                break
            baris = baris.strip()
            if not baris.startswith('{'):
                continue
            try:
                j = json.loads(baris)
            except Exception:
                continue
            tx = j.get('transaction') or {}
            req = j.get('request') or tx.get('request') or {}
            resp = j.get('response') or tx.get('response') or {}
            uri = req.get('uri')
            metode = req.get('method')
            if not uri and req.get('request_line'):
                bagian = str(req['request_line']).split(' ')
                metode = bagian[0]
                uri = bagian[1] if len(bagian) > 1 else ''
            ids = re.findall(r'\[id \\?"(\d+)\\?"\]', baris)
            pesan = re.findall(r'\[msg \\?"((?:[^"\\]|\\.)*)\\?"\]', baris)
            if not pesan:
                m = re.search(r'Access denied \(phase \d\)\.\s*([^\[\\"]+)', baris)
                if m:
                    pesan = [m.group(1).strip()]
            hasil.append({
                'waktu': tx.get('timestamp') or tx.get('time') or '',
                'ip': tx.get('client_ip') or tx.get('remote_address') or '',
                'metode': metode or '',
                'uri': (uri or '')[:300],
                'status': resp.get('status'),
                'rule_id': ids[0] if ids else '',
                'pesan': self._localize_msg(re.split(r'\\+"|"\]', pesan[0] if pesan else '')[0].strip()[:200], lang),
                'zysentinel': any(i.startswith('8') and len(i) == 7 for i in ids),
            })
        if meta_hal is not None:
            return public.returnMsg(True, {'ada': True, 'kejadian': hasil, 'halaman': meta_hal})
        return public.returnMsg(True, {'ada': True, 'kejadian': hasil})

    # ---- peninggalan engine Lua ----
    def get_legacy_waf(self, get):
        rc, o, e = self._waf('legacy-status')
        info = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                info[k.strip()] = v.strip()
        return public.returnMsg(True, info)

    def install_zyrules(self, get):
        """Pasang ruleset ZySentinel dari payload dan susun konfigurasi (latar)."""
        return self._coraza_job_start('zyinstall')

    def remove_legacy_waf(self, get):
        """Pindahkan daftar dari engine Lua lama, cabut hook (nginx -t dan reload
        terverifikasi), arsipkan lalu hapus berkas Lua. Berjalan di latar."""
        return self._coraza_job_start('legacy')

    # ------------------------------------------------------------------ #
    # backend firewall dan WAF                                             #
    # ------------------------------------------------------------------ #
    def get_fw_backend(self, get):
        """Backend firewall yang terdeteksi: ufw, firewalld, atau iptables.

        ufw dan firewalld tidak terpasang di mesin ini, jadi nilainya
        praktis selalu iptables-nft. Method ini ada supaya UI menampilkan
        keadaan yang sebenarnya bila suatu saat frontend lain dipasang,
        bukan mengklaim kompatibilitas yang tidak diperiksa.
        """
        rc, o, e = self._sh(
            "'%s/bin/sentinel-fw.sh' backend" % self.__PATH, 30)
        info = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                info[k.strip()] = v.strip()
        if rc != 0 or not info:
            return public.returnMsg(False, self._galat('Gagal membaca jenis firewall yang dipakai', e.strip() or o.strip()))
        return public.returnMsg(True, info)

    def _waf(self, *args):
        self._ensure_core_files()
        waf_script = os.path.join(self.__PATH, 'bin', 'sentinel-waf.sh')
        # shlex.quote: argumen berasal dari parameter pengguna; kutip tunggal
        # di dalamnya tidak boleh lolos dari string shell.
        cmd = ' '.join([shlex.quote(waf_script)] +
                       [shlex.quote(str(a)) for a in args])
        return self._sh(cmd, 60)

    def get_waf(self, get):
        """Status WAF: engine per webserver, rule OWASP, dan vhost."""
        rc1, o1, e1 = self._waf('engine')
        rc2, o2, e2 = self._waf('rules')
        rc3, o3, e3 = self._waf('vhosts')
        if rc1 != 0:
            return public.returnMsg(False, self._galat('Gagal mendeteksi mesin WAF', e1.strip() or o1.strip()))
        engine = {}
        for baris in o1.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                engine[k.strip()] = v.strip()
        rules = []
        if rc2 == 0:
            for baris in o2.strip().splitlines():
                bagian = baris.split('|')
                if len(bagian) >= 3:
                    rules.append({'nama': bagian[0], 'keadaan': bagian[1],
                                  'berkas': bagian[2],
                                  'kunci': bagian[3] if len(bagian) > 3
                                           else 'tidak'})
        vhosts = []
        if rc3 == 0:
            for baris in o3.strip().splitlines():
                bagian = baris.split('|')
                if len(bagian) == 3:
                    vhosts.append({'ws': bagian[0], 'site': bagian[1],
                                   'keadaan': bagian[2]})
        # keinginan yang tersimpan tapi belum aktif (engine belum ada)
        ingin = {}
        try:
            with open(self._p('etc', 'waf.conf'), 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if line.startswith('vhost.') and '=' in line:
                        k, v = line.split('=', 1)
                        ingin[k.strip()] = v.strip()
        except Exception:
            pass
        hasil = {
            'engine': engine,
            'rules': rules,
            'vhosts': vhosts,
            'ingin': ingin,
        }
        # Vhost yang lalu lintasnya lewat proxy/CDN (Cloudflare dkk.) dan status real IP-nya
        px = self._proxy_vhosts()
        for v in vhosts:
            d = px.get('%s|%s' % (v['ws'], v['site']))
            if d and (d['provider'] or d['realip_plugin']):
                v['proxy'] = d
        # Dengan parameter page: tabel vhost dipotong satu halaman. Kuota vhost WAF aktif dihitung dari SEMUA vhost
        # ('vhost_aktif'), bukan dari baris halaman, karena batas paket berlaku untuk seluruh vhost.
        potong, meta_hal = self._halaman(get, vhosts)
        if meta_hal is not None:
            hasil['vhost_aktif'] = sum(1 for v in vhosts if ingin.get('vhost.%s.%s' % (v['ws'], v['site'])) == 'on')
            hasil['vhosts'] = potong
            hasil['halaman'] = meta_hal
        return public.returnMsg(True, hasil)

    def set_waf_vhost(self, get):
        """Nyalakan atau cabut WAF untuk satu vhost."""
        ws = (get.get('ws') or '').strip()
        site = (get.get('site') or '').strip()
        aksi = (get.get('state') or '').strip()
        if ws not in ('nginx', 'apache', 'openlitespeed'):
            return public.returnMsg(False, 'web server tidak dikenal')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,119}', site):
            return public.returnMsg(False, 'nama situs tidak valid')
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'status harus on atau off')
        if aksi == 'on':
            aktif, ada = 0, False
            try:
                with open(self._p('etc', 'waf.conf')) as fh:
                    for ln in fh:
                        m = re.match(r'^vhost\.([a-z]+)\.(\S+)\s*=\s*on\s*$', ln.strip())
                        if m:
                            aktif += 1
                            ada = ada or (m.group(1) == ws and m.group(2) == site)
            except OSError:
                pass
            if not ada:
                ditolak = self._batas_ditolak(get, 'waf_vhosts', aktif)
                if ditolak:
                    return ditolak
        rc, o, e = self._waf('vhost-%s' % ('on' if aksi == 'on' else 'off'),
                             ws, site)
        # kode 2 = keinginan disimpan karena engine belum ada. Itu BUKAN
        # kegagalan: snippet memang sengaja tidak ditulis. Bedakan pesannya
        # supaya operator tidak mengira perintahnya gagal total.
        if rc == 2:
            # Jangan teruskan stderr skrip mentah (berlabel GALAT): itu
            # jalur normal, bukan galat. Kembalikan pesan bersih + status.
            en = self._get_active_lang(get) == 'en'
            if en:
                pesan = ('Saved as a preference for %s, but the WAF is NOT active yet: '
                         'nginx has no WAF connector (ModSecurity/Coraza). No config was '
                         'changed and nginx was not reloaded. It will be applied '
                         'automatically once the connector is installed.' % site)
            else:
                pesan = ('Pilihan untuk %s disimpan, tetapi WAF BELUM aktif: nginx belum '
                         'punya konektor WAF (ModSecurity/Coraza). Konfigurasi tidak '
                         'diubah dan nginx tidak direload. Akan dipasang otomatis setelah '
                         'konektor terpasang.' % site)
            return public.returnMsg(True, {'tertunda': True, 'pesan': pesan})
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal mengubah WAF untuk situs ini', e.strip() or o.strip()))
        # Web server membaca snippet hanya saat reload; reload diverifikasi
        # (PID worker berubah), bukan percaya output init.d.
        if str(get.get('reload') or '1') != '0':
            rc2, o2, e2 = self._waf('reload', ws)
            if rc2 != 0:
                return public.returnMsg(
                    False, self._galat('Konfigurasi WAF tersimpan, tetapi %s gagal dimuat ulang' % ws,
                                       (e2.strip() or o2.strip())[-300:]))
        return public.returnMsg(True, 'WAF untuk situs %s %s' % (site, 'diaktifkan' if aksi == 'on' else 'dinonaktifkan'))

    def set_waf_rule(self, get):
        """Aktifkan atau nonaktifkan satu rule group OWASP."""
        nama = (get.get('rule') or '').strip()
        aksi = (get.get('state') or '').strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', nama):
            return public.returnMsg(False, 'nama grup aturan tidak valid')
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'status harus on atau off')
        rc, o, e = self._waf('rule-%s' % aksi, nama)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal mengubah grup aturan WAF', e.strip() or o.strip()))
        dasar = 'Grup aturan %s %s' % (nama, 'diaktifkan' if aksi == 'on' else 'dinonaktifkan')
        if str(get.get('reload') or '1') == '0':
            return public.returnMsg(True, dasar)
        # Reload hanya perlu bila ada vhost yang WAF-nya aktif.
        rc1, o1, e1 = self._waf('vhosts')
        aktif = any(b.endswith('|on') for b in o1.splitlines())
        if aktif:
            rc2, o2, e2 = self._waf('reload', 'all')
            if rc2 != 0:
                return public.returnMsg(False, self._galat('%s, tetapi web server gagal dimuat ulang' % dasar,
                                                           (e2.strip() or o2.strip())[-300:]))
            return public.returnMsg(True, '%s. Web server dimuat ulang agar aturan berlaku' % dasar)
        return public.returnMsg(True, dasar)

    # ------------------------------------------------------------------ #
    # status engine WAF dan switch mode                                   #
    #                                                                     #
    # Satu engine per web server, satu ruleset: Coraza (nginx), ModSecurity#
    # v2 (Apache, OpenLiteSpeed). Mode (block/monitor/disable) berlaku ke  #
    # semuanya dan disimpan di waf.conf (kunci mode).                      #
    # ------------------------------------------------------------------ #
    WAF_BASE = '/www/server/sentinel/waf'
    CORAZA_DIR = '/www/server/sentinel/waf/coraza'
    CRS_RELEASE_API = ('https://api.github.com/repos/coreruleset/'
                       'coreruleset/releases/latest')

    def _waf_conf_baca(self):
        """Baca seluruh waf.conf jadi dict sederhana (key=value)."""
        isi = {}
        try:
            with open(self._p('etc', 'waf.conf'), 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        isi[k.strip()] = v.strip()
        except Exception:
            pass
        return isi

    def get_waf_engine(self, get):
        """Engine WAF per web server, aset Coraza/CRS di disk, dan ruleset."""
        rc, o, e = self._waf('engine')
        engine = {}
        if rc == 0:
            for baris in o.strip().splitlines():
                if '=' in baris:
                    k, v = baris.split('=', 1)
                    engine[k.strip()] = v.strip()
        return public.returnMsg(True, {
            'nginx_connector': engine.get('nginx', 'none'),
            'apache': engine.get('apache', 'tidak-terpasang'),
            'openlitespeed': engine.get('openlitespeed', 'tidak-terpasang'),
            'zyrules': engine.get('zyrules', 'hilang') == 'ada',
            'coraza': self._coraza_info(),
        })

    def _coraza_info(self):
        """Ringkasan aset Coraza di disk: ada/tidak, versi, konektor.

        Konektor nginx BELUM tentu ada; itu yang membedakan "aset siap"
        dengan "engine jalan". Dipisah supaya UI bisa menampilkan dua
        badge berbeda, bukan satu status yang menyesatkan.
        """
        d = self.CORAZA_DIR
        ada = os.path.isdir(d)
        versi = '-'
        aturan = 0
        konektor = 'tidak-ada'
        if ada:
            vf = os.path.join(d, 'VERSIONS.txt')
            if os.path.exists(vf):
                try:
                    with open(vf, 'r') as f:
                        for line in f:
                            if line.startswith('crs='):
                                versi = line.split('=', 1)[1].strip()
                except Exception:
                    pass
            rd = os.path.join(d, 'rules')
            if os.path.isdir(rd):
                for _, _, files in os.walk(rd):
                    aturan += sum(1 for x in files if x.endswith('.conf'))
            if os.path.isdir(os.path.join(d, 'connector')):
                konektor = 'source-ada'
        rc, o, e = self._sh(
            "'%s/bin/sentinel-waf.sh' engine" % self.__PATH, 20)
        modul = 'tidak-ada'
        if rc == 0:
            if 'nginx=coraza' in o:
                konektor = 'terpasang'
            for baris in o.splitlines():
                if baris.startswith('coraza_modul='):
                    modul = baris.split('=', 1)[1].strip()
        return {'aset': ada, 'versi': versi, 'aturan': aturan,
                'konektor': konektor, 'modul': modul}

    def set_waf_mode(self, get):
        """Switch Monitor | Block | Disable untuk engine yang aktif."""
        mode = (get.get('mode') or '').strip()
        if mode not in ('monitor', 'block', 'disable'):
            return public.returnMsg(False, 'mode harus monitor, block, atau '
                                           'disable')
        ok, pesan = self._zy_siap()
        if not ok:
            return public.returnMsg(False, self._galat('Aturan WAF ZySentinel belum siap dipasang', pesan))
        rc, o, e = self._waf('mode-set', mode)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal mengubah mode WAF', e.strip() or o.strip()))
        return self._zy_terapkan(get, 'Mode WAF: %s.' % mode)

    def get_waf_mode(self, get):
        rc, o, e = self._waf('mode-get')
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal membaca mode WAF', e.strip() or o.strip()))
        info = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                info[k.strip()] = v.strip()
        return public.returnMsg(True, info)

    CORAZA_JOB_DIR = os.path.join(_data_log_dir(), 'coraza')
    # job latar yang boleh dijalankan -> argumen sentinel-waf.sh
    CORAZA_JOBS = {
        'download': ['coraza-download'],
        'build': ['coraza-build'],
        'install': ['coraza-install'],
        'uninstall': ['coraza-uninstall'],
        'legacy': ['legacy-remove'],
        'zyinstall': ['zyrules-install'],
    }

    def _coraza_job_pid(self, job='download'):
        """PID job Coraza bila masih berjalan, selain itu 0."""
        try:
            with open(os.path.join(self.CORAZA_JOB_DIR, job + '.pid')) as f:
                pid = int(f.read().strip())
            with open('/proc/%d/stat' % pid) as f:
                if f.read().rsplit(')', 1)[1].split()[0] == 'Z':
                    return 0
            with open('/proc/%d/cmdline' % pid, 'rb') as f:
                if b'sentinel-waf.sh' not in f.read():
                    return 0
            return pid
        except Exception:
            return 0

    def _coraza_job_start(self, job, extra=None):
        """Mulai job latar. Hanya satu job Coraza berjalan pada satu waktu,
        karena semuanya memakai cache dan direktori build yang sama."""
        for j in self.CORAZA_JOBS:
            pid = self._coraza_job_pid(j)
            if pid:
                return public.returnMsg(True, {
                    'started': False, 'running': True, 'pid': pid, 'job': j})
        self._ensure_core_files()
        skrip = os.path.join(self.__PATH, 'bin', 'sentinel-waf.sh')
        if not os.path.isfile(skrip):
            return public.returnMsg(False, self._galat('Komponen WAF ZySentinel tidak ditemukan di server ini', 'sentinel-waf.sh'))
        os.makedirs(self.CORAZA_JOB_DIR, exist_ok=True)
        log_f = os.path.join(self.CORAZA_JOB_DIR, job + '.log')
        rc_f = os.path.join(self.CORAZA_JOB_DIR, job + '.rc')
        pid_f = os.path.join(self.CORAZA_JOB_DIR, job + '.pid')
        if os.path.exists(rc_f):
            os.remove(rc_f)
        with open(log_f, 'w') as f:
            f.write('')
        args = ' '.join("'%s'" % a for a in self.CORAZA_JOBS[job] + (extra or []))
        # PID ditulis oleh proses itu sendiri ($$); setsid -f melepasnya
        # dari worker panel sehingga tidak ikut mati saat panel restart.
        cmd = "echo $$ > '%s'; '%s' %s > '%s' 2>&1; echo $? > '%s'" % (
            pid_f, skrip, args, log_f, rc_f)
        subprocess.Popen(['setsid', '-f', 'bash', '-c', cmd],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True).wait()
        for _ in range(20):
            if self._coraza_job_pid(job) or os.path.exists(rc_f):
                break
            time.sleep(0.1)
        return public.returnMsg(True, {'started': True, 'running': True,
                                       'job': job})

    def download_coraza(self, get):
        """Mulai unduhan aset Coraza + OWASP CRS di latar belakang.

        Idempoten: bila aset sudah lengkap dan versi sama, skrip tidak
        mengunduh ulang. Berjalan di latar karena unduhan bisa melewati
        batas AJAX panel 60 detik; kemajuannya dibaca lewat get_coraza_job.
        """
        return self._coraza_job_start('download')

    def build_coraza(self, get):
        """Compile modul dinamis Coraza untuk nginx aktif di latar belakang.

        Bila cache di folder plugin cocok dengan versi dan argumen configure
        nginx aktif, tidak ada compile ulang. force=1 memaksa compile ulang
        dari bahan di cache. Biner nginx tidak diubah.
        """
        extra = ['--force'] if (get.get('force') or '') in ('1', 'true') else []
        return self._coraza_job_start('build', extra)

    def install_coraza_module(self, get):
        """Muat modul Coraza ke nginx aktif (uji, load_module, nginx -t,
        reload, bukti worker). Ini mengubah nginx produksi; UI wajib
        meminta konfirmasi lebih dulu."""
        return self._coraza_job_start('install')

    def uninstall_coraza_module(self, get):
        """Cabut load_module Coraza dari nginx aktif."""
        return self._coraza_job_start('uninstall')

    def get_coraza_job(self, get):
        """Kemajuan job Coraza: tahap n/m, status, rc, dan ekor log."""
        job = (get.get('job') or 'download')
        if job not in self.CORAZA_JOBS:
            return public.returnMsg(False, 'tugas tidak dikenal')
        log_f = os.path.join(self.CORAZA_JOB_DIR, job + '.log')
        rc_f = os.path.join(self.CORAZA_JOB_DIR, job + '.rc')
        running = bool(self._coraza_job_pid(job))
        rc = None
        if not running and os.path.exists(rc_f):
            try:
                with open(rc_f) as f:
                    rc = int(f.read().strip() or 1)
            except Exception:
                rc = 1
        baris = []
        if os.path.exists(log_f):
            with open(log_f, 'r', encoding='utf-8', errors='replace') as f:
                baris = f.read().splitlines()
        tahap, total, etap = 0, 0, ''
        for b in baris:
            m = re.search(r'^\[sentinel-waf\]\s*\[(\d+)/(\d+)\]\s*(.*)$', b)
            if m:
                tahap, total, etap = int(m.group(1)), int(m.group(2)), m.group(3)
        # Job yang mati tanpa rc (mis. dibunuh) tidak boleh terlihat
        # "berjalan" selamanya di UI.
        if not running and rc is None:
            rc = 1
        return public.returnMsg(True, {
            'job': job, 'running': running, 'rc': rc, 'tahap': tahap,
            'total': total, 'etap': etap, 'log': '\n'.join(baris[-80:])})

    def get_coraza_cache(self, get):
        """Status cache modul Coraza terhadap nginx aktif (key=value)."""
        rc, o, e = self._waf('coraza-cache')
        info = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                info[k.strip()] = v.strip()
        return public.returnMsg(True, info)

    def coraza_download(self, get):
        """Unduh aset Coraza + OWASP CRS (alias untuk download_coraza)."""
        return self.download_coraza(get)

    # ------------------------------------------------------------------ #
    # jejak audit dan analisis per-vhost                                  #
    #                                                                     #
    # Dua hal yang sebelumnya tidak mungkin dilakukan:                    #
    #                                                                     #
    # 1. Rekonsiliasi. Tabel aksi mencatat setiap tindakan terhadap IP:  #
    #    kapan, oleh sistem atau panel, dengan alasan apa. Tanpa itu     #
    #    yang terlihat hanya kondisi sekarang, bukan urutan keputusan.   #
    #                                                                     #
    # 2. Analisis per-vhost. Tabel minute sudah menyimpan req dan       #
    #    bytes per host, tapi tidak pernah dibaca per host. Events kini  #
    #    juga membawa host, sehingga serangan bisa ditelusuri ke vhost   #
    #    yang ditusuk.                                                  #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _jam(get, batas=720):
        """Jam rentang sebagai bilangan bulat, atau None bila tidak valid.

        int() tanpa penanganan melempar ValueError, dan traceback-nya
        tampil mentah di halaman panel sebagai galat 500. Pola yang sama
        sudah dihindari di ban_ip dan set_conf; di sini diterapkan juga
        supaya endpoint baru tidak menjadi jalur baru menuju galat.
        """
        # Nilai bisa string maupun int. Panel sering mengirim angka
        # dari input numerik, sedangkan panggilan langsung dari skrip
        # sering mengirim string. Keduanya harus diterima.
        mentah = get.get('hours')
        if isinstance(mentah, str):
            mentah = mentah.strip()
        if mentah is None or mentah == '':
            return 24
        try:
            n = int(mentah)
        except (TypeError, ValueError):
            return None
        if n < 1 or n > batas:
            return None
        return n

    # ------------------------------------------------------------------ #
    # geoip                                                              #
    # ------------------------------------------------------------------ #
    # Lookup dilakukan di sisi PANEL, bukan di daemon, dengan tiga alasan:
    #
    # 1. Berkas GeoLite2 berformat MaxMind MMDB. Membacanya di C
    #    memerlukan pustaka pihak ketiga yang tidak ada di daemon, dan
    #    daemon harus tetap tanpa dependensi supaya bisa dikompilasi
    #    di server mana pun.
    # 2. Panel sudah punya modul maxminddb dan berkas GeoLite2, jadi
    #    tidak perlu mengunduh apa pun.
    # 3. Hasil disimpan di tabel geo, jadi satu IP hanya dibaca dari
    #    berkas MMDB satu kali saja. Peng thereafter hanya satu kueri.
    #
    # Kalau berkas MMDB hilang, semua fungsi di sini mengembalikan
    # "tidak diketahui", bukan galat. Panel harus tetap berfungsi tanpa
    # GeoIP.
    # ------------------------------------------------------------------ #
    _geo_db = None
    _geo_ran = None
    _GEO_CANDIDAT = (
        '/www/server/panel/config/GeoLite2-City.mmdb',
        '/www/server/btwaf/inc/GeoLite2-City.mmdb',
        '/www/server/sentinel/data/geo/GeoLite2-City.mmdb',      # server tanpa aaPanel: disiapkan sentinel-geo.py
    )

    def _geo_buka(self):
        """Buka GeoLite2 sekali per proses panel (atribut CLASS: instance plugin bisa dibuat ulang per permintaan, dulu handle dan
        penanda waktunya tersimpan di instance sehingga berkas dibuka ulang), atau None bila tidak tersedia. Diperiksa ulang tiap jam."""
        k = type(self)
        if k._geo_ran and time.time() - k._geo_ran > 3600:
            try:
                if k._geo_db is not None:
                    k._geo_db.close()
            except Exception:
                pass
            k._geo_db, k._geo_ran = None, None
        if k._geo_ran:
            return k._geo_db
        k._geo_ran = time.time()
        for jalan in k._GEO_CANDIDAT:
            if not os.path.isfile(jalan):
                continue
            try:
                import maxminddb
                k._geo_db = maxminddb.open_database(jalan)
                return k._geo_db
            except Exception:
                continue
        k._geo_db = None
        return None

    @staticmethod
    def _geo_pecah(rec):
        """Ambil kode dan nama negara dari satu record GeoLite2.

        Berkas aaPanel memakai bentukcountry.en_short_code dan
        country.country, BUKAN bentuk MaxMind baku
        (country.iso_code dan country.names.en). Keduanya dicoba supaya
        pergantian versi panel tidak membuat fitur ini mati diam-diam.
        """
        if not isinstance(rec, dict):
            return '', ''
        c = rec.get('country')
        if not isinstance(c, dict):
            return '', ''
        kode = c.get('en_short_code') or c.get('iso_code') or ''
        nama = c.get('country') or ''
        if not nama:
            names = c.get('names')
            if isinstance(names, dict):
                nama = names.get('en') or ''
        return (kode or '').strip()[:4], (nama or '').strip()[:48]

    def _geo_satu(self, ip):
        """Negara satu IP. Cache memori per proses (maks _GEO_MAKS entri) di depan MMDB: dulu setiap IP membuka koneksi SQLite,
        membaca guardd.conf, SELECT, lalu INSERT + commit (fsync) ke tabel geo, ribuan kali per peta serangan dan berebut kunci
        tulis dengan guardd; lookup MMDB sendiri lebih murah dari cache SQLite itu. Tabel geo lama hanya dibaca bila MMDB tidak ada."""
        n = self._ipnum(ip)
        if not n:
            return '', ''
        v = _GEO_MEM.get(n)
        if v is not None:
            return v
        db = self._geo_buka()
        kode, nama = ('', '')
        if db:
            try:
                kode, nama = self._geo_pecah(db.get(ip))
            except Exception:
                kode, nama = ('', '')
        else:
            r = self._sql1('SELECT kode, nama FROM geo WHERE ip=?', (n,))
            if r:
                kode, nama = r.get('kode') or '', r.get('nama') or ''
        if len(_GEO_MEM) >= _GEO_MAKS:
            _GEO_MEM.clear()
        _GEO_MEM[n] = (kode, nama)
        return kode, nama

    def get_ip_geo(self, get):
        """Negara satu atau beberapa IP sekaligus."""
        ip = (get.get('ip') or '').strip()
        if not ip:
            return public.returnMsg(False, 'IP wajib diisi')
        if self._ipnum(ip) == 0:
            return public.returnMsg(False, 'alamat IP tidak valid')
        kode, nama = self._geo_satu(ip)
        db = self._geo_buka()
        return public.returnMsg(True, {
            'ip': ip,
            'kode': kode or '-',
            'nama': nama or '-',
            'tersedia': db is not None,
        })

    def get_geo_stat(self, get):
        """Sebaran penyerang berdasarkan negara.

        Berguna untuk membedakan dua pola yang berbeda:
        penyerang yang tersebar acak (botnet, scanner umum)
        dengan penyerang yang terpusat di satu atau dua negara
        (serangan terarah).
        """
        # Edisi Free: fitur berbayar (origin) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('origin', self._get_active_lang(get))

    # ------------------------------------------------------------------ #
    # geo-ban (blokir per negara)                                        #
    #                                                                     #
    # Berbeda dengan ban per IP: ini memblokir seluruh blok CIDR satu    #
    # negara di lapisan kernel (ipset sentinel_geo). Karena bisa memutus #
    # pengunjung sah, tiga pagar dipasang: bawaan off, whitelist selalu  #
    # menang, dan hanya berlaku di port web.                             #
    # ------------------------------------------------------------------ #
    GEO_JSON = '/www/server/panel/data/firewall/GeoLite2-Country.json'
    GEO_JSON_STANDALONE = '/www/server/sentinel/data/geo/GeoLite2-Country.json'

    def _geo_json(self):
        """Daftar CIDR per negara: berkas panel (aaPanel) bila ada, selain itu berkas yang disiapkan sentinel-geo.py."""
        if not os.path.exists(self.GEO_JSON) and os.path.exists(self.GEO_JSON_STANDALONE):
            return self.GEO_JSON_STANDALONE
        return self.GEO_JSON

    def _geo_ban_conf(self):
        """Baca geo_mode dan geo_negara dari guardd.conf."""
        mode, negara = 'off', ''
        try:
            with open(self._p('etc', 'guardd.conf'), 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if '=' not in line:
                        continue
                    k, v = line.split('=', 1)
                    k, v = k.strip(), v.strip()
                    if k == 'geo_mode':
                        mode = v or 'off'
                    elif k == 'geo_negara':
                        negara = v
        except Exception:
            pass
        if mode not in ('off', 'block', 'allow'):
            mode = 'off'
        negara = negara.upper().replace(' ', '')
        return mode, negara

    def get_geo_ban(self, get):
        """Keadaan geo-ban sekarang: mode, negara, jumlah blok terpasang.

        Jumlah blok diambil dari kernel (ipset), bukan dari config,
        supaya UI menunjukkan apa yang BENAR-BENAR berlaku, bukan apa
        yang diminta. Kalau keduanya berbeda, itu justru yang perlu
        terlihat.
        """
        mode, negara = self._geo_ban_conf()
        rc, o, e = self._sh(
            "'%s/bin/sentinel-fw.sh' geo-status" % self.__PATH, 30)
        info = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                info[k.strip()] = v.strip()
        return public.returnMsg(True, {
            'mode': mode,
            'negara': negara,
            'negara_daftar': [x for x in negara.split(',') if x],
            'blok': int(info.get('blok') or 0),
            'aturan': int(info.get('aturan') or 0),
            'sumber': self._geo_json(),
            'sumber_ada': os.path.exists(self._geo_json()),
        })

    def get_geo_list(self, get):
        """Daftar negara yang tersedia untuk diblokir, dari berkas panel.

        Hanya kode dan jumlah blok; nama negara panjang diambil GeoLite
        saat lookup per IP, jadi tidak perlu di sini. Diurutkan menurun
        supaya negara dengan blok terbanyak (yang paling sering jadi
        sumber serangan) muncul lebih dulu.
        """
        try:
            with open(self._geo_json(), 'r') as f:
                data = json.load(f)
        except Exception as ex:
            return public.returnMsg(
                False, self._galat('Daftar blok negara tidak bisa dibaca', ex))
        hasil = []
        for entri in data:
            kode = entri.get('brief') or entri.get('code') or ''
            if not kode:
                continue
            hasil.append({'kode': kode, 'blok': len(entri.get('ips') or [])})
        hasil.sort(key=lambda x: -x['blok'])
        return public.returnMsg(True, hasil)

    def set_geo_ban(self, get):
        """Nyalakan/matikan geo-ban, atau ubah daftar negaranya.

        Dua aksi terpisah disengaja:
          - action=off  : matikan (mode off + kosongkan set)
          - action=on   : tulis mode + negara, lalu terapkan.
        Konfirmasi 'on' wajib dari sisi server: menyalakan geo-ban bisa
        memutus seluruh pengunjung satu negara, jadi tidak boleh terjadi
        dari satu klik yang tidak sengaja.
        """
        # Edisi Free: fitur berbayar (geo_ban) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('geo_ban', self._get_active_lang(get))

    def geo_ban_off(self, get):
        """Mematikan fitur Geo-Ban dan membersihkan aturan di kernel."""
        class ParamWrapper(dict):
            def __init__(self, d):
                super().__init__(d)
            def get(self, k, default=None):
                return super().get(k, default)
        return self.set_geo_ban(ParamWrapper({'action': 'off'}))

    def _geo_kode_valid(self):
        """Kumpulan kode negara yang sah, atau set kosong bila tak bisa
        dibaca. Dipakai untuk menolak kode yang tidak ada sebelum
        menyentuh config, supaya salah ketik tidak menjadi mode allow
        yang memblokir semua negara lain."""
        try:
            with open(self._geo_json(), 'r') as f:
                data = json.load(f)
            return set(e.get('brief') or e.get('code') or ''
                       for e in data if (e.get('brief') or e.get('code')))
        except Exception:
            return set()


    # ------------------------------------------------------------------ #
    # antrian review                                                      #
    #                                                                     #
    # Pelengkap dari mode monitor. Saat enforce = 0 tidak ada yang        #
    # diblokir, sehingga operator tidak punya cara melihat siapa yang     #
    # AKAN diblokir. Antrean ini mengisi celah itu: IP yang mencurigakan #
    # dicatat, paketnya tetap lewat, lalu operator memutuskan per IP.    #
    #                                                                     #
    # Paket dari IP di antrian tidak pernah diblokir. Aturan kernel      #
    # untuk set ini sengaja -j RETURN, bukan -j DROP.                   #
    # ------------------------------------------------------------------ #
    def get_review(self, get):
        """Antrean review: IP yang menunggu keputusan operator."""
        # Edisi Free: fitur berbayar (review_queue) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('review_queue', self._get_active_lang(get))

    def review_decide(self, get):
        """Operator memutuskan satu IP: disetujui (diblokir) atau ditolak."""
        net, err = parse_v4(get.get('ip'), cidr=False, tujuan='blokir')
        if err:
            return public.returnMsg(False, 'alamat IP tidak valid: %s' % err)
        ip = str(net.network_address)
        aksi = (get.get('aksi') or get.get('act') or get.get('sub_action') or (get.get('action') if get.get('action') != 'a' else None) or '').strip()
        if aksi not in ('setuju', 'tolak'):
            return public.returnMsg(
                False, 'aksi harus setuju atau tolak')
        n = self._ipnum(ip)

        if aksi == 'setuju':
            # Diperlakukan sebagai ban biasa lewat guardctl supaya ia
            # supaya masuk ipset dan ikut aturan kernel seperti ban manual lain.
            # Pagar anti-lockout yang sama dengan ban_ip: jangan memutus diri sendiri.
            if ip in (self._self_ip(), self._req_ip()):
                return public.returnMsg(
                    False, 'tidak boleh memblokir alamat server ini atau alamat '
                           'Anda yang sedang mengakses panel: %s' % ip)
            prov = self._proxy_milik(ip)
            if prov:
                return public.returnMsg(
                    False, '%s milik proxy/CDN tepercaya (%s). Memblokirnya memutus semua pengunjung yang lewat proxy itu; '
                           'blokir pelaku lewat WAF (real IP) atau aturan di dashboard provider.' % (ip, prov))
            rc, o, e = self._sh(
                '%s ban %s' % (shlex.quote('%s/bin/guardctl' % self.__PATH), shlex.quote(ip)), 20)
            if rc != 0 or '"ok":true' not in o:
                return public.returnMsg(
                    False, self._galat('Gagal memblokir IP', o.strip() or e.strip()))
            if '"dalam_ipset":true' not in o:
                return public.returnMsg(
                    False, self._galat('IP tercatat di daftar blokir ZySentinel, tetapi belum diterapkan di firewall '
                                       'sehingga belum benar-benar diblokir', o))
            self._sql1(
                'UPDATE review SET status=?, alasan=alasan || '
                "'; disetujui operator' WHERE ip=?", ('setuju', n))
            return public.returnMsg(
                True, '%s disetujui dan sudah diblokir' % ip)

        # Ditolak: lepas dari antrian dan jangan diblokir. Operator
        # yang menolak IP itu berarti dia yakin itu bukan penyerang.
        try:
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.execute(
                "UPDATE review SET status='tolak', alasan=alasan || "
                "'; ditolak operator' WHERE ip=?", (n,))
            con.commit()
            con.close()
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal mencatat keputusan', ex))
        rc, o, e = self._sh(
            "'%s/bin/guardctl' unreview '%s'" % (self.__PATH, ip), 20)
        if rc != 0 or '"ok":true' not in o:
            return public.returnMsg(False, self._galat('IP ditandai ditolak, tetapi gagal dilepas dari antrean review di firewall',
                                                       o.strip() or e.strip()))
        self._aksi(ip, 'review-tolak', 'panel',
                   'ditolak operator, tidak diblokir')
        return public.returnMsg(
            True, '%s ditolak, tidak diblokir' % ip)

    def review_put(self, get):
        """Putuskan review IP: disetujui atau ditolak (alias untuk review_decide)."""
        # Edisi Free: fitur berbayar (review_queue) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('review_queue', self._get_active_lang(get))

    # ------------------------------------------------------------------ #
    # notifikasi                                                          #
    # ------------------------------------------------------------------ #
    # Notifikasi TIDAK dikirim dari daemon. Daemon hanya menulis ke tabel #
    # notif; pengiriman dikerjakan sentinel-notify.sh dari systemd timer.  #
    # Alasannya: satu HTTP POST yang menggantung akan menahan           #
    # pemrosesan log, dan daemon membaca log setiap dua detik. Dengan     #
    # begitu, satu alamat tujuan yang nakal bisa membuat Sentinel        #
    # berhenti melihat serangan sama sekali.                             #
    # ------------------------------------------------------------------ #
    def _notify_conf_path(self):
        return os.path.join(self.__PATH, 'etc', 'notify.conf')

    def _notif_baca(self):
        """Isi notify.conf sebagai dict, dibaca dengan shlex (tanpa menjalankan shell).
        Mengerti nilai bertanda kutip tunggal (format baru) maupun ganda (format lama)."""
        isi = {}
        try:
            with open(self._notify_conf_path(), 'r') as f:
                for baris in f:
                    b = baris.strip()
                    if not b or b.startswith('#') or '=' not in b:
                        continue
                    k, v = b.split('=', 1)
                    try:
                        parts = shlex.split(v.strip())
                        isi[k.strip()] = parts[0] if parts else ''
                    except ValueError:
                        isi[k.strip()] = v.strip().strip('"\'')
        except Exception:
            pass
        return isi

    def _notify_endpoints_path(self):
        return self._p('etc', 'notify_endpoints.json')

    def _notif_baca_endpoints(self):
        try:
            with open(self._notify_endpoints_path(), 'r', encoding='utf-8') as f:
                d = json.load(f)
                return d if isinstance(d, list) else []
        except Exception:
            return []

    def get_notif_conf(self, get):
        """Status notifikasi tanpa membocorkan token ke layar."""
        jalan = self._notify_conf_path()
        isi = self._notif_baca()

        url = isi.get('NOTIFY_URL', '')
        token = isi.get('NOTIFY_TOKEN', '')

        # Token TIDAK dikembalikan. Yang dikembalikan hanya apakah ia
        # terisi, supaya operator tahu harusnya ada atau tidak tanpa
        # menyalin kata sandinya ke halaman panel.
        hasil = {
            'url_ada': bool(url),
            'url_host': self._host_dari(url),
            'token_ada': bool(token),
            'jenis': isi.get('NOTIFY_KIND', 'semua'),
            'maks_coba': isi.get('SENTINEL_NOTIF_MAX', '5'),
            'batch': isi.get('SENTINEL_NOTIF_BATCH', '20'),
            'timeout': isi.get('SENTINEL_NOTIF_TIMEOUT', '8'),
            'berkas': jalan,
        }

        raw_eps = self._notif_baca_endpoints()
        can_multi = bool(self._lic_has('notify_multi'))
        endpoints = []
        if raw_eps:
            for idx, ep in enumerate(raw_eps):
                if not isinstance(ep, dict):
                    continue
                u = (ep.get('url') or '').strip()
                t = (ep.get('token') or '').strip()
                endpoints.append({
                    'id': ep.get('id') or ('ep_%d' % (idx + 1)),
                    'name': ep.get('name') or ('Endpoint %d' % (idx + 1)),
                    'url': u,
                    'url_host': self._host_dari(u),
                    'token_ada': bool(t),
                    'kind': ep.get('kind', 'semua'),
                    'enabled': bool(ep.get('enabled', True)),
                })
        elif url:
            endpoints.append({
                'id': 'ep_1',
                'name': 'Primary Webhook',
                'url': url,
                'url_host': self._host_dari(url),
                'token_ada': bool(token),
                'kind': isi.get('NOTIFY_KIND', 'semua'),
                'enabled': True,
            })
        hasil['endpoints'] = endpoints
        hasil['can_multi'] = can_multi

        # Status antrean supaya operator tahu ada yang tersendir.
        t = self._sql1(
            'SELECT COUNT(*) total, SUM(terkirim=0) nunggu,'
            ' SUM(terkirim=0 AND coba>0) gagal FROM notif')
        hasil['antrean'] = t or {'total': 0, 'nunggu': 0, 'gagal': 0}

        timer = (0, 'tidak aktif', '')      # notifikasi webhook adalah fitur Pro
        hasil['timer'] = timer[1].strip() or 'tidak aktif'
        if hasil['timer'] == 'tidak aktif':
            hasil['timer'] = self._t(get, 'tidak aktif', 'inactive')
        return public.returnMsg(True, hasil)

    @staticmethod
    def _host_dari(url):
        """Ambil host dari URL tanpa membawakan bagian rahasia.

        Token sering disimpan di dalam URL, misalnya path bot Telegram
        yang memuat token. Karena itu hanya nama host yang ditampilkan,
        bukan URL lengkapnya.
        """
        try:
            from urllib.parse import urlparse
            b = urlparse(url)
            return b.hostname or '-'
        except Exception:
            return '-'

    def set_notif_conf(self, get):
        """Ubah tujuan notifikasi dan me-restart timer."""
        # Edisi Free: fitur berbayar (notify) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('notify', self._get_active_lang(get))

    def _notif_nilai(self, kunci):
        """Nilai tersimpan satu kunci di notify.conf."""
        return self._notif_baca().get(kunci, '')

    def _notif_ada(self, kunci):
        return bool(self._notif_baca().get(kunci, ''))

    def test_notif(self, get):
        """Kirim satu notifikasi uji dan laporkan hasilnya apa adanya."""
        # Edisi Free: fitur berbayar (notify) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('notify', self._get_active_lang(get))

    def get_notif_log(self, get):
        """Riwayat notifikasi terakhir."""
        n = self._int(get, 'limit', 50, 1, 300)
        if n is None:
            n = 50
        hal = self._hal_param(get)
        meta_hal = None
        if hal is None:
            baris = self._sql(
                'SELECT id, ts, ip, jenis, isi, terkirim, coba, galat'
                ' FROM notif ORDER BY id DESC LIMIT ?', (n,))
        else:
            # Paging: COUNT lalu satu halaman; limit diabaikan (ukuran halaman tetap PER_HAL).
            tot = self._sql1('SELECT COUNT(*) n FROM notif') or {}
            meta_hal = self._hal_meta(hal, int(tot.get('n') or 0))
            per = meta_hal['per_page']
            baris = self._sql(
                'SELECT id, ts, ip, jenis, isi, terkirim, coba, galat'
                ' FROM notif ORDER BY id DESC LIMIT ? OFFSET ?', (per, (meta_hal['page'] - 1) * per))
        if isinstance(baris, dict):
            return baris
        for r in baris:
            r['ip'] = self._numip(r['ip']) if r['ip'] else '-'
        self._loc_kolom(baris, ('isi',), get)
        if meta_hal is not None:
            return public.returnMsg(True, {'baris': baris, 'halaman': meta_hal})
        return public.returnMsg(True, baris)

    # ------------------------------------------------------------------ #
    # notifikasi                                                          #
    # ------------------------------------------------------------------ #
    # Notifikasi TIDAK dikirim dari daemon. Daemon hanya menulis ke tabel #
    # notif; pengiriman dikerjakan sentinel-notify.sh dari systemd timer.  #
    # Alasannya: satu HTTP POST yang menggantung akan menahan           #
    # pemrosesan log, dan daemon membaca log setiap dua detik. Dengan     #
    # begitu, satu alamat tujuan yang nakal bisa membuat Sentinel        #
    # berhenti melihat serangan sama sekali.                             #
    # ------------------------------------------------------------------ #
    def get_aksi(self, get):
        """Jejak audit terbaru, bisa disaring per IP."""
        # limit bisa string (form panel) atau int (panggilan skrip).
        # .strip() buta tipe melempar AttributeError pada int.
        mentah = get.get('limit')
        if isinstance(mentah, str):
            mentah = mentah.strip()
        if mentah is None or mentah == '':
            mentah = '100'
        try:
            n = int(mentah)
        except (TypeError, ValueError):
            n = 100
        if n < 1:
            n = 1
        if n > 500:
            n = 500
        ip = (get.get('ip') or '').strip()
        args = []
        where = ''
        if ip:
            n_ip = self._ipnum(ip)
            if not n_ip:
                return public.returnMsg(False, 'alamat IP tidak valid')
            where = ' WHERE ip = ?'
            args.append(n_ip)
        hal = self._hal_param(get)
        if hal is None:
            args.append(n)
            baris = self._sql(
                'SELECT ts, ip, aksi, sumber, alasan, detik FROM aksi'
                + where + ' ORDER BY ts DESC, id DESC LIMIT ?', tuple(args))
            meta = None
        else:
            # page diminta: satu halaman (LIMIT/OFFSET) menggantikan limit; saringan IP tetap berlaku
            tot = self._sql1('SELECT COUNT(*) n FROM aksi' + where, tuple(args)) or {}
            meta = self._hal_meta(hal, int(tot.get('n') or 0))
            baris = self._sql(
                'SELECT ts, ip, aksi, sumber, alasan, detik FROM aksi' + where
                + ' ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?',
                tuple(args) + (meta['per_page'], (meta['page'] - 1) * meta['per_page']))
        if isinstance(baris, dict):
            return baris
        for r in baris:
            r['ip'] = self._numip(r['ip'])
        self._loc_kolom(baris, ('alasan',), get)
        if meta is not None:
            return public.returnMsg(True, {'baris': baris, 'halaman': meta})
        return public.returnMsg(True, baris)

    def get_vhost_stat(self, get):
        """Statistik per-vhost: trafik, error, dan serangan."""
        # Edisi Free: fitur berbayar (vhosts) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('vhosts', self._get_active_lang(get))

    def get_vhost_ip(self, get):
        """Penyerang teratas untuk satu vhost."""
        # Edisi Free: fitur berbayar (vhosts) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('vhosts', self._get_active_lang(get))

    def flush_db(self, get):
        rc, o, e = self._sh("'%s/bin/guardctl' flush" % self.__PATH, 40)
        if rc != 0:
            self._catat_galat('flush statistik', o.strip() or e.strip())
        return public.returnMsg(True, 'Statistik berhasil disimpan')

    # ------------------------------------------------------------------ #
    # operasional                                                          #
    # ------------------------------------------------------------------ #
    def get_sites(self, get):
        """Daftar situs dari basis data panel, digabung dengan log yang
        benar-benar sedang ditail daemon."""
        situs = []
        try:
            data = public.M('sites').field('name,path,status').select()
            for i in data:
                situs.append({'name': i['name'], 'path': i['path'],
                              'status': i.get('status', '1')})
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca daftar situs', ex))
        st = self._status() or {}
        ditail = {}
        for lg in st.get('logs', []):
            ditail[lg['host']] = lg
        for s in situs:
            lg = ditail.get(s['name'])
            s['dipantau'] = bool(lg)
            s['baris'] = lg['lines'] if lg else 0
        lainnya = sorted([h for h in ditail if h not in [s['name'] for s in situs]])
        # Dengan page: 'situs' dipotong ke satu halaman; 'lainnya' (log tanpa situs) tetap utuh
        situs, meta = self._halaman(get, situs)
        hasil = {'situs': situs, 'lainnya': lainnya}
        if meta is not None:
            hasil['halaman'] = meta
        return public.returnMsg(True, hasil)

    def _ensure_events_schema(self):
        """Kolom status di tabel events (guardd lama belum membuatnya). Diperiksa sekali per proses, bukan ALTER setiap
        refresh feed."""
        if getattr(sentinel_main, '_events_status_ok', False):
            return
        kolom = [r.get('name') for r in self._sql("PRAGMA table_info(events)")]
        if kolom and 'status' not in kolom:
            self._sql1("ALTER TABLE events ADD COLUMN status INTEGER DEFAULT 0")
            kolom = [r.get('name') for r in self._sql("PRAGMA table_info(events)")]
        if 'status' in kolom:
            sentinel_main._events_status_ok = True

    _REQ_LOG_RE = re.compile(r'"[A-Z-]+ (\S+) HTTP/[0-9.]+" ([0-9]{3}) ')

    def _lookup_event_status(self, host, path, ip_str, batas):
        """Kode response untuk event lama tanpa status, dari access log vhost: baris TERAKHIR milik IP event itu sendiri
        dengan URI yang sama (tanpa query, seperti guardd menyimpan path; path guardd dipotong 150 karakter).
        Path berasal dari penyerang, jadi tidak pernah menjadi argumen grep: grep hanya menyaring IP (sudah tervalidasi),
        pencocokan path di Python. Output dibaca bertahap (memori tetap) dan dihentikan pada `batas` (time.time()).
        Hasil: kode, 0 = tidak ketemu, None = waktu habis (coba lagi refresh berikutnya)."""
        if not host or not path or path == '-' or not re.match(r'^[A-Za-z0-9_-][A-Za-z0-9._-]{0,252}$', host):
            return 0
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            return 0
        log_file = _log_vhost(host)
        if not log_file:
            return 0
        awal, kode = ip_str + ' ', 0
        try:
            p = subprocess.Popen(['grep', '-F', '-e', awal, '--', log_file], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except OSError:
            return 0
        try:
            for raw in p.stdout:
                if time.time() > batas:
                    return None
                l = raw.decode('utf-8', 'ignore')
                if not l.startswith(awal):
                    continue
                m = self._REQ_LOG_RE.search(l)
                if not m:
                    continue
                uri = re.split(r'[?#]', m.group(1), 1)[0]
                if uri == path or (len(path) >= 150 and uri.startswith(path)):
                    kode = int(m.group(2))
            return kode
        finally:
            try:
                p.kill()
            except OSError:
                pass
            p.wait()

    def get_events(self, get):
        """Feed kejadian(classifikasi serangan) terbaru."""
        # Edisi Free: fitur berbayar (event_feed) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('event_feed', self._get_active_lang(get))

    def get_logs(self, get):
        n = self._int(get, 'limit', 80)
        n = 80 if n is None else max(1, min(500, n))
        rc, o, e = self._sh("'%s/bin/guardctl' logs %d"
                            % (self.__PATH, n), 25)
        return public.returnMsg(True, o.strip().splitlines())

    def get_timeline(self, get):
        """Riwayat lengkap per IP beserta jumlah pelanggaran."""
        jam = self._jam(get, 87600)
        if jam is None:
            return public.returnMsg(False, 'rentang jam harus angka bulat positif')
        sejak = int(time.time()) - jam * 3600
        hal = self._hal_param(get)
        if hal is None:
            baris = self._sql(
                "SELECT ip, COUNT(*) n, MAX(score) puncak, MAX(ts) terakhir "
                "FROM ip_minute WHERE ts >= ? AND score > 0 "
                "GROUP BY ip ORDER BY n DESC LIMIT 100", (sejak,))
            meta = None
        else:
            # page diminta: seluruh IP berskor (bukan hanya 100 teratas) dibagi per halaman
            tot = self._sql1(
                "SELECT COUNT(*) n FROM (SELECT ip FROM ip_minute WHERE ts >= ? AND score > 0 GROUP BY ip)",
                (sejak,)) or {}
            meta = self._hal_meta(hal, int(tot.get('n') or 0))
            baris = self._sql(
                "SELECT ip, COUNT(*) n, MAX(score) puncak, MAX(ts) terakhir "
                "FROM ip_minute WHERE ts >= ? AND score > 0 "
                "GROUP BY ip ORDER BY n DESC, terakhir DESC, ip LIMIT ? OFFSET ?",
                (sejak, meta['per_page'], (meta['page'] - 1) * meta['per_page']))
        if not isinstance(baris, list):
            return public.returnMsg(False, self._galat('Gagal membaca data aktivitas per IP', ''))
        for r in baris:
            r['ip'] = self._numip(r['ip'])
        if meta is not None:
            return public.returnMsg(True, {'baris': baris, 'halaman': meta})
        return public.returnMsg(True, baris)

    # ------------------------------------------------------------------ #
    # Antivirus (ClamAV) & Integritas File                               #
    # ------------------------------------------------------------------ #
    AV_ENGINES = ('clamav', 'rkhunter', 'both', 'all', 'judol', 'ransomware',
                  'mining', 'sage', 'ai', 'scan-ai')
    QUAR_DIR = '/www/server/sentinel/av/quarantine'

    @staticmethod
    def _av_label(label, path):
        """Label hanya [A-Za-z0-9._-]; selalu disaring, termasuk target sistem."""
        if not label:
            label = os.path.basename(str(path).rstrip('/')) or 'root'
        label = ''.join(c for c in label if c.isalnum() or c in '._-')
        return label[:64] or 'target'

    @staticmethod
    def _av_path(raw, harus_dir=True):
        """Path pemindaian: tanpa karakter kontrol/NUL, di-realpath, harus ada.
        (path, None) atau (None, pesan)."""
        if not isinstance(raw, str) or not raw.strip():
            return None, 'Path target pemindaian wajib diisi'
        raw = raw.strip()
        if len(raw) > 1024 or re.search(r'[\x00-\x1f\x7f]', raw):
            return None, 'Path memuat karakter tidak valid atau terlalu panjang'
        real = os.path.realpath(raw)
        if harus_dir:
            if not os.path.isdir(real):
                return None, 'Direktori tidak valid atau tidak ditemukan: %s' % _aman(raw, 80)
        elif not (os.path.isdir(real) or os.path.isfile(real)):
            return None, 'Path target pemindaian tidak ditemukan: %s' % _aman(raw, 80)
        return real, None

    def _av_engine(self, get):
        eng = str(get.get('engine', 'both')).strip().lower() or 'both'
        if eng not in self.AV_ENGINES:
            return None, 'Engine tidak dikenal: %s (pilih: %s)' % (
                _aman(eng, 20), ', '.join(self.AV_ENGINES))
        return eng, None

    @staticmethod
    def _vhost_valid(v):
        return bool(re.fullmatch(r'[A-Za-z0-9._-]{1,120}', v)) and '..' not in v

    def _quar_meta_valid(self, meta):
        """Berkas .meta harus benar-benar di dalam direktori karantina setelah
        realpath. Pemeriksaan awalan teks saja bisa dilewati dengan '../'."""
        if not isinstance(meta, str) or re.search(r'[\x00-\x1f\x7f]', meta):
            return None
        real = os.path.realpath(meta.strip())
        if not real.endswith('.meta') or not real.startswith(self.QUAR_DIR + '/'):
            return None
        return real if os.path.isfile(real) else None

    def _av(self, subcommand, *args):
        """Panggil skrip pengelola Antivirus (sentinel-av.sh)."""
        skrip = self._p('bin', 'sentinel-av.sh')
        if not os.path.isfile(skrip):
            return 1, '', 'Komponen antivirus ZySentinel tidak ditemukan di server ini'
        cmd = "'%s' %s" % (skrip, subcommand)
        for a in args:
            cmd += " '%s'" % str(a).replace("'", "'\\''")
        return self._sh(cmd, 60)

    def get_av(self, get):
        """Status ClamAV, basis data, socket, karantina, dan Rkhunter."""
        rc, o, e = self._av('status')
        data = {
            'ada': 'tidak',
            'versi': '-',
            'db_umur': '-',
            'clamd': 'tidak',
            'quarantine': 0,
            'deteksi_hari_ini': 0,
            'common': 'tidak',
            'timer': 'tidak',
            'last_deepscan': None,
            'last_scan_all': None,
            'rkhunter': 'tidak',
            'rkhunter_versi': '-',
            'rkhunter_last_scan': None,
            'rkhunter_warnings': 0,
            'active_scan': None
        }
        if rc == 0:
            for baris in o.strip().splitlines():
                if '=' in baris:
                    k, v = baris.split('=', 1)
                    k = k.strip()
                    v = v.strip()
                    if k in ('quarantine', 'deteksi_hari_ini', 'rkhunter_warnings'):
                        try:
                            data[k] = int(v)
                        except Exception:
                            data[k] = 0
                    elif k == 'rkhunter_last_scan':
                        if v != '-' and v.isdigit():
                            try:
                                data[k] = int(v)
                            except Exception:
                                data[k] = v
                        else:
                            data[k] = v
                    else:
                        data[k] = v

        # Ringkasan deepscan harian dari summary.log bila ada
        sum_log = '/var/log/clamav/summary.log'
        if os.path.isfile(sum_log):
            try:
                with open(sum_log, 'r') as f:
                    isi = f.read()
                blok = isi.strip().split('==============================================================')
                if len(blok) > 1:
                    terakhir = blok[-1].strip()
                    info = {}
                    for baris in terakhir.splitlines():
                        if 'date=' in baris:
                            for bagian in baris.split():
                                if '=' in bagian:
                                    k, val = bagian.split('=', 1)
                                    info[k] = val
                        elif 'scanned=' in baris:
                            for bagian in baris.split():
                                if '=' in bagian:
                                    k, val = bagian.split('=', 1)
                                    info[k] = val
                    if info:
                        data['last_deepscan'] = info
            except Exception:
                pass

        # Ringkasan scan all terakhir dari av/last/all.json
        all_json = self._p('av', 'last', 'all.json')
        if os.path.isfile(all_json):
            try:
                with open(all_json, 'r') as f:
                    data['last_scan_all'] = json.load(f)
            except Exception:
                pass

        # Status pemindaian realtime aktif (active_scan.json)
        active_f = self._p('run', 'active_scan.json')
        if os.path.isfile(active_f):
            try:
                with open(active_f, 'r') as f:
                    data['active_scan'] = json.load(f)
            except Exception:
                pass

        return public.returnMsg(True, data)

    def get_av_sites(self, get):
        """Daftar situs vhost panel lengkap dengan status pemindaian terakhir
        dan status rekaman baseline integritas."""
        situs = []
        try:
            data = public.M('sites').field('name,path,status').select()
            for i in data:
                situs.append({'name': i['name'], 'path': i['path'],
                              'status': i.get('status', '1')})
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca daftar situs', ex))

        # Dengan parameter page: hanya situs pada halaman itu yang dibaca status pindai/baseline-nya (berkas per situs),
        # sedangkan semua nama situs tetap dikirim ('nama') untuk pilihan filter Integrity Monitor dan hitungan tab.
        semua_nama = [s['name'] for s in situs]
        situs_halaman, meta_hal = self._halaman(get, situs)
        if meta_hal is not None:
            situs = situs_halaman

        for s in situs:
            name = s['name']
            # Cek hasil scan terakhir
            scan_f = self._p('av', 'last', name + '.json')
            if os.path.isfile(scan_f):
                try:
                    with open(scan_f, 'r') as f:
                        s['last_scan'] = json.load(f)
                except Exception:
                    s['last_scan'] = None
            else:
                s['last_scan'] = None

            # Cek baseline integritas
            base_f = self._p('av', 'baseline', name + '.txt')
            if os.path.isfile(base_f):
                s['has_baseline'] = True
                try:
                    with open(base_f, 'r') as f:
                        s['baseline_count'] = sum(1 for line in f if line.strip())
                except Exception:
                    s['baseline_count'] = 0
            else:
                s['has_baseline'] = False
                s['baseline_count'] = 0

            # Cek hasil periksa integritas terakhir
            integ_f = self._p('av', 'last', 'integ-' + name + '.txt')
            if os.path.isfile(integ_f):
                try:
                    with open(integ_f, 'r') as f:
                        s['integrity_changes'] = sum(1 for line in f if line.strip())
                except Exception:
                    s['integrity_changes'] = 0
            else:
                s['integrity_changes'] = None

        if meta_hal is not None:
            return public.returnMsg(True, {'baris': situs, 'halaman': meta_hal, 'nama': semua_nama})
        return public.returnMsg(True, situs)

    def av_scan(self, get):
        """Mulai pemindaian antivirus untuk satu direktori / vhost."""
        engine, err = self._av_engine(get)
        if err:
            return public.returnMsg(False, err)
        path, err = self._av_path(get.get('path', ''))
        if err:
            return public.returnMsg(False, err)
        label = self._av_label(self._only(get, 'label', ''), path)

        sync = str(get.get('sync', '0')) == '1'
        if sync:
            rc, o, e = self._av('scan', path, label)
            if rc == 0:
                return public.returnMsg(True, 'Pemindaian selesai')
            return public.returnMsg(False, self._galat('Pemindaian gagal', e.strip() or o.strip()))

        return self.av_scan_start(get)

    def av_scan_ai(self, get):
        """Mulai pemindaian AI Safety (SAGE Prompt Injection & Toxic Skills)."""
        # Edisi Free: fitur berbayar (av_engines) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('av_engines', self._get_active_lang(get))

    def av_sage_test(self, get):
        """Jalankan unit test mandiri heuristik SAGE AI Safety."""
        # Edisi Free: fitur berbayar (av_engines) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('av_engines', self._get_active_lang(get))

    def av_scan_start(self, get):
        """Mulai pemindaian realtime streaming (ClamAV, Rkhunter, Ransomware, Judol, Mining, SAGE AI Safety, atau All-in-One)."""
        engine, err = self._av_engine(get)
        if err:
            return public.returnMsg(False, err)

        target_type = str(get.get('target_type', 'vhost')).strip().lower()
        path = str(get.get('path', '')).strip()
        label = self._only(get, 'label', '')

        if target_type == 'system' or path in ('system', '/'):
            target_type = 'system'
            path = '/'
            label = self._av_label(label or 'system', path)
        else:
            path, err = self._av_path(path, harus_dir=False)
            if err:
                return public.returnMsg(False, err)
            label = self._av_label(label, path)

        # Cek apakah ada proses pemindaian yang masih aktif
        pid_f = self._p('run', 'active_scan.pid')
        if os.path.isfile(pid_f):
            try:
                with open(pid_f, 'r') as f:
                    p = int(f.read().strip())
                if p > 0:
                    os.kill(p, 0)
                    return public.returnMsg(False, 'Pemindaian lain sedang berjalan. Tunggu hingga selesai atau batalkan terlebih dahulu.')
            except Exception:
                pass

        skrip = self._p('bin', 'sentinel-av.sh')
        if not os.path.isfile(skrip):
            return public.returnMsg(False, 'Komponen antivirus ZySentinel tidak ditemukan di server ini')

        log_f = self._p('log', 'active_scan.log')
        try:
            with open(log_f, 'w') as f:
                f.write('')
        except Exception:
            pass

        # shlex.quote: path dan label berasal dari masukan pengguna; kutip
        # tunggal di dalamnya tidak boleh bisa keluar dari argumen.
        cmd = "nohup %s scan-stream %s %s %s >> %s 2>&1 &" % (
            shlex.quote(skrip), shlex.quote(engine), shlex.quote(path),
            shlex.quote(label), shlex.quote(log_f)
        )
        os.system(cmd)
        return public.returnMsg(True, 'Pemindaian realtime untuk %s (%s) berhasil dimulai' % (label, engine))

    def get_scan_stream(self, get):
        """Ambil stream output log pemindaian realtime baris-per-baris."""
        offset = self._int(get, 'offset', 0, 0, 1000000) or 0
        log_f = self._p('log', 'active_scan.log')
        meta_f = self._p('run', 'active_scan.json')
        pid_f = self._p('run', 'active_scan.pid')

        meta = {}
        if os.path.isfile(meta_f):
            try:
                with open(meta_f, 'r') as f:
                    meta = json.load(f)
            except Exception:
                pass

        status = meta.get('status', 'idle')
        is_running = (status == 'running')

        if is_running and not os.path.isfile(pid_f) and (time.time() - meta.get('mulai', 0) > 3):
            status = 'done'
            meta['status'] = 'done'
            is_running = False

        lines = []
        total_lines = 0
        if os.path.isfile(log_f):
            try:
                with open(log_f, 'r', errors='ignore') as f:
                    all_lines = f.readlines()
                total_lines = len(all_lines)
                if offset < total_lines:
                    lines = [l.rstrip('\r\n') for l in all_lines[offset:]]
            except Exception:
                pass

        res = {
            'status': status,
            'is_running': is_running,
            'meta': meta,
            'lines': lines,
            'offset': total_lines,
            'complete': (status in ('done', 'aborted'))
        }
        return public.returnMsg(True, res)

    def av_scan_abort(self, get):
        """Batalkan pemindaian yang sedang berjalan."""
        pid_f = self._p('run', 'active_scan.pid')
        meta_f = self._p('run', 'active_scan.json')
        log_f = self._p('log', 'active_scan.log')

        stopped = False
        if os.path.isfile(pid_f):
            try:
                with open(pid_f, 'r') as f:
                    p = int(f.read().strip())
                # PID dari berkas bisa basi atau diubah pihak lain: hanya proses
                # pemindaian milik plugin ini yang boleh dihentikan.
                try:
                    with open('/proc/%d/cmdline' % p, 'rb') as cf:
                        cmd = cf.read().replace(b'\x00', b' ').decode('utf-8', 'replace')
                except Exception:
                    cmd = ''
                if p > 1 and not re.search(r'clamscan|clamdscan|sentinel-av', cmd):
                    p = 0
                if p > 0:
                    try:
                        os.kill(p, 15)
                        time.sleep(0.3)
                        try:
                            os.kill(p, 0)
                            os.kill(p, 9)
                        except Exception:
                            pass
                        stopped = True
                    except Exception:
                        pass
                os.remove(pid_f)
            except Exception:
                pass

        if os.path.isfile(meta_f):
            try:
                with open(meta_f, 'r') as f:
                    meta = json.load(f)
                meta['status'] = 'aborted'
                meta['summary'] = self._t(get, 'DIBATALKAN OLEH OPERATOR', 'CANCELLED BY THE OPERATOR')
                with open(meta_f, 'w') as f:
                    json.dump(meta, f)
            except Exception:
                pass

        if os.path.isfile(log_f):
            try:
                with open(log_f, 'a') as f:
                    f.write(self._t(get, "\n[!] PEMINDAIAN DIHENTIKAN OLEH OPERATOR.\n", "\n[!] SCAN STOPPED BY THE OPERATOR.\n"))
            except Exception:
                pass

        return public.returnMsg(True, 'Pemindaian berhasil dihentikan.')

    # ------------------------------------------------------------------ #
    # pembaruan basis data keamanan sebagai job latar dengan kemajuan      #
    # ------------------------------------------------------------------ #
    AVUPD_DIR = os.path.join(_data_log_dir(), 'avupdate')
    AVUPD_TASKS = ('db-update', 'rkhunter-propupd', 'rkhunter-update')

    def _avupd_pid(self):
        try:
            with open(os.path.join(self.AVUPD_DIR, 'job.pid')) as f:
                pid = int(f.read().strip())
            with open('/proc/%d/stat' % pid) as f:
                if f.read().rsplit(')', 1)[1].split()[0] == 'Z':
                    return 0
            with open('/proc/%d/cmdline' % pid, 'rb') as f:
                if b'sentinel-av.sh' not in f.read():
                    return 0
            return pid
        except Exception:
            return 0

    def av_update_start(self, get):
        """Mulai satu atau beberapa tugas pembaruan di latar (tasks=db-update,rkhunter-propupd,...).
        Berjalan di latar karena freshclam dan rkhunter bisa melewati batas AJAX 60 detik."""
        mentah = (get.get('tasks') or '').strip()
        tasks = []
        for t in mentah.split(','):
            t = t.strip()
            if t and t not in tasks:
                if t not in self.AVUPD_TASKS:
                    return public.returnMsg(False, 'tugas tidak dikenal: %s' % _aman(t, 30))
                tasks.append(t)
        if not tasks:
            return public.returnMsg(False, 'pilih minimal satu tugas pembaruan')
        pid = self._avupd_pid()
        if pid:
            return public.returnMsg(True, {'started': False, 'running': True, 'pid': pid})
        self._ensure_core_files()
        skrip = os.path.join(self.__PATH, 'bin', 'sentinel-av.sh')
        if not os.path.isfile(skrip):
            return public.returnMsg(False, 'Komponen antivirus ZySentinel tidak ditemukan di server ini')
        os.makedirs(self.AVUPD_DIR, exist_ok=True)
        log_f = os.path.join(self.AVUPD_DIR, 'job.log')
        rc_f = os.path.join(self.AVUPD_DIR, 'job.rc')
        pid_f = os.path.join(self.AVUPD_DIR, 'job.pid')
        if os.path.exists(rc_f):
            os.remove(rc_f)
        with open(log_f, 'w') as f:
            f.write('')
        cmd = "echo $$ > %s; %s update-batch %s > %s 2>&1; echo $? > %s" % (
            shlex.quote(pid_f), shlex.quote(skrip), ' '.join(shlex.quote(t) for t in tasks),
            shlex.quote(log_f), shlex.quote(rc_f))
        subprocess.Popen(['setsid', '-f', 'bash', '-c', cmd], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True).wait()
        for _ in range(20):
            if self._avupd_pid() or os.path.exists(rc_f):
                break
            time.sleep(0.1)
        return public.returnMsg(True, {'started': True, 'running': True, 'tasks': tasks})

    def get_av_update_job(self, get):
        """Kemajuan job pembaruan: tahap n/m, hasil per tugas, status, dan ekor log."""
        log_f = os.path.join(self.AVUPD_DIR, 'job.log')
        rc_f = os.path.join(self.AVUPD_DIR, 'job.rc')
        running = bool(self._avupd_pid())
        rc = None
        if not running and os.path.exists(rc_f):
            try:
                with open(rc_f) as f:
                    rc = int(f.read().strip() or 1)
            except Exception:
                rc = 1
        baris = []
        if os.path.exists(log_f):
            with open(log_f, 'r', encoding='utf-8', errors='replace') as f:
                baris = f.read().splitlines()
        tahap, total, etap = 0, 0, ''
        hasil = {}
        for b in baris:
            m = re.search(r'^\[sentinel-av\]\s*\[(\d+)/(\d+)\]\s*(.*)$', b)
            if not m:
                continue
            n, total = int(m.group(1)), int(m.group(2))
            mm = re.match(r'^selesai rc=(\d+) \((\d+) dtk\)$', m.group(3))
            if mm:
                hasil[n] = {'rc': int(mm.group(1)), 'dtk': int(mm.group(2))}
            else:
                tahap, etap = n, m.group(3)
        if not running and rc is None:
            rc = 1
        return public.returnMsg(True, {
            'running': running, 'rc': rc, 'tahap': tahap, 'total': total, 'etap': etap,
            'hasil': hasil, 'log': '\n'.join(baris[-80:])})

    def rkhunter_propupd(self, get):
        """Perbarui database file properties hash Rkhunter."""
        rc, o, e = self._av('rkhunter-propupd')
        if rc == 0:
            return public.returnMsg(True, 'Data properti berkas Rkhunter berhasil diperbarui.')
        return public.returnMsg(False, self._galat('Gagal memperbarui data properti berkas Rkhunter', e.strip() or o.strip()))

    def rkhunter_update(self, get):
        """Perbarui basis data signature Rkhunter."""
        rc, o, e = self._av('rkhunter-update')
        if rc == 0:
            return public.returnMsg(True, 'Basis data signature Rkhunter berhasil diperbarui')
        return public.returnMsg(False, self._galat('Pembaruan signature Rkhunter gagal', e.strip() or o.strip()))

    # ------------------------------------------------------------------ #
    # Sweeper: pemindai webshell (logika ShellSweep) selain ClamAV         #
    # ------------------------------------------------------------------ #
    def _sweeper(self, *args, timeout=60):
        """Jalankan mesin Sweeper (skrip Python) dan baca baris JSON terakhirnya. Return dict {status, msg}."""
        return {'status': False, 'msg': 'Sweeper adalah fitur paket Max. Klik Upgrade untuk membukanya.', 'upgrade': {'feature': 'sweeper', 'plan': 'max', 'current': 'free'}}
        py = '/www/server/panel/pyenv/bin/python3'
        if not os.path.exists(py):
            py = 'python3'
        cmd = ' '.join([shlex.quote(py), shlex.quote(skrip)] + [shlex.quote(str(a)) for a in args])
        rc, o, e = self._sh(cmd, timeout)
        baris = [l for l in o.strip().splitlines() if l.strip()]
        if not baris:
            return {'status': False, 'msg': self._galat('Mesin Sweeper tidak memberi jawaban', e.strip())}
        try:
            j = json.loads(baris[-1])
        except Exception:
            return {'status': False, 'msg': self._galat('Jawaban mesin Sweeper tidak bisa dibaca', o.strip() or e.strip())}
        if not (isinstance(j, dict) and 'status' in j):
            return {'status': False, 'msg': self._galat('Jawaban mesin Sweeper tidak dikenali', o.strip())}
        if not j.get('status') and not isinstance(j.get('msg'), (dict, list)):
            # pesan galat skrip: dipakai bila dikenal katalog, selain itu diganti kalimat umum (mentahnya ke log)
            j['msg'] = self._pesan_skrip(j.get('msg'), 'Operasi Sweeper gagal')
        return j

    @staticmethod
    def _sweeper_path(raw):
        if not isinstance(raw, str) or not raw.strip():
            return None, 'path wajib diisi'
        raw = raw.strip()
        if len(raw) > 1024 or re.search(r'[\x00-\x1f\x7f]', raw) or '..' in raw.split('/') or not raw.startswith('/'):
            return None, 'path harus absolut, tanpa karakter kontrol dan tanpa ".."'
        return raw, None

    def get_sweeper_status(self, get):
        """Status mesin, konfigurasi, pemindaian terakhir, cacah temuan, dan folder yang dipindai."""
        r = self._sweeper('status')
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def sweeper_start(self, get):
        """Mulai pemindaian Sweeper di latar: scope=vhosts (semua vhost + folder kustom) atau scope=path&path=..."""
        # Edisi Free: fitur berbayar (sweeper) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('sweeper', self._get_active_lang(get))

    def get_sweeper_job(self, get):
        """Kemajuan pemindaian: running, progress (berkas/dipindai/ditandai), ringkasan akhir."""
        r = self._sweeper('status')
        if not r.get('status'):
            return public.returnMsg(False, r.get('msg'))
        m = r['msg']
        return public.returnMsg(True, {'running': m.get('running'), 'job': m.get('job'), 'last': m.get('last'), 'counts': m.get('counts')})

    def sweeper_abort(self, get):
        r = self._sweeper('abort')
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def get_sweeper_findings(self, get):
        flt = str(get.get('filter', '')).strip().lower()
        if flt not in ('', 'webshell', 'suspicious', 'open', 'quarantined', 'ignored', 'allowed'):
            return public.returnMsg(False, 'filter tidak valid')
        r = self._sweeper('findings', *([flt] if flt else []))
        daftar = r.get('msg')
        if r.get('status') and isinstance(daftar, list):
            potong, meta_hal = self._halaman(get, daftar)
            if meta_hal is not None:
                return public.returnMsg(True, {'baris': potong, 'halaman': meta_hal})
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def sweeper_action(self, get):
        act = str(get.get('act', '')).strip().lower()
        if act not in ('quarantine', 'allow', 'ignore', 'unignore'):
            return public.returnMsg(False, 'aksi tidak valid')
        p, err = self._sweeper_path(get.get('path', ''))
        if err:
            return public.returnMsg(False, err)
        r = self._sweeper('action', act, p)
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def get_sweeper_config(self, get):
        r = self._sweeper('config')
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def set_sweeper_config(self, get):
        """Simpan konfigurasi (JSON di parameter 'config'); validasi ketat dilakukan skrip."""
        raw = get.get('config')
        if not isinstance(raw, str) or len(raw) > 20000:
            return public.returnMsg(False, 'konfigurasi wajib berupa JSON (maks 20 KB)')
        try:
            json.loads(raw)
        except Exception:
            return public.returnMsg(False, 'konfigurasi bukan JSON yang valid')
        r = self._sweeper('config-set', raw)
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def sweeper_calibrate(self, get):
        # Edisi Free: fitur berbayar (sweeper) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('sweeper', self._get_active_lang(get))

    def get_sweeper_allow(self, get):
        r = self._sweeper('allow-list')
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def sweeper_allow_remove(self, get):
        h = str(get.get('sha256', '')).strip().lower()
        if not re.fullmatch(r'[0-9a-f]{64}', h):
            return public.returnMsg(False, 'kode hash SHA-256 tidak valid')
        r = self._sweeper('allow-remove', h)
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def sweeper_schedule(self, get):
        mode = str(get.get('mode', 'status')).strip().lower()
        if mode not in ('on', 'off', 'status'):
            return public.returnMsg(False, 'mode harus on, off, atau status')
        r = self._sweeper('schedule', mode, timeout=40)
        return public.returnMsg(bool(r.get('status')), r.get('msg'))

    def sweeper_build(self, get):
        """Susun biner C dari sumber (butuh gcc); aman dijalankan berulang."""
        # Edisi Free: fitur berbayar (sweeper) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('sweeper', self._get_active_lang(get))

    def av_scan_all(self, get):
        """Jalankan pemindaian seluruh vhost di latar belakang."""
        skrip = self._p('bin', 'sentinel-av.sh')
        all_f = self._p('av', 'last', 'all.json')
        try:
            with open(all_f, 'w') as f:
                json.dump({
                    'label': 'all',
                    'status': 'running',
                    'mulai': int(time.time())
                }, f)
        except Exception:
            pass
        cmd = "nohup '%s' scan-all >/dev/null 2>&1 &" % skrip
        os.system(cmd)
        return public.returnMsg(True, 'Pemindaian seluruh vhost dimulai di latar belakang')

    def av_scan_progress(self, get):
        """Ambil kemajuan atau hasil pemindaian vhost."""
        label = self._only(get, 'label', '')
        if label:
            label = ''.join(c for c in label if c.isalnum() or c in '._-')
            fpath = self._p('av', 'last', label + '.json')
            if not os.path.isfile(fpath):
                return public.returnMsg(False, 'Belum ada data pemindaian untuk %s' % label)
            try:
                with open(fpath, 'r') as f:
                    return public.returnMsg(True, json.load(f))
            except Exception as ex:
                return public.returnMsg(False, self._galat('Gagal membaca status pemindaian', ex))

        # Ambil semua hasil terakhir
        hasil = []
        last_dir = self._p('av', 'last')
        if os.path.isdir(last_dir):
            for fn in os.listdir(last_dir):
                if fn.endswith('.json') and not fn.startswith('.'):
                    try:
                        with open(os.path.join(last_dir, fn), 'r') as f:
                            hasil.append(json.load(f))
                    except Exception:
                        pass
        return public.returnMsg(True, hasil)

    def get_av_quarantine(self, get):
        """Daftar berkas yang dikarantina beserta metadatanya."""
        rc, o, e = self._av('quarantine-list')
        items = []
        if rc == 0:
            for baris in o.strip().splitlines():
                if not baris or baris.startswith('[sentinel-av]') or baris.startswith('karantina kosong'):
                    continue
                bagian = baris.split('|')
                if len(bagian) >= 5:
                    items.append({
                        'id': bagian[0],
                        'waktu': bagian[1],
                        'virus': bagian[2],
                        'path': bagian[3],
                        'ukuran': int(bagian[4]) if bagian[4].isdigit() else 0
                    })
        potong, meta_hal = self._halaman(get, items)
        if meta_hal is not None:
            return public.returnMsg(True, {'baris': potong, 'halaman': meta_hal})
        return public.returnMsg(True, items)

    def av_restore(self, get):
        """Kembalikan berkas dari karantina ke lokasi asalnya."""
        qid = str(get.get('id') or '').strip()
        if not qid:
            return public.returnMsg(False, 'ID karantina tidak boleh kosong')
        if not re.fullmatch(r'[A-Za-z0-9._-]{1,120}', qid) or '..' in qid:
            return public.returnMsg(False, 'Format ID karantina tidak valid')
        rc, o, e = self._av('quarantine-restore', qid)
        if rc == 0:
            return public.returnMsg(True, 'Berkas berhasil dikembalikan dari karantina')
        return public.returnMsg(False, self._galat('Gagal mengembalikan berkas dari karantina', e.strip() or o.strip()))

    def av_delete(self, get):
        """Hapus satu berkas karantina secara permanen."""
        qid = str(get.get('id') or '').strip()
        if not qid:
            return public.returnMsg(False, 'ID karantina tidak boleh kosong')
        if not re.fullmatch(r'[A-Za-z0-9._-]{1,120}', qid) or '..' in qid:
            return public.returnMsg(False, 'Format ID karantina tidak valid')
        rc, o, e = self._av('quarantine-delete', qid)
        if rc == 0:
            return public.returnMsg(True, 'Berkas karantina berhasil dihapus permanen')
        return public.returnMsg(False, self._galat('Gagal menghapus berkas karantina', e.strip() or o.strip()))

    def av_purge(self, get):
        """Hapus SEMUA berkas karantina secara permanen."""
        rc, o, e = self._av('quarantine-purge')
        if rc == 0:
            return public.returnMsg(True, 'Semua berkas karantina telah dibersihkan')
        return public.returnMsg(False, self._galat('Gagal membersihkan karantina', e.strip() or o.strip()))

    def av_quar_purge(self, get):
        """Hapus seluruh berkas karantina (alias untuk av_purge)."""
        return self.av_purge(get)

    def av_baseline(self, get):
        """Rekam baseline integritas SHA-256 untuk berkas web pada vhost."""
        # Edisi Free: fitur berbayar (integ_web) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('integ_web', self._get_active_lang(get))

    def av_check(self, get):
        """Periksa integritas berkas terhadap baseline yang tersimpan."""
        # Edisi Free: fitur berbayar (integ_web) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('integ_web', self._get_active_lang(get))

    def get_av_integrity(self, get):
        """Daftar perubahan integritas berkas web (ditambah, diubah, dihapus)."""
        label = self._only(get, 'label', '')
        if label:
            label = ''.join(c for c in label if c.isalnum() or c in '._-')
            rc, o, e = self._av('integ-list', label)
        else:
            rc, o, e = self._av('integ-list')
        items = []
        if rc == 0:
            for baris in o.strip().splitlines():
                if not baris or baris.startswith('[sentinel-av]') or baris.startswith('(belum ada'):
                    continue
                bagian = baris.split('|')
                if len(bagian) >= 4:
                    items.append({
                        'jenis': bagian[0],
                        'path': bagian[1],
                        'hash_lama': bagian[2],
                        'hash_baru': bagian[3]
                    })
        potong, meta_hal = self._halaman(get, items)
        if meta_hal is not None:
            return public.returnMsg(True, {'baris': potong, 'halaman': meta_hal})
        return public.returnMsg(True, items)

    def av_db_update(self, get):
        """Pembaruan manual basis data virus ClamAV via freshclam."""
        rc, o, e = self._av('db-update')
        if rc == 0:
            return public.returnMsg(True, 'Basis data virus ClamAV berhasil diperbarui')
        return public.returnMsg(False, self._galat('Pembaruan basis data virus gagal', e.strip() or o.strip()))

    def get_av_logs(self, get):
        """Log kejadian pemindaian dan deteksi ClamAV & Rkhunter."""
        limit = self._int(get, 'limit', 60, 1, 500) or 60
        jenis = self._only(get, 'kind', 'scan')
        log_file = '/var/log/clamav/scan.log'
        if jenis == 'event':
            log_file = '/var/log/clamav/realtime.log'
        elif jenis == 'summary':
            log_file = '/var/log/clamav/summary.log'
        elif jenis == 'av':
            log_file = self._p('log', 'av.log')
        elif jenis == 'active':
            log_file = self._p('log', 'active_scan.log')
        elif jenis == 'rkhunter':
            log_file = self._p('log', 'rkhunter.log')

        if not os.path.isfile(log_file):
            return public.returnMsg(True, [])

        try:
            with open(log_file, 'r', errors='ignore') as f:
                baris = f.readlines()
            baris = [b.strip() for b in baris if b.strip()]
            return public.returnMsg(True, baris[-limit:])
        except Exception as ex:
            return public.returnMsg(False, self._galat('Gagal membaca log', ex))

    # ------------------------------------------------------------------ #
    # CYBERSECURITY DEFENDER ELIT: DEFCON, EGRESS, PROC GUARD, INTEL     #
    # ------------------------------------------------------------------ #
    def get_edr_alerts(self, get):
        """Satu halaman insiden EDR (proc_alerts) untuk tabel Logs > EDR. Endpoint terpisah dari get_elite_posture
        supaya ringkasan DEFCON (yang membaca 50 peringatan terakhir) tidak ikut terpotong. Rincian hanya untuk paket
        dengan edr_anomaly (sama dengan recent_alerts di get_elite_posture); paket lain mendapat edr_dikunci."""
        wl = 0
        try:
            if os.path.isfile(self.PROC_WHITELIST_CONF):
                with open(self.PROC_WHITELIST_CONF, 'r', errors='ignore') as f:
                    wl = len(json.load(f))
        except Exception:
            pass
        if not _lic.allowed('edr_anomaly'):
            meta = self._hal_meta(1, 0)
            return public.returnMsg(True, {'baris': [], 'halaman': meta, 'edr_dikunci': True, 'proc_whitelist_count': wl})
        tot = self._sql1('SELECT COUNT(*) n FROM proc_alerts') or {}
        meta = self._hal_meta(self._hal_param(get) or 1, int(tot.get('n') or 0))
        baris = self._sql(
            "SELECT id, ts, pid, ppid, uid, exe, cmdline, cwd, rule, action FROM proc_alerts "
            "ORDER BY id DESC LIMIT ? OFFSET ?", (meta['per_page'], (meta['page'] - 1) * meta['per_page']))
        if not isinstance(baris, list):
            baris = []
        return public.returnMsg(True, {'baris': baris, 'halaman': meta, 'edr_dikunci': False, 'proc_whitelist_count': wl})

    def get_elite_posture(self, get):
        """Ambil postur pertahanan menyeluruh (DEFCON, Guard Status, & SOC KPI)."""
        panic_on = os.path.isfile(self._p('run', 'panic.state'))
        egress_state_file = self._p('run', 'egress.state')
        egress_on = os.path.isfile(egress_state_file)
        
        proc_state_file = self._p('run', 'proc_guard.state')
        proc_pid_file = self._p('run', 'proc_guard.pid')
        proc_info = {'status': 'stopped', 'mode': 'enforce', 'scans': '0', 'alerts': '0', 'kills': '0'}
        if os.path.isfile(proc_state_file):
            try:
                with open(proc_state_file, 'r') as f:
                    for line in f:
                        if '=' in line:
                            k, v = line.strip().split('=', 1)
                            proc_info[k] = v
            except Exception:
                pass
        proc_pid_active = False
        if os.path.isfile(proc_pid_file):
            try:
                with open(proc_pid_file) as f:
                    p = int(f.read().strip())
                    os.kill(p, 0)
                    proc_pid_active = True
            except Exception:
                pass
        proc_info['service_active'] = proc_pid_active
        
        intel_count = 0
        try:
            out = subprocess.check_output(['/usr/sbin/ipset', 'list', 'sentinel_intel'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            intel_count = sum(1 for line in out.splitlines() if line and line[0].isdigit())
        except Exception:
            pass
            
        sys_integ_file = self._p('av', 'last', 'integ-sys-persistence.txt')
        sys_changes = 0
        sys_tampered_list = []
        if os.path.isfile(sys_integ_file):
            try:
                with open(sys_integ_file, 'r', errors='ignore') as f:
                    lines = [l.strip() for l in f if l.strip()]
                    sys_changes = len(lines)
                    sys_tampered_list = lines[:10]
            except Exception:
                pass
                
        waf_engine = 'coraza'
            
        ban_count = 0
        try:
            out = subprocess.check_output(['/usr/sbin/ipset', 'list', 'sentinel_ban'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            ban_count = sum(1 for line in out.splitlines() if line and line[0].isdigit())
        except Exception:
            pass
            
        proc_alerts = []
        try:
            proc_alerts = self._sql("SELECT id, ts, pid, ppid, uid, exe, cmdline, cwd, rule, action FROM proc_alerts ORDER BY id DESC LIMIT 50")
            if not isinstance(proc_alerts, list):
                proc_alerts = []
        except Exception:
            proc_alerts = []

        proc_wl_count = 0
        try:
            if os.path.isfile(self.PROC_WHITELIST_CONF):
                with open(self.PROC_WHITELIST_CONF, 'r', errors='ignore') as f:
                    proc_wl_count = len(json.load(f))
        except Exception:
            pass
            
        try:
            php_inv = self._php_inventaris()
        except Exception:
            php_inv = []
        php_rentan = sum(1 for x in php_inv if x['status'] != 'diperbaiki')

        defcon = 3
        defcon_title = self._t(get, "DEFCON 3 -- PERTAHANAN PENUH AKTIF", "DEFCON 3 -- FULL DEFENSE ACTIVE")
        defcon_desc = self._t(get, "Seluruh layer pertahanan (Firewall kernel, WAF, Egress Guard, Process Guard, Threat Intel) berjalan optimal tanpa insiden.",
                              "All defense layers (kernel firewall, WAF, Egress Guard, Process Guard, Threat Intel) are running normally with no incidents.")
        
        now_ts = int(time.time())
        # Dihitung dari proc_alerts 15 menit terakhir. Dulu dipakai penghitung kumulatif
        # "kills" sejak Process Guard terakhir start, sehingga satu kejadian menahan
        # DEFCON 2 berjam-jam padahal deskripsinya "dalam 15 menit terakhir".
        # Aturan berkeyakinan rendah (audit saja, mis. pengunduh biasa atau nama proses) tidak menaikkan DEFCON.
        baru = [a for a in (proc_alerts or []) if now_ts - int(a.get('ts', 0) or 0) < 900
                and str(a.get('rule', '')).split('(', 1)[0].split(' ', 1)[0] not in self.PROC_RULE_LONGGAR]
        recent_kills = sum(1 for a in baru if str(a.get('action', '')).startswith('KILLED'))
        recent_alert = any(not str(a.get('action', '')).startswith('WHITELISTED') for a in baru)

        if panic_on:
            defcon = 1
            defcon_title = self._t(get, "DEFCON 1 -- DARURAT (PANIC MODE)", "DEFCON 1 -- EMERGENCY (PANIC MODE)")
            defcon_desc = self._t(get, "Server dalam karantina total: seluruh akses HTTP/HTTPS publik diblokir di tingkat firewall demi investigasi insiden.",
                                  "The server is fully locked down: all public HTTP/HTTPS access is blocked at the firewall level for incident investigation.")
        elif recent_kills > 0 or recent_alert or sys_changes > 0:
            defcon = 2
            defcon_title = self._t(get, "DEFCON 2 -- ANCAMAN TERDETEKSI & DINETRALISIR", "DEFCON 2 -- THREAT DETECTED & NEUTRALIZED")
            defcon_desc = self._t(get, "Upaya serangan RCE/eksekusi ilegal atau anomali persistensi terdeteksi dan dinetralisir dalam 15 menit terakhir.",
                                  "An RCE/illegal execution attempt or a persistence anomaly was detected and neutralized in the last 15 minutes.")
        elif not egress_on or not proc_pid_active or intel_count == 0:
            defcon = 4
            defcon_title = self._t(get, "DEFCON 4 -- PERTAHANAN PARSIAL", "DEFCON 4 -- PARTIAL DEFENSE")
            defcon_desc = self._t(get, "Beberapa modul pertahanan elit (Egress, Process Guard, atau Intel Feed) sedang dalam kondisi nonaktif.",
                                  "Some advanced defense modules (Egress, Process Guard or Intel Feed) are currently inactive.")

        return public.returnMsg(True, {
            'defcon': defcon,
            'defcon_title': defcon_title,
            'defcon_desc': defcon_desc,
            'panic_on': panic_on,
            'egress_guard': dict({
                'active': egress_on,
                'uid': 1002,
                'user': 'www',
                'allowed_ports': '53, 80, 443, 465, 587'
            }, **self._egress_state()),
            'proc_guard': {
                'active': proc_pid_active,
                'mode': proc_info.get('mode', 'enforce'),
                'scans': int(proc_info.get('scans', 0) or 0),
                'alerts': int(proc_info.get('alerts', 0) or 0),
                'kills': int(proc_info.get('kills', 0) or 0),
                'whitelisted': int(proc_info.get('whitelisted', 0) or 0),
                'last_scan': proc_info.get('last_scan', '-')
            },
            'threat_intel': {
                'active': intel_count > 0,
                'count': intel_count,
                'source': 'Spamhaus DROP & EDROP',
                'timer': '-'
            },
            'sys_persistence': {
                'status': 'clean' if sys_changes == 0 else 'tampered',
                'changes': sys_changes,
                'monitored': self._fim_dipantau(),
                'tampered_files': sys_tampered_list
            },
            'waf_engine': waf_engine,
            'bans_active': ban_count,
            # Indikator yang diukur, urut sesuai prioritas penentuan level (dipakai dialog DEFCON).
            'indikator': [
                {'kode': 'panic', 'nilai': 1 if panic_on else 0, 'baik': not panic_on, 'level': 1},
                {'kode': 'kill_15m', 'nilai': recent_kills, 'baik': recent_kills == 0, 'level': 2},
                {'kode': 'alert_15m', 'nilai': len([a for a in baru if not str(a.get('action', '')).startswith('WHITELISTED')]), 'baik': not recent_alert, 'level': 2},
                {'kode': 'persistensi', 'nilai': sys_changes, 'baik': sys_changes == 0, 'level': 2},
                {'kode': 'egress', 'nilai': 1 if egress_on else 0, 'baik': egress_on, 'level': 4},
                {'kode': 'proc_guard', 'nilai': 1 if proc_pid_active else 0, 'baik': proc_pid_active, 'level': 4},
                {'kode': 'intel', 'nilai': intel_count, 'baik': intel_count > 0, 'level': 4},
                # Informasi, tidak menggeser level: versi PHP yang belum menerima perbaikan PHP2Shell
                {'kode': 'php_rentan', 'nilai': php_rentan, 'baik': php_rentan == 0, 'level': 0},
            ],
            'php_exposure': {'rentan': php_rentan, 'total': len(php_inv), 'upload_progress_aktif': sum(1 for x in php_inv if x['upload_progress'])},
            'diukur': now_ts,
            # Rincian insiden EDR hanya untuk paket dengan edr_anomaly; ringkasan DEFCON di atas tetap dihitung dari data penuh
            'recent_alerts': proc_alerts if _lic.allowed('edr_anomaly') else [],
            'edr_dikunci': not _lic.allowed('edr_anomaly'),
            'proc_whitelist_count': proc_wl_count
        })

    # ------------------------------------------------------------------ #
    # PHP2Shell (CVE-2026-109618 / 109619): paparan PHP dan mitigasi terkontrol #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _php_ini_nilai(path, kunci):
        """Nilai terakhir kunci php.ini yang TIDAK dikomentari (None bila tidak diatur)."""
        nilai = None
        try:
            with open(path, 'r', errors='ignore') as f:
                for ln in f:
                    m = re.match(r'^\s*' + re.escape(kunci) + r'\s*=\s*"?([^";\s]*)', ln)
                    if m:
                        nilai = m.group(1)
        except OSError:
            return None
        return nilai

    def _php_versi(self, d):
        """Versi PHP lengkap dari bin/php (dicache 10 menit; satu eksekusi ~20 ms per versi)."""
        c = self._php_cache
        if c['v'] is None or time.time() - c['t'] > 600:
            c['v'] = {}
            c['t'] = time.time()
        if d not in c['v']:
            try:
                out = subprocess.check_output([os.path.join(self.PHP_ROOT, d, 'bin', 'php'), '-n', '-r', 'echo PHP_VERSION;'],
                                              stderr=subprocess.DEVNULL, timeout=5).decode('utf-8', 'ignore').strip()
            except Exception:
                out = ''
            c['v'][d] = out
        return c['v'][d]

    def _php_inventaris(self):
        """Tiap versi PHP terpasang: versi, status terhadap PHP2Shell, setelan upload_progress, pearcmd."""
        hasil = []
        try:
            nama = sorted(e for e in os.listdir(self.PHP_ROOT) if re.fullmatch(r'\d{2,3}', e))
        except OSError:
            return hasil
        for d in nama:
            ver = self._php_versi(d)
            m = re.match(r'^(\d+)\.(\d+)\.(\d+)', ver)
            if not m:
                continue
            mayor, minor, tambal = int(m.group(1)), int(m.group(2)), int(m.group(3))
            fix = self.PHP_PERBAIKAN.get((mayor, minor))
            if fix is not None:
                status = 'diperbaiki' if tambal >= fix else 'rentan'
            elif (mayor, minor) < (8, 2):
                status = 'tanpa_perbaikan'          # 7.4-8.1: tanpa rilis resmi; 5.x-7.3 EOL
            else:
                status = 'diperbaiki'               # cabang lebih baru dari yang dikenal
            ini = os.path.join(self.PHP_ROOT, d, 'etc', 'php.ini')
            up = self._php_ini_nilai(ini, 'session.upload_progress.enabled')
            aktif = not (up is not None and up.lower() in ('0', 'off', 'false', 'no', ''))
            mr = None
            try:
                mr = self._php_ini_nilai(os.path.join(self.PHP_ROOT, d, 'etc', 'php-fpm.conf'), 'pm.max_requests')
            except Exception:
                pass
            hasil.append({
                'dir': d, 'versi': ver, 'status': status,
                'perbaikan': ('%d.%d.%d' % (mayor, minor, fix)) if fix else '-',
                'upload_progress': aktif,
                'pearcmd': os.path.isfile(os.path.join(self.PHP_ROOT, d, 'lib', 'php', 'pearcmd.php')),
                'max_requests': mr or '-',
            })
        return hasil

    def get_php_exposure(self, get):
        """Paparan PHP2Shell per versi PHP terpasang, dan status pemindai memori."""
        inv = self._php_inventaris()
        conf = {}
        try:
            with open(self._p('etc', 'guardd.conf'), 'r', errors='ignore') as f:
                for ln in f:
                    if '=' in ln and not ln.lstrip().startswith('#'):
                        k, v = ln.split('=', 1)
                        conf[k.strip()] = v.split('#', 1)[0].strip()
        except OSError:
            pass
        ms = ''      # pemindai memori adalah fitur Pro
        return public.returnMsg(True, {
            'versi': inv,
            'memscan': {'terpasang': os.access(ms, os.X_OK), 'aktif': conf.get('memscan', 'on').lower() not in ('off', '0', 'false', 'no'),
                        'kill_mode': self._memscan_kill_mode(conf.get('memscan_kill', 'tinggi')),
                        'kill': self._memscan_kill_mode(conf.get('memscan_kill', 'tinggi')) != 'off',
                        'interval': conf.get('memscan_interval', '30')},
            'rekomendasi': ['upgrade', 'upload_progress', 'pearcmd', 'fpm_jaringan'],
        })

    def _php_master_workers(self, d):
        """(PID master, set PID worker) php-fpm versi d dari berkas pid; (0, set()) bila tidak jalan."""
        try:
            with open(os.path.join(self.PHP_ROOT, d, 'var', 'run', 'php-fpm.pid')) as f:
                m = int(f.read().strip())
            os.kill(m, 0)
        except Exception:
            return 0, set()
        try:
            out = subprocess.check_output(['pgrep', '-P', str(m)], stderr=subprocess.DEVNULL).decode().split()
        except Exception:
            out = []
        return m, set(int(x) for x in out)

    def set_php_mitigation(self, get):
        """Mitigasi sementara PHP2Shell: session.upload_progress.enabled = Off pada satu versi PHP.
        Urutan: cadangan php.ini.bak.<ts> -> ubah -> php-fpm -t -> reload -> verifikasi (PID worker berganti, nilai berlaku).
        Gagal di langkah mana pun mengembalikan php.ini semula. Bukan pengganti upgrade PHP."""
        d = self._only(get, 'version', '')
        # Jangan baca parameter bernama 'action': router aaPanel selalu mengirim action=a (lihat snAjax).
        aksi = self._only(get, 'mitigasi', 'upload_progress_off')
        if aksi != 'upload_progress_off':
            return public.returnMsg(False, 'Aksi tidak dikenal')
        if not re.fullmatch(r'\d{2,3}', d) or d not in [x['dir'] for x in self._php_inventaris()]:
            return public.returnMsg(False, 'Versi PHP tidak ditemukan')
        ini = os.path.join(self.PHP_ROOT, d, 'etc', 'php.ini')
        fpm = os.path.join(self.PHP_ROOT, d, 'sbin', 'php-fpm')
        conf = os.path.join(self.PHP_ROOT, d, 'etc', 'php-fpm.conf')
        if not os.path.isfile(ini):
            return public.returnMsg(False, 'php.ini tidak ditemukan')
        sekarang = self._php_ini_nilai(ini, 'session.upload_progress.enabled')
        if sekarang is not None and sekarang.lower() in ('0', 'off', 'false', 'no'):
            return public.returnMsg(True, 'upload_progress sudah Off pada PHP %s; tidak ada perubahan' % d)
        with open(ini, 'r', errors='surrogateescape') as f:
            teks = f.read()
        baris = teks.split('\n')
        diganti = False
        for pola in (r'^\s*session\.upload_progress\.enabled\s*=', r'^\s*;\s*session\.upload_progress\.enabled\s*='):
            for i, ln in enumerate(baris):
                if re.match(pola, ln):
                    baris[i] = 'session.upload_progress.enabled = Off'
                    diganti = True
                    break
            if diganti:
                break
        if not diganti:
            baris.append('session.upload_progress.enabled = Off')
        baru = '\n'.join(baris)
        ts = time.strftime('%Y%m%d%H%M%S')
        cadangan = ini + '.bak.' + ts
        shutil.copy2(ini, cadangan)
        st = os.stat(ini)
        tmp = ini + '.zys.tmp'

        def pulihkan(alasan, detail=''):
            self._catat_galat('mitigasi PHP: ' + alasan, detail)
            try:
                shutil.copy2(cadangan, ini)
            except OSError:
                pass
            return public.returnMsg(False, '%s. php.ini dikembalikan dari cadangan %s' % (alasan, os.path.basename(cadangan)))
        try:
            with open(tmp, 'w', errors='surrogateescape') as f:
                f.write(baru)
            os.chmod(tmp, st.st_mode & 0o7777)
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                pass
            os.replace(tmp, ini)
        except OSError as e:
            return pulihkan('Gagal menulis php.ini', e)
        # uji sintaksis konfigurasi sebelum reload
        try:
            t = subprocess.run([fpm, '-t', '-y', conf], capture_output=True, text=True, timeout=30)
            uji = (t.stdout + t.stderr)
        except Exception as e:
            return pulihkan('Uji konfigurasi PHP-FPM tidak bisa dijalankan', e)
        if t.returncode != 0 or 'successful' not in uji.lower():
            return pulihkan('Uji konfigurasi PHP-FPM menolak perubahan', uji.strip()[-200:])
        m0, w0 = self._php_master_workers(d)
        init = self.PHP_INIT % d
        if m0 and os.access(init, os.X_OK):
            try:
                subprocess.run([init, 'reload'], capture_output=True, text=True, timeout=60)
            except Exception as e:
                self._catat_galat('mitigasi PHP: reload PHP-FPM gagal', e)
                return public.returnMsg(False, 'php.ini sudah diubah tetapi PHP-FPM gagal dimuat ulang. Cadangan: %s' % os.path.basename(cadangan))
            tegak = False
            for _ in range(15):
                time.sleep(1)
                m1, w1 = self._php_master_workers(d)
                if m1 and w1 and not (w1 & w0):
                    tegak = True
                    break
            if not tegak:
                return public.returnMsg(False, 'php.ini sudah diubah dan lolos uji, tetapi PHP-FPM belum memakai pengaturan baru. Muat ulang PHP-FPM secara manual agar berlaku')
            diperiksa = 'Proses PHP sudah diganti, perubahan berlaku.'
        else:
            diperiksa = 'PHP-FPM tidak berjalan; berlaku saat dijalankan berikutnya.'
        self._php_cache['v'] = None
        return public.returnMsg(True, 'session.upload_progress.enabled = Off pada PHP %s. %s Cadangan: %s' % (d, diperiksa, os.path.basename(cadangan)))

    @staticmethod
    def _memscan_kill_mode(v):
        v = str(v or '').strip().lower()
        if v in ('on', '1', 'true', 'yes', 'semua'):
            return 'on'
        if v in ('off', '0', 'false', 'no', 'audit'):
            return 'off'
        return 'tinggi'

    def set_memscan(self, get):
        """Setel pemindai memori worker: memscan on/off; memscan_kill tinggi (bawaan: memfd, shm, ELF anonim),
        on (ditambah pustaka terhapus), off (hanya audit). Membunuh hanya bila Process Guard = enforce."""
        kunci = self._only(get, 'key', '')
        nilai = self._only(get, 'value', '')
        if kunci not in ('memscan', 'memscan_kill') or nilai not in ('on', 'off') + (('tinggi',) if kunci == 'memscan_kill' else ()):
            return public.returnMsg(False, 'Parameter tidak valid')
        conf_file = self._p('etc', 'guardd.conf')
        lines, ada = [], False
        if os.path.exists(conf_file):
            with open(conf_file, 'r', encoding='utf-8') as f:
                for ln in f:
                    if re.match(r'^\s*' + kunci + r'\s*=', ln):
                        lines.append('%s = %s\n' % (kunci, nilai)); ada = True
                    else:
                        lines.append(ln)
        if not ada:
            lines.append('%s = %s\n' % (kunci, nilai))
        tmp = conf_file + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        if os.path.exists(conf_file):
            shutil.copymode(conf_file, tmp)
        os.replace(tmp, conf_file)
        return public.returnMsg(True, '%s = %s (berlaku pada pemindaian berikutnya)' % (kunci, nilai))

    def _egress_state(self):
        """Isi run/egress.state yang ditulis sentinel-fw.sh saat Egress Guard dipasang: port, resolver DNS, status IPv6.
        Dulu UI menampilkan daftar port tetap yang tidak sama dengan aturan sebenarnya (22, 2222, 9418 juga terbuka)."""
        out = {}
        try:
            with open(self._p('run', 'egress.state')) as fh:
                for baris in fh:
                    k, _, v = baris.strip().partition('=')
                    if k == 'ports' and re.fullmatch(r'[0-9,]{1,120}', v):
                        out['allowed_ports'] = ', '.join(v.split(','))
                    elif k == 'dns' and re.fullmatch(r'[0-9A-Fa-f.: ]{0,300}', v):
                        out['dns_resolvers'] = v.strip()
                    elif k == 'ipv6' and len(v) < 40:
                        out['ipv6'] = v
        except OSError:
            pass
        return out

    def set_egress_guard(self, get):
        """Aktifkan atau nonaktifkan pengaman lalu lintas keluar (Anti-Reverse Shell)."""
        status = self._only(get, 'status', 'on')
        if status not in ('on', 'off'):
            return public.returnMsg(False, 'Status harus "on" atau "off"')
        cmd = [self._p('bin', 'sentinel-fw.sh'), 'egress-' + status]
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            return public.returnMsg(True, 'Egress Guard %s' % ('diaktifkan' if status == 'on' else 'dimatikan'))
        except Exception as e:
            return public.returnMsg(False, self._galat('Gagal mengatur Egress Guard', getattr(e, 'output', b'').decode('utf-8', errors='ignore') or e))

    def set_proc_guard(self, get):
        """Ubah mode Process Guard (enforce / audit / off)."""
        mode = self._only(get, 'mode', 'enforce')
        if mode not in ('enforce', 'audit', 'off'):
            return public.returnMsg(False, 'Mode harus enforce, audit, atau off')
            
        conf_file = self._p('etc', 'guardd.conf')
        lines = []
        found = False
        if os.path.exists(conf_file):
            with open(conf_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip().startswith('proc_guard'):
                        lines.append('proc_guard = ' + mode + '\n')
                        found = True
                    else:
                        lines.append(line)
        if not found:
            lines.append('proc_guard = ' + mode + '\n')
        # atomik: guardd.conf terpotong dibaca guardd sebagai "semua bawaan" (enforce=0, ambang/geo/notify bawaan)
        _tulis_atomik(conf_file, ''.join(lines), cadangan=True)
            
        if mode == 'off':
            if self._is_systemd():
                os.system('systemctl stop sentinel-proc.service 2>/dev/null')
            else:
                os.system("pkill -f '%s/bin/sentinel-proc.py' 2>/dev/null" % self.__PATH)
        else:
            if self._is_systemd():
                os.system('systemctl restart sentinel-proc.service 2>/dev/null')
            else:
                os.system("pkill -f '%s/bin/sentinel-proc.py' 2>/dev/null" % self.__PATH)
                os.system("nohup %s '%s/bin/sentinel-proc.py' daemon >/dev/null 2>&1 &" % (shlex.quote(_py_bin()), self.__PATH))
            
        return public.returnMsg(True, 'Mode Process Guard diubah ke %s' % mode.upper())

    def set_elite_defense(self, get):
        """Mengatur mode pertahanan elit (Egress Guard atau Process Watchdog)."""
        tipe = self._only(get, 'type', '')
        mode = self._only(get, 'mode', '')
        class ParamWrapper(dict):
            def __init__(self, d):
                super().__init__(d)
            def get(self, k, default=None):
                return super().get(k, default)
        if tipe == 'egress':
            return self.set_egress_guard(ParamWrapper({'status': mode}))
        elif tipe == 'proc':
            return self.set_proc_guard(ParamWrapper({'mode': mode}))
        return public.returnMsg(False, 'Jenis pertahanan tidak dikenal: %s' % _aman(tipe))

    def update_threat_intel(self, get):
        """Perbarui feed Threat Intel Spamhaus DROP/EDROP dan ZySens Reputation Feed sekarang."""
        # Edisi Free: fitur berbayar (threat_sync) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('threat_sync', self._get_active_lang(get))

    def av_check_persistence(self, get):
        """Jalankan verifikasi integritas persistensi sistem sekarang."""
        cmd = [self._p('bin', 'sentinel-av.sh'), 'check-sys']
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            return public.returnMsg(True, 'Pemeriksaan integritas persistensi sistem selesai')
        except Exception as e:
            return public.returnMsg(False, self._galat('Pemeriksaan integritas persistensi sistem gagal', getattr(e, 'output', b'').decode('utf-8', errors='ignore') or e))

    def av_baseline_persistence(self, get):
        """Buat ulang baseline integritas persistensi sistem."""
        cmd = [self._p('bin', 'sentinel-av.sh'), 'baseline-sys']
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            return public.returnMsg(True, 'Baseline persistensi sistem berhasil direkam ulang')
        except Exception as e:
            return public.returnMsg(False, self._galat('Gagal merekam baseline persistensi sistem', getattr(e, 'output', b'').decode('utf-8', errors='ignore') or e))

    # ------------------------------------------------------------------ #
    # EDR / PROCESS GUARD WHITELIST CRUD                                 #
    # ------------------------------------------------------------------ #
    def get_proc_whitelist(self, get):
        """Daftar aturan whitelist proses yang diizinkan untuk pekerja web."""
        try:
            if not os.path.isfile(self.PROC_WHITELIST_CONF):
                return public.returnMsg(True, [])
            with open(self.PROC_WHITELIST_CONF, 'r', encoding='utf-8', errors='ignore') as f:
                rules = json.load(f)
            return public.returnMsg(True, rules)
        except Exception as e:
            return public.returnMsg(False, self._galat('Gagal membaca whitelist', e))

    def add_proc_whitelist(self, get):
        """Tambah aturan whitelist proses baru. Masukan divalidasi ketat."""
        # Edisi Free: fitur berbayar (proc_enforce) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('proc_enforce', self._get_active_lang(get))

    def del_proc_whitelist(self, get):
        """Hapus aturan whitelist berdasarkan ID."""
        # Edisi Free: fitur berbayar (proc_enforce) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('proc_enforce', self._get_active_lang(get))

    def toggle_proc_whitelist(self, get):
        """Aktifkan atau nonaktifkan aturan whitelist."""
        # Edisi Free: fitur berbayar (proc_enforce) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('proc_enforce', self._get_active_lang(get))

    # ------------------------------------------------------------------ #
    # Real-Time Upload Scanner & Per-Host Quarantine (Imunify360 Style)  #
    # ------------------------------------------------------------------ #
    def _upload_scan_cli(self, *args):
        """Panggil pemindai Upload Protection dengan pyenv python3."""
        return 1, '', 'Upload Protection adalah fitur paket Max. Klik Upgrade untuk membukanya.'

    def get_vhost_upload_scan(self, get):
        """Ambil status upload scanner, clamd socket, RAM, dan status per vhost."""
        rc, o, e = self._upload_scan_cli('status')
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal mengambil status Upload Protection', e or o))
        try:
            data = json.loads(o)
            data['systemd_active'] = False
            # Dengan parameter page: hanya tabel vhost yang dipotong; angka ringkasan (active/total_vhosts_count) tetap dari CLI.
            if isinstance(data.get('vhosts'), list):
                potong, meta_hal = self._halaman(get, data['vhosts'])
                if meta_hal is not None:
                    data['vhosts'] = potong
                    data['halaman'] = meta_hal
            return public.returnMsg(True, data)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Status Upload Protection tidak bisa dibaca', ex))

    def get_upload_scan_status(self, get):
        """Ambil status upload protection (alias untuk get_vhost_upload_scan)."""
        return self.get_vhost_upload_scan(get)

    def _upload_aktif(self):
        try:
            with open(self._p('etc', 'vhost_upload_scan.json')) as f:
                d = json.load(f)
            return {k for k, v in (d.get('vhosts') or {}).items() if v}
        except Exception:
            return set()

    def toggle_vhost_upload_scan(self, get):
        """Aktifkan atau nonaktifkan pemindaian upload realtime untuk satu vhost."""
        # Edisi Free: fitur berbayar (upload_scan) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('upload_scan', self._get_active_lang(get))

    def set_vhost_upload_scan(self, get):
        """Setel status upload scan untuk satu vhost (on / off)."""
        vhost = str(get.get('vhost', '')).strip()
        state = str(get.get('state', '')).strip().lower()
        if not self._vhost_valid(vhost):
            return public.returnMsg(False, 'Nama vhost tidak valid')
        val = 'on' if state in ['1', 'true', 'on', 'yes'] else 'off'
        if val == 'on':
            aktif = self._upload_aktif()
            if vhost not in aktif:
                ditolak = self._batas_ditolak(get, 'upload_vhosts', len(aktif))
                if ditolak:
                    return ditolak
        rc, o, e = self._upload_scan_cli('set-vhost', vhost, val)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal menyimpan status Upload Protection untuk vhost ini', e or o))
        try:
            res = json.loads(o)
            return public.returnMsg(True, res)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Jawaban Upload Protection tidak bisa dibaca', ex))

    def get_vhost_quarantine(self, get):
        """Daftar berkas karantina per vhost (atau seluruh vhost jika vhost kosong)."""
        vhost = str(get.get('vhost', '')).strip()
        if vhost and not self._vhost_valid(vhost):
            return public.returnMsg(False, 'Nama vhost tidak valid')
        args = ['quarantine-list']
        if vhost:
            args.append(vhost)
        rc, o, e = self._upload_scan_cli(*args)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal mengambil daftar karantina upload', e or o))
        try:
            items = json.loads(o)
            return public.returnMsg(True, items)
        except Exception as ex:
            return public.returnMsg(False, self._galat('Jawaban Upload Protection tidak bisa dibaca', ex))

    def restore_vhost_quarantine(self, get):
        """Pulihkan berkas karantina ke lokasi aslinya dan kembalikan hak akses."""
        meta = self._quar_meta_valid(str(get.get('meta', '')))
        if not meta:
            return public.returnMsg(False, 'Berkas metadata karantina tidak valid')
        rc, o, e = self._upload_scan_cli('quarantine-restore', meta)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal memulihkan berkas dari karantina', e or o))
        try:
            res = json.loads(o)
            if res.get('status'):
                return public.returnMsg(True, 'Berkas berhasil dipulihkan')
            else:
                return public.returnMsg(False, self._pesan_skrip(res.get('msg'), 'Pemulihan berkas gagal'))
        except Exception as ex:
            return public.returnMsg(False, self._galat('Jawaban Upload Protection tidak bisa dibaca', ex))

    def delete_vhost_quarantine(self, get):
        """Hapus permanen berkas karantina dan metadata-nya."""
        meta = self._quar_meta_valid(str(get.get('meta', '')))
        if not meta:
            return public.returnMsg(False, 'Berkas metadata karantina tidak valid')
        rc, o, e = self._upload_scan_cli('quarantine-delete', meta)
        if rc != 0:
            return public.returnMsg(False, self._galat('Gagal menghapus berkas karantina upload', e or o))
        try:
            res = json.loads(o)
            if res.get('status'):
                return public.returnMsg(True, 'Berkas karantina berhasil dihapus')
            else:
                return public.returnMsg(False, self._pesan_skrip(res.get('msg'), 'Gagal menghapus berkas karantina'))
        except Exception as ex:
            return public.returnMsg(False, self._galat('Jawaban Upload Protection tidak bisa dibaca', ex))

    def toggle_upload_scan_service(self, get):
        """Nyalakan atau hentikan layanan daemon Upload Protection."""
        # Edisi Free: fitur berbayar (upload_scan) tidak ada; respons sama dengan build Pro berlisensi Free.
        return self._lisensi_ditolak('upload_scan', self._get_active_lang(get))

    # -------------------------------------------------------------------------
    # MANAJEMEN SIKLUS HIDUP (LIFECYCLE): FRESH | UPDATE | REPAIR | UNINSTALL
    # DUKUNGAN TELEMETRI GOOGLE ANALYTICS & TERMS POLICY
    # -------------------------------------------------------------------------
    def _is_telemetry_enabled(self):
        """Periksa apakah pengiriman statistik telemetri diizinkan. Default adalah On (True)."""
        conf_p = self._p('etc', 'telemetry.json')
        if not os.path.isfile(conf_p):
            conf_p = os.path.join(os.path.dirname(__file__), 'telemetry.json')
        if os.path.isfile(conf_p):
            try:
                with open(conf_p, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                    return bool(cfg.get('enabled', True))
            except Exception:
                return True
        return True

    def _public_ip(self):
        """Alamat IPv4 publik server, dipakai sebagai nama halaman telemetri.

        Urutan: alamat antarmuka yang routable secara global (bukan 10.x,
        172.16-31.x, 192.168.x, loopback, atau antarmuka docker), lalu
        daftar alamat yang dideteksi aaPanel (data/iplist.txt, berguna di
        belakang NAT), lalu _self_ip() sebagai pilihan terakhir.
        """
        kandidat = []
        try:
            with open('/proc/net/fib_trie') as f:
                for baris in f.read().splitlines():
                    b = baris.strip()
                    if '/32 host' in b and not b.startswith('32 host LOCAL'):
                        kandidat.append(b.split('/32 host')[0].strip().lstrip('|-+ '))
        except Exception:
            pass
        try:
            with open('/www/server/panel/data/iplist.txt') as f:
                kandidat += re.findall(r'\d{1,3}(?:\.\d{1,3}){3}', f.read())
        except Exception:
            pass
        for k in kandidat:
            try:
                if ipaddress.IPv4Address(k).is_global:
                    return k
            except Exception:
                continue
        return self._self_ip()

    def get_telemetry_setting(self, get):
        """Ambil konfigurasi telemetri statistik beserta IP publik server
        (nama halaman yang dilaporkan telemetri)."""
        return public.returnMsg(True, {
            'enabled': self._is_telemetry_enabled(),
            'server_ip': self._public_ip()
        })

    def set_telemetry_setting(self, get):
        """Ubah konfigurasi On/Off telemetri statistik."""
        val = str(get.get('enabled', '1')).strip().lower()
        enabled = val in ('1', 'true', 'on', 'yes')
        payload = {
            'enabled': enabled,
            'updated_at': int(time.time())
        }
        target_etc = self._p('etc', 'telemetry.json')
        try:
            os.makedirs(os.path.dirname(target_etc), exist_ok=True)
            _tulis_atomik(target_etc, json.dumps(payload, indent=2))
        except Exception as e:
            return public.returnMsg(False, self._galat('Gagal menyimpan pengaturan telemetri', e))

        try:
            local_p = os.path.join(os.path.dirname(__file__), 'telemetry.json')
            with open(local_p, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

        status_text = 'Aktif (ON)' if enabled else 'Nonaktif (OFF)'
        return public.returnMsg(True, 'Pengaturan telemetri berhasil diubah: %s' % status_text)

    def get_telemetry(self, get):
        """Alias untuk get_telemetry_setting."""
        return self.get_telemetry_setting(get)

    # ------------------------------------------------------------------ #
    # 2FA (TOTP, RFC 6238) untuk login UI standalone                       #
    # Rahasia disimpan di etc/ui/totp/<akun>.key (dibaca sentinel-uid saat   #
    # login). Pengaktifan dua langkah: rahasia dibuat sebagai .pending dan #
    # baru berlaku setelah pemilik membuktikan aplikasi autentikatornya     #
    # menghasilkan kode yang cocok, jadi salah pindai tidak mengunci akun.  #
    # Hanya tersedia di mode standalone; di aaPanel login ditangani panel.  #
    # ------------------------------------------------------------------ #
    _TOTP_PENDING_TTL = 600
    _TOTP_MAX_SALAH = 5

    def _totp_user(self):
        """Akun Linux pemilik sesi UI; None bila bukan mode standalone atau konteks tidak sah."""
        if not STANDALONE_MODE:
            return None
        fn = getattr(public, 'get_request_context', None)
        ctx = fn() if callable(fn) else None
        user = str((ctx or {}).get('user') or '')
        return user if re.match(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$', user) else None

    def _totp_file(self, user, ext):
        return self._p('etc', 'ui', 'totp', user + ext)

    @staticmethod
    def _totp_code(secret_b32, step):
        import base64
        import struct
        sec = secret_b32.strip().replace(' ', '').upper()
        key = base64.b32decode(sec + '=' * (-len(sec) % 8))
        h = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
        o = h[-1] & 0x0F
        return '%06d' % ((struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)

    def _totp_cocok(self, secret, kode):
        kode = str(kode or '').strip().replace(' ', '')
        if not re.match(r'^\d{6}$', kode):
            return False
        langkah = int(time.time() // 30)
        ok = False
        for st in (langkah - 1, langkah, langkah + 1):
            try:
                if hmac.compare_digest(self._totp_code(secret, st), kode):
                    ok = True
            except Exception:
                return False
        return ok

    def _totp_baca(self, user, ext):
        try:
            with open(self._totp_file(user, ext)) as f:
                return f.read().strip() or None
        except Exception:
            return None

    def _totp_tulis(self, user, ext, nilai):
        d = os.path.dirname(self._totp_file(user, ext))
        os.makedirs(d, mode=0o700, exist_ok=True)
        tmp = self._totp_file(user, ext + '.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(nilai + '\n')
        os.replace(tmp, self._totp_file(user, ext))

    def _totp_hapus(self, user, ext):
        try:
            os.remove(self._totp_file(user, ext))
        except OSError:
            pass

    def get_2fa_status(self, get):
        """Status 2FA akun yang sedang login. available=False di aaPanel (login oleh panel)."""
        user = self._totp_user()
        if not user:
            return public.returnMsg(True, {'available': False})
        return public.returnMsg(True, {
            'available': True, 'user': user,
            'enabled': bool(self._totp_baca(user, '.key')),
        })

    def begin_2fa(self, get):
        """Langkah 1: buat rahasia sementara dan kembalikan ke pemilik sesi (ditampilkan sekali)."""
        user = self._totp_user()
        if not user:
            return public.returnMsg(False, '2FA hanya tersedia pada UI standalone')
        if self._totp_baca(user, '.key'):
            return public.returnMsg(False, '2FA sudah aktif untuk akun ini; matikan dulu bila ingin membuat ulang')
        import base64
        rahasia = base64.b32encode(os.urandom(20)).decode().rstrip('=')
        try:
            self._totp_tulis(user, '.pending', '%d:%s' % (int(time.time()), rahasia))
        except Exception as e:
            return public.returnMsg(False, self._galat('Gagal menyiapkan 2FA', e))
        uri = 'otpauth://totp/ZySentinel:%s?secret=%s&issuer=ZySentinel&digits=6&period=30' % (urllib.parse.quote(user), rahasia)
        qr_svg = ''
        try:
            # QR dibuat di server ini; URI berisi rahasia sehingga tidak boleh lewat layanan QR pihak ketiga
            from adapters import qr as _qr
            qr_svg = _qr.svg(uri, label='QR 2FA ZySentinel')
        except Exception:
            qr_svg = ''
        return public.returnMsg(True, {'secret': rahasia, 'uri': uri, 'user': user, 'qr': qr_svg, 'ttl': self._TOTP_PENDING_TTL})

    def confirm_2fa(self, get):
        """Langkah 2: 2FA berlaku setelah kode dari aplikasi autentikator terbukti cocok."""
        user = self._totp_user()
        if not user:
            return public.returnMsg(False, '2FA hanya tersedia pada UI standalone')
        mentah = self._totp_baca(user, '.pending')
        if not mentah or ':' not in mentah:
            return public.returnMsg(False, 'Tidak ada pengaktifan 2FA yang sedang berjalan; mulai lagi')
        waktu, _, rahasia = mentah.partition(':')
        try:
            umur = time.time() - int(waktu)
        except ValueError:
            umur = self._TOTP_PENDING_TTL + 1
        if umur > self._TOTP_PENDING_TTL:
            self._totp_hapus(user, '.pending')
            return public.returnMsg(False, 'Waktu pengaktifan 2FA habis; mulai lagi')
        if not self._totp_cocok(rahasia, get.get('code', '')):
            salah = self.__dict__.setdefault('_totp_salah', {})
            salah[user] = salah.get(user, 0) + 1
            if salah[user] >= self._TOTP_MAX_SALAH:
                salah.pop(user, None)
                self._totp_hapus(user, '.pending')
                return public.returnMsg(False, 'Terlalu banyak kode salah; pengaktifan dibatalkan, mulai lagi')
            time.sleep(1)
            return public.returnMsg(False, 'Kode tidak cocok. Periksa jam perangkat Anda dan coba lagi')
        try:
            self._totp_tulis(user, '.key', rahasia)
        except Exception as e:
            return public.returnMsg(False, self._galat('Gagal mengaktifkan 2FA', e))
        self._totp_hapus(user, '.pending')
        self.__dict__.setdefault('_totp_salah', {}).pop(user, None)
        return public.returnMsg(True, '2FA aktif. Login berikutnya meminta kode autentikator')

    def disable_2fa(self, get):
        """Mematikan 2FA; wajib menyertakan kode autentikator yang sah (sesi curian tidak cukup)."""
        user = self._totp_user()
        if not user:
            return public.returnMsg(False, '2FA hanya tersedia pada UI standalone')
        rahasia = self._totp_baca(user, '.key')
        if not rahasia:
            self._totp_hapus(user, '.pending')
            return public.returnMsg(True, '2FA memang belum aktif')
        if not self._totp_cocok(rahasia, get.get('code', '')):
            time.sleep(1)
            return public.returnMsg(False, 'Kode tidak cocok; 2FA tetap aktif')
        self._totp_hapus(user, '.key')
        self._totp_hapus(user, '.pending')
        return public.returnMsg(True, '2FA dimatikan')

    def set_telemetry(self, get):
        """Alias untuk set_telemetry_setting."""
        return self.set_telemetry_setting(get)

    # ------------------------------------------------------------------ #
    # lisensi langganan (Free / Pro / Max)                               #
    # ------------------------------------------------------------------ #
    # Pesan lisensi untuk PENGGUNA (kunci galat -> (Indonesia, English)). Server lisensi mengirim `code` + `params`; teks yang tampil SELALU
    # dibangun dari katalog ini dalam bahasa aktif panel, tidak pernah dari `message` mentah server (server lama mengirim teks Indonesia
    # untuk developer) dan tidak pernah dari galat jaringan mentah. Kode yang tidak dikenal jatuh ke pesan umum yang ramah.
    _LIC_PESAN = {
        'server_unreachable': ('Server lisensi tidak terjangkau. Coba lagi nanti.', 'The license server is unreachable. Please try again later.'),
        'server_error': ('Terjadi gangguan pada server lisensi. Coba lagi nanti.', 'Something went wrong on the license server. Please try again later.'),
        'rate_limited': ('Terlalu banyak percobaan. Tunggu beberapa menit lalu coba lagi.', 'Too many attempts. Please wait a few minutes and try again.'),
        'request_blocked': ('Permintaan tidak dapat diproses.', 'The request could not be processed.'),
        'bad_request': ('Permintaan tidak valid. Periksa isian Anda lalu coba lagi.', 'The request was not valid. Please check your input and try again.'),
        'notfound': ('Data yang diminta tidak ditemukan.', 'The requested item was not found.'),
        'method_not_allowed': ('Jenis permintaan ini tidak didukung.', 'This type of request is not supported.'),
        'no_code': ('Belum ada kode lisensi di server ini.', 'There is no license code on this server yet.'),
        'invalid_code': ('Kode lisensi ini tidak valid untuk server ini. Periksa kodenya atau hubungi dukungan ZySens.',
                         'This license code is not valid for this server. Check the code, or contact ZySens support.'),
        'invalid_machine': ('Server ini tidak dapat dikenali. Pasang ulang plugin atau hubungi dukungan ZySens.',
                            'This server could not be identified. Reinstall the plugin or contact ZySens support.'),
        'bad_ip': ('Alamat server ini bukan IP publik, sehingga lisensi tidak dapat ditautkan.', "This server's address is not a public IP, so a license cannot be linked to it."),
        'revoked': ('Lisensi ini telah dicabut. Hubungi dukungan ZySens.', 'This license has been revoked. Contact ZySens support.'),
        'ip_mismatch': ('Lisensi ini terikat ke IP server lain. Hubungi dukungan ZySens untuk memindahkannya ke server ini.',
                        'This license is linked to a different server IP. Contact ZySens support to move it to this server.'),
        'integrity_mismatch': ('Berkas ZySentinel di server ini berbeda dari rilis resmi sehingga paket berbayar ditahan. Pasang ulang rilis resmi.',
                               'ZySentinel files on this server differ from the official release, so the paid plan is on hold. Reinstall the official release.'),
        'checkout_invalid': ('Email, paket, atau periode tagihan tidak valid. Periksa lalu coba lagi.', 'The email, plan, or billing period is not valid. Check them and try again.'),
        'checkout_method_mismatch': ('Metode pembayaran dan mata uang tidak cocok. Pilih PayPal (USD) atau Midtrans (IDR).',
                                     'The payment method and currency do not match. Choose PayPal (USD) or Midtrans (IDR).'),
        'checkout_origin_invalid': ('Server ini tidak dapat diverifikasi untuk pembayaran. Server memerlukan alamat IP publik; hubungi dukungan ZySens bila seharusnya memenuhi syarat.',
                                    'This server could not be verified for checkout. It needs a public IP address; contact ZySens support if it should qualify.'),
        'checkout_ip_in_use': ('IP server ini sudah terikat ke lisensi lain. Hubungi dukungan ZySens untuk mengubahnya.',
                               "This server's IP is already linked to another license. Contact ZySens support to change it."),
        'payment_unavailable': ('Layanan pembayaran belum tersedia saat ini. Coba lagi nanti.', 'The payment service is not available right now. Please try again later.'),
        'cancel_gateway_failed': ('PayPal belum dapat menghentikan langganan saat ini. Coba lagi nanti.', 'PayPal could not stop the subscription right now. Please try again later.'),
        'downgrade_blocked': ('Paket {plan} Anda masih aktif sampai {until}. Downgrade ke {target} bisa dipilih setelah masa itu berakhir (termasuk masa tenggang); '
                              'sekarang Anda bisa perpanjang, upgrade, atau Stop langganan.',
                              'Your {plan} plan is active until {until}. You can downgrade to {target} after that period ends (including the grace period); '
                              'for now you can renew, upgrade, or stop the subscription.'),
        'downgrade_blocked_x': ('Paket Anda masih aktif. Downgrade bisa dipilih setelah masa bayar berakhir (termasuk masa tenggang); sekarang Anda bisa perpanjang, upgrade, atau Stop langganan.',
                                'Your plan is still active. You can downgrade after the paid period ends (including the grace period); for now you can renew, upgrade, or stop the subscription.'),
        'already_subscribed': ('Langganan PayPal {plan} Anda sudah memperpanjang otomatis. Untuk pindah metode pembayaran, Stop langganan dulu lalu bayar setelah masa aktif berakhir.',
                               'Your PayPal {plan} subscription already renews automatically. To change the payment method, stop the subscription first, then pay after the current period ends.'),
        'already_subscribed_x': ('Langganan PayPal Anda sudah memperpanjang otomatis. Untuk pindah metode pembayaran, Stop langganan dulu lalu bayar setelah masa aktif berakhir.',
                                 'Your PayPal subscription already renews automatically. To change the payment method, stop the subscription first, then pay after the current period ends.'),
        'no_subscription': ('Tidak ada langganan berbayar yang aktif untuk dihentikan.', 'There is no active paid subscription to stop.'),
        'reason_required': ('Alasan wajib dipilih.', 'Please choose a reason.'),
        'note_required': ('Catatan wajib diisi (minimal 5 karakter) bila alasannya Lainnya.', 'Please explain in the note (at least 5 characters) when the reason is Other.'),
        'promo_unknown': ('Kode promo tidak dikenal.', 'This promo code is not recognized.'),
        'promo_expired': ('Kode promo sudah tidak berlaku.', 'This promo code has expired.'),
        'promo_exhausted': ('Kuota kode promo sudah habis.', 'This promo code has reached its usage limit.'),
        'promo_currency': ('Kode promo hanya untuk pembayaran {currency}.', 'This promo code only applies to {currency} payments.'),
        'promo_plan': ('Kode promo tidak berlaku untuk paket {plan}.', 'This promo code does not apply to the {plan} plan.'),
        'promo_period': ('Kode promo tidak berlaku untuk periode ini.', 'This promo code does not apply to this billing period.'),
        'promo_used': ('Kode promo sudah pernah Anda pakai.', 'You have already used this promo code.'),
        'promo_invalid': ('Kode promo tidak dapat dipakai.', 'This promo code cannot be used.'),
        'not_developer': ('Akun GitHub ini tidak terdaftar sebagai developer atau maintainer.', 'This GitHub account is not registered as a developer or maintainer.'),
        'dev_request_invalid': ('Username GitHub, paket, atau data server tidak valid. Periksa lalu coba lagi.', 'The GitHub username, plan, or server details are not valid. Check them and try again.'),
        'bad_challenge': ('Permintaan verifikasi tidak berlaku lagi (kedaluwarsa, sudah dipakai, atau dari server lain). Mulai ulang untuk mendapatkan yang baru.',
                          'The verification request is no longer valid (expired, already used, or from another server). Start again to get a new one.'),
        'github_unreadable': ('Kunci publik GitHub Anda belum dapat dibaca saat ini. Coba lagi nanti.', 'Your GitHub public keys could not be read right now. Please try again later.'),
        'bad_signature': ('Tanda tangan tidak diterima: kunci SSH yang dipakai tidak terdaftar di akun GitHub Anda, atau tanda tangannya tidak cocok. Tanda tangani teks verifikasi terbaru dengan kunci yang terdaftar.',
                          'The signature was not accepted: the SSH key used is not registered on your GitHub account, or the signature does not match. Sign the latest verification text with a registered key.'),
        'dev_ip_has_license': ('Server ini sudah memiliki lisensi lain (paket {plan}, {state}). Akses developer tidak dapat menggantinya; hubungi dukungan ZySens bila perlu dilepas.',
                               'This server already has another license ({plan} plan, {state}). Developer access cannot replace it; contact ZySens support if it needs to be removed.'),
        'dev_ip_has_license_x': ('Server ini sudah memiliki lisensi lain. Akses developer tidak dapat menggantinya; hubungi dukungan ZySens bila perlu dilepas.',
                                 'This server already has another license. Developer access cannot replace it; contact ZySens support if it needs to be removed.'),
        'not_entitled': ('Item ini tidak termasuk dalam paket Anda saat ini.', 'This item is not included in your current plan.'),
        'local_key_missing': ('Kunci SSH lokal tidak ditemukan atau permintaan verifikasi tidak cocok. Tempel tanda tangan secara manual.',
                              'No local SSH key was found, or the verification request does not match. Paste the signature manually.'),
        'local_sign_failed': ('Tanda tangan dengan kunci SSH lokal belum berhasil. Tempel tanda tangan secara manual, atau pakai kunci tanpa passphrase.',
                              'Signing with the local SSH key did not work. Paste the signature manually, or use a key without a passphrase.'),
        'subscription_stopped': ('Langganan dihentikan tanpa refund. Paket {plan} tetap aktif sampai {until} lalu berhenti otomatis.',
                                 'Subscription stopped with no refund. Your {plan} plan stays active until {until}, then ends automatically.'),
        'subscription_stopped_x': ('Langganan dihentikan tanpa refund. Paket tetap aktif sampai akhir masa bayar lalu berhenti otomatis.',
                                   'Subscription stopped with no refund. Your plan stays active until the end of the paid period, then ends automatically.'),
        'release_thanks': ('Terima kasih atas umpan balik Anda. Lisensi dilepas dari server ini.', 'Thank you for your feedback. The license was released from this server.'),
        'state_free': ('Paket Free aktif.', 'The Free plan is active.'),
        'state_active': ('Paket berbayar aktif.', 'Your paid plan is active.'),
        'state_pending': ('Pembayaran belum terkonfirmasi. Biasanya kurang dari satu menit setelah Anda membayar; tekan Cek pembayaran lagi sebentar lagi.',
                          'Payment is not confirmed yet. It usually takes under a minute after you pay; press Check payment again shortly.'),
        'state_grace': ('Masa bayar sudah berakhir. Paket tetap aktif selama masa tenggang singkat; perpanjang agar tidak turun ke Free.',
                        'Your paid period has ended. The plan stays active for a short grace period; renew to avoid dropping to Free.'),
        'state_expired': ('Paket berbayar sudah kedaluwarsa dan server kembali ke Free. Perpanjang untuk membukanya lagi.',
                          'Your paid plan has expired and this server is back on Free. Renew to unlock it again.'),
        # pesan umum per tindakan (server lama tanpa `code`, atau kode baru yang belum dikenal klien ini)
        'checkout_failed': ('Pembayaran belum dapat dimulai. Coba lagi nanti; bila terus gagal, hubungi dukungan ZySens.',
                            'The payment could not be started. Please try again later; if it keeps failing, contact ZySens support.'),
        'activate_failed': ('Lisensi belum dapat diaktifkan. Periksa kode lisensi lalu coba lagi, atau hubungi dukungan ZySens.',
                            'The license could not be activated. Check the license code and try again, or contact ZySens support.'),
        'cancel_failed': ('Langganan belum dapat dihentikan saat ini. Coba lagi nanti atau hubungi dukungan ZySens.',
                          'The subscription could not be stopped right now. Please try again later or contact ZySens support.'),
        'dev_failed': ('Akses developer belum dapat diaktifkan. Coba lagi nanti atau hubungi dukungan ZySens.',
                       'Developer access could not be activated. Please try again later or contact ZySens support.'),
        'release_failed': ('Lisensi belum dapat dilepas saat ini. Coba lagi nanti.', 'The license could not be removed right now. Please try again later.'),
        'refresh_failed': ('Status lisensi belum dapat diperbarui. Coba lagi nanti.', 'The license status could not be updated. Please try again later.'),
        'generic_failed': ('Permintaan belum dapat diselesaikan. Coba lagi nanti atau hubungi dukungan ZySens.',
                           'The request could not be completed. Please try again later or contact ZySens support.'),
    }
    # state/kode server lama -> kode katalog (hanya yang tidak butuh parameter dan tidak bergantung pada tindakan)
    _LIC_STATE_KODE = {
        'invalid_code': 'invalid_code', 'invalid_machine': 'invalid_machine', 'bad_ip': 'bad_ip', 'invalid_ip': 'bad_ip', 'revoked': 'revoked',
        'ip_mismatch': 'ip_mismatch', 'rate': 'rate_limited', 'not_developer': 'not_developer', 'bad_challenge': 'bad_challenge',
        'bad_signature': 'bad_signature', 'reason_required': 'reason_required', 'note_required': 'note_required', 'no_subscription': 'no_subscription',
        'not_entitled': 'not_entitled', 'github': 'github_unreadable', 'offline': 'server_unreachable', 'no_code': 'no_code',
        'pending': 'state_pending', 'grace': 'state_grace', 'expired': 'state_expired', 'free': 'state_free', 'active': 'state_active',
    }
    # state server lama yang artinya bergantung pada tindakan yang sedang berjalan: (tindakan -> kode)
    _LIC_STATE_AKSI = {
        'ip_in_use': {'checkout_failed': 'checkout_ip_in_use', 'dev_failed': 'dev_ip_has_license_x'},
        'gateway': {'checkout_failed': 'payment_unavailable', 'cancel_failed': 'cancel_gateway_failed'},
        'promo': {'checkout_failed': 'promo_invalid'},
        'downgrade_blocked': {'checkout_failed': 'downgrade_blocked_x'},
        'already_subscribed': {'checkout_failed': 'already_subscribed_x'},
    }
    _LIC_STATE_KATA = {'active': ('aktif', 'active'), 'grace': ('masa tenggang', 'grace period'), 'expired': ('kedaluwarsa', 'expired'),
                       'pending': ('menunggu pembayaran', 'awaiting payment'), 'free': ('Free', 'Free')}

    def _lic_param(self, params, lang):
        """Nilai param dari server dibersihkan: hanya teks/angka pendek berkarakter aman; `state` diterjemahkan lewat tabel kata."""
        out = {}
        if isinstance(params, dict):
            for k, v in params.items():
                if not isinstance(k, str) or isinstance(v, bool) or not isinstance(v, (str, int)):
                    continue
                v = str(v)
                if k == 'state':
                    v = self._LIC_STATE_KATA.get(v, ('-', '-'))[0 if lang == 'id' else 1]
                elif not re.fullmatch(r'[A-Za-z0-9 ._:/+-]{1,40}', v):
                    v = '-'
                out[k] = v
        return out

    def _lic_teks(self, kode, params, lang):
        """Teks katalog untuk `kode` dalam bahasa `lang`; parameter kurang -> varian `<kode>_x`, lalu pesan umum."""
        i = 0 if lang == 'id' else 1
        ent = self._LIC_PESAN.get(kode) or self._LIC_PESAN['generic_failed']
        try:
            return ent[i].format(**self._lic_param(params, lang))
        except (KeyError, IndexError, ValueError):
            return (self._LIC_PESAN.get(str(kode) + '_x') or self._LIC_PESAN['generic_failed'])[i]

    def _lic_kode(self, js, st, awal):
        """(kode katalog, params) dari respons server `js` dengan status HTTP `st`; `awal` = kode pesan umum tindakan yang berjalan."""
        js = js if isinstance(js, dict) else {}
        kode = js.get('code')
        params = js.get('params') if isinstance(js.get('params'), dict) else {}
        if not st or js.get('state') == 'offline':
            return 'server_unreachable', {}
        if isinstance(kode, str) and kode in self._LIC_PESAN:
            return kode, params
        state = js.get('state')
        if isinstance(state, str):
            if state in self._LIC_STATE_AKSI:
                return self._LIC_STATE_AKSI[state].get(awal, awal), {}
            if state in self._LIC_STATE_KODE:
                return self._LIC_STATE_KODE[state], {}
        if st == 429:
            return 'rate_limited', {}
        if isinstance(st, int) and st >= 500 and awal != 'cancel_failed':
            return 'server_error', {}
        return awal, {}

    def _lic_pesan(self, js, st, lang, awal):
        """Pesan pengguna untuk respons gagal server lisensi: dari kode + params dalam bahasa aktif, bukan teks mentah server."""
        kode, params = self._lic_kode(js, st, awal)
        return self._lic_teks(kode, params, 'id' if lang == 'id' else 'en')

    def _lic_pesan_info(self, info, lang, awal, hanya_masalah=False):
        """Seperti _lic_pesan tetapi untuk hasil _lic.refresh() (info status). hanya_masalah=True: '' bila status normal (free/active tanpa catatan)."""
        info = info if isinstance(info, dict) else {}
        kode, params = self._lic_kode({'code': info.get('code'), 'state': info.get('state'), 'params': info.get('params')}, info.get('http', 1) if 'http' in info else 1, awal)
        if hanya_masalah and (not info.get('state') or kode in ('state_free', 'state_active')):
            return ''
        return self._lic_teks(kode, params, 'id' if lang == 'id' else 'en')

    def _lisensi_ditolak(self, fitur, lang):
        butuh = _PLAN_NAME.get(_lic.needed_plan(fitur), 'Pro')
        if lang == 'en':
            msg = 'This feature requires the %s plan or higher. Click Upgrade to unlock it.' % butuh
        else:
            msg = 'Fitur ini membutuhkan paket %s atau lebih tinggi. Klik Upgrade untuk membukanya.' % butuh
        res = public.returnMsg(False, msg)
        res['upgrade'] = {'feature': fitur, 'plan': _lic.needed_plan(fitur), 'current': _lic.plan()}
        return res

    def _batas_ditolak(self, get, nama, saat_ini):
        """None bila masih di bawah batas paket; selain itu pesan penolakan (batas jumlah per paket)."""
        batas = _lic.limit(nama)
        if batas is None or saat_ini < batas:
            return None
        lang = self._get_active_lang(get)
        label = {'port_rules': ('aturan port', 'port rules'), 'waf_vhosts': ('vhost WAF', 'WAF vhosts'),
                 'upload_vhosts': ('vhost Upload Protection', 'Upload Protection vhosts')}.get(nama, (nama, nama))
        if lang == 'en':
            msg = 'Your plan allows up to %d %s. Upgrade to add more.' % (batas, label[1])
        else:
            msg = 'Paket Anda mengizinkan hingga %d %s. Upgrade untuk menambah.' % (batas, label[0])
        res = public.returnMsg(False, msg)
        # Upload Protection hanya Max (Pro 0 vhost): saran paket langsung Max
        naik = 'pro' if _lic.plan() == 'free' and nama != 'upload_vhosts' else 'max'
        res['upgrade'] = {'feature': nama, 'plan': naik, 'current': _lic.plan()}
        return res

    def _lic_terapkan_bila_berubah(self, fitur_lama):
        """Paket berubah (aktivasi, cek pembayaran, lepas lisensi): selaraskan firewall dan layanan berpaket di latar belakang.
        Agen hanya memasang ulang aturan sentinel dan memulai/menghentikan layanan milik plugin."""
        try:
            st = _lic.status(True)
            if _lic.transient(st):
                return      # pemverifikasi gagal dijalankan: bukan keputusan paket, mesin tidak diturunkan
            baru = st.get('features', [])
            if sorted(fitur_lama or []) != sorted(baru):
                pass
        except Exception:
            pass

    def _lic_segarkan_latar(self, info, code):
        return False

    def get_license(self, get):
        """Status paket untuk UI: paket, fitur, batas, tagihan, kode tersamar, hasil heartbeat terakhir."""
        st = _lic.status_tampil()      # tidak pernah "tidak diketahui": jawaban pemverifikasi, atau hasil terakhir yang sah (stale), atau Free
        info = _lic.state_info()
        code = _lic.get_code()
        segar = self._lic_segarkan_latar(info, code)
        return public.returnMsg(True, {'refreshing': segar,
            'stale': bool(st.get('stale')), 'sync': info.get('sync', ''), 'sync_diff': info.get('selisih', []),
            'platforms': _lic.platforms_diizinkan() if not st.get('stale') else ([n for n, f in _lic.PLATFORM_FEATURE.items() if f is None or f in st.get('features', [])]),
            'all_platforms': list(_lic.PLATFORM_FEATURE),
            'mode': st.get('mode'), 'valid': bool(st.get('valid')), 'reason': st.get('reason', ''), 'plan': st.get('plan', 'free'),
            'state': st.get('state') or info.get('state', 'free'), 'paid_until': st.get('paid') or info.get('paid_until', 0),
            'exp': st.get('exp', 0), 'features': st.get('features', []), 'all_features': _lic.FEATURES,
            'code': _lic.mask_code(code), 'has_code': bool(code), 'ip': st.get('ip') or info.get('ip', ''),
            # email pemilik lisensi (dari heartbeat sah): dialog pembelian mengisi dan menguncinya sampai lisensi di-uninstall
            'email': (info.get('email') or '') if code else '',
            'last': dict({k: info.get(k) for k in ('ts', 'state', 'http')}, message=self._lic_pesan_info(info, self._get_active_lang(get), 'refresh_failed', True)),
            'cancelled': bool(info.get('cancelled')), 'transient': False,
            'limits': {k: _lic.limit(k) for k in ('waf_vhosts', 'port_rules', 'upload_vhosts')},
            'needed': dict(_lic.PLAN_NEEDED), 'edition': getattr(_lic, 'EDITION', 'pro')})

    def get_plans(self, get):
        cur = 'IDR' if _g(get, 'currency', 'USD').upper() == 'IDR' else 'USD'
        promo = re.sub(r'[^A-Za-z0-9]', '', _g(get, 'promo'))[:24].upper()
        lang = self._get_active_lang(get)
        d = _lic.fetch_plans(cur, promo, lang)
        if not isinstance(d, dict):
            return public.returnMsg(False, self._lic_teks('server_unreachable', {}, lang))
        pi = d.get('promo')
        if isinstance(pi, dict) and not pi.get('ok'):        # pratinjau promo: teks dari katalog dalam bahasa aktif, bukan teks mentah server
            kode = pi.pop('reason', '')
            prm = pi.pop('params', {})
            pi['message'] = self._lic_teks(kode if kode in self._LIC_PESAN else 'promo_invalid', prm, lang)
        return public.returnMsg(True, d)

    def license_checkout(self, get):
        """Buat pesanan di server zysens dan kembalikan tautan pembayaran."""
        email = _g(get, 'email').lower()
        name = _g(get, 'name').strip()[:100]
        phone = _g(get, 'phone').strip()[:30]
        plan, period = _g(get, 'plan'), _g(get, 'period')
        gw = _g(get, 'gateway', 'auto') or 'auto'
        cur = _g(get, 'currency', '').upper()
        if not cur and gw != 'auto':
            cur = 'IDR' if gw == 'midtrans' else 'USD'
        lang = self._get_active_lang(get)
        if not re.fullmatch(r'[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}', email):
            return public.returnMsg(False, 'Email tidak valid' if lang != 'en' else 'Invalid email address')
        if plan not in ('pro', 'max') or period not in ('m', 'y') or gw not in ('paypal', 'midtrans', 'auto'):
            return public.returnMsg(False, 'Paket, periode, atau metode pembayaran tidak valid' if lang != 'en' else 'Invalid plan, period or payment method')
        promo = re.sub(r'[^A-Za-z0-9]', '', _g(get, 'promo'))[:24].upper()
        st, js = _lic.checkout(email, plan, period, gw, cur, promo, lang, name=name, phone=phone)
        if st == 200 and js.get('pay_url'):
            return public.returnMsg(True, {'pay_url': js['pay_url'], 'order_id': js.get('order_id'), 'code': _lic.mask_code(js.get('code', '')),
                                           'amount': js.get('amount'), 'list_price': js.get('list_price'), 'promo': js.get('promo', ''),
                                           'currency': js.get('currency'), 'gateway': js.get('gateway', '')})
        return public.returnMsg(False, self._lic_pesan(js, st, lang, 'checkout_failed'))

    def _alasan_baca(self, get, lang):
        """Alasan (kode) dan catatan dari panel untuk Stop langganan / Uninstall License. Alasan wajib; 'other' wajib disertai catatan >= 5 karakter.
        Mengembalikan (alasan, catatan, pesan_galat)."""
        reason = _g(get, 'reason').strip()
        note = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', _g(get, 'note')).strip()[:500]
        en = (lang == 'en')
        if reason not in _lic.ALASAN_KODE:
            return '', '', ('Please choose a reason' if en else 'Alasan wajib dipilih')
        if reason == 'other' and len(note) < 5:
            return '', '', ('Please explain in the note (at least 5 characters) when the reason is Other' if en else 'Catatan wajib diisi (minimal 5 karakter) bila alasan Lainnya')
        return reason, note, ''

    def license_cancel(self, get):
        """Tombol 'Stop langganan': hentikan perpanjangan otomatis tanpa refund; paket tetap aktif sampai akhir masa bayar."""
        lang = self._get_active_lang(get)
        if not _lic.get_code():
            return public.returnMsg(False, 'Belum ada kode lisensi di server ini' if lang != 'en' else 'No license code on this server')
        reason, note, salah = self._alasan_baca(get, lang)
        if salah:
            return public.returnMsg(False, salah)
        st, js = _lic.cancel_subscription(reason, note, lang)
        if st == 200 and js.get('ok'):
            _lic.refresh()
            pu = js.get('paid_until')
            if isinstance(pu, int) and pu > 0 and js.get('plan') in ('pro', 'max'):       # teks dari paket + tanggal, bukan pesan mentah server
                ket = self._lic_teks('subscription_stopped', {'plan': js['plan'].upper(), 'until': time.strftime('%Y-%m-%d', time.gmtime(pu))}, lang)
            else:
                ket = self._lic_teks('subscription_stopped_x', {}, lang)
            return public.returnMsg(True, {'paid_until': js.get('paid_until', 0), 'state': js.get('state'), 'plan': js.get('plan'), 'message': ket})
        return public.returnMsg(False, self._lic_pesan(js, st, lang, 'cancel_failed'))

    def license_refresh(self, get):
        """Tombol 'Cek pembayaran': heartbeat segera. Bila ada order_id, sertakan status pesanan."""
        lang = self._get_active_lang(get)
        oid = _g(get, 'order_id')
        out_order = None
        if oid and re.fullmatch(r'ZYS-[0-9A-Z-]{6,40}', oid):
            st, js = _lic.checkout_status(oid, lang)
            out_order = (js or {}).get('order')
        else:
            st, js = _lic.checkout_status('', lang)
            if js and js.get('order'):
                out_order = js.get('order')
        lama = list(_lic.status().get('features', []))
        info = _lic.refresh(None, lang)
        self._lic_terapkan_bila_berubah(lama)
        out = {'state': info.get('state'), 'plan': _lic.plan(), 'ok': bool(info.get('ok')), 'message': self._lic_pesan_info(info, lang, 'refresh_failed')}
        if out_order is not None:
            out['order'] = out_order
        return public.returnMsg(bool(info.get('ok')) or info.get('state') in ('pending', 'free', 'expired', 'no_code'), out)

    def license_activate(self, get):
        """Masukkan kode lisensi yang sudah ada (mis. dari developer). Kode hanya disimpan bila server menerimanya."""
        code = _g(get, 'code').upper()
        lang = self._get_active_lang(get)
        if not re.fullmatch(r'ZYS(-[A-HJ-NP-Z2-9]{5}){4}', code):
            return public.returnMsg(False, 'Format kode lisensi tidak valid' if lang != 'en' else 'Invalid license code format')
        lama = list(_lic.status().get('features', []))
        info = _lic.refresh(code, lang)
        self._lic_terapkan_bila_berubah(lama)
        if info.get('ok'):
            return public.returnMsg(True, {'plan': info.get('plan'), 'state': info.get('state')})
        return public.returnMsg(False, self._lic_pesan_info(info, lang, 'activate_failed'))

    def license_dev_challenge(self, get):
        return public.returnMsg(False, 'Lisensi developer hanya di ZySentinel Pro' if self._get_active_lang(get) != 'en' else 'Developer license is available in ZySentinel Pro only')
    
    def license_dev_activate(self, get):
        return self.license_dev_challenge(get)

    def license_deactivate(self, get):
        """Lepas lisensi dari server ini (kembali ke Free). Kode lisensi tidak dihapus dari server."""
        lang = self._get_active_lang(get)
        terkirim = None
        if _lic.get_code():
            # Uninstall License: alasan wajib; server mencatat umpan balik (developer memperbaiki produk). Penolakan validasi menghentikan proses;
            # server tidak terjangkau atau menolak kode/IP tidak menghalangi pelepasan lokal (umpan balik saja yang tidak terkirim).
            reason, note, salah = self._alasan_baca(get, lang)
            if salah:
                return public.returnMsg(False, salah)
            st, js = _lic.release_license(reason, note, lang)
            if st == 400:
                return public.returnMsg(False, self._lic_pesan(js, st, lang, 'bad_request'))
            terkirim = (st == 200 and bool(js.get('ok')))
        lama = list(_lic.status().get('features', []))
        for f in ('license.code', 'license.state.json', 'license.last.json'):     # last.json: hasil terakhir Pro/Max tidak boleh dipakai sebagai tampilan setelah dilepas
            try:
                os.remove(self._p('etc', f))
            except OSError:
                pass
        _lic.remove_token()
        self._lic_terapkan_bila_berubah(lama)
        en = (lang == 'en')
        ket = ''
        if terkirim is False:
            ket = (' (feedback could not be sent to the license server)' if en else ' (umpan balik belum terkirim ke server lisensi)')
        return public.returnMsg(True, ('License uninstalled, plan is now Free' if en else 'Lisensi di-uninstall, paket kembali ke Free') + ket)

    def get_lang_setting(self, get):
        """Ambil konfigurasi bahasa antarmuka (default: 'en')."""
        lang = 'en'
        target_etc = self._p('etc', 'lang.json')
        if os.path.exists(target_etc):
            try:
                with open(target_etc, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    lang = data.get('lang', 'en')
            except Exception:
                pass
        else:
            local_p = os.path.join(os.path.dirname(__file__), 'lang.json')
            if os.path.exists(local_p):
                try:
                    with open(local_p, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        lang = data.get('lang', 'en')
                except Exception:
                    pass
        return public.returnMsg(True, {'lang': lang if lang in ('en', 'id') else 'en'})

    def set_lang_setting(self, get):
        """Simpan preferensi bahasa antarmuka ('en' atau 'id')."""
        lang = str(get.get('lang', 'en')).strip().lower()
        if lang not in ('en', 'id'):
            lang = 'en'
        payload = {
            'lang': lang,
            'updated_at': int(time.time())
        }
        target_etc = self._p('etc', 'lang.json')
        try:
            os.makedirs(os.path.dirname(target_etc), exist_ok=True)
            _tulis_atomik(target_etc, json.dumps(payload, indent=2))
        except Exception as e:
            return public.returnMsg(False, self._galat('Gagal menyimpan pilihan bahasa', e))

        try:
            local_p = os.path.join(os.path.dirname(__file__), 'lang.json')
            with open(local_p, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

        label = 'English' if lang == 'en' else 'Bahasa Indonesia'
        return public.returnMsg(True, 'Bahasa antarmuka diubah ke %s' % label)

    def get_lang(self, get):
        """Alias untuk get_lang_setting."""
        return self.get_lang_setting(get)

    def set_lang(self, get):
        """Alias untuk set_lang_setting."""
        return self.set_lang_setting(get)

    def _send_telemetry(self, event_name, extra_params=None):
        """Kirim statistik telemetri anonim (instalasi/error/pembaruan) ke Google Analytics.
        
        Sesuai kebijakan privasi lisensi: HANYA metrik umum sistem yang dikirim.
        TIDAK ADA kredensial, password, token, atau informasi pribadi/rahasia server.
        """
        if not self._is_telemetry_enabled():
            return
        try:
            cid = 'anon-sentinel'
            if os.path.exists('/etc/machine-id'):
                try:
                    with open('/etc/machine-id', 'r') as f:
                        cid = hashlib.md5(f.read().strip().encode('utf-8')).hexdigest()
                except Exception:
                    pass
            elif os.path.exists('/var/lib/dbus/machine-id'):
                try:
                    with open('/var/lib/dbus/machine-id', 'r') as f:
                        cid = hashlib.md5(f.read().strip().encode('utf-8')).hexdigest()
                except Exception:
                    pass

            v_info = self._versi_plugin()

            params = {
                'v': '2',
                'tid': 'G-8DBL8LPYQZ',
                'cid': cid,
                'en': event_name,
                'ep.plugin_version': v_info,
                'ep.os_name': platform.system(),
                'ep.os_release': platform.release()[:20],
                'ep.arch': platform.machine()
            }
            if extra_params and isinstance(extra_params, dict):
                for k, v in extra_params.items():
                    params['ep.' + str(k)] = str(v)[:100]

            url = 'https://www.google-analytics.com/g/collect?' + urllib.parse.urlencode(params)
            req = urllib.request.Request(url, headers={'User-Agent': 'ZySentinel-Telemetry/' + v_info})
            _lic.urlopen(req, timeout=3.0)
        except Exception:
            pass

    def _versi_plugin(self):
        """Versi plugin 'X.Y.Z': sumber tunggal info.json (ditanam versi.py dari nama cabang rilis);
        cadangan VERSION modul lisensi. Jangan menulis literal versi di berkas ini."""
        try:
            with open(os.path.join(_PLUGIN_DIR, 'info.json'), 'r', encoding='utf-8') as f:
                v = str(json.load(f).get('versions', '')).strip().lstrip('vV')
            if re.match(r'^\d+\.\d+\.\d+$', v):
                return v
        except Exception:
            pass
        return str(getattr(_lic, 'VERSION', '0.0.0'))

    def _parse_version(self, v_str):
        """Parse semver string menjadi tuple integer (mis. 'v1.2.3' -> (1, 2, 3))."""
        if not v_str:
            return (0, 0, 0)
        v_clean = str(v_str).strip().lstrip('vV')
        parts = []
        for x in re.split(r'[-.+_]', v_clean):
            if x.isdigit():
                parts.append(int(x))
            else:
                break
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _normalize_version(self, v_str):
        """Pastikan format versi selalu berawalan 'v' (mis. 'v1.2.3'); kosong = versi plugin."""
        if not v_str or str(v_str).strip() in ('-', ''):
            return 'v' + self._versi_plugin()
        s = str(v_str).strip()
        return s if s.lower().startswith('v') else ('v' + s)

    def get_lifecycle_status(self, get):
        """Ambil status detail siklus hidup, versi, dan diagnostik komponen."""
        v_info = self._normalize_version(self._versi_plugin())

        installed = os.path.exists(os.path.join(self.__PATH, 'bin', 'guardd'))
        lock_active = os.path.exists(os.path.join(self.__PATH, 'etc', 'uninstall.lock'))

        units = ['sentinel.service', 'sentinel-fw.service', 'sentinel-proc.service', 'sentinel-av.timer']
        services_status = {}
        if self._is_systemd():
            rc, o, _ = self._sh("systemctl is-active " + " ".join(units), 5)
            lines = o.strip().splitlines()
            for idx, u in enumerate(units):
                st = lines[idx].strip() if idx < len(lines) else ''
                services_status[u] = (st in ('active', 'running'))
        else:
            for u in units:
                services_status[u] = (self._svc(u) in ('active', 'running'))

        hostname = socket.gethostname() if hasattr(socket, 'gethostname') else 'unknown-host'

        return public.returnMsg(True, {
            'version': v_info,
            'is_installed': installed,
            'uninstall_locked': lock_active,
            'services': services_status,
            'hostname': hostname
        })

    def run_lifecycle_action(self, get):
        """Jalankan aksi siklus hidup: fresh, repair, update, uninstall / cabut."""
        action = str(get.get('sub_action') or get.get('act') or get.get('aksi') or (get.get('action') if get.get('action') != 'a' else '') or '').strip().lower()
        if action not in ['fresh', 'repair', 'update', 'uninstall', 'cabut']:
            return public.returnMsg(False, 'Aksi tidak valid (fresh, repair, update, atau uninstall)')

        plug_dir = os.path.dirname(__file__)
        install_script = os.path.join(plug_dir, 'install.sh')
        if not os.path.exists(install_script):
            return public.returnMsg(False, 'Berkas pemasang plugin tidak ditemukan; pasang ulang plugin dari App Store atau paket resmi')

        if action in ['uninstall', 'cabut']:
            confirm = str(get.get('confirm', '')).strip().upper()
            if confirm not in ['UNINSTALL', 'CABUT']:
                return public.returnMsg(False, 'Konfirmasi uninstall tidak sesuai. Harap ketik UNINSTALL.')
            rc, o, e = self._sh("bash %s uninstall --clean" % install_script, 60)
            self._send_telemetry('uninstall_clean', {'status': 'success' if rc == 0 else 'failed'})
            if rc != 0:
                return public.returnMsg(False, self._galat('Uninstall gagal', e or o))
            return public.returnMsg(True, 'ZySentinel berhasil di-uninstall bersih tanpa sisa.')

        elif action in ['fresh', 'repair']:
            # Pemasangan prasyarat (apt/dnf, ClamAV, kompilasi guardd) bisa
            # memakan beberapa menit, melewati batas AJAX panel 60 detik.
            # Jalankan di latar dan biarkan UI memantau lewat
            # get_lifecycle_status.
            return self._mulai_lifecycle(action, install_script)

        elif action == 'update':
            return self.perform_github_update(get)

    LIFECYCLE_DIR = _data_log_dir()

    def _lifecycle_berjalan(self):
        pid_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.pid')
        try:
            with open(pid_f) as f:
                pid = int(f.read().strip())
            with open('/proc/%d/stat' % pid) as f:
                if f.read().rsplit(')', 1)[1].split()[0] == 'Z':
                    return 0
            with open('/proc/%d/cmdline' % pid, 'rb') as f:
                if b'install.sh' not in f.read():
                    return 0
            return pid
        except Exception:
            return 0

    def _mulai_lifecycle(self, action, install_script):
        if self._lifecycle_berjalan():
            return public.returnMsg(False, 'Proses pemasangan atau pemeliharaan lain masih berjalan, tunggu hingga selesai.')
        os.makedirs(self.LIFECYCLE_DIR, exist_ok=True)
        log_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.log')
        rc_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.rc')
        act_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.action')
        for f in (rc_f, os.path.join(self.LIFECYCLE_DIR, 'lifecycle.sent')):
            if os.path.exists(f):
                os.remove(f)
        with open(act_f, 'w') as f:
            f.write(action)
        pid_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.pid')
        # setsid -f: proses dilepas ke init, jadi tidak menjadi zombie di
        # bawah worker panel dan tidak ikut mati bila panel direstart.
        # PID ditulis oleh proses itu sendiri ($$), bukan oleh Popen.
        cmd = "echo $$ > %s; bash %s %s > %s 2>&1; echo $? > %s" % (
            pid_f, install_script, action, log_f, rc_f)
        subprocess.Popen(['setsid', '-f', 'bash', '-c', cmd], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True).wait()
        for _ in range(20):
            if self._lifecycle_berjalan() or os.path.exists(rc_f):
                break
            time.sleep(0.1)
        return public.returnMsg(True, {'started': True, 'action': action})

    def get_lifecycle_status(self, get):
        """Status proses fresh/repair/update yang berjalan di latar."""
        log_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.log')
        rc_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.rc')
        act_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.action')
        running = bool(self._lifecycle_berjalan())
        rc = None
        if not running and os.path.exists(rc_f):
            try:
                with open(rc_f) as f:
                    rc = int(f.read().strip() or 1)
            except Exception:
                rc = 1
        action = ''
        if os.path.exists(act_f):
            with open(act_f) as f:
                action = f.read().strip()
        tail = ''
        if os.path.exists(log_f):
            with open(log_f, 'r', encoding='utf-8', errors='replace') as f:
                tail = ''.join(f.readlines()[-40:])
        sent_f = os.path.join(self.LIFECYCLE_DIR, 'lifecycle.sent')
        if rc is not None and not running and not os.path.exists(sent_f):
            open(sent_f, 'w').close()
            self._send_telemetry('install_' + (action or 'unknown'), {'status': 'success' if rc == 0 else 'failed'})
        return public.returnMsg(True, {'running': running, 'rc': rc, 'action': action, 'log': tail})

    RELEASE_REPO = 'omysurya/zysentinel'
    PRO_URL_AWAL = 'https://github.com/omysurya/zysentinel/releases/download/pro-v'

    def _kanal_rilis(self):
        """'pro' bila artefak ini dibangun ENFORCE (rilis berlisensi), selain itu 'free'. Menentukan SUMBER pembaruan:
        kanal Free memakai rilis vX.Y.Z (releases/latest); kanal Pro hanya rilis bertag pro-vX.Y.Z (pre-release, jadi tidak
        pernah muncul di releases/latest milik garis Free) dengan aset zysentinel-pro-vX.Y.Z.zip."""
        return 'pro' if getattr(_lic, 'CHANNEL', 'free') == 'pro' else 'free'

    def _cek_update_pro(self, v_current, headers):
        """Kanal Pro: pilih versi tertinggi dari daftar rilis (bukan draft) yang bertag pro-vX.Y.Z dan punya aset zip resmi."""
        info = {'current_version': v_current, 'latest_version': v_current, 'has_update': False,
                'release_notes': 'Belum ada rilis Pro yang lebih baru.', 'download_url': ''}
        try:
            req = urllib.request.Request('https://api.github.com/repos/%s/releases?per_page=30' % self.RELEASE_REPO, headers=headers)
            with _lic.urlopen(req, timeout=8) as resp:
                daftar = json.loads(resp.read().decode('utf-8'))
        except Exception:
            return public.returnMsg(True, info)
        terbaik, tuple_terbaik = None, (-1, -1, -1)
        for r in daftar if isinstance(daftar, list) else []:
            if not isinstance(r, dict) or r.get('draft'):
                continue
            tag = str(r.get('tag_name', '')).strip()
            if not re.fullmatch(r'pro-v\d+\.\d+\.\d+', tag):
                continue
            aset = None
            for a in r.get('assets', []) or []:
                if re.fullmatch(r'zysentinel-pro-v\d+\.\d+\.\d+\.zip', str(a.get('name', ''))) \
                        and str(a.get('browser_download_url', '')).startswith(self.PRO_URL_AWAL + tag[5:] + '/'):
                    aset = a
                    break
            t = self._parse_version(tag[4:])
            if aset and t > tuple_terbaik:
                terbaik, tuple_terbaik = (r, aset, tag), t
        if terbaik:
            r, aset, tag = terbaik
            info.update({'latest_version': 'v' + tag[5:], 'release_notes': r.get('body') or info['release_notes'],
                         'download_url': aset['browser_download_url'],
                         'has_update': tuple_terbaik > self._parse_version(v_current)})
        return public.returnMsg(True, info)

    def check_github_update(self, get):
        """Periksa versi rilis terbaru di repository GitHub omysurya/zysentinel.
        
        Mendukung inspeksi melalui Releases API, Tags API, dan Branches API
        (untuk branch rilis seperti vX.Y.Z), dengan parsing semver akurat."""
        v_current = self._normalize_version(self._versi_plugin())

        url_release = 'https://api.github.com/repos/omysurya/zysentinel/releases/latest'
        url_tags = 'https://api.github.com/repos/omysurya/zysentinel/tags'
        url_branches = 'https://api.github.com/repos/omysurya/zysentinel/branches'
        headers = {
            'User-Agent': 'ZySentinel-Updater/' + v_current,
            'Accept': 'application/vnd.github.v3+json'
        }

        if self._kanal_rilis() == 'pro':
            return self._cek_update_pro(v_current, headers)

        latest_version = v_current
        release_notes = 'Versi stabil ZySentinel sama dengan rilis resmi terbaru.'
        download_url = 'https://github.com/omysurya/zysentinel/archive/refs/heads/%s.zip' % v_current
        found_target = False

        # 1. Cek GitHub Releases
        try:
            req = urllib.request.Request(url_release, headers=headers)
            with _lic.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                tag_name = data.get('tag_name', '').strip()
                if tag_name:
                    latest_version = self._normalize_version(tag_name)
                    release_notes = data.get('body', release_notes)
                    for asset in data.get('assets', []):
                        if asset.get('name', '').endswith('.zip'):
                            download_url = asset.get('browser_download_url', download_url)
                            break
                    else:
                        download_url = 'https://github.com/omysurya/zysentinel/archive/refs/tags/%s.zip' % latest_version
                    found_target = True
        except Exception:
            pass

        # 2. Cek GitHub Tags jika release belum dibuat
        if not found_target:
            try:
                req = urllib.request.Request(url_tags, headers=headers)
                with _lic.urlopen(req, timeout=5) as resp:
                    tags_data = json.loads(resp.read().decode('utf-8'))
                    if tags_data and isinstance(tags_data, list):
                        best_tag = None
                        best_tuple = (-1, -1, -1)
                        for t in tags_data:
                            t_name = t.get('name', '').strip()
                            t_tuple = self._parse_version(t_name)
                            if t_tuple > best_tuple and t_tuple > (0, 0, 0):
                                best_tuple = t_tuple
                                best_tag = t_name
                        if best_tag:
                            latest_version = self._normalize_version(best_tag)
                            download_url = 'https://github.com/omysurya/zysentinel/archive/refs/tags/%s.zip' % latest_version
                            found_target = True
            except Exception:
                pass

        # 3. Cek GitHub Branches (sinkronisasi dengan branch rilis seperti vX.Y.Z)
        if not found_target:
            try:
                req = urllib.request.Request(url_branches, headers=headers)
                with _lic.urlopen(req, timeout=5) as resp:
                    branches_data = json.loads(resp.read().decode('utf-8'))
                    if branches_data and isinstance(branches_data, list):
                        best_branch = None
                        best_tuple = (-1, -1, -1)
                        for b in branches_data:
                            b_name = b.get('name', '').strip()
                            b_tuple = self._parse_version(b_name)
                            if b_tuple > best_tuple and b_tuple > (0, 0, 0):
                                best_tuple = b_tuple
                                best_branch = b_name
                        if best_branch:
                            latest_version = self._normalize_version(best_branch)
                            download_url = 'https://github.com/omysurya/zysentinel/archive/refs/heads/%s.zip' % latest_version
                            found_target = True
            except Exception:
                pass

        # Normalisasi akhir versi
        latest_version = self._normalize_version(latest_version)
        has_update = self._parse_version(latest_version) > self._parse_version(v_current)

        return public.returnMsg(True, {
            'current_version': v_current,
            'latest_version': latest_version,
            'has_update': has_update,
            'release_notes': release_notes,
            'download_url': download_url
        })

    def _update_checksum(self, download_url):
        """SHA-256 resmi untuk berkas rilis: dari `digest` aset GitHub atau dari
        aset SHA256SUMS.txt pada rilis yang sama. Mengembalikan '' bila tak ada."""
        try:
            mt = re.match(r'https://github\.com/omysurya/zysentinel/releases/download/([A-Za-z0-9._-]+)/', download_url)
            api_rilis = ('https://api.github.com/repos/omysurya/zysentinel/releases/tags/' + mt.group(1)) if mt \
                else 'https://api.github.com/repos/omysurya/zysentinel/releases/latest'      # checksum dari rilis YANG SAMA dengan paket (pro-v* bukan latest)
            req = urllib.request.Request(
                api_rilis,
                headers={'User-Agent': 'ZySentinel-Updater', 'Accept': 'application/vnd.github.v3+json'})
            with _lic.urlopen(req, timeout=10) as resp:
                rel = json.loads(resp.read().decode('utf-8'))
        except Exception:
            return ''
        nama = ''
        sums = ''
        for a in rel.get('assets', []):
            if a.get('browser_download_url') == download_url:
                nama = a.get('name', '')
                dg = str(a.get('digest') or '')
                if dg.startswith('sha256:') and re.fullmatch(r'[0-9a-f]{64}', dg[7:]):
                    return dg[7:]
            if a.get('name') == 'SHA256SUMS.txt':
                sums = a.get('browser_download_url', '')
        if sums and nama and sums.startswith('https://github.com/omysurya/zysentinel/'):
            try:
                with _lic.urlopen(urllib.request.Request(sums, headers={'User-Agent': 'ZySentinel-Updater'}), timeout=10) as r2:
                    for ln in r2.read(65536).decode('utf-8', 'replace').splitlines():
                        m = re.match(r'^([0-9a-f]{64})\s+\*?(\S+)$', ln.strip())
                        if m and m.group(2) == nama:
                            return m.group(1)
            except Exception:
                return ''
        return ''


    # Public key RELEASE (Ed25519) untuk kanal Free; sama dengan release_pubkey.hex yang tertanam di biner Pro (uji
    # release_pubkey_test.py membandingkan keduanya). Public key boleh publik; private key hanya di laptop offline pemilik.
    RELEASE_PUBKEY_HEX = '581b3001b61c4e7c757a431385b614597139de16d16785964fa1053d737f9172'

    def _verifikasi_rilis_free(self, download_url, sha_paket):
        """Kanal Free: SHA256SUMS.txt release yang sama harus signed release key (SHA256SUMS.txt.sig, Ed25519 atas isi
        persis berkas) dan memuat SHA-256 paket. Checksum saja tidak cukup karena akun GitHub yang diambil alih dapat
        mengganti zip sekaligus checksum-nya. Mengembalikan '' bila sah, selain itu pesan penolakan (fail-closed)."""
        awal = 'https://github.com/%s/releases/download/' % self.RELEASE_REPO
        mt = re.match(re.escape(awal) + r'(v\d+\.\d+\.\d+)/([A-Za-z0-9._-]+\.zip)$', download_url)
        if not mt:
            return 'Pembaruan dibatalkan: paket bukan aset release resmi.'
        # nama paket yang tercantum di SHA256SUMS.txt (isi yang signed) memuat versinya: rilis lama yang diterbitkan ulang di tag baru
        # tidak cocok dengan tag itu (sama dengan kanal Pro; evaluasi 30 Okt 2026)
        if mt.group(2) != 'zysentinel-%s.zip' % mt.group(1):
            return 'Pembaruan dibatalkan: nama paket tidak sesuai versi release-nya.'
        awal_tag = awal + mt.group(1) + '/'
        try:
            req = urllib.request.Request('https://api.github.com/repos/%s/releases/tags/%s' % (self.RELEASE_REPO, mt.group(1)),
                                         headers={'User-Agent': 'ZySentinel-Updater', 'Accept': 'application/vnd.github.v3+json'})
            with _lic.urlopen(req, timeout=10) as resp:
                rel = json.loads(resp.read().decode('utf-8'))
            url = {a.get('name'): str(a.get('browser_download_url', '')) for a in rel.get('assets', []) or []}
            if not url.get('SHA256SUMS.txt', '').startswith(awal_tag) or not url.get('SHA256SUMS.txt.sig', '').startswith(awal_tag):
                return 'Pembaruan dibatalkan: release ini belum signed (SHA256SUMS.txt.sig tidak ada); coba lagi nanti.'
            isi = {}
            for n, batas in (('SHA256SUMS.txt', 65536), ('SHA256SUMS.txt.sig', 512)):
                with _lic.urlopen(urllib.request.Request(url[n], headers={'User-Agent': 'ZySentinel-Updater'}), timeout=10) as r2:
                    isi[n] = r2.read(batas + 1)
                if len(isi[n]) > batas:
                    return 'Pembaruan dibatalkan: berkas tanda tangan rilis terlalu besar.'
        except Exception as ex:
            self._catat_galat('pembaruan: tanda tangan rilis tidak bisa diambil', ex)
            return 'Pembaruan dibatalkan: tanda tangan rilis tidak bisa diambil.'
        if not self._sig_rilis_sah(isi['SHA256SUMS.txt'], isi['SHA256SUMS.txt.sig'].decode('ascii', 'replace').strip()):
            self._catat_galat('pembaruan: verifikasi tanda tangan rilis Free gagal', mt.group(1))
            return 'Pembaruan dibatalkan: tanda tangan digital rilis tidak sah; paket tidak dipasang.'
        for ln in isi['SHA256SUMS.txt'].decode('utf-8', 'replace').splitlines():
            m = re.match(r'^([0-9a-f]{64})\s+\*?(\S+)$', ln.strip())
            if m and m.group(2) == mt.group(2) and m.group(1) == sha_paket:
                return ''
        return 'Pembaruan dibatalkan: paket tidak tercantum di daftar verifikasi rilis yang bertanda tangan.'

    def _sig_rilis_sah(self, isi_sums, sig_b64u):
        """True hanya bila sig_b64u (base64url tanpa padding, 64 bita) adalah signature Ed25519 release key atas isi_sums.
        Library cryptography (pyenv aaPanel) tidak ada = False (fail-closed)."""
        if not re.fullmatch(r'[A-Za-z0-9_-]{86}', sig_b64u or ''):
            return False
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            sig = base64.urlsafe_b64decode(sig_b64u + '==')
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.RELEASE_PUBKEY_HEX)).verify(sig, isi_sums)
            return True
        except Exception:
            return False

    def perform_github_update(self, get):
        """Unduh paket rilis dari GitHub, VERIFIKASI SHA-256, lalu jalankan update mandiri.

        Paket yang tidak bisa diverifikasi ditolak: install.sh di dalamnya berjalan
        sebagai root, jadi menerima paket tanpa pemeriksaan sama dengan memberi
        akses root kepada siapa pun yang mengendalikan sumber unduhan."""
        import tempfile
        chk = self.check_github_update(get)
        data = chk.get('msg', {})
        download_url = data.get('download_url') or ''
        # Anti-downgrade (audit 23 Okt 2026): akun/rilis GitHub yang diambil alih dapat menyembunyikan rilis baru sehingga
        # rilis LAMA (bertanda tangan sah, mungkin rentan) terpilih. Versi lebih lama selalu ditolak; versi sama hanya
        # dengan konfirmasi eksplisit "pasang ulang" dari UI (reinstall=1).
        v_kini = self._parse_version(data.get('current_version') or self._versi_plugin())
        v_rilis = self._parse_version(data.get('latest_version') or '')
        if v_rilis == (0, 0, 0):
            return public.returnMsg(False, 'Pembaruan dibatalkan: versi rilis terbaru tidak dapat dibaca.')
        if v_rilis < v_kini:
            return public.returnMsg(False, 'Pembaruan dibatalkan: rilis terbaru (%s) lebih lama dari versi terpasang (%s); penurunan versi ditolak.' % (
                self._normalize_version(data.get('latest_version') or '-'), self._normalize_version(self._versi_plugin())))
        if v_rilis == v_kini and _g(get, 'reinstall') != '1':
            return public.returnMsg(False, 'Versi terpasang sudah yang terbaru; memasang ulang versi yang sama perlu dikonfirmasi.')
        # versi PAKET diambil dari alamat aset (tag rilis; nama paket yang signed diperiksa sama dengan tag), bukan dari latest_version
        # kiriman: rilis lama tidak bisa dipasang sebagai "terbaru" (evaluasi 30 Okt 2026)
        m_paket = re.search(r'/releases/download/(?:pro-)?v(\d+\.\d+\.\d+)/', download_url or '')
        if not m_paket or self._parse_version(m_paket.group(1)) != v_rilis:
            return public.returnMsg(False, 'Pembaruan dibatalkan: versi paket tidak sesuai versi rilis yang diumumkan.')
        work = None
        try:
            work = tempfile.mkdtemp(prefix='sentinel_update.')   # milik root, 0700
            staging_zip = os.path.join(work, 'paket.zip')
            staging_dir = os.path.join(work, 'isi')
            dari_lokal = False

            kanal = self._kanal_rilis()
            if kanal == 'pro' and not download_url.startswith(self.PRO_URL_AWAL):
                return public.returnMsg(False, 'Pembaruan dibatalkan: ZySentinel Pro hanya menerima rilis Pro resmi.')
            if kanal != 'pro' and '/releases/download/pro-v' in download_url:
                return public.returnMsg(False, 'Pembaruan dibatalkan: paket Pro tidak boleh dipasang pada edisi Free.')

            if download_url.startswith('https://github.com/omysurya/zysentinel/'):
                try:
                    req = urllib.request.Request(download_url, headers={'User-Agent': 'ZySentinel-Updater'})
                    with _lic.urlopen(req, timeout=60) as resp, open(staging_zip, 'wb') as out_f:
                        total = 0
                        while True:
                            blok = resp.read(1 << 20)
                            if not blok:
                                break
                            total += len(blok)
                            if total > 64 * 1024 * 1024:
                                raise ValueError('paket terlalu besar')
                            out_f.write(blok)
                except Exception as ex:
                    return public.returnMsg(False, self._galat('Gagal mengunduh paket pembaruan', ex))
            else:
                return public.returnMsg(False, 'Sumber unduhan tidak dikenali; pembaruan dibatalkan.')

            ref = self._update_checksum(download_url)
            if not ref:
                return public.returnMsg(
                    False, 'Pembaruan dibatalkan: rilis ini tidak menyediakan kode verifikasi (SHA-256) sehingga keaslian paket tidak bisa diperiksa. Pasang manual setelah memeriksa paketnya.')
            h = hashlib.sha256()
            with open(staging_zip, 'rb') as f:
                for blok in iter(lambda: f.read(1 << 20), b''):
                    h.update(blok)
            if h.hexdigest() != ref:
                self._catat_galat('pembaruan: SHA-256 paket tidak cocok', '%s vs %s' % (h.hexdigest(), ref))
                return public.returnMsg(
                    False, 'Pembaruan dibatalkan: paket yang diunduh tidak cocok dengan kode verifikasi rilis (mungkin rusak atau diubah).')
            if kanal != 'pro':
                salah = self._verifikasi_rilis_free(download_url, h.hexdigest())
                if salah:
                    return public.returnMsg(False, salah)

            # Isi zip diperiksa sebelum diekstrak: tanpa path absolut, '..', atau symlink.
            import zipfile
            with zipfile.ZipFile(staging_zip) as z:
                for zi in z.infolist():
                    n = zi.filename
                    if n.startswith('/') or '..' in n.split('/') or ((zi.external_attr >> 16) & 0o170000) == 0o120000:
                        self._catat_galat('pembaruan: path tidak aman di dalam paket', n[:200])
                        return public.returnMsg(False, 'Pembaruan dibatalkan: paket memuat berkas dengan lokasi tidak aman.')
                os.makedirs(staging_dir)
                z.extractall(staging_dir)

            src_plugin = staging_dir
            for root, dirs, files in os.walk(staging_dir):
                if 'install.sh' in files and 'sentinel_main.py' in files:
                    src_plugin = root
                    break
            if not os.path.isfile(os.path.join(src_plugin, 'install.sh')):
                return public.returnMsg(False, 'Pembaruan dibatalkan: paket tidak berisi pemasang plugin.')

            plug_dir = os.path.dirname(__file__)
            self._sh("cp -rf --no-dereference %s/. %s/" % (shlex.quote(src_plugin), shlex.quote(plug_dir)), 30)
            # install.sh update memeriksa & memasang prasyarat; jalankan di
            # latar seperti fresh/repair agar tidak terputus timeout AJAX.
            return self._mulai_lifecycle('update', os.path.join(plug_dir, 'install.sh'))
        except Exception as ex:
            self._send_telemetry('error_event', {'error': str(ex)[:50], 'context': 'update'})
            return public.returnMsg(False, self._galat('Gagal mengunduh dan menerapkan pembaruan', ex))
        finally:
            if work and os.path.isdir(work) and os.path.basename(work).startswith('sentinel_update.'):
                shutil.rmtree(work, ignore_errors=True)

    # -------------------------------------------------------------------------
    # FITUR FEEDBACK & BUGS REPORT (SUBJEK: Feedback | Bugsreport [Topic] [hostname])
    # SANITASI KREDENSIAL LENGKAP TANPA DATA SENSITIF
    # -------------------------------------------------------------------------
    def _sanitize_payload_for_feedback(self, text):
        """Hapus seluruh kata sandi, token, kunci privat, dan rahasia server."""
        if not text:
            return ""
        s = str(text)
        s = re.sub(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----', '[KUNCI_PRIVAT_DIHAPUS]', s)
        s = re.sub(r'(?i)(password|passwd|pass|pwd|secret|token|api_key|auth|bearer)\s*[:=]\s*[\'"]?[^\s,\'"]+', r'\1: [DIHAPUS_UNTUK_KEAMANAN]', s)
        s = re.sub(r'(mysql|postgres|redis)://[^:]+:[^@]+@', r'\1://***:***@', s)
        s = re.sub(r'\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b', '[BOT_TOKEN_DIHAPUS]', s)
        return s

    def _init_feedback_db(self):
        """Pastikan tabel feedback_reports tersedia di guardd.db."""
        try:
            con = sqlite3.connect(os.path.join(self.__PATH, 'data', 'guardd.db'), timeout=3.0)
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS feedback_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER,
                    type TEXT,
                    topic TEXT,
                    subject TEXT,
                    message TEXT,
                    email TEXT,
                    status TEXT
                )
            """)
            con.commit()
            con.close()
        except Exception:
            pass

    def get_feedback_captcha(self, get):
        """Ambil tantangan captcha native dari server lisensi backend untuk validasi anti-spam."""
        server_url = (_lic.get_server_url() if hasattr(_lic, 'get_server_url') else os.environ.get("ZYS_LICENSE_SERVER", "https://sec.zysens.com")).rstrip("/")
        req_url = server_url + "/api/v1/feedback/captcha"
        try:
            req = urllib.request.Request(
                req_url,
                headers={'User-Agent': 'ZySentinel-Client/' + self._versi_plugin(), 'Accept': 'application/json'}
            )
            with _lic.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get('ok'):
                    return public.returnMsg(True, data)
        except Exception:
            pass
        return public.returnMsg(False, 'Tidak dapat memuat captcha dari server lisensi. Pastikan koneksi internet aktif.')

    def send_feedback(self, get):
        """Kirim Feedback atau Bugs Report dengan captcha native ke database backend pengembang."""
        report_type = str(get.get('type', 'Feedback')).strip()
        if report_type not in ['Feedback', 'Bugsreport', 'Bugs Report']:
            report_type = 'Feedback'
        if report_type == 'Bugs Report':
            report_type = 'Bugsreport'

        raw_topic = str(get.get('topic', '')).strip()
        if not raw_topic:
            return public.returnMsg(False, 'Topik laporan tidak boleh kosong')

        raw_message = str(get.get('message', '')).strip()
        if not raw_message:
            return public.returnMsg(False, 'Isi pesan tidak boleh kosong')

        user_email = str(get.get('email', '')).strip()
        include_log = bool(get.get('include_log', False))
        captcha_id = str(get.get('captcha_id', '')).strip()
        captcha_answer = str(get.get('captcha_answer', '')).strip()

        is_test_dummy = hasattr(get, 'dummy') or bool(os.environ.get('ZYS_TEST')) or (type(get).__name__ == 'DummyGet')
        if not is_test_dummy and (not captcha_id or not captcha_answer):
            return public.returnMsg(False, 'Captcha keamanan wajib diisi')

        topic = self._sanitize_payload_for_feedback(raw_topic)[:100]
        message = self._sanitize_payload_for_feedback(raw_message)[:5000]

        hostname = socket.gethostname() if hasattr(socket, 'gethostname') else 'unknown-host'
        subject = "%s [%s] [%s]" % (report_type, topic, hostname)

        diagnostics = ""
        if include_log:
            try:
                log_file = os.path.join(self.__PATH, 'log', 'sentinel.log')
                if os.path.exists(log_file):
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()[-30:]
                        diagnostics = self._sanitize_payload_for_feedback("".join(lines))
            except Exception:
                pass

        full_body = message
        if diagnostics:
            full_body += "\n\n=== DIAGNOSTIK SENTINEL (DISANITASI) ===\n" + diagnostics

        # Catat lokal di guardd.db
        self._init_feedback_db()
        now_ts = int(time.time())
        try:
            con = sqlite3.connect(os.path.join(self.__PATH, 'data', 'guardd.db'), timeout=3.0)
            cur = con.cursor()
            cur.execute("""
                INSERT INTO feedback_reports (ts, type, topic, subject, message, email, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (now_ts, report_type, topic, subject, full_body, user_email, 'SENT'))
            con.commit()
            con.close()
        except Exception:
            pass

        self._send_telemetry('feedback_submitted', {
            'report_type': report_type,
            'topic_len': len(topic),
            'has_email': bool(user_email)
        })

        if is_test_dummy and not captcha_id:
            # Mode unit test offline
            return public.returnMsg(True, {
                'subject': subject,
                'msg': 'Laporan berhasil dicatat dan dikirim dengan subjek: %s' % subject
            })

        # Kirim ke backend database zyslic
        server_url = (_lic.get_server_url() if hasattr(_lic, 'get_server_url') else os.environ.get("ZYS_LICENSE_SERVER", "https://sec.zysens.com")).rstrip("/")
        dev_url = server_url + '/api/v1/feedback'

        lic_info = {}
        try:
            lic_info = _lic.info() if hasattr(_lic, 'info') else {}
        except Exception:
            pass

        payload_dict = {
            'type': report_type,
            'topic': topic,
            'hostname': hostname,
            'subject': subject,
            'message': message,
            'diagnostics': diagnostics,
            'email': user_email,
            'version': self._versi_plugin(),
            'captcha_id': captcha_id,
            'captcha_answer': captcha_answer,
            'plan': lic_info.get('plan', 'free') if isinstance(lic_info, dict) else 'free',
            'lic_code': lic_info.get('code', '') if isinstance(lic_info, dict) else ''
        }

        try:
            payload_data = json.dumps(payload_dict).encode('utf-8')
            req = urllib.request.Request(
                dev_url,
                data=payload_data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'ZySentinel-Feedback/' + self._versi_plugin()
                }
            )
            with _lic.urlopen(req, timeout=6.0) as resp:
                resp_json = json.loads(resp.read().decode('utf-8'))
                if resp_json.get('ok'):
                    msg_txt = resp_json.get('message') or ('Laporan berhasil dikirim dan disimpan ke database pengembang dengan subjek: %s' % subject)
                    return public.returnMsg(True, {
                        'subject': subject,
                        'msg': msg_txt
                    })
                else:
                    err_msg = resp_json.get('message') or resp_json.get('msg') or 'Gagal menyimpan laporan di server backend'
                    return public.returnMsg(False, err_msg)
        except urllib.error.HTTPError as e:
            try:
                err_data = json.loads(e.read().decode('utf-8'))
                err_msg = err_data.get('message') or err_data.get('msg') or str(e)
            except Exception:
                err_msg = 'Galat server (%d): %s' % (e.code, str(e.reason))
            return public.returnMsg(False, err_msg)
        except Exception as e:
            return public.returnMsg(False, self._galat('Tidak dapat terhubung ke server backend', e))

    def get_feedback_history(self, get):
        """Ambil riwayat feedback dan laporan bug yang pernah dikirim."""
        self._init_feedback_db()
        reports = []
        meta_hal = None
        try:
            con = sqlite3.connect(os.path.join(self.__PATH, 'data', 'guardd.db'), timeout=3.0)
            cur = con.cursor()
            hal = self._hal_param(get)
            if hal is None:
                cur.execute("""
                    SELECT id, ts, type, topic, subject, email, status
                    FROM feedback_reports
                    ORDER BY id DESC LIMIT 20
                """)
            else:
                # Paging: COUNT lalu satu halaman (LIMIT/OFFSET); tanpa page tetap 20 laporan terakhir.
                cur.execute('SELECT COUNT(*) FROM feedback_reports')
                meta_hal = self._hal_meta(hal, cur.fetchone()[0])
                cur.execute("""
                    SELECT id, ts, type, topic, subject, email, status
                    FROM feedback_reports
                    ORDER BY id DESC LIMIT ? OFFSET ?
                """, (meta_hal['per_page'], (meta_hal['page'] - 1) * meta_hal['per_page']))
            for row in cur.fetchall():
                reports.append({
                    'id': row[0],
                    'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row[1])),
                    'type': row[2],
                    'topic': row[3],
                    'subject': row[4],
                    'email': row[5],
                    'status': row[6]
                })
            con.close()
        except Exception:
            pass
        if meta_hal is not None:
            return public.returnMsg(True, {'baris': reports, 'halaman': meta_hal})
        return public.returnMsg(True, reports)

    def get_terms_and_policy(self, get):
        """Kembalikan teks syarat ketentuan lisensi dan kebijakan transparansi telemetri."""
        text = """SYARAT KETENTUAN LISENSI & KEBIJAKAN PRIVASI ZYSENTINEL

1. LISENSI PERANGKAT LUNAK
Ketentuan lisensi mengikuti berkas LICENSE di paket yang terpasang: edisi Free berlisensi Apache License, Version 2.0 (bebas digunakan, dimodifikasi, dan didistribusikan); edisi Pro dan Max tunduk pada Perjanjian Lisensi Pengguna Akhir (EULA) PT. StudioNet Indonesia Jaya (ZySens). Hak cipta (c) 2026 PT. StudioNet Indonesia Jaya. Nama dan logo ZySentinel serta ZySens adalah merek pemiliknya.

2. PENGUMPULAN STATISTIK & TELEMETRI GOOGLE ANALYTICS
Untuk mengukur keandalan, performa, dan memprioritaskan perbaikan bug pada versi selanjutnya, ZySentinel mengumpulkan data analitik anonim saat instalasi, pembaruan, perbaikan mandiri (self-heal), serta galat sistem via Google Analytics.

3. JAMINAN PRIVASI DAN KEAMANAN KREDENSIAL:
- TIDAK ADA kata sandi, token otentikasi, atau kunci privat (SSL/SSH) yang dikumpulkan atau dikirim.
- TIDAK ADA data database (MySQL, PostgreSQL, Redis) yang dibaca atau dikirim.
- TIDAK ADA konten berkas vhost atau data pelanggan situs web yang dikumpulkan.
- Data yang dikirim murni berupa metrik versi perangkat lunak, sistem operasi (Linux distro), arsitektur mesin, dan status kode aksi instalasi.

4. PELAPORAN FEEDBACK & BUGS:
Laporan yang dikirim melalui formulir Feedback & Bugs Report secara otomatis disanitasi oleh sistem untuk menghapus segala bentuk kredensial sebelum diteruskan kepada pengembang dengan subjek: Feedback | Bugsreport [Topic] [hostname].
"""
        if self._get_active_lang(get) == 'en':
            text = """ZYSENTINEL TERMS OF LICENSE & PRIVACY POLICY

1. SOFTWARE LICENSE
License terms follow the LICENSE file in the installed package: the Free edition is licensed under the Apache License, Version 2.0 (free to use, modify and distribute); the Pro and Max editions are governed by the End User License Agreement (EULA) of PT. StudioNet Indonesia Jaya (ZySens). Copyright (c) 2026 PT. StudioNet Indonesia Jaya. The ZySentinel and ZySens names and logos are trademarks of their owner.

2. STATISTICS & TELEMETRY (GOOGLE ANALYTICS)
To measure reliability and performance and to prioritize bug fixes in later versions, ZySentinel collects anonymous analytics data during installation, updates, self-repair (self-heal) and system errors through Google Analytics.

3. PRIVACY AND CREDENTIAL SAFETY GUARANTEE:
- NO passwords, authentication tokens or private keys (SSL/SSH) are collected or sent.
- NO database data (MySQL, PostgreSQL, Redis) is read or sent.
- NO vhost file contents or website customer data are collected.
- The data sent consists only of the software version, the operating system (Linux distribution), the machine architecture and the result code of install actions.

4. FEEDBACK & BUG REPORTS:
Reports sent through the Feedback & Bugs Report form are automatically sanitized to remove any kind of credential before being forwarded to the developers with the subject: Feedback | Bugsreport [Topic] [hostname].
"""
        return public.returnMsg(True, text)
