#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
# ==================================================================
# sentinel-harden.py -- audit hardening per situs (nginx/Apache) dan perbaikan TLS yang aman.
#
# Audit 13 Nov 2026 menemukan celah yang tidak terlihat dari panel: TLSv1.1 tertulis di vhost, header keamanan terkirim GANDA
# (vhost + include + aplikasi), dan open_basedir hanya di sebagian situs. Skrip ini memeriksa keadaan NYATA, bukan hanya teks:
#   - protokol TLS: yang tertulis di konfigurasi (vhost, lalu tingkat http) DAN yang benar-benar diterima (handshake lokal TLS 1.0/1.1)
#   - header respons (permintaan lokal ke 127.0.0.1 dengan SNI/Host situs): ganda, hilang, versi server terbuka
#   - open_basedir untuk situs PHP (aaPanel .user.ini / PHP_ADMIN_VALUE / pool php-fpm)
# Hanya membaca, kecuali fix-tls.
#
#   audit [situs]   JSON: {"situs": [...], "ringkas": {...}}
#   fix-tls <situs> buang TLSv1/TLSv1.1 (dan SSLv2/SSLv3) dari vhost situs; cadangan NAMA.bak.<ts>, uji -t, reload terverifikasi
#                   (sentinel-waf.sh reload), gagal di langkah mana pun = berkas dikembalikan
# ==================================================================
import glob
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor

warnings.filterwarnings('ignore', category=DeprecationWarning)      # ssl.TLSVersion.TLSv1* sengaja dipakai untuk menguji server

BASE = os.environ.get('SENTINEL_BASE', '/www/server/sentinel')
HERE = os.path.dirname(os.path.abspath(__file__))
VHOST_NGINX = os.environ.get('ZYS_HARDEN_VHOST_NGINX', '/www/server/panel/vhost/nginx')
VHOST_APACHE = os.environ.get('ZYS_HARDEN_VHOST_APACHE', '/www/server/panel/vhost/apache')
AA_BIN_NGINX = os.environ.get('ZYS_HARDEN_BIN_NGINX', '/www/server/nginx/sbin/nginx')
AA_BIN_APACHE = os.environ.get('ZYS_HARDEN_BIN_APACHE', '/www/server/apache/bin/httpd')
# vhost bawaan aaPanel yang bukan situs pelanggan (status php-fpm, monitor WAF aaPanel, snippet WAF)
VHOST_INTERNAL = ('phpfpm_status', 'free_waf', 'sentinel_waf', 'waf2monitor_data')
# OpenLiteSpeed/LiteSpeed (CyberPanel): diaudit baca-saja (TLS diterima, header, versi, open_basedir); fix-tls hanya nginx/Apache
OLS_ROOT = os.environ.get('ZYS_HARDEN_OLS_ROOT', '/usr/local/lsws')
WS_OLS = ('openlitespeed', 'litespeed')
# cPanel: protokol TLS Apache diatur GLOBAL oleh EasyApache 4 (ea4.conf -> rebuildhttpdconf); httpd.conf yang dibangkitkan panel tidak
# boleh disunting langsung (ditimpa pada rebuild berikutnya). fix-tls di cPanel = cara WHM "Global Configuration".
CP_EA4_CONF = os.environ.get('ZYS_HARDEN_CP_EA4', '/etc/cpanel/ea4/ea4.conf')
CP_REBUILD = os.environ.get('ZYS_HARDEN_CP_REBUILD', '/scripts/rebuildhttpdconf')
CP_PROTO_AMAN = 'all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1'
# DirectAdmin: protokol TLS Apache diatur CustomBuild (options.conf ssl_configuration = modern|intermediate|old -> ./build rewrite_confs
# menulis ulang /etc/httpd/conf/extra/httpd-ssl.conf). "old" mengizinkan TLS 1.0/1.1; "intermediate" = TLS 1.2+ (bawaan DA).
DA_CB = os.environ.get('ZYS_HARDEN_DA_CB', '/usr/local/directadmin/custombuild')
HOST_UJI = os.environ.get('ZYS_HARDEN_HOST', '127.0.0.1')          # tujuan permintaan lokal (uji: server tiruan)
PORT_HTTPS = int(os.environ.get('ZYS_HARDEN_PORT_HTTPS', '443'))
PORT_HTTP = int(os.environ.get('ZYS_HARDEN_PORT_HTTP', '80'))
WAF_SH = os.environ.get('ZYS_HARDEN_WAF', os.path.join(HERE, 'sentinel-waf.sh'))
NAMA_SITUS = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$')
LAMA = ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1')
# fix-tls hanya mengubah vhost di folder konfigurasi web server (aaPanel, distro Debian/RHEL)
DIR_KONF = tuple(os.environ.get('ZYS_HARDEN_DIR_KONF', '/www/server/panel/vhost/ /etc/nginx/ /etc/apache2/ /etc/httpd/ /usr/local/nginx/conf/').split())
# Header keamanan yang hanya boleh muncul sekali (dua nilai berbeda = browser memakai yang paling ketat atau mengabaikan keduanya).
HEADER = ('Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy',
          'Content-Security-Policy', 'Permissions-Policy')


def _baca(p, batas=2000000):
    try:
        with open(p, 'r', errors='replace') as f:
            return f.read(batas)
    except OSError:
        return ''


def _tanpa_komentar(t):
    return re.sub(r'(?m)(^|[^\\$])#[^\n]*', r'\1', t)


def _env_sh():
    d = {}
    for ln in _baca(os.path.join(BASE, 'etc', 'env.sh')).splitlines():
        m = re.match(r"^([A-Z_]+)='?(.*?)'?$", ln.strip())
        if m:
            d[m.group(1)] = m.group(2)
    return d


def nginx_conf():
    if os.environ.get('ZYS_HARDEN_NGINX_CONF'):
        return os.environ['ZYS_HARDEN_NGINX_CONF']
    e = _env_sh().get('ZYS_NGINX_CONF')
    for p in (e, '/www/server/nginx/conf/nginx.conf', '/etc/nginx/nginx.conf'):
        if p and os.path.isfile(p):
            return p
    return ''


def _apache_main():
    # /etc/httpd/conf/extra/httpd-ssl.conf: SSLProtocol global DirectAdmin (CustomBuild), di-Include httpd.conf
    for p in ('/www/server/apache/conf/httpd.conf', '/etc/apache2/apache2.conf', '/etc/httpd/conf/httpd.conf',
              os.environ.get('ZYS_HARDEN_DA_SSLCONF', '/etc/httpd/conf/extra/httpd-ssl.conf'),
              '/etc/apache2/mods-enabled/ssl.conf', '/etc/httpd/conf.d/ssl.conf'):
        if os.path.isfile(p):
            yield p


def daftar_situs():
    """[(situs, ws, berkas_vhost)] : aaPanel = folder vhost panel; lainnya = deteksi lingkungan (adapters/env.py)."""
    hasil = []
    if os.path.isdir(VHOST_NGINX) or os.path.isdir(VHOST_APACHE):
        # aaPanel menulis vhost nginx DAN apache untuk setiap situs walau hanya satu web server terpasang (uji aaPanel nyata 14 Nov 2026:
        # setiap situs tercatat dua kali). Hanya web server yang binernya ada yang dinilai; bila tidak terdeteksi, keduanya (perilaku lama).
        aktif = [ws for ws, b in (('nginx', AA_BIN_NGINX), ('apache', AA_BIN_APACHE)) if os.path.exists(b)] or ['nginx', 'apache']
        for ws, d in (('nginx', VHOST_NGINX), ('apache', VHOST_APACHE)):
            if ws not in aktif:
                continue
            for f in sorted(glob.glob(os.path.join(d, '*.conf'))):
                s = os.path.basename(f)[:-5]
                if s.startswith('0.') or '.bak' in s or not NAMA_SITUS.match(s) or s in VHOST_INTERNAL:
                    continue
                hasil.append((s, ws, f))
        return hasil
    try:
        sys.path.insert(0, HERE)
        from adapters import env as e
        for v in e.sites():
            if v.get('webserver') in WS_OLS and v.get('domain') == 'Example':
                continue                                    # vhost contoh bawaan OpenLiteSpeed (CyberPanel), bukan situs pelanggan
            if v.get('webserver') in ('nginx', 'apache') + WS_OLS and NAMA_SITUS.match(v.get('domain') or '') and v.get('config'):
                hasil.append((v['domain'], v['webserver'], v['config']))
    except Exception:
        pass
    return hasil


def _blok_server_nginx(teks, situs):
    """Isi blok server{} yang memuat server_name situs (komentar dibuang)."""
    t = _tanpa_komentar(teks)
    out = []
    for m in re.finditer(r'\bserver\s*\{', t):
        i, k = m.end(), 1
        while i < len(t) and k:
            k += {'{': 1, '}': -1}.get(t[i], 0)
            i += 1
        blk = t[m.end():i - 1]
        nama = ' '.join(re.findall(r'\bserver_name\s+([^;]+);', blk)).split()
        if situs in nama or not nama:
            out.append(blk)
    return out


def tls_nginx(berkas, situs):
    blk = _blok_server_nginx(_baca(berkas), situs)
    ssl_on = any(re.search(r'\blisten\s+[^;]*\bssl\b', b) or re.search(r'\bssl_certificate\s', b) for b in blk)
    for b in blk:
        m = re.search(r'\bssl_protocols\s+([^;]+);', b)
        if m:
            return ssl_on, m.group(1).split(), 'vhost'
    m = re.search(r'\bssl_protocols\s+([^;]+);', _tanpa_komentar(_baca(nginx_conf())))
    if m:
        return ssl_on, m.group(1).split(), 'nginx.conf'
    # bawaan nginx bila tidak ditulis: TLSv1 TLSv1.1 TLSv1.2 (+TLSv1.3 sejak 1.23.4)
    return ssl_on, ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'], 'bawaan'


def _apache_protokol(nilai):
    semua = ['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
    aktif = []
    for tok in nilai.split():
        tanda, nama = (tok[0], tok[1:]) if tok[0] in '+-' else ('', tok)
        daftar = semua if nama.lower() == 'all' else [x for x in semua if x.lower() == nama.lower()]
        if tanda == '-':
            aktif = [x for x in aktif if x not in daftar]
        elif tanda == '+':
            aktif += [x for x in daftar if x not in aktif]
        else:
            aktif = list(daftar) if not aktif else aktif + [x for x in daftar if x not in aktif]
    return aktif


def tls_apache(berkas, situs):
    t = _tanpa_komentar(_baca(berkas))
    ssl_on = bool(re.search(r'(?im)^\s*SSLEngine\s+on', t))
    m = re.search(r'(?im)^\s*SSLProtocol\s+(.+)$', t)
    if m:
        return ssl_on, _apache_protokol(m.group(1)), 'vhost'
    for p in _apache_main():
        m = re.search(r'(?im)^\s*SSLProtocol\s+(.+)$', _tanpa_komentar(_baca(p)))
        if m:
            return ssl_on, _apache_protokol(m.group(1)), os.path.basename(p)
    return ssl_on, ['TLSv1.2', 'TLSv1.3'], 'bawaan'      # mod_ssl modern: bawaan all -SSLv3 (OpenSSL 3 menolak < 1.2)


# sslProtocol OpenLiteSpeed = bitmask
OLS_PROTO = ((1, 'SSLv3'), (2, 'TLSv1'), (4, 'TLSv1.1'), (8, 'TLSv1.2'), (16, 'TLSv1.3'))


def _blok_ols(teks, kata):
    """[(nama, isi)] blok tingkat atas 'kata [nama] { ... }' (blok bersarang ikut di isi)."""
    hasil = []
    for m in re.finditer(r'(?m)^[ \t]*' + kata + r'\b[ \t]*([^{\n]*)\{', teks):
        i, d = m.end(), 1
        while i < len(teks) and d:
            d += {'{': 1, '}': -1}.get(teks[i], 0)
            i += 1
        hasil.append((m.group(1).strip(), teks[m.end():i - 1]))
    return hasil


def _ols_proto(isi):
    m = re.search(r'(?m)^\s*sslProtocol\s+(\d+)', isi)
    return [n for b, n in OLS_PROTO if int(m.group(1)) & b] if m else None


def tls_ols(berkas, situs):
    t = _tanpa_komentar(_baca(berkas))
    vh = [isi for _, isi in _blok_ols(t, 'vhssl') if re.search(r'(?m)^\s*(certFile|keyFile)\s', isi)]
    ssl_on, proto, sumber = bool(vh), (_ols_proto(vh[0]) if vh else None), 'vhost'
    # listener ber-SSL (secure 1) yang memetakan situs ini: SSL juga bisa diatur di tingkat listener httpd_config.conf
    utama = _tanpa_komentar(_baca(os.path.join(OLS_ROOT, 'conf', 'httpd_config.conf')))
    for _, isi in _blok_ols(utama, 'listener'):
        if re.search(r'(?m)^\s*secure\s+1\b', isi) and re.search(r'(?m)^\s*map\s+' + re.escape(situs) + r'\s', isi):
            ssl_on = True
            if proto is None:
                proto, sumber = _ols_proto(isi), 'httpd_config.conf'
    # tidak tertulis: bawaan bergantung versi/OpenSSL, dinilai dari handshake sungguhan saja
    return ssl_on, proto or [], sumber if proto is not None else 'bawaan'


def uji_tls_lama(situs):
    """Handshake lokal dengan TLS 1.0/1.1 saja. True = server MENERIMA, False = menolak, None = klien tidak bisa menawarkan."""
    hasil = {}
    tv = getattr(ssl, 'TLSVersion', None)          # Python >= 3.7
    for nama, ver in (('TLSv1', getattr(tv, 'TLSv1', None)), ('TLSv1.1', getattr(tv, 'TLSv1_1', None))):
        if ver is None:
            hasil[nama] = None
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except (ValueError, ssl.SSLError):
            hasil[nama] = None
            continue
        try:
            with socket.create_connection((HOST_UJI, PORT_HTTPS), timeout=4) as s:
                with ctx.wrap_socket(s, server_hostname=situs):
                    hasil[nama] = True
        except ssl.SSLError as ex:
            # klien sendiri yang menolak (OpenSSL tanpa dukungan protokol lama) bukan bukti server menolak
            hasil[nama] = None if 'NO_PROTOCOLS_AVAILABLE' in str(ex).upper() else False
        except OSError:
            hasil[nama] = None
    return hasil


def ambil_header(situs, https):
    try:
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection(HOST_UJI, PORT_HTTPS, timeout=5, context=ctx)
            # SNI = nama situs (HTTPSConnection memakai host koneksi untuk SNI): bungkus soket sendiri
            sock = socket.create_connection((HOST_UJI, PORT_HTTPS), timeout=5)
            c.sock = ctx.wrap_socket(sock, server_hostname=situs)
        else:
            c = http.client.HTTPConnection(HOST_UJI, PORT_HTTP, timeout=5)
        c.request('GET', '/', headers={'Host': situs, 'User-Agent': 'ZySentinel-Hardening-Audit'})
        r = c.getresponse()
        r.read(65536)
        h = {k: r.msg.get_all(k) or [] for k in HEADER + ('Server', 'X-Powered-By')}
        c.close()
        return r.status, h
    except Exception as ex:
        return None, str(ex)[:120]


def _php_situs(ws, berkas):
    t = _tanpa_komentar(_baca(berkas))
    if ws == 'nginx':
        return bool(re.search(r'\bfastcgi_pass\b|enable-php-\d+\.conf|\bphp-cgi', t))
    if ws in WS_OLS:
        return bool(re.search(r'(?im)^\s*add\s+lsapi:\S+\s+.*\bphp\b|/lsphp', t))
    return bool(re.search(r'(?i)proxy:unix:.*php|SetHandler\s+.*php|php_admin_value', t))


def open_basedir(ws, berkas, docroot):
    """True/False untuk situs PHP; None bila tidak bisa ditentukan."""
    t = _tanpa_komentar(_baca(berkas))
    if re.search(r'open_basedir', t):
        return True
    if docroot and re.search(r'(?m)^\s*open_basedir\s*=', _baca(os.path.join(docroot, '.user.ini'))):
        return True
    # pool php-fpm yang socket-nya dipakai vhost (standalone)
    m = re.search(r'fastcgi_pass\s+unix:([^;\s]+)', t) or re.search(r'proxy:unix:([^|"\s]+)', t)
    if m:
        sock = m.group(1)
        for p in glob.glob('/etc/php/*/fpm/pool.d/*.conf') + glob.glob('/etc/php-fpm.d/*.conf') + glob.glob('/www/server/php/*/etc/php-fpm.conf'):
            pt = _tanpa_komentar(_baca(p)).replace(';', '#')
            pt = _tanpa_komentar(pt)
            if re.search(r'(?m)^\s*listen\s*=\s*' + re.escape(sock) + r'\s*$', pt):
                return bool(re.search(r'php_admin_value\[open_basedir\]', pt))
    return False if docroot else None


def _docroot(ws, berkas):
    t = _tanpa_komentar(_baca(berkas))
    if ws in WS_OLS:
        m = re.search(r'(?im)^\s*docRoot\s+(\S+)', t)
        if not m:
            return ''
        nama = os.path.basename(os.path.dirname(berkas))      # .../conf/vhosts/<situs>/vhost.conf
        akar = '/home/' + nama if os.path.isdir('/home/' + nama) else os.path.join(OLS_ROOT, nama)
        return m.group(1).replace('$VH_ROOT', akar).replace('$VH_NAME', nama).replace('$SERVER_ROOT', OLS_ROOT)
    m = re.search(r'(?:^|[;{\s])root\s+([^;]+);', t) if ws == 'nginx' else re.search(r'(?im)^\s*DocumentRoot\s+"?([^"\n]+)"?', t)
    return m.group(1).strip().strip('"\'') if m else ''


def audit_satu(item):
    situs, ws, berkas = item
    temuan = []
    ssl_on, proto, sumber = {'nginx': tls_nginx, 'apache': tls_apache}.get(ws, tls_ols)(berkas, situs)
    lama = [p for p in proto if p in LAMA]
    diterima = {}
    if ssl_on:
        diterima = uji_tls_lama(situs)
        terima = [k for k, v in diterima.items() if v]
        if terima:
            temuan.append({'id': 'tls_lama_diterima', 'tingkat': 'tinggi', 'detail': ' '.join(terima)})
        elif lama:
            temuan.append({'id': 'tls_lama_tertulis', 'tingkat': 'rendah', 'detail': ' '.join(lama)})
    status, hdr = ambil_header(situs, ssl_on)
    ganda, hilang, bocor = [], [], ''
    if status is not None and not 200 <= status < 400:
        # add_header nginx tanpa 'always' tidak dikirim pada 4xx/5xx: header tidak bisa dinilai dari respons ini
        temuan.append({'id': 'header_tidak_dinilai', 'tingkat': 'info', 'detail': 'HTTP %s pada /' % status})
    elif status is not None:
        for k in HEADER:
            if len(hdr[k]) > 1:
                ganda.append(k)
        if ssl_on and not hdr['Strict-Transport-Security']:
            hilang.append('Strict-Transport-Security')
        if not hdr['X-Content-Type-Options']:
            hilang.append('X-Content-Type-Options')
        if not hdr['X-Frame-Options'] and not any('frame-ancestors' in v for v in hdr['Content-Security-Policy']):
            hilang.append('X-Frame-Options')
        if ganda:
            temuan.append({'id': 'header_ganda', 'tingkat': 'sedang', 'detail': ', '.join(ganda)})
        if hilang:
            temuan.append({'id': 'header_hilang', 'tingkat': 'rendah', 'detail': ', '.join(hilang)})
    if status is not None:
        # versi di header Server/X-Powered-By terkirim di semua status
        for k in ('Server', 'X-Powered-By'):
            for v in hdr[k]:
                if re.search(r'\d+\.\d+', v):
                    bocor = (bocor + '; ' if bocor else '') + '%s: %s' % (k, v[:60])
        if bocor:
            temuan.append({'id': 'versi_terbuka', 'tingkat': 'rendah', 'detail': bocor})
    docroot = _docroot(ws, berkas)
    php = _php_situs(ws, berkas)
    obd = open_basedir(ws, berkas, docroot) if php else None
    if php and obd is False:
        temuan.append({'id': 'open_basedir', 'tingkat': 'sedang', 'detail': docroot})
    bobot = {'tinggi': 30, 'sedang': 15, 'rendah': 5, 'info': 0}
    return {'situs': situs, 'ws': ws, 'berkas': berkas, 'ssl': ssl_on, 'tls_tertulis': proto, 'tls_sumber': sumber,
            'tls_lama_diterima': diterima, 'http_status': status, 'header': hdr if status is not None else {},
            'header_galat': '' if status is not None else hdr, 'php': php, 'open_basedir': obd,
            'temuan': temuan, 'skor': max(0, 100 - sum(bobot[t['tingkat']] for t in temuan)),
            'bisa_fix_tls': bool(ws == 'apache' and ssl_on and lama and _panel() == 'directadmin' and os.path.isdir(DA_CB)) or bool(ws in WS_OLS and ssl_on and lama and os.path.realpath(berkas).startswith(OLS_ROOT.rstrip('/') + '/conf/')) or bool(ws == 'apache' and ssl_on and lama and _panel() == 'cpanel' and os.path.isfile(CP_EA4_CONF)) or bool(ws in ('nginx', 'apache') and ssl_on and lama and _panel() not in ('cpanel', 'directadmin') and os.path.realpath(berkas).startswith(DIR_KONF) and berkas.endswith('.conf'))}


def audit(hanya=''):
    daftar = [x for x in daftar_situs() if not hanya or x[0] == hanya][:200]
    with ThreadPoolExecutor(max_workers=8) as ex:
        hasil = list(ex.map(audit_satu, daftar))
    n = len(hasil)
    ringkas = {'situs': n, 'skor': round(sum(h['skor'] for h in hasil) / n) if n else 100,
               'tls_lama_diterima': sum(1 for h in hasil if any(t['id'] == 'tls_lama_diterima' for t in h['temuan'])),
               'tls_lama_tertulis': sum(1 for h in hasil if any(t['id'] == 'tls_lama_tertulis' for t in h['temuan'])),
               'header_ganda': sum(1 for h in hasil if any(t['id'] == 'header_ganda' for t in h['temuan'])),
               'open_basedir': sum(1 for h in hasil if any(t['id'] == 'open_basedir' for t in h['temuan'])),
               'php': sum(1 for h in hasil if h['php']), 'ts': int(time.time())}
    return {'situs': hasil, 'ringkas': ringkas}


def _ganti_tls_nginx(teks):
    """Buang protokol lama dari setiap ssl_protocols; bila server ber-SSL tidak menulisnya, sisipkan setelah ssl_certificate_key."""
    def ganti(m):
        sisa = [p for p in m.group(2).split() if p not in LAMA] or ['TLSv1.2', 'TLSv1.3']
        return m.group(1) + ' '.join(sisa) + ';'
    baru, n = re.subn(r'(?m)^(\s*ssl_protocols\s+)([^;#\n]+);', ganti, teks)
    if n == 0:
        baru, n = re.subn(r'(?m)^(\s*)(ssl_certificate_key\s+[^;]+;)', r'\1\2\n\1ssl_protocols TLSv1.2 TLSv1.3;', teks, count=1)
    return baru, n


def _ganti_tls_apache(teks):
    baru, n = re.subn(r'(?im)^(\s*SSLProtocol\s+)(.+)$', r'\1all -SSLv3 -TLSv1 -TLSv1.1', teks)
    if n == 0:
        baru, n = re.subn(r'(?im)^(\s*)(SSLEngine\s+on)\s*$', r'\1\2\n\1SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1', teks)
    return baru, n


def _panel():
    return _env_sh().get('ZYS_PANEL', '')


def fix_tls_cpanel(situs):
    """cPanel: SSLProtocol global lewat ea4.conf + rebuildhttpdconf, reload terverifikasi, cadangan dikembalikan bila gagal."""
    try:
        with open(CP_EA4_CONF) as f:
            data = json.load(f)
    except (OSError, ValueError) as ex:
        return False, 'ea4.conf cPanel tidak terbaca: %s' % ex
    lama = data.get('sslprotocol', '')
    if not [p for p in _apache_protokol(lama or 'all') if p in LAMA] and lama:
        return True, 'tidak ada perubahan: SSLProtocol global cPanel (%s) tidak memuat TLS 1.0/1.1' % lama
    cadangan = '%s.bak.%s' % (CP_EA4_CONF, time.strftime('%Y%m%d%H%M%S'))
    shutil.copy2(CP_EA4_CONF, cadangan)
    data['sslprotocol'] = CP_PROTO_AMAN
    data['sslprotocol_list_str'] = 'TLSv1.2 TLSv1.3'

    def tulis(d):
        tmp = CP_EA4_CONF + '.zys.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=3, sort_keys=True)
            f.write('\n')
        st = os.stat(CP_EA4_CONF)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, CP_EA4_CONF)

    def bangun_reload():
        try:
            r1 = subprocess.run([CP_REBUILD], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, cwd='/')
            r2 = subprocess.run(['bash', WAF_SH, 'reload', 'apache'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, cwd='/')
            return r1.returncode == 0 and r2.returncode == 0, (r1.stdout + r2.stdout).decode('utf-8', 'replace')
        except (OSError, subprocess.SubprocessError) as ex:
            return False, str(ex)
    try:
        tulis(data)
    except OSError as ex:
        return False, 'gagal menulis ea4.conf: %s' % ex
    ok, out = bangun_reload()
    if not ok:
        shutil.copy2(cadangan, CP_EA4_CONF)
        bangun_reload()
        return False, 'rebuildhttpdconf/reload gagal, ea4.conf dikembalikan dari %s: %s' % (os.path.basename(cadangan), out.strip()[-200:])
    masih = [k for k, v in uji_tls_lama(situs).items() if v]
    pesan = 'TLS 1.0/1.1 dimatikan untuk SEMUA situs Apache cPanel (pengaturan global EasyApache, cadangan %s)' % os.path.basename(cadangan)
    if masih:
        pesan += '; PERHATIAN: server masih menerima %s' % ' '.join(masih)
    return True, pesan


def _ols_buang_lama(teks, kata):
    """sslProtocol di setiap blok `kata` (vhssl / listener ber-SSL): buang bit SSLv3/TLSv1/TLSv1.1 (1+2+4); minimal TLSv1.2+1.3 (24)."""
    n = 0
    hasil, pos = [], 0
    for m in re.finditer(r'(?m)^[ \t]*' + kata + r'\b[^{\n]*\{', teks):
        i, d = m.end(), 1
        while i < len(teks) and d:
            d += {'{': 1, '}': -1}.get(teks[i], 0)
            i += 1
        blok = teks[m.end():i - 1]

        def ganti(mm):
            nonlocal n
            v = int(mm.group(2))
            baru = (v & ~7) or 24
            if baru != v:
                n += 1
            return mm.group(1) + str(baru)
        blok2 = re.sub(r'(?m)^(\s*sslProtocol\s+)(\d+)', ganti, blok)
        hasil.append(teks[pos:m.end()] + blok2)
        pos = i - 1
    hasil.append(teks[pos:])
    return ''.join(hasil), n


def fix_tls_ols(situs, berkas):
    """OpenLiteSpeed (CyberPanel): sslProtocol di vhssl situs dan listener ber-SSL yang memetakannya; openlitespeed -t, restart halus,
    cadangan dikembalikan bila gagal. CyberPanel sendiri menulis sslProtocol 24 saat menerbitkan SSL, jadi hasilnya tidak dilemahkan ulang."""
    utama = os.path.join(OLS_ROOT, 'conf', 'httpd_config.conf')
    ubah = []
    for p, kata in ((berkas, 'vhssl'), (utama, 'listener')):
        t = _baca(p)
        if not t:
            continue
        baru, n = _ols_buang_lama(t, kata)
        if n:
            ubah.append((p, t, baru))
    if not ubah:
        return True, 'tidak ada perubahan: %s tidak menulis protokol TLS lama' % situs
    ts = time.strftime('%Y%m%d%H%M%S')
    for p, lama, baru in ubah:
        shutil.copy2(p, '%s.bak.%s' % (p, ts))
        st = os.stat(p)
        with open(p + '.zys.tmp', 'w') as f:
            f.write(baru)
        os.chmod(p + '.zys.tmp', st.st_mode & 0o7777)
        try:
            os.chown(p + '.zys.tmp', st.st_uid, st.st_gid)
        except OSError:
            pass
        os.replace(p + '.zys.tmp', p)
    bin_ols = os.path.join(OLS_ROOT, 'bin', 'openlitespeed')
    try:
        r = subprocess.run([bin_ols, '-t'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60, cwd='/')
        ok = r.returncode < 2 and '[ERROR]' not in r.stdout.decode('utf-8', 'replace')
        if ok:
            subprocess.run([os.path.join(OLS_ROOT, 'bin', 'lswsctrl'), 'restart'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, cwd='/')
            time.sleep(3)
    except (OSError, subprocess.SubprocessError):
        ok = False
    if not ok:
        for p, lama, baru in ubah:
            shutil.copy2('%s.bak.%s' % (p, ts), p)
        return False, 'uji konfigurasi OpenLiteSpeed gagal; berkas dikembalikan dari cadangan .bak.%s' % ts
    masih = [k for k, v in uji_tls_lama(situs).items() if v]
    pesan = 'TLS 1.0/1.1 dimatikan untuk %s di OpenLiteSpeed (cadangan .bak.%s)' % (situs, ts)
    if masih:
        pesan += '; PERHATIAN: server masih menerima %s' % ' '.join(masih)
    return True, pesan


def _da_opsi(nama):
    m = re.search(r'(?m)^' + re.escape(nama) + r'=(.*)$', _baca(os.path.join(DA_CB, 'options.conf')))
    return m.group(1).strip() if m else ''


def fix_tls_da(situs):
    """DirectAdmin: ssl_configuration CustomBuild (bukan menyunting httpd-ssl.conf yang ditulis ulang panel), rewrite_confs, reload
    terverifikasi; options.conf dikembalikan bila gagal."""
    opsi = os.path.join(DA_CB, 'options.conf')
    if not os.path.isfile(opsi):
        return False, 'options.conf CustomBuild tidak ditemukan (%s)' % opsi
    lama = _da_opsi('ssl_configuration')
    if lama in ('intermediate', 'modern'):
        return True, 'tidak ada perubahan: ssl_configuration CustomBuild = %s (TLS 1.2+); periksa SSLProtocol kustom bila audit masih melaporkan TLS lama' % lama
    cadangan = '%s.bak.%s' % (opsi, time.strftime('%Y%m%d%H%M%S'))
    shutil.copy2(opsi, cadangan)

    def jalankan(*arg, batas=900):
        try:
            r = subprocess.run(['./build'] + list(arg), cwd=DA_CB, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=batas)
            return r.returncode == 0, r.stdout.decode('utf-8', 'replace')
        except (OSError, subprocess.SubprocessError) as ex:
            return False, str(ex)
    ok, out = jalankan('set', 'ssl_configuration', 'intermediate', batas=120)
    if ok:
        ok, out = jalankan('rewrite_confs')
    if ok:
        try:
            r = subprocess.run(['bash', WAF_SH, 'reload', 'apache'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, cwd='/')
            ok, out = r.returncode == 0, r.stdout.decode('utf-8', 'replace')
        except (OSError, subprocess.SubprocessError) as ex:
            ok, out = False, str(ex)
    if not ok:
        shutil.copy2(cadangan, opsi)
        jalankan('rewrite_confs')
        return False, 'CustomBuild rewrite_confs/reload gagal, options.conf dikembalikan dari %s: %s' % (os.path.basename(cadangan), out.strip()[-200:])
    masih = [k for k, v in uji_tls_lama(situs).items() if v]
    pesan = 'TLS 1.0/1.1 dimatikan untuk SEMUA situs Apache DirectAdmin (CustomBuild ssl_configuration=intermediate, cadangan %s)' % os.path.basename(cadangan)
    if masih:
        pesan += '; PERHATIAN: server masih menerima %s' % ' '.join(masih)
    return True, pesan


def fix_tls(situs):
    if not NAMA_SITUS.match(situs or ''):
        return False, 'nama situs tidak valid'
    cocok = [x for x in daftar_situs() if x[0] == situs]
    if not cocok:
        return False, 'situs tidak ditemukan'
    _, ws, berkas = cocok[0]
    if ws == 'apache' and _panel() == 'cpanel' and os.path.isfile(CP_EA4_CONF):
        return fix_tls_cpanel(situs)
    if ws == 'apache' and _panel() == 'directadmin' and os.path.isdir(DA_CB):
        return fix_tls_da(situs)
    if ws in WS_OLS and os.path.realpath(berkas).startswith(OLS_ROOT.rstrip('/') + '/conf/'):
        return fix_tls_ols(situs, berkas)
    if ws not in ('nginx', 'apache'):
        return False, 'perbaikan otomatis hanya untuk nginx/Apache/OpenLiteSpeed; atur sslProtocol situs %s di panel (%s)' % (situs, ws)
    # sites-enabled Debian berisi symlink ke sites-available: yang diubah adalah berkas tujuannya, dan hanya bila berada di folder
    # konfigurasi web server milik root (bukan berkas yang bisa ditulis akun lain)
    berkas = os.path.realpath(berkas)
    try:
        st0 = os.stat(berkas)
    except OSError:
        return False, 'berkas vhost tidak ditemukan'
    if (not berkas.endswith('.conf') or not berkas.startswith(DIR_KONF) or st0.st_uid != 0 or st0.st_mode & 0o022
            or not os.path.isfile(berkas)):
        return False, 'berkas vhost tidak bisa diubah dengan aman: %s' % berkas
    lama = _baca(berkas)
    baru, n = (_ganti_tls_nginx if ws == 'nginx' else _ganti_tls_apache)(lama)
    if n == 0 or baru == lama:
        return True, 'tidak ada perubahan: %s tidak menulis protokol TLS lama' % situs
    cadangan = '%s.bak.%s' % (berkas, time.strftime('%Y%m%d%H%M%S'))
    shutil.copy2(berkas, cadangan)
    st = os.stat(berkas)
    tmp = berkas + '.zys.tmp'
    try:
        with open(tmp, 'w') as f:
            f.write(baru)
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
        os.replace(tmp, berkas)
    except OSError as ex:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False, 'gagal menulis vhost: %s' % ex
    # uji konfigurasi + reload terverifikasi (PID worker) + pemeriksaan ruleset WAF: dipakai bersama sentinel-waf.sh
    try:
        r = subprocess.run(['bash', WAF_SH, 'reload', ws], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, cwd='/')
        rc, out = r.returncode, r.stdout.decode('utf-8', 'replace')
    except (OSError, subprocess.SubprocessError) as ex:
        rc, out = 1, str(ex)
    if rc != 0:
        shutil.copy2(cadangan, berkas)
        try:
            subprocess.run(['bash', WAF_SH, 'reload', ws], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180, cwd='/')
        except (OSError, subprocess.SubprocessError):
            pass
        return False, 'uji/reload %s gagal, vhost dikembalikan dari %s: %s' % (ws, os.path.basename(cadangan), out.strip()[-200:])
    sisa = uji_tls_lama(situs)
    masih = [k for k, v in sisa.items() if v]
    pesan = 'TLS 1.0/1.1 dimatikan untuk %s (cadangan %s)' % (situs, os.path.basename(cadangan))
    if masih:
        pesan += '; PERHATIAN: server masih menerima %s (diatur di tingkat lain, mis. vhost bawaan yang berbagi IP:443)' % ' '.join(masih)
    if os.path.isdir('/www/server/panel/vhost'):
        pesan += '. aaPanel dapat menulis ulang baris ini saat pengaturan SSL situs diubah di panel; audit ulang setelahnya'
    return True, pesan


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    if cmd == 'audit':
        print(json.dumps(audit(argv[2] if len(argv) > 2 else ''), ensure_ascii=False))
        return 0
    if cmd == 'fix-tls' and len(argv) > 2:
        ok, msg = fix_tls(argv[2])
        print(json.dumps({'status': ok, 'msg': msg}, ensure_ascii=False))
        return 0 if ok else 1
    print('pakai: sentinel-harden.py audit [situs] | fix-tls <situs>', file=sys.stderr)
    return 64


if __name__ == '__main__':
    sys.exit(main(sys.argv))
