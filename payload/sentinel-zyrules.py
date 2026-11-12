#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
# ==================================================================
# sentinel-zyrules.py -- penyusun konfigurasi WAF ZySentinel (Coraza + OWASP CRS)
#
# Satu-satunya tempat yang menulis berkas konfigurasi turunan di
# $ZY_DIR/gen/. Dipakai oleh sentinel-waf.sh dan panel, sehingga nginx
# (Coraza), Apache (ModSecurity v2), dan OpenLiteSpeed (ModSecurity)
# memuat berkas yang SAMA.
#
#   build   tulis ulang gen/ dari waf.conf, daftar IP/URL, dan allowlist.txt
#   status  keluaran JSON ringkas (modul, pengaturan, jumlah daftar, CRS)
#
# Semua nilai dari daftar divalidasi ulang di sini (pertahanan berlapis):
# entri tak valid dilewati dan dilaporkan, tidak pernah ditulis ke aturan.
# ==================================================================
import sys
import os
import re
import hashlib
import json
import shutil
import stat
import ipaddress

BASE = os.environ.get('SENTINEL_BASE', '/www/server/sentinel')
WAF_CONF = os.environ.get('SENTINEL_WAF_CONF', BASE + '/etc/waf.conf')
WAF_BASE = os.environ.get('SENTINEL_WAF_BASE', BASE + '/waf')
ZY_DIR = os.environ.get('SENTINEL_ZY_DIR', WAF_BASE + '/zyrules')
CRS_DIR = os.environ.get('SENTINEL_CRS_DIR', WAF_BASE + '/coraza/rules')
LISTS_DIR = os.environ.get('SENTINEL_WAF_LISTS', BASE + '/etc/waf-lists')
ALLOWLIST = os.environ.get('SENTINEL_ALLOWLIST', BASE + '/etc/allowlist.txt')
AUDIT_LOG = os.environ.get('SENTINEL_WAF_AUDIT', '/www/wwwlogs/zysentinel_waf_audit.jsonl')
def _user_web():
    """User yang menjalankan worker web server: www (aaPanel), www-data, apache, nginx."""
    if os.environ.get('SENTINEL_WEB_USER'):
        return os.environ['SENTINEL_WEB_USER']
    try:
        import pwd
        for u in ('www', 'www-data', 'apache', 'nginx'):
            try:
                pwd.getpwnam(u)
                return u
            except KeyError:
                continue
    except Exception:
        pass
    return 'www'


WEB_USER = _user_web()

GEN = ZY_DIR + '/gen'

# Modul = kelompok ID aturan yang bisa dimatikan dari panel.
MODULES = {
    'sensitive_files': ('8000101-8000115', 'Berkas dan folder sensitif: .env, .git/, .htpasswd, kunci, API key, cadangan'),
    'webshell':        ('8000120-8000121', 'Webshell, jalur eksploit, dan skrip di folder unggahan'),
    'spam':            ('8000125-8000125', 'URL judi online dan penambang kripto'),
    'scanner':         ('8000130-8000132', 'Pemindai kerentanan (User-Agent, header, penanda)'),
    'bot':             ('8000140-8000143', 'Bot scraper dan crawler (tingkat diatur terpisah)'),
    'lfi_args':        ('8000160-8000160', 'Baca berkas sensitif dan path traversal lewat parameter'),
    'probe_cms':       ('8000400-8000409', 'Probe WordPress/Joomla/Drupal pada situs yang bukan CMS itu'),
    'probe_tools':     ('8000410-8000419', 'Probe Adminer/phpMyAdmin, phpinfo, endpoint debug, aplikasi infrastruktur'),
    'probe_cve':       ('8000420-8000429', 'Eksploit router/IoT/CVE dan trik path traversal ;/'),
    'probe_archive':   ('8000430-8000439', 'Tebakan nama arsip cadangan di root situs'),
    'probe_secrets':   ('8000440-8000449', 'Berkas berawalan titik, kredensial, internal Laravel, skrip di .well-known'),
    'php2shell':       ('8000450-8000459', 'Medan upload-progress PHP (jalur PHP2Shell CVE-2026-109618/109619), bawaan hanya dicatat'),
    'app_laravel':     ('8000500-8000509', 'Proteksi Laravel: kunci Passport, storage logs, cache bootstrap, SQLite, Livewire upload'),
    'app_wordpress':   ('8000510-8000519', 'Proteksi WordPress: debug.log, cadangan plugin migrasi, TimThumb, user enumeration'),
    'app_codeigniter': ('8000520-8000529', 'Proteksi CodeIgniter: CI2/3 logs & database config, CI4 writable logs & spark'),
    'app_cms':         ('8000530-8000539', 'Proteksi CMS umum: konfigurasi Joomla/Drupal/Magento/PrestaShop, Drupalgeddon RCE'),
    'app_nodejs':      ('8000540-8000549', 'Proteksi Node.js: fast-drop Prototype Pollution, Next.js manifests, log package manager'),
    'app_golang':      ('8000550-8000559', 'Proteksi Golang: runtime profiling pprof, expvar debug vars, Go SSTI'),
    'app_python':      ('8000560-8000569', 'Proteksi Python: Werkzeug/Flask debug console, Python bytecode pyc, Jinja2/Mako SSTI'),
}
MODE_ENGINE = {'block': 'On', 'monitor': 'DetectionOnly', 'disable': 'Off'}
LISTS = ('ip_white', 'ip_black', 'url_white', 'url_black')

# Berkas data dan aturan statis yang harus ada di ZY_DIR.
STATIC = ('zysentinel-config.conf', 'zysentinel-before.conf', 'zysentinel-after.conf',
          'zysentinel-base.conf.in', 'zy-scanner-ua.data', 'zy-bots-l1.data',
          'zy-bots-l2.data', 'zy-bots-l3.data')

PERINGATAN = []


def warn(msg):
    PERINGATAN.append(msg)
    sys.stderr.write('[zyrules] PERINGATAN: %s\n' % msg)


# ---------------------------------------------------------------- waf.conf --
def conf_baca():
    d = {}
    try:
        with open(WAF_CONF, 'r') as f:
            for line in f:
                line = line.split('#')[0].strip()
                if '=' in line:
                    k, v = line.split('=', 1)
                    d[k.strip()] = v.strip()
    except Exception:
        pass
    return d


def conf_int(d, k, bawaan, lo, hi):
    try:
        v = int(d.get(k, bawaan))
    except Exception:
        return bawaan
    return v if lo <= v <= hi else bawaan


# ------------------------------------------------------------------ daftar --
_OKTET = r'(?:0|[1-9][0-9]{0,2})'
_RE_V4 = re.compile(r'%s(?:\.%s){3}' % (_OKTET, _OKTET))


def _v4(s):
    if not _RE_V4.fullmatch(s or ''):
        return None
    try:
        return ipaddress.IPv4Address(s)
    except ValueError:
        return None


# Prefix terluas yang diterima di daftar IP WAF, sama dengan panel (parse_v4 min_prefix=8). Ditegakkan lagi di sini karena
# berkas daftar bisa diubah di luar panel: entri /0../7 di ip_white mematikan WAF untuk hampir semua alamat.
MIN_PREFIX = 8


def ip_ke_cidr(entri):
    """IPv4 tunggal, CIDR (/8../32), atau rentang a-b -> daftar string CIDR (tanpa /32 untuk host).
    Mengembalikan None bila tidak valid atau lebih luas dari /MIN_PREFIX."""
    entri = (entri or '').strip()
    try:
        if '-' in entri:
            a, b = [x.strip() for x in entri.split('-')]
            ia, ib = _v4(a), _v4(b)
            if ia is None or ib is None or int(ia) > int(ib):
                return None
            nets = list(ipaddress.summarize_address_range(ia, ib))
            if any(n.prefixlen < MIN_PREFIX for n in nets):
                return None
            return [str(n) if n.prefixlen != 32 else str(n.network_address) for n in nets]
        ip_s, sep, pre = entri.partition('/')
        if _v4(ip_s) is None:
            return None
        if sep:
            if not re.fullmatch(r'(?:0|[1-9][0-9]?)', pre) or not MIN_PREFIX <= int(pre) <= 32:
                return None
            n = ipaddress.IPv4Network(entri, strict=True)
            return [str(n) if n.prefixlen != 32 else str(n.network_address)]
        return [ip_s]
    except ValueError:
        return None


def ler_lista(nama):
    p = '%s/%s.txt' % (LISTS_DIR, nama)
    out = []
    try:
        with open(p, 'r', encoding='utf-8') as f:
            for line in f:
                t = line.split('#')[0].strip()
                if t:
                    out.append(t)
    except FileNotFoundError:
        pass
    return out


# Entri daftar URL (url_white/url_black), satu baris: [crs+](lit:|rx:)?pola
#   lit:/api/v1        mode Normal: awalan path per segmen (tanpa regex): ^<path di-escape> lalu /, ?, ; atau akhir path
#   rx:^/api/.*\.json$  mode Regex (RE2)
#   tanpa awalan       bentuk lama = Regex
#   crs+               (url_white saja) cakupan "hanya OWASP CRS": aturan ZySentinel tetap berjalan, CRS dilewati untuk URL itu
# Sama dengan sentinel_main.url_entri (uji audit_20261030 membandingkan keduanya).
_URL_ENTRI = re.compile(r'^(?:(crs)\+)?(?:(lit|rx):)?(.*)$', re.S)


def url_entri(e):
    """baris daftar URL -> (cakupan 'semua'|'crs', mode 'normal'|'regex', pola seperti ditulis admin, regex untuk WAF)."""
    crs, mode, isi = _URL_ENTRI.match(e or '').groups()
    cakupan = 'crs' if crs else 'semua'
    if mode == 'lit':
        # batas segmen: /api cocok dengan /api, /api/..., /api?..., tetapi tidak /api-internal (evaluasi 30 Okt 2026)
        return cakupan, 'normal', isi, '^' + re.escape(isi) + ('' if isi.endswith('/') else '(?:[/?;]|$)')
    return cakupan, 'regex', isi, isi


def allowlist_cidr():
    hasil = []
    try:
        with open(ALLOWLIST, 'r') as f:
            for line in f:
                t = line.split('#')[0].strip()
                if not t:
                    continue
                c = ip_ke_cidr(t)
                if c is None:
                    warn('allowlist.txt: baris tak valid dilewati: %r' % t[:40])
                    continue
                for x in c:
                    if x not in hasil and x != '0.0.0.0/0':
                        hasil.append(x)
    except FileNotFoundError:
        pass
    return hasil


def seclang_rx(pola):
    """Regex pengguna -> aman di dalam string SecLang yang dikutip.
    - `\\\\` menjadi `\\x5c`: ModSecurity v2 meng-unescape `\\\\` menjadi `\\`,
      Coraza tidak; `\\x5c` sama di keduanya.
    - `"` menjadi `\\x22`."""
    out = []
    i = 0
    while i < len(pola):
        c = pola[i]
        if c == '\\' and i + 1 < len(pola):
            n = pola[i + 1]
            if n == '\\':
                out.append('\\x5c')
            elif n == '"':
                out.append('\\x22')
            else:
                out.append(c + n)
            i += 2
            continue
        if c == '"':
            out.append('\\x22')
        else:
            out.append(c)
        i += 1
    return ''.join(out)


_RX_WORKER = "\nimport re, sys, json\npats = json.loads(sys.stdin.read())\nout = []\nPR = ('/', '/index.php', '/a/b/c', '/x?y=1')\nADV = ['a' * 40 + '!', '/' + 'a' * 40 + '!', '/' + '/a' * 20 + '!', '/' + '1' * 40 + 'x', ('a' * 20 + ' ') * 4 + '!']\nfor p in pats:\n    try:\n        rx = re.compile(p)\n    except re.error:\n        out.append('err'); continue\n    luas = all(rx.search(x) for x in PR)\n    for x in ADV:\n        rx.search(x)\n    out.append('luas' if luas else 'ok')\nprint(json.dumps(out))\n"
_RX_CACHE = {}


def _rx_uji(pola_list, timeout):
    import subprocess
    try:
        r = subprocess.run([sys.executable, '-I', '-c', _RX_WORKER], input=json.dumps(list(pola_list)),
                           capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        pass
    return ['err'] * len(pola_list)


def rx_siapkan(pola_list):
    """Uji semua pola sekaligus di proses terpisah dengan batas waktu. Bila satu pola
    lambat (ReDoS) seluruh kelompok kena timeout, lalu diuji satu per satu supaya hanya
    pola yang bermasalah yang dibuang; build (root) tidak pernah ikut macet."""
    baru = [p for p in dict.fromkeys(pola_list) if p not in _RX_CACHE]
    if not baru:
        return
    hasil = _rx_uji(baru, 10)
    if hasil is None:
        hasil = []
        for p in baru:
            r = _rx_uji([p], 2)
            hasil.append('lambat' if r is None else r[0])
    for p, h in zip(baru, hasil):
        _RX_CACHE[p] = h


def rx_valid(pola):
    if not pola or len(pola) > 300 or re.search(r'[\x00-\x1f\x7f]', pola):
        return False
    # Sintaks yang tidak didukung RE2 (Coraza) menggagalkan seluruh ruleset.
    # \Z dan flag x (verbose) ada di Python tetapi tidak di RE2/Go regexp (dulu lolos validasi lalu ruleset gagal dimuat)
    if re.search(r'\(\?<?[=!]|\(\?>|\(\?P=|\\[1-9]|[*+?}]\+|\\Z|\(\?[a-zA-Z-]*x', pola):
        warn('pola dibuang karena tidak didukung WAF (RE2): %r' % pola[:40])
        return False
    if pola not in _RX_CACHE:
        rx_siapkan([pola])
    h = _RX_CACHE.get(pola)
    if h == 'lambat':
        warn('pola dibuang karena terlalu lambat dievaluasi (risiko ReDoS): %r' % pola[:40])
    return h == 'ok'


# ----------------------------------------------------------------- penulis --
def tulis(nama, isi, mode=0o644):
    os.makedirs(os.path.dirname('%s/%s' % (GEN, nama)), exist_ok=True)
    p = '%s/%s' % (GEN, nama)
    tmp = p + '.tmp'
    with open(tmp, 'w') as f:
        f.write(isi)
    os.chmod(tmp, mode)
    os.replace(tmp, p)
    return p


def gen_base(conf):
    mode = conf.get('mode', 'block')
    if mode not in MODE_ENGINE:
        mode = 'block'
    src = open(ZY_DIR + '/zysentinel-base.conf.in').read()
    # Batas badan permintaan. Biaya CPU CRS naik linear dengan ukuran badan (diukur sekitar 27 ms per KB
    # untuk satu argumen besar): bodi tanpa berkas dibatasi 128 KB secara bawaan supaya satu
    # permintaan paling mahal sekitar 4 detik, dan yang lebih besar langsung ditolak 413.
    # Situs dengan JSON/form besar (editor blok, impor) dapat menaikkannya dari pengaturan.
    # Total (termasuk unggahan berkas) mengikuti client_max_body_size nginx (50 MB bawaan aaPanel);
    # berkas unggahan tidak diperiksa isinya sehingga murah, dan disimpan di berkas sementara.
    nofiles = conf_int(conf, 'zy.body_nofiles_kb', 128, 16, 4096) * 1024
    total = conf_int(conf, 'zy.body_total_mb', 50, 1, 512) * 1048576
    return (src.replace('@MODE@', MODE_ENGINE[mode]).replace('@AUDIT_LOG@', AUDIT_LOG)
            .replace('@BODY_NOFILES@', str(nofiles)).replace('@BODY_TOTAL@', str(total)))


# ------------------------------------------------------- pengecualian per vhost --
VHOST_DIRS = os.environ.get('SENTINEL_VHOST_DIRS', '/www/server/panel/vhost/nginx:/www/server/panel/vhost/apache').split(':')


def detect_apps():
    """Situs yang SAH menjalankan WordPress/CMS, phpMyAdmin/Adminer, atau CGI: aturan probe
    untuk kelompok itu dikecualikan di vhost tersebut (bila tidak, situs sahnya ikut terblokir).
    Hasil: {'zys-cms': [host...], 'zys-tools': [...], 'zys-cve': [...]}."""
    hasil = {'zys-cms': set(), 'zys-tools': set(), 'zys-cve': set()}
    for d in VHOST_DIRS:
        try:
            berkas = sorted(os.listdir(d))
        except OSError:
            continue
        for f in berkas:
            if not f.endswith('.conf') or '.bak.' in f:
                continue
            try:
                isi = open(os.path.join(d, f), errors='replace').read(65536)
            except OSError:
                continue
            m_root = re.search(r'^\s*root\s+([^;\s]+);', isi, re.M) or re.search(r'^\s*DocumentRoot\s+"?([^"\s]+)"?', isi, re.M)
            m_name = re.search(r'^\s*server_name\s+([^;]+);', isi, re.M) or re.search(r'^\s*ServerName\s+(\S+)', isi, re.M)
            if not m_root or not m_name:
                continue
            root = m_root.group(1)
            hosts = [h.lower() for h in m_name.group(1).split() if re.fullmatch(r'[A-Za-z0-9._-]{1,253}', h) and h != '_']
            if not hosts or not os.path.isdir(root):
                continue
            def ada(*nama):
                return any(os.path.exists(os.path.join(root, n)) for n in nama)
            if ada('wp-config.php', 'wp-includes', 'wp-load.php', 'administrator/index.php', 'typo3', 'core/install.php'):
                hasil['zys-cms'].update(hosts)
            if ada('phpmyadmin', 'pma', 'adminer.php', 'adminer', 'phpMyAdmin', 'index.php/_profiler') or \
               any(n.lower().startswith(('adminer', 'phpmyadmin')) for n in os.listdir(root)):
                hasil['zys-tools'].update(hosts)
            if ada('cgi-bin') and os.listdir(os.path.join(root, 'cgi-bin')):
                hasil['zys-cve'].update(hosts)
    return {k: sorted(v) for k, v in hasil.items()}


def gen_exceptions():
    """Aturan pengecualian per vhost (dimuat SEBELUM aturan probe)."""
    s = ''
    nomor = 8000490
    for tag, hosts in detect_apps().items():
        if not hosts:
            continue
        rx = '^(?:%s)(?::[0-9]+)?$' % '|'.join(re.escape(h) for h in hosts)
        s += ('# Situs sah yang memakai aplikasi ini: %s\n'
              'SecRule REQUEST_HEADERS:Host "@rx %s" "id:%d,phase:1,pass,nolog,t:none,t:lowercase,ctl:ruleRemoveByTag=%s"\n'
              % (', '.join(hosts), rx, nomor, tag))
        nomor += 1
    return s


def gen_settings(conf):
    bot = conf_int(conf, 'zy.bot_level', 1, 0, 3)
    strict = conf_int(conf, 'zy.strict', 0, 0, 1)
    fb = conf_int(conf, 'zy.fallback', 1, 0, 1)
    return ('# Dibuat oleh sentinel-zyrules.py dari waf.conf. Jangan edit.\n'
            'SecAction "id:8000300,phase:1,pass,nolog,t:none,'
            'setvar:tx.zy_bot_level=%d,setvar:tx.zy_strict=%d,setvar:tx.zy_fallback=%d"\n'
            % (bot, strict, fb)) + gen_exceptions()


def gen_disable(conf):
    s = '# Dibuat oleh sentinel-zyrules.py. Modul yang dimatikan dari panel.\n'
    for nama, (rentang, _) in MODULES.items():
        if conf.get('zy.mod.%s' % nama, 'on') == 'off':
            s += 'SecRuleRemoveById %s\n' % rentang
    return s


def _ipmatch_rules(cidrs, id_awal, aksi, msg, tag, tag2=''):
    """Pecah daftar panjang menjadi beberapa aturan @ipMatch (maks 200 entri)."""
    s = ''
    for i in range(0, len(cidrs), 200):
        potongan = cidrs[i:i + 200]
        s += 'SecRule REMOTE_ADDR "@ipMatch %s" "id:%d,phase:1,%s,t:none,msg:\'%s\',tag:\'zysentinel\',tag:\'%s\'"\n' % (
            ','.join(potongan), id_awal + i // 200, aksi, msg, tag)
    return s


ACME_RULE = (
    '# Validasi sertifikat: HTTP-01 Let\'s Encrypt/ACME (/.well-known/acme-challenge/<token>) dan validasi berkas CA\n'
    '# (/.well-known/pki-validation/<berkas>). Ditaruh PALING AWAL (sebelum daftar hitam IP, aturan bot, dan CRS) dan seluruh engine\n'
    '# dimatikan untuk permintaan itu: dulu hanya aturan fase-1 ZySentinel yang dilewati, sehingga CRS/bot/daftar hitam masih bisa\n'
    '# menolak server validasi CA. Hanya GET/HEAD, token diawali huruf/angka, tanpa query, tanpa ".." atau "/". Aksi ada di aturan\n'
    '# TERAKHIR rantai (aksi kepala rantai dijalankan walau rantai gagal).\n'
    'SecRule REQUEST_URI "@rx ^/\\.well-known/(?:acme-challenge|pki-validation)/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,254}$" '
    '"id:8000010,phase:1,pass,nolog,t:none,chain"\n'
    '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none,setvar:tx.zy_skip=1,ctl:ruleEngine=Off"\n')


def gen_lists(conf):
    s = '# Dibuat oleh sentinel-zyrules.py dari daftar WAF dan allowlist.txt. Jangan edit.\n' + ACME_RULE
    putih = []
    for e in ler_lista('ip_white'):
        c = ip_ke_cidr(e)
        if c is None:
            warn('ip_white: entri tak valid dilewati: %r' % e[:40])
            continue
        putih += [x for x in c if x not in putih]
    fw = [x for x in allowlist_cidr() if x not in putih]
    s += '# Daftar putih IP (WAF): seluruh pemeriksaan dilewati.\n'
    s += _ipmatch_rules(putih, 8000020, 'pass,nolog,ctl:ruleEngine=Off', 'IP daftar putih WAF', 'ip-whitelist')
    s += '# Daftar putih firewall (allowlist.txt): infrastruktur tepercaya, tidak pernah diblokir.\n'
    s += _ipmatch_rules(fw, 8000040, 'pass,nolog,ctl:ruleEngine=Off', 'IP daftar putih firewall', 'ip-whitelist')
    hitam = []
    for e in ler_lista('ip_black'):
        c = ip_ke_cidr(e)
        if c is None:
            warn('ip_black: entri tak valid dilewati: %r' % e[:40])
            continue
        hitam += [x for x in c if x not in hitam]
    s += '# Daftar hitam IP: ditolak.\n'
    s += _ipmatch_rules(hitam, 8000060, 'deny,status:403,log,auditlog', 'ZySentinel: IP daftar hitam', 'attack-ip-blacklist')
    rx_siapkan([url_entri(e)[3] for e in ler_lista('url_white') + ler_lista('url_black')])
    n = 0
    for baris in ler_lista('url_white'):
        cakupan, _mode, _isi, e = url_entri(baris)
        if not rx_valid(e):
            warn('url_white: pola tak valid dilewati: %r' % baris[:40])
            continue
        # cakupan "semua" = WAF dimatikan untuk URL ini; "crs" = hanya aturan bertag OWASP_CRS yang dilewati (aturan ZySentinel tetap
        # memeriksa berkas sensitif, webshell, pemindai). Pilihan "crs" untuk endpoint API JSON tepercaya: biaya CRS per argumen JSON
        # adalah sumber utama overhead (T-172).
        aksi = 'ctl:ruleEngine=Off' if cakupan == 'semua' else 'ctl:ruleRemoveByTag=OWASP_CRS'
        # Dicocokkan ke PATH yang sudah didekode dan dinormalkan (bukan query), supaya
        # "//x", "/./x", "/%78" dan "?a=/x" tidak menyamar. ctl ditaruh di aturan
        # TERAKHIR rantai: Coraza dan ModSecurity v2 menjalankan aksi kepala rantai
        # walau rantai gagal, sehingga pemeriksaan traversal tidak berguna di kepala.
        s += ('SecRule REQUEST_FILENAME "@rx %s" "id:%d,phase:1,pass,nolog,t:none,t:removeNulls,t:urlDecodeUni,t:normalizePath,chain"\n'
              '    SecRule REQUEST_URI "!@rx (?:^|[/\\x5c])\\.\\.(?:[/\\x5c;?]|$)" "t:none,t:removeNulls,t:urlDecodeUni,t:urlDecodeUni,%s"\n') % (seclang_rx(e), 8001000 + n, aksi)
        n += 1
        if n >= 400:
            warn('url_white: maksimal 400 pola, sisanya dilewati')
            break
    n = 0
    for baris in ler_lista('url_black'):
        e = url_entri(baris)[3]
        if not rx_valid(e):
            warn('url_black: pola tak valid dilewati: %r' % baris[:40])
            continue
        # Path dinormalkan (//, /./, %xx, \\) dan URI mentah diperiksa; huruf besar/kecil
        # tidak membedakan. Dulu hanya REQUEST_URI mentah: "//private/x" lolos.
        s += ('SecRule REQUEST_FILENAME|REQUEST_URI "@rx (?i)%s" "id:%d,phase:1,deny,status:403,log,auditlog,t:none,t:removeNulls,t:urlDecodeUni,t:normalizePathWin,'
              "msg:'ZySentinel: URL daftar hitam',tag:'zysentinel',tag:'attack-url-blacklist',severity:'CRITICAL',"
              'logdata:\'%%{MATCHED_VAR}\'"\n') % (seclang_rx(e), 8001500 + n)
        n += 1
        if n >= 400:
            warn('url_black: maksimal 400 pola, sisanya dilewati')
            break
    return s


def crs_grup():
    """Daftar berkas CRS: [(nama, path)] terurut."""
    d = CRS_DIR + '/rules'
    try:
        return [(f[:-5], '%s/%s' % (d, f)) for f in sorted(os.listdir(d)) if f.endswith('.conf')]
    except FileNotFoundError:
        return []


def crs_ada():
    return os.path.isfile(CRS_DIR + '/crs-setup.conf.example') and bool(crs_grup())


def gen_crs_setup(conf):
    src = ''
    try:
        src = open(CRS_DIR + '/crs-setup.conf.example').read()
    except FileNotFoundError:
        return ''
    pl = conf_int(conf, 'zy.paranoia', 1, 1, 4)
    th = conf_int(conf, 'zy.threshold', 5, 1, 100)
    extra = ''
    # CRS menolak SEMUA header Expect (kebijakan smuggling). Klien sah mengirim
    # "Expect: 100-continue" otomatis untuk badan besar (curl > 1 MB, .NET HttpClient, beberapa
    # pustaka mobile), sehingga unggahan/API mereka diblokir. Hanya nilai 100-continue yang
    # dilonggarkan; nilai Expect lain tetap ditolak oleh aturan 8000216 (before.conf).
    try:
        init = open(CRS_DIR + '/rules/REQUEST-901-INITIALIZATION.conf').read()
        m = re.search(r"tx\.restricted_headers_basic=([^'\"]*)", init)
        if m and '/expect/' in m.group(1):
            nilai = ' '.join(t for t in m.group(1).split() if t != '/expect/')
            extra = 'SecAction "id:900250,phase:1,nolog,pass,t:none,setvar:\'tx.restricted_headers_basic=%s\'"\n' % nilai
    except Exception:
        pass
    return (src + '\n# --- ZySentinel ---\n'
            'SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d"\n'
            'SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"\n'
            % (pl, th, th * 2) + extra)


def premium_include():
    """Jalur modul premium waf_premium (DATA SecLang) bila lisensi saat ini mengizinkan dan semua pemeriksaan
    (hash, tanda tangan server, kebijakan data-saja) lolos lagi; selain itu None. Tidak pernah menjalankan isinya."""
    return None      # edisi Free: modul aturan premium (waf_premium) adalah fitur Max


def gen_vpatch():
    """Virtual patch CVE Advisor (waf/zyrules/vpatch/*.conf, ditulis sentinel-cve.py dari feed bertanda tangan) digabung ke
    gen/vpatch.conf. Hanya dengan fitur cve_vpatch; setiap berkas diperiksa ulang kebijakan data-saja (rentang id
    8200000-8299999); berkas yang tidak lolos dilewati. Mengembalikan jalur gen/vpatch.conf atau None."""
    return None      # edisi Free: virtual patch CVE Advisor (cve_vpatch) adalah fitur Max


# ------------------------------------------------- aturan bawaan web server --
# Lapisan kedua untuk berkas dan folder sensitif, ditulis dalam format ASLI tiap web server (nginx location, Apache LocationMatch,
# OpenLiteSpeed RewriteRule) dari SATU daftar di bawah, yang mengikuti aturan WAF dengan modul yang sama (8000101-8000108, 8000121,
# 8000441, 8000443). Berlaku hanya pada mode Block dan bila modulnya menyala; tidak bergantung pada engine WAF (Coraza/ModSecurity
# yang gagal dimuat, mode Monitor, atau permintaan yang dikecualikan CRS). /.well-known/ (ACME acme-challenge, pki-validation,
# security.txt, assetlinks, passkey) TIDAK pernah ditolak lapisan ini; skrip di /.well-known tetap ditolak WAF (8000443).
# Regex PCRE (nginx, Apache, dan OLS semuanya PCRE), dicocokkan tanpa membedakan huruf besar/kecil ke path URL yang sudah didekode.
NATIVE = (
    ('sensitive_files', 'repositori kode (.git/.svn/.hg)', r'(^|/)\.(git|svn|hg|bzr|cvs)(ignore|attributes|config|modules|keep)?(/|$)'),
    ('sensitive_files', 'berkas lingkungan (.env)', r'(^|/)\.env([._-][a-z0-9._-]*)?(/|$)'),
    ('sensitive_files', 'kendali akses (.htaccess/.htpasswd/.user.ini)', r'(^|/)(\.ht(access|passwd|digest|group|users)([._~-][a-z0-9._~-]*)?|\.(user|php)\.ini)$'),
    ('sensitive_files', 'dotfile kredensial dan folder konfigurasi',
     r'(^|/)(\.(bash_history|bashrc|zsh_history|zshrc|sh_history|mysql_history|psql_history|rediscli_history|python_history|node_repl_history|lesshst|viminfo|netrc|npmrc|yarnrc|pypirc|pgpass|my\.cnf|s3cfg|boto|git-credentials|gitconfig|msmtprc|dockercfg|ds_store)|\.(ssh|aws|azure|kube|docker|gnupg|gcloud|idea|vscode|terraform|ansible|bundle|cargo|gem|npm)(/|$))'),
    ('sensitive_files', 'kunci privat dan sertifikat', r'((^|/)(id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|authorized_keys|known_hosts)$|\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx|gpg)$)'),
    ('sensitive_files', 'cadangan, dump database, berkas sementara',
     r'(\.(bak|backup|old|orig|save|swp|swo|sql|sqlite3?|dump)$|~$|\.(php|inc|ini|conf|config|cfg|ya?ml|json|xml|env)\.(bak|backup|old|orig|save|swp|swo|txt|dist|tmp|zip)$)'),
    ('sensitive_files', 'konfigurasi aplikasi dan infrastruktur',
     r'((^|/)(wp-config\.php[._~-][a-z0-9._~-]*|web\.config|docker-compose(\.[a-z0-9-]+)?\.ya?ml|dockerfile(\.[a-z0-9-]+)?|vagrantfile|terraform\.tfstate(\.backup)?|\.circleci/|\.github/workflows/)|\.(tfstate|tfvars)$)'),
    ('webshell', 'skrip di folder unggahan',
     r'^/(uploads?|uploadfiles|attachments?|forumdata|avatars?|wp-content/uploads|public/uploads?|storage/app/public)/.*\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|cgi|pl)$'),
    ('probe_secrets', 'berkas/folder berawalan titik kecuali /.well-known', r'^(?!/\.well-known(/|$)).*(^|/)\.[^/.][^/]*'),
    ('app_laravel', 'internal Laravel & kredensial',
     r'(^|/)(storage/(oauth-(private|public)\.key|logs/laravel(-[0-9-]+)?\.log)|bootstrap/cache/(config|routes-v[0-9]+|services)\.php|database/database\.sqlite|artisan)$'),
    ('app_codeigniter', 'internal CodeIgniter',
     r'(^|/)(application/(config/(database|config)\.php|logs/log-[0-9-]+\.php)|writable/(logs/log-[0-9-]+\.log|session/|cache/)|app/Config/(Database|App)\.php|spark)$'),
    ('app_cms', 'kredensial CMS umum',
     r'(^|/)(configuration\.php([._~-][a-z0-9._-]*)?|sites/default/(settings|settings\.local)\.php|app/etc/(local\.xml|env\.php)|app/config/parameters\.php)$'),
    ('app_nodejs', 'log build & manifest Node.js',
     r'(^|/)(npm-debug\.log|yarn-error\.log|pnpm-debug\.log|\.strapi-updater\.json|build-manifest\.json|prerender-manifest\.json)$'),
    ('app_python', 'bytecode & SQLite Python',
     r'(^|/)(__pycache__/|\.pytest_cache/|\.coverage$|manage\.py$|wsgi\.py$|asgi\.py$|db\.sqlite3$|\.(pyc|pyo)$)'),
)
NATIVE_MAKS_PUTIH = 8000     # panjang gabungan pola url_white yang masih ditanam sebagai pengecualian


def native_aturan(conf):
    """(daftar (nama, regex), pesan). Kosong bila mode bukan Block. Pola url_white (dicocokkan ke path seperti di WAF) menjadi
    pengecualian di depan setiap regex, supaya URL yang sengaja diizinkan admin juga tidak ditolak lapisan bawaan."""
    mode = conf.get('mode', 'block')
    if mode != 'block':
        return [], 'mode %s: aturan bawaan tidak aktif (hanya mode Block)' % mode
    # hanya entri cakupan "semua": cakupan "crs" tetap diperiksa aturan bawaan berkas sensitif (bukan aturan CRS)
    putih = [x[3] for x in map(url_entri, ler_lista('url_white')) if x[0] == 'semua' and rx_valid(x[3])][:400]
    pre = ''
    if putih:
        gab = '|'.join('(?:%s)' % e for e in putih)
        if len(gab) > NATIVE_MAKS_PUTIH:
            return [], 'url_white terlalu panjang untuk lapisan bawaan (%d karakter): hanya WAF yang aktif' % len(gab)
        pre = '^(?!.*?(?:%s))' % gab
    out = []
    for modul, nama, rx in NATIVE:
        if conf.get('zy.mod.%s' % modul, 'on') == 'off':
            continue
        if pre:
            r = pre + (rx[1:] if rx.startswith('^') else '.*?' + ('(?:%s)' % rx))
        else:
            r = rx
        try:
            re.compile(r, re.I)
        except re.error as ex:
            warn('aturan bawaan %s tidak valid: %s' % (nama, ex))
            continue
        out.append((nama, r))
    return out, '%d aturan aktif' % len(out)


def gen_native(conf):
    """Isi berkas aturan bawaan per web server: {'nginx': ..., 'apache': ..., 'ols': ...}."""
    aturan, pesan = native_aturan(conf)
    kepala = '# Dibuat oleh sentinel-zyrules.py (aturan bawaan berkas/folder sensitif, %s). Jangan edit.\n' % pesan
    ng, ap, ol = kepala, kepala, kepala
    if aturan:
        ap += '<IfModule authz_core_module>\n'
        ol += '<IfModule mod_rewrite.c>\n    RewriteEngine on\n'
    for nama, r in aturan:
        q = r.replace('"', '\\x22')
        ng += '# %s\nlocation ~* "%s" {\n    return 403;\n}\n' % (nama, q)
        ap += '    # %s\n    <LocationMatch "(?i)%s">\n        Require all denied\n    </LocationMatch>\n' % (nama, q)
        ol += '    # %s\n    RewriteRule %s - [F,NC,L]\n' % (nama, r.replace(' ', '\\x20'))
    if aturan:
        ap += '</IfModule>\n'
        ol += '</IfModule>\n'
    return {'nginx': ng, 'apache': ap, 'ols': ol}


# Direktif yang dikenal Coraza/ModSecurity v3 tetapi TIDAK oleh ModSecurity v2 (Apache, OpenLiteSpeed): ModSecurity v2 menolak seluruh
# konfigurasi bila menemuinya ("Invalid command"). Varian main-v2.conf memakai base-v2.conf tanpa direktif ini; main.conf (Coraza) tetap utuh.
V2_TIDAK_DIDUKUNG = ('SecArgumentsLimit',)


def v2_lewati():
    """Berkas CRS yang dilewati di varian ModSecurity v2 karena ModSecurity v2 terpasang terlalu lama untuk sintaksnya
    (mis. 2.9.5 Ubuntu 22.04 tidak mengenal MULTIPART_PART_HEADERS). Daftar ditulis sentinel-waf.sh saat uji konfigurasi gagal."""
    try:
        with open(GEN + '/modsec2-skip.list') as f:
            return set(x.strip() for x in f if x.strip() and '/' not in x)
    except OSError:
        return set()


def gen_base_v2(base_txt):
    baris = [ln for ln in base_txt.split('\n') if not (ln.split() and ln.split()[0] in V2_TIDAK_DIDUKUNG)]
    return '\n'.join(baris)


def gen_main(conf, v2=False):
    ada = crs_ada()
    inc = ['# Dibuat oleh sentinel-zyrules.py. Dimuat oleh semua vhost (nginx/Coraza, Apache/OpenLiteSpeed ModSecurity).',
           'Include %s/%s' % (GEN, 'base-v2.conf' if v2 else 'base.conf'),
           'Include %s/zysentinel-config.conf' % ZY_DIR,
           'Include %s/zysentinel-config.local.conf' % ZY_DIR,
           'Include %s/settings.conf' % GEN,
           'Include %s/lists.conf' % GEN]
    if ada:
        inc.append('Include %s/crs-setup.conf' % GEN)
    inc.append('Include %s/zysentinel-before.conf' % ZY_DIR)
    if ada:
        for nama, path in crs_grup():
            if conf.get('rule.%s' % nama, 'on') != 'off':
                if v2 and os.path.basename(path) in v2_lewati():
                    inc.append('# dilewati (ModSecurity v2 terlalu lama untuk berkas ini): %s' % os.path.basename(path))
                    continue
                inc.append('Include %s' % path)
    inc.append('Include %s/zysentinel-after.conf' % ZY_DIR)
    prem = premium_include()
    if prem:
        inc.append('# modul premium (paket Max), dilewati bila lisensi tidak mengizinkan')
        inc.append('Include %s' % prem)
    vp = gen_vpatch()
    if vp:
        inc.append('# virtual patch CVE Advisor (paket Max, feed bertanda tangan)')
        inc.append('Include %s' % vp)
    inc.append('Include %s/disable.conf' % GEN)
    inc.append('Include %s/zysentinel-exclusions.local.conf' % ZY_DIR)
    return '\n'.join(inc) + '\n'


def lic_ref():
    """Sidik lisensi publik untuk halaman blokir (prioritas 6, 30 Okt 2026): sha256("zysref|" + kode)[:12], sama dengan
    integrity.ref_lisensi di server. Satu arah (bukan kode lisensi); dashboard developer bisa mencari lisensi dari ref yang terlihat di
    tangkapan layar halaman blokir build yang beredar tanpa izin. Tanpa kode lisensi (Free/pengembangan): "free"."""
    try:
        aku = os.path.dirname(os.path.abspath(__file__))
        if aku not in sys.path:
            sys.path.insert(0, aku)
        import sentinel_license as sl
        kode = sl.get_code() if hasattr(sl, 'get_code') else ''
    except Exception:
        kode = ''
    return hashlib.sha256(('zysref|' + kode).encode()).hexdigest()[:12] if kode else 'free'


def gen_pages():
    src = ZY_DIR + '/html/zysentinel-block.html'
    if not os.path.isfile(src):
        warn('halaman blocker tidak ditemukan: %s' % src)
        return
    html = open(src, encoding='utf-8').read().replace('{{LIC_REF}}', lic_ref())
    for ws, ip, rid in (
            ('nginx', '{{CLIENT_IP}}', '{{REQ_ID}}'),
            ('apache', '<!--#echo var="REMOTE_ADDR" -->', '<!--#echo var="UNIQUE_ID" -->'),
            ('ols', '&mdash;', '&mdash;')):
        d = '%s/html/%s' % (GEN, ws)
        os.makedirs(d, exist_ok=True)
        isi = html.replace('{{CLIENT_IP}}', ip).replace('{{REQ_ID}}', rid)
        p = d + '/__zysentinel_403.html'
        with open(p, 'w', encoding='utf-8') as f:
            f.write(isi)
        os.chmod(p, 0o644)
        os.chmod(d, 0o755)


def pastikan_log():
    """Berkas log audit harus bisa ditulis user web server.

    /www/wwwlogs dimiliki user web server (www), jadi isinya dikendalikan penyerang yang menguasai situs.
    chown/chmod berbasis path (mengikuti symlink) membuat root mengubah pemilik berkas sistem mana pun yang
    ditunjuk symlink bernama zysentinel_waf_audit.jsonl. Di sini berkas dibuka O_NOFOLLOW, harus berkas biasa
    dengan satu hard link, dan pemilik/mode diubah lewat fd yang sama."""
    d = os.path.dirname(AUDIT_LOG)
    try:
        os.makedirs(d, exist_ok=True)
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o640)
    except OSError as ex:
        warn('log audit %s tidak bisa disiapkan: %s' % (AUDIT_LOG, ex))
        return
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            warn('log audit %s bukan berkas biasa bertaut tunggal (symlink/hard link?); pemilik dan mode tidak diubah' % AUDIT_LOG)
            return
        try:
            import pwd
            u = pwd.getpwnam(WEB_USER)
            os.fchown(fd, u.pw_uid, u.pw_gid)
            os.fchmod(fd, 0o640)
        except Exception:
            # user web server tidak dikenal: jangan kunci log dari mereka
            os.fchmod(fd, 0o666)
    except OSError as ex:
        warn('log audit %s tidak bisa disiapkan: %s' % (AUDIT_LOG, ex))
    finally:
        os.close(fd)


def build():
    for f in STATIC:
        if not os.path.isfile('%s/%s' % (ZY_DIR, f)):
            sys.stderr.write('[zyrules] GALAT: berkas ruleset hilang: %s/%s\n' % (ZY_DIR, f))
            return 1
    conf = conf_baca()
    for f in ('zysentinel-config.local.conf', 'zysentinel-exclusions.local.conf'):
        p = '%s/%s' % (ZY_DIR, f)
        if not os.path.exists(p):
            with open(p, 'w') as fh:
                fh.write('# Pengaturan lokal; tidak ditimpa pembaruan plugin.\n')
            os.chmod(p, 0o644)
    tulis('base.conf', gen_base(conf))
    tulis('base-v2.conf', gen_base_v2(gen_base(conf)))
    tulis('settings.conf', gen_settings(conf))
    tulis('disable.conf', gen_disable(conf))
    tulis('lists.conf', gen_lists(conf))
    if crs_ada():
        tulis('crs-setup.conf', gen_crs_setup(conf))
    tulis('main.conf', gen_main(conf))
    tulis('main-v2.conf', gen_main(conf, v2=True))       # ModSecurity v2 (Apache/OpenLiteSpeed)
    for ws, isi in gen_native(conf).items():
        tulis('native/%s.conf' % ws, isi)
    gen_pages()
    pastikan_log()
    # izin baca untuk user web server pada seluruh pohon ruleset
    for root, dirs, files in os.walk(ZY_DIR):
        os.chmod(root, 0o755)
        for fn in files:
            p = os.path.join(root, fn)
            if not os.access(p, os.R_OK | os.W_OK) or (os.stat(p).st_mode & 0o004) == 0:
                os.chmod(p, 0o644)
    print('main=%s' % (GEN + '/main.conf'))
    print('crs=%s' % ('ya' if crs_ada() else 'tidak'))
    print('peringatan=%d' % len(PERINGATAN))
    return 0


def status():
    conf = conf_baca()
    mod = {}
    for nama, (rentang, ket) in MODULES.items():
        mod[nama] = {'aktif': conf.get('zy.mod.%s' % nama, 'on') != 'off', 'rentang_id': rentang, 'keterangan': ket}
    listas = {n: len(ler_lista(n)) for n in LISTS}
    hasil = {
        'mode': conf.get('mode', 'block') if conf.get('mode', 'block') in MODE_ENGINE else 'block',
        'modul': mod,
        'pengaturan': {
            'bot_level': conf_int(conf, 'zy.bot_level', 1, 0, 3),
            'strict': conf_int(conf, 'zy.strict', 0, 0, 1),
            'fallback': conf_int(conf, 'zy.fallback', 1, 0, 1),
            'paranoia': conf_int(conf, 'zy.paranoia', 1, 1, 4),
            'body_nofiles_kb': conf_int(conf, 'zy.body_nofiles_kb', 128, 16, 4096),
            'body_total_mb': conf_int(conf, 'zy.body_total_mb', 50, 1, 512),
            'threshold': conf_int(conf, 'zy.threshold', 5, 1, 100),
        },
        'daftar': listas,
        'crs': {'ada': crs_ada(), 'grup': [{'nama': n, 'aktif': conf.get('rule.%s' % n, 'on') != 'off'} for n, _ in crs_grup()]},
        'terpasang': all(os.path.isfile('%s/%s' % (ZY_DIR, f)) for f in STATIC),
        'tersusun': os.path.isfile(GEN + '/main.conf'),
        'main': GEN + '/main.conf',
        'audit_log': AUDIT_LOG,
    }
    print(json.dumps(hasil, ensure_ascii=False))
    return 0


def main():
    perintah = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if perintah == 'build':
        return build()
    if perintah == 'status':
        return status()
    sys.stderr.write('Penggunaan: %s [build|status]\n' % sys.argv[0])
    return 2


if __name__ == '__main__':
    sys.exit(main())
