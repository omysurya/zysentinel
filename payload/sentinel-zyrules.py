#!/usr/bin/env python3
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
import json
import shutil
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


def ip_ke_cidr(entri):
    """IPv4 tunggal, CIDR, atau rentang a-b -> daftar string CIDR (tanpa /32 untuk host).
    Mengembalikan None bila tidak valid."""
    entri = (entri or '').strip()
    try:
        if '-' in entri:
            a, b = [x.strip() for x in entri.split('-')]
            ia, ib = _v4(a), _v4(b)
            if ia is None or ib is None or int(ia) > int(ib):
                return None
            return [str(n) if n.prefixlen != 32 else str(n.network_address)
                    for n in ipaddress.summarize_address_range(ia, ib)]
        ip_s, sep, pre = entri.partition('/')
        if _v4(ip_s) is None:
            return None
        if sep:
            if not re.fullmatch(r'(?:0|[1-9][0-9]?)', pre) or int(pre) > 32:
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
                t = line.rstrip('\n')
                if t.strip() and not t.lstrip().startswith('#'):
                    out.append(t.strip())
    except FileNotFoundError:
        pass
    return out


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
    if pola not in _RX_CACHE:
        rx_siapkan([pola])
    h = _RX_CACHE.get(pola)
    if h == 'lambat':
        warn('pola dibuang karena terlalu lambat dievaluasi (risiko ReDoS): %r' % pola[:40])
    return h == 'ok'


# ----------------------------------------------------------------- penulis --
def tulis(nama, isi, mode=0o644):
    os.makedirs(GEN, exist_ok=True)
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


def gen_lists(conf):
    s = '# Dibuat oleh sentinel-zyrules.py dari daftar WAF dan allowlist.txt. Jangan edit.\n'
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
    rx_siapkan(list(ler_lista('url_white')) + list(ler_lista('url_black')))
    n = 0
    for e in ler_lista('url_white'):
        if not rx_valid(e):
            warn('url_white: pola tak valid dilewati: %r' % e[:40])
            continue
        # Dicocokkan ke PATH yang sudah didekode dan dinormalkan (bukan query), supaya
        # "//x", "/./x", "/%78" dan "?a=/x" tidak menyamar. ctl ditaruh di aturan
        # TERAKHIR rantai: Coraza dan ModSecurity v2 menjalankan aksi kepala rantai
        # walau rantai gagal, sehingga pemeriksaan traversal tidak berguna di kepala.
        s += ('SecRule REQUEST_FILENAME "@rx %s" "id:%d,phase:1,pass,nolog,t:none,t:removeNulls,t:urlDecodeUni,t:normalizePath,chain"\n'
              '    SecRule REQUEST_URI "!@rx (?:^|[/\\x5c])\\.\\.(?:[/\\x5c;?]|$)" "t:none,t:removeNulls,t:urlDecodeUni,t:urlDecodeUni,ctl:ruleEngine=Off"\n') % (seclang_rx(e), 8001000 + n)
        n += 1
        if n >= 400:
            warn('url_white: maksimal 400 pola, sisanya dilewati')
            break
    n = 0
    for e in ler_lista('url_black'):
        if not rx_valid(e):
            warn('url_black: pola tak valid dilewati: %r' % e[:40])
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


def gen_main(conf):
    ada = crs_ada()
    inc = ['# Dibuat oleh sentinel-zyrules.py. Dimuat oleh semua vhost (nginx/Coraza, Apache/OpenLiteSpeed ModSecurity).',
           'Include %s/base.conf' % GEN,
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
                inc.append('Include %s' % path)
    inc.append('Include %s/zysentinel-after.conf' % ZY_DIR)
    inc.append('Include %s/disable.conf' % GEN)
    inc.append('Include %s/zysentinel-exclusions.local.conf' % ZY_DIR)
    return '\n'.join(inc) + '\n'


def gen_pages():
    src = ZY_DIR + '/html/zysentinel-block.html'
    if not os.path.isfile(src):
        warn('halaman blocker tidak ditemukan: %s' % src)
        return
    html = open(src, encoding='utf-8').read()
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
    """Berkas log audit harus bisa ditulis user web server."""
    d = os.path.dirname(AUDIT_LOG)
    try:
        os.makedirs(d, exist_ok=True)
        if not os.path.exists(AUDIT_LOG):
            open(AUDIT_LOG, 'a').close()
        try:
            import pwd
            u = pwd.getpwnam(WEB_USER)
            os.chown(AUDIT_LOG, u.pw_uid, u.pw_gid)
            os.chmod(AUDIT_LOG, 0o640)
        except Exception:
            # user web server tidak dikenal: jangan kunci log dari mereka
            os.chmod(AUDIT_LOG, 0o666)
    except Exception as ex:
        warn('log audit %s tidak bisa disiapkan: %s' % (AUDIT_LOG, ex))


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
    tulis('settings.conf', gen_settings(conf))
    tulis('disable.conf', gen_disable(conf))
    tulis('lists.conf', gen_lists(conf))
    if crs_ada():
        tulis('crs-setup.conf', gen_crs_setup(conf))
    tulis('main.conf', gen_main(conf))
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
