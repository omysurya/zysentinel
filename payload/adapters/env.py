# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Deteksi lingkungan server ZySentinel: OS, tipe panel, web server (terpasang/aktif/versi), dan tata letak default.

Tujuan defensif: semua komponen (guardd, antivirus, sweeper, upload protection, process guard, WAF, UI) harus tahu LEBIH DULU
di lingkungan apa mereka berjalan, bukan menebak lewat keberadaan /www/wwwroot milik aaPanel. Urutan keputusan:
  1. OS (keluarga deb/rpm/alpine + versi) menentukan lokasi bawaan distro (apache2 vs httpd, sites-enabled vs conf.d, dst.);
  2. panel hosting: aaPanel, cPanel/WHM, DirectAdmin, CyberPanel, Plesk (dilaporkan), atau standalone;
  3. web server: nginx, Apache, OpenLiteSpeed, LiteSpeed Enterprise, Caddy: terpasang? aktif? versi? berkas konfigurasi dan log;
  4. keadaan: `panel` | `standalone` (ada web server) | `fresh` (belum ada web server: pakai lokasi bawaan OS, vhost dibaca
     ulang saat web server dipasang).
Hanya stdlib. Uji memakai ZYS_ENV_ROOT (awalan sistem berkas) dan ZYS_ENV_ACTIVE (daftar web server aktif) tanpa menyentuh host.

CLI:  python3 env.py detect [--json] | panel | sites [--tsv] | guardd-conf | shell
"""
import glob
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

ROOT = os.environ.get('ZYS_ENV_ROOT', '')
CACHE = os.environ.get('ZYS_ENV_CACHE', '/www/server/sentinel/etc/env.json')
SHELL_ENV = os.environ.get('ZYS_ENV_SHELL', '/www/server/sentinel/etc/env.sh')


def P(path):
    return (ROOT + path) if ROOT else path


def isdir(p):
    return os.path.isdir(P(p))


def isfile(p):
    return os.path.isfile(P(p))


def readtext(p, limit=1_000_000):
    try:
        with open(P(p), 'r', errors='replace') as f:
            return f.read(limit)
    except OSError:
        return ''


# ---------------------------------------------------------------- OS
def detect_os():
    d = {}
    for ln in readtext('/etc/os-release').splitlines():
        if '=' in ln:
            k, _, v = ln.partition('=')
            d[k.strip()] = v.strip().strip('"')
    oid = d.get('ID', '').lower()
    like = d.get('ID_LIKE', '').lower().split()
    ver = d.get('VERSION_ID', '')
    fam = 'other'
    if oid in ('debian', 'ubuntu', 'linuxmint', 'raspbian', 'kali') or 'debian' in like or 'ubuntu' in like:
        fam = 'deb'
    elif oid in ('rhel', 'centos', 'rocky', 'almalinux', 'ol', 'fedora', 'amzn', 'cloudlinux') or 'rhel' in like or 'fedora' in like:
        fam = 'rpm'
    elif oid == 'alpine':
        fam = 'alpine'
    pm = {'deb': 'apt', 'rpm': 'dnf' if (isfile('/usr/bin/dnf') or not isfile('/usr/bin/yum')) else 'yum', 'alpine': 'apk'}.get(fam, '')
    major = ver.split('.')[0] if ver else ''
    return {'id': oid, 'name': d.get('PRETTY_NAME', oid), 'version': ver, 'major': major, 'family': fam, 'pm': pm,
            'codename': d.get('VERSION_CODENAME', '')}


# ---------------------------------------------------------------- panel
def _port_from(path, pattern, default=0):
    m = re.search(pattern, readtext(path), re.M)
    try:
        return int(m.group(1)) if m else default
    except ValueError:
        return default


def detect_panel():
    """Tipe panel hosting. Urutan pasti; satu server hampir selalu satu panel."""
    if isfile('/www/server/panel/class/public.py') or isfile('/www/server/panel/data/port.pl'):
        port = _port_from('/www/server/panel/data/port.pl', r'^\s*(\d{2,5})\s*$', 8888)
        return {'type': 'aapanel', 'name': 'aaPanel', 'version': '', 'root': '/www/server/panel', 'ports': [port]}
    if isfile('/usr/local/cpanel/version'):
        return {'type': 'cpanel', 'name': 'cPanel/WHM', 'version': readtext('/usr/local/cpanel/version').strip()[:40],
                'root': '/usr/local/cpanel', 'ports': [2082, 2083, 2086, 2087, 2095, 2096]}
    if isfile('/usr/local/directadmin/directadmin'):
        port = _port_from('/usr/local/directadmin/conf/directadmin.conf', r'^\s*port\s*=\s*(\d+)', 2222)
        return {'type': 'directadmin', 'name': 'DirectAdmin', 'version': '', 'root': '/usr/local/directadmin', 'ports': [port]}
    if isdir('/usr/local/CyberCP'):
        return {'type': 'cyberpanel', 'name': 'CyberPanel', 'version': readtext('/usr/local/CyberCP/version.txt').strip()[:40],
                'root': '/usr/local/CyberCP', 'ports': [8090, 7080]}
    if isdir('/usr/local/psa'):
        return {'type': 'plesk', 'name': 'Plesk', 'version': readtext('/usr/local/psa/version').strip()[:40],
                'root': '/usr/local/psa', 'ports': [8443]}
    return {'type': 'none', 'name': 'standalone', 'version': '', 'root': '', 'ports': []}


# ---------------------------------------------------------------- web server
def _run_version(argv, pattern):
    if ROOT or os.environ.get('ZYS_ENV_NOEXEC'):
        return ''
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        m = re.search(pattern, (p.stderr or '') + (p.stdout or ''))
        return m.group(1) if m else ''
    except Exception:
        return ''


def _first(paths):
    for p in paths:
        if isfile(p) and (ROOT or os.access(p, os.X_OK)):
            return p
    return ''


def _first_file(paths):
    for p in paths:
        if isfile(p):
            return p
    return ''


def _procs():
    """Nama proses yang sedang berjalan (comm). Uji: ZYS_ENV_ACTIVE='nginx,apache2'."""
    if 'ZYS_ENV_ACTIVE' in os.environ:
        return set(x for x in os.environ['ZYS_ENV_ACTIVE'].split(',') if x)
    out = set()
    try:
        for pid in os.listdir('/proc'):
            if pid.isdigit():
                try:
                    with open('/proc/%s/comm' % pid) as f:
                        out.add(f.read().strip())
                except OSError:
                    pass
    except OSError:
        pass
    return out


def detect_webservers(os_info, panel):
    """Daftar web server yang TERPASANG (dan apakah aktif), dengan lokasi konfigurasi/log menurut panel + keluarga OS."""
    fam, ptype = os_info['family'], panel['type']
    procs = _procs()
    res = []

    # --- nginx
    nbin = _first(['/www/server/nginx/sbin/nginx', '/usr/sbin/nginx', '/usr/local/sbin/nginx', '/usr/bin/nginx', '/opt/nginx/sbin/nginx'])
    if nbin:
        aap = nbin.startswith('/www/server/nginx')
        conf = '/www/server/nginx/conf/nginx.conf' if aap else '/etc/nginx/nginx.conf'
        if aap:
            vh = ['/www/server/panel/vhost/nginx', '/www/server/nginx/conf']
            logs, mod = ['/www/wwwlogs'], '/www/server/nginx/modules'
            pid = '/www/server/nginx/logs/nginx.pid'
        else:
            vh = ['/etc/nginx/sites-enabled', '/etc/nginx/conf.d']
            if ptype == 'directadmin':
                vh += ['/etc/nginx/directadmin-vhosts.conf', '/etc/nginx/nginx-includes']
            if ptype == 'cpanel':
                vh += ['/etc/nginx/conf.d/users']
            logs = ['/var/log/nginx'] + (['/var/log/nginx/domains'] if ptype == 'directadmin' else [])
            mod = '/usr/lib/nginx/modules' if (fam == 'deb' or isdir('/usr/lib/nginx/modules')) else '/usr/lib64/nginx/modules'
            pid = '/run/nginx.pid'
        res.append({'type': 'nginx', 'bin': nbin, 'version': _run_version([P(nbin), '-v'], r'nginx/([0-9.]+)'), 'conf': conf,
                    'vhost_paths': vh, 'log_dirs': logs, 'modules_dir': mod, 'pid': pid, 'service': 'nginx',
                    'active': 'nginx' in procs, 'managed_by': 'aapanel' if aap else 'distro'})

    # --- apache
    abin = _first(['/www/server/apache/bin/httpd', '/usr/local/apache/bin/httpd', '/usr/sbin/apache2', '/usr/sbin/httpd', '/usr/local/sbin/httpd'])
    if abin:
        aap = abin.startswith('/www/server/apache')
        if aap:
            conf, vh = '/www/server/apache/conf/httpd.conf', ['/www/server/panel/vhost/apache']
            logs, pid, svc = ['/www/wwwlogs'], '/www/server/apache/logs/httpd.pid', 'httpd'
        elif ptype == 'cpanel':
            conf = '/etc/apache2/conf/httpd.conf'
            vh = ['/etc/apache2/conf/httpd.conf', '/etc/apache2/conf.d']
            logs, pid, svc = ['/var/log/apache2/domlogs', '/etc/apache2/logs/domlogs'], '/etc/apache2/logs/httpd.pid', 'httpd'
        elif ptype == 'directadmin':
            conf = '/etc/httpd/conf/httpd.conf'
            vh = ['/usr/local/directadmin/data/users/*/httpd.conf', '/etc/httpd/conf/extra', '/etc/httpd/conf.d']
            logs, pid, svc = ['/var/log/httpd/domains', '/var/log/httpd'], '/run/httpd.pid', 'httpd'
        elif fam == 'deb' or abin.endswith('apache2'):
            conf, vh = '/etc/apache2/apache2.conf', ['/etc/apache2/sites-enabled', '/etc/apache2/conf-enabled']
            logs, pid, svc = ['/var/log/apache2'], '/run/apache2/apache2.pid', 'apache2'
        else:
            conf, vh = '/etc/httpd/conf/httpd.conf', ['/etc/httpd/conf.d', '/etc/httpd/conf']
            logs, pid, svc = ['/var/log/httpd'], '/run/httpd/httpd.pid', 'httpd'
        res.append({'type': 'apache', 'bin': abin, 'version': _run_version([P(abin), '-v'], r'Apache/([0-9.]+)'), 'conf': conf,
                    'vhost_paths': vh, 'log_dirs': logs, 'modules_dir': '', 'pid': pid, 'service': svc,
                    'active': bool(procs & {'apache2', 'httpd'}), 'managed_by': 'aapanel' if aap else ('panel' if ptype in ('cpanel', 'directadmin') else 'distro')})

    # --- OpenLiteSpeed / LiteSpeed Enterprise (/usr/local/lsws)
    olsbin = _first(['/usr/local/lsws/bin/openlitespeed'])
    lsbin = _first(['/usr/local/lsws/bin/lshttpd', '/usr/local/lsws/bin/litespeed'])
    if olsbin or lsbin:
        ent = bool(lsbin) and not olsbin
        res.append({'type': 'litespeed' if ent else 'openlitespeed', 'bin': olsbin or lsbin,
                    'version': readtext('/usr/local/lsws/VERSION').strip()[:30] or '', 'conf': '/usr/local/lsws/conf/httpd_config.xml' if ent else '/usr/local/lsws/conf/httpd_config.conf',
                    'vhost_paths': ['/usr/local/lsws/conf/vhosts/*/vhost.conf', '/usr/local/lsws/conf/vhosts/*/vhconf.conf'],
                    'log_dirs': ['/usr/local/lsws/logs'] + ['/home/*/logs'] if ptype == 'cyberpanel' else ['/usr/local/lsws/logs'],
                    'modules_dir': '', 'pid': '/tmp/lshttpd/lshttpd.pid', 'service': 'lsws' if not ent else 'lshttpd',
                    'active': bool(procs & {'openlitespeed', 'litespeed', 'lshttpd', 'lsphp'}), 'managed_by': 'cyberpanel' if ptype == 'cyberpanel' else 'distro'})

    # --- Caddy
    cbin = _first(['/usr/bin/caddy', '/usr/local/bin/caddy', '/usr/sbin/caddy'])
    if cbin:
        res.append({'type': 'caddy', 'bin': cbin, 'version': _run_version([P(cbin), 'version'], r'v?([0-9]+\.[0-9]+\.[0-9]+)'), 'conf': '/etc/caddy/Caddyfile',
                    'vhost_paths': ['/etc/caddy/Caddyfile', '/etc/caddy/conf.d', '/etc/caddy/sites'], 'log_dirs': ['/var/log/caddy'],
                    'modules_dir': '', 'pid': '', 'service': 'caddy', 'active': 'caddy' in procs, 'managed_by': 'distro'})
    return res


# ---------------------------------------------------------------- tata letak
def default_layout(os_info):
    """Lokasi bawaan distro untuk web server yang BELUM terpasang (server fresh) atau dipasang belakangan."""
    if os_info['family'] == 'rpm':
        return {'conf_dirs': ['/etc/nginx/conf.d', '/etc/httpd/conf.d', '/etc/httpd/conf', '/etc/caddy'],
                'log_dirs': ['/var/log/nginx', '/var/log/httpd'], 'docroots': ['/var/www/html', '/usr/share/nginx/html']}
    return {'conf_dirs': ['/etc/nginx/sites-enabled', '/etc/nginx/conf.d', '/etc/apache2/sites-enabled', '/etc/apache2/conf-enabled', '/etc/caddy'],
            'log_dirs': ['/var/log/nginx', '/var/log/apache2'], 'docroots': ['/var/www/html']}


def _expand(paths):
    out = []
    for p in paths:
        if any(c in p for c in '*?['):
            out += [x[len(ROOT):] if ROOT else x for x in sorted(glob.glob(P(p)))]
        else:
            out.append(p)
    return out


PANEL_LAYOUT = {
    'aapanel': {'conf': ['/www/server/panel/vhost/nginx', '/www/server/nginx/conf', '/www/server/panel/vhost/apache', '/www/server/panel/vhost/openlitespeed'],
                'log': ['/www/wwwlogs']},
    'cpanel': {'conf': ['/etc/apache2/conf/httpd.conf', '/etc/apache2/conf.d'], 'log': ['/var/log/apache2/domlogs', '/etc/apache2/logs/domlogs']},
    'directadmin': {'conf': ['/usr/local/directadmin/data/users/*/httpd.conf', '/etc/httpd/conf/extra', '/etc/nginx/conf.d'],
                    'log': ['/var/log/httpd/domains', '/var/log/nginx/domains']},
    'cyberpanel': {'conf': ['/usr/local/lsws/conf/vhosts/*/vhost.conf'], 'log': ['/usr/local/lsws/logs', '/home/*/logs']},
}


def detect():
    os_info = detect_os()
    panel = detect_panel()
    servers = detect_webservers(os_info, panel)
    dflt = default_layout(os_info)
    aktif = [s for s in servers if s['active']]
    utama = (aktif or servers or [None])[0]
    if panel['type'] != 'none':
        state = 'panel'
    elif servers:
        state = 'standalone'
    else:
        state = 'fresh'
    conf_dirs, log_dirs = [], []
    for s in (aktif or servers):
        conf_dirs += s['vhost_paths']
        log_dirs += s['log_dirs']
    # lokasi milik panel ikut walau biner web server belum terdeteksi (panel mengelola web server-nya sendiri)
    pl = PANEL_LAYOUT.get(panel['type'])
    if pl:
        conf_dirs += pl['conf']
        log_dirs += pl['log']
    # default distro selalu ikut (web server dipasang belakangan tetap terbaca) kecuali pada server aaPanel
    if panel['type'] != 'aapanel':
        conf_dirs += dflt['conf_dirs']
        log_dirs += dflt['log_dirs']
    uniq = lambda xs: [x for i, x in enumerate(xs) if x not in xs[:i]]
    return {'detected_at': int(time.time()), 'os': os_info, 'panel': panel, 'webservers': servers,
            'primary': utama['type'] if utama else '', 'state': state,
            'layout': {'conf_dirs': uniq(conf_dirs), 'log_dirs': uniq(_expand(log_dirs)), 'default_docroots': dflt['docroots'],
                       'sites_source': {'aapanel': 'panel-db', 'none': 'vhost-conf'}.get(panel['type'], 'vhost-conf')}}


def profile(max_age=300, refresh=False):
    """Profil terdeteksi dari cache (maks `max_age` detik); dideteksi ulang bila basi/tidak ada. Cache gagal ditulis = tetap dikembalikan."""
    if not refresh and not ROOT:
        try:
            if time.time() - os.path.getmtime(CACHE) < max_age:
                with open(CACHE) as f:
                    return json.load(f)
        except (OSError, ValueError):
            pass
    prof = detect()
    if not ROOT:
        try:
            tmp = CACHE + '.baru'
            os.makedirs(os.path.dirname(CACHE), exist_ok=True)
            with open(tmp, 'w') as f:
                json.dump(prof, f, indent=1)
            os.chmod(tmp, 0o644)
            os.replace(tmp, CACHE)
        except OSError:
            pass
    return prof


def panel_type(prof=None):
    return (prof or profile())['panel']['type']


def is_aapanel(prof=None):
    return panel_type(prof) == 'aapanel'


# ---------------------------------------------------------------- penguraian konfigurasi vhost
def strip_comments(text):
    return '\n'.join(re.sub(r'(^|\s)#.*$', '', ln) for ln in text.splitlines())


def _blocks(text, opener):
    out = []
    for m in opener.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += (text[i] == '{') - (text[i] == '}')
            i += 1
        out.append(text[m.end():i - 1])
    return out


def conf_files(paths):
    """Berkas konfigurasi dari daftar path: berkas, folder (tidak rekursif), atau glob. Folder conf.d/conf-enabled/extra hanya *.conf."""
    out, seen = [], set()
    for p in paths:
        cand, dir_conf = [], False
        if any(c in p for c in '*?['):
            cand = sorted(glob.glob(P(p)))
        elif os.path.isdir(P(p)):
            dir_conf = os.path.basename(p.rstrip('/')) in ('conf.d', 'conf-enabled', 'extra', 'users', 'conf')
            try:
                cand = [os.path.join(P(p), n) for n in sorted(os.listdir(P(p)))]
            except OSError:
                cand = []
        elif os.path.isfile(P(p)):
            cand = [P(p)]
        for c in cand:
            n = os.path.basename(c)
            if n.startswith('.') or n.endswith(('.bak', '.dpkg-old', '.dpkg-dist', '~', '.swp')):
                continue
            if dir_conf and not n.endswith('.conf'):
                continue
            if os.path.isfile(c) and c not in seen:
                seen.add(c)
                out.append(c)
    return out


def _php_ver(text):
    m = re.search(r'php-?(\d\.\d)', text)
    return m.group(1) if m else ''


def parse_nginx(files):
    res = []
    opener = re.compile(r'\bserver\s*\{')
    for path in files:
        text = strip_comments(readfile(path))
        for blk in _blocks(text, opener):
            names = []
            for m in re.finditer(r'\bserver_name\s+([^;]+);', blk):
                names += [n for n in m.group(1).split() if n not in ('_', 'localhost') and not n.startswith('~') and '*' not in n]
            if not names:
                continue
            root = re.search(r'(?:^|[;{])\s*root\s+([^;]+);', blk, re.M)
            cert = re.search(r'\bssl_certificate\s+([^;]+);', blk)
            res.append({'domain': names[0], 'docroot': root.group(1).strip().strip('"\'') if root else '', 'webserver': 'nginx',
                        'ssl': bool(re.search(r'\blisten\s+[^;]*\bssl\b', blk)) or bool(cert), 'php': _php_ver(blk), 'aliases': names[1:], 'config': path})
    return res


def readfile(abs_path, limit=2_000_000):
    try:
        with open(abs_path, 'r', errors='replace') as f:
            return f.read(limit)
    except OSError:
        return ''


def parse_apache(files):
    res = []
    for path in files:
        text = strip_comments(readfile(path))
        for m in re.finditer(r'<VirtualHost\b[^>]*>(.*?)</VirtualHost>', text, re.S | re.I):
            blk = m.group(1)
            sn = re.search(r'^\s*ServerName\s+(\S+)', blk, re.M | re.I)
            if not sn or sn.group(1).lower() in ('localhost', '_default_'):
                continue
            dr = re.search(r'^\s*DocumentRoot\s+(\S+)', blk, re.M | re.I)
            res.append({'domain': sn.group(1).split(':')[0], 'docroot': dr.group(1).strip('"\'') if dr else '', 'webserver': 'apache',
                        'ssl': bool(re.search(r'^\s*SSLEngine\s+on', blk, re.M | re.I)), 'php': _php_ver(blk), 'aliases': [], 'config': path})
    return res


def parse_ols(files):
    res = []
    for path in files:
        parts = path.rstrip('/').split('/')
        domain = parts[-2] if len(parts) >= 2 else ''
        text = strip_comments(readfile(path))
        dr = re.search(r'^\s*docRoot\s+(\S+)', text, re.M | re.I)
        if not domain or not dr:
            continue
        root = dr.group(1)
        if '$VH_ROOT' in root:
            root = root.replace('$VH_ROOT', '/home/' + domain if os.path.isdir(P('/home/' + domain)) else '/usr/local/lsws/' + domain)
        res.append({'domain': domain, 'docroot': root, 'webserver': 'openlitespeed', 'ssl': 'vhssl' in text.lower(), 'php': '', 'aliases': [], 'config': path})
    return res


def parse_caddy(files):
    res = []
    for path in files:
        text = strip_comments(readfile(path))
        for m in re.finditer(r'^([A-Za-z0-9*._:,\s-]+?)\s*\{\s*$', text, re.M):
            addr = m.group(1).strip()
            if not addr or addr.startswith(('(', '{')) or ' ' in addr.replace(',', ' ').strip() and not re.match(r'^[\w.*:,\s-]+$', addr):
                continue
            body = text[m.end():m.end() + 4000]
            body = body.split('\n}')[0]
            root = re.search(r'^\s*root\s+(?:\*\s+)?(\S+)', body, re.M)
            if not root:
                continue
            for dom in [d.strip() for d in re.split(r'[,\s]+', addr) if d.strip()]:
                dom = re.sub(r'^https?://', '', dom).split(':')[0]
                if dom and '*' not in dom and dom != 'localhost':
                    res.append({'domain': dom, 'docroot': root.group(1).strip('"\''), 'webserver': 'caddy', 'ssl': True, 'php': '', 'aliases': [], 'config': path})
    return res


def _aapanel_sites():
    """Situs aaPanel dari basis datanya (baca-saja); cadangan: folder /www/wwwroot hanya pada server yang memang aaPanel."""
    out = []
    for db in ('/www/server/panel/data/db/site.db', '/www/server/panel/data/default.db'):
        if not isfile(db):
            continue
        try:
            con = sqlite3.connect('file:%s?mode=ro' % P(db), uri=True, timeout=3)
            rows = con.execute('SELECT name, path FROM sites').fetchall()
            con.close()
            out = [{'domain': r[0], 'docroot': r[1], 'webserver': '', 'ssl': False, 'php': '', 'aliases': [], 'config': db} for r in rows if r[0] and r[1]]
            if out:
                return out
        except sqlite3.Error:
            continue
    if isdir('/www/wwwroot'):
        for n in sorted(os.listdir(P('/www/wwwroot'))):
            p = '/www/wwwroot/' + n
            if isdir(p) and not n.startswith('.') and not os.path.islink(P(p)):
                out.append({'domain': n, 'docroot': p, 'webserver': '', 'ssl': False, 'php': '', 'aliases': [], 'config': ''})
    return out


def sites(prof=None):
    """Situs (domain, docroot) menurut tipe panel: aaPanel = basis data panel; lainnya = konfigurasi vhost web server yang terdeteksi
    (ditambah lokasi bawaan distro bila web server belum aktif). Docroot dibaca dari konfigurasi, tidak ditebak."""
    prof = prof or profile()
    if prof['panel']['type'] == 'aapanel':
        return _aapanel_sites()
    parsers = {'nginx': parse_nginx, 'apache': parse_apache, 'openlitespeed': parse_ols, 'litespeed': parse_ols, 'caddy': parse_caddy}
    use = [s for s in prof['webservers'] if s['active']] or prof['webservers']
    res, seen = [], set()
    for s in use:
        for v in parsers.get(s['type'], lambda f: [])(conf_files(s['vhost_paths'])):
            k = (v['domain'].lower(), v['webserver'])
            if k not in seen:
                seen.add(k)
                res.append(v)
    return res


def docroots(prof=None):
    """Docroot nyata yang ada di disk, unik."""
    out = []
    for v in sites(prof):
        d = v['docroot']
        if d and isdir(d) and not os.path.islink(P(d)) and d not in out:
            out.append(d)
    return out


# ---------------------------------------------------------------- keluaran untuk bash dan guardd
def guardd_conf_lines(prof=None):
    """Baris conf_dir/log_dir untuk guardd.conf dari profil: lokasi web server terdeteksi + bawaan distro. Glob (mis. vhost OLS,
    users DirectAdmin) dipecah menjadi folder induk berkas yang ada, karena guardd memindai folder."""
    prof = prof or profile()
    lines = []
    for d in prof['layout']['conf_dirs']:
        if any(c in d for c in '*?['):
            ds = []
            for f in glob.glob(P(d)):
                par = os.path.dirname(f)
                ds.append(par[len(ROOT):] if ROOT else par)
        else:
            ds = [d if isdir(d) or not isfile(d) else os.path.dirname(d)]
        for x in ds:
            ln = 'conf_dir = %s' % x
            if ln not in lines:
                lines.append(ln)
    for d in prof['layout']['log_dirs']:
        ln = 'log_dir = %s' % d
        if ln not in lines:
            lines.append(ln)
    return lines


def shell_env(prof=None):
    """Berkas env.sh (KEY=nilai) untuk skrip bash."""
    prof = prof or profile()
    ws = {s['type']: s for s in prof['webservers']}
    q = lambda v: "'%s'" % str(v).replace("'", "'\\''")
    rows = [('ZYS_OS_FAMILY', prof['os']['family']), ('ZYS_OS_ID', prof['os']['id']), ('ZYS_OS_VERSION', prof['os']['version']),
            ('ZYS_PANEL', prof['panel']['type']), ('ZYS_STATE', prof['state']), ('ZYS_PRIMARY_WS', prof['primary']),
            ('ZYS_PANEL_PORTS', ' '.join(str(x) for x in prof['panel']['ports']))]
    for t in ('nginx', 'apache', 'openlitespeed', 'litespeed', 'caddy'):
        s = ws.get(t)
        u = t.upper()
        rows += [('ZYS_%s_BIN' % u, s['bin'] if s else ''), ('ZYS_%s_CONF' % u, s['conf'] if s else ''),
                 ('ZYS_%s_VERSION' % u, s['version'] if s else ''), ('ZYS_%s_ACTIVE' % u, '1' if s and s['active'] else '0'),
                 ('ZYS_%s_MODDIR' % u, s['modules_dir'] if s else '')]
    return '\n'.join('%s=%s' % (k, q(v)) for k, v in rows) + '\n'


def summary(prof):
    o, p = prof['os'], prof['panel']
    ws = ', '.join('%s %s (%s)' % (s['type'], s['version'] or '?', 'aktif' if s['active'] else 'terpasang, tidak aktif') for s in prof['webservers']) or 'belum ada'
    return 'OS %s | panel %s%s | web server: %s | keadaan: %s' % (o['name'] or o['id'], p['name'], (' ' + p['version']) if p['version'] else '', ws, prof['state'])


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'detect'
    if cmd == 'detect':
        prof = profile(refresh=True)
        if not ROOT:
            try:
                tmp = SHELL_ENV + '.baru'
                with open(tmp, 'w') as f:
                    f.write(shell_env(prof))
                os.chmod(tmp, 0o644)
                os.replace(tmp, SHELL_ENV)
            except OSError:
                pass
        print(json.dumps(prof, indent=1) if '--json' in argv else summary(prof))
    elif cmd == 'panel':
        print(profile()['panel']['type'])
    elif cmd == 'sites':
        for v in sites():
            if '--full' in argv:
                print('%s\t%s\t%s' % (v['domain'], v['webserver'], v['config']))
            elif '--tsv' in argv:
                lab = re.sub(r'[^A-Za-z0-9._-]', '', v['domain'])
                if lab and v['docroot'] and isdir(v['docroot']) and not os.path.islink(P(v['docroot'])):
                    print('%s\t%s' % (lab, v['docroot']))
            else:
                print(json.dumps(v))
    elif cmd == 'guardd-conf':
        print('\n'.join(guardd_conf_lines()))
    elif cmd == 'shell':
        sys.stdout.write(shell_env())
    else:
        print('pakai: env.py detect [--json] | panel | sites [--tsv] | guardd-conf | shell')
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
