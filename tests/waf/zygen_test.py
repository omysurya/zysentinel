#!/usr/bin/env python3
# Uji fitur yang dikelola sentinel-zyrules.py: daftar IP/URL, modul, mode, tingkat bot, allowlist.txt.
# Pemakaian: ENGINE=nginx|apache zygen_test.py <payload zyrules> <generator.py> <CRS> [nginx modul libdir]
import sys, os, re, json, time, subprocess, http.client, shutil, tempfile, signal

ENGINE = os.environ.get('ENGINE', 'nginx')
SRC_ZY, GENERATOR, CRS = sys.argv[1:4]
if ENGINE == 'nginx':
    NGINX, MOD, LIBDIR = sys.argv[4:7]
T = tempfile.mkdtemp(prefix='zygen.')
os.chmod(T, 0o777)
HTML = T + '/html'
GAGAL = []
USER = 'www' if ENGINE == 'nginx' else 'www-data'

def cek(nama, ok, info=''):
    print('  %s %s%s' % ('LULUS' if ok else 'GAGAL', nama, '' if ok else '  -> ' + str(info)[:250]))
    if not ok: GAGAL.append(nama)

for rel in ['/api_key.txt', '/dump.sql', '/index.html', '/api/webhook/x', '/private/x', '/public/x', '/credentials.json', '/news/index.html']:
    p = HTML + rel; os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'w').write('ok\n')

# --------------------------------------------------------------- skenario
# nama: dict(conf=waf.conf, lists={nama: [baris]}, allow=[baris])
SK = {
 'dasar':    dict(conf='', lists={}, allow=[]),
 'ipblack':  dict(conf='', lists={'ip_black': ['127.0.0.1']}, allow=[]),
 'ipwhite':  dict(conf='', lists={'ip_white': ['127.0.0.0/8'], 'ip_black': ['127.0.0.1']}, allow=[]),
 'urlblack': dict(conf='', lists={'url_black': ['^/private/']}, allow=[]),
 'urlwhite': dict(conf='', lists={'url_white': ['^/api/webhook/']}, allow=[]),
 'modoff':   dict(conf='zy.mod.scanner = off\nzy.mod.sensitive_files = off\n', lists={}, allow=[]),
 'monitor':  dict(conf='mode = monitor\n', lists={}, allow=[]),
 'disable':  dict(conf='mode = disable\n', lists={}, allow=[]),
 'allowfw':  dict(conf='', lists={}, allow=['# komentar', '127.0.0.1', '10.9.0.0/16']),
 'kotor':    dict(conf='', lists={'ip_black': ['abc', '1.2.3.999', '300.1.1.1/8', '8.8.8.0/24'], 'url_black': ['(', '[a-', '.*', '^/ok-blacklist/'],
                  'ip_white': ['bukan-ip']}, allow=['zzz', '1.2.3.4']),
 'strictbot': dict(conf='zy.strict = 1\nzy.bot_level = 3\n', lists={}, allow=[]),
 'nofb':     dict(conf='zy.fallback = 0\n', lists={}, allow=[]),
}
PORTS = {}
base_port = 31000 + (os.getpid() % 1500) * 20
servers = ''
mains = {}
warns = {}
for i, (nm, sc) in enumerate(SK.items()):
    d = '%s/zy-%s' % (T, nm)
    shutil.copytree(SRC_ZY, d, ignore=shutil.ignore_patterns('gen'))
    os.makedirs(d + '/lists', exist_ok=True)
    for ln, rows in sc['lists'].items():
        open('%s/lists/%s.txt' % (d, ln), 'w').write('\n'.join(rows) + '\n')
    open(d + '/waf.conf', 'w').write(sc['conf'])
    open(d + '/allowlist.txt', 'w').write('\n'.join(sc['allow']) + '\n')
    env = dict(os.environ, SENTINEL_ZY_DIR=d, SENTINEL_CRS_DIR=CRS, SENTINEL_WAF_CONF=d + '/waf.conf', SENTINEL_WAF_LISTS=d + '/lists',
               SENTINEL_ALLOWLIST=d + '/allowlist.txt', SENTINEL_WAF_AUDIT=d + '/audit.log', SENTINEL_WEB_USER=USER)
    r = subprocess.run([sys.executable, GENERATOR, 'build'], env=env, capture_output=True, text=True)
    if r.returncode:
        print('generator GAGAL', nm, r.stdout, r.stderr); sys.exit(2)
    warns[nm] = len(re.findall(r'PERINGATAN', r.stderr))
    mains[nm] = d + '/gen/main.conf'
    PORTS[nm] = base_port + i
shutil.copy(SRC_ZY + '/html/zysentinel-block.html', T + '/block.html')
os.makedirs(T + '/block', exist_ok=True)
shutil.copy(SRC_ZY + '/html/zysentinel-block.html', T + '/block/__zysentinel_403.html')
subprocess.run('chmod -R a+rwX %s; chmod -R a+rX %s' % (T, SRC_ZY), shell=True)

if ENGINE == 'nginx':
    for nm, port in PORTS.items():
        servers += '''
  server { listen 127.0.0.1:%d; root %s; coraza on; coraza_rules_file %s;
    error_page 403 /__zysentinel_403.html;
    location = /__zysentinel_403.html { internal; root %s/block; default_type text/html; }
    location / { } }''' % (port, HTML, mains[nm], T)
    lua = 'lua_package_path "/www/server/nginx/lib/lua/?.lua;;";' if os.path.exists('/www/server/nginx/lib/lua') else ''
    open(T + '/nginx.conf', 'w').write('load_module %s/ngx_http_coraza_module.so;\nworker_processes 1;\npid %s/nginx.pid;\nerror_log %s/error.log notice;\nevents { worker_connections 256; }\nhttp {\n %s\n access_log off;\n client_body_temp_path %s/tmp/b; proxy_temp_path %s/tmp/p; fastcgi_temp_path %s/tmp/f; uwsgi_temp_path %s/tmp/u; scgi_temp_path %s/tmp/s;\n%s\n}\n' % (T, T, T, lua, T, T, T, T, T, servers))
    os.makedirs(T + '/lib'); os.makedirs(T + '/tmp')
    shutil.copy(MOD, T + '/ngx_http_coraza_module.so'); shutil.copy(LIBDIR + '/libcoraza.so', T + '/lib/libcoraza.so')
    subprocess.run('chmod -R a+rwX %s' % T, shell=True)
    env = dict(os.environ, LD_LIBRARY_PATH=T + '/lib')
    r = subprocess.run([NGINX, '-p', T, '-c', T + '/nginx.conf', '-e', T + '/startup.log', '-t'], env=env, capture_output=True, text=True)
    print('nginx -t:', (r.stdout + r.stderr).strip().splitlines()[-1])
    if r.returncode: print(r.stdout + r.stderr); sys.exit(2)
    subprocess.run([NGINX, '-p', T, '-c', T + '/nginx.conf', '-e', T + '/startup.log'], env=env)
    LOGF = T + '/error.log'; PIDF = T + '/nginx.pid'
else:
    mods = '/usr/lib/apache2/modules/'
    vh = lis = ''
    for nm, port in PORTS.items():
        lis += 'Listen 127.0.0.1:%d\n' % port
        vh += '<VirtualHost 127.0.0.1:%d>\n ServerName uji.local\n DocumentRoot %s\n <Directory %s>\n  Require all granted\n  Options None\n </Directory>\n SecRuleEngine On\n Include %s\n Alias /__zysentinel_403.html %s/block/__zysentinel_403.html\n <Directory %s/block>\n  Require all granted\n </Directory>\n ErrorDocument 403 /__zysentinel_403.html\n</VirtualHost>\n' % (port, HTML, HTML, mains[nm], T, T)
    open(T + '/apache2.conf', 'w').write('ServerRoot "/etc/apache2"\nServerName localhost\nPidFile %s/apache.pid\nErrorLog %s/apache_error.log\nLogLevel warn\nUser www-data\nGroup www-data\nDefaultRuntimeDir %s/run\nMutex file:%s/run default\n' % (T, T, T, T) + ''.join('LoadModule %s_module %smod_%s.so\n' % (m, mods, m) for m in ('mpm_prefork', 'authz_core', 'mime', 'dir', 'alias', 'unique_id', 'security2')).replace('mpm_prefork_module', 'mpm_prefork_module') + 'TypesConfig /etc/mime.types\nDirectoryIndex index.html\n' + lis + vh)
    os.makedirs(T + '/run'); subprocess.run('chmod -R a+rwX %s' % T, shell=True)
    r = subprocess.run(['apache2', '-f', T + '/apache2.conf', '-t'], capture_output=True, text=True)
    print('apache2 -t:', (r.stdout + r.stderr).strip().splitlines()[-1])
    if r.returncode: print(r.stdout + r.stderr); sys.exit(2)
    subprocess.run(['apache2', '-f', T + '/apache2.conf'])
    LOGF = T + '/apache_error.log'; PIDF = T + '/apache.pid'
for _ in range(20):
    try:
        c = http.client.HTTPConnection('127.0.0.1', base_port, timeout=3); c.request('GET', '/'); c.getresponse().read(); break
    except Exception: time.sleep(0.5)

UA = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36'}
def req(nm, path, headers=None, method='GET', body=None):
    h = dict(UA); h.update(headers or {})
    h = {k: v for k, v in h.items() if v is not None}
    try:
        c = http.client.HTTPConnection('127.0.0.1', PORTS[nm], timeout=10)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True); c.putheader('Host', 'uji.local')
        for k, v in h.items(): c.putheader(k, v)
        c.endheaders(); r = c.getresponse(); r.read(); c.close(); return r.status
    except Exception as ex:
        return 'EXC ' + str(ex)

SQLI = "/?id=1%20UNION%20SELECT%201,2,3--"
print('\n## Dasar')
cek('permintaan sah 200', req('dasar', '/') == 200)
cek('.env 403', req('dasar', '/.env') == 403)
cek('SQLi 403 (CRS)', req('dasar', SQLI) == 403)

print('\n## Daftar IP')
cek('ip_black 127.0.0.1: permintaan sah pun 403', req('ipblack', '/') == 403, req('ipblack', '/'))
cek('ip_black: halaman lain juga 403', req('ipblack', '/news/index.html') == 403)
cek('ip_white mengalahkan ip_black: sah 200', req('ipwhite', '/') == 200, req('ipwhite', '/'))
cek('ip_white: .env dilewati (WAF mati untuk IP itu)', req('ipwhite', '/.env') in (200, 404), req('ipwhite', '/.env'))
cek('ip_white: SQLi dilewati', req('ipwhite', SQLI) == 200, req('ipwhite', SQLI))

print('\n## Daftar URL')
cek('url_black ^/private/: 403', req('urlblack', '/private/x') == 403, req('urlblack', '/private/x'))
cek('url_black: /public/x tetap 200', req('urlblack', '/public/x') == 200)
cek('url_white ^/api/webhook/: SQLi di dalamnya dilewati', req('urlwhite', '/api/webhook/x?id=1%20UNION%20SELECT%201,2,3--') == 200, req('urlwhite', '/api/webhook/x?id=1%20UNION%20SELECT%201,2,3--'))
cek('url_white: SQLi di luar pola tetap 403', req('urlwhite', SQLI) == 403)
cek('url_white: traversal di dalam pola TETAP diperiksa', req('urlwhite', '/api/webhook/x?f=../../../../etc/passwd') != 200 or req('urlwhite', '/api/webhook/../../.env') in (400, 403, 404), (req('urlwhite', '/api/webhook/x?f=../../../../etc/passwd'), req('urlwhite', '/api/webhook/../../.env')))

print('\n## Modul')
cek('modul scanner off: header Acunetix-Aspect lolos', req('modoff', '/', {'Acunetix-Aspect': '1'}) == 200, req('modoff', '/', {'Acunetix-Aspect': '1'}))
cek('modul scanner on (dasar): header Acunetix-Aspect 403', req('dasar', '/', {'Acunetix-Aspect': '1'}) == 403)
cek('modul sensitive_files off: /api_key.txt lolos (CRS tidak memilikinya)', req('modoff', '/api_key.txt') == 200, req('modoff', '/api_key.txt'))
cek('modul sensitive_files on (dasar): /api_key.txt 403', req('dasar', '/api_key.txt') == 403)
cek('modul off tidak mematikan CRS: SQLi tetap 403', req('modoff', SQLI) == 403)
cek('modul bot tetap aktif saat modul lain off', req('modoff', '/', {'User-Agent': 'MJ12bot/1.4'}) == 403)

print('\n## Mode')
cek('monitor: .env tidak diblokir', req('monitor', '/.env') in (200, 404), req('monitor', '/.env'))
cek('monitor: SQLi tidak diblokir', req('monitor', SQLI) == 200, req('monitor', SQLI))
cek('disable: .env tidak diblokir', req('disable', '/.env') in (200, 404), req('disable', '/.env'))
time.sleep(1)
alog = open(T + '/zy-monitor/audit.log').read() if os.path.exists(T + '/zy-monitor/audit.log') else ''
cek('monitor: kejadian tetap tercatat di log audit', 'ZySentinel' in alog or '8000102' in alog, alog[:150])

print('\n## allowlist.txt firewall')
cek('allowlist 127.0.0.1: .env dilewati', req('allowfw', '/.env') in (200, 404), req('allowfw', '/.env'))
cek('allowlist: SQLi dilewati', req('allowfw', SQLI) == 200, req('allowfw', SQLI))

print('\n## Masukan kotor diabaikan, WAF tetap berjalan')
cek('generator melaporkan peringatan untuk entri tak valid', warns['kotor'] >= 5, warns['kotor'])
cek('situs sah tetap 200', req('kotor', '/') == 200, req('kotor', '/'))
cek('pola url_black valid di antara yang kotor bekerja', req('kotor', '/ok-blacklist/x') == 403, req('kotor', '/ok-blacklist/x'))
cek('regex terlalu luas ".*" TIDAK memblokir seluruh situs', req('kotor', '/news/index.html') == 200)
cek('.env tetap 403', req('kotor', '/.env') == 403)

print('\n## Pengaturan')
cek('strict+bot3: curl 403', req('strictbot', '/', {'User-Agent': 'curl/8.5.0'}) == 403)
cek('dasar: curl 200', req('dasar', '/', {'User-Agent': 'curl/8.5.0'}) == 200)
cek('fallback off tetap berjalan', req('nofb', '/') == 200)
print('  info: peringatan generator per skenario:', warns)

try: os.kill(int(open(PIDF).read()), signal.SIGTERM)
except Exception: pass
print('\nTOTAL GAGAL: %d' % len(GAGAL))
if GAGAL: print('dipertahankan: ' + T)
else: shutil.rmtree(T, ignore_errors=True)
sys.exit(1 if GAGAL else 0)
