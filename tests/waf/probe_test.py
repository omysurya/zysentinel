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

for rel in ['/.env', '/.git/config', '/backup.sql', '/wp-config.php.bak', '/private/x', '/api_key.txt', '/dump.sql', '/index.html', '/api/webhook/x', '/private/x', '/public/x', '/credentials.json', '/news/index.html']:
    p = HTML + rel; os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'w').write('ok\n')

# --------------------------------------------------------------- skenario
# nama: dict(conf=waf.conf, lists={nama: [baris]}, allow=[baris])
SK = {
 'dasar':    dict(conf='', lists={}, allow=[]),
 'urlblack': dict(conf='', lists={'url_black': ['^/private/', '/admin-evil']}, allow=[]),
 'urlwhite': dict(conf='', lists={'url_white': ['^/api/webhook/']}, allow=[]),
 'strict':   dict(conf='zy.strict = 1\nzy.bot_level = 2\n', lists={}, allow=[]),
 'wpsite':   dict(conf='', lists={}, allow=[]),
 'probeoff': dict(conf='zy.mod.probe_cms = off\nzy.mod.probe_tools = off\nzy.mod.probe_cve = off\nzy.mod.probe_archive = off\nzy.mod.probe_secrets = off\n', lists={}, allow=[]),
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
    VH = T + '/vhosts'; os.makedirs(VH + '/wp.root', exist_ok=True); os.makedirs(VH, exist_ok=True)
    open(VH + '/wp.root/wp-config.php', 'w').write('<?php')
    open(VH + '/wp.test.conf', 'w').write('server {\n server_name wp.test;\n root %s/wp.root;\n}\n' % VH) if nm == 'wpsite' else None
    env = dict(os.environ, SENTINEL_VHOST_DIRS=VH if nm == 'wpsite' else '/nonexistent', SENTINEL_ZY_DIR=d, SENTINEL_CRS_DIR=CRS, SENTINEL_WAF_CONF=d + '/waf.conf', SENTINEL_WAF_LISTS=d + '/lists',
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
    open(T + '/nginx.conf', 'w').write('load_module %s/ngx_http_coraza_module.so;\nworker_processes 1;\npid %s/nginx.pid;\nerror_log %s/error.log notice;\nevents { worker_connections 256; }\nhttp {\n %s\n access_log off;\n client_max_body_size 100m;\n client_body_temp_path %s/tmp/b; proxy_temp_path %s/tmp/p; fastcgi_temp_path %s/tmp/f; uwsgi_temp_path %s/tmp/u; scgi_temp_path %s/tmp/s;\n%s\n}\n' % (T, T, T, lua, T, T, T, T, T, servers))
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
        if body is not None:
            _b = body if isinstance(body, bytes) else body.encode()
            c.putheader('Content-Length', str(len(_b)))
        c.endheaders()
        if body is not None: c.send(_b)
        r = c.getresponse(); r.read(); c.close(); return r.status
    except Exception as ex:
        return 'EXC ' + str(ex)



def reqh(nm, path, host='uji.local', ua=None):
    h={'Host':host}
    return req(nm, path, {'Host':host} if host!='uji.local' else None)
import http.client as _hc
def get(nm, path, host='uji.local', ua='Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36'):
    try:
        c=_hc.HTTPConnection('127.0.0.1',PORTS[nm],timeout=10); c.putrequest('GET',path,skip_host=True,skip_accept_encoding=True); c.putheader('Host',host); c.putheader('User-Agent',ua); c.endheaders(); r=c.getresponse(); r.read(); c.close(); return r.status
    except Exception as e: return 'EXC'
G=[]
def ok(n,k,i=''):
    print('  %s %s%s'%('LULUS' if k else 'GAGAL',n,'' if k else '  -> '+str(i)[:120]))
    if not k: G.append(n)
ATK=['/wp-login.php','/wp-admin/','/wp-admin/admin-ajax.php','/xmlrpc.php','/wp-content/plugins/x/readme.txt','/wp-includes/wlwmanifest.xml','/wordpress/','/wp/','/blog/wp/v2/posts/1','/?rest_route=/wp/v2/users/','/?option=com_users','/administrator/','/adminer.php','/adminer-4.8.1-mysql.php','/phpmyadmin/','/pma/','/phpinfo.php','/info.php','/test.php','/pi.php','/php-info.php','/_ignition/execute-solution','/telescope/requests','/horizon/','/_profiler/open','/actuator/env','/actuator','/debug/pprof/','/debug/vars','/env','/api/env','/geoserver/web/','/solr/admin/cores','/jenkins/','/manager/html','/containers/json','/mgmt/tm/util/bash','/owa/auth.php','/remote/login','/cgi-bin/luci/;stok=/locale','/cgi-bin/test.cgi','/HNAP1/','/SDK/webLanguage','/onvif/device_service','/boaform/admin/formLogin','/login.action','/cstecgi.cgi','/s/6323e29393e27/_/;/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.properties','/2023.zip','/1.zip','/backup.tar.gz','/example.com.zip','/www.tar.gz','/serverless.yml','/settings.py','/firebase-service-account.json','/google-service-account.json','/credentials','/parameters.yml','/config/credentials.yml.enc','/.aws/credentials','/.config/hub','/.ssh/id_rsa','/.claude/settings.json','/.cursor/mcp.json','/.npmrc','/.my.cnf','/storage/logs/laravel.log','/bootstrap/cache/config.php','/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php','/vendor/composer/installed.json','/.well-known/file.php','/.well-known/x.php','/etc/passwd','/var/run/secrets/kubernetes.io/serviceaccount/token','/proc/self/environ','/webroot/index.php/_environment','/app_dev.php/cache']
print('## Probe/eksploit diblokir (403) pada situs biasa')
for p in ATK:
    st=get('dasar',p); ok('403 '+p[:70], st in (403,400), st)
print('\n## Jalur sah tetap lolos (200)')
for p in ['/','/index.html','/.well-known/security.txt','/.well-known/acme-challenge/abc123','/.well-known/assetlinks.json','/.well-known/apple-app-site-association','/news/index.html','/?q=wordpress','/?page=2','/assets/app.js','/graphql','/swagger.json','/metrics','/status','/api/users','/downloads/brosur.zip','/files/laporan.pdf','/vendor/adminlte/dist/css/a.css','/storage/avatar.png','/mcp']:
    st=get('dasar',p); ok('lolos '+p, st in (200,404,405), st)
print('\n## Klien API sah (CRS 943120 sessionID tanpa Referer)')
for p in ['/api/v1/sponsor?sessionID=prEyXNWVcz&timestamp=2026-01-21+14%3A10%3A40','/api/v1/user/pong?sessionID=abc&latitude=-6.2','/v2/orders?session_id=12345','/api/dokter?sessionid=xyz']:
    st=get('dasar',p); ok('API lolos '+p[:55], st in (200,404,405), st)
ok('di luar /api/ parameter sessionID tanpa Referer tetap diblokir CRS', get('dasar','/halaman?sessionID=abc')==403, get('dasar','/halaman?sessionID=abc'))
print('\n## Pengecualian otomatis per vhost (situs WordPress sah)')
for p in ['/wp-login.php','/wp-admin/','/xmlrpc.php','/wp-content/plugins/x/a.js','/?rest_route=/wp/v2/posts']:
    ok('wp.test %s lolos'%p, get('wpsite',p,host='wp.test') in (200,404,405), get('wpsite',p,host='wp.test'))
    ok('situs lain %s tetap 403 (server sama)'%p, get('wpsite',p,host='lain.test')==403, get('wpsite',p,host='lain.test'))
ok('wp.test: adminer tetap 403 (hanya grup cms dikecualikan)', get('wpsite','/adminer.php',host='wp.test')==403)
ok('wp.test: .env tetap 403', get('wpsite','/.env',host='wp.test')==403)
ok('wp.test:8080 (dengan port) juga dikecualikan', get('wpsite','/wp-login.php',host='wp.test:8080') in (200,404,405))
print('\n## Modul dimatikan')
for p in ['/wp-login.php','/cgi-bin/x','/2023.zip']:
    ok('probeoff %s lolos'%p, get('probeoff',p) in (200,404,405), get('probeoff',p))
for p in ['/phpinfo.php','/.aws/credentials','/adminer.php']:
    ok('probeoff %s tetap 403 (dilindungi modul sensitive_files lama)'%p, get('probeoff',p)==403, get('probeoff',p))
ok('probeoff: CRS/ZySentinel lain tetap aktif (SQLi 403)', get('probeoff','/?id=1%20UNION%20SELECT%201,2,3--')==403)
print('\n## Scanner baru')
for ua in ['Mozilla/5.0 (l9scan/2.0.63; +https://leakix.net)','Mozilla/5.0 (compatible; CensysInspect/1.1)','Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity','Mozilla/5.0 (compatible; InternetMeasurement/1.0)']:
    ok('UA diblokir: '+ua[:45], get('dasar','/',ua=ua)==403)
print('\nRINGKAS: %d gagal'%len(G)); print(G)
try: os.kill(int(open(PIDF).read()), signal.SIGTERM)
except Exception: pass
