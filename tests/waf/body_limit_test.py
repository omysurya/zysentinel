#!/usr/bin/env python3
# Uji batas badan WAF (aturan 8000217-8000219) dan pembatasan log audit, dengan Coraza NYATA:
# ruleset disusun di direktori sementara dari payload/zyrules, lalu biner nginx produksi dijalankan
# dengan konfigurasi sementara di network namespace terpisah (127.0.0.1). Tidak ada reload, tidak ada
# berkas produksi yang ditulis. Bisa dibandingkan dengan berkas base.conf.in lama:
#
#   python3 -B body_limit_test.py <direktori payload> [base.conf.in pembanding]
import os, sys, json, time, shutil, tempfile, subprocess, glob

PAY = os.path.abspath(sys.argv[1])
BASE_IN = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else PAY + '/zyrules/zysentinel-base.conf.in'
if os.environ.get('ZYS_WAF_NETNS') != '1':
    os.environ['ZYS_WAF_NETNS'] = '1'
    os.execvp('unshare', ['unshare', '-n', sys.executable, '-B'] + sys.argv)
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)

PROD = '/www/server/sentinel'
CACHE = os.path.dirname(PAY) + '/coraza-cache'
NGINX = '/www/server/nginx/sbin/nginx'
gagal = 0
def cek(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]))
    if not k: gagal += 1

T = tempfile.mkdtemp(prefix='zyswaf.', dir='/tmp')
ZY = T + '/zy'
shutil.copytree(PAY + '/zyrules', ZY)
shutil.copy(BASE_IN, ZY + '/zysentinel-base.conf.in')
for f in ('zysentinel-config.local.conf', 'zysentinel-exclusions.local.conf'):
    if os.path.isfile(PROD + '/waf/zyrules/' + f):
        shutil.copy(PROD + '/waf/zyrules/' + f, ZY + '/' + f)
os.makedirs(T + '/etc')
shutil.copy(PROD + '/etc/waf.conf', T + '/etc/waf.conf')
if os.path.isdir(PROD + '/etc/waf-lists'):
    shutil.copytree(PROD + '/etc/waf-lists', T + '/etc/waf-lists')
open(T + '/etc/allowlist.txt', 'w').write('')   # IP uji (127.0.0.1) tidak boleh dikecualikan
AUDIT = T + '/audit.jsonl'
env = dict(os.environ, SENTINEL_BASE=T, SENTINEL_WAF_CONF=T + '/etc/waf.conf', SENTINEL_ZY_DIR=ZY,
           SENTINEL_CRS_DIR=PROD + '/waf/coraza/rules', SENTINEL_WAF_LISTS=T + '/etc/waf-lists',
           SENTINEL_ALLOWLIST=T + '/etc/allowlist.txt', SENTINEL_WAF_AUDIT=AUDIT, SENTINEL_WEB_USER='www')
r = subprocess.run([sys.executable, '-B', PAY + '/sentinel-zyrules.py', 'build'], env=env, capture_output=True, text=True)
cek('ruleset disusun di sandbox', r.returncode == 0 and os.path.isfile(ZY + '/gen/main.conf'), r.stderr[-400:])

mod = glob.glob(CACHE + '/modules/*/ngx_http_coraza_module.so')[0]
lib = glob.glob(CACHE + '/libcoraza/*/lib/libcoraza.so')[0]
for d in ('lib', 'logs', 'tmp', 'html'):
    os.makedirs(T + '/' + d, exist_ok=True)
shutil.copy(mod, T + '/coraza.so'); shutil.copy(lib, T + '/lib/libcoraza.so')
open(T + '/html/index.html', 'w').write('ok\n')
lua = ''
for l in open('/www/server/nginx/conf/nginx.conf'):
    if l.strip().startswith('lua_package_path'):
        lua = l.strip(); break
open(T + '/nginx.conf', 'w').write('''load_module %(t)s/coraza.so;
user www;
worker_processes 1;
pid %(t)s/nginx.pid;
error_log %(t)s/logs/error.log notice;
events { worker_connections 64; }
http {
  %(lua)s
  access_log off;
  client_max_body_size 60m;
  client_body_temp_path %(t)s/tmp/b; proxy_temp_path %(t)s/tmp/p;
  fastcgi_temp_path %(t)s/tmp/f; uwsgi_temp_path %(t)s/tmp/u; scgi_temp_path %(t)s/tmp/s;
  server {
    listen 127.0.0.1:18080;
    coraza on;
    coraza_rules_file %(zy)s/gen/main.conf;
    root %(t)s/html;
    location / { }
  }
}
''' % {'t': T, 'zy': ZY, 'lua': lua})
subprocess.run(['chmod', '-R', 'a+rX', T])
open(AUDIT, 'a').close(); shutil.chown(AUDIT, 'www', 'www')
envn = dict(os.environ, LD_LIBRARY_PATH=T + '/lib')
r = subprocess.run([NGINX, '-p', T, '-c', T + '/nginx.conf', '-e', T + '/logs/startup.log', '-t'], env=envn, capture_output=True, text=True)
cek('nginx -t terisolasi menerima ruleset', r.returncode == 0, (r.stdout + r.stderr)[-500:])
subprocess.run([NGINX, '-p', T, '-c', T + '/nginx.conf', '-e', T + '/logs/startup.log'], env=envn, check=True)
time.sleep(1.5)


def curl(*a):
    r = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code} %{time_total}', '--max-time', '60'] + list(a) + ['http://127.0.0.1:18080/'],
                       capture_output=True, text=True)
    k, t = (r.stdout.split() + ['000', '0'])[:2]
    return int(k), float(t)


big = T + '/big.txt'
open(big, 'w').write('a' * 140 * 1024)
upl = T + '/upload.bin'
open(upl, 'wb').write(os.urandom(1024 * 1024))
hasil = {}
try:
    hasil['multipart_teks'] = curl('-F', 'komentar=<' + big)
    hasil['tanpa_ct'] = curl('-X', 'POST', '-H', 'Content-Type:', '--data-binary', '@' + big)
    hasil['urlencoded'] = curl('--data-binary', '@' + big)
    hasil['multipart_berkas_1mb'] = curl('-F', 'berkas=@' + upl)
    hasil['multipart_kecil'] = curl('-F', 'nama=budi', '-F', 'catatan=halo dunia')
    hasil['get_sqli'] = curl('-G', '--data-urlencode', "q=1' UNION SELECT password FROM users--")
    hasil['get_biasa'] = curl()
    subprocess.run(['curl', '-s', '-o', '/dev/null', 'http://127.0.0.1:18080/tidak-ada'])
finally:
    subprocess.run([NGINX, '-p', T, '-c', T + '/nginx.conf', '-s', 'quit'], env=envn)
    time.sleep(1)

for k, v in hasil.items():
    print('    %-22s status %s  %.2f dtk' % (k, v[0], v[1]))
cek('multipart dengan field TEKS 140 KB ditolak 413 dengan cepat', hasil['multipart_teks'][0] == 413 and hasil['multipart_teks'][1] < 1.0, hasil['multipart_teks'])
cek('badan 140 KB tanpa Content-Type ditolak 413 dengan cepat', hasil['tanpa_ct'][0] == 413 and hasil['tanpa_ct'][1] < 1.0, hasil['tanpa_ct'])
cek('urlencoded 140 KB tetap 413 (aturan lama)', hasil['urlencoded'][0] == 413)
cek('unggahan BERKAS 1 MB multipart tidak terkena batas argumen', hasil['multipart_berkas_1mb'][0] not in (403, 413), hasil['multipart_berkas_1mb'])
cek('form multipart kecil lolos WAF', hasil['multipart_kecil'][0] not in (403, 413), hasil['multipart_kecil'])
cek('SQLi tetap diblokir 403', hasil['get_sqli'][0] == 403, hasil['get_sqli'])
cek('GET biasa 200', hasil['get_biasa'][0] == 200, hasil['get_biasa'])
uris = []
for l in open(AUDIT):
    try: uris.append((json.loads(l)['transaction']['response'].get('status'), json.loads(l)['transaction']['request']['uri']))
    except Exception: pass
cek('log audit: 404 aplikasi tanpa rule match TIDAK dicatat', not any(u == '/tidak-ada' for _, u in uris), uris)
bocor = [l for l in open(AUDIT) if '"headers"' in l and json.loads(l)['transaction']['request'].get('headers')]
cek('log audit: tidak ada header request (Cookie) yang tersimpan', not bocor, bocor[:1])
cek('log audit: metode dan URI tetap ada untuk panel', all(u for _, u in uris) and len(uris) > 0, uris)
cek('log audit: permintaan yang diblokir tetap dicatat', any(s == 403 for s, _ in uris), uris)
if os.environ.get('ZYS_WAF_DUMP'):
    for l in open(AUDIT):
        j = json.loads(l)['transaction']
        print('    AUDIT', j['response'].get('status'), j['request'].get('method'), j['request'].get('uri'), 'headers=' + ','.join(sorted((j['request'].get('headers') or {}).keys())))
shutil.rmtree(T, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal)
sys.exit(1 if gagal else 0)
