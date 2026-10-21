#!/usr/bin/env python3
# Uji regresi perbaikan audit guardd (21 Okt 2026): guardd NYATA disusun dari guardd.c dan dijalankan
# di network namespace terpisah dengan db/log/ipset sendiri. Tidak menyentuh /www/server/sentinel.
#
# Pemakaian: python3 -B guardd_audit_test.py <direktori payload>
import os, sys, json, time, shutil, tempfile, subprocess, sqlite3, socket

PAY = os.path.abspath(sys.argv[1])
if os.environ.get('ZYS_AUDIT_NETNS') != '1':
    os.environ['ZYS_AUDIT_NETNS'] = '1'
    os.execvp('unshare', ['unshare', '-n', sys.executable, '-B'] + sys.argv)

gagal = 0
def cek(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:400]))
    if not k: gagal += 1

T = tempfile.mkdtemp(prefix='zysaudit.', dir='/tmp')
D = T + '/d'
for d in ('etc', 'data', 'run', 'log', 'conf', 'logs'):
    os.makedirs(D + '/' + d)
GBIN = T + '/guardd'
r = subprocess.run(['gcc', '-O2', '-Wall', '-Wextra', '-o', GBIN, PAY + '/guardd.c', '-lsqlite3', '-lm'], capture_output=True, text=True)
cek('guardd.c disusun tanpa peringatan', r.returncode == 0 and not r.stderr.strip(), r.stderr[-500:])
LOG = D + '/logs/situs.test.log'
proc = None


def ipn(s):
    a, b, c, d = [int(x) for x in s.split('.')]
    return (a << 24) | (b << 16) | (c << 8) | d


def baris(ip, path, status, ua='Mozilla/5.0 Chrome', method='GET', ref='-'):
    return '%s - - [21/Oct/2026:09:00:00 +0700] "%s %s HTTP/1.1" %d 123 "%s" "%s"\n' % (ip, method, path, status, ref, ua)


def tulis(*bar):
    with open(LOG, 'a') as f:
        f.write(''.join(bar))


def conf(enforce, extra=''):
    open(D + '/etc/guardd.conf', 'w').write(
        'enforce = %d\ndb_path = %s/data/guardd.db\nrun_dir = %s/run\nlog_file = %s/log/guardd.log\n'
        'allow_file = %s/etc/allowlist.txt\nlearn_file = %s/etc/learned.tsv\nconf_dir = %s/conf\nlog_dir = %s/logs\n'
        'rescan_interval = 5\nstartup_backfill = 0\nflush_interval = 1\n%s' % (enforce, D, D, D, D, D, D, D, extra))


def ipset_members(s):
    o = subprocess.run(['/usr/sbin/ipset', 'list', s], capture_output=True, text=True).stdout
    return [l.split()[0] for l in o.splitlines() if l and l[0].isdigit()]


def tunggu(fn, detik=12):
    t0 = time.time()
    while time.time() - t0 < detik:
        if fn(): return True
        time.sleep(0.3)
    return fn()


def q(sql, a=()):
    c = sqlite3.connect(D + '/data/guardd.db', timeout=10)
    try: return c.execute(sql, a).fetchall()
    finally: c.close()


def ctl(cmd):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5)
    s.connect(D + '/run/guardd.sock'); s.sendall(cmd.encode())
    o = s.recv(4096).decode(); s.close()
    return o


def status():
    try: return json.load(open(D + '/run/status.json'))
    except Exception: return {}


def mulai(enforce, extra=''):
    global proc
    conf(enforce, extra)
    proc = subprocess.Popen([GBIN, '-f', '-c', D + '/etc/guardd.conf'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok = tunggu(lambda: os.path.exists(D + '/run/guardd.sock'), 10)
    time.sleep(1.5)
    return ok


def henti():
    global proc
    if proc:
        proc.terminate()
        try: proc.wait(10)
        except Exception: proc.kill()
        proc = None
    try: os.remove(D + '/run/guardd.sock')
    except Exception: pass


def ev_kind(ip):
    return [k for (k,) in q('SELECT kind FROM events WHERE ip=?', (ipn(ip),))]


tulis(baris('203.0.113.250', '/warm', 200))
open(D + '/etc/allowlist.txt', 'w').write('198.51.100.23/32\n')
try:
    print('## enforce=1')
    cek('daemon berjalan', mulai(1))
    # 1. UA alat
    tulis(*[baris('198.51.100.11', '/p%d' % i, 200, 'sqlmap/1.7.2#stable (https://sqlmap.org)') for i in range(22)])
    tulis(*[baris('198.51.100.12', '/p%d' % i, 200, 'Mozilla/5.0 (compatible; Nuclei - Open-source project)') for i in range(22)])
    tulis(*[baris('198.51.100.13', '/p%d' % i, 200, 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36') for i in range(22)])
    cek('UA sqlmap terdeteksi (dulu tidak pernah: buffer int)', tunggu(lambda: 'bad-ua' in ev_kind('198.51.100.11')), ev_kind('198.51.100.11'))
    cek('UA alat di tengah string Mozilla (Nuclei) terdeteksi', tunggu(lambda: 'bad-ua' in ev_kind('198.51.100.12')), ev_kind('198.51.100.12'))
    cek('peramban biasa tidak ditandai', not ev_kind('198.51.100.13'), ev_kind('198.51.100.13'))
    # 2. allowlist /32 tidak lagi memutihkan /24
    tulis(*[baris('198.51.100.99', '/.env', 404) for _ in range(25)])
    tulis(*[baris('198.51.100.23', '/.env', 404) for _ in range(25)])
    tulis(*[baris('10.200.1.1', '/.env', 404) for _ in range(25)])
    cek('tetangga /24 dari IP allowlist /32 tetap diblokir', tunggu(lambda: '198.51.100.99' in ipset_members('sentinel_ban')), ipset_members('sentinel_ban'))
    cek('IP allowlist /32 sendiri tidak diblokir', '198.51.100.23' not in ipset_members('sentinel_ban'))
    cek('10.200.1.1 (di dalam 10/8 bawaan) tidak diblokir; dulu hanya 10.0.0.0/24', '10.200.1.1' not in ipset_members('sentinel_ban'), ipset_members('sentinel_ban'))
    # 3. normalisasi path
    varian = ['//.env', '/./.env', '/%2eenv', '/.ENV', '/blog/.env', '/app/.git/config', '/sub/wp-login.php']
    tulis(*[baris('198.51.100.31', varian[i % len(varian)], 404) for i in range(25)])
    cek('varian //.env, /%2eenv, /.ENV, /blog/.env, ... dihitung scanner hingga ban', tunggu(lambda: '198.51.100.31' in ipset_members('sentinel_ban')), q('SELECT ip,kind,score FROM events WHERE ip=?', (ipn('198.51.100.31'),)))
    # 4. baris > 4 KB
    ref = 'https://x/' + 'A' * 4300
    tulis(*[baris('198.51.100.41', '/.env', 404, ref=ref) for _ in range(25)])
    tulis(baris('198.51.100.42', '/after-long', 200))
    cek('baris dengan Referer 4,3 KB tetap dinilai (kepala baris) hingga ban', tunggu(lambda: '198.51.100.41' in ipset_members('sentinel_ban')), status().get('parse_fail'))
    cek('baris normal sesudah baris panjang tetap terbaca', tunggu(lambda: any(t.get('ip') == '198.51.100.42' for t in status().get('top', []) or []) or bool(q('SELECT 1 FROM ip_minute WHERE ip=?', (ipn('198.51.100.42'),)))))
    # 5. throttle tidak menahan ban
    tulis(*[baris('198.51.100.51', '/.git/HEAD', 404) for _ in range(9)])
    cek('9 hit scanner (skor 72): masuk throttle', tunggu(lambda: '198.51.100.51' in ipset_members('sentinel_throttle')), ipset_members('sentinel_throttle'))
    tulis(*[baris('198.51.100.51', '/.git/HEAD', 404) for _ in range(12)])
    cek('hit berikutnya (skor >= 150) tetap BAN walau throttle masih berlaku (dulu kebal 30 menit)', tunggu(lambda: '198.51.100.51' in ipset_members('sentinel_ban')), (ipset_members('sentinel_ban'), q('SELECT aksi,alasan FROM aksi WHERE ip=?', (ipn('198.51.100.51'),))))
    cek('setelah ban, IP dikeluarkan dari set throttle', tunggu(lambda: '198.51.100.51' not in ipset_members('sentinel_throttle'), 4))
    # 6. flood
    tulis(*[baris('198.51.100.61', '/', 200) for _ in range(13000)])
    tulis(*[baris('198.51.100.62', '/', 200) for _ in range(4000)])
    tulis(*[baris('198.51.100.63', '/', 200) for _ in range(600)])
    cek('flood rata-rata >200 rps (13000/64 dtk): BAN, kategori flood', tunggu(lambda: '198.51.100.61' in ipset_members('sentinel_ban'), 15), (ipset_members('sentinel_ban'), q("SELECT alasan FROM aksi WHERE ip=?", (ipn('198.51.100.61'),))))
    cek('flood >60 rps (4000/64 dtk): throttle, bukan ban', tunggu(lambda: '198.51.100.62' in ipset_members('sentinel_throttle')) and '198.51.100.62' not in ipset_members('sentinel_ban'))
    cek('600 permintaan/menit (pengguna berat sah) tidak terkena', '198.51.100.63' not in ipset_members('sentinel_throttle') + ipset_members('sentinel_ban'))
    # 7. WordPress
    tulis(*[baris('198.51.100.71', '/wp-content/themes/a/style%d.css' % i, 200) for i in range(60)])
    tulis(*[baris('198.51.100.71', '/wp-json/wp/v2/posts', 200) for i in range(20)])
    tulis(*[baris('198.51.100.71', '/wp-includes/js/jquery.js', 304) for i in range(20)])
    time.sleep(4)
    cek('pengunjung WordPress (aset /wp-content, /wp-json 200/304) tidak ditandai', not ev_kind('198.51.100.71'), ev_kind('198.51.100.71'))
    tulis(*[baris('198.51.100.72', '/wp-login.php', 200, method='POST') for _ in range(15)])
    cek('brute wp-login (POST dijawab 200) kini dihitung: throttle', tunggu(lambda: '198.51.100.72' in ipset_members('sentinel_throttle')), ev_kind('198.51.100.72'))
    tulis(baris('198.51.100.73', '/wp-login.php', 200, method='POST'), baris('198.51.100.73', '/wp-admin/', 302))
    time.sleep(3)
    cek('satu login WordPress sah tidak ditandai', not ev_kind('198.51.100.73') and '198.51.100.73' not in ipset_members('sentinel_throttle'))
    # 8. /upload.php tidak lagi dibebaskan oleh awalan "/up"
    tulis(*[baris('198.51.100.81', '/upload%d.php' % i, 404) for i in range(25)])
    cek('enumerasi /uploadN.php dihitung (dulu dibebaskan awalan /up)', tunggu(lambda: bool(ev_kind('198.51.100.81'))), ev_kind('198.51.100.81'))
    henti()

    print('\n## enforce=0: antrean review')
    cek('daemon (enforce=0) berjalan', mulai(0))
    tulis(*[baris('198.51.100.91', '/.env', 404) for _ in range(15)])
    ok_rev = tunggu(lambda: bool(q("SELECT 1 FROM review WHERE ip=? AND status='tunggu'", (ipn('198.51.100.91'),))) and '198.51.100.91' in ipset_members('sentinel_review'), 20)
    cek('skor >= review_score: masuk antrean review dan set review', ok_rev, (q('SELECT * FROM review'), ipset_members('sentinel_review'), q('SELECT ip,kind,score,level FROM events WHERE ip=?', (ipn('198.51.100.91'),))))
    tulis(*[baris('198.51.100.91', '/.env', 404) for _ in range(5)])
    time.sleep(3)
    n = q("SELECT COUNT(*) FROM aksi WHERE ip=? AND aksi='review'", (ipn('198.51.100.91'),))[0][0]
    cek('review dicatat sekali (tidak dikueri/ditulis ulang tiap detak)', n == 1, n)
    o = ctl('ban 198.51.100.91')
    cek('persetujuan (ctl ban): masuk sentinel_ban DAN keluar dari sentinel_review', '"ok":true' in o and '198.51.100.91' in ipset_members('sentinel_ban') and '198.51.100.91' not in ipset_members('sentinel_review'), (o, ipset_members('sentinel_review')))
    henti()
finally:
    henti()
shutil.rmtree(T, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal)
sys.exit(1 if gagal else 0)
