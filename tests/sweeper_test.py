#!/usr/bin/env python3
# Uji ZySentinel Sweeper di sandbox (tanpa menyentuh produksi): mesin C, mesin Python, paritas, karantina, abaikan/allowlist,
# pengecualian path, inkremental, validasi konfigurasi, keamanan karantina (hash berubah, symlink), kalibrasi, batal.
# Sampel webshell dibuat saat uji berjalan di folder sementara (tidak disimpan di repo).
# Pemakaian: sweeper_test.py <direktori payload>
import os, sys, json, time, shutil, sqlite3, subprocess, tempfile, hashlib, signal

PAY = os.path.abspath(sys.argv[1])
T = tempfile.mkdtemp(prefix='zysweep.', dir='/tmp')
BASE = T + '/base'; BIN = T + '/bin'; WWW = T + '/www'; NGX = T + '/nginx'
for d in (BASE + '/etc', BASE + '/log', BASE + '/data', BASE + '/run', BIN, WWW, NGX):
    os.makedirs(d, exist_ok=True)
ENV = dict(os.environ, ZYS_SWEEPER_BASE=BASE, ZYS_SWEEPER_BIN=BIN, ZYS_SWEEPER_NGINX=NGX, ZYS_SWEEPER_APACHE=T + '/apache', ZYS_SWEEPER_WWWROOT=WWW)
gagal = 0
def T_(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]), flush=True)
    if not k: gagal += 1
def sw(*a, check=True, timeout=300):
    r = subprocess.run(['python3', PAY + '/sentinel-sweeper.py'] + list(a), capture_output=True, text=True, env=ENV, timeout=timeout)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {'status': False, 'msg': r.stderr[-300:]}
    except Exception:
        return {'status': False, 'msg': (r.stdout + r.stderr)[-300:]}
def w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'wb').write(data if isinstance(data, bytes) else data.encode())
def conf(**kw):
    r = sw('config-set', json.dumps(kw))
    return r

try:
    # ---- siapkan mesin
    shutil.copy(PAY + '/sentinel-sweeplib.py', BIN + '/sentinel-sweeplib.py')
    shutil.copy(PAY + '/sentinel-sweeper.c', BIN + '/sentinel-sweeper.c')
    r = subprocess.run(['gcc', '-O2', '-std=gnu11', '-Wall', '-o', BIN + '/sentinel-sweeper', PAY + '/sentinel-sweeper.c', '-lm'], capture_output=True, text=True)
    T_('mesin C dapat disusun (gcc -Wall)', r.returncode == 0 and 'error' not in r.stderr, r.stderr[-300:])
    con = sqlite3.connect(BASE + '/data/guardd.db')
    con.execute('CREATE TABLE notif( id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER, jenis TEXT, isi TEXT, terkirim INTEGER DEFAULT 0, coba INTEGER DEFAULT 0, galat TEXT)')
    con.commit(); con.close()
    # dua vhost
    for v in ('situs-a.test', 'situs-b.test'):
        os.makedirs('%s/%s/public' % (WWW, v), exist_ok=True)
        open('%s/%s.conf' % (NGX, v), 'w').write('server {\n  server_name %s;\n  root %s/%s/public;\n}\n' % (v, WWW, v))

    JAHAT = {
        'a.test/public/uploads/shell1.php': b'<?php @eval($_POST["x"]);?>',
        'a.test/public/uploads/shell2.php': b'<?php system($_GET["cmd"]);',
        'a.test/public/uploads/shell3.php': b'<?php $f=$_POST["f"]; $f($_POST["a"]);',
        'a.test/public/wp-content/dynfn.php': b'<?php $a="sys"."tem"; $a($_REQUEST["c"]);',
        'a.test/public/wp-content/preg.php': b"<?php preg_replace('/x/e', $_POST['c'], 'x');",
        'a.test/public/wp-content/ext.php': b'<?php @extract($_REQUEST); @die($ctime($atime));',
        'a.test/public/wp-content/drop.php': b'<?php file_put_contents($_POST["p"], base64_decode($_POST["d"]));',
        'b.test/public/assert.php': b'<?php assert($_POST["a"]);',
        'b.test/public/octal.php': b'<?php $r="\\142\\141\\163\\145\\66\\64\\137\\144\\145\\143\\157\\144\\145"; @eval($r("ZWNobyAxOw=="));',
        'b.test/public/cmd.jsp': b'<%Runtime.getRuntime().exec(request.getParameter("c"));%>',
        'b.test/public/x.asp': b'<%eval request("x")%>',
        'b.test/public/callb.php': b'<?php usort($a, $_GET["f"]);',
    }
    SUSP = {'b.test/public/inc.php': b"<?php include('app/' . $_GET['app'] . '/class.php');"}
    SAH = {
        'a.test/public/index.php': b'<?php\nnamespace App;\nclass Home { public function index() { return view("home"); } }\n',
        'a.test/public/doc.php': b'<?php\n/**\n * Contoh: eval($_POST["x"]) jangan dipakai; system($_GET["c"]) berbahaya\n */\nfunction aman($x){ return htmlspecialchars($x); }\n',
        'a.test/public/komentar.php': b'<?php\n// eval($_POST["x"]);\n# system($_GET["c"]);\necho "halo";\n',
        'a.test/public/string.php': b'<?php $s = \'eval($_POST[x]); system($_GET[c])\'; echo strlen($s);\n',
        'a.test/public/cli.php': b'<?php $cmd = escapeshellarg($argv[1]); exec($cmd, $out); echo implode("\\n", $out);\n',
        'a.test/public/preg.php': b"<?php echo preg_replace('/a/i', 'b', $_GET['q'] ?? '');\n",
        'a.test/public/cb.php': b'<?php $r = array_map("trim", $_POST["ids"] ?? []); usort($r, fn($a, $b) => $a <=> $b);\n',
        'a.test/public/anon.php': b'<?php function f($d){ $x = $d; return eval("return 1;"); }\nfunction g(){ $p = 1; return $p; }\n',
        'b.test/public/ok.jsp': b'<%@ page language="java" %><html><body><%= new java.util.Date() %></body></html>',
        'b.test/public/ok.asp': b'<% Response.Write("halo") %>',
        'b.test/public/readme.txt': b'<?php eval($_POST[x]);',
        'b.test/public/gambar.php.jpg': b'\xff\xd8\xff\xe0' + os.urandom(500),
    }
    for d in (JAHAT, SUSP, SAH):
        for k, v in d.items():
            w('%s/situs-%s' % (WWW, k), v)

    print('\n## 1. Status awal dan konfigurasi')
    st = sw('status')['msg']
    T_('mesin C terdeteksi', st['engine']['kind'] == 'c' and st['engine']['c_available'], st['engine'])
    T_('dua vhost dan root-nya ditemukan dari konfigurasi nginx', sorted(r['vhost'] for r in st['roots']) == ['situs-a.test', 'situs-b.test'], st['roots'])
    T_('konfigurasi bawaan: karantina otomatis aktif, ambang karantina 90', st['config']['auto_quarantine'] is True and st['config']['quarantine_min_score'] == 90)
    for patch, ket in [({'quarantine_min_score': 80}, 'ambang karantina < 90 ditolak'), ({'nice': 99}, 'nice di luar rentang ditolak'),
                       ({'custom_paths': ['relatif/path']}, 'path kustom relatif ditolak'), ({'custom_paths': ['/tmp/../etc']}, 'path kustom dengan .. ditolak'),
                       ({'custom_paths': ['/tidak/ada/sama/sekali']}, 'path kustom yang tidak ada ditolak'), ({'custom_paths': ['/']}, 'path kustom "/" ditolak'),
                       ({'engine': 'perl'}, 'engine tak dikenal ditolak'), ({'aneh': 1}, 'kunci tak dikenal ditolak'), ({'entropy': {'mean': 9}}, 'entropy di luar rentang ditolak'),
                       ({'exclude': ['a\nb']}, 'pengecualian dengan newline ditolak'), ({'auto_quarantine': 'ya'}, 'bukan boolean ditolak')]:
        T_(ket, conf(**patch)['status'] is False, conf(**patch))

    print('\n## 2. Pemindaian semua vhost dengan karantina otomatis (mesin C)')
    r = sw('scan', '--all-vhosts')
    T_('pemindaian selesai', r['status'] is True, r)
    fnd = {e['path']: e for e in sw('findings')['msg']}
    web = [p for p, e in fnd.items() if e['verdict'] == 'webshell']
    T_('%d dari %d webshell terdeteksi dan dikarantina' % (len([p for p in web if fnd[p]['status'] == 'quarantined']), len(JAHAT)),
       len(web) == len(JAHAT) and all(fnd[p]['status'] == 'quarantined' for p in web), sorted(set('%s/situs-%s' % (WWW, k) for k in JAHAT) - set(web)))
    T_('berkas webshell sudah tidak ada di webroot', not any(os.path.exists('%s/situs-%s' % (WWW, k)) for k in JAHAT))
    T_('berkas sah TIDAK tersentuh (%d berkas)' % len(SAH), all(os.path.exists('%s/situs-%s' % (WWW, k)) for k in SAH))
    T_('tidak ada temuan pada berkas sah', not any(p.endswith(tuple(k.split('/')[-1] for k in SAH)) and fnd[p]['verdict'] != 'x' for p in fnd if any(p.endswith('/' + k.split('/')[-1]) for k in SAH) and fnd[p]['status'] == 'open'), [p for p in fnd if any(p.endswith('/' + k.split('/')[-1]) for k in SAH)])
    susp = [p for p, e in fnd.items() if e['verdict'] == 'suspicious']
    T_('berkas mencurigakan dilaporkan tetapi TIDAK dikarantina', len(susp) == 1 and fnd[susp[0]]['status'] == 'open' and os.path.exists(susp[0]), susp)
    qf = sorted(os.listdir(BASE + '/av/quarantine/files')); qm = sorted(os.listdir(BASE + '/av/quarantine/meta'))
    T_('karantina memakai format AV: %d berkas + %d metadata' % (len(qf), len(qm)), len(qf) == len(JAHAT) and len(qm) == len(JAHAT))
    meta = dict(l.strip().split('=', 1) for l in open(BASE + '/av/quarantine/meta/' + qm[0]) if '=' in l)
    T_('metadata memuat kunci yang dibaca tab Karantina AV', set(meta) == {'quarantined_at', 'original_path', 'quarantine_path', 'signature', 'sha256', 'size', 'uid', 'gid', 'mode'}, meta.keys())
    T_('signature berawalan ZySweep.Webshell dan sha256 benar', meta['signature'].startswith('ZySweep.Webshell.') and hashlib.sha256(open(meta['quarantine_path'], 'rb').read()).hexdigest() == meta['sha256'])
    T_('berkas karantina bermode 600', oct(os.stat(meta['quarantine_path']).st_mode & 0o777) == '0o600')
    c = sqlite3.connect(BASE + '/data/guardd.db'); nn = c.execute("select count(*) from notif where jenis='sweeper'").fetchone()[0]; c.close()
    T_('satu notifikasi per karantina (%d)' % nn, nn == len(JAHAT), nn)
    av = open(PAY + '/sentinel-av.sh').read()
    T_('format metadata sama dengan cv_quarantine_fallback di sentinel-av.sh', all(('printf \'%s=' % k) in av for k in meta), meta.keys())
    stj = sw('status')['msg']
    T_('status: ringkasan pemindaian terakhir tercatat', stj['last']['summary']['webshell'] >= len(JAHAT) and stj['last']['engine'] == 'c', stj['last'])

    print('\n## 3. Paritas mesin Python dan C pada pohon yang sama')
    # pulihkan webshell ke tempat semula (salinan) agar kedua mesin melihat berkas yang sama
    for k, v in JAHAT.items(): w('%s/situs-%s' % (WWW, k), v)
    def verdicts(engine):
        conf(engine=engine, auto_quarantine=False)
        sw('scan', '--all-vhosts', '--report-only')
        return {os.path.relpath(e['path'], WWW): (e['verdict'], e['score'], sorted(x[0] for x in e['rules'])) for e in sw('findings')['msg'] if e['status'] == 'open'}
    vc = verdicts('c'); vp = verdicts('python')
    T_('hasil C = hasil Python (verdict, skor, indikator) pada %d berkas' % len(vc), vc == vp and len(vc) == len(JAHAT) + len(SUSP), {k: (vc.get(k), vp.get(k)) for k in set(vc) | set(vp) if vc.get(k) != vp.get(k)})
    conf(engine='auto', auto_quarantine=True)

    print('\n## 4. Mode laporan saja, pengecualian path, dan allowlist')
    r = sw('scan', '--all-vhosts', '--report-only')
    T_('mode --report-only: tidak ada yang dikarantina', all(os.path.exists('%s/situs-%s' % (WWW, k)) for k in JAHAT))
    conf(exclude=['/uploads/', '/.git/'])
    sw('scan', '--all-vhosts', '--report-only')
    f2 = {e['path'] for e in sw('findings')['msg'] if e['status'] == 'open'}
    T_('pengecualian path dipakai: berkas di /uploads/ tidak dilaporkan (bug ShellSweepPlus: pengecualian tak pernah dibaca)', not any('/uploads/' in p for p in f2) and any('/wp-content/' in p for p in f2), sorted(f2)[:3])
    conf(exclude=['/.git/', '/node_modules/'])
    target = '%s/situs-a.test/public/uploads/shell1.php' % WWW
    sha = hashlib.sha256(open(target, 'rb').read()).hexdigest()
    open(BASE + '/etc/sweeper_allow.txt', 'w').write(sha.upper() + '  # huruf besar sengaja (bug ShellSweep: hash HEX besar tak pernah cocok)\n')
    sw('scan', '--all-vhosts', '--report-only')
    f3 = {e['path'] for e in sw('findings')['msg'] if e['status'] == 'open'}
    T_('allowlist HEX HURUF BESAR tetap cocok (versi asli membandingkan besar vs kecil)', target not in f3 and any('shell2.php' in p for p in f3), target in f3)
    T_('allow-list menampilkan entri dalam huruf kecil', sw('allow-list')['msg'][0]['sha256'] == sha)
    open(target, 'ab').write(b'\n// diubah')
    sw('scan', '--all-vhosts', '--report-only')
    f4 = {e['path'] for e in sw('findings')['msg'] if e['status'] == 'open'}
    T_('berkas yang diubah (hash baru) dilaporkan lagi', target in f4)
    T_('allow-remove menghapus entri', sw('allow-remove', sha)['status'] is True and sw('allow-list')['msg'] == [])

    print('\n## 5. Tindakan manual: karantina, tandai sah, abaikan; keamanan')
    sw('scan', '--all-vhosts', '--report-only')
    p_susp = '%s/situs-b.test/public/inc.php' % WWW
    T_('abaikan: status ignored dan tidak dilaporkan lagi pada pemindaian ulang', sw('action', 'ignore', p_susp)['status'] is True and (sw('scan', '--all-vhosts', '--report-only') and [e for e in sw('findings')['msg'] if e['path'] == p_susp][0]['status'] == 'ignored'))
    w(p_susp, b"<?php include('app/' . $_GET['mod'] . '/other.php');")
    sw('scan', '--all-vhosts', '--report-only')
    T_('isi berubah: status ignored dibuka kembali (open)', [e for e in sw('findings')['msg'] if e['path'] == p_susp][0]['status'] == 'open')
    r = sw('action', 'quarantine', p_susp)
    T_('karantina manual berhasil', r['status'] is True and not os.path.exists(p_susp), r)
    # hash berubah antara pindai dan karantina
    p2 = '%s/situs-a.test/public/wp-content/preg.php' % WWW
    sw('scan', '--all-vhosts', '--report-only')
    open(p2, 'ab').write(b'\n// ubah')
    r = sw('action', 'quarantine', p2)
    T_('karantina ditolak bila berkas berubah sejak dipindai (TOCTOU)', r['status'] is False and 'berubah' in r['msg'] and os.path.exists(p2), r)
    # symlink pada direktori induk
    os.makedirs(T + '/luar', exist_ok=True)
    w(T + '/luar/korban.php', b'<?php @eval($_POST["x"]);')
    os.symlink(T + '/luar', '%s/situs-a.test/public/tautan' % WWW)
    fj = jj = json.load(open(BASE + '/sweeper/findings.json'))
    fj['%s/situs-a.test/public/tautan/korban.php' % WWW] = {'path': '%s/situs-a.test/public/tautan/korban.php' % WWW, 'verdict': 'webshell', 'score': 98, 'rules': [['eval-input', 98, '']], 'sha256': hashlib.sha256(open(T + '/luar/korban.php', 'rb').read()).hexdigest(), 'status': 'open'}
    json.dump(fj, open(BASE + '/sweeper/findings.json', 'w'))
    r = sw('action', 'quarantine', '%s/situs-a.test/public/tautan/korban.php' % WWW)
    T_('karantina menolak path yang melewati symlink (berkas di luar vhost tidak tersentuh)', r['status'] is False and os.path.exists(T + '/luar/korban.php'), r)
    r = sw('action', 'quarantine', '/etc/passwd')
    T_('aksi pada path di luar vhost ditolak', r['status'] is False, r)
    r = sw('scan', '--path', '/etc')
    T_('pemindaian path di luar vhost/kustom ditolak', r['status'] is False, r)
    os.unlink('%s/situs-a.test/public/tautan' % WWW)
    sw('action', 'allow', p2)
    T_('"tandai sah" ditolak bila berkas berubah sejak dipindai', 'berubah' in sw('action', 'allow', p2)['msg'])

    print('\n## 6. Folder kustom, inkremental terjadwal')
    os.makedirs(T + '/kustom/sub', exist_ok=True)
    w(T + '/kustom/sub/x.php', b'<?php system($_GET["c"]);')
    T_('folder kustom valid diterima', conf(custom_paths=[T + '/kustom'])['status'] is True)
    sw('scan', '--all-vhosts')
    T_('webshell di folder kustom ikut dikarantina', not os.path.exists(T + '/kustom/sub/x.php') and any('kustom' in e['vhost'] for e in sw('findings')['msg']))
    conf(incremental_margin_s=0)
    w('%s/situs-a.test/public/lama_tak_berubah.php' % WWW, b'<?php @eval($_POST["lama"]);')
    time.sleep(1.3)
    sw('scan', '--all-vhosts', '--report-only')                  # pemindaian penuh terakhir: berkas lama sudah dilihat, tidak dikarantina
    time.sleep(1.3)
    w('%s/situs-a.test/public/baru.php' % WWW, b'<?php @eval($_POST["z"]);')
    r = sw('scan', '--all-vhosts', '--scheduled')
    T_('terjadwal inkremental: berkas baru dikarantina', not os.path.exists('%s/situs-a.test/public/baru.php' % WWW), r)
    T_('terjadwal inkremental: berkas lama yang tidak berubah dilewati (bukti hemat; hanya %s berkas dibaca)' % r['msg']['summary']['scanned'], r['msg']['full'] is False and os.path.exists('%s/situs-a.test/public/lama_tak_berubah.php' % WWW) and r['msg']['summary']['scanned'] <= 3, r)
    sw('scan', '--all-vhosts')
    T_('pemindaian penuh menangkap yang dilewati inkremental', not os.path.exists('%s/situs-a.test/public/lama_tak_berubah.php' % WWW))

    print('\n## 7. Batal dan kalibrasi entropi')
    os.makedirs(T + '/banyak', exist_ok=True)
    import random
    random.seed(5)
    KATA = ['alpha', 'beta', 'gamma', 'delta', 'laporan', 'pelanggan', 'faktur', 'stok', 'gudang', 'produk', 'harga', 'diskon', 'pajak', 'total', 'tanggal']
    for i in range(3000):
        w('%s/banyak/f%d.php' % (T, i), '<?php\n// %s\nfunction f%d($a, $b) {\n    $hasil = [];\n    foreach ($a as $k => $v) { $hasil[$k] = $v + $b + %d; }\n    return $hasil;\n}\n' % (' '.join(random.choice(KATA) for _ in range(40)), i, i))
    conf(custom_paths=[T + '/banyak'], throttle_ms=300)
    p = subprocess.Popen(['python3', PAY + '/sentinel-sweeper.py', 'scan', '--path', T + '/banyak'], env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)
    T_('pemindaian panjang berstatus running', sw('status')['msg']['running'] is True)
    sw('abort'); p.wait(timeout=60)
    time.sleep(0.5)
    T_('abort menghentikan pemindaian: status aborted', sw('status')['msg']['job']['state'] == 'aborted', sw('status')['msg']['job'])
    T_('setelah dibatalkan tidak ada proses mesin sisa', subprocess.run('pgrep -f "[s]entinel-sweeper .*banyak"', shell=True, capture_output=True).returncode != 0)
    conf(throttle_ms=0)
    r = sw('calibrate', T + '/banyak')
    T_('kalibrasi pada pohon PHP bersih (3000 berkas) memperbarui prior entropi', r['status'] is True and r['msg']['n'] >= 2900, r)
    T_('prior baru tersimpan di konfigurasi', abs(sw('config')['msg']['entropy']['mean'] - r['msg']['mean']) < 1e-6)
    w(T + '/banyak/jahat.php', b'<?php system($_GET["c"]);')
    r = sw('calibrate', T + '/banyak')
    T_('kalibrasi ditolak bila pohon memuat temuan', r['status'] is False and 'ditandai' in r['msg'], r)
    r = sw('calibrate', T + '/www')
    T_('kalibrasi ditolak bila berkas PHP terlalu sedikit', r['status'] is False, r)

    print('\n## 8. Mesin tidak ada: fallback Python dan build')
    os.rename(BIN + '/sentinel-sweeper', BIN + '/sentinel-sweeper.hilang')
    conf(custom_paths=[], throttle_ms=0, engine='auto')
    st = sw('status')['msg']['engine']
    T_('tanpa biner C: mesin terdeteksi python', st['kind'] == 'python' and st['c_available'] is False and st['gcc'] is True, st)
    w('%s/situs-b.test/public/baru2.php' % WWW, b'<?php @eval($_POST["z"]);')
    r = sw('scan', '--path', '%s/situs-b.test/public' % WWW)
    T_('scan memicu penyusunan otomatis biner C bila gcc ada (tidak jatuh ke Python lambat)', os.path.exists(BIN + '/sentinel-sweeper') and r['status'] is True and r['msg']['engine'] == 'c', r)
    T_('stempel hash sumber ditulis', os.path.exists(BIN + '/sentinel-sweeper.srchash'))
    T_('build kedua: sudah mutakhir', sw('build')['msg'] == 'sudah mutakhir', sw('build'))
    print('\n## 9. Folder karantina mengikuti pustaka ClamAV bersama (seperti sentinel-av.sh di produksi)')
    os.makedirs(T + '/extq/files'); os.makedirs(T + '/extq/meta')
    open(T + '/realtime.conf', 'w').write('QUARANTINE_DIR=%s/extq\nQUARANTINE_FILES="%s/extq/files"  # komentar\nQUARANTINE_META=%s/extq/meta\nQUARANTINE_DAYS=30\n' % (T, T, T))
    open(T + '/clamav-common.sh', 'w').write('# tiruan\n')
    ENV['ZYS_SWEEPER_AVCOMMON'] = T + '/clamav-common.sh'; ENV['ZYS_SWEEPER_AVCONF'] = T + '/realtime.conf'
    w('%s/situs-b.test/public/ext.php' % WWW, b'<?php @eval($_POST["e"]);')
    n_lama = len(os.listdir(BASE + '/av/quarantine/files'))
    r = sw('scan', '--path', '%s/situs-b.test/public' % WWW)
    T_('karantina masuk ke folder pustaka bersama (QUARANTINE_FILES/META), tidak ke folder cadangan', len(os.listdir(T + '/extq/files')) == 1 and len(os.listdir(T + '/extq/meta')) == 1 and len(os.listdir(BASE + '/av/quarantine/files')) == n_lama, r)
    mm = dict(l.strip().split('=', 1) for l in open(T + '/extq/meta/' + os.listdir(T + '/extq/meta')[0]) if '=' in l)
    T_('metadata di folder bersama tetap memuat original_path dan signature', mm['original_path'].endswith('ext.php') and mm['signature'].startswith('ZySweep.'), mm)
    os.remove(T + '/clamav-common.sh')
    w('%s/situs-b.test/public/ext2.php' % WWW, b'<?php @eval($_POST["e"]);')
    sw('scan', '--path', '%s/situs-b.test/public' % WWW)
    T_('tanpa pustaka bersama: kembali ke folder cadangan', len(os.listdir(BASE + '/av/quarantine/files')) == n_lama + 1)
finally:
    sw('abort')
    shutil.rmtree(T, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal)
sys.exit(1 if gagal else 0)
