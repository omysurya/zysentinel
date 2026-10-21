#!/usr/bin/env python3
# Uji API panel Sweeper (sentinel_main.py -> sentinel-sweeper.py) di sandbox: validasi parameter, pemindaian di latar,
# temuan, aksi, konfigurasi, jadwal. Memakai direktori sementara (tidak menyentuh /www/server/sentinel produksi).
# Pemakaian: /www/server/panel/pyenv/bin/python3 sweeper_api_test.py <direktori payload>
import os, sys, json, time, shutil, tempfile, subprocess, sqlite3
PAY = os.path.abspath(sys.argv[1])
sys.path.insert(0, '/www/server/panel'); sys.path.insert(0, '/www/server/panel/class')
sys.path.insert(0, os.path.dirname(PAY))
import sentinel_main as m
class G(dict):
    def get(self, k, d=None): return dict.get(self, k, d)
gagal = 0
def cek(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]))
    if not k: gagal += 1

T = tempfile.mkdtemp(prefix='zysweepapi.', dir='/tmp')
BASE = T + '/base'; WWW = T + '/www'; NGX = T + '/nginx'
for d in (BASE + '/bin', BASE + '/etc', BASE + '/log', BASE + '/data', BASE + '/run', WWW + '/situs.test/public', NGX):
    os.makedirs(d, exist_ok=True)
for f in ('sentinel-sweeper.py', 'sentinel-sweeplib.py', 'sentinel-sweeper.c'):
    shutil.copy(PAY + '/' + f, BASE + '/bin/' + f)
r = subprocess.run(['gcc', '-O2', '-std=gnu11', '-o', BASE + '/bin/sentinel-sweeper', PAY + '/sentinel-sweeper.c', '-lm'], capture_output=True)
con = sqlite3.connect(BASE + '/data/guardd.db')
con.execute('CREATE TABLE notif( id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER, jenis TEXT, isi TEXT, terkirim INTEGER DEFAULT 0, coba INTEGER DEFAULT 0, galat TEXT)'); con.commit(); con.close()
open(NGX + '/situs.test.conf', 'w').write('server {\n  root %s/situs.test/public;\n}\n' % WWW)
open(WWW + '/situs.test/public/ok.php', 'w').write('<?php echo "halo";')
open(WWW + '/situs.test/public/shell.php', 'w').write('<?php @eval($_POST["x"]);')
open(WWW + '/situs.test/public/inc.php', 'w').write("<?php include('a/' . $_GET['m'] . '.php');")
os.environ.update(ZYS_SWEEPER_BASE=BASE, ZYS_SWEEPER_NGINX=NGX, ZYS_SWEEPER_APACHE=T + '/apache', ZYS_SWEEPER_WWWROOT=WWW)
sm = m.sentinel_main()
sm._sentinel_main__PATH = BASE
sm._ensure_core_files = lambda: None
try:
    print('## Status dan validasi')
    r = sm.get_sweeper_status(G())
    cek('get_sweeper_status sukses dengan mesin C dan 1 vhost', r['status'] is True and r['msg']['engine']['kind'] == 'c' and len(r['msg']['roots']) == 1, r)
    for nama, g in [('scope tidak dikenal', {'scope': 'semua'}), ('mode tidak dikenal', {'mode': 'x'}), ('path relatif', {'scope': 'path', 'path': 'relatif'}),
                    ('path berisi ..', {'scope': 'path', 'path': '/www/../etc'}), ('path kosong', {'scope': 'path', 'path': ''}),
                    ('path di luar vhost', {'scope': 'path', 'path': '/etc'}), ('path tidak ada', {'scope': 'path', 'path': WWW + '/situs.test/tidak-ada'}),
                    ('path berisi newline', {'scope': 'path', 'path': '/etc\n/x'})]:
        r = sm.sweeper_start(G(g))
        cek('sweeper_start menolak: ' + nama, r['status'] is False, r)
    cek('filter temuan tidak valid ditolak', sm.get_sweeper_findings(G({'filter': 'aneh'}))['status'] is False)
    for nama, g in [('aksi tak dikenal', {'act': 'hapus', 'path': '/x'}), ('path relatif', {'act': 'ignore', 'path': 'x'}), ('path berisi ..', {'act': 'ignore', 'path': '/a/../b'})]:
        cek('sweeper_action menolak: ' + nama, sm.sweeper_action(G(g))['status'] is False)
    cek('config bukan JSON ditolak', sm.set_sweeper_config(G({'config': 'bukan json'}))['status'] is False)
    cek('config terlalu besar ditolak', sm.set_sweeper_config(G({'config': '{"x":"' + 'a' * 30000 + '"}'}))['status'] is False)
    cek('config dengan nilai tak valid ditolak oleh skrip', sm.set_sweeper_config(G({'config': json.dumps({'quarantine_min_score': 10})}))['status'] is False)
    cek('config valid diterima', sm.set_sweeper_config(G({'config': json.dumps({'throttle_ms': 0, 'exclude': ['/.git/']})}))['status'] is True)
    cek('sha256 tidak valid ditolak', sm.sweeper_allow_remove(G({'sha256': 'zz'}))['status'] is False)
    cek('jadwal: mode tidak valid ditolak', sm.sweeper_schedule(G({'mode': 'sering'}))['status'] is False)
    cek('jadwal: status', sm.sweeper_schedule(G({'mode': 'status'}))['msg'] == {'enabled': False})
    cek('kalibrasi: path relatif ditolak', sm.sweeper_calibrate(G({'path': 'x'}))['status'] is False)
    cek('build: sudah mutakhir atau disusun', sm.sweeper_build(G())['status'] is True)

    print('\n## Pemindaian di latar (semua vhost, karantina otomatis)')
    r = sm.sweeper_start(G({'scope': 'vhosts', 'mode': 'auto'}))
    cek('sweeper_start berhasil dimulai', r['status'] is True and r['msg'].get('started'), r)
    t0 = time.time(); j = None
    while time.time() - t0 < 60:
        j = sm.get_sweeper_job(G())['msg']
        if not j['running'] and j['job'].get('state') in ('done', 'failed'): break
        time.sleep(0.5)
    cek('job selesai (state=done)', j and j['job']['state'] == 'done', j)
    cek('ringkasan: 3 berkas dipindai, 1 webshell, 1 dikarantina', j['job']['summary']['scanned'] == 3 and j['job']['summary']['webshell'] == 1 and j['job']['summary']['quarantined'] == 1, j['job'].get('summary'))
    cek('webshell hilang dari webroot, berkas sah utuh', not os.path.exists(WWW + '/situs.test/public/shell.php') and os.path.exists(WWW + '/situs.test/public/ok.php'))
    f = sm.get_sweeper_findings(G({'filter': ''}))['msg']
    cek('temuan: 1 dikarantina + 1 mencurigakan terbuka', sorted((e['verdict'], e['status']) for e in f) == [('suspicious', 'open'), ('webshell', 'quarantined')], f)
    cek('filter suspicious hanya mencurigakan', [e['verdict'] for e in sm.get_sweeper_findings(G({'filter': 'suspicious'}))['msg']] == ['suspicious'])
    sus = [e for e in f if e['verdict'] == 'suspicious'][0]['path']
    cek('aksi ignore lewat API', sm.sweeper_action(G({'act': 'ignore', 'path': sus}))['status'] is True and sm.get_sweeper_findings(G({'filter': 'ignored'}))['msg'][0]['path'] == sus)
    cek('aksi unignore', sm.sweeper_action(G({'act': 'unignore', 'path': sus}))['status'] is True)
    r = sm.sweeper_action(G({'act': 'allow', 'path': sus}))
    cek('aksi allow: hash masuk daftar sah', r['status'] is True and len(sm.get_sweeper_allow(G())['msg']) == 1, r)
    h = sm.get_sweeper_allow(G())['msg'][0]['sha256']
    cek('allow-remove lewat API', sm.sweeper_allow_remove(G({'sha256': h}))['status'] is True and sm.get_sweeper_allow(G())['msg'] == [])
    r = sm.sweeper_start(G({'scope': 'path', 'path': WWW + '/situs.test/public', 'mode': 'report'}))
    t0 = time.time()
    while time.time() - t0 < 60 and sm.get_sweeper_job(G())['msg']['running']: time.sleep(0.4)
    cek('scan satu folder (mode laporan) selesai', sm.get_sweeper_job(G())['msg']['job']['state'] == 'done' and sm.get_sweeper_job(G())['msg']['job']['report_only'] is True)
    cek('status menunjukkan cacah temuan', sm.get_sweeper_status(G())['msg']['counts']['quarantined'] == 1)
finally:
    shutil.rmtree(T, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
