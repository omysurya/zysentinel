#!/usr/bin/env python3
# Uji NYATA dengan systemd (tanpa menyentuh layanan produksi): unit uji zys-test-*.service memakai direktif pemulihan
# yang sama dengan unit plugin (Restart=on-failure, RestartForceExitStatus, RestartSteps, StartLimit), diskala agar
# cepat, dan sentinel-selfheal.py dijalankan sungguhan terhadap unit tersebut (ZYS_SELFHEAL_BASE ke direktori uji).
# Yang dibuktikan: crash dipulihkan systemd dengan jeda; crash terus-menerus BERHENTI (failed), tidak berputar tanpa
# akhir dan log terbatas; selfheal memulihkan unit failed dengan jeda dan batas; operator `systemctl stop` dihormati;
# unit macet di-restart setelah beberapa pemeriksaan; kill -9 dan SIGTERM dipulihkan.
# Pemakaian (root): selfheal_systemd_test.py <path sentinel-selfheal.py> <direktori payload/systemd>
import sys, os, re, json, time, shutil, signal, subprocess, tempfile

SELF = sys.argv[1]
PAYLOAD_SYSTEMD = sys.argv[2]
gagal = 0
def T(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]), flush=True)
    if not k: gagal += 1
def sh(c, t=60):
    return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
def prop(unit, *p):
    o = sh('systemctl show %s --property=%s' % (unit, ','.join(p))).stdout
    return dict(l.split('=', 1) for l in o.splitlines() if '=' in l)
def tunggu(k, d=30, step=0.2):
    t0 = time.time()
    while time.time() - t0 < d:
        if k(): return time.time() - t0
        time.sleep(step)
    return None

TMP = tempfile.mkdtemp(prefix='zyheal.', dir='/tmp'); os.makedirs(TMP + '/etc'); os.makedirs(TMP + '/run'); os.makedirs(TMP + '/log')
RUN = '/run/zys-test'; os.makedirs(RUN, exist_ok=True)
UD = '/run/systemd/system'
UNITS = ['zys-test-crash.service', 'zys-test-hung.service']

# direktif disalin dari pola unit plugin, hanya angkanya diperkecil
POLA = """[Unit]
Description=uji self-heal %(n)s
StartLimitIntervalSec=60
StartLimitBurst=4
[Service]
Type=simple
ExecStart=%(cmd)s
Restart=on-failure
RestartForceExitStatus=0 SIGTERM SIGHUP SIGINT SIGPIPE
RestartSec=1
RestartSteps=3
RestartMaxDelaySec=4
LogRateLimitIntervalSec=30s
LogRateLimitBurst=100
[Install]
WantedBy=multi-user.target
"""
def tulis(n, cmd):
    open('%s/%s' % (UD, n), 'w').write(POLA % {'n': n, 'cmd': cmd})
open(RUN + '/crash.sh', 'w').write("if [ -f %s/ok ]; then trap 'exit 0' TERM; /bin/sleep 100000 & wait $!; exit 0; fi\necho crash disengaja >&2\nexit 1\n" % RUN)
tulis('zys-test-crash.service', '/bin/sh %s/crash.sh' % RUN)
tulis('zys-test-hung.service', '/bin/sleep 100000')
sh('systemctl daemon-reload')

def selfheal():
    env = dict(os.environ, ZYS_SELFHEAL_BASE=TMP)
    return subprocess.run(['python3', SELF, 'run'], env=env, capture_output=True, text=True, timeout=120)

def conf(**kw):
    c = {'cooldowns': [4, 6], 'max_attempts_24h': 12, 'probe_fail_limit': 3, 'healthy_reset_s': 3600,
         'services': [{'unit': 'zys-test-crash.service'}, {'unit': 'zys-test-hung.service', 'probe': ['file', TMP + '/hb', 5], 'grace': 0}]}
    c.update(kw); json.dump(c, open(TMP + '/etc/selfheal.json', 'w'))

try:
    print('## 0. Direktif pada unit plugin dan drop-in dikenali systemd')
    cek = sh('cd %s && systemd-analyze verify %s 2>&1' % (os.path.dirname(PAYLOAD_SYSTEMD) + '/systemd', ' '.join(sorted(f for f in os.listdir(PAYLOAD_SYSTEMD) if f.endswith(('.service', '.timer'))))))
    asing = [l for l in (cek.stdout + cek.stderr).splitlines() if re.search(r'Unknown (key|section)|Invalid|Failed to parse|bad setting', l) and 'sentinel' in l]
    T('systemd-analyze verify: tidak ada kunci tak dikenal/tak valid pada unit payload', not asing, asing)
    for f in sorted(os.listdir(PAYLOAD_SYSTEMD + '/dropin')):
        isi = open(PAYLOAD_SYSTEMD + '/dropin/' + f).read()
        T('drop-in %s memuat Restart/StartLimit/RestartSteps yang dikenal' % f, 'StartLimitBurst' in isi and 'RestartSteps' in isi)
    for f in ('sentinel.service', 'sentinel-proc.service', 'sentinel-upload-scan.service'):
        isi = open(PAYLOAD_SYSTEMD + '/' + f).read()
        T('%s: Restart=on-failure, StartLimitBurst, RestartSteps, tanpa Restart=always' % f, 'Restart=on-failure' in isi and 'StartLimitBurst=6' in isi and 'RestartSteps=5' in isi and 'RestartForceExitStatus=0 SIGTERM' in isi and 'Restart=always' not in isi)

    print('\n## 1. Crash terus-menerus: systemd memulihkan dengan jeda lalu BERHENTI (tidak berputar tanpa akhir)')
    sh('systemctl reset-failed zys-test-crash.service; systemctl enable --runtime zys-test-crash.service 2>&1')
    t0 = time.time(); sh('systemctl start --no-block zys-test-crash.service')
    dt = tunggu(lambda: prop('zys-test-crash.service', 'ActiveState')['ActiveState'] == 'failed', 60, 0.3)
    p = prop('zys-test-crash.service', 'ActiveState', 'Result', 'NRestarts')
    T('unit akhirnya failed setelah tepat StartLimitBurst=4 pemulihan dalam %.1f dtk (bukan berputar terus)' % (dt or -1), dt is not None and p['NRestarts'] == '4' and p['Result'] in ('start-limit-hit', 'exit-code'), p)
    n1 = p['NRestarts']; time.sleep(12)
    p2 = prop('zys-test-crash.service', 'ActiveState', 'NRestarts')
    T('12 dtk kemudian TIDAK ada percobaan baru dari systemd (NRestarts tetap %s)' % n1, p2['NRestarts'] == n1 and p2['ActiveState'] == 'failed', p2)
    lines = len([l for l in sh('journalctl -u zys-test-crash.service --since "-3min" -o cat --no-pager').stdout.splitlines() if l.strip()])
    T('jumlah baris log selama crash-loop terbatas (%d baris, bukan banjir)' % lines, lines < 60, lines)
    cpu = int(prop('zys-test-crash.service', 'CPUUsageNSec')['CPUUsageNSec'] or 0) / 1e9
    T('CPU total seluruh crash-loop kecil (%.2f dtk)' % cpu, cpu < 2.0, cpu)

    print('\n## 2. selfheal: unit failed dicoba lagi dengan jeda dan batas')
    conf()
    r = selfheal(); log1 = open(TMP + '/log/selfheal.log').read() if os.path.exists(TMP + '/log/selfheal.log') else ''
    T('tick pertama: selfheal melakukan reset-failed + start dan mencatat percobaan #1', 'pemulihan #1' in log1 and 'zys-test-crash' in log1, log1[-300:])
    time.sleep(1.5); selfheal(); log2 = open(TMP + '/log/selfheal.log').read()
    T('tick berikutnya dalam masa jeda (4 dtk): TIDAK ada percobaan baru', 'pemulihan #2' not in log2, log2[-300:])
    st = json.load(open(TMP + '/run/selfheal.json'))
    T('keadaan tersimpan: 1 percobaan, indeks backoff naik', len(st['zys-test-crash.service']['attempts']) == 1 and st['zys-test-crash.service']['idx'] == 1, st['zys-test-crash.service'])

    print('\n## 3. Penyebab diperbaiki: selfheal memulihkan unit')
    dt = tunggu(lambda: prop('zys-test-crash.service', 'ActiveState')['ActiveState'] == 'failed', 40, 0.3)
    open(RUN + '/ok', 'w').write('1')
    time.sleep(4.5)                          # lewati jeda
    selfheal()
    dt = tunggu(lambda: prop('zys-test-crash.service', 'ActiveState')['ActiveState'] == 'active', 20, 0.3)
    T('unit kembali active sendiri tanpa campur tangan operator (%.1f dtk)' % (dt or -1), dt is not None, prop('zys-test-crash.service', 'ActiveState', 'Result'))
    T('pemulihan tercatat di log selfheal', 'pulih: ActiveState=active' in open(TMP + '/log/selfheal.log').read())

    print('\n## 4. Crash setelah pulih: kill -9, SIGTERM; operator stop dihormati')
    pid0 = prop('zys-test-crash.service', 'MainPID')['MainPID']
    os.kill(int(pid0), signal.SIGKILL)
    dt = tunggu(lambda: prop('zys-test-crash.service', 'ActiveState', 'MainPID')['ActiveState'] == 'active' and prop('zys-test-crash.service', 'MainPID')['MainPID'] not in ('0', pid0), 15, 0.2)
    T('kill -9: systemd memulai ulang dalam %.1f dtk (PID baru)' % (dt or -1), dt is not None)
    pid1 = prop('zys-test-crash.service', 'MainPID')['MainPID']
    os.kill(int(pid1), signal.SIGTERM)
    dt = tunggu(lambda: prop('zys-test-crash.service', 'ActiveState', 'MainPID')['ActiveState'] == 'active' and prop('zys-test-crash.service', 'MainPID')['MainPID'] not in ('0', pid1), 15, 0.2)
    T('SIGTERM dari luar pada daemon yang menangkapnya lalu exit 0 (seperti daemon plugin): tetap dipulihkan dalam %.1f dtk' % (dt or -1), dt is not None)
    sh('systemctl stop zys-test-crash.service'); time.sleep(3)
    T('systemctl stop oleh operator: unit tetap mati (tidak dihidupkan systemd)', prop('zys-test-crash.service', 'ActiveState')['ActiveState'] == 'inactive')
    n_log = len(open(TMP + '/log/selfheal.log').read().splitlines()); selfheal(); selfheal()
    T('selfheal membiarkan unit yang dihentikan operator (tidak ada baris log baru berisi pemulihan)', 'inactive' not in open(TMP + '/log/selfheal.log').read().split('pulih: ActiveState=active')[-1] or prop('zys-test-crash.service', 'ActiveState')['ActiveState'] == 'inactive')
    T('unit tetap inactive setelah dua tick selfheal', prop('zys-test-crash.service', 'ActiveState')['ActiveState'] == 'inactive')

    print('\n## 5. Unit macet (active tetapi detak mati): di-restart setelah 3 pemeriksaan gagal berturut-turut')
    sh('systemctl enable --runtime zys-test-hung.service 2>&1; systemctl start zys-test-hung.service'); time.sleep(1)
    open(TMP + '/hb', 'w').write('x'); old = time.time() - 600; os.utime(TMP + '/hb', (old, old))
    pid_h = prop('zys-test-hung.service', 'MainPID')['MainPID']
    selfheal(); selfheal()
    T('2 pemeriksaan gagal: belum di-restart', prop('zys-test-hung.service', 'MainPID')['MainPID'] == pid_h)
    selfheal(); time.sleep(1)
    pid_h2 = prop('zys-test-hung.service', 'MainPID')['MainPID']
    T('pemeriksaan ke-3 gagal: di-restart (PID %s -> %s)' % (pid_h, pid_h2), pid_h2 not in ('0', pid_h) and prop('zys-test-hung.service', 'ActiveState')['ActiveState'] == 'active')
    os.utime(TMP + '/hb', None)
    pid_h3 = prop('zys-test-hung.service', 'MainPID')['MainPID']; selfheal(); selfheal(); selfheal()
    T('detak sehat: tidak di-restart', prop('zys-test-hung.service', 'MainPID')['MainPID'] == pid_h3)
finally:
    for u in UNITS:
        sh('systemctl stop %s; systemctl disable --runtime %s; systemctl reset-failed %s' % (u, u, u))
        try: os.remove('%s/%s' % (UD, u))
        except OSError: pass
    sh('systemctl daemon-reload')
    shutil.rmtree(RUN, ignore_errors=True); shutil.rmtree(TMP, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
