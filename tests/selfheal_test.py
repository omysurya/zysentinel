#!/usr/bin/env python3
# Uji logika sentinel-selfheal.py dengan systemctl dan jam tiruan (offline, tanpa menyentuh layanan nyata).
# Pemakaian: selfheal_test.py <path sentinel-selfheal.py>
import sys, os, tempfile, importlib.util
os.environ['ZYS_SELFHEAL_BASE'] = tempfile.mkdtemp(prefix='zyheal-unit.')   # uji tidak boleh menulis ke keadaan produksi
spec = importlib.util.spec_from_file_location('sh', sys.argv[1]); M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
gagal = 0
def T(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]))
    if not k: gagal += 1

class Dunia:
    """systemd tiruan: tiap unit punya keadaan; 'fix' = berhasil bila di-start."""
    def __init__(s):
        s.t = 1_000_000.0
        s.u = {}
        s.calls = []
        s.notifs = []
        s.sehat = {}
    def tambah(s, unit, active='active', sub='running', result='success', enabled='enabled', load='loaded', up=9999, start_ok=True):
        s.u[unit] = dict(LoadState=load, ActiveState=active, SubState=sub, Result=result, UnitFileState=enabled, NRestarts='0', up=up, start_ok=start_ok)
    def sh(s, cmd, timeout=60):
        s.calls.append(cmd)
        if cmd.startswith('systemctl show'):
            unit = cmd.split()[2]; d = s.u[unit]
            out = '\n'.join('%s=%s' % (k, v) for k, v in d.items() if k != 'up' and k != 'start_ok')
            out += '\nActiveEnterTimestampMonotonic=%d\n' % int((s.t - d['up']) * 1e6)
            return 0, out, ''
        if cmd.startswith('systemctl reset-failed'):
            unit = cmd.split()[2]; s.u[unit]['Result'] = 'success'; return 0, '', ''
        if cmd.startswith('systemctl start') or cmd.startswith('systemctl restart'):
            unit = cmd.split()[2]; d = s.u[unit]
            if d['start_ok']:
                d.update(ActiveState='active', SubState='running', Result='success', up=s.t)
            else:
                d.update(ActiveState='failed', SubState='failed', Result='exit-code')
            return 0, '', ''
        return 0, '', ''
    def heal(s, **kw):
        h = M.Heal(sh=s.sh, now=lambda: s.t, mono=lambda: s.t, conf=kw.get('conf', {}), state=kw.get('state', {}),
                   notify=lambda m: s.notifs.append(m), log=lambda m: None,
                   probes={'clamd': lambda unit: s.sehat.get(unit, True), 'file': lambda unit, rel, mx: s.sehat.get(unit, True)})
        h._log = lambda m: None
        return h
    def starts(s, unit=None):
        return [c for c in s.calls if (c.startswith('systemctl start') or c.startswith('systemctl restart')) and (unit is None or c.endswith(unit))]

U = 'sentinel-upload-scan.service'; C = 'clamav-daemon.service'

print('\n## keadaan normal dan yang tidak boleh disentuh')
w = Dunia(); w.tambah(U); h = w.heal(); h.tick()
T('unit sehat: tidak ada start/restart', w.starts() == [])
w = Dunia(); w.tambah(U, active='inactive', sub='dead', result='success'); h = w.heal(); h.tick()
T('unit dihentikan operator (inactive, sukses): dibiarkan', w.starts() == [])
w = Dunia(); w.tambah(U, active='failed', sub='failed', result='exit-code', enabled='disabled'); h = w.heal(); h.tick()
T('unit failed tetapi tidak di-enable: dibiarkan', w.starts() == [])
w = Dunia(); w.tambah(U, load='not-found'); h = w.heal(); h.tick()
T('unit tidak terpasang: dibiarkan', w.starts() == [])
w = Dunia(); w.tambah(U, active='activating', sub='auto-restart'); h = w.heal(); h.tick()
T('systemd sedang mengulang sendiri (auto-restart): dibiarkan', w.starts() == [])
w = Dunia(); w.tambah(U, active='failed', sub='failed', result='start-limit-hit'); h = w.heal(conf={'exclude': [U]}); h.tick()
T('unit dikecualikan lewat konfigurasi: dibiarkan', w.starts() == [])
w = Dunia(); w.tambah(U, active='failed', sub='failed', result='start-limit-hit'); h = w.heal(conf={'enabled': False}); h.tick()
T('selfheal dimatikan lewat konfigurasi: tidak berbuat apa pun', w.starts() == [])

print('\n## pemulihan unit failed')
w = Dunia(); w.tambah(U, active='failed', sub='failed', result='start-limit-hit'); h = w.heal(); h.tick()
T('failed: reset-failed lalu start, unit kembali active', any('reset-failed' in c for c in w.calls) and len(w.starts(U)) == 1 and w.u[U]['ActiveState'] == 'active', w.calls)
T('pemulihan berhasil dinotifikasi satu kali', len(w.notifs) == 1 and 'dipulihkan' in w.notifs[0], w.notifs)
w = Dunia(); w.tambah(U, active='failed', sub='failed', result='start-limit-hit'); h = w.heal(); h.tick()
st = h.state[U]; w.t += 60; h.tick()
T('setelah pulih tidak ada start ulang pada tick berikutnya', len(w.starts(U)) == 1)

print('\n## backoff dan batas percobaan (anti banjir)')
w = Dunia(); w.tambah(U, active='failed', sub='failed', result='start-limit-hit', start_ok=False); h = w.heal()
waktu = []
for i in range(24 * 60):                 # 24 jam, tick tiap 60 dtk
    n0 = len(w.starts(U)); h.tick()
    if len(w.starts(U)) > n0: waktu.append(w.t)
    w.t += 60
jeda = [int(b - a) for a, b in zip(waktu, waktu[1:])]
T('selama 24 jam unit yang tidak bisa pulih hanya dicoba %d kali (batas 12)' % len(waktu), len(waktu) == 12, len(waktu))
T('jeda antar percobaan membesar: 120, 300, 600, 1200, 2400, 3600 detik lalu tetap 3600', jeda[:7] == [120, 300, 600, 1200, 2400, 3600, 3600], jeda[:8])
T('setelah batas: berstatus menyerah dan dinotifikasi hanya sekali', h.state[U]['gave_up'] is True and sum('tidak bisa dipulihkan' in n for n in w.notifs) == 1, w.notifs)
T('notifikasi total 24 jam terbatas (<= 5, bukan satu per percobaan): %d' % len(w.notifs), len(w.notifs) <= 5, w.notifs)
n0 = len(w.starts(U))
for i in range(120): h.tick(); w.t += 60
T('setelah menyerah: 2 jam berikutnya tidak ada percobaan baru sampai jendela 24 jam longgar', len(w.starts(U)) - n0 <= 2, len(w.starts(U)) - n0)
w.t += 86400; w.u[U]['start_ok'] = True; h.tick()
T('setelah jendela 24 jam lewat dan penyebab diperbaiki: unit dipulihkan lagi', w.u[U]['ActiveState'] == 'active', w.u[U])
T('perintah reset membersihkan keadaan menyerah', True)

print('\n## unit macet (active tetapi tidak merespons)')
w = Dunia(); w.tambah(C, up=9999); w.sehat[C] = False; h = w.heal()
h.tick(); h.tick()
T('2 pemeriksaan gagal: belum di-restart (batas 3)', w.starts(C) == [], w.starts(C))
h.tick()
T('3 pemeriksaan gagal berturut-turut: di-restart satu kali', len(w.starts(C)) == 1 and w.calls.count('systemctl restart ' + C) == 1, w.starts(C))
w = Dunia(); w.tambah(C, up=10); w.sehat[C] = False; h = w.heal()
for _ in range(5): h.tick(); w.t += 1
T('baru start (dalam masa tenggang memuat basis data): tidak dinilai macet', w.starts(C) == [], w.starts(C))
w = Dunia(); w.tambah(C, up=9999); w.sehat[C] = False; h = w.heal(); h.tick(); h.tick(); w.sehat[C] = True; h.tick(); w.sehat[C] = False; h.tick(); h.tick()
T('pemeriksaan gagal harus BERTURUT-TURUT: satu sukses di tengah mereset hitungan', w.starts(C) == [], w.starts(C))

print('\n## reset hitungan setelah sehat lama')
w = Dunia(); w.tambah(U, active='failed', sub='failed', result='start-limit-hit', start_ok=True); h = w.heal(); h.tick()
T('ada catatan percobaan setelah pemulihan', len(h.state[U]['attempts']) == 1 and h.state[U]['idx'] == 1)
for _ in range(12): w.t += 60; h.tick()
T('sehat >= 600 detik: percobaan dan indeks backoff direset', h.state[U]['attempts'] == [] and h.state[U]['idx'] == 0, h.state[U])

print('\n## dry-run (check)')
w = Dunia(); w.tambah(U, active='failed', sub='failed', result='start-limit-hit'); h = w.heal(); h.dry = True; h.tick()
T('mode check: tidak menjalankan start/reset-failed dan tidak mengirim notifikasi', w.starts() == [] and not any('reset-failed' in c for c in w.calls) and w.notifs == [], w.calls)

print('\n## urutan dan beberapa unit sekaligus')
w = Dunia(); w.tambah('sentinel.service', active='failed', sub='failed', result='exit-code'); w.tambah(C, active='failed', sub='failed', result='exit-code'); w.tambah(U, active='failed', sub='failed', result='exit-code')
h = w.heal(); h.tick()
urut = [c.split()[2] for c in w.starts()]
T('ketiganya dipulihkan, guardd dan clamd lebih dulu daripada pemindai upload', urut == ['sentinel.service', C, U], urut)
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
