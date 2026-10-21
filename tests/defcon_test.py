#!/usr/bin/env python3
# Uji penentuan level DEFCON di get_elite_posture: kill/alert dihitung 15 menit terakhir (bukan penghitung kumulatif),
# alert WHITELISTED (cron deploy) tidak dihitung, indikator dikirim. Sandbox __PATH; ipset hanya dibaca.
# Pemakaian: /www/server/panel/pyenv/bin/python3 -B defcon_test.py <path sentinel_main.py>
import sys, os, time, tempfile, importlib.util
sys.path[:0] = ['/www/server/panel', '/www/server/panel/class']
spec = importlib.util.spec_from_file_location('sm', sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
gagal = 0
def T(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]))
    if not k: gagal += 1
d = tempfile.mkdtemp(prefix='zysdefcon.', dir='/tmp')
for x in ('run', 'av/last', 'etc'): os.makedirs(os.path.join(d, x))
open(d + '/run/egress.state', 'w').write('on')
open(d + '/run/proc_guard.pid', 'w').write(str(os.getpid()))
open(d + '/run/proc_guard.state', 'w').write('status=running\nmode=enforce\nkills=7\nalerts=99\n')   # kumulatif lama
sm = mod.sentinel_main(); sm._sentinel_main__PATH = d; sm._ensure_core_files = lambda: None
now = int(time.time())
def set_alerts(rows):
    sm._sql = lambda q, a=(): rows if 'FROM proc_alerts' in q else []
def lv():
    r = sm.get_elite_posture({})['msg']; return r['defcon'], r
set_alerts([{'ts': now - 30, 'action': 'WHITELISTED', 'rule': 'ILLEGAL_SHELL'}])
l, r = lv()
T('cron ter-whitelist 30 dtk lalu + kills kumulatif 7: tetap DEFCON 3 (dulu 2 terus-menerus)', l == 3, (l, r['indikator']))
T('indikator berisi 7 butir dan nilai intel dari ipset', len(r['indikator']) == 7 and r['indikator'][-1]['kode'] == 'intel')
set_alerts([{'ts': now - 3600, 'action': 'KILLED', 'rule': 'ILLEGAL_SHELL'}])
T('pembunuhan 1 jam lalu: DEFCON 3', lv()[0] == 3)
set_alerts([{'ts': now - 60, 'action': 'KILLED', 'rule': 'ILLEGAL_SHELL'}])
l, r = lv(); k = [x for x in r['indikator'] if x['kode'] == 'kill_15m'][0]
T('pembunuhan 1 menit lalu: DEFCON 2, indikator kill_15m = 1', l == 2 and k['nilai'] == 1 and not k['baik'], (l, k))
set_alerts([{'ts': now - 60, 'action': 'AUDIT', 'rule': 'TEMP_DIR_EXEC'}])
T('alert non-whitelist 1 menit lalu: DEFCON 2', lv()[0] == 2)
set_alerts([])
open(d + '/av/last/integ-sys-persistence.txt', 'w').write('added|/etc/cron.d/x|-|abc\n')
T('perubahan persistensi sistem: DEFCON 2', lv()[0] == 2)
os.remove(d + '/av/last/integ-sys-persistence.txt'); os.remove(d + '/run/egress.state')
T('Egress Guard mati: DEFCON 4', lv()[0] == 4)
open(d + '/run/panic.state', 'w').write('on')
T('panic aktif: DEFCON 1 (prioritas tertinggi)', lv()[0] == 1)
import shutil; shutil.rmtree(d, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
