#!/usr/bin/env python3
# Uji penguraian penghitung paket firewall (panel Packet Counters): get_fw harus mengirim OBJEK
# {target, rule, detail, pkts, bytes}, bukan baris teks mentah iptables.
# Pemakaian: fw_counters_test.py <path sentinel_main.py>
import sys, importlib.util, subprocess
sys.path[:0] = ['/www/server/panel', '/www/server/panel/class']
spec = importlib.util.spec_from_file_location('sm', sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
cls = mod.sentinel_main
gagal = 0
def T(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]))
    if not k: gagal += 1
CONTOH = '''Chain SENTINEL (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 RETURN     0    --  *      *       127.0.0.0/8          0.0.0.0/0
      12      560 DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0            match-set sentinel_intel src /* sentinel:intel-drop */
 1234567 98765432 DROP       6    --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 80,443 tcp flags:0x17/0x02 ctstate NEW #conn src/32 > 40 /* sentinel:syn-guard */
       0        0 RETURN     6    --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 80,443 match-set sentinel_throttle src limit: up to 5/sec burst 15 htable-expire 600000
       5      300 DROP       0    --  wg0    *       0.0.0.0/0            0.0.0.0/0            /* sentinel:tanpa-detail */
     bukan baris aturan /* sentinel:palsu */
'''
h = cls._fw_penghitung(CONTOH)
T('hanya aturan bertanda sentinel: yang diambil (3 dari 6 baris)', [x['rule'] for x in h] == ['intel-drop', 'syn-guard', 'tanpa-detail'], h)
T('angka eksak (-x) menjadi int', h[1]['pkts'] == 1234567 and h[1]['bytes'] == 98765432, h[1])
T('target dan detail terisi', h[0]['target'] == 'DROP' and h[0]['detail'] == 'match-set sentinel_intel src', h[0])
T('aturan tanpa kriteria: detail kosong, tidak ada nilai None', h[2]['detail'] == '' and all(v is not None for x in h for v in x.values()), h[2])
T('masukan kosong / None aman', cls._fw_penghitung('') == [] and cls._fw_penghitung(None) == [])
T('tidak ada butir bertipe string', all(isinstance(x, dict) for x in h))
# data produksi nyata (hanya baca)
nyata = subprocess.run('iptables -L SENTINEL -n -v -x 2>/dev/null', shell=True, capture_output=True, text=True).stdout
if 'sentinel:' in nyata:
    n = nyata.count('/* sentinel:')
    hn = cls._fw_penghitung(nyata)
    T('produksi: semua %d aturan bertanda terurai' % n, len(hn) == n and all(x['target'] and x['rule'] for x in hn), hn)
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
