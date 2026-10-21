#!/usr/bin/env python3
# Uji akurasi Sweeper pada korpus NYATA (opsional; korpus tidak disimpan di repo).
#   --legit DIR ...   pohon berkas SAH (mis. /www/wwwroot): syarat 0 putusan "webshell"
#   --shell DIR ...   kumpulan webshell publik (mis. git clone https://github.com/tennc/webshell): hanya dilaporkan recall-nya
#   --parity N        bandingkan mesin C dan Python pada N berkas pertama tiap korpus (verdict, skor, indikator harus sama)
# Pemakaian: sweeper_corpus_test.py <payload> --legit /www/wwwroot --shell /tmp/korpus [--parity 300]
import os, sys, json, subprocess, importlib.util, collections
PAY = os.path.abspath(sys.argv[1]); args = sys.argv[2:]
legit, shell, parity = [], [], 0
mode = None
i = 0
while i < len(args):
    if args[i] in ('--legit', '--shell'): mode = args[i]; i += 1; continue
    if args[i] == '--parity': parity = int(args[i + 1]); i += 2; continue
    (legit if mode == '--legit' else shell).append(args[i]); i += 1
BIN = PAY + '/sentinel-sweeper'
if not os.access(BIN, os.X_OK):
    print('biner %s belum ada (build-release.sh atau gcc -O2 -o ...)' % BIN); sys.exit(2)
gagal = 0
def cek(n, k, x=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(x)[:300]))
    if not k: gagal += 1
def pindai(root):
    r = subprocess.run([BIN, '--all', '--max-size', '3145728', root], capture_output=True, text=True)
    rows, summ = [], {}
    for l in r.stdout.splitlines():
        j = json.loads(l)
        if 'summary' in j: summ = j['summary']
        else: rows.append(j)
    return rows, summ
spec = importlib.util.spec_from_file_location('sl', PAY + '/sentinel-sweeplib.py'); sl = importlib.util.module_from_spec(spec); spec.loader.exec_module(sl)
for root in legit:
    rows, s = pindai(root); c = collections.Counter(r['verdict'] for r in rows)
    print('\n## sah: %s (%d berkas dipindai, %.1f dtk CPU, %d MB RSS)' % (root, s['scanned'], s['cpu_seconds'], s['max_rss_kb'] // 1024))
    cek('0 putusan webshell dari %d berkas' % s['scanned'], c['webshell'] == 0, [r['path'] for r in rows if r['verdict'] == 'webshell'])
    print('    mencurigakan (tinjau): %d' % c['suspicious'])
for root in shell:
    rows, s = pindai(root); c = collections.Counter(r['verdict'] for r in rows)
    ext = collections.defaultdict(collections.Counter)
    for r in rows: ext[os.path.splitext(r['path'])[1].lower()][r['verdict']] += 1
    print('\n## webshell: %s (%d berkas)' % (root, s['scanned']))
    print('    webshell %d, mencurigakan %d, bersih %d' % (c['webshell'], c['suspicious'], c['clean']))
    for e, v in sorted(ext.items(), key=lambda x: -sum(x[1].values()))[:6]: print('      %-7s %s' % (e, dict(v)))
if parity:
    for root in legit + shell:
        rows, _ = pindai(root); sel = rows[:parity]; beda = 0
        for r in sel:
            try: data = open(r['path'], 'rb').read(sl.MAX_FILE)
            except OSError: continue
            p = sl.analyze(r['path'], data, os.path.splitext(r['path'])[1].lower())
            if (p['verdict'], p['score'], sorted(set(x[0] for x in p['rules']))) != (r['verdict'], r['score'], sorted(set(x[0] for x in r['rules']))): beda += 1
        cek('paritas C = Python pada %d berkas di %s' % (len(sel), root), beda == 0, '%d berbeda' % beda)
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
