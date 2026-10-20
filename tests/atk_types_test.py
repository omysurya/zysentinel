#!/usr/bin/env python3
# Uji get_attack_types (diagram donat Jenis Serangan): klasifikasi log audit WAF, filter waktu/loopback, cache.
# Pemakaian: atk_types_test.py <path sentinel_main.py>
import sys, os, json, time, importlib.util, tempfile
sys.path[:0] = ['/www/server/panel', '/www/server/panel/class']
spec = importlib.util.spec_from_file_location('sm', sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
sm = mod.sentinel_main()
class G(dict):
    def get(self, k, d=None): return dict.get(self, k, d)
gagal = 0
def T(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:200]))
    if not k: gagal += 1
def tx(ip, ts, tags, ids):
    e = ''.join('[id "%s"] [tag "%s"] ' % (i, t) for i, t in zip(ids, tags))
    return json.dumps({'transaction': {'client_ip': ip, 'unix_timestamp': int(ts * 1e9)},
                       'messages': [{'error_message': 'Coraza: Access denied ' + e}]})
now = time.time()
L = [tx('1.1.1.1', now, ['attack-sqli', 'attack-reputation-scanner'], ['942100', '913100']),
     tx('1.1.1.2', now, ['attack-xss'], ['941100']),
     tx('1.1.1.3', now, ['attack-lfi'], ['930100']),
     tx('1.1.1.4', now, ['attack-rce'], ['932100']),
     tx('1.1.1.5', now, ['zysentinel', 'attack-sensitive-file'], ['8000102', '8000102']),
     tx('1.1.1.6', now, ['attack-bot'], ['8000300']),
     tx('1.1.1.7', now, ['attack-protocol'], ['920350']),
     tx('1.1.1.8', now, ['zysentinel'], ['8000999']),
     tx('127.0.0.1', now, ['attack-sqli'], ['942100']),
     tx('1.1.1.9', now - 99 * 3600, ['attack-sqli'], ['942100'])]
d = tempfile.mkdtemp(); p = os.path.join(d, 'a.jsonl'); open(p, 'w').write('\n'.join(L) + '\nsampah\n')
sm.WAF_AUDIT_LOG = p
h = sm._attack_waf_jenis(int(now) - 3600)
T('delapan jenis masing-masing 1 (SQLi menang atas scanner, loopback dan data lama dibuang)',
  h == {'sqli': 1, 'xss': 1, 'traversal': 1, 'rce': 1, 'scanner': 1, 'bot': 1, 'protocol': 1, 'lainnya': 1}, h)
h = sm._attack_waf_jenis(int(now) - 200 * 3600)
T('rentang panjang ikut menghitung entri lama', h.get('sqli') == 2, h)
r = sm.get_attack_types(G(hours=24))
m = r.get('msg')
T('respons sukses dengan total = jumlah jenis', r.get('status') is True and m['total'] == sum(x['n'] for x in m['jenis']), r)
T('jenis terurut menurun', [x['n'] for x in m['jenis']] == sorted([x['n'] for x in m['jenis']], reverse=True))
T('jam di luar batas dijepit 1..168', sm.get_attack_types(G(hours=99999))['msg']['jam'] == 168 and sm.get_attack_types(G(hours=-5))['msg']['jam'] == 1)
sm.WAF_AUDIT_LOG = os.path.join(d, 'tidak-ada.jsonl')
T('log audit tidak ada: tetap sukses', sm.get_attack_types(G(hours=24)).get('status') is True)
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
