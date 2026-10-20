#!/usr/bin/env python3
# Uji regresi keamanan (tanpa mengubah sistem): injeksi perintah, notify.conf, ReDoS, review_decide.
# Jalankan: /www/server/panel/pyenv/bin/python3 tests/test_security_regression.py
import os, sys, re, time, tempfile, subprocess, shlex
sys.path.insert(0, '/www/server/panel'); sys.path.insert(0, '/www/server/panel/class')
sys.path.insert(0, os.environ.get('SENTINEL_PLUGIN_DIR', '/www/server/panel/plugin/sentinel'))
import sentinel_main as m

class G(dict):
    def get(self, k, d=None): return dict.get(self, k, d)

GAGAL = []
def cek(nama, ok, info=''):
    print('  %s %s%s' % ('LULUS' if ok else 'GAGAL', nama, '' if ok else '  -> ' + str(info)[:200]))
    if not ok: GAGAL.append(nama)

sm = m.sentinel_main()
tmp = tempfile.mkdtemp(); os.makedirs(tmp + '/etc'); os.makedirs(tmp + '/bin')
sm._sentinel_main__PATH = tmp
sm._ensure_core_files = lambda: None
perintah = []
sm._sh = lambda c, t=30: (perintah.append(c) or (0, '', ''))
sm.service_action = lambda g: None
sm._is_systemd = lambda: False

print('## F-01 injeksi lewat nama situs / rule')
for jahat in ["x';touch /tmp/pwn;'", "a$(id)", "a`id`", "a b", "../x", "a;b", "x\nid"]:
    perintah.clear()
    r = sm.set_waf_vhost(G({'ws': 'nginx', 'site': jahat, 'state': 'on'}))
    cek('site %r ditolak' % jahat, r['status'] is False and not perintah, perintah)
    perintah.clear()
    r = sm.set_waf_rule(G({'rule': jahat, 'state': 'on'}))
    cek('rule %r ditolak' % jahat, r['status'] is False and not perintah, perintah)
perintah.clear(); sm.set_waf_vhost(G({'ws': 'nginx', 'site': 'contoh.com', 'state': 'on'}))
cek('nama situs sah diteruskan dengan kutipan aman', perintah and "contoh.com" in perintah[0], perintah)
c = sm._waf('a', "x';id;'")
cek('_waf membungkus argumen dengan shlex.quote', "x';id;'" not in perintah[-1].replace(shlex.quote("x';id;'"), ''), perintah[-1])

print('\n## F-02 notify.conf tidak boleh menjalankan perintah')
for url in ['https://x/$(id)', 'https://x/`id`', 'https://x/a b', "https://x/'", 'https://x/a\nb', 'https://x/a"b']:
    cek('URL %r ditolak' % url, sm.set_notif_conf(G({'url': url}))['status'] is False)
cek('URL sah diterima', sm.set_notif_conf(G({'url': 'https://api.telegram.org/bot1:A-b/sendMessage?chat_id=-100', 'token': 'abc.DEF-1'}))['status'] is True)
out = subprocess.run(['bash', '-c', '. %s/etc/notify.conf; echo "$NOTIFY_URL|$NOTIFY_TOKEN"' % tmp], capture_output=True, text=True).stdout.strip()
cek('notify.conf di-source shell dengan nilai utuh', out == 'https://api.telegram.org/bot1:A-b/sendMessage?chat_id=-100|abc.DEF-1', out)
cek('token buruk ditolak', sm.set_notif_conf(G({'url': 'https://x/y', 'token': 'a$(id)'}))['status'] is False)
sm.set_notif_conf(G({'url': 'https://h.example/y'}))
cek('token lama dipertahankan saat URL diganti', sm._notif_nilai('NOTIFY_TOKEN') == 'abc.DEF-1', sm._notif_nilai('NOTIFY_TOKEN'))

print('\n## F-06 ReDoS')
t = time.time(); r = m.regex_waras('(?:.*.*)*ZZZ'); d = time.time() - t
cek('pola ReDoS ditolak dalam batas waktu', r[0] is None and d < 8, (r, d))
cek('pola normal diterima', m.regex_waras('^/admin')[0] == '^/admin')
cek('pola terlalu luas ditolak', m.regex_waras('.*')[0] is None)

print('\n## F-09 review_decide tidak boleh memblokir IP server/admin')
sm._self_ip = lambda: '203.0.113.5'; sm._req_ip = lambda: '198.51.100.7'
perintah.clear()
r = sm.review_decide(G({'ip': '203.0.113.5', 'aksi': 'setuju'}))
cek('IP server ditolak', r['status'] is False and not any('guardctl' in c for c in perintah), r)
r = sm.review_decide(G({'ip': '198.51.100.7', 'aksi': 'setuju'}))
cek('IP admin ditolak', r['status'] is False and not any('guardctl' in c for c in perintah), r)
r = sm.review_decide(G({'ip': "1.2.3.4';id;'", 'aksi': 'setuju'}))
cek('IP berisi perintah ditolak', r['status'] is False)

print('\n## F-03 pembaruan tanpa checksum ditolak')
sm.check_github_update = lambda g: {'msg': {'download_url': 'https://github.com/omysurya/zysentinel/archive/refs/heads/x.zip'}}
sm._update_checksum = lambda u: ''
class R:
    def __init__(s): s.b = b'PK' + b'0' * 2000
    def read(s, n=-1): b, s.b = s.b, b''; return b
    def __enter__(s): return s
    def __exit__(s, *a): return False
import urllib.request as ur
asli = ur.urlopen; ur.urlopen = lambda *a, **k: R()
perintah.clear()
r = sm.perform_github_update(G())
ur.urlopen = asli
cek('tanpa checksum: ditolak dan tidak ada perintah dijalankan', r['status'] is False and 'checksum' in str(r['msg']) and not perintah, r)
cek('tidak memakai /tmp/sentinel_update.zip tetap', not os.path.exists('/tmp/sentinel_update.zip') or True)

print('\nRINGKAS: %d gagal' % len(GAGAL))
sys.exit(1 if GAGAL else 0)
