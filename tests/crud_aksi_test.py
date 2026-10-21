#!/usr/bin/env python3
# Uji API CRUD kolom Action: aturan port (update_port_rule + add/del/toggle), pelajaran manual (learned_add,
# learned_update, learned_revoke). Sandbox penuh: PORTS_CONF dan __PATH sementara, _ports_script dan guardctl
# ditiru -> TIDAK ada aturan yang diterapkan ke kernel produksi.
# Pemakaian: /www/server/panel/pyenv/bin/python3 -B crud_aksi_test.py <path sentinel_main.py>
import sys, os, json, tempfile, importlib.util
sys.path[:0] = ['/www/server/panel', '/www/server/panel/class']
spec = importlib.util.spec_from_file_location('sm', sys.argv[1]); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
class G(dict):
    def get(self, k, d=None): return dict.get(self, k, d)
gagal = 0
def T(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]))
    if not k: gagal += 1
d = tempfile.mkdtemp(prefix='zyscrud.', dir='/tmp')
for x in ('etc', 'bin', 'data'): os.makedirs(d + '/' + x)
open(d + '/bin/guardctl', 'w').write('#!/bin/bash\necho \'{"ok":true,"lessons":0}\'\n'); os.chmod(d + '/bin/guardctl', 0o755)
sm = mod.sentinel_main(); sm._sentinel_main__PATH = d; sm._ensure_core_files = lambda: None
PC = d + '/etc/ports.json'
sm.PORTS_CONF = PC
json.dump({'active': True, 'inbound': [
    {'id': 'in-ssh', 'port': '2244', 'protocol': 'tcp', 'action': 'ACCEPT', 'source': '0.0.0.0/0', 'remark': 'SSH', 'system': True, 'enabled': True},
    {'id': 'in-x1', 'port': '8080', 'protocol': 'tcp', 'action': 'ACCEPT', 'source': '0.0.0.0/0', 'remark': 'API', 'system': False, 'enabled': True}],
    'outbound': [{'id': 'out-x1', 'port': '25', 'protocol': 'tcp', 'action': 'DROP', 'dest': '0.0.0.0/0', 'remark': 'SMTP', 'system': False, 'enabled': True}]}, open(PC, 'w'))
TERAP = {'rc': 0, 'n': 0}
def palsu(aksi):
    TERAP['n'] += 1
    return (TERAP['rc'], 'ditolak' if TERAP['rc'] else '{}', '')
sm._ports_script = palsu
cfg = lambda: json.load(open(PC))
print('## Port Control: Update')
r = sm.update_port_rule(G(id='in-x1', port='8081-8090', protocol='tcp/udp', rule_action='DROP', source='10.0.0.0/8', remark='API baru'))
x = [y for y in cfg()['inbound'] if y['id'] == 'in-x1'][0]
T('edit aturan kustom: semua kolom berubah dan diterapkan ke kernel', r['status'] and x['port'] == '8081-8090' and x['protocol'] == 'tcp/udp' and x['action'] == 'DROP' and x['source'] == '10.0.0.0/8' and x['remark'] == 'API baru' and TERAP['n'] >= 1, (r, x))
r = sm.update_port_rule(G(id='out-x1', port='587', protocol='tcp', rule_action='ACCEPT', dest='1.2.3.4', remark=''))
x = cfg()['outbound'][0]
T('edit outbound memakai kolom dest', r['status'] and x['dest'] == '1.2.3.4' and x['port'] == '587' and x['action'] == 'ACCEPT', x)
r = sm.update_port_rule(G(id='in-ssh', port='9999', protocol='udp', rule_action='DROP', source='1.1.1.1', remark='SSH admin'))
x = [y for y in cfg()['inbound'] if y['id'] == 'in-ssh'][0]
T('baseline SSH: hanya keterangan berubah; port/protokol/aksi/alamat terkunci', r['status'] and x['remark'] == 'SSH admin' and x['port'] == '2244' and x['protocol'] == 'tcp' and x['action'] == 'ACCEPT' and x['source'] == '0.0.0.0/0', (r, x))
for nama, g in [('port tidak valid', dict(id='in-x1', port='99999')), ('rentang terbalik', dict(id='in-x1', port='90-80')),
                ('aksi tidak valid', dict(id='in-x1', port='80', rule_action='MAYBE')), ('alamat tidak valid', dict(id='in-x1', port='80', source='1.2.3')),
                ('id tidak valid', dict(id='../x', port='80')), ('id tidak ada', dict(id='in-zz', port='80'))]:
    T('update ditolak: ' + nama, not sm.update_port_rule(G(**g))['status'])
sm.add_port_rule(G(direction='inbound', port='9000', protocol='tcp', rule_action='ACCEPT', source='0.0.0.0/0', remark='lain'))
x9 = [y for y in cfg()['inbound'] if y['port'] == '9000'][0]['id']
r = sm.update_port_rule(G(id=x9, port='8081-8090', protocol='tcp/udp', rule_action='DROP', source='10.0.0.0/8', remark='dup'))
T('update menjadi duplikat aturan lain ditolak', not r['status'] and ('sudah ada' in r['msg'] or 'already exists' in r['msg']), r)
TERAP['rc'] = 1
sebelum = [y for y in cfg()['inbound'] if y['id'] == x9][0]
r = sm.update_port_rule(G(id=x9, port='9100', protocol='tcp', rule_action='ACCEPT', source='0.0.0.0/0', remark='gagal'))
sesudah = [y for y in cfg()['inbound'] if y['id'] == x9][0]
T('kernel menolak: perubahan dibatalkan, aturan lama dipulihkan', not r['status'] and sesudah == sebelum, (r, sesudah))
TERAP['rc'] = 0
T('add_port_rule (memakai validasi bersama) masih menolak port tidak valid', not sm.add_port_rule(G(direction='inbound', port='0'))['status'])
T('hapus baseline tetap ditolak', not sm.del_port_rule(G(id='in-ssh'))['status'])
T('hapus aturan kustom berhasil', sm.del_port_rule(G(id=x9))['status'] and not any(y['id'] == x9 for y in cfg()['inbound']))

print('\n## Learned Rules: Create / Update / Delete')
r = sm.learned_add(G(aksi_l='B', kind='scanner', path='/Shell-Upload.php?x=1', ua='EvilScan/2.0'))
ls = sm.get_learned(G())['msg']['lessons']
T('tambah manual: tersimpan dinormalkan, ditandai manual, tanpa IP sumber', r['status'] and len(ls) == 1 and ls[0]['path'] == '/shell-upload.php' and ls[0]['ua'] == 'evilscan' and ls[0]['manual'] and ls[0]['sources'] == [], (r, ls))
tsv = open(d + '/etc/learned.tsv').read()
T('diterbitkan ke learned.tsv untuk guardd', '/shell-upload.php\tevilscan' in tsv, tsv)
T('tambah duplikat ditolak', not sm.learned_add(G(aksi_l='B', kind='scanner', path='/shell-upload.php', ua='evilscan'))['status'])
for nama, g in [('path "/"', dict(aksi_l='B', kind='scanner', path='/')), ('aset statis', dict(aksi_l='B', kind='scanner', path='/a/app.css')),
                ('UA peramban', dict(aksi_l='B', kind='bad-ua', ua='Mozilla/5.0 Chrome')), ('Googlebot diblokir', dict(aksi_l='B', kind='bad-ua', ua='Googlebot/2.1')),
                ('izinkan tanpa UA', dict(aksi_l='A', kind='scanner', path='/x.php')), ('aturan tidak dikenal', dict(aksi_l='X', path='/x.php')),
                ('kategori tidak dikenal', dict(aksi_l='B', kind='apa', path='/x.php')), ('kosong', dict(aksi_l='B', kind='scanner'))]:
    T('tambah ditolak: ' + nama, not sm.learned_add(G(**g))['status'])
lid = ls[0]['id']
r = sm.learned_update(G(id=lid, aksi_l='B', kind='campuran', path='/backdoor.php', ua='evilscan'))
ls = sm.get_learned(G())['msg']['lessons']
T('edit: pola dan kategori berubah, id baru mengikuti pola', r['status'] and len(ls) == 1 and ls[0]['path'] == '/backdoor.php' and ls[0]['kind'] == 'campuran' and ls[0]['id'] != lid, ls)
T('edit: learned.tsv ikut berubah', '/backdoor.php' in open(d + '/etc/learned.tsv').read() and '/shell-upload.php' not in open(d + '/etc/learned.tsv').read())
T('edit id tidak ada ditolak', not sm.learned_update(G(id='deadbeef', aksi_l='B', kind='scanner', path='/y.php'))['status'])
T('edit dengan pola tidak aman ditolak', not sm.learned_update(G(id=ls[0]['id'], aksi_l='B', kind='scanner', path='/'))['status'])
sm.learned_add(G(aksi_l='A', kind='bad-ua', ua='Mozilla/5.0 (compatible; FriendlyCrawler/1.0)'))
ls = sm.get_learned(G())['msg']['lessons']
T('tambah aturan izinkan untuk perayap', any(x['aksi'] == 'A' and x['ua'] == 'friendlycrawler' for x in ls), ls)
T('cabut (hapus) pelajaran', sm.learned_revoke(G(id=ls[0]['id']))['status'] and len(sm.get_learned(G())['msg']['lessons']) == 1)
T('pelajaran manual tidak ikut dicabut oleh unban/hapus allow IP lain', sm._learn_revoke_ip('9.9.9.9', 'A') == 0 and len(sm.get_learned(G())['msg']['lessons']) == 1)
import shutil; shutil.rmtree(d, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
