#!/usr/bin/env python3
# Uji CRUD whitelist / block / unblock: firewall, WAF, EDR, antivirus.
# Harapan SAMA untuk kode lama dan baru; kode lama gagal di tempat yang memang cacat.
# Pemakaian: crud_test.py <path sentinel_main.py> [ringkas]
import sys, os, json, re, time, hashlib, subprocess, importlib.util, shutil, copy

MOD = sys.argv[1]
sys.path.insert(0, '/www/server/panel'); sys.path.insert(0, '/www/server/panel/class')
sys.path.insert(0, '/www/server/panel/plugin/sentinel')
spec = importlib.util.spec_from_file_location('sm_uji', MOD)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

class G(dict):
    def get(self, k, d=None): return dict.get(self, k, d)

sm = mod.sentinel_main()
HASIL = []
GRUP = ['']

def grup(n):
    GRUP[0] = n
    print('\n## ' + n)

def T(nama, kondisi, detail=''):
    HASIL.append((GRUP[0], nama, bool(kondisi), detail))
    print('  %s %s%s' % ('LULUS' if kondisi else 'GAGAL', nama, '' if kondisi else '  -> ' + str(detail)[:200]))

def call(fn, **kw):
    try:
        return getattr(sm, fn)(G(kw))
    except Exception as ex:
        return {'status': False, 'msg': 'EXC %s: %s' % (type(ex).__name__, ex)}

def ok(r): return r.get('status') is True
def msg(r): return str(r.get('msg'))
def sh(c):
    p = subprocess.run(c, shell=True, capture_output=True, text=True)
    return p.stdout + p.stderr
def sha(path):
    try: return hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except Exception: return '-'

ALLOW = '/www/server/sentinel/etc/allowlist.txt'
PORTS = '/www/server/sentinel/etc/ports.json'
PROCWL = '/www/server/sentinel/etc/proc_whitelist.json'
FW = '/www/server/sentinel/waf/lua_waf/'
def ban_set(): return sh('ipset save sentinel_ban | grep "^add" | awk \'{print $3}\' | sort')
def fw_sentinel(): return sh('iptables -S SENTINEL; iptables -S SENTINEL_IN_PORTS 2>&1')

# ---------------------------------------------------------------- matriks IP
IP_VALID_HOST = ['203.0.113.10', '8.8.8.8', '198.51.100.77', ' 203.0.113.11 ']
IP_INVALID = [
    '', ' ', 'abc', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.256', '999.999.999.999',
    '01.2.3.4', '1.2.3.04', '1.2.3.-4', '+1.2.3.4', '1_0.2.3.4', '1.2.3.4/33', '1.2.3.4/',
    '1.2.3.4/-1', '1.2.3.4/08', '::1', '2001:db8::1', '1.2.3.4;id', "1.2.3.4'; touch /tmp/pwn_ip; '",
    '1.2.3.4\n5.6.7.8', '1.2.3.4 5.6.7.8', '1.2.3.4,5.6.7.8', '0.0.0.0', '255.255.255.255',
    '224.0.0.1', '240.0.0.1', '0.1.2.3', '1..2.3', '.1.2.3', '1.2.3.', 'localhost', '1.2.3.4/abc',
    '１.２.３.４', None, 123, ['1.2.3.4'], {'a': 1},
]

# =============================================================== 1. FIREWALL
grup('Firewall: block / unblock IP (ban_ip, unban_ip)')
awal = ban_set()
for ip in IP_VALID_HOST[:2]:
    r = call('ban_ip', ip=ip, secs='120')
    T('ban %r diterima' % ip, ok(r), msg(r))
    T('  masuk ipset kernel', ip.strip() in ban_set(), ban_set()[:80])
    r = call('unban_ip', ip=ip)
    T('unban %r diterima' % ip, ok(r), msg(r))
    T('  keluar dari ipset', ip.strip() not in ban_set())
r = call('ban_ip', ip=' 203.0.113.11 ')
T('ban dengan spasi di tepi dinormalkan', ok(r) and '203.0.113.11' in ban_set(), msg(r))
call('unban_ip', ip='203.0.113.11')
for secs in ['abc', '-5', '0', '1.5', '9' * 30 + 'x']:
    r = call('ban_ip', ip='203.0.113.12', secs=secs)
    T('ban durasi %r ditolak' % secs, not ok(r), msg(r))
for secs in ['60', '86400']:
    r = call('ban_ip', ip='203.0.113.12', secs=secs); call('unban_ip', ip='203.0.113.12')
    T('ban durasi %r diterima' % secs, ok(r), msg(r))
sebelum = ban_set()
for v in IP_INVALID + ['1.2.3.0/24', '10.0.0.0/8', '127.0.0.1', '169.254.1.1', sm._self_ip()]:
    r = call('ban_ip', ip=v)
    T('ban %r DITOLAK' % (v,), not ok(r), msg(r))
T('ipset tidak berubah setelah semua ban tak valid', ban_set() == sebelum, (ban_set(), sebelum))
T('tidak ada eksekusi perintah dari nilai IP (/tmp/pwn_ip)', not os.path.exists('/tmp/pwn_ip'))
for v in IP_INVALID + ['1.2.3.0/24']:
    r = call('unban_ip', ip=v)
    T('unban %r DITOLAK' % (v,), not ok(r), msg(r))
T('ipset utuh sesudah semua uji ban', ban_set() == awal, (ban_set(), awal))

grup('Firewall: daftar putih IP/CIDR (allow_ip, del_allow)')
a0 = sha(ALLOW)
VALID_ALLOW = [('203.0.113.50', '203.0.113.50'), ('192.0.2.0/24', '192.0.2.0/24'), ('198.51.100.0/25', '198.51.100.0/25'),
               ('203.0.113.60/32', '203.0.113.60'), ('172.31.0.0/16', '172.31.0.0/16'), ('100.64.0.0/10', '100.64.0.0/10')]
for masuk, tersimpan in VALID_ALLOW:
    r = call('allow_ip', ip=masuk)
    isi = [l.split('#')[0].strip() for l in open(ALLOW)]
    T('allow %r diterima' % masuk, ok(r), msg(r))
    T('  tersimpan sebagai %r' % tersimpan, tersimpan in isi, isi[-4:])
    rr = call('allow_ip', ip=masuk)
    isi2 = [l.split('#')[0].strip() for l in open(ALLOW)]
    T('  pemasangan ulang idempoten (tanpa duplikat)', ok(rr) and isi2.count(tersimpan) == 1, (msg(rr), isi2.count(tersimpan)))
fw = fw_sentinel()
T('CIDR 192.0.2.0/24 benar-benar menjadi aturan RETURN di kernel', '-s 192.0.2.0/24 -j RETURN' in fw, fw[:200])
for masuk, tersimpan in VALID_ALLOW:
    r = call('del_allow', ip=masuk)
    isi = [l.split('#')[0].strip() for l in open(ALLOW)]
    T('del %r diterima' % masuk, ok(r), msg(r))
    T('  hilang dari berkas', tersimpan not in isi)
T('allowlist.txt kembali identik setelah tambah+hapus', [l.split('#')[0].strip() for l in open(ALLOW)] == [l.split('#')[0].strip() for l in open('/www/server/sentinel/etc/allowlist.txt')] and True)
sebelum = sha(ALLOW)
fw0 = fw_sentinel()
INV_ALLOW = IP_INVALID + ['0.0.0.0/0', '10.0.0.0/7', '128.0.0.0/1', '192.0.2.5/24', '1.2.3.4/32/1', '192.0.2.0/24 ', ]
for v in [x for x in INV_ALLOW if x != '192.0.2.0/24 ']:
    r = call('allow_ip', ip=v)
    T('allow %r DITOLAK' % (v,), not ok(r), msg(r))
T('allowlist.txt tidak berubah oleh semua masukan tak valid', sha(ALLOW) == sebelum)
T('aturan iptables SENTINEL tidak berubah', fw_sentinel() == fw0)
for v in IP_INVALID + ['0.0.0.0/0']:
    r = call('del_allow', ip=v)
    T('del_allow %r DITOLAK' % (v,), not ok(r), msg(r))
r = call('del_allow', ip='203.0.113.99')
T('del_allow IP yang tidak ada -> gagal jelas', not ok(r), msg(r))
T('allowlist.txt utuh sesudah semua uji', sha(ALLOW) == sebelum)

grup('Firewall: aturan port (add_port_rule, toggle, del)')
p0 = json.load(open(PORTS)); fw0 = fw_sentinel(); h0 = sha(PORTS)
r = call('add_port_rule', direction='inbound', protocol='tcp', port='8080', rule_action='ACCEPT', source='203.0.113.0/24', remark='uji 1')
T('inbound sah diterima', ok(r), msg(r))
r2 = call('add_port_rule', direction='inbound', protocol='tcp/udp', port='9000-9010', rule_action='deny', source='198.51.100.1,198.51.100.2/31', remark='uji 2')
T('rentang port + daftar sumber + aksi huruf kecil diterima', ok(r2), msg(r2))
r3 = call('add_port_rule', direction='outbound', protocol='all', port='all', rule_action='ACCEPT', dest='10.9.0.0/16', remark='uji out')
T('outbound sah diterima', ok(r3), msg(r3))
cfg = json.load(open(PORTS))
ids = [x['id'] for x in cfg['inbound'] + cfg['outbound']]
T('ID aturan unik', len(ids) == len(set(ids)), ids)
sah = [x for x in cfg['inbound'] if x['port'] in ('8080', '9000-9010')]
T('aturan tersimpan dalam bentuk ternormalisasi', any(x['source'] == '203.0.113.0/24' for x in sah) and any(x['action'] == 'DROP' for x in sah), sah)
fwk = fw_sentinel()
T('aturan 8080 benar-benar ada di kernel (SENTINEL_IN_PORTS)', '--dport 8080' in fwk and '203.0.113.0/24' in fwk, fwk[-400:])
r = call('add_port_rule', direction='inbound', protocol='tcp', port='8080', rule_action='ACCEPT', source='203.0.113.0/24')
T('aturan duplikat DITOLAK', not ok(r), msg(r))
# dua pembuatan dalam detik yang sama tidak boleh bentrok ID
a = call('add_port_rule', direction='inbound', protocol='tcp', port='7001', rule_action='ACCEPT')
b = call('add_port_rule', direction='inbound', protocol='tcp', port='7002', rule_action='ACCEPT')
cfg = json.load(open(PORTS)); idl = [x['id'] for x in cfg['inbound']]
T('dua aturan beruntun: ID tidak bentrok', len(idl) == len(set(idl)), idl)
h1 = sha(PORTS); fw1 = fw_sentinel()
BAD = [
    dict(port='0'), dict(port='65536'), dict(port='abc'), dict(port='80-70'), dict(port='80-'), dict(port='-80'),
    dict(port='8000-8080-9000'), dict(port='٨٠'), dict(port=' '), dict(port='80;id'), dict(port='99999999'), dict(port='0080x'),
    dict(protocol='icmp'), dict(protocol='xyz'), dict(protocol='tcp;id'),
    dict(rule_action='REJECT'), dict(rule_action='ALLOWED'), dict(rule_action='ACCEPT;id'),
    dict(source='999.1.1.1'), dict(source='1.2.3.4/33'), dict(source='::1'), dict(source='1.2.3.4;ls'), dict(source='a,b'),
    dict(source=',,'), dict(source='1.2.3.4/24'), dict(source='01.2.3.4'), dict(source='1.2.3.4 -j ACCEPT'), dict(source='dead:beef::1'),
    dict(source=','.join('10.0.0.%d' % i for i in range(1, 30))),
    dict(direction='sideways'), dict(remark='x' * 500), dict(remark='a\nb\x00c'),
]
for kw in BAD:
    base = dict(direction='inbound', protocol='tcp', port='7777', rule_action='ACCEPT', source='203.0.113.0/24')
    base.update(kw)
    r = call('add_port_rule', **base)
    T('add_port_rule %s DITOLAK' % kw, not ok(r), msg(r))
bad_out = call('add_port_rule', direction='outbound', protocol='tcp', port='443', rule_action='DROP', dest='1.2.3.999')
T('outbound dest tak valid DITOLAK', not ok(bad_out), msg(bad_out))
T('ports.json tidak berubah oleh semua masukan tak valid', sha(PORTS) == h1)
T('kernel tidak berubah oleh masukan tak valid', fw_sentinel() == fw1)
sysid = 'in-ssh'
r = call('del_port_rule', id=sysid); T('hapus aturan baseline SSH DITOLAK', not ok(r), msg(r))
r = call('toggle_port_rule', id=sysid); T('matikan aturan baseline SSH DITOLAK', not ok(r), msg(r))
for bid in ['', ' ', "x'; touch /tmp/pwn_id; '", '../etc', 'a b', 'x' * 100, None, 5, ['in-ssh']]:
    r = call('del_port_rule', id=bid); T('del_port_rule id %r DITOLAK' % (bid,), not ok(r), msg(r))
    r = call('toggle_port_rule', id=bid); T('toggle_port_rule id %r DITOLAK' % (bid,), not ok(r), msg(r))
r = call('del_port_rule', id='in-tidak-ada'); T('hapus ID tak ada -> gagal jelas', not ok(r), msg(r))
cfg = json.load(open(PORTS))
mine = [x for x in cfg['inbound'] + cfg['outbound'] if not x.get('system')]
tid = mine[0]['id']
r = call('toggle_port_rule', id=tid); T('toggle aturan buatan pengguna', ok(r), msg(r))
r = call('toggle_port_rule', id=tid); T('toggle kembali', ok(r), msg(r))
for x in list(mine):
    call('del_port_rule', id=x['id'])
cfg = json.load(open(PORTS))
T('semua aturan uji terhapus, tinggal baseline', all(x.get('system') for x in cfg['inbound'] + cfg['outbound']), [x['id'] for x in cfg['inbound']])
T('ports.json kembali ke isi semula', [x['id'] for x in cfg['inbound']] == [x['id'] for x in p0['inbound']])
# edit manual berbahaya pada ports.json harus dilewati saat apply
cfg = json.load(open(PORTS)); backup = copy.deepcopy(cfg)
cfg['inbound'] += [
    {'id': 'manual-bad1', 'port': '31337', 'protocol': 'tcp', 'action': 'ACCEPT', 'source': "1.2.3.4' ; touch /tmp/pwn_apply ; '", 'enabled': True},
    {'id': 'manual-bad2', 'port': '31338', 'protocol': 'tcp', 'action': 'ALLOW', 'source': '0.0.0.0/0', 'enabled': True},
    {'id': 'manual-bad3', 'port': '31339', 'protocol': 'bogus', 'action': 'DROP', 'source': '0.0.0.0/0', 'enabled': True},
    {'id': 'manual-bad4', 'port': '31340', 'protocol': 'tcp', 'action': 'DROP', 'source': '1.2.3.999', 'enabled': True},
    {'id': 'manual-ok', 'port': '31341', 'protocol': 'tcp', 'action': 'ACCEPT', 'source': '203.0.113.0/24', 'enabled': True}]
json.dump(cfg, open(PORTS, 'w'), indent=2)
out = sh('/www/server/panel/pyenv/bin/python3 /www/server/sentinel/bin/sentinel-ports.py apply; echo "exit=$?"')
k = fw_sentinel()
T('apply melaporkan aturan tak valid dilewati (exit non-nol)', 'exit=3' in out and 'dilewati' in out, out[:300])
T('aturan manual tak valid TIDAK masuk kernel', not any(x in k for x in ('31337', '31338', '31339', '31340')), k[-300:])
T('aturan manual valid tetap terpasang', '--dport 31341' in k, k[-300:])
T('tidak ada eksekusi perintah dari ports.json (/tmp/pwn_apply)', not os.path.exists('/tmp/pwn_apply'))
json.dump(backup, open(PORTS, 'w'), indent=2); sh('/www/server/panel/pyenv/bin/python3 /www/server/sentinel/bin/sentinel-ports.py apply')

# ================================================================== 2. WAF
LISTS = '/www/server/sentinel/etc/waf-lists/'
ZYGEN = '/www/server/sentinel/waf/zyrules/gen/lists.conf'
import ipaddress
def isi(nama):
    try: return [l.strip() for l in open(LISTS + nama + '.txt') if l.strip()]
    except FileNotFoundError: return []
def lists_match(ids, ip):
    """Apakah ip termasuk dalam aturan @ipMatch dengan id di rentang ids (dari lists.conf hasil generator)."""
    teks = open(ZYGEN).read()
    ipo = ipaddress.ip_address(ip)
    for m in re.finditer(r'@ipMatch ([^"]+)" "id:(\d+)', teks):
        if int(m.group(2)) in ids:
            for c in m.group(1).split(','):
                if ipo in ipaddress.ip_network(c, strict=False): return True
    return False
def ctl(fn, **kw):
    kw.setdefault('reload', '0')
    return call(fn, **kw)
sh('/www/server/sentinel/bin/sentinel-waf.sh zyrules-install >/dev/null 2>&1')
grup('WAF: daftar IP (ip_black / ip_white) disimpan dan disusun ke aturan SecLang')
w0 = {n: sha(LISTS + n + '.txt') for n in ('ip_black', 'ip_white', 'url_black', 'url_white')}
for nama, ids in (('ip_black', range(8000060, 8000100)), ('ip_white', range(8000020, 8000040))):
    for nilai, simpan, cocok, tidak in [('203.0.113.7', '203.0.113.7', '203.0.113.7', '203.0.113.8'),
                                         ('198.51.100.0/24', '198.51.100.0/24', '198.51.100.55', '198.51.101.1'),
                                         ('192.0.2.10-192.0.2.20', '192.0.2.10-192.0.2.20', '192.0.2.15', '192.0.2.21'),
                                         (' 203.0.113.99 ', '203.0.113.99', '203.0.113.99', '203.0.113.98')]:
        r = ctl('waf_list_add', list=nama, value=nilai)
        T('%s: tambah %r diterima' % (nama, nilai), ok(r), msg(r))
        T('  tersimpan sebagai %r' % simpan, simpan in isi(nama), isi(nama))
        T('  aturan SecLang COCOK untuk %s' % cocok, lists_match(ids, cocok), '')
        T('  aturan SecLang TIDAK cocok untuk %s' % tidak, not lists_match(ids, tidak), '')
    r = ctl('waf_list_add', list=nama, value='203.0.113.7')
    T('%s: duplikat DITOLAK' % nama, not ok(r), msg(r))
    r = ctl('waf_list_add', list=nama, value='203.0.113.7/32')
    T('%s: bentuk setara (/32) juga duplikat' % nama, not ok(r), msg(r))
    r = ctl('waf_list_add', list=nama, value='198.51.100.0-198.51.100.255')
    T('%s: rentang setara CIDR juga duplikat' % nama, not ok(r), msg(r))
    tampil = call('get_waf_lists')['msg'][nama]
    T('%s: daftar ditampilkan sebagai teks IP/CIDR/rentang' % nama, all(isinstance(x, str) and re.fullmatch(r'[0-9./-]+', x) for x in tampil) and '198.51.100.0/24' in tampil, tampil)
    for nilai in ['203.0.113.7', '198.51.100.0/24', '192.0.2.10-192.0.2.20', '203.0.113.99']:
        r = ctl('waf_list_del', list=nama, value=nilai)
        T('%s: hapus %r' % (nama, nilai), ok(r), msg(r))
    T('%s: kosong kembali' % nama, isi(nama) == [], isi(nama))
bad_ip = IP_INVALID + ['1.2.3.0/24x', '0.0.0.0/0', '10.0.0.0/7', '1.2.3.4-1.2.3.3', '1.2.3.4-', '-1.2.3.4', '1.2.3.4-5.6.7.8-9.9.9.9', '1.2.3.4-abc',
                       '0.0.0.0-255.255.255.255', '10.0.0.0-200.0.0.0', '192.0.2.5/24']
for nama in ('ip_black', 'ip_white'):
    s0 = sha(LISTS + nama + '.txt')
    for v in bad_ip:
        r = ctl('waf_list_add', list=nama, value=v)
        T('%s: tambah %r DITOLAK' % (nama, v), not ok(r), msg(r))
    T('%s: berkas tidak berubah oleh masukan tak valid' % nama, sha(LISTS + nama + '.txt') == s0)
r = ctl('waf_list_add', list='ip_black', value='127.0.0.1'); T('ip_black: loopback DITOLAK', not ok(r), msg(r))
r = ctl('waf_list_add', list='ip_black', value='127.0.0.0/8'); T('ip_black: 127.0.0.0/8 DITOLAK', not ok(r), msg(r))
r = ctl('waf_list_add', list='ip_black', value=sm._self_ip() + '-' + sm._self_ip()); T('ip_black: alamat server sendiri DITOLAK', not ok(r), msg(r))
for lst in ('nope', '', None, 'ip_black;id'):
    r = ctl('waf_list_add', list=lst, value='1.2.3.4'); T('daftar %r DITOLAK' % (lst,), not ok(r), msg(r))
for v in [None, 123, ['1.2.3.4']]:
    r = ctl('waf_list_add', list='ip_black', value=v); T('nilai non-teks %r DITOLAK tanpa crash' % (v,), not ok(r) and 'EXC' not in msg(r), msg(r))
r = ctl('waf_list_del', list='ip_black', value='203.0.113.200'); T('hapus entri yang tak ada -> gagal jelas', not ok(r), msg(r))
for v in [None, 123, '', 'x' * 600]:
    r = ctl('waf_list_del', list='ip_black', value=v); T('waf_list_del nilai %r DITOLAK tanpa crash' % (str(v)[:10],), not ok(r) and 'EXC' not in msg(r), msg(r))

grup('WAF: daftar URL (url_black / url_white) = regex')
for nama in ('url_black', 'url_white'):
    for v in ['^/admin/', r'/wp-login\.php', r'\.(env|git)$']:
        r = ctl('waf_list_add', list=nama, value=v); T('%s: tambah %r' % (nama, v), ok(r), msg(r))
    r = ctl('waf_list_add', list=nama, value='^/admin/'); T('%s: duplikat DITOLAK' % nama, not ok(r), msg(r))
    s0 = sha(LISTS + nama + '.txt')
    for v in ['(', '[a-', '*abc', '(?P<x', '.*', '^', '.', '|', '', ' ', 'x' * 400, 'a\nb', 'a\x00b', '(a' * 3, None, 5]:
        r = ctl('waf_list_add', list=nama, value=v); T('%s: tambah %r DITOLAK' % (nama, str(v)[:20]), not ok(r) and 'EXC' not in msg(r), msg(r))
    T('%s: berkas tidak berubah oleh masukan tak valid' % nama, sha(LISTS + nama + '.txt') == s0)
    T('%s: konfigurasi turunan valid (generator tanpa peringatan)' % nama, 'peringatan=0' in sh('/www/server/sentinel/bin/sentinel-waf.sh zyrules-build 2>&1'))
    for v in ['^/admin/', r'/wp-login\.php', r'\.(env|git)$']:
        r = ctl('waf_list_del', list=nama, value=v); T('%s: hapus %r' % (nama, v), ok(r), msg(r))
T('semua daftar WAF kembali ke isi semula', all(isi(n) == [] for n in w0), {n: isi(n) for n in w0})

grup('WAF: modul dan pengaturan ZySentinel')
MODUL = ['sensitive_files', 'webshell', 'spam', 'scanner', 'bot', 'lfi_args']
for m in MODUL:
    r = ctl('set_zy_module', name=m, state='off'); T('modul %s off diterima' % m, ok(r), msg(r))
    dis = open('/www/server/sentinel/waf/zyrules/gen/disable.conf').read()
    T('  SecRuleRemoveById tertulis untuk %s' % m, 'SecRuleRemoveById' in dis, dis)
    r = ctl('set_zy_module', name=m, state='on'); T('modul %s on kembali' % m, ok(r), msg(r))
T('semua modul on: disable.conf kosong dari RemoveById', 'SecRuleRemoveById' not in open('/www/server/sentinel/waf/zyrules/gen/disable.conf').read())
for nama in ['nope', '', None, 'scanner;id', 'a b', 5, ['scanner']]:
    r = ctl('set_zy_module', name=nama, state='off'); T('modul %r DITOLAK' % (nama,), not ok(r) and 'EXC' not in msg(r), msg(r))
for st in ['maybe', '', None, 'ON ', 1]:
    r = ctl('set_zy_module', name='scanner', state=st); T('state %r DITOLAK' % (st,), not ok(r) and 'EXC' not in msg(r), msg(r))
for k, v in (('bot_level', '0'), ('bot_level', '3'), ('strict', '1'), ('strict', '0'), ('fallback', '0'), ('fallback', '1'), ('paranoia', '4'), ('paranoia', '1'), ('threshold', '100'), ('threshold', '5'), ('bot_level', '1')):
    r = ctl('set_zy_setting', key=k, value=v); T('pengaturan %s=%s diterima' % (k, v), ok(r), msg(r))
for k, v in (('bot_level', '4'), ('bot_level', '-1'), ('bot_level', 'a'), ('bot_level', ''), ('strict', '2'), ('paranoia', '0'), ('paranoia', '5'), ('threshold', '0'), ('threshold', '101'), ('bot_level', '1;id'), ('bot_level', '01234'), ('nope', '1'), ('', '1'), (None, '1'), ('bot_level', None)):
    r = ctl('set_zy_setting', key=k, value=v); T('pengaturan %r=%r DITOLAK' % (k, v), not ok(r) and 'EXC' not in msg(r), msg(r))
st = call('get_zyrules')['msg']
T('pengaturan akhir kembali ke bawaan', st['pengaturan'] == {'bot_level': 1, 'strict': 0, 'fallback': 1, 'paranoia': 1, 'threshold': 5}, st['pengaturan'])

# ================================================================== 3. EDR
grup('EDR: whitelist proses (add/del/toggle_proc_whitelist)')
e0 = json.load(open(PROCWL)) if os.path.exists(PROCWL) else []
GOOD = [('cmdline_match', 'git fetch-uji', 'Git uji'), ('exe_exact', '/usr/bin/composer', 'Composer'), ('exe_exact', 'composer', 'Composer nama'),
        ('basename', 'rsync', 'Rsync'), ('cwd_match', '/www/wwwroot/situs-a', 'Situs A')]
dibuat = []
for t, pat, nm in GOOD:
    r = call('add_proc_whitelist', type=t, pattern=pat, name=nm, remark='uji')
    T('tambah %s %r diterima' % (t, pat), ok(r), msg(r))
cur = json.load(open(PROCWL))
T('ID aturan unik (termasuk 5 pembuatan dalam detik yang sama)', len({x['id'] for x in cur}) == len(cur), [x['id'] for x in cur])
r = call('add_proc_whitelist', type='basename', pattern='rsync'); T('duplikat DITOLAK', not ok(r), msg(r))
h = sha(PROCWL)
BADW = [dict(type='nonsense', pattern='abcdef'), dict(type='', pattern='abcdef'), dict(type='cmdline_match', pattern=''), dict(type='cmdline_match', pattern='  '),
        dict(type='cmdline_match', pattern='a'), dict(type='cmdline_match', pattern='ab'), dict(type='basename', pattern='/bin/sh'), dict(type='basename', pattern='a b c'),
        dict(type='cwd_match', pattern='/'), dict(type='cwd_match', pattern='/www'), dict(type='cwd_match', pattern='relatif/path'), dict(type='cwd_match', pattern='/www/../etc'),
        dict(type='exe_exact', pattern='../bin/x'), dict(type='exe_exact', pattern='dir/relatif'), dict(type='exe_exact', pattern='/usr/bin/a b'),
        dict(type='cmdline_match', pattern='x' * 301), dict(type='cmdline_match', pattern='abc\ndef'), dict(type='cmdline_match', pattern='abc\x00def'),
        dict(type='cmdline_match', pattern='abcdef', name='n' * 200), dict(type='cmdline_match', pattern='abcdef', remark='r' * 500),
        dict(type='cmdline_match', pattern='abcdef', name='a\nb')]
for kw in BADW:
    r = call('add_proc_whitelist', **kw)
    T('tambah %s DITOLAK' % {k: (str(v)[:18]) for k, v in kw.items()}, not ok(r) and 'EXC' not in msg(r), msg(r))
T('proc_whitelist.json tidak berubah oleh masukan tak valid', sha(PROCWL) == h)
try:
    json.load(open(PROCWL)); T('proc_whitelist.json tetap JSON valid', True)
except Exception as ex:
    T('proc_whitelist.json tetap JSON valid', False, ex)
for bid in ['', "x'; touch /tmp/pwn_wl; '", '../x', 'a b', 'x' * 100, None]:
    for fn in ('del_proc_whitelist', 'toggle_proc_whitelist'):
        r = call(fn, id=bid); T('%s id %r DITOLAK' % (fn, bid), not ok(r) and 'EXC' not in msg(r), msg(r))
for fn in ('del_proc_whitelist', 'toggle_proc_whitelist'):
    r = call(fn, id='wl-tidak-ada'); T('%s ID tak ada -> gagal jelas' % fn, not ok(r), msg(r))
cur = json.load(open(PROCWL)); baru = [x for x in cur if x['id'] not in {y['id'] for y in e0}]
r = call('toggle_proc_whitelist', id=baru[0]['id']); T('toggle aturan', ok(r), msg(r))
T('  status berubah di berkas', json.load(open(PROCWL))[len(e0)]['enabled'] is False)
for x in baru:
    r = call('del_proc_whitelist', id=x['id']); T('hapus %s' % x['id'], ok(r), msg(r))
T('whitelist EDR kembali ke isi semula', json.load(open(PROCWL)) == e0)

# ========================================================== 4. ANTIVIRUS
grup('Antivirus: pemindaian, baseline, karantina')
for f in ('/tmp/pwn_av', '/tmp/pwn_label', '/tmp/pwn_meta', '/tmp/pwn_vhost'):
    if os.path.exists(f): os.remove(f)
os.makedirs('/tmp/av_uji', exist_ok=True); open('/tmp/av_uji/a.txt', 'w').write('uji')
inj = "/tmp/av_uji/x'; touch /tmp/pwn_av; '"
os.makedirs(inj, exist_ok=True)
for fn in ('av_scan_abort',):
    call(fn)
for eng in ['hacker', 'both;id', '', 'ALL ', 'clamav\n']:
    r = call('av_scan_start', path='/tmp/av_uji', engine=eng, label='uji')
    if eng in ('', 'ALL ', 'clamav\n'):   # nilai yang setelah strip/lower sah ('' = bawaan both)
        T('av_scan_start engine %r tidak crash' % eng, 'EXC' not in msg(r), msg(r))
    else:
        T('av_scan_start engine %r DITOLAK' % eng, not ok(r), msg(r))
    call('av_scan_abort')
for pth in ['', ' ', '/tidak/ada/sama/sekali', '/tmp/av_uji/a.txt\n/etc', '/tmp/av_uji\x00/etc', None, 5, 'x' * 2000]:
    r = call('av_scan_start', path=pth, engine='judol'); T('av_scan_start path %r DITOLAK' % (str(pth)[:20],), not ok(r) and 'EXC' not in msg(r), msg(r)); call('av_scan_abort')
    r = call('av_scan', path=pth, engine='judol'); T('av_scan path %r DITOLAK' % (str(pth)[:20],), not ok(r) and 'EXC' not in msg(r), msg(r))
    r = call('av_baseline', path=pth); T('av_baseline path %r DITOLAK' % (str(pth)[:20],), not ok(r) and 'EXC' not in msg(r), msg(r))
    r = call('av_check', path=pth); T('av_check path %r DITOLAK' % (str(pth)[:20],), not ok(r) and 'EXC' not in msg(r), msg(r))
# injeksi lewat label (target sistem) dan lewat nama direktori
r = call('av_scan_start', target_type='system', engine='judol', label="x'; touch /tmp/pwn_label; '")
time.sleep(3); call('av_scan_abort')
T('label berisi kutip tunggal tidak mengeksekusi perintah (/tmp/pwn_label)', not os.path.exists('/tmp/pwn_label'))
r = call('av_scan_start', path=inj, engine='judol', label='uji2')
time.sleep(3); call('av_scan_abort')
T('nama direktori berisi kutip tunggal tidak mengeksekusi perintah (/tmp/pwn_av)', not os.path.exists('/tmp/pwn_av'))
r = call('av_scan_start', path='/tmp/av_uji', engine='judol', label='uji3')
T('pemindaian sah dimulai', ok(r), msg(r)); time.sleep(2); call('av_scan_abort')
for qid in ['', "x'; touch /tmp/pwn_meta; '", '../etc/passwd', 'a b', 'x' * 200, None]:
    for fn in ('av_restore', 'av_delete'):
        r = call(fn, id=qid); T('%s id %r DITOLAK' % (fn, qid), not ok(r) and 'EXC' not in msg(r), msg(r))
QD = '/www/server/sentinel/av/quarantine'
open('/tmp/luar.meta', 'w').write('{}')
metas = ['/tmp/luar.meta', QD + '/../../../../tmp/luar.meta', QD + "/x'; touch /tmp/pwn_meta; '.meta", QD + '/tidak-ada.meta', QD + '/a.txt', '', None]
for m in metas:
    for fn in ('restore_vhost_quarantine', 'delete_vhost_quarantine'):
        r = call(fn, meta=m); T('%s meta %r DITOLAK' % (fn, str(m)[:50]), not ok(r) and 'EXC' not in msg(r), msg(r))
T('berkas di luar karantina tidak tersentuh', os.path.exists('/tmp/luar.meta'))
T('tidak ada eksekusi perintah dari meta (/tmp/pwn_meta)', not os.path.exists('/tmp/pwn_meta'))
VH_BAD = ["a'; touch /tmp/pwn_vhost; 'b", 'a/b', '..', 'a b', '', 'x' * 200, '$(id)', 'a;b', '`id`', 'a|b']
for v in VH_BAD:
    for fn, kw in (('toggle_vhost_upload_scan', {}), ('set_vhost_upload_scan', {'state': 'on'})):
        r = call(fn, vhost=v, **kw); T('%s vhost %r DITOLAK' % (fn, v[:20]), not ok(r) and 'EXC' not in msg(r), msg(r))
    if v:
        r = call('get_vhost_quarantine', vhost=v); T('get_vhost_quarantine vhost %r DITOLAK' % v[:20], not ok(r) and 'EXC' not in msg(r), msg(r))
T('tidak ada eksekusi perintah dari nama vhost (/tmp/pwn_vhost)', not os.path.exists('/tmp/pwn_vhost'))
r = call('set_vhost_upload_scan', vhost='situs-uji.example.com', state='on'); T('nama vhost sah diterima', ok(r), msg(r))
r = call('set_vhost_upload_scan', vhost='situs-uji.example.com', state='off')

grup('Geo-ban: kode negara (hanya penolakan; tidak menyalakan geo-ban sungguhan)')
for kode in ['C', 'CNN', '1;', '..', 'ZZ', 'C N;id', 'cn,', ',,', '', None, 'CN,RU,;;', '$(', '`id`']:
    r = call('set_geo_ban', aksi='on', confirm='GEO', negara=kode, mode='block')
    T('geo on negara %r DITOLAK' % (kode,), not ok(r) and 'EXC' not in msg(r), msg(r))
r = call('set_geo_ban', aksi='on', confirm='geo', negara='CN'); T('konfirmasi salah DITOLAK', not ok(r), msg(r))
r = call('set_geo_ban', aksi='on', confirm='GEO', negara='CN', mode='bogus'); T('mode tak valid DITOLAK', not ok(r), msg(r))
r = call('set_geo_ban', aksi='maybe'); T('aksi tak valid DITOLAK', not ok(r), msg(r))

# ================================================================ ringkasan
print('\n================ RINGKASAN (%s)' % os.path.basename(MOD))
per = {}
for g, n, c, d in HASIL:
    p = per.setdefault(g, [0, 0]); p[0 if c else 1] += 1
tot = [0, 0]
for g, (l, f) in per.items():
    print('%-70s lulus=%-4d gagal=%d' % (g, l, f)); tot[0] += l; tot[1] += f
print('TOTAL lulus=%d gagal=%d' % tuple(tot))
json.dump([h for h in HASIL if not h[2]], open('/tmp/gagal_%s.json' % ('baru' if 'old' not in MOD else 'lama'), 'w'), ensure_ascii=False, indent=1)
sys.exit(1 if tot[1] else 0)
