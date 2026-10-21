#!/usr/bin/env python3
# Uji PERILAKU PAKET sentinel-fw.sh + sentinel-ports.py di dua network namespace (server dan klien,
# dihubungkan veth). Firewall host tidak tersentuh: aturan dipasang di netns "zysfw_srv". Skrip
# dijalankan dengan mount namespace privat: /www/server/sentinel/run dan log = tmpfs, etc = read-only,
# bin/sentinel-ports.py = salinan yang diuji. Tidak ada yang ditulis ke produksi.
#
#   python3 -B fw_netns_test.py <sentinel-fw.sh> <sentinel-ports.py>
import os, sys, time, subprocess, socket, shutil, tempfile

FW = os.path.abspath(sys.argv[1]); PORTS = os.path.abspath(sys.argv[2])
SRV, CLI = 'zysfw_srv', 'zysfw_cli'
gagal = 0
def cek(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:300]))
    if not k: gagal += 1

def sh(cmd, ns=None, check=False, timeout=60):
    if ns:
        # SELURUH perintah (termasuk ; && |) harus berjalan di dalam netns. Dulu hanya
        # perintah pertama yang dibungkus, sisanya berjalan di host.
        import shlex
        cmd = 'ip netns exec %s bash -c %s' % (ns, shlex.quote(cmd))
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError('%s -> %s' % (cmd, r.stderr))
    return r

def bersih():
    sh('ip netns pids %s 2>/dev/null | xargs -r kill -9' % SRV)
    sh('ip netns pids %s 2>/dev/null | xargs -r kill -9' % CLI)
    sh('ip netns del %s' % SRV); sh('ip netns del %s' % CLI)

T = tempfile.mkdtemp(prefix='zysfwns.', dir='/tmp')
FW_PASANG = '''set -e
mount --make-rprivate / 2>/dev/null || true
mount --bind %(t)s/run /www/server/sentinel/run
mount --bind %(t)s/log /www/server/sentinel/log
mount --bind /www/server/sentinel/etc /www/server/sentinel/etc
mount -o remount,ro,bind /www/server/sentinel/etc
mount --bind %(ports)s /www/server/sentinel/bin/sentinel-ports.py
bash %(fw)s "$@"
''' % {'ports': PORTS, 'fw': FW, 't': T}
os.makedirs(T + '/run'); os.makedirs(T + '/log')
open(T + '/fw_in_ns.sh', 'w').write(FW_PASANG)

def fw(*arg):
    return sh('unshare -m --propagation private bash %s/fw_in_ns.sh %s' % (T, ' '.join(arg)), ns=SRV, timeout=180)

LISTEN = r'''
import socket, threading, sys
def tcp(p):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', p)); s.listen(512)
    while True:
        c, _ = s.accept(); c.close()
def udp(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', p))
    while True:
        d, a = s.recvfrom(2048); s.sendto(b'ok', a)
for p in (80, 443, 2244, 15960, 8888):
    threading.Thread(target=tcp, args=(p,), daemon=True).start()
threading.Thread(target=udp, args=(443,), daemon=True).start()
threading.Event().wait()
'''
open(T + '/listen.py', 'w').write(LISTEN)

PROBE = r'''
import socket, sys, time
src, proto, port, n = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
ok = 0
for i in range(n):
    try:
        if proto == 'tcp':
            s = socket.socket(); s.settimeout(0.6); s.bind((src, 0)); s.connect(('203.0.113.1', port)); s.close(); ok += 1
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.6); s.bind((src, 0))
            s.sendto(b'x', ('203.0.113.1', port)); s.recvfrom(16); ok += 1
    except Exception:
        pass
print(ok)
'''
open(T + '/probe.py', 'w').write(PROBE)

def probe(src, proto, port, n=1):
    r = sh('python3 %s/probe.py %s %s %d %d' % (T, src, proto, port, n), ns=CLI, timeout=120)
    try: return int(r.stdout.strip())
    except Exception: return -1

def siapkan():
    bersih()
    sh('ip netns add %s' % SRV, check=True); sh('ip netns add %s' % CLI, check=True)
    sh('ip link add zysfw0 type veth peer name zysfw1', check=True)
    sh('ip link set zysfw0 netns %s' % SRV, check=True); sh('ip link set zysfw1 netns %s' % CLI, check=True)
    sh('ip link set zysfw0 name eth0', ns=SRV, check=True)
    sh('ip addr add 203.0.113.1/24 dev eth0', ns=SRV, check=True)
    sh('ip link set eth0 up', ns=SRV, check=True); sh('ip link set lo up', ns=SRV, check=True)
    sh('ip route add default via 203.0.113.254 dev eth0 onlink', ns=SRV, check=True)
    sh('ip addr add 203.0.113.2/24 dev zysfw1', ns=CLI, check=True)
    for a in range(3, 12):
        sh('ip addr add 203.0.113.%d/32 dev zysfw1' % a, ns=CLI)
    sh('ip addr add 10.9.9.9/32 dev zysfw1', ns=CLI)
    sh('ip link set zysfw1 up', ns=CLI, check=True); sh('ip link set lo up', ns=CLI)
    sh('ip route add 203.0.113.0/24 dev zysfw1', ns=CLI)
    sh('sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.eth0.rp_filter=0', ns=SRV)
    sh('ip route add 10.9.9.9/32 dev eth0', ns=SRV)   # balasan ke sumber privat palsu lewat eth0
    for f in os.listdir(T + '/run'):
        os.remove(os.path.join(T + '/run', f))
    # meniru aaPanel: set whitelist panel dan chain IN_BT; Docker: DOCKER-USER
    sh('ipset create aapanel.ipv4.whitelist hash:net', ns=SRV)
    sh('iptables -N IN_BT', ns=SRV); sh('iptables -A INPUT -j IN_BT', ns=SRV)
    sh('iptables -N DOCKER-USER', ns=SRV); sh('iptables -A FORWARD -j DOCKER-USER', ns=SRV)
    subprocess.Popen('ip netns exec %s python3 %s/listen.py' % (SRV, T), shell=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

def rangkaian(label):
    print('\n## %s' % label)
    siapkan()
    r = fw('install')
    cek('install berhasil', r.returncode == 0, (r.stdout + r.stderr)[-600:])
    rules = sh('iptables -S SENTINEL', ns=SRV).stdout
    cek('chain SENTINEL ter-hook dari IN_BT dan berisi ban-drop', '-A SENTINEL -m set --match-set sentinel_ban src' in rules and '-A IN_BT -j SENTINEL' in sh('iptables -S IN_BT', ns=SRV).stdout, rules[-500:])
    h = {}
    h['normal_443'] = probe('203.0.113.2', 'tcp', 443, 3)
    h['ssh_2244'] = probe('203.0.113.2', 'tcp', 2244, 1)
    h['panel_15960'] = probe('203.0.113.2', 'tcp', 15960, 1)
    h['quic_normal'] = probe('203.0.113.2', 'udp', 443, 2)
    sh('ipset add sentinel_ban 203.0.113.3', ns=SRV)
    h['ban_443'] = probe('203.0.113.3', 'tcp', 443, 2)
    sh('ipset add sentinel_review 203.0.113.4', ns=SRV); sh('ipset add sentinel_ban 203.0.113.4', ns=SRV)
    h['review_dan_ban_443'] = probe('203.0.113.4', 'tcp', 443, 2)
    sh('ipset add sentinel_review 203.0.113.11', ns=SRV)
    h['review_saja_443'] = probe('203.0.113.11', 'tcp', 443, 2)
    h['review_saja_port_tertutup_8888'] = probe('203.0.113.11', 'tcp', 8888, 1)
    sh('ipset add sentinel_throttle 203.0.113.5', ns=SRV); sh('ipset add sentinel_throttle 203.0.113.6', ns=SRV)
    h['throttle_A_banjir_40'] = probe('203.0.113.5', 'tcp', 443, 40)
    h['throttle_B_3_sesudahnya'] = probe('203.0.113.6', 'tcp', 443, 3)
    h['throttle_quic'] = probe('203.0.113.6', 'udp', 443, 2)
    h['privat_palsu_eth0_8888'] = probe('10.9.9.9', 'tcp', 8888, 1)
    h['publik_8888'] = probe('203.0.113.7', 'tcp', 8888, 1)
    for k, v in h.items():
        print('    %-32s %s' % (k, v))
    return h

def panic_uji():
    print('\n## panic (versi baru)')
    r = fw('panic-on')
    cek('panic-on berhasil', r.returncode == 0, (r.stdout + r.stderr)[-300:])
    a = (probe('203.0.113.8', 'tcp', 443, 1), probe('203.0.113.8', 'udp', 443, 1), probe('203.0.113.8', 'tcp', 15960, 1), probe('203.0.113.8', 'tcp', 2244, 1))
    cek('panic: TCP 443 dan UDP 443 ditutup, panel 15960 dan SSH 2244 tetap terbuka', a == (0, 0, 1, 1), a)
    fw('install')     # seperti sentinel-fw.timer
    b = (probe('203.0.113.9', 'tcp', 443, 1), probe('203.0.113.9', 'tcp', 15960, 1))
    cek('panic BERTAHAN setelah install ulang (timer 5 menit)', b == (0, 1), b)
    fw('panic-off')
    c = probe('203.0.113.9', 'tcp', 443, 1)
    cek('panic-off membuka 443 kembali', c == 1, c)
    du = sh('iptables -S SENTINEL_DOCKER', ns=SRV).stdout
    cek('ban juga dipasang di DOCKER-USER', 'sentinel:docker-ban' in du and '-A DOCKER-USER -j SENTINEL_DOCKER' in sh('iptables -S DOCKER-USER', ns=SRV).stdout, du)
    r1 = sh('iptables -S SENTINEL', ns=SRV).stdout
    fw('install'); r2 = sh('iptables -S SENTINEL', ns=SRV).stdout
    cek('install berulang idempoten (aturan identik, tidak menumpuk)', r1 == r2 and r1.count('ban-drop') == 1, (r1.count('\n'), r2.count('\n')))
    r = fw('install')
    cek('install tanpa perubahan: tidak dipasang ulang', 'tidak berubah' in r.stdout, r.stdout[-400:])
    # penghitung paket bertahan melewati install (dulu selalu kembali ke nol)
    sh('ipset add sentinel_ban 203.0.113.10', ns=SRV)
    probe('203.0.113.10', 'tcp', 443, 3)
    def hit(chain, kom):
        for l in sh('iptables -L %s -v -x -n' % chain, ns=SRV).stdout.splitlines():
            if kom in l:
                return int(l.split()[0])
        return -1
    b1, d1 = hit('SENTINEL', 'sentinel:ban-drop'), hit('SENTINEL_IN_PORTS', 'sentinel:in-default-drop')
    probe('203.0.113.7', 'tcp', 8888, 1)
    d1 = hit('SENTINEL_IN_PORTS', 'sentinel:in-default-drop')
    fw('install')
    b2, d2 = hit('SENTINEL', 'sentinel:ban-drop'), hit('SENTINEL_IN_PORTS', 'sentinel:in-default-drop')
    cek('penghitung ban-drop bertahan setelah install (timer 5 menit)', b1 > 0 and b2 >= b1, (b1, b2))
    cek('penghitung default-drop port firewall bertahan setelah install', d1 > 0 and d2 >= d1, (d1, d2))
    # perubahan nyata tetap diterapkan, atomik
    sh('ipset create sentinel_intel hash:net 2>/dev/null; ipset add sentinel_intel 192.0.2.0/24', ns=SRV)
    r = fw('install')
    cek('perubahan aturan (threat intel muncul) dipasang ulang secara atomik', 'dipasang atomik' in r.stdout and 'intel-drop' in sh('iptables -S SENTINEL', ns=SRV).stdout, r.stdout[-400:])
    cek('chain Docker diperbarui (intel) saat set intel muncul', 'docker-intel' in sh('iptables -S SENTINEL_DOCKER', ns=SRV).stdout)
    pr = sh('iptables -S SENTINEL_IN_PORTS', ns=SRV).stdout
    cek('SENTINEL_IN_PORTS utuh: default-drop di akhir, SSH dan panel diizinkan', pr.strip().splitlines()[-1].endswith('-j DROP') and 'auto-ssh' in pr and 'auto-panel' in pr, pr[-300:])
    sen = [l for l in sh('iptables -S SENTINEL', ns=SRV).stdout.splitlines() if l.startswith('-A ')]
    cek('SENTINEL diakhiri lompatan port firewall lalu RETURN, tanpa duplikat', sen[-2:] == ['-A SENTINEL -j SENTINEL_IN_PORTS', '-A SENTINEL -j RETURN'] and sum(1 for l in sen if l == '-A SENTINEL -j SENTINEL_IN_PORTS') == 1, sen[-3:])

try:
    lama_fw = sorted(p for p in os.listdir(os.path.dirname(FW)) if p.startswith('sentinel-fw.sh.bak.'))
    lama_ports = sorted(p for p in os.listdir(os.path.dirname(PORTS)) if p.startswith('sentinel-ports.py.bak.'))
    if lama_fw and lama_ports:
        FW0, PORTS0 = FW, PORTS
        FW, PORTS = os.path.join(os.path.dirname(FW0), lama_fw[0]), os.path.join(os.path.dirname(PORTS0), lama_ports[0])
        open(T + '/fw_in_ns.sh', 'w').write(FW_PASANG.replace(FW0, FW).replace(PORTS0, PORTS))
        lama = rangkaian('SEBELUM: %s' % lama_fw[0])
        FW, PORTS = FW0, PORTS0
        open(T + '/fw_in_ns.sh', 'w').write(FW_PASANG)
    baru = rangkaian('SESUDAH: versi diuji')
    cek('klien normal: 443 TCP, SSH 2244, panel 15960, QUIC tetap jalan', baru['normal_443'] == 3 and baru['ssh_2244'] == 1 and baru['panel_15960'] == 1 and baru['quic_normal'] == 2, baru)
    cek('IP di sentinel_ban diblokir', baru['ban_443'] == 0)
    cek('IP di review DAN ban kini DIBLOKIR', baru['review_dan_ban_443'] == 0, baru['review_dan_ban_443'])
    cek('IP review saja tetap bisa ke web (review tidak memblokir)', baru['review_saja_443'] == 2)
    cek('IP review saja tidak lagi melewati default-drop port tertutup', baru['review_saja_port_tertutup_8888'] == 0)
    cek('throttle per IP: banjir A dibatasi', 0 < baru['throttle_A_banjir_40'] < 40, baru['throttle_A_banjir_40'])
    cek('throttle per IP: B tidak kehabisan jatah karena A', baru['throttle_B_3_sesudahnya'] == 3, baru['throttle_B_3_sesudahnya'])
    cek('IP throttle tidak bisa pindah ke QUIC (UDP 443)', baru['throttle_quic'] == 0)
    cek('alamat privat palsu dari eth0 tidak lagi melewati default-drop', baru['privat_palsu_eth0_8888'] == 0, baru['privat_palsu_eth0_8888'])
    cek('IP publik ke port tertutup tetap ditolak (default-drop jalan)', baru['publik_8888'] == 0)
    panic_uji()
finally:
    bersih()
    shutil.rmtree(T, ignore_errors=True)
print('\nRINGKAS: %d gagal' % gagal)
sys.exit(1 if gagal else 0)
