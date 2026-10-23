#!/usr/bin/env python3
# ==================================================================
# sentinel-ports.py -- Pengelola Port Firewall (Inbound & Outbound)
#
# Menyediakan kontrol akses port masuk (Inbound) dan keluar (Outbound)
# dengan konfigurasi default preinstall:
#   - Outbound: Allow All (Trafik keluar diizinkan penuh)
#   - Inbound : Allow HTTP (80), HTTPS (443), SSH (terdeteksi),
#               dan aaPanel (terdeteksi). Port lainnya ditolak.
# ==================================================================
import sys
import os
import json
import re
import subprocess
import ipaddress

CONF_DIR = '/www/server/sentinel/etc'
CONF_FILE = os.path.join(CONF_DIR, 'ports.json')
PANEL_PORT_FILE = '/www/server/panel/data/port.pl'
SSH_CONFIG_FILES = [
    '/etc/ssh/sshd_config',
    '/etc/ssh/sshd_config.d/00-aapanel.conf',
    '/etc/ssh/sshd_config.d/50-cloud-init.conf'
]

# ---- validasi aturan sebelum menyentuh shell/iptables --------------------
# ports.json bisa berubah di luar API (edit manual, versi lama), dan nilainya
# disisipkan ke perintah shell. Aturan yang tidak lolos DILEWATI dan dilaporkan,
# bukan dikirim ke iptables.
_PROTO_OK = ('tcp', 'udp', 'tcp/udp', 'tcp+udp', 'all', 'any')

def _src_valid(v):
    """Daftar IPv4/CIDR dipisah koma, semuanya ketat dan IPv4 saja."""
    if not isinstance(v, str) or not v.strip() or len(v) > 400:
        return False
    for b in v.split(','):
        b = b.strip()
        if not re.fullmatch(r'(?:(?:0|[1-9][0-9]{0,2})\.){3}(?:0|[1-9][0-9]{0,2})(?:/(?:0|[1-9][0-9]?))?', b):
            return False
        try:
            ipaddress.IPv4Network(b if '/' in b else b + '/32', strict=True)
        except ValueError:
            return False
    return True

def rule_problem(r, kolom):
    """None bila aturan aman dipasang, selain itu alasan penolakan."""
    if not isinstance(r, dict):
        return 'bukan objek aturan'
    proto = str(r.get('protocol', 'tcp')).lower()
    if proto not in _PROTO_OK:
        return 'protokol tidak valid: %r' % proto[:20]
    action = str(r.get('action', 'ACCEPT')).upper()
    if action not in ('ACCEPT', 'DROP'):
        return 'aksi tidak valid: %r' % action[:20]
    port = str(r.get('port', '')).strip().lower()
    if port not in ('', 'all', 'any'):
        m = re.fullmatch(r'([1-9][0-9]{0,4})(?:[-:]([1-9][0-9]{0,4}))?', port)
        if not m or int(m.group(1)) > 65535 or (m.group(2) and (int(m.group(2)) > 65535 or int(m.group(2)) <= int(m.group(1)))):
            return 'port tidak valid: %r' % port[:20]
    if not _src_valid(str(r.get(kolom, '0.0.0.0/0')).strip() or '0.0.0.0/0'):
        return 'alamat %s tidak valid: %r' % (kolom, str(r.get(kolom))[:40])
    return None

def clean_rid(r):
    return re.sub(r'[^A-Za-z0-9_-]', '', str(r.get('id', 'rule')))[:20] or 'rule'


def get_iptables_bin():
    for b in ['/usr/sbin/iptables', '/sbin/iptables', 'iptables']:
        if os.path.isfile(b) and os.access(b, os.X_OK):
            return b
    return 'iptables'

# ---- mode rencana (pemasangan atomik) ----
# Saat _PLAN berupa list, perintah "-A SENTINEL_IN_PORTS/SENTINEL_OUT_PORTS ..." tidak
# dijalankan tetapi dikumpulkan, lalu _plan_commit menerapkannya dalam SATU transaksi
# iptables-restore. Dulu setiap 5 menit chain di-flush lalu diisi ~25 perintah: selama
# itu default-drop belum ada dan penghitung paket selalu kembali ke nol.
_PLAN = None
_PLAN_RE = re.compile(r'^\S+ -w \d+ (-A SENTINEL_(?:IN|OUT)_PORTS .*?)(?: 2>/dev/null)?(?: \|\| true)?$')
_PLAN_STATE = '/www/server/sentinel/run/.ports-plan.sha'


def _plan_line(cmd):
    import shlex
    m = _PLAN_RE.match(cmd.strip())
    if not m:
        return None
    try:
        toks = shlex.split(m.group(1))
    except ValueError:
        return None
    # Set ipset yang tidak ada membuat SELURUH transaksi restore ditolak. Di cara lama
    # aturan seperti itu gagal sendiri dan dilewati ("|| true"); di sini dibuang dari rencana.
    if '--match-set' in toks:
        nama = toks[toks.index('--match-set') + 1] if toks.index('--match-set') + 1 < len(toks) else ''
        if nama not in _ipset_ada():
            return ''
    return ' '.join('"%s"' % t if re.search(r'[\s"\']', t) else t for t in toks)


_IPSET_CACHE = None


def _ipset_ada():
    global _IPSET_CACHE
    if _IPSET_CACHE is None:
        try:
            o = subprocess.run(['ipset', 'list', '-n'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10).stdout
            _IPSET_CACHE = set(o.split())
        except Exception:
            _IPSET_CACHE = set()
    return _IPSET_CACHE


def _plan_commit(ipt_bin, rencana, chains):
    """Terapkan rencana. Return 'sama' (tidak diubah, penghitung tetap), 'ok', atau None (gagal)."""
    import hashlib
    teks = '\n'.join(rencana) + '\n'
    sha = hashlib.sha256(teks.encode()).hexdigest()
    try:
        lama = open(_PLAN_STATE).read().strip()
    except Exception:
        lama = ''
    if lama == sha:
        jumlah = 0
        for c in chains:
            rc, o, _ = run_cmd(f"{ipt_bin} -w 10 -S {c} 2>/dev/null")
            if rc != 0:
                jumlah = -1
                break
            jumlah += sum(1 for l in o.splitlines() if l.startswith('-A '))
        if jumlah == len(rencana):
            return 'sama'
    restore = ipt_bin + '-restore'
    if not os.path.exists(restore):
        restore = 'iptables-restore'
    isi = '*filter\n' + ''.join(':%s - [0:0]\n' % c for c in chains) + teks + 'COMMIT\n'
    try:
        p = subprocess.run([restore, '-w', '10', '--noflush'], input=isi, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    try:
        with open(_PLAN_STATE + '.tmp', 'w') as f:
            f.write(sha)
        os.replace(_PLAN_STATE + '.tmp', _PLAN_STATE)
    except Exception:
        pass
    return 'ok'


def run_cmd(cmd):
    if _PLAN is not None:
        baris = _plan_line(cmd)
        if baris is not None:
            if baris:
                _PLAN.append(baris)
            return 0, '', ''
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 1, '', str(e)

def detect_panel_port():
    try:
        if os.path.isfile(PANEL_PORT_FILE):
            with open(PANEL_PORT_FILE, 'r') as fp:
                val = fp.read().strip()
                p = re.sub(r'[^0-9]', '', val)
                if p and 1 <= int(p) <= 65535:
                    return int(p)
    except Exception:
        pass
    return 8888

def detect_ssh_port():
    for f in SSH_CONFIG_FILES:
        if os.path.isfile(f):
            try:
                with open(f, 'r') as fp:
                    for line in fp:
                        line = line.strip()
                        if line.startswith('#'): continue
                        m = re.match(r'^Port\s+([0-9]+)', line, re.I)
                        if m and 1 <= int(m.group(1)) <= 65535:
                            return int(m.group(1))
            except Exception:
                pass
    return 22

def get_default_config():
    ssh_p = detect_ssh_port()
    panel_p = detect_panel_port()
    return {
        'active': True,
        'inbound_policy': 'DROP',
        'outbound_policy': 'ACCEPT',
        'detected_ssh_port': ssh_p,
        'detected_panel_port': panel_p,
        'inbound': [
            {
                'id': 'in-http',
                'port': '80',
                'protocol': 'tcp',
                'action': 'ACCEPT',
                'source': '0.0.0.0/0',
                'remark': 'Web Server HTTP',
                'system': True,
                'enabled': True
            },
            {
                'id': 'in-https',
                'port': '443',
                'protocol': 'tcp/udp',
                'action': 'ACCEPT',
                'source': '0.0.0.0/0',
                'remark': 'Web Server HTTPS (SSL & HTTP/3 QUIC)',
                'system': True,
                'enabled': True
            },
            {
                'id': 'in-ssh',
                'port': str(ssh_p),
                'protocol': 'tcp',
                'action': 'ACCEPT',
                'source': '0.0.0.0/0',
                'remark': f'Remote SSH Terminal (Port {ssh_p})',
                'system': True,
                'enabled': True
            },
            {
                'id': 'in-panel',
                'port': str(panel_p),
                'protocol': 'tcp',
                'action': 'ACCEPT',
                'source': '0.0.0.0/0',
                'remark': f'aaPanel Web Management (Port {panel_p})',
                'system': True,
                'enabled': True
            }
        ],
        'outbound': [
            {
                'id': 'out-all',
                'port': '1-65535',
                'protocol': 'all',
                'action': 'ACCEPT',
                'dest': '0.0.0.0/0',
                'remark': 'Allow All Outbound Traffic',
                'system': True,
                'enabled': True
            }
        ]
    }

def load_config():
    if not os.path.exists(CONF_DIR):
        os.makedirs(CONF_DIR, exist_ok=True)
    if not os.path.isfile(CONF_FILE):
        cfg = get_default_config()
        save_config(cfg)
        return cfg
    try:
        with open(CONF_FILE, 'r') as fp:
            data = json.load(fp)
            if not isinstance(data, dict):
                data = get_default_config()
                save_config(data)
            return data
    except Exception:
        cfg = get_default_config()
        save_config(cfg)
        return cfg

def save_config(cfg):
    if not os.path.exists(CONF_DIR):
        os.makedirs(CONF_DIR, exist_ok=True)
    tmp_file = CONF_FILE + '.tmp'
    with open(tmp_file, 'w') as fp:
        json.dump(cfg, fp, indent=2)
    os.replace(tmp_file, CONF_FILE)
    os.chmod(CONF_FILE, 0o644)

def sshd_ports():
    """Port SSH yang BENAR-BENAR dipakai sekarang: baris Port di sshd_config dan
    soket sshd yang listen. Dibaca ulang setiap apply; dulu hanya terdeteksi sekali saat
    ports.json pertama dibuat, sehingga mengganti port SSH berujung terkunci."""
    ports = set()
    for f in SSH_CONFIG_FILES:
        try:
            with open(f, 'r') as fp:
                for line in fp:
                    m = re.match(r'^\s*Port\s+([0-9]+)', line, re.I)
                    if m and 1 <= int(m.group(1)) <= 65535:
                        ports.add(int(m.group(1)))
        except Exception:
            pass
    rc, o, _ = run_cmd("ss -Hltnp 2>/dev/null | grep -w sshd")
    if rc == 0:
        for ln in o.splitlines():
            m = re.search(r':([0-9]+)\s', ln)
            if m and 1 <= int(m.group(1)) <= 65535:
                ports.add(int(m.group(1)))
    if not ports:
        ports.add(detect_ssh_port())
    return sorted(ports)


def apply_kernel(cfg=None):
    """Atomik bila bisa: rencana dikumpulkan lalu diterapkan sekaligus, atau tidak
    diubah sama sekali bila identik dengan yang terpasang. Bila iptables-restore menolak,
    jatuh ke cara lama (per aturan) yang punya pengaman fail-open per aturan."""
    global _PLAN
    _PLAN = []
    try:
        hasil = _apply_kernel(cfg, rencana=True)
    finally:
        rencana, _PLAN = _PLAN, None
    if hasil is None:
        _hapus_state()
        return _apply_kernel(cfg, rencana=False)
    return hasil


def _hapus_state():
    try:
        os.remove(_PLAN_STATE)
    except Exception:
        pass


def _apply_kernel(cfg=None, rencana=False):
    # Satu apply pada satu waktu: apply bersamaan (timer + UI) menghapus dan memasang
    # ulang chain secara berselang-seling dan bisa meninggalkan urutan aturan yang salah.
    import fcntl
    _lk = None
    try:
        os.makedirs('/www/server/sentinel/run', exist_ok=True)
        _lk = open('/www/server/sentinel/run/.ports-apply.lock', 'w')
        fcntl.flock(_lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True, 'apply lain sedang berjalan, dilewati'
    except Exception:
        _lk = None
    if cfg is None:
        cfg = load_config()
    ipt = get_iptables_bin() + ' -w 10'   # tunggu kunci xtables (iptables lain bisa sedang jalan)
    in_chain = 'SENTINEL_IN_PORTS'
    out_chain = 'SENTINEL_OUT_PORTS'
    dilewati = []   # aturan tidak valid, tidak dikirim ke iptables
    gagal = []      # aturan valid tetapi ditolak iptables

    def pasang(cmd, rid):
        rc, _, e = run_cmd(cmd)
        if rc != 0:
            gagal.append('%s (%s)' % (rid, (e or 'iptables gagal')[:60]))

    # Buat chain jika belum ada (mode rencana: dikosongkan di dalam transaksi restore)
    run_cmd(f"{ipt} -N {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -N {out_chain} 2>/dev/null || true")
    if not rencana:
        run_cmd(f"{ipt} -F {in_chain}")
        run_cmd(f"{ipt} -F {out_chain}")

    if not cfg.get('active', True):
        # Jika nonaktif, chain hanya me-return
        run_cmd(f"{ipt} -A {in_chain} -j RETURN")
        run_cmd(f"{ipt} -A {out_chain} -j RETURN")
        if rencana and _plan_commit(get_iptables_bin(), list(_PLAN), [in_chain, out_chain]) is None:
            return None
        return True, "Port firewall dinonaktifkan di kernel (mode pasif/return)"

    # --- ATURAN INBOUND (SENTINEL_IN_PORTS) ---
    # 1. Loopback bebas
    run_cmd(f"{ipt} -A {in_chain} -i lo -j ACCEPT")
    # 2. Established & Related koneksi tidak boleh terganggu
    run_cmd(f"{ipt} -A {in_chain} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    # 3. Whitelist set & allowlist
    run_cmd(f"{ipt} -A {in_chain} -m set --match-set sentinel_white src -j ACCEPT 2>/dev/null || true")
    run_cmd(f"{ipt} -A {in_chain} -m set --match-set aapanel.ipv4.whitelist src -j ACCEPT 2>/dev/null || true")
    # 4. Jaringan lokal privat, KECUALI bila datang dari antarmuka internet (rute
    #    bawaan): alamat privat di eth0 pasti dipalsukan dan dulu melewati
    #    default-drop untuk semua port (mis. UDP buta dari 10.x palsu).
    rc_w, o_w, _ = run_cmd("ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i==\"dev\"){print $(i+1); exit}}'")
    wan = o_w.strip() if rc_w == 0 and re.fullmatch(r'[A-Za-z0-9_.@-]{1,15}', (o_w or '').strip()) else ''
    for net in ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']:
        if wan:
            run_cmd(f"{ipt} -A {in_chain} ! -i {wan} -s {net} -j ACCEPT 2>/dev/null || true")
        else:
            run_cmd(f"{ipt} -A {in_chain} -s {net} -j ACCEPT 2>/dev/null || true")

    # 4b. Antarmuka VPN aktif (WireGuard, OpenVPN, Tailscale, ZeroTier)
    rc_v, o_v, _ = run_cmd("ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(wg|tun|tap|tailscale|zt|ppp)' | cut -d'@' -f1 | sort -u")
    if rc_v == 0 and o_v:
        for vpn_iface in o_v.splitlines():
            vpn_iface = vpn_iface.strip()
            if vpn_iface:
                run_cmd(f"{ipt} -A {in_chain} -i {vpn_iface} -j ACCEPT 2>/dev/null || true")

    # 5. Pasang aturan port inbound
    for r in cfg.get('inbound', []):
        if not r.get('enabled', True):
            continue
        masalah = rule_problem(r, 'source')
        if masalah:
            dilewati.append('%s: %s' % (clean_rid(r), masalah))
            continue
        proto = r.get('protocol', 'tcp').lower()
        port = str(r.get('port', '')).strip().replace('-', ':')
        action = r.get('action', 'ACCEPT').upper()
        src = r.get('source', '0.0.0.0/0').strip() or '0.0.0.0/0'
        rid = clean_rid(r)
        cmt = f"sentinel:in:{rid}"

        is_all_ports = (port in ['all', 'any', '1:65535', '0:65535', ''])
        if proto in ['all', 'any']:
            pasang(f"{ipt} -A {in_chain} -s {src} -m comment --comment '{cmt}' -j {action}", rid)
        elif proto in ['tcp/udp', 'tcp+udp']:
            if is_all_ports:
                pasang(f"{ipt} -A {in_chain} -p tcp -s {src} -m comment --comment '{cmt}' -j {action}", rid)
                pasang(f"{ipt} -A {in_chain} -p udp -s {src} -m comment --comment '{cmt}' -j {action}", rid)
            else:
                pasang(f"{ipt} -A {in_chain} -p tcp --dport {port} -s {src} -m comment --comment '{cmt}' -j {action}", rid)
                pasang(f"{ipt} -A {in_chain} -p udp --dport {port} -s {src} -m comment --comment '{cmt}' -j {action}", rid)
        else:
            if is_all_ports:
                pasang(f"{ipt} -A {in_chain} -p {proto} -s {src} -m comment --comment '{cmt}' -j {action}", rid)
            else:
                pasang(f"{ipt} -A {in_chain} -p {proto} --dport {port} -s {src} -m comment --comment '{cmt}' -j {action}", rid)

    # 5b. SSH dan panel yang SEDANG dipakai selalu boleh (tidak bergantung pada ports.json),
    #     supaya mengganti port SSH/panel tidak mengunci operator di balik DROP default.
    for lbl, plist in (('ssh', sshd_ports()), ('panel', [detect_panel_port()])):
        for pn in plist:
            pasang(f"{ipt} -A {in_chain} -p tcp --dport {int(pn)} -m comment --comment 'sentinel:in:auto-{lbl}' -j ACCEPT", 'auto-' + lbl)

    # 5c. Port UDP yang dipakai WireGuard di server ini (listen-port tiap antarmuka wg*):
    #     handshake dari peer yang memulai koneksi adalah paket NEW dan akan jatuh ke DROP
    #     default bila port ini tidak diizinkan (terowongan putus begitu conntrack kedaluwarsa).
    rc_w, o_w, _ = run_cmd("wg show interfaces 2>/dev/null")
    if rc_w == 0 and o_w.strip():
        for wif in o_w.split():
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', wif):
                continue
            rc_p, o_p, _ = run_cmd(f"wg show {wif} listen-port 2>/dev/null")
            if rc_p == 0 and o_p.strip().isdigit() and 1 <= int(o_p.strip()) <= 65535:
                pasang(f"{ipt} -A {in_chain} -p udp --dport {int(o_p.strip())} -m comment --comment 'sentinel:in:auto-wg-{wif}' -j ACCEPT", 'auto-wg-' + wif)

    # 6. ICMP Ping diizinkan
    run_cmd(f"{ipt} -A {in_chain} -p icmp -j ACCEPT")

    # 7. Kebijakan default inbound
    # DROP default HANYA dipasang bila SEMUA aturan izin (SSH, panel, WireGuard, dan aturan
    # pengguna) benar-benar terpasang. Satu aturan izin yang gagal (kunci xtables, nilai
    # tak sah) lalu disusul DROP default memutus layanan itu, termasuk SSH: dalam keadaan
    # itu chain dibiarkan fail-open (RETURN) dan kegagalan dilaporkan.
    if cfg.get('inbound_policy', 'DROP').upper() == 'DROP' and not gagal:
        run_cmd(f"{ipt} -A {in_chain} -m conntrack --ctstate NEW -m comment --comment 'sentinel:in-default-drop' -j DROP")
    else:
        run_cmd(f"{ipt} -A {in_chain} -j RETURN")
        if gagal:
            gagal.append('DROP default TIDAK dipasang (fail-open) karena ada aturan izin yang gagal')

    # --- ATURAN OUTBOUND (SENTINEL_OUT_PORTS) ---
    run_cmd(f"{ipt} -A {out_chain} -o lo -j ACCEPT")
    run_cmd(f"{ipt} -A {out_chain} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")

    # Bypass antarmuka VPN aktif pada trafik keluar
    if rc_v == 0 and o_v:
        for vpn_iface in o_v.splitlines():
            vpn_iface = vpn_iface.strip()
            if vpn_iface:
                run_cmd(f"{ipt} -A {out_chain} -o {vpn_iface} -j ACCEPT 2>/dev/null || true")

    out_allow_all = False
    for r in cfg.get('outbound', []):
        if not r.get('enabled', True):
            continue
        port = str(r.get('port', '')).strip()
        proto = r.get('protocol', '').lower()
        act = r.get('action', '').upper()
        if (port in ['1-65535', 'all', '1:65535'] or proto == 'all') and act == 'ACCEPT':
            out_allow_all = True
            break

    if out_allow_all or cfg.get('outbound_policy', 'ACCEPT').upper() == 'ACCEPT':
        run_cmd(f"{ipt} -A {out_chain} -m comment --comment 'sentinel:out-allow-all' -j ACCEPT")
    else:
        for r in cfg.get('outbound', []):
            if not r.get('enabled', True):
                continue
            masalah = rule_problem(r, 'dest')
            if masalah:
                dilewati.append('%s: %s' % (clean_rid(r), masalah))
                continue
            proto = r.get('protocol', 'tcp').lower()
            port = str(r.get('port', '')).strip().replace('-', ':')
            action = r.get('action', 'ACCEPT').upper()
            dst = r.get('dest', '0.0.0.0/0').strip() or '0.0.0.0/0'
            rid = clean_rid(r)
            cmt = f"sentinel:out:{rid}"
            is_all_ports = (port in ['all', 'any', '1:65535', '0:65535', ''])
            if proto in ['all', 'any']:
                pasang(f"{ipt} -A {out_chain} -d {dst} -m comment --comment '{cmt}' -j {action}", rid)
            elif proto in ['tcp/udp', 'tcp+udp']:
                if is_all_ports:
                    pasang(f"{ipt} -A {out_chain} -p tcp -d {dst} -m comment --comment '{cmt}' -j {action}", rid)
                    pasang(f"{ipt} -A {out_chain} -p udp -d {dst} -m comment --comment '{cmt}' -j {action}", rid)
                else:
                    pasang(f"{ipt} -A {out_chain} -p tcp --dport {port} -d {dst} -m comment --comment '{cmt}' -j {action}", rid)
                    pasang(f"{ipt} -A {out_chain} -p udp --dport {port} -d {dst} -m comment --comment '{cmt}' -j {action}", rid)
            else:
                if is_all_ports:
                    pasang(f"{ipt} -A {out_chain} -p {proto} -d {dst} -m comment --comment '{cmt}' -j {action}", rid)
                else:
                    pasang(f"{ipt} -A {out_chain} -p {proto} --dport {port} -d {dst} -m comment --comment '{cmt}' -j {action}", rid)

        if cfg.get('outbound_policy', 'ACCEPT').upper() == 'DROP':
            run_cmd(f"{ipt} -A {out_chain} -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable")

    if rencana:
        # Mode rencana: aturan belum terpasang; "gagal" tidak bisa diketahui per aturan.
        # Pasang sekaligus; bila restore menolak, pemanggil mengulang dengan cara lama.
        status = _plan_commit(get_iptables_bin(), list(_PLAN), [in_chain, out_chain])
        if status is None:
            return None

    # --- HOOKING KE CHAIN UTAMA ---
    # Hook SENTINEL_IN_PORTS ke dalam SENTINEL (tepat sebelum baris RETURN terakhir).
    # Bila dua aturan terakhir SENTINEL sudah "-j SENTINEL_IN_PORTS" lalu "-j RETURN"
    # (dipasang sentinel-fw.sh), tidak diubah: menghapus lalu menambah lagi membuka celah
    # singkat tanpa default-drop.
    rc, s_chain, _ = run_cmd(f"{ipt} -S SENTINEL 2>/dev/null")
    akhir = [l.strip() for l in s_chain.splitlines() if l.strip().startswith('-A SENTINEL ')][-2:] if rc == 0 else []
    if rc == 0 and akhir == [f"-A SENTINEL -j {in_chain}", "-A SENTINEL -j RETURN"]:
        pass
    elif rc == 0:
        # Bersihkan hook in_chain lama dari SENTINEL bila sudah ada
        while True:
            rc_d, _, _ = run_cmd(f"{ipt} -D SENTINEL -j {in_chain} 2>/dev/null")
            if rc_d != 0:
                break

        # Bersihkan trailing -j RETURN di akhir chain SENTINEL
        while True:
            _, s_curr, _ = run_cmd(f"{ipt} -S SENTINEL 2>/dev/null")
            lines = [l.strip() for l in s_curr.splitlines() if l.strip().startswith("-A SENTINEL")]
            if lines and lines[-1] == "-A SENTINEL -j RETURN":
                run_cmd(f"{ipt} -D SENTINEL -j RETURN 2>/dev/null")
            else:
                break

        # Pasang hook in_chain tepat di akhir aturan inspeksi L1
        run_cmd(f"{ipt} -A SENTINEL -j {in_chain}")
        # Pasang kembali baris penutup fallback RETURN
        run_cmd(f"{ipt} -A SENTINEL -j RETURN")
    else:
        # Cadangan jika SENTINEL belum terpasang: hook langsung ke INPUT
        rc_in, s_in, _ = run_cmd(f"{ipt} -S INPUT 2>/dev/null")
        if f"-j {in_chain}" not in s_in:
            run_cmd(f"{ipt} -I INPUT 1 -j {in_chain}")

    # Hook SENTINEL_OUT_PORTS ke OUTPUT
    rc_out, s_out, _ = run_cmd(f"{ipt} -S OUTPUT 2>/dev/null")
    if f"-j {out_chain}" not in s_out:
        run_cmd(f"{ipt} -I OUTPUT 1 -j {out_chain}")

    if dilewati or gagal:
        pesan = "Sebagian aturan TIDAK diterapkan."
        if dilewati:
            pesan += " Tidak valid, dilewati: " + "; ".join(dilewati)
        if gagal:
            pesan += " Ditolak iptables: " + "; ".join(gagal)
        return False, pesan
    return True, "Aturan port firewall Inbound & Outbound berhasil diterapkan ke kernel"

def remove_kernel():
    ipt = get_iptables_bin() + ' -w 10'   # tunggu kunci xtables (iptables lain bisa sedang jalan)
    in_chain = 'SENTINEL_IN_PORTS'
    out_chain = 'SENTINEL_OUT_PORTS'

    # Unhook dari SENTINEL, INPUT, OUTPUT
    run_cmd(f"{ipt} -D SENTINEL -j {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -D INPUT -j {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -D OUTPUT -j {out_chain} 2>/dev/null || true")

    run_cmd(f"{ipt} -F {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -X {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -F {out_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -X {out_chain} 2>/dev/null || true")
    return True, "Chain port firewall berhasil dicabut dari kernel"

def get_status():
    ipt = get_iptables_bin() + ' -w 10'   # tunggu kunci xtables (iptables lain bisa sedang jalan)
    cfg = load_config()
    in_chain = 'SENTINEL_IN_PORTS'
    out_chain = 'SENTINEL_OUT_PORTS'

    rc_in, out_in, _ = run_cmd(f"{ipt} -S {in_chain} 2>/dev/null")
    rc_out, out_out, _ = run_cmd(f"{ipt} -S {out_chain} 2>/dev/null")

    is_active = (rc_in == 0 and bool(out_in) and cfg.get('active', True))
    return {
        'config': cfg,
        'kernel_in_active': rc_in == 0,
        'kernel_out_active': rc_out == 0,
        'in_rules_count': len(cfg.get('inbound', [])),
        'out_rules_count': len(cfg.get('outbound', [])),
        'is_active': is_active
    }

def main():
    action = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if action == 'status':
        st = get_status()
        print(json.dumps(st, indent=2))
    elif action == 'apply':
        ok, msg = apply_kernel()
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
        sys.exit(0 if ok else 3)
    elif action == 'reset':
        cfg = get_default_config()
        save_config(cfg)
        ok, msg = apply_kernel(cfg)
        print(f"[{'OK' if ok else 'FAIL'}] Reset selesai: {msg}")
    elif action == 'remove':
        ok, msg = remove_kernel()
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
    elif action == 'init':
        cfg = load_config()
        print(f"[OK] ports.json siap ({len(cfg.get('inbound', []))} inbound, {len(cfg.get('outbound', []))} outbound)")
    else:
        print(f"Penggunaan: {sys.argv[0]} [status|apply|reset|remove|init]")

if __name__ == '__main__':
    main()
