#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
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
import time

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

# Panel hosting yang dikenali. Port panel HARUS ikut diizinkan oleh baseline firewall: tanpa itu DROP default memutus
# akses admin ke panel (dan seluruh layanan panel) setelah plugin terpasang di DirectAdmin, CyberPanel, atau WHM/cPanel.
# (kunci, nama tampilan, penanda berkas, port bawaan)
HOSTING_PANELS = [
    ('aapanel', 'aaPanel', ['/www/server/panel/class/public.py', '/www/server/panel/data/port.pl'], []),
    ('directadmin', 'DirectAdmin', ['/usr/local/directadmin/directadmin'], [2222]),
    ('cyberpanel', 'CyberPanel', ['/usr/local/CyberCP'], [8090, 7080]),
    ('cpanel', 'WHM/cPanel', ['/usr/local/cpanel/cpanel', '/usr/local/cpanel/version'], [2082, 2083, 2086, 2087, 2095, 2096]),
    # UI standalone ZySentinel (hanya bila diaktifkan: penanda dibuat/dihapus installer dan `guardctl ui enable|disable`);
    # port-nya diperlakukan sebagai port admin: tidak ikut tertutup aturan umum dan tidak mengunci akses pemilik.
    ('zysentinel-ui', 'ZySentinel UI', ['/etc/zysentinel-ui/enabled'], [18491]),
]
DIRECTADMIN_CONF = '/usr/local/directadmin/conf/directadmin.conf'

def detect_aapanel_port():
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

def detect_panels():
    """Daftar panel hosting yang terpasang: [{'key', 'name', 'ports': [int]}]. Kosong = server standalone."""
    hasil = []
    for key, nama, penanda, ports in HOSTING_PANELS:
        if not any(os.path.exists(x) for x in penanda):
            continue
        ps = list(ports)
        if key == 'aapanel':
            ps = [detect_aapanel_port()]
        elif key == 'directadmin':
            try:
                with open(DIRECTADMIN_CONF, 'r') as fp:
                    for ln in fp:
                        m = re.match(r'^\s*port\s*=\s*([0-9]+)\s*$', ln)
                        if m and 1 <= int(m.group(1)) <= 65535:
                            ps = [int(m.group(1))]
                            break
            except Exception:
                pass
        hasil.append({'key': key, 'name': nama, 'ports': ps})
    return hasil

def detect_panel_ports():
    """Semua port panel yang terdeteksi (terurut, unik)."""
    return sorted({int(p) for x in detect_panels() for p in x['ports']})

def detect_panel_port():
    """Port panel utama (kompatibel mundur): aaPanel bila ada, selain itu panel terdeteksi pertama, bawaan 8888."""
    ps = detect_panels()
    for x in ps:
        if x['key'] == 'aapanel':
            return int(x['ports'][0])
    if ps and ps[0]['ports']:
        return int(ps[0]['ports'][0])
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

# Layanan hosting umum yang sedang melayani publik saat ports.json pertama dibuat DIADOPSI sebagai aturan biasa (bukan baseline),
# supaya memasang plugin tidak memutus FTP, email, atau DNS yang sudah berjalan. Port lain (basis data, cache, remote desktop, dst.)
# TIDAK diadopsi: default-drop menutupnya. Admin meninjau dan membatasinya dari analisis port.
HOSTING_SERVICE_PORTS = {
    21: ('tcp', 'FTP'), 25: ('tcp', 'SMTP'), 465: ('tcp', 'SMTPS'), 587: ('tcp', 'SMTP submission'),
    110: ('tcp', 'POP3'), 995: ('tcp', 'POP3S'), 143: ('tcp', 'IMAP'), 993: ('tcp', 'IMAPS'), 53: ('tcp/udp', 'DNS'),
    888: ('tcp', 'phpMyAdmin (aaPanel)'),
}
PUREFTPD_CONF = ('/www/server/pure-ftpd/etc/pure-ftpd.conf', '/etc/pure-ftpd/pure-ftpd.conf', '/etc/pure-ftpd.conf')


def ftp_pasif():
    """Rentang port data FTP pasif (PassivePortRange pure-ftpd aaPanel, bawaan 39000-40000) sebagai 'a-b', atau None. Tanpa
    rentang ini FTP pasif putus di balik default-drop: helper conntrack FTP tidak aktif otomatis sejak kernel 4.7."""
    for f in PUREFTPD_CONF:
        try:
            with open(f) as fp:
                for ln in fp:
                    m = re.match(r'^\s*PassivePortRange\s+(\d{1,5})\s+(\d{1,5})\s*$', ln)
                    if m and 1024 <= int(m.group(1)) <= int(m.group(2)) <= 65535:
                        return '%s-%s' % (m.group(1), m.group(2))
        except OSError:
            continue
    return None


def aturan_ftp_pasif(inbound):
    """Aturan ACCEPT rentang FTP pasif bila FTP (21) diizinkan dan rentangnya belum tercakup; None bila tidak perlu."""
    rentang = ftp_pasif()
    if not rentang:
        return None
    ftp = any(str(r.get('port')) == '21' and r.get('action') == 'ACCEPT' and r.get('enabled', True) for r in inbound)
    if not ftp or any(str(r.get('port')) == rentang for r in inbound):
        return None
    return {'id': 'in-adopt-ftp-pasif', 'port': rentang, 'protocol': 'tcp', 'action': 'ACCEPT', 'source': '0.0.0.0/0',
            'remark': 'FTP pasif (PassivePortRange pure-ftpd), menyertai FTP port 21', 'system': False, 'enabled': True}

def adopt_hosting_services(sudah):
    """Aturan ACCEPT untuk layanan hosting yang sedang listen publik dan belum tercakup oleh `sudah` (himpunan port)."""
    aturan = []
    for it in _listeners():
        if it['scope'] != 'public' or it['port'] in sudah or it['port'] not in HOSTING_SERVICE_PORTS:
            continue
        proto, nama = HOSTING_SERVICE_PORTS[it['port']]
        rid = 'in-adopt-%d' % it['port']
        if any(r['id'] == rid for r in aturan):
            continue
        aturan.append({'id': rid, 'port': str(it['port']), 'protocol': proto, 'action': 'ACCEPT', 'source': '0.0.0.0/0',
                       'remark': 'Layanan %s terdeteksi aktif saat pemasangan (tinjau dan batasi bila tidak dipakai)' % nama,
                       'system': False, 'enabled': True})
    return aturan

def get_default_config():
    ssh_p = detect_ssh_port()
    panel_p = detect_panel_port()
    panels = detect_panels()
    panel_nama = next((x['name'] for x in panels if panel_p in x['ports']), 'Panel')
    cfg = {
        'active': True,
        'inbound_policy': 'DROP',
        'outbound_policy': 'ACCEPT',
        'detected_ssh_port': ssh_p,
        'detected_panel_port': panel_p,
        'detected_panels': panels,
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
                'remark': f'{panel_nama} Web Management (Port {panel_p})',
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
    # port panel lain (DirectAdmin, CyberPanel, WHM/cPanel) dan port tambahan aaPanel: baseline sistem agar tidak terkunci
    ada = {int(r['port']) for r in cfg['inbound'] if str(r['port']).isdigit()}
    for pn in panels:
        for pt in pn['ports']:
            if int(pt) in ada:
                continue
            ada.add(int(pt))
            cfg['inbound'].append({'id': 'in-panel-%s-%d' % (pn['key'], pt), 'port': str(pt), 'protocol': 'tcp', 'action': 'ACCEPT',
                                   'source': '0.0.0.0/0', 'remark': '%s Web Management (Port %d)' % (pn['name'], pt), 'system': True, 'enabled': True})
    cfg['inbound'].extend(adopt_hosting_services(ada | set(sshd_ports())))
    pasif = aturan_ftp_pasif(cfg['inbound'])
    if pasif:
        cfg['inbound'].append(pasif)
    cfg['migrasi'] = ['ftp_pasif']
    return cfg


def migrasi_config(data):
    """Perbaikan sekali jalan untuk ports.json lama (ditandai di 'migrasi'): rentang FTP pasif ditambahkan bila FTP 21 sudah
    diizinkan (instalasi lama memutus FTP pasif). Hanya MEMBUKA yang menyertai layanan yang sudah diizinkan admin."""
    sudah = data.get('migrasi') if isinstance(data.get('migrasi'), list) else []
    if 'ftp_pasif' in sudah:
        return data
    pasif = aturan_ftp_pasif(data.get('inbound') or [])
    if pasif:
        data.setdefault('inbound', []).append(pasif)
    data['migrasi'] = sudah + ['ftp_pasif']
    try:
        save_config(data)
    except OSError:
        pass
    return data

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
        if isinstance(data, dict):
            return migrasi_config(data)
    except Exception:
        pass
    # ports.json ada tetapi rusak (disk penuh, tulis terputus): dulu langsung ditimpa bawaan sehingga semua aturan dan pembatasan
    # port admin hilang permanen dan bawaan diterapkan ke kernel. Sekarang: pulihkan dari ports.json.bak (ditulis panel setiap
    # simpan); bila cadangan juga rusak, berkas rusak disimpan di samping dan pemanggil menolak (aturan kernel lama tetap berlaku).
    try:
        with open(CONF_FILE + '.bak', 'r') as fp:
            data = json.load(fp)
        if isinstance(data, dict):
            save_config(data)
            print("[WARN] ports.json rusak: dipulihkan dari ports.json.bak", file=sys.stderr)
            return data
    except Exception:
        pass
    # berkas rusak DIBIARKAN di tempatnya (salinan forensik di samping): kalau dipindahkan, panggilan berikutnya melihat "tidak ada
    # berkas" lalu membuat bawaan, sama dengan perilaku lama. Pulih lewat Reset Default (aksi reset) atau perbaikan manual.
    rusak = '%s.corrupt.%d' % (CONF_FILE, int(time.time()))
    try:
        if not any(n.startswith(os.path.basename(CONF_FILE) + '.corrupt.') for n in os.listdir(CONF_DIR)):
            with open(CONF_FILE, 'rb') as a, open(rusak, 'wb') as b:
                b.write(a.read(16 << 20))
    except OSError:
        pass
    raise KonfigRusak('ports.json rusak dan tidak ada cadangan sah; aturan kernel tidak diubah (pulihkan dengan Reset Default)')


class KonfigRusak(Exception):
    pass

def save_config(cfg):
    if not os.path.exists(CONF_DIR):
        os.makedirs(CONF_DIR, exist_ok=True)
    tmp_file = '%s.%d.tmp' % (CONF_FILE, os.getpid())
    with open(tmp_file, 'w') as fp:
        json.dump(cfg, fp, indent=2)
        fp.flush()
        os.fsync(fp.fileno())
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
    # Hanya pendengar milik root (uid:0): proses lain bernama "sshd" (comm bisa dipalsukan siapa pun) tidak boleh
    # membuka port sembarang di balik DROP default lewat aturan auto-ssh.
    rc, o, _ = run_cmd("ss -Hltnpe 2>/dev/null | grep -w sshd | grep -w 'uid:0'")
    if rc == 0:
        for ln in o.splitlines():
            m = re.search(r':([0-9]+)\s', ln)
            if m and 1 <= int(m.group(1)) <= 65535:
                ports.add(int(m.group(1)))
    if not ports:
        ports.add(detect_ssh_port())
    return sorted(ports)


def menutup_admin(r, admin_ports):
    """True bila aturan DROP ini menutup SSH/panel untuk SEMUA alamat (sumber 0.0.0.0/0 dengan port yang mencakup port admin, atau
    tanpa port). Aturan pengguna dipasang sebelum auto-ssh/auto-panel, jadi aturan seperti itu mengunci admin dari koneksi baru.
    DROP untuk sumber tertentu tetap sah (memblokir penyerang di port admin)."""
    if str(r.get('action', 'ACCEPT')).upper() != 'DROP' or not _src_terbuka(str(r.get('source') or '')):
        return False
    po = str(r.get('port', '')).strip().lower()
    if po in ('', 'all', 'any'):
        return True
    m = re.fullmatch(r'([0-9]+)(?:[-:]([0-9]+))?', po)
    if not m:
        return False
    a = int(m.group(1)); b = int(m.group(2) or a)
    return any(a <= int(p) <= b for p in admin_ports)

def admin_restrict_map(cfg):
    """{port(str): [CIDR, ...]} untuk port SSH/panel yang dibatasi ke IP admin. Entri tak valid dibuang (fail-open: lebih baik
    port admin terbuka daripada admin terkunci akibat berkas rusak)."""
    mentah = cfg.get('admin_restrict') if isinstance(cfg, dict) else None
    hasil = {}
    if isinstance(mentah, dict):
        for k, v in mentah.items():
            if str(k).isdigit() and isinstance(v, list) and v and all(isinstance(x, str) and _src_valid(x) for x in v):
                hasil[str(int(k))] = [x.strip() for x in v]
    return hasil

def apply_kernel(cfg=None):
    """Atomik bila bisa: rencana dikumpulkan lalu diterapkan sekaligus, atau tidak
    diubah sama sekali bila identik dengan yang terpasang. Bila iptables-restore menolak,
    jatuh ke cara lama (per aturan) yang punya pengaman fail-open per aturan.
    Sesudah IPv4, aturan masuk yang sama diterapkan ke IPv6 (_apply_v6)."""
    global _PLAN
    _PLAN = []
    try:
        hasil = _apply_kernel(cfg, rencana=True)
    finally:
        rencana, _PLAN = _PLAN, None
    if hasil is None:
        _hapus_state()
        hasil = _apply_kernel(cfg, rencana=False)
    try:
        v6 = _apply_v6(cfg if cfg is not None else load_config())
    except Exception as e:
        v6 = 'IPv6: gagal diterapkan (%s)' % str(e)[:80]
    if v6 and isinstance(hasil, tuple):
        return hasil[0], hasil[1] + ' ' + v6
    return hasil


def _ipv6_global():
    rc, o, _ = run_cmd("ip -6 addr show scope global 2>/dev/null | grep -c inet6")
    return rc == 0 and (o or '0').strip() not in ('', '0')


V6_CHAIN = 'SENTINEL6_IN'


def _hapus_v6(ip6):
    """Cabut rantai masuk IPv6 (bila ada). Tidak menyentuh aturan IPv6 lain."""
    for c in (V6_CHAIN, V6_CHAIN + '_NEW'):
        while run_cmd(f"{ip6} -w 10 -D INPUT -j {c} 2>/dev/null")[0] == 0:
            pass
        run_cmd(f"{ip6} -w 10 -F {c} 2>/dev/null")
        run_cmd(f"{ip6} -w 10 -X {c} 2>/dev/null")


def _apply_v6(cfg):
    """Paritas IPv6 untuk port firewall masuk. Dulu hanya IPv4 yang disaring: di server dual-stack SSH, panel, basis data, dst.
    yang listen di [::] terbuka lewat IPv6 walau ditutup di IPv4.

    Hanya dipasang bila ip6tables ada, port firewall aktif, dan server punya alamat IPv6 global; selain itu rantai dicabut.
    Isi: loopback, ESTABLISHED, ICMPv6 (wajib untuk neighbour discovery), link-local, antarmuka VPN, aturan pengguna yang
    sumbernya "semua alamat" (aturan bersumber IPv4 tertentu tidak berlaku di IPv6), SSH/panel/WireGuard otomatis, lalu
    DROP default. Port admin yang dibatasi ke IP IPv4 (admin_restrict) TIDAK dibuka di IPv6. Rantai baru diisi lebih dulu
    lalu ditukar (tidak ada jeda tanpa aturan); satu aturan izin gagal = fail-open (RETURN), sama dengan IPv4."""
    ip6 = get_ip6tables_bin()
    if not ip6:
        return ''
    if not cfg.get('active', True) or not _ipv6_global():
        _hapus_v6(ip6)
        return ''
    baru = V6_CHAIN + '_NEW'
    run_cmd(f"{ip6} -w 10 -D INPUT -j {baru} 2>/dev/null")
    run_cmd(f"{ip6} -w 10 -F {baru} 2>/dev/null")
    run_cmd(f"{ip6} -w 10 -X {baru} 2>/dev/null")
    if run_cmd(f"{ip6} -w 10 -N {baru}")[0] != 0:
        return 'IPv6: rantai tidak bisa dibuat, IPv6 tidak disaring.'
    gagal = []

    def pasang(args, rid):
        rc, _, e = run_cmd(f"{ip6} -w 10 -A {baru} {args}")
        if rc != 0:
            gagal.append('%s (%s)' % (rid, (e or 'ip6tables gagal')[:60]))

    pasang("-i lo -j ACCEPT", 'lo')
    pasang("-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", 'established')
    pasang("-p ipv6-icmp -j ACCEPT", 'icmpv6')
    pasang("-s fe80::/10 -j ACCEPT", 'link-local')
    rc_v, o_v, _ = run_cmd("ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(wg|tun|tap|tailscale|zt|ppp)' | cut -d'@' -f1 | sort -u")
    for vif in (o_v.splitlines() if rc_v == 0 else []):
        vif = vif.strip()
        if re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', vif):
            pasang(f"-i {vif} -j ACCEPT", 'vpn')
    restrict = admin_restrict_map(cfg)
    admin_ports = set(sshd_ports()) | set(detect_panel_ports() or [detect_panel_port()])
    for r in cfg.get('inbound', []):
        if not r.get('enabled', True) or rule_problem(r, 'source') or menutup_admin(r, admin_ports):
            continue
        if not _src_terbuka(str(r.get('source') or '')):
            continue      # sumber IPv4 tertentu: tidak punya padanan di IPv6
        if (r.get('system') and str(r.get('action', 'ACCEPT')).upper() == 'ACCEPT' and str(r.get('port', '')).strip() in restrict):
            continue
        proto = str(r.get('protocol', 'tcp')).lower()
        port = str(r.get('port', '')).strip().replace('-', ':')
        act = str(r.get('action', 'ACCEPT')).upper()
        cmt = f"sentinel:in6:{clean_rid(r)}"
        semua_port = port in ('all', 'any', '1:65535', '0:65535', '')
        protos = ['tcp', 'udp'] if proto in ('tcp/udp', 'tcp+udp') else ([''] if proto in ('all', 'any') else [proto])
        for pr in protos:
            if pr == '':
                pasang(f"-m comment --comment '{cmt}' -j {act}", clean_rid(r))
            elif semua_port:
                pasang(f"-p {pr} -m comment --comment '{cmt}' -j {act}", clean_rid(r))
            else:
                pasang(f"-p {pr} --dport {port} -m comment --comment '{cmt}' -j {act}", clean_rid(r))
    for lbl, plist in (('ssh', sshd_ports()), ('panel', detect_panel_ports() or [detect_panel_port()])):
        for pn in plist:
            if str(int(pn)) in restrict:
                continue      # dibatasi ke IP admin IPv4: tertutup di IPv6
            pasang(f"-p tcp --dport {int(pn)} -m comment --comment 'sentinel:in6:auto-{lbl}' -j ACCEPT", 'auto-' + lbl)
    for wp in sorted(_wg_ports()):
        pasang(f"-p udp --dport {int(wp)} -m comment --comment 'sentinel:in6:auto-wg' -j ACCEPT", 'auto-wg')
    if str(cfg.get('inbound_policy', 'DROP')).upper() == 'DROP' and not gagal:
        pasang("-m conntrack --ctstate NEW -m comment --comment 'sentinel:in6-default-drop' -j DROP", 'default-drop')
    else:
        pasang("-j RETURN", 'return')
    # tukar: rantai baru dipasang di depan, rantai lama dicabut, lalu nama baru menggantikan nama lama
    if run_cmd(f"{ip6} -w 10 -I INPUT 1 -j {baru}")[0] != 0:
        run_cmd(f"{ip6} -w 10 -F {baru} 2>/dev/null")
        run_cmd(f"{ip6} -w 10 -X {baru} 2>/dev/null")
        return 'IPv6: rantai tidak bisa dipasang, IPv6 tidak disaring.'
    while run_cmd(f"{ip6} -w 10 -D INPUT -j {V6_CHAIN} 2>/dev/null")[0] == 0:
        pass
    run_cmd(f"{ip6} -w 10 -F {V6_CHAIN} 2>/dev/null")
    run_cmd(f"{ip6} -w 10 -X {V6_CHAIN} 2>/dev/null")
    run_cmd(f"{ip6} -w 10 -E {baru} {V6_CHAIN}")
    if gagal:
        return 'IPv6: sebagian aturan ditolak (' + '; '.join(gagal) + '); DROP default IPv6 tidak dipasang (fail-open).'
    return ''


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
    restrict = admin_restrict_map(cfg)
    admin_ports = set(sshd_ports()) | set(detect_panel_ports() or [detect_panel_port()])
    for r in cfg.get('inbound', []):
        if not r.get('enabled', True):
            continue
        if menutup_admin(r, admin_ports):
            dilewati.append('%s: aturan DROP untuk semua alamat pada port SSH/panel tidak dipasang (mengunci admin)' % clean_rid(r))
            continue
        if (r.get('system') and str(r.get('action', 'ACCEPT')).upper() == 'ACCEPT' and str(r.get('port', '')).strip() in restrict
                and (r.get('source') or '0.0.0.0/0').strip() in ('0.0.0.0/0', '0.0.0.0')):
            continue      # port admin dibatasi ke IP tertentu: baseline "semua IP" tidak dipasang (lihat 5b)
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

    # 5b. SSH dan SEMUA panel terdeteksi (aaPanel, DirectAdmin, CyberPanel, WHM/cPanel) yang SEDANG dipakai selalu boleh (tidak
    #     bergantung pada ports.json), supaya mengganti port SSH/panel tidak mengunci operator di balik DROP default. Bila port itu
    #     dibatasi ke IP admin (cfg['admin_restrict']), hanya IP tersebut yang diizinkan.
    for lbl, plist in (('ssh', sshd_ports()), ('panel', detect_panel_ports() or [detect_panel_port()])):
        for pn in plist:
            batas = restrict.get(str(int(pn)))
            if batas:
                for sr in batas:
                    pasang(f"{ipt} -A {in_chain} -p tcp --dport {int(pn)} -s {sr} -m comment --comment 'sentinel:in:auto-{lbl}' -j ACCEPT", 'auto-' + lbl)
            else:
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
    # Aturan proxy/CDN sentinel-fw.sh melompat (goto) ke in_chain; ganti di tempat jadi RETURN
    # supaya chain bisa dihapus dan IP proxy tetap dikecualikan dari ban/throttle.
    rc_s, s_chain, _ = run_cmd(f"{ipt} -S SENTINEL 2>/dev/null")
    if rc_s == 0:
        aturan = [l.strip() for l in s_chain.splitlines() if l.strip().startswith('-A SENTINEL ')]
        for i, l in enumerate(aturan, 1):
            if l.endswith(f'-g {in_chain}'):
                spek = l[len('-A SENTINEL '):-len(f'-g {in_chain}')]
                run_cmd(f"{ipt} -R SENTINEL {i} {spek}-j RETURN 2>/dev/null || true")
    run_cmd(f"{ipt} -D INPUT -j {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -D OUTPUT -j {out_chain} 2>/dev/null || true")

    run_cmd(f"{ipt} -F {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -X {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -F {out_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -X {out_chain} 2>/dev/null || true")
    ip6 = get_ip6tables_bin()
    if ip6:
        _hapus_v6(ip6)
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

# ---- katalog layanan: port -> (nama, kategori). Kategori menentukan risiko bila terbuka ke internet.
SERVICE_CATALOG = {
    80: ('HTTP', 'web'), 443: ('HTTPS', 'web'), 8080: ('HTTP alt', 'web'), 8443: ('HTTPS alt', 'web'), 888: ('phpMyAdmin (aaPanel)', 'tool'),
    21: ('FTP', 'ftp'), 22: ('SSH', 'ssh'),
    25: ('SMTP', 'mail'), 465: ('SMTPS', 'mail'), 587: ('SMTP submission', 'mail'), 110: ('POP3', 'mail'), 995: ('POP3S', 'mail'),
    143: ('IMAP', 'mail'), 993: ('IMAPS', 'mail'),
    53: ('DNS', 'dns'), 123: ('NTP', 'ntp'), 161: ('SNMP', 'exposed'), 1900: ('SSDP/UPnP', 'exposed'), 5353: ('mDNS', 'exposed'),
    3306: ('MySQL/MariaDB', 'database'), 5432: ('PostgreSQL', 'database'), 27017: ('MongoDB', 'database'), 1433: ('SQL Server', 'database'),
    9042: ('Cassandra', 'database'), 6379: ('Redis', 'cache'), 11211: ('Memcached', 'cache'),
    9200: ('Elasticsearch', 'database'), 9300: ('Elasticsearch cluster', 'database'), 5672: ('RabbitMQ', 'database'), 15672: ('RabbitMQ admin', 'tool'),
    2375: ('Docker API (tanpa TLS)', 'remote'), 2376: ('Docker API (TLS)', 'remote'),
    23: ('Telnet', 'remote'), 3389: ('RDP', 'remote'), 5900: ('VNC', 'remote'), 5901: ('VNC', 'remote'), 5902: ('VNC', 'remote'),
    2222: ('DirectAdmin', 'panel'), 8090: ('CyberPanel', 'panel'), 7080: ('OpenLiteSpeed WebAdmin', 'panel'), 10000: ('Webmin', 'panel'),
    8880: ('Plesk', 'panel'),
    2082: ('cPanel', 'panel'), 2083: ('cPanel (SSL)', 'panel'), 2086: ('WHM', 'panel'), 2087: ('WHM (SSL)', 'panel'),
    2095: ('Webmail cPanel', 'panel'), 2096: ('Webmail cPanel (SSL)', 'panel'),
    9090: ('Prometheus', 'monitoring'), 9100: ('Node Exporter', 'monitoring'), 3000: ('Grafana/aplikasi', 'tool'), 45876: ('Beszel agent', 'monitoring'),
    1514: ('Wazuh/OSSEC agent', 'monitoring'), 1515: ('Wazuh enrollment', 'monitoring'), 55000: ('Wazuh API', 'monitoring'),
    21115: ('RustDesk', 'remote'), 21116: ('RustDesk', 'remote'), 21117: ('RustDesk relay', 'remote'), 21118: ('RustDesk web', 'remote'), 21119: ('RustDesk web', 'remote'),
}
# Kategori yang berisiko TINGGI bila terbuka untuk seluruh internet (tanpa pembatasan IP)
_KATEGORI_TINGGI = ('database', 'cache', 'remote', 'exposed')
_KATEGORI_SEDANG = ('panel', 'ssh', 'ftp', 'monitoring', 'tool')

def _scope(host):
    """public | private | loopback | linklocal untuk alamat bind sebuah listener."""
    h = (host or '').strip().strip('[]').split('%')[0]
    if h in ('', '*', '0.0.0.0', '::'):
        return 'public'
    try:
        a = ipaddress.ip_address(h)
    except ValueError:
        return 'public'
    if a.is_loopback:
        return 'loopback'
    if a.is_link_local:
        return 'linklocal'
    if a.is_private or (a.version == 4 and a in ipaddress.ip_network('100.64.0.0/10')):
        return 'private'
    return 'public'

def _listeners():
    """Listener TCP (LISTEN) dan UDP aktif, digabung per (protokol, port): satu baris per port dengan semua alamat bind-nya."""
    mentah = []
    rc, out, _ = run_cmd("ss -H -lntup 2>/dev/null")
    if rc == 0 and out.strip():
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            if proto not in ('tcp', 'udp'):
                continue
            loc = parts[4]
            if ':' not in loc:
                continue
            host, _, port_s = loc.rpartition(':')
            if not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
                continue
            m = re.search(r'users:\(\("([^"]+)",pid=([0-9]+)', " ".join(parts[5:]))
            mentah.append((proto, int(port_s), host.strip('[]'), m.group(1) if m else '', int(m.group(2)) if m else 0))
    elif os.path.isfile('/proc/net/tcp'):
        def _proc(fpath, proto):
            try:
                with open(fpath, 'r') as fp:
                    for line in fp.readlines()[1:]:
                        f = line.strip().split()
                        if len(f) < 10 or (proto == 'tcp' and f[3] != '0A'):
                            continue
                        ip_h, port_h = f[1].split(':')
                        n = int(ip_h, 16)
                        ip_addr = ".".join(str((n >> (8 * i)) & 0xFF) for i in range(4))
                        mentah.append((proto, int(port_h, 16), ip_addr, '', 0))
            except Exception:
                pass
        _proc('/proc/net/tcp', 'tcp')
        _proc('/proc/net/udp', 'udp')
    gabung = {}
    for proto, port, host, proc, pid in mentah:
        it = gabung.setdefault((proto, port), {'protocol': proto, 'port': port, 'binds': [], 'process': '', 'pid': 0, 'scopes': set()})
        sc = _scope(host)
        it['scopes'].add(sc)
        if host not in it['binds']:
            it['binds'].append(host)
        if proc and not it['process']:
            it['process'], it['pid'] = proc, pid
    hasil = []
    prioritas = ('public', 'private', 'linklocal', 'loopback')
    for it in gabung.values():
        it['scope'] = next(x for x in prioritas if x in it['scopes'])
        it['bind_address'] = next((b for b in it['binds'] if _scope(b) == it['scope']), it['binds'][0])
        del it['scopes']
        hasil.append(it)
    return hasil

def _wg_ports():
    """Port UDP listen WireGuard di server ini (diizinkan otomatis oleh _apply_kernel 5c)."""
    hasil = set()
    rc, o, _ = run_cmd("wg show interfaces 2>/dev/null")
    if rc == 0 and o.strip():
        for wif in o.split():
            if re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', wif):
                rc2, o2, _ = run_cmd(f"wg show {wif} listen-port 2>/dev/null")
                if rc2 == 0 and o2.strip().isdigit() and 1 <= int(o2.strip()) <= 65535:
                    hasil.add(int(o2.strip()))
    return hasil

def _docker_published():
    """Himpunan (protokol, port) yang dipublikasikan Docker (DNAT di rantai nat DOCKER). Lalu lintasnya lewat FORWARD,
    jadi aturan INPUT/port firewall TIDAK berlaku untuknya."""
    ipt = get_iptables_bin()
    rc, out, _ = run_cmd(f"{ipt} -w 10 -t nat -S DOCKER 2>/dev/null")
    hasil = set()
    if rc == 0:
        for ln in out.splitlines():
            m = re.search(r'-p (tcp|udp) .*--dport ([0-9]+) -j DNAT', ln)
            if m and ' -d 127.' not in ln:
                hasil.add((m.group(1), int(m.group(2))))
    return hasil

def _port_cocok(r, proto, port):
    """Apakah aturan inbound r mencakup (proto, port)?"""
    rp = str(r.get('protocol', 'tcp')).lower()
    if rp not in ('all', 'any') and rp not in ('tcp/udp', 'tcp+udp') and rp != proto:
        return False
    po = str(r.get('port', '')).strip().lower()
    if po in ('', 'all', 'any'):
        return True
    m = re.fullmatch(r'([0-9]+)(?:[-:]([0-9]+))?', po)
    if not m:
        return False
    a = int(m.group(1)); b = int(m.group(2) or a)
    return a <= port <= b

def _src_terbuka(src):
    return (src or '0.0.0.0/0').strip() in ('', '0.0.0.0/0', '0.0.0.0')

def _status_fw(cfg, aktif, proto, port, auto_ports):
    """Keadaan efektif satu port di port firewall: (status, sumber, id_aturan, aturan_sistem).
    status: open_all | restricted | closed | unmanaged. Evaluasi first-match menurut urutan aturan."""
    if not aktif:
        return 'unmanaged', [], '', False
    restrict = cfg.get('admin_restrict') if isinstance(cfg.get('admin_restrict'), dict) else {}
    izin, rid, sistem = [], '', False
    if port in auto_ports:
        pembatas = restrict.get(str(port))
        if isinstance(pembatas, list) and pembatas and all(_src_valid(x) for x in pembatas):
            izin.extend(pembatas)
        elif proto == 'tcp':
            return 'open_all', [], 'auto', True
    for r in cfg.get('inbound', []):
        if not r.get('enabled', True) or not _port_cocok(r, proto, port):
            continue
        act = str(r.get('action', 'ACCEPT')).upper()
        src = str(r.get('source', '0.0.0.0/0'))
        if act == 'ACCEPT':
            if _src_terbuka(src):
                if str(port) in restrict and r.get('system'):
                    continue      # aturan baseline dilewati karena port dibatasi (lihat _apply_kernel)
                return 'open_all', [], r.get('id', ''), bool(r.get('system'))
            izin.extend([x.strip() for x in src.split(',') if x.strip()])
            rid, sistem = r.get('id', ''), bool(r.get('system'))
        elif act == 'DROP' and _src_terbuka(src):
            return ('restricted' if izin else 'closed'), izin, r.get('id', ''), bool(r.get('system'))
    if izin:
        return 'restricted', izin, rid, sistem
    return ('closed' if str(cfg.get('inbound_policy', 'DROP')).upper() == 'DROP' else 'unmanaged'), [], '', False

def _kategori(port, proc, panel_ports, ssh_ports):
    if port in ssh_ports:
        return 'SSH', 'ssh'
    if port in panel_ports:
        for pn in detect_panels():
            if port in pn['ports']:
                return pn['name'], 'panel'
    if port in SERVICE_CATALOG:
        return SERVICE_CATALOG[port]
    if proc in ('mysqld', 'mariadbd'):
        return 'MySQL/MariaDB', 'database'
    if proc in ('redis-server',):
        return 'Redis', 'cache'
    if proc in ('nginx', 'httpd', 'apache2', 'lshttpd', 'caddy'):
        return proc, 'web'
    return (proc or ''), 'other'

def _format_bytes(b):
    """Format angka byte menjadi representasi manusia (B, KB, MB, GB, TB)."""
    try:
        b = float(b)
    except Exception:
        return '0 B'
    if b <= 0:
        return '0 B'
    for u in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024.0:
            return f"{b:.1f} {u}" if u != 'B' else f"{int(b)} B"
        b /= 1024.0
    return f"{b:.1f} PB"

def _is_traffic_anomaly(port, proto, kat, scope, fw_state, bytes_in, bytes_out):
    """Mengevaluasi apakah trafik realtime/terkini pada port ini berada di atas batas wajar (anomali)."""
    if bytes_in <= 0 and bytes_out <= 0:
        return False, ''

    if scope == 'public':
        if kat in ('database', 'cache', 'remote', 'exposed') and bytes_in > 512 * 1024:
            return True, 'Exposed sensitive service with high traffic'
        if kat in ('panel', 'ssh') and bytes_in > 20 * 1024 * 1024 and fw_state != 'restricted':
            return True, 'High traffic on unrestricted admin port'
        if kat == 'web' and bytes_in > 500 * 1024 * 1024:
            return True, 'Traffic spike on web service'
        if kat not in ('web', 'panel', 'ssh', 'vpn') and bytes_in > 10 * 1024 * 1024:
            return True, 'Unusual traffic volume on exposed port'
        if fw_state in ('open_all', 'unmanaged') and bytes_in > 50 * 1024 * 1024:
            return True, 'High incoming traffic on open public port'
        if fw_state in ('closed', 'restricted') and bytes_in > 1024 * 1024:
            return True, 'Suspicious traffic probe on blocked/restricted port'
    else:
        if bytes_in > 2 * 1024 * 1024 * 1024:
            return True, 'Unusually high loopback traffic'

    return False, ''

def _port_traffic():
    """Mengumpulkan statistik trafik byte masuk (inbound) dan keluar (outbound) per port.
    Sumber data:
    1. Socket TCP aktif (ss -tin): membaca bytes_received (In) dan bytes_sent (Out) per koneksi.
    2. Counter iptables (SENTINEL_IN_PORTS / SENTINEL_OUT_PORTS): mencatat kumulatif bytes yang melewati rantai firewall.
    Hasil: dict (proto, port) -> {'bytes_in': int, 'bytes_out': int}
    """
    traffic = {}

    # 1. ss -tin (TCP socket byte counters)
    rc, out, _ = run_cmd("ss -tin 2>/dev/null")
    if rc == 0 and out.strip():
        cur_port = None
        for line in out.strip().splitlines():
            if not line:
                continue
            if line[0] not in (' ', '\t'):
                parts = line.split()
                if len(parts) >= 4:
                    loc = parts[3]
                    if ':' in loc:
                        _, _, p_s = loc.rpartition(':')
                        if p_s.isdigit() and 1 <= int(p_s) <= 65535:
                            cur_port = int(p_s)
                        else:
                            cur_port = None
                    else:
                        cur_port = None
                else:
                    cur_port = None
            elif cur_port is not None:
                m_in = re.search(r'bytes_received:([0-9]+)', line)
                m_out = re.search(r'bytes_sent:([0-9]+)', line)
                if m_in or m_out:
                    entry = traffic.setdefault(('tcp', cur_port), {'bytes_in': 0, 'bytes_out': 0})
                    if m_in:
                        entry['bytes_in'] += int(m_in.group(1))
                    if m_out:
                        entry['bytes_out'] += int(m_out.group(1))

    # 2. iptables counter pada SENTINEL_IN_PORTS (inbound bytes)
    ipt = get_iptables_bin()
    if ipt:
        rc, out_in, _ = run_cmd(f"{ipt} -w 10 -nvx -L SENTINEL_IN_PORTS 2>/dev/null")
        if rc == 0 and out_in:
            for ln in out_in.splitlines():
                f = ln.split()
                if len(f) >= 2 and f[0].isdigit() and f[1].isdigit():
                    b_cnt = int(f[1])
                    m_dpt = re.search(r'(tcp|udp) dpt:([0-9]+)', ln)
                    if m_dpt:
                        pr, pt = m_dpt.group(1).lower(), int(m_dpt.group(2))
                        ent = traffic.setdefault((pr, pt), {'bytes_in': 0, 'bytes_out': 0})
                        ent['bytes_in'] = max(ent['bytes_in'], b_cnt)

        # Counter pada SENTINEL_OUT_PORTS (outbound bytes)
        rc, out_out, _ = run_cmd(f"{ipt} -w 10 -nvx -L SENTINEL_OUT_PORTS 2>/dev/null")
        if rc == 0 and out_out:
            for ln in out_out.splitlines():
                f = ln.split()
                if len(f) >= 2 and f[0].isdigit() and f[1].isdigit():
                    b_cnt = int(f[1])
                    m_spt = re.search(r'(tcp|udp) (?:spt|dpt):([0-9]+)', ln)
                    if m_spt:
                        pr, pt = m_spt.group(1).lower(), int(m_spt.group(2))
                        ent = traffic.setdefault((pr, pt), {'bytes_in': 0, 'bytes_out': 0})
                        ent['bytes_out'] = max(ent['bytes_out'], b_cnt)

    return traffic

def get_port_analysis():
    """Analisis keterbukaan port: tiap port yang listen, ditandai cakupan (public/private/loopback), layanan dan kategori
    (termasuk port panel DirectAdmin, CyberPanel, WHM/cPanel, aaPanel), keadaan efektif di port firewall, tingkat risiko,
    kunci rekomendasi, dan daftar aksi terstruktur (block, allow_ip, restrict_admin, restrict_rule). Teks rekomendasi
    dibuat controller menurut bahasa panel."""
    cfg = load_config()
    st = get_status()
    aktif = bool(st.get('is_active'))
    panels = detect_panels()
    panel_ports = set(detect_panel_ports()) or {detect_panel_port()}
    ssh_ports = set(sshd_ports())
    auto_ports = panel_ports | ssh_ports
    docker = _docker_published()
    wg = _wg_ports()
    traf_map = _port_traffic()
    hasil = []
    for it in _listeners():
        proto, port, scope = it['protocol'], it['port'], it['scope']
        layanan, kat = _kategori(port, it['process'], panel_ports, ssh_ports)
        if proto == 'udp' and port in wg:
            layanan, kat = 'WireGuard', 'vpn'
        # Docker hanya relevan untuk port yang benar-benar publik (publish ke 127.0.0.1 aman dari internet)
        dock = scope == 'public' and ((proto, port) in docker or it['process'] == 'docker-proxy')
        if scope == 'public':
            fw, sumber, rid, sis = _status_fw(cfg, aktif, proto, port, auto_ports)
            if proto == 'udp' and port in wg and aktif:
                fw = 'open_all'      # handshake peer WireGuard diizinkan otomatis (auto-wg)
            if dock:
                fw = 'docker_bypass'
        else:
            fw, sumber, rid, sis = 'internal', [], '', False
        terbuka = scope == 'public' and fw in ('open_all', 'unmanaged', 'docker_bypass')
        risiko, rek, aksi = 'LOW', '', []
        if scope == 'public':
            if kat in _KATEGORI_TINGGI:
                dasar = 'HIGH'
            elif kat in _KATEGORI_SEDANG or (kat == 'other' and port > 1023):
                dasar = 'MEDIUM'
            else:
                dasar = 'LOW'
            if port == 123 and proto == 'udp':
                dasar = 'LOW'
            if port == 22 and kat == 'ssh':
                dasar = 'MEDIUM'
            risiko = dasar if terbuka else 'LOW'
            if fw == 'closed':
                rek = 'closed_fw'
                if kat not in ('web',):
                    aksi.append({'type': 'allow_ip', 'port': port, 'protocol': proto})
            elif fw == 'restricted':
                rek = 'restricted_ok'
                if kat in ('panel', 'ssh'):
                    aksi.append({'type': 'restrict_admin', 'port': port, 'protocol': 'tcp', 'edit': True})
                elif rid:
                    aksi.append({'type': 'restrict_rule', 'port': port, 'protocol': proto, 'rule_id': rid})
            elif fw == 'docker_bypass':
                rek = 'docker_bypass'
                risiko = dasar if dasar != 'LOW' else 'MEDIUM'
            elif kat in ('panel', 'ssh'):
                rek = 'ssh_default_port' if (kat == 'ssh' and port == 22) else ('ssh_open' if kat == 'ssh' else 'panel_open')
                aksi.append({'type': 'restrict_admin', 'port': port, 'protocol': 'tcp'})
            elif kat == 'web':
                rek = 'web_ok'
            elif kat == 'vpn':
                rek = 'web_ok'      # terowongan VPN: terbuka memang disengaja
            elif kat in ('mail', 'dns'):
                rek = 'hosting_service'
                if rid and not sis:
                    aksi.append({'type': 'restrict_rule', 'port': port, 'protocol': proto, 'rule_id': rid})
            elif kat == 'ntp':
                rek = 'ntp_public'
            elif kat in _KATEGORI_TINGGI:
                rek = {'database': 'db_public', 'cache': 'db_public', 'remote': 'remote_public', 'exposed': 'exposed_public'}[kat]
            elif kat == 'ftp':
                rek = 'ftp_plain'
            elif kat in ('monitoring', 'tool'):
                rek = 'agent_public'
            else:
                rek = 'other_open'
            if fw in ('open_all', 'unmanaged') and kat not in ('web', 'panel', 'ssh', 'ntp', 'vpn'):
                if rid and not sis:
                    aksi.append({'type': 'block', 'port': port, 'protocol': proto, 'rule_id': rid})
                    aksi.append({'type': 'restrict_rule', 'port': port, 'protocol': proto, 'rule_id': rid})
                else:
                    aksi.append({'type': 'block', 'port': port, 'protocol': proto, 'rule_id': ''})
                    aksi.append({'type': 'allow_ip', 'port': port, 'protocol': proto})
            if fw == 'unmanaged' and aktif is False:
                rek = 'fw_inactive' if kat != 'web' else rek

        tr = traf_map.get((proto, port)) or traf_map.get(('tcp', port)) or traf_map.get(('udp', port)) or {'bytes_in': 0, 'bytes_out': 0}
        b_in = tr.get('bytes_in', 0)
        b_out = tr.get('bytes_out', 0)
        is_anom, anom_reason = _is_traffic_anomaly(port, proto, kat, scope, fw, b_in, b_out)

        if is_anom:
            tipe_ada = {a['type'] for a in aksi}
            if kat in ('panel', 'ssh'):
                if 'restrict_admin' not in tipe_ada:
                    aksi.append({'type': 'restrict_admin', 'port': port, 'protocol': 'tcp'})
                if 'block' not in tipe_ada:
                    aksi.append({'type': 'block', 'port': port, 'protocol': proto, 'rule_id': rid})
            else:
                if 'block' not in tipe_ada:
                    aksi.append({'type': 'block', 'port': port, 'protocol': proto, 'rule_id': rid})
                if 'allow_ip' not in tipe_ada and 'restrict_rule' not in tipe_ada:
                    aksi.append({'type': 'allow_ip', 'port': port, 'protocol': proto})

        hasil.append({
            'protocol': proto, 'port': port, 'bind_address': it['bind_address'], 'binds': it['binds'], 'process': it['process'],
            'pid': it['pid'], 'scope': scope, 'is_public': scope == 'public', 'service': layanan, 'category': kat,
            'docker_published': dock, 'fw_state': fw, 'fw_sources': sumber, 'rule_id': rid, 'system_rule': sis,
            'risk_level': risiko, 'rec_key': rek, 'actions': aksi,
            'bytes_in': b_in, 'bytes_out': b_out,
            'traffic_in': _format_bytes(b_in), 'traffic_out': _format_bytes(b_out),
            'is_traffic_anomaly': is_anom, 'traffic_anomaly_reason': anom_reason,
            'recommendation': ''})
    urut = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    hasil.sort(key=lambda x: (0 if x['is_public'] else 1, urut.get(x['risk_level'], 2), x['port'], x['protocol']))
    v6 = {'global': False, 'ingress_filtered': False}
    rc, o, _ = run_cmd("ip -6 addr show scope global 2>/dev/null | grep -c inet6")
    v6['global'] = (o or '0').strip() not in ('', '0')
    ip6 = get_ip6tables_bin()
    if ip6:
        rc, o, _ = run_cmd(f"{ip6} -S INPUT 2>/dev/null")
        v6['ingress_filtered'] = rc == 0 and ('-j ' + V6_CHAIN in o or '-P INPUT DROP' in o)
    ringkas = {
        'public': sum(1 for x in hasil if x['is_public']),
        'exposed': sum(1 for x in hasil if x['is_public'] and x['fw_state'] in ('open_all', 'unmanaged', 'docker_bypass')),
        'high': sum(1 for x in hasil if x['risk_level'] == 'HIGH'),
        'medium': sum(1 for x in hasil if x['risk_level'] == 'MEDIUM'),
        'docker': sum(1 for x in hasil if x['docker_published']),
        'traffic_anomalies': sum(1 for x in hasil if x.get('is_traffic_anomaly')),
        'firewall_active': aktif, 'policy': str(cfg.get('inbound_policy', 'DROP')).upper(),
    }
    return {'inventory': hasil, 'summary': ringkas, 'panels': panels, 'ipv6': v6}

def get_port_inventory():
    """Kompatibel mundur: hanya daftar port dari analisis."""
    return get_port_analysis()['inventory']

def get_ip6tables_bin():
    for b in ('/usr/sbin/ip6tables', '/sbin/ip6tables', '/usr/bin/ip6tables'):
        if os.path.exists(b):
            return b
    return ''

def main():
    try:
        _main()
    except KonfigRusak as ex:
        print("[FAIL] %s" % ex)
        sys.exit(3)


def _main():
    action = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if action == 'status':
        st = get_status()
        print(json.dumps(st, indent=2))
    elif action == 'inventory':
        print(json.dumps(get_port_analysis(), indent=2))
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
