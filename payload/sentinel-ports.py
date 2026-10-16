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

CONF_DIR = '/www/server/sentinel/etc'
CONF_FILE = os.path.join(CONF_DIR, 'ports.json')
PANEL_PORT_FILE = '/www/server/panel/data/port.pl'
SSH_CONFIG_FILES = [
    '/etc/ssh/sshd_config',
    '/etc/ssh/sshd_config.d/00-aapanel.conf',
    '/etc/ssh/sshd_config.d/50-cloud-init.conf'
]

def get_iptables_bin():
    for b in ['/usr/sbin/iptables', '/sbin/iptables', 'iptables']:
        if os.path.isfile(b) and os.access(b, os.X_OK):
            return b
    return 'iptables'

def run_cmd(cmd):
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

def apply_kernel(cfg=None):
    if cfg is None:
        cfg = load_config()
    ipt = get_iptables_bin()
    in_chain = 'SENTINEL_IN_PORTS'
    out_chain = 'SENTINEL_OUT_PORTS'

    # Buat chain jika belum ada
    run_cmd(f"{ipt} -N {in_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -F {in_chain}")
    run_cmd(f"{ipt} -N {out_chain} 2>/dev/null || true")
    run_cmd(f"{ipt} -F {out_chain}")

    if not cfg.get('active', True):
        # Jika nonaktif, chain hanya me-return
        run_cmd(f"{ipt} -A {in_chain} -j RETURN")
        run_cmd(f"{ipt} -A {out_chain} -j RETURN")
        return True, "Port firewall dinonaktifkan di kernel (mode pasif/return)"

    # --- ATURAN INBOUND (SENTINEL_IN_PORTS) ---
    # 1. Loopback bebas
    run_cmd(f"{ipt} -A {in_chain} -i lo -j ACCEPT")
    # 2. Established & Related koneksi tidak boleh terganggu
    run_cmd(f"{ipt} -A {in_chain} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    # 3. Whitelist set & allowlist
    run_cmd(f"{ipt} -A {in_chain} -m set --match-set sentinel_white src -j ACCEPT 2>/dev/null || true")
    run_cmd(f"{ipt} -A {in_chain} -m set --match-set aapanel.ipv4.whitelist src -j ACCEPT 2>/dev/null || true")
    # 4. Jaringan lokal privat
    for net in ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']:
        run_cmd(f"{ipt} -A {in_chain} -s {net} -j ACCEPT 2>/dev/null || true")

    # 5. Pasang aturan port inbound
    for r in cfg.get('inbound', []):
        if not r.get('enabled', True):
            continue
        proto = r.get('protocol', 'tcp').lower()
        port = str(r.get('port', '')).strip().replace('-', ':')
        action = r.get('action', 'ACCEPT').upper()
        src = r.get('source', '0.0.0.0/0').strip() or '0.0.0.0/0'
        rid = str(r.get('id', 'rule'))[:20]
        cmt = f"sentinel:in:{rid}"

        if proto in ['all', 'any']:
            run_cmd(f"{ipt} -A {in_chain} -s {src} -m comment --comment '{cmt}' -j {action}")
        elif proto in ['tcp/udp', 'tcp+udp']:
            run_cmd(f"{ipt} -A {in_chain} -p tcp --dport {port} -s {src} -m comment --comment '{cmt}' -j {action}")
            run_cmd(f"{ipt} -A {in_chain} -p udp --dport {port} -s {src} -m comment --comment '{cmt}' -j {action}")
        else:
            run_cmd(f"{ipt} -A {in_chain} -p {proto} --dport {port} -s {src} -m comment --comment '{cmt}' -j {action}")

    # 6. ICMP Ping diizinkan
    run_cmd(f"{ipt} -A {in_chain} -p icmp -j ACCEPT")

    # 7. Kebijakan default inbound
    if cfg.get('inbound_policy', 'DROP').upper() == 'DROP':
        run_cmd(f"{ipt} -A {in_chain} -m conntrack --ctstate NEW -m comment --comment 'sentinel:in-default-drop' -j DROP")
    else:
        run_cmd(f"{ipt} -A {in_chain} -j RETURN")

    # --- ATURAN OUTBOUND (SENTINEL_OUT_PORTS) ---
    run_cmd(f"{ipt} -A {out_chain} -o lo -j ACCEPT")
    run_cmd(f"{ipt} -A {out_chain} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")

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
            proto = r.get('protocol', 'tcp').lower()
            port = str(r.get('port', '')).strip().replace('-', ':')
            action = r.get('action', 'ACCEPT').upper()
            dst = r.get('dest', '0.0.0.0/0').strip() or '0.0.0.0/0'
            rid = str(r.get('id', 'rule'))[:20]
            cmt = f"sentinel:out:{rid}"
            if proto in ['all', 'any']:
                run_cmd(f"{ipt} -A {out_chain} -d {dst} -m comment --comment '{cmt}' -j {action}")
            elif proto in ['tcp/udp', 'tcp+udp']:
                run_cmd(f"{ipt} -A {out_chain} -p tcp --dport {port} -d {dst} -m comment --comment '{cmt}' -j {action}")
                run_cmd(f"{ipt} -A {out_chain} -p udp --dport {port} -d {dst} -m comment --comment '{cmt}' -j {action}")
            else:
                run_cmd(f"{ipt} -A {out_chain} -p {proto} --dport {port} -d {dst} -m comment --comment '{cmt}' -j {action}")

        if cfg.get('outbound_policy', 'ACCEPT').upper() == 'DROP':
            run_cmd(f"{ipt} -A {out_chain} -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable")

    # --- HOOKING KE CHAIN UTAMA ---
    # Hook SENTINEL_IN_PORTS ke dalam SENTINEL (tepat sebelum baris RETURN terakhir)
    rc, s_chain, _ = run_cmd(f"{ipt} -S SENTINEL 2>/dev/null")
    if rc == 0:
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

    return True, "Aturan port firewall Inbound & Outbound berhasil diterapkan ke kernel"

def remove_kernel():
    ipt = get_iptables_bin()
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
    ipt = get_iptables_bin()
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
