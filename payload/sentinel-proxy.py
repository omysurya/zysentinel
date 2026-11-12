#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
# ==================================================================
# sentinel-proxy.py -- rentang IP proxy/CDN tepercaya (Cloudflare, Fastly, Sucuri, QUIC.cloud) dan deteksi per vhost.
#
# Di balik proxy, alamat yang dilihat server adalah IP TEPI proxy, bukan pengunjung. Tanpa pengetahuan ini ZySentinel bisa
# mem-ban IP tepi Cloudflare (semua pengunjung lewat tepi itu ikut terblokir), throttle per-IP mencekik tepi yang membawa ribuan
# pengguna, dan daftar IP WAF tidak pernah cocok dengan penyerang sebenarnya. Berkas yang ditulis di sini dibaca:
#   guardd           baris log ber-IP proxy tidak diberi skor/ban/review (etc/proxy-ranges.txt)
#   sentinel-fw.sh   ipset sentinel_proxy: dikecualikan dari ban, throttle, geo-ban, intel
#   sentinel-waf.sh  real IP bawaan web server per vhost (nginx set_real_ip_from, Apache mod_remoteip)
#   panel            deteksi per vhost dan penolakan ban manual ke IP proxy
#
#   sync [--if-stale]   perbarui dari daftar resmi provider (gagal/aneh = daftar lama dipertahankan); --if-stale: hanya bila > 7 hari
#   list                cetak "cidr provider" (bawaan + sinkron + lokal)
#   detect [n]          JSON per vhost: provider yang terlihat di n baris terakhir access log, real IP terpasang atau belum
#   realip              pasang/cabut extension/<situs>/sentinel-realip.conf (nginx, Apache) sesuai deteksi; diuji -t, gagal = rollback
# ==================================================================
import ipaddress
import json
import os
import re
import sys
import time

BASE = os.environ.get('SENTINEL_BASE', '/www/server/sentinel')
ETC = os.path.join(BASE, 'etc')
OUT = os.path.join(ETC, 'proxy-ranges.txt')            # gabungan yang dibaca semua komponen: "cidr provider"
SYNC = os.path.join(ETC, 'proxy-ranges.sync.json')     # hasil sinkron terakhir per provider
LOCAL = os.path.join(ETC, 'proxy-ranges.local.txt')    # tambahan admin: "cidr [nama]" per baris
BASI = 7 * 86400

# Bawaan (dipakai sampai sinkron pertama berhasil, dan bila sinkron gagal). Cloudflare: cloudflare.com/ips (Okt 2026);
# Fastly: api.fastly.com/public-ip-list; Sucuri: dokumentasi firewall Sucuri (rentang statis, tanpa API).
BAWAAN = {
    'cloudflare': ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
                   '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                   '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
                   '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'],
    'fastly': ['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23', '103.245.224.0/24', '104.156.80.0/20',
               '140.248.64.0/18', '140.248.128.0/17', '146.75.0.0/17', '151.101.0.0/16', '157.52.64.0/18', '167.82.0.0/17',
               '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20', '172.111.64.0/18', '185.31.16.0/22', '199.27.72.0/21',
               '199.232.0.0/16', '2a04:4e40::/32', '2a04:4e42::/32'],
    'sucuri': ['192.88.134.0/23', '185.93.228.0/22', '66.248.200.0/22', '208.109.0.0/22', '2a02:fe80::/29'],
}
# Sumber resmi untuk sinkron. Format: 'baris' = satu CIDR per baris; 'fastly' = JSON {addresses, ipv6_addresses}; 'cloudflare_api' = JSON Cloudflare API v4 {result: {ipv4_cidrs, ipv6_cidrs}}.
SUMBER = {
    'cloudflare': [('https://api.cloudflare.com/client/v4/ips', 'cloudflare_api'),
                   ('https://www.cloudflare.com/ips-v4', 'baris'),
                   ('https://www.cloudflare.com/ips-v6', 'baris')],
    'fastly': [('https://api.fastly.com/public-ip-list', 'fastly')],
    'quic.cloud': [('https://quic.cloud/ips?ln', 'baris')],
}
MAKS_PER_PROVIDER = 2000


def cidr_sah(s):
    """IPv4Network/IPv6Network publik dengan prefix wajar (v4 >= /8, v6 >= /16), atau None."""
    try:
        n = ipaddress.ip_network(str(s).strip(), strict=False)
    except ValueError:
        return None
    if (n.version == 4 and n.prefixlen < 8) or (n.version == 6 and n.prefixlen < 16):
        return None
    if n.is_private or n.is_loopback or n.is_multicast or n.is_reserved or n.is_unspecified or n.is_link_local:
        return None
    return n


def _ambil(url, jenis, timeout=15):
    import urllib.request


def _urlopen(req, timeout=10):
    """sentinel_license.urlopen (IPv4 dulu, CA sistem sebagai cadangan) bila modulnya ada di folder ini; selain itu urllib biasa."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from sentinel_license import urlopen as _u
    except Exception:
        _u = urllib.request.urlopen
    return _u(req, timeout=timeout)
    req = urllib.request.Request(url, headers={'User-Agent': 'ZySentinel-proxy-sync'})
    with _urlopen(req, timeout=timeout) as r:
        isi = r.read(1 << 20).decode('utf-8', 'replace')
    if jenis == 'fastly':
        js = json.loads(isi)
        cand = list(js.get('addresses') or []) + list(js.get('ipv6_addresses') or [])
    elif jenis == 'cloudflare_api':
        js = json.loads(isi)
        res = js.get('result') or {}
        cand = list(res.get('ipv4_cidrs') or []) + list(res.get('ipv6_cidrs') or [])
    else:
        cand = re.split(r'[\s,]+', isi)
    return [str(n) for n in (cidr_sah(c) for c in cand if c) if n]


def _baca_json(p):
    try:
        with open(p) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _tulis(p, isi, mode=0o644):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = '%s.%d.tmp' % (p, os.getpid())
    with open(tmp, 'w') as f:
        f.write(isi)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, p)


def gabung():
    """[(network, provider)] dari bawaan, hasil sinkron (menggantikan bawaan provider yang sama), dan daftar lokal admin."""
    sync = _baca_json(SYNC).get('provider') or {}
    per = {k: list(v) for k, v in BAWAAN.items()}
    for prov, d in sync.items():
        if isinstance(d, dict) and isinstance(d.get('cidr'), list) and d['cidr']:
            per[prov] = d['cidr']
    out, lihat = [], set()
    for prov, daftar in per.items():
        for c in daftar[:MAKS_PER_PROVIDER]:
            n = cidr_sah(c)
            if n and n not in lihat:
                lihat.add(n)
                out.append((n, prov))
    try:
        with open(LOCAL) as f:
            for ln in f:
                t = ln.split('#', 1)[0].split()
                if not t:
                    continue
                n = cidr_sah(t[0])
                if n and n not in lihat:
                    lihat.add(n)
                    out.append((n, re.sub(r'[^a-z0-9._-]', '', (t[1] if len(t) > 1 else 'lokal').lower())[:32] or 'lokal'))
    except OSError:
        pass
    return out


def tulis_gabungan():
    baris = ['# Dibuat sentinel-proxy.py: rentang proxy/CDN tepercaya "cidr provider". Jangan edit; tambahan admin di proxy-ranges.local.txt']
    baris += ['%s %s' % (n, p) for n, p in gabung()]
    _tulis(OUT, '\n'.join(baris) + '\n')
    return len(baris) - 1


REMARK_CF = 'cloudflare IPs Proxy'


def ambil_cf_ips():
    """Mengambil rentang IP Cloudflare dari endpoint resmi https://api.cloudflare.com/client/v4/ips,
    fallback ke https://www.cloudflare.com/ips-v4 dan BAWAAN bila gagal."""
    try:
        cand = _ambil('https://api.cloudflare.com/client/v4/ips', 'cloudflare_api', timeout=8)
        if cand and len(cand) >= 15:
            return cand
    except Exception:
        pass
    try:
        cand = _ambil('https://www.cloudflare.com/ips-v4', 'baris', timeout=8)
        cand += _ambil('https://www.cloudflare.com/ips-v6', 'baris', timeout=8)
        if cand:
            return sorted(set(cand))
    except Exception:
        pass
    sync_data = _baca_json(SYNC).get('provider') or {}
    return (sync_data.get('cloudflare') or {}).get('cidr') or BAWAAN.get('cloudflare') or []


def sync_cloudflare_waf_whitelist(cf_cidrs=None):
    """Pastikan seluruh CIDR IPv4 Cloudflare terdaftar di WAF IP Whitelist (ip_white.txt) dengan remark
    'cloudflare IPs Proxy' dan dicabut dari ip_black.txt / blokir agar tidak kena block."""
    if not cf_cidrs:
        cf_list = ambil_cf_ips()
    else:
        cf_list = cf_cidrs
    v4_cidrs = []
    for c in cf_list:
        n = cidr_sah(c)
        if n and n.version == 4:
            v4_cidrs.append(str(n))
    if not v4_cidrs:
        return {'ok': False, 'alasan': 'tidak ada CIDR Cloudflare IPv4'}

    waf_dir = os.path.join(ETC, 'waf-lists')
    os.makedirs(waf_dir, exist_ok=True)
    p_white = os.path.join(waf_dir, 'ip_white.txt')
    p_black = os.path.join(waf_dir, 'ip_black.txt')

    baris_white = []
    if os.path.isfile(p_white):
        try:
            with open(p_white, 'r', encoding='utf-8') as f:
                baris_white = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        except OSError:
            baris_white = []

    white_map = {}
    for b in baris_white:
        val = b.split('#')[0].strip()
        white_map[val] = b

    diubah = False
    for cidr in v4_cidrs:
        target_line = '%s # %s' % (cidr, REMARK_CF)
        if cidr not in white_map:
            baris_white.append(target_line)
            white_map[cidr] = target_line
            diubah = True
        elif REMARK_CF not in white_map[cidr]:
            idx = baris_white.index(white_map[cidr])
            baris_white[idx] = target_line
            white_map[cidr] = target_line
            diubah = True

    if diubah:
        _tulis(p_white, '\n'.join(baris_white) + '\n')

    black_diubah = False
    if os.path.isfile(p_black):
        try:
            with open(p_black, 'r', encoding='utf-8') as f:
                baris_black = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            baru_black = []
            for b in baris_black:
                val = b.split('#')[0].strip()
                val_net = cidr_sah(val)
                kena_cf = False
                if val_net:
                    for cf in v4_cidrs:
                        cf_net = cidr_sah(cf)
                        if cf_net and (val_net == cf_net or val_net.subnet_of(cf_net) or cf_net.subnet_of(val_net)):
                            kena_cf = True
                            break
                if kena_cf:
                    black_diubah = True
                else:
                    baru_black.append(b)
            if black_diubah:
                _tulis(p_black, '\n'.join(baru_black) + ('\n' if baru_black else ''))
        except OSError:
            pass

    if diubah or black_diubah:
        zy = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sentinel-zyrules.py')
        if not os.path.isfile(zy):
            zy = os.path.join(BASE, 'bin', 'sentinel-zyrules.py')
        if os.path.isfile(zy):
            try:
                import subprocess
                subprocess.run([sys.executable, zy, 'build'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    return {'ok': True, 'diubah': diubah or black_diubah, 'jumlah': len(v4_cidrs)}


def sync(hanya_basi=False):
    d = _baca_json(SYNC)
    if hanya_basi and time.time() - float(d.get('ts', 0) or 0) < BASI and os.path.isfile(OUT):
        return {'dilewati': 'belum basi', 'jumlah': tulis_gabungan()}
    prov = d.get('provider') if isinstance(d.get('provider'), dict) else {}
    hasil = {}
    for nama, sumber in SUMBER.items():
        try:
            cidr = []
            terakhir_ex = None
            berhasil_ambil = False
            for url, jenis in sumber:
                try:
                    res = _ambil(url, jenis)
                    if res:
                        cidr += res
                        berhasil_ambil = True
                        if jenis == 'cloudflare_api' and len(res) >= 15:
                            break
                except Exception as ex:
                    terakhir_ex = ex
                    continue
            if not berhasil_ambil and terakhir_ex is not None:
                raise terakhir_ex
            cidr = sorted(set(cidr))[:MAKS_PER_PROVIDER]
            lama = (prov.get(nama) or {}).get('cidr') or BAWAAN.get(nama) or []
            # daftar yang menyusut tajam (halaman galat, respons terpotong) tidak dipercaya: daftar lama dipertahankan
            if not cidr or (lama and len(cidr) < len(lama) // 2):
                hasil[nama] = 'ditolak (%d entri, sebelumnya %d)' % (len(cidr), len(lama))
                continue
            prov[nama] = {'cidr': cidr, 'ts': int(time.time())}
            hasil[nama] = 'ok (%d entri)' % len(cidr)
        except Exception as ex:
            hasil[nama] = 'gagal: %s' % str(ex)[:120]
    _tulis(SYNC, json.dumps({'ts': int(time.time()), 'provider': prov}, separators=(',', ':')))
    try:
        sync_cloudflare_waf_whitelist(prov.get('cloudflare', {}).get('cidr'))
    except Exception:
        pass
    return {'provider': hasil, 'jumlah': tulis_gabungan()}


def cari(daftar, ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for n, p in daftar:
        if a.version == n.version and a in n:
            return p
    return None


def _tail(path, n):
    """n baris terakhir berkas (tanpa mengikuti symlink, berkas biasa saja, maks 4 MB dibaca dari ujung)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return []
    try:
        st = os.fstat(fd)
        import stat as _st
        if not _st.S_ISREG(st.st_mode):
            return []
        mulai = max(0, st.st_size - min(4 << 20, max(n, 100) * 600))
        os.lseek(fd, mulai, 0)
        data = b''
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            data += b
        return data.decode('utf-8', 'replace').splitlines()[-n:]
    finally:
        os.close(fd)


# Konfigurasi real IP yang sudah ada (milik admin atau plugin ini) per jenis web server
RX_REALIP = {'nginx': re.compile(r'^\s*(?:set_real_ip_from|real_ip_header)\b', re.M),
             'apache': re.compile(r'^\s*(?:RemoteIPHeader|RemoteIPTrustedProxy|RemoteIPInternalProxy)\b', re.M | re.I)}
VHOST = {'nginx': '/www/server/panel/vhost/nginx', 'apache': '/www/server/panel/vhost/apache',
         'openlitespeed': '/www/server/panel/vhost/openlitespeed'}
LOGDIR = '/www/wwwlogs'


def realip_ada(ws, site, kecuali_milik_plugin=True):
    """'vhost' / 'global' bila konfigurasi real IP sudah ada di vhost (termasuk extension/) atau konfigurasi utama; '' bila tidak."""
    if ws not in RX_REALIP:
        return ''
    berkas = ['%s/%s.conf' % (VHOST[ws], site)]
    ext = '%s/extension/%s' % (VHOST[ws], site)
    if os.path.isdir(ext):
        berkas += [os.path.join(ext, f) for f in sorted(os.listdir(ext)) if f.endswith('.conf')
                   and not (kecuali_milik_plugin and f == 'sentinel-realip.conf')]
    for f in berkas:
        try:
            if RX_REALIP[ws].search(open(f, errors='replace').read()):
                return 'vhost'
        except OSError:
            continue
    utama = {'nginx': ['/www/server/nginx/conf/nginx.conf'],
             'apache': ['/www/server/apache/conf/httpd.conf', '/www/server/apache/conf/extra/httpd-remoteip.conf']}[ws]
    for f in utama:
        try:
            if RX_REALIP[ws].search(open(f, errors='replace').read()):
                return 'global'
        except OSError:
            continue
    return ''


def _log_vhost(ws, site):
    nama = {'nginx': ['%s.log'], 'apache': ['%s-access_log'], 'openlitespeed': ['%s_ols.access_log']}[ws]
    for pola in nama:
        p = os.path.join(LOGDIR, pola % site)
        if os.path.isfile(p):
            return p
    return ''


def detect(n=2000):
    """Per vhost: berapa dari n baris terakhir access log datang dari IP proxy (field pertama), provider terbanyak, dan apakah
    real IP sudah terpasang. via_proxy tinggi + realip kosong = guardd/WAF melihat IP tepi proxy (saran: pasang real IP)."""
    daftar = gabung()
    hasil = []
    for ws, d in VHOST.items():
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith('.conf'):
                continue
            site = f[:-5]
            if not re.fullmatch(r'[A-Za-z0-9._-]+', site) or site.startswith('0.') or '.bak.' in site \
                    or site in ('free_waf', 'sentinel_waf', 'phpfpm_status', 'waf2monitor_data'):
                continue
            log = _log_vhost(ws, site)
            total, via, prov = 0, 0, {}
            for ln in _tail(log, n) if log else []:
                ip = ln.split(' ', 1)[0].split(',', 1)[0].strip()
                if not ip:
                    continue
                total += 1
                p = cari(daftar, ip)
                if p:
                    via += 1
                    prov[p] = prov.get(p, 0) + 1
            hasil.append({'ws': ws, 'site': site, 'log': bool(log), 'baris': total, 'via_proxy': via,
                          'persen': round(100.0 * via / total, 1) if total else 0.0,
                          'provider': max(prov, key=prov.get) if prov else '',
                          'realip': realip_ada(ws, site, kecuali_milik_plugin=False) if ws in RX_REALIP else 'server',
                          'realip_plugin': os.path.isfile('%s/extension/%s/sentinel-realip.conf' % (d, site))})
    if any(r.get('provider') == 'cloudflare' or r.get('realip_plugin') for r in hasil):
        try:
            sync_cloudflare_waf_whitelist()
        except Exception:
            pass
    return hasil


NGINX_BIN = os.environ.get('SENTINEL_NGINX', '/www/server/nginx/sbin/nginx')
REALIP_NAMA = 'sentinel-realip.conf'
REALIP_PERSEN = 20.0     # vhost dianggap di balik proxy bila >= 20% baris log terakhir datang dari IP proxy


def _jalankan(cmd, timeout=30):
    import subprocess
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.decode('utf-8', 'replace')
    except (OSError, subprocess.SubprocessError) as ex:
        return 127, str(ex)


def _apache_cmd():
    for b in ('/www/server/apache/bin/httpd', '/usr/sbin/apache2ctl', '/usr/sbin/apachectl', '/usr/sbin/httpd'):
        if os.path.isfile(b) and os.access(b, os.X_OK):
            return b
    return ''


def realip_isi(ws, daftar):
    """Isi berkas real IP per vhost. Hanya alamat dari rentang tepercaya yang boleh menentukan IP pengunjung (header dari
    sumber lain diabaikan, jadi X-Forwarded-For palsu dari klien langsung tidak berpengaruh)."""
    kepala = ('# Dikelola ZySentinel (sentinel-proxy.py): IP pengunjung asli dari proxy/CDN tepercaya. Jangan edit manual.\n'
              '# Konfigurasi real IP milik admin di vhost/extension membuat berkas ini dicabut otomatis.\n')
    if ws == 'nginx':
        return kepala + ''.join('set_real_ip_from %s;\n' % n for n, _ in daftar) + \
            'real_ip_header X-Forwarded-For;\nreal_ip_recursive on;\n'
    return kepala + '<IfModule remoteip_module>\n    RemoteIPHeader X-Forwarded-For\n' + \
        ''.join('    RemoteIPTrustedProxy %s\n' % n for n, _ in daftar) + '</IfModule>\n'


def realip_terapkan(n=1000):
    """Pasang/segarkan/cabut extension/<situs>/sentinel-realip.conf untuk vhost nginx & Apache yang lalu lintasnya lewat proxy
    (atau sudah punya berkas ini: setelah real IP aktif log berisi IP asli, jadi deteksi persen tidak lagi terlihat). Vhost
    dengan konfigurasi real IP sendiri tidak disentuh. Setiap web server yang berubah diuji (-t); gagal = semua berkas web
    server itu dikembalikan. Reload adalah tugas pemanggil (sentinel-waf.sh realip)."""
    daftar = gabung()
    rows = detect(n)
    modul = {'nginx': False, 'apache': bool(_apache_cmd())}
    if os.path.isfile(NGINX_BIN):
        rc, out = _jalankan([NGINX_BIN, '-V'])
        modul['nginx'] = 'http_realip_module' in out
    cadangan = {'nginx': [], 'apache': []}     # (path, isi_lama atau None)
    hasil = {'diubah': {}, 'gagal': {}, 'catatan': []}
    if not modul['nginx'] and os.path.isdir(VHOST['nginx']):
        hasil['catatan'].append('nginx tanpa http_realip_module: real IP tidak dipasang')
    for r in rows:
        ws, site = r['ws'], r['site']
        if ws not in cadangan or not modul[ws]:
            continue
        ext = '%s/extension/%s' % (VHOST[ws], site)
        path = os.path.join(ext, REALIP_NAMA)
        punya = os.path.isfile(path)
        admin = realip_ada(ws, site)
        ingin = not admin and (punya or r['persen'] >= REALIP_PERSEN)
        lama = None
        if punya:
            try:
                lama = open(path).read()
            except OSError:
                lama = None
        if ingin:
            isi = realip_isi(ws, daftar)
            if lama == isi:
                continue
            os.makedirs(ext, exist_ok=True)
            _tulis(path, isi)
        elif punya:
            os.remove(path)
        else:
            continue
        cadangan[ws].append((path, lama))
        hasil['diubah'].setdefault(ws, []).append(site)
    for ws, daftar_ubah in cadangan.items():
        if not daftar_ubah:
            continue
        if ws == 'nginx':
            rc, out = _jalankan([NGINX_BIN, '-t'])
            ok = 'test is successful' in out
        else:
            rc, out = _jalankan([_apache_cmd(), '-t'])
            ok = rc == 0
        if ok:
            continue
        for path, lama in daftar_ubah:
            try:
                if lama is None:
                    os.remove(path)
                else:
                    _tulis(path, lama)
            except OSError:
                pass
        hasil['gagal'][ws] = out.strip().splitlines()[-1][:200] if out.strip() else 'uji konfigurasi gagal'
        hasil['diubah'].pop(ws, None)
    return hasil


def main():
    aksi = sys.argv[1] if len(sys.argv) > 1 else 'list'
    if aksi == 'sync':
        print(json.dumps(sync('--if-stale' in sys.argv[2:])))
    elif aksi == 'list':
        if not os.path.isfile(OUT):
            tulis_gabungan()
        for n, p in gabung():
            print('%s %s' % (n, p))
    elif aksi == 'write':
        print(tulis_gabungan())
    elif aksi == 'realip':
        print(json.dumps(realip_terapkan()))
    elif aksi == 'detect':
        n = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 2000
        print(json.dumps(detect(max(100, min(n, 20000)))))
    elif aksi == 'sync-waf':
        print(json.dumps(sync_cloudflare_waf_whitelist()))
    elif aksi == 'cf-ips':
        print(json.dumps(ambil_cf_ips()))
    else:
        print('Penggunaan: sentinel-proxy.py sync [--if-stale] | sync-waf | list | write | detect [n] | realip | cf-ips')
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
