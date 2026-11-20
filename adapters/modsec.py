# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Deteksi ModSecurity yang SUDAH aktif di web server dan ruleset milik panel/admin yang dimuatnya.

Tujuan defensif (15 Nov 2026): satu web server tidak boleh menjalankan dua engine WAF sekaligus (Coraza + ModSecurity di nginx yang sama)
dan CRS tidak boleh diperiksa dua kali (CRS bawaan panel + salinan ZySentinel: ID ganda, beban CPU ganda, skor anomali tumpang tindih).
Bila ModSecurity sudah dimuat, ZySentinel memakai engine itu; bila ModSecurity itu sudah memuat CRS/Comodo milik panel, ZySentinel memasang
"mode pendamping" (aturan ZySentinel + premium + virtual patch saja, tanpa CRS salinannya).

CLI (keluaran kunci=nilai, satu per baris):
  modsec.py nginx <biner-nginx>        modul=ya|tidak  crs=owasp|comodo|lain|tidak  berkas=<n>
  modsec.py apache < DUMP_INCLUDES     crs=...  berkas=<n>          (stdin = keluaran `httpd -t -D DUMP_INCLUDES`)
  modsec.py ols [httpd_config.conf]    modul=ya|tidak  crs=...  berkas=<n>
  modsec.py jembatan <nginx|ols> [biner-nginx]   salin entri baru log audit ModSecurity milik panel ke umpan WAF ZySentinel
Ruleset di bawah folder ZySentinel sendiri (SENTINEL_BASE) tidak pernah dihitung sebagai milik panel.

Jembatan log audit (15 Nov 2026): libmodsecurity v3 (nginx, OpenLiteSpeed) memakai SecAuditLog tingkat server milik panel/admin dan
mengabaikan SecAuditLog per vhost dari ruleset ZySentinel; blokir di engine itu dulu tidak pernah muncul di umpan WAF/dasbor ZySentinel.
Entri baru (native v2/v3 atau JSON) dibaca dari offset terakhir dan ditambahkan sebagai JSON ke log audit ZySentinel.
"""
import glob
import os
import re
import subprocess
import sys
import time

SENDIRI = tuple(p.rstrip('/') + '/' for p in os.environ.get('ZYS_MODSEC_SENDIRI', os.environ.get('SENTINEL_BASE', '/www/server/sentinel')).split())
OLS_CONF = os.environ.get('ZYS_MODSEC_OLS_CONF', '/usr/local/lsws/conf/httpd_config.conf')
OLS_MOD = os.environ.get('ZYS_MODSEC_OLS_MOD', '/usr/local/lsws/modules/mod_security.so')
MAKS_BERKAS = 3000
BACA = 262144

RX_OWASP = re.compile(r'OWASP_CRS|coreruleset|crs_setup_version|REQUEST-9\d\d-|"id:9[0-4]\d{4}|\bid:9[0-4]\d{4}', re.I)
RX_COMODO = re.compile(r'comodo', re.I)
RX_ATURAN = re.compile(r'(?mi)^\s*(SecRule|SecAction)\s')
RX_INCLUDE = re.compile(r'(?mi)^\s*Include(?:Optional)?\s+"?([^"\s]+)"?')


def sendiri(p):
    p = os.path.realpath(p)
    return any(p.startswith(s) or p + '/' == s for s in SENDIRI)


def _baca(p):
    try:
        with open(p, 'r', errors='replace') as f:
            return f.read(BACA)
    except OSError:
        return ''


def _tanpa_komentar(t):
    return re.sub(r'(?m)^\s*#.*$', '', t)


def ikuti(akar, dasar='/'):
    """Berkas aturan + semua Include di dalamnya (glob, relatif terhadap folder berkas), tanpa milik ZySentinel."""
    hasil, antre, lihat = [], list(akar), set()
    while antre and len(hasil) < MAKS_BERKAS:
        p = antre.pop(0)
        if not os.path.isabs(p):
            p = os.path.join(dasar, p)
        for f in sorted(glob.glob(p)) if any(c in p for c in '*?[') else [p]:
            r = os.path.realpath(f)
            if r in lihat or sendiri(r) or not os.path.isfile(r):
                continue
            lihat.add(r)
            hasil.append(r)
            for inc in RX_INCLUDE.findall(_tanpa_komentar(_baca(r))):
                antre.append(inc if os.path.isabs(inc) else os.path.join(os.path.dirname(r), inc))
    return hasil


def kelas(berkas):
    """owasp | comodo | lain (ada SecRule lain) | tidak (tidak ada aturan milik panel)."""
    ada = False
    comodo = False
    for p in berkas:
        t = _baca(p)
        if RX_OWASP.search(p) or RX_OWASP.search(t):
            return 'owasp'
        if RX_COMODO.search(p) or RX_COMODO.search(t[:4096]):
            comodo = True
        if RX_ATURAN.search(t):
            ada = True
    return 'comodo' if comodo else ('lain' if ada else 'tidak')


def nginx(biner):
    """ModSecurity (konektor libmodsecurity) dimuat nginx? + ruleset yang dimuatnya (modsecurity_rules_file / modsecurity_rules)."""
    try:
        v = subprocess.run([biner, '-V'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20, cwd='/').stdout.decode('utf-8', 'replace')
        t = subprocess.run([biner, '-T'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, cwd='/').stdout.decode('utf-8', 'replace')
    except (OSError, subprocess.SubprocessError):
        return {'modul': 'tidak', 'crs': 'tidak', 'berkas': 0}
    return nginx_teks(t, v)


def nginx_teks(t, v=''):
    tk = _tanpa_komentar(t)
    modul = bool(re.search(r'(?m)^\s*load_module\s+[^;]*ngx_http_modsecurity_module', tk) or re.search(r'(?i)modsecurity', v))
    akar = re.findall(r'(?m)^\s*modsecurity_rules_file\s+"?([^";\s]+)"?\s*;', tk)
    akar += re.findall(r'(?mi)^\s*Include\s+"?([^"\s\']+)', '\n'.join(re.findall(r"(?s)modsecurity_rules\s+'(.*?)'\s*;", tk)))
    b = ikuti(akar)
    return {'modul': 'ya' if modul else 'tidak', 'crs': kelas(b), 'berkas': len(b)}


def apache_teks(dump):
    """Keluaran `httpd -t -D DUMP_INCLUDES`: semua berkas konfigurasi yang benar-benar dibaca (termasuk Include ruleset ModSecurity)."""
    akar = [m for m in re.findall(r'\)\s+(/\S+)', dump)]
    b = [p for p in ikuti(akar) if RX_ATURAN.search(_baca(p)) or RX_INCLUDE.search(_baca(p)) and 'modsec' in p.lower()]
    return {'crs': kelas(b), 'berkas': len(b)}


def _blok(teks, kata):
    """Isi blok '<kata> { ... }' tingkat atas (blok bersarang ikut)."""
    hasil = []
    for m in re.finditer(r'(?m)^[ \t]*' + re.escape(kata) + r'[ \t]*\{', teks):
        i, d = m.end(), 1
        while i < len(teks) and d:
            d += {'{': 1, '}': -1}.get(teks[i], 0)
            i += 1
        hasil.append(teks[m.end():i - 1])
    return hasil


def ols(conf=None):
    """OpenLiteSpeed: ModSecurity aktif hanya bila mod_security.so ada DAN httpd_config.conf memuat blok `module mod_security`
    dengan `modsecurity on` (CyberPanel > Security > ModSecurity Conf menulis blok ini)."""
    conf = conf or OLS_CONF
    t = _tanpa_komentar(_baca(conf))
    blok = _blok(t, 'module mod_security')
    aktif = bool(blok) and os.path.isfile(OLS_MOD) and bool(re.search(r'(?m)^\s*modsecurity\s+on\b', blok[0]))
    akar = []
    for b in blok:
        akar += re.findall(r'(?m)^\s*modsecurity_rules_file\s+(\S+)', b)
        akar += re.findall(r'(?mi)^\s*Include\s+"?([^"\s`]+)', '\n'.join(re.findall(r'(?s)modsecurity_rules\s+`(.*?)`', b)))
    f = ikuti(akar, os.path.dirname(conf))
    return {'modul': 'ya' if aktif else 'tidak', 'crs': kelas(f), 'berkas': len(f)}


UMPAN = os.environ.get('ZYS_MODSEC_UMPAN', '/www/wwwlogs/zysentinel_waf_audit.jsonl')
STATE_DIR = os.environ.get('ZYS_MODSEC_STATE', '/www/server/sentinel/run')
MAKS_BACA = 8 * 1024 * 1024


def _audit_dari(berkas, teks_tambahan=''):
    """(path SecAuditLog, format) terakhir yang ditulis konfigurasi panel; ('', '') bila tidak ada."""
    log, fmt = '', 'native'
    for t in [teks_tambahan] + [_tanpa_komentar(_baca(p)) for p in berkas]:
        for m in re.finditer(r'(?mi)^\s*SecAuditLog\s+"?([^"\s]+)"?\s*$', t):
            log = m.group(1)
        for m in re.finditer(r'(?mi)^\s*SecAuditLogFormat\s+(\w+)', t):
            fmt = m.group(1).lower()
    return log, ('json' if fmt == 'json' else 'native')


def audit_sumber_ols(conf=None):
    conf = conf or OLS_CONF
    t = _tanpa_komentar(_baca(conf))
    inline, akar = '', []
    for b in _blok(t, 'module mod_security'):
        inline += '\n'.join(re.findall(r'(?s)modsecurity_rules\s+`(.*?)`', b))
        akar += re.findall(r'(?m)^\s*modsecurity_rules_file\s+(\S+)', b)
    return _audit_dari(ikuti(akar, os.path.dirname(conf)), inline)


def audit_sumber_nginx(teks):
    tk = _tanpa_komentar(teks)
    akar = re.findall(r'(?m)^\s*modsecurity_rules_file\s+"?([^";\s]+)"?\s*;', tk)
    inline = '\n'.join(re.findall(r"(?s)modsecurity_rules\s+'(.*?)'\s*;", tk))
    return _audit_dari(ikuti(akar), inline)


RX_BAGIAN = re.compile(r'^-{2,3}([A-Za-z0-9]+)-{2,3}([A-Z])--\s*$')


def entri_native(teks):
    """[(id, {huruf bagian: teks})] dari log audit native (v2 "--id-A--", v3 "---id---A--"); entri tanpa penutup Z diabaikan."""
    hasil, kini, bagian, huruf = [], None, {}, None
    for baris in teks.split('\n'):
        m = RX_BAGIAN.match(baris)
        if m:
            if m.group(2) == 'A':
                kini, bagian = m.group(1), {}
            if kini is None or m.group(1) != kini:
                huruf = None
                continue
            huruf = m.group(2)
            if huruf == 'Z':
                hasil.append((kini, bagian))
                kini, huruf = None, None
            else:
                bagian[huruf] = ''
            continue
        if kini is not None and huruf:
            bagian[huruf] += baris + '\n'
    return hasil


def native_ke_json(eid, b):
    import ipaddress
    a = (b.get('A') or '').strip().split()
    waktu, ip = '', ''
    if a and a[0].startswith('['):
        waktu = ' '.join(a[:2]).strip('[]')
        # "[tgl zona] unique_id ip_klien port ip_server port"; unique_id v3 berbentuk 179475435875.843821 (bukan IP): IP divalidasi
        for x in a[2:5]:
            try:
                ipaddress.ip_address(x)
                ip = x
                break
            except ValueError:
                continue
    ts = 0
    try:
        ts = int(time.mktime(time.strptime(waktu.split()[0], '%d/%b/%Y:%H:%M:%S')))
    except (ValueError, IndexError):
        ts = int(time.time())
    req = (b.get('B') or '').strip().split('\n')
    rl = req[0].split(' ') if req and req[0] else []
    host = ''
    for h in req[1:]:
        if h.lower().startswith('host:'):
            host = h.split(':', 1)[1].strip()
    st = re.search(r'HTTP/[\d.]+\s+(\d{3})', b.get('F') or '')
    pesan = (b.get('H') or '').strip()
    # tanpa bagian B (CyberPanel: SecAuditLogParts AFH): URI dan host dari pesan H
    if len(rl) < 2:
        m = re.search(r'\[uri "([^"]*)"\]', pesan)
        rl = ['', m.group(1)] if m else rl
    if not host:
        m = re.search(r'\[hostname "([^"]*)"\]', pesan)
        host = m.group(1) if m else ''
    if not st:
        st = re.search(r'Access denied with code (\d{3})', pesan)
    return {'transaction': {'client_ip': ip, 'timestamp': time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(ts)),
                            'unix_timestamp': ts * 1000000000, 'id': eid, 'host': host},
            'request': {'method': rl[0] if rl else '', 'uri': rl[1] if len(rl) > 1 else '', 'request_line': req[0] if req else ''},
            'response': {'status': int(st.group(1)) if st else None},
            'zys_sumber': 'panel', 'messages': pesan[:8000]}


def jembatan(src, fmt, dst=None, state=None):
    """Tambahkan entri baru src (milik panel) ke dst (umpan ZySentinel). Kembalikan jumlah entri."""
    import json
    dst = dst or UMPAN
    state = state or os.path.join(STATE_DIR, 'modsec-jembatan.' + re.sub(r'[^A-Za-z0-9]', '_', src) + '.state')
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return 0
    try:
        st = os.fstat(fd)
        if not stat_reg(st):
            return 0
        ino, off = 0, None
        try:
            ino, off = [int(x) for x in open(state).read().split()[:2]]
        except (OSError, ValueError):
            pass
        if off is None:
            off = st.st_size                       # pertama kali: mulai dari akhir (riwayat lama panel tidak dibanjirkan)
        if ino != st.st_ino or off > st.st_size:
            off = 0                                # rotasi
        data = os.pread(fd, min(MAKS_BACA, st.st_size - off), off).decode('utf-8', 'replace')
    finally:
        os.close(fd)
    keluar, maju = [], 0
    if fmt == 'json':
        akhir = data.rfind('\n') + 1
        for b in data[:akhir].split('\n'):
            if b.strip().startswith('{'):
                keluar.append(b.strip())
        maju = len(data[:akhir].encode('utf-8'))
    else:
        z = max(data.rfind('-Z--\n'), -1)
        if z >= 0:
            potong = data[:z + 5]
            for eid, b in entri_native(potong):
                keluar.append(json.dumps(native_ke_json(eid, b), ensure_ascii=False))
            maju = len(potong.encode('utf-8'))
    if keluar:
        dfd = os.open(dst, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            if stat_reg(os.fstat(dfd)):
                os.write(dfd, ('\n'.join(keluar) + '\n').encode('utf-8'))
        finally:
            os.close(dfd)
    try:
        os.makedirs(os.path.dirname(state), exist_ok=True)
        with open(state + '.baru', 'w') as f:
            f.write('%d %d\n' % (st.st_ino, off + maju))
        os.replace(state + '.baru', state)
    except OSError:
        pass
    return len(keluar)


def stat_reg(st):
    import stat as _s
    return _s.S_ISREG(st.st_mode)


def _cetak(d):
    for k, v in d.items():
        print('%s=%s' % (k, v))


def main(argv):
    if len(argv) >= 3 and argv[1] == 'nginx':
        _cetak(nginx(argv[2]))
    elif len(argv) >= 2 and argv[1] == 'apache':
        _cetak(apache_teks(sys.stdin.read()))
    elif len(argv) >= 3 and argv[1] == 'jembatan':
        if argv[2] == 'ols':
            src, fmt = audit_sumber_ols()
        else:
            try:
                t = subprocess.run([argv[3] if len(argv) > 3 else 'nginx', '-T'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   timeout=60, cwd='/').stdout.decode('utf-8', 'replace')
            except (OSError, subprocess.SubprocessError):
                t = ''
            src, fmt = audit_sumber_nginx(t)
        n = jembatan(src, fmt) if src and not sendiri(src) else 0
        _cetak({'sumber': src or '-', 'format': fmt, 'entri': n})
    elif len(argv) >= 2 and argv[1] == 'ols':
        _cetak(ols(argv[2] if len(argv) > 2 else None))
    else:
        sys.stderr.write(__doc__)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
