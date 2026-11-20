# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Pasang/cabut `include` snippet WAF ZySentinel di konfigurasi vhost web server yang BUKAN buatan panel (nginx/Apache distro).

Tujuan defensif: di aaPanel snippet WAF dimuat otomatis dari extension/<situs>/; di server standalone vhost ditulis manual atau oleh
alat lain, jadi baris include harus disuntikkan ke blok server/VirtualHost situs yang bersangkutan. Penyuntikan dibuat aman:
  - hanya blok yang memuat domain situs (server_name / ServerName), ditandai komentar `# zysentinel-waf` agar bisa dicabut persis;
  - berkas asli dicadangkan sekali (<berkas>.zysentinel.bak), ditulis atomik dengan izin/pemilik sama, symlink (sites-enabled)
    diikuti ke berkas sebenarnya;
  - idempoten (dua kali pasang = satu include); pemanggil wajib menguji konfigurasi (nginx -t / apachectl -t) dan memanggil `del` bila gagal.
CLI: wafinject.py add|del|has <nginx|apache> <berkas> <domain> <snippet>   (kode keluar: add/del 0 = ada perubahan atau sudah sesuai, 3 = blok situs tidak ditemukan; has 0 = ada)
OpenLiteSpeed (CyberPanel, 15 Nov 2026): vhost.conf tidak mengenal include, jadi yang disuntikkan adalah blok `module mod_security` bertanda
`# zysentinel-waf BEGIN/END` dengan <snippet> = berkas ruleset; add = 4 bila vhost sudah punya blok mod_security milik panel (tidak ditimpa).
"""
import os
import re
import shutil
import sys

MARK = '# zysentinel-waf'


def _read(path):
    with open(path, 'r', errors='surrogateescape') as f:
        return f.read()


def _write_atomic(path, text):
    real = os.path.realpath(path)
    st = os.stat(real)
    tmp = real + '.zysentinel.tmp'
    with open(tmp, 'w', errors='surrogateescape') as f:
        f.write(text)
    os.chmod(tmp, st.st_mode & 0o7777)
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except OSError:
        pass
    os.replace(tmp, real)


def _backup_once(path):
    real = os.path.realpath(path)
    bak = real + '.zysentinel.bak'
    if not os.path.exists(bak):
        shutil.copy2(real, bak)


def _include_line(ws, snippet):
    q = snippet.replace('"', '')
    return ('    include %s;' % q) if ws == 'nginx' else ('    IncludeOptional %s' % q)


def has(ws, path, snippet):
    try:
        return _include_line(ws, snippet).strip() in _read(path)
    except OSError:
        return False


def _nginx_spans(text):
    """[(awal, akhir)] isi tiap blok `server { ... }` (indeks di text)."""
    out = []
    for m in re.finditer(r'(?m)^[ \t]*server\s*\{', text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += (text[i] == '{') - (text[i] == '}')
            i += 1
        out.append((m.end(), i - 1))
    return out


def _apache_spans(text):
    return [(m.start(1), m.end(1)) for m in re.finditer(r'<VirtualHost\b[^>]*>(.*?)</VirtualHost>', text, re.S | re.I)]


def _names(ws, block):
    if ws == 'nginx':
        out = []
        for m in re.finditer(r'(?m)^[ \t]*server_name\s+([^;]+);', block):
            out += m.group(1).split()
        return out
    out = []
    for m in re.finditer(r'(?mi)^[ \t]*Server(?:Name|Alias)\s+(.+)$', block):
        out += m.group(1).split()
    return [x.split(':')[0] for x in out]


def add(ws, path, domain, snippet):
    text = _read(path)
    line = _include_line(ws, snippet)
    if line.strip() in text:
        return 0
    spans = _nginx_spans(text) if ws == 'nginx' else _apache_spans(text)
    kena = [(a, b) for a, b in spans if domain.lower() in [n.lower() for n in _names(ws, text[a:b])]]
    if not kena:
        return 3
    out, pos = [], 0
    for a, b in kena:
        blok = text[a:b]
        pat = r'(?m)^([ \t]*server_name\s+[^;]+;[^\n]*)$' if ws == 'nginx' else r'(?mi)^([ \t]*ServerName\s+[^\n]+)$'
        m = re.search(pat, blok)
        at = a + (m.end() if m else 0)
        out.append(text[pos:at])
        out.append('\n%s\n%s' % ('    ' + MARK, line))
        pos = at
    out.append(text[pos:])
    _backup_once(path)
    _write_atomic(path, ''.join(out))
    return 0


def delete(ws, path, domain, snippet):
    try:
        text = _read(path)
    except OSError:
        return 0
    line = _include_line(ws, snippet)
    lines = text.split('\n')
    res, i, changed = [], 0, False
    while i < len(lines):
        if lines[i].strip() == MARK and i + 1 < len(lines) and lines[i + 1].strip() == line.strip():
            i += 2
            changed = True
            continue
        if lines[i].strip() == line.strip():      # include tanpa penanda (disunting tangan): ikut dicabut
            i += 1
            changed = True
            continue
        res.append(lines[i])
        i += 1
    if changed:
        _backup_once(path)
        _write_atomic(path, '\n'.join(res))
    return 0


OLS_AWAL, OLS_AKHIR = MARK + ' BEGIN (dikelola ZySentinel, jangan disunting)', MARK + ' END'
RX_OLS_KAMI = re.compile(r'(?ms)^[ \t]*' + re.escape(MARK) + r' BEGIN[^\n]*\n.*?^[ \t]*' + re.escape(MARK) + r' END[^\n]*\n?')


def _ols_blok(rules):
    return '%s\nmodule mod_security {\n  modsecurity             on\n  modsecurity_rules_file  %s\n  ls_enabled              1\n}\n%s\n' % (
        OLS_AWAL, rules.replace('\n', ''), OLS_AKHIR)


def ols_has(path, rules):
    try:
        m = RX_OLS_KAMI.search(_read(path))
    except OSError:
        return False
    return bool(m) and ('modsecurity_rules_file  %s\n' % rules) in m.group(0)


def ols_add(path, rules):
    text = _read(path)
    lain = RX_OLS_KAMI.sub('', text)
    if re.search(r'(?m)^[ \t]*module[ \t]+mod_security\b', lain):
        return 4                                    # blok ModSecurity per situs milik panel/admin: jangan ada dua blok
    baru = lain.rstrip('\n') + '\n\n' + _ols_blok(rules)
    if baru == text:
        return 0
    _backup_once(path)
    _write_atomic(path, baru)
    return 0


def ols_del(path):
    try:
        text = _read(path)
    except OSError:
        return 0
    baru = RX_OLS_KAMI.sub('', text)
    if baru != text:
        _backup_once(path)
        _write_atomic(path, baru.rstrip('\n') + '\n')
    return 0


def main(argv):
    if len(argv) < 6:
        print(__doc__)
        return 2
    op, ws, path, domain, snippet = argv[1:6]
    if ws == 'openlitespeed' and re.match(r'^[A-Za-z0-9._*-]+$', domain) and '\n' not in snippet:
        if op == 'has':
            return 0 if ols_has(path, snippet) else 1
        if op == 'add':
            return ols_add(path, snippet)
        if op == 'del':
            return ols_del(path)
        return 2
    if ws not in ('nginx', 'apache') or not re.match(r'^[A-Za-z0-9._*-]+$', domain) or '\n' in snippet:
        return 2
    if op == 'has':
        return 0 if has(ws, path, snippet) else 1
    if op == 'add':
        return add(ws, path, domain, snippet)
    if op == 'del':
        return delete(ws, path, domain, snippet)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
