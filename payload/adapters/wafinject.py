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


def main(argv):
    if len(argv) < 6:
        print(__doc__)
        return 2
    op, ws, path, domain, snippet = argv[1:6]
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
