# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Pembuat kode QR (SVG) murni Python, tanpa dependensi dan tanpa layanan luar.

Dipakai untuk mendaftarkan 2FA (TOTP): URI otpauth berisi rahasia, jadi kode QR dibuat di server sendiri dan
tidak pernah dikirim ke layanan pihak ketiga. Mode byte, koreksi galat level M, versi 1-10 (sampai 213 byte).
Salinan identik ada di _client/adapters/qr.py; ubah keduanya bersamaan.
"""

# koreksi galat level M: (codeword ECC per blok, jumlah blok) untuk versi 1..10
_ECC_M = {1: (10, 1), 2: (16, 1), 3: (26, 1), 4: (18, 2), 5: (24, 2), 6: (16, 4), 7: (18, 4), 8: (22, 4), 9: (22, 5), 10: (26, 5)}
MAX_VERSION = 10


def _raw_modules(ver):
    r = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        r -= (25 * n - 10) * n - 55
        if ver >= 7:
            r -= 36
    return r


def _data_codewords(ver):
    ecc, blocks = _ECC_M[ver]
    return _raw_modules(ver) // 8 - ecc * blocks


def _gf_mul(x, y):
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree):
    res = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            res[j] = _gf_mul(res[j], root)
            if j + 1 < degree:
                res[j] ^= res[j + 1]
        root = _gf_mul(root, 2)
    return res


def _rs_remainder(data, divisor):
    res = [0] * len(divisor)
    for b in data:
        f = b ^ res.pop(0)
        res.append(0)
        for i, c in enumerate(divisor):
            res[i] ^= _gf_mul(c, f)
    return res


def _codewords(data, ver):
    """Data + ECC per blok, disisipkan sesuai standar."""
    ecc_len, nblocks = _ECC_M[ver]
    raw = _raw_modules(ver) // 8
    nshort = nblocks - raw % nblocks
    short_len = raw // nblocks
    div = _rs_divisor(ecc_len)
    blocks, k = [], 0
    for i in range(nblocks):
        n = short_len - ecc_len + (0 if i < nshort else 1)
        d = data[k:k + n]
        k += n
        blocks.append((d, _rs_remainder(d, div)))
    out = []
    for i in range(short_len - ecc_len + 1):
        for j, (d, _) in enumerate(blocks):
            if i != short_len - ecc_len or j >= nshort:
                out.append(d[i])
    for i in range(ecc_len):
        for _, e in blocks:
            out.append(e[i])
    return out


def _align_positions(ver):
    if ver == 1:
        return []
    n = ver // 7 + 2
    step = (ver * 4 + n * 2 + 1) // (n * 2 - 2) * 2
    res = [6]
    pos = ver * 4 + 17 - 7
    for _ in range(n - 1):
        res.insert(1, pos)
        pos -= step
    return res


class _Matrix(object):
    def __init__(self, ver):
        self.ver = ver
        self.size = ver * 4 + 17
        self.m = [[False] * self.size for _ in range(self.size)]
        self.fn = [[False] * self.size for _ in range(self.size)]
        self._function_patterns()

    def _set(self, x, y, dark):
        self.m[y][x] = bool(dark)
        self.fn[y][x] = True

    def _finder(self, cx, cy):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < self.size and 0 <= y < self.size:
                    dist = max(abs(dx), abs(dy))
                    self._set(x, y, dist not in (2, 4))

    def _function_patterns(self):
        s = self.size
        for i in range(s):
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        self._finder(3, 3)
        self._finder(s - 4, 3)
        self._finder(3, s - 4)
        pos = _align_positions(self.ver)
        for i, ax in enumerate(pos):
            for j, ay in enumerate(pos):
                if (i == 0 and j == 0) or (i == 0 and j == len(pos) - 1) or (i == len(pos) - 1 and j == 0):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self._format(0)           # menandai area format sebagai fungsi; nilai sebenarnya ditulis setelah topeng dipilih
        self._version()

    def _format(self, mask):
        bits = (0 << 3) | mask    # level M = 00
        rem = bits
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = ((bits << 10) | rem) ^ 0x5412
        s = self.size
        for i in range(6):
            self._set(8, i, (bits >> i) & 1)
        self._set(8, 7, (bits >> 6) & 1)
        self._set(8, 8, (bits >> 7) & 1)
        self._set(7, 8, (bits >> 8) & 1)
        for i in range(9, 15):
            self._set(14 - i, 8, (bits >> i) & 1)
        for i in range(8):
            self._set(s - 1 - i, 8, (bits >> i) & 1)
        for i in range(8, 15):
            self._set(8, s - 15 + i, (bits >> i) & 1)
        self._set(8, s - 8, True)  # modul gelap tetap

    def _version(self):
        if self.ver < 7:
            return
        rem = self.ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = (self.ver << 12) | rem
        s = self.size
        for i in range(18):
            a, b = s - 11 + i % 3, i // 3
            self._set(a, b, (bits >> i) & 1)
            self._set(b, a, (bits >> i) & 1)

    def draw_codewords(self, cw):
        s = self.size
        i = 0
        total = len(cw) * 8
        right = s - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(s):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = (s - 1 - vert) if upward else vert
                    if not self.fn[y][x] and i < total:
                        self.m[y][x] = ((cw[i >> 3] >> (7 - (i & 7))) & 1) != 0
                        i += 1
            right -= 2

    def apply_mask(self, mask):
        for y in range(self.size):
            for x in range(self.size):
                inv = [(x + y) % 2 == 0, y % 2 == 0, x % 3 == 0, (x + y) % 3 == 0, (x // 3 + y // 2) % 2 == 0,
                       x * y % 2 + x * y % 3 == 0, (x * y % 2 + x * y % 3) % 2 == 0, ((x + y) % 2 + x * y % 3) % 2 == 0][mask]
                if not self.fn[y][x] and inv:
                    self.m[y][x] = not self.m[y][x]

    def penalty(self):
        s, m = self.size, self.m
        p = 0
        for rows in (m, [list(c) for c in zip(*m)]):
            for line in rows:
                run, prev = 1, line[0]
                for v in line[1:]:
                    if v == prev:
                        run += 1
                    else:
                        if run >= 5:
                            p += run - 2
                        run, prev = 1, v
                if run >= 5:
                    p += run - 2
        for y in range(s - 1):
            for x in range(s - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    p += 3
        dark = sum(sum(r) for r in m)
        p += abs(dark * 100 // (s * s) - 50) // 5 * 10
        return p


def encode(text, mask=None):
    """Matriks QR (list of list bool) untuk teks ASCII/UTF-8; ValueError bila terlalu panjang.
    mask=None memilih topeng berpenalti terendah; angka 0-7 memaksa satu topeng (untuk uji)."""
    data = text.encode('utf-8')
    for ver in range(1, MAX_VERSION + 1):
        cap = _data_codewords(ver)
        cc = 8 if ver < 10 else 16
        if 4 + cc + len(data) * 8 <= cap * 8:
            break
    else:
        raise ValueError('teks terlalu panjang untuk kode QR (maks %d byte)' % (_data_codewords(MAX_VERSION) - 3))
    bits = [0, 1, 0, 0] + [(len(data) >> i) & 1 for i in range(cc - 1, -1, -1)]
    for b in data:
        bits += [(b >> i) & 1 for i in range(7, -1, -1)]
    bits += [0] * min(4, cap * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < cap:
        words.append(pad)
        pad ^= 0xEC ^ 0x11
    cw = _codewords(words, ver)
    best = None
    for mk in ([mask] if mask is not None else range(8)):
        q = _Matrix(ver)
        q.draw_codewords(cw)
        q.apply_mask(mk)
        q._format(mk)
        pen = q.penalty()
        if best is None or pen < best[0]:
            best = (pen, q)
    return best[1].m


def svg(text, border=4, fg='#0b1426', bg='#ffffff', label='QR code', mask=None):
    """Kode QR sebagai markup SVG mandiri (modul dirangkai jadi satu path; aman disisipkan sebagai HTML)."""
    m = encode(text, mask)
    n = len(m)
    d = []
    for y, row in enumerate(m):
        x = 0
        while x < n:
            if row[x]:
                x0 = x
                while x < n and row[x]:
                    x += 1
                d.append('M%d %dh%dv1h-%dz' % (x0 + border, y + border, x - x0, x - x0))
            else:
                x += 1
    size = n + border * 2
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="%s" shape-rendering="crispEdges" '
            'style="width:100%%;height:auto;display:block">'
            '<rect width="%d" height="%d" fill="%s"/><path d="%s" fill="%s"/></svg>') % (size, size, label, size, size, bg, ''.join(d), fg)
