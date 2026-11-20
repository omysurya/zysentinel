#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""sentinel-geo: data GeoIP untuk server TANPA aaPanel (di aaPanel datanya disediakan panel).

Tujuan defensif: peta asal serangan (lookup negara/kota per IP) dan blokir per negara (geo-ban) butuh data GeoIP. Di server
tanpa aaPanel tidak ada berkas milik panel, jadi skrip ini menyiapkannya dari DB-IP Lite (gratis, tanpa akun, CC BY 4.0):
  - GeoLite2-City.mmdb       format MaxMind DB (dibaca modul maxminddb), nama dipertahankan agar pembaca yang ada tidak berubah
  - GeoLite2-Country.json    [{"brief": "ID", "ips": ["1.2.3.0/24", ...]}, ...] (IPv4; set ipset sentinel_geo bertipe inet)
Semua berkas ditulis atomik (berkas sementara + rename) setelah divalidasi; gagal = berkas lama tetap dipakai.

Pemakaian: sentinel-geo.py update | status
Atribusi: "IP Geolocation by DB-IP" (https://db-ip.com), lisensi CC BY 4.0.
"""
import csv
import gzip
import ipaddress
import json
import os
import shutil
import sys
import time
import urllib.request


def _urlopen(req, timeout=10):
    """sentinel_license.urlopen (IPv4 dulu, CA sistem sebagai cadangan) bila modulnya ada di folder ini; selain itu urllib biasa."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from sentinel_license import urlopen as _u
    except Exception:
        _u = urllib.request.urlopen
    return _u(req, timeout=timeout)

BASE = os.environ.get('ZYS_BASE', '/www/server/sentinel')
GEO_DIR = os.environ.get('ZYS_GEO_DIR', os.path.join(BASE, 'data', 'geo'))
SRC = os.environ.get('ZYS_GEO_SRC', 'https://download.db-ip.com/free')
MAX_BYTES = 400 * 1024 * 1024
MMDB_MAGIC = b'\xab\xcd\xefMaxMind.com'


def bulan_kandidat():
    """Bulan ini dan bulan lalu (DB-IP menerbitkan awal bulan; bulan berjalan bisa belum ada)."""
    t = time.gmtime()
    y, m = t.tm_year, t.tm_mon
    py, pm = (y, m - 1) if m > 1 else (y - 1, 12)
    return ['%04d-%02d' % (y, m), '%04d-%02d' % (py, pm)]


def unduh(nama_fmt, tujuan_gz):
    """Unduh nama_fmt % bulan (bulan ini lalu bulan lalu) ke tujuan_gz; kembalikan bulan yang berhasil."""
    galat = None
    for bln in bulan_kandidat():
        url = '%s/%s' % (SRC, nama_fmt % bln)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'zysentinel-geo/1'})
            # batas waktu TOTAL (bukan hanya per baca): koneksi yang terus mengalir sangat lambat dulu menahan proses tanpa batas
            batas = time.time() + int(os.environ.get('ZYS_GEO_BATAS', '1800'))
            with _urlopen(req, timeout=90) as r, open(tujuan_gz, 'wb') as f:
                n = 0
                while True:
                    b = r.read(1 << 20)
                    if not b:
                        break
                    n += len(b)
                    if n > MAX_BYTES:
                        raise ValueError('berkas terlalu besar')
                    if time.time() > batas:
                        raise TimeoutError('unduhan melebihi batas waktu total; dicoba lagi pada pembaruan berikutnya')
                    f.write(b)
            return bln
        except Exception as e:
            galat = e
    raise RuntimeError('unduhan gagal: %s' % galat)


def atomik(tmp, final):
    os.replace(tmp, final)
    os.chmod(final, 0o644)


def update_mmdb():
    gz = os.path.join(GEO_DIR, '.city.gz')
    tmp = os.path.join(GEO_DIR, '.city.mmdb.baru')
    bln = unduh('dbip-city-lite-%s.mmdb.gz', gz)
    with gzip.open(gz, 'rb') as a, open(tmp, 'wb') as b:
        shutil.copyfileobj(a, b)
    os.unlink(gz)
    with open(tmp, 'rb') as f:
        f.seek(-min(os.path.getsize(tmp), 128 * 1024), os.SEEK_END)
        if MMDB_MAGIC not in f.read():
            os.unlink(tmp)
            raise RuntimeError('berkas bukan MaxMind DB yang sah')
    try:
        import maxminddb
        db = maxminddb.open_database(tmp)
        hasil = db.get('8.8.8.8')
        db.close()
        if not isinstance(hasil, dict) or not (hasil.get('country') or hasil.get('location')):
            raise RuntimeError('uji lookup 8.8.8.8 tidak menghasilkan negara/lokasi')
    except ImportError:
        pass          # modul belum ada: validasi magic cukup; lookup divalidasi saat modul terpasang
    except Exception:
        os.unlink(tmp)
        raise
    atomik(tmp, os.path.join(GEO_DIR, 'GeoLite2-City.mmdb'))
    return bln


def update_country_json():
    gz = os.path.join(GEO_DIR, '.country.gz')
    tmp = os.path.join(GEO_DIR, '.country.json.baru')
    bln = unduh('dbip-country-lite-%s.csv.gz', gz)
    negara = {}
    with gzip.open(gz, 'rt', newline='') as f:
        for baris in csv.reader(f):
            if len(baris) < 3:
                continue
            try:
                a, b = ipaddress.ip_address(baris[0]), ipaddress.ip_address(baris[1])
            except ValueError:
                continue
            kode = baris[2].strip().upper()
            if a.version != 4 or len(kode) != 2 or not kode.isalpha() or kode == 'ZZ':
                continue
            negara.setdefault(kode, []).extend(str(c) for c in ipaddress.summarize_address_range(a, b))
    os.unlink(gz)
    if len(negara) < 150 or sum(len(v) for v in negara.values()) < 100000:
        raise RuntimeError('daftar negara tidak masuk akal (%d negara): unduhan rusak?' % len(negara))
    data = [{'brief': k, 'ips': v} for k, v in sorted(negara.items())]
    with open(tmp, 'w') as f:
        json.dump(data, f, separators=(',', ':'))
    atomik(tmp, os.path.join(GEO_DIR, 'GeoLite2-Country.json'))
    return bln, len(data)


def status():
    out = {}
    for n in ('GeoLite2-City.mmdb', 'GeoLite2-Country.json'):
        p = os.path.join(GEO_DIR, n)
        out[n] = {'ada': os.path.isfile(p), 'ukuran': os.path.getsize(p) if os.path.isfile(p) else 0,
                  'diubah': int(os.path.getmtime(p)) if os.path.isfile(p) else 0}
    return out


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    os.makedirs(GEO_DIR, exist_ok=True)
    os.chmod(GEO_DIR, 0o755)
    if cmd == 'status':
        print(json.dumps(status(), indent=2))
        return 0
    if cmd != 'update':
        print('pakai: sentinel-geo.py update | status')
        return 2
    rc = 0
    try:
        print('city mmdb: DB-IP %s' % update_mmdb())
    except Exception as e:
        print('GAGAL city mmdb: %s' % e, file=sys.stderr)
        rc = 1
    try:
        bln, n = update_country_json()
        print('negara json: DB-IP %s (%d negara)' % (bln, n))
    except Exception as e:
        print('GAGAL negara json: %s' % e, file=sys.stderr)
        rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
