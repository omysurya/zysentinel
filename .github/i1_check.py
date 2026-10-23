#!/usr/bin/env python3
"""Pemeriksaan invarian I1 repositori ZySentinel FREE: tidak ada berkas, penanda, atau rujukan infrastruktur fitur berbayar (Pro/Max).
DIBANGKITKAN oleh alat ekspor edisi dari sumber tunggal; jangan disunting manual (tertimpa pada rilis berikut). Dipakai juga oleh ekspor itu sendiri.

Pemakaian: python3 .github/i1_check.py [folder]      kode keluar 0 = lulus, 1 = ada pelanggaran (CI menolak push/PR)
Pengecualian: baris komentar yang sekadar menyebut nama komponen, dan baris bertanda "zys-legacy-cleanup" (pembersihan sisa komponen
instalasi lama saat pasang/cabut, bukan implementasi fitur)."""
import fnmatch
import hashlib
import os
import re
import subprocess
import sys

PRO_FILES = ['license_pubkey.hex', 'license_pubkey2.hex', 'release_pubkey.hex', 'LICENSE.pro', 'release-pro.sh', 'release-all.sh', 'release-notes/*.pro.md', 'payload/sentinel-license.c', 'payload/license_core.h', 'payload/license_features.h', 'payload/gen-license-headers.py', 'payload/sentinel-licgate', 'payload/sentinel-license-agent.py', 'payload/sentinel_modpolicy.py', 'payload/systemd/sentinel-license.service', 'payload/systemd/sentinel-license.timer', 'payload/sentinel-memscan', 'payload/sentinel-memscan.c', 'payload/sentinel-memscan.srchash', 'payload/sentinel-sweeper', 'payload/sentinel-sweeper.c', 'payload/sentinel-sweeper.srchash', 'payload/sentinel-sweeper.py', 'payload/sentinel-sweeplib.py', 'payload/systemd/sentinel-sweeper.service', 'payload/systemd/sentinel-sweeper.timer', 'payload/sentinel-upload-scan.py', 'payload/systemd/sentinel-upload-scan.service', 'payload/sentinel-selfheal.py', 'payload/systemd/sentinel-selfheal.service', 'payload/systemd/sentinel-selfheal.timer', 'payload/systemd/sentinel-intel.service', 'payload/systemd/sentinel-intel.timer', 'payload/sentinel-notify.sh', 'payload/notify.conf.default', 'payload/systemd/sentinel-notify.service', 'payload/systemd/sentinel-notify.timer', 'payload/sentinel-sage.py', 'payload/systemd/sentinel-integ.service', 'payload/systemd/sentinel-integ.timer']
LARANGAN = [('ZYS-PRO|ZYS_FREE|^\\s*#FREE\\b', 'penanda edisi tertinggal'), ('sentinel-license(?!-)|sentinel-licgate|sentinel-license-agent|license_core\\.h|license_features\\.h', 'infrastruktur lisensi Pro'), ('\\blic_ok\\b|LIC_F_|verify-module|module_ok|modules_sync|sentinel_modpolicy', 'gerbang/modul lisensi Pro'), ('sentinel-memscan|sentinel-sweeper|sentinel-sweeplib|sentinel-upload-scan|sentinel-selfheal|sentinel-sage|sentinel-intel\\.(?:service|timer)|sentinel-notify', 'komponen berbayar')]
LEWATI = ['.cursorrules', '.github/i1_check.py', '.windsurfrules', 'AGENTS.md', 'CLAUDE.md', 'LICENSE', 'README.md', 'index.html', 'lang.json', 'payload/README.md', 'payload/index.html', 'payload/lang.json', 'payload/telemetry.json', 'telemetry.json']
ABAIKAN_DIR = (".git", "__pycache__", "node_modules", "coraza-cache")
# string yang hanya ada di guardd hasil susun sumber Pro (blokir otomatis dan ban belajar)
GUARDD_PRO = (b"BAN-BELAJAR", b"BAN %s -> %u detik")


def berkas_pro(rel):
    return any(fnmatch.fnmatch(rel, p) or (p.endswith("/*") and rel.startswith(p[:-1])) for p in PRO_FILES)


def periksa(akar):
    err = []
    for root, dirs, files in os.walk(akar):
        dirs[:] = sorted(d for d in dirs if d not in ABAIKAN_DIR)
        for f in sorted(files):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, akar)
            if berkas_pro(rel):
                err.append("berkas Pro ada di edisi Free: " + rel)
            if rel in LEWATI:
                continue
            try:
                teks = open(p, encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            for pol, alasan in LARANGAN:
                for no, b in enumerate(teks.split("\n"), 1):
                    komentar = re.match(r"\s*(#(?!FREE)|//|/?\*)", b) is not None
                    if alasan != "penanda edisi tertinggal" and ("zys-legacy-cleanup" in b or komentar):
                        continue
                    if re.search(pol, b):
                        err.append("%s:%d: %s: %s" % (rel, no, alasan, b.strip()[:120]))
            if f.endswith(".py"):
                try:
                    compile(teks, rel, "exec")
                except SyntaxError as e:
                    err.append("%s: sintaks Python: %s" % (rel, e))
            if f.endswith(".sh"):
                if subprocess.run(["bash", "-n", p], capture_output=True).returncode != 0:
                    err.append("%s: sintaks shell" % rel)
    g = os.path.join(akar, "payload", "guardd")
    if os.path.isfile(g):
        raw = open(g, "rb").read()
        for t in GUARDD_PRO:
            if t in raw:
                err.append("payload/guardd disusun dari sumber Pro (memuat %r)" % t.decode())
        src, cap = os.path.join(akar, "payload", "guardd.c"), os.path.join(akar, "payload", "guardd.srchash")
        if not (os.path.isfile(src) and os.path.isfile(cap)
                and open(cap).read().strip() == hashlib.sha256(open(src, "rb").read()).hexdigest()):
            err.append("payload/guardd.srchash tidak cocok dengan payload/guardd.c")
    return err


if __name__ == "__main__":
    e = periksa(os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "."))
    for x in e:
        print("I1 " + x)
    print("I1: %s (%d masalah)" % ("GAGAL" if e else "LULUS", len(e)))
    sys.exit(1 if e else 0)
