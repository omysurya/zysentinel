#!/usr/bin/env python3
# ==============================================================================
# versi.py: SUMBER TUNGGAL versi plugin ZySentinel, diturunkan dari NAMA CABANG git.
#
# Aturan: cabang rilis bernama  release/vX.Y.Z  (repositori Pro) atau  vX.Y.Z  (repositori Free hasil ekspor).
# Versi ditanam ke info.json (dibaca aaPanel dan semua kode runtime) dan ke sedikit tempat yang memang harus
# statis (DAFTAR di bawah). Kode runtime TIDAK menyimpan literal versi: Python membaca info.json (_versi_plugin),
# index.html memakai konstanta SN_VERSI, pemasang membaca info.json.
#
# Pemakaian:
#   python3 versi.py cabang                          cetak X.Y.Z dari cabang rilis saat ini (kode 2 bila bukan cabang rilis)
#   python3 versi.py sekarang                        cetak versi di info.json
#   python3 versi.py terapkan [X.Y.Z] [--dry-run] [--backend A.B.C] [--paksa]
#                                                    tanam versi (bawaan: dari cabang) ke semua tempat; idempoten;
#                                                    menolak versi mundur kecuali --paksa
#   python3 versi.py periksa [--cabang]              gagal bila satu tempat berbeda dari info.json atau ada literal versi
#                                                    di luar DAFTAR; --cabang: info.json juga wajib = versi cabang rilis
# Lingkungan: ZYS_CABANG menggantikan nama cabang git (CI dengan HEAD terlepas, salinan tanpa .git).
# Uji: tests/versi_test.sh.
# ==============================================================================
import datetime
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEMVER = r"\d+\.\d+\.\d+"
POLA_CABANG = re.compile(r"^(?:release/)?v(%s)$" % SEMVER)

# Tempat versi yang harus statis: (berkas, regex dengan grup bernama 'v', jumlah kemunculan; 0 = minimal satu).
# Menambah literal versi baru di kode? Jangan: baca info.json / SN_VERSI. Bila memang harus statis, daftarkan di sini.
DAFTAR = [
    ("info.json", r'"versions": *"(?P<v>%s)"' % SEMVER, 1),
    ("sentinel_license.py", r'^VERSION = "(?P<v>%s)"' % SEMVER, 1),
    ("payload/sentinel_license.py", r'^VERSION = "(?P<v>%s)"' % SEMVER, 1),
    ("payload/guardd.c", r'^#define VERSION "v(?P<v>%s)"' % SEMVER, 1),
    (".github/workflows/release.yml", r"default: 'v(?P<v>%s)'" % SEMVER, 1),
]
for _h in ("index.html", "payload/index.html"):
    DAFTAR += [
        (_h, r"^var SN_VERSI = '(?P<v>%s)';" % SEMVER, 1),           # konstanta JS: sumber semua teks versi di UI
        (_h, r"ico-sentinel\.png\?v=(?P<v>%s)" % SEMVER, 0),          # pemecah cache ikon (HTML statis)
        (_h, r'class="sn-brand-sub">ZYSENTINEL v(?P<v>%s)<' % SEMVER, 1),  # teks awal sebelum JS berjalan
        (_h, r'id="snVerBadge"[^\n]*?>v(?P<v>%s)</span>' % SEMVER, 1),
        (_h, r'id="snUpdStatusTxt"[^>]*>Versi: v(?P<v>%s)<' % SEMVER, 1),
    ]
for _r in ("README.md", "payload/README.md"):
    DAFTAR.append((_r, r"(?<![\d.])(?P<v>%s)(?![\d])" % SEMVER, 0))  # README: SEMUA X.Y.Z = versi plugin
BACKEND = ("../_backend/zyslic/__init__.py", r'^__version__ = "(?P<v>%s)"' % SEMVER)
# Pemindaian literal liar: berkas teks di _client selain ini tidak boleh memuat versi saat ini secara harfiah.
LEWATI_DIR = {".git", "tests", "edition", "__pycache__", "coraza-cache"}
LEWATI_AKHIRAN = (".orig", ".rej", ".png", ".jpg", ".ico", ".gz", ".zip", ".srchash", ".hex")


def gagal(pesan, kode=1):
    print("[GAGAL] " + pesan, file=sys.stderr)
    sys.exit(kode)


def semver(v):
    return tuple(int(x) for x in v.split("."))


def baca(rel):
    with open(os.path.join(HERE, rel), encoding="utf-8") as f:
        return f.read()


def nama_cabang():
    c = os.environ.get("ZYS_CABANG", "").strip()
    if c:
        return c
    try:
        out = subprocess.run(["git", "-C", HERE, "rev-parse", "--abbrev-ref", "HEAD"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def versi_cabang():
    """X.Y.Z dari cabang rilis, atau None bila cabang saat ini bukan cabang rilis."""
    m = POLA_CABANG.match(nama_cabang())
    return m.group(1) if m else None


def versi_info():
    m = re.search(DAFTAR[0][1], baca("info.json"))
    if not m:
        gagal("versi di info.json tidak dikenali")
    return m.group("v")


def temuan():
    """[(berkas, nomor baris, versi, regex)] untuk semua tempat di DAFTAR, plus daftar kesalahan struktur."""
    hasil, salah = [], []
    for rel, rx, jumlah in DAFTAR:
        p = os.path.join(HERE, rel)
        if not os.path.isfile(p):
            continue  # mis. .github tidak ada di salinan tertentu
        s = baca(rel)
        cocok = list(re.finditer(rx, s, re.M))
        if (jumlah and len(cocok) != jumlah) or not cocok:
            salah.append("%s: pola %r ditemukan %d kali (harus %s)" % (rel, rx, len(cocok), jumlah or ">= 1"))
        for m in cocok:
            hasil.append((rel, s.count("\n", 0, m.start("v")) + 1, m.group("v"), rx))
    return hasil, salah


def literal_liar(versi, dikenal):
    """Kemunculan harfiah versi di berkas teks _client yang TIDAK tercakup DAFTAR (literal baru yang lupa didaftarkan)."""
    pola = re.compile(r"(?<![\d.])v?%s(?![\d])" % re.escape(versi))
    liar = []
    for akar, dirs, files in os.walk(HERE):
        dirs[:] = [d for d in dirs if d not in LEWATI_DIR]
        for nm in files:
            if nm.endswith(LEWATI_AKHIRAN) or ".bak" in nm:
                continue
            p = os.path.join(akar, nm)
            rel = os.path.relpath(p, HERE)
            try:
                with open(p, encoding="utf-8") as f:
                    isi = f.read()
            except (UnicodeDecodeError, OSError):
                continue  # biner
            for i, ln in enumerate(isi.splitlines(), 1):
                if pola.search(ln) and (rel, i) not in dikenal:
                    liar.append("%s:%d: %s" % (rel, i, ln.strip()[:120]))
    return liar


def periksa(wajib_cabang=False, diam=False):
    target = versi_info()
    hasil, salah = temuan()
    beda = ["%s:%d versi %s" % (rel, n, v) for rel, n, v, _ in hasil if v != target]
    liar = literal_liar(target, {(rel, n) for rel, n, _, _ in hasil})
    vc = versi_cabang()
    if vc and vc != target:
        salah.append("cabang %s menunjuk %s tetapi info.json %s: jalankan  python3 versi.py terapkan" % (nama_cabang(), vc, target))
    elif not vc and wajib_cabang:
        salah.append("cabang '%s' bukan cabang rilis (release/vX.Y.Z); rilis hanya dari cabang rilis" % (nama_cabang() or "?"))
    for daftar, judul in ((salah, "kesalahan"), (beda, "versi berbeda dari info.json %s" % target),
                          (liar, "literal versi di luar DAFTAR versi.py (baca info.json/SN_VERSI, atau daftarkan)")):
        if daftar:
            print("[!] %s:" % judul, file=sys.stderr)
            for x in daftar:
                print("    " + x, file=sys.stderr)
    if salah or beda or liar:
        gagal("versi tidak konsisten (%d kesalahan, %d berbeda, %d literal liar)" % (len(salah), len(beda), len(liar)))
    if not diam:
        print("OK versi %s konsisten di %d tempat (%d berkas)%s" % (
            target, len(hasil), len({h[0] for h in hasil}),
            ", cabang %s" % nama_cabang() if vc else " (bukan cabang rilis: pemeriksaan cabang dilewati)"))


def terapkan(baru, dry, be, paksa):
    vc = versi_cabang()
    if not baru:
        if not vc:
            gagal("cabang '%s' bukan cabang rilis (release/vX.Y.Z); sebutkan versi atau pindah cabang" % (nama_cabang() or "?"))
        baru = vc
    baru = baru.lstrip("v")
    if not re.fullmatch(SEMVER, baru):
        gagal("versi harus X.Y.Z (bukan '%s')" % baru)
    if vc and vc != baru:
        gagal("versi %s berbeda dari cabang rilis %s (%s)" % (baru, vc, nama_cabang()))
    lama = versi_info()
    if semver(baru) < semver(lama) and not paksa:
        gagal("versi baru %s lebih rendah dari %s (pakai --paksa bila memang mundur)" % (baru, lama))
    total, ubah = 0, []
    isi = {}
    for rel, rx, _ in DAFTAR:
        if os.path.isfile(os.path.join(HERE, rel)):
            isi.setdefault(rel, baca(rel))
    for rel, rx, _ in DAFTAR:
        if rel not in isi:
            continue
        n = [0]

        def ganti(m):
            if m.group("v") == baru:
                return m.group(0)
            n[0] += 1
            a, b = m.span("v")
            return m.group(0)[:a - m.start()] + baru + m.group(0)[b - m.start():]
        isi[rel] = re.sub(rx, ganti, isi[rel], flags=re.M)
        total += n[0]
    if lama != baru:
        isi["info.json"] = re.sub(r'("date": *")[^"]*(")', r"\g<1>%s\g<2>" % datetime.date.today().isoformat(), isi["info.json"], count=1)
    for rel, s in isi.items():
        if s != baca(rel):
            ubah.append(rel)
            print("  %-34s diubah" % rel)
            if not dry:
                with open(os.path.join(HERE, rel), "w", encoding="utf-8") as f:
                    f.write(s)
    if be:
        if not re.fullmatch(SEMVER, be):
            gagal("versi backend harus X.Y.Z")
        p = os.path.normpath(os.path.join(HERE, BACKEND[0]))
        with open(p, encoding="utf-8") as f:
            s = f.read()
        s2 = re.sub(BACKEND[1], lambda m: m.group(0).replace(m.group("v"), be), s, count=1, flags=re.M)
        print("  %-34s backend -> %s" % ("_backend/zyslic/__init__.py", be))
        if s2 != s and not dry:
            with open(p, "w", encoding="utf-8") as f:
                f.write(s2)
    print("%s: %s -> %s, %d tempat di %d berkas" % ("RENCANA (dry-run)" if dry else "SELESAI", lama, baru, total, len(ubah)))
    if dry:
        return
    periksa(diam=False)
    if "payload/guardd.c" in ubah:
        print("  catatan: guardd.c berubah; build-release.sh menyusun ulang payload/guardd dan memperbarui guardd.srchash")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        kepala = open(os.path.abspath(__file__), encoding="utf-8").read().split("# ====")[1].split("\n", 1)[1]
        print(re.sub(r"^# ?", "", kepala, flags=re.M).rstrip("=\n"))
        return
    perintah, sisa = argv[0], argv[1:]
    if perintah == "cabang":
        v = versi_cabang()
        if not v:
            gagal("cabang '%s' bukan cabang rilis (release/vX.Y.Z)" % (nama_cabang() or "?"), 2)
        print(v)
    elif perintah == "sekarang":
        print(versi_info())
    elif perintah == "periksa":
        periksa(wajib_cabang="--cabang" in sisa)
    elif perintah == "terapkan":
        baru, dry, be, paksa = "", False, "", False
        i = 0
        while i < len(sisa):
            a = sisa[i]
            if a == "--dry-run":
                dry = True
            elif a == "--paksa":
                paksa = True
            elif a == "--backend":
                i += 1
                be = sisa[i] if i < len(sisa) else gagal("--backend butuh A.B.C", 64)
            elif a.startswith("-"):
                gagal("argumen tidak dikenal: " + a, 64)
            else:
                baru = a
            i += 1
        terapkan(baru, dry, be, paksa)
    else:
        gagal("perintah tidak dikenal: %s (cabang|sekarang|terapkan|periksa)" % perintah, 64)


if __name__ == "__main__":
    main(sys.argv[1:])
