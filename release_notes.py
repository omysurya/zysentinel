#!/usr/bin/env python3
# ==============================================================================
# release_notes.py: release notes WAJIB per versi (fitur, perbaikan, fix bug, cara download, install, update).
#
# Sumber per versi (ditulis tangan, satu berkas per versi):
#   release-notes/vX.Y.Z.md       bagian umum, aman untuk publik (ikut ke repositori Free)
#   release-notes/vX.Y.Z.pro.md   tambahan khusus Pro (opsional; dibuang saat export Free lewat edition/PRO-FILES.txt)
# Bagian wajib di sumber (judul persis, isi minimal satu butir "- ..."; tulis "- Tidak ada." bila memang kosong):
#   ## ✨ Fitur Baru
#   ## 🔧 Perbaikan & Peningkatan
#   ## 🐛 Fix Bug
# Bagian opsional: ## 🔒 Keamanan
# Bagian Download, Install, dan Update DIBANGKITKAN otomatis per edisi (nama aset, tag, dan URL benar), tidak ditulis tangan.
#
# Pemakaian:
#   python3 release_notes.py periksa X.Y.Z --edisi free|pro        gagal (kode 1) bila sumber tidak ada/tidak lengkap
#   python3 release_notes.py buat X.Y.Z --edisi free|pro [--out F]  cetak release notes lengkap (Markdown)
# Gerbang: release-pro.sh, release-all.sh, dan CI release Free menolak release tanpa catatan yang lengkap.
# Uji: tests/release_notes_test.sh.
# ==============================================================================
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(HERE, "release-notes")
REPO_RELEASE = "omysurya/zysentinel"
SITUS = "https://zysens.com"
WAJIB = ["✨ Fitur Baru", "🔧 Perbaikan & Peningkatan", "🐛 Fix Bug"]
OPSIONAL = ["🔒 Keamanan"]
SEMUA = WAJIB + OPSIONAL
PENGISI = re.compile(r"\b(TODO|TBD|xxx|lorem ipsum)\b|\.\.\.\s*$", re.I)


def gagal(pesan):
    print("[GAGAL] " + pesan, file=sys.stderr)
    sys.exit(1)


def bagian(teks, sumber):
    """{judul: [butir]} dari berkas sumber; galat bila ada judul tak dikenal."""
    hasil, cur, salah = {}, None, []
    for no, ln in enumerate(teks.splitlines(), 1):
        if ln.startswith("## "):
            cur = ln[3:].strip()
            if cur not in SEMUA:
                salah.append("%s:%d: judul bagian tidak dikenal '%s' (boleh: %s)" % (sumber, no, cur, ", ".join(SEMUA)))
            hasil.setdefault(cur, [])
        elif ln.startswith("- ") and cur:
            hasil[cur].append(ln[2:].rstrip())
        elif ln.startswith("  ") and cur and hasil.get(cur):
            hasil[cur][-1] += "\n  " + ln.strip()          # lanjutan butir
        elif ln.strip() and not ln.startswith(("# ", ">")) and cur:
            salah.append("%s:%d: baris di luar butir '- ...'" % (sumber, no))
    return hasil, salah


def muat(versi, edisi):
    versi = versi.lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", versi):
        gagal("versi harus X.Y.Z (bukan '%s')" % versi)
    if edisi not in ("free", "pro"):
        gagal("--edisi harus free atau pro")
    umum = os.path.join(DIR, "v%s.md" % versi)
    if not os.path.isfile(umum):
        gagal("release notes release-notes/v%s.md tidak ada: tulis fitur, perbaikan, dan fix bug versi ini dulu" % versi)
    isi, salah = bagian(open(umum, encoding="utf-8").read(), os.path.relpath(umum, HERE))
    judul = None
    for ln in open(umum, encoding="utf-8"):
        if ln.startswith("# "):
            judul = ln[2:].strip()
            break
    pro = os.path.join(DIR, "v%s.pro.md" % versi)
    if edisi == "pro" and os.path.isfile(pro):
        tambah, s2 = bagian(open(pro, encoding="utf-8").read(), os.path.relpath(pro, HERE))
        salah += s2
        for k, v in tambah.items():
            isi.setdefault(k, [])
            isi[k] = v + isi[k]                              # butir khusus Pro di atas butir umum
    for k in WAJIB:
        if not isi.get(k):
            salah.append("bagian wajib '## %s' tidak ada atau kosong (tulis '- Tidak ada.' bila memang tidak ada)" % k)
    for k, v in isi.items():
        for b in v:
            if PENGISI.search(b):
                salah.append("butir pengisi di '%s': %s" % (k, b[:80]))
    if salah:
        gagal("release notes v%s (%s) tidak lengkap:\n  " % (versi, edisi) + "\n  ".join(salah))
    return versi, judul, isi


def download_install(versi, edisi):
    tag = ("pro-v%s" if edisi == "pro" else "v%s") % versi
    url = "https://github.com/%s/releases/download/%s" % (REPO_RELEASE, tag)
    zipn = "zysentinel-pro-v%s.zip" % versi if edisi == "pro" else "sentinel.zip"
    out = ["### 📥 Cara Download", ""]
    if edisi == "pro":
        out += ["1. Unduh `%s`, `SHA256SUMS.txt`, dan `SHA256SUMS.txt.sig` dari daftar aset di bawah." % zipn,
                "2. Verifikasi integritas: `sha256sum -c SHA256SUMS.txt --ignore-missing` harus mencetak `%s: OK`." % zipn,
                "3. `SHA256SUMS.txt.sig` adalah tanda tangan release resmi; pembaruan dari dalam plugin memverifikasinya otomatis."]
    else:
        out += ["1. Unduh `sentinel.zip` dan `SHA256SUMS.txt` dari daftar aset di bawah (`zysentinel-v%s.zip` berisi paket yang sama)." % versi,
                "2. Verifikasi integritas: `sha256sum -c SHA256SUMS.txt --ignore-missing` harus mencetak `sentinel.zip: OK`."]
    out += ["", "### 🛠️ Cara Install", "",
            "**Lewat aaPanel:** App Store → tab **Third-party plugin** → **Import Plugin** → pilih `%s`. "
            "aaPanel mengekstrak paket dan menjalankan `install.sh` otomatis." % zipn, "",
            "**Lewat terminal (root):**", "", "```bash",
            "curl -fsSL -o /tmp/%s %s/%s" % (zipn, url, zipn),
            "cd /tmp && sha256sum %s   # cocokkan dengan SHA256SUMS.txt" % zipn,
            "unzip -q -o /tmp/%s -d /www/server/panel/plugin/" % zipn,
            "bash /www/server/panel/plugin/sentinel/install.sh install", "```", ""]
    if edisi == "pro":
        out += ["**Aktivasi:** buka ZySentinel di panel → lencana paket di kanan atas → masukkan kode lisensi `ZYS-...`. "
                "Tanpa kode, plugin berjalan sebagai paket Free.", ""]
    out += ["### ⬆️ Cara Update", "",
            "Buka ZySentinel di panel → klik lencana versi (atau **Setting → Maintenance**) → **Cek & Update**%s. "
            "Alternatif: ulangi langkah install di atas; konfigurasi, daftar putih, dan data tetap dipertahankan." %
            (" (kanal Pro: hanya release bertanda tangan resmi yang dipasang)" if edisi == "pro" else ""), ""]
    return out


def buat(versi, edisi):
    versi, judul, isi = muat(versi, edisi)
    nama = "ZySentinel Pro" if edisi == "pro" else "ZySentinel"
    out = ["## %s v%s%s" % (nama, versi, (": " + judul) if judul else ""), ""]
    for k in SEMUA:
        if isi.get(k):
            out += ["### " + k, ""] + ["- " + b for b in isi[k]] + [""]
    out += download_install(versi, edisi)
    if edisi == "free":
        out += ["### ✨ Segera Hadir: ZySentinel Pro & Max", "",
                "Fitur kelas enterprise sudah terlihat di panel Anda dengan lencana **SOON**: pemblokiran otomatis, "
                "WAF untuk semua situs, Upload Protection realtime, Webshell Sweeper, pemindai memori PHP2Shell, "
                "Self-Heal, Threat Intel otomatis, notifikasi webhook, dan banyak lagi. Ikuti kabarnya di **%s**." % SITUS, "",
                "*Coming soon: ZySentinel Pro & Max. Enterprise-grade features are already visible in your panel with a "
                "**SOON** badge. Follow the launch at %s.*" % SITUS, ""]
    else:
        out += ["Kode sumber Pro tidak dipublikasikan; paket ini adalah build berlisensi (mode ENFORCE). Info paket: **%s**." % SITUS, ""]
    return "\n".join(out).rstrip() + "\n"


def main(argv):
    if len(argv) < 2 or argv[0] in ("-h", "--help"):
        kepala = open(os.path.abspath(__file__), encoding="utf-8").read().split("# ====")[1].split("\n", 1)[1]
        print(re.sub(r"^# ?", "", kepala, flags=re.M).rstrip("=\n"))
        return 0 if argv and argv[0] in ("-h", "--help") else 64
    perintah, versi, sisa = argv[0], argv[1], argv[2:]
    edisi, out = "free", None
    i = 0
    while i < len(sisa):
        if sisa[i] == "--edisi" and i + 1 < len(sisa):
            edisi = sisa[i + 1]; i += 2
        elif sisa[i] == "--out" and i + 1 < len(sisa):
            out = sisa[i + 1]; i += 2
        else:
            gagal("argumen tidak dikenal: " + sisa[i])
    if perintah == "periksa":
        v, _, isi = muat(versi, edisi)
        print("OK release notes v%s (%s): %s" % (v, edisi, ", ".join("%s %d" % (k.split(" ", 1)[1], len(isi.get(k, []))) for k in SEMUA if isi.get(k))))
    elif perintah == "buat":
        teks = buat(versi, edisi)
        if out:
            with open(out, "w", encoding="utf-8") as f:
                f.write(teks)
        else:
            sys.stdout.write(teks)
    else:
        gagal("perintah tidak dikenal: %s (periksa|buat)" % perintah)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
