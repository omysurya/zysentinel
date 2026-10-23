#!/bin/bash
# ==============================================================================
# build-release.sh — Skrip Pembangun Paket Rilis Bersih ZySentinel
#
# Mem-package seluruh komponen proyek menjadi 'sentinel.zip' siap upload
# ke aaPanel App Store (Import Plugin) dan siap diunggah ke GitHub Releases.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Versi: sumber tunggal info.json (ditanam versi.py dari nama cabang rilis release/vX.Y.Z); argumen 1 hanya boleh sama.
INFO_VERSION="$(python3 "$SCRIPT_DIR/versi.py" sekarang)"
VERSION="${1:-$INFO_VERSION}"
[ "$VERSION" = "$INFO_VERSION" ] || { echo "[GAGAL] versi $VERSION tidak sama dengan info.json ($INFO_VERSION): python3 versi.py terapkan" >&2; exit 1; }
python3 "$SCRIPT_DIR/versi.py" periksa || { echo "[GAGAL] string versi tidak konsisten: python3 versi.py terapkan" >&2; exit 1; }
OUT_DIR="${2:-/www/backup}"
STAGE_DIR="/tmp/sentinel_build_staging"

echo "===================================================================="
echo " [ZySentinel] Membangun Paket Distribusi Bersih (Versi: v${VERSION})"
echo "===================================================================="

# 0. Edisi Free: tidak ada mode lisensi; semua fitur edisi ini tersedia tanpa server lisensi.
LIC_OPEN=1
echo "[*] Edisi Free (https://github.com/omysurya/zysentinel)"

# 1. Biner guardd dikompilasi dari SUMBER (hardening) dan diberi stempel hash sumber.
#    Dulu biner payload hanya disalin dari server yang sedang berjalan sehingga
#    rilis bisa membawa biner basi tanpa perbaikan keamanan terbaru.
SRC_C="$SCRIPT_DIR/payload/guardd.c"
if command -v gcc >/dev/null 2>&1 && [ -f /usr/include/sqlite3.h ]; then
    echo "[*] Mengompilasi payload/guardd dari guardd.c (canary, PIE, RELRO)..."
    gcc -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now \
        -o "$SCRIPT_DIR/payload/guardd" "$SRC_C" -lsqlite3 -lm
    chmod 755 "$SCRIPT_DIR/payload/guardd"
    sha256sum "$SRC_C" | awk '{print $1}' > "$SCRIPT_DIR/payload/guardd.srchash"
elif [ "$(sha256sum "$SRC_C" | awk '{print $1}')" != "$(cat "$SCRIPT_DIR/payload/guardd.srchash" 2>/dev/null)" ]; then
    echo "[!] gcc/sqlite3.h tidak ada dan payload/guardd tidak cocok dengan guardd.c; rilis dibatalkan" >&2
    exit 1
fi


# 1b. Penjaga: update_zip aaPanel memilih folder TERAKHIR (urutan os.walk)
#     yang berisi info.json + install.sh. Bila payload/ juga punya keduanya,
#     panel memasang payload/ sebagai plugin dan installer kehilangan payload.
if [ -f "$SCRIPT_DIR/payload/info.json" ]; then
    echo "[!] payload/info.json tidak boleh ada (aaPanel akan salah memilih folder plugin)" >&2
    exit 1
fi

# 2. Siapkan direktori staging
echo "[*] Menyiapkan struktur direktori staging..."
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/sentinel"

# 3. Salin berkas bersih tanpa sampah (*.bak, *.pyc, __pycache__)
rsync -rltD --exclude='.git' \
            --exclude='.github' \
            --exclude='*.bak.*' \
            --exclude='*.bak' \
            --exclude='__pycache__' \
            --exclude='*.pyc' \
            --exclude='*.orig' \
            --exclude='*.rej' \
            --exclude='coraza-cache' \
            --exclude='build-release.sh' \
            --exclude='release-pro.sh' \
            --exclude='bump-version.sh' \
            --exclude='versi.py' \
            --exclude='release_notes.py' \
            --exclude='release-notes' \
            --exclude='release-all.sh' \
            --exclude='CONTRIBUTING.md' \
            --exclude='edition' \
            --exclude='tests' \
            "$SCRIPT_DIR/" "$STAGE_DIR/sentinel/"


# 4. Pastikan izin eksekusi berkas skrip & library
chmod 755 "$STAGE_DIR/sentinel/install.sh"
chmod 755 "$STAGE_DIR/sentinel/payload"/*.sh \
          "$STAGE_DIR/sentinel/payload"/*.py \
          "$STAGE_DIR/sentinel/payload"/guardctl 2>/dev/null || true
[ -f "$STAGE_DIR/sentinel/payload/guardd" ] && chmod 755 "$STAGE_DIR/sentinel/payload/guardd" || true
find "$STAGE_DIR/sentinel/payload/systemd" -type f -exec chmod 644 {} + 2>/dev/null || true
[ -f "$STAGE_DIR/sentinel/payload/init.d/sentinel" ] && chmod 755 "$STAGE_DIR/sentinel/payload/init.d/sentinel" || true

# 5. Kompresi menjadi ZIP resmi
mkdir -p "$OUT_DIR"
TARGET_ZIP="$OUT_DIR/sentinel.zip"
VERSIONED_ZIP="$OUT_DIR/zysentinel-v${VERSION}.zip"
# Rilis ENFORCE (Pro) memakai nama BERBEDA supaya tidak pernah tertukar dengan aset garis publik: zysentinel-pro-vX.Y.Z.zip

echo "[*] Mengompresi paket ke $TARGET_ZIP..."
rm -f "$TARGET_ZIP" "$VERSIONED_ZIP" "/tmp/sentinel.zip"
(cd "$STAGE_DIR" && zip -r -9 "$TARGET_ZIP" sentinel/ >/dev/null)
cp -f "$TARGET_ZIP" "$VERSIONED_ZIP"
cp -f "$TARGET_ZIP" "/tmp/sentinel.zip"

# 6. Hitung Checksum (SHA256SUMS.txt memuat berkas bernama versi; pembaruan klien membacanya dari aset rilis)
SHA256="$(sha256sum "$TARGET_ZIP" | cut -d' ' -f1)"
( cd "$OUT_DIR" && sha256sum "$(basename "$VERSIONED_ZIP")" > SHA256SUMS.txt )
ZIP_SIZE="$(ls -lh "$TARGET_ZIP" | awk '{print $5}')"

# 7. Bersihkan staging
rm -rf "$STAGE_DIR"

echo "===================================================================="
echo " [OK] Paket rilis berhasil dibuat!"
echo "      - Lokasi Utama : $TARGET_ZIP (${ZIP_SIZE})"
echo "      - Versi Rilis  : $VERSIONED_ZIP"
echo "      - SHA-256      : $SHA256"
echo "===================================================================="
echo " CARA PAKAI:"
echo " 1. Unggah berkas 'sentinel.zip' ke menu aaPanel:"
echo "    App Store -> Third-party plugin -> Import / Upload Plugin."
echo " 2. aaPanel akan otomatis mengekstrak dan menjalankan setup mandiri."
echo "===================================================================="
