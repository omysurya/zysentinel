#!/bin/bash
# ==============================================================================
# build-release.sh — Skrip Pembangun Paket Rilis Bersih ZySentinel
#
# Mem-package seluruh komponen proyek menjadi 'sentinel.zip' siap upload
# ke aaPanel App Store (Import Plugin) dan siap diunggah ke GitHub Releases.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${1:-$(grep -o '"versions": "[^"]*"' "$SCRIPT_DIR/info.json" | cut -d'"' -f4 || echo "1.6.1")}"
OUT_DIR="${2:-/www/backup}"
STAGE_DIR="/tmp/sentinel_build_staging"

echo "===================================================================="
echo " [ZySentinel] Membangun Paket Distribusi Bersih (Versi: v${VERSION})"
echo "===================================================================="

# 1. Pastikan biner precompiled guardd tersedia di payload
if [ -f "/www/server/sentinel/bin/guardd" ] && [ ! -f "$SCRIPT_DIR/payload/guardd" ]; then
    echo "[*] Menyinkronkan biner guardd ke payload/..."
    cp -p "/www/server/sentinel/bin/guardd" "$SCRIPT_DIR/payload/guardd"
    chmod 755 "$SCRIPT_DIR/payload/guardd"
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
            --exclude='build-release.sh' \
            --exclude='tests' \
            "$SCRIPT_DIR/" "$STAGE_DIR/sentinel/"

# 4. Pastikan izin eksekusi berkas skrip
chmod 755 "$STAGE_DIR/sentinel/install.sh"
chmod 755 "$STAGE_DIR/sentinel/payload"/*.sh \
          "$STAGE_DIR/sentinel/payload"/*.py \
          "$STAGE_DIR/sentinel/payload"/guardctl 2>/dev/null || true
[ -f "$STAGE_DIR/sentinel/payload/guardd" ] && chmod 755 "$STAGE_DIR/sentinel/payload/guardd" || true

# 5. Kompresi menjadi ZIP resmi
mkdir -p "$OUT_DIR"
TARGET_ZIP="$OUT_DIR/sentinel.zip"
VERSIONED_ZIP="$OUT_DIR/zysentinel-v${VERSION}.zip"

echo "[*] Mengompresi paket ke $TARGET_ZIP..."
(cd "$STAGE_DIR" && zip -r -9 "$TARGET_ZIP" sentinel/ >/dev/null)
cp -f "$TARGET_ZIP" "$VERSIONED_ZIP"
cp -f "$TARGET_ZIP" "/tmp/sentinel.zip"

# 6. Hitung Checksum
SHA256="$(sha256sum "$TARGET_ZIP" | cut -d' ' -f1)"
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
