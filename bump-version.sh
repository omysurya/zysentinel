#!/bin/bash
# ==============================================================================
# bump-version.sh: pembungkus kompatibilitas untuk versi.py (sumber tunggal versi, diturunkan dari nama cabang).
#
# Alur yang dianjurkan:   git checkout -b release/vX.Y.Z && python3 versi.py terapkan
# Pemakaian lama tetap:   bash bump-version.sh [X.Y.Z] [--dry-run] [--backend A.B.C] [--paksa]
#   (= python3 versi.py terapkan ...; tanpa X.Y.Z versi diambil dari cabang rilis; X.Y.Z wajib sama dengan cabang rilis)
# ==============================================================================
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/versi.py" terapkan "$@"
