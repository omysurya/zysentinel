#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
# Unduh aset pihak ketiga untuk UI standalone (saat build rilis, bukan saat pemasangan di server pelanggan).
# Versi dikunci dan setiap berkas diverifikasi terhadap assets.sha256; ketidakcocokan = gagal (rantai pasok).
# Lisensi: jQuery MIT, layer MIT, ECharts Apache-2.0, world.json (ECharts 4.9.0, data Natural Earth domain publik). Lihat THIRD-PARTY-NOTICES.md.
# Pemakaian: fetch-assets.sh            (unduh + verifikasi)
#            fetch-assets.sh --pin      (unduh lalu tulis ulang assets.sha256 setelah ditinjau manusia)
set -euo pipefail
cd "$(dirname "$0")/assets"
mkdir -p layer/theme/default
get() { curl -fsSL --max-time 60 -o "$1" "$2"; }   # tujuan relatif terhadap assets/ (atau mutlak)
L=https://cdn.jsdelivr.net/gh/sentsin/layer@v3.5.1/src
get jquery.min.js https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js
get echarts.min.js https://cdn.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js
get world.json https://cdn.jsdelivr.net/npm/echarts@4.9.0/map/json/world.json
# ikon layui (dipakai dasbor): font + css yang disaring supaya hanya ikon, bukan komponen layui lain
LU=https://cdn.jsdelivr.net/npm/layui@2.9.16/dist
mkdir -p layui/font
get layui/font/iconfont.woff2 "$LU/font/iconfont.woff2"; get layui/font/iconfont.woff "$LU/font/iconfont.woff"; get layui/font/iconfont.ttf "$LU/font/iconfont.ttf"
get /tmp/layui-full.css "$LU/css/layui.css"
python3 ../build-icons.py /tmp/layui-full.css layui/layui-icon.css
get layer/layer.js "$L/layer.js"
for f in layer.css icon.png icon-ext.png loading-0.gif loading-1.gif loading-2.gif; do get "layer/theme/default/$f" "$L/theme/default/$f"; done
LIST="layui/layui-icon.css layui/font/iconfont.woff2 layui/font/iconfont.woff layui/font/iconfont.ttf jquery.min.js echarts.min.js world.json layer/layer.js layer/theme/default/layer.css layer/theme/default/icon.png layer/theme/default/icon-ext.png layer/theme/default/loading-0.gif layer/theme/default/loading-1.gif layer/theme/default/loading-2.gif"
if [ "${1:-}" = "--pin" ]; then
  # shellcheck disable=SC2086
  sha256sum $LIST >assets.sha256
  echo "assets.sha256 diperbarui; tinjau diff-nya sebelum commit." >&2
else
  sha256sum -c assets.sha256
fi
