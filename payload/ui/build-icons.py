#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Saring layui.css menjadi layui-icon.css: hanya font ikon + kelas .layui-icon-* + animasi putar.

Tujuan: dasbor memakai ikon `layui-icon` yang di aaPanel disediakan panel; di UI standalone ikon itu harus ikut terbundel
tanpa membawa gaya komponen layui lain (tombol, form, dll.) yang akan menimpa tampilan dasbor.
Pemakaian: build-icons.py <layui.css> <keluaran layui-icon.css>
"""
import re
import sys

src = open(sys.argv[1], encoding='utf-8').read()
icons = re.findall(r'\.layui-icon-[a-z0-9-]+:before\{content:"\\[0-9a-f]+"\}', src)
base = re.search(r'\.layui-icon\{[^}]*\}', src).group(0)
rot = re.search(r'@keyframes layui-rotate\{[^}]*\{[^}]*\}[^}]*\{[^}]*\}\}', src)
anim = [re.search(p, src).group(0) for p in (r'\.layui-anim\{[^}]*\}', r'\.layui-anim-rotate\{[^}]*\}', r'\.layui-anim-loop\{[^}]*\}')]
if not icons or not rot:
    sys.exit('layui.css tidak memuat ikon/animasi yang diharapkan')
face = ('@font-face{font-family:layui-icon;src:url(font/iconfont.woff2) format("woff2"),url(font/iconfont.woff) format("woff"),'
        'url(font/iconfont.ttf) format("truetype");font-weight:normal;font-style:normal;font-display:block}')
out = ['/* Dibangkitkan oleh ui/build-icons.py dari layui 2.9.16 (MIT). Jangan disunting tangan. */', face, base]
out += icons + [rot.group(0)] + anim
open(sys.argv[2], 'w', encoding='utf-8').write('\n'.join(out) + '\n')
print('%d ikon -> %s' % (len(icons), sys.argv[2]))
