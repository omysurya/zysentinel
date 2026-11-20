#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Bangkitkan ui-allowlist.json: metode publik plugin yang disebut UI.

Tujuan defensif: sentinel-uid menolak metode di luar daftar ini (metode berawalan `_`, internal, atau yang tidak ada di plugin).
Daftar = irisan (a) nama metode publik kelas sentinel_main (dibaca lewat ast, tanpa menjalankan kode) dengan (b) literal string
di index.html. Irisan dipakai karena UI memanggil metode juga lewat pembungkus (snTabelMuat, kirim, snCzRun, ternary), bukan hanya
snAjax('...'). Literal yang bukan nama metode (nilai argumen `service_action`, dsb.) disaring lewat NAMA_BUKAN_METODE.
Pemakaian: gen-ui-allowlist.py [index.html] [sentinel_main.py] [keluaran.json]   (--check: verifikasi saja)
"""
import ast
import json
import os
import re
import sys

# Kata yang kebetulan sama dengan nama metode publik, tetapi di UI hanya nilai argumen (mis. snSvc('start') -> service_action).
NAMA_BUKAN_METODE = frozenset(('start', 'stop', 'restart', 'reload', 'rescan'))

here = os.path.dirname(os.path.abspath(__file__))
args = [a for a in sys.argv[1:] if not a.startswith('--')]
html_p = args[0] if args else os.path.join(here, 'index.html')
main_p = args[1] if len(args) > 1 else os.path.join(here, 'sentinel_main.py')
dst = args[2] if len(args) > 2 else os.path.join(here, 'ui-allowlist.json')

tree = ast.parse(open(main_p, encoding='utf-8').read())
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'sentinel_main')
publik = {f.name for f in cls.body if isinstance(f, ast.FunctionDef) and not f.name.startswith('_')}
literal = set(re.findall(r"""['"]([a-z][a-z0-9_]{1,63})['"]""", open(html_p, encoding='utf-8').read()))
names = sorted((publik & literal) - NAMA_BUKAN_METODE)
out = json.dumps(names, indent=1) + '\n'
if '--check' in sys.argv:
    cur = open(dst).read() if os.path.isfile(dst) else ''
    if cur != out:
        sys.exit('ui-allowlist.json tidak sinkron dengan index.html/sentinel_main.py (jalankan gen-ui-allowlist.py)')
    print('ui-allowlist.json sinkron (%d metode)' % len(names))
else:
    with open(dst, 'w') as f:
        f.write(out)
    print('%d metode -> %s' % (len(names), dst))
