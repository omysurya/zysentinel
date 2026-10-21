#!/bin/bash
# Uji integritas berkas web (anti-tamper) sentinel-av.sh: baseline otomatis, deteksi
# tambah/ubah/hapus, .user.ini/.htaccess/.phar, path berspasi, folder cache dikecualikan,
# notifikasi hanya untuk perubahan BARU. Berjalan di mount namespace privat: /www/wwwroot,
# /www/server/sentinel/av, dan data/ diganti direktori sementara (produksi tidak tersentuh).
#   bash integ_test.sh <path sentinel-av.sh>
AV="$(realpath "$1")"
if [ "${ZYS_INTEG_NS:-}" != 1 ]; then
  exec env ZYS_INTEG_NS=1 unshare -m --propagation private bash "$0" "$@"
fi
T=$(mktemp -d /tmp/zysinteg.XXXX)
mkdir -p $T/www $T/av/baseline $T/av/last $T/data
mount --bind $T/www /www/wwwroot
mount --bind $T/av /www/server/sentinel/av
mount --bind $T/data /www/server/sentinel/data
sqlite3 /www/server/sentinel/data/guardd.db "CREATE TABLE notif(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER, jenis TEXT, isi TEXT, terkirim INTEGER DEFAULT 0, coba INTEGER DEFAULT 0, galat TEXT);"
gagal=0
cek() { if eval "$2"; then echo "  LULUS $1"; else echo "  GAGAL $1"; gagal=$((gagal+1)); fi; }
S=/www/wwwroot/situs.test
mkdir -p "$S/public/up" "$S/storage/framework/views" "$S/app dir"
echo '<?php echo 1;' > "$S/public/index.php"
echo 'a' > "$S/app dir/spasi file.php"
echo 'x' > "$S/public/style.css"

bash "$AV" check-all >/dev/null 2>&1
cek "baseline otomatis untuk vhost baru (tanpa laporan)" "[ -f /www/server/sentinel/av/baseline/situs.test.txt ] && [ \$(sqlite3 /www/server/sentinel/data/guardd.db 'select count(*) from notif') = 0 ]"
cek "path berspasi direkam" "grep -q 'app dir/spasi file.php' /www/server/sentinel/av/baseline/situs.test.txt"
cek "css tidak termasuk" "! grep -q style.css /www/server/sentinel/av/baseline/situs.test.txt"

bash "$AV" check-all >/dev/null 2>&1
cek "tanpa perubahan: 0 perubahan, tanpa notifikasi" "[ ! -s /www/server/sentinel/av/last/integ-situs.test.txt ] && [ \$(sqlite3 /www/server/sentinel/data/guardd.db 'select count(*) from notif') = 0 ]"

echo 'auto_prepend_file=/tmp/x.php' > "$S/public/.user.ini"
echo 'AddHandler application/x-httpd-php .jpg' > "$S/public/up/.htaccess"
echo 'phar' > "$S/public/up/x.phar"
echo '<?php eval($_POST[1]);' >> "$S/public/index.php"
echo 'ubah' >> "$S/app dir/spasi file.php"
echo '<?php cache' > "$S/storage/framework/views/abc.php"
rm -f "$S/public/style.css"
bash "$AV" check-all >/dev/null 2>&1
R=/www/server/sentinel/av/last/integ-situs.test.txt
cek ".user.ini baru terdeteksi" "grep -q '^added|.*public/.user.ini|' $R"
cek ".htaccess baru di folder upload terdeteksi" "grep -q '^added|.*up/.htaccess|' $R"
cek ".phar terdeteksi" "grep -q '^added|.*x.phar|' $R"
cek "index.php diubah terdeteksi" "grep -q '^changed|.*public/index.php|' $R"
cek "berkas berspasi diubah = changed (dulu selalu added)" "grep -q '^changed|.*spasi file.php|' $R"
cek "cache Laravel (storage/framework) dikecualikan" "! grep -q 'storage/framework' $R"
cek "satu notifikasi 'integritas' dengan 5 perubahan" "[ \$(sqlite3 /www/server/sentinel/data/guardd.db \"select count(*) from notif where jenis='integritas' and isi like '%5 perubahan baru%'\") = 1 ]"

bash "$AV" check-all >/dev/null 2>&1
cek "jalan berikutnya tanpa perubahan baru: tidak ada notifikasi ulang" "[ \$(sqlite3 /www/server/sentinel/data/guardd.db \"select count(*) from notif where jenis='integritas'\") = 1 ]"
rm -f "$S/public/index.php"   # ada di baseline -> "deleted" = perubahan baru
bash "$AV" check-all >/dev/null 2>&1
cek "perubahan baru berikutnya (hapus) memicu notifikasi baru" "[ \$(sqlite3 /www/server/sentinel/data/guardd.db \"select count(*) from notif where jenis='integritas'\") = 2 ]"
bash "$AV" baseline "$S" situs.test >/dev/null 2>&1; bash "$AV" check-all >/dev/null 2>&1
cek "baseline ulang (operator menerima perubahan): 0 perubahan" "[ ! -s $R ]"
cek "baseline sys-persistence dibuat otomatis" "[ -f /www/server/sentinel/av/baseline/sys-persistence.txt ]"

umount /www/wwwroot /www/server/sentinel/av /www/server/sentinel/data
rm -rf "$T"
echo; echo "RINGKAS: $gagal gagal"; exit $gagal
