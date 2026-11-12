#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
# Interpreter ZySentinel (dipilih installer, lihat etc/python): bin/py hanya berisi symlink python3, mis. ke python3.9 di EL8.
# Tanpa bin/py (instalasi lama) perilaku tidak berubah: python3 dari PATH sistem.
PATH="/www/server/sentinel/bin/py:$PATH"
# ============================================================
# sentinel-waf.sh -- pengelola WAF ZySentinel
#
# Engine: Coraza (Go) untuk nginx; ModSecurity v2 untuk Apache dan
# OpenLiteSpeed. Ketiganya membaca SATU ruleset SecLang yang sama:
#   OWASP CRS  +  ruleset ZySentinel (zyrules)  +  daftar IP/URL panel.
# Tidak ada engine Lua. Halaman blocker yang sama dipakai di ketiganya.
#
# Skrip ini mengelola KONFIGURASI WAF; modul Coraza untuk nginx
# dibangun oleh bagian coraza-* di bawah, ruleset dan berkas konfigurasi
# turunan disusun oleh sentinel-zyrules.py.
#
# Aturan main:
#   1. Keinginan (desired state) disimpan di waf.conf. Keadaan aktif
#      dibaca dari berkas konfigurasi sebenarnya (snippet extension).
#   2. Snippet nginx TIDAK PERNAH ditulis bila modul Coraza belum dimuat:
#      directive coraza tidak dikenal nginx polos, nginx -t akan GAGAL dan
#      reload berikutnya ditolak diam-diam (master tetap pakai worker lama).
#   3. Setiap penulisan snippet nginx diikuti nginx -t; gagal berarti
#      rollback otomatis (snippet dihapus).
#   4. Snippet Apache dibungkus <IfModule> sehingga aman walau modul belum
#      ada. Snippet OpenLiteSpeed ditulis terpisah dan tidak disuntik otomatis.
#   5. Reload nginx selalu diverifikasi lewat PID worker berubah.
# ============================================================
set -u

WAF_CONF="${SENTINEL_WAF_CONF:-/www/server/sentinel/etc/waf.conf}"
WAF_BASE="${SENTINEL_WAF_BASE:-/www/server/sentinel/waf}"
CORAZA_DIR="${SENTINEL_CORAZA_DIR:-$WAF_BASE/coraza}"
CRS_DIR="${SENTINEL_CRS_DIR:-$CORAZA_DIR/rules}"
ZY_DIR="${SENTINEL_ZY_DIR:-$WAF_BASE/zyrules}"
ZY_MAIN="$ZY_DIR/gen/main.conf"
ZYGEN="${SENTINEL_ZYGEN:-/www/server/sentinel/bin/sentinel-zyrules.py}"
LISTS_DIR="${SENTINEL_WAF_LISTS:-/www/server/sentinel/etc/waf-lists}"
NGINX_BIN="${SENTINEL_NGINX:-/www/server/nginx/sbin/nginx}"
NGINX_CONF="${SENTINEL_NGINX_CONF:-/www/server/nginx/conf/nginx.conf}"
# Biner/konfigurasi nginx dari deteksi lingkungan (env.sh dari adapters/env.py: nginx aaPanel, distro Debian/RHEL, panel lain). Tanpa
# env.sh dipakai lokasi standar. Override uji (SENTINEL_NGINX*) selalu menang; di aaPanel nilainya sama dengan bawaan di atas.
if [ -z "${SENTINEL_NGINX:-}${SENTINEL_NGINX_CONF:-}" ]; then
  if [ -r /www/server/sentinel/etc/env.sh ]; then
    . /www/server/sentinel/etc/env.sh
    [ -n "${ZYS_NGINX_BIN:-}" ] && NGINX_BIN="$ZYS_NGINX_BIN"
    [ -n "${ZYS_NGINX_CONF:-}" ] && NGINX_CONF="$ZYS_NGINX_CONF"
  elif [ ! -x /www/server/nginx/sbin/nginx ]; then
    for _n in /usr/sbin/nginx /usr/local/sbin/nginx /usr/bin/nginx; do
      if [ -x "$_n" ]; then NGINX_BIN="$_n"; break; fi
    done
    [ -f /etc/nginx/nginx.conf ] && NGINX_CONF=/etc/nginx/nginx.conf
  fi
fi
# Salinan access log per vhost milik root untuk guardd (audit 29 Okt 2026): log aaPanel di /www/wwwlogs milik akun web, sehingga proses web
# yang disusupi bisa menghapus isinya (deteksi buta) atau menyisipkan baris palsu (IP pihak lain di-ban). Berkas di folder ini dibuka master
# nginx (root); folder 0700 root tidak bisa dijangkau akun web.
AKSES_DIR="${SENTINEL_AKSES_DIR:-/www/server/sentinel/log/akses}"
akses_dir_siap() { install -d -m 700 -o root -g root "$AKSES_DIR" 2>/dev/null || mkdir -p "$AKSES_DIR"; chmod 700 "$AKSES_DIR" 2>/dev/null; return 0; }
NGINX_VHOST=/www/server/panel/vhost/nginx
APACHE_VHOST=/www/server/panel/vhost/apache
OLS_VHOST=/www/server/panel/vhost/openlitespeed
# Mode standalone WAF: lingkungan terdeteksi BUKAN aaPanel (ZYS_PANEL dari env.sh) dan tidak ada override uji. Di sini panel tidak memuat
# extension/<situs>/ otomatis, jadi folder snippet milik kita sendiri ($WAF_BASE/vhost-<ws>/extension/<situs>/, struktur sama dengan aaPanel
# supaya semua pemeriksaan "WAF dipakai?" tetap berlaku) dan SATU baris include (glob, aman bila kosong) disuntikkan ke blok server situs.
WAF_STANDALONE=0
if [ -z "${SENTINEL_NGINX:-}${SENTINEL_NGINX_CONF:-}${SENTINEL_WAF_VHOST_TEST:-}" ] && [ -n "${ZYS_PANEL:-}" ] && [ "$ZYS_PANEL" != aapanel ] && [ ! -d /www/server/panel/vhost ]; then
  WAF_STANDALONE=1
  NGINX_VHOST="$WAF_BASE/vhost-nginx"; APACHE_VHOST="$WAF_BASE/vhost-apache"; OLS_VHOST="$WAF_BASE/vhost-ols"
fi
_WAF_HERE="$(dirname "$(readlink -f "$0")")"
_PYBIN=python3; [ -x /www/server/panel/pyenv/bin/python3 ] && _PYBIN=/www/server/panel/pyenv/bin/python3
WAFINJECT="$_WAF_HERE/adapters/wafinject.py"
ENVPY="$_WAF_HERE/adapters/env.py"
sa_sites() { "$_PYBIN" "$ENVPY" sites --full 2>/dev/null; }          # domain<TAB>webserver<TAB>berkas
sa_conf_of() { sa_sites | awk -F'\t' -v w="$1" -v s="$2" '$2==w && $1==s {print $3; exit}'; }
sa_include_line_path() { printf '%s/extension/%s/*.conf' "$(vhost_dir "$1")" "$2"; }

say() { printf '[sentinel-waf] %s\n' "$*"; }
err() { printf '[sentinel-waf] GALAT: %s\n' "$*" >&2; }

zy_py() {
  if [ -x /www/server/panel/pyenv/bin/python3 ]; then printf '%s' /www/server/panel/pyenv/bin/python3; else printf '%s' python3; fi
}

# ------------------------------------------------------------ waf.conf --
waf_conf_get() {
  local v=""
  if [ -f "$WAF_CONF" ]; then
    v="$(sed -n -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*([^#]*).*/\1/p" \
         "$WAF_CONF" 2>/dev/null | head -1)"
    v="$(printf '%s' "$v" | tr -d ' \t\r')"
  fi
  [ -n "$v" ] && printf '%s' "$v" || printf '%s' "$2"
}

waf_set() {
  # tulis key=value ke waf.conf (idempoten, dengan backup sekali sehari)
  local today
  [ -f "$WAF_CONF" ] || { mkdir -p "$(dirname "$WAF_CONF")"; printf '# konfigurasi WAF sentinel (key = value)\n' > "$WAF_CONF"; }
  today="$(date +%Y%m%d)"
  if [ -z "$(find "$(dirname "$WAF_CONF")" -maxdepth 1 -name "waf.conf.bak.$today" 2>/dev/null)" ]; then
    cp -p "$WAF_CONF" "$WAF_CONF.bak.$today" 2>/dev/null || true
  fi
  if grep -qE "^[[:space:]]*$1[[:space:]]*=" "$WAF_CONF"; then
    sed -i -E "s|^[[:space:]]*$1[[:space:]]*=.*|$1 = $2|" "$WAF_CONF"
  else
    printf '%s = %s\n' "$1" "$2" >> "$WAF_CONF"
  fi
}

waf_unset() {
  [ -f "$WAF_CONF" ] && sed -i -E "/^[[:space:]]*$1[[:space:]]*=/d" "$WAF_CONF"
}

# User web server: direktif `user` di nginx.conf; bila tidak ada, yang ada di sistem (aaPanel: www; Debian: www-data; RHEL: nginx/apache).
# Worker uji harus berjalan sebagai user yang SAMA dengan produksi, sebab berkas (log audit, aturan) dimiliki user itu.
waf_web_user() {
  local u=""
  [ -r "$NGINX_CONF" ] && u="$(sed -n 's/^[[:space:]]*user[[:space:]]\+\([A-Za-z0-9_.-]\+\)[[:space:];].*/\1/p' "$NGINX_CONF" | head -1)"
  if [ -z "$u" ] || ! id -u "$u" >/dev/null 2>&1; then
    u=""
    for c in www www-data nginx apache; do id -u "$c" >/dev/null 2>&1 && { u="$c"; break; }; done
  fi
  printf '%s' "$u"
}

payload_dir() {
  if [ -n "${SENTINEL_PAYLOAD:-}" ] && [ -d "$SENTINEL_PAYLOAD" ]; then
    printf '%s' "$SENTINEL_PAYLOAD"
  elif [ ! -d /www/server/panel/plugin/sentinel/payload ] && [ -d /www/server/sentinel/ui/payload ]; then
    printf '%s' "/www/server/sentinel/ui/payload"            # tanpa aaPanel: payload ada di folder UI standalone
  else
    printf '%s' "/www/server/panel/plugin/sentinel/payload"
  fi
}

# ---------------------------------------------------- ruleset ZySentinel --
do_zyrules_install() {
  # Salin ruleset statis dari payload ke $ZY_DIR (berkas lokal dan gen/ tidak
  # ditimpa), lalu susun konfigurasi turunan.
  local src; src="$(payload_dir)/zyrules"
  [ -d "$src" ] || { err "payload zyrules tidak ditemukan: $src"; return 1; }
  mkdir -p "$ZY_DIR/html" "$ZY_DIR/.prev" || return 1
  local f
  # Penggantian harus ATOMIK per berkas (tulis ke nama sementara lalu rename): bila nginx
  # direload tepat saat pasang ulang, berkas yang hilang sesaat membuat worker Coraza mati.
  # Versi lama disimpan di .prev untuk rollback bila ruleset baru tidak lolos uji.
  for f in zysentinel-config.conf zysentinel-before.conf zysentinel-after.conf zysentinel-base.conf.in \
           zy-scanner-ua.data zy-bots-l1.data zy-bots-l2.data zy-bots-l3.data; do
    [ -f "$src/$f" ] || { err "berkas ruleset hilang di payload: $f"; return 1; }
  done
  for f in zysentinel-config.conf zysentinel-before.conf zysentinel-after.conf zysentinel-base.conf.in \
           zy-scanner-ua.data zy-bots-l1.data zy-bots-l2.data zy-bots-l3.data; do
    [ -f "$ZY_DIR/$f" ] && cp -p "$ZY_DIR/$f" "$ZY_DIR/.prev/$f"
    install -m 0644 "$src/$f" "$ZY_DIR/.$f.new" && mv -f "$ZY_DIR/.$f.new" "$ZY_DIR/$f" \
      || { err "gagal mengganti $f"; rm -f "$ZY_DIR/.$f.new"; return 1; }
  done
  install -m 0644 "$src/html/zysentinel-block.html" "$ZY_DIR/html/.blk.new" \
    && mv -f "$ZY_DIR/html/.blk.new" "$ZY_DIR/html/zysentinel-block.html"
  mkdir -p "$LISTS_DIR" && chmod 755 "$LISTS_DIR"
  # Log audit tidak berakhiran .log sengaja: guardd menelusuri *.log di
  # /www/wwwlogs dan tidak boleh mencoba mem-parse log audit sebagai access log.
  if [ -d /etc/logrotate.d ] && [ ! -f /etc/logrotate.d/zysentinel-waf ]; then
    cat > /etc/logrotate.d/zysentinel-waf <<'LR'
/www/wwwlogs/zysentinel_waf_audit.jsonl {
    su www www
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LR
  fi
  say "ruleset ZySentinel terpasang di $ZY_DIR"
  do_zyrules_build || return 1
  # Bila nginx SEDANG memakai Coraza, ruleset baru diuji dulu; gagal => kembali ke versi lama.
  if waf_nginx_dipakai && ! do_rules_check; then
    err "ruleset baru tidak lolos uji; mengembalikan versi sebelumnya"
    for f in zysentinel-config.conf zysentinel-before.conf zysentinel-after.conf zysentinel-base.conf.in \
             zy-scanner-ua.data zy-bots-l1.data zy-bots-l2.data zy-bots-l3.data; do
      [ -f "$ZY_DIR/.prev/$f" ] && install -m 0644 "$ZY_DIR/.prev/$f" "$ZY_DIR/.$f.new" && mv -f "$ZY_DIR/.$f.new" "$ZY_DIR/$f"
    done
    do_zyrules_build >/dev/null 2>&1
    return 1
  fi
}

# Salinan access log milik root untuk SEMUA vhost nginx/Apache (bukan hanya yang ber-WAF): extension/<site>/sentinel-akses.conf.
# Berkas dibuka proses induk web server (root) sebelum menurunkan hak; folder AKSES_DIR root 0700 tidak terjangkau akun web. guardd
# mengutamakan salinan ini atas /www/wwwlogs (milik www). Hanya vhost yang conf-nya memang meng-include extension/<site>/. Konfigurasi diuji
# (nginx -t / apachectl -t) dan dikembalikan bila gagal; reload tetap tugas pemanggil. OpenLiteSpeed belum (format vhconf berbeda).
akses_body() {
  case "$1" in
    nginx)  printf '# dikelola sentinel-waf.sh, jangan edit manual\n# salinan access log milik root untuk guardd (log aaPanel tetap ditulis)\naccess_log %s/%s.log;\n' "$AKSES_DIR" "$2" ;;
    apache) printf '# dikelola sentinel-waf.sh, jangan edit manual\n# salinan access log milik root untuk guardd (log aaPanel tetap ditulis)\nCustomLog "%s/%s.log" combined\n' "$AKSES_DIR" "$2" ;;
  esac
}
do_akses_sync() {
  local ws site keadaan d f diubah baru uji_ok
  [ "$WAF_STANDALONE" = 1 ] && return 0      # standalone: guardd membaca log distro langsung (tidak ada salinan lewat extension/)
  akses_dir_siap
  for ws in nginx apache; do
    d="$(vhost_dir "$ws")" || continue
    [ -d "$d" ] || continue
    diubah=""
    while IFS='|' read -r w site keadaan; do
      [ "$w" = "$ws" ] || continue
      case "$site" in ''|*/*|.*|*[!A-Za-z0-9._-]*) continue ;; esac
      grep -q "extension/$site/" "$d/$site.conf" 2>/dev/null || continue
      f="$d/extension/$site/sentinel-akses.conf"
      baru="$(akses_body "$ws" "$site")"
      [ -f "$f" ] && [ "$(cat "$f")" = "$baru" ] && continue
      mkdir -p "$d/extension/$site" 2>/dev/null || continue
      printf '%s\n' "$baru" > "$f.baru" && mv -f "$f.baru" "$f" && diubah="$diubah $f"
    done < <(do_vhosts)
    [ -n "$diubah" ] || continue
    uji_ok=1
    if [ "$ws" = nginx ] && [ -x "$NGINX_BIN" ]; then
      "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful' || uji_ok=0
    elif [ "$ws" = apache ] && apache_bin >/dev/null; then
      apache_cmd -t >/dev/null 2>&1 || uji_ok=0
    fi
    if [ "$uji_ok" = 0 ]; then
      err "$ws: konfigurasi gagal diuji setelah salinan log root ditambahkan; dikembalikan"
      for f in $diubah; do rm -f "$f"; done
    else
      say "$ws: salinan access log root diperbarui untuk $(echo "$diubah" | wc -w | tr -d ' ') vhost"
      [ "${AKSES_RELOAD:-0}" = 1 ] && do_reload "$ws"
    fi
  done
  return 0
}

do_zyrules_build() {
  [ -f "$ZYGEN" ] || ZYGEN="$(payload_dir)/sentinel-zyrules.py"
  [ -f "$ZYGEN" ] || { err "sentinel-zyrules.py tidak ditemukan"; return 1; }
  "$(zy_py)" "$ZYGEN" build || return $?
  snippet_segarkan
  do_akses_sync
  ols_native_sync
}

# Snippet vhost lama (dipasang versi plugin sebelumnya) disamakan dengan snippet_body terbaru, supaya perubahan seperti aturan
# bawaan berkas/folder sensitif ikut berlaku setelah update tanpa menyalakan ulang WAF per vhost. nginx diuji (nginx -t) dan
# semua snippet nginx yang diubah dikembalikan bila gagal; reload tetap tugas pemanggil (panel/apply).
snippet_segarkan() {
  local ws snip baru diubah f
  for ws in nginx apache; do
    diubah=""
    for snip in "$(vhost_dir "$ws")"/extension/*/sentinel-waf.conf; do
      [ -f "$snip" ] || continue
      baru="$(snippet_body "$ws")"
      [ "$(cat "$snip")" = "$baru" ] && continue
      cp -p "$snip" "$snip.lama" && printf '%s\n' "$baru" > "$snip.baru" && mv -f "$snip.baru" "$snip" \
        || { rm -f "$snip.baru" "$snip.lama"; continue; }
      diubah="$diubah $snip"
    done
    [ -n "$diubah" ] || continue
    local uji_ok=1
    if [ "$ws" = nginx ] && [ -x "$NGINX_BIN" ]; then
      "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful' || uji_ok=0
    elif [ "$ws" = apache ] && apache_bin >/dev/null; then
      apache_cmd -t >/dev/null 2>&1 || uji_ok=0
    fi
    if [ "$uji_ok" = 0 ]; then
      err "snippet WAF $ws terbaru gagal diuji; dikembalikan ke versi sebelumnya"
      for f in $diubah; do [ -f "$f.lama" ] && mv -f "$f.lama" "$f"; done
      continue
    fi
    for f in $diubah; do rm -f "$f.lama"; done
    say "snippet WAF $ws diperbarui:$(printf '%s' "$diubah" | wc -w) vhost"
  done
  return 0
}

# Aturan bawaan berkas/folder sensitif untuk OpenLiteSpeed: salinan gen/native/ols.conf di redirect/<situs>/ (di-include blok
# rewrite vhost aaPanel), hanya untuk situs yang WAF-nya menyala. nginx dan Apache memuat gen/native/*.conf langsung dari snippet.
ols_native_path() { printf '%s/redirect/%s/zysentinel-files.conf' "$OLS_VHOST" "$1"; }
ols_native_sync() {
  local src="$ZY_DIR/gen/native/ols.conf" f site dst
  [ -d "$OLS_VHOST" ] || return 0
  for f in "$OLS_VHOST"/*.conf; do
    [ -f "$f" ] || continue
    site="$(basename "$f" .conf)"
    case "$site" in ''|0.*|*.bak.*|*[!A-Za-z0-9._-]*) continue ;; esac
    dst="$(ols_native_path "$site")"
    if [ "$(waf_conf_get "vhost.openlitespeed.$site")" = "on" ] && [ -f "$src" ]; then
      mkdir -p "$(dirname "$dst")" && cp -f "$src" "$dst.baru" && chmod 644 "$dst.baru" && mv -f "$dst.baru" "$dst"
    else
      rm -f "$dst"
    fi
  done
  return 0
}

do_zyrules_status() {
  [ -f "$ZYGEN" ] || ZYGEN="$(payload_dir)/sentinel-zyrules.py"
  "$(zy_py)" "$ZYGEN" status
}

zy_ready() { [ -f "$ZY_MAIN" ]; }

# ------------------------------------------------------------- deteksi --
# Modul Coraza yang dimuat nginx.conf masih bisa dimuat nginx AKTIF? (nginx di-upgrade aaPanel = modul lama ditolak: "version X instead of Y").
# Hasil lulus disimpan per (ukuran+mtime biner nginx, sha256 modul) agar status panel tidak menjalankan nginx -t setiap kali.
cz_terpasang_cocok() {
  local mod lib stempel kunci
  mod="$(sed -n -E 's/^[[:space:]]*load_module[[:space:]]+([^;[:space:]]*ngx_http_coraza_module[^;[:space:]]*)[[:space:]]*;.*/\1/p' "$NGINX_CONF" 2>/dev/null | head -1)"
  [ -n "$mod" ] || mod="$NGINX_MODDIR/ngx_http_coraza_module.so"
  case "$mod" in /*) : ;; *) mod="$(dirname "$NGINX_BIN")/../$mod" ;; esac
  lib="$(dirname "$mod")/libcoraza.so"
  [ -f "$mod" ] && [ -f "$lib" ] || return 1
  stempel=/www/server/sentinel/run/cz-muat.ok
  kunci="$(stat -c '%s.%Y' "$NGINX_BIN" 2>/dev/null)|$(cz_sha "$mod")|$(cz_sha "$lib")"
  [ -f "$stempel" ] && [ "$(cat "$stempel" 2>/dev/null)" = "$kunci" ] && return 0
  cz_nginx_info >/dev/null 2>&1 || return 1
  cz_uji_muat "$mod" "$lib" || return 1
  mkdir -p "$(dirname "$stempel")" 2>/dev/null && printf '%s' "$kunci" > "$stempel" 2>/dev/null
  return 0
}

cz_modul_state() {
  # dimuat | usang (dimuat, tetapi tidak lagi cocok dengan nginx aktif: compile ulang + muat ulang) | tersimpan (ada di cache, cocok
  # dengan nginx aktif) | tidak-ada
  if grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_coraza_module' "$NGINX_CONF" 2>/dev/null; then
    if cz_terpasang_cocok; then printf 'dimuat'; else printf 'usang'; fi
  elif cz_nginx_info 2>/dev/null && cz_cache_ok "$(cz_key)"; then
    printf 'tersimpan'
  else
    printf 'tidak-ada'
  fi
}

apache_cmd() {
  # Jalankan httpd dengan lingkungan yang benar: di Debian/Ubuntu biner apache2
  # butuh envvars (apache2ctl); di aaPanel httpd dipanggil langsung.
  if [ -x /www/server/apache/bin/httpd ]; then /www/server/apache/bin/httpd "$@"
  elif command -v apache2ctl >/dev/null 2>&1; then apache2ctl "$@"
  elif command -v apachectl >/dev/null 2>&1; then apachectl "$@"
  else local b; b="$(apache_bin)" && "$b" "$@"; fi
}

apache_bin() {
  local b
  for b in /www/server/apache/bin/httpd /usr/sbin/apache2 /usr/sbin/httpd; do
    [ -x "$b" ] && { printf '%s' "$b"; return 0; }
  done
  return 1
}

do_engine() {
  # Satu baris per webserver: nginx=<coraza|none|nginx-tidak-ada>,
  # apache=<modsecurity|terpasang-tanpa-waf|tidak-terpasang>, dst.
  # Modul dinamis tidak tampil di nginx -V, jadi nginx dideteksi lewat
  # load_module di nginx.conf.
  local n a o b
  n="none"
  if [ -x "$NGINX_BIN" ]; then
    if grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_coraza_module' "$NGINX_CONF" 2>/dev/null \
       && [ -f "${SENTINEL_NGINX_MODDIR:-${ZYS_NGINX_MODDIR:-/www/server/nginx/modules}}/ngx_http_coraza_module.so" ]; then
      n="coraza"
    fi
  else
    n="nginx-tidak-ada"
  fi
  a="tidak-terpasang"
  if b="$(apache_bin)"; then
    a="terpasang-tanpa-waf"
    if apache_cmd -M 2>/dev/null | grep -qiE 'security2_module'; then a="modsecurity"; fi
  fi
  o="tidak-terpasang"
  if [ -x /usr/local/lsws/bin/openlitespeed ] || [ -x /usr/local/lsws/bin/litespeed ]; then
    o="terpasang-tanpa-waf"
    # OLS memuat ModSecurity hanya bila blok "module mod_security" ada di
    # httpd_config.conf (tingkat server); berkas mod_security.so saja belum cukup.
    if [ -f /usr/local/lsws/modules/mod_security.so ] \
       && grep -qE '^[[:space:]]*module[[:space:]]+mod_security' /usr/local/lsws/conf/httpd_config.conf 2>/dev/null; then
      o="modsecurity"
    fi
  fi
  printf 'nginx=%s\napache=%s\nopenlitespeed=%s\n' "$n" "$a" "$o"
  printf 'owasp=%s\n' "$([ -f "$CRS_DIR/crs-setup.conf.example" ] && echo ada || echo hilang)"
  printf 'zyrules=%s\n' "$(zy_ready && echo ada || echo hilang)"
  printf 'coraza_modul=%s\n' "$(cz_modul_state)"
}

# ----------------------------------------------------- grup OWASP CRS --
do_rules() {
  # Keluaran: NAMA|keadaan|berkas|kunci. kunci selalu "tidak": setiap grup CRS
  # boleh dimatikan; crs-setup dan ruleset ZySentinel dikelola terpisah.
  local f nama st
  [ -d "$CRS_DIR/rules" ] || { err "OWASP CRS belum diunduh ($CRS_DIR)"; return 1; }
  for f in "$CRS_DIR"/rules/*.conf; do
    [ -f "$f" ] || continue
    nama="$(basename "$f" .conf)"
    st="$(waf_conf_get "rule.$nama" on)"
    [ "$st" = "off" ] || st="on"
    printf '%s|%s|%s|tidak\n' "$nama" "$st" "$f"
  done
}

do_rule_set() {
  # $1 = on|off, $2 = nama grup (mis. REQUEST-942-APPLICATION-ATTACK-SQLI)
  local aksi="$1" nama="$2"
  case "$aksi" in on|off) ;; *) err "aksi harus on atau off"; return 1 ;; esac
  case "$nama" in *[!A-Za-z0-9._-]*|'') err "nama rule tidak valid"; return 1 ;; esac
  [ -f "$CRS_DIR/rules/$nama.conf" ] || { err "rule tidak dikenal: $nama"; return 1; }
  waf_set "rule.$nama" "$aksi"
  do_zyrules_build >/dev/null || return 1
  say "rule $nama -> $aksi (berlaku setelah web server di-reload)"
}

KUNCI_MODUL="sensitive_files webshell spam scanner bot lfi_args probe_cms probe_tools probe_cve probe_archive probe_secrets app_laravel app_wordpress app_codeigniter app_cms app_nodejs app_golang app_python"

do_modul_set() {
  # $1 = nama modul ZySentinel, $2 = on|off
  local nama="$1" aksi="$2" m ok=0
  for m in $KUNCI_MODUL; do [ "$m" = "$nama" ] && ok=1; done
  [ "$ok" = 1 ] || { err "modul tidak dikenal: $nama (pilih: $KUNCI_MODUL)"; return 1; }
  case "$aksi" in on|off) ;; *) err "aksi harus on atau off"; return 1 ;; esac
  waf_set "zy.mod.$nama" "$aksi"
  do_zyrules_build >/dev/null || return 1
  say "modul $nama -> $aksi (berlaku setelah web server di-reload)"
}

do_setting_set() {
  # $1 = bot_level|strict|fallback|paranoia|threshold, $2 = nilai
  local k="$1" v="$2" lo hi
  case "$k" in
    bot_level) lo=0; hi=3 ;;
    strict|fallback) lo=0; hi=1 ;;
    paranoia) lo=1; hi=4 ;;
    threshold) lo=1; hi=100 ;;
    body_nofiles_kb) lo=16; hi=4096 ;;
    body_total_mb) lo=1; hi=512 ;;
    *) err "pengaturan tidak dikenal: $k"; return 1 ;;
  esac
  case "$v" in ''|*[!0-9]*) err "nilai $k harus bilangan bulat $lo-$hi"; return 1 ;; esac
  if [ "$v" -lt "$lo" ] || [ "$v" -gt "$hi" ]; then err "nilai $k harus $lo-$hi"; return 1; fi
  waf_set "zy.$k" "$v"
  do_zyrules_build >/dev/null || return 1
  say "pengaturan $k = $v (berlaku setelah web server di-reload)"
}

# --------------------------------------------------------------- vhosts --
vhost_dir() {
  case "$1" in
    nginx) printf '%s' "$NGINX_VHOST" ;;
    apache) printf '%s' "$APACHE_VHOST" ;;
    openlitespeed|ols) printf '%s' "$OLS_VHOST" ;;
    *) return 1 ;;
  esac
}

# Berkas di direktori vhost yang BUKAN situs (milik panel atau plugin lain).
BUKAN_SITUS="free_waf sentinel_waf phpfpm_status waf2monitor_data"

do_vhosts() {
  # Keluaran: ws|site|keadaan. keadaan dibaca dari snippet sentinel.
  local ws d site snip keadaan skip f b dom cfg
  if [ "$WAF_STANDALONE" = 1 ]; then
    # situs dari deteksi lingkungan (konfigurasi web server yang aktif), bukan dari folder vhost panel
    while IFS=$'\t' read -r dom ws cfg; do
      case "$ws" in nginx|apache) ;; *) continue ;; esac
      case "$dom" in ''|*[!A-Za-z0-9._-]*) continue ;; esac
      snip="$(snippet_path "$ws" "$dom")"
      if [ -f "$snip" ]; then keadaan="on"; else keadaan="off"; fi
      printf '%s|%s|%s\n' "$ws" "$dom" "$keadaan"
    done < <(sa_sites)
    return 0
  fi
  for ws in nginx apache openlitespeed; do
    d="$(vhost_dir "$ws")" || continue
    [ -d "$d" ] || continue
    for f in "$d"/*.conf; do
      [ -f "$f" ] || continue
      site="$(basename "$f" .conf)"
      case "$site" in 0.*) continue ;; esac
      case "$site" in *.bak.*) continue ;; esac
      skip=0
      for b in $BUKAN_SITUS; do
        [ "$site" = "$b" ] && { skip=1; break; }
      done
      [ "$skip" -eq 1 ] && continue
      snip="$(snippet_path "$ws" "$site")"
      if [ -f "$snip" ]; then keadaan="on"; else keadaan="off"; fi
      printf '%s|%s|%s\n' "$ws" "$site" "$keadaan"
    done
  done
}

snippet_path() {
  # $1 = ws, $2 = site. OLS memakai direktori waf/ terpisah.
  case "$1" in
    nginx)  printf '%s/extension/%s/sentinel-waf.conf' "$NGINX_VHOST" "$2" ;;
    apache) printf '%s/extension/%s/sentinel-waf.conf' "$APACHE_VHOST" "$2" ;;
    openlitespeed|ols) printf '%s/waf/%s.conf' "$OLS_VHOST" "$2" ;;
  esac
}

snippet_body() {
  # $1 = ws. Isi snippet; memuat main.conf yang sama untuk semua web server
  # dan memasang halaman blocker.
  case "$1" in
    nginx)
      cat <<EOF
# dikelola sentinel-waf.sh, jangan edit manual
coraza on;
coraza_rules_file $ZY_MAIN;
# aturan bawaan berkas/folder sensitif (mode Block; /.well-known tidak pernah ditolak). Glob: tidak gagal bila belum disusun.
include $ZY_DIR/gen/native/nginx*.conf;
error_page 403 /__zysentinel_403.html;
location = /__zysentinel_403.html {
    internal;
    root $ZY_DIR/gen/html/nginx;
    default_type text/html;
    sub_filter_once off;
    sub_filter '{{CLIENT_IP}}' '\$remote_addr';
    sub_filter '{{REQ_ID}}' '\$request_id';
    add_header Cache-Control "no-store" always;
}
EOF
      ;;
    apache)
      cat <<EOF
# dikelola sentinel-waf.sh, jangan edit manual
# aturan bawaan berkas/folder sensitif (mode Block; /.well-known tidak pernah ditolak), berlaku walau ModSecurity tidak dimuat
IncludeOptional $ZY_DIR/gen/native/apache.conf
<IfModule security2_module>
    SecRuleEngine On
    Include ${ZY_MAIN%main.conf}main-v2.conf
    Alias /__zysentinel_403.html $ZY_DIR/gen/html/apache/__zysentinel_403.html
    <Directory $ZY_DIR/gen/html/apache>
        Require all granted
        <IfModule include_module>
            Options +IncludesNOEXEC
            AddOutputFilter INCLUDES .html
        </IfModule>
    </Directory>
    ErrorDocument 403 /__zysentinel_403.html
</IfModule>
EOF
      ;;
    openlitespeed|ols)
      cat <<EOF
# CONTOH untuk OpenLiteSpeed, perlu ditambahkan manual (diuji pada OLS 1.9.3 +
# libmodsecurity 3.0.15; paket ols-modsecurity). Ruleset sama dengan nginx dan Apache.
#
# 1) TINGKAT SERVER (/usr/local/lsws/conf/httpd_config.conf): tanpa blok ini modul
#    ModSecurity tidak aktif walau mod_security.so ada.
#      module mod_security {
#        modsecurity on
#        modsecurity_rules_file $ZY_MAIN
#        ls_enabled 1
#      }
# 2) Tambahkan blok yang sama di vhconf.conf vhost yang dilindungi.
#    Aturan bawaan berkas/folder sensitif (RewriteRule) dipasang OTOMATIS di redirect/<situs>/zysentinel-files.conf.
module mod_security {
  modsecurity on
  modsecurity_rules_file $ZY_MAIN
  ls_enabled 1
}
# Batasan: halaman blocker ZySentinel belum dapat diterapkan di OpenLiteSpeed.
# Pemblokiran tetap berlaku (403), tetapi OLS menampilkan halaman 403 bawaannya.
EOF
      ;;
  esac
}

# Apache ModSecurity v2 dari repo OS (tanpa compile): Debian/Ubuntu libapache2-mod-security2, RHEL mod_security (EPEL bila perlu).
# Modul dimuat, konfigurasi diuji (apachectl -t), Apache di-reload. Ruleset (CRS + ZyRules) tetap dimuat per vhost lewat snippet.
do_modsec_install() {
  local fam="${ZYS_OS_FAMILY:-}"
  command -v apt-get >/dev/null 2>&1 && fam=deb
  [ -z "$fam" ] && { command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; } && fam=rpm
  apache_bin >/dev/null || { err "Apache tidak terpasang; ModSecurity tidak dipasang"; return 1; }
  if apache_cmd -M 2>/dev/null | grep -qiE 'security2_module'; then say "modul ModSecurity sudah dimuat"; return 0; fi
  case "$fam" in
    deb)
      say "memasang libapache2-mod-security2 dari repo OS"
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends libapache2-mod-security2 >/dev/null 2>&1 || { err "pemasangan libapache2-mod-security2 gagal"; return 1; }
      command -v a2enmod >/dev/null 2>&1 && a2enmod -q security2 unique_id headers >/dev/null 2>&1 ;;
    rpm)
      say "memasang mod_security dari repo OS"
      if ! { dnf install -y mod_security || yum install -y mod_security; } >/dev/null 2>&1; then
        { dnf install -y epel-release || yum install -y epel-release; } >/dev/null 2>&1
        { dnf install -y mod_security || yum install -y mod_security; } >/dev/null 2>&1 || { err "pemasangan mod_security gagal (repo OS/EPEL)"; return 1; }
      fi ;;
    *) err "keluarga OS tidak dikenal untuk memasang ModSecurity"; return 1 ;;
  esac
  if ! apache_cmd -t >/dev/null 2>&1; then err "uji konfigurasi apache GAGAL setelah memasang ModSecurity; modul tidak dimuat"; return 1; fi
  apache_cmd -M 2>/dev/null | grep -qiE 'security2_module' || { err "modul security2 belum termuat setelah pemasangan"; return 1; }
  do_reload apache >/dev/null 2>&1 || true
  say "ModSecurity (security2_module) termuat di Apache"
}

# Cabut semua include WAF yang disuntik ke vhost web server non-panel (standalone). Aman dijalankan kapan saja (idempoten); dipanggil uninstall.
do_strip_includes() {
  [ "$WAF_STANDALONE" = 1 ] || { say "bukan mode standalone: tidak ada include yang disuntik"; return 0; }
  local dom ws cfg n=0
  while IFS=$'\t' read -r dom ws cfg; do
    case "$ws" in nginx|apache) ;; *) continue ;; esac
    case "$dom" in ''|*[!A-Za-z0-9._-]*) continue ;; esac
    if "$_PYBIN" "$WAFINJECT" has "$ws" "$cfg" "$dom" "$(sa_include_line_path "$ws" "$dom")"; then
      "$_PYBIN" "$WAFINJECT" del "$ws" "$cfg" "$dom" "$(sa_include_line_path "$ws" "$dom")" && n=$((n + 1))
    fi
  done < <(sa_sites)
  say "$n include WAF dicabut dari konfigurasi vhost"
  [ "$n" -gt 0 ] && do_reload all >/dev/null 2>&1
  return 0
}

do_vhost_set() {
  # $1 = ws, $2 = site, $3 = on|off
  local ws="$1" site="$2" aksi="$3" snip dirn eng
  case "$ws" in nginx|apache|openlitespeed|ols) ;; *)
    err "webserver tidak dikenal: $ws (nginx|apache|openlitespeed)"; return 1 ;;
  esac
  [ "$ws" = "ols" ] && ws="openlitespeed"
  case "$site" in ''|*/*|.*|*[!A-Za-z0-9._-]*) err "nama situs tidak valid: $site"; return 1 ;; esac
  local sa_cfg=""
  if [ "$WAF_STANDALONE" = 1 ]; then
    sa_cfg="$(sa_conf_of "$ws" "$site")"
    [ -n "$sa_cfg" ] || { err "situs tidak ditemukan di konfigurasi $ws yang terdeteksi: $site"; return 1; }
  elif [ ! -f "$(vhost_dir "$ws")/$site.conf" ]; then
    err "vhost tidak ada: $ws/$site"; return 1
  fi
  snip="$(snippet_path "$ws" "$site")"

  if [ "$aksi" = "off" ]; then
    rm -f "$snip"
    # standalone: include berglob dibiarkan bila masih ada snippet lain di folder itu (mis. akses); dicabut bila folder kosong
    if [ "$WAF_STANDALONE" = 1 ] && [ -z "$(ls -A "$(dirname "$snip")" 2>/dev/null)" ]; then
      "$_PYBIN" "$WAFINJECT" del "$ws" "$sa_cfg" "$site" "$(sa_include_line_path "$ws" "$site")" 2>/dev/null
    fi
    waf_set "vhost.$ws.$site" "off"
    [ "$ws" = "openlitespeed" ] && rm -f "$(ols_native_path "$site")"
    [ "$ws" = "nginx" ] && "$NGINX_BIN" -t 2>&1 | tail -1
    say "$ws/$site -> off"
    return 0
  fi

  # --- aksi on: gerbang engine ---
  eng="$(do_engine | sed -n "s/^$ws=//p" | head -1)"
  case "$ws" in
    nginx)
      if [ "$eng" != "coraza" ]; then
        err "modul Coraza belum dimuat ke nginx. Snippet tidak ditulis."
        err "Keinginan disimpan (vhost.$ws.$site=on) dan dipasang otomatis oleh"
        err "'sentinel-waf.sh apply' setelah modul dimuat (coraza-build, lalu coraza-install)."
        waf_set "vhost.$ws.$site" "on"
        return 2
      fi
      ;;
    apache|openlitespeed)
      case "$eng" in
        tidak-terpasang)
          say "$ws tidak terpasang di mesin ini. Keinginan disimpan;"
          say "snippet ditulis sebagai berkas siap-pakai, tetapi TIDAK aktif sampai server dipasang."
          ;;
        terpasang-tanpa-waf)
          say "PERINGATAN: $ws terpasang tetapi modul ModSecurity belum dimuat; snippet baru aktif setelah modul dimuat."
          ;;
      esac
      ;;
  esac
  zy_ready || do_zyrules_install || { err "ruleset ZySentinel belum siap"; return 1; }

  dirn="$(dirname "$snip")"
  mkdir -p "$dirn" 2>/dev/null || { err "tidak bisa membuat $dirn"; return 1; }
  snippet_body "$ws" > "$snip" || { err "gagal menyusun snippet"; return 1; }
  chmod 0644 "$snip" 2>/dev/null
  if [ "$WAF_STANDALONE" = 1 ]; then
    if ! "$_PYBIN" "$WAFINJECT" add "$ws" "$sa_cfg" "$site" "$(sa_include_line_path "$ws" "$site")"; then
      err "blok server/VirtualHost untuk $site tidak ditemukan di $sa_cfg; tidak diubah"
      rm -f "$snip"; return 1
    fi
    # ModSecurity v2 distro bisa lebih tua dari sintaks CRS 4 (mis. 2.9.5: MULTIPART_PART_HEADERS tidak dikenal). Berkas CRS yang membuat
    # uji gagal dicatat di gen/modsec2-skip.list dan dilewati di varian v2 (perlindungan berkurang, dilaporkan), lalu diuji ulang.
    local _n=0 _bad _skip="$ZY_DIR/gen/modsec2-skip.list"
    while [ "$ws" = apache ] && apache_bin >/dev/null && ! apache_cmd -t >/dev/null 2>&1 && [ "$_n" -lt 20 ]; do
      _bad="$(apache_cmd -t 2>&1 | sed -n 's|.*of \(.*/rules/rules/[A-Za-z0-9._-]*\.conf\):.*|\1|p' | head -1)"
      [ -n "$_bad" ] || break
      printf '%s\n' "$(basename "$_bad")" >> "$_skip"
      say "PERINGATAN: ModSecurity v2 terpasang tidak mengenal sintaks $(basename "$_bad"); berkas itu dilewati di varian v2"
      "$_PYBIN" "$ZYGEN" build >/dev/null 2>&1 || break
      _n=$((_n + 1))
    done
    if [ "$ws" = apache ] && apache_bin >/dev/null && ! apache_cmd -t >/dev/null 2>&1; then
      err "uji konfigurasi apache GAGAL setelah include disuntik. Rollback."
      apache_cmd -t 2>&1 | grep -v AH00558 | head -4 >&2
      "$_PYBIN" "$WAFINJECT" del "$ws" "$sa_cfg" "$site" "$(sa_include_line_path "$ws" "$site")"; rm -f "$snip"
      return 1
    fi
  fi

  if [ "$ws" = "nginx" ]; then
    if ! "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful'; then
      err "nginx -t GAGAL setelah snippet ditulis. Rollback."
      [ "$WAF_STANDALONE" = 1 ] && "$_PYBIN" "$WAFINJECT" del "$ws" "$sa_cfg" "$site" "$(sa_include_line_path "$ws" "$site")"
      rm -f "$snip"
      "$NGINX_BIN" -t 2>&1 | tail -3 >&2
      return 1
    fi
    say "nginx -t OK"
  fi
  waf_set "vhost.$ws.$site" "on"
  [ "$ws" = "openlitespeed" ] && ols_native_sync
  say "$ws/$site -> on (snippet: $snip)"
}

# Real IP pengunjung di balik proxy/CDN tepercaya (Cloudflare dkk.) per vhost nginx/Apache; berkas disusun dan diuji
# sentinel-proxy.py, di sini hanya reload web server yang berubah. OpenLiteSpeed: real IP hanya tingkat server (dilaporkan panel).
do_realip() {
  local py bin out ws
  bin=/www/server/sentinel/bin/sentinel-proxy.py
  [ -f "$bin" ] || bin="$(payload_dir)/sentinel-proxy.py"
  [ -f "$bin" ] || { err "sentinel-proxy.py tidak ditemukan"; return 1; }
  py="$(zy_py)"
  # vhost baru sejak pemeriksaan terakhir mendapat salinan access log root (job ini berjalan tiap jam dari sentinel-fw)
  AKSES_RELOAD=1 do_akses_sync >&2
  out="$("$py" "$bin" realip 2>/dev/null)" || { err "sentinel-proxy.py realip gagal"; return 1; }
  printf '%s\n' "$out"
  for ws in nginx apache; do
    printf '%s' "$out" | "$py" -c 'import json,sys; sys.exit(0 if sys.argv[1] in (json.load(sys.stdin).get("diubah") or {}) else 1)' "$ws" \
      && do_reload "$ws"
  done
  return 0
}

# Direktori kerja master nginx (T-174, 30 Okt 2026). Coraza (Go) memanggil getwd saat membangun WAF di worker, dan worker mewarisi
# direktori kerja master. Bila master pernah dijalankan dari folder yang kemudian dihapus (folder sementara, folder plugin yang diganti
# saat update), SETIAP reload membuat worker gagal fatal ("getwd: no such file or directory", "cannot be respawned") dan semua situs
# berhenti merespons. Reload dalam keadaan itu diganti restart penuh dari "/", dan setiap start/restart dari ZySentinel berjalan dari "/".
nginx_cwd_hilang() {
  local m p
  m="$(cz_master_pid)"
  [ -n "$m" ] || return 1
  p="$(readlink "/proc/$m/cwd" 2>/dev/null)" || return 1
  case "$p" in *' (deleted)') return 0 ;; esac
  [ -d "$p" ] && return 1
  return 0
}
# Dijalankan DI DALAM unit systemd (INVOCATION_ID; mis. guard dari sentinel-fw.service yang diurutkan Before=nginx.service): start/restart
# nginx yang menunggu (init.d dialihkan ke systemctl) baru jalan setelah unit ini selesai, sedangkan unit ini menunggu perintah itu =
# deadlock sampai TimeoutStartSec (VM aaPanel 7 Nov 2026: nginx 1.31.8 mati 2+ menit lebih lama, sentinel-fw.service gagal timeout).
# Jadwalkan job tanpa menunggu: berjalan begitu unit ini selesai. 0 = dijadwalkan; 1 = pemanggil menjalankan sendiri (panel/terminal).
nginx_jadwalkan() {  # $1 = start|restart
  [ -n "${INVOCATION_ID:-}" ] && command -v systemctl >/dev/null 2>&1 && systemctl cat nginx.service >/dev/null 2>&1 || return 1
  systemctl reset-failed nginx.service >/dev/null 2>&1
  systemctl --no-block "$1" nginx.service >/dev/null 2>&1 || return 1
  say "nginx $1 dijadwalkan lewat systemd (berjalan begitu layanan ini selesai)"
  NGINX_DIJADWALKAN=1
  return 0
}

# Reload yang aman di dalam unit systemd: sinyal langsung ke master (job reload systemd juga tunduk pada urutan Before=/After=).
nginx_reload_langsung() {
  if [ -n "${INVOCATION_ID:-}" ] || [ ! -x "$NGINX_INIT" ]; then (cd / && "$NGINX_BIN" -s reload) >/dev/null 2>&1
  else (cd / && "$NGINX_INIT" reload) >/dev/null 2>&1; fi
}

nginx_restart_bersih() {
  nginx_jadwalkan restart && return 0
  say "direktori kerja master nginx sudah dihapus: restart penuh dari / (reload akan mematikan worker Coraza)"
  if [ -x "${NGINX_INIT:-/etc/init.d/nginx}" ]; then
    (cd / && "${NGINX_INIT:-/etc/init.d/nginx}" restart) >/dev/null 2>&1
  else
    "$NGINX_BIN" -s stop 2>/dev/null; sleep 2; (cd / && "$NGINX_BIN")
  fi
  sleep 3
  # skrip init yang start terlalu cepat setelah stop (master lama belum keluar, port masih dipakai): tunggu lalu start dari /
  if [ "$(cz_workers_hidup)" -lt 1 ]; then
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do [ -z "$(cz_master_pid)" ] && break; sleep 1; done
    [ -z "$(cz_master_pid)" ] && (cd / && "$NGINX_BIN") >/dev/null 2>&1
    sleep 3
  fi
}
nginx_reload_ok() {
  # Reload dengan verifikasi PID worker, bukan percaya output "done".
  local sebelum sesudah
  sebelum="$(ps -o pid= -C nginx 2>/dev/null | sort | tr -d ' ' | tr '\n' ',')"
  if nginx_cwd_hilang; then nginx_restart_bersih; else (cd / && /etc/init.d/nginx reload) >/dev/null 2>&1; fi
  sleep 5
  sesudah="$(ps -o pid= -C nginx 2>/dev/null | sort | tr -d ' ' | tr '\n' ',')"
  if [ "$sebelum" = "$sesudah" ]; then
    err "RELOAD GAGAL: PID worker tidak berubah. Config ditolak diam-diam."
    return 1
  fi
  say "reload OK (worker berganti)"
}

do_reload() {
  # $1 = nginx | apache | openlitespeed | all. Konfigurasi diuji dulu.
  local ws="${1:-all}" b rc=0
  case "$ws" in nginx|all)
    if [ -x "$NGINX_BIN" ]; then
      "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful' || { err "nginx -t gagal, reload dibatalkan"; return 1; }
      # Ruleset yang salah mematikan worker Coraza (semua situs terlindungi error): uji dulu.
      if waf_nginx_dipakai && ! do_rules_check; then
        err "reload dibatalkan: ruleset produksi tidak lolos uji. Worker lama tetap melayani."
        return 1
      fi
      nginx_reload_ok || rc=1
      # Worker mati setelah reload (aturan ditolak): cabut WAF segera, jangan tunggu timer.
      if grep -qE "$CZ_LOAD_RE" "$NGINX_CONF" 2>/dev/null && [ -n "$(cz_master_pid)" ] && [ "$(cz_workers_hidup)" -lt 1 ]; then
        err "reload membuat worker mati; mencabut WAF otomatis"
        waf_cabut_semua "worker mati setelah reload"; rc=1
      fi
    fi ;;
  esac
  case "$ws" in apache|all)
    if apache_bin >/dev/null; then
      apache_cmd -t >/dev/null 2>&1 || { err "uji konfigurasi apache gagal, reload dibatalkan"; return 1; }
      if [ -x /www/server/apache/bin/apachectl ]; then /www/server/apache/bin/apachectl -k graceful >/dev/null 2>&1 || rc=1
      elif command -v apache2ctl >/dev/null 2>&1; then apache2ctl graceful >/dev/null 2>&1 || rc=1
      elif command -v apachectl >/dev/null 2>&1; then apachectl graceful >/dev/null 2>&1 || rc=1
      elif [ -x /etc/init.d/httpd ]; then /etc/init.d/httpd reload >/dev/null 2>&1 || rc=1; fi
      say "apache di-reload"
    fi ;;
  esac
  case "$ws" in openlitespeed|all)
    if [ -x /usr/local/lsws/bin/lswsctrl ]; then /usr/local/lsws/bin/lswsctrl reload >/dev/null 2>&1 || rc=1; say "openlitespeed di-reload"; fi ;;
  esac
  return $rc
}

do_apply() {
  # Pasang semua keinginan vhost=on yang tertunda (dipakai setelah modul
  # dimuat). Melewati yang gagal, melaporkan ringkasannya.
  local ok=0 gagal=0 baris ws site st
  [ -f "$WAF_CONF" ] || { say "waf.conf belum ada, tidak ada yang dikerjakan"; return 0; }
  while IFS= read -r baris; do
    case "$baris" in 'vhost.'*'= on'|'vhost.'*'=on') : ;; *) continue ;; esac
    ws="$(printf '%s' "$baris" | sed -E 's/^vhost\.([^.]+)\..*/\1/')"
    site="$(printf '%s' "$baris" | sed -E 's/^vhost\.[^.]+\.([^= ]+).*/\1/')"
    st="$(do_vhosts | grep -E "^$ws\|$site\|" | cut -d'|' -f3)"
    if [ "$st" = "on" ]; then ok=$((ok+1)); continue; fi
    if do_vhost_set "$ws" "$site" on >/dev/null 2>&1; then
      ok=$((ok+1))
    else
      gagal=$((gagal+1)); say "tertunda: $ws/$site"
    fi
  done < "$WAF_CONF"
  say "apply selesai: $ok aktif, $gagal tertunda"
  [ "$gagal" -eq 0 ]
}

# --------------------------------------------------------------- mode --
do_mode_get() {
  local m; m="$(waf_conf_get mode block)"
  case "$m" in disable|monitor|block) ;; *) m="block" ;; esac
  printf 'engine=coraza\nmode=%s\n' "$m"
}

do_mode_set() {
  # $1 = disable | monitor | block. Disusun ulang ke SecRuleEngine
  # Off / DetectionOnly / On; berlaku setelah web server di-reload.
  local m="$1"
  case "$m" in disable|monitor|block) ;; *)
    err "mode harus disable, monitor, atau block"; return 1 ;; esac
  waf_set mode "$m"
  do_zyrules_build >/dev/null || return 1
  say "mode -> $m (berlaku setelah web server di-reload)"
}

# ----------------------------------------------- peninggalan engine Lua --
# Versi lama memakai WAF Lua (lua_waf / free_waf) yang hanya bisa berjalan di
# nginx. Fungsi ini memindahkan pengguna lama ke ruleset SecLang: daftar IP/URL
# dikonversi, hook Lua dicabut (nginx -t + reload terverifikasi), lalu berkas
# Lua diarsipkan dan dihapus. Hook DICABUT DULU; menghapus berkas lebih dulu
# membuat nginx -t gagal pada reload berikutnya.
LEGACY_LUA="$WAF_BASE/lua_waf"
LEGACY_FW="$WAF_BASE/free_waf"
LEGACY_HOOK="${SENTINEL_LEGACY_HOOK:-$NGINX_VHOST/sentinel_waf.conf}"

do_legacy_status() {
  local ada=tidak
  { [ -d "$LEGACY_LUA" ] || [ -d "$LEGACY_FW" ] || [ -f "$LEGACY_HOOK" ]; } && ada=ya
  printf 'legacy=%s\nhook=%s\nlua_waf=%s\nfree_waf=%s\n' "$ada" \
    "$([ -f "$LEGACY_HOOK" ] && echo ada || echo tidak)" \
    "$([ -d "$LEGACY_LUA" ] && echo ada || echo tidak)" \
    "$([ -d "$LEGACY_FW" ] && echo ada || echo tidak)"
}

legacy_convert_lists() {
  # rule/ip_*.json ([[a,b,c,d],[e,f,g,h]]) dan url_*.json -> $LISTS_DIR/*.txt
  local d
  for d in "$LEGACY_LUA" "$LEGACY_FW"; do
    [ -d "$d/rule" ] || continue
    mkdir -p "$LISTS_DIR"
    LEGACY_RULE="$d/rule" LISTS="$LISTS_DIR" "$(zy_py)" - <<'PY'
import json, os, re, ipaddress
src, dst = os.environ['LEGACY_RULE'], os.environ['LISTS']
def lama(n):
    p = '%s/%s.txt' % (dst, n)
    try:
        return [l.strip() for l in open(p) if l.strip() and not l.startswith('#')]
    except FileNotFoundError:
        return []
for nama in ('ip_white', 'ip_black', 'url_white', 'url_black'):
    try:
        data = json.load(open('%s/%s.json' % (src, nama)))
    except Exception:
        continue
    if not isinstance(data, list):
        continue
    ada = lama(nama)
    baru = []
    for e in data:
        if nama.startswith('ip_'):
            try:
                if isinstance(e, list) and len(e) == 2:
                    a = '.'.join(str(int(x)) for x in e[0]); b = '.'.join(str(int(x)) for x in e[1])
                    ia, ib = ipaddress.IPv4Address(a), ipaddress.IPv4Address(b)
                    if int(ia) > int(ib):
                        continue
                    nets = list(ipaddress.summarize_address_range(ia, ib))
                    v = a if a == b else (str(nets[0]) if len(nets) == 1 else '%s-%s' % (a, b))
                elif isinstance(e, str):
                    v = e.strip(); ipaddress.ip_network(v if '/' in v else v + '/32', strict=True)
                else:
                    continue
            except Exception:
                continue
        else:
            if not isinstance(e, str) or not e.strip() or len(e) > 300:
                continue
            try:
                rx = re.compile(e)
            except re.error:
                continue
            # pola yang cocok dengan SEMUA URL memblokir seluruh situs (url_black)
            # atau melewatkan seluruh pemeriksaan (url_white): tidak dipindahkan
            if all(rx.search(x) for x in ('/', '/index.php', '/a/b/c', '/x?y=1')):
                continue
            v = e.strip()
        if v not in ada and v not in baru:
            baru.append(v)
    if baru:
        with open('%s/%s.txt' % (dst, nama), 'a') as f:
            f.write('\n'.join(baru) + '\n')
        print('daftar %s: %d entri dipindahkan' % (nama, len(baru)))
PY
  done
}

do_legacy_remove() {
  # Idempoten. Kode keluar bukan-nol bila pencabutan hook gagal (berkas Lua
  # TIDAK dihapus dalam kasus itu).
  local ts bak
  ts="$(date +%Y%m%d%H%M%S)"
  if [ ! -d "$LEGACY_LUA" ] && [ ! -d "$LEGACY_FW" ] && [ ! -f "$LEGACY_HOOK" ]; then
    say "tidak ada peninggalan engine Lua"; return 0
  fi
  legacy_convert_lists
  if [ -f "$LEGACY_HOOK" ]; then
    bak="$LEGACY_HOOK.bak.$ts"
    cp -p "$LEGACY_HOOK" "$bak" || return 1
    rm -f "$LEGACY_HOOK"
    if [ -x "$NGINX_BIN" ]; then
      if ! "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful'; then
        err "nginx -t gagal setelah hook Lua dicabut; hook dikembalikan, berkas Lua TIDAK dihapus"
        cp -p "$bak" "$LEGACY_HOOK"; return 1
      fi
      if ! nginx_reload_ok; then
        err "reload gagal; hook dikembalikan, berkas Lua TIDAK dihapus"
        cp -p "$bak" "$LEGACY_HOOK"; return 1
      fi
    fi
    say "hook Lua dicabut dan nginx direload (backup: $bak)"
  fi
  # Arsipkan lalu hapus berkas Lua.
  local arsip="$(dirname "$WAF_BASE")/backup/engine-lua-$ts.tgz" d
  mkdir -p "$(dirname "$arsip")"
  d=""; [ -d "$LEGACY_LUA" ] && d="$d lua_waf"; [ -d "$LEGACY_FW" ] && d="$d free_waf"
  if [ -n "$d" ]; then
    ( cd "$WAF_BASE" && tar -czf "$arsip" $d ) 2>/dev/null && say "arsip engine Lua: $arsip"
    rm -rf "$LEGACY_LUA" "$LEGACY_FW"
  fi
  waf_unset engine
  waf_unset mode_coraza
  say "peninggalan engine Lua dibersihkan; WAF kini memakai Coraza + CRS + ruleset ZySentinel"
}

do_coraza_status() {
  # Keluaran sama bentuknya dengan engine: key=value.
  local ada="tidak" versi="-" aturan=0 konektor="tidak-ada"
  [ -d "$CORAZA_DIR" ] && ada="ya"
  if [ -f "$CORAZA_DIR/VERSIONS.txt" ]; then
    versi="$(sed -n 's/^crs=//p' "$CORAZA_DIR/VERSIONS.txt" | head -1)"
    [ -n "$versi" ] || versi="-"
  fi
  if [ -d "$CORAZA_DIR/rules" ]; then
    aturan="$(find "$CORAZA_DIR/rules" -name '*.conf' 2>/dev/null | wc -l | tr -d ' ')"
  fi
  # "source-ada" hanya bila konektornya benar-benar berisi, bukan
  # direktori kosong sisa percobaan unduh yang gagal.
  if [ -d "$CORAZA_DIR/connector/.git" ] \
     || [ -f "$CORAZA_DIR/connector/config" ]; then
    konektor="source-ada"
  fi
  case "$(do_engine | sed -n 's/^nginx=//p')" in coraza) konektor="terpasang" ;; esac
  printf 'aset=%s\nversi=%s\naturan=%s\nkonektor=%s\n' \
    "$ada" "$versi" "$aturan" "$konektor"
}

unduh_konektor() {
  # Source konektor Coraza untuk nginx (tidak dibangun; disimpan saja).
  # Repo resmi: corazawaf/coraza-nginx (Connector NGINX eksperimental).
  # Bila git tidak ada atau clone gagal, JANGAN tinggalkan direktori
  # kosong: status akan salah melaporkan "source ada".
  if [ -d "$CORAZA_DIR/connector/.git" ]; then
    say "source konektor sudah ada di $CORAZA_DIR/connector"
    return 0
  fi
  rm -rf "$CORAZA_DIR/connector"
  if command -v git >/dev/null 2>&1 \
     && git clone --depth 1 https://github.com/corazawaf/coraza-nginx.git \
          "$CORAZA_DIR/connector" >/dev/null 2>&1; then
    say "source konektor tersimpan di $CORAZA_DIR/connector"
  else
    rm -rf "$CORAZA_DIR/connector"
    say "PERINGATAN: source konektor gagal diunduh; lanjut tanpa itu."
  fi
}

do_coraza_download() {
  # Unduh OWASP CRS terbaru + source konektor Coraza. Idempoten.
  # Semua diunduh ke /tmp dulu, diperiksa, baru dipindah.
  need_net() { command -v curl >/dev/null 2>&1 || { err "curl tidak ada"; return 1; }; }
  need_net || return 1
  mkdir -p "$CORAZA_DIR/rules" "$CORAZA_DIR/connector"

  local api="https://api.github.com/repos/coreruleset/coreruleset/releases/latest"
  say "[1/4] mencari versi CRS terbaru dari GitHub"
  local json ver url
  json="$(curl -fsSL --max-time 30 "$api" 2>/dev/null)" || {
    err "tidak bisa menghubungi GitHub (offline?). Aset tidak diubah."
    return 1
  }
  ver="$(printf '%s' "$json" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  url="$(printf '%s' "$json" | tr ',' '\n' | sed -n 's/.*"browser_download_url":[[:space:]]*"\([^"]*minimal\.tar\.gz\)".*/\1/p' | head -1)"
  if [ -z "$ver" ] || [ -z "$url" ]; then
    err "tidak menemukan aset CRS di balasan GitHub"; return 1
  fi
  say "CRS terbaru: $ver"

  # Idempoten: bila versi terpasang SAMA dengan terbaru dan berkasnya
  # masih ada, tidak perlu mengunduh ulang. Tetap pastikan konektornya
  # ada, karena itu bisa hilang terpisah dari CRS.
  local terpasang=""
  [ -f "$CORAZA_DIR/VERSIONS.txt" ] \
    && terpasang="$(sed -n 's/^crs=//p' "$CORAZA_DIR/VERSIONS.txt" | head -1)"
  if [ "$terpasang" = "$ver" ] && [ -d "$CORAZA_DIR/rules" ] \
     && [ "$(find "$CORAZA_DIR/rules" -name '*.conf' 2>/dev/null | wc -l)" -gt 0 ]; then
    say "[2/4] CRS $ver sudah terpasang, arsip tidak diunduh ulang"
    say "[3/4] aturan CRS tidak berubah"
    say "[4/4] memeriksa source konektor"
    unduh_konektor
    say "aset Coraza siap: CRS $ver (tidak berubah)"
    return 0
  fi

  local tmp; tmp="$(mktemp -d /tmp/sentinel-coraza.XXXXXX)"
  say "[2/4] mengunduh arsip CRS $ver"
  say "sumber: $url"
  if ! curl -fsSL --max-time 120 -o "$tmp/crs.tar.gz" "$url" 2>/dev/null; then
    err "unduhan CRS gagal"; rm -rf "$tmp"; return 1
  fi
  # Integritas: GitHub menyertakan SHA-256 (digest) pada tiap aset rilis.
  local want got
  want="$(printf '%s' "$json" | "$(zy_py)" -c 'import sys,json
u=sys.argv[1]
try:
    d=json.load(sys.stdin)
    print(next((a.get("digest","") for a in d.get("assets",[]) if a.get("browser_download_url")==u),""))
except Exception:
    print("")' "$url" 2>/dev/null | sed 's/^sha256://')"
  got="$(sha256sum "$tmp/crs.tar.gz" 2>/dev/null | awk '{print $1}')"
  if printf '%s' "$want" | grep -qE '^[0-9a-f]{64}$'; then
    if [ "$want" != "$got" ]; then
      err "SHA-256 arsip CRS TIDAK cocok dengan digest GitHub (diharapkan ${want:0:12}..., didapat ${got:0:12}...). Dibatalkan."
      rm -rf "$tmp"; return 1
    fi
    say "SHA-256 arsip CRS terverifikasi (${got:0:12}...)"
  else
    say "PERINGATAN: GitHub tidak memberi digest untuk aset ini; SHA-256 yang diunduh: $got"
  fi
  # periksa arsip sebelum ekstrak
  if ! tar -tzf "$tmp/crs.tar.gz" >/dev/null 2>&1; then
    err "arsip CRS rusak"; rm -rf "$tmp"; return 1
  fi
  say "[3/4] memverifikasi arsip dan memasang aturan CRS"
  tar -xzf "$tmp/crs.tar.gz" -C "$tmp"
  local crsroot
  crsroot="$(find "$tmp" -maxdepth 2 -type f -name 'crs-setup.conf*' | head -1)"
  if [ -z "$crsroot" ]; then
    err "isi arsip tidak seperti CRS (crs-setup.conf tidak ditemukan)"
    rm -rf "$tmp"; return 1
  fi
  crsroot="$(dirname "$crsroot")"
  # ganti isi rules/ lama dengan yang baru (atomik: unpack ke .baru lalu tukar)
  rm -rf "$CORAZA_DIR/rules.baru"
  mkdir -p "$CORAZA_DIR/rules.baru"
  cp -a "$crsroot"/. "$CORAZA_DIR/rules.baru"/
  rm -rf "$CORAZA_DIR/rules.lama"
  [ -d "$CORAZA_DIR/rules" ] && mv "$CORAZA_DIR/rules" "$CORAZA_DIR/rules.lama"
  mv "$CORAZA_DIR/rules.baru" "$CORAZA_DIR/rules"
  rm -rf "$CORAZA_DIR/rules.lama" "$tmp"

  say "[4/4] mengunduh source konektor coraza-nginx"
  unduh_konektor
  local jml
  jml="$(find "$CORAZA_DIR/rules" -name '*.conf' 2>/dev/null | wc -l | tr -d ' ')"
  {
    printf 'crs=%s\n' "$ver"
    printf 'aturan=%s\n' "$jml"
    printf 'diunduh=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
  } > "$CORAZA_DIR/VERSIONS.txt"
  say "aset Coraza siap: CRS $ver, $jml berkas aturan"
  zy_ready && do_zyrules_build >/dev/null 2>&1
  say "CATATAN: engine belum berjalan. Langkah berikutnya: coraza-build"
  say "(compile modul sesuai nginx aktif), lalu coraza-install."
}

# ============================================================
#  Konektor Coraza untuk nginx: unduh + compile modul dinamis
# ============================================================
# Yang dibangun HANYA modul dinamis (ngx_http_coraza_module.so),
# bukan nginx. Modul di-compile dengan argumen configure yang SAMA
# dengan nginx aktif (dari nginx -V), supaya signature biner cocok
# dan modul bisa dimuat tanpa --with-compat. Biner nginx tidak
# disentuh sama sekali oleh coraza-build.
#
# libcoraza (Go) dibangun dengan Go dari aaPanel Go SDK Manager
# (pygvm, SDK di /usr/local/btgojdk). Hasil build disimpan di
# $CZ_CACHE; selama versi dan argumen configure nginx sama, build
# berikutnya langsung memakai cache dan tidak compile ulang.
#
#   $CZ_CACHE/src/                    bahan: tarball source (nginx, coraza-nginx, libcoraza)
#   $CZ_CACHE/libcoraza/<versi>/      libcoraza.so + include/coraza/coraza.h
#   $CZ_CACHE/modules/<kunci>/        ngx_http_coraza_module.so + MANIFEST
PLUGIN_DIR="${SENTINEL_PLUGIN_DIR:-/www/server/panel/plugin/sentinel}"
[ "$WAF_STANDALONE" = 1 ] && [ -z "${SENTINEL_PLUGIN_DIR:-}" ] && PLUGIN_DIR=/www/server/sentinel      # tanpa aaPanel: cache modul di bawah $BASE, tidak membuat /www/server/panel
CZ_CACHE="${SENTINEL_CORAZA_CACHE:-$PLUGIN_DIR/coraza-cache}"
CZ_BUILD="${SENTINEL_CORAZA_BUILD:-$CORAZA_DIR/build}"
NGINX_MODDIR="${SENTINEL_NGINX_MODDIR:-${ZYS_NGINX_MODDIR:-/www/server/nginx/modules}}"
GO_SDK_DIR="${SENTINEL_GO_SDK_DIR:-/usr/local/btgojdk}"
[ "$WAF_STANDALONE" = 1 ] && [ -z "${SENTINEL_GO_SDK_DIR:-}" ] && GO_SDK_DIR="$WAF_BASE/gosdk"   # tanpa aaPanel: SDK milik kita sendiri
CZ_LIB_REPO="https://github.com/corazawaf/libcoraza.git"
CZ_CONN_REPO="https://github.com/corazawaf/coraza-nginx.git"
CZ_STEPS=8

cz_step() { say "[$1/$CZ_STEPS] $2"; }
cz_mf_get() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1; }
cz_have_hdr() { printf '#include <%s>\n' "$1" | gcc -E -x c - >/dev/null 2>&1; }
cz_sha() { sha256sum "$1" | awk '{print $1}'; }

# Versi dengan 2 komponen (go1.26) dinormalkan jadi 3 (1.26.0) supaya
# perbandingan sort -V benar.
cz_vnorm() { case "$1" in *.*.*) printf '%s' "$1" ;; *) printf '%s.0' "$1" ;; esac; }
cz_ver_ge() {  # $1 >= $2 ?
  local a b; a="$(cz_vnorm "$1")"; b="$(cz_vnorm "$2")"
  [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)" = "$b" ]
}

# Opsi `-e <berkas>` (log galat awal) baru ada di nginx 1.19.5; nginx lama (1.18 distro) menolaknya ("invalid option: e").
cz_elog_args() {
  if "$NGINX_BIN" -h 2>&1 | grep -qE '^[[:space:]]*-e[[:space:]]'; then printf '%s' "-e $1/logs/startup.log"; fi
}

# Uji muat modul dengan nginx AKTIF tanpa menjalankan server (nginx -t pada konfigurasi sementara): satu-satunya cara memastikan modul
# dibangun untuk VERSI nginx ini. Signature modul (cz_sig_of) tidak memuat nomor versi: modul nginx 1.31.7 lolos cek signature di nginx
# 1.31.8 tetapi ditolak saat dimuat ("version 1031007 instead of 1031008"). Mengisi CZ_UJI_GALAT dengan baris galat pertama.
cz_uji_muat() {  # $1 = modul .so, $2 = libcoraza.so
  local t rc
  CZ_UJI_GALAT=""
  [ -f "$1" ] && [ -f "$2" ] || { CZ_UJI_GALAT="modul atau libcoraza tidak ada"; return 1; }
  t="$(mktemp -d /tmp/sentinel-coraza-muat.XXXXXX)" || return 1
  mkdir -p "$t/lib" "$t/logs"
  cp "$1" "$t/ngx_http_coraza_module.so" && cp "$2" "$t/lib/libcoraza.so" || { rm -rf "$t"; CZ_UJI_GALAT="gagal menyalin modul"; return 1; }
  chmod -R a+rX "$t"
  printf 'load_module %s/ngx_http_coraza_module.so;\npid %s/nginx.pid;\nerror_log %s/logs/error.log;\nevents { worker_connections 16; }\nhttp {\n  %s\n}\n' \
    "$t" "$t" "$t" "$(cz_lua_line)" > "$t/nginx.conf"
  LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" $(cz_elog_args "$t") -t >"$t/logs/t.out" 2>&1; rc=$?
  [ "$rc" = 0 ] || CZ_UJI_GALAT="$(grep -m1 -E 'emerg|error|failed' "$t/logs/t.out" | sed "s|$t/||g" | cut -c1-200)"
  rm -rf "$t"
  return "$rc"
}

cz_nginx_info() {
  local v
  [ -x "$NGINX_BIN" ] || { err "nginx tidak ditemukan di $NGINX_BIN"; return 1; }
  v="$("$NGINX_BIN" -V 2>&1 || true)"
  case "$v" in
    "nginx version: nginx/"*) : ;;
    *) err "hanya nginx resmi yang didukung (openresty/tengine memakai versi sumber berbeda)"; return 1 ;;
  esac
  CZ_NGX_VER="$(printf '%s\n' "$v" | sed -n 's|^nginx version: nginx/\([0-9][0-9.]*\).*|\1|p' | head -1)"
  CZ_NGX_ARGS="$(printf '%s\n' "$v" | sed -n 's/^configure arguments: //p' | head -1)"
  [ -n "$CZ_NGX_VER" ] && [ -n "$CZ_NGX_ARGS" ] || { err "tidak bisa membaca versi/argumen dari nginx -V"; return 1; }
}

# Argumen configure yang mempengaruhi signature modul. Yang dibuang:
# path (prefix/user/group), modul pihak ketiga statis, dan pustaka yang
# di-build dari source (openssl/pcre/zlib), sebab semuanya tidak
# mengubah signature dan source-nya sudah dihapus dari server.
cz_sig_args() {
  # Argumen configure nginx dipecah dengan aturan kutip shell (shlex): nginx distro memuat --with-cc-opt='-g -O2 ...' yang berspasi;
  # pemecahan per kata mengirim potongan '-O2', '-flto=auto', dst. ke configure sebagai argumen liar (configure gagal).
  printf '%s' "$CZ_NGX_ARGS" | "$_PYBIN" -c '
import shlex, sys
SKIP = ("--prefix=", "--user=", "--group=", "--add-module=", "--add-dynamic-module=", "--with-openssl=", "--with-pcre=", "--with-zlib=",
        "--with-libatomic=", "--with-ld-opt=", "--with-cc-opt=")
for a in shlex.split(sys.stdin.read()):
    if a.startswith(SKIP) or a == "--with-pcre":
        continue
    print(a)'
}

# Kunci cache = versi nginx + hash argumen + arsitektur.
cz_key() {
  printf '%s-%s' "$CZ_NGX_VER" \
    "$( { cz_sig_args; uname -m; } | sha256sum | cut -c1-10)"
}

cz_sig_of() { grep -aoE '[0-9]+,[0-9]+,[0-9]+,[01]{20,}' "$1" 2>/dev/null | sort -u | head -1; }

# Server tanpa aaPanel: pasang prasyarat compile dari repo OS (Debian: apt, RHEL: dnf/yum), satu paket per panggilan agar satu nama yang
# tidak ada tidak menggagalkan yang lain. Hanya dipanggil bila ada yang kurang.
cz_prereq_pasang() {
  local fam="${ZYS_OS_FAMILY:-}" p pkgs=()
  command -v apt-get >/dev/null 2>&1 && fam=deb
  [ -z "$fam" ] && { command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; } && fam=rpm
  case "$fam" in
    deb) pkgs=(build-essential git curl ca-certificates tar libssl-dev zlib1g-dev libpcre2-dev libpcre3-dev libgd-dev libxslt1-dev libgeoip-dev) ;;
    rpm) pkgs=(gcc gcc-c++ make git curl ca-certificates tar openssl-devel zlib-devel pcre2-devel pcre-devel gd-devel libxslt-devel GeoIP-devel) ;;
    *) return 1 ;;
  esac
  say "memasang prasyarat compile dari repo OS (${fam}): ${pkgs[*]}"
  [ "$fam" = deb ] && DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null 2>&1
  for p in "${pkgs[@]}"; do
    if [ "$fam" = deb ]; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "$p" >/dev/null 2>&1
    else { dnf install -y "$p" || yum install -y "$p"; } >/dev/null 2>&1; fi
  done
  return 0
}

cz_prereq() {
  if [ "$WAF_STANDALONE" = 1 ] && ! { command -v gcc >/dev/null 2>&1 && command -v make >/dev/null 2>&1 && command -v git >/dev/null 2>&1 \
        && cz_have_hdr openssl/ssl.h && cz_have_hdr zlib.h && { cz_have_hdr pcre2.h || cz_have_hdr pcre.h; }; }; then
    cz_prereq_pasang
  elif [ "$WAF_STANDALONE" = 1 ]; then
    case "$CZ_NGX_ARGS" in *http_image_filter_module*|*http_xslt_module*|*http_geoip_module*) cz_prereq_pasang ;; esac
  fi
  local falta=() c
  for c in gcc make git curl tar sha256sum; do
    command -v "$c" >/dev/null 2>&1 || falta+=("$c")
  done
  cz_have_hdr openssl/ssl.h || falta+=("libssl-dev (deb) / openssl-devel (rpm)")
  cz_have_hdr zlib.h || falta+=("zlib1g-dev (deb) / zlib-devel (rpm)")
  if ! cz_have_hdr pcre2.h && ! cz_have_hdr pcre.h; then
    falta+=("libpcre2-dev (deb) / pcre2-devel (rpm)")
  fi
  case "$CZ_NGX_ARGS" in *http_image_filter_module*)
    cz_have_hdr gd.h || falta+=("libgd-dev (deb) / gd-devel (rpm)") ;; esac
  case "$CZ_NGX_ARGS" in *http_xslt_module*)
    cz_have_hdr libxslt/xslt.h || falta+=("libxslt1-dev (deb) / libxslt-devel (rpm)") ;; esac
  case "$CZ_NGX_ARGS" in *http_geoip_module*)
    cz_have_hdr GeoIP.h || falta+=("libgeoip-dev (deb) / GeoIP-devel (rpm)") ;; esac
  if [ "${#falta[@]}" -gt 0 ]; then
    err "prasyarat compile belum lengkap: ${falta[*]}"
    err "pasang dulu (contoh Debian/Ubuntu: apt-get install -y build-essential git curl libssl-dev zlib1g-dev libpcre2-dev libgd-dev), lalu ulangi."
    return 1
  fi
  say "prasyarat compile lengkap (gcc $(gcc -dumpversion), make, git, header openssl/pcre/zlib)"
}

# ---------------------------------------------------------- Go SDK (pygvm) --
cz_pygvm() {
  if command -v pygvm >/dev/null 2>&1; then
    pygvm "$@"
  elif [ -f /www/server/panel/class_v2/projectModelV2/aapanelpygvm.py ]; then
    /www/server/panel/pyenv/bin/python3 /www/server/panel/class_v2/projectModelV2/aapanelpygvm.py "$@"
  else
    return 127
  fi
}

# Memilih dari stdin (satu versi per baris) yang terbaik untuk minimum $1:
# lini minor yang SAMA dengan minimum (patch tertinggi), karena itu yang
# ditargetkan go.mod libcoraza; bila tak ada, versi terendah yang memenuhi.
cz_go_pick() {
  local min="$1" x same="" low="" mm
  mm="$(printf '%s' "$(cz_vnorm "$min")" | cut -d. -f1-2)"
  while read -r x; do
    [ -n "$x" ] || continue
    case "$x" in *[!0-9.]*) continue ;; esac
    cz_ver_ge "$x" "$min" || continue
    if [ "$(printf '%s' "$(cz_vnorm "$x")" | cut -d. -f1-2)" = "$mm" ]; then
      if [ -z "$same" ] || cz_ver_ge "$x" "$same"; then same="$x"; fi
    fi
    if [ -z "$low" ] || ! cz_ver_ge "$x" "$low"; then low="$x"; fi
  done
  [ -n "$same" ] && printf '%s' "$same" || printf '%s' "$low"
}

# $1 = versi Go minimum. Mencari SDK stabil terpasang yang memenuhi.
cz_go_find() {
  local d v pilih
  pilih="$(for d in "$GO_SDK_DIR"/go1.*; do [ -x "$d/bin/go" ] && printf '%s\n' "${d##*/go}"; done | cz_go_pick "$1")"
  [ -n "$pilih" ] || return 1
  CZ_GOVER="$pilih"
  CZ_GOROOT="$GO_SDK_DIR/go$pilih"
}

# Daftar versi bagian "Stable Version:" dari pygvm ls-remote.
cz_go_stable_list() {
  cz_pygvm ls-remote 2>/dev/null \
    | awk '/^Stable Version:/{s=1;next} /^History Version:/{s=0} s&&NF{print $1}' \
    | sed 's/^go//'
}

# $1 = versi Go minimum. Pasang SDK stabil terbaru lewat aaPanel Go SDK
# Manager. pygvm install selalu menjalankan "use" (mengganti symlink global
# /usr/local/btgo); bila sebelumnya sudah ada Go aktif, dikembalikan supaya
# proyek Go lain di server ini tidak berubah.
# Go SDK tanpa aaPanel: unduh rilis stabil dari go.dev, diverifikasi sha256 dari daftar resmi go.dev/dl, dipasang ke $GO_SDK_DIR/go<versi>
# (tidak menyentuh Go milik sistem). Versi mengikuti aturan cz_go_pick: baris minor yang sama dengan minimum bila ada.
cz_go_install_dl() {
  local min="$1" arch info ver file sha tmp
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) err "arsitektur $(uname -m) tidak didukung untuk Go SDK"; return 1 ;; esac
  info="$(curl -fsSL --max-time 60 'https://go.dev/dl/?mode=json' 2>/dev/null)" || { err "daftar rilis Go (go.dev) tidak bisa diunduh"; return 1; }
  ver="$(printf '%s' "$info" | "$_PYBIN" -c '
import json, sys
mn = [int(x) for x in sys.argv[1].split(".")] + [0, 0]
mn = tuple(mn[:3])
v = lambda s: tuple(int(x) for x in (s[2:].split(".") + ["0", "0"])[:3])
ok = [r for r in json.load(sys.stdin) if r.get("stable") and v(r["version"]) >= mn]
same = [r for r in ok if v(r["version"])[:2] == mn[:2]]
pick = max(same, key=lambda r: v(r["version"])) if same else (min(ok, key=lambda r: v(r["version"])) if ok else None)
if pick:
    f = [x for x in pick["files"] if x["os"] == "linux" and x["arch"] == sys.argv[2] and x["kind"] == "archive"]
    if f:
        print(pick["version"][2:], f[0]["filename"], f[0]["sha256"])' "$min" "$arch")"
  [ -n "$ver" ] || { err "tidak ada Go stabil >= $min untuk linux/$arch di go.dev"; return 1; }
  set -- $ver; ver="$1"; file="$2"; sha="$3"
  say "memasang Go $ver dari go.dev ($file)"
  tmp="$(mktemp -d /tmp/sentinel-go.XXXXXX)" || return 1
  if ! curl -fsSL --max-time 600 -o "$tmp/$file" "https://go.dev/dl/$file"; then err "unduhan $file gagal"; rm -rf "$tmp"; return 1; fi
  if [ "$(sha256sum "$tmp/$file" | awk '{print $1}')" != "$sha" ]; then err "sha256 $file TIDAK cocok dengan daftar go.dev; dibatalkan"; rm -rf "$tmp"; return 1; fi
  mkdir -p "$GO_SDK_DIR" && tar -C "$tmp" -xzf "$tmp/$file" && rm -rf "$GO_SDK_DIR/go$ver" && mv "$tmp/go" "$GO_SDK_DIR/go$ver" || { err "ekstrak Go gagal"; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  [ -x "$GO_SDK_DIR/go$ver/bin/go" ] || { err "pemasangan Go $ver gagal"; return 1; }
  say "Go $ver terpasang di $GO_SDK_DIR/go$ver"
}

cz_go_install() {
  local min="$1" pilih="" v prev
  if [ "$WAF_STANDALONE" = 1 ] && ! cz_pygvm ls >/dev/null 2>&1; then cz_go_install_dl "$min"; return $?; fi
  cz_pygvm ls >/dev/null 2>&1 || { err "aaPanel Go SDK Manager (pygvm) tidak tersedia. Pasang Go >= $min lewat panel (Website > Go > SDK)."; return 1; }
  pilih="$(cz_go_stable_list | cz_go_pick "$min")"
  if [ -z "$pilih" ]; then
    say "daftar Go stabil di cache pygvm belum memuat >= $min, menyegarkan daftar"
    cz_pygvm clean-cache >/dev/null 2>&1 || true
    pilih="$(cz_go_stable_list | cz_go_pick "$min")"
  fi
  if [ -z "$pilih" ]; then
    err "tidak ada Go stabil >= $min di daftar aaPanel Go SDK Manager"
    return 1
  fi
  say "memasang Go $pilih lewat aaPanel Go SDK Manager (pygvm install)"
  prev="$(readlink /usr/local/btgo 2>/dev/null || true)"
  # Output pygvm memakai penanda [n/4] sendiri dan ratusan baris persentase;
  # diubah supaya tidak bentrok dengan penanda tahap [n/8] milik skrip ini.
  cz_pygvm install "$pilih" 2>&1 | tr '\r' '\n' | awk '
    /Downloading\.\.\.\./ { if (match($0, /[0-9]+\.[0-9]+% completed/)) {
        p = int(substr($0, RSTART, RLENGTH) + 0 / 1); p = int(p / 25) * 25;
        if (p > last) { print "  unduh Go: " p "%"; last = p } } next }
    /^\[[0-9]+\/[0-9]+\]/ { sub(/^\[[0-9]+\/[0-9]+\] */, "  pygvm: "); print; next }
    /Already|complete|Using \[/ { print "  pygvm: " $0 }
    { fflush() }'
  if [ -n "$prev" ] && [ "$(readlink /usr/local/btgo 2>/dev/null)" != "$prev" ]; then
    ln -sfn "$prev" /usr/local/btgo
    say "Go aktif global dikembalikan ke $(basename "$prev")"
  fi
  [ -x "$GO_SDK_DIR/go$pilih/bin/go" ] || [ -x "$GO_SDK_DIR/go${pilih%.0}/bin/go" ] || { err "pemasangan Go $pilih gagal"; return 1; }
}

# ----------------------------------------------------------- bahan (source) --
# $1 = nama (libcoraza|coraza-nginx) $2 = url repo. Menulis CZ_SRC_TGZ.
# Memakai tarball dari cache bila ada (tanpa jaringan); --refresh mengunduh ulang.
cz_src_fetch() {
  local nama="$1" repo="$2" t sha ver
  mkdir -p "$CZ_CACHE/src"
  if [ "${CZ_REFRESH:-0}" != "1" ]; then
    t="$(ls -1t "$CZ_CACHE/src/$nama"-*.tar.gz 2>/dev/null | head -1)"
    if [ -n "$t" ]; then CZ_SRC_TGZ="$t"; say "bahan $nama dari cache: $(basename "$t")"; return 0; fi
  fi
  t="$(mktemp -d /tmp/sentinel-src.XXXXXX)"
  if ! git clone --depth 1 "$repo" "$t/$nama" >/dev/null 2>&1; then
    err "gagal mengunduh $nama dari $repo"; rm -rf "$t"; return 1
  fi
  sha="$(git -C "$t/$nama" rev-parse --short=12 HEAD)"
  tar -C "$t" --exclude=.git -czf "$CZ_CACHE/src/$nama-$sha.tar.gz" "$nama" \
    || { rm -rf "$t"; return 1; }
  rm -rf "$t"
  CZ_SRC_TGZ="$CZ_CACHE/src/$nama-$sha.tar.gz"
  say "bahan $nama diunduh: $(basename "$CZ_SRC_TGZ")"
}

cz_src_nginx() {  # menulis CZ_NGX_TGZ (source nginx versi aktif)
  local v="$CZ_NGX_VER" t="$CZ_CACHE/src/nginx-$CZ_NGX_VER.tar.gz"
  mkdir -p "$CZ_CACHE/src"
  [ -s "$t" ] && tar -tzf "$t" >/dev/null 2>&1 && { CZ_NGX_TGZ="$t"; say "source nginx $v dari cache"; return 0; }
  # source persis yang dipakai aaPanel saat meng-compile nginx ini
  local lokal="$(dirname "$NGINX_BIN")/../src.tar.gz"
  if [ -s "$lokal" ] && tar -tzf "$lokal" 2>/dev/null | head -1 | grep -q "^nginx-$v/"; then
    cp "$lokal" "$t" && CZ_NGX_TGZ="$t" && say "source nginx $v disalin dari $lokal" && return 0
  fi
  # mirror aaPanel dulu (source yang sama dengan yang dipakai nginx.sh), lalu nginx.org
  local u
  local urls=("https://node.aapanel.com/src/nginx-$v.tar.gz" "https://nginx.org/download/nginx-$v.tar.gz")
  [ "$WAF_STANDALONE" = 1 ] && urls=("https://nginx.org/download/nginx-$v.tar.gz" "https://node.aapanel.com/src/nginx-$v.tar.gz")   # tanpa aaPanel: sumber resmi dulu
  for u in "${urls[@]}"; do
    say "mengunduh source nginx $v dari ${u%%/nginx-*}"
    if curl -fsSL --max-time 180 -o "$t.tmp" "$u" 2>/dev/null \
       && tar -tzf "$t.tmp" 2>/dev/null | head -1 | grep -q "^nginx-$v/"; then
      mv "$t.tmp" "$t"; CZ_NGX_TGZ="$t"; return 0
    fi
    rm -f "$t.tmp"
  done
  err "gagal mengunduh source nginx $v dari mirror aaPanel maupun nginx.org"
  return 1
}

# ------------------------------------------------------------- build utama --
# Menjalankan perintah dengan prioritas terendah dan menjadi korban
# pertama OOM-killer, supaya compile tidak mengganggu situs produksi.
cz_lowprio() {
  ( echo 1000 > /proc/self/oom_score_adj 2>/dev/null
    if command -v ionice >/dev/null 2>&1; then
      exec nice -n 19 ionice -c3 "$@"
    else
      exec nice -n 19 "$@"
    fi )
}

cz_cache_ok() {  # $1 = kunci
  local d="$CZ_CACHE/modules/$1" mf want
  mf="$d/MANIFEST"
  [ -f "$mf" ] && [ -f "$d/ngx_http_coraza_module.so" ] || return 1
  want="$(cz_mf_get "$mf" sha256)"
  [ -n "$want" ] && [ "$(cz_sha "$d/ngx_http_coraza_module.so")" = "$want" ] || return 1
  [ -f "$CZ_CACHE/libcoraza/$(cz_mf_get "$mf" libcoraza)/lib/libcoraza.so" ] || return 1
  # Cache hasil ADOPSI modul terpasang tanpa uji muat (sebelum 6 Nov 2026) bisa berisi modul untuk versi nginx lama (nginx di-upgrade
  # aaPanel, modul lama tertinggal di modules/): tidak sah, sehingga compile ulang dilakukan. Cache hasil compile dari source nginx versi
  # aktif tetap sah.
  if [ "$(cz_mf_get "$mf" diadopsi)" = ya ] && [ "$(cz_mf_get "$mf" uji_muat)" != lulus ]; then return 1; fi
}

# Menyiapkan semua bahan (tarball) dan mengekstraknya ke $CZ_BUILD.
cz_prepare_sources() {
  local lib conn
  cz_src_fetch libcoraza "$CZ_LIB_REPO" || return 1; lib="$CZ_SRC_TGZ"
  cz_src_fetch coraza-nginx "$CZ_CONN_REPO" || return 1; conn="$CZ_SRC_TGZ"
  cz_src_nginx || return 1
  CZ_CONN_NAME="$(basename "$conn" .tar.gz)"
  rm -rf "$CZ_BUILD/libcoraza" "$CZ_BUILD/coraza-nginx" "$CZ_BUILD/nginx-$CZ_NGX_VER"
  mkdir -p "$CZ_BUILD"
  tar -C "$CZ_BUILD" -xzf "$lib" && tar -C "$CZ_BUILD" -xzf "$conn" \
    && tar -C "$CZ_BUILD" -xzf "$CZ_NGX_TGZ" || { err "gagal mengekstrak bahan"; return 1; }
  [ -x "$CZ_BUILD/nginx-$CZ_NGX_VER/configure" ] && [ -f "$CZ_BUILD/coraza-nginx/config" ] \
    && [ -f "$CZ_BUILD/libcoraza/version.txt" ] || { err "bahan tidak lengkap"; return 1; }
  CZ_LIBVER="$(tr -d '[:space:]' < "$CZ_BUILD/libcoraza/version.txt")"
  [ -n "$CZ_LIBVER" ] || { err "version.txt libcoraza kosong"; return 1; }
}

cz_libcoraza_cached() {
  [ "${CZ_FORCE:-0}" != "1" ] \
    && [ -f "$CZ_CACHE/libcoraza/$CZ_LIBVER/lib/libcoraza.so" ] \
    && [ -f "$CZ_CACHE/libcoraza/$CZ_LIBVER/include/coraza/coraza.h" ]
}

cz_go_prepare() {
  local need
  need="$(sed -n 's/^go[[:space:]]\{1,\}\([0-9][0-9.]*\).*/\1/p' "$CZ_BUILD/libcoraza/go.mod" | head -1)"
  [ -n "$need" ] || need="1.21"
  say "libcoraza $CZ_LIBVER butuh Go minimal $need"
  if ! cz_go_find "$need"; then
    cz_go_install "$need" || return 1
    cz_go_find "$need" || { err "Go >= $need tidak ditemukan sesudah pemasangan"; return 1; }
  fi
  say "memakai Go $CZ_GOVER ($CZ_GOROOT)"
}

cz_libcoraza_compile() {
  local dir="$CZ_BUILD/libcoraza" cpu out="$CZ_BUILD/libcoraza-build.log"
  cpu="$(nproc 2>/dev/null || echo 2)"; [ "$cpu" -gt 2 ] && cpu=2
  rm -rf "$CZ_BUILD/gopath" "$CZ_BUILD/gocache"
  if ! ( cd "$dir" && mkdir -p coraza \
      && export GOROOT="$CZ_GOROOT" PATH="$CZ_GOROOT/bin:$PATH" GOTOOLCHAIN=local \
             GOPATH="$CZ_BUILD/gopath" GOCACHE="$CZ_BUILD/gocache" \
             GOMAXPROCS="$cpu" GOMEMLIMIT=1GiB CGO_ENABLED=1 \
      && cz_lowprio go tool cgo -exportheader coraza/coraza.h libcoraza/coraza.go libcoraza/log.go \
      && cz_lowprio go build -p "$cpu" -trimpath -ldflags "-s -w" -buildmode=c-shared -o libcoraza.so \
           libcoraza/coraza.go libcoraza/log.go ) >"$out" 2>&1; then
    err "compile libcoraza gagal; ekor log ($out):"
    tail -n 15 "$out" >&2
    return 1
  fi
  [ -f "$dir/libcoraza.so" ] && [ -f "$dir/coraza/coraza.h" ] || { err "libcoraza.so/coraza.h tidak terbentuk"; return 1; }
  mkdir -p "$CZ_CACHE/libcoraza/$CZ_LIBVER/lib" "$CZ_CACHE/libcoraza/$CZ_LIBVER/include/coraza"
  install -m 0755 "$dir/libcoraza.so" "$CZ_CACHE/libcoraza/$CZ_LIBVER/lib/libcoraza.so"
  install -m 0644 "$dir/coraza/coraza.h" "$CZ_CACHE/libcoraza/$CZ_LIBVER/include/coraza/coraza.h"
  printf 'libcoraza=%s\ngo=%s\ndibangun=%s\nsha256=%s\n' "$CZ_LIBVER" "$CZ_GOVER" \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$(cz_sha "$dir/libcoraza.so")" \
    > "$CZ_CACHE/libcoraza/$CZ_LIBVER/MANIFEST"
  say "libcoraza $CZ_LIBVER dibangun dan disimpan di cache ($(du -h "$CZ_CACHE/libcoraza/$CZ_LIBVER/lib/libcoraza.so" | cut -f1))"
  rm -rf "$CZ_BUILD/gopath" "$CZ_BUILD/gocache"
}

# Pembangunan modul Coraza butuh nginx resmi yang terdeteksi (nginx aaPanel atau nginx distro Debian/RHEL: argumen configure dibaca dari
# `nginx -V`). Tanpa nginx: pesan jelas. Override uji (SENTINEL_NGINX*, SENTINEL_CORAZA_DIR) melewati gerbang ini.
coraza_butuh_aapanel() {
  [ -x "$NGINX_BIN" ] && return 0
  [ -n "${SENTINEL_NGINX:-}${SENTINEL_NGINX_CONF:-}${SENTINEL_CORAZA_DIR:-}" ] && return 0
  err "nginx tidak ditemukan di server ini (dicari: $NGINX_BIN); modul Coraza untuk nginx tidak dapat dibangun. Untuk Apache gunakan ModSecurity (sentinel-waf.sh modsec-install)."
  return 1
}

do_coraza_build() {
  coraza_butuh_aapanel || return 1
  # coraza-build [--force] [--refresh]
  #   --force   : compile ulang modul dan libcoraza dari bahan di cache
  #   --refresh : seperti --force, tapi bahan diunduh ulang dari GitHub
  CZ_FORCE=0; CZ_REFRESH=0
  local a
  for a in "$@"; do
    case "$a" in --force) CZ_FORCE=1 ;; --refresh) CZ_REFRESH=1; CZ_FORCE=1 ;; esac
  done
  local key d mod nsrc jobs
  cz_step 1 "memeriksa nginx aktif dan prasyarat compile"
  cz_nginx_info || return 1
  say "nginx aktif: $CZ_NGX_VER"
  if grep -qE "$CZ_LOAD_RE" "$NGINX_CONF" 2>/dev/null && ! cz_terpasang_cocok; then
    say "modul Coraza yang dimuat nginx TIDAK cocok dengan nginx $CZ_NGX_VER (${CZ_UJI_GALAT:-uji muat gagal}): dibangun ulang untuk versi ini"
  fi
  cz_prereq || return 1
  key="$(cz_key)"
  d="$CZ_CACHE/modules/$key"

  cz_step 2 "memeriksa cache modul (kunci $key)"
  if [ "$CZ_FORCE" != "1" ] && cz_cache_ok "$key"; then
    say "cache cocok: nginx $CZ_NGX_VER dengan argumen configure yang sama, TIDAK compile ulang"
    say "modul: $d/ngx_http_coraza_module.so"
    for a in 3 4 5 6 7; do cz_step "$a" "dilewati (memakai cache)"; done
    cz_step 8 "cache modul siap dipakai"
    say "selesai: modul Coraza untuk nginx $CZ_NGX_VER siap (dari cache)"
    return 0
  fi
  say "cache belum ada atau tidak cocok, compile diperlukan"
  mkdir -p "$CZ_CACHE" "$CZ_BUILD" || return 1

  cz_step 3 "menyiapkan bahan: source libcoraza, coraza-nginx, dan nginx $CZ_NGX_VER"
  cz_prepare_sources || return 1

  if cz_libcoraza_cached; then
    cz_step 4 "Go SDK tidak diperlukan (libcoraza $CZ_LIBVER sudah ada di cache)"
    cz_step 5 "libcoraza $CZ_LIBVER dipakai dari cache, tidak dibangun ulang"
  else
    cz_step 4 "menyiapkan Go SDK stabil lewat aaPanel Go SDK Manager"
    cz_go_prepare || return 1
    cz_step 5 "compile libcoraza $CZ_LIBVER dengan Go $CZ_GOVER (beberapa menit, prioritas rendah)"
    cz_libcoraza_compile || return 1
  fi

  nsrc="$CZ_BUILD/nginx-$CZ_NGX_VER"
  cz_step 6 "configure modul dinamis dengan argumen yang sama seperti nginx aktif"
  local inc="$CZ_CACHE/libcoraza/$CZ_LIBVER/include" args=() ccx=""
  while IFS= read -r a; do args+=("$a"); done < <(cz_sig_args)
  # nginx < 1.21.1 (mis. 1.18.0 bawaan Debian 11 / Ubuntu 22.04) belum punya NGX_HTTP_CONNECT yang dirujuk connector Coraza. Konstanta itu
  # tidak pernah diset nginx lama, jadi cukup didefinisikan sebagai bit yang tak terpakai; hanya bila header sumbernya memang belum punya.
  grep -qE 'define[[:space:]]+NGX_HTTP_CONNECT([[:space:]]|$)' "$nsrc/src/http/ngx_http_request.h" 2>/dev/null || ccx=" -DNGX_HTTP_CONNECT=0x00010000"
  [ -n "$ccx" ] && say "nginx $CZ_NGX_VER belum punya NGX_HTTP_CONNECT: didefinisikan untuk kompilasi connector"
  if ! ( cd "$nsrc" && cz_lowprio ./configure "${args[@]}" \
          --add-dynamic-module="$CZ_BUILD/coraza-nginx" \
          --with-cc-opt="-I$inc -Wno-error -Wno-unused-function$ccx" ) >"$CZ_BUILD/configure.log" 2>&1; then
    err "configure gagal; ekor log ($CZ_BUILD/configure.log):"
    tail -n 15 "$CZ_BUILD/configure.log" >&2
    return 1
  fi

  cz_step 7 "compile modul ngx_http_coraza_module.so"
  jobs="$(nproc 2>/dev/null || echo 2)"; [ "$jobs" -gt 2 ] && jobs=2
  if ! ( cd "$nsrc" && cz_lowprio make -j"$jobs" modules ) >"$CZ_BUILD/make.log" 2>&1; then
    err "make modules gagal; ekor log ($CZ_BUILD/make.log):"
    tail -n 15 "$CZ_BUILD/make.log" >&2
    return 1
  fi
  mod="$nsrc/objs/ngx_http_coraza_module.so"
  [ -f "$mod" ] || { err "modul tidak terbentuk"; return 1; }

  cz_step 8 "memverifikasi signature biner dan menyimpan ke cache"
  local sig_bin sig_mod
  sig_bin="$(cz_sig_of "$NGINX_BIN")"; sig_mod="$(cz_sig_of "$mod")"
  say "signature nginx : ${sig_bin:-tidak-terbaca}"
  say "signature modul : ${sig_mod:-tidak-terbaca}"
  if [ -z "$sig_bin" ] || [ "$sig_bin" != "$sig_mod" ]; then
    err "signature modul TIDAK cocok dengan nginx aktif; modul tidak disimpan"
    return 1
  fi
  if ! cz_uji_muat "$mod" "$CZ_CACHE/libcoraza/$CZ_LIBVER/lib/libcoraza.so"; then
    err "modul hasil compile tidak bisa dimuat nginx $CZ_NGX_VER (${CZ_UJI_GALAT:-nginx -t gagal}); modul tidak disimpan"
    return 1
  fi
  say "uji muat modul dengan nginx $CZ_NGX_VER: lulus"
  mkdir -p "$d"
  install -m 0755 "$mod" "$d/ngx_http_coraza_module.so"
  {
    printf 'nginx=%s\nkunci=%s\n' "$CZ_NGX_VER" "$key"
    printf 'argumen_sha=%s\n' "$(cz_sig_args | sha256sum | cut -c1-16)"
    printf 'signature=%s\n' "$sig_mod"
    printf 'libcoraza=%s\n' "$CZ_LIBVER"
    printf 'konektor=%s\n' "$CZ_CONN_NAME"
    printf 'go=%s\n' "$(cz_mf_get "$CZ_CACHE/libcoraza/$CZ_LIBVER/MANIFEST" go)"
    printf 'dibangun=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf 'sha256=%s\n' "$(cz_sha "$d/ngx_http_coraza_module.so")"
    printf 'uji_muat=lulus\n'
  } > "$d/MANIFEST"
  printf '%s\n' "$CZ_NGX_ARGS" > "$d/nginx-configure-args.txt"
  rm -rf "$nsrc" "$CZ_BUILD/coraza-nginx" "$CZ_BUILD/libcoraza"
  say "selesai: modul Coraza untuk nginx $CZ_NGX_VER tersimpan di $d"
  say "tidak ada yang dimuat ke nginx; jalankan coraza-selftest lalu coraza-install"
}

cz_cache_adopt() {
  # Cache modul hilang (mis. folder plugin diganti saat deploy/instal ulang) padahal modul Coraza sudah terpasang di nginx: isi ulang cache
  # dari modul dan libcoraza TERPASANG itu bila signature modul sama dengan nginx aktif. Tanpa compile, tidak memuat atau mengubah nginx.
  # Tanpa cache, do_rules_check menolak SETIAP perubahan vhost WAF ("modul untuk nginx X tidak ada di cache").
  cz_nginx_info >/dev/null 2>&1 || return 1
  local key d mod lib sig_bin sig_mod
  key="$(cz_key)"
  cz_cache_ok "$key" && return 0
  mod="$NGINX_MODDIR/ngx_http_coraza_module.so"; lib="$NGINX_MODDIR/libcoraza.so"
  [ -f "$mod" ] && [ -f "$lib" ] || return 1
  [ "$(stat -c %u "$mod")" = 0 ] && [ "$(stat -c %u "$lib")" = 0 ] || { err "modul terpasang bukan milik root; cache tidak diisi dari berkas itu"; return 1; }
  sig_bin="$(cz_sig_of "$NGINX_BIN")"; sig_mod="$(cz_sig_of "$mod")"
  if [ -z "$sig_bin" ] || [ "$sig_bin" != "$sig_mod" ]; then
    err "modul terpasang tidak cocok dengan nginx $CZ_NGX_VER (signature beda); jalankan coraza-build"; return 1
  fi
  if ! cz_uji_muat "$mod" "$lib"; then
    err "modul terpasang tidak bisa dimuat nginx $CZ_NGX_VER (${CZ_UJI_GALAT:-nginx -t gagal}); kemungkinan dibangun untuk versi nginx lain, cache TIDAK diisi; jalankan coraza-build"
    return 1
  fi
  d="$CZ_CACHE/modules/$key"
  mkdir -p "$d" "$CZ_CACHE/libcoraza/adopsi/lib" || return 1
  install -m 0755 "$mod" "$d/ngx_http_coraza_module.so" || return 1
  install -m 0755 "$lib" "$CZ_CACHE/libcoraza/adopsi/lib/libcoraza.so" || return 1
  {
    printf 'nginx=%s\nkunci=%s\n' "$CZ_NGX_VER" "$key"
    printf 'argumen_sha=%s\n' "$(cz_sig_args | sha256sum | cut -c1-16)"
    printf 'signature=%s\n' "$sig_mod"
    printf 'libcoraza=adopsi\nkonektor=terpasang\ngo=-\n'
    printf 'dibangun=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf 'sha256=%s\n' "$(cz_sha "$d/ngx_http_coraza_module.so")"
    printf 'diadopsi=ya\nuji_muat=lulus\n'
  } > "$d/MANIFEST"
  say "cache modul diisi ulang dari modul terpasang di $NGINX_MODDIR (nginx $CZ_NGX_VER)"
  cz_cache_ok "$key"
}

do_coraza_cache() {
  # Ringkasan cache + kecocokan dengan nginx aktif (key=value).
  local key="-" ok="tidak" mv="-" lv="-" ngx="-"
  if cz_nginx_info 2>/dev/null; then
    ngx="$CZ_NGX_VER"; key="$(cz_key)"
    if cz_cache_ok "$key"; then
      ok="ya"
      mv="$(cz_mf_get "$CZ_CACHE/modules/$key/MANIFEST" dibangun)"
      lv="$(cz_mf_get "$CZ_CACHE/modules/$key/MANIFEST" libcoraza)"
    fi
  fi
  printf 'nginx=%s\nkunci=%s\ncache_cocok=%s\ndibangun=%s\nlibcoraza=%s\ncache_dir=%s\n' \
    "$ngx" "$key" "$ok" "$mv" "$lv" "$CZ_CACHE"
}

# --------------------------------------------- uji terisolasi + aktivasi --
NGINX_INIT="${SENTINEL_NGINX_INIT:-/etc/init.d/nginx}"
CZ_LOAD_RE='^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_coraza_module'

cz_http() { local c; c="$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$@" 2>/dev/null)"; printf '%s' "${c:-000}"; }

# nginx dengan lua_nginx_module butuh lua_package_path agar resty.core terbaca;
# tanpa itu worker gagal start. Ikuti persis yang dipakai nginx.conf aktif.
cz_lua_line() {
  local l
  l="$(grep -m1 -E '^[[:space:]]*lua_package_path[[:space:]]' "$NGINX_CONF" 2>/dev/null)"
  if [ -z "$l" ]; then
    case "$CZ_NGX_ARGS" in
      *lua_nginx_module*|*with-luajit*) l="lua_package_path \"$(dirname "$NGINX_BIN")/../lib/lua/?.lua;;\";" ;;
    esac
  fi
  printf '%s' "$l"
}

# ---- penyesuaian otomatis setelah upgrade nginx (8 Nov 2026) ----
# Dulu: upgrade nginx di aaPanel (mis. 1.31.7 -> 1.31.8) dengan Coraza termuat = nginx GAGAL start dan semua situs mati sampai guard
# (timer 5 menit) mencabut WAF; konektor untuk versi baru harus dibangun manual lewat Set Up Coraza.

# Drop-in nginx.service (ExecStartPre nginx-prestart) dari payload; dipastikan saat Coraza dimuat (nginx bisa dipasang setelah plugin).
cz_dropin_pastikan() {
  local src d
  src="$(payload_dir)/systemd/dropin/nginx.service.conf"
  [ -f "$src" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 || return 0
  systemctl cat nginx.service >/dev/null 2>&1 || return 0
  d=/etc/systemd/system/nginx.service.d
  cmp -s "$src" "$d/zysentinel-restart.conf" 2>/dev/null && return 0
  mkdir -p "$d" && install -m 0644 "$src" "$d/zysentinel-restart.conf" && systemctl daemon-reload >/dev/null 2>&1 \
    && say "pemeriksaan modul Coraza sebelum nginx start dipasang ($d/zysentinel-restart.conf)"
  return 0
}

coraza_sesuai_jadwalkan() {
  if command -v systemctl >/dev/null 2>&1 && systemctl cat sentinel-coraza-sesuai.service >/dev/null 2>&1 \
     && systemctl --no-block start sentinel-coraza-sesuai.service >/dev/null 2>&1; then
    say "penyesuaian konektor Coraza dijadwalkan (sentinel-coraza-sesuai.service)"
  else
    setsid -f "$(readlink -f "$0")" coraza-sesuaikan >/dev/null 2>&1 < /dev/null
    say "penyesuaian konektor Coraza dijalankan di latar"
  fi
}

do_nginx_prestart() {
  # ExecStartPre nginx.service: hanya berpengaruh bila modul Coraza dimuat DAN tidak cocok dengan biner nginx yang akan start.
  grep -qE "$CZ_LOAD_RE" "$NGINX_CONF" 2>/dev/null || return 0
  cz_terpasang_cocok && return 0
  err "modul Coraza tidak cocok dengan nginx yang akan start (${CZ_UJI_GALAT:-uji muat gagal}); WAF dilepas sementara agar nginx tetap start"
  waf_cabut_semua "nginx di-upgrade: modul Coraza untuk versi lain" tanpa-restart || return 0
  waf_set coraza_sesuai 1
  coraza_sesuai_jadwalkan
  return 0
}

do_coraza_sesuaikan() {
  # Compile konektor untuk nginx aktif, uji, muat, lalu pulihkan vhost terlindungi (vhost.*=on di waf.conf). Gagal = WAF tetap dilepas,
  # situs tetap berjalan; Set Up Coraza di panel dapat mengulang.
  mkdir -p /www/server/sentinel/run 2>/dev/null
  exec 8>/www/server/sentinel/run/.coraza-sesuai.lock
  flock -n 8 || { say "penyesuaian konektor Coraza lain sedang berjalan"; return 0; }
  [ "$(waf_conf_get coraza_sesuai 0)" = 1 ] || { say "tidak ada penyesuaian konektor Coraza yang tertunda"; return 0; }
  local i
  for i in $(seq 1 60); do [ -n "$(cz_master_pid)" ] && break; sleep 1; done
  [ -n "$(cz_master_pid)" ] || { err "nginx tidak berjalan; penyesuaian ditunda"; return 1; }
  cz_nginx_info || return 1
  say "menyesuaikan konektor Coraza dengan nginx $CZ_NGX_VER (setelah upgrade nginx)"
  if ! do_coraza_build; then
    err "konektor untuk nginx $CZ_NGX_VER gagal dibangun; WAF tetap dilepas dan situs tetap berjalan (ulangi lewat Set Up Coraza)"
    return 1
  fi
  if ! do_coraza_install; then
    err "konektor untuk nginx $CZ_NGX_VER gagal dimuat; nginx aktif tidak diubah (ulangi lewat Set Up Coraza)"
    return 1
  fi
  do_apply || true
  # vhost-on/do_apply hanya menulis snippet; proteksi baru berlaku setelah reload (diuji: nginx -t + uji ruleset sebelum reload)
  do_reload nginx || err "reload setelah memulihkan vhost terlindungi gagal; worker lama tetap melayani (ulangi reload dari panel)"
  waf_set coraza_sesuai 0
  say "selesai: Coraza aktif kembali di nginx $CZ_NGX_VER dan vhost terlindungi dipulihkan"
}

do_coraza_selftest() {
  # Menjalankan biner nginx ASLI di direktori sementara dan port
  # 127.0.0.1 acak, memuat modul dari cache. nginx produksi tidak
  # disentuh (tidak ada reload, tidak ada berkas produksi yang diubah).
  cz_nginx_info || return 1
  local key mod libver lib t port pid rc=0 r_ok r_blk c_ok c_blk rules maps="tidak"
  key="$(cz_key)"
  cz_cache_ok "$key" || { err "modul untuk nginx $CZ_NGX_VER belum ada di cache (jalankan coraza-build)"; return 1; }
  mod="$CZ_CACHE/modules/$key/ngx_http_coraza_module.so"
  libver="$(cz_mf_get "$CZ_CACHE/modules/$key/MANIFEST" libcoraza)"
  lib="$CZ_CACHE/libcoraza/$libver/lib/libcoraza.so"
  t="$(mktemp -d /tmp/sentinel-coraza-test.XXXXXX)"
  mkdir -p "$t/lib" "$t/logs" "$t/tmp" "$t/html/crs"
  echo ok > "$t/html/index.html"; echo ok > "$t/html/crs/index.html"
  cp "$mod" "$t/ngx_http_coraza_module.so"; cp "$lib" "$t/lib/libcoraza.so"
  chmod -R a+rX "$t"
  port="$(cz_port_libre)"
  rules="$CORAZA_DIR/rules"

  cat > "$t/rules.conf" <<EOF
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS:uji "@contains sentinel-blokir" "id:100001,phase:2,deny,status:403,msg:'uji sentinel'"
EOF
  {
    echo 'SecRuleEngine On'
    echo 'SecRequestBodyAccess On'
    [ -f "$rules/crs-setup.conf.example" ] && echo "Include $rules/crs-setup.conf.example"
    echo "Include $rules/rules/*.conf"
  } > "$t/crs.conf"
  cat > "$t/nginx.conf" <<EOF
load_module $t/ngx_http_coraza_module.so;
worker_processes 1;
working_directory /;
pid $t/nginx.pid;
error_log $t/logs/error.log notice;
events { worker_connections 64; }
http {
  $(cz_lua_line)
  access_log off;
  client_body_temp_path $t/tmp/b; proxy_temp_path $t/tmp/p;
  fastcgi_temp_path $t/tmp/f; uwsgi_temp_path $t/tmp/u; scgi_temp_path $t/tmp/s;
  server {
    listen 127.0.0.1:$port;
    coraza on;
    coraza_rules_file $t/rules.conf;
    # konten statis, bukan "return": return berjalan di fase rewrite sebelum
    # Coraza sempat memeriksa, sehingga uji akan selalu lolos tanpa makna.
    root $t/html;
    location / { }
    location /crs/ { coraza_rules_file $t/crs.conf; }
  }
}
EOF
  say "uji terisolasi: nginx $CZ_NGX_VER, modul dari cache, 127.0.0.1:$port"
  if ! LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" $(cz_elog_args "$t") -t >"$t/logs/t.out" 2>&1; then
    err "nginx -t menolak konfigurasi uji:"; sed 's/^/    /' "$t/logs/t.out" >&2
    rm -rf "$t"; return 1
  fi
  say "nginx -t pada konfigurasi uji: sukses (modul dimuat, signature cocok)"
  LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" $(cz_elog_args "$t") >"$t/logs/run.out" 2>&1
  # tunggu siap; bila master mati (mis. aturan ditolak) tidak perlu menunggu timeout
  local i pid0; pid0="$(cat "$t/nginx.pid" 2>/dev/null)"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(cz_http "http://127.0.0.1:$port/")" != "000" ] && break
    [ -n "$pid0" ] && ! kill -0 "$pid0" 2>/dev/null && break
    sleep 1
  done
  r_ok="$(cz_http "http://127.0.0.1:$port/")"
  r_blk="$(cz_http "http://127.0.0.1:$port/?uji=sentinel-blokir")"
  c_ok="$(cz_http "http://127.0.0.1:$port/crs/?q=halo")"
  c_blk="$(cz_http "http://127.0.0.1:$port/crs/?id=1%27%20OR%20%271%27%3D%271")"
  pid="$(cat "$t/nginx.pid" 2>/dev/null)"
  for w in $(pgrep -P "${pid:-0}" 2>/dev/null); do
    cz_lib_in_proc "$w"
    case $? in
      0) maps="ya" ;;
      2) # /proc tidak terbaca: bukti cadangan dari log uji (level notice)
         grep -q 'coraza: libcoraza.so loaded via dynlib_open' "$t/logs/error.log" 2>/dev/null \
           && maps="ya (dari log, /proc tidak terbaca)" ;;
    esac
  done
  say "request normal            : $r_ok (harapan 200)"
  say "request kena aturan uji   : $r_blk (harapan 403)"
  say "request normal  + CRS     : $c_ok (harapan 200)"
  say "serangan SQLi   + CRS     : $c_blk (harapan 403)"
  say "worker memuat libcoraza   : $maps"
  [ "$r_ok" = "200" ] && [ "$r_blk" = "403" ] && [ "${maps%% *}" = "ya" ] || rc=1
  if [ "$rc" = "1" ] && grep -q 'coraza: failed' "$t/logs/error.log" 2>/dev/null; then
    err "worker menolak konfigurasi Coraza: $(grep -m1 'coraza: failed' "$t/logs/error.log" | sed 's/^.*\] //')"
  fi
  [ "$c_ok" = "200" ] && [ "$c_blk" = "403" ] || say "PERINGATAN: uji CRS tidak sesuai harapan; lihat $t/logs/error.log (dipertahankan)"
  # Pastikan master uji mati walau file pid belum terisi (worker gagal start):
  # cocokkan lewat path konfigurasi unik di direktori sementara ini.
  [ -n "$pid" ] && kill "$pid" 2>/dev/null
  pkill -f -- "-c $t/nginx.conf" 2>/dev/null
  sleep 1
  if [ "$rc" = "0" ] && [ "$c_ok" = "200" ] && [ "$c_blk" = "403" ]; then rm -rf "$t"; fi
  if [ "$rc" = "0" ]; then say "uji terisolasi LULUS"; else err "uji terisolasi GAGAL (log: $t/logs/error.log)"; fi
  return "$rc"
}

# 0 = libcoraza termuat di proses $1, 1 = tidak, 2 = /proc tidak terbaca
# (mis. container tanpa CAP_SYS_PTRACE: root pun tak bisa membaca maps user lain).
cz_lib_in_proc() {
  local m
  m="$(cat "/proc/$1/maps" 2>/dev/null)" || return 2
  case "$m" in *libcoraza*) return 0 ;; *) return 1 ;; esac
}

cz_worker_pids() { ps -o pid= -C nginx 2>/dev/null | sort | tr -d ' ' | tr '\n' ','; }

# PID master nginx dan jumlah worker yang HIDUP (bukan zombie). Master bisa tetap hidup
# tanpa worker sama sekali bila worker mati fatal (mis. aturan ditolak): semua situs
# lalu menggantung, dan pembandingan PID worker saja tidak melihatnya.
# Port acak 127.0.0.1 yang benar-benar bebas untuk nginx uji terisolasi (bentrok port membuat uji
# gagal dan pemasangan/reload dibatalkan).
cz_port_libre() {
  local p t=0
  while :; do
    p=$((20000 + RANDOM % 20000)); t=$((t + 1))
    ss -ltnH 2>/dev/null | awk '{print $4}' | grep -q ":$p$" || break
    [ "$t" -ge 30 ] && break
  done
  printf '%s' "$p"
}
# Master nginx yang SAH: milik root dan exe = biner nginx terpasang (pidfile lebih dulu, lalu daftar proses). Dulu proses pertama bernama
# "nginx" dengan argumen "master process" dianggap master: proses tiruan milik akun web bisa memicu restart berulang atau pencabutan WAF
# ("tanpa worker hidup") di semua situs (evaluasi 30 Okt 2026).
cz_master_pid() {
  local p exe nb
  nb="$(readlink -f "${NGINX_BIN:-/www/server/nginx/sbin/nginx}" 2>/dev/null)"
  for p in $(cat /www/server/nginx/logs/nginx.pid /run/nginx.pid /var/run/nginx.pid 2>/dev/null; ps -C nginx -o pid=,args= 2>/dev/null | awk '/master process/ {print $1}'); do
    case "$p" in ''|*[!0-9]*) continue ;; esac
    [ "$(stat -c %u "/proc/$p" 2>/dev/null)" = 0 ] || continue
    exe="$(readlink "/proc/$p/exe" 2>/dev/null)"; exe="${exe% (deleted)}"
    [ -n "$exe" ] || continue
    [ -z "$nb" ] || [ "$exe" = "$nb" ] || [ "$(readlink -f "$exe" 2>/dev/null)" = "$nb" ] || continue
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q 'master process' || continue
    echo "$p"; return 0
  done
}
cz_workers_hidup() {
  local m; m="$(cz_master_pid)"; [ -n "$m" ] || { echo 0; return; }
  ps -o stat=,args= --ppid "$m" 2>/dev/null | awk '$1 !~ /^Z/ && /nginx: worker/ {n++} END {print n+0}'
}

cz_nginx_reload_verified() {
  # nginx -t, reload, lalu bukti PID worker berubah (init.d selalu mencetak "done").
  local b a
  "$NGINX_BIN" -t >/dev/null 2>&1 || return 2
  b="$(cz_worker_pids)"
  if nginx_cwd_hilang; then nginx_restart_bersih
  elif [ -x "$NGINX_INIT" ]; then "$NGINX_INIT" reload >/dev/null 2>&1; else "$NGINX_BIN" -s reload; fi
  sleep 5
  a="$(cz_worker_pids)"
  [ "$b" != "$a" ] || return 3
  # worker baru harus benar-benar hidup (aturan salah = worker mati fatal, master tetap ada)
  [ "$(cz_workers_hidup)" -ge 1 ] || return 4
}

do_coraza_install() {
  coraza_butuh_aapanel || return 1
  # Memuat modul Coraza ke nginx AKTIF: salin modul + libcoraza, tambahkan
  # load_module di nginx.conf, nginx -t, reload, bukti worker memuat libcoraza.
  # Gagal di langkah mana pun mengembalikan nginx.conf dari backup.
  cz_nginx_info || return 1
  local key mod libver lib ts conf="$NGINX_CONF" bak n=0 w
  key="$(cz_key)"
  cz_cache_ok "$key" || { err "modul untuk nginx $CZ_NGX_VER belum ada di cache (jalankan coraza-build)"; return 1; }
  say "[1/5] uji terisolasi sebelum menyentuh nginx aktif"
  do_coraza_selftest || { err "uji terisolasi gagal; nginx aktif tidak diubah"; return 1; }
  mod="$CZ_CACHE/modules/$key/ngx_http_coraza_module.so"
  libver="$(cz_mf_get "$CZ_CACHE/modules/$key/MANIFEST" libcoraza)"
  lib="$CZ_CACHE/libcoraza/$libver/lib/libcoraza.so"

  say "[2/5] menyalin modul dan libcoraza ke $NGINX_MODDIR"
  mkdir -p "$NGINX_MODDIR" || return 1
  install -m 0755 "$mod" "$NGINX_MODDIR/ngx_http_coraza_module.so"
  install -m 0755 "$lib" "$NGINX_MODDIR/libcoraza.so"
  printf '%s\n' "$NGINX_MODDIR" > /etc/ld.so.conf.d/sentinel-coraza.conf
  command -v ldconfig >/dev/null 2>&1 && ldconfig
  # worker berjalan sebagai user nginx: aturan CRS dan rantai direktori harus terbaca
  chmod -R a+rX "$CORAZA_DIR/rules" 2>/dev/null
  local dd
  for dd in "$(dirname "$WAF_BASE")" "$WAF_BASE" "$CORAZA_DIR"; do
    [ -d "$dd" ] && [ "$(stat -c %A "$dd" | cut -c10)" != "x" ] && chmod o+x "$dd"
  done
  local wuser; wuser="$(waf_web_user)"
  if [ -n "$wuser" ] && command -v runuser >/dev/null 2>&1; then
    runuser -u "$wuser" -- test -r "$NGINX_MODDIR/libcoraza.so" \
      || { err "user $wuser tidak bisa membaca $NGINX_MODDIR/libcoraza.so"; return 1; }
  fi

  say "[3/5] menambahkan load_module di $conf (backup .bak.<waktu>)"
  ts="$(date +%Y%m%d%H%M%S)"; bak="$conf.bak.$ts"
  if grep -qE "$CZ_LOAD_RE" "$conf"; then
    say "load_module sudah ada, tidak diubah"
  else
    cp -p "$conf" "$bak" || return 1
    sed -i "1i load_module $NGINX_MODDIR/ngx_http_coraza_module.so;" "$conf"
    # Coraza membuka direktori kerja ('.') saat membuat WAF di worker. Bila nginx dijalankan
    # dari direktori yang tidak bisa diakses user worker (mis. /root atau /www/server/panel/plugin
    # yang 0600), SEMUA worker mati fatal ("stat .: permission denied"). working_directory
    # membuat worker selalu berada di / terlepas dari cara nginx dijalankan.
    if ! grep -qE '^[[:space:]]*working_directory[[:space:]]' "$conf"; then
      sed -i "1i working_directory /;  # sentinel-coraza" "$conf"
    fi
  fi

  say "[4/5] nginx -t, reload, dan verifikasi PID worker"
  cz_nginx_reload_verified; local rr=$?
  if [ "$rr" != "0" ]; then
    [ -f "$bak" ] && cp -p "$bak" "$conf"
    case "$rr" in
      2) err "nginx -t menolak konfigurasi; nginx.conf dikembalikan dari $bak" ;;
      4) err "worker nginx mati setelah reload (tidak ada worker hidup); nginx.conf dikembalikan"
         cz_nginx_reload_verified >/dev/null 2>&1 || true ;;
      *) err "RELOAD GAGAL: PID worker tidak berubah; nginx.conf dikembalikan"
         cz_nginx_reload_verified >/dev/null 2>&1 || true ;;
    esac
    return 1
  fi

  say "[5/5] bukti: worker nginx memuat libcoraza"
  local total=0 tak=0
  for w in $(pgrep -f 'nginx: worker' 2>/dev/null); do
    total=$((total+1))
    cz_lib_in_proc "$w"
    case $? in 0) n=$((n+1)) ;; 2) tak=$((tak+1)) ;; esac
  done
  if [ "$tak" -gt 0 ]; then
    say "PERINGATAN: /proc worker tidak terbaca (tanpa CAP_SYS_PTRACE); bukti memuat libcoraza hanya dari uji terisolasi + nginx -t + reload"
  else
    say "worker yang memuat libcoraza: $n dari $total"
    if [ "$n" -lt 1 ]; then
      err "tidak ada worker yang memuat libcoraza; periksa error_log nginx"; return 1
    fi
  fi
  zy_ready || do_zyrules_install >/dev/null 2>&1 || true
  cz_terpasang_cocok >/dev/null 2>&1 || true          # stempel uji muat: pemeriksaan sebelum nginx start menjadi instan
  cz_dropin_pastikan
  say "modul Coraza aktif di nginx $CZ_NGX_VER. Backup konfigurasi: ${bak:-tidak-ada}"
}

do_coraza_uninstall() {
  # Mencabut load_module (berkas modul dan cache dipertahankan).
  # Gagal bila masih ada vhost yang memakai directive coraza: nginx -t menolak.
  local conf="$NGINX_CONF" ts bak rr
  grep -qE "$CZ_LOAD_RE" "$conf" || { say "load_module coraza tidak ada di $conf, tidak ada yang dicabut"; return 0; }
  ts="$(date +%Y%m%d%H%M%S)"; bak="$conf.bak.$ts"
  cp -p "$conf" "$bak" || return 1
  sed -i -E "/$CZ_LOAD_RE/d; /# sentinel-coraza\$/d" "$conf"
  cz_nginx_reload_verified; rr=$?
  if [ "$rr" != "0" ]; then
    cp -p "$bak" "$conf"
    err "gagal mencabut (kode $rr). Kemungkinan vhost masih memakai directive coraza. nginx.conf dikembalikan."
    cz_nginx_reload_verified >/dev/null 2>&1 || true
    return 1
  fi
  say "load_module coraza dicabut dan nginx direload (backup: $bak)"
}


# ------------------------------------------------------ ketahanan (fail-safe) --
# Worker Coraza MATI bila satu aturan salah, dan `nginx -t` tidak memeriksa aturan.
# Satu kesalahan kecil di ruleset bisa mematikan SEMUA situs yang dilindungi.
# do_rules_check menjalankan nginx terisolasi dengan ruleset PRODUKSI yang asli
# dan baru lolos bila permintaan sah dijawab 200 dan serangan 403.
do_rules_check() {
  cz_nginx_info >/dev/null 2>&1 || { err "nginx tidak terdeteksi"; return 1; }
  [ -f "$ZY_MAIN" ] || { err "ruleset belum disusun ($ZY_MAIN)"; return 1; }
  local key mod libver lib t port pid0 i ok blk wu
  key="$(cz_key)"
  cz_cache_ok "$key" || cz_cache_adopt || { err "modul untuk nginx $CZ_NGX_VER tidak ada di cache"; return 1; }
  mod="$CZ_CACHE/modules/$key/ngx_http_coraza_module.so"
  libver="$(cz_mf_get "$CZ_CACHE/modules/$key/MANIFEST" libcoraza)"
  lib="$CZ_CACHE/libcoraza/$libver/lib/libcoraza.so"
  t="$(mktemp -d /tmp/sentinel-rules-check.XXXXXX)"
  mkdir -p "$t/lib" "$t/logs" "$t/tmp" "$t/html"
  echo ok > "$t/html/index.html"
  cp "$mod" "$t/ngx_http_coraza_module.so"; cp "$lib" "$t/lib/libcoraza.so"
  chmod -R a+rX "$t"
  # port acak yang BENAR-BENAR bebas (bentrok port membuat uji gagal dan reload dibatalkan)
  local tries=0
  while :; do
    port=$((20000 + RANDOM % 20000)); tries=$((tries + 1))
    ss -ltnH 2>/dev/null | awk '{print $4}' | grep -q ":$port$" || break
    [ "$tries" -ge 20 ] && break
  done
  wu=""; local wuser; wuser="$(waf_web_user)"; [ -n "$wuser" ] && wu="user $wuser;"
  cat > "$t/nginx.conf" <<EOF
load_module $t/ngx_http_coraza_module.so;
$wu
worker_processes 1;
working_directory /;
pid $t/nginx.pid;
error_log $t/logs/error.log notice;
events { worker_connections 64; }
http {
  $(cz_lua_line)
  access_log off;
  client_body_temp_path $t/tmp/b; proxy_temp_path $t/tmp/p;
  fastcgi_temp_path $t/tmp/f; uwsgi_temp_path $t/tmp/u; scgi_temp_path $t/tmp/s;
  server {
    listen 127.0.0.1:$port;
    coraza on;
    coraza_rules_file $ZY_MAIN;
    root $t/html;
    location / { }
  }
}
EOF
  if ! LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" $(cz_elog_args "$t") -t >"$t/logs/t.out" 2>&1; then
    err "ruleset ditolak (nginx -t terisolasi):"; sed 's/^/    /' "$t/logs/t.out" | tail -5 >&2
    rm -rf "$t"; return 1
  fi
  LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" $(cz_elog_args "$t") >"$t/logs/run.out" 2>&1
  pid0="$(cat "$t/nginx.pid" 2>/dev/null)"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(cz_http "http://127.0.0.1:$port/")" != "000" ] && break
    [ -n "$pid0" ] && ! kill -0 "$pid0" 2>/dev/null && break
    sleep 1
  done
  ok="$(cz_http "http://127.0.0.1:$port/")"
  blk="$(cz_http "http://127.0.0.1:$port/?id=1%20UNION%20SELECT%201,2,3--")"
  [ -n "$pid0" ] && kill "$pid0" 2>/dev/null
  sleep 1
  # Serangan uji HARUS 403 hanya bila WAF memang menahan permintaan dari 127.0.0.1: pada mode
  # monitor/disable, atau bila loopback ada di daftar putih IP, 200 adalah jawaban yang benar.
  local wajib_blok=1 mode_now
  mode_now="$(waf_conf_get mode block 2>/dev/null)"
  case "$mode_now" in monitor|disable) wajib_blok=0 ;; esac
  if grep -E '@ipMatch ([^" ]*,)?127\.' "$ZY_DIR/gen/lists.conf" 2>/dev/null | grep -q 'ruleEngine=Off'; then wajib_blok=0; fi
  if [ "$ok" = "200" ] && { [ "$blk" = "403" ] || [ "$wajib_blok" = "0" ]; }; then
    rm -rf "$t"; say "uji ruleset produksi: OK (sah=$ok, serangan=$blk, wajib_blok=$wajib_blok)"; return 0
  fi
  err "uji ruleset produksi GAGAL (sah=$ok, serangan=$blk). Cuplikan log:"
  tail -n 6 "$t/logs/error.log" 2>/dev/null | sed 's/^/    /' >&2
  rm -rf "$t"; return 1
}

# true bila nginx aktif memuat modul Coraza dan ada vhost yang memakainya
waf_nginx_dipakai() {
  grep -qE "$CZ_LOAD_RE" "$NGINX_CONF" 2>/dev/null || return 1
  ls "$NGINX_VHOST"/extension/*/sentinel-waf.conf >/dev/null 2>&1
}

# Penjaga (dipanggil timer 5 menit): bila nginx memuat modul Coraza tetapi konfigurasinya
# tidak lagi lolos `nginx -t` (mis. nginx di-upgrade aaPanel sehingga modul tidak
# cocok), WAF dicabut AGAR NGINX TIDAK MATI saat restart/reload berikutnya. Hanya berkas
# milik plugin yang disentuh; backup berdampingan; semua dicatat.
# Cabut WAF dari nginx dengan aman: snippet vhost milik plugin, lalu load_module dan
# working_directory yang ditambahkan plugin; uji; reload atau mulai ulang; bila nginx -t
# tetap gagal (penyebabnya bukan WAF) semuanya dikembalikan. $1 = alasan (untuk log).
waf_cabut_semua() {  # $1 = alasan, $2 = tanpa-restart (dari ExecStartPre nginx: nginx sedang akan start)
  local alasan="$1" ts bdir f n=0
  ts="$(date +%Y%m%d%H%M%S)"
  bdir="$(dirname "$ZY_DIR")/backup/guard-$ts"
  mkdir -p "$bdir" 2>/dev/null
  for f in "$NGINX_VHOST"/extension/*/sentinel-waf.conf; do
    [ -f "$f" ] || continue
    cp -p "$f" "$bdir/$(basename "$(dirname "$f")").conf" 2>/dev/null
    rm -f "$f"; n=$((n + 1))
  done
  say "$n snippet vhost dicabut (cadangan: $bdir)"
  cp -p "$NGINX_CONF" "$NGINX_CONF.bak.$ts" || return 1
  sed -i -E "/$CZ_LOAD_RE/d; /# sentinel-coraza\$/d" "$NGINX_CONF"
  if "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful'; then
    waf_set guard_dicabut "$ts"
    say "load_module coraza dicabut dari nginx.conf ($alasan; backup: $NGINX_CONF.bak.$ts)"
    if [ "${2:-}" = tanpa-restart ]; then
      say "nginx akan start dengan konfigurasi tanpa WAF (proteksi dipulihkan setelah konektor disesuaikan)"
      return 0
    fi
    if [ -n "$(cz_master_pid)" ]; then
      # master hidup tetapi tanpa worker: reload cukup, master membuat worker baru dari config baru
      nginx_reload_langsung
      sleep 4
      if [ "$(cz_workers_hidup)" -lt 1 ]; then
        say "worker belum hidup setelah reload, restart nginx"
        if ! nginx_jadwalkan restart; then
          if [ -x "$NGINX_INIT" ]; then (cd / && "$NGINX_INIT" restart) >/dev/null 2>&1; else "$NGINX_BIN" -s stop; sleep 2; (cd / && "$NGINX_BIN"); fi
          sleep 3
        fi
      fi
    else
      say "nginx tidak berjalan, memulai ulang"
      if ! nginx_jadwalkan start; then
        if [ -x "$NGINX_INIT" ]; then (cd / && "$NGINX_INIT" start) >/dev/null 2>&1; else (cd / && "$NGINX_BIN"); fi
        sleep 3
      fi
    fi
    if [ "${NGINX_DIJADWALKAN:-0}" = 1 ]; then
      say "nginx akan melayani kembali setelah layanan ini selesai (job systemd dijadwalkan)"
    else
      [ "$(cz_workers_hidup)" -ge 1 ] && say "nginx melayani kembali ($(cz_workers_hidup) worker hidup)" || err "nginx TIDAK punya worker hidup; periksa manual"
    fi
    return 0
  fi
  # penyebabnya ternyata bukan modul: kembalikan semuanya
  cp -p "$NGINX_CONF.bak.$ts" "$NGINX_CONF"
  for f in "$bdir"/*.conf; do
    [ -f "$f" ] || continue
    mkdir -p "$NGINX_VHOST/extension/$(basename "$f" .conf)" && cp -p "$f" "$NGINX_VHOST/extension/$(basename "$f" .conf)/sentinel-waf.conf"
  done
  err "nginx -t masih gagal setelah WAF dicabut; semua dikembalikan seperti semula"
  return 1
}

# Penjaga (dipanggil timer 5 menit). Bertindak hanya bila nginx memuat modul Coraza DAN
#  (a) `nginx -t` gagal (mis. nginx di-upgrade sehingga modul tidak cocok), atau
#  (b) master hidup tetapi TIDAK ADA worker hidup (aturan ditolak / worker mati fatal).
do_guard() {
  grep -qE "$CZ_LOAD_RE" "$NGINX_CONF" 2>/dev/null || return 0
  [ -x "$NGINX_BIN" ] || return 0
  local out stempel=/www/server/sentinel/run/nginx-t.ok
  # nginx -t (memuat Coraza + seluruh ruleset) hanya bila biner, modul, atau konfigurasi nginx berubah sejak tes terakhir yang
  # lulus: dulu dijalankan tiap 5 menit (288 kali sehari, lonjakan CPU/RAM). Pemeriksaan worker hidup (b) tetap tiap kali.
  if [ -f "$stempel" ] && [ ! "$NGINX_BIN" -nt "$stempel" ] \
     && [ -z "$(find "$(dirname "$NGINX_CONF")" "$NGINX_VHOST" /www/server/nginx/modules /www/server/sentinel/waf -newer "$stempel" \( -name '*.conf' -o -name '*.so' \) -print -quit 2>/dev/null)" ]; then
    out="test is successful (tanpa perubahan sejak tes terakhir)"
  else
    out="$("$NGINX_BIN" -t 2>&1)"
    printf '%s' "$out" | grep -q 'test is successful' && touch "$stempel" 2>/dev/null
  fi
  if ! printf '%s' "$out" | grep -q 'test is successful'; then
    err "nginx -t GAGAL dengan modul Coraza dimuat ($(printf '%s' "$out" | tail -1 | cut -c1-120)). Mencoba mencabut WAF supaya nginx tetap bisa start/reload."
    if printf '%s' "$out" | grep -q 'instead of'; then
      # modul dibangun untuk versi nginx lain (nginx di-upgrade): cabut lalu sesuaikan konektor otomatis
      waf_cabut_semua "nginx di-upgrade: modul Coraza untuk versi lain" || return $?
      waf_set coraza_sesuai 1; coraza_sesuai_jadwalkan; return 0
    fi
    waf_cabut_semua "nginx -t gagal"; return $?
  fi
  if [ -n "$(cz_master_pid)" ] && [ "$(cz_workers_hidup)" -lt 1 ]; then
    # Worker Coraza butuh beberapa detik memuat runtime Go + ruleset saat nginx baru start (boot: BT-Panel menyalakan nginx bersamaan dengan
    # sentinel-fw.service; restart). Dulu menunggu 3 detik lalu mencabut WAF: WAF tercabut diam-diam setelah reboot (VM aaPanel 10 Nov 2026).
    local umur up i
    umur="$(ps -o etimes= -p "$(cz_master_pid)" 2>/dev/null | tr -d ' ')"; up="$(cut -d. -f1 /proc/uptime 2>/dev/null)"
    if [ "${umur:-0}" -lt 60 ] || [ "${up:-0}" -lt 300 ]; then
      say "nginx baru start (master ${umur:-?} dtk, uptime ${up:-?} dtk): pemeriksaan worker ditunda ke giliran berikutnya"
      return 0
    fi
    for i in $(seq 1 15); do [ "$(cz_workers_hidup)" -ge 1 ] && break; sleep 1; done
    # penyebab yang bisa dipulihkan tanpa mencabut WAF: direktori kerja master hilang (worker Coraza gagal getwd)
    if [ "$(cz_workers_hidup)" -lt 1 ] && nginx_cwd_hilang; then
      nginx_restart_bersih
      # restart dijadwalkan lewat systemd (guard di dalam sentinel-fw.service): belum bisa diperiksa sekarang; giliran guard berikutnya memeriksa
      [ "${NGINX_DIJADWALKAN:-0}" = 1 ] && return 0
      [ "$(cz_workers_hidup)" -ge 1 ] && { say "worker nginx pulih setelah restart dari / (WAF tetap aktif)"; return 0; }
    fi
    if [ "$(cz_workers_hidup)" -lt 1 ]; then
      err "master nginx hidup tetapi tidak ada worker hidup: semua situs menggantung. Mencabut WAF."
      waf_cabut_semua "tanpa worker hidup"; return $?
    fi
  fi
  return 0
}

case "${1:-help}" in
  engine) do_engine ;;
  mode-get)  do_mode_get ;;
  mode-set)  do_mode_set "${2:?mode}" ;;
  zyrules-install) do_zyrules_install ;;
  zyrules-build)   do_zyrules_build ;;
  zyrules-status)  do_zyrules_status ;;
  modul-set)   do_modul_set "${2:?modul}" "${3:?on|off}" ;;
  setting-set) do_setting_set "${2:?kunci}" "${3:?nilai}" ;;
  reload)      do_reload "${2:-all}" ;;
  realip)      do_realip ;;
  coraza-status)   do_coraza_status ;;
  coraza-download) do_coraza_download ;;
  coraza-build)    shift; do_coraza_build "$@" ;;
  coraza-cache)    do_coraza_cache ;;
  coraza-adopt)    cz_cache_adopt ;;
  coraza-selftest) do_coraza_selftest ;;
  coraza-install)  do_coraza_install ;;
  coraza-uninstall) do_coraza_uninstall ;;
  modsec-install) do_modsec_install ;;
  strip-includes) do_strip_includes ;;
  rules)  do_rules ;;
  rule-on)  do_rule_set on "${2:?nama rule}" ;;
  rule-off) do_rule_set off "${2:?nama rule}" ;;
  vhosts) do_vhosts ;;
  akses-sync) do_akses_sync ;;
  vhost-on)  do_vhost_set "${2:?ws}" "${3:?site}" on ;;
  vhost-off) do_vhost_set "${2:?ws}" "${3:?site}" off ;;
  apply)  do_apply ;;
  legacy-status) do_legacy_status ;;
  legacy-remove) do_legacy_remove ;;
  rules-check) do_rules_check ;;
  guard)  do_guard ;;
  nginx-prestart)   do_nginx_prestart ;;
  coraza-sesuaikan) do_coraza_sesuaikan ;;
  help|*) cat <<'EOF'
Usage: sentinel-waf.sh <command>
  engine                 deteksi engine WAF per webserver, CRS, ruleset, modul Coraza
  zyrules-install        pasang ruleset ZySentinel dari payload lalu susun konfigurasi
  zyrules-build          susun ulang konfigurasi turunan (gen/) dari waf.conf dan daftar
  zyrules-status         status ruleset dalam JSON
  modul-set <nama> <on|off>   hidupkan/matikan modul ZySentinel
  setting-set <kunci> <nilai> bot_level|strict|fallback|paranoia|threshold|body_nofiles_kb|body_total_mb
  rules                  daftar grup OWASP CRS (nama|on|off|berkas|kunci)
  rule-on <nama>         aktifkan satu grup CRS
  rule-off <nama>        nonaktifkan satu grup CRS
  vhosts                 daftar vhost (ws|site|on|off)
  vhost-on <ws> <site>   lindungi satu vhost
  vhost-off <ws> <site>  lepas perlindungan satu vhost
  apply                  pasang semua keinginan yang tertunda
  reload [ws]            reload web server dengan verifikasi (nginx|apache|openlitespeed|all)
  realip                 real IP pengunjung di balik proxy/CDN (sentinel-realip.conf per vhost nginx/Apache)
  mode-get               tampilkan mode WAF
  mode-set <m>           setel mode: disable | monitor | block
  legacy-status          adakah peninggalan engine Lua (lua_waf/free_waf)
  rules-check            uji ruleset produksi di nginx terisolasi (sah=200, serangan=403)
  guard                  cabut WAF bila nginx -t gagal karena modul Coraza (dipanggil timer)
  nginx-prestart         ExecStartPre nginx.service: modul Coraza tidak cocok nginx baru = WAF dilepas sementara, penyesuaian dijadwalkan
  coraza-sesuaikan       compile + muat konektor untuk nginx aktif lalu pulihkan vhost terlindungi (setelah upgrade nginx)
  legacy-remove          pindahkan daftar, cabut hook Lua (terverifikasi), arsipkan lalu hapus berkas Lua
  coraza-status          status aset Coraza (aset, versi, konektor)
  coraza-download        unduh OWASP CRS + source konektor Coraza
  coraza-build [--force|--refresh]
                         compile modul dinamis Coraza sesuai nginx aktif (cache dipakai
                         ulang bila versi dan argumen nginx sama)
  coraza-cache           status cache modul terhadap nginx aktif
  coraza-adopt           isi ulang cache dari modul Coraza yang sudah terpasang (bila cache hilang)
  coraza-selftest        uji modul di nginx sementara (nginx produksi tidak disentuh)
  modsec-install         pasang ModSecurity v2 untuk Apache dari repo OS (Debian: libapache2-mod-security2, RHEL: mod_security)
  coraza-install         muat modul ke nginx aktif (uji, load_module, nginx -t, reload)
  coraza-uninstall       cabut load_module coraza dari nginx aktif
EOF
esac
