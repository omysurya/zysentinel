#!/bin/bash
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
NGINX_VHOST=/www/server/panel/vhost/nginx
APACHE_VHOST=/www/server/panel/vhost/apache
OLS_VHOST=/www/server/panel/vhost/openlitespeed

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

payload_dir() {
  if [ -n "${SENTINEL_PAYLOAD:-}" ] && [ -d "$SENTINEL_PAYLOAD" ]; then
    printf '%s' "$SENTINEL_PAYLOAD"
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

do_zyrules_build() {
  [ -f "$ZYGEN" ] || ZYGEN="$(payload_dir)/sentinel-zyrules.py"
  [ -f "$ZYGEN" ] || { err "sentinel-zyrules.py tidak ditemukan"; return 1; }
  "$(zy_py)" "$ZYGEN" build
}

do_zyrules_status() {
  [ -f "$ZYGEN" ] || ZYGEN="$(payload_dir)/sentinel-zyrules.py"
  "$(zy_py)" "$ZYGEN" status
}

zy_ready() { [ -f "$ZY_MAIN" ]; }

# ------------------------------------------------------------- deteksi --
cz_modul_state() {
  # dimuat | tersimpan (ada di cache, cocok dengan nginx aktif) | tidak-ada
  if grep -qE '^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_coraza_module' "$NGINX_CONF" 2>/dev/null; then
    printf 'dimuat'
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
       && [ -f "${SENTINEL_NGINX_MODDIR:-/www/server/nginx/modules}/ngx_http_coraza_module.so" ]; then
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

KUNCI_MODUL="sensitive_files webshell spam scanner bot lfi_args"

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
  local ws d site snip keadaan skip f b
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
<IfModule security2_module>
    SecRuleEngine On
    Include $ZY_MAIN
    Alias /__zysentinel_403.html $ZY_DIR/gen/html/apache/__zysentinel_403.html
    <Directory $ZY_DIR/gen/html/apache>
        Require all granted
        <IfModule include_module>
            Options +Includes
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
# 2) Tambahkan blok yang sama di vhconf.conf vhost yang dilindungi:
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

do_vhost_set() {
  # $1 = ws, $2 = site, $3 = on|off
  local ws="$1" site="$2" aksi="$3" snip dirn eng
  case "$ws" in nginx|apache|openlitespeed|ols) ;; *)
    err "webserver tidak dikenal: $ws (nginx|apache|openlitespeed)"; return 1 ;;
  esac
  [ "$ws" = "ols" ] && ws="openlitespeed"
  case "$site" in ''|*/*|.*|*[!A-Za-z0-9._-]*) err "nama situs tidak valid: $site"; return 1 ;; esac
  if [ ! -f "$(vhost_dir "$ws")/$site.conf" ]; then
    err "vhost tidak ada: $ws/$site"; return 1
  fi
  snip="$(snippet_path "$ws" "$site")"

  if [ "$aksi" = "off" ]; then
    rm -f "$snip"
    waf_set "vhost.$ws.$site" "off"
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

  if [ "$ws" = "nginx" ]; then
    if ! "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful'; then
      err "nginx -t GAGAL setelah snippet ditulis. Rollback."
      rm -f "$snip"
      "$NGINX_BIN" -t 2>&1 | tail -3 >&2
      return 1
    fi
    say "nginx -t OK"
  fi
  waf_set "vhost.$ws.$site" "on"
  say "$ws/$site -> on (snippet: $snip)"
}

nginx_reload_ok() {
  # Reload dengan verifikasi PID worker, bukan percaya output "done".
  local sebelum sesudah
  sebelum="$(ps -o pid= -C nginx 2>/dev/null | sort | tr -d ' ' | tr '\n' ',')"
  /etc/init.d/nginx reload >/dev/null 2>&1
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
CZ_CACHE="${SENTINEL_CORAZA_CACHE:-$PLUGIN_DIR/coraza-cache}"
CZ_BUILD="${SENTINEL_CORAZA_BUILD:-$CORAZA_DIR/build}"
NGINX_MODDIR="${SENTINEL_NGINX_MODDIR:-/www/server/nginx/modules}"
GO_SDK_DIR="${SENTINEL_GO_SDK_DIR:-/usr/local/btgojdk}"
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
  local a
  for a in $CZ_NGX_ARGS; do
    case "$a" in
      --prefix=*|--user=*|--group=*|--add-module=*|--add-dynamic-module=*) ;;
      --with-openssl=*|--with-pcre=*|--with-pcre|--with-zlib=*|--with-libatomic=*) ;;
      --with-ld-opt=*|--with-cc-opt=*) ;;
      *) printf '%s\n' "$a" ;;
    esac
  done
}

# Kunci cache = versi nginx + hash argumen + arsitektur.
cz_key() {
  printf '%s-%s' "$CZ_NGX_VER" \
    "$( { cz_sig_args; uname -m; } | sha256sum | cut -c1-10)"
}

cz_sig_of() { grep -aoE '[0-9]+,[0-9]+,[0-9]+,[01]{20,}' "$1" 2>/dev/null | sort -u | head -1; }

cz_prereq() {
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
cz_go_install() {
  local min="$1" pilih="" v prev
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
  for u in "https://node.aapanel.com/src/nginx-$v.tar.gz" "https://nginx.org/download/nginx-$v.tar.gz"; do
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

do_coraza_build() {
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
  local inc="$CZ_CACHE/libcoraza/$CZ_LIBVER/include" args=()
  while IFS= read -r a; do args+=("$a"); done < <(cz_sig_args)
  if ! ( cd "$nsrc" && cz_lowprio ./configure "${args[@]}" \
          --add-dynamic-module="$CZ_BUILD/coraza-nginx" \
          --with-cc-opt="-I$inc -Wno-error -Wno-unused-function" ) >"$CZ_BUILD/configure.log" 2>&1; then
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
  } > "$d/MANIFEST"
  printf '%s\n' "$CZ_NGX_ARGS" > "$d/nginx-configure-args.txt"
  rm -rf "$nsrc" "$CZ_BUILD/coraza-nginx" "$CZ_BUILD/libcoraza"
  say "selesai: modul Coraza untuk nginx $CZ_NGX_VER tersimpan di $d"
  say "tidak ada yang dimuat ke nginx; jalankan coraza-selftest lalu coraza-install"
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
  if ! LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" -e "$t/logs/startup.log" -t >"$t/logs/t.out" 2>&1; then
    err "nginx -t menolak konfigurasi uji:"; sed 's/^/    /' "$t/logs/t.out" >&2
    rm -rf "$t"; return 1
  fi
  say "nginx -t pada konfigurasi uji: sukses (modul dimuat, signature cocok)"
  LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" -e "$t/logs/startup.log" >"$t/logs/run.out" 2>&1
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
cz_master_pid() { ps -C nginx -o pid=,args= 2>/dev/null | awk '/master process/ {print $1; exit}'; }
cz_workers_hidup() {
  local m; m="$(cz_master_pid)"; [ -n "$m" ] || { echo 0; return; }
  ps -o stat=,args= --ppid "$m" 2>/dev/null | awk '$1 !~ /^Z/ && /nginx: worker/ {n++} END {print n+0}'
}

cz_nginx_reload_verified() {
  # nginx -t, reload, lalu bukti PID worker berubah (init.d selalu mencetak "done").
  local b a
  "$NGINX_BIN" -t >/dev/null 2>&1 || return 2
  b="$(cz_worker_pids)"
  if [ -x "$NGINX_INIT" ]; then "$NGINX_INIT" reload >/dev/null 2>&1; else "$NGINX_BIN" -s reload; fi
  sleep 5
  a="$(cz_worker_pids)"
  [ "$b" != "$a" ] || return 3
  # worker baru harus benar-benar hidup (aturan salah = worker mati fatal, master tetap ada)
  [ "$(cz_workers_hidup)" -ge 1 ] || return 4
}

do_coraza_install() {
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
  if id www >/dev/null 2>&1 && command -v runuser >/dev/null 2>&1; then
    runuser -u www -- test -r "$NGINX_MODDIR/libcoraza.so" \
      || { err "user www tidak bisa membaca $NGINX_MODDIR/libcoraza.so"; return 1; }
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
  cz_cache_ok "$key" || { err "modul untuk nginx $CZ_NGX_VER tidak ada di cache"; return 1; }
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
  wu=""; id -u www >/dev/null 2>&1 && wu="user www;"
  cat > "$t/nginx.conf" <<EOF
load_module $t/ngx_http_coraza_module.so;
$wu
worker_processes 1;
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
  if ! LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" -e "$t/logs/startup.log" -t >"$t/logs/t.out" 2>&1; then
    err "ruleset ditolak (nginx -t terisolasi):"; sed 's/^/    /' "$t/logs/t.out" | tail -5 >&2
    rm -rf "$t"; return 1
  fi
  LD_LIBRARY_PATH="$t/lib" "$NGINX_BIN" -p "$t" -c "$t/nginx.conf" -e "$t/logs/startup.log" >"$t/logs/run.out" 2>&1
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
waf_cabut_semua() {
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
    if [ -n "$(cz_master_pid)" ]; then
      # master hidup tetapi tanpa worker: reload cukup, master membuat worker baru dari config baru
      if [ -x "$NGINX_INIT" ]; then "$NGINX_INIT" reload >/dev/null 2>&1; else "$NGINX_BIN" -s reload; fi
      sleep 4
      if [ "$(cz_workers_hidup)" -lt 1 ]; then
        say "worker belum hidup setelah reload, restart nginx"
        if [ -x "$NGINX_INIT" ]; then "$NGINX_INIT" restart >/dev/null 2>&1; else "$NGINX_BIN" -s stop; sleep 2; (cd / && "$NGINX_BIN"); fi
        sleep 3
      fi
    else
      say "nginx tidak berjalan, memulai ulang"
      if [ -x "$NGINX_INIT" ]; then "$NGINX_INIT" start >/dev/null 2>&1; else (cd / && "$NGINX_BIN"); fi
      sleep 3
    fi
    [ "$(cz_workers_hidup)" -ge 1 ] && say "nginx melayani kembali ($(cz_workers_hidup) worker hidup)" || err "nginx TIDAK punya worker hidup; periksa manual"
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
  local out
  out="$("$NGINX_BIN" -t 2>&1)"
  if ! printf '%s' "$out" | grep -q 'test is successful'; then
    err "nginx -t GAGAL dengan modul Coraza dimuat ($(printf '%s' "$out" | tail -1 | cut -c1-120)). Mencoba mencabut WAF supaya nginx tetap bisa start/reload."
    waf_cabut_semua "nginx -t gagal"; return $?
  fi
  if [ -n "$(cz_master_pid)" ] && [ "$(cz_workers_hidup)" -lt 1 ]; then
    sleep 3
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
  coraza-status)   do_coraza_status ;;
  coraza-download) do_coraza_download ;;
  coraza-build)    shift; do_coraza_build "$@" ;;
  coraza-cache)    do_coraza_cache ;;
  coraza-selftest) do_coraza_selftest ;;
  coraza-install)  do_coraza_install ;;
  coraza-uninstall) do_coraza_uninstall ;;
  rules)  do_rules ;;
  rule-on)  do_rule_set on "${2:?nama rule}" ;;
  rule-off) do_rule_set off "${2:?nama rule}" ;;
  vhosts) do_vhosts ;;
  vhost-on)  do_vhost_set "${2:?ws}" "${3:?site}" on ;;
  vhost-off) do_vhost_set "${2:?ws}" "${3:?site}" off ;;
  apply)  do_apply ;;
  legacy-status) do_legacy_status ;;
  legacy-remove) do_legacy_remove ;;
  rules-check) do_rules_check ;;
  guard)  do_guard ;;
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
  mode-get               tampilkan mode WAF
  mode-set <m>           setel mode: disable | monitor | block
  legacy-status          adakah peninggalan engine Lua (lua_waf/free_waf)
  rules-check            uji ruleset produksi di nginx terisolasi (sah=200, serangan=403)
  guard                  cabut WAF bila nginx -t gagal karena modul Coraza (dipanggil timer)
  legacy-remove          pindahkan daftar, cabut hook Lua (terverifikasi), arsipkan lalu hapus berkas Lua
  coraza-status          status aset Coraza (aset, versi, konektor)
  coraza-download        unduh OWASP CRS + source konektor Coraza
  coraza-build [--force|--refresh]
                         compile modul dinamis Coraza sesuai nginx aktif (cache dipakai
                         ulang bila versi dan argumen nginx sama)
  coraza-cache           status cache modul terhadap nginx aktif
  coraza-selftest        uji modul di nginx sementara (nginx produksi tidak disentuh)
  coraza-install         muat modul ke nginx aktif (uji, load_module, nginx -t, reload)
  coraza-uninstall       cabut load_module coraza dari nginx aktif
EOF
esac
