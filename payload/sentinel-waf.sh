#!/bin/bash
# ============================================================
# sentinel-waf.sh -- pengelola WAF (Coraza / ModSecurity + OWASP CRS)
#
# Tugas skrip ini BUKAN menjalankan engine WAF, melainkan mengelola
# KONFIGURASINYA: rule OWASP mana yang aktif, dan vhost mana yang
# dilindungi. Engine-nya sendiri (konektor nginx/apache/OLS) adalah
# prasyarat terpisah, lihat bagian DETEKSI ENGINE di bawah.
#
# Keadaan di mesin ini (Oktober 2026):
#   - nginx 1.31.6 berjalan TANPA modul WAF (--with-compat tidak ada,
#     nginx -V tidak menyebut modsecurity maupun coraza).
#   - apache dan openlitespeed TIDAK terpasang (hanya berkas vhost).
#   - Aturan CRS lengkap tersedia di /www/server/modsec (27 berkas).
#   - owasp.conf kurasi sudah ada (8 aktif, 23 nonaktif).
#
# Aturan main:
#   1. Keinginan (desired state) disimpan di waf.conf. Keadaan aktif
#      dibaca dari berkas konfigurasi yang sebenarnya (owasp.conf dan
#      snippet extension). Keduanya DITAMPILKAN berdampingan supaya
#      selisihnya terlihat, bukan disembunyikan.
#   2. Snippet nginx TIDAK PERNAH ditulis bila engine tidak terdeteksi.
#      Directive modsecurity/coraza tidak dikenal nginx polos, sehingga
#      satu baris yang salah membuat nginx -t GAGAL dan reload berikutnya
#      ditolak diam-diam (master tetap pakai worker lama).
#   3. Setiap penulisan snippet nginx diikuti nginx -t. Gagal berarti
#      rollback otomatis (snippet dihapus) dan perintah mengembalikan
#      kode bukan-nol.
#   4. Snippet apache dibungkus <IfModule> sehingga aman walau modul
#      belum ada. Snippet OLS ditulis terpisah dan TIDAK disuntik
#      otomatis ke detail conf (format OLS tidak bisa diverifikasi
#      tanpa OLS terpasang).
# ============================================================
set -u

WAF_CONF="${SENTINEL_WAF_CONF:-/www/server/sentinel/etc/waf.conf}"
# Aset WAF kini bermaster di /www/server/sentinel/waf/ supaya tidak
# berceceran. Path lama (/www/server/modsec, dst) tetap ada sebagai
# symlink, jadi vhost dan owasp.conf yang menyebut path lama tetap
# valid. Skrip memakai path BARU supaya jelas mana sumber kebenarannya.
WAF_BASE="${SENTINEL_WAF_BASE:-/www/server/sentinel/waf}"
OWASP="${SENTINEL_OWASP:-$WAF_BASE/modsec/owasp.conf}"
NGINX_BIN="${SENTINEL_NGINX:-/www/server/nginx/sbin/nginx}"
NGINX_CONF="${SENTINEL_NGINX_CONF:-/www/server/nginx/conf/nginx.conf}"
NGINX_VHOST=/www/server/panel/vhost/nginx
APACHE_VHOST=/www/server/panel/vhost/apache
OLS_VHOST=/www/server/panel/vhost/openlitespeed

say() { printf '[sentinel-waf] %s\n' "$*"; }
err() { printf '[sentinel-waf] GALAT: %s\n' "$*" >&2; }

# ---------------------------------------------------------------- deteksi --
waf_conf_get() {
  local v=""
  if [ -f "$WAF_CONF" ]; then
    v="$(sed -n -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*([^#]*).*/\1/p" \
         "$WAF_CONF" 2>/dev/null | head -1)"
    v="$(printf '%s' "$v" | tr -d ' \t\r')"
  fi
  [ -n "$v" ] && printf '%s' "$v" || printf '%s' "$2"
}

do_engine() {
  # Satu baris per webserver: nginx=<none|modsecurity|coraza> dst.
  # apache/ols dilaporkan termasuk ketiadaannya, supaya UI tidak
  # menampilkan seolah-olah bisa diaktifkan padahal servernya mati.
  local n a o
  n="none"
  if [ -x "$NGINX_BIN" ]; then
    v="$("$NGINX_BIN" -V 2>&1 || true)"
    case "$v" in
      *[Cc]oraza*) n="coraza" ;;
      *[Mm]od[Ss]ecurity*) n="modsecurity" ;;
      *)
        if [ "$v" != "${v#*lua_nginx_module}" ]; then
          if [ -f "$FREEWAF_CONF" ] || [ -f /www/server/panel/vhost/nginx/sentinel_waf.conf ] || [ -f /www/server/panel/vhost/nginx/free_waf.conf ]; then
            n="lua_waf"
          fi
        fi
        ;;
    esac
  else
    n="nginx-tidak-ada"
  fi
  a="tidak-terpasang"
  for b in /www/server/apache/bin/httpd /usr/sbin/apache2 /usr/sbin/httpd; do
    [ -x "$b" ] && { a="terpasang-tanpa-waf"; break; }
  done
  if [ "$a" = "terpasang-tanpa-waf" ]; then
    for b in /www/server/apache/bin/httpd /usr/sbin/apache2 /usr/sbin/httpd; do
      [ -x "$b" ] || continue
      if "$b" -M 2>/dev/null | grep -qiE 'security2_module|coraza'; then
        a="terpasang-dengan-waf"; break
      fi
    done
  fi
  o="tidak-terpasang"
  [ -x /usr/local/lsws/bin/openlitespeed ] && o="terpasang-tanpa-waf"
  [ -x /usr/local/lsws/bin/litespeed ] && o="terpasang-tanpa-waf"
  printf 'nginx=%s\napache=%s\nopenlitespeed=%s\n' "$n" "$a" "$o"
  printf 'owasp=%s\n' "$([ -f "$OWASP" ] && echo ada || echo hilang)"
  printf 'directives_verified=%s\n' "$(waf_conf_get directives_verified 0)"
}

# ----------------------------------------------------------------- rules --
rule_name() {
  # Ubah baris Include menjadi nama rule: REQUEST-942... atau *-config.
  # tr -d '\r' wajib: owasp.conf ber-CRLF, tanpa ini nama rule berekor
  # carriage return dan tidak cocok dengan apa pun di UI.
  printf '%s' "$1" | tr -d '\r' | sed -E 's|.*/||; s|\.conf$||'
}

# Entri konfigurasi inti yang TIDAK BOLEH dimatikan lewat UI.
# modsecurity.conf = engine on/off dan logging. crs-setup.conf =
# inisialisasi variabel scoring CRS. Mematikan salah satunya merusak
# seluruh WAF, bukan satu rule group.
KUNCI_RULE="modsecurity crs-setup"

do_rules() {
  # Keluaran: NAMA|keadaan|berkas|kunci. keadaan = on/off,
  # kunci = ya (tidak boleh diubah) atau tidak.
  [ -f "$OWASP" ] || { err "owasp.conf tidak ditemukan: $OWASP"; return 1; }
  grep -E '^[[:space:]]*#?[[:space:]]*Include' "$OWASP" 2>/dev/null \
    | grep -E 'crs|imunify|owasp|modsec' \
    | while IFS= read -r line; do
    s="$(printf '%s' "$line" | tr -d '\r')"
    case "$s" in
      \#*) keadaan="off" ;;
      *)   keadaan="on" ;;
    esac
    inc="$(printf '%s' "$s" | sed -E 's/^[[:space:]#]+//; s/^Include[[:space:]]+//')"
    nama="$(rule_name "$inc")"
    kunci="tidak"
    for k in $KUNCI_RULE; do
      [ "$nama" = "$k" ] && { kunci="ya"; break; }
    done
    printf '%s|%s|%s|%s\n' "$nama" "$keadaan" "$inc" "$kunci"
  done
}

do_rule_set() {
  # $1 = on|off, $2 = nama rule (mis. REQUEST-942-APPLICATION-ATTACK-SQLI)
  local aksi="$1" nama="$2" f k
  [ -f "$OWASP" ] || { err "owasp.conf hilang"; return 1; }
  for k in $KUNCI_RULE; do
    if [ "$nama" = "$k" ]; then
      err "rule $nama adalah konfigurasi inti, tidak boleh diubah."
      return 1
    fi
  done
  # cari baris Include yang mengarah ke nama itu (aktif maupun komentar)
  if ! grep -qE "^[[:space:]]*#?[[:space:]]*Include[^#]*${nama}\.conf" "$OWASP"; then
    err "rule tidak dikenal: $nama"
    return 1
  fi
  f="$OWASP.$(date +%Y%m%d%H%M%S).bak"
  cp -p "$OWASP" "$f"
  if [ "$aksi" = "on" ]; then
    sed -i -E "s|^([[:space:]]*)#[[:space:]]*(Include[^#]*${nama}\.conf)|\1\2|" "$OWASP"
  else
    sed -i -E "s|^([[:space:]]*)(Include[^#]*${nama}\.conf)|\1# \2|" "$OWASP"
  fi
  # verifikasi perubahan benar terjadi
  if [ "$aksi" = "on" ]; then
    grep -qE "^[[:space:]]*Include[^#]*${nama}\.conf" "$OWASP" \
      || { err "gagal mengaktifkan, dikembalikan"; cp -p "$f" "$OWASP"; return 1; }
  else
    grep -qE "^[[:space:]]*Include[^#]*${nama}\.conf" "$OWASP" \
      && { err "gagal menonaktifkan, dikembalikan"; cp -p "$f" "$OWASP"; return 1; }
  fi
  say "rule $nama -> $aksi (backup: $f)"
}

# ---------------------------------------------------------------- vhosts --
vhost_dir() {
  case "$1" in
    nginx) printf '%s' "$NGINX_VHOST" ;;
    apache) printf '%s' "$APACHE_VHOST" ;;
    openlitespeed|ols) printf '%s' "$OLS_VHOST" ;;
    *) return 1 ;;
  esac
}

# Berkas di direktori vhost yang BUKAN situs: helper panel, status,
# dan pemantau. Tanpa daftar ini UI akan menawarkan WAF untuk berkas
# yang bukan situs.
BUKAN_SITUS="free_waf sentinel_waf phpfpm_status waf2monitor_data"

do_vhosts() {
  # Keluaran: ws|site|keadaan. keadaan dibaca dari snippet sentinel.
  local ws d site snip keadaan skip
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
  # $1 = ws. Isi snippet sesuai engine yang terdeteksi.
  local eng
  eng="$(do_engine | sed -n 's/^'"$1"'=//p' | head -1)"
  case "$1" in
    nginx)
      case "$eng" in
        modsecurity)
          printf '# dikelola sentinel-waf.sh, jangan edit manual\nmodsecurity on;\nmodsecurity_rules_file %s;\n' "$OWASP" ;;
        coraza)
          if [ "$(waf_conf_get directives_verified 0)" = "1" ]; then
            printf '# dikelola sentinel-waf.sh, jangan edit manual\ncoraza on;\ncoraza_rules_file %s;\n' "$OWASP"
          else
            return 1
          fi
          ;;
        *) return 1 ;;
      esac
      ;;
    apache)
      # <IfModule> membuat snippet aman walau modul belum ada.
      printf '# dikelola sentinel-waf.sh, jangan edit manual\n<IfModule mod_security2.c>\n    SecRuleEngine On\n    Include %s\n</IfModule>\n' "$OWASP" ;;
    openlitespeed|ols)
      # OLS tidak diverifikasi tanpa OLS terpasang: tulis sebagai
      # contoh yang perlu di-include manual.
      printf '# CONTOH untuk OpenLiteSpeed, perlu di-include manual.\n# Lihat dokumentasi sentinel.\nmodsecurity on\nmodsecurity_rules_file %s\n' "$OWASP" ;;
  esac
}

do_vhost_set() {
  # $1 = ws, $2 = site, $3 = on|off
  local ws="$1" site="$2" aksi="$3" snip dirn eng
  case "$ws" in nginx|apache|openlitespeed|ols) ;; *)
    err "webserver tidak dikenal: $ws (nginx|apache|openlitespeed)"; return 1 ;;
  esac
  [ "$ws" = "ols" ] && ws="openlitespeed"
  if [ ! -f "$(vhost_dir "$ws")/$site.conf" ]; then
    err "vhost tidak ada: $ws/$site"; return 1
  fi
  snip="$(snippet_path "$ws" "$site")"

  if [ "$aksi" = "off" ]; then
    rm -f "$snip"
    # simpan keinginan di waf.conf
    waf_set "vhost.$ws.$site" "off"
    [ "$ws" = "nginx" ] && "$NGINX_BIN" -t 2>&1 | tail -1
    say "$ws/$site -> off"
    return 0
  fi

  # --- aksi on: gerbang engine ---
  eng="$(do_engine | sed -n "s/^$ws=//p" | head -1)"
  case "$ws" in
    nginx)
      case "$eng" in
        modsecurity) : ;;
        coraza)
          if [ "$(waf_conf_get directives_verified 0)" != "1" ]; then
            err "engine coraza terdeteksi, tetapi nama directive belum diverifikasi."
            err "Baca dokumentasi konektor coraza-nginx, lalu isi directives_verified=1 di $WAF_CONF."
            return 1
          fi
          ;;
        *)
          err "nginx berjalan TANPA modul WAF. Snippet tidak ditulis."
          err "Keinginan disimpan (vhost.$ws.$site=on) dan akan dipasang otomatis"
          err "oleh 'sentinel-waf.sh apply' setelah konektor dipasang."
          err "Membangun konektor butuh rebuild nginx: JANGAN dilakukan diam-diam di produksi."
          waf_set "vhost.$ws.$site" "on"
          return 2
          ;;
      esac
      ;;
    apache|openlitespeed)
      case "$eng" in
        tidak-terpasang)
          say "$ws tidak terpasang di mesin ini. Keinginan disimpan;"
          say "snippet ditulis sebagai berkas siap-pakai, tetapi TIDAK aktif"
          say "sampai server dipasang."
          ;;
      esac
      ;;
  esac

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

waf_set() {
  # tulis key=value ke waf.conf (idempoten, dengan backup sekali sehari)
  local f today
  [ -f "$WAF_CONF" ] || printf '# konfigurasi WAF sentinel (key = value)\n' > "$WAF_CONF"
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

# ==================================================================
# ENGINE free_waf (Nginx free firewall, difork ke Sentinel)
#
# free_waf adalah WAF Lua yang berjalan di dalam nginx lewat
# lua_nginx_module. Sifat pentingnya:
#  - nginx saja yang bisa. apache dan openlitespeed TIDAK BISA
#    menjalankan engine ini (tidak ada Lua di sana). Untuk keduanya
#    tetap dipakai jalur snippet ModSecurity/Coraza (vhost-on).
#  - Butuh lua_nginx_module terkompilasi di nginx. Tanpa itu,
#    directive access_by_lua_file tidak dikenal dan nginx -t GAGAL.
#  - Hidup berdampingan dengan aturan CRS: free_waf memeriksa pola
#    serangan umum + CC per IP, CRS memeriksa pola OWASP. Keduanya
#    tidak saling menimpa karena levelnya berbeda (Lua vs ModSecurity).
# ==================================================================
FREEWAF_HOME="${SENTINEL_FREEWAF_HOME:-$WAF_BASE/lua_waf}"
FREEWAF_CONF="${SENTINEL_FREEWAF_CONF:-/www/server/panel/vhost/nginx/sentinel_waf.conf}"
FREEWAF_LOGDIR="${SENTINEL_FREEWAF_LOGDIR:-/www/wwwlogs/free_waf_log}"

payload_dir() {
  # Lokasi payload di dalam direktori plugin. Bisa dioverride lewat
  # environment untuk pengujian.
  if [ -n "${SENTINEL_PAYLOAD:-}" ] && [ -d "$SENTINEL_PAYLOAD" ]; then
    printf '%s' "$SENTINEL_PAYLOAD"
  else
    printf '%s' "/www/server/panel/plugin/sentinel/payload"
  fi
}

nginx_has_lua() {
  [ -x "$NGINX_BIN" ] || return 1
  "$NGINX_BIN" -V 2>&1 | grep -q 'lua_nginx_module'
}

freewaf_mode() {
  # Baca mode dari config.json memakai JSON parser, BUKAN grep.
  # config.json adalah satu baris panjang berisi banyak kunci "open"
  # (open global + open di tiap modul), sehingga grep '"open": true'
  # bisa cocok pada modul dan melaporkan mode yang salah. Keluaran:
  # disable | monitor | block | tidak-diketahui
  [ -f "$FREEWAF_HOME/config.json" ] || { printf 'tidak-diketahui'; return; }
  FREEWAF_CFG="$FREEWAF_HOME/config.json" \
    /www/server/panel/pyenv/bin/python3 - <<'PY' 2>/dev/null || printf 'tidak-diketahui'
import json, os
try:
    d = json.load(open(os.environ['FREEWAF_CFG']))
except Exception:
    raise SystemExit(1)
if not isinstance(d, dict):
    raise SystemExit(1)
if not d.get('open'):
    print('disable')
elif d.get('monitor'):
    print('monitor')
else:
    print('block')
PY
}

do_freewaf_status() {
  # Satu baris per kunci, seperti do_engine.
  local lua mod conf loaded mode
  lua="tidak-ada"; nginx_has_lua && lua="ada"
  mod="tidak-ada"; [ -d "$FREEWAF_HOME/rule" ] && mod="ada"
  conf="tidak-ada"
  { [ -f "$FREEWAF_CONF" ] || [ -f "/www/server/panel/vhost/nginx/free_waf.conf" ]; } && conf="ada"
  loaded="tidak"
  if [ -x "$NGINX_BIN" ] && "$NGINX_BIN" -T 2>/dev/null | grep -qE 'access_by_lua_file.*/waf\.lua'; then
    loaded="ya"
  fi
  mode="$(freewaf_mode)"
  printf 'lua=%s\nengine_file=%s\nconf=%s\nloaded=%s\nmode=%s\nhome=%s\n' \
    "$lua" "$mod" "$conf" "$loaded" "$mode" "$FREEWAF_HOME"
}

do_freewaf_install() {
  # Pasang engine WAF untuk nginx. Idempoten: berkas config dan
  # site yang sudah ada TIDAK PERNAH ditimpa (isinya adalah keadaan
  # produksi). Hanya berkas yang hilang yang disalin dari payload.
  local P; P="$(payload_dir)"
  local P_WAF="$P/waf/lua_waf"
  [ -d "$P_WAF" ] || P_WAF="$P/lua_waf"
  [ -d "$P_WAF" ] || P_WAF="$P/free_waf"
  [ -d "$P_WAF" ] || { err "payload tidak ditemukan: $P/waf/lua_waf atau $P/lua_waf"; return 1; }
  if ! nginx_has_lua; then
    err "nginx tanpa lua_nginx_module. Engine tidak bisa dipasang."
    err "Bangun ulang nginx dengan modul lua di panel, lalu ulangi."
    return 1
  fi

  # Pasang cjson.so mandiri bila tersedia di payload
  mkdir -p "$FREEWAF_HOME/rule" "$FREEWAF_HOME/html" "$FREEWAF_LOGDIR" /usr/local/lib/lua/5.1
  if [ -f "$P_WAF/cjson.so" ]; then
    cp -p "$P_WAF/cjson.so" "$FREEWAF_HOME/cjson.so"
    [ -f /usr/local/lib/lua/5.1/cjson.so ] || cp -p "$P_WAF/cjson.so" /usr/local/lib/lua/5.1/cjson.so 2>/dev/null || true
  fi
  [ -f "$P_WAF/json_pure.lua" ] && cp -p "$P_WAF/json_pure.lua" "$FREEWAF_HOME/json_pure.lua"

  # Salin modul resty & ngx mandiri langsung ke direktori WAF dan share
  if [ -d "$P_WAF/resty" ]; then
    cp -rn "$P_WAF/resty" "$FREEWAF_HOME/" 2>/dev/null || true
    mkdir -p /usr/local/share/lua/5.1
    [ -e /usr/local/share/lua/5.1/resty ] || cp -rn "$P_WAF/resty" /usr/local/share/lua/5.1/ 2>/dev/null || true
  fi
  if [ -d "$P_WAF/ngx" ]; then
    cp -rn "$P_WAF/ngx" "$FREEWAF_HOME/" 2>/dev/null || true
  fi

  # engine: selalu segarkan dari payload (kode, bukan keadaan)
  cp -p "$P_WAF/init.lua" "$P_WAF/waf.lua" "$FREEWAF_HOME/"
  # rules: hanya yang hilang (operator boleh menambah rule sendiri)
  local f b
  for f in "$P_WAF/rule"/*.json; do
    b="$(basename "$f")"
    [ -f "$FREEWAF_HOME/rule/$b" ] || cp -p "$f" "$FREEWAF_HOME/rule/$b"
  done
  for f in "$P_WAF/html"/*.html; do
    b="$(basename "$f")"
    [ -f "$FREEWAF_HOME/html/$b" ] || cp -p "$f" "$FREEWAF_HOME/html/$b"
  done
  # keadaan: JANGAN timpa bila sudah ada
  for f in config.json site.json total.json drop_ip.log; do
    if [ ! -f "$FREEWAF_HOME/$f" ]; then
      cp -p "$P_WAF/$f.default" "$FREEWAF_HOME/$f"
      say "dibuat: $FREEWAF_HOME/$f (dari default)"
    fi
  done
  chown -R www:www "$FREEWAF_HOME" 2>/dev/null || true
  chmod 755 "$FREEWAF_HOME" "$FREEWAF_HOME/rule" "$FREEWAF_HOME/html" 2>/dev/null || true

  # hook nginx: tulis sentinel_waf.conf dari template dan bersihkan hook lama
  rm -f /www/server/panel/vhost/nginx/free_waf.conf 2>/dev/null || true
  if [ ! -f "$FREEWAF_CONF" ]; then
    if [ -f "$P_WAF/sentinel_waf.conf.template" ]; then
      cp -p "$P_WAF/sentinel_waf.conf.template" "$FREEWAF_CONF"
    else
      cp -p "$P_WAF/free_waf.conf.template" "$FREEWAF_CONF"
    fi
    say "ditulis: $FREEWAF_CONF"
  fi
  # guard duplikat: luawaf panel tidak boleh aktif bersamaan
  if grep -qE '^[[:space:]]*include[[:space:]]+luawaf\.conf' "$NGINX_CONF" 2>/dev/null; then
    err "luawaf.conf panel aktif. Dua access_by_lua per level membuat nginx gagal start."
    err "Matikan salah satunya, lalu ulangi."
    return 1
  fi
  if ! "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful'; then
    err "nginx -t GAGAL. Rollback: $FREEWAF_CONF dihapus."
    rm -f "$FREEWAF_CONF"
    "$NGINX_BIN" -t 2>&1 | tail -5 >&2
    return 1
  fi
  nginx_reload_ok || return 1
  say "engine WAF terpasang dan termuat."
}

do_freewaf_remove() {
  # Cabut hook nginx. Data (config, site, log, drop_ip) SENGAJA
  # dipertahankan supaya install ulang tidak menghilangkan keadaan.
  rm -f "$FREEWAF_CONF" /www/server/panel/vhost/nginx/free_waf.conf 2>/dev/null || true
  "$NGINX_BIN" -t 2>&1 | grep -q 'test is successful' \
    || { err "nginx -t gagal setelah pencabutan"; return 1; }
  nginx_reload_ok || return 1
  say "hook WAF dicabut. Data di $FREEWAF_HOME tetap ada."
}

nginx_reload_ok() {
  # Reload dengan verifikasi PID worker, bukan percaya output "done".
  # /etc/init.d/nginx reload selalu mencetak done walau config ditolak.
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

do_apply() {
  # Pasang semua keinginan vhost=on yang tertunda (dipakai setelah
  # engine dipasang). Melewati yang gagal, melaporkan ringkasannya.
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

# ==================================================================
# ENGINE AKTIF dan SWITCH MODE
#
# Engine aktif disimpan di waf.conf (kunci engine). Mode diatur pada
# engine itu: Disable / Monitor / Block.
#   free_waf : config.json -> open + monitor
#   coraza   : SecRuleEngine Off / DetectionOnly / On pada snippet
# ==================================================================
CORAZA_DIR="${SENTINEL_CORAZA_DIR:-$WAF_BASE/coraza}"

do_engine_set() {
  # $1 = free_waf | coraza
  local eng="$1"
  case "$eng" in free_waf|coraza) ;; *)
    err "engine harus free_waf atau coraza"; return 1 ;;
  esac
  waf_set engine "$eng"
  say "engine aktif: $eng"
}

engine_aktif() {
  waf_conf_get engine free_waf
}

do_mode_get() {
  # Keluaran: engine=... mode=disable|monitor|block
  local eng mode
  eng="$(engine_aktif)"
  case "$eng" in
    free_waf)
      # Memakai freewaf_mode() yang membaca lewat JSON parser, bukan
      # grep, supaya tidak tertipu kunci "open" bersarang.
      mode="$(freewaf_mode)"
      case "$mode" in disable|monitor|block) ;; *) mode="disable" ;; esac
      ;;
    coraza)
      # Coraza belum tentu jalan; mode dibaca dari waf.conf sebagai
      # keinginan yang akan berlaku saat konektor ada.
      mode="$(waf_conf_get mode_coraza disable)"
      ;;
    *)
      mode="disable"
      ;;
  esac
  printf 'engine=%s\nmode=%s\n' "$eng" "$mode"
}

do_mode_set() {
  # $1 = disable | monitor | block
  local eng="$1" m="$1"
  case "$m" in disable|monitor|block) ;; *)
    err "mode harus disable, monitor, atau block"; return 1 ;;
  esac
  eng="$(engine_aktif)"
  if [ "$eng" = "coraza" ]; then
    # Simpan keinginan + tulis ke snippet coraza bila konektor ada.
    waf_set mode_coraza "$m"
    say "mode coraza -> $m (berlaku saat konektor terpasang)"
    return 0
  fi
  # free_waf: ubah config.json.
  #
  # WAJIB lewat JSON parser, BUKAN sed. config.json adalah satu baris
  # panjang berisi BANYAK kunci "open": ada open global dan open di
  # dalam tiap modul (drop_abroad.open = false). sed hanya mengganti
  # kemunculan pertama pada satu baris, jadi bisa mengenai modul yang
  # salah dan meninggalkan open global tak tersentuh. Diedit lewat
  # Python supaya hanya jalur yang benar yang berubah.
  if [ ! -f "$FREEWAF_HOME/config.json" ]; then
    err "config.json free_waf tidak ada; engine belum terpasang"; return 1
  fi
  local sebelum="$FREEWAF_HOME/config.json.$(date +%Y%m%d%H%M%S).bak"
  cp -p "$FREEWAF_HOME/config.json" "$sebelum"
  if ! FREEWAF_CFG="$FREEWAF_HOME/config.json" MODE="$m" \
       /www/server/panel/pyenv/bin/python3 - <<'PY'
import json, os, sys
p = os.environ['FREEWAF_CFG']
m = os.environ['MODE']
try:
    d = json.load(open(p))
except Exception:
    sys.exit(1)
if not isinstance(d, dict):
    sys.exit(1)
# HANYA kunci tingkat akar yang diubah.
d['open'] = (m != 'disable')
if m == 'disable':
    d['monitor'] = True          # tidak memblokir apa pun saat mati
else:
    d['monitor'] = (m == 'monitor')
tmp = p + '.tmp'
json.dump(d, open(tmp, 'w'))
os.rename(tmp, p)
sys.exit(0)
PY
  then
    err "gagal mengubah config.json, dikembalikan"
    cp -p "$sebelum" "$FREEWAF_HOME/config.json"
    return 1
  fi
  do_freewaf_install >/dev/null 2>&1 || true
  say "mode free_waf -> $m"
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
  [ -d "$CORAZA_DIR/connector/.git" ] && return 0
  say "mengunduh source konektor coraza-nginx"
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
  say "mencari versi CRS terbaru dari GitHub"
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
    say "CRS $ver sudah terpasang, tidak diunduh ulang"
    unduh_konektor
    say "aset Coraza siap: CRS $ver (tidak berubah)"
    return 0
  fi

  local tmp; tmp="$(mktemp -d /tmp/sentinel-coraza.XXXXXX)"
  say "mengunduh $url"
  if ! curl -fsSL --max-time 120 -o "$tmp/crs.tar.gz" "$url" 2>/dev/null; then
    err "unduhan CRS gagal"; rm -rf "$tmp"; return 1
  fi
  # periksa arsip sebelum ekstrak
  if ! tar -tzf "$tmp/crs.tar.gz" >/dev/null 2>&1; then
    err "arsip CRS rusak"; rm -rf "$tmp"; return 1
  fi
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

  unduh_konektor
  local jml
  jml="$(find "$CORAZA_DIR/rules" -name '*.conf' 2>/dev/null | wc -l | tr -d ' ')"
  {
    printf 'crs=%s\n' "$ver"
    printf 'aturan=%s\n' "$jml"
    printf 'diunduh=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
  } > "$CORAZA_DIR/VERSIONS.txt"
  say "aset Coraza siap: CRS $ver, $jml berkas aturan"
  say "CATATAN: engine belum berjalan. Konektor nginx perlu dipasang"
  say "(butuh rebuild nginx dengan --with-compat)."
}

case "${1:-help}" in
  engine) do_engine ;;
  engine-set) do_engine_set "${2:?nama engine}" ;;
  mode-get)  do_mode_get ;;
  mode-set)  do_mode_set "${2:?mode}" ;;
  coraza-status)   do_coraza_status ;;
  coraza-download) do_coraza_download ;;
  rules)  do_rules ;;
  rule-on)  do_rule_set on "${2:?nama rule}" ;;
  rule-off) do_rule_set off "${2:?nama rule}" ;;
  vhosts) do_vhosts ;;
  vhost-on)  do_vhost_set "${2:?ws}" "${3:?site}" on ;;
  vhost-off) do_vhost_set "${2:?ws}" "${3:?site}" off ;;
  apply)  do_apply ;;
  freewaf-status) do_freewaf_status ;;
  freewaf-install) do_freewaf_install ;;
  freewaf-remove) do_freewaf_remove ;;
  help|*) cat <<'EOF'
Usage: sentinel-waf.sh <command>
  engine              deteksi engine WAF per webserver
  rules               daftar rule OWASP (nama|on|off|berkas)
  rule-on <nama>      aktifkan satu rule group
  rule-off <nama>     nonaktifkan satu rule group
  vhosts              daftar vhost (ws|site|on|off)
  vhost-on <ws> <site>   lindungi satu vhost
  vhost-off <ws> <site>  lepas perlindungan satu vhost
  apply               pasang semua keinginan yang tertunda
  freewaf-status      status engine free_waf (nginx saja)
  freewaf-install     pasang engine free_waf dari payload
  freewaf-remove      cabut hook free_waf (data dipertahankan)
  engine-set <e>      pilih engine aktif: free_waf | coraza
  mode-get            tampilkan engine aktif dan modenya
  mode-set <m>        setel mode: disable | monitor | block
  coraza-status       status aset Coraza (aset, versi, konektor)
  coraza-download     unduh OWASP CRS + source konektor Coraza
EOF
esac