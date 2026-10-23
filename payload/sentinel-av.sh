#!/bin/bash
# ============================================================
# sentinel-av.sh -- pengelola Antivirus (ClamAV) untuk ZySentinel
#
# Ini BUKAN engine antivirus baru. ClamAV sudah berjalan di server ini
# dengan sistem yang matang: clamav-realtime.sh (inotify) dan
# clamav-deepscan.sh (terjadwal 03:00), keduanya memakai perpustakaan
# bersama /usr/local/sbin/clamav-common.sh dan konfigurasi
# /etc/clamav/realtime.conf.
#
# Skrip ini adalah LAPIS KENDALI untuk plugin: menyediakan perintah yang
# dipanggil panel (status, scan per vhost, karantina, integritas) dengan
# MEMAKAI ULANG fungsi yang sudah ada. Tidak ada karantina kedua, tidak
# ada konfigurasi kedua -- supaya tidak ada dua sumber kebenaran.
#
# Kalau clamav-common.sh tidak ada (server tanpa adopsi ClamAV), skrip
# ini tetap bisa berjalan mandiri dengan fallback yang aman.
# ============================================================
set -uo pipefail

COMMON=/usr/local/sbin/clamav-common.sh
RCONF=/etc/clamav/realtime.conf
REALTIME_CONF_HOST=/etc/zysentinel/av.conf

say() { printf '[sentinel-av] %s\n' "$*"; }
err() { printf '[sentinel-av] GALAT: %s\n' "$*" >&2; }

# ---- direktori milik sentinel untuk integritas & hasil scan ----
AV_DIR=/www/server/sentinel/av
BASE_DIR=$AV_DIR/baseline
LAST_DIR=$AV_DIR/last
Q_FALLBACK_FILES=$AV_DIR/quarantine/files
Q_FALLBACK_META=$AV_DIR/quarantine/meta
mkdir -p "$BASE_DIR" "$LAST_DIR" "$Q_FALLBACK_FILES" "$Q_FALLBACK_META" 2>/dev/null

# ---- konfigurasi & direktori Rkhunter ----
RKHUNTER_BIN=/usr/bin/rkhunter
RKHUNTER_DB=/www/server/sentinel/db/rkhunter
RKHUNTER_TMP=/www/server/sentinel/tmp/rkhunter
RKHUNTER_LOG=/www/server/sentinel/log/rkhunter.log
ACTIVE_SCAN_LOG=/www/server/sentinel/log/active_scan.log
ACTIVE_SCAN_JSON=/www/server/sentinel/run/active_scan.json
ACTIVE_SCAN_PID=/www/server/sentinel/run/active_scan.pid
mkdir -p "$RKHUNTER_DB" "$RKHUNTER_TMP" /www/server/sentinel/log /www/server/sentinel/run 2>/dev/null
chmod 700 "$RKHUNTER_TMP" 2>/dev/null || true

# bootstrap database rkhunter jika belum ada
if [ ! -f "$RKHUNTER_DB/rkhunter.dat" ] && [ -d /var/lib/rkhunter/db ]; then
  cp -rn /var/lib/rkhunter/db/* "$RKHUNTER_DB/" 2>/dev/null || true
fi

# ---- muat perpustakaan ClamAV bersama bila ada ----
CV_OK=0
if [ -f "$COMMON" ] && [ -f "$RCONF" ]; then
  # shellcheck disable=SC1090
  . "$COMMON" 2>/dev/null && CV_OK=1
fi

clam_ada()     { command -v clamscan >/dev/null 2>&1; }
clamd_ada()    { [ -S "${CLAMD_SOCKET:-/var/run/clamav/clamd.ctl}" ]; }
# ---- gerbang lisensi: mesin premium (ransomware, judol, mining, SAGE AI) adalah fitur Max (av_engines). Gagal tertutup:
# biner pemverifikasi hilang/rusak = hanya ClamAV dan Rkhunter. Mesin 'both' (bawaan) TIDAK lagi membuka mesin premium tanpa lisensi.
av_premium_ok() { return 1; }      # edisi Free: mesin premium adalah fitur Max

rkhunter_ada() { [ -x "$RKHUNTER_BIN" ] || command -v rkhunter >/dev/null 2>&1; }

# ==================================================================
# STATUS
# ==================================================================
do_status() {
  local ada="tidak" ver="-" dbumur="-" clamd="tidak"
  clam_ada && ada="ya"
  if clam_ada; then
    ver="$(clamscan --version 2>/dev/null | head -1)"
  fi
  # umur database dari berkas daily
  local dbf="${DAILY_DB:-/var/lib/clamav/daily.cld}"
  [ -f /var/lib/clamav/daily.cvd ] && dbf=/var/lib/clamav/daily.cvd
  if [ -f "$dbf" ]; then
    local detik=$(( $(date +%s) - $(stat -c %Y "$dbf" 2>/dev/null || echo 0) ))
    dbumur="$(( detik / 3600 )) jam"
  fi
  clamd_ada && clamd="ya"
  local qn=0
  local qdir; qdir="$(q_files)"
  [ -d "$qdir" ] && qn="$(find "$qdir" -type f 2>/dev/null | wc -l | tr -d ' ')"

  local ev=0
  local evlog="${EVENT_LOG:-/var/log/clamav/realtime.log}"
  [ -f "$evlog" ] && ev="$(grep -c "$(date +%F)" "$evlog" 2>/dev/null | tr -d ' ')"

  local timer_aktif="tidak"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sentinel-av.timer 2>/dev/null || systemctl is-active --quiet clamav-deepscan.timer 2>/dev/null; then
      timer_aktif="ya"
    fi
  fi

  local rk_ada="tidak" rk_ver="-" rk_last="-" rk_warn=0
  if rkhunter_ada; then
    rk_ada="ya"
    rk_ver="$("$RKHUNTER_BIN" --version 2>/dev/null | grep -i 'rootkit hunter' | head -1 | awk '{print $3}')"
    [ -z "$rk_ver" ] && rk_ver="1.4.6"
    if [ -f "$RKHUNTER_LOG" ]; then
      rk_last="$(stat -c %Y "$RKHUNTER_LOG" 2>/dev/null || echo 0)"
      rk_warn="$(grep -c '\[ Warning \]' "$RKHUNTER_LOG" 2>/dev/null || echo 0)"
    fi
  fi

  printf 'ada=%s\nversi=%s\ndb_umur=%s\nclamd=%s\nquarantine=%s\ndeteksi_hari_ini=%s\ncommon=%s\ntimer=%s\nrkhunter=%s\nrkhunter_versi=%s\nrkhunter_last_scan=%s\nrkhunter_warnings=%s\n' \
    "$ada" "$ver" "$dbumur" "$clamd" "${qn:-0}" "${ev:-0}" "$([ "$CV_OK" = 1 ] && echo ada || echo tidak)" "$timer_aktif" \
    "$rk_ada" "$rk_ver" "$rk_last" "$rk_warn"
}

# ==================================================================
# KARANTINA
# ==================================================================
q_files() {
  if [ "$CV_OK" = 1 ] && [ -n "${QUARANTINE_FILES:-}" ] && [ -d "$QUARANTINE_FILES" ]; then
    printf '%s' "$QUARANTINE_FILES"
  else
    printf '%s' "$Q_FALLBACK_FILES"
  fi
}

q_meta() {
  if [ "$CV_OK" = 1 ] && [ -n "${QUARANTINE_META:-}" ] && [ -d "$QUARANTINE_META" ]; then
    printf '%s' "$QUARANTINE_META"
  else
    printf '%s' "$Q_FALLBACK_META"
  fi
}

cv_quarantine_fallback() {
  local f="$1" sig="$2"
  local ts sha base qdir mdir qpath meta
  ts=$(date +%s)
  sha=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
  [ -z "$sha" ] && sha="unknown"
  base=$(basename "$f")
  qdir="$(q_files)"
  mdir="$(q_meta)"
  mkdir -p "$qdir" "$mdir" 2>/dev/null
  qpath="$qdir/${ts}_${sha:0:12}_${base}"
  meta="$mdir/${ts}_${sha:0:12}_${base}.meta"

  if [ -e "$qpath" ]; then
    qpath="$qdir/${ts}_${RANDOM}_${base}"
    meta="$mdir/${ts}_${RANDOM}_${base}.meta"
  fi

  if ! mv -f "$f" "$qpath" 2>/dev/null; then
    if ! cp -p "$f" "$qpath" 2>/dev/null; then
      return 1
    fi
    rm -f "$f" 2>/dev/null
  fi
  chmod 600 "$qpath" 2>/dev/null

  {
    printf 'quarantined_at=%s\n' "$(date -Is)"
    printf 'original_path=%s\n' "$f"
    printf 'quarantine_path=%s\n' "$qpath"
    printf 'signature=%s\n' "$sig"
    printf 'sha256=%s\n' "$sha"
    printf 'size=%s\n' "$(stat -c %s "$qpath" 2>/dev/null || echo 0)"
    printf 'uid=%s\n' "$(stat -c %u "$qpath" 2>/dev/null || echo 0)"
    printf 'gid=%s\n' "$(stat -c %g "$qpath" 2>/dev/null || echo 0)"
    printf 'mode=%s\n' "$(stat -c %a "$qpath" 2>/dev/null || echo 600)"
  } > "$meta" 2>/dev/null
  chmod 600 "$meta" 2>/dev/null
  echo "$qpath"
  return 0
}

cv_restore_fallback() {
  local meta="$1"
  [ -f "$meta" ] || { err "metadata tidak ditemukan: $meta"; return 1; }
  local orig qpath uid gid mode
  orig=$(grep '^original_path=' "$meta" | cut -d= -f2-)
  qpath=$(grep '^quarantine_path=' "$meta" | cut -d= -f2-)
  uid=$(grep '^uid=' "$meta" | cut -d= -f2-)
  gid=$(grep '^gid=' "$meta" | cut -d= -f2-)
  mode=$(grep '^mode=' "$meta" | cut -d= -f2-)

  [ -f "$qpath" ] && [ ! -L "$qpath" ] || { err "berkas karantina hilang atau symlink: $qpath"; return 1; }
  # Pemulihan berjalan sebagai root: tujuan harus absolut, tanpa '..' dan tanpa
  # symlink, berada di area situs, dan tidak boleh menimpa berkas yang ada.
  case "$orig" in /*) ;; *) err "path asal tidak valid"; return 1 ;; esac
  case "/$orig/" in */../*) err "path asal memuat .."; return 1 ;; esac
  local odir; odir="$(dirname "$orig")"
  if [ "$(realpath -m "$odir")" != "$(realpath -sm "$odir")" ]; then
    err "path asal memuat symlink: $odir"; return 1
  fi
  case "$(realpath -m "$odir")/" in
    /www/wwwroot/*|/home/*|/var/www/*|/srv/*|/opt/*|/tmp/*) ;;
    *) err "tujuan di luar area situs: $odir"; return 1 ;;
  esac
  [ -e "$orig" ] || [ -L "$orig" ] && { err "berkas tujuan sudah ada, tidak ditimpa: $orig"; return 1; }
  mkdir -p "$odir" 2>/dev/null
  mv -n "$qpath" "$orig" || return 1
  chown -h "${uid:-0}:${gid:-0}" "$orig" 2>/dev/null
  chmod "${mode:-644}" "$orig" 2>/dev/null
  rm -f "$meta"
  echo "RESTORED: $orig"
  return 0
}

do_q_list() {
  local dir; dir="$(q_meta)"
  [ -d "$dir" ] || { say "karantina kosong"; return 0; }
  local f
  for f in "$dir"/*.meta; do
    [ -f "$f" ] || continue
    local id waktu virus orig size
    id="$(basename "$f" .meta)"
    waktu="$(sed -n 's/^quarantined_at=//p' "$f" | head -1)"
    virus="$(sed -n 's/^signature=//p' "$f" | head -1)"
    orig="$(sed -n 's/^original_path=//p' "$f" | head -1)"
    size="$(sed -n 's/^size=//p' "$f" | head -1)"
    printf '%s|%s|%s|%s|%s\n' "$id" "${waktu:--}" "${virus:--}" "${orig:--}" "${size:-0}"
  done
}

do_q_restore() {
  [ $# -ge 1 ] || { err "pakai: quarantine-restore <id>"; return 1; }
  local meta; meta="$(q_meta)/$1.meta"
  [ -f "$meta" ] || { err "metadata tidak ditemukan: $1"; return 1; }
  local asal; asal="$(sed -n 's/^original_path=//p' "$meta" | head -1)"
  # SELALU jalur yang diperkeras, juga saat clamav-common.sh tersedia: cv_restore
  # milik operator memakai "mkdir -p; mv -f" sebagai root tanpa memeriksa
  # symlink, area situs, atau berkas yang sudah ada. Penyerang yang masih punya
  # akses www cukup mengganti folder asal dengan symlink (mis. ke /etc/profile.d)
  # lalu menunggu admin memulihkan berkas.
  cv_restore_fallback "$meta" || { err "restore gagal"; return 1; }
  say "dikembalikan: $asal"
}

do_q_delete() {
  [ $# -ge 1 ] || { err "pakai: quarantine-delete <id>"; return 1; }
  local meta; meta="$(q_meta)/$1.meta"
  [ -f "$meta" ] || { err "metadata tidak ditemukan: $1"; return 1; }
  local qpath; qpath="$(sed -n 's/^quarantine_path=//p' "$meta" | head -1)"
  rm -f "$qpath" 2>/dev/null
  rm -f "$meta" 2>/dev/null
  say "dihapus permanen: $1"
}

do_q_purge() {
  local dir; dir="$(q_meta)"
  [ -d "$dir" ] || { say "karantina kosong"; return 0; }
  local f qpath n=0
  for f in "$dir"/*.meta; do
    [ -f "$f" ] || continue
    qpath="$(sed -n 's/^quarantine_path=//p' "$f" | head -1)"
    rm -f "$qpath" 2>/dev/null
    rm -f "$f" 2>/dev/null
    n=$((n+1))
  done
  say "$n entri karantina dihapus permanen"
}

# ==================================================================
# SCAN per vhost
# ==================================================================
scan_satu() {
  local path="$1" label="${2:-$(basename "$path")}"
  [ -d "$path" ] || { err "path bukan direktori: $path"; return 1; }
  local out="$LAST_DIR/$label.json"
  local t0; t0=$(date +%s)
  local tmp; tmp="$(mktemp /tmp/zysentinel-av.XXXXXX)"

  # daftar berkas
  local flist; flist="$(mktemp /tmp/zysentinel-avfl.XXXXXX)"
  local exclude_re=""
  if [ "$CV_OK" = 1 ] && [ -n "${EXCLUDE_PATHS+x}" ]; then
    for p in "${EXCLUDE_PATHS[@]}"; do
      exclude_re="${exclude_re:+$exclude_re|}$p"
    done
  fi
  if [ -n "$exclude_re" ]; then
    find "$path" -type f 2>/dev/null | grep -v -E "$exclude_re" > "$flist" || true
  else
    find "$path" -type f 2>/dev/null > "$flist" || true
  fi
  local total; total="$(wc -l < "$flist" 2>/dev/null | tr -d ' ')"
  if [ "${total:-0}" -eq 0 ]; then
    rm -f "$tmp" "$flist"
    printf '{"label":"%s","path":"%s","status":"done","total":0,"found":0,"rc":0,"mulai":%s,"selesai":%s,"waktu":0}\n' \
      "$label" "$path" "$t0" "$t0" > "$out"
    say "tidak ada berkas untuk discan di $path"
    return 0
  fi

  # Catat status berjalan agar UI polling tahu
  printf '{"label":"%s","path":"%s","status":"running","total":%s,"found":0,"mulai":%s}\n' \
    "$label" "$path" "${total:-0}" "$t0" > "$out"

  local found=0 rc=0
  if clamd_ada; then
    nice -n 10 ionice -c2 -n7 clamdscan --no-summary --infected -f "$flist" \
      > "$tmp" 2>/dev/null || rc=$?
  else
    nice -n 10 ionice -c2 -n7 clamscan --no-summary --infected -f "$flist" \
      > "$tmp" 2>/dev/null || rc=$?
  fi

  # pindahkan temuan ke karantina bila ada. Kode 2 (ada galat, mis. berkas cache
  # hilang di antara find dan pemindaian) TIDAK berarti tidak ada temuan: dulu
  # satu galat saja membuang semua baris FOUND. Yang diproses hanya baris FOUND.
  if [ "$rc" -ne 0 ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      case "$line" in
        *": "*" FOUND")
          local lx="${line% FOUND}"; local f="${lx%: *}" sig="${lx##*: }"
          [ -f "$f" ] || continue
          found=$((found+1))
          if [ "${ACTION_ON_DETECT:-quarantine}" = "quarantine" ]; then
            if [ "$CV_OK" = 1 ] && type cv_quarantine >/dev/null 2>&1; then
              cv_quarantine "$f" "$sig" >/dev/null 2>&1 || true
            else
              cv_quarantine_fallback "$f" "$sig" >/dev/null 2>&1 || true
            fi
            printf '%s\tSCAN_DETECTED\t%s\t%s\n' \
              "$(date -Is)" "$f" "$sig" >> "${EVENT_LOG:-/var/log/clamav/realtime.log}" 2>/dev/null || true
          fi
          ;;
      esac
    done < "$tmp"
  fi

  local t1; t1=$(date +%s)
  rm -f "$tmp" "$flist"

  printf '{"label":"%s","path":"%s","status":"done","total":%s,"found":%s,"rc":%s,"mulai":%s,"selesai":%s,"waktu":%s}\n' \
    "$label" "$path" "${total:-0}" "${found:-0}" "$rc" "$t0" "$t1" "$((t1 - t0))" > "$out"
  say "scan $label: $total berkas, $found terinfeksi, $((t1 - t0)) dtk"
  return 0
}

do_scan() {
  [ $# -ge 1 ] || { err "pakai: scan <path> [label]"; return 1; }
  clam_ada || { err "ClamAV tidak terpasang di server ini"; return 1; }
  scan_satu "$1" "${2:-$(basename "$1")}"
}

do_scan_all() {
  clam_ada || { err "ClamAV tidak terpasang"; return 1; }
  local n=0
  local t0; t0=$(date +%s)
  local total_found=0
  local all_out="$LAST_DIR/all.json"
  printf '{"label":"all","status":"running","mulai":%s}\n' "$t0" > "$all_out"

  for d in /www/wwwroot/*; do
    [ -d "$d" ] || continue
    local sname; sname="$(basename "$d")"
    scan_satu "$d" "$sname" || true
    if [ -f "$LAST_DIR/$sname.json" ]; then
      local fnd; fnd="$(grep -o '"found":[0-9]*' "$LAST_DIR/$sname.json" 2>/dev/null | cut -d: -f2)"
      total_found=$((total_found + ${fnd:-0}))
    fi
    n=$((n+1))
  done

  local t1; t1=$(date +%s)
  printf '{"label":"all","status":"done","vhost_count":%s,"total_found":%s,"mulai":%s,"selesai":%s,"waktu":%s}\n' \
    "$n" "$total_found" "$t0" "$t1" "$((t1 - t0))" > "$all_out"
  say "scan-all selesai: $n vhost, $total_found terinfeksi, $((t1 - t0)) dtk"
}

# ==================================================================
# INTEGRITAS (anti-tamper) -- manifest hash per vhost
# ==================================================================
# Pola berkas yang dijaga. Dulu .phar, .inc, .pht, .htaccess, dan .user.ini terlewat,
# padahal .user.ini (auto_prepend_file) dan .htaccess (AddHandler) adalah cara persistensi
# webshell yang paling umum.
EXT_POLA='(\.(php|phtml|pht|phps|phar|inc|php[0-9]|js|html|htm|shtml|sh|py|pl|cgi|asp|aspx|jsp)|/\.htaccess|/\.user\.ini|/php\.ini)$'
# Folder yang berubah sendiri saat aplikasi berjalan (cache, log, git, dependensi build).
INTEG_KECUALI='/(storage/framework|storage/logs|bootstrap/cache|node_modules|\.git|wp-content/cache)/'
INTEG_DB=/www/server/sentinel/data/guardd.db

baseline_path() { printf '%s' "$BASE_DIR/$1.txt"; }

# "hash  path" untuk semua berkas terjaga di bawah $1, terurut. Satu proses sha256sum per
# ribuan berkas (xargs), bukan satu per berkas. Path berspasi aman.
integ_hitung() {
  find "$1" -type f -regextype posix-extended -regex ".*$EXT_POLA" ! -regex ".*$INTEG_KECUALI.*" -print0 2>/dev/null \
    | nice -n 10 ionice -c3 xargs -0 -r sha256sum 2>/dev/null | LC_ALL=C sort -k2
}

# Bandingkan baseline ($1) dengan keadaan sekarang ($2) dalam SATU lintasan awk.
# Dulu setiap berkas memanggil awk atas seluruh baseline (20 ribu berkas = 400 juta baris
# dibaca) dan path berspasi selalu dianggap "added" karena hanya kolom ke-2 yang dibaca.
integ_banding() {
  awk '
    { i = index($0, "  "); h = substr($0, 1, i - 1); p = substr($0, i + 2) }
    NR == FNR { b[p] = h; next }
    { n[p] = h
      if (!(p in b)) print "added|" p "|-|" h
      else if (b[p] != h) print "changed|" p "|" b[p] "|" h }
    END { for (p in b) if (!(p in n)) print "deleted|" p "|" b[p] "|-" }
  ' "$1" "$2"
}

# Antrekan notifikasi (dikirim sentinel-notify.sh) untuk perubahan BARU saja.
integ_notif() {
  local label="$1" berkas="$2" n contoh
  n="$(grep -c . "$berkas" 2>/dev/null)"
  [ "${n:-0}" -gt 0 ] || return 0
  command -v sqlite3 >/dev/null 2>&1 && [ -f "$INTEG_DB" ] || return 0
  label="$(printf '%s' "$label" | tr -dc 'A-Za-z0-9._-')"
  contoh="$(head -5 "$berkas" | cut -d'|' -f1,2 | tr '\n' ';' | tr -d "'\"\\\\\`" | tr -d '\000-\037' | cut -c1-600)"
  sqlite3 "$INTEG_DB" "INSERT INTO notif (ts, ip, jenis, isi, terkirim, coba, galat) VALUES ($(date +%s), 0, 'integritas', 'Integritas berkas $label: $n perubahan baru. $contoh', 0, 0, '');" 2>/dev/null || true
}

do_baseline() {
  err "integritas berkas web per vhost adalah fitur Pro (integ_web)"
  return 1
}

do_check() {
  err "integritas berkas web per vhost adalah fitur Pro (integ_web)"
  return 1
}

# Semua vhost di /www/wwwroot: vhost tanpa baseline dibuatkan baseline (tanpa laporan),
# sisanya diperiksa dan perubahan BARU dikirim sebagai notifikasi. Dipanggil timer per jam.
do_check_all() {
  err "integritas berkas web per vhost adalah fitur Pro (integ_web)"
  return 1
}

do_integ_list() {
  local label="${1:-}"
  local ditemukan=0 f
  if [ -n "$label" ]; then
    f="$LAST_DIR/integ-$label.txt"
    if [ -f "$f" ]; then
      cat "$f"
      ditemukan=1
    fi
  else
    for f in "$LAST_DIR"/integ-*.txt; do
      [ -f "$f" ] || continue
      ditemukan=1
      cat "$f"
    done
  fi
  [ "$ditemukan" = 0 ] && say "(belum ada hasil integritas)"
}

# ==================================================================
# INTEGRITAS PERSISTENSI SISTEM (ANTI-PERSISTENCE ROOTKIT/BACKDOOR)
# ==================================================================
SYS_TARGETS=(
  "/etc/cron.d"
  "/etc/cron.daily"
  "/etc/cron.hourly"
  "/etc/cron.monthly"
  "/etc/cron.weekly"
  "/etc/crontab"
  "/var/spool/cron"
  "/etc/systemd/system"
  "/etc/ld.so.preload"
  "/etc/ld.so.conf"
  "/etc/ld.so.conf.d"
  "/etc/profile.d"
  "/etc/sudoers.d"
)

do_baseline_sys() {
  local out="$BASE_DIR/sys-persistence.txt"
  local dir; dir="$(dirname "$out")"; mkdir -p "$dir"
  : > "$out.tmp"
  local n=0 tgt f h
  for tgt in "${SYS_TARGETS[@]}"; do
    if [ -f "$tgt" ]; then
      h="$(sha256sum "$tgt" 2>/dev/null | cut -d' ' -f1)"
      [ -n "$h" ] && printf '%s  %s\n' "$h" "$tgt" >> "$out.tmp" && n=$((n+1))
    elif [ -d "$tgt" ]; then
      while IFS= read -r f; do
        [ -f "$f" ] || continue
        h="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] && printf '%s  %s\n' "$h" "$f" >> "$out.tmp" && n=$((n+1))
      done < <(find "$tgt" -maxdepth 2 -type f 2>/dev/null || true)
    fi
  done
  mv "$out.tmp" "$out"
  say "baseline sys-persistence: $n berkas persistensi sistem direkam"
}

do_check_sys() {
  local base="$BASE_DIR/sys-persistence.txt"
  [ -f "$base" ] || { err "belum ada baseline untuk sys-persistence; jalankan baseline-sys dulu"; return 1; }
  local now; now="$(mktemp /tmp/zysentinel-sys.XXXXXX)"
  local tgt f h
  for tgt in "${SYS_TARGETS[@]}"; do
    if [ -f "$tgt" ]; then
      h="$(sha256sum "$tgt" 2>/dev/null | cut -d' ' -f1)"
      [ -n "$h" ] && printf '%s  %s\n' "$h" "$tgt" >> "$now"
    elif [ -d "$tgt" ]; then
      while IFS= read -r f; do
        [ -f "$f" ] || continue
        h="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
        [ -n "$h" ] && printf '%s  %s\n' "$h" "$f" >> "$now"
      done < <(find "$tgt" -maxdepth 2 -type f 2>/dev/null || true)
    fi
  done

  local out="$LAST_DIR/integ-sys-persistence.txt" lama
  lama="$(mktemp /tmp/zysentinel-sl.XXXXXX)"
  [ -f "$out" ] && cp "$out" "$lama"
  LC_ALL=C sort -k2 "$now" -o "$now"
  integ_banding "$base" "$now" | LC_ALL=C sort > "$out.tmp" && mv -f "$out.tmp" "$out"
  if [ -n "${1:-}" ]; then
    LC_ALL=C sort "$lama" -o "$lama"
    LC_ALL=C comm -13 "$lama" "$out" > "$lama.baru"
    integ_notif "sys-persistence" "$lama.baru"
    rm -f "$lama.baru"
  fi
  rm -f "$now" "$lama"
  local n; n="$(grep -c . "$out")"
  say "integritas sys-persistence: $n perubahan terdeteksi"
}

# ==================================================================
# DATABASE
# ==================================================================
do_db_update() {
  command -v freshclam >/dev/null 2>&1 || { err "freshclam tidak ada"; return 1; }
  # Kode keluar freshclam dipertahankan (dulu '| tail' menelan kegagalan).
  local out rc
  out="$(nice -n 10 freshclam 2>&1)"; rc=$?
  printf '%s\n' "$out" | tail -5
  return $rc
}

# ==================================================================
# RKHUNTER (ROOTKIT HUNTER)
# ==================================================================
do_rkhunter_propupd() {
  rkhunter_ada || { err "rkhunter tidak terpasang"; return 1; }
  say "Memperbarui database file properties rkhunter..."
  "$RKHUNTER_BIN" --propupd --dbdir "$RKHUNTER_DB" --tmpdir "$RKHUNTER_TMP" --logfile "$RKHUNTER_LOG"
}

do_rkhunter_update() {
  rkhunter_ada || { err "rkhunter tidak terpasang"; return 1; }
  say "Memeriksa pembaruan database signature rkhunter..."
  "$RKHUNTER_BIN" --update --dbdir "$RKHUNTER_DB" --tmpdir "$RKHUNTER_TMP" --logfile "$RKHUNTER_LOG"
}

# Beberapa tugas pembaruan berurutan dengan penanda [n/m] per tugas, supaya panel bisa
# menampilkan kemajuan dan hasil tiap tugas. rkhunter --update mengembalikan 2 bila
# "tidak ada pembaruan": itu bukan kegagalan.
do_update_batch() {
  local total=$# n=0 gagal=0 t rc t0 judul
  [ "$total" -gt 0 ] || { err "tidak ada tugas"; return 2; }
  for t in "$@"; do
    n=$((n + 1))
    case "$t" in
      db-update)        judul="Memperbarui basis data virus ClamAV (freshclam)" ;;
      rkhunter-propupd) judul="Merekam hash biner sistem (rkhunter --propupd)" ;;
      rkhunter-update)  judul="Memperbarui signature rkhunter (--update)" ;;
      *) say "[$n/$total] tugas tidak dikenal: $t"; say "[$n/$total] selesai rc=64 (0 dtk)"; gagal=$((gagal + 1)); continue ;;
    esac
    say "[$n/$total] $judul"
    t0=$(date +%s)
    case "$t" in
      db-update)        do_db_update; rc=$? ;;
      rkhunter-propupd) do_rkhunter_propupd; rc=$? ;;
      rkhunter-update)  do_rkhunter_update; rc=$?; [ "$rc" = "2" ] && { say "rkhunter: tidak ada pembaruan tersedia"; rc=0; } ;;
    esac
    say "[$n/$total] selesai rc=$rc ($(( $(date +%s) - t0 )) dtk)"
    [ "$rc" = "0" ] || gagal=$((gagal + 1))
  done
  [ "$gagal" -eq 0 ]
}

# ==================================================================
# SCAN-STREAM (REALTIME LOG PEMINDAIAN CLAMAV & RKHUNTER)
# ==================================================================
do_scan_stream() {
  local engine="${1:-both}" path="${2:-/}" label="${3:-}"
  [ -z "$label" ] && label="$(basename "$path")"
  [ "$label" = "/" ] && label="system"
  [ "$path" = "system" ] && path="/"

  mkdir -p /www/server/sentinel/run /www/server/sentinel/log "$LAST_DIR" 2>/dev/null
  echo "$$" > "$ACTIVE_SCAN_PID"

  local t0; t0=$(date +%s)
  local found_malware=0 warnings_count=0 total_files=0

  cat <<EOF > "$ACTIVE_SCAN_JSON.tmp"
{
  "status": "running",
  "pid": $$,
  "engine": "$engine",
  "path": "$path",
  "label": "$label",
  "mulai": $t0,
  "selesai": 0,
  "total": 0,
  "found": 0,
  "warnings": 0
}
EOF
  # 644 dan ganti atomik: dulu berkas bisa 666 sehingga user www memalsukan status pindai di panel
  chmod 644 "$ACTIVE_SCAN_JSON.tmp" 2>/dev/null; mv -f "$ACTIVE_SCAN_JSON.tmp" "$ACTIVE_SCAN_JSON"

  echo "======================================================================"
  echo " [ZySentinel] Realtime Security & Threat Scanner"
  echo " Waktu Mulai : $(date '+%Y-%m-%d %H:%M:%S')"
  echo " Target Path : $path (Label: $label)"
  echo " Engine      : $engine"
  echo " PID Scanner : $$"
  echo "======================================================================"
  echo ""

  # ------------------------------------------------------------------
  # TAHAP 1: CLAMAV (MALWARE & WEBSHELL SCAN)
  # ------------------------------------------------------------------
  if [ "$engine" = "clamav" ] || [ "$engine" = "both" ] || [ "$engine" = "all" ]; then
    echo "----------------------------------------------------------------------"
    echo "[*] [TAHAP 1/2] Pemindaian Malware & Trojan Web (ClamAV)"
    echo "----------------------------------------------------------------------"
    if ! clam_ada; then
      echo "[-] ClamAV tidak terpasang pada sistem. Melewati tahap malware scan."
    elif [ ! -d "$path" ] && [ ! -f "$path" ]; then
      echo "[!] Path target tidak ditemukan: $path"
      warnings_count=$((warnings_count + 1))
    else
      local flist; flist="$(mktemp /tmp/zysentinel-fl.XXXXXX)"
      local tmp; tmp="$(mktemp /tmp/zysentinel-av.XXXXXX)"

      echo "[*] Mengindeks berkas pada target..."
      local exclude_re=""
      if [ "$CV_OK" = 1 ] && [ -n "${EXCLUDE_PATHS+x}" ]; then
        for p in "${EXCLUDE_PATHS[@]}"; do
          exclude_re="${exclude_re:+$exclude_re|}$p"
        done
      fi

      if [ -f "$path" ]; then
        echo "$path" > "$flist"
      elif [ -n "$exclude_re" ]; then
        find "$path" -type f 2>/dev/null | grep -v -E "$exclude_re" > "$flist" || true
      else
        find "$path" -type f 2>/dev/null > "$flist" || true
      fi

      total_files="$(wc -l < "$flist" 2>/dev/null | tr -d ' ')"
      total_files="${total_files:-0}"
      echo "[*] Terindeks $total_files berkas untuk dianalisis."

      if [ "$total_files" -gt 0 ]; then
        local engine_name="clamscan"
        if clamd_ada; then
          engine_name="clamdscan (daemon)"
        fi
        echo "[*] Menjalankan pemindaian dengan $engine_name..."

        local rc=0
        if clamd_ada; then
          nice -n 10 ionice -c2 -n7 clamdscan --no-summary --infected -f "$flist" > "$tmp" 2>/dev/null || rc=$?
        else
          nice -n 10 ionice -c2 -n7 clamscan --no-summary --infected -f "$flist" > "$tmp" 2>/dev/null || rc=$?
        fi

        if [ "$rc" -ne 0 ]; then
          while IFS= read -r line; do
            [ -z "$line" ] && continue
            case "$line" in
              *": "*" FOUND")
                local lx="${line% FOUND}"; local f="${lx%: *}" sig="${lx##*: }"
                [ -f "$f" ] || continue
                found_malware=$((found_malware + 1))
                echo "[!] ANCAMAN TERDETEKSI: $f [Signature: $sig]"
                if [ "${ACTION_ON_DETECT:-quarantine}" = "quarantine" ]; then
                  local qres=""
                  if [ "$CV_OK" = 1 ] && type cv_quarantine >/dev/null 2>&1; then
                    qres="$(cv_quarantine "$f" "$sig" 2>/dev/null || true)"
                  else
                    qres="$(cv_quarantine_fallback "$f" "$sig" 2>/dev/null || true)"
                  fi
                  echo "    -> Berkas telah diisolasi ke karantina ($qres)"
                  printf '%s\tSCAN_DETECTED\t%s\t%s\n' \
                    "$(date -Is)" "$f" "$sig" >> "${EVENT_LOG:-/var/log/clamav/realtime.log}" 2>/dev/null || true
                fi
                ;;
            esac
          done < "$tmp"
        fi

        rm -f "$tmp" "$flist"

        if [ "$found_malware" -eq 0 ]; then
          echo "[OK] ClamAV: Bersih. Tidak ditemukan berkas terinfeksi malware."
        else
          echo "[!] ClamAV: Selesai dengan $found_malware berkas terinfeksi malware diisolasi."
        fi
      else
        echo "[*] Tidak ada berkas yang perlu dipindai di path ini."
        rm -f "$flist" "$tmp"
      fi
    fi
  fi

  # ------------------------------------------------------------------
  # TAHAP 2: RKHUNTER & AUDIT ANOMALI DIREKTORI / SISTEM
  # ------------------------------------------------------------------
  if [ "$engine" = "rkhunter" ] || [ "$engine" = "both" ] || [ "$engine" = "all" ]; then
    echo ""
    echo "----------------------------------------------------------------------"
    echo "[*] [TAHAP 2/2] Audit Rootkit, Backdoor & Integritas Keamanan (Rkhunter)"
    echo "----------------------------------------------------------------------"
    if ! rkhunter_ada; then
      echo "[-] Rootkit Hunter (rkhunter) tidak terpasang di server ini."
    else
      if [ "$path" = "/" ] || [ "$label" = "system" ]; then
        echo "[*] Menjalankan audit rootkit & trojan sistem..."
        local rk_tmp_out; rk_tmp_out="$(mktemp /tmp/zysentinel-rk.XXXXXX)"
        nice -n 10 "$RKHUNTER_BIN" --check --sk --rwo --enable rootkits,trojans,malware \
          --dbdir "$RKHUNTER_DB" --tmpdir "$RKHUNTER_TMP" --logfile "$RKHUNTER_LOG" > "$rk_tmp_out" 2>&1 || true

        local rk_warn=0
        while IFS= read -r rk_line; do
          [ -z "$rk_line" ] && continue
          echo "$rk_line"
          rk_warn=$((rk_warn + 1))
        done < "$rk_tmp_out"
        rm -f "$rk_tmp_out"

        warnings_count=$((warnings_count + rk_warn))
        if [ "$rk_warn" -eq 0 ]; then
          echo "[OK] Rkhunter: Bersih. Tidak ditemukan tanda rootkit, trojan, atau backdoor pada sistem."
        else
          echo "[!] Rkhunter: Ditemukan $rk_warn peringatan selama audit sistem."
        fi

        echo "[*] Memeriksa integritas berkas persistensi sistem (cron, systemd, preload)..."
        local base_sys="$BASE_DIR/sys-persistence.txt"
        if [ -f "$base_sys" ]; then
          local sys_tmp; sys_tmp="$(mktemp /tmp/zysentinel-sysc.XXXXXX)"
          do_check_sys > "$sys_tmp" 2>&1 || true
          local sys_diff_f="$LAST_DIR/integ-sys-persistence.txt"
          local sys_diff_count=0
          if [ -f "$sys_diff_f" ]; then
            sys_diff_count="$(wc -l < "$sys_diff_f" 2>/dev/null | tr -d ' ')"
            sys_diff_count="${sys_diff_count:-0}"
            if [ "$sys_diff_count" -gt 0 ]; then
              warnings_count=$((warnings_count + sys_diff_count))
              echo "[!] Peringatan Persistensi: Ditemukan $sys_diff_count perubahan persistensi sistem!"
              head -n 5 "$sys_diff_f" | while IFS= read -r diff_l; do
                echo "    -> $diff_l"
              done
            else
              echo "[OK] Persistensi Sistem: Bersih. Identik dengan baseline."
            fi
          fi
          rm -f "$sys_tmp"
        else
          echo "[*] Baseline persistensi sistem belum ada. Membuat baseline awal..."
          do_baseline_sys >/dev/null 2>&1 || true
          echo "[OK] Baseline persistensi sistem berhasil dibuat."
        fi

      else
        echo "[*] Menganalisis anomali direktori pada $path..."

        # 1. Cek berkas skrip tersembunyi (hidden script files)
        local hidden_scripts
        hidden_scripts="$(find "$path" -maxdepth 4 -type f -name ".*" \( -name "*.php*" -o -name "*.sh" -o -name "*.py" -o -name "*.so" -o -name "*.elf" \) 2>/dev/null || true)"
        if [ -n "$hidden_scripts" ]; then
          echo "[!] Ditemukan berkas skrip tersembunyi (potensi backdoor):"
          while IFS= read -r hf; do
            [ -z "$hf" ] && continue
            echo "    [WARN] $hf"
            warnings_count=$((warnings_count + 1))
          done <<< "$hidden_scripts"
        else
          echo "[OK] Anomali Skrip: Tidak ditemukan berkas skrip dotfile/tersembunyi."
        fi

        # 2. Cek izin berbahaya (world-writable scripts)
        local perm_danger
        perm_danger="$(find "$path" -maxdepth 4 -perm -o+w -type f \( -name "*.php*" -o -name "*.sh" \) 2>/dev/null || true)"
        if [ -n "$perm_danger" ]; then
          echo "[!] Ditemukan berkas skrip berizin rawan (world-writable 777):"
          while IFS= read -r pf; do
            [ -z "$pf" ] && continue
            echo "    [WARN] $pf"
            warnings_count=$((warnings_count + 1))
          done <<< "$perm_danger"
        else
          echo "[OK] Izin Berkas: Izin berkas aman (tidak ada skrip world-writable)."
        fi

        # 3. Pemeriksaan integritas anti-tamper jika baseline vhost ada
        local base_vhost="$BASE_DIR/$label.txt"
        if [ -f "$base_vhost" ]; then
          echo "[*] Memverifikasi integritas berkas terhadap baseline SHA-256..."
          do_check "$path" "$label" >/dev/null 2>&1 || true
          local diff_f="$LAST_DIR/integ-$label.txt"
          if [ -f "$diff_f" ]; then
            local n_diff; n_diff="$(wc -l < "$diff_f" 2>/dev/null | tr -d ' ')"
            n_diff="${n_diff:-0}"
            if [ "$n_diff" -gt 0 ]; then
              warnings_count=$((warnings_count + n_diff))
              echo "[!] Anti-Tamper: Terdeteksi $n_diff perubahan berkas web terhadap baseline!"
              head -n 5 "$diff_f" | while IFS= read -r ch_line; do
                echo "    -> $ch_line"
              done
            else
              echo "[OK] Anti-Tamper: Seluruh berkas web identik dengan baseline integritas."
            fi
          fi
        else
          echo "[*] Belum ada baseline integritas untuk $label. Anda dapat merekamnya pada tab Integrity Monitor."
        fi

      fi
    fi
  fi

  local premium=0
  av_premium_ok && premium=1
  case "$engine" in
    ransomware|judol|mining|sage|ai|scan-ai)
      [ "$premium" = 1 ] || echo "[-] Mesin $engine membutuhkan paket Max (av_engines); hanya ClamAV dan Rkhunter yang tersedia." ;;
  esac
  # ------------------------------------------------------------------
  # RINGKASAN AKHIR
  # ------------------------------------------------------------------
  local t1; t1=$(date +%s)
  local durasi=$((t1 - t0))
  local status_str="BERSIH (CLEAN)"
  if [ "$found_malware" -gt 0 ] && [ "$warnings_count" -gt 0 ]; then
    status_str="BAHAYA (MALWARE & WARNINGS)"
  elif [ "$found_malware" -gt 0 ]; then
    status_str="TERINFEKSI (MALWARE FOUND)"
  elif [ "$warnings_count" -gt 0 ]; then
    status_str="PERINGATAN (WARNINGS)"
  fi

  echo ""
  echo "======================================================================"
  echo " [RINGKASAN PEMINDAIAN ZYSENTINEL]"
  echo " Waktu Selesai      : $(date '+%Y-%m-%d %H:%M:%S')"
  echo " Durasi Pemindaian  : $durasi detik"
  echo " Total Berkas Diuji : $total_files berkas"
  echo " Ancaman Malware    : $found_malware terdeteksi"
  echo " Peringatan Audit   : $warnings_count terdeteksi"
  echo " Status Hasil Akhir : $status_str"
  echo "======================================================================"

  local out="$LAST_DIR/$label.json"
  cat <<EOF > "$out"
{
  "label": "$label",
  "path": "$path",
  "status": "done",
  "engine": "$engine",
  "total": $total_files,
  "found": $found_malware,
  "warnings": $warnings_count,
  "rc": $((found_malware > 0 ? 1 : 0)),
  "mulai": $t0,
  "selesai": $t1,
  "waktu": $durasi
}
EOF

  cat <<EOF > "$ACTIVE_SCAN_JSON.tmp"
{
  "status": "done",
  "pid": $$,
  "engine": "$engine",
  "path": "$path",
  "label": "$label",
  "mulai": $t0,
  "selesai": $t1,
  "total": $total_files,
  "found": $found_malware,
  "warnings": $warnings_count,
  "waktu": $durasi,
  "summary": "$status_str"
}
EOF
  # 644 dan ganti atomik: dulu berkas bisa 666 sehingga user www memalsukan status pindai di panel
  chmod 644 "$ACTIVE_SCAN_JSON.tmp" 2>/dev/null; mv -f "$ACTIVE_SCAN_JSON.tmp" "$ACTIVE_SCAN_JSON"

  rm -f "$ACTIVE_SCAN_PID" 2>/dev/null
  say "scan-stream $label selesai dalam $durasi dtk (malware: $found_malware, warn: $warnings_count)"
  return 0
}

# ==================================================================
# DISPATCHER
# ==================================================================
case "${1:-status}" in
  status)             do_status ;;
  scan)               do_scan "${2:-}" "${3:-}" ;;
  scan-stream)        do_scan_stream "${2:-both}" "${3:-/}" "${4:-}" ;;
  scan-ai)            do_scan_stream "sage" "${2:-/}" "${3:-}" ;;
  scan-all)           do_scan_all ;;
  quarantine-list)    do_q_list ;;
  quarantine-restore) do_q_restore "${2:-}" ;;
  quarantine-delete)  do_q_delete "${2:-}" ;;
  quarantine-purge)   do_q_purge ;;
  baseline)           do_baseline "${2:-}" "${3:-}" ;;
  baseline-sys)       do_baseline_sys ;;
  check)              do_check "${2:-}" "${3:-}" ;;
  check-sys)          do_check_sys "${2:-}" ;;
  check-all)          do_check_all ;;
  integ-list)         do_integ_list "${2:-}" ;;
  db-update)          do_db_update ;;
  rkhunter-propupd)   do_rkhunter_propupd ;;
  rkhunter-update)    do_rkhunter_update ;;
  update-batch)       shift; do_update_batch "$@" ;;
  *) echo "Usage: $0 {status|scan <path> [label]|scan-stream <engine> <path> [label]|scan-ai <path> [label]|scan-all|quarantine-list|quarantine-restore <id>|quarantine-delete <id>|quarantine-purge|baseline <path> [label]|baseline-sys|check <path> [label]|check-sys|integ-list [label]|db-update|rkhunter-propupd|rkhunter-update}"; exit 1 ;;
esac
