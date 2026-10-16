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

# ---- muat perpustakaan ClamAV bersama bila ada ----
CV_OK=0
if [ -f "$COMMON" ] && [ -f "$RCONF" ]; then
  # shellcheck disable=SC1090
  . "$COMMON" 2>/dev/null && CV_OK=1
fi

clam_ada()   { command -v clamscan >/dev/null 2>&1; }
clamd_ada()  { [ -S "${CLAMD_SOCKET:-/var/run/clamav/clamd.ctl}" ]; }

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

  printf 'ada=%s\nversi=%s\ndb_umur=%s\nclamd=%s\nquarantine=%s\ndeteksi_hari_ini=%s\ncommon=%s\ntimer=%s\n' \
    "$ada" "$ver" "$dbumur" "$clamd" "${qn:-0}" "${ev:-0}" "$([ "$CV_OK" = 1 ] && echo ada || echo tidak)" "$timer_aktif"
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

  [ -f "$qpath" ] || { err "berkas karantina hilang: $qpath"; return 1; }
  mkdir -p "$(dirname "$orig")" 2>/dev/null
  mv -f "$qpath" "$orig" || return 1
  chown "${uid:-0}:${gid:-0}" "$orig" 2>/dev/null
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
  if [ "$CV_OK" = 1 ] && type cv_restore >/dev/null 2>&1; then
    cv_restore "$meta" || { err "restore gagal"; return 1; }
  else
    cv_restore_fallback "$meta" || { err "restore gagal"; return 1; }
  fi
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

  # pindahkan temuan ke karantina bila ada
  if [ "$rc" -eq 1 ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      case "$line" in
        *": "*" FOUND")
          local f="${line%%: *}" sig="${line#*: }"; sig="${sig% FOUND}"
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
EXT_POLA='\.(php|phtml|php[0-9]|js|html|htm|sh|py|pl|cgi|asp|aspx|jsp)$'

baseline_path() { printf '%s' "$BASE_DIR/$1.txt"; }

do_baseline() {
  [ $# -ge 1 ] || { err "pakai: baseline <path> [label]"; return 1; }
  local path="$1" label="${2:-$(basename "$path")}"
  [ -d "$path" ] || { err "path bukan direktori: $path"; return 1; }
  local out; out="$(baseline_path "$label")"
  local dir; dir="$(dirname "$out")"; mkdir -p "$dir"
  : > "$out.tmp"
  local n=0
  while IFS= read -r f; do
    local h; h="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
    [ -z "$h" ] && continue
    printf '%s  %s\n' "$h" "$f" >> "$out.tmp"
    n=$((n+1))
  done < <(find "$path" -type f -regextype posix-extended -regex ".*$EXT_POLA" 2>/dev/null || true)
  mv "$out.tmp" "$out"
  say "baseline $label: $n berkas direkam"
}

do_check() {
  [ $# -ge 1 ] || { err "pakai: check <path> [label]"; return 1; }
  local path="$1" label="${2:-$(basename "$path")}"
  local base; base="$(baseline_path "$label")"
  [ -f "$base" ] || { err "belum ada baseline untuk $label; jalankan baseline dulu"; return 1; }
  local now; now="$(mktemp /tmp/zysentinel-id.XXXXXX)"
  while IFS= read -r f; do
    local h; h="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
    [ -z "$h" ] && continue
    printf '%s  %s\n' "$h" "$f" >> "$now"
  done < <(find "$path" -type f -regextype posix-extended -regex ".*$EXT_POLA" 2>/dev/null || true)

  local out="$LAST_DIR/integ-$label.txt"
  : > "$out"
  # tambah / berubah
  while IFS= read -r linha; do
    [ -z "$linha" ] && continue
    local h f lama
    h="${linha%%  *}"; f="${linha#*  }"
    lama="$(awk -v path="$f" '$2 == path { print $1; exit }' "$base" 2>/dev/null || true)"
    if [ -z "$lama" ]; then
      printf 'added|%s|-|%s\n' "$f" "$h" >> "$out"
    elif [ "$lama" != "$h" ]; then
      printf 'changed|%s|%s|%s\n' "$f" "$lama" "$h" >> "$out"
    fi
  done < "$now"
  # hapus
  while IFS= read -r linha; do
    [ -z "$linha" ] && continue
    local f; f="${linha#*  }"
    [ -e "$f" ] || printf 'deleted|%s|%s|-\n' "$f" "${linha%%  *}" >> "$out"
  done < "$base"
  rm -f "$now"
  local n; n="$(wc -l < "$out" | tr -d ' ')"
  say "integritas $label: $n perubahan"
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

  local out="$LAST_DIR/integ-sys-persistence.txt"
  : > "$out"
  # tambah / berubah
  while IFS= read -r linha; do
    [ -z "$linha" ] && continue
    local h f lama
    h="${linha%%  *}"; f="${linha#*  }"
    lama="$(awk -v path="$f" '$2 == path { print $1; exit }' "$base" 2>/dev/null || true)"
    if [ -z "$lama" ]; then
      printf 'added|%s|-|%s\n' "$f" "$h" >> "$out"
    elif [ "$lama" != "$h" ]; then
      printf 'changed|%s|%s|%s\n' "$f" "$lama" "$h" >> "$out"
    fi
  done < "$now"
  # hapus
  while IFS= read -r linha; do
    [ -z "$linha" ] && continue
    local f; f="${linha#*  }"
    [ -e "$f" ] || printf 'deleted|%s|%s|-\n' "$f" "${linha%%  *}" >> "$out"
  done < "$base"
  rm -f "$now"
  local n; n="$(wc -l < "$out" | tr -d ' ')"
  say "integritas sys-persistence: $n perubahan terdeteksi"
}

# ==================================================================
# DATABASE
# ==================================================================
do_db_update() {
  command -v freshclam >/dev/null 2>&1 || { err "freshclam tidak ada"; return 1; }
  nice -n 10 freshclam 2>&1 | tail -5
}

# ==================================================================
# DISPATCHER
# ==================================================================
case "${1:-status}" in
  status)             do_status ;;
  scan)               do_scan "${2:-}" "${3:-}" ;;
  scan-all)           do_scan_all ;;
  quarantine-list)    do_q_list ;;
  quarantine-restore) do_q_restore "${2:-}" ;;
  quarantine-delete)  do_q_delete "${2:-}" ;;
  quarantine-purge)   do_q_purge ;;
  baseline)           do_baseline "${2:-}" "${3:-}" ;;
  baseline-sys)       do_baseline_sys ;;
  check)              do_check "${2:-}" "${3:-}" ;;
  check-sys)          do_check_sys ;;
  integ-list)         do_integ_list "${2:-}" ;;
  db-update)          do_db_update ;;
  *) echo "pakai: $0 {status|scan <path> [label]|scan-all|quarantine-list|quarantine-restore <id>|quarantine-delete <id>|quarantine-purge|baseline <path> [label]|baseline-sys|check <path> [label]|check-sys|integ-list [label]|db-update}"; exit 1 ;;
esac
