#!/bin/bash
# ============================================================
# sentinel-intel.sh -- Pengelola Global Threat Intelligence Feed
#
# Memuat daftar reputasi penyerang siber global (Spamhaus DROP/EDROP,
# botnet, scanner terkoordinasi) ke dalam ipset kernel 'sentinel_intel'.
#
# Pembaruan dilakukan secara atomik di memori kernel (swap set)
# sehingga tidak menyebabkan lonjakan latensi atau kehilangan paket.
# ============================================================
set -uo pipefail

BASE=/www/server/sentinel
DATA_DIR="$BASE/data"
LOG_DIR="$BASE/log"
CONF_FILE="$BASE/etc/guardd.conf"
mkdir -p "$DATA_DIR" "$LOG_DIR" 2>/dev/null

IPSET="$(command -v ipset || echo /usr/sbin/ipset)"
IPT="$(command -v iptables || echo /usr/sbin/iptables)"
SET_NAME="sentinel_intel"
SET_TMP="sentinel_intel_tmp"
CACHE_FILE="$DATA_DIR/threat_intel_cached.txt"
META_FILE="$DATA_DIR/threat_intel.json"
SEED_FILE="$DATA_DIR/threat_intel_seed.txt"

say() { printf '[sentinel-intel] %s\n' "$*"; }
err() { printf '[sentinel-intel] GALAT: %s\n' "$*" >&2; }

ensure_set() {
  local name="$1"
  if "$IPSET" list "$name" >/dev/null 2>&1; then
    return 0
  fi
  if printf 'create %s hash:net family inet hashsize 4096 maxelem 262144\n' "$name" | "$IPSET" restore 2>/dev/null; then
    say "ipset $name dibuat"
  else
    err "gagal membuat ipset $name"
    return 1
  fi
}

# --- Data cadangan bawaan jika server offline ---
prepare_seed() {
  [ -f "$SEED_FILE" ] && return 0
  cat > "$SEED_FILE" <<'EOF'
# Daftar cadangan blok IP berbahaya (botnet & scanner global)
1.10.16.0/20
1.19.0.0/16
1.32.128.0/18
2.26.75.0/24
2.27.5.0/24
2.27.62.0/24
5.188.62.0/24
5.188.206.0/24
45.146.164.0/24
45.154.255.0/24
185.220.101.0/24
185.220.102.0/24
194.26.29.0/24
195.54.160.0/24
EOF
}

do_update() {
  ensure_set "$SET_NAME" || return 1
  prepare_seed

  local tmp_raw; tmp_raw="$(mktemp /tmp/zysentinel_intel_raw.XXXXXX)"
  local tmp_clean; tmp_clean="$(mktemp /tmp/zysentinel_intel_clean.XXXXXX)"

  say "mengunduh feed reputasi Spamhaus DROP dan EDROP..."
  local unduh_ok=0

  # Unduh Spamhaus DROP & EDROP
  if curl -s -f -m 15 https://www.spamhaus.org/drop/drop.txt >> "$tmp_raw" 2>/dev/null; then
    unduh_ok=1
  fi
  if curl -s -f -m 15 https://www.spamhaus.org/drop/edrop.txt >> "$tmp_raw" 2>/dev/null; then
    unduh_ok=1
  fi

  # Bila unduhan gagal atau kosong, gunakan seed lokal
  if [ "$unduh_ok" -eq 0 ] || [ ! -s "$tmp_raw" ]; then
    say "unduhan daring tidak tersedia, menggunakan data seed lokal"
    cat "$SEED_FILE" > "$tmp_raw"
  fi

  # Ekstrak format CIDR IPv4 valid
  grep -o -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' "$tmp_raw" | sort -u > "$tmp_clean" || true
  local total; total="$(wc -l < "$tmp_clean" | tr -d ' ')"

  if [ "${total:-0}" -eq 0 ]; then
    rm -f "$tmp_raw" "$tmp_clean"
    err "tidak ada data CIDR valid ditemukan"
    return 1
  fi

  # Bentuk file instruksi restore ipset
  local tmp_restore; tmp_restore="$(mktemp /tmp/zysentinel_intel_res.XXXXXX)"
  {
    printf 'create %s hash:net family inet hashsize 4096 maxelem 262144 -exist\n' "$SET_TMP"
    printf 'flush %s\n' "$SET_TMP"
    while IFS= read -r cidr; do
      [ -n "$cidr" ] && printf 'add %s %s -exist\n' "$SET_TMP" "$cidr"
    done < "$tmp_clean"
  } > "$tmp_restore"

  if "$IPSET" restore < "$tmp_restore" 2>/dev/null; then
    # Tukar set secara atomik di kernel
    "$IPSET" swap "$SET_TMP" "$SET_NAME" 2>/dev/null
    "$IPSET" destroy "$SET_TMP" 2>/dev/null || true
    cp -f "$tmp_clean" "$CACHE_FILE" 2>/dev/null || true

    local now; now="$(date +%s)"
    printf '{"updated":%s,"total":%s,"status":"active","source":"Spamhaus DROP/EDROP"}\n' \
      "$now" "$total" > "$META_FILE"
    say "pembaruan berhasil: $total blok CIDR penyerang global dimuat ke kernel"
  else
    "$IPSET" destroy "$SET_TMP" 2>/dev/null || true
    err "gagal memuat set ipset ke kernel"
    rm -f "$tmp_raw" "$tmp_clean" "$tmp_restore"
    return 1
  fi

  rm -f "$tmp_raw" "$tmp_clean" "$tmp_restore"
  return 0
}

do_status() {
  local ada="tidak" total=0 hit=0 tgl="-"
  if "$IPSET" list "$SET_NAME" >/dev/null 2>&1; then
    ada="ya"
    total="$("$IPSET" list "$SET_NAME" 2>/dev/null | grep -c '^[0-9]')"
  fi

  if [ -f "$META_FILE" ]; then
    local ts; ts="$(grep -o '"updated":[0-9]*' "$META_FILE" 2>/dev/null | cut -d: -f2)"
    if [ -n "$ts" ]; then
      tgl="$(date -d "@$ts" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "-")"
    fi
  fi

  # Hit counter dari iptables jika terpasang di chain SENTINEL
  local rule_line
  rule_line="$("$IPT" -L SENTINEL -v -n 2>/dev/null | grep -E "match-set $SET_NAME" | head -1 || true)"
  if [ -n "$rule_line" ]; then
    hit="$(printf '%s' "$rule_line" | awk '{print $1}')"
  fi

  printf 'ada=%s\ntotal=%s\nterakhir=%s\nhit_count=%s\n' \
    "$ada" "$total" "$tgl" "${hit:-0}"
}

do_flush() {
  if "$IPSET" list "$SET_NAME" >/dev/null 2>&1; then
    "$IPSET" flush "$SET_NAME" 2>/dev/null
    say "set $SET_NAME dikosongkan"
  fi
  if [ -f "$META_FILE" ]; then
    printf '{"updated":%s,"total":0,"status":"empty","source":"flushed"}\n' "$(date +%s)" > "$META_FILE"
  fi
}

do_list() {
  if [ -f "$CACHE_FILE" ]; then
    cat "$CACHE_FILE"
  elif "$IPSET" list "$SET_NAME" >/dev/null 2>&1; then
    "$IPSET" list "$SET_NAME" 2>/dev/null | grep '^[0-9]'
  else
    say "(belum ada data threat intelligence)"
  fi
}

case "${1:-status}" in
  update) do_update ;;
  status) do_status ;;
  flush)  do_flush ;;
  list)   do_list ;;
  *) echo "Usage: $0 {update|status|flush|list}"; exit 1 ;;
esac
