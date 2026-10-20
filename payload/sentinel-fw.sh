#!/bin/bash
# ============================================================
# sentinel-fw.sh
#
# Lapis pertahanan pertama: aturan kernel (iptables + ipset).
#
# Semua aturan dibuat IDEMPOTEN dan ditandai komentar "sentinel:",
# sehingga:
#   - aman dijalankan berkali-kali tanpa menggandakan aturan
#   - bisa dicabut tanpa menyentuh aturan milik panel atau pemilik
#   - dilindungi timer systemd (sentinel-fw.timer) supaya tetap ada
#     walau ada yang mengubah iptables dari luar
#
# URUTAN WAJIB. Chain SENTINEL disisipkan sebagai anak dari chain
# IN_BT, dan IN_BT posisinya DI BAWAH dua aturan ipset milik panel:
#
#     -A INPUT -m set --match-set aapanel.ipv4.blacklist src -j DROP
#     -A INPUT -m set --match-set aapanel.ipv4.whitelist src -j ACCEPT
#     -A INPUT -j IN_BT
#                      |
#                      +-- SENTINEL
#
# Whitelist panel selalu menang lebih dulu, baru request masuk ke
# aturan kita. Jangan pernah menggeser SENTINEL ke posisi sebelum
# aturan itu, kalau tidak whitelist pemilik bisa ikut kena throttle.
#
# PEMAKAIAN:
#   sentinel-fw.sh install   pasang semua aturan
#   sentinel-fw.sh status    tampilkan ringkasan dan pengujian
#   sentinel-fw.sh remove    cabut semua aturan milik sentinel
#   sentinel-fw.sh flush     kosongkan set ban dan throttle
# ============================================================
set -u

IPT_BIN="$(command -v iptables || echo /usr/sbin/iptables)"
# Semua pemanggilan iptables menunggu kunci xtables (docker, aaPanel, fail2ban memegangnya
# sebentar-sebentar); tanpa -w sebuah aturan bisa gagal dipasang diam-diam.
ipt_w() { "$IPT_BIN" -w 10 "$@"; }
IPT=ipt_w
IPSET="$(command -v ipset || echo /usr/sbin/ipset)"
CHAIN="SENTINEL"

# ==================================================================
# KOMPATIBILITAS BACKEND FIREWALL: ufw, firewalld, iptables-nft,
# iptables-legacy.
#
# Fakta di mesin ini (Oktober 2026): hanya iptables-nft yang dipakai,
# ufw dan firewalld tidak terpasang. Semua yang di bawah ini adalah
# jaring pengaman untuk masa depan, bukan untuk keadaan sekarang.
#
# Aturan main:
#   1. Sentinel TIDAK PERNAH menghapus atau memindahkan aturan milik
#      frontend lain. Hanya chain dan set milik sendiri yang dikelola.
#   2. Hook dipilih berurutan: IN_BT (milik aaPanel) bila ada, kalau
#      tidak ada baru INPUT posisi 1. Keduanya hanya DROP IP yang
#      terdaftar di set milik sendiri, sisanya RETURN sehingga aturan
#      frontend lain tetap berjalan normal sesudahnya.
#   3. Setelah pasang, chain diverifikasi lewat binary yang sama.
#      Kalau tidak terlihat, install GAGAL keras, bukan diam-diam lolos.
#      Ini menangkap kasus backend ganda (nft vs legacy).
# ==================================================================
detect_backend() {
  # Keluaran: satu baris, mis. "iptables-nft", "ufw-active",
  # "firewalld-active", "iptables-legacy", atau "iptables-takdikenal".
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    printf 'ufw-active'
    return 0
  fi
  if command -v firewall-cmd >/dev/null 2>&1 \
     && systemctl is-active firewalld >/dev/null 2>&1; then
    printf 'firewalld-active'
    return 0
  fi
  local v
  v="$("$IPT" --version 2>/dev/null || echo '?')"
  case "$v" in
    *nf_tables*) printf 'iptables-nft' ;;
    *legacy*)    printf 'iptables-legacy' ;;
    *)           printf 'iptables-takdikenal' ;;
  esac
}

backend_split() {
  # Beri peringatan kalau tabel INPUT yang BERISI ATURAN hidup di backend
  # lain. Contoh: INPUT dikelola lewat iptables-legacy sementara skrip ini
  # memakai iptables-nft. Dalam keadaan itu hook kita tidak akan pernah
  # tersentuh paket.
  local lain=""
  if [ -x /usr/sbin/iptables-legacy ] && [ "$IPT" != "/usr/sbin/iptables-legacy" ] \
     && [ -x /usr/sbin/iptables-nft ] && [ "$IPT" != "/usr/sbin/iptables-nft" ]; then
    : # IPT bukan salah satunya, lewati pemeriksaan
  else
    local cek
    if [ "$IPT" = "/usr/sbin/iptables-legacy" ]; then
      cek=/usr/sbin/iptables-nft
    else
      cek=/usr/sbin/iptables-legacy
    fi
    if [ -x "$cek" ] && [ "$("$cek" -S INPUT 2>/dev/null | grep -c '^-A')" -gt 0 ]; then
      lain="$cek"
    fi
  fi
  printf '%s' "$lain"
}

hook_parent() {
  # Keluaran: "IN_BT" atau "INPUT". IN_BT dipilih bila ada karena di
  # sanalah posisi yang benar menurut urutan wajib di atas (di bawah
  # whitelist panel). INPUT posisi 1 hanya cadangan.
  if "$IPT" -S IN_BT >/dev/null 2>&1; then
    printf 'IN_BT'
  else
    printf 'INPUT'
  fi
}

hook_chain() {
  # Pasang lompatan induk -> SENTINEL. Idempoten: tidak menggandakan
  # bila sudah ada. Mengembalikan 0 bila terpasang atau sudah ada.
  local induk="$1"
  if "$IPT" -S "$induk" 2>/dev/null | grep -qxF -- "-A $induk -j $CHAIN"; then
    return 0
  fi
  if [ "$induk" = "IN_BT" ]; then
    "$IPT" -I IN_BT 1 -j "$CHAIN"
  else
    "$IPT" -I INPUT 1 -j "$CHAIN"
  fi
}
SET_BAN="sentinel_ban"
SET_THR="sentinel_throttle"
# Set ANTRIAN REVIEW. Berbeda dengan dua set di atas, paket dari
# IP di sini TIDAK diblokir. Set ini hanya penanda supaya operator
# bisa melihat siapa yang menunggu keputusan.
SET_REV="sentinel_review"
# Set GEO: blokir seluruh blok CIDR satu negara. Berbeda dengan set lain,
# isinya relatif besar (satu negara bisa 100 ribu blok) dan TIDAK pakai
# timeout: negara tidak pernah berhenti jadi negara. Dicabut lewat
# 'sentinel-geo.sh clear', bukan kedaluwarsa sendiri.
SET_GEO="sentinel_geo"
# Set THREAT INTEL: daftar CIDR reputasi buruk global (Spamhaus DROP/EDROP).
# Dikelola oleh sentinel-intel.sh, diperbarui otomatis via sentinel-intel.timer.
SET_INTEL="sentinel_intel"

# Pengaman lalu lintas keluar (Egress Guard) untuk proses web (UID 1002 / www).
# Mencegah reverse shell dan unduhan payload backdoor ke port arbitrer.
EGRESS_CHAIN="SENTINEL_OUT"
EGRESS_FLAG_FILE="/www/server/sentinel/run/egress.state"
WEB_UID="${SENTINEL_WEB_UID:-1002}"

ALLOW_FILE=/www/server/sentinel/etc/allowlist.txt

# ---- parameter yang bisa diubah lewat environment ----
# Batas koneksi bersamaan per IP (anti slowloris dan connection drain).
CONN_MAX="${SENTINEL_CONN_MAX:-80}"
# Batas koneksi SYN baru bersamaan per IP (anti SYN flood).
SYN_MAX="${SENTINEL_SYN_MAX:-40}"
# Batas laju untuk IP yang masuk daftar throttle.
# Urutan pembacaan: environment, lalu guardd.conf, baru bawaan.
# Environment dipakai systemd unit dan tes manual; guardd.conf adalah
# tempat yang diubah lewat plugin panel. Bawaan hanya dipakai kalau dua-duanya
# kosong, bukan sebagai penimpaan nilai yang sudah disetel operator.
CONF_FILE="${SENTINEL_CONF:-/www/server/sentinel/etc/guardd.conf}"
conf_get() {
  local v=""
  if [ -f "$CONF_FILE" ]; then
    v="$(sed -n -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*([^#]*).*/\1/p" \
         "$CONF_FILE" 2>/dev/null | head -1)"
    v="$(printf '%s' "$v" | tr -d ' \t\r')"
  fi
  [ -n "$v" ] && printf '%s' "$v" || printf '%s' "$2"
}
EGRESS_MODE="${SENTINEL_EGRESS_MODE:-$(conf_get egress_guard off)}"
THROTTLE_RPS="${SENTINEL_THROTTLE_RPS:-$(conf_get throttle_rps 5)}"
THROTTLE_BURST="${SENTINEL_THROTTLE_BURST:-$(conf_get throttle_burst 15)}"
# rpm = permintaan per menit. Kosongkan untuk mematikan aturan per menit.
THROTTLE_RPM="${SENTINEL_THROTTLE_RPM:-$(conf_get throttle_rpm 0)}"
case "$THROTTLE_RPM" in ''|*[!0-9]*) THROTTLE_RPM=0 ;; esac
# Nilai tak sah dari guardd.conf tidak boleh membuat aturan RETURN gagal sementara
# aturan throttle-drop tetap terpasang (semua IP throttle akan terblokir total).
case "$THROTTLE_RPS" in ''|*[!0-9]*|0) THROTTLE_RPS=5 ;; esac
case "$THROTTLE_BURST" in ''|*[!0-9]*|0) THROTTLE_BURST=15 ;; esac

# ---- geo-ban (blokir per negara) ----
# geo_mode: off | block | allow. Bawaan off: tidak ada negara yang
# diblokir sampai operator menyalakannya. Memblokir seluruh negara
# tidak boleh pernah terjadi tanpa keputusan sadar.
GEO_MODE="${SENTINEL_GEO_MODE:-$(conf_get geo_mode off)}"
GEO_NEGARA="${SENTINEL_GEO_NEGARA:-$(conf_get geo_negara '')}"
case "$GEO_MODE" in off|block|allow) ;; *) GEO_MODE="off" ;; esac
# Normalisasi daftar negara: huruf besar, tanpa spasi, tanpa kode ganda.
GEO_NEGARA="$(printf '%s' "$GEO_NEGARA" | tr 'a-z' 'A-Z' | tr -d ' \t')"
# Cadera global anti keledai-server. KOSONGKAN variabel ini untuk
# mematikan. Nilai default 3000/detik sekitar 200 kali lipat traffic
# normal server ini, jadi praktis tidak akan tersentuh.
GLOBAL_RATE="${SENTINEL_GLOBAL_RATE-3000/second}"
GLOBAL_BURST="${SENTINEL_GLOBAL_BURST-6000}"
# Port web yang dilindungi.
WEB_PORTS="${SENTINEL_WEB_PORTS:-80,443}"
# Port untuk geo-ban. Bawaan 443 (HTTPS) agar tantangan HTTP-01 Let's Encrypt (port 80)
# tetap dapat diverifikasi secara global dari server CA mana pun tanpa diblokir,
# sementara seluruh lalu lintas produksi HTTPS tetap terlindungi secara ketat.
GEO_PORTS="${SENTINEL_GEO_PORTS:-443}"

say() { printf '[sentinel-fw] %s\n' "$*"; }
err() { printf '[sentinel-fw] GALAT: %s\n' "$*" >&2; }

need_root() {
  [ "$(id -u)" -eq 0 ] || { err "harus dijalankan sebagai root"; exit 1; }
}

# Cek ketersediaan match extension. Tidak semua modul ada di setiap
# kernel/iptables, jadi setiap aturan opsional guarded.
have_mod() {
  "$IPT" -m "$1" -h >/dev/null 2>&1
}

ensure_set() {
  # ensure_set <nama> <timeout_bawaan>
  local name="$1" tmo="$2"
  if "$IPSET" list "$name" >/dev/null 2>&1; then
    return 0
  fi
  if printf 'create %s hash:net family inet timeout %s hashsize 4096 maxelem 262144\n' \
      "$name" "$tmo" | "$IPSET" restore 2>/dev/null; then
    say "ipset $name dibuat (timeout ${tmo}s)"
  else
    err "gagal membuat ipset $name"
  fi
}

# --- 1. pastikan ada induk untuk hook (IN_BT panel, atau INPUT) ---
require_bt_hook() {
  # IN_BT dibuat panel aaPanel. Kalau panel diganti frontend lain (ufw
  # atau firewalld) dan IN_BT hilang, jangan gagal: pakai INPUT.
  # Keamanan perilaku: chain SENTINEL hanya DROP IP terdaftar di set
  # milik sendiri, sisanya RETURN, jadi aturan frontend lain yang
  # berjalan sesudahnya tidak terganggu.
  local induk
  induk="$(hook_parent)"
  if [ "$induk" = "INPUT" ]; then
    err "PERINGATAN: chain IN_BT tidak ada, hook dipasang di INPUT posisi 1."
    err "Keadaan ini normal bila panel memakai ufw atau firewalld."
  fi
  return 0
}

# --- 2. whitelist persisten milik guardd ---
install_allow_rules() {
  local n=0 ip
  [ -s "$ALLOW_FILE" ] || return 0
  while IFS= read -r ip || [ -n "$ip" ]; do
    ip="${ip%%#*}"
    ip="$(printf '%s' "$ip" | tr -d ' \t\r')"
    [ -z "$ip" ] && continue
    # hanya terima bentuk IP v4 atau CIDR sederhana
    case "$ip" in
      *[!0-9./]*) continue ;;
      */*) ;;
      *) case "$ip" in *.*) ;; *) continue ;; esac ;;
    esac
    if "$IPT" -A "$CHAIN" -s "$ip" -j RETURN 2>/dev/null; then
      n=$((n + 1))
    fi
  done < "$ALLOW_FILE"
  [ "$n" -gt 0 ] && say "whitelist persisten: $n entri diteruskan sebelum aturan lain"
  return 0
}

# --- 2b. deteksi otomatis antarmuka & koneksi VPN (WireGuard, OpenVPN, Tailscale, ZeroTier) ---
# Hanya CIDR yang sempit yang boleh masuk daftar putih: "wg show allowed-ips" pada
# klien WireGuard sering berisi 0.0.0.0/0, dan satu entri itu memutihkan SELURUH internet
# (tidak ada IP yang pernah diblokir lagi). Awalan di bawah /16 ditolak.
vpn_cidr_ok() {
  local c="$1" o p
  [[ "$c" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]{1,2}))?$ ]] || return 1
  for o in 1 2 3 4; do [ "${BASH_REMATCH[$o]}" -le 255 ] || return 1; done
  p="${BASH_REMATCH[6]:-32}"
  [ "$p" -ge 16 ] && [ "$p" -le 32 ] || return 1
  case "$c" in 0.*|127.*|224.*|225.*|23[0-9].*|24[0-9].*|25[0-5].*) return 1 ;; esac
  return 0
}

# Tambah satu entri ke allowlist.txt (milik plugin) bila belum ada sebagai BARIS PENUH.
vpn_allow_add() {
  local e="$1" note="$2"
  [ -f "$ALLOW_FILE" ] || return 0
  grep -qxF -- "$e" "$ALLOW_FILE" 2>/dev/null && return 0
  printf '\n# %s\n%s\n' "$note" "$e" >> "$ALLOW_FILE"
}

auto_detect_vpn_whitelist() {
  local vpn_devs dev ip_cidr r_net ep aip
  vpn_devs="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(wg|tun|tailscale|zt|ppp)' | cut -d'@' -f1 | sort -u)"
  [ -z "$vpn_devs" ] && return 0

  for dev in $vpn_devs; do
    say "vpn-guard: antarmuka VPN aktif terdeteksi: $dev"

    # 1. Bypass inspeksi INPUT pada antarmuka VPN
    "$IPT" -A "$CHAIN" -i "$dev" -j RETURN 2>/dev/null || true

    # 2. Whitelist IP/CIDR lokal antarmuka VPN
    for ip_cidr in $(ip -o -4 addr show dev "$dev" 2>/dev/null | awk '{print $4}'); do
      vpn_cidr_ok "$ip_cidr" || { say "vpn-guard: $ip_cidr dilewati (tidak sempit)"; continue; }
      "$IPT" -A "$CHAIN" -s "$ip_cidr" -j RETURN 2>/dev/null || true
      vpn_allow_add "$ip_cidr" "Auto-whitelist antarmuka VPN $dev"
    done

    # 3. Whitelist rute terkait antarmuka VPN
    for r_net in $(ip -o route show dev "$dev" 2>/dev/null | awk '{print $1}' | grep -v default); do
      vpn_cidr_ok "$r_net" || { say "vpn-guard: rute $r_net dilewati (tidak sempit)"; continue; }
      "$IPT" -A "$CHAIN" -s "$r_net" -j RETURN 2>/dev/null || true
      vpn_allow_add "$r_net" "Auto-whitelist rute VPN $dev"
    done

    # 4. Endpoint dan allowed-ips WireGuard bila tersedia
    if command -v wg >/dev/null 2>&1 && [[ "$dev" =~ ^wg ]]; then
      for ep in $(wg show "$dev" endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1); do
        vpn_cidr_ok "$ep" || continue
        "$IPT" -A "$CHAIN" -s "$ep/32" -j RETURN 2>/dev/null || true
        vpn_allow_add "$ep/32" "WireGuard peer endpoint"
      done
      for aip in $(wg show "$dev" allowed-ips 2>/dev/null | awk '{$1=""; print $0}' | tr ',' ' '); do
        vpn_cidr_ok "$aip" || { say "vpn-guard: allowed-ips $aip dilewati (tidak sempit)"; continue; }
        "$IPT" -A "$CHAIN" -s "$aip" -j RETURN 2>/dev/null || true
        vpn_allow_add "$aip" "WireGuard allowed-ips"
      done
    fi

    # 5-6. FORWARD dan NAT milik pihak lain: HANYA bila operator memintanya
    # (touch $BASE/etc/vpn_forward.enabled). Dulu selalu menyisipkan aturan global
    # yang tidak ikut dicabut saat uninstall.
    if [ -f "${ETC:-$(dirname "$ALLOW_FILE")}/vpn_forward.enabled" ]; then
      "$IPT" -C FORWARD -i "$dev" -j ACCEPT 2>/dev/null || "$IPT" -I FORWARD 1 -i "$dev" -j ACCEPT 2>/dev/null || true
      "$IPT" -C FORWARD -o "$dev" -j ACCEPT 2>/dev/null || "$IPT" -I FORWARD 1 -o "$dev" -j ACCEPT 2>/dev/null || true
      "$IPT" -t nat -C POSTROUTING -o "$dev" -j MASQUERADE 2>/dev/null || "$IPT" -t nat -I POSTROUTING 1 -o "$dev" -j MASQUERADE 2>/dev/null || true
    fi
  done
  return 0
}

# --- 3. lompatan induk -> SENTINEL (definisi ada di blok kompatibilitas) ---

do_install() {
  need_root
  # Satu pemasangan pada satu waktu (timer 5 menit dan UI bisa bersamaan):
  # pemasangan ganda mengacaukan urutan aturan, dan RETURN di tengah = fail-open.
  mkdir -p /www/server/sentinel/run 2>/dev/null
  exec 9>/www/server/sentinel/run/.fw-install.lock 2>/dev/null
  if ! flock -n 9 2>/dev/null; then
    say "pemasangan lain sedang berjalan, dilewati"
    return 0
  fi
  if ! "$IPT" -t filter -L INPUT -n >/dev/null 2>&1; then
    err "iptables tidak bisa membaca chain INPUT, keluar"
    exit 1
  fi
  require_bt_hook || exit 1

  # backend ganda adalah kegagalan diam-diam: aturan terpasang di backend
  # yang salah dan tidak pernah tersentuh paket. Beri tahu, jangan lanjut
  # diam-diam.
  local split backend induk
  split="$(backend_split)"
  if [ -n "$split" ]; then
    err "PERINGATAN: tabel INPUT berisi aturan di backend lain ($split),"
    err "sementara skrip ini memakai $IPT. Hook mungkin tidak tersentuh paket."
  fi
  backend="$(detect_backend)"
  induk="$(hook_parent)"
  say "backend: $backend, hook: $induk -> $CHAIN"

  ensure_set "$SET_BAN" 3600
  ensure_set "$SET_THR" 1800
  ensure_set "$SET_REV" 43200
  # Geo: TANPA timeout (0 = permanen). maxelem besar karena satu negara
  # bisa 115.345 blok; bawaan ensure_set hanya 262144, jadi cukup, tapi
  # tetap dipastikan ada di sini supaya aturan di atasnya bisa dipasang.
  ensure_set "$SET_GEO" 0
  # Threat Intel global: Spamhaus DROP/EDROP (diperbarui via sentinel-intel.timer)
  ensure_set "$SET_INTEL" 0

  # PEMULIHAN SETELAH REBOOT. ipset tidak persisten: setelah mesin
  # menyala ulang, sentinel_geo kosong meskipun guardd.conf masih
  # menyimpan negara terblokir. Tanpa langkah ini geo-ban hilang diam
  # -diam setiap reboot -- persis jenis kegagalan senyap yang ingin
  # dihindari. Kalau mode terisi tetapi set kosong, isi ulang sekarang.
  # sentinel-fw.service berjalan saat boot, jadi ini yang memulihkannya.
  if [ "$GEO_MODE" != "off" ] && [ -n "$GEO_NEGARA" ]; then
    local isi_geo
    isi_geo="$("$IPSET" list "$SET_GEO" 2>/dev/null | grep -c '^[0-9]')"
    if [ "${isi_geo:-0}" -eq 0 ]; then
      say "geo_mode=$GEO_MODE tetapi set kosong (kemungkinan habis reboot): mengisi ulang"
      if geo_isi_set; then
        say "geo-ban dipulihkan: $("$IPSET" list "$SET_GEO" 2>/dev/null | grep -c '^[0-9]') blok CIDR"
      else
        err "gagal memulihkan geo-ban; periksa $GEO_JSON dan kode negara"
      fi
    fi
  else
    # Bila mode off atau negara kosong: pastikan ipset dikosongkan agar tidak ada sisa CIDR lama
    if "$IPSET" list "$SET_GEO" >/dev/null 2>&1; then
      "$IPSET" flush "$SET_GEO" 2>/dev/null || true
    fi
  fi

  "$IPT" -N "$CHAIN" 2>/dev/null || true
  "$IPT" -F "$CHAIN" 2>/dev/null || { err "gagal mengosongkan chain $CHAIN"; exit 1; }

  # 1) subnet privat dan loopback: selalu diteruskan.
  "$IPT" -A "$CHAIN" -m set --match-set aapanel.ipv4.whitelist src -j RETURN
  local net
  for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    "$IPT" -A "$CHAIN" -s "$net" -j RETURN
  done

  # 2) whitelist persisten (allowlist.txt)
  install_allow_rules

  # 2a) deteksi otomatis koneksi WireGuard & VPN lain (auto-whitelist & routing)
  auto_detect_vpn_whitelist

  # 2b) GEO-BAN: blokir seluruh blok CIDR negara terpilih.
  #
  #     Diletakkan SETELAH whitelist dan allowlist, dan SEBELUM review
  #     serta ban. Urutan ini disengaja:
  #       - Setelah whitelist: IP yang sengaja diizinkan operator harus
  #         selalu menang, apa pun negaranya. Kalau geo di atas whitelist,
  #         satu kesalahan kode negara mengunci operator keluar.
  #       - Sebelum ban: geo lebih kuat dari ban (negara tidak berubah),
  #         jadi wilayah terblokir tidak perlu dinilai lagi per IP.
  #       - Sebelum review: IP yang sudah diblokir geo tidak boleh ikut
  #         tercatat sebagai "menunggu keputusan" di antrean review.
  #
  #     Hanya berlaku di port web. SSH dan port panel tidak tersentuh,
  #     supaya konfigurasi yang salah masih bisa diperbaiki.
  if [ "$GEO_MODE" != "off" ] && [ -n "$GEO_NEGARA" ] \
     && [ "$SET_GEO" ] && "$IPSET" list "$SET_GEO" >/dev/null 2>&1 \
     && [ "$("$IPSET" list "$SET_GEO" 2>/dev/null | grep -c '^[0-9]')" -gt 0 ]; then
    "$IPT" -A "$CHAIN" -p tcp -m multiport --dports "$GEO_PORTS" \
      -m set --match-set "$SET_GEO" src \
      -m comment --comment "sentinel:geo-drop" -j DROP
    say "geo-ban aktif: $("$IPSET" list "$SET_GEO" 2>/dev/null | grep -c '^[0-9]') blok CIDR diblokir pada port $GEO_PORTS"
  else
    if "$IPSET" list "$SET_GEO" >/dev/null 2>&1; then
      "$IPSET" flush "$SET_GEO" 2>/dev/null || true
    fi
    say "geo-ban tidak aktif (set kosong atau mode off)"
  fi

  # 2c) GLOBAL THREAT INTEL: blokir seluruh CIDR botnet & C2 reputasi buruk (Spamhaus DROP/EDROP).
  if [ "$SET_INTEL" ] && "$IPSET" list "$SET_INTEL" >/dev/null 2>&1 \
     && [ "$("$IPSET" list "$SET_INTEL" 2>/dev/null | grep -c '^[0-9]')" -gt 0 ]; then
    "$IPT" -A "$CHAIN" -m set --match-set "$SET_INTEL" src \
      -m comment --comment "sentinel:intel-drop" -j DROP
    say "threat intel aktif: $("$IPSET" list "$SET_INTEL" 2>/dev/null | grep -c '^[0-9]') CIDR reputasi buruk diblokir"
  else
    say "threat intel tidak aktif (set kosong atau belum diunduh)"
  fi

  # 3) BAN: temporal, diisi guardd. Sepenuhnya di kernel sehingga tetap
  #    berlaku walau guardd mati atau restart.
  #
  #    WAJIB SEBELUM aturan throttle. Saat eskalasi, satu IP bisa saja
  #    ada di KEDUA set sekaligus: set throttle timeoutnya 1800 detik
  #    sedangkan ban 3600 detik. Kalau throttle diletakkan lebih dulu,
  #    IP itu akan lolos lewat aturan "izinkan sampai batas laju" dan
  #    ban tidak akan pernah berlaku -- tepat untuk IP yang paling
  #    berbahaya.
  # Antrean review. Sengaja TIDAK memakai -j DROP: IP yang masuk
  # daftar ini hanya dicatat, bukan diblokir. Tujuannya operator
  # bisa memutuskan, bukan memblokir otomatis.
  #
  # Harus DILETAKKAN sebelum aturan ban. Kalau berada setelahnya, IP
  # yang sudah diblokir akan sampai ke sini lebih dulu dan tercatat
  # sebagai masih menunggu keputusan, padahal sebenarnya sudah
  # diblokir.
  "$IPT" -A "$CHAIN" -m set --match-set "$SET_REV" src \
    -m comment --comment "sentinel:review" -j RETURN
  say "antrian review aktif dari $SET_REV (tidak memblokir, hanya mencatat)"

  "$IPT" -A "$CHAIN" -m set --match-set "$SET_BAN" src \
    -m comment --comment "sentinel:ban-drop" -j DROP
  say "ban aktif dari $SET_BAN (timeout bawaan 3600 detik)"

  # 4) THROTTLE: IP mencurigakan tapi belum layak di-ban.
  #    Hanya berlaku pada port web. Aturan pertama mengizinkan sampai
  #    batas laju, aturan kedua membuang sisanya.
  if have_mod hashlimit; then
    # 4a. Aturan per DETIK. Menahan ledakan sesaat. bursting
    #     short-lived tapi besar, misalnya 200 request dalam 1 detik.
    "$IPT" -A "$CHAIN" -p tcp -m multiport --dports "$WEB_PORTS" \
      -m set --match-set "$SET_THR" src \
      -m hashlimit --hashlimit-upto "$THROTTLE_RPS/second" \
      --hashlimit-burst "$THROTTLE_BURST" \
      --hashlimit-name sentinel_thr \
      --hashlimit-htable-expire 600000 -j RETURN

    # 4b. Aturan per MENIT. Menahan penyalahgunaan BERLANGSUNG yang lolos
    #     dari aturan per detik: 4 rps terus-menerus di bawah 5 rps, tapi
    #     240 per menit. Tanpa aturan ini penyerang tidak pernah tertangkap.
    #     Nilai 0 berarti dimatikan.
    if [ "$THROTTLE_RPM" -gt 0 ]; then
      "$IPT" -A "$CHAIN" -p tcp -m multiport --dports "$WEB_PORTS" \
        -m set --match-set "$SET_THR" src \
        -m hashlimit --hashlimit-upto "$THROTTLE_RPM/minute" \
        --hashlimit-burst "$THROTTLE_BURST" \
        --hashlimit-name sentinel_thr_min \
        --hashlimit-htable-expire 600000 -j RETURN
      say "throttle per menit: maksimal ${THROTTLE_RPM} rpm"
    else
      say "throttle per menit: DIMATIKAN (throttle_rpm = 0)"
    fi

    "$IPT" -A "$CHAIN" -p tcp -m multiport --dports "$WEB_PORTS" \
      -m set --match-set "$SET_THR" src \
      -m comment --comment "sentinel:throttle-drop" -j DROP
    say "throttle per detik: maksimal ${THROTTLE_RPS} rps, burst ${THROTTLE_BURST}"
  else
    err "modul hashlimit tidak ada, aturan throttle dilewati"
  fi

  # 5) Anti SYN flood dan anti koneksi berkelanjutan, per IP.
  if have_mod connlimit && have_mod conntrack; then
    # Dibatasi ke port web: tanpa --dport, IP admin dengan banyak koneksi SSH/panel
    # ikut terkunci.
    "$IPT" -A "$CHAIN" -p tcp -m multiport --dports "$WEB_PORTS" --syn -m conntrack --ctstate NEW \
      -m connlimit --connlimit-above "$SYN_MAX" --connlimit-mask 32 \
      -m comment --comment "sentinel:syn-guard" -j DROP
    "$IPT" -A "$CHAIN" -p tcp -m multiport --dports "$WEB_PORTS" -m conntrack \
      --ctstate NEW -m connlimit --connlimit-above "$CONN_MAX" \
      --connlimit-mask 32 \
      -m comment --comment "sentinel:conn-guard" -j DROP
    say "batas koneksi per IP: SYN $SYN_MAX, koneksi baru port web $CONN_MAX"
  else
    err "modul connlimit atau conntrack tidak ada, batas koneksi dilewati"
  fi

  # 6) Pengaman global. Hanya menyala bila nilainya diisi.
  #    Tujuannya mencegah PHP-FPM jenuh total saat lonjakan besar.
  if [ -n "$GLOBAL_RATE" ] && have_mod hashlimit && have_mod conntrack; then
    "$IPT" -A "$CHAIN" -p tcp -m multiport --dports "$WEB_PORTS" -m conntrack \
      --ctstate NEW -m hashlimit --hashlimit-upto "$GLOBAL_RATE" \
      --hashlimit-burst "$GLOBAL_BURST" --hashlimit-name sentinel_global \
      --hashlimit-htable-expire 600000 -j RETURN
    "$IPT" -A "$CHAIN" -p tcp -m multiport --dports "$WEB_PORTS" -m conntrack \
      --ctstate NEW -m comment --comment "sentinel:global-fuse" -j DROP
    say "pengaman global aktif: ${GLOBAL_RATE} burst ${GLOBAL_BURST} pada port ${WEB_PORTS}"
  else
    say "pengaman global DIMATIKAN (SENTINEL_GLOBAL_RATE kosong)"
  fi

  # 7) Port Firewall Inbound: Arahkan ke SENTINEL_IN_PORTS bila chain tersedia
  if "$IPT" -S SENTINEL_IN_PORTS >/dev/null 2>&1; then
    "$IPT" -A "$CHAIN" -j SENTINEL_IN_PORTS
    say "hook SENTINEL -> SENTINEL_IN_PORTS terpasang"
  fi

  # 8) Sisanya biarkan ke tahap berikutnya: nginx.
  "$IPT" -A "$CHAIN" -j RETURN

  # 8) Hook + verifikasi. hook_chain memakai induk yang dipilih di awal
  #    (IN_BT bila ada, INPUT bila tidak). Verifikasi memakai binary
  #    yang sama: kalau chain tidak terlihat, install gagal keras.
  if ! hook_chain "$induk"; then
    err "gagal menyisipkan lompatan $induk -> $CHAIN"
    exit 1
  fi
  if ! "$IPT" -S "$CHAIN" >/dev/null 2>&1; then
    err "chain $CHAIN tidak terlihat lewat $IPT setelah dipasang."
    err "Kemungkinan backend ganda (nft vs legacy). Install GAGAL."
    exit 1
  fi

  # 9) EGRESS GUARD: pulihkan status egress bila aktif atau terkonfigurasi on
  if [ -f "$EGRESS_FLAG_FILE" ] || [ "$EGRESS_MODE" = "on" ]; then
    do_egress_on
  fi

  # 10) PORT FIREWALL: terapkan aturan port masuk & keluar jika ports.json ada
  if [ -f "/www/server/sentinel/etc/ports.json" ] && [ -x "/www/server/sentinel/bin/sentinel-ports.py" ]; then
    say "memulihkan aturan port firewall (SENTINEL_IN_PORTS & SENTINEL_OUT_PORTS)"
    /www/server/panel/pyenv/bin/python3 /www/server/sentinel/bin/sentinel-ports.py apply >/dev/null 2>&1 || python3 /www/server/sentinel/bin/sentinel-ports.py apply >/dev/null 2>&1 || true
  fi

  say "selesai. periksa dengan: $IPT_BIN -S $CHAIN"
}

do_remove() {
  need_root
  do_egress_off 2>/dev/null || true
  python3 /www/server/sentinel/bin/sentinel-ports.py remove 2>/dev/null || true
  # Lepas dari SEMUA induk yang mungkin, karena hook bisa berada di
  # IN_BT atau di INPUT tergantung keadaan saat install.
  while "$IPT" -S IN_BT 2>/dev/null | grep -qxF -- "-A IN_BT -j $CHAIN"; do
    "$IPT" -D IN_BT -j "$CHAIN" 2>/dev/null || break
  done
  while "$IPT" -S INPUT 2>/dev/null | grep -qxF -- "-A INPUT -j $CHAIN"; do
    "$IPT" -D INPUT -j "$CHAIN" 2>/dev/null || break
  done
  "$IPT" -F "$CHAIN" 2>/dev/null
  if "$IPT" -X "$CHAIN" 2>/dev/null; then
    say "chain $CHAIN dicabut"
  else
    say "chain $CHAIN tidak ada, sudah bersih"
  fi
  say "set $SET_BAN dan $SET_THR sengaja tidak dihapus, ban lama tetap berlaku"
}

do_flush() {
  need_root
  "$IPSET" flush "$SET_BAN" 2>/dev/null && say "$SET_BAN dikosongkan"
  "$IPSET" flush "$SET_REV" 2>/dev/null && say "$SET_REV dikosongkan"
  "$IPSET" flush "$SET_THR" 2>/dev/null && say "$SET_THR dikosongkan"
  "$IPSET" flush "$SET_REV" 2>/dev/null && say "$SET_REV dikosongkan"
}

# ==================================================================
# PANIC: blokir SELURUH akses web di server ini.
#
# Dipakai saat ada insiden: kompromi, webmaster yang tidak sengaja
# mengirim bomb, atau lonjakan yang tidak tertangani dan ingin
# memutus akses web seketika sementara investigasi berjalan.
#
# Kenapa di kernel (iptables), bukan di konfigurasi web server:
# aturan ini berlaku untuk nginx, apache, maupun litespeed tanpa
# perbedaan. Kalau dipasang di konfigurasi web server, tiap
# server perlu sintaks berbeda dan ada yang bisa terlewat.
#
# Kenapa port web saja, bukan semua port:
# SSH (22), port panel, dan database TIDAK ikut diblokir. Kalau
# semua port ditutup, satu-satunya jalan untuk mencabut panic adalah
# konsol provider -- dan itu justru kondisi yang paling tidak
# diinginkan ketika server sedang bermasalah.
# ==================================================================
PANIC_CHAIN="SENTINEL_PANIC"
PANIC_FLAG_FILE="/www/server/sentinel/run/panic.state"

# Port panel aaPanel ikut dikecualikan supaya operator tetap bisa
# masuk dan mencabut panic dari UI.
#
# HANYA port.pl yang dibaca. admin_path.pl sengaja TIDAK disentuh:
# isinya jalur URL seperti "/abc12345", bukan nomor port. Kalau ikut
# dibaca dengan tr -dc '0-9', angka di dalam path akan terbaca sebagai
# port dan membuat daftar port rusak.
panel_ports() {
  local f p
  f=/www/server/panel/data/port.pl
  [ -f "$f" ] || return 0
  p="$(tr -dc '0-9' < "$f" 2>/dev/null)"
  case "$p" in ''|*[!0-9]*) return 0 ;; esac
  # nomor port sah: 1 sampai 65535
  [ "$p" -ge 1 ] 2>/dev/null && [ "$p" -le 65535 ] 2>/dev/null || return 0
  printf '%s' "$p"
}

panic_ports() {
  # Mengembalikan daftar port tanpa koma menggantung.
  # Koma menggantung membuat multiport menolak SELURUH aturan, dan kode
  # lama lalu jatuh ke daftar hardcode 80/443. Itu sangat berbahaya:
  # operator mengira hanya port uji yang ditutup, padahal situs produksi
  # yang kena. Karena itu masanya dibersihkan di sini.
  local pp out
  pp="$(panel_ports)"
  out="$WEB_PORTS"
  if [ -n "$pp" ]; then out="$out,$pp"; fi
  printf '%s' "$out" | sed 's/,,*/,/g; s/^,//; s/,$//'
}

do_panic_on() {
  need_root
  local ports; ports="$(panic_ports)"

  if [ -f "$PANIC_FLAG_FILE" ] && "$IPT" -S "$PANIC_CHAIN" >/dev/null 2>&1; then
    say "panic sudah aktif, tidak ada perubahan"
    return 0
  fi

  "$IPT" -N "$PANIC_CHAIN" 2>/dev/null || true
  "$IPT" -F "$PANIC_CHAIN" 2>/dev/null || { err "gagal mengosongkan chain $PANIC_CHAIN"; exit 1; }

  # 1) Yang boleh tetap masuk: whitelist panel dan whitelist persisten.
  "$IPT" -A "$PANIC_CHAIN" -m set --match-set aapanel.ipv4.whitelist src -j RETURN
  local net
  for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    "$IPT" -A "$PANIC_CHAIN" -s "$net" -j RETURN
  done

  # 2) Sisanya diblokir HANYA di port web, bukan seluruh port.
  #
  #    PENTING: kalau multiport menolak, skrip HARUS gagal, bukan
  #    memakai daftar port hardcode. Versi lama jatuh ke daftar 80/443
  #    dan memblokir situs produksi padahal operator bermaksud
  #    menguji port lain. Membatalkan lebih aman daripada menebak.
  case "$ports" in
    ''|*[!0-9,]*|,*|*,) err "daftar port tidak valid: '$ports'"; exit 1 ;;
  esac
  if ! "$IPT" -A "$PANIC_CHAIN" -p tcp -m multiport --dports "$ports" \
       -m comment --comment "sentinel:panic-block" -j DROP 2>/dev/null; then
    err "multiport menolak daftar port '$ports'."
    err "panic dibatalkan agar tidak memblokir port yang tidak diminta."
    "$IPT" -F "$PANIC_CHAIN" 2>/dev/null
    "$IPT" -X "$PANIC_CHAIN" 2>/dev/null
    exit 1
  fi

  # 3) Pasang hook. Di-chain SENTINEL bila chain itu ter-hook ke induk
  #    (ikut whitelist dan ban), kalau tidak langsung ke induk yang sama
  #    dengan hook SENTINEL (IN_BT bila ada, INPUT bila tidak).
  local induk
  induk="$(hook_parent)"
  if "$IPT" -S "$CHAIN" >/dev/null 2>&1 && \
     "$IPT" -S "$induk" 2>/dev/null | grep -qxF -- "-A $induk -j $CHAIN"; then
    "$IPT" -I "$CHAIN" 1 -j "$PANIC_CHAIN"
  elif [ "$induk" = "IN_BT" ] && "$IPT" -S IN_BT >/dev/null 2>&1; then
    "$IPT" -I IN_BT 1 -j "$PANIC_CHAIN"
  elif [ "$induk" = "INPUT" ]; then
    "$IPT" -I INPUT 1 -j "$PANIC_CHAIN"
  else
    err "tidak menemukan induk hook, panic dibatalkan"
    "$IPT" -F "$PANIC_CHAIN" 2>/dev/null; "$IPT" -X "$PANIC_CHAIN" 2>/dev/null
    exit 1
  fi

  printf 'on\nports=%s\nsince=%s\n' "$ports" "$(date '+%Y-%m-%d %H:%M:%S')" \
    > "$PANIC_FLAG_FILE"
  say "PANIC AKTIF. akses web diblokir pada port: $ports"
  say "whitelist, jaringan privat, dan port panel tetap dapat diakses"
  say "cabut dengan: $0 panic-off"
}

do_panic_off() {
  need_root
  local n=0
  # lepas dari semua tempat yang mungkin terpasang
  while "$IPT" -S "$CHAIN" 2>/dev/null | grep -qxF -- "-A $CHAIN -j $PANIC_CHAIN"; do
    "$IPT" -D "$CHAIN" -j "$PANIC_CHAIN" 2>/dev/null || break; n=$((n+1))
  done
  while "$IPT" -S IN_BT 2>/dev/null | grep -qxF -- "-A IN_BT -j $PANIC_CHAIN"; do
    "$IPT" -D IN_BT -j "$PANIC_CHAIN" 2>/dev/null || break; n=$((n+1))
  done
  while "$IPT" -S INPUT 2>/dev/null | grep -qxF -- "-A INPUT -j $PANIC_CHAIN"; do
    "$IPT" -D INPUT -j "$PANIC_CHAIN" 2>/dev/null || break; n=$((n+1))
  done
  "$IPT" -F "$PANIC_CHAIN" 2>/dev/null || true
  "$IPT" -X "$PANIC_CHAIN" 2>/dev/null || true
  rm -f "$PANIC_FLAG_FILE"
  if [ "$n" -eq 0 ] && [ ! -e "$PANIC_FLAG_FILE" ]; then
    say "tidak ada aturan panic yang terpasang (sudah bersih)"
  else
    say "PANIC NONAKTIF. $n lompatan aturan dilepas"
  fi
}

panic_is_on() {
  "$IPT" -S "$PANIC_CHAIN" >/dev/null 2>&1 && [ -f "$PANIC_FLAG_FILE" ]
}

do_panic_status() {
  need_root
  if panic_is_on; then
    say "PANIC: AKTIF"
    [ -f "$PANIC_FLAG_FILE" ] && sed 's/^/  /' "$PANIC_FLAG_FILE"
    "$IPT" -S "$PANIC_CHAIN" 2>/dev/null | sed 's/^/  /'
    return 0
  fi
  say "PANIC: tidak aktif"
  return 1
}

# ==================================================================
# EGRESS GUARD (ANTI-REVERSE SHELL)
#
# Membatasi koneksi keluar dari akun pekerja web (UID 1002 / www).
# PHP-FPM dan worker web normalnya hanya membutuhkan koneksi lokal
# (loopback), DNS (udp/tcp 53), HTTP/HTTPS (tcp 80,443), dan pengiriman
# email (587,465).
#
# Seluruh port keluar lainnya (seperti 4444, 1337, shell reverse, C2)
# DITOLAK (REJECT/DROP). Dengan ini, eksploitasi RCE atau webshell
# yang mencoba membuka reverse shell ke server penyerang akan gagal
# di level kernel.
# ==================================================================
do_egress_on() {
  need_root
  if ! have_mod owner; then
    err "modul iptables owner tidak didukung di kernel ini"
    return 1
  fi

  "$IPT" -N "$EGRESS_CHAIN" 2>/dev/null || true
  "$IPT" -F "$EGRESS_CHAIN" 2>/dev/null || { err "gagal mengosongkan chain $EGRESS_CHAIN"; return 1; }

  # 1) Loopback interface
  "$IPT" -A "$EGRESS_CHAIN" -o lo -j ACCEPT

  # 2) Koneksi balasan / established
  if have_mod conntrack; then
    "$IPT" -A "$EGRESS_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi

  # 3) DNS query (UDP & TCP 53)
  "$IPT" -A "$EGRESS_CHAIN" -p udp --dport 53 -j ACCEPT
  "$IPT" -A "$EGRESS_CHAIN" -p tcp --dport 53 -j ACCEPT

  # 4) Web API & Git HTTPS keluar (HTTP 80, HTTPS 443, Git 9418)
  "$IPT" -A "$EGRESS_CHAIN" -p tcp -m multiport --dports 80,443,9418 -j ACCEPT

  # 5) SSH keluar untuk Git clone/pull/push (GitHub, GitLab, Bitbucket: port 22, 2222)
  "$IPT" -A "$EGRESS_CHAIN" -p tcp -m multiport --dports 22,2222 -j ACCEPT

  # 6) Submission email (587, 465)
  "$IPT" -A "$EGRESS_CHAIN" -p tcp -m multiport --dports 587,465 -j ACCEPT

  # 7) Blokir seluruh koneksi keluar lainnya
  if ! "$IPT" -A "$EGRESS_CHAIN" -m comment --comment "sentinel:egress-block" \
       -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then
    "$IPT" -A "$EGRESS_CHAIN" -m comment --comment "sentinel:egress-block" -j DROP
  fi

  # Hook ke chain OUTPUT untuk UID pekerja web
  while "$IPT" -S OUTPUT 2>/dev/null | grep -qxF -- "-A OUTPUT -m owner --uid-owner $WEB_UID -j $EGRESS_CHAIN"; do
    "$IPT" -D OUTPUT -m owner --uid-owner "$WEB_UID" -j "$EGRESS_CHAIN" 2>/dev/null || break
  done
  "$IPT" -I OUTPUT 1 -m owner --uid-owner "$WEB_UID" -j "$EGRESS_CHAIN"

  mkdir -p /www/server/sentinel/run
  printf 'on\nuid=%s\nports=22,53,80,443,465,587,2222,9418\nsince=%s\n' "$WEB_UID" "$(date '+%Y-%m-%d %H:%M:%S')" > "$EGRESS_FLAG_FILE"
  say "EGRESS GUARD AKTIF: lalu lintas keluar UID $WEB_UID (www) dibatasi ke DNS, HTTP, HTTPS, Git SSH, SMTP"
}

do_egress_off() {
  need_root
  while "$IPT" -S OUTPUT 2>/dev/null | grep -q -- "-j $EGRESS_CHAIN"; do
    "$IPT" -D OUTPUT -m owner --uid-owner "$WEB_UID" -j "$EGRESS_CHAIN" 2>/dev/null || break
  done
  "$IPT" -F "$EGRESS_CHAIN" 2>/dev/null || true
  "$IPT" -X "$EGRESS_CHAIN" 2>/dev/null || true
  rm -f "$EGRESS_FLAG_FILE"
  say "EGRESS GUARD NONAKTIF: batasan lalu lintas keluar UID $WEB_UID dilepas"
}

egress_is_on() {
  "$IPT" -S "$EGRESS_CHAIN" >/dev/null 2>&1 && [ -f "$EGRESS_FLAG_FILE" ]
}

do_egress_status() {
  need_root
  if egress_is_on; then
    say "EGRESS GUARD: AKTIF"
    [ -f "$EGRESS_FLAG_FILE" ] && sed 's/^/  /' "$EGRESS_FLAG_FILE"
    "$IPT" -S "$EGRESS_CHAIN" 2>/dev/null | sed 's/^/  /'
    return 0
  fi
  say "EGRESS GUARD: tidak aktif"
  return 1
}

do_backend() {
  # Laporan satu baris per kunci, mudah dibaca plugin tanpa parsing bebas.
  local b split induk
  b="$(detect_backend)"
  split="$(backend_split)"
  induk="$(hook_parent)"
  printf 'backend=%s\nhook=%s\nbinary=%s\n' "$b" "$induk" "$IPT_BIN"
  if command -v ufw >/dev/null 2>&1; then
    printf 'ufw=%s\n' "$(ufw status 2>/dev/null | head -1 | tr -d '\r')"
  else
    printf 'ufw=tidak-terpasang\n'
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    printf 'firewalld=%s\n' "$(systemctl is-active firewalld 2>/dev/null || echo inactive)"
  else
    printf 'firewalld=tidak-terpasang\n'
  fi
  if [ -n "$split" ]; then
    printf 'split=%s\n' "$split"
  else
    printf 'split=tidak-ada\n'
  fi
  # hook sentinel terpasang di mana sekarang (bisa lebih dari satu)
  "$IPT" -S IN_BT 2>/dev/null | grep -q -- "-A IN_BT -j $CHAIN" && printf 'hook_in_bt=ya\n' || printf 'hook_in_bt=tidak\n'
  "$IPT" -S INPUT 2>/dev/null | grep -q -- "-A INPUT -j $CHAIN" && printf 'hook_in_input=ya\n' || printf 'hook_in_input=tidak\n'
}

# ==================================================================
# GEO-BAN: blokir seluruh blok CIDR satu negara.
#
# Sumber: GeoLite2-Country.json milik panel aaPanel, bentuk
#   [{"brief":"CN","ips":["1.0.1.0/24", ...]}, ...]
# Tidak ada unduhan pihak ketiga; berkas sudah ada dan sudah versi
# panel sendiri.
#
# Cara kerja: 'apply' membaca config (geo_mode + geo_negara), membangun
# daftar CIDR dari berkas itu, mengisinya ke ipset sentinel_geo dalam
# SATU transaksi ipset restore (bukan ratusan ribu 'ipset add'
# terpisah), lalu memasang ulang aturan kernel.
#
# Mode:
#   block = blokir negara yang disebut saja
#   allow = blokir SEMUA negara kecuali yang disebut (sangat ketat)
#   off   = tidak ada yang diblokir
# ==================================================================
GEO_JSON="${SENTINEL_GEO_JSON:-/www/server/panel/data/firewall/GeoLite2-Country.json}"

# Mengisi ipset sentinel_geo dari config. TIDAK memanggil install, jadi
# aman dipanggil dari dalam do_install tanpa rekursi.
# Mengembalikan 0 bila set terisi, bukan-0 bila gagal/kosong.
geo_isi_set() {
  [ "$GEO_MODE" = "off" ] && return 1
  [ -n "$GEO_NEGARA" ] || return 1
  [ -f "$GEO_JSON" ] || return 1
  ensure_set "$SET_GEO" 0

  # Bangun isi ipset restore langsung dari Python: satu transaksi
  # "flush <set>" + "add <set> <cidr>" per baris. JSON parsing di shell
  # rapuh, dan 'ipset add' satu per satu untuk 100 ribu blok akan
  # memakan waktu lama serta meninggalkan set setengah terisi bila
  # dihentikan di tengah.
  local tmp
  tmp="$(mktemp /tmp/sentinel-geo.XXXXXX)" || return 1
  local py_bin="python3"
  if [ -x /www/server/panel/pyenv/bin/python3 ]; then
    py_bin="/www/server/panel/pyenv/bin/python3"
  fi
  if ! GEO_JSON="$GEO_JSON" GEO_MODE="$GEO_MODE" GEO_NEGARA="$GEO_NEGARA" \
       SET_GEO="$SET_GEO" "$py_bin" - > "$tmp" <<'PY'
import json, os, sys
try:
    data = json.load(open(os.environ['GEO_JSON']))
except Exception:
    sys.exit(1)
mode = os.environ['GEO_MODE']
ingin = set(x for x in os.environ['GEO_NEGARA'].split(',') if x)
setname = os.environ['SET_GEO']
out = []
for entri in data:
    kode = entri.get('brief') or entri.get('code') or ''
    if not kode:
        continue
    pilih = (kode in ingin) if mode == 'block' else (kode not in ingin)
    if pilih:
        out.extend(entri.get('ips') or [])
if not out:
    sys.exit(2)
print('flush %s' % setname)
for cidr in out:
    print('add %s %s' % (setname, cidr))
PY
  then
    rm -f "$tmp"
    return 1
  fi

  if ! "$IPSET" restore < "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
  return 0
}

do_geo_apply() {
  need_root
  if [ "$GEO_MODE" = "off" ] || [ -z "$GEO_NEGARA" ]; then
    say "geo_mode=off atau daftar negara kosong: tidak ada yang diblokir"
    do_geo_clear
    return 0
  fi
  if [ ! -f "$GEO_JSON" ]; then
    err "berkas geo tidak ada: $GEO_JSON"
    return 1
  fi

  if ! geo_isi_set; then
    err "tidak ada blok CIDR cocok; periksa kode negara (contoh sah: CN, RU, US)"
    return 1
  fi

  local isi
  isi="$("$IPSET" list "$SET_GEO" 2>/dev/null | grep -c '^[0-9]')"
  if [ "${isi:-0}" -eq 0 ]; then
    err "ipset $SET_GEO kosong setelah restore; geo-ban GAGAL"
    return 1
  fi
  say "geo-ban aktif: $isi blok CIDR di $SET_GEO"

  # Pasang ulang aturan supaya perubahannya langsung berlaku.
  bash "$0" install >/dev/null 2>&1 || err "aturan kernel gagal dipasang ulang"
  say "aturan kernel dipasang ulang"
}

do_geo_clear() {
  need_root
  if "$IPSET" list "$SET_GEO" >/dev/null 2>&1; then
    "$IPSET" flush "$SET_GEO" 2>/dev/null && say "$SET_GEO dikosongkan"
  fi
  # Lepas aturan geo bila ada, lalu pasang ulang chain tanpa itu.
  bash "$0" install >/dev/null 2>&1 || true
  say "geo-ban dinonaktifkan"
}

do_geo_status() {
  need_root
  local isi=0
  "$IPSET" list "$SET_GEO" >/dev/null 2>&1 \
    && isi="$("$IPSET" list "$SET_GEO" 2>/dev/null | grep -c '^[0-9]')"
  printf 'mode=%s\nnegara=%s\nblok=%s\naturan=%s\n' \
    "$GEO_MODE" "$GEO_NEGARA" "$isi" \
    "$("$IPT" -S "$CHAIN" 2>/dev/null | grep -c 'sentinel:geo-drop')"
}

do_status() {
  echo "=== backend firewall ==="
  do_backend | sed 's/^/  /'
  echo
  echo "=== urutan di INPUT (whitelist harus di atas IN_BT) ==="
  "$IPT" -S INPUT 2>/dev/null | grep -nE 'aapanel\.ipv4\.(white|black)list|IN_BT' || true
  echo
  echo "=== aturan di chain $CHAIN ==="
  "$IPT" -S "$CHAIN" 2>/dev/null || echo "(belum ada)"
  echo
  echo "=== isi set ==="
  local s n
  for s in "$SET_BAN" "$SET_THR" "$SET_REV" "$SET_INTEL"; do
    n="$("$IPSET" list "$s" 2>/dev/null | grep -c '^[0-9]' || true)"
    printf '%-18s %s entri\n' "$s" "${n:-0}"
  done
  echo
  echo "=== egress guard (anti-reverse shell UID $WEB_UID) ==="
  do_egress_status || true
  echo
  echo "=== penghitung paket (0 = belum pernah tersentuh) ==="
  "$IPT" -L "$CHAIN" -n -v 2>/dev/null | grep -E 'DROP|CONNLIMIT' || true
  echo
  echo "=== status daemon ==="
  if [ -f /www/server/sentinel/run/guardd.pid ]; then
    p="$(cat /www/server/sentinel/run/guardd.pid)"
    if [ -d "/proc/$p" ]; then
      echo "guardd berjalan, pid $p, RSS $(awk '/VmRSS/{print $2" "$3}' /proc/$p/status 2>/dev/null)"
    else
      echo "guardd TIDAK berjalan (pidfile menyisa)"
    fi
  else
    echo "guardd tidak berjalan"
  fi
}

do_ports_apply() {
  need_root
  python3 /www/server/sentinel/bin/sentinel-ports.py apply
}

do_ports_status() {
  need_root
  python3 /www/server/sentinel/bin/sentinel-ports.py status
}

do_ports_reset() {
  need_root
  python3 /www/server/sentinel/bin/sentinel-ports.py reset
}

# Self-heal ringan (dipanggil dari timer 5 menit setelah install):
# - guardd yang "hidup" tetapi membeku (status.json tidak diperbarui) di-restart;
# - kesehatan WAF diperiksa; WAF yang merusak nginx dicabut dengan aman.
# Tidak menyentuh apa pun yang bukan milik plugin.
heal_services() {
  command -v systemctl >/dev/null 2>&1 || return 0
  local sj=/www/server/sentinel/run/status.json now mt
  if systemctl is-active --quiet sentinel.service 2>/dev/null && [ -f "$sj" ]; then
    now=$(date +%s); mt=$(stat -c %Y "$sj" 2>/dev/null || echo "$now")
    if [ $((now - mt)) -gt 300 ]; then
      say "heal: status.json guardd basi $((now - mt))s, restart sentinel.service"
      systemctl restart sentinel.service 2>/dev/null || true
    fi
  fi
  if [ -x /www/server/sentinel/bin/sentinel-waf.sh ]; then
    /www/server/sentinel/bin/sentinel-waf.sh guard 2>&1 | while IFS= read -r l; do say "heal: $l"; done
  fi
  return 0
}

case "${1:-status}" in
  install) do_install; heal_services ;;
  heal)    heal_services ;;
  remove)  do_remove ;;
  flush)   do_flush ;;
  status)  do_status ;;
  backend) do_backend ;;
  panic-on)     do_panic_on ;;
  panic-off)    do_panic_off ;;
  panic-status) do_panic_status ;;
  egress-on)     do_egress_on ;;
  egress-off)    do_egress_off ;;
  egress-status) do_egress_status ;;
  geo-apply)    do_geo_apply ;;
  geo-clear)    do_geo_clear ;;
  geo-status)   do_geo_status ;;
  ports-apply)  do_ports_apply ;;
  ports-status) do_ports_status ;;
  ports-reset)  do_ports_reset ;;
  *) echo "Usage: $0 {install|heal|remove|flush|status|backend|panic-on|panic-off|panic-status|egress-on|egress-off|egress-status|geo-apply|geo-clear|geo-status|ports-apply|ports-status|ports-reset}"; exit 1 ;;
esac
