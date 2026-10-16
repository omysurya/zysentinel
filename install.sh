#!/bin/bash
# ============================================================
# Pemasangan dan pencabutan Sentinel.
#
# Dipanggil panel lewat info.json (kolom "shell"). Aman dijalankan
# berkali-kali: tidak menghapus apa pun milik panel maupun pemilik.
# ============================================================
set -u
BASE=/www/server/sentinel
BIN="$BASE/bin"
ETC="$BASE/etc"

say() { echo "[zysentinel] $*"; }
err() { echo "[zysentinel] GALAT: $*" >&2; }

butuh_root() {
  [ "$(id -u)" -eq 0 ] || { err "jalankan sebagai root"; exit 1; }
}

cek_depe() {
  # Dependensi untuk server baru. Tanpa ini instalasi gagal di tengah
  # dengan pesan yang membingungkan (mis. gcc tidak ada -> guardd tidak
  # terkompilasi -> checks gagal -> panel bilang instalasi gagal).
  local kurang=""
  command -v gcc >/dev/null 2>&1 || kurang="$kurang gcc"
  command -v ipset >/dev/null 2>&1 || kurang="$kurang ipset"
  command -v iptables >/dev/null 2>&1 || kurang="$kurang iptables"
  # header sqlite3 untuk kompilasi guardd (-lsqlite3)
  if ! echo '#include <sqlite3.h>' | gcc -E - >/dev/null 2>&1; then
    kurang="$kurang libsqlite3-dev"
  fi
  # cjson untuk engine free_waf (hanya bila nginx + lua ada)
  if [ -x /www/server/nginx/sbin/nginx ] \
     && /www/server/nginx/sbin/nginx -V 2>&1 | grep -q 'lua_nginx_module' \
     && [ ! -f /usr/local/lib/lua/5.1/cjson.so ]; then
    kurang="$kurang lua-cjson"
  fi
  [ -z "$kurang" ] && { say "dependensi OK"; return 0; }
  say "dependensi kurang:$kurang, mencoba pasang otomatis"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq 2>&1 | tail -1
    # shellcheck disable=SC2086
    apt-get install -y gcc libsqlite3-dev ipset iptables lua-cjson $kurang >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc sqlite-devel ipset iptables lua-cjson 2>&1 | tail -1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc sqlite-devel ipset iptables lua-cjson 2>&1 | tail -1 || true
  else
    err "manajer paket tidak dikenal, pasang manual:$kurang"
    return 1
  fi
  # verifikasi ulang yang kritis (guardd tidak bisa tanpa ini)
  command -v gcc >/dev/null 2>&1 || { err "gcc tetap tidak ada"; return 1; }
  echo '#include <sqlite3.h>' | gcc -E - >/dev/null 2>&1 \
    || { err "header sqlite3 tetap tidak ada"; return 1; }
  say "dependensi OK"
  return 0
}

pasang_daemon() {
  mkdir -p "$ETC" "$BASE/run" "$BASE/data" "$BASE/log" "$BASE/src" "$BASE/av/baseline" "$BASE/av/last" "$BASE/av/quarantine/files" "$BASE/av/quarantine/meta"
  local pay
  pay="$(dirname "$0")/payload"

  # Salin BERKAS yang dibutuhkan dari payload ke tempat kerjanya.
  #
  # Tanpa langkah ini plugin hanya berfungsi di mesin yang sudah punya
  # semuanya. Di server aaPanel baru, guardd.conf tidak ada (baris di
  # bawah akan menolak jalan) dan sentinel-fw.sh tidak ada sehingga
  # aturan kernel tidak bisa dipasang sama sekali.
  if [ -d "$pay" ]; then
    mkdir -p "$BIN" "$BASE/src"
    for f in guardctl sentinel-fw.sh sentinel-waf.sh sentinel-av.sh sentinel-proc.py sentinel-intel.sh sentinel-notify.sh sentinel-ports.py; do
      if [ -f "$pay/$f" ]; then
        cp -p "$pay/$f" "$BIN/$f"
        chmod 755 "$BIN/$f"
      fi
    done
    [ -f "$pay/guardd" ] && cp -p "$pay/guardd" "$BIN/guardd" && chmod 755 "$BIN/guardd"
    [ -f "$pay/guardd.c" ] && cp -p "$pay/guardd.c" "$BASE/src/guardd.c"
    # config TIDAK ditimpa bila sudah ada: isinya memuat penyesuaian
    # operator (ambang, geo-ban, throttle) yang tidak boleh hilang saat
    # update plugin.
    if [ -f "$pay/guardd.conf.default" ] && [ ! -f "$ETC/guardd.conf" ]; then
      cp -p "$pay/guardd.conf.default" "$ETC/guardd.conf"
      say "guardd.conf dibuat dari default"
    fi
    if [ -f "$pay/allowlist.txt.default" ] && [ ! -f "$ETC/allowlist.txt" ]; then
      cp -p "$pay/allowlist.txt.default" "$ETC/allowlist.txt"
    fi
    if [ -f "$pay/proc_whitelist.json.default" ] && [ ! -f "$ETC/proc_whitelist.json" ]; then
      cp -p "$pay/proc_whitelist.json.default" "$ETC/proc_whitelist.json"
      say "proc_whitelist.json dibuat dari default"
    fi
  fi

  [ -f "$ETC/allowlist.txt" ] || {
    cat > "$ETC/allowlist.txt" <<'EOF'
# ============================================================
# sentinel - daftar putih yang tidak boleh pernah diblokir
#
# Format: satu entri per baris. Boleh IP tunggal atau CIDR.
# Baris kosong dan komentar diabaikan.
#
# PENTING: guardd tidak pernah memasukkan IP ini ke ipset manapun,
# sehingga tidak bisa ter-ban maupun ter-throttle.
# ============================================================
EOF
    say "allowlist.txt dibuat"
  }
  if [ ! -f "$ETC/guardd.conf" ]; then
    err "guardd.conf tidak ada, konfigurasi tidak bisa dibuat otomatis"
    return 1
  fi
  if [ ! -x "$BIN/guardd" ] || ! "$BIN/guardd" -V >/dev/null 2>&1; then
    if [ -f "$pay/guardd" ]; then
      cp -p "$pay/guardd" "$BIN/guardd"
      chmod 755 "$BIN/guardd"
      say "binary guardd dipasang dari payload"
    fi
    if [ ! -x "$BIN/guardd" ] || ! "$BIN/guardd" -V >/dev/null 2>&1; then
      if [ -f "$BASE/src/guardd.c" ] && command -v gcc >/dev/null 2>&1; then
        say "menyusun guardd dari sumber C"
        gcc -O2 -Wall -Wextra -o "$BIN/guardd" "$BASE/src/guardd.c" \
            -lsqlite3 -lm || { err "gagal menyusun guardd"; return 1; }
      else
        err "binary guardd tidak dapat dijalankan dan compiler gcc tidak tersedia"
        return 1
      fi
    fi
  fi
  chmod 755 "$BIN/guardd" "$BIN/guardctl" "$BIN/sentinel-fw.sh" "$BIN/sentinel-av.sh" "$BIN/sentinel-proc.py" "$BIN/sentinel-intel.sh" "$BIN/sentinel-notify.sh" "$BIN/sentinel-ports.py" 2>/dev/null
  return 0
}

pasang_firewall() {
  bash "$BIN/sentinel-fw.sh" install || {
    err "pemasangan aturan kernel gagal"
    return 1
  }
  if [ -f "$BIN/sentinel-ports.py" ]; then
    say "menginisialisasi baseline port firewall (inbound whitelist & outbound allow-all)"
    /www/server/panel/pyenv/bin/python3 "$BIN/sentinel-ports.py" init >/dev/null 2>&1 || python3 "$BIN/sentinel-ports.py" init >/dev/null 2>&1 || true
    bash "$BIN/sentinel-fw.sh" ports-apply >/dev/null 2>&1 || true
  fi
}

pasang_notif() {
  # Skrip pengirim notifikasi dan berkas konfigurasinya.
  #
  # notify.conf TIDAK ditulis ulang kalau sudah ada: isinya memuat
  # token yang setara kata sandi, dan menimpanya saat update plugin
  # akan membuat semua notifikasi diam-diam berhenti terkirim.
  local pay
  pay="$(dirname "$0")/payload"

  if [ -f "$pay/sentinel-notify.sh" ] && [ ! -f "$BIN/sentinel-notify.sh" ]; then
    cp -p "$pay/sentinel-notify.sh" "$BIN/sentinel-notify.sh"
    say "skrip notifikasi dipasang"
  fi
  if [ -f "$pay/notify.conf.default" ] && [ ! -f "$ETC/notify.conf" ]; then
    cp -p "$pay/notify.conf.default" "$ETC/notify.conf"
    chmod 600 "$ETC/notify.conf"
    say "berkas notify.conf dibuat, notifikasi mati sampai diisi"
  fi
  # Skripnya selalu disegarkan: itu bukan keadaan, dan versi lama
  # bisa salah menangani format baru.
  if [ -f "$pay/sentinel-notify.sh" ] && [ -f "$BIN/sentinel-notify.sh" ]; then
    cp -p "$pay/sentinel-notify.sh" "$BIN/sentinel-notify.sh"
    chmod 755 "$BIN/sentinel-notify.sh"
  fi

  command -v systemctl >/dev/null 2>&1 || return 0
  if [ -f "$ETC/notify.conf" ]; then
    if systemctl enable --now sentinel-notify.timer 2>/dev/null; then
      say "timer notifikasi aktif, tiap 10 detik"
    else
      say "timer notifikasi gagal diaktifkan"
    fi
  fi
  return 0
}

konsolidasi_waf() {
  # Pastikan aset WAF bermaster di bawah sentinel, dan path lama tetap
  # valid sebagai symlink. Idempoten:
  #   - bila direktori lama masih direktori biasa (belum dipindah),
  #     pindahkan ke sentinel/waf/ lalu ganti dengan symlink.
  #   - bila sudah symlink, tidak ada yang dikerjakan.
  # Dipakai saat pemasangan di server baru maupun sesudah upgrade.
  mkdir -p "$BASE/waf" || return 1
  # Di server BARU, aset belum ada. Salin dari payload bila tersedia,
  # supaya semua ada di dalam folder sentinel sejak awal.
  local pay; pay="$(dirname "$0")/payload/waf"
  if [ -d "$pay" ]; then
    for d in modsec crs free_waf; do
      if [ -d "$pay/$d" ] && [ ! -e "$BASE/waf/$d" ]; then
        cp -a "$pay/$d" "$BASE/waf/$d"
        say "aset $d disalin dari payload ke sentinel/waf"
      fi
    done
  fi
  # Pindahkan direktori lama (server yang sudah terpasang) + symlink.
  local pair src dst
  for pair in "modsec:modsec" "modsecurity-crs:crs" "free_waf:free_waf"; do
    src="/www/server/${pair%%:*}"; dst="$BASE/waf/${pair##*:}"
    if [ -d "$src" ] && [ ! -L "$src" ]; then
      if [ ! -e "$dst" ]; then
        mv "$src" "$dst" && say "dipindah: $src -> $dst"
      else
        # tujuan sudah ada: jangan menimpa, cukup ganti sumber lama
        # dengan symlink ke tujuan agar tidak berceceran.
        rm -rf "$src" && say "digantikan symlink (tujuan sudah ada): $src"
      fi
    fi
    if [ -d "$BASE/waf/${pair##*:}" ] && [ ! -e "$src" ]; then
      ln -sfn "$BASE/waf/${pair##*:}" "$src"
      say "symlink: $src -> $BASE/waf/${pair##*:}"
    fi
  done
  return 0
}

pasang_waf() {
  # Pasang engine WAF sesuai webserver yang TERPASANG di mesin ini.
  # nginx + lua -> engine free_waf dari payload (idempoten, config
  #   yang sudah ada tidak ditimpa).
  # apache / openlitespeed -> engine Lua tidak berlaku di sana; yang
  #   dipakai jalur snippet ModSecurity (dikelola tab Config > WAF).
  #   Di sini hanya dilaporkan kesiapannya, tidak ada yang diubah.
  local skrip="$BIN/sentinel-waf.sh"
  [ -x "$skrip" ] || { err "$skrip tidak ada"; return 1; }
  local nginx_bin="/www/server/nginx/sbin/nginx"
  if [ -x "$nginx_bin" ]; then
    if "$nginx_bin" -V 2>&1 | grep -q 'lua_nginx_module'; then
      say "nginx + lua terdeteksi, memasang engine free_waf"
      bash "$skrip" freewaf-install || {
        err "pemasangan engine free_waf gagal (lihat pesan di atas)"
        return 1
      }
    else
      say "nginx ada tetapi TANPA lua_nginx_module."
      say "Engine free_waf dilewati. Bangun ulang nginx dengan modul lua,"
      say "lalu jalankan: bash $skrip freewaf-install"
    fi
  else
    say "nginx tidak terpasang, engine free_waf dilewati."
  fi
  local ada_apache=0 ada_ols=0
  [ -x /www/server/apache/bin/httpd ] && ada_apache=1
  [ -x /usr/local/lsws/bin/openlitespeed ] && ada_ols=1
  [ -x /usr/local/lsws/bin/litespeed ] && ada_ols=1
  [ "$ada_apache" -eq 1 ] && say "apache terdeteksi: pakai tab Config > WAF (jalur snippet)."
  [ "$ada_ols" -eq 1 ] && say "openlitespeed terdeteksi: pakai tab Config > WAF (jalur snippet)."
  return 0
}

pasang_antivirus() {
  # Pasang modul Antivirus (ClamAV) dan jadwalkan pemindaian berkala.
  # Idempoten: bila clamav sudah ada, langsung siapkan unit dan folder.
  # Bila belum ada, coba pasang lewat package manager OS. Bila gagal,
  # instalasi sentinel TETAP lanjut (antivirus nonaktif), tidak digagalkan.
  local kurang=""
  command -v clamscan >/dev/null 2>&1 || kurang="clamav"

  if [ -n "$kurang" ]; then
    say "clamav belum terpasang, mencoba memasang..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq 2>&1 | tail -1
      apt-get install -y clamav clamav-daemon clamav-freshclam >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y clamav clamd clamav-update >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
      yum install -y clamav clamd clamav-update >/dev/null 2>&1 || true
    fi
  fi

  if command -v clamscan >/dev/null 2>&1; then
    say "antivirus ClamAV siap"
  else
    say "ClamAV tidak tersedia di sistem ini; fitur Antivirus nonaktif"
  fi

  # Struktur direktori sentinel/av
  mkdir -p "$BASE/av/baseline" "$BASE/av/last" "$BASE/av/quarantine/files" "$BASE/av/quarantine/meta" 2>/dev/null
  chmod 750 "$BASE/av" "$BASE/av/quarantine" 2>/dev/null || true

  # Salin skrip dari payload
  local pay; pay="$(dirname "$0")/payload"
  if [ -f "$pay/sentinel-av.sh" ]; then
    cp -p "$pay/sentinel-av.sh" "$BIN/sentinel-av.sh"
    chmod 755 "$BIN/sentinel-av.sh"
  fi

  # Aktifkan timer pemindaian otomatis
  if command -v systemctl >/dev/null 2>&1; then
    if [ -f /etc/systemd/system/sentinel-av.timer ]; then
      systemctl enable --now sentinel-av.timer 2>/dev/null || true
      say "timer pemindaian antivirus aktif (03:30 harian)"
    fi
  fi
  return 0
}

pasang_defender_elit() {
  # Pasang modul Pembela Elit: Process Guard (EDR), Threat Intel, & FIM Persistensi.
  if command -v systemctl >/dev/null 2>&1; then
    if [ -f /etc/systemd/system/sentinel-proc.service ]; then
      systemctl enable --now sentinel-proc.service 2>/dev/null || true
      say "layanan sentinel-proc (Runtime EDR) aktif"
    fi
    if [ -f /etc/systemd/system/sentinel-intel.timer ]; then
      systemctl enable --now sentinel-intel.timer 2>/dev/null || true
      say "timer sentinel-intel (Spamhaus DROP) aktif"
    fi
  fi

  if command -v ipset >/dev/null 2>&1 && [ -x "$BIN/sentinel-intel.sh" ]; then
    local isi
    isi="$(ipset list sentinel_intel 2>/dev/null | grep -c '^[0-9]' || true)"
    if [ "${isi:-0}" -eq 0 ]; then
      say "mengunduh feed Threat Intel global..."
      bash "$BIN/sentinel-intel.sh" update >/dev/null 2>&1 || true
    fi
  fi

  if [ -x "$BIN/sentinel-av.sh" ] && [ ! -f "$BASE/av/baseline/sys-persistence.txt" ]; then
    bash "$BIN/sentinel-av.sh" baseline-sys >/dev/null 2>&1 || true
    say "baseline persistensi sistem direkam"
  fi
  return 0
}

pasang_unit_dari_payload() {
  # Salin unit systemd dari payload HANYA bila belum ada. Unit yang
  # sudah ada tidak pernah ditimpa (bisa berisi penyesuaian operator).
  local pay
  pay="$(dirname "$0")/payload/systemd"
  [ -d "$pay" ] || { say "payload systemd tidak ada, unit tidak dipasang"; return 0; }
  if ! command -v systemctl >/dev/null 2>&1; then
    say "systemctl tidak ada, unit tidak dipasang"
    return 0
  fi
  local f b
  for f in "$pay"/*.service "$pay"/*.timer; do
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    if [ -f "/etc/systemd/system/$b" ]; then
      say "unit $b sudah ada, tidak ditimpa"
    else
      cp -p "$f" "/etc/systemd/system/$b"
      say "unit $b dipasang dari payload"
    fi
  done
  systemctl daemon-reload 2>/dev/null
  return 0
}

pasang_layanan() {
  if ! command -v systemctl >/dev/null 2>&1; then
    say "systemctl tidak ada, layanan tidak dipasang"
    return 0
  fi
  for f in sentinel.service sentinel-fw.service sentinel-fw.timer; do
    src="/etc/systemd/system/$f"
    if [ ! -f "$src" ]; then
      say "unit $f tidak ditemukan di $src, dilewati"
      continue
    fi
  done
  systemctl daemon-reload 2>/dev/null
  systemctl enable sentinel.service sentinel-fw.service sentinel-fw.timer \
      >/dev/null 2>&1
  systemctl start sentinel-fw.service 2>/dev/null
  systemctl start sentinel-fw.timer 2>/dev/null
  systemctl restart sentinel.service 2>/dev/null
  say "layanan sentinel dijalankan"
}

cabut() {
  say "Mencabut hook free_waf (data dipertahankan)"
  bash "$BIN/sentinel-waf.sh" freewaf-remove 2>/dev/null
  say "Mencabut aturan kernel"
  bash "$BIN/sentinel-fw.sh" remove 2>/dev/null
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now sentinel-proc.service 2>/dev/null
    systemctl disable --now sentinel-intel.timer 2>/dev/null
    systemctl disable --now sentinel-intel.service 2>/dev/null
    systemctl disable --now sentinel-av.timer 2>/dev/null
    systemctl disable --now sentinel-av.service 2>/dev/null
    systemctl disable --now sentinel-fw.timer 2>/dev/null
    systemctl disable --now sentinel-notify.timer 2>/dev/null
    systemctl disable --now sentinel.service 2>/dev/null
    systemctl disable --now sentinel-fw.service 2>/dev/null
    say "layanan sentinel dihentikan"
  fi
  say "Berkas di $BASE dan unit systemd TIDAK dihapus, hanya dimatikan."
  say "Data karantina, statistik, dan daftar putih tetap tersimpan."
}

butuh_root
AKSI="${1:-pasang}"
case "$AKSI" in
  pasang|install|update|upgrade)
    # update = pasang ulang idempoten. Semua langkah aman dijalankan
    # berkali-kali: config yang ada tidak ditimpa, unit yang ada tidak
    # diganti, aturan kernel tidak digandakan.
    cek_depe \
      && pasang_daemon && pasang_unit_dari_payload && pasang_firewall \
      && pasang_layanan && pasang_notif && konsolidasi_waf && pasang_waf \
      && pasang_antivirus && pasang_defender_elit
    say "selesai. Status: systemctl status sentinel.service"
    ;;
  cabut|uninstall)
    cabut
    ;;
  *)
    echo "pakai: $0 {pasang|cabut}"; exit 1
    ;;
esac