# ZySentinel — AI-Powered Security Plugin for aaPanel

Build ZySentinel from the ground up into a comprehensive, AI-powered security
plugin for aaPanel, designed around real-world server administration
experience, practical security requirements, and the limitations of aaPanel's
restricted or locked security features. Develop the entire solution end to
end, from architecture and threat analysis to implementation, testing, and
production deployment, delivering a powerful, modular, and extensible security
platform that enhances server protection, threat detection, attack analysis,
automated incident response, and security monitoring beyond aaPanel's built-in
capabilities.

---

## Why ZySentinel exists

aaPanel ships useful security defaults, but several of the controls that matter
most in production are either locked behind paid tiers, hidden behind opaque
config, or tuned for a generic server rather than the one in front of you.
ZySentinel was written from the position of running real sites on a real
aaPanel box, where the questions were always the same:

- Which firewall is actually in effect on this OS right now?
- Who is attacking, from where, and how hard?
- What did the server do about it, and can I prove it later?
- Can I change a single limit without taking the whole site down?

Every feature here exists because a specific operational question had no good
answer out of the box.

## What it does

**Monitoring and attack analysis.** A C daemon (`guardd`) tails the access
logs, scores every source IP across several signals (scanner paths, brute
force, suspicious user agents, distinct-4xx enumeration, flood), and writes a
queryable timeline. A dashboard renders live statistics, request trends, and
per-vhost breakdowns. Attacker origin is resolved from a local GeoLite2
database — no request ever leaves the machine.

**Firewall control in one place.** A dedicated Firewall tab shows which
firewall backend the OS is really using (iptables-nft, iptables-legacy, ufw, or
firewalld), the active kernel rules, and a single CRUD table for every rule
ZySentinel manages: ban, allow, and country blocks. Rule changes are safe by
construction — ZySentinel only ever touches its own chain and its own IP sets,
never the system's other rules, so a mistake cannot lock you out of SSH or the
panel.

**Port Access Control (Inbound & Outbound).** Panel kontrol akses port dengan tab terpisah untuk Inbound (Trafik Masuk) dan Outbound (Trafik Keluar) dengan kemampuan CRUD (tambah, hapus, aktifkan/nonaktifkan, dan reset).
- **Standar Baseline Preinstall:**
  - *Outbound:* Mengizinkan seluruh koneksi keluar (`1-65535` ALLOW ALL) agar OS bebas mengambil paket pembaruan, sertifikat SSL, dan API publik.
  - *Inbound:* Hanya mengizinkan port publik penting: HTTP (`80`), HTTPS (`443`), port SSH terdeteksi (misal `2244`), dan port aaPanel terdeteksi (misal `15960`). Port liar lainnya diblokir di tingkat kernel (`SENTINEL_IN_PORTS`).
  - *Fail-Safe Rails:* Koneksi loopback (`lo`), koneksi berstatus `ESTABLISHED,RELATED`, serta subnet lokal/privat otomatis dilewati sehingga administrator tidak akan pernah terkunci.

**Structured Kernel Rules Flow.** Tampilan Rantai Kernel SENTINEL kini disajikan dalam tabel modern dan terstruktur (bukan lagi teks polos/plain text). Setiap baris memuat nomor urut, label tindakan (`DROP`, `RETURN`, `ACCEPT`), protokol & port, kriteria/match-set, serta penjelasan fungsi pertahanan siber yang mudah dipahami disertai baris perintah iptables asli yang dapat dilihat.

**Runtime EDR & Process Guard.** Memantau eksekusi proses web secara real-time (`sentinel-proc.py`). Menghentikan seketika (`SIGKILL` < 1 detik) bila akun web `www` memicu eksekusi shell liar (`bash`, `sh`), reverse shell (`nc`, `socat`), compiler, atau proses download berbahaya. Kini dilengkapi **Tindakan Whitelist (Pengecualian)**: operator dapat mengecualikan perintah pemeliharaan atau auto-deploy sah (misalnya `git pull`, `artisan`, `composer`, atau skrip khusus) langsung dari tabel insiden EDR via tombol `+ Whitelist` atau melalui manajer whitelist mandiri (`proc_whitelist.json`), sehingga proses sah diberi tindakan `WHITELISTED` tanpa dihentikan paksa.

**Threat Intelligence & Egress Guard.** Mengimpor ribuan CIDR penyerang global terverifikasi (Spamhaus DROP) langsung ke kernel ipset (`sentinel-intel.sh`), serta membatasi lalu lintas keluar (`SENTINEL_OUT`) akun `www` hanya ke port web aman untuk memblokir komunikasi Command and Control (C2) dan reverse shell.

**Antivirus and file integrity (anti-tamper).** An Antivirus tab integrates
with ClamAV as a production replacement for the retired Imunify360 stack. It
provides on-demand malware scanning per active vhost, background scheduled scans
via a systemd timer, an isolated quarantine store with safe restore and permanent
delete actions, and a SHA-256 integrity baseline checker to detect web file
tampering (webshells, backdoor additions, modifications, or code deletion).

**Web application firewall, two engines.** A WAF tab exposes a
`Monitor | Block | Disable` control and two engines side by side:

- **LUA (Free Nginx)** — a lightweight Lua WAF that runs inside nginx and
  inspects common attack patterns and per-IP request rates. Runs today on any
  nginx built with the Lua module.
- **Coraza + OWASP CRS** — the full OWASP Core Rule Set on the Coraza engine.
  Assets (rules and the nginx connector source) are fetched from official
  upstream repositories on demand, verified, and staged. The engine is a
  deliberate switch: nothing is compiled or swapped into a production binary
  without an operator decision.

**Automated response, with a human in the loop.** Suspicious IPs can be routed
to a review queue instead of being blocked outright. The operator approves or
dismisses each one, and every action — automatic or manual — is written to an
audit trail with a reason. Notifications (webhook) are queued and delivered by
a separate timer so a slow endpoint can never stall log reading.

**Safety rails.** Dangerous moves require an explicit confirmation typed on
the server side, not just a checkbox. Country blocking defaults to off and
never touches SSH or the panel ports. Every change to a config file is backed
up first and verified after. The whole thing is idempotent: reinstalling never
overwrites operator state.

## Architecture

```
aaPanel plugin (Python + HTML fragment)
        │  panel API  (/plugin?action=a&name=sentinel)
        ▼
sentinel_main.py  ── controller: reads state, validates input, relays to tools
        │
        ├── guardd (C daemon)          log tailing, scoring, ban/throttle/review
        ├── guardctl (bash)            daemon control over a unix socket
        ├── sentinel-fw.sh (bash)      kernel rules: ban, throttle, geo, panic
        ├── sentinel-waf.sh (bash)     WAF engine + rule + vhost management
        ├── sentinel-av.sh (bash)      Antivirus (ClamAV) + integrity check + quarantine
        ├── sentinel-proc.py (python)  Runtime EDR Process Guard (SIGKILL www illegal shell)
        ├── sentinel-intel.sh (bash)   Threat Intelligence IPSet (Spamhaus DROP feed)
        └── sentinel-notify.sh (bash)  webhook delivery from a queue
                                         (driven by a systemd timer)
```

Design rules that apply everywhere:

- **One source of truth.** Scores and block decisions live in the daemon and
  the kernel; the plugin displays what is true rather than what was requested.
- **Displayed ≠ done.** Every action reports what actually happened — the
  duration the kernel really used, the number of CIDR blocks really loaded —
  not just "command sent".
- **Fail loudly, never silently.** A rejected nginx reload, a missing Lua
  module, or an unreadable config surface as clear errors instead of a screen
  that looks fine while nothing works.
- **Backups beside the original.** Config edits leave a `.bak.<timestamp>`
  next to the file, and destructive kernel operations are confirm-gated.

## Assets and layout

All assets and state live under the plugin's own tree so nothing is scattered across
the system:

```
/www/server/sentinel/
  bin/        guardd, guardctl, sentinel-fw.sh, sentinel-waf.sh, sentinel-av.sh, sentinel-proc.py, sentinel-intel.sh, sentinel-notify.sh
  etc/        guardd.conf, waf.conf, allowlist.txt, notify.conf
  data/       guardd.db (statistics, events, audit, review, geo cache)
  run/        status.json, pid, socket, panic flag
  av/         quarantine/, baseline/, last/         ← Antivirus and integrity
  waf/        modsec/, crs/, free_waf/, coraza/     ← engines and rules
```

Legacy paths (`/www/server/modsec`, `/www/server/modsecurity-crs`,
`/www/server/free_waf`) are kept as symlinks into `sentinel/waf/`, so existing
vhost configuration keeps working untouched.

## Requirements

- aaPanel 8.x on a systemd host
- nginx with `lua_nginx_module` for the LUA WAF engine
- `gcc`, `sqlite3` dev headers, `ipset`, `iptables` for the kernel layer
- `clamav` and `clamav-daemon` for the Antivirus and integrity layer
- `curl` and network access for on-demand Coraza/CRS asset downloads
- Go toolchain is **not** required; ZySentinel never builds a production
  binary behind your back

## Deployment & Installation Guide (Panduan Upload, Install & Uninstall)

ZySentinel dikemas sebagai arsip mandiri `sentinel.zip` yang siap dipasang di server aaPanel baru. Paket ini dapat diunggah, dipasang, dan dicabut baik melalui GUI aaPanel maupun baris perintah terminal (SSH).

---

### 1. Metode aaPanel GUI (Antarmuka Web)

#### A. Cara Upload & Install via aaPanel:
1. **Buka Panel:** Masuk ke dasbor web aaPanel Anda (`https://<IP-SERVER>:<PORT-PANEL>/`).
2. **Buka App Store:** Klik menu **App Store** pada bilah navigasi sebelah kiri.
3. **Impor Plugin Pihak Ketiga:** Klik tombol **Import third-party plugin** (atau **Import plugin**) yang terletak di bagian kanan atas daftar plugin.
4. **Unggah Arsip:** Pilih berkas `sentinel.zip` dari komputer Anda, lalu klik tombol konfirmasi unggah/impor.
5. **Eksekusi Pemasangan:** Setelah paket terunggah, panel akan mendaftarkan **ZySentinel** dalam daftar plugin. Klik tombol **Install** di sebelah kanan plugin.
   * aaPanel secara otomatis akan mengekstrak arsip ke `/www/server/panel/plugin/sentinel/` dan menjalankan `bash install.sh install`.
   * Skrip instalasi mendeteksi dependensi (`gcc`, `libsqlite3-dev`, `ipset`, `iptables`, `lua-cjson`), mengompilasi daemon C `guardd`, memasang aturan firewall, dan mengaktifkan service di latar belakang.
6. **Buka Dasbor:** Setelah status berubah menjadi *Installed* (terpasang), klik nama atau ikon **ZySentinel** untuk membuka dasbor pertahanan 4-tab.

#### B. Cara Uninstall via aaPanel:
1. Masuk ke **App Store** ➔ pilih tab **Installed** (Plugin Terpasang).
2. Cari kartu plugin **ZySentinel**.
3. Klik tombol **Uninstall** (ikon tempat sampah / tombol cabut).
4. aaPanel secara otomatis menjalankan perintah `bash install.sh uninstall`.
   * Hook modul WAF dicabut dari konfigurasi Nginx.
   * Rantai firewall `SENTINEL` dan `SENTINEL_OUT` dibersihkan dari iptables.
   * Seluruh service dan timer systemd dimatikan dan dinonaktifkan.
   * *Catatan:* Data statistik, log karantina, dan daftar putih tetap tersimpan aman di direktori `/www/server/sentinel/data` agar tidak hilang jika Anda ingin memasang ulang di kemudian hari.

---

### 2. Metode Terminal SSH (Command Line Interface)

#### A. Cara Upload Berkas `sentinel.zip` via SSH:
* **Menggunakan SCP (dari komputer lokal / server lama):**
  ```bash
  scp /path/ke/sentinel.zip root@<IP_SERVER_BARU>:/tmp/
  ```
* **Menggunakan Rsync (dari komputer lokal / server lama):**
  ```bash
  rsync -avP /path/ke/sentinel.zip root@<IP_SERVER_BARU>:/tmp/
  ```
* **Atau unduh langsung di server baru jika di-host di storage/web:**
  ```bash
  curl -fsSL -o /tmp/sentinel.zip "https://domain-anda.com/sentinel.zip"
  ```

#### B. Cara Install via SSH:
Jalankan langkah berikut di server baru sebagai pengguna `root`:

```bash
# 1. Pastikan direktori plugin panel ada
mkdir -p /www/server/panel/plugin

# 2. Ekstrak arsip zip ke direktori plugin
unzip -q /tmp/sentinel.zip -d /www/server/panel/plugin/

# 3. Masuk ke direktori plugin dan jalankan instalasi
cd /www/server/panel/plugin/sentinel
bash install.sh install

# 4. Verifikasi status layanan dan timer pertahanan
systemctl status sentinel.service sentinel-proc.service sentinel-fw.timer sentinel-intel.timer
```

#### C. Cara Update / Upgrade via SSH:
Bila ada pembaruan kode atau aturan baru, unggah zip versi terbaru dan jalankan:
```bash
cd /www/server/panel/plugin/sentinel
bash install.sh update
```
*Aksi `update` bersifat idempoten: memperbarui biner dan skrip tanpa pernah menimpa konfigurasi operator (`guardd.conf`, `notify.conf`, `allowlist.txt`), data karantina, atau riwayat review/audit.*

#### D. Cara Uninstall via SSH:
Untuk mencabut seluruh aturan keamanan dan mematikan layanan secara bersih:

```bash
cd /www/server/panel/plugin/sentinel
bash install.sh uninstall
```

Jika Anda ingin menghapus seluruh sisa direktori data dan modul secara permanen dari server:
```bash
rm -rf /www/server/panel/plugin/sentinel
rm -rf /www/server/sentinel
```

## Operating it

- **Dashboard** — live traffic, trends, per-vhost analysis, event feed with
  inline Allow/Block actions, review queue, audit trail.
- **Antivirus** — per-vhost on-demand scanning, automated daily scans, safe
  quarantine management (restore/delete/purge), and anti-tamper web file integrity monitoring.
- **Firewall** — backend detection, active kernel rules, managed-rule CRUD.
- **WAF** — engine choice, `Monitor | Block | Disable` switch, OWASP rules,
  protected vhosts, and asset download.
- **Setting** — score thresholds, rate limits, and the panic switch that
  cuts all web access while keeping SSH and the panel reachable.

## Status

Running in production. The kernel firewall layer, the monitoring daemon, the
review queue, notifications, geo blocking, and the LUA WAF engine are live and
tested. The Coraza engine is staged: its assets are downloaded and verified,
and it activates once a Coraza nginx connector is present — building that
connector is deliberately left as an explicit, operator-confirmed step.

## License

Provided as-is for aaPanel administrators. Review before deploying to
production and adapt the thresholds to your own traffic.
