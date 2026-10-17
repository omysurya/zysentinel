# ZySentinel — AI-Powered Security Plugin for aaPanel

[![Release](https://img.shields.io/github/v/release/omysurya/zysentinel?color=blue&logo=github)](https://github.com/omysurya/zysentinel/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-aaPanel%208.x-orange.svg)](https://www.aapanel.com)
[![Engine](https://img.shields.io/badge/waf-Lua%20%7C%20Coraza%20CRS-blueviolet.svg)](#)

---

### [English]
**ZySentinel** is an AI-powered aaPanel security plugin for developers, sysadmins, hosting providers, and businesses. Features WAF, intrusion detection, malware scanning, vulnerability assessment, log analysis, and automated threat response, overcoming locked features to strengthen server protection and centralize security monitoring.

### [Bahasa Indonesia]
**ZySentinel** adalah plugin keamanan aaPanel bertenaga AI untuk pengembang, administrator sistem, penyedia hosting, dan bisnis. Dilengkapi WAF, deteksi intrusi, pemindaian malware, penilaian kerentanan, analisis log, dan respons ancaman otomatis, mengatasi batasan fitur terkunci untuk memperkuat perlindungan server dan memusatkan pemantauan keamanan.

---

## Official Repository & Releases / Repositori & Rilis Resmi

- **GitHub Repository:** [https://github.com/omysurya/zysentinel](https://github.com/omysurya/zysentinel)
- **Latest Releases (ZIP Packages):** [https://github.com/omysurya/zysentinel/releases](https://github.com/omysurya/zysentinel/releases)
- **Issues & Feedback:** [https://github.com/omysurya/zysentinel/issues](https://github.com/omysurya/zysentinel/issues)

---

## Key Features / Fitur Utama

| Feature / Fitur | English Description | Deskripsi Bahasa Indonesia |
| :--- | :--- | :--- |
| **Intrusion Detection & Traffic Analysis** | High-performance C daemon (`guardd`) tails web server logs, calculating dynamic threat scores (scanners, brute-force, distinct 4xx enumeration, floods). | Daemon C berkecepatan tinggi (`guardd`) memantau access log dan menghitung skor ancaman secara real-time (pemindai celah, brute force, lonjakan trafik). |
| **Dual-Engine WAF** | Flexible web application firewall supporting **Free Nginx (Lua)** for lightweight native filtering and **Coraza + OWASP CRS** for enterprise compliance. | Mendukung dua engine WAF: **Free Nginx (Lua)** untuk efisiensi tinggi serta **Coraza + OWASP CRS** untuk perlindungan standar industri per vhost. |
| **Kernel Firewall & Port Control** | Direct integration with `iptables` and `ipset` with zero lock-out risk. Provides Inbound and Outbound port access control (CRUD) with pre-configured secure baselines. | Integrasi langsung dengan `iptables` dan `ipset`. Kontrol akses port Inbound & Outbound dengan aturan fail-safe agar admin tidak terkunci. |
| **EDR Process Guard** | Real-time process supervisor (`sentinel-proc.py`) terminating webshells, illegal reverse shells, and malicious tools (`SIGKILL` < 1s) with process whitelist management. | Pengawasan proses runtime real-time. Mematikan webshell dan reverse shell seketika (< 1 detik) dengan dukungan daftar putih (whitelist) perintah sah. |
| **Antivirus & Upload Protection** | ClamAV integration with realtime per-vhost upload quarantine, safe restore/delete actions, and SHA-256 file integrity baseline monitoring. | Integrasi ClamAV dengan karantina otomatis upload berbahaya per vhost, pemulihan aman, dan pemantauan integritas berkas (anti-tamper). |
| **Threat Intelligence & Egress Guard** | Automatically imports verified global attacker CIDRs (Spamhaus DROP) into kernel ipsets, and restricts unauthorized outbound connections from web worker accounts. | Sinkronisasi feed intelijen ancaman global (Spamhaus DROP) langsung ke kernel ipset, serta memblokir koneksi reverse shell keluar dari user `www`. |
| **Automated Response & Review Queue** | Configurable action escalation: Monitor, Rate Limit (RPS/RPM Throttle), Kernel Ban, or Human-in-the-loop Review Queue with webhook notifications. | Eskalasi tindakan otomatis: mode monitor, pembatasan laju (RPS/RPM), blokir kernel, atau antrean review operator disertai notifikasi webhook. |
| **Automated Lifecycle & Self-Heal** | Interactive lifecycle dialogs: Fresh install, automated GitHub updates, zero-downtime self-healing repairs, and clean uninstallation without residue. | Manajemen siklus hidup mandiri: instalasi bersih (*fresh*), pembaruan otomatis dari GitHub, perbaikan mandiri (*self-heal*), dan pencabutan bersih total. |

---

## Architecture / Arsitektur Sistem

```text
aaPanel Web UI / App Store
         │  panel API (/plugin?action=a&name=sentinel)
         ▼
sentinel_main.py  ── Controller: reads state, validates inputs, lifecycle manager
         │
         ├── guardd (C daemon)            Kernel-integrated log scoring, ban/throttle/review
         ├── guardctl (bash/python)       Daemon CLI control over Unix socket
         ├── sentinel-fw.sh (bash)        Kernel firewall: ipset rules, ports, geo, egress
         ├── sentinel-ports.py (python)   Inbound/Outbound port rule management
         ├── sentinel-waf.sh (bash)       Lua WAF & Coraza OWASP CRS management
         ├── sentinel-av.sh (bash)        ClamAV antivirus & SHA-256 integrity checker
         ├── sentinel-upload-scan.py (py) Realtime per-vhost upload scanner & quarantine
         ├── sentinel-proc.py (python)    Runtime EDR Process Guard (SIGKILL unauthorized shells)
         ├── sentinel-intel.sh (bash)     Threat Intelligence feed updater (Spamhaus DROP)
         └── sentinel-notify.sh (bash)    Queued webhook notification dispatcher
```

---

## Deployment & Installation Guide / Panduan Pemasangan

### Method 1: aaPanel App Store (Recommended GUI) / Metode App Store

#### English:
1. **Download Release:** Download `zysentinel-v1.6.1.zip` (or `sentinel.zip`) from [GitHub Releases](https://github.com/omysurya/zysentinel/releases/latest).
2. **Access aaPanel:** Log in to your aaPanel dashboard (`https://<YOUR-SERVER-IP>:<PANEL-PORT>/`).
3. **Open App Store:** Navigate to **App Store** on the left menu.
4. **Import Plugin:** Click **Import third-party plugin** (or **Import plugin**) located at the top-right corner.
5. **Upload & Install:** Select the downloaded zip file and confirm the upload.
6. **One-Click Setup:** aaPanel automatically extracts the plugin and executes `bash install.sh install`. Dependencies, C compilation, kernel rules, and systemd services are configured automatically.
7. **Launch Dashboard:** Click on **ZySentinel** in the App Store to open the centralized security monitoring dashboard.

#### Bahasa Indonesia:
1. **Unduh Paket Rilis:** Unduh berkas `zysentinel-v1.6.1.zip` (atau `sentinel.zip`) dari [GitHub Releases](https://github.com/omysurya/zysentinel/releases/latest).
2. **Buka aaPanel:** Masuk ke dasbor web aaPanel Anda (`https://<IP-SERVER>:<PORT-PANEL>/`).
3. **Buka App Store:** Klik menu **App Store** pada bilah navigasi sebelah kiri.
4. **Impor Plugin:** Klik tombol **Import third-party plugin** (atau **Import plugin**) di kanan atas.
5. **Unggah Berkas:** Pilih berkas zip yang telah diunduh dari komputer Anda dan konfirmasi unggah.
6. **Setup Otomatis:** aaPanel secara otomatis mengekstrak plugin dan menjalankan `bash install.sh install`. Seluruh dependensi, kompilasi daemon C, aturan kernel, dan unit systemd terpasang mandiri (*plug-and-play*).
7. **Buka Dasbor:** Klik nama atau ikon **ZySentinel** pada App Store untuk membuka antarmuka keamanan terpusat.

---

### Method 2: Command Line via Git Clone / Metode Terminal SSH

#### A. Install via Git Clone (Full Repo Build):
```bash
# 1. Pastikan direktori plugin panel tersedia / Ensure plugin directory exists
mkdir -p /www/server/panel/plugin

# 2. Clone repositori resmi / Clone official repository (branch v1.6.1)
git clone -b v1.6.1 https://github.com/omysurya/zysentinel.git /www/server/panel/plugin/sentinel

# 3. Jalankan skrip instalasi / Execute installation script
cd /www/server/panel/plugin/sentinel
bash install.sh install

# 4. Verifikasi status / Verify service status
systemctl status sentinel.service sentinel-proc.service sentinel-upload-scan.service
bash /www/server/sentinel/bin/sentinel-fw.sh status
```

#### B. Install via GitHub Release Archive (ZIP):
```bash
# 1. Unduh rilis zip resmi dari GitHub / Download official release zip from GitHub
curl -fsSL -o /tmp/sentinel.zip https://github.com/omysurya/zysentinel/releases/download/v1.6.1/zysentinel-v1.6.1.zip

# 2. Ekstrak ke folder plugin / Extract to plugin directory
mkdir -p /www/server/panel/plugin
unzip -q /tmp/sentinel.zip -d /www/server/panel/plugin/

# 3. Jalankan pemasangan / Execute installation
cd /www/server/panel/plugin/sentinel
bash install.sh install
```

---

## Lifecycle Management & Updates / Pemeliharaan & Pembaruan

### 1. Automatic Updates from GitHub / Pembaruan Otomatis dari GitHub
- **Via Web UI:** In the ZySentinel header, click the version badge `v1.6.1` or go to **Settings ➔ Maintenance**, click **Check GitHub Update**, and apply the update directly with one click.
- **Via Terminal (CLI):**
  ```bash
  cd /www/server/panel/plugin/sentinel
  git pull origin v1.6.1
  bash install.sh update
  ```
  *Idempotent Update: Updates binaries and scripts without overwriting custom operator configs (`guardd.conf`, `ports.json`, `proc_whitelist.json`, notification tokens, or audit logs).*

### 2. Self-Healing & Repair / Perbaikan Mandiri (Zero Downtime)
If any binary is missing or a service is halted unexpectedly:
- **Via Web UI:** Open **Maintenance** tab ➔ Click **Repair (Self-Heal)**.
- **Via Terminal (CLI):**
  ```bash
  cd /www/server/panel/plugin/sentinel
  bash install.sh repair
  ```

### 3. Clean Uninstallation / Pencabutan Bersih
To cleanly remove ZySentinel without residue:
- **Via Web UI:** Open **Maintenance** tab ➔ Click **Uninstall** ➔ Type `UNINSTALL` to confirm.
- **Via Terminal (CLI):**
  ```bash
  cd /www/server/panel/plugin/sentinel
  bash install.sh cabut --clean
  ```
  *Removes WAF hooks, revokes firewall chains/ipsets, stops systemd services, and cleans all `/www/server/sentinel` files without affecting existing production websites.*

---

## Feedback & Bug Reports / Laporan & Umpan Balik

You can submit feedback or bug reports directly from the ZySentinel UI:
- **Automated Credential Scrubbing:** All sensitive secrets (`password=...`, private keys, API tokens, Telegram bot tokens) are automatically filtered out before sending.
- **Subject Standard:** `Feedback | Bugsreport [Topic] [hostname]`
- **GitHub Issues:** [https://github.com/omysurya/zysentinel/issues](https://github.com/omysurya/zysentinel/issues)

---

## License / Lisensi

Distributed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for more information.
Designed for aaPanel sysadmins, developers, and hosting operators worldwide.
