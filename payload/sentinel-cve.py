#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
# ==============================================================================
# sentinel-cve.py -- CVE Advisor: inventaris komponen server, pencocokan dengan basis data kerentanan, skor postur, dan
# rekomendasi tiga tingkat (virtual patch WAF, hardening konfigurasi, panduan update resmi).
#
# Sumber data (audit 24 Okt 2026):
#   - feed bertanda tangan server (fitur cve_feed), diverifikasi ULANG setiap dibaca oleh sentinel_license.cve_feed_entries()
#     (hash isi + tanda tangan Ed25519 lewat sentinel-license verify-module); berkas yang diubah setelah disimpan ditolak;
#   - selain itu data bawaan kecil di bawah (tanpa isi aturan WAF);
#   - dependensi aplikasi di docroot (composer.lock, package-lock.json, yarn.lock, requirements.txt, poetry.lock, go.mod, Gemfile.lock,
#     Cargo.lock, ...) dinilai realtime terhadap database OSV lewat API resminya (api.osv.dev /v1/querybatch + /v1/vulns, sumber data
#     yang sama dengan osv-scanner) dengan Python stdlib saja: tanpa biner tambahan, zip tetap kecil. Rincian advisori di-cache per id dan
#     diambil ulang hanya bila 'modified' berubah. Gagal atau API tidak terjangkau: hasil OSV terakhir dipakai bila belum kedaluwarsa,
#     sisanya tetap dari feed. Bisa dimatikan (etc/cve.conf).
# Virtual patch hanya dari feed sah, hanya dengan fitur cve_vpatch, dan isinya wajib lolos sentinel_modpolicy (rentang id
# 8200000-8299999). Berkas ditulis ke waf/zyrules/vpatch/; sentinel-zyrules.py meng-include-nya, controller panel menyusun
# ulang + menguji ruleset + reload terverifikasi (dan mengembalikan perubahan bila gagal).
# Paket yang dikelola distro (dpkg/rpm, php sistem) TIDAK dinilai dari nomor versi upstream: distro menambal (backport) tanpa
# menaikkan versi upstream, sehingga perbandingan versi menghasilkan false positive. Entri feed boleh menandai
# "distro_aware": true bila rentangnya memakai penomoran paket distro.
# ==============================================================================
import glob
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

BASE_DIR = os.environ.get("SENTINEL_BASE", "/www/server/sentinel")
DATA_DIR = os.path.join(BASE_DIR, "data")
ZY_DIR = os.path.join(BASE_DIR, "waf", "zyrules")
VPATCH_DIR = os.path.join(ZY_DIR, "vpatch")
REPORT_FILE = os.path.join(DATA_DIR, "cve_report.json")
OSV_CACHE = os.path.join(DATA_DIR, "osv_cache.json")                 # rincian advisori OSV per id (+ modified)
OSV_LAST = os.path.join(DATA_DIR, "osv_last.json")                   # hasil OSV sukses terakhir (cadangan saat API tidak terjangkau)
CVE_CONF = os.path.join(BASE_DIR, "etc", "cve.conf")                 # {"osv": true|false}
OSV_TIMEOUT = 120                                                    # batas total pencarian lockfile + permintaan API
OSV_HTTP_TIMEOUT = 25
OSV_BASI = 7 * 86400                                                 # hasil cadangan lebih tua dari ini tidak dipakai
OSV_MAKS_AKAR = 300
OSV_MAKS_DALAM = 6                                                   # kedalaman folder di bawah docroot
OSV_MAKS_ENTRI = 400000                                              # entri direktori yang ditelusuri per pemindaian
OSV_MAKS_LOCKFILE = 2000
OSV_MAKS_BERKAS = 8 << 20                                            # ukuran satu lockfile (json.loads ~10x ukuran di memori)
OSV_MAKS_PAKET = 20000                                               # paket per lockfile
OSV_MAKS_JAWABAN = 32 << 20
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
WP_ROOTS = ("/www/wwwroot", "/var/www", "/home")       # cadangan bila adapter panel tidak tersedia
MAKS_PLUGIN = 400
MAKS_BACA = 8192

_AKU = os.path.dirname(os.path.abspath(__file__))
for _d in (_AKU, os.path.join(BASE_DIR, "bin")):
    if os.path.isdir(_d) and _d not in sys.path:
        sys.path.insert(0, _d)


def _modul(nama):
    try:
        return __import__(nama)
    except Exception:
        return None


# ---------------------------------------------------------------------- #
# Data bawaan: hanya entri yang terverifikasi dari advisori resmi vendor. #
# Tanpa isi aturan WAF (virtual patch hanya datang dari feed bertanda    #
# tangan). Pembaruan data = feed server, bukan mengubah daftar ini.      #
# ---------------------------------------------------------------------- #
BUILTIN_CVE_DB = [
    {
        "cve_id": "CVE-2024-27956",
        "title": "WordPress Automatic plugin: SQL injection tanpa autentikasi",
        "title_en": "WordPress Automatic plugin: unauthenticated SQL injection",
        "component": "wp_plugin_wp-automatic",
        "affected_ranges": [{"min": "0", "max": "3.92.0"}],
        "cvss": 9.9,
        "severity": "CRITICAL",
        "exploit_status": "IN_THE_WILD",
        "remediations": {
            "tier2_hardening": "Nonaktifkan plugin wp-automatic bila tidak dipakai sampai diperbarui",
            "tier2_hardening_en": "Deactivate the wp-automatic plugin if unused until it is updated",
            "tier3_upgrade": "wp plugin update wp-automatic (versi aman: 3.92.1 atau lebih baru)",
            "tier3_upgrade_en": "wp plugin update wp-automatic (safe version: 3.92.1 or later)",
        },
    },
    {
        "cve_id": "CVE-2024-28000",
        "title": "LiteSpeed Cache plugin: eskalasi hak akses tanpa autentikasi",
        "title_en": "LiteSpeed Cache plugin: unauthenticated privilege escalation",
        "component": "wp_plugin_litespeed-cache",
        "affected_ranges": [{"min": "1.9", "max": "6.3.0.1"}],
        "cvss": 9.8,
        "severity": "CRITICAL",
        "exploit_status": "IN_THE_WILD",
        "remediations": {
            "tier2_hardening": "Nonaktifkan fitur crawler LiteSpeed Cache sampai diperbarui",
            "tier2_hardening_en": "Disable the LiteSpeed Cache crawler until it is updated",
            "tier3_upgrade": "wp plugin update litespeed-cache (versi aman: 6.4 atau lebih baru)",
            "tier3_upgrade_en": "wp plugin update litespeed-cache (safe version: 6.4 or later)",
        },
    },
]


# ---------------------------------------------------------------------- #
# Versi                                                                   #
# ---------------------------------------------------------------------- #
def _versi(v):
    parts = [int(x) for x in re.findall(r"\d+", str(v))[:8]]
    return tuple(parts) if parts else (0,)


def versi_dalam(ver, v_min, v_max):
    a, lo, hi = _versi(ver), _versi(v_min), _versi(v_max)
    n = max(len(a), len(lo), len(hi))
    pad = lambda t: t + (0,) * (n - len(t))
    return pad(lo) <= pad(a) <= pad(hi)


# ---------------------------------------------------------------------- #
# Pembacaan berkas di docroot (milik user web) secara aman              #
# ---------------------------------------------------------------------- #
def baca_aman(path, maks=MAKS_BACA):
    """Isi awal berkas BIASA tanpa mengikuti symlink dan tanpa menggantung di FIFO/perangkat. Pemindai berjalan sebagai root
    di direktori yang bisa ditulis user web: symlink ke berkas sistem atau FIFO bernama plugin.php tidak boleh diikuti."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return ""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ""
        return os.read(fd, maks).decode("utf-8", "ignore")
    except OSError:
        return ""
    finally:
        os.close(fd)


def _dir_asli(path):
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _jalankan(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""


def _hak_biner(path):
    """(uid, gid) untuk menjalankan biner temuan, atau None bila tidak aman. Pemindai berjalan sebagai root: biner yang
    bisa ditulis akun lain (mis. redis-server milik redis:redis 0700) tidak boleh dijalankan sebagai root. Biner milik
    akun non-root dijalankan sebagai pemiliknya; biner root wajib tidak bisa ditulis grup/lain, begitu pula semua
    direktori induknya (kecuali sticky, mis. /tmp)."""
    try:
        asli = os.path.realpath(path)
        st = os.stat(asli)
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
        return None
    if st.st_uid != 0:
        return st.st_uid, st.st_gid
    if st.st_mode & 0o022:
        return None
    d = os.path.dirname(asli)
    while True:
        try:
            sd = os.stat(d)
        except OSError:
            return None
        if sd.st_uid != 0 or (sd.st_mode & 0o022 and not sd.st_mode & stat.S_ISVTX):
            return None
        if d == "/":
            return 0, 0
        d = os.path.dirname(d)


def _jalankan_biner(path, args, timeout=5):
    hak = _hak_biner(path)
    if hak is None:
        return ""
    turun = None
    if hak[0] != os.geteuid():
        if os.geteuid() != 0:
            return ""
        uid, gid = hak

        def turun():
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
    try:
        p = subprocess.run([os.path.realpath(path)] + list(args), capture_output=True, text=True, timeout=timeout,
                           cwd="/", preexec_fn=turun)
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""


# ---------------------------------------------------------------------- #
# Inventaris Komponen Server                                              #
# ---------------------------------------------------------------------- #
def scan_environment():
    """Deteksi control panel host: aaPanel, cPanel/WHM, DirectAdmin, CyberPanel, atau Standalone."""
    items = []
    ad = _modul("adapters")
    panel_name = "Standalone"
    panel_ver = ""
    panel_path = "system"
    try:
        if ad and hasattr(ad, "get_panel_adapter"):
            pa = ad.get_panel_adapter()
            pinfo = pa.get_panel_info()
            panel_name = pinfo.name or "Standalone"
            panel_ver = pinfo.version or ""
            panel_path = pinfo.config_dir or ""
    except Exception:
        pass

    if panel_name.lower() in ("standalone", ""):
        if os.path.exists("/www/server/panel/class/common.py") or os.path.exists("/www/server/panel/BT-Panel"):
            panel_name = "aaPanel"
            panel_path = "/www/server/panel"
            v_file = "/www/server/panel/class/common.py"
            if os.path.isfile(v_file):
                m = re.search(r"g\.version\s*=\s*['\"]([0-9.]+)['\"]", baca_aman(v_file, 4096))
                if m:
                    panel_ver = m.group(1)
        elif os.path.exists("/usr/local/cpanel"):
            panel_name = "cPanel"
            panel_path = "/usr/local/cpanel"
            ver_file = "/usr/local/cpanel/version"
            if os.path.isfile(ver_file):
                panel_ver = baca_aman(ver_file, 128).strip()
        elif os.path.exists("/usr/local/directadmin"):
            panel_name = "DirectAdmin"
            panel_path = "/usr/local/directadmin"
            out = _jalankan_biner("/usr/local/directadmin/directadmin", ["v"], 3)
            m = re.search(r"DirectAdmin\s+v?([0-9.]+)", out, re.I)
            if m:
                panel_ver = m.group(1)
        elif os.path.exists("/usr/local/CyberCP"):
            panel_name = "CyberPanel"
            panel_path = "/usr/local/CyberCP"
            ver_file = "/usr/local/CyberCP/version.txt"
            if os.path.isfile(ver_file):
                panel_ver = baca_aman(ver_file, 128).strip()

    items.append({
        "category": "panel",
        "component": "panel_" + panel_name.lower().replace(" ", "_"),
        "display_name": panel_name,
        "version": panel_ver or "active",
        "path": panel_path or "system",
        "managed_by": "panel",
    })
    return items


def scan_webserver():
    items = []
    seen = set()

    # Nginx
    nginx_cands = [
        ("/www/server/nginx/sbin/nginx", "upstream"),
        ("/usr/sbin/nginx", "distro"),
        ("/usr/bin/nginx", "distro"),
        ("/usr/local/nginx/sbin/nginx", "upstream"),
    ]
    sys_ng = shutil.which("nginx")
    if sys_ng and sys_ng not in [c[0] for c in nginx_cands]:
        nginx_cands.append((sys_ng, "distro"))
    for cand, kelola in nginx_cands:
        if os.access(cand, os.X_OK):
            m = re.search(r"nginx/([0-9.]+)", _jalankan_biner(cand, ["-v"], 3))
            if m and ("nginx", m.group(1)) not in seen:
                seen.add(("nginx", m.group(1)))
                items.append({"category": "webserver", "component": "nginx", "version": m.group(1), "path": cand, "managed_by": kelola})
                break

    # Apache HTTPD
    apache_cands = [
        ("/www/server/apache/bin/httpd", "upstream"),
        ("/usr/sbin/apache2", "distro"),
        ("/usr/sbin/httpd", "distro"),
        ("/usr/local/apache2/bin/httpd", "upstream"),
    ]
    sys_ap = shutil.which("httpd") or shutil.which("apache2")
    if sys_ap and sys_ap not in [c[0] for c in apache_cands]:
        apache_cands.append((sys_ap, "distro"))
    for cand, kelola in apache_cands:
        if os.access(cand, os.X_OK):
            m = re.search(r"Apache/([0-9.]+)", _jalankan_biner(cand, ["-v"], 3))
            if m and ("apache", m.group(1)) not in seen:
                seen.add(("apache", m.group(1)))
                items.append({"category": "webserver", "component": "apache", "version": m.group(1), "path": cand, "managed_by": kelola})
                break

    # Caddy
    caddy_cands = [
        ("/usr/bin/caddy", "distro"),
        ("/usr/local/bin/caddy", "upstream"),
    ]
    sys_cd = shutil.which("caddy")
    if sys_cd and sys_cd not in [c[0] for c in caddy_cands]:
        caddy_cands.append((sys_cd, "distro"))
    for cand, kelola in caddy_cands:
        if os.access(cand, os.X_OK):
            m = re.search(r"v?([0-9.]+)", _jalankan_biner(cand, ["version"], 3))
            if m and ("caddy", m.group(1)) not in seen:
                seen.add(("caddy", m.group(1)))
                items.append({"category": "webserver", "component": "caddy", "version": m.group(1), "path": cand, "managed_by": kelola})
                break

    # LiteSpeed / OpenLiteSpeed
    ols_cands = [
        ("/usr/local/lsws/bin/openlitespeed", "openlitespeed", "upstream"),
        ("/usr/local/lsws/bin/lshttpd", "litespeed", "upstream"),
    ]
    for cand, comp, kelola in ols_cands:
        if os.access(cand, os.X_OK):
            out = _jalankan_biner(cand, ["-v"], 3)
            m = re.search(r"(?:OpenLiteSpeed|LiteSpeed)(?:/|\s+v?)([0-9.]+)", out, re.I)
            if m and (comp, m.group(1)) not in seen:
                seen.add((comp, m.group(1)))
                items.append({"category": "webserver", "component": comp, "version": m.group(1), "path": cand, "managed_by": kelola})
                break

    return items


def scan_php():
    items, seen = [], set()
    calon = []
    # aaPanel
    if os.path.isdir("/www/server/php"):
        calon += [(os.path.join("/www/server/php", e, "bin", "php"), "upstream") for e in sorted(os.listdir("/www/server/php"))]
    # cPanel EA
    for d in sorted(glob.glob("/opt/cpanel/ea-php*/root/usr/bin/php")):
        calon.append((d, "upstream"))
    # DirectAdmin
    for d in sorted(glob.glob("/usr/local/php*/bin/php")):
        calon.append((d, "upstream"))
    # CyberPanel / LSPHP
    for d in sorted(glob.glob("/usr/local/lsws/lsphp*/bin/php")):
        calon.append((d, "upstream"))
    # System php
    sys_php = shutil.which("php")
    if sys_php:
        calon.append((sys_php, "distro"))
    for b, kelola in calon:
        if not os.access(b, os.X_OK):
            continue
        v = _jalankan_biner(b, ["-n", "-r", "echo PHP_VERSION;"], 3).strip()
        if re.fullmatch(r"\d+\.\d+\.\d+[0-9A-Za-z.+~-]*", v) and (v, kelola) not in seen:
            seen.add((v, kelola))
            items.append({"category": "runtime", "component": "php", "version": v, "path": b, "managed_by": kelola})
    return items


def scan_runtimes():
    items, seen = [], set()

    # Python
    py_cands = [
        ("/www/server/panel/pyenv/bin/python3", "panel"),
        ("/usr/bin/python3", "distro"),
        ("/usr/local/bin/python3", "upstream"),
        ("/usr/bin/python", "distro"),
    ]
    sys_py = shutil.which("python3")
    if sys_py and sys_py not in [c[0] for c in py_cands]:
        py_cands.append((sys_py, "distro"))
    for cand, kelola in py_cands:
        if os.access(cand, os.X_OK):
            out = _jalankan_biner(cand, ["-V"], 3)
            m = re.search(r"Python\s+([0-9.]+)", out)
            if m and ("python", m.group(1), kelola) not in seen:
                seen.add(("python", m.group(1), kelola))
                items.append({"category": "runtime", "component": "python", "version": m.group(1), "path": cand, "managed_by": kelola})

    # Node.js
    node_cands = []
    if os.path.isdir("/www/server/nodejs"):
        for vd in sorted(os.listdir("/www/server/nodejs")):
            nb = os.path.join("/www/server/nodejs", vd, "bin", "node")
            if os.access(nb, os.X_OK):
                node_cands.append((nb, "panel"))
    sys_node = shutil.which("node")
    if sys_node and sys_node not in [c[0] for c in node_cands]:
        node_cands.append((sys_node, "distro"))
    for cand, kelola in node_cands:
        if os.access(cand, os.X_OK):
            m = re.search(r"v?([0-9.]+)", _jalankan_biner(cand, ["-v"], 3).strip())
            if m and ("nodejs", m.group(1)) not in seen:
                seen.add(("nodejs", m.group(1)))
                items.append({"category": "runtime", "component": "nodejs", "version": m.group(1), "path": cand, "managed_by": kelola})

    # Go / Golang
    go_cands = [
        ("/usr/local/btgo/bin/go", "panel"),
        ("/usr/local/go/bin/go", "upstream"),
        ("/usr/bin/go", "distro"),
        ("/root/go/bin/go", "upstream"),
    ]
    sys_go = shutil.which("go")
    if sys_go and sys_go not in [c[0] for c in go_cands]:
        go_cands.append((sys_go, "distro"))
    for cand, kelola in go_cands:
        if os.access(cand, os.X_OK):
            m = re.search(r"go([0-9.]+)", _jalankan_biner(cand, ["version"], 3))
            if m and ("go", m.group(1)) not in seen:
                seen.add(("go", m.group(1)))
                items.append({"category": "runtime", "component": "go", "version": m.group(1), "path": cand, "managed_by": kelola})

    return items


def scan_databases():
    items, seen = [], set()

    # MySQL / MariaDB
    sql_cands = [
        ("/www/server/mysql/bin/mysql", "upstream"),
        ("/www/server/mysql/bin/mysqld", "upstream"),
        ("/usr/bin/mariadb", "distro"),
        ("/usr/bin/mysql", "distro"),
        ("/usr/sbin/mysqld", "distro"),
    ]
    sys_sql = shutil.which("mysql") or shutil.which("mariadb")
    if sys_sql and sys_sql not in [c[0] for c in sql_cands]:
        sql_cands.append((sys_sql, "distro"))
    for cand, kelola in sql_cands:
        if os.access(cand, os.X_OK):
            out = _jalankan_biner(cand, ["-V"], 3)
            m_m = re.search(r"(?:Distrib|from|Ver)\s+([0-9.]+)-MariaDB", out, re.I) or re.search(r"mariadb.*?([0-9.]+)", out, re.I)
            m_s = re.search(r"Ver\s+([0-9.]+)\s+for", out, re.I) or re.search(r"Distrib\s+([0-9.]+)", out, re.I)
            if m_m:
                v = m_m.group(1)
                if ("mariadb", v) not in seen:
                    seen.add(("mariadb", v))
                    items.append({"category": "database", "component": "mariadb", "version": v, "path": cand, "managed_by": kelola})
                    break
            elif m_s:
                v = m_s.group(1)
                if ("mysql", v) not in seen:
                    seen.add(("mysql", v))
                    items.append({"category": "database", "component": "mysql", "version": v, "path": cand, "managed_by": kelola})
                    break

    # Redis
    redis_cands = [
        ("/www/server/redis/src/redis-server", "upstream"),
        ("/www/server/redis/bin/redis-server", "upstream"),
        ("/usr/bin/redis-server", "distro"),
        ("/usr/local/bin/redis-server", "upstream"),
    ]
    sys_rd = shutil.which("redis-server")
    if sys_rd and sys_rd not in [c[0] for c in redis_cands]:
        redis_cands.append((sys_rd, "distro"))
    for cand, kelola in redis_cands:
        if os.access(cand, os.X_OK):
            m = re.search(r"v=([0-9.]+)", _jalankan_biner(cand, ["-v"], 3))
            if m and ("redis", m.group(1)) not in seen:
                seen.add(("redis", m.group(1)))
                items.append({"category": "database", "component": "redis", "version": m.group(1), "path": cand, "managed_by": kelola})
                break

    return items


def scan_os_and_kernel():
    items = []
    # Linux Kernel
    kv = _jalankan(["uname", "-r"], 3).strip()
    if kv:
        m = re.search(r"^([0-9.]+)", kv)
        ver = m.group(1) if m else kv
        items.append({
            "category": "os_kernel",
            "component": "linux_kernel",
            "version": ver,
            "raw_version": kv,
            "path": "/proc/version",
            "managed_by": "distro",
        })

    # OS Distro
    if os.path.isfile("/etc/os-release"):
        os_info = {}
        # /etc/os-release adalah symlink ke /usr/lib/os-release di Ubuntu/Debian; O_NOFOLLOW baca_aman menolak symlink
        # (dulu OS selalu tercatat "os_linux generic"). Berkas sistem milik root, aman diikuti ke tujuannya.
        for line in baca_aman(os.path.realpath("/etc/os-release"), 2048).splitlines():
            if "=" in line:
                k, val = line.split("=", 1)
                os_info[k.strip()] = val.strip().strip('"').strip("'")
        distro_id = os_info.get("ID", "linux").lower()
        distro_ver = os_info.get("VERSION_ID", "")
        distro_name = os_info.get("PRETTY_NAME", os_info.get("NAME", "Linux"))
        items.append({
            "category": "os_kernel",
            "component": "os_" + distro_id,
            "display_name": distro_name,
            "version": distro_ver or "generic",
            "path": "/etc/os-release",
            "managed_by": "distro",
        })

    return items


def scan_containers():
    items = []
    docker_cands = [
        ("/usr/bin/docker", "distro"),
        ("/usr/local/bin/docker", "upstream"),
    ]
    sys_doc = shutil.which("docker")
    if sys_doc and sys_doc not in [c[0] for c in docker_cands]:
        docker_cands.append((sys_doc, "distro"))
    for cand, kelola in docker_cands:
        if os.access(cand, os.X_OK):
            m = re.search(r"version\s+([0-9.]+)", _jalankan_biner(cand, ["-v"], 3), re.I)
            if m:
                items.append({
                    "category": "container",
                    "component": "docker",
                    "version": m.group(1),
                    "path": cand,
                    "managed_by": kelola,
                })
                break
    return items


def scan_os_packages():
    items = []
    for pkg in ("openssl", "openssh-server", "sudo", "curl", "systemd"):
        if shutil.which("dpkg-query"):
            v = _jalankan(["dpkg-query", "-W", "-f=${Version}", pkg], 3).strip()
            if v and "no packages" not in v.lower():
                items.append({"category": "os_package", "component": pkg, "version": v, "path": "dpkg:" + pkg, "managed_by": "distro"})
        elif shutil.which("rpm"):
            v = _jalankan(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg], 3).strip()
            if v and "not installed" not in v:
                items.append({"category": "os_package", "component": pkg, "version": v, "path": "rpm:" + pkg, "managed_by": "distro"})
    return items


def docroots():
    """Docroot dari adapter panel (aaPanel, cPanel, DirectAdmin, CyberPanel, standalone); cadangan: subdirektori WP_ROOTS."""
    akar = []
    ad = _modul("adapters")
    try:
        pa = ad.get_panel_adapter() if ad else None
        for vh in (pa.get_vhosts() if pa else []):
            d = getattr(vh, "docroot", "") or ""
            if d and os.path.isabs(d):
                akar.append(d)
    except Exception:
        akar = []
    if not akar:
        for base in WP_ROOTS:
            if _dir_asli(base):
                try:
                    akar += [os.path.join(base, s) for s in sorted(os.listdir(base))]
                except OSError:
                    pass
    out, seen = [], set()
    for d in akar:
        r = os.path.realpath(d)
        if r not in seen and _dir_asli(r):
            seen.add(r)
            out.append(r)
    return out


def scan_wordpress():
    items = []
    for site in docroots():
        m = re.search(r"\$wp_version\s*=\s*['\"]([0-9][0-9A-Za-z.-]{0,20})['\"]", baca_aman(os.path.join(site, "wp-includes", "version.php")))
        if m:
            items.append({"category": "cms_plugin", "component": "wordpress_core", "version": m.group(1), "path": site, "managed_by": "upstream"})
        plugins = os.path.join(site, "wp-content", "plugins")
        if not _dir_asli(plugins):
            continue
        try:
            daftar = sorted(os.listdir(plugins))[:MAKS_PLUGIN]
        except OSError:
            continue
        for plug in daftar:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", plug) or not _dir_asli(os.path.join(plugins, plug)):
                continue
            for fname in (plug + ".php", "readme.txt"):
                m = re.search(r"(?:^|\n)\s*\*?\s*(?:Version|Stable tag):\s*([0-9][0-9A-Za-z.-]{0,20})", baca_aman(os.path.join(plugins, plug, fname)), re.I)
                if m:
                    items.append({"category": "cms_plugin", "component": "wp_plugin_" + plug.lower(), "version": m.group(1), "path": os.path.join(plugins, plug), "managed_by": "upstream"})
                    break
    return items


# ---------------------------------------------------------------------- #
# Dependensi aplikasi: API database OSV realtime (api.osv.dev)          #
# ---------------------------------------------------------------------- #
# Perintah perbaikan per ekosistem OSV (Tier 3); {n} = nama paket, {v} = versi aman
OSV_PERINTAH = {
    "Packagist": "composer require {n}:^{v}", "npm": "npm install {n}@{v}", "PyPI": "pip install '{n}>={v}'",
    "Go": "go get {n}@v{v}", "RubyGems": "bundle update {n} (>= {v})", "crates.io": "cargo update -p {n} --precise {v}",
    "Maven": "mvn versions:use-dep-version -Dincludes={n} -DdepVersion={v}", "NuGet": "dotnet add package {n} --version {v}",
    "Pub": "dart pub upgrade {n}", "Hex": "mix deps.update {n}",
}


def osv_aktif():
    """Pemeriksaan OSV aktif kecuali dimatikan pengguna (etc/cve.conf {"osv": false})."""
    try:
        with open(CVE_CONF) as f:
            return json.load(f).get("osv", True) is not False
    except (OSError, ValueError, AttributeError):
        return True


def _osv_severity(skor, db_sev):
    try:
        x = float(skor)
    except (TypeError, ValueError):
        x = None
    if x is not None and x > 0:
        return ("CRITICAL" if x >= 9 else "HIGH" if x >= 7 else "MEDIUM" if x >= 4 else "LOW"), x
    s = str(db_sev or "").upper()
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(s, "MEDIUM"), 0.0


def _osv_versi_aman(vuln, eko, nama, ver=""):
    """Versi 'fixed' untuk rentang OSV yang MEMUAT versi terpasang (introduced <= ver < fixed); satu advisori bisa punya beberapa
    rentang (mis. 6.x diperbaiki di 6.5.8, 7.x di 7.4.5). Tanpa rentang yang cocok: fixed terkecil di atas versi terpasang; '' bila tidak ada."""
    sah = lambda v: bool(re.fullmatch(r"[0-9A-Za-z.+_~-]{1,40}", v))
    cocok, di_atas = [], []
    pv = _versi(ver) if ver else None
    for af in vuln.get("affected") or []:
        pk = af.get("package") or {}
        if pk.get("ecosystem") != eko or str(pk.get("name", "")).lower() != nama.lower():
            continue
        for rg in af.get("ranges") or []:
            mulai = None
            for ev in rg.get("events") or []:
                if "introduced" in ev:
                    mulai = str(ev.get("introduced") or "0")
                v = str(ev.get("fixed", "") or "")
                if not (v and sah(v)):
                    continue
                if pv is not None and mulai is not None and _versi(mulai) <= pv < _versi(v):
                    cocok.append(v)
                elif pv is None or _versi(v) > pv:
                    di_atas.append(v)
    pilih = cocok or di_atas
    return min(pilih, key=_versi) if pilih else ""


def osv_urai(js):
    """Keluaran berbentuk JSON osv-scanner (dibangun osv_periksa) -> (komponen, temuan) dalam bentuk laporan CVE Advisor. Satu temuan per kelompok alias (CVE/GHSA/PYSEC
    yang sama digabung osv-scanner lewat `groups`); id yang ditampilkan: alias CVE bila ada, selain itu id OSV pertama."""
    komponen, temuan = [], []
    for res in (js or {}).get("results") or []:
        sumber = str(((res.get("source") or {}).get("path")) or "")[:300]
        for p in res.get("packages") or []:
            pk = p.get("package") or {}
            eko, nama, ver = str(pk.get("ecosystem", ""))[:20], str(pk.get("name", ""))[:120], str(pk.get("version", ""))[:40]
            if not (eko and nama):
                continue
            komp = "%s:%s" % (eko.lower(), nama)
            komponen.append({"category": "dependency", "component": komp, "display_name": nama, "ecosystem": eko, "version": ver,
                             "path": sumber, "managed_by": "lockfile", "assessed": True})
            vulns = {v.get("id"): v for v in p.get("vulnerabilities") or [] if isinstance(v, dict) and v.get("id")}
            grup = p.get("groups") or [{"ids": [i], "aliases": [i], "max_severity": ""} for i in vulns]
            for g in grup:
                ids = [i for i in (g.get("ids") or []) if i in vulns]
                if not ids:
                    continue
                alias = [str(a) for a in (g.get("aliases") or []) + ids]
                cve = next((a for a in sorted(alias) if CVE_RE.match(a)), "")
                v = vulns[ids[0]]
                sev, cvss = _osv_severity(g.get("max_severity"), (v.get("database_specific") or {}).get("severity"))
                aman = _osv_versi_aman(v, eko, nama, ver)
                judul = str(v.get("summary") or v.get("details") or ids[0]).strip().splitlines()[0][:200]
                perintah = OSV_PERINTAH.get(eko, "")
                t3 = perintah.format(n=nama, v=aman) if (aman and perintah) else ""
                temuan.append({
                    "cve_id": cve or str(ids[0])[:40], "osv_ids": sorted(set(alias))[:8], "title": judul, "component": komp,
                    "detected_version": ver, "detected_path": sumber, "managed_by": "lockfile", "cvss": cvss, "severity": sev,
                    "exploit_status": "NONE", "source": "osv",
                    "remediations": {
                        "tier2_hardening": ("Perbarui dependensi %s di %s ke versi %s atau lebih baru, lalu deploy ulang aplikasi" % (nama, os.path.basename(sumber), aman))
                                           if aman else ("Belum ada versi perbaikan untuk %s; batasi pemakaian fitur yang terdampak (lihat %s)" % (nama, ids[0])),
                        "tier2_hardening_en": ("Update dependency %s in %s to version %s or later, then redeploy the application" % (nama, os.path.basename(sumber), aman))
                                              if aman else ("No fixed version for %s yet; restrict use of the affected feature (see %s)" % (nama, ids[0])),
                        "tier3_upgrade": t3 or ("lihat https://osv.dev/vulnerability/%s" % ids[0]),
                        "tier3_upgrade_en": t3 or ("see https://osv.dev/vulnerability/%s" % ids[0]),
                    },
                })
    return komponen, temuan


# --- lockfile: pencarian aman dan pengurai per ekosistem (tanpa pustaka luar) ---------------------------------------
_OSV_LEWATI_DIR = {"node_modules", "vendor", ".git", ".svn", ".hg", "bower_components", ".cache", "__pycache__", ".venv", "venv"}


def _osv_baca(path):
    """Isi lockfile (teks) atau None. Pemindai berjalan sebagai root atas berkas yang bisa ditulis akun web: tanpa mengikuti symlink,
    hanya berkas biasa, tanpa memblokir (FIFO), dan dibatasi ukurannya."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > OSV_MAKS_BERKAS:
            return None
        with os.fdopen(fd, "rb", closefd=False) as f:
            return f.read(OSV_MAKS_BERKAS + 1)[:OSV_MAKS_BERKAS].decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def _osv_paket(nama, ver):
    nama, ver = str(nama or "").strip(), str(ver or "").strip()
    if not nama or not ver or len(nama) > 214 or len(ver) > 64 or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_~!-]*", ver):
        return None
    return nama, ver


def _urai_composer(t):
    js = json.loads(t)
    return [(p.get("name"), p.get("version")) for k in ("packages", "packages-dev") for p in (js.get(k) or []) if isinstance(p, dict)]


def _urai_npm_lock(t):
    js, out = json.loads(t), []
    for k, p in (js.get("packages") or {}).items():          # lockfileVersion 2/3
        if k and isinstance(p, dict) and not p.get("link"):
            out.append((p.get("name") or k.rsplit("node_modules/", 1)[-1], p.get("version")))

    def jalan(deps, kedalaman=0):                             # lockfileVersion 1 (bersarang)
        for n, p in (deps or {}).items():
            if isinstance(p, dict) and kedalaman < 64:
                out.append((n, p.get("version")))
                jalan(p.get("dependencies"), kedalaman + 1)
    if not js.get("packages"):
        jalan(js.get("dependencies"))
    return out


def _urai_yarn(t):
    out, nama = [], None
    for ln in t.splitlines():
        if ln and not ln[0].isspace() and ln.rstrip().endswith(":") and not ln.startswith("#"):
            spec = ln.rstrip()[:-1].split(",")[0].strip().strip('"')
            spec = spec.split("@npm:")[0] if "@npm:" in spec else spec
            nama = spec.rsplit("@", 1)[0] if spec.count("@") >= (2 if spec.startswith("@") else 1) else spec
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', ln)
            if m and nama:
                out.append((nama, m.group(1)))
                nama = None
    return out


def _urai_pnpm(t):
    out = []
    for m in re.finditer(r"^\s{2}'?/?((?:@[^/@\s']+/)?[^/@\s'(]+)[@/]([0-9][^(:'\s]*)", t, re.M):
        out.append((m.group(1), m.group(2)))
    return out


def _urai_requirements(t):
    return [(m.group(1), m.group(2)) for m in re.finditer(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,]*)", t, re.M)]


def _urai_pipfile(t):
    js = json.loads(t)
    return [(n, str(p.get("version", "")).lstrip("=")) for k in ("default", "develop") for n, p in (js.get(k) or {}).items() if isinstance(p, dict)]


def _urai_toml_paket(t):
    """poetry.lock / Cargo.lock / uv.lock: blok [[package]] dengan name dan version."""
    out = []
    for blok in re.split(r"^\[\[package\]\]\s*$", t, flags=re.M)[1:]:
        n = re.search(r'^name\s*=\s*"([^"]+)"', blok, re.M)
        v = re.search(r'^version\s*=\s*"([^"]+)"', blok, re.M)
        if n and v:
            out.append((n.group(1), v.group(1)))
    return out


def _urai_gomod(t):
    out = []
    for m in re.finditer(r"^\s*(?:require\s+)?([a-zA-Z0-9][^\s]*\.[^\s]+)\s+v([0-9][^\s/]*)(?:\s*//.*)?$", t, re.M):
        if not m.group(1).startswith(("module", "go ", "replace", "exclude", "retract")):
            out.append((m.group(1), m.group(2).split("+incompatible")[0]))
    return out


def _urai_gemfile(t):
    out, di_specs = [], False
    for ln in t.splitlines():
        if ln.strip() == "specs:":
            di_specs = True
            continue
        if di_specs:
            m = re.match(r"^ {4}([A-Za-z0-9._-]+) \(([0-9][^)\s-]*)(?:-[^)]*)?\)\s*$", ln)
            if m:
                out.append((m.group(1), m.group(2)))
            elif ln and not ln.startswith(" "):
                di_specs = False
    return out


OSV_LOCKFILE = {
    "composer.lock": ("Packagist", _urai_composer), "package-lock.json": ("npm", _urai_npm_lock), "npm-shrinkwrap.json": ("npm", _urai_npm_lock),
    "yarn.lock": ("npm", _urai_yarn), "pnpm-lock.yaml": ("npm", _urai_pnpm), "requirements.txt": ("PyPI", _urai_requirements),
    "Pipfile.lock": ("PyPI", _urai_pipfile), "poetry.lock": ("PyPI", _urai_toml_paket), "uv.lock": ("PyPI", _urai_toml_paket),
    "go.mod": ("Go", _urai_gomod), "Gemfile.lock": ("RubyGems", _urai_gemfile), "Cargo.lock": ("crates.io", _urai_toml_paket),
}


def osv_cari_lockfile(akar, batas_waktu):
    """Lockfile di bawah docroot: kedalaman <= OSV_MAKS_DALAM, tanpa mengikuti symlink, tanpa folder dependensi terpasang
    (node_modules, vendor: sudah diwakili lockfile di atasnya), dibatasi jumlah entri dan waktu."""
    hasil, dilihat, tumpuk = [], 0, [(os.path.realpath(a), 0) for a in akar]
    seen = set()
    while tumpuk and len(hasil) < OSV_MAKS_LOCKFILE and dilihat < OSV_MAKS_ENTRI and time.time() < batas_waktu:
        d, dalam = tumpuk.pop()
        if d in seen:
            continue
        seen.add(d)
        try:
            with os.scandir(d) as it:
                for e in it:
                    dilihat += 1
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if dalam < OSV_MAKS_DALAM and e.name not in _OSV_LEWATI_DIR:
                                tumpuk.append((e.path, dalam + 1))
                        elif e.name in OSV_LOCKFILE and e.is_file(follow_symlinks=False):
                            hasil.append(e.path)
                    except OSError:
                        continue
        except OSError:
            continue
    return sorted(hasil)


def osv_inventaris(lockfiles):
    """{lockfile: [(ekosistem, nama, versi)]} dari lockfile yang bisa diurai (yang rusak dilewati)."""
    out = {}
    for lf in lockfiles:
        eko, urai = OSV_LOCKFILE[os.path.basename(lf)]
        t = _osv_baca(lf)
        if t is None:
            continue
        try:
            pk = urai(t)
        except Exception:
            continue
        uniq = sorted({(eko,) + x for x in (_osv_paket(n, v) for n, v in pk) if x})
        if uniq:
            out[lf] = uniq[:OSV_MAKS_PAKET]
    return out


# --- klien API OSV (https://google.github.io/osv.dev/api/) -----------------------------------------------------------
def _osv_url():
    u = os.environ.get("ZYS_OSV_API", "https://api.osv.dev").rstrip("/")
    return u if (u.startswith("https://") or u.startswith("http://127.0.0.1:")) else "https://api.osv.dev"


def _osv_http(jalur, data=None, batas_waktu=None):
    import urllib.request


def _urlopen(req, timeout=10):
    """sentinel_license.urlopen (IPv4 dulu, CA sistem sebagai cadangan) bila modulnya ada di folder ini; selain itu urllib biasa."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from sentinel_license import urlopen as _u
    except Exception:
        _u = urllib.request.urlopen
    return _u(req, timeout=timeout)
    sisa = (batas_waktu - time.time()) if batas_waktu else OSV_HTTP_TIMEOUT
    if sisa <= 0:
        raise TimeoutError("batas waktu pemeriksaan OSV habis")
    req = urllib.request.Request(_osv_url() + jalur, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", "User-Agent": "ZySentinel-CVE-Advisor"},
                                 method="POST" if data is not None else "GET")
    with _urlopen(req, timeout=min(OSV_HTTP_TIMEOUT, sisa)) as r:
        isi = r.read(OSV_MAKS_JAWABAN + 1)
    if len(isi) > OSV_MAKS_JAWABAN:
        raise ValueError("jawaban OSV terlalu besar")
    return json.loads(isi.decode("utf-8", "replace") or "{}")


def osv_query(paket, batas_waktu):
    """[(ekosistem, nama, versi)] -> {(e, n, v): [{id, modified}]} lewat /v1/querybatch (1000 per permintaan, dengan halaman lanjutan)."""
    hasil, daftar = {}, list(paket)
    for i in range(0, len(daftar), 1000):
        potong = daftar[i:i + 1000]
        js = _osv_http("/v1/querybatch", {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in potong]}, batas_waktu)
        for k, r in zip(potong, js.get("results") or []):
            vs = list((r or {}).get("vulns") or [])
            token, putaran = (r or {}).get("next_page_token"), 0
            while token and putaran < 10:
                lanjut = _osv_http("/v1/querybatch", {"queries": [{"package": {"ecosystem": k[0], "name": k[1]}, "version": k[2], "page_token": token}]}, batas_waktu)
                r2 = (lanjut.get("results") or [{}])[0] or {}
                vs += r2.get("vulns") or []
                token, putaran = r2.get("next_page_token"), putaran + 1
            if vs:
                hasil[k] = [x for x in vs if isinstance(x, dict) and re.fullmatch(r"[A-Za-z0-9._:-]{3,64}", str(x.get("id", "")))]
    return hasil


def osv_rincian(ids_modified, batas_waktu):
    """{id: vuln}. Rincian di-cache per id; diambil ulang hanya bila 'modified' di OSV berubah (tetap terbaru, hemat permintaan)."""
    try:
        with open(OSV_CACHE) as f:
            cache = json.load(f)
        cache = cache if isinstance(cache, dict) else {}
    except (OSError, ValueError):
        cache = {}
    perlu = [i for i, m in ids_modified.items() if not (isinstance(cache.get(i), dict) and cache[i].get("modified") == m and cache[i].get("v"))]
    gagal = []
    if perlu:
        from concurrent.futures import ThreadPoolExecutor
        def ambil(i):
            try:
                return i, _osv_http("/v1/vulns/" + i, None, batas_waktu)
            except Exception:
                return i, None
        with ThreadPoolExecutor(max_workers=6) as ex:
            for i, v in ex.map(ambil, perlu):
                if isinstance(v, dict) and v.get("id") == i:
                    cache[i] = {"modified": ids_modified[i], "v": v}
                else:
                    gagal.append(i)
    hasil = {i: cache[i]["v"] for i in ids_modified if isinstance(cache.get(i), dict) and cache[i].get("v")}
    try:
        simpan = {i: cache[i] for i in hasil}                  # hanya id yang masih relevan (cache tidak tumbuh tanpa batas)
        tmp = OSV_CACHE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(simpan, f, separators=(",", ":"))
        os.chmod(tmp, 0o600)
        os.replace(tmp, OSV_CACHE)
    except OSError:
        pass
    return hasil, gagal


_CVSS3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62},
          "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0}, "A": {"H": 0.56, "L": 0.22, "N": 0}}


def cvss3_skor(vektor):
    """Skor dasar CVSS v3.0/v3.1 dari vektor (spesifikasi FIRST); None bila bukan vektor v3 yang sah."""
    if not str(vektor).startswith("CVSS:3."):
        return None
    try:
        m = dict(x.split(":", 1) for x in str(vektor).split("/")[1:])
        s = m["S"]
        pr = {"N": 0.85, "L": 0.68 if s == "C" else 0.62, "H": 0.5 if s == "C" else 0.27}[m["PR"]]
        iss = 1 - (1 - _CVSS3["C"][m["C"]]) * (1 - _CVSS3["I"][m["I"]]) * (1 - _CVSS3["A"][m["A"]])
        imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if s == "C" else 6.42 * iss
        eks = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if imp <= 0:
        return 0.0
    dasar = min(1.08 * (imp + eks), 10) if s == "C" else min(imp + eks, 10)
    n = int(round(dasar * 100000))                            # roundup satu desimal sesuai CVSS 3.1
    return n / 100000.0 if n % 10000 == 0 else (n // 10000 + 1) / 10.0


def _osv_kelompok(vulns):
    """Kelompok alias seperti osv-scanner: advisori yang saling beralias (GHSA <-> CVE <-> PYSEC) digabung."""
    induk = {}

    def akar(x):
        while induk.setdefault(x, x) != x:
            induk[x] = induk[induk[x]]
            x = induk[x]
        return x
    for v in vulns:
        for a in [v["id"]] + list(v.get("aliases") or []):
            induk[akar(a)] = akar(v["id"])
    grup = {}
    for v in vulns:
        grup.setdefault(akar(v["id"]), []).append(v)
    out = []
    for vs in grup.values():
        skor = [x for x in (cvss3_skor(sv.get("score")) for v in vs for sv in (v.get("severity") or []) if isinstance(sv, dict)) if x is not None]
        alias = sorted({a for v in vs for a in [v["id"]] + list(v.get("aliases") or [])})
        out.append({"ids": sorted(v["id"] for v in vs), "aliases": alias, "max_severity": ("%.1f" % max(skor)) if skor else ""})
    return out


def osv_periksa(akar):
    """Docroot -> (status, js bentuk keluaran osv-scanner, pesan, jumlah lockfile, jumlah paket). status: ok, tanpa_lockfile, galat, timeout."""
    batas = time.time() + OSV_TIMEOUT
    lockfiles = osv_cari_lockfile(akar, batas)
    inv = osv_inventaris(lockfiles)
    paket = sorted({p for ps in inv.values() for p in ps})
    if not paket:
        return "tanpa_lockfile", None, "", len(inv), 0
    try:
        q = osv_query(paket, batas)
        ids = {x["id"]: str(x.get("modified", "")) for vs in q.values() for x in vs}
        rinci, gagal = osv_rincian(ids, batas) if ids else ({}, [])
    except TimeoutError as ex:
        return "timeout", None, str(ex)[:200], len(inv), len(paket)
    except Exception as ex:
        return "galat", None, ("api.osv.dev: %s" % ex)[:300], len(inv), len(paket)
    if gagal and len(gagal) * 2 > len(ids):
        return "galat", None, "rincian %d dari %d advisori gagal diambil dari api.osv.dev" % (len(gagal), len(ids)), len(inv), len(paket)
    hasil = []
    for lf, ps in inv.items():
        pk = []
        for p in ps:
            vulns = [rinci.get(x["id"]) or {"id": x["id"]} for x in q.get(p, [])]
            if vulns:
                pk.append({"package": {"ecosystem": p[0], "name": p[1], "version": p[2]}, "vulnerabilities": vulns, "groups": _osv_kelompok(vulns)})
        if pk:
            hasil.append({"source": {"path": lf, "type": "lockfile"}, "packages": pk})
    pesan = ("%d advisori tanpa rincian (api.osv.dev)" % len(gagal)) if gagal else ""
    return "ok", {"results": hasil}, pesan, len(inv), len(paket)

def scan_osv(akar=None):
    """Dependensi aplikasi di docroot dinilai database OSV realtime. (komponen, temuan, info). info.status: ok, tanpa_lockfile, nonaktif,
    cadangan (API gagal: hasil sukses terakhir <= 7 hari dipakai), galat, timeout."""
    info = {"status": "nonaktif", "checked_at": 0, "lockfiles": 0, "packages": 0, "vulns": 0, "message": ""}
    return [], [], info


# ---------------------------------------------------------------------- #
# Mesin                                                                   #
# ---------------------------------------------------------------------- #
class CVEAdvisorEngine:
    def __init__(self, cve_db=None):
        self.sl = _modul("sentinel_license")
        self.feed = None
        if cve_db is None and self.sl and hasattr(self.sl, "cve_feed_entries"):
            self.feed = self.sl.cve_feed_entries()
        self.cve_db = cve_db if cve_db is not None else (self.feed if self.feed else BUILTIN_CVE_DB)
        self.sumber = "feed" if (cve_db is None and self.feed) else ("uji" if cve_db is not None else "bawaan")

    def _boleh_vpatch(self):
        return bool(self.sl and hasattr(self.sl, "allowed") and self.sl.allowed("cve_vpatch"))

    def _aturan_vpatch(self, cve_id):
        """Isi virtual patch hanya dari feed SAH (bukan data bawaan) dan hanya bila lolos kebijakan modpolicy."""
        if self.sumber != "feed":
            return ""
        return ""

    def scan_system(self):
        # Inventaris SAMA untuk feed, data bawaan, maupun uji (dulu jalur uji memakai cabang lama tanpa runtime/database/
        # kernel/container/panel sehingga pemindai baru tidak pernah diuji).
        env_items = scan_environment()
        komponen = (env_items + scan_webserver() + scan_php() + scan_runtimes() + scan_databases() + scan_os_and_kernel()
                    + scan_os_packages() + scan_containers() + scan_wordpress())
        seen_k, unik = set(), []
        for k in komponen:
            key = (k.get("component"), k.get("version"), k.get("path"))
            if key not in seen_k:
                seen_k.add(key)
                unik.append(k)
        komponen = unik
        osv_komp, osv_temuan, osv_info = scan_osv()
        # assessed: komponen benar-benar dinilai (punya versi berangka dan ada entri CVE yang berlaku untuknya). Selain itu
        # UI menampilkan "tidak dinilai", bukan "aman": tanpa feed, data bawaan hanya memuat beberapa plugin WordPress.
        for k in komponen:
            berangka = bool(re.search(r"\d", str(k.get("version", ""))))
            distro = k.get("managed_by") == "distro"
            k["assessed"] = berangka and any(e.get("component") == k["component"] and (not distro or e.get("distro_aware"))
                                             for e in self.cve_db if isinstance(e, dict))
        temuan, dedup = [], set()
        for k in komponen:
            if not k["assessed"]:
                continue
            for e in self.cve_db:
                if e.get("component") != k["component"]:
                    continue
                if k.get("managed_by") == "distro" and not e.get("distro_aware"):
                    continue
                if not any(versi_dalam(k["version"], r.get("min", "0"), r.get("max", "0")) for r in e.get("affected_ranges", []) if isinstance(r, dict)):
                    continue
                kunci = (e.get("cve_id"), k["component"], k["version"], k["path"])
                if kunci in dedup or not CVE_RE.match(str(e.get("cve_id", ""))):
                    continue
                dedup.add(kunci)
                rem = dict(e.get("remediations") or {})
                rem.pop("tier1_vpatch", None)                  # isi aturan tidak dikirim ke UI
                # teks per bahasa (tier2_hardening_en/_id, tier3_upgrade_en/_id) ikut dikirim; UI memilih sesuai bahasa aktif panel
                rem = {rk: (str(rv)[:500] if isinstance(rv, str) else rv) for rk, rv in rem.items()}
                judul = {jk: str(e[jk])[:200] for jk in ("title_en", "title_id") if isinstance(e.get(jk), str) and e.get(jk)}
                tersedia = bool(self._aturan_vpatch(e["cve_id"]))
                temuan.append({
                    "cve_id": e["cve_id"], "title": str(e.get("title", ""))[:200], **judul, "component": k["component"],
                    "detected_version": k["version"], "detected_path": k["path"], "managed_by": k.get("managed_by", ""),
                    "cvss": float(e.get("cvss", 0) or 0), "severity": e.get("severity", "MEDIUM") if e.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
                    "exploit_status": str(e.get("exploit_status", "NONE"))[:30], "remediations": rem,
                    "vpatch_available": tersedia and self._boleh_vpatch(), "vpatch_active": self.vpatch_aktif(e["cve_id"]),
                })
        # temuan OSV digabung; CVE yang sudah dilaporkan feed untuk komponen yang sama tidak digandakan
        sudah = {(t["cve_id"], t["component"]) for t in temuan}
        for t in osv_temuan:
            if (t.get("cve_id"), t.get("component")) in sudah:
                continue
            t = dict(t)
            t["vpatch_available"] = bool(CVE_RE.match(str(t.get("cve_id")))) and bool(self._aturan_vpatch(t["cve_id"])) and self._boleh_vpatch()
            t["vpatch_active"] = self.vpatch_aktif(t.get("cve_id"))
            temuan.append(t)
        komponen = komponen + osv_komp
        skor = 100
        # dependensi OSV: penalti sekali per paket rentan (severity tertinggi), bukan per advisori; satu library usang bisa membawa
        # belasan advisori dan dulu langsung membuat skor 0 walau perbaikannya satu kali update
        bobot = {"CRITICAL": 25, "HIGH": 15}
        per_paket = {}
        for t in temuan:
            if t.get("source") == "osv":
                k = (t["component"], t.get("detected_path"))
                per_paket[k] = max(per_paket.get(k, 0), bobot.get(t["severity"], 5))
                continue
            f = 0.3 if t["vpatch_active"] else 1.0
            skor -= int(bobot.get(t["severity"], 5) * f)
        skor -= sum(per_paket.values())
        env_info = env_items[0] if env_items else {"name": "Standalone", "version": ""}
        laporan = {
            "posture_score": max(0, min(100, skor)), "components_scanned": len(komponen),
            "components_assessed": sum(1 for k in komponen if k["assessed"]), "vulnerabilities_found": len(temuan),
            "vulnerabilities": temuan, "components": komponen, "environment": env_info,
            "data_source": self.sumber + ("+osv" if osv_info["status"] in ("ok", "cadangan") else ""), "osv": osv_info,
            "distro_packages_skipped": sum(1 for k in komponen if k.get("managed_by") == "distro"),
            "note": "Paket distro (dpkg/rpm, php sistem) tidak dinilai dari nomor versi upstream karena distro menambal tanpa menaikkan versi; pakai update keamanan distro (apt/dnf).",
            "note_en": "Distro packages (dpkg/rpm, system PHP) are not assessed against upstream version numbers because Linux distros backport security patches without bumping version numbers; use distro security updates (apt/dnf).",
        }
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            tmp = REPORT_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(laporan, f)
            os.replace(tmp, REPORT_FILE)
        except OSError:
            pass
        return laporan

    @staticmethod
    def vpatch_aktif(cve_id):
        return CVE_RE.match(str(cve_id)) is not None and os.path.isfile(os.path.join(VPATCH_DIR, cve_id + ".conf"))

    def apply_vpatch(self, cve_id, action="on"):
        if not CVE_RE.match(str(cve_id)):
            return False, "Format CVE ID tidak valid"
        berkas = os.path.join(VPATCH_DIR, cve_id + ".conf")
        if action == "off":
            try:
                os.remove(berkas)
                return True, "Virtual patch %s dicabut" % cve_id
            except FileNotFoundError:
                return True, "Virtual patch %s sudah nonaktif" % cve_id
            except OSError as e:
                return False, "Gagal mencabut virtual patch: %s" % e
        if not self._boleh_vpatch():
            return False, "Virtual patch membutuhkan paket Max (fitur cve_vpatch)"
        isi = self._aturan_vpatch(cve_id)
        if not isi:
            return False, "Virtual patch untuk %s tidak tersedia (hanya dari feed CVE bertanda tangan yang sah)" % cve_id
        os.makedirs(VPATCH_DIR, mode=0o755, exist_ok=True)
        tmp = berkas + ".tmp"
        with open(tmp, "w") as f:
            f.write("# ZySentinel virtual patch %s (feed bertanda tangan)\n%s\n" % (cve_id, isi))
        os.chmod(tmp, 0o644)
        os.replace(tmp, berkas)
        return True, "Virtual patch %s ditulis" % cve_id


def main():
    aksi = sys.argv[1] if len(sys.argv) > 1 else "report"
    eng = CVEAdvisorEngine()
    if aksi == "scan":
        print(json.dumps(eng.scan_system()))
    elif aksi == "report":
        try:
            with open(REPORT_FILE) as f:
                print(json.dumps(json.load(f)))
                return 0
        except (OSError, ValueError):
            print(json.dumps(eng.scan_system()))
    elif aksi == "vpatch" and len(sys.argv) >= 3:
        ok, pesan = eng.apply_vpatch(sys.argv[2].upper(), (sys.argv[3].lower() if len(sys.argv) > 3 else "on"))
        print("[%s] %s" % ("OK" if ok else "FAIL", pesan))
        return 0 if ok else 1
    else:
        print("Penggunaan: sentinel-cve.py scan | report | vpatch <CVE-ID> [on|off]")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
