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
#
# Bila mode 'enforce' aktif, proses penyerang dimatikan dengan SIGKILL
# dalam waktu < 1 detik, dicatat ke SQLite & berkas log, serta dikirim
# ke antrean notifikasi darurat.
# ============================================================
import os
import sys
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
        return "enforce"
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
        
        # 3. Masukkan ke antrean notifikasi (notif) jika tindakan berupa KILLED
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

def check_process_whitelist(pid, ppid, uid, exe_path, cmdline, cwd, basename):
    """Periksa apakah proses cocok dengan salah satu aturan whitelist aktif."""
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
                if pbase in ("sudo", "cron", "crond", "systemd", "bash", "sh"):
                    return True, "Root / Systemd Parent"
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

    for r in rules:
        if not r.get("enabled", True):
            continue
        w_type = r.get("type", "cmdline_match").lower()
        pat = str(r.get("pattern", "")).strip()
        if not pat:
            continue
        pat_lower = pat.lower()

        if w_type in ("cmdline_match", "cmdline_contains"):
            if pat_lower in cmd_lower:
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

    for pid in current_pids:
        proc_dir = f"/proc/{pid}"
        
        try:
            st = os.stat(proc_dir)
            st_uid = st.st_uid
            # Lewati proses root (UID 0) - root memiliki kendali penuh
            if st_uid == 0:
                continue
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue

        exe_path = ""
        try:
            exe_path = os.readlink(f"{proc_dir}/exe")
        except Exception:
            pass

        cmdline = ""
        try:
            with open(f"{proc_dir}/cmdline", "rb") as f:
                raw = f.read().split(b"\x00")
                cmdline = " ".join([p.decode("utf-8", errors="ignore") for p in raw if p])
        except Exception:
            pass

        cwd = ""
        try:
            cwd = os.readlink(f"{proc_dir}/cwd")
        except Exception:
            pass

        ppid = 0
        try:
            with open(f"{proc_dir}/stat", "r") as f:
                stat_fields = f.read().split()
                if len(stat_fields) > 3:
                    ppid = int(stat_fields[3])
        except Exception:
            pass

        basename = os.path.basename(exe_path) if exe_path else ""
        if not basename and cmdline:
            basename = os.path.basename(cmdline.split()[0])

        if basename in WHITELISTED_BASENAMES:
            continue

        # Evaluasi aturan deteksi pelanggaran
        rule_violation = None
        # Deteksi apakah perintah adalah operasi Git resmi (git pull, clone, fetch, checkout)
        is_git_cmd = (basename in ("git", "git-remote-https", "git-remote-http", "git-upload-pack", "git-receive-pack", "ssh")) or \
                     (cmdline and any(cmdline.strip().startswith(prefix) for prefix in ("git ", "/usr/bin/git ", "git-", "/usr/bin/git-")))

        # Aturan Proteksi Benteng Anti-Tamper:
        # Berlaku untuk SEMUA user non-root (UID != 0)!
        # Melarang keras modifikasi, uninstall, penghapusan, atau penghentian Sentinel & plugin panel.
        if not is_git_cmd and cmdline and any(p in cmdline for p in (
            "/www/server/sentinel", "/www/server/panel/plugin",
            "/etc/systemd/system/sentinel", "sentinel.service", "sentinel-",
            "guardd", "guardctl", "uninstall.lock"
        )):
            rule_violation = f"TAMPER_ATTEMPT({cmdline[:50]})"

        # Aturan Khusus Web Worker (UID 1002 / www):
        elif is_web_user:
            # Aturan 1: Shell interaktif
            if basename in BLOCKED_SHELLS:
                rule_violation = f"ILLEGAL_SHELL({basename})"
            
            # Aturan 2: Alat tunnel / scanner / sistem tamper
            elif basename in BLOCKED_TOOLS:
                rule_violation = f"BLOCKED_TOOL({basename})"
                
            # Aturan 3: Eksekusi binary dari folder temporer
            elif exe_path and any(exe_path.startswith(d) for d in SUSPICIOUS_DIRS):
                rule_violation = f"TEMP_DIR_EXEC({exe_path})"
                
            # Aturan 4: Binary ELF yang berjalan langsung di direktori webroot
            elif exe_path and exe_path.startswith("/www/wwwroot/") and is_elf(exe_path):
                rule_violation = f"WEBROOT_ELF_EXEC({exe_path})"

        if rule_violation:
            # Periksa apakah proses ini cocok dengan whitelist EDR
            is_wl, wl_info = check_process_whitelist(pid, ppid, st_uid, exe_path, cmdline, cwd, basename)
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
                continue

            # Jika tidak whitelisted, lakukan tindakan penegakan (SIGKILL bila mode enforce)
            action = "AUDIT"
            if mode == "enforce":
                try:
                    os.kill(pid, signal.SIGKILL)
                    action = "KILLED"
                    kills_count += 1
                except Exception as e:
                    action = f"KILL_FAILED({e})"
            
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
    try:
        while running:
            mode = get_mode()
            if mode != "off":
                scan_once(target_uid=DEFAULT_WEB_UID, mode=mode)
                scans_count += 1
            
            now = time.time()
            if now - last_state_write >= 3:
                write_state("running" if mode != "off" else "standby", mode)
                last_state_write = now
                
            time.sleep(1.0)
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
