#!/usr/bin/env python3
# ==============================================================================
# sentinel-upload-scan.py
#
# Real-Time Upload Scanner & Per-Host Quarantine Guard (Imunify360 Style)
# untuk ZySentinel.
#
# CARA KERJA & KEAMANAN MEMORI (ANTI-CRASH):
#   1. Clamd Socket Streaming:
#      Menggunakan 'clamdscan --stream' ke socket /var/run/clamav/clamd.ctl
#      tanpa memanggil 'clamscan' baru (TIDAK ADA overhead reload database 1.3GB).
#      Penggunaan RAM konstan, streaming berlangsung < 50ms.
#   2. Memory Safety Fuse:
#      Memeriksa MemAvailable di /proc/meminfo. Jika RAM bebas < 100 MB,
#      scan di-skip secara aman guna mencegah OOM Killer.
#   3. Batasan Ukuran Berkas:
#      Hanya memindai berkas <= 25 MB (berkas raksasa tidak membebani buffer).
#   4. Karantina Per Host (Per-Vhost Isolation):
#      Jika terdeteksi malware, berkas segera dipindahkan ke:
#        /www/server/sentinel/av/quarantine/<vhost>/files/
#      dan dikunci rapat dengan 'chmod 000' (tidak dapat dibaca/dieksekusi siapapun).
#      Berkas asli di webroot dihapus seketika.
#   5. Kontrol Granular Per Vhost:
#      Status aktif/nonaktif dapat dikontrol ON | OFF per vhost via JSON config
#      dan antarmuka dasbor aaPanel.
# ==============================================================================
import os
import sys
import time
import json
import subprocess
import signal
import sqlite3
import hashlib
import glob
from datetime import datetime

CONF_DIR = '/www/server/sentinel/etc'
CONF_FILE = os.path.join(CONF_DIR, 'vhost_upload_scan.json')
BASE_QUARANTINE = '/www/server/sentinel/av/quarantine'
NGINX_VHOST_DIR = '/www/server/panel/vhost/nginx'
APACHE_VHOST_DIR = '/www/server/panel/vhost/apache'
WWWROOT_DIR = '/www/wwwroot'
LOG_FILE = '/www/server/sentinel/log/upload_scan.log'
STATE_FILE = '/www/server/sentinel/run/upload_scan.state'
PID_FILE = '/www/server/sentinel/run/upload_scan.pid'
DB_PATH = '/www/server/sentinel/data/guardd.db'

CLAMD_SOCKETS = [
    '/var/run/clamav/clamd.ctl',
    '/run/clamav/clamd.ctl',
    '/var/run/clamd.scan/clamd.sock',
    '/run/clamd.scan/clamd.sock'
]

# Pola folder yang sering digunakan untuk upload berkas di CMS (WordPress, Laravel, dll)
UPLOAD_SUBDIRS = [
    'public/uploads',
    'public/format_upload',
    'public/honeypot',
    'public/assets/uploads',
    'storage/app',
    'wp-content/uploads',
    'uploads',
    'media',
    'upload'
]

# Ekstensi atau path yang selalu dilewati dari realtime scan (cache / vendor / git)
EXCLUDE_PATH_PATTERNS = [
    '/storage/framework/',
    '/storage/logs/',
    '/vendor/',
    '/node_modules/',
    '/.git/',
    '/.cache/',
    '/bootstrap/cache/',
    '/.well-known/'
]

running = True

def handle_signal(sig, frame):
    global running
    log(f"Menerima sinyal {sig}, menghentikan upload scan watcher...")
    running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

def log(msg):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"{ts} [upload-scan] {msg}"
    print(line)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'a', encoding='utf-8') as fp:
            fp.write(line + '\n')
    except Exception:
        pass

def get_available_memory_mb():
    """Membaca ketersediaan RAM bebas dari /proc/meminfo untuk mencegah OOM."""
    try:
        with open('/proc/meminfo', 'r') as fp:
            for line in fp:
                if line.startswith('MemAvailable:'):
                    kb = int(line.split()[1])
                    return kb // 1024
    except Exception:
        pass
    return 512

def get_clamd_socket():
    for s in CLAMD_SOCKETS:
        if os.path.exists(s):
            return s
    return None

def is_clamd_ready():
    return get_clamd_socket() is not None

def load_config():
    os.makedirs(CONF_DIR, exist_ok=True)
    default_cfg = {
        'enabled': True,
        'max_file_size_mb': 25,
        'min_memory_mb': 100,
        'action': 'quarantine',
        'vhosts': {}
    }
    if not os.path.isfile(CONF_FILE):
        save_config(default_cfg)
        return default_cfg
    try:
        with open(CONF_FILE, 'r') as fp:
            data = json.load(fp)
            if not isinstance(data, dict):
                data = default_cfg
            return data
    except Exception:
        return default_cfg

def save_config(cfg):
    os.makedirs(CONF_DIR, exist_ok=True)
    tmp = CONF_FILE + '.tmp'
    with open(tmp, 'w') as fp:
        json.dump(cfg, fp, indent=2)
    os.replace(tmp, CONF_FILE)
    os.chmod(CONF_FILE, 0o644)

def discover_vhosts():
    """Mendeteksi daftar vhost yang terdaftar di aaPanel."""
    vhosts = {}
    # 1. Dari Nginx vhost configs
    if os.path.isdir(NGINX_VHOST_DIR):
        for f in os.listdir(NGINX_VHOST_DIR):
            if f.endswith('.conf') and not f.startswith(('0.', 'free_waf', 'phpfpm_status', 'waf2monitor')):
                site = f[:-5]
                root = os.path.join(WWWROOT_DIR, site)
                # Coba cari root directive asli di dalam file conf
                try:
                    with open(os.path.join(NGINX_VHOST_DIR, f), 'r', errors='ignore') as fp:
                        for line in fp:
                            line = line.strip()
                            if line.startswith('root ') and line.endswith(';'):
                                parts = line[5:-1].strip()
                                if os.path.isdir(parts):
                                    root = parts
                                break
                except Exception:
                    pass
                vhosts[site] = {
                    'server': 'nginx',
                    'root': root,
                    'exists': os.path.isdir(root)
                }

    # 2. Dari Apache vhost configs
    if os.path.isdir(APACHE_VHOST_DIR):
        for f in os.listdir(APACHE_VHOST_DIR):
            if f.endswith('.conf') and not f.startswith('0.'):
                site = f[:-5]
                if site not in vhosts:
                    root = os.path.join(WWWROOT_DIR, site)
                    vhosts[site] = {
                        'server': 'apache',
                        'root': root,
                        'exists': os.path.isdir(root)
                    }

    # 3. Direktori di wwwroot
    if os.path.isdir(WWWROOT_DIR):
        for d in os.listdir(WWWROOT_DIR):
            p = os.path.join(WWWROOT_DIR, d)
            if os.path.isdir(p) and d not in vhosts and not d.startswith('.'):
                vhosts[d] = {
                    'server': 'generic',
                    'root': p,
                    'exists': True
                }
    return vhosts

def get_vhost_watch_dirs(vhost_name, vhost_info):
    """Menentukan subdirektori sensitif vhost yang perlu diawasi realtime."""
    watch_dirs = []
    root = vhost_info.get('root', os.path.join(WWWROOT_DIR, vhost_name))
    if not os.path.isdir(root):
        return []

    # Cek subdirektori upload yang ada
    for sub in UPLOAD_SUBDIRS:
        target = os.path.join(root, sub)
        if os.path.isdir(target):
            watch_dirs.append(target)

    # Jika tidak ada subdirektori spesifik, awasi root vhost langsung
    if not watch_dirs:
        watch_dirs.append(root)

    return watch_dirs

def scan_file_stream(filepath):
    """
    Pindai 1 berkas menggunakan clamdscan --stream via socket.
    Return: (status, signature)
      - status: 'CLEAN', 'INFECTED', 'SKIPPED', 'ERROR'
    """
    if not os.path.isfile(filepath) or os.path.islink(filepath):
        return 'SKIPPED', 'Not a regular file'

    # 1. Cek ukuran berkas
    try:
        sz = os.path.getsize(filepath)
        if sz <= 0:
            return 'SKIPPED', 'Empty file'
        cfg = load_config()
        max_sz = cfg.get('max_file_size_mb', 25) * 1024 * 1024
        if sz > max_sz:
            return 'SKIPPED', f'Size {sz} exceeds limit {max_sz}'
    except Exception as e:
        return 'SKIPPED', str(e)

    # 2. Cek memori sistem (Anti-Crash OOM Fuse)
    free_ram = get_available_memory_mb()
    min_ram = load_config().get('min_memory_mb', 100)
    if free_ram < min_ram:
        log(f"PERINGATAN OOM FUSE: RAM bebas tersisa {free_ram} MB (< {min_ram} MB). Melewati streaming scan untuk {filepath}.")
        return 'SKIPPED', 'Low memory fuse triggered'

    # 3. Pindai via clamdscan stream
    cmd = ['nice', '-n', '19', 'ionice', '-c', '3', 'clamdscan', '--stream', '--no-summary', filepath]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        out = p.stdout.strip()
        if p.returncode == 0:
            # 4. Pindai heuristik AI Safety & Toxic Prompt (Gen Digital SAGE)
            try:
                fname = os.path.basename(filepath)
                fext = os.path.splitext(fname)[1].lower()
                ai_exts = {'.md', '.txt', '.prompt', '.rules', '.json', '.yaml', '.yml', '.sh', '.py', '.php', '.js', '.htaccess'}
                is_ai_file = fext in ai_exts or fname.startswith('.') or fname in {'SKILL.md', 'AGENTS.md', 'CLAUDE.md'}
                if is_ai_file and sz <= 15 * 1024 * 1024:
                    sage_bin = '/www/server/sentinel/bin/sentinel-sage.py'
                    if not os.path.isfile(sage_bin):
                        sage_bin = '/www/server/panel/plugin/sentinel/payload/sentinel-sage.py'
                    if os.path.isfile(sage_bin):
                        py_bin = '/www/server/panel/pyenv/bin/python3'
                        if not os.path.isfile(py_bin):
                            py_bin = 'python3'
                        sp = subprocess.run([py_bin, sage_bin, 'check', filepath, '--json'],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                        if sp.returncode != 0 and sp.stdout:
                            try:
                                sres = json.loads(sp.stdout)
                                if sres.get('status') == 'INFECTED':
                                    th = sres.get('threats', [{}])[0]
                                    rule_id = th.get('rule_id', 'SAGE.PromptInjection.Detected')
                                    return 'INFECTED', f"AI.{rule_id}"
                            except Exception:
                                pass
            except Exception as e_sage:
                log(f"Peringatan evaluasi SAGE upload scan: {e_sage}")

            return 'CLEAN', 'Clean'
        elif p.returncode == 1:
            # Malware terdeteksi: parsing nama signature
            # Format output: /path/to/file: Signature FOUND
            sig = 'Malware.Detected'
            if 'FOUND' in out:
                parts = out.split(':')
                if len(parts) >= 2:
                    sig = parts[1].replace('FOUND', '').strip()
            return 'INFECTED', sig
        else:
            return 'ERROR', f'rc={p.returncode}: {p.stderr.strip() or out}'
    except subprocess.TimeoutExpired:
        return 'ERROR', 'Scan timeout (10s)'
    except Exception as e:
        return 'ERROR', str(e)

def quarantine_vhost_file(vhost_name, filepath, signature):
    """
    Pindahkan berkas terinfeksi ke karantina per-vhost dan KUNCI (chmod 000).
    Return: (ok, quarantine_path, meta_path)
    """
    try:
        ts = int(time.time())
        vhost_safe = vhost_name.replace('/', '_').replace('..', '')
        q_vhost_dir = os.path.join(BASE_QUARANTINE, vhost_safe)
        q_files_dir = os.path.join(q_vhost_dir, 'files')
        q_meta_dir = os.path.join(q_vhost_dir, 'meta')
        os.makedirs(q_files_dir, exist_ok=True)
        os.makedirs(q_meta_dir, exist_ok=True)

        # Hitung sha256
        sha = 'unknown'
        try:
            with open(filepath, 'rb') as fp:
                sha = hashlib.sha256(fp.read()).hexdigest()
        except Exception:
            pass

        base = os.path.basename(filepath)
        stat_info = os.stat(filepath)
        orig_mode = oct(stat_info.st_mode)[-3:]
        orig_uid = stat_info.st_uid
        orig_gid = stat_info.st_gid
        orig_size = stat_info.st_size

        q_name = f"{ts}_{sha[:12]}_{base}"
        q_path = os.path.join(q_files_dir, q_name)
        meta_path = os.path.join(q_meta_dir, f"{q_name}.meta")

        # Pindahkan berkas fisik ke karantina
        os.replace(filepath, q_path)

        # KUNCI BERKAS TOTAL: chmod 000 (tidak ada akses baca/tulis/eksekusi)
        os.chmod(q_path, 0o000)

        # Tulis metadata
        meta_content = (
            f"quarantined_at={datetime.now().isoformat()}\n"
            f"vhost={vhost_name}\n"
            f"original_path={filepath}\n"
            f"quarantine_path={q_path}\n"
            f"signature={signature}\n"
            f"sha256={sha}\n"
            f"size={orig_size}\n"
            f"uid={orig_uid}\n"
            f"gid={orig_gid}\n"
            f"orig_mode={orig_mode}\n"
            f"locked_mode=000\n"
        )
        with open(meta_path, 'w', encoding='utf-8') as mfp:
            mfp.write(meta_content)
        os.chmod(meta_path, 0o600)

        # Catat ke database SQLite guardd.db
        record_quarantine_db(vhost_name, filepath, q_path, signature, sha, orig_size)

        log(f"MALWARE TERKUNCI & DIKARANTINA PER VHOST: [{vhost_name}] {filepath} -> {q_path} ({signature})")
        return True, q_path, meta_path
    except Exception as e:
        log(f"GALAT KARANTINA [{vhost_name}] {filepath}: {e}")
        return False, None, None

def record_quarantine_db(vhost, orig_path, q_path, sig, sha, sz):
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        con = sqlite3.connect(DB_PATH, timeout=5.0)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vhost_quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER,
                vhost TEXT,
                orig_path TEXT,
                q_path TEXT,
                signature TEXT,
                sha256 TEXT,
                size INTEGER,
                status TEXT
            )
        """)
        cur.execute("""
            INSERT INTO vhost_quarantine (ts, vhost, orig_path, q_path, signature, sha256, size, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'quarantined')
        """, (int(time.time()), vhost, orig_path, q_path, sig, sha, sz))

        # Masukkan ke antrean notifikasi darurat
        pesan = f"[ZYSENTINEL UPLOAD GUARD] Malware upload otomatis dikarantina & dikunci (000):\nVhost: {vhost}\nSignature: {sig}\nFile: {orig_path}"
        cur.execute("""
            INSERT INTO notif (ts, ip, jenis, isi, terkirim, coba, galat)
            VALUES (?, 0, 'upload_quarantine', ?, 0, 0, '')
        """, (int(time.time()), pesan))

        con.commit()
        con.close()
    except Exception as e:
        log(f"Gagal mencatat karantina ke SQLite: {e}")

def restore_vhost_quarantine(meta_file):
    if not os.path.isfile(meta_file):
        return False, "Berkas metadata tidak ditemukan"
    try:
        data = {}
        with open(meta_file, 'r', encoding='utf-8') as fp:
            for line in fp:
                if '=' in line:
                    k, v = line.strip().split('=', 1)
                    data[k] = v

        orig = data.get('original_path')
        qpath = data.get('quarantine_path')
        uid = int(data.get('uid', 1002))
        gid = int(data.get('gid', 1002))
        mode = int(data.get('orig_mode', '644'), 8)

        if not orig or not qpath or not os.path.exists(qpath):
            return False, "Berkas fisik karantina tidak ditemukan"

        os.makedirs(os.path.dirname(orig), exist_ok=True)
        os.chmod(qpath, mode)
        os.replace(qpath, orig)
        os.chown(orig, uid, gid)
        os.chmod(orig, mode)
        os.remove(meta_file)
        log(f"Berkas dipulihkan: {qpath} -> {orig}")
        return True, f"Dipulihkan ke {orig}"
    except Exception as e:
        return False, str(e)

def get_vhost_quarantine_list(vhost=None):
    """Membaca daftar berkas karantina terisolasi per vhost."""
    results = []
    search_pattern = os.path.join(BASE_QUARANTINE, '*', 'meta', '*.meta')
    if vhost:
        vhost_clean = vhost.replace('/', '_').replace('..', '')
        search_pattern = os.path.join(BASE_QUARANTINE, vhost_clean, 'meta', '*.meta')

    for meta_file in glob.glob(search_pattern):
        try:
            info = {}
            with open(meta_file, 'r', encoding='utf-8') as fp:
                for line in fp:
                    if '=' in line:
                        k, v = line.strip().split('=', 1)
                        info[k] = v
            info['meta_file'] = meta_file
            info['id'] = os.path.basename(meta_file).replace('.meta', '')
            results.append(info)
        except Exception:
            pass

    results.sort(key=lambda x: x.get('quarantined_at', ''), reverse=True)
    return results

def run_watcher():
    """
    Loop utama watcher realtime berbasis inotifywait untuk seluruh vhost yang aktif.
    """
    global running
    log("Memulai Sentinel Real-Time Upload Scanner Watcher...")

    if not is_clamd_ready():
        log("PERINGATAN: Socket clamd tidak terdeteksi. Pastikan clamav-daemon aktif.")

    with open(PID_FILE, 'w') as fp:
        fp.write(str(os.getpid()))

    last_scan_times = {}

    while running:
        cfg = load_config()
        if not cfg.get('enabled', True):
            write_state('standby', 0, 0)
            time.sleep(5)
            continue

        all_vhosts = discover_vhosts()
        active_watches = []
        dir_to_vhost = {}

        # Kumpulkan direktori pantau untuk vhost yang aktif
        for vh_name, vh_info in all_vhosts.items():
            is_active = cfg.get('vhosts', {}).get(vh_name, False)
            if is_active:
                dirs = get_vhost_watch_dirs(vh_name, vh_info)
                for d in dirs:
                    if os.path.isdir(d):
                        active_watches.append(d)
                        dir_to_vhost[d] = vh_name

        if not active_watches:
            write_state('idle_no_active_vhosts', 0, 0)
            time.sleep(5)
            continue

        write_state('watching', len(active_watches), len(dir_to_vhost))

        # Bangun perintah inotifywait
        cmd = [
            'inotifywait', '-m', '-q', '-r',
            '--format', '%e\t%w%f',
            '-e', 'close_write', '-e', 'moved_to'
        ] + active_watches

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            log(f"Inotifywait aktif memantau {len(active_watches)} direktori pada vhost aktif.")

            while running and proc.poll() is None:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line or '\t' not in line:
                    continue

                event, found_path = line.split('\t', 1)

                # Filter eksklusi path
                if any(p in found_path for p in EXCLUDE_PATH_PATTERNS):
                    continue

                # Identifikasi vhost pemilik berkas
                vhost_match = 'unknown'
                for d, vh in dir_to_vhost.items():
                    if found_path.startswith(d):
                        vhost_match = vh
                        break

                # Debounce / cooldown 3 detik per path
                now = time.time()
                if found_path in last_scan_times and (now - last_scan_times[found_path]) < 3.0:
                    continue
                last_scan_times[found_path] = now

                # Bersihkan cache cooldown lama
                if len(last_scan_times) > 1000:
                    last_scan_times = {k: v for k, v in last_scan_times.items() if (now - v) < 60.0}

                # Pindai berkas menggunakan streaming clamd
                status, sig = scan_file_stream(found_path)
                if status == 'INFECTED':
                    quarantine_vhost_file(vhost_match, found_path, sig)
                elif status == 'ERROR':
                    log(f"Status scan {found_path}: {sig}")

            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
        except Exception as e:
            log(f"Inotifywait loop error: {e}")
            time.sleep(3)

    write_state('stopped', 0, 0)
    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except Exception:
            pass
    log("Watcher dihentikan.")

def write_state(st, watch_cnt, vhost_cnt):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, 'w') as fp:
            fp.write(f"status={st}\n")
            fp.write(f"active_watches={watch_cnt}\n")
            fp.write(f"active_vhosts={vhost_cnt}\n")
            fp.write(f"clamd_socket={'ready' if is_clamd_ready() else 'missing'}\n")
            fp.write(f"clamd_socket_path={get_clamd_socket() or 'none'}\n")
            fp.write(f"mem_available_mb={get_available_memory_mb()}\n")
            fp.write(f"updated_at={datetime.now().isoformat()}\n")
    except Exception:
        pass

def get_status():
    cfg = load_config()
    all_vhosts = discover_vhosts()
    vhost_list = []
    active_count = 0
    total_quarantined = 0

    for name, info in all_vhosts.items():
        is_on = cfg.get('vhosts', {}).get(name, False)
        if is_on:
            active_count += 1
        q_count = len(get_vhost_quarantine_list(name))
        total_quarantined += q_count
        vhost_list.append({
            'vhost': name,
            'root': info.get('root', ''),
            'server': info.get('server', 'nginx'),
            'enabled': is_on,
            'quarantined_count': q_count
        })

    is_running = False
    pid = None
    state_data = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as sfp:
                for sline in sfp:
                    if '=' in sline:
                        sk, sv = sline.strip().split('=', 1)
                        state_data[sk] = sv
        except Exception:
            pass

    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE) as fp:
                pid = int(fp.read().strip())
                try:
                    os.kill(pid, 0)
                    is_running = True
                except Exception:
                    up_at = state_data.get('updated_at')
                    if up_at and state_data.get('status') != 'stopped':
                        dt = datetime.fromisoformat(up_at)
                        if abs((datetime.now() - dt).total_seconds()) < 60:
                            is_running = True
        except Exception:
            is_running = False

    clamd_ready = is_clamd_ready() or (state_data.get('clamd_socket') == 'ready')
    clamd_sock = get_clamd_socket() or state_data.get('clamd_socket_path')

    return {
        'service_running': is_running,
        'pid': pid,
        'clamd_ready': clamd_ready,
        'clamd_socket': clamd_sock,
        'available_ram_mb': get_available_memory_mb(),
        'config': cfg,
        'active_vhosts_count': active_count,
        'total_vhosts_count': len(all_vhosts),
        'total_quarantined': total_quarantined,
        'vhosts': vhost_list
    }

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    if cmd == 'daemon':
        run_watcher()
    elif cmd == 'status':
        print(json.dumps(get_status(), indent=2))
    elif cmd == 'scan' and len(sys.argv) > 2:
        f = sys.argv[2]
        vh = sys.argv[3] if len(sys.argv) > 3 else 'manual'
        st, sig = scan_file_stream(f)
        res = {'file': f, 'vhost': vh, 'status': st, 'signature': sig}
        if st == 'INFECTED':
            ok, qpath, meta = quarantine_vhost_file(vh, f, sig)
            res['quarantined'] = ok
            res['quarantine_path'] = qpath
        print(json.dumps(res, indent=2))
    elif cmd == 'toggle-vhost' and len(sys.argv) > 2:
        vh = sys.argv[2]
        cfg = load_config()
        cur = cfg.get('vhosts', {}).get(vh, False)
        cfg.setdefault('vhosts', {})[vh] = not cur
        save_config(cfg)
        print(json.dumps({'vhost': vh, 'enabled': not cur}))
    elif cmd == 'set-vhost' and len(sys.argv) > 3:
        vh = sys.argv[2]
        val = sys.argv[3].lower() in ['1', 'true', 'on', 'yes']
        cfg = load_config()
        cfg.setdefault('vhosts', {})[vh] = val
        save_config(cfg)
        print(json.dumps({'vhost': vh, 'enabled': val}))
    elif cmd == 'quarantine-list':
        vh = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(get_vhost_quarantine_list(vh), indent=2))
    elif cmd == 'quarantine-restore' and len(sys.argv) > 2:
        meta = sys.argv[2]
        ok, msg = restore_vhost_quarantine(meta)
        print(json.dumps({'status': ok, 'msg': msg}))
    elif cmd == 'quarantine-delete' and len(sys.argv) > 2:
        meta = sys.argv[2]
        if os.path.exists(meta):
            try:
                qpath = None
                with open(meta) as fp:
                    for line in fp:
                        if line.startswith('quarantine_path='):
                            qpath = line.strip().split('=', 1)[1]
                if qpath and os.path.exists(qpath):
                    os.remove(qpath)
                os.remove(meta)
                print(json.dumps({'status': True, 'msg': 'Berkas karantina dihapus permanen'}))
            except Exception as e:
                print(json.dumps({'status': False, 'msg': str(e)}))
        else:
            print(json.dumps({'status': False, 'msg': 'Metadata tidak ditemukan'}))
    else:
        print(f"Penggunaan: {sys.argv[0]} [daemon|status|scan <file> [vhost]|toggle-vhost <vhost>|set-vhost <vhost> <on|off>|quarantine-list [vhost]|quarantine-restore <meta>|quarantine-delete <meta>]")

if __name__ == '__main__':
    main()
