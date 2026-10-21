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
import queue
import threading
import re
import socket
import struct
import stat
import collections
import ctypes
import select
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
    forced = os.environ.get('ZYS_CLAMD_SOCKET')
    if forced:
        return forced if os.path.exists(forced) else None
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

    # Cek subdirektori upload yang ada. Bila docroot adalah ".../public" (Laravel dan
    # framework sejenis), folder upload yang sebenarnya ada di AKAR PROYEK
    # (storage/app, public/uploads relatif terhadap proyek). Dulu hanya docroot yang
    # dipakai, sehingga storage/app tidak pernah diawasi.
    basis = [root]
    if os.path.basename(root.rstrip('/')) == 'public':
        basis.append(os.path.dirname(root.rstrip('/')))
    dilihat = set()
    di_docroot = False
    for b in basis:
        for sub in UPLOAD_SUBDIRS:
            target = os.path.normpath(os.path.join(b, sub))
            if os.path.isdir(target) and target not in dilihat:
                dilihat.add(target)
                watch_dirs.append(target)
                if target.startswith(os.path.normpath(root) + '/'):
                    di_docroot = True

    # Docroot tanpa folder upload yang dikenal tetap diawasi utuh (tidak ketat),
    # walau folder upload proyek ditemukan di luar docroot.
    if not di_docroot:
        watch_dirs.append(root)

    return watch_dirs

# ==============================================================================
# MESIN PEMINDAIAN (v2)
#
# Sasaran: berkas upload TIDAK PERNAH menahan atau menolak request (pemindaian terjadi
# sesudah berkas ditulis), tetapi diputuskan secepat mungkin (milidetik) dan TIDAK ADA berkas
# yang lolos tanpa dipindai walau aliran peristiwa inotify terputus:
#   1. Aliran peristiwa (inotify) dibaca satu thread dan langsung dimasukkan ke ANTREAN
#      berprioritas (skrip/berkas eksekusi lebih dulu); beberapa pekerja memindai paralel.
#   2. Pemindaian langsung ke socket clamd (INSTREAM) di proses yang sama, tanpa menjalankan
#      proses baru per berkas; ditambah heuristik webshell/backdoor/polyglot yang berjalan
#      dalam mikrodetik dan tidak butuh clamd.
#   3. TAHAN-DULU: berkas eksekusi di folder upload langsung di-chmod 000 begitu peristiwa
#      diterima (sebelum antre) dan dipulihkan hanya bila bersih. Penyerang tidak bisa
#      mengeksekusinya selama pemindaian; catatan penahanan (jurnal) bertahan walau proses mati.
#   4. Jaring pengaman bila sinyal terputus: titik periksa (checkpoint) yang bertahan di disk;
#      saat daemon (re)start, saat inotifywait dimulai ulang, saat Q_OVERFLOW, dan berkala
#      (sapuan) berkas dengan ctime baru dimasukkan ke antrean yang sama.
#   5. Galat clamd: berkas tetap ditahan dan dicoba ulang dengan jeda bertahap; baru dilepas
#      (fail-open, tercatat) setelah semua percobaan gagal.
# ==============================================================================
CHECKPOINT_FILE = os.path.join(os.path.dirname(STATE_FILE), 'upload_scan.checkpoint')
HELD_FILE = os.path.join(os.path.dirname(STATE_FILE), 'upload_scan.held.json')

WORKERS_DEFAULT = 4
SWEEP_INTERVAL_DEFAULT = 20
RETRY_DELAYS_DEFAULT = [1, 2, 4, 8, 16]
HEAD_BYTES = 256 * 1024
SNIFF_MAX = 4 * 1024 * 1024
CLAMD_TIMEOUT = 10
SEEN_MAX = 100000

EXEC_EXTS = ('.php', '.php3', '.php4', '.php5', '.php7', '.php8', '.phtml', '.pht', '.phps', '.phar',
             '.inc', '.jsp', '.jspx', '.jsw', '.jsv', '.asp', '.aspx', '.asa', '.ashx', '.asmx', '.cer',
             '.cgi', '.pl', '.py', '.sh', '.bash', '.rb', '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
             '.jar', '.war')
HOLD_NAMES = ('.htaccess', '.user.ini', 'php.ini', 'web.config')
MEDIA_EXTS = ('.jpg', '.jpeg', '.jpe', '.png', '.gif', '.webp', '.bmp', '.ico', '.tif', '.tiff',
              '.avif', '.heic', '.pdf')
DOUBLE_EXEC_RE = re.compile(r'\.(?:php[0-9]?|phtml|pht|phar)(?:\.|$)')

WEBSHELL_RULES = [
    ('Eval.UserInput', re.compile(rb'(?:eval|assert|create_function)\s*\(\s*(?:@?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)|@?\$\{?\s*_(?:GET|POST|REQUEST)|(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|urldecode|strrev|hex2bin|convert_uudecode)\s*\()', re.I)),
    ('Exec.UserInput', re.compile(rb'(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*@?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)', re.I)),
    ('Backtick.UserInput', re.compile(rb'`[^`\n]{0,80}\$_(?:GET|POST|REQUEST|COOKIE)', re.I)),
    ('DynamicCall.UserInput', re.compile(rb'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', re.I)),
    ('Include.UserInput', re.compile(rb'(?:include|require)(?:_once)?\s*\(?\s*@?\$_(?:GET|POST|REQUEST|COOKIE)', re.I)),
    ('PregReplaceE', re.compile(rb'preg_replace\s*\(\s*[\'"][^\'"\n]{1,200}/[a-z]*e[a-z]*[\'"]\s*,', re.I)),
    ('Eval.Variable', re.compile(rb'eval\s*\(\s*\$\w+\s*\(', re.I)),
    ('Known.Webshell', re.compile(rb'(?:c99shell|r57shell|b374k|FilesMan|WSO\s*[0-9.]*\s*(?:shell|web)|IndoXploit|Mini\s*Shell|China\s*Chopper|Priv8\s*Shell|WebShell\s+by|Weevely)', re.I)),
    ('JSP.Exec', re.compile(rb'Runtime\.getRuntime\(\)\s*\.exec\s*\(\s*request\.getParameter', re.I)),
    ('ASP.Eval', re.compile(rb'(?:eval|execute)\s*\(?\s*request\s*[\.\(]', re.I)),
    ('ReverseShell', re.compile(rb'(?:bash\s+-i\s*>&?\s*/dev/tcp/|/dev/tcp/\d{1,3}\.\d|nc(?:at)?\s+-[a-z]*e\s+/bin/(?:ba)?sh|pty\.spawn\s*\()', re.I)),
]
# hanya di folder upload sungguhan (strict): .htaccess dan .user.ini yang mengubah cara PHP dijalankan
HTACCESS_RE = re.compile(rb'(?:AddType\s+application/x-httpd-php\s+\.[a-z0-9]+|AddHandler\s+(?:application/x-httpd-php|php[0-9.]*-script|cgi-script)|SetHandler\s+application/x-httpd-php|php_(?:value|flag)\s+auto_(?:prepend|append)_file)', re.I)
USERINI_RE = re.compile(rb'auto_(?:prepend|append)_file', re.I)
# '<?=' sendirian terlalu pendek untuk data biner (muncul acak pada ~0,1% gambar 20 KB dan lebih sering
# pada gambar besar), jadi hanya dihitung bila langsung diikuti kode PHP yang berbahaya.
POLYGLOT_RE = re.compile(rb'<\?php\b|<\?=\s*@?(?:\$_|\$\w+\s*\(|(?:system|exec|passthru|shell_exec|eval|assert|popen)\s*\()|<script[^>]{0,40}language\s*=\s*["\']?php', re.I)

_LOCK = threading.RLock()
SEEN = {}                  # path -> (ino, mtime_ns, size) yang sudah dinyatakan bersih
PENDING = {}               # path -> [token, t_wall, started]
HELD = {}                  # path -> {'mode','ino','vhost','strict'}  (jurnal penahanan)
STATS = {'scanned': 0, 'infected': 0, 'clean': 0, 'skipped': 0, 'errors': 0, 'retries': 0,
         'sweep_enq': 0, 'catchup_enq': 0, 'overflow': 0, 'held_total': 0, 'released': 0,
         'gate_events': 0, 'gate_wait': 0, 'gate_allow': 0, 'gate_deny': 0}
LATENCY = collections.deque(maxlen=2000)     # milidetik: peristiwa -> putusan
QUEUE = queue.PriorityQueue()        # etapa 1 (heuristik, cepat)
CLAMD_Q = queue.PriorityQueue()      # etapa 2 (clamd)
_SEQ = [0]
CATCHUP_REQ = queue.Queue()
SWEEP_WAKE = threading.Event()


def _seq():
    with _LOCK:
        _SEQ[0] += 1
        return _SEQ[0]


def is_exec_name(name):
    n = name.lower()
    return n.endswith(EXEC_EXTS) or n in HOLD_NAMES or bool(DOUBLE_EXEC_RE.search(n))


def heuristic_scan(name, head, tail, strict):
    """Heuristik statis (mikrodetik, tanpa clamd). Return signature atau None."""
    n = name.lower()
    exec_ = is_exec_name(n)
    media = n.endswith(MEDIA_EXTS)
    if n == '.htaccess' and strict and HTACCESS_RE.search(head):
        return 'ZySentinel.Backdoor.HtaccessHandler'
    if n in ('.user.ini', 'php.ini') and strict and USERINI_RE.search(head):
        return 'ZySentinel.Backdoor.UserIniPrepend'
    if exec_:
        for nama, rx in WEBSHELL_RULES:
            if rx.search(head):
                return 'ZySentinel.Webshell.' + nama
    elif media:
        if POLYGLOT_RE.search(head) or (tail and POLYGLOT_RE.search(tail)):
            return 'ZySentinel.Polyglot.PHPInMedia'
    return None


# ------------------------------------------------------------------ clamd langsung
def _balasan_clamd(s):
    buf = b''
    while b'\0' not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    return buf.split(b'\0')[0].decode('utf-8', 'replace').strip()


def _putusan_clamd(resp):
    if resp.endswith('OK'):
        return 'CLEAN', 'Clean'
    if resp.endswith('FOUND'):
        sig = resp.split(':', 1)[-1].replace('FOUND', '').strip() or 'Malware.Detected'
        return 'INFECTED', sig
    return 'ERROR', resp or 'respons clamd kosong'


def clamd_fildes(fd):
    """Pindai lewat FILDES: fd dikirim ke clamd (SCM_RIGHTS); clamd membaca berkas itu sendiri."""
    sock_path = get_clamd_socket()
    if not sock_path:
        return 'ERROR', 'clamd socket tidak ada'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(CLAMD_TIMEOUT)
        s.connect(sock_path)
        s.sendall(b'zFILDES\0')
        socket.send_fds(s, [b'\0'], [fd])      # fd lewat SCM_RIGHTS dengan satu bita pengiring
        resp = _balasan_clamd(s)
    except Exception as e:
        return 'ERROR', 'clamd FILDES: %s' % e
    finally:
        try:
            s.close()
        except Exception:
            pass
    return _putusan_clamd(resp)


def clamd_instream(fd, size):
    """Pindai isi fd lewat socket clamd (INSTREAM). Return (status, signature)."""
    sock_path = get_clamd_socket()
    if not sock_path:
        return 'ERROR', 'clamd socket tidak ada'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(CLAMD_TIMEOUT)
        s.connect(sock_path)
        s.sendall(b'zINSTREAM\0')
        off = 0
        while off < size:
            chunk = os.pread(fd, min(65536, size - off), off)
            if not chunk:
                break
            s.sendall(struct.pack('!I', len(chunk)) + chunk)
            off += len(chunk)
        s.sendall(struct.pack('!I', 0))
        resp = _balasan_clamd(s)
    except Exception as e:
        return 'ERROR', 'clamd: %s' % e
    finally:
        try:
            s.close()
        except Exception:
            pass
    return _putusan_clamd(resp)


def clamd_cli(filepath):
    """Cadangan bila socket langsung gagal: clamdscan --stream."""
    cmd = ['nice', '-n', '0', 'clamdscan', '--stream', '--no-summary', filepath]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=CLAMD_TIMEOUT)
        out = p.stdout.strip()
        if p.returncode == 0:
            return 'CLEAN', 'Clean'
        if p.returncode == 1:
            sig = 'Malware.Detected'
            if 'FOUND' in out:
                parts = out.split(':')
                if len(parts) >= 2:
                    sig = parts[1].replace('FOUND', '').strip()
            return 'INFECTED', sig
        return 'ERROR', 'rc=%s: %s' % (p.returncode, p.stderr.strip() or out)
    except subprocess.TimeoutExpired:
        return 'ERROR', 'Scan timeout (%ds)' % CLAMD_TIMEOUT
    except Exception as e:
        return 'ERROR', str(e)


def sage_check(filepath, name, size):
    """Heuristik teks AI (prompt injection). Hanya dijalankan bila karantina SAGE diaktifkan
    operator (etc/sage_quarantine.enabled); selain itu hasilnya hanya dicatat dan tidak
    berpengaruh pada keamanan, jadi dilewati agar putusan tetap cepat."""
    if not os.path.exists('/www/server/sentinel/etc/sage_quarantine.enabled'):
        return None
    ext = os.path.splitext(name)[1].lower()
    ai_exts = {'.md', '.txt', '.prompt', '.rules', '.json', '.yaml', '.yml', '.sh', '.py', '.php', '.js', '.htaccess'}
    if not (ext in ai_exts or name.startswith('.') or name in {'SKILL.md', 'AGENTS.md', 'CLAUDE.md'}) or size > 15 * 1024 * 1024:
        return None
    sage_bin = '/www/server/sentinel/bin/sentinel-sage.py'
    if not os.path.isfile(sage_bin):
        sage_bin = '/www/server/panel/plugin/sentinel/payload/sentinel-sage.py'
    if not os.path.isfile(sage_bin):
        return None
    py_bin = '/www/server/panel/pyenv/bin/python3'
    if not os.path.isfile(py_bin):
        py_bin = 'python3'
    try:
        sp = subprocess.run([py_bin, sage_bin, 'check', filepath, '--json'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=5)
        if sp.returncode != 0 and sp.stdout:
            sres = json.loads(sp.stdout)
            if sres.get('status') == 'INFECTED':
                return 'AI.%s' % sres.get('threats', [{}])[0].get('rule_id', 'SAGE.PromptInjection.Detected')
    except Exception as e:
        log(f"Peringatan evaluasi SAGE upload scan: {e}")
    return None


def _open_regular(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0))
    except OSError:
        return None, None
    try:
        st = os.fstat(fd)
    except OSError:
        os.close(fd)
        return None, None
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        return None, None
    return fd, st


def etapa_cepat(fd, st, path, strict):
    """Etapa 1 (mikrodetik, tanpa clamd): heuristik webshell/backdoor/polyglot dan penyaringan.
    Return (status, signature) bila putusan sudah final, atau None bila masih perlu clamd."""
    sz = st.st_size
    if sz <= 0:
        return 'SKIPPED', 'Empty file'
    name = os.path.basename(path)
    media = name.lower().endswith(MEDIA_EXTS)
    try:
        head = os.pread(fd, min(sz, SNIFF_MAX if media else HEAD_BYTES), 0)
        tail = b''
        if media and sz > SNIFF_MAX:
            tail = os.pread(fd, HEAD_BYTES, sz - HEAD_BYTES)
    except OSError as e:
        return 'ERROR', 'baca gagal: %s' % e
    sig = heuristic_scan(name, head, tail, strict)
    if sig:
        return 'INFECTED', sig
    cfg = load_config()
    if sz > cfg.get('max_file_size_mb', 25) * 1024 * 1024:
        return 'SKIPPED', f'Size {sz} exceeds limit'
    free_ram = get_available_memory_mb()
    min_ram = cfg.get('min_memory_mb', 100)
    if free_ram < min_ram:
        log(f"PERINGATAN OOM FUSE: RAM bebas tersisa {free_ram} MB (< {min_ram} MB). Melewati clamd untuk {path}.")
        return 'SKIPPED', 'Low memory fuse triggered'
    return None


def etapa_clamd(fd, st, path):
    """Etapa 2: pindai dengan clamd. FILDES lebih dulu (clamd membaca fd yang sama, tanpa menyalin data
    dan tanpa batas StreamMaxLength), lalu INSTREAM, lalu clamdscan CLI."""
    sz = st.st_size
    status, sig = clamd_fildes(fd)
    if status == 'ERROR':
        status, sig = clamd_instream(fd, sz)
    if status == 'ERROR':
        status, sig = clamd_cli(path)
    if status == 'INFECTED':
        return 'INFECTED', sig
    if status == 'ERROR':
        return 'ERROR', sig
    sg = sage_check(path, os.path.basename(path), sz)
    if sg:
        return 'INFECTED', sg
    return 'CLEAN', 'Clean'


def analyze_fd(fd, st, path, strict):
    """Dua etapa berurutan (dipakai CLI `scan`). Return (status, signature)."""
    r = etapa_cepat(fd, st, path, strict)
    return r if r is not None else etapa_clamd(fd, st, path)


def scan_file_stream(filepath):
    """Pemakaian CLI (`scan <berkas>`): satu berkas, tanpa antrean dan tanpa penahanan."""
    fd, st = _open_regular(filepath)
    if fd is None:
        return 'SKIPPED', 'Not a regular file'
    try:
        return analyze_fd(fd, st, filepath, False)
    finally:
        os.close(fd)


# ------------------------------------------------------------------ penahanan (hold)
def _held_save():
    try:
        tmp = HELD_FILE + '.tmp'
        with open(tmp, 'w') as fp:
            json.dump(HELD, fp)
        os.replace(tmp, HELD_FILE)
    except Exception:
        pass


def hold_file(fd, st, path, vhost, strict):
    """chmod 000 segera; catat di jurnal supaya bisa dipulihkan walau proses mati."""
    mode = st.st_mode & 0o7777
    if mode == 0:
        return False
    try:
        os.fchmod(fd, 0)
    except OSError:
        return False
    with _LOCK:
        HELD[path] = {'mode': mode, 'ino': st.st_ino, 'vhost': vhost, 'strict': strict}
        STATS['held_total'] += 1
        _held_save()
    return True


def release_file(path):
    """Kembalikan mode semula bila berkas yang sama masih ada dan masih terkunci."""
    with _LOCK:
        info = HELD.pop(path, None)
        if info is not None:
            _held_save()
    if not info:
        return
    fd, st = _open_regular(path)
    if fd is None:
        return
    try:
        if st.st_ino == info['ino'] and (st.st_mode & 0o7777) == 0:
            os.fchmod(fd, info['mode'])
            with _LOCK:
                STATS['released'] += 1
    except OSError:
        pass
    finally:
        os.close(fd)


def load_held():
    global HELD
    try:
        with open(HELD_FILE) as fp:
            d = json.load(fp)
        if isinstance(d, dict):
            HELD = d
    except Exception:
        HELD = {}


# ------------------------------------------------------------------ antrean
def enqueue(path, vhost, strict, source='event', attempt=0, t_mono=None, t_wall=None):
    """Masukkan berkas ke antrean pemindaian (dedup: berkas yang belum mulai dipindai tidak
    dimasukkan dua kali; yang sedang dipindai boleh dimasukkan lagi karena isinya bisa berubah)."""
    now_w = t_wall or time.time()
    with _LOCK:
        e = PENDING.get(path)
        if e and not e[2] and attempt == 0:
            return False
        token = _seq()
        PENDING[path] = [token, now_w, False]
        prio = 0 if is_exec_name(os.path.basename(path)) else 1
        QUEUE.put((prio, token, {'path': path, 'vhost': vhost, 'strict': strict, 'token': token,
                                 'attempt': attempt, 'source': source,
                                 't_mono': t_mono or time.monotonic()}))
        if source == 'sweep':
            STATS['sweep_enq'] += 1
        elif source in ('catchup', 'recover'):
            STATS['catchup_enq'] += 1
    return True


def _putusan(it, status, sig, sigkey):
    """Tindak lanjut putusan akhir: karantina, coba ulang bila galat, atau lepas penahanan."""
    path, vhost, strict = it['path'], it['vhost'], it['strict']
    ms = (time.monotonic() - it['t_mono']) * 1000.0
    with _LOCK:
        STATS['scanned'] += 1
        LATENCY.append(ms)
    if status == 'INFECTED':
        with _LOCK:
            STATS['infected'] += 1
        quarantine_vhost_file(vhost, path, sig)
        with _LOCK:
            HELD.pop(path, None)
            _held_save()
    elif status == 'ERROR':
        delays = load_config().get('retry_delays', RETRY_DELAYS_DEFAULT)
        with _LOCK:
            STATS['errors'] += 1
        if it['attempt'] < len(delays):
            with _LOCK:
                STATS['retries'] += 1
            log(f"Status scan {path}: {sig} (percobaan {it['attempt'] + 1}/{len(delays)}; berkas tetap ditahan)")
            tm = threading.Timer(delays[it['attempt']], enqueue, args=(path, vhost, strict, 'retry', it['attempt'] + 1))
            tm.daemon = True
            tm.start()
        else:
            log(f"GAGAL memindai {path} setelah {len(delays)} percobaan ({sig}); berkas dilepas (fail-open).")
            release_file(path)
    else:
        with _LOCK:
            STATS['clean' if status == 'CLEAN' else 'skipped'] += 1
            if status == 'CLEAN':
                if len(SEEN) > SEEN_MAX:
                    SEEN.clear()
                SEEN[path] = sigkey
        release_file(path)


def _etapa1(it):
    """Return True bila berkas diteruskan ke etapa 2 (PENDING tetap sampai putusan akhir)."""
    path, strict, token = it['path'], it['strict'], it['token']
    with _LOCK:
        e = PENDING.get(path)
        if e and e[0] == token:
            e[2] = True
    fd, st = _open_regular(path)
    if fd is None:
        release_file(path)
        return False
    try:
        sigkey = (st.st_ino, st.st_mtime_ns, st.st_size, st.st_ctime_ns)
        with _LOCK:
            sudah = SEEN.get(path) == sigkey and it['attempt'] == 0
        if sudah:
            if path in HELD:
                release_file(path)
            return False
        r = etapa_cepat(fd, st, path, strict)
    finally:
        os.close(fd)
    if r is None:
        it['sigkey'] = sigkey
        prio = 0 if is_exec_name(os.path.basename(path)) else 1
        CLAMD_Q.put((prio, it['token'], it))
        return True
    _putusan(it, r[0], r[1], sigkey)
    return False


def _etapa2(it):
    path = it['path']
    fd, st = _open_regular(path)
    if fd is None:
        release_file(path)
        return
    try:
        status, sig = etapa_clamd(fd, st, path)
    finally:
        os.close(fd)
    _putusan(it, status, sig, (st.st_ino, st.st_mtime_ns, st.st_size, st.st_ctime_ns))


def proses_item(it):
    diteruskan = False
    try:
        diteruskan = _etapa1(it)
    finally:
        if not diteruskan:
            _selesai(it['path'], it['token'])


def proses_clamd(it):
    try:
        _etapa2(it)
    finally:
        _selesai(it['path'], it['token'])


def _selesai(path, token):
    with _LOCK:
        e = PENDING.get(path)
        if e and e[0] == token:
            del PENDING[path]


def worker_loop(antrean, fungsi):
    while True:
        try:
            _, _, it = antrean.get(timeout=1.0)
        except queue.Empty:
            if not running:
                return
            continue
        try:
            fungsi(it)
        except Exception as ex:
            log(f"Galat memproses {it.get('path')}: {ex}")
            _selesai(it.get('path'), it.get('token'))
        if not running and antrean.empty():
            return


# ------------------------------------------------------------------ titik periksa, sapuan, catch-up
def checkpoint_value():
    """Waktu terlama yang masih belum selesai diproses, atau sekarang bila antrean kosong.
    Berkas dengan ctime >= nilai ini dijamin dimasukkan ulang bila daemon mati."""
    with _LOCK:
        if PENDING:
            return min(v[1] for v in PENDING.values())
    return time.time()


def write_checkpoint():
    try:
        tmp = CHECKPOINT_FILE + '.tmp'
        with open(tmp, 'w') as fp:
            fp.write('%.3f\n' % checkpoint_value())
        os.replace(tmp, CHECKPOINT_FILE)
    except Exception:
        pass


def read_checkpoint():
    try:
        with open(CHECKPOINT_FILE) as fp:
            return float(fp.read().strip())
    except Exception:
        return None


def sapu(dir_info, since, source):
    """Masukkan berkas ber-ctime >= since di direktori pantau ke antrean (find, C cepat)."""
    n = 0
    for d, (vhost, strict) in dir_info.items():
        if not running:
            break
        try:
            r = subprocess.run(['find', d, '-xdev', '-type', 'f', '-newerct', '@%d' % int(since), '-print0'],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
        except Exception as e:
            log(f"Sapuan {d} gagal: {e}")
            continue
        for raw in r.stdout.split(b'\0'):
            if not raw:
                continue
            p = raw.decode('utf-8', 'surrogateescape')
            # Pola pengecualian (vendor, .cache, .git, ...) TIDAK berlaku di folder
            # upload: di sana folder bernama begitu dibuat penyerang (ekstrak zip).
            if not strict and any(x in p for x in EXCLUDE_PATH_PATTERNS):
                continue
            if strict and is_exec_name(os.path.basename(p)):
                fd, st = _open_regular(p)
                if fd is not None:
                    try:
                        with _LOCK:
                            baru = SEEN.get(p) != (st.st_ino, st.st_mtime_ns, st.st_size, st.st_ctime_ns)
                        if baru and p not in HELD:
                            hold_file(fd, st, p, vhost, strict)
                    finally:
                        os.close(fd)
            if enqueue(p, vhost, strict, source):
                n += 1
    return n


CURRENT_DIRS = {}


def sweeper_loop():
    """Thread terpisah: catch-up sesuai permintaan dan sapuan berkala."""
    last = time.time()
    while running:
        interval = load_config().get('sweep_interval_s', SWEEP_INTERVAL_DEFAULT)
        SWEEP_WAKE.wait(timeout=max(1, float(interval)))
        SWEEP_WAKE.clear()
        if not running:
            return
        dirs = dict(CURRENT_DIRS)
        # permintaan catch-up khusus (daemon mulai, inotify dimulai ulang, direktori baru, overflow)
        while True:
            try:
                req_dirs, since, src = CATCHUP_REQ.get_nowait()
            except queue.Empty:
                break
            sapu(req_dirs if req_dirs is not None else dirs, since, src)
        start = time.time()
        sapu(dirs, last - 5, 'sweep')
        last = start


def minta_catchup(dirs, since, src='catchup'):
    CATCHUP_REQ.put((dirs, since, src))
    SWEEP_WAKE.set()


def recover_held():
    """Setelah daemon mati mendadak: berkas yang masih terkunci dipindai ulang."""
    load_held()
    for p, info in list(HELD.items()):
        fd, st = _open_regular(p)
        if fd is None:
            HELD.pop(p, None)
            continue
        os.close(fd)
        enqueue(p, info.get('vhost', 'unknown'), info.get('strict', False), 'recover')
    _held_save()


def quarantine_vhost_file(vhost_name, filepath, signature):
    """
    Pindahkan berkas terinfeksi ke karantina per-vhost dan KUNCI (chmod 000).
    Return: (ok, quarantine_path, meta_path)
    """
    if not os.path.lexists(filepath):
        return False, None, None      # sudah dikarantina oleh jalur lain (gerbang/antrean)
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
            h = hashlib.sha256()
            with open(filepath, 'rb') as fp:
                # bertahap: fp.read() utuh pada berkas besar menghabiskan MemoryMax daemon
                for blok in iter(lambda: fp.read(1 << 20), b''):
                    h.update(blok)
            sha = h.hexdigest()
        except Exception:
            pass

        base = os.path.basename(filepath)
        # Nama > ~230 byte membuat os.replace gagal (ENAMETOOLONG) dan webshell tetap
        # di tempat. Nama asli tetap tersimpan di metadata (original_path).
        if len(base.encode('utf-8', 'surrogateescape')) > 150:
            ekst = os.path.splitext(base)[1][:16]
            base = hashlib.sha256(base.encode('utf-8', 'surrogateescape')).hexdigest()[:24] + ekst
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

RESTORE_ROOTS = ('/www/wwwroot/', '/home/', '/var/www/', '/srv/', '/opt/', '/tmp/')


def _restore_aman(orig):
    """Tujuan pemulihan harus berada di area situs, tanpa symlink, dan tidak menimpa berkas.
    Pemulihan berjalan sebagai root: tanpa ini penyerang yang menguasai vhost bisa
    menukar folder asal dengan symlink lalu 'memulihkan' berkasnya ke direktori sistem."""
    if not orig or not orig.startswith('/') or '\x00' in orig or '..' in orig.split('/'):
        return False, 'path asal tidak valid'
    d = os.path.dirname(orig)
    cur = '/'
    for part in [x for x in d.split('/') if x]:
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            return False, 'path asal memuat symlink: %s' % cur
    real = os.path.realpath(d)
    if not any((real + '/').startswith(r) for r in RESTORE_ROOTS):
        return False, 'tujuan di luar area situs: %s' % real
    if os.path.lexists(orig):
        return False, 'berkas tujuan sudah ada dan tidak ditimpa: %s' % orig
    return True, ''


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

        ok, why = _restore_aman(orig)
        if not ok:
            return False, why
        os.makedirs(os.path.dirname(orig), exist_ok=True)
        if os.path.islink(qpath):
            return False, 'berkas karantina adalah symlink; dibatalkan'
        os.chmod(qpath, mode)
        os.replace(qpath, orig)
        os.lchown(orig, uid, gid)
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

# ------------------------------------------------------------------ gerbang saat berkas dibuka (fanotify)
# Penahanan chmod 000 dan antrean menutup jendela eksekusi hingga sekitar satu milidetik, tetapi tidak
# sampai nol: penyerang yang memberondong URL berkas yang baru ditulis bisa menang di jendela itu.
# Gerbang ini menutupnya: kernel MENUNGGU putusan kami sebelum open() berkas eksekusi yang belum
# terverifikasi di folder upload (FAN_OPEN_PERM). Yang ditahan hanya pembukaan berkas eksekusi
# (php, phtml, jsp, ...) di folder upload; berkas lain dan berkas yang sudah terverifikasi lolos
# seketika. Bila daemon mati atau gerbang dimatikan, kernel melepas semua pembukaan yang menunggu.
FAN_CLOEXEC = 0x1
FAN_CLASS_CONTENT = 0x4
FAN_OPEN_PERM = 0x10000
FAN_EVENT_ON_CHILD = 0x08000000
FAN_MARK_ADD = 0x1
FAN_ALLOW = 1
FAN_DENY = 2
_FAN_META = struct.Struct('IBBHQii')
OWN_PID = os.getpid()


def _libc():
    lib = ctypes.CDLL(None, use_errno=True)
    lib.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
    lib.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    return lib


def _ppid(pid):
    try:
        with open('/proc/%d/stat' % pid) as fp:
            return int(fp.read().rsplit(')', 1)[1].split()[1])
    except Exception:
        return -1


AV_COMM = ('clamd', 'clamscan', 'clamdscan')


def _comm(pid):
    try:
        with open('/proc/%d/comm' % pid) as fp:
            return fp.read().strip()
    except Exception:
        return ''


class FanGate:
    def __init__(self):
        self.fd = None
        self.dirs = ()
        self.lock = threading.Lock()
        self.work = queue.Queue()
        self.libc = None
        self.threads_started = False

    def _tandai(self, fd, d):
        n = 0
        # Gerbang hanya dipasang di folder upload (ketat): pola pengecualian tidak berlaku.
        for root, subdirs, _ in os.walk(d):
            r = self.libc.fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, -100, root.encode('utf-8', 'surrogateescape'))
            if r != 0:
                log(f"Gerbang: fanotify_mark {root} gagal: {os.strerror(ctypes.get_errno())}")
                break
            n += 1
        return n

    def sync(self, dirs):
        """Pasang gerbang pada direktori upload sungguhan. Grup baru dibuat dan ditandai dulu, baru
        yang lama ditutup, sehingga tidak ada celah tanpa gerbang saat daftar berubah."""
        dirs = tuple(sorted(dirs))
        with self.lock:
            if dirs == self.dirs and self.fd is not None:
                return True
            if not dirs:
                self._tutup_lama(None)
                self.dirs = ()
                return False
            try:
                if self.libc is None:
                    self.libc = _libc()
                fd = self.libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, os.O_RDONLY)
                if fd < 0:
                    raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
                total = sum(self._tandai(fd, d) for d in dirs)
            except Exception as e:
                log(f"Gerbang eksekusi (fanotify) tidak aktif: {e}. Perlindungan tetap lewat penahanan chmod 000 dan antrean.")
                return False
            lama = self.fd
            self.fd = fd
            self.dirs = dirs
            threading.Thread(target=self._leitor, args=(fd,), daemon=True).start()
            if not self.threads_started:
                self.threads_started = True
                for _ in range(4):
                    threading.Thread(target=self._pekerja, daemon=True).start()
            log(f"Gerbang eksekusi aktif: {total} direktori ditandai (kernel menunggu putusan sebelum berkas eksekusi dibuka).")
            if lama is not None:
                threading.Timer(1.0, self._tutup_fd, args=(lama,)).start()
            return True

    def _tutup_lama(self, _):
        lama, self.fd = self.fd, None
        if lama is not None:
            self._tutup_fd(lama)

    @staticmethod
    def _tutup_fd(fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def tambah_dir(self, d):
        with self.lock:
            if self.fd is not None:
                self._tandai(self.fd, d)

    def berhenti(self):
        with self.lock:
            self._tutup_lama(None)
            self.dirs = ()

    def _jawab(self, fd, evfd, ok):
        try:
            os.write(fd, struct.pack('iI', evfd, FAN_ALLOW if ok else FAN_DENY))
        except OSError:
            pass
        try:
            os.close(evfd)
        except OSError:
            pass

    def _leitor(self, fd):
        while running:
            try:
                r, _, _ = select.select([fd], [], [], 1.0)
                if not r:
                    continue
                buf = os.read(fd, 65536)
            except (OSError, ValueError):
                return          # grup ditutup (diganti atau dimatikan): kernel melepas yang menunggu
            off = 0
            while off + _FAN_META.size <= len(buf):
                evlen, vers, _, mlen, mask, evfd, pid = _FAN_META.unpack_from(buf, off)
                off += max(evlen, _FAN_META.size)
                if evfd < 0:
                    continue
                try:
                    self._tangani(fd, evfd, pid)
                except Exception:
                    self._jawab(fd, evfd, True)

    def _tangani(self, fd, evfd, pid):
        """Putusan cepat di thread pembaca (tidak boleh memblokir): lolos seketika bila bukan berkas
        eksekusi, berasal dari kami/anak proses kami, atau sudah terverifikasi bersih."""
        with _LOCK:
            STATS['gate_events'] += 1
        try:
            path = os.readlink('/proc/self/fd/%d' % evfd)
        except OSError:
            return self._jawab(fd, evfd, True)
        if not is_exec_name(os.path.basename(path)):
            return self._jawab(fd, evfd, True)
        if pid == OWN_PID or _ppid(pid) == OWN_PID:
            return self._jawab(fd, evfd, True)
        if _comm(pid) in AV_COMM:
            # mesin antivirus (clamd membaca berkas lewat path) tidak boleh menunggu kami: clamd dengan
            # MaxThreads 1 yang tertahan di open() akan membuat pemindaian kami sendiri macet (kebuntuan)
            return self._jawab(fd, evfd, True)
        try:
            st = os.fstat(evfd)
        except OSError:
            return self._jawab(fd, evfd, True)
        with _LOCK:
            sudah = SEEN.get(path) == (st.st_ino, st.st_mtime_ns, st.st_size, st.st_ctime_ns)
        if sudah or st.st_size <= 0:
            return self._jawab(fd, evfd, True)
        with _LOCK:
            STATS['gate_wait'] += 1
        self.work.put((fd, evfd, path, st))

    def _pekerja(self):
        while True:
            fd, evfd, path, st = self.work.get()
            try:
                self._putuskan(fd, evfd, path, st)
            except Exception as e:
                log(f"Gerbang: galat memutuskan {path}: {e}")
                self._jawab(fd, evfd, path not in HELD)

    def _putuskan(self, fd, evfd, path, st):
        vhost, strict = 'unknown', True
        for d, (vh, st_) in dict(CURRENT_DIRS).items():
            if path.startswith(d):
                vhost, strict = vh, st_
                break
        r = etapa_cepat(evfd, st, path, True)
        if r is None:
            r = etapa_clamd(evfd, st, path)
        status, sig = r
        sigkey = (st.st_ino, st.st_mtime_ns, st.st_size, st.st_ctime_ns)
        if status == 'INFECTED':
            with _LOCK:
                STATS['gate_deny'] += 1
            self._jawab(fd, evfd, False)          # lepaskan pembuka dengan EPERM, baru karantina
            if quarantine_vhost_file(vhost, path, sig)[0]:
                with _LOCK:
                    STATS['infected'] += 1
                    HELD.pop(path, None)
                    _held_save()
        elif status == 'ERROR':
            ok = path not in HELD          # masih ditahan = belum ada putusan: tolak (fail-closed)
            with _LOCK:
                STATS['gate_allow' if ok else 'gate_deny'] += 1
            self._jawab(fd, evfd, ok)
            enqueue(path, vhost, strict, 'gate')
        else:
            with _LOCK:
                STATS['gate_allow'] += 1
                if status == 'CLEAN':
                    SEEN[path] = sigkey
            self._jawab(fd, evfd, True)
            release_file(path)


GATE = FanGate()


# Selang (detik) pemeriksaan ulang konfigurasi/daftar vhost saat inotifywait berjalan.
RECHECK_INTERVAL = 3.0

def kumpulkan_watch(cfg):
    """Direktori yang harus dipantau untuk vhost yang sedang aktif di konfigurasi.
    Return: (daftar_direktori, {direktori: (vhost, strict)}). strict = folder upload sungguhan
    (bukan akar situs): di sana berkas eksekusi ditahan dan heuristik .htaccess/.user.ini berlaku."""
    active_watches = []
    info = {}
    for vh_name, vh_info in discover_vhosts().items():
        if cfg.get('vhosts', {}).get(vh_name, False):
            root = os.path.normpath(vh_info.get('root', os.path.join(WWWROOT_DIR, vh_name)))
            for d in get_vhost_watch_dirs(vh_name, vh_info):
                if os.path.isdir(d):
                    active_watches.append(d)
                    info[d] = (vh_name, os.path.normpath(d) != root)
    return active_watches, info


def _stat_lines(extra=None):
    with _LOCK:
        lat = sorted(LATENCY)
        n = len(lat)
        out = {
            'stat_scanned': STATS['scanned'], 'stat_infected': STATS['infected'], 'stat_clean': STATS['clean'],
            'stat_skipped': STATS['skipped'], 'stat_errors': STATS['errors'], 'stat_retries': STATS['retries'],
            'stat_sweep_enq': STATS['sweep_enq'], 'stat_catchup_enq': STATS['catchup_enq'],
            'stat_overflow': STATS['overflow'], 'stat_held_now': len(HELD), 'stat_held_total': STATS['held_total'],
            'stat_gate_on': 1 if GATE.fd is not None else 0, 'stat_gate_events': STATS['gate_events'],
            'stat_gate_wait': STATS['gate_wait'], 'stat_gate_allow': STATS['gate_allow'], 'stat_gate_deny': STATS['gate_deny'],
            'stat_queue': QUEUE.qsize() + CLAMD_Q.qsize(),
            'stat_lat_p50_ms': round(lat[n // 2], 1) if n else 0,
            'stat_lat_avg_ms': round(sum(lat) / n, 1) if n else 0,
            'stat_lat_p95_ms': round(lat[min(n - 1, int(n * 0.95))], 1) if n else 0,
            'stat_lat_max_ms': round(lat[-1], 1) if n else 0,
        }
    return out


def run_watcher():
    """
    Loop utama watcher realtime. Pemindaian terjadi SETELAH berkas ditulis (close_write/moved_to),
    jadi tidak pernah menahan atau menolak request upload. Lihat catatan MESIN PEMINDAIAN di atas:
    antrean berprioritas + pekerja paralel + clamd langsung + penahanan berkas eksekusi + titik periksa,
    sapuan, dan catch-up supaya tidak ada berkas terlewat walau inotify terputus.
    Konfigurasi diperiksa ulang tiap RECHECK_INTERVAL detik: tombol ON/OFF vhost berlaku tanpa restart.
    """
    global running, CURRENT_DIRS
    log("Memulai Sentinel Real-Time Upload Scanner Watcher...")

    if not is_clamd_ready():
        log("PERINGATAN: Socket clamd tidak terdeteksi. Pastikan clamav-daemon aktif.")

    with open(PID_FILE, 'w') as fp:
        fp.write(str(os.getpid()))

    cfg0 = load_config()
    n_workers = max(1, min(16, int(cfg0.get('workers', WORKERS_DEFAULT))))
    workers = [threading.Thread(target=worker_loop, args=(QUEUE, proses_item), daemon=True) for _ in range(2)]
    workers += [threading.Thread(target=worker_loop, args=(CLAMD_Q, proses_clamd), daemon=True) for _ in range(n_workers)]
    for t in workers:
        t.start()
    threading.Thread(target=sweeper_loop, daemon=True).start()
    ckpt_awal = read_checkpoint()
    recover_held()
    last_write = 0.0
    first_gen = True

    while running:
        cfg = load_config()
        if not cfg.get('enabled', True):
            GATE.berhenti()
            write_state('standby', 0, 0, _stat_lines())
            write_checkpoint()
            time.sleep(1)
            continue

        # Kumpulkan direktori pantau untuk vhost yang aktif
        active_watches, dir_info = kumpulkan_watch(cfg)
        CURRENT_DIRS = dict(dir_info)
        if cfg.get('onaccess_block', True):
            GATE.sync([d for d, (vh, strict) in dir_info.items() if strict])
        else:
            GATE.berhenti()

        if not active_watches:
            GATE.berhenti()
            write_state('idle_no_active_vhosts', 0, 0, _stat_lines())
            write_checkpoint()
            time.sleep(1)
            continue

        write_state('watching', len(active_watches), len(dir_info), _stat_lines())

        # Bangun perintah inotifywait. 'create' hanya dipakai untuk mendeteksi folder baru.
        cmd = [
            'inotifywait', '-m', '-q', '-r',
            '--format', '%e\t%w%f',
            '-e', 'close_write', '-e', 'moved_to', '-e', 'create'
        ] + active_watches

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                    errors='surrogateescape')
            log(f"Inotifywait aktif memantau {len(active_watches)} direktori pada vhost aktif.")

            # Jaring pengaman: SETELAH inotifywait hidup, masukkan berkas yang berubah selama
            # jeda (daemon baru mulai, inotifywait dimulai ulang, konfigurasi berubah).
            if first_gen:
                since = (ckpt_awal if ckpt_awal else time.time() - 3600) - 5
                first_gen = False
            else:
                since = time.time() - RECHECK_INTERVAL - 10
            minta_catchup(None, since, 'catchup')

            # Pembaca terpisah supaya loop utama bisa memeriksa konfigurasi berkala
            # walau tidak ada berkas baru (readline() langsung akan menunggu tanpa batas).
            antrean = queue.Queue()
            def _baca(p, q):
                try:
                    for ln in p.stdout:
                        q.put(ln)
                finally:
                    q.put(None)
            threading.Thread(target=_baca, args=(proc, antrean), daemon=True).start()
            cek_terakhir = time.time()
            mulai = time.time()

            while running and proc.poll() is None:
                try:
                    line = antrean.get(timeout=1.0)
                except queue.Empty:
                    line = ''
                if line is None:
                    break
                now_w = time.time()
                if now_w - last_write >= 1.0:
                    last_write = now_w
                    write_checkpoint()
                    write_state('watching', len(active_watches), len(dir_info), _stat_lines())
                if now_w - cek_terakhir >= RECHECK_INTERVAL:
                    cek_terakhir = now_w
                    cfg_baru = load_config()
                    baru, _ = kumpulkan_watch(cfg_baru)
                    if not cfg_baru.get('enabled', True) or sorted(baru) != sorted(active_watches):
                        log("Konfigurasi atau daftar vhost berubah, pemantauan dimuat ulang tanpa restart layanan.")
                        break
                    # gerbang eksekusi dapat dinyalakan/dimatikan langsung lewat konfigurasi
                    if cfg_baru.get('onaccess_block', True):
                        GATE.sync([d for d, (vh, strict) in dir_info.items() if strict])
                    else:
                        GATE.berhenti()
                if not line:
                    continue
                t_mono = time.monotonic()
                line = line.rstrip('\n')
                if '\t' not in line:
                    continue

                event, found_path = line.split('\t', 1)

                if 'Q_OVERFLOW' in event:
                    # antrean peristiwa kernel penuh: peristiwa hilang, sapu semuanya segera
                    with _LOCK:
                        STATS['overflow'] += 1
                    log("PERINGATAN: antrean inotify meluap (Q_OVERFLOW); sapuan darurat dijalankan.")
                    minta_catchup(None, checkpoint_value() - 30, 'catchup')
                    continue
                if not found_path:
                    continue

                # Identifikasi vhost pemilik berkas
                vhost_match, strict = 'unknown', False
                for d, (vh, st_) in dir_info.items():
                    if found_path.startswith(d):
                        vhost_match, strict = vh, st_
                        break

                # Filter eksklusi path (tidak berlaku di folder upload)
                if not strict and any(p in found_path for p in EXCLUDE_PATH_PATTERNS):
                    continue

                if 'ISDIR' in event:
                    if strict:
                        GATE.tambah_dir(found_path)
                    # folder baru: watch rekursif baru terpasang beberapa milidetik kemudian, jadi
                    # berkas yang sudah ada di dalamnya disapu segera (dipindah masuk = semua berkas)
                    since = 0 if event.startswith('MOVED_TO') else time.time() - 60
                    minta_catchup({found_path: (vhost_match, strict)}, since, 'catchup')
                    continue
                if event.startswith('CREATE'):
                    continue

                # TAHAN-DULU: berkas eksekusi di folder upload dikunci sebelum antre
                nama = os.path.basename(found_path)
                if strict and is_exec_name(nama):
                    fd, st = _open_regular(found_path)
                    if fd is not None:
                        try:
                            with _LOCK:
                                baru_ = SEEN.get(found_path) != (st.st_ino, st.st_mtime_ns, st.st_size, st.st_ctime_ns)
                            if baru_:
                                hold_file(fd, st, found_path, vhost_match, strict)
                        finally:
                            os.close(fd)
                enqueue(found_path, vhost_match, strict, 'event', t_mono=t_mono)

            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
            if time.time() - mulai < 2 and running:
                time.sleep(2)   # inotifywait gagal hidup (mis. batas watch): sapuan berkala tetap berjalan
        except Exception as e:
            log(f"Inotifywait loop error: {e}")
            time.sleep(3)

    # berhenti: tutup gerbang (kernel melepas pembukaan yang menunggu), tunggu antrean singkat, simpan titik periksa
    GATE.berhenti()
    SWEEP_WAKE.set()
    t_akhir = time.time() + 5
    while not (QUEUE.empty() and CLAMD_Q.empty()) and time.time() < t_akhir:
        time.sleep(0.1)
    write_checkpoint()
    write_state('stopped', 0, 0, _stat_lines())
    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except Exception:
            pass
    log("Watcher dihentikan.")


def write_state(st, watch_cnt, vhost_cnt, extra=None):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + '.tmp'
        with open(tmp, 'w') as fp:
            fp.write(f"status={st}\n")
            fp.write(f"active_watches={watch_cnt}\n")
            fp.write(f"active_vhosts={vhost_cnt}\n")
            fp.write(f"clamd_socket={'ready' if is_clamd_ready() else 'missing'}\n")
            fp.write(f"clamd_socket_path={get_clamd_socket() or 'none'}\n")
            fp.write(f"mem_available_mb={get_available_memory_mb()}\n")
            fp.write(f"updated_at={datetime.now().isoformat()}\n")
            for k, v in (extra or {}).items():
                fp.write(f"{k}={v}\n")
        os.replace(tmp, STATE_FILE)
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
        'stats': dict((k[5:], v) for k, v in state_data.items() if k.startswith('stat_')),
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
