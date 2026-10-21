#!/usr/bin/env python3
# ==============================================================================
# sentinel-sweeper.py : ZySentinel Sweeper (pemindai webshell selain ClamAV)
#
# Memindai semua folder vhost dan folder kustom untuk webshell/backdoor dengan logika keluarga ShellSweep
# (entropi, abaikan-hash, pengecualian path, heuristik berlapis) yang dikalibrasi agar tidak menandai kode sah.
# Mesin analisis: biner C `sentinel-sweeper` (cepat, hemat memori); bila tidak ada dan tidak bisa disusun,
# pustaka Python `sentinel-sweeplib.py` (putusan identik, tetapi jauh lebih lambat).
#
# Karantina memakai format dan folder yang sama dengan antivirus (sentinel-av.sh), sehingga muncul di tab
# Karantina dan bisa dipulihkan/dihapus dari sana.
#
# Pemakaian: sentinel-sweeper.py <perintah> [opsi]; keluaran JSON di stdout untuk perintah non-scan.
#   status | scan [--all-vhosts | --path P ...] [--report-only] [--scheduled] [--full] [--compat]
#   findings | action <quarantine|allow|ignore|unignore> <path> | allow-list | allow-add <sha|path> | allow-remove <sha>
#   config | config-set <json> | calibrate <path> | build | abort | schedule <on|off|status>
# ==============================================================================
import os
import sys
import re
import json
import time
import shutil
import hashlib
import sqlite3
import signal
import subprocess
from datetime import datetime

BASE = os.environ.get('ZYS_SWEEPER_BASE', '/www/server/sentinel')
BIN_DIR = os.path.dirname(os.path.abspath(__file__))
if os.environ.get('ZYS_SWEEPER_BASE'):
    BIN_DIR = os.environ.get('ZYS_SWEEPER_BIN', BIN_DIR)
ETC = os.path.join(BASE, 'etc')
SWD = os.path.join(BASE, 'sweeper')
CONF_FILE = os.path.join(ETC, 'sweeper.json')
ALLOW_FILE = os.path.join(ETC, 'sweeper_allow.txt')
JOB_FILE = os.path.join(SWD, 'job.json')
PID_FILE = os.path.join(SWD, 'job.pid')
LAST_FILE = os.path.join(SWD, 'last.json')
FIND_FILE = os.path.join(SWD, 'findings.json')
HIST_FILE = os.path.join(SWD, 'history.jsonl')
LOG_FILE = os.path.join(BASE, 'log', 'sweeper.log')
# Mode uji (ZYS_SWEEPER_BASE di-set) tidak boleh menyentuh karantina produksi: pustaka bersama baru dipakai bila
# variabelnya diberi nilai eksplisit.
_UJI = bool(os.environ.get('ZYS_SWEEPER_BASE'))
AV_COMMON = os.environ.get('ZYS_SWEEPER_AVCOMMON', '' if _UJI else '/usr/local/sbin/clamav-common.sh')
AV_RCONF = os.environ.get('ZYS_SWEEPER_AVCONF', '' if _UJI else '/etc/clamav/realtime.conf')
DB_PATH = os.path.join(BASE, 'data', 'guardd.db')
NGINX_VHOST_DIR = os.environ.get('ZYS_SWEEPER_NGINX', '/www/server/panel/vhost/nginx')
APACHE_VHOST_DIR = os.environ.get('ZYS_SWEEPER_APACHE', '/www/server/panel/vhost/apache')
WWWROOT = os.environ.get('ZYS_SWEEPER_WWWROOT', '/www/wwwroot')
ENGINE_BIN = os.path.join(BIN_DIR, 'sentinel-sweeper')
SRC_C = os.path.join(BASE, 'src', 'sentinel-sweeper.c')
SRC_STAMP = os.path.join(BIN_DIR, 'sentinel-sweeper.srchash')
TIMER = 'sentinel-sweeper.timer'
SCHEDULE_FLAG = os.path.join(ETC, 'sweeper.schedule')
RESTORE_ROOTS = ('/www/wwwroot/', '/home/', '/var/www/', '/srv/', '/opt/', '/tmp/')

DEFAULTS = {
    'custom_paths': [],
    'exclude': ['/.git/', '/node_modules/'],
    'skip_vhosts': [],
    'auto_quarantine': True,        # karantina otomatis untuk putusan webshell
    'quarantine_min_score': 90,
    'report_min_score': 50,         # di bawah ini tidak dilaporkan
    'throttle_ms': 2,               # jeda tiap 50 berkas (hemat CPU)
    'nice': 10,
    'ionice': True,
    'max_size_mb': 2,
    'incremental': True,            # pemindaian terjadwal hanya berkas yang berubah sejak pemindaian terakhir
    'full_every_days': 7,
    'incremental_margin_s': 300,    # berkas dengan ctime sejak (mulai pemindaian terakhir - margin) ikut dipindai
    'engine': 'auto',               # auto | c | python
    'entropy': {'mean': 4.664, 'sd': 0.325, 'z_flag': 3.2, 'z_strong': 4.2},
    'notify': True,
}
SAFE_VERDICT = ('webshell', 'suspicious')


def now():
    return int(time.time())


def log(msg):
    line = '%s [sweeper] %s' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'a', encoding='utf-8', errors='replace') as fp:
            fp.write(line + '\n')
    except Exception:
        pass


def jload(p, default):
    try:
        with open(p, 'r', encoding='utf-8') as fp:
            v = json.load(fp)
        return v if isinstance(v, type(default)) else default
    except Exception:
        return default


def jsave(p, obj):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + '.tmp.%d' % os.getpid()
    with open(tmp, 'w', encoding='utf-8') as fp:
        json.dump(obj, fp, ensure_ascii=False)
    os.replace(tmp, p)


def out(obj):
    print(json.dumps(obj, ensure_ascii=False))


# ------------------------------------------------------------------ konfigurasi
def load_config():
    c = json.loads(json.dumps(DEFAULTS))
    raw = jload(CONF_FILE, {})
    for k, v in raw.items():
        if k in c:
            if isinstance(c[k], dict) and isinstance(v, dict):
                c[k].update(v)
            else:
                c[k] = v
    return c


def valid_path(p):
    return isinstance(p, str) and p.startswith('/') and '\x00' not in p and '..' not in p.split('/') and len(p) < 4000 and p.rstrip('/') != ''


def sanitize_config(patch):
    """Validasi ketat. Return (konfigurasi_baru, galat)."""
    c = load_config()
    if not isinstance(patch, dict):
        return None, 'konfigurasi harus berupa objek'
    for k, v in patch.items():
        if k not in DEFAULTS:
            return None, 'kunci tidak dikenal: %s' % str(k)[:40]
        if k in ('custom_paths', 'skip_vhosts', 'exclude'):
            if not isinstance(v, list) or len(v) > 200:
                return None, '%s harus berupa daftar (maks 200)' % k
            hasil = []
            for x in v:
                if not isinstance(x, str) or not x.strip() or '\x00' in x or '\n' in x or len(x) > 1000:
                    return None, 'entri %s tidak valid' % k
                x = x.strip()
                if k == 'custom_paths':
                    if not valid_path(x):
                        return None, 'path kustom harus absolut tanpa ".." dan bukan "/": %s' % x[:80]
                    if not os.path.exists(x):
                        return None, 'path kustom tidak ada: %s' % x[:80]
                elif k == 'skip_vhosts':
                    if not re.fullmatch(r'[A-Za-z0-9._-]{1,120}', x):
                        return None, 'nama vhost tidak valid: %s' % x[:60]
                if x not in hasil:
                    hasil.append(x)
            c[k] = hasil
        elif k in ('auto_quarantine', 'ionice', 'incremental', 'notify'):
            if not isinstance(v, bool):
                return None, '%s harus true atau false' % k
            c[k] = v
        elif k in ('quarantine_min_score', 'report_min_score'):
            if not isinstance(v, int) or isinstance(v, bool) or v < 50 or v > 100:
                return None, '%s harus bilangan bulat 50..100' % k
            if k == 'quarantine_min_score' and v < 90:
                return None, 'quarantine_min_score tidak boleh di bawah 90 (karantina otomatis hanya untuk putusan webshell)'
            c[k] = v
        elif k in ('throttle_ms', 'nice', 'max_size_mb', 'full_every_days', 'incremental_margin_s'):
            lo, hi = {'throttle_ms': (0, 1000), 'nice': (0, 19), 'max_size_mb': (1, 8), 'full_every_days': (1, 60), 'incremental_margin_s': (0, 3600)}[k]
            if not isinstance(v, int) or isinstance(v, bool) or v < lo or v > hi:
                return None, '%s harus bilangan bulat %d..%d' % (k, lo, hi)
            c[k] = v
        elif k == 'engine':
            if v not in ('auto', 'c', 'python'):
                return None, 'engine harus auto, c, atau python'
            c[k] = v
        elif k == 'entropy':
            if not isinstance(v, dict):
                return None, 'entropy harus berupa objek'
            e = dict(c['entropy'])
            for ek, ev in v.items():
                if ek not in e or not isinstance(ev, (int, float)) or isinstance(ev, bool):
                    return None, 'kunci entropy tidak valid: %s' % str(ek)[:30]
                lim = {'mean': (3.0, 6.0), 'sd': (0.05, 1.5), 'z_flag': (1.0, 10.0), 'z_strong': (1.0, 12.0)}[ek]
                if not (lim[0] <= ev <= lim[1]):
                    return None, 'entropy.%s di luar rentang %s..%s' % (ek, lim[0], lim[1])
                e[ek] = float(ev)
            if e['z_strong'] < e['z_flag']:
                return None, 'z_strong tidak boleh lebih kecil dari z_flag'
            c['entropy'] = e
    return c, None


def save_config(c):
    jsave(CONF_FILE, c)
    try:
        os.chmod(CONF_FILE, 0o640)
    except OSError:
        pass


# ------------------------------------------------------------------ vhost dan root
def vhost_roots():
    """{nama_vhost: root} dari konfigurasi nginx/apache aaPanel dan folder wwwroot (hanya yang ada)."""
    out_ = {}
    for dirp, srv in ((NGINX_VHOST_DIR, 'nginx'), (APACHE_VHOST_DIR, 'apache')):
        if not os.path.isdir(dirp):
            continue
        for f in sorted(os.listdir(dirp)):
            if not f.endswith('.conf') or f.startswith(('0.', 'free_waf', 'phpfpm_status', 'waf2monitor', 'sentinel_waf')):
                continue
            site = f[:-5]
            root = os.path.join(WWWROOT, site)
            try:
                with open(os.path.join(dirp, f), 'r', errors='ignore') as fp:
                    for line in fp:
                        line = line.strip()
                        if line.startswith('root ') and line.endswith(';'):
                            cand = line[5:-1].strip()
                            if os.path.isdir(cand):
                                root = cand
                            break
            except Exception:
                pass
            # docroot sering berupa subfolder (mis. .../public); kode aplikasi (app/, vendor/, storage/) ada di folder
            # proyek di atasnya dan juga bisa disusupi backdoor, jadi yang dipindai adalah folder proyek di bawah wwwroot.
            wr = WWWROOT.rstrip('/') + '/'
            if root.startswith(wr):
                proj = os.path.join(WWWROOT, root[len(wr):].split('/')[0])
                if os.path.isdir(proj) and not os.path.islink(proj):
                    root = proj
            if os.path.isdir(root) and site not in out_:
                out_[site] = root
    if os.path.isdir(WWWROOT):
        for d in sorted(os.listdir(WWWROOT)):
            p = os.path.join(WWWROOT, d)
            if os.path.isdir(p) and not d.startswith('.') and d not in out_ and not os.path.islink(p):
                out_[d] = p
    return out_


def all_roots(cfg):
    roots = []
    for name, root in vhost_roots().items():
        if name in cfg['skip_vhosts']:
            continue
        if root not in [r[1] for r in roots]:
            roots.append((name, root))
    for p in cfg['custom_paths']:
        if os.path.exists(p) and p not in [r[1] for r in roots]:
            roots.append(('kustom:' + p, p))
    return roots


def vhost_of(path, roots):
    best, bl = '-', -1
    for name, root in roots:
        r = root.rstrip('/') + '/'
        if (path + '/').startswith(r) or path == root.rstrip('/'):
            if len(r) > bl:
                best, bl = name, len(r)
    return best


def path_allowed_for_action(path, cfg):
    """Path harus berada di bawah root vhost atau path kustom, tanpa symlink pada direktorinya."""
    if not valid_path(path):
        return False, 'path tidak valid'
    roots = [r[1] for r in all_roots(cfg)]
    d = os.path.dirname(path)
    cur = '/'
    for part in [x for x in d.split('/') if x]:
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            return False, 'path memuat symlink: %s' % cur
    for r in roots:
        rr = r.rstrip('/') + '/'
        if (path + '/').startswith(rr) or path == r.rstrip('/'):
            return True, ''
    return False, 'path di luar vhost dan folder kustom yang dipindai'


# ------------------------------------------------------------------ allowlist (hash)
def allow_entries():
    res = []
    try:
        with open(ALLOW_FILE, 'r', encoding='utf-8', errors='replace') as fp:
            for line in fp:
                line = line.rstrip('\n')
                if not line.strip() or line.lstrip().startswith('#'):
                    continue
                parts = line.split('#', 1)
                h = parts[0].strip().lower()
                if re.fullmatch(r'[0-9a-f]{64}', h):
                    res.append({'sha256': h, 'catatan': parts[1].strip() if len(parts) > 1 else ''})
    except OSError:
        pass
    return res


def allow_add(h, note=''):
    h = h.strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', h):
        return False, 'sha256 tidak valid'
    if any(e['sha256'] == h for e in allow_entries()):
        return True, 'sudah ada'
    os.makedirs(ETC, exist_ok=True)
    with open(ALLOW_FILE, 'a', encoding='utf-8') as fp:
        fp.write('%s  # %s (%s)\n' % (h, note.replace('\n', ' ')[:200], datetime.now().strftime('%Y-%m-%d')))
    try:
        os.chmod(ALLOW_FILE, 0o640)
    except OSError:
        pass
    return True, 'ditambahkan'


def allow_remove(h):
    h = h.strip().lower()
    if not re.fullmatch(r'[0-9a-f]{64}', h):
        return False, 'sha256 tidak valid'
    try:
        with open(ALLOW_FILE, 'r', encoding='utf-8', errors='replace') as fp:
            lines = fp.read().splitlines()
    except OSError:
        return False, 'daftar kosong'
    baru = [l for l in lines if not l.strip().lower().startswith(h)]
    if len(baru) == len(lines):
        return False, 'tidak ditemukan'
    with open(ALLOW_FILE, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(baru) + ('\n' if baru else ''))
    return True, 'dihapus'


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, 'rb') as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ karantina (format sama dengan sentinel-av.sh)
def notif(isi):
    try:
        con = sqlite3.connect(DB_PATH, timeout=5.0)
        con.execute("INSERT INTO notif (ts, ip, jenis, isi, terkirim, coba, galat) VALUES (?, 0, 'sweeper', ?, 0, 0, '')", (now(), isi))
        con.commit()
        con.close()
    except Exception as e:
        log('notifikasi gagal dicatat: %s' % e)


def _open_parent(path):
    """Buka direktori induk lewat rantai O_NOFOLLOW sehingga komponen symlink ditolak dan tidak bisa ditukar saat berjalan."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in [x for x in os.path.dirname(path).split('/') if x]:
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except Exception:
        os.close(fd)
        raise


def quarantine_dirs():
    """Folder karantina yang dibaca tab Karantina AV. sentinel-av.sh memakai folder pustaka ClamAV bersama
    (QUARANTINE_FILES/META di realtime.conf) bila pustaka itu ada, selain itu $BASE/av/quarantine."""
    files = os.path.join(BASE, 'av', 'quarantine', 'files')
    meta = os.path.join(BASE, 'av', 'quarantine', 'meta')
    if os.path.isfile(AV_COMMON) and os.path.isfile(AV_RCONF):
        kv = {}
        try:
            with open(AV_RCONF, 'r', errors='replace') as fp:
                for ln in fp:
                    m = re.match(r'^\s*(QUARANTINE_FILES|QUARANTINE_META)=(.*?)\s*(?:#.*)?$', ln)
                    if m:
                        kv[m.group(1)] = m.group(2).strip().strip('"\'')
        except OSError:
            pass
        f, mt = kv.get('QUARANTINE_FILES'), kv.get('QUARANTINE_META')
        if f and mt and os.path.isdir(f) and os.path.isdir(mt):
            return f, mt
    return files, meta


def quarantine(path, signature, expect_sha=None):
    """Pindahkan berkas ke karantina AV tanpa mengikuti symlink. Return (ok, id_atau_pesan)."""
    import stat as _st
    base = os.path.basename(path)
    try:
        dfd = _open_parent(path)
    except OSError as e:
        return False, 'direktori induk tidak aman atau tidak ada: %s' % e
    try:
        try:
            st = os.stat(base, dir_fd=dfd, follow_symlinks=False)
        except OSError as e:
            return False, 'berkas tidak ada: %s' % e
        if not _st.S_ISREG(st.st_mode):
            return False, 'bukan berkas biasa (symlink atau khusus)'
        try:
            ffd = os.open(base, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except OSError as e:
            return False, 'tidak bisa dibaca: %s' % e
        h = hashlib.sha256()
        with os.fdopen(ffd, 'rb') as fp:
            st = os.fstat(fp.fileno())
            for chunk in iter(lambda: fp.read(1 << 20), b''):
                h.update(chunk)
        sha = h.hexdigest()
        if expect_sha and sha != expect_sha:
            return False, 'berkas berubah sejak dipindai (hash berbeda); pindai ulang'
        ts = now()
        Q_FILES, Q_META = quarantine_dirs()
        os.makedirs(Q_FILES, exist_ok=True)
        os.makedirs(Q_META, exist_ok=True)
        qid = '%d_%s_%s' % (ts, sha[:12], base)
        qpath = os.path.join(Q_FILES, qid)
        if os.path.exists(qpath):
            qid = '%d_%d_%s' % (ts, os.getpid(), base)
            qpath = os.path.join(Q_FILES, qid)
        try:
            try:
                os.rename(base, qpath, src_dir_fd=dfd)
            except OSError:
                src = os.open(base, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
                with os.fdopen(src, 'rb') as fi, open(qpath, 'wb') as fo:
                    shutil.copyfileobj(fi, fo)
                os.unlink(base, dir_fd=dfd)
            os.chmod(qpath, 0o600)
        except Exception as e:
            return False, 'gagal memindahkan: %s' % e
    finally:
        os.close(dfd)
    meta = os.path.join(Q_META, qid + '.meta')
    try:
        with open(meta, 'w', encoding='utf-8', errors='surrogateescape') as fp:
            fp.write('quarantined_at=%s\n' % datetime.now().astimezone().isoformat(timespec='seconds'))
            fp.write('original_path=%s\n' % path)
            fp.write('quarantine_path=%s\n' % qpath)
            fp.write('signature=%s\n' % signature)
            fp.write('sha256=%s\n' % sha)
            fp.write('size=%d\n' % st.st_size)
            fp.write('uid=%d\n' % st.st_uid)
            fp.write('gid=%d\n' % st.st_gid)
            fp.write('mode=%o\n' % (st.st_mode & 0o7777))
        os.chmod(meta, 0o600)
    except Exception as e:
        log('metadata karantina gagal: %s' % e)
    log('DIKARANTINA: %s -> %s (%s)' % (path, qpath, signature))
    return True, qid


# ------------------------------------------------------------------ mesin
def engine_info(cfg=None):
    cfg = cfg or load_config()
    want = cfg.get('engine', 'auto')
    c_ok = os.path.isfile(ENGINE_BIN) and os.access(ENGINE_BIN, os.X_OK)
    ver = ''
    if c_ok:
        try:
            ver = subprocess.run([ENGINE_BIN, '--version'], capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            c_ok = False
    kind = 'c' if (c_ok and want in ('auto', 'c')) else 'python'
    return {'kind': kind, 'c_available': c_ok, 'version': ver, 'want': want, 'path': ENGINE_BIN,
            'gcc': bool(shutil.which('gcc') or shutil.which('cc'))}


def build_engine(force=False):
    """Susun biner C dari sumber (hardening, uji --version), dengan stempel hash sumber."""
    src = None
    for cand in (SRC_C, os.path.join(BIN_DIR, 'sentinel-sweeper.c'), '/www/server/panel/plugin/sentinel/payload/sentinel-sweeper.c'):
        if os.path.isfile(cand):
            src = cand
            break
    if not src:
        return False, 'sumber sentinel-sweeper.c tidak ditemukan'
    want = hashlib.sha256(open(src, 'rb').read()).hexdigest()
    have = ''
    try:
        have = open(SRC_STAMP).read().strip()
    except OSError:
        pass
    if not force and have == want and os.access(ENGINE_BIN, os.X_OK):
        return True, 'sudah mutakhir'
    cc = shutil.which('gcc') or shutil.which('cc')
    if not cc:
        return False, 'gcc tidak tersedia'
    tmp = ENGINE_BIN + '.tmp'
    r = subprocess.run([cc, '-O2', '-std=gnu11', '-Wall', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', '-fPIE', '-pie',
                        '-Wl,-z,relro,-z,now', '-o', tmp, src, '-lm'], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        try: os.remove(tmp)
        except OSError: pass
        log('kompilasi gagal: %s' % r.stderr[-400:])
        return False, 'kompilasi gagal: %s' % r.stderr[-200:]
    try:
        t = subprocess.run([tmp, '--version'], capture_output=True, text=True, timeout=10)
        if t.returncode != 0:
            raise RuntimeError(t.stderr)
    except Exception as e:
        try: os.remove(tmp)
        except OSError: pass
        return False, 'biner hasil kompilasi tidak bisa dijalankan: %s' % e
    os.chmod(tmp, 0o750)
    os.replace(tmp, ENGINE_BIN)
    with open(SRC_STAMP, 'w') as fp:
        fp.write(want + '\n')
    log('biner sweeper disusun dari sumber (%s)' % want[:12])
    return True, 'disusun'


def engine_args(cfg, roots_paths, since=None, compat=False):
    e = cfg['entropy']
    a = [ENGINE_BIN, '--min-score', str(cfg['report_min_score']), '--max-size', str(cfg['max_size_mb'] * 1024 * 1024),
         '--throttle-ms', str(cfg['throttle_ms']), '--nice', str(cfg['nice']), '--progress-sec', '2',
         '--entropy', '%g,%g,%g,%g' % (e['mean'], e['sd'], e['z_flag'], e['z_strong'])]
    for x in cfg['exclude']:
        a += ['--exclude', x]
    if os.path.isfile(ALLOW_FILE):
        a += ['--allow-file', ALLOW_FILE]
    if since:
        a += ['--since', str(int(since))]
    if compat:
        a += ['--compat', '--min-score', '50']
    return a + list(roots_paths)


def python_iter(cfg, roots_paths, since=None, abort_flag=None):
    """Mesin cadangan (lambat): menghasilkan dict dengan format yang sama dengan keluaran C."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('zy_sweeplib', os.path.join(BIN_DIR, 'sentinel-sweeplib.py'))
    sw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sw)
    allow = set(e['sha256'] for e in allow_entries())
    exts = sw.PHP_EXTS | sw.JSP_EXTS | sw.ASP_EXTS | sw.OTHER_EXTS | {'.html', '.htm'}
    maxsz = cfg['max_size_mb'] * 1024 * 1024
    e = cfg['entropy']
    sw.ENT_MEAN, sw.ENT_SD, sw.Z_FLAG, sw.Z_STRONG = e['mean'], e['sd'], e['z_flag'], e['z_strong']
    stats = {'files': 0, 'scanned': 0, 'skipped_large': 0, 'skipped_unreadable': 0, 'excluded': 0, 'flagged': 0,
             'webshell': 0, 'suspicious': 0, 'allowed': 0}
    t0 = time.time(); last = 0
    for root in roots_paths:
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if not any(x in os.path.join(dp, d) + '/' for x in cfg['exclude'])]
            for f in fn:
                if abort_flag and abort_flag():
                    return
                p = os.path.join(dp, f)
                if any(x in p for x in cfg['exclude']):
                    stats['excluded'] += 1
                    continue
                ext = os.path.splitext(f)[1].lower()
                if ext not in exts:
                    continue
                stats['files'] += 1
                try:
                    st = os.lstat(p)
                    if not os.path.isfile(p) or os.path.islink(p) or st.st_size == 0:
                        continue
                    if since and st.st_mtime < since and st.st_ctime < since:
                        continue
                    if st.st_size > maxsz:
                        stats['skipped_large'] += 1
                        continue
                    data = open(p, 'rb').read(sw.MAX_FILE)
                except OSError:
                    stats['skipped_unreadable'] += 1
                    continue
                stats['scanned'] += 1
                r = sw.analyze(p, data, ext)
                if time.time() - last > 2:
                    last = time.time()
                    yield {'progress': {'files': stats['files'], 'scanned': stats['scanned'], 'flagged': stats['flagged'], 'path': p}}
                if cfg['throttle_ms'] and stats['scanned'] % 50 == 0:
                    time.sleep(cfg['throttle_ms'] / 1000.0)
                if r['score'] < cfg['report_min_score']:
                    continue
                h = hashlib.sha256(data if len(data) == st.st_size else open(p, 'rb').read()).hexdigest()
                if h in allow:
                    stats['allowed'] += 1
                    continue
                stats['flagged'] += 1
                stats['webshell' if r['verdict'] == 'webshell' else 'suspicious'] += 1
                yield {'path': p, 'verdict': r['verdict'], 'score': r['score'], 'entropy': r['entropy'], 'size': len(data),
                       'mtime': int(st.st_mtime), 'sha256': h, 'allowed': False,
                       'rules': [[x[0], x[1], x[2]] for x in r['rules']], 'markers': r['markers'][:4]}
    stats.update({'seconds': int(time.time() - t0), 'cpu_seconds': round(time.process_time(), 3), 'max_rss_kb': 0, 'engine': 'python'})
    yield {'summary': stats}


# ------------------------------------------------------------------ job
def running_pid():
    try:
        pid = int(open(PID_FILE).read().strip())
        os.kill(pid, 0)
        with open('/proc/%d/cmdline' % pid, 'rb') as fp:
            if b'sentinel-sweeper' not in fp.read():
                return 0
        return pid
    except Exception:
        return 0


def write_job(**kw):
    j = jload(JOB_FILE, {})
    j.update(kw)
    jsave(JOB_FILE, j)


def do_scan(args):
    cfg = load_config()
    report_only = '--report-only' in args or not cfg['auto_quarantine']
    scheduled = '--scheduled' in args
    full = '--full' in args or not scheduled
    compat = '--compat' in args
    paths = []
    i = 0
    while i < len(args):
        if args[i] == '--path' and i + 1 < len(args):
            paths.append(args[i + 1]); i += 2
        else:
            i += 1
    if running_pid() and running_pid() != os.getpid():
        out({'status': False, 'msg': 'pemindaian lain masih berjalan (PID %d)' % running_pid()})
        return 1
    roots = all_roots(cfg)
    if paths:
        sel = []
        for p in paths:
            ok, why = path_allowed_for_action(p, cfg)
            if not ok or not os.path.exists(p):
                out({'status': False, 'msg': 'path ditolak: %s' % (why or 'tidak ada')})
                return 1
            sel.append((vhost_of(p, roots), p))
        scan_roots = sel
    else:
        scan_roots = roots
    if not scan_roots:
        out({'status': False, 'msg': 'tidak ada folder untuk dipindai'})
        return 1
    ei = engine_info(cfg)
    if ei['kind'] == 'python' and not ei['c_available'] and cfg['engine'] in ('auto', 'c'):
        ok, msg = build_engine()
        if ok:
            ei = engine_info(cfg)
    os.makedirs(SWD, exist_ok=True)
    with open(PID_FILE, 'w') as fp:
        fp.write(str(os.getpid()))
    last = jload(LAST_FILE, {})
    since = None
    if scheduled and cfg['incremental'] and last.get('full_at') and now() - last['full_at'] < cfg['full_every_days'] * 86400:
        since = max(0, last.get('started', 0) - cfg['incremental_margin_s'])
        full = False
    started = now()
    write_job(state='running', pid=os.getpid(), started=started, finished=0, engine=ei['kind'], roots=[r[1] for r in scan_roots],
              progress={'files': 0, 'scanned': 0, 'flagged': 0, 'path': ''}, full=full, report_only=report_only,
              msg='', compat=compat)
    abort = {'v': False}

    def on_term(sig, frm):
        abort['v'] = True
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    root_paths = [r[1] for r in scan_roots]
    findings = jload(FIND_FILE, {})
    summary = None
    quarantined = 0
    seen_paths = set()
    log('pemindaian dimulai (mesin=%s, %d root, full=%s)' % (ei['kind'], len(root_paths), full))
    proc = None
    try:
        if ei['kind'] == 'c':
            cmd = engine_args(cfg, root_paths, since, compat)
            if cfg['ionice'] and shutil.which('ionice'):
                cmd = ['ionice', '-c', '3'] + cmd
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='surrogateescape')
            import threading

            def drain_err():
                for ln in proc.stderr:
                    try:
                        j = json.loads(ln)
                        if 'progress' in j:
                            write_job(progress=j['progress'])
                    except Exception:
                        pass
            threading.Thread(target=drain_err, daemon=True).start()
            stream = (json.loads(l) for l in proc.stdout if l.strip())
        else:
            stream = python_iter(cfg, root_paths, since, lambda: abort['v'])
        compat_hits = []
        for rec in stream:
            if abort['v']:
                if proc:
                    proc.terminate()
                break
            if 'summary' in rec:
                summary = rec['summary']
                continue
            if 'progress' in rec:
                write_job(progress=rec['progress'])
                continue
            path = rec['path'].encode('utf-8', 'surrogateescape').decode('utf-8', 'surrogateescape')
            if compat:
                compat_hits.append({'path': path, 'entropy': rec['entropy'], 'size': rec['size']})
                continue
            seen_paths.add(path)
            vh = vhost_of(path, roots)
            old = findings.get(path)
            ent = {'path': path, 'vhost': vh, 'verdict': rec['verdict'], 'score': rec['score'], 'rules': rec['rules'],
                   'entropy': rec['entropy'], 'size': rec['size'], 'mtime': rec['mtime'], 'sha256': rec['sha256'],
                   'markers': rec.get('markers', []), 'first_seen': (old or {}).get('first_seen', now()), 'last_seen': now(),
                   'status': 'open'}
            if old and old.get('sha256') == rec['sha256'] and old.get('status') == 'ignored':
                ent['status'] = 'ignored'
            if rec['verdict'] == 'webshell' and rec['score'] >= cfg['quarantine_min_score'] and not report_only and ent['status'] == 'open':
                top = sorted(rec['rules'], key=lambda r: -r[1])[0][0] if rec['rules'] else 'webshell'
                ok, res = quarantine(path, 'ZySweep.Webshell.%s' % top, rec['sha256'])
                if ok:
                    ent['status'] = 'quarantined'; ent['quarantine_id'] = res; ent['quarantined_at'] = now(); quarantined += 1
                    if cfg['notify']:
                        notif('Webshell dikarantina oleh Sweeper:\nVhost: %s\nBerkas: %s\nSkor: %s\nIndikator: %s' % (
                            vh, path, rec['score'], ', '.join(r[0] for r in rec['rules'][:4])))
                else:
                    ent['msg'] = res
                    log('karantina gagal %s: %s' % (path, res))
            findings[path] = ent
        if proc:
            try:
                proc.wait(timeout=30)
            except Exception:
                proc.kill()
        # berkas yang tidak muncul lagi pada pemindaian penuh: hasil lama dianggap selesai (berubah/bersih/hilang)
        if full and not paths and not compat and not abort['v'] and summary is not None:
            for p, e in list(findings.items()):
                if e.get('status') == 'open' and p not in seen_paths:
                    e['status'] = 'resolved'; e['resolved_at'] = now()
        if not compat:
            jsave(FIND_FILE, findings)
        elif compat_hits:
            compat_hits.sort(key=lambda x: -x['entropy'])
            jsave(os.path.join(SWD, 'compat.json'), {'at': now(), 'total': len(compat_hits), 'top': compat_hits[:200]})
    except Exception as ex:
        log('pemindaian galat: %s' % ex)
        write_job(state='failed', finished=now(), msg=str(ex)[:300])
        try: os.remove(PID_FILE)
        except OSError: pass
        out({'status': False, 'msg': str(ex)})
        return 1
    state = 'aborted' if abort['v'] else 'done'
    summary = summary or {}
    summary['quarantined'] = quarantined
    res = {'started': started, 'finished': now(), 'engine': ei['kind'], 'full': full, 'summary': summary,
           'roots': root_paths, 'report_only': report_only, 'state': state}
    if not compat and state == 'done':
        if full and not paths:
            res['full_at'] = started
        else:
            res['full_at'] = last.get('full_at', 0)
        jsave(LAST_FILE, res)
        with open(HIST_FILE, 'a', encoding='utf-8') as fp:
            fp.write(json.dumps({'at': now(), 'engine': ei['kind'], 'state': state, 'full': full, 'summary': summary}) + '\n')
    write_job(state=state, finished=now(), summary=summary, msg='')
    try: os.remove(PID_FILE)
    except OSError: pass
    log('pemindaian %s: %s' % (state, json.dumps(summary)))
    out({'status': True, 'msg': res})
    return 0


# ------------------------------------------------------------------ perintah lain
def finding_list(flt=None):
    f = jload(FIND_FILE, {})
    rows = [e for e in f.values() if e.get('status') != 'resolved']
    if flt:
        rows = [e for e in rows if e.get('status') == flt or e.get('verdict') == flt]
    rows.sort(key=lambda e: (-e.get('score', 0), e.get('path', '')))
    return rows


def do_action(act, path):
    cfg = load_config()
    f = jload(FIND_FILE, {})
    e = f.get(path)
    if not e:
        return False, 'temuan tidak ada: %s' % path[:80]
    if act in ('quarantine', 'allow'):
        ok, why = path_allowed_for_action(path, cfg)
        if not ok:
            return False, why
    if act == 'quarantine':
        if e.get('status') == 'quarantined':
            return False, 'sudah dikarantina'
        top = sorted(e.get('rules', []), key=lambda r: -r[1])[0][0] if e.get('rules') else e.get('verdict', 'manual')
        ok, res = quarantine(path, 'ZySweep.%s.%s' % ('Webshell' if e.get('verdict') == 'webshell' else 'Suspicious', top), e.get('sha256'))
        if ok:
            e.update({'status': 'quarantined', 'quarantine_id': res, 'quarantined_at': now()})
            jsave(FIND_FILE, f)
        return ok, ('dikarantina: %s' % res) if ok else res
    if act == 'allow':
        try:
            sha = sha256_file(path)
        except OSError as ex:
            return False, 'tidak bisa dibaca: %s' % ex
        if sha != e.get('sha256'):
            return False, 'berkas berubah sejak dipindai; pindai ulang sebelum menandai sah'
        ok, msg = allow_add(sha, path)
        if ok:
            e['status'] = 'allowed'
            jsave(FIND_FILE, f)
        return ok, msg
    if act == 'ignore':
        e['status'] = 'ignored'
        jsave(FIND_FILE, f)
        return True, 'diabaikan (hash yang sama tidak dilaporkan lagi)'
    if act == 'unignore':
        e['status'] = 'open'
        jsave(FIND_FILE, f)
        return True, 'dibuka kembali'
    return False, 'aksi tidak dikenal'


def do_status():
    cfg = load_config()
    j = jload(JOB_FILE, {})
    pid = running_pid()
    if j.get('state') == 'running' and not pid:
        j['state'] = 'failed'; j['msg'] = 'proses pemindaian berhenti tanpa hasil'
    roots = all_roots(cfg)
    f = finding_list()
    cnt = {'webshell': 0, 'suspicious': 0, 'open': 0, 'quarantined': 0, 'ignored': 0, 'allowed': 0}
    for e in f:
        st = e.get('status')
        if st in cnt:
            cnt[st] += 1
        if st == 'open' and e.get('verdict') in cnt:
            cnt[e['verdict']] += 1
    sched = os.path.exists(SCHEDULE_FLAG)
    return {'engine': engine_info(cfg), 'config': cfg, 'job': j, 'running': bool(pid), 'last': jload(LAST_FILE, {}),
            'roots': [{'vhost': r[0], 'path': r[1]} for r in roots], 'counts': cnt, 'allow_count': len(allow_entries()),
            'schedule': sched, 'compat': jload(os.path.join(SWD, 'compat.json'), {})}


def do_calibrate(path):
    cfg = load_config()
    ok, why = path_allowed_for_action(path, cfg)
    if not ok:
        return False, why
    ei = engine_info(cfg)
    if ei['kind'] != 'c':
        return False, 'kalibrasi memerlukan mesin C (jalankan: sentinel-sweeper.py build)'
    r = subprocess.run([ENGINE_BIN, '--quiet', '--nice', '10', path], capture_output=True, text=True, timeout=3600)
    try:
        s = json.loads(r.stdout.strip().splitlines()[-1])['summary']
    except Exception:
        return False, 'keluaran mesin tidak terbaca'
    n, mean, sd = s.get('php_entropy_n', 0), s.get('php_entropy_mean', 0), s.get('php_entropy_sd', 0)
    if n < 300:
        return False, 'terlalu sedikit berkas PHP (%d); butuh minimal 300 berkas PHP yang SAH untuk kalibrasi' % n
    if s.get('flagged', 0) > 0:
        return False, 'folder memuat %d berkas yang ditandai; kalibrasi hanya boleh pada pohon yang diyakini bersih' % s['flagged']
    c, err = sanitize_config({'entropy': {'mean': round(mean, 4), 'sd': round(max(sd, 0.05), 4)}})
    if err:
        return False, err
    save_config(c)
    return True, {'mean': round(mean, 4), 'sd': round(sd, 4), 'n': n}


def do_schedule(mode):
    if mode == 'status':
        return True, {'enabled': os.path.exists(SCHEDULE_FLAG)}
    if mode not in ('on', 'off'):
        return False, 'gunakan on, off, atau status'
    os.makedirs(ETC, exist_ok=True)
    if mode == 'on' and not os.environ.get('ZYS_SWEEPER_BASE'):
        # unit systemd belum ada (plugin diperbarui tanpa pasang ulang): salin dari payload plugin
        for u in ('sentinel-sweeper.service', TIMER):
            dst = '/etc/systemd/system/' + u
            for src in (os.path.join(BIN_DIR, 'systemd', u), '/www/server/panel/plugin/sentinel/payload/systemd/' + u):
                if not os.path.exists(dst) and os.path.isfile(src):
                    shutil.copy2(src, dst)
                    os.chmod(dst, 0o644)
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
    if mode == 'on':
        open(SCHEDULE_FLAG, 'w').write(str(now()))
        r = subprocess.run(['systemctl', 'enable', '--now', TIMER], capture_output=True, text=True)
    else:
        try: os.remove(SCHEDULE_FLAG)
        except OSError: pass
        r = subprocess.run(['systemctl', 'disable', '--now', TIMER], capture_output=True, text=True)
    if r.returncode != 0 and not os.environ.get('ZYS_SWEEPER_BASE'):
        return False, (r.stderr or r.stdout).strip()[:200] or 'systemctl gagal'
    return True, {'enabled': mode == 'on'}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'status'
    rest = sys.argv[2:]
    if cmd == 'scan':
        sys.exit(do_scan(rest))
    elif cmd == 'status':
        out({'status': True, 'msg': do_status()})
    elif cmd == 'findings':
        out({'status': True, 'msg': finding_list(rest[0] if rest else None)})
    elif cmd == 'action' and len(rest) >= 2:
        ok, m = do_action(rest[0], rest[1])
        out({'status': ok, 'msg': m})
    elif cmd == 'validate-path' and rest:
        ok, why = path_allowed_for_action(rest[0], load_config())
        out({'status': ok and os.path.exists(rest[0]), 'msg': why or ('tidak ada: %s' % rest[0][:80] if not os.path.exists(rest[0]) else 'ok')})
    elif cmd == 'allow-list':
        out({'status': True, 'msg': allow_entries()})
    elif cmd == 'allow-add' and rest:
        t = rest[0]
        if os.path.isfile(t):
            try:
                t = sha256_file(t)
            except OSError as e:
                out({'status': False, 'msg': str(e)}); return
        ok, m = allow_add(t, rest[1] if len(rest) > 1 else 'manual')
        out({'status': ok, 'msg': m})
    elif cmd == 'allow-remove' and rest:
        ok, m = allow_remove(rest[0])
        out({'status': ok, 'msg': m})
    elif cmd == 'config':
        out({'status': True, 'msg': load_config()})
    elif cmd == 'config-set' and rest:
        try:
            patch = json.loads(rest[0])
        except Exception:
            out({'status': False, 'msg': 'JSON tidak valid'}); return
        c, err = sanitize_config(patch)
        if err:
            out({'status': False, 'msg': err}); return
        save_config(c)
        out({'status': True, 'msg': c})
    elif cmd == 'calibrate' and rest:
        ok, m = do_calibrate(rest[0])
        out({'status': ok, 'msg': m})
    elif cmd == 'build':
        ok, m = build_engine('--force' in rest)
        out({'status': ok, 'msg': m})
    elif cmd == 'abort':
        pid = running_pid()
        if pid:
            os.kill(pid, signal.SIGTERM)
        out({'status': True, 'msg': 'dihentikan' if pid else 'tidak ada pemindaian berjalan'})
    elif cmd == 'schedule':
        ok, m = do_schedule(rest[0] if rest else 'status')
        out({'status': ok, 'msg': m})
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == '__main__':
    main()
