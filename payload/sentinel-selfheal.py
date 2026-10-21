#!/usr/bin/env python3
# ==============================================================================
# sentinel-selfheal.py
#
# Penjaga pemulihan mandiri (self-heal) untuk layanan milik ZySentinel dan layanan turunan yang
# dibutuhkannya (clamd, freshclam, clamav-realtime). Dijalankan timer systemd tiap 60 detik
# (satu proses singkat, bukan daemon yang menetap).
#
# Pembagian tugas dengan systemd:
#   - systemd (Restart=on-failure + RestartSteps/RestartMaxDelaySec + StartLimitBurst) memulihkan
#     crash biasa dengan jeda yang makin panjang, lalu BERHENTI mencoba (unit berstatus failed)
#     bila terlalu sering crash. Jadi tidak ada putaran restart tanpa akhir.
#   - skrip ini mengambil alih setelah itu: unit failed dicoba lagi dengan JEDA MAKIN PANJANG
#     (2, 5, 10, 20, 40, 60 menit), paling banyak 12 kali per 24 jam, lalu MENYERAH dan memberi
#     tahu operator satu kali. Layanan yang masih "active" tetapi macet (tidak menjawab / tidak
#     memperbarui detak) di-restart setelah 3 pemeriksaan gagal berturut-turut.
#
# Yang TIDAK dilakukan: unit yang dihentikan operator (inactive, hasil sukses) dibiarkan;
# unit yang tidak di-enable dibiarkan; log hanya ditulis saat keadaan berubah (tidak membanjiri).
#
# Pemakaian: sentinel-selfheal.py [run|check|status|reset [unit]|pause|resume]
# ==============================================================================
import os
import sys
import json
import time
import socket
import sqlite3
import subprocess

BASE = os.environ.get('ZYS_SELFHEAL_BASE', '/www/server/sentinel')   # variabel hanya untuk pengujian
STATE_FILE = BASE + '/run/selfheal.json'
LOG_FILE = BASE + '/log/selfheal.log'
CONF_FILE = BASE + '/etc/selfheal.json'
PAUSE_FILE = BASE + '/etc/selfheal.pause'
DB_PATH = BASE + '/data/guardd.db'
LOG_MAX = 512 * 1024

DEFAULTS = {
    'enabled': True,
    'cooldowns': [120, 300, 600, 1200, 2400, 3600],   # detik, jeda antar percobaan pemulihan
    'max_attempts_24h': 12,
    'probe_fail_limit': 3,                            # pemeriksaan gagal berturut-turut sebelum restart
    'healthy_reset_s': 600,                           # sehat selama ini = hitungan percobaan direset
    'notify_min_gap_s': {'pulih': 3600, 'gagal': 21600, 'menyerah': 86400},   # jeda minimal notifikasi serupa per unit
    'exclude': [],
    'services': None,          # daftar unit pengganti (pengujian); None = daftar bawaan SERVICES
}

# Urutan penting: unit yang diandalkan unit lain ditulis lebih dulu (dipulihkan lebih dulu).
SERVICES = [
    {'unit': 'sentinel.service', 'probe': ('file', 'run/status.json', 30), 'grace': 60},
    {'unit': 'clamav-daemon.service', 'probe': ('clamd',), 'grace': 240},
    {'unit': 'clamav-freshclam.service'},
    {'unit': 'sentinel-proc.service', 'probe': ('file', 'run/proc_guard.state', 30), 'grace': 60},
    {'unit': 'sentinel-upload-scan.service', 'probe': ('file', 'run/upload_scan.state', 30), 'grace': 60},
    {'unit': 'clamav-realtime.service'},
    {'unit': 'sentinel-fw.timer'},
    {'unit': 'sentinel-notify.timer'},
    {'unit': 'sentinel-av.timer'},
    {'unit': 'sentinel-intel.timer'},
]
CLAMD_SOCKETS = ('/var/run/clamav/clamd.ctl', '/run/clamav/clamd.ctl', '/var/run/clamd.scan/clamd.sock')


class Heal:
    def __init__(self, sh=None, now=None, mono=None, probes=None, conf=None, state=None, notify=None, log=None, dry=False):
        self.settle = 0 if sh else 3           # jeda sesudah start sebelum memeriksa hasilnya
        self.sh = sh or self._sh
        self.now = now or time.time
        self.mono = mono or (lambda: time.clock_gettime(time.CLOCK_MONOTONIC))
        self.probes = probes or {'clamd': self.probe_clamd, 'file': self.probe_file}
        self.conf = dict(DEFAULTS)
        self.conf.update(conf if conf is not None else self._load_json(CONF_FILE, {}))
        self.state = state if state is not None else self._load_json(STATE_FILE, {})
        self._notify = notify or self._notify_db
        self._log = log or self._log_file
        self.dry = dry
        self.events = []          # (unit, teks): untuk pengujian dan ringkasan

    # ---------------------------------------------------------------- utilitas
    @staticmethod
    def _load_json(p, d):
        try:
            with open(p) as fp:
                v = json.load(fp)
            return v if isinstance(v, type(d)) else d
        except Exception:
            return d

    @staticmethod
    def _sh(cmd, timeout=60):
        try:
            p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 124, '', 'timeout'
        except Exception as e:
            return 1, '', str(e)

    def _log_file(self, msg):
        line = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.now())) + ' [selfheal] ' + msg
        try:
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX:
                os.replace(LOG_FILE, LOG_FILE + '.1')           # satu salinan lama, tidak menumpuk
            with open(LOG_FILE, 'a', encoding='utf-8') as fp:
                fp.write(line + '\n')
        except Exception:
            pass
        print(line)

    def log(self, unit, msg):
        self.events.append((unit, msg))
        self._log('%s: %s' % (unit, msg))

    def _notify_db(self, msg):
        try:
            con = sqlite3.connect(DB_PATH, timeout=5.0)
            con.execute("INSERT INTO notif (ts, ip, jenis, isi, terkirim, coba, galat) VALUES (?, 0, 'selfheal', ?, 0, 0, '')",
                        (int(self.now()), '[ZYSENTINEL SELF-HEAL] ' + msg))
            con.commit()
            con.close()
        except Exception as e:
            self._log('notifikasi gagal dicatat: %s' % e)

    def notif(self, unit, st, kind, msg):
        """Notifikasi dibatasi: satu jenis per unit per notify_min_gap_s."""
        last = st.setdefault('last_notify', {})
        gap = self.conf['notify_min_gap_s']
        gap = gap.get(kind, 3600) if isinstance(gap, dict) else gap
        if self.now() - last.get(kind, 0) < gap:
            return
        last[kind] = self.now()
        if not self.dry:
            self._notify('%s: %s' % (unit, msg))

    # ---------------------------------------------------------------- keadaan unit
    def show(self, unit):
        rc, o, _ = self.sh('systemctl show %s --property=LoadState,ActiveState,SubState,Result,UnitFileState,NRestarts,ActiveEnterTimestampMonotonic' % unit, 20)
        d = {}
        for ln in o.splitlines():
            if '=' in ln:
                k, v = ln.split('=', 1)
                d[k] = v
        return d

    def uptime(self, d):
        try:
            t = int(d.get('ActiveEnterTimestampMonotonic', '0')) / 1e6
            return self.mono() - t if t > 0 else 0
        except Exception:
            return 0

    # ---------------------------------------------------------------- probe kesehatan
    def probe_clamd(self, unit):
        for s in CLAMD_SOCKETS:
            if os.path.exists(s):
                c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    c.settimeout(5)
                    c.connect(s)
                    c.sendall(b'zPING\0')
                    return c.recv(64).startswith(b'PONG')
                except Exception:
                    return False
                finally:
                    c.close()
        return False

    def probe_file(self, unit, rel, maks_umur):
        try:
            return self.now() - os.path.getmtime(os.path.join(BASE, rel)) <= maks_umur
        except OSError:
            return False

    def sehat(self, svc, d):
        pr = svc.get('probe')
        if not pr:
            return True
        if self.uptime(d) < svc.get('grace', 60):
            return True                      # baru mulai (clamd memuat basis data): jangan dinilai dulu
        fn = self.probes.get(pr[0])
        return bool(fn(svc['unit'], *pr[1:])) if fn else True

    # ---------------------------------------------------------------- pemulihan
    def aksi(self, svc, st, d, alasan, restart):
        unit = svc['unit']
        now = self.now()
        att = [t for t in st.get('attempts', []) if now - t < 86400]
        st['attempts'] = att
        if st.get('gave_up') and len(att) < self.conf['max_attempts_24h']:
            st['gave_up'] = False
        if len(att) >= self.conf['max_attempts_24h']:
            if not st.get('gave_up'):
                st['gave_up'] = True
                self.log(unit, 'MENYERAH: %d percobaan pemulihan dalam 24 jam tidak berhasil (%s). Periksa: journalctl -u %s -n 50; setelah diperbaiki jalankan: sentinel-selfheal.py reset %s' % (len(att), alasan, unit, unit))
                self.notif(unit, st, 'menyerah', 'layanan tidak bisa dipulihkan otomatis (%d percobaan/24 jam): %s' % (len(att), alasan))
            return False
        if now < st.get('next_try', 0):
            return False
        cd = self.conf['cooldowns']
        idx = min(st.get('idx', 0), len(cd) - 1)
        st['next_try'] = now + cd[idx]
        st['idx'] = idx + 1
        att.append(now)
        self.log(unit, 'pemulihan #%d (%s): %s' % (len(att), alasan, 'restart' if restart else 'reset-failed + start'))
        if self.dry:
            return True
        if not restart:
            self.sh('systemctl reset-failed %s' % unit, 20)
        self.sh('systemctl %s %s' % ('restart' if restart else 'start', unit), 150)
        if self.settle:
            time.sleep(self.settle)
        d2 = self.show(unit)
        if d2.get('ActiveState') in ('active', 'activating'):
            self.log(unit, 'pulih: ActiveState=%s' % d2.get('ActiveState'))
            self.notif(unit, st, 'pulih', 'dipulihkan otomatis (%s)' % alasan)
            st['healthy_since'] = None
            return True
        self.log(unit, 'belum pulih: ActiveState=%s Result=%s; percobaan berikut paling cepat %d detik lagi' % (d2.get('ActiveState'), d2.get('Result'), cd[idx]))
        self.notif(unit, st, 'gagal', 'pemulihan otomatis gagal (%s); mencoba lagi dengan jeda makin panjang' % alasan)
        return False

    def periksa(self, svc):
        unit = svc['unit']
        if unit in self.conf.get('exclude', []):
            return 'dikecualikan'
        d = self.show(unit)
        if d.get('LoadState') != 'loaded':
            return 'tidak-ada'
        if d.get('UnitFileState') not in ('enabled', 'enabled-runtime'):
            return 'tidak-enabled'
        st = self.state.setdefault(unit, {})
        act, sub = d.get('ActiveState'), d.get('SubState')
        now = self.now()
        status = act
        if act == 'failed':
            status = 'failed'
            self.aksi(svc, st, d, 'unit failed (Result=%s, systemd berhenti mencoba)' % d.get('Result'), restart=False)
        elif act == 'activating' and sub == 'auto-restart':
            status = 'systemd-mengulang'
        elif act == 'active':
            if self.sehat(svc, d):
                st['probe_fail'] = 0
                if not st.get('healthy_since'):
                    st['healthy_since'] = now
                if st.get('healthy_since') and now - st['healthy_since'] >= self.conf['healthy_reset_s'] and (st.get('attempts') or st.get('idx')):
                    self.log(unit, 'sehat %d detik: hitungan percobaan direset' % self.conf['healthy_reset_s'])
                    st.update({'attempts': [], 'idx': 0, 'next_try': 0, 'gave_up': False})
            else:
                st['probe_fail'] = st.get('probe_fail', 0) + 1
                st['healthy_since'] = None
                status = 'tidak-merespons'
                if st['probe_fail'] >= self.conf['probe_fail_limit']:
                    if self.aksi(svc, st, d, 'tidak merespons %d pemeriksaan berturut-turut' % st['probe_fail'], restart=True):
                        st['probe_fail'] = 0
        if st.get('last_status') != status:
            if st.get('last_status') is not None:
                self.log(unit, 'status: %s -> %s' % (st.get('last_status'), status))
            st['last_status'] = status
        return status

    def tick(self):
        if not self.conf.get('enabled', True) or os.path.exists(PAUSE_FILE):
            return {}
        hasil = {}
        for svc in (self.conf.get('services') or SERVICES):
            try:
                hasil[svc['unit']] = self.periksa(svc)
            except Exception as e:
                self._log('galat memeriksa %s: %s' % (svc['unit'], e))
        if not self.dry:
            self.simpan()
        return hasil

    def simpan(self):
        try:
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            tmp = STATE_FILE + '.tmp'
            with open(tmp, 'w') as fp:
                json.dump(self.state, fp)
            os.replace(tmp, STATE_FILE)
        except Exception:
            pass


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'run'
    if cmd in ('run', 'check'):
        h = Heal(dry=(cmd == 'check'))
        r = h.tick()
        if cmd == 'check':
            print(json.dumps(r, indent=1))
    elif cmd == 'status':
        h = Heal()
        out = {}
        for svc in SERVICES:
            u = svc['unit']
            d = h.show(u)
            if d.get('LoadState') != 'loaded':
                continue
            st = h.state.get(u, {})
            out[u] = {'active': d.get('ActiveState'), 'sub': d.get('SubState'), 'enabled': d.get('UnitFileState'),
                      'nrestarts': d.get('NRestarts'), 'percobaan_24j': len([t for t in st.get('attempts', []) if time.time() - t < 86400]),
                      'menyerah': bool(st.get('gave_up')), 'probe_gagal': st.get('probe_fail', 0),
                      'percobaan_berikut': max(0, int(st.get('next_try', 0) - time.time()))}
        print(json.dumps({'dijeda': os.path.exists(PAUSE_FILE), 'unit': out}, indent=1))
    elif cmd == 'reset':
        h = Heal()
        unit = sys.argv[2] if len(sys.argv) > 2 else None
        for u in list(h.state):
            if unit is None or u == unit or u == unit + '.service':
                h.state[u].update({'attempts': [], 'idx': 0, 'next_try': 0, 'gave_up': False, 'probe_fail': 0})
        h.simpan()
        print('hitungan percobaan direset: %s' % (unit or 'semua unit'))
    elif cmd == 'pause':
        open(PAUSE_FILE, 'w').write(str(int(time.time())))
        print('pemulihan mandiri dijeda (hapus %s atau jalankan resume)' % PAUSE_FILE)
    elif cmd == 'resume':
        try:
            os.remove(PAUSE_FILE)
        except OSError:
            pass
        print('pemulihan mandiri dilanjutkan')
    else:
        print('Pemakaian: %s [run|check|status|reset [unit]|pause|resume]' % sys.argv[0])
        sys.exit(2)


if __name__ == '__main__':
    main()
