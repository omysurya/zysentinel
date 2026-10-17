# -*- coding: utf-8 -*-
"""Plugin panel untuk ZySentinel.

ZySentinel adalah sistem monitoring dan firewall untuk server aaPanel.
Plugin ini hanya antarmuka: seluruh keputusan ada di daemon guardd
(bahasa C) dan aturan kernel (iptables + ipset). Plugin tidak pernah
menghitung skor atau memutuskan pemblokiran sendiri, supaya tidak ada
dua sumber kebenaran yang bisa berbeda pendapat.
"""
import sys
import os
import re
import json
import time
import subprocess
import socket
import hashlib
import platform
import sqlite3
import urllib.request
import urllib.parse

if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')
os.chdir('/www/server/panel')

import public
if not hasattr(public, 'returnMsg'):
    public.returnMsg = lambda status, msg: {'status': bool(status), 'msg': msg}
try:
    if __name__ != '__main__':
        from panelAuth import panelAuth
except Exception:
    panelAuth = None


def _angka_json(teks, kunci):
    """Ambil satu angka dari balasan JSON daemon.

    Balasan guardctl sudah berbentuk JSON, jadi lebih aman dibaca dengan
    json.loads daripada dengan pencarian potongan teks. Kalau parsing
    gagal, kembalikan None supaya pemanggil bisa memutuskan sendiri apa
    yang ditampilkan, bukan menebak dari string.
    """
    try:
        nilai = json.loads(teks).get(kunci)
    except Exception:
        return None
    if isinstance(nilai, bool) or not isinstance(nilai, (int, float)):
        return None
    return int(nilai)


class sentinel_main(object):
    __PATH = '/www/server/sentinel/'

    # ------------------------------------------------------------------ #
    # penjaga keamanan endpoint & otentikasi                             #
    # ------------------------------------------------------------------ #
    def _enforce_security_guard(self, method_name, get):
        """Pemeriksaan ketat otentikasi, proteksi intercept, anti-CSRF, dan sanitisasi.

        Menjamin endpoint tidak dapat di-bypass via request langsung tanpa login yang sah,
        mencegah manipulasi lintas domain (CSRF/Origin/Referer), dan memblokir upaya injeksi.
        """
        try:
            from flask import request, session, has_request_context, g
            if not has_request_context():
                # Pemanggilan internal via CLI, cron, atau pengujian lokal server
                return True, ''
        except Exception:
            return True, ''

        # 1. Otentikasi Sah aaPanel: wajib ada sesi login aktif
        if not session or not session.get('login'):
            return False, 'Akses ditolak: sesi tidak terotentikasi, silakan login ke aaPanel'

        # 2. Batas waktu sesi (session timeout)
        st = session.get('session_timeout', 0)
        if st and st < time.time():
            return False, 'Akses ditolak: sesi telah kedaluwarsa, silakan login ulang'

        # 3. Proteksi Intercept (Enkripsi Channel): jika panel ber-SSL, cegah koneksi HTTP polos
        # Di aaPanel, port panel mendengarkan langsung via SSL/TLS (termasuk sertifikat self-signed IP).
        # Request diteruskan secara lokal ke socket unix, sehingga scheme WSGI internal bernilai 'http'.
        # Tolak bila ada indikasi eksplisit koneksi HTTP polos eksternal (misal proxy atau referer/origin berawalan http://).
        if os.path.isfile('/www/server/panel/data/ssl.pl'):
            fwd_proto = (request.headers.get('X-Forwarded-Proto') or '').lower()
            origin = request.headers.get('Origin', '')
            referer = request.headers.get('Referer', '')
            if fwd_proto == 'http':
                return False, 'Akses ditolak: koneksi tidak terenkripsi, gunakan HTTPS'
            if origin and origin.lower().startswith('http://'):
                return False, 'Akses ditolak: koneksi tidak terenkripsi, gunakan HTTPS'
            if referer and referer.lower().startswith('http://'):
                return False, 'Akses ditolak: koneksi tidak terenkripsi, gunakan HTTPS'

        # 4. Validasi Cross-Origin / Referer (Anti pencurian sesi dan request palsu)
        def _get_host_name(h):
            if not h:
                return ''
            if '://' in h:
                h = h.split('://', 1)[1]
            h = h.split('/', 1)[0]
            if ':' in h:
                h = h.split(':', 1)[0]
            return h.strip().lower()

        host_name = _get_host_name(getattr(request, 'host', ''))
        origin = request.headers.get('Origin', '')
        referer = request.headers.get('Referer', '')
        if origin:
            orig_host = _get_host_name(origin)
            if orig_host and host_name and orig_host != host_name:
                return False, 'Akses ditolak: Origin lintas domain tidak diizinkan'
        elif referer:
            ref_host = _get_host_name(referer)
            if ref_host and host_name and ref_host != host_name:
                return False, 'Akses ditolak: Referer lintas domain tidak diizinkan'

        # 5. Anti-CSRF Token: Periksa token jika bukan panggilan API ber-kunci
        is_api = getattr(g, 'api_request', False)
        if not is_api:
            expected_csrf = ''
            if hasattr(public, 'get_csrf_sess_html_token_value'):
                try:
                    expected_csrf = public.get_csrf_sess_html_token_value()
                except Exception:
                    pass
            if expected_csrf:
                client_csrf = request.headers.get('x-http-token') or request.headers.get('X-Http-Token')
                if not client_csrf and get:
                    client_csrf = getattr(get, 'x_http_token', None) or getattr(get, 'request_token', None)
                if not client_csrf:
                    client_csrf = request.cookies.get('request_token')
                if not client_csrf or client_csrf != expected_csrf:
                    return False, 'Akses ditolak: verifikasi token anti-CSRF gagal'

        # 6. Sanitisasi Parameter Masukan
        if get:
            for k in dir(get):
                if k.startswith('_'):
                    continue
                val = getattr(get, k, None)
                if isinstance(val, str):
                    if '\x00' in val:
                        return False, 'Akses ditolak: karakter null byte dilarang'
                    if k in ('path', 'target', 'file', 'target_path'):
                        if '..' in val or val.startswith('//'):
                            return False, 'Akses ditolak: path traversal tidak diizinkan'

        return True, ''

    def __getattribute__(self, name):
        attr = super(sentinel_main, self).__getattribute__(name)
        if name.startswith('_') or not callable(attr):
            return attr

        def secure_api_wrapper(get=None, *args, **kwargs):
            ok, err_msg = self._enforce_security_guard(name, get)
            if not ok:
                return public.returnMsg(False, err_msg)
            return attr(get, *args, **kwargs)

        return secure_api_wrapper

    # ------------------------------------------------------------------ #
    # pembantu                                                           #
    # ------------------------------------------------------------------ #
    def _p(self, *parts):
        return os.path.join(self.__PATH, *parts)

    def _db(self):
        """Jalur database. Dibaca dari guardd.conf supaya tetap sinkron
        dengan yang dipakai daemon, tidak ditebak ulang di sini."""
        conf = self._p('etc', 'guardd.conf')
        db = self._p('data', 'guardd.db')
        try:
            with open(conf, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('db_path'):
                        return line.split('=', 1)[1].strip()
        except Exception:
            pass
        return db

    def _sql(self, query, args=()):
        """Jalankan kueri SQLite lewat sqlite3 CLI.

        Sengaja tidak memakai modul sqlite3 python supaya tidak
       bersaing dengan daemon yang sedang menulis ke berkas sama.
        WAL dan busy timeout sudah disiapkan daemon."""
        try:
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.row_factory = sqlite3.Row
            cur = con.execute(query, args)
            rows = [dict(r) for r in cur.fetchall()]
            con.close()
            return rows
        except Exception as e:
            return public.returnMsg(False, 'kueri basis data gagal: %s' % str(e))

    def _sql1(self, query, args=()):
        """Satu baris saja, atau None.

        Dipakai untuk pembacaan nilai tunggal DAN untuk penulisan
        satu baris. Karena itu WAJIB commit. Tanpa commit, setiap
        INSERT atau UPDATE yang lewat sini dibatalkan saat koneksi
        ditutup: perintahnya terlihat berhasil, tidak ada galat,
        tapi tidak ada yang berubah. Itu penyebab status review tidak
        pernah berubah dari "tunggu".
        """
        try:
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.row_factory = sqlite3.Row
            cur = con.execute(query, args)
            row = cur.fetchone()
            if con.in_transaction:
                con.commit()
            con.close()
            return dict(row) if row else None
        except Exception:
            return None

    @staticmethod
    def _only(get, kunci, bawaan, panjang=64):
        """Ambil satu nilai teks, dipotong ke panjang aman.

        Nilai dari parameter bisa berisi apa saja. Dipotong supaya
        tidak ada baris tambahan yang bisa menyisipkan kunci konfigurasi
        palsu ke berkas.
        """
        v = get.get(kunci)
        if v is None:
            v = bawaan
        v = str(v).strip()
        if not v:
            v = bawaan
        v = v.replace('\n', ' ').replace('"', '')
        return v[:panjang]

    @staticmethod
    def _int(get, kunci, bawaan, minimal=None, maksimal=None):
        """Baca bilangan bulat dari parameter, aman untuk string maupun int.

        Pola ini muncul berulang di seluruh endpoint. Panel sering
        mengirim angka dari input numerik, sedangkan panggilan dari
        skrip sering mengirim teks. Menganggap keduanya string membuat
        galat AttributeError yang tampil mentah sebagai galat 500.
        """
        mentah = get.get(kunci)
        if isinstance(mentah, str):
            mentah = mentah.strip()
        if mentah is None or mentah == '':
            n = bawaan
        else:
            try:
                n = int(mentah)
            except (TypeError, ValueError):
                return None
        if minimal is not None and n < minimal:
            return None
        if maksimal is not None and n > maksimal:
            return None
        return n

    def _notif(self, jenis, isi, ip=''):
        """Tulis satu baris ke antrean notifikasi dari sisi panel.

        Dipakai untuk aksi yang tidak melewati daemon, yaitu panic.
        Ban dan throttle otomatis sudah ditulis daemon sendiri, jadi
        ditulis lagi di sini akan menjadi dua notifikasi untuk satu
        kejadian yang sama.
        """
        try:
            n = self._ipnum(ip) if ip else 0
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.execute(
                'INSERT INTO notif(ts,ip,jenis,isi) VALUES(?,?,?,?)',
                (int(time.time()), n, jenis, isi[:500]))
            con.commit()
            con.close()
            return True
        except Exception:
            return False

    def _aksi(self, ip, aksi, sumber, alasan='', detik=0):
        """Catat satu tindakan terhadap IP ke tabel aksi.

        Kegagalan menulis TIDAK boleh membatalkan tindakan aslinya.
        Ban yang sudah masuk ipset tetapi gagal dicatat ke audit hanya
        berarti catatannya kurang, bukan blokirannya gagal. Karena itu
        error sengaja tidak dikembalikan ke pemanggil.
        """
        try:
            n = self._ipnum(ip)
            if not n:
                return False
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.execute(
                'INSERT INTO aksi(ts,ip,aksi,sumber,alasan,detik)'
                ' VALUES(?,?,?,?,?,?)',
                (int(time.time()), n, aksi, sumber, alasan or '-', int(detik)))
            con.commit()
            con.close()
            return True
        except Exception:
            return False

    def _status(self):
        """Baca status.json yang ditulis daemon setiap detak."""
        try:
            with open(self._p('run', 'status.json'), 'r') as f:
                return json.load(f)
        except Exception:
            return None

    def _sh(self, cmd, timeout=30):
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            o, e = p.communicate(timeout=timeout)
            return p.returncode, o.decode('utf-8', 'replace'), \
                e.decode('utf-8', 'replace')
        except Exception as ex:
            return 1, '', str(ex)

    def _svc(self, name):
        rc, o, e = self._sh('systemctl is-active %s' % name, 15)
        return o.strip() if rc == 0 else 'tidak aktif'

    def _self_ip(self):
        """Alamat publik server ini.

        public.get_local_ip() tidak dipakai: di server ini fungsi itu
        mengembalikan string kosong karena mencoba mengambil alamat dari
        layanan luar. Yang dipakai justru cara yang sama dengan guardd,
        yaitu membaca daftar antarmuka dan memilih alamat routable."""
        alamat = []
        try:
            with open('/proc/net/fib_trie') as f:
                isi = f.read()
            for baris in isi.splitlines():
                b = baris.strip()
                if b.startswith('32 host LOCAL'):
                    continue
                if '/32 host' in b and b.split('/32 host')[0].strip():
                    alamat.append(b.split('/32 host')[0].strip())
        except Exception:
            pass
        if not alamat:
            rc, o, _ = self._sh("ip -4 -o addr show scope global | "
                                "awk '{print $4}' | cut -d/ -f1", 10)
            alamat = o.split()
        for ip in alamat:
            if ip.startswith('127.') or ip.startswith('169.254.'):
                continue
            return ip
        return alamat[0] if alamat else '127.0.0.1'

    def _ipnum(self, ip):
        try:
            parts = ip.strip().split('.')
            if len(parts) != 4:
                return 0
            v = 0
            for p in parts:
                n = int(p)
                if n < 0 or n > 255:
                    return 0
                v = (v << 8) | n
            return v
        except Exception:
            return 0

    def _numip(self, v):
        try:
            v = int(v) & 0xFFFFFFFF
            return '%d.%d.%d.%d' % ((v >> 24) & 255, (v >> 16) & 255,
                                    (v >> 8) & 255, v & 255)
        except Exception:
            return str(v)

    # ------------------------------------------------------------------ #
    # tampilan utama                                                     #
    # ------------------------------------------------------------------ #
    def _get_security_totals(self):
        """Hitung total penyerang unik, total ancaman (threats), dan total virus."""
        attackers = 0
        threats = 0
        virus = 0
        try:
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=5)
            cur = con.cursor()
            try:
                r_ev = cur.execute('SELECT COUNT(*), COUNT(DISTINCT ip) FROM events').fetchone()
                if r_ev:
                    threats += (r_ev[0] or 0)
                    attackers += (r_ev[1] or 0)
            except Exception:
                pass
            try:
                r_proc = cur.execute('SELECT COUNT(*) FROM proc_alerts').fetchone()
                if r_proc:
                    threats += (r_proc[0] or 0)
            except Exception:
                pass
            try:
                r_vq = cur.execute('SELECT COUNT(*) FROM vhost_quarantine').fetchone()
                if r_vq:
                    virus += (r_vq[0] or 0)
            except Exception:
                pass
            con.close()
        except Exception:
            pass

        # Tambahkan deteksi dari file scan ClamAV per vhost
        try:
            all_scan = self._p('av', 'last', 'all.json')
            if os.path.isfile(all_scan):
                with open(all_scan, 'r', encoding='utf-8') as f:
                    v_data = json.load(f)
                    virus += v_data.get('total_found', 0)
        except Exception:
            pass

        # Fallback bans bila events kosong
        st = self._status()
        if st:
            b_tot = st.get('bans_total', 0)
            if b_tot > attackers:
                attackers = b_tot

        return attackers, threats, virus

    def get_status(self, get):
        """Ringkasan untuk dasbor: kondisi daemon, angka lalu lintas,
        dan status tiga lapis pertahanan."""
        st = self._status()
        if st is None:
            return public.returnMsg(False, 'guardd tidak menulis status.json; '
                                         'daemon belum berjalan')
        guardd = self._svc('sentinel.service')
        timer = self._svc('sentinel-fw.timer')
        rc_c, _, _ = self._sh('iptables -C IN_BT -j SENTINEL 2>/dev/null || iptables -C INPUT -j SENTINEL 2>/dev/null || iptables -L SENTINEL -n 2>/dev/null', 5)
        if rc_c == 0 or timer == 'active':
            fw = 'active'
        else:
            fw = self._svc('sentinel-fw.service')
        self_ip = self._self_ip()

        tot_attackers, tot_threats, tot_virus = self._get_security_totals()
        if st is not None:
            st['total_attackers'] = tot_attackers
            st['total_threats'] = tot_threats
            st['total_virus'] = tot_virus

        return public.returnMsg(True, {
            'status': st,
            'guardd_service': guardd,
            'fw_service': fw,
            'fw_timer': timer,
            'enforce': st.get('enforce', 0),
            'self_ip': self_ip,
            'rss_mb': round(st.get('rss_kb', 0) / 1024.0, 1),
            'total_attackers': tot_attackers,
            'total_threats': tot_threats,
            'total_virus': tot_virus,
        })

    # cache CPU. Persentase CPU butuh dua pembacaan /proc/stat dengan
    # jeda di antaranya. Dasbor sendiri menyegarkan tiap 10 detik, jadi
    # tanpa cache setiap penyegaran akan menahan 0,2 detik.
    _cpu_cache = {'pada': 0, 'nilai': 0.0}

    def _cpu_persen(self, maks_tunggu=0):
        """Persentase pemakaian CPU, atau nilai cache bila masih segar.

        Tidakblocking kalau maks_tunggu 0 dan cache masih dipakai ulang,
        sehingga penyegaran dasbor tidak tertahan.
        """
        sekarang = time.time()
        if maks_tunggu <= 0 and (sekarang - self._cpu_cache['pada']) < 6:
            return self._cpu_cache['nilai']

        def baca():
            try:
                with open('/proc/stat', 'r') as f:
                    bagian = f.readline().split()
                v = [int(x) for x in bagian[1:]]
                idle = v[3] + (v[4] if len(v) > 4 else 0)
                return sum(v), idle
            except Exception:
                return None
        t1 = baca()
        if not t1:
            return self._cpu_cache['nilai']
        if maks_tunggu <= 0:
            # Mode cepat: tanpa jeda, hasilnya kurang presisi tapi cukup
            # untuk indikator. Jeda nyata diambil saat cache sudah kedaluwarsa.
            t2 = t1
        else:
            time.sleep(0.25)
            t2 = baca()
            if not t2:
                return self._cpu_cache['nilai']
        d_total = t2[0] - t1[0]
        d_idle = t2[1] - t1[1]
        nilai = 0.0
        if d_total > 0:
            nilai = round(100.0 * (d_total - d_idle) / d_total, 1)
        self._cpu_cache['pada'] = sekarang
        self._cpu_cache['nilai'] = nilai
        return nilai

    def get_sysinfo(self, get):
        """Ringkasan mesin untuk panel System di dasbor.

        Sengaja dipisah dari get_status: isinya berubah jauh lebih
        lambat dan tidak perlu ikut dihitung pada setiap penyegaran
        grafik yang sering.
        """
        st = self._status() or {}
        info = {}

        # sistem operasi
        osnama = 'Linux'
        versi = ''
        try:
            with open('/etc/os-release', 'r') as f:
                for baris in f:
                    baris = baris.strip()
                    if baris.startswith('PRETTY_NAME='):
                        osnama = baris.split('=', 1)[1].strip().strip('"')
                        break
        except Exception:
            pass
        info['os'] = osnama
        info['kernel'] = os.uname().release

        # uptime mesin dan uptime daemon
        try:
            with open('/proc/uptime', 'r') as f:
                detik = float(f.read().split()[0])
            info['uptime_mesin'] = self._durat(detik)
        except Exception:
            info['uptime_mesin'] = '-'
        info['uptime_daemon'] = self._durat(st.get('uptime', 0))

        # beban rata-rata
        rc, o, e = self._sh("awk '{print $1\" \"$2\" \"$3}' /proc/loadavg", 10)
        info['load'] = o.strip() or '-'
        try:
            with open('/proc/cpuinfo', 'r') as f:
                info['core'] = sum(1 for l in f if l.startswith('processor'))
        except Exception:
            info['core'] = 0

        info['cpu'] = self._cpu_persen(maks_tunggu=1)

        # memori
        try:
            with open('/proc/meminfo', 'r') as f:
                isi = dict((l.split(':')[0], l.split()[1])
                           for l in f if ':' in l)
            total = float(isi.get('MemTotal', 0)) / 1024.0
            tersedia = float(isi.get('MemAvailable', 0)) / 1024.0
            dipakai = total - tersedia
            info['mem_total'] = round(total, 0)
            info['mem_pakai'] = round(dipakai, 0)
            info['mem_persen'] = round(100.0 * dipakai / total, 1) if total else 0.0
        except Exception:
            info['mem_total'] = 0
            info['mem_pakai'] = 0
            info['mem_persen'] = 0.0

        st_ver = st.get('version')
        if not st_ver or str(st_ver).strip() in ('1.0.0', '1.6', '1.6.0', '1.6.1', '-'):
            info['versi'] = 'v1.6.1'
        else:
            info['versi'] = str(st_ver) if str(st_ver).lower().startswith('v') else ('v' + str(st_ver))
        info['pid'] = st.get('pid', 0)
        info['host'] = st.get('hosts', 0)
        info['ip'] = self._self_ip()
        return public.returnMsg(True, info)

    def _durat(self, detik):
        """Ubah detik menjadi teks yang enak dibaca."""
        try:
            d = int(detik)
        except Exception:
            return '-'
        if d <= 0:
            return '-'
        h = d // 3600
        m = (d % 3600) // 60
        s = d % 60
        if h:
            return '%d d %d h %d m' % (h, m, s)
        if m:
            return '%d m %d s' % (m, s)
        return '%d s' % s

    def get_chart(self, get):
        """Deret waktu untuk grafik dasbor.

        req: jumlah request per menit per situs.
        kode status per menit."""
        jam = int(get.get('hours', 24) or 24)
        if jam < 1:
            jam = 1
        if jam > 168:
            jam = 168
        sejak = int(time.time()) - jam * 3600

        rows = self._sql(
            "SELECT ts, host, SUM(req) req, SUM(bytes) bytes, "
            "SUM(s2) s2, SUM(s3) s3, SUM(s4) s4, SUM(s5) s5, SUM(s429) s429 "
            "FROM minute WHERE ts >= ? GROUP BY ts ORDER BY ts ASC",
            (sejak,))
        agg = {}
        total = {}
        for r in rows:
            m = int(r['ts'])
            agg.setdefault(m, {'req': 0, 'bytes': 0, 's2': 0, 's3': 0,
                               's4': 0, 's5': 0, 's429': 0, 'hosts': {}})
            for k in ('req', 'bytes', 's2', 's3', 's4', 's5', 's429'):
                agg[m][k] += r[k] or 0
            agg[m]['hosts'][r['host']] = r['req'] or 0
            total[r['host']] = total.get(r['host'], 0) + (r['req'] or 0)

        events = self._sql(
            "SELECT ts, kind, level, COUNT(*) n FROM events "
            "WHERE ts >= ? GROUP BY ts, kind", (sejak,))

        return public.returnMsg(True, {
            'series': [{'ts': m, 'v': v} for m, v in sorted(agg.items())],
            'hosts': sorted(total.items(), key=lambda x: -x[1]),
            'events': [{'ts': int(e['ts']), 'kind': e['kind'],
                        'level': e['level'], 'n': e['n']} for e in events],
        })

    # ------------------------------------------------------------------ #
    # daftar ban dan throttle                                            #
    # ------------------------------------------------------------------ #
    def get_bans(self, get):
        """Daftar blokir yang masih berlaku, digabung dengan riwayat."""
        st = self._status() or {}
        aktif = []
        for b in st.get('bans', []):
            b = dict(b)
            b['ip'] = self._numip(b.get('ip', 0))
            b['sisa'] = max(0, int(b.get('until', 0)) - int(time.time()))
            aktif.append(b)

        riwayat = self._sql(
            "SELECT b.ip, b.kind, b.score, b.start, b.until, b.offenses, "
            "b.reason FROM bans b WHERE b.until >= ? "
            "ORDER BY b.until DESC LIMIT 200", (int(time.time()),))
        for r in riwayat:
            r['ip'] = self._numip(r['ip'])
            r['sisa'] = max(0, int(r['until']) - int(time.time()))

        rc, o, e = self._sh('ipset list sentinel_ban 2>/dev/null | '
                            "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        set_ban = [x for x in o.split() if x]
        rc, o, e = self._sh('ipset list sentinel_throttle 2>/dev/null | '
                            "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        set_thr = [x for x in o.split() if x]

        return public.returnMsg(True, {
            'aktif': aktif,
            'riwayat': riwayat,
            'set_ban': set_ban,
            'set_throttle': set_thr,
            'enforce': st.get('enforce', 0),
        })

    def ban_ip(self, get):
        """Blokir satu IP sekarang juga lewat soket daemon."""
        ip = (get.get('ip') or '').strip()
        if not ip or self._ipnum(ip) == 0:
            return public.returnMsg(False, 'alamat IP tidak valid')
        # Durasi harus diperiksa eksplisit, bukan sekadar int() yang
        # dibungkus-or. Dua kegagalan nyata muncul dari cara lama:
        #   - "abc" membuat int() melempar galat, dan traceback-nya
        #     tampil mentah di halaman panel.
        #   - "-5" dianggap benar oleh int(), lalu dibuang diam-diam
        #     oleh "if secs > 0", sehingga ban berjalan memakai durasi
        #     bawaan sementara layar tetap menampilkan "berhasil".
        # Yang kedua lebih berbahaya karena tidak ada tanda apa pun.
        mentah = (get.get('secs') or '').strip()
        secs = 0
        if mentah:
            if not mentah.isdigit():
                return public.returnMsg(
                    False, 'durasi harus angka bulat nonnegative')
            secs = int(mentah)
            if secs <= 0:
                return public.returnMsg(
                    False, 'durasi harus lebih besar dari nol')
        args = ['%s/bin/guardctl' % self.__PATH, 'ban', ip]
        if secs > 0:
            args.append(str(secs))
        rc, o, e = self._sh(
            ' '.join(["'%s'" % a for a in args]), 20)
        if rc != 0 or '"ok":true' not in o:
            return public.returnMsg(False, 'gagal memblokir: %s'
                                    % (o.strip() or e.strip()))
        # Daemon membalas dengan keadaan sebenarnya, jadi yang ditampilkan
        # ke pengguna bukan sekadar "perintah terkirim" tetapi apa yang
        # benar-benar terjadi di kernel.
        if '"dalam_ipset":true' not in o:
            return public.returnMsg(
                False, 'IP dicatat di daftar blokir ZySentinel, tetapi TIDAK '
                       'masuk ipset kernel sehingga belum benar-benar '
                       'diblokir')
        # Tampilkan durasi yang benar-benar dipakai daemon, bukan yang
        # diketik pengguna. Kalau keduanya berbeda, angka yang diketik
        # tidak berlaku dan itu harus terlihat.
        #
        # Status tetap berhasil karena ban memang sudah terjadi. Melapor
        # galat di sini akan menyesatkan: di layar operator terlihat
        # seperti pemblokiran gagal, padahal ipset sudah terisi.
        dipakai = _angka_json(o, 'detik')
        # CATATAN: ban tidak dicatat di sini. Perintah "ban" sudah
        # dicatat oleh daemon di tabel aksi, jadi mencatatnya lagi di
        # sini akan menghasilkan dua baris untuk satu tindakan yang
        # sama. unban juga sama: dicatat daemon lewat ban_remove.
        if dipakai and secs > 0 and dipakai != secs:
            # Penyebab paling umum adalah nilai yang diminta melewati
            # ban_seconds_max, jadi Causes_hint disebut apa adanya tanpa
            # mengklaim pasti.
            return public.returnMsg(
                True, '%s diblokir dan masuk ipset kernel, durasi %d detik. '
                      'Durasi %d detik yang diminta TIDAK berlaku; angka '
                      'yang dipakai adalah yang dibatasi daemon '
                      '(ban_seconds_max).'
                      % (ip, dipakai, secs))
        if dipakai:
            return public.returnMsg(
                True, '%s diblokir dan masuk ipset kernel, durasi %d detik'
                      % (ip, dipakai))
        return public.returnMsg(True, '%s diblokir dan masuk ipset kernel' % ip)

    def unban_ip(self, get):
        """Lepas blokir dan hapus dari allowlist supaya tidak diblokir lagi."""
        ip = (get.get('ip') or '').strip()
        if not ip or self._ipnum(ip) == 0:
            return public.returnMsg(False, 'alamat IP tidak valid')
        rc, o, e = self._sh(
            "'%s/bin/guardctl' unban '%s'" % (self.__PATH, ip), 20)
        if rc != 0 or '"ok":true' not in o:
            return public.returnMsg(False, 'gagal melepas blokir: %s'
                                    % (o.strip() or e.strip()))
        return public.returnMsg(True, '%s dilepas dari daftar blokir' % ip)

    # ------------------------------------------------------------------ #
    # daftar putih                                                       #
    # ------------------------------------------------------------------ #
    def _allow_path(self):
        return self._p('etc', 'allowlist.txt')

    def get_allow(self, get):
        isi = []
        alamat_server = self._self_ip()
        try:
            with open(self._allow_path(), 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    isi.append(line)
        except Exception:
            pass
        rc, o, e = self._sh('ipset list aapanel.ipv4.whitelist 2>/dev/null | '
                            "sed -n 's/^\\([0-9.]*\\).*/\\1/p'", 15)
        return public.returnMsg(True, {
            'daftar': isi,
            'panel': [x for x in o.split() if x],
            'alamat_server': alamat_server,
            'jumlah': len(isi),
        })

    def allow_ip(self, get):
        """Tambahkan ke daftar putih permanen."""
        ip = (get.get('ip') or '').strip()
        if not ip or self._ipnum(ip) == 0:
            return public.returnMsg(False, 'alamat IP tidak valid')
        rc, o, e = self._sh(
            "'%s/bin/guardctl' allow '%s'" % (self.__PATH, ip), 20)
        if rc != 0 or '"ok":true' not in o:
            return public.returnMsg(False, 'gagal menambah: %s'
                                    % (o.strip() or e.strip()))
        # aturan iptables perlu dipasang ulang supaya whitelist langsung
        # berlaku di kernel, bukan menunggu timer lima menit.
        self._sh("'%s/bin/sentinel-fw.sh' install" % self.__PATH, 60)
        self._aksi(ip, 'allow', 'panel', 'ditambahkan ke daftar putih')
        return public.returnMsg(True, '%s masuk daftar putih' % ip)

    def del_allow(self, get):
        """Keluarkan dari daftar putih permanen."""
        ip = (get.get('ip') or '').strip()
        if not ip:
            return public.returnMsg(False, 'alamat IP tidak valid')
        path = self._allow_path()
        try:
            with open(path, 'r') as f:
                baris = f.readlines()
        except Exception as ex:
            return public.returnMsg(False, 'gagal membaca daftar putih: %s' % ex)
        sisa = [b for b in baris if b.split('#')[0].strip() != ip]
        if len(sisa) == len(baris):
            return public.returnMsg(False, '%s tidak ada di daftar putih' % ip)
        with open(path, 'w') as f:
            f.writelines(sisa)
        self._sh("'%s/bin/sentinel-fw.sh' install" % self.__PATH, 60)
        self._sh("'%s/bin/guardctl' rescan" % self.__PATH, 20)
        self._aksi(ip, 'del-allow', 'panel',
                   'dikeluarkan dari daftar putih, blokir lama berlaku lagi')
        return public.returnMsg(True, '%s dikeluarkan dari daftar putih' % ip)

    # ------------------------------------------------------------------ #
    # pengaturan                                                         #
    # ------------------------------------------------------------------ #
    def get_conf(self, get):
        """Ambang skor dan bobot, plus status-mode enforcement."""
        st = self._status() or {}
        kunci = ['enforce', 'watch_score', 'throttle_score', 'ban_score',
                 'weight_scan', 'weight_brute', 'weight_badua',
                 'weight_distinct', 'cap_scan', 'cap_brute', 'cap_badua',
                 'cap_distinct', 'ban_seconds', 'ban_seconds_max',
                 'max_ips', 'rescan_interval', 'startup_backfill',
                 'throttle_rps', 'throttle_burst', 'throttle_rpm']
        nilai = dict((k, st.get(k)) for k in kunci)
        isi = {}
        try:
            with open(self._p('etc', 'guardd.conf'), 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        isi[k.strip()] = v.strip()
        except Exception:
            pass
        for k in kunci:
            if k in isi:
                nilai[k] = isi[k]
        return public.returnMsg(True, nilai)

    def set_conf(self, get):
        """Ubah satu nilai konfigurasi.

        Nilai laju (throttle_rps, throttle_rpm, throttle_burst) dibaca
        sentinel-fw.sh, bukan guardd. Jadi tidak butuh restart daemon,
        cukup pasang ulang aturan kernel. Memaksa restart daemon untuk
        ketiga nilai itu hanya menambah downtime tanpa ada gunanya.

        Kunci lain tetap perlu restart karena guardd membaca konfigurasi
        satu kali saat start.
        """
        kunci_laju = ['throttle_rps', 'throttle_rpm', 'throttle_burst']
        kunci_boleh = ['watch_score', 'throttle_score', 'ban_score',
                       'weight_scan', 'weight_brute', 'weight_badua',
                       'weight_distinct', 'cap_scan', 'cap_brute',
                       'cap_badua', 'cap_distinct', 'ban_seconds',
                       'ban_seconds_max', 'max_ips', 'rescan_interval',
                       'startup_backfill', 'enforce'] + kunci_laju
        k = (get.get('key') or '').strip()
        v = (get.get('value') or '').strip()
        if k not in kunci_boleh:
            return public.returnMsg(False, 'kunci tidak dikenal: %s' % k)
        if not v.isdigit():
            return public.returnMsg(False, 'nilai harus angka bulat')

        # throttle_rps = 0 membuat aturan per detik tidak masuk akal,
        # dan throttle_rpm dibatasi 100000 supaya tidak ada angka
        # gila yang lolos ke iptables.
        if k == 'throttle_rps' and int(v) < 1:
            return public.returnMsg(
                False, 'throttle_rps minimal 1. Nilai 0 membuat throttle '
                       'berhenti bekerja tanpa sengaja')
        if k in ('throttle_rpm', 'throttle_burst') and int(v) > 100000:
            return public.returnMsg(False, 'nilai maksimal 100000')

        rc, o, e = self._sh(
            "'%s/bin/guardctl' set '%s' '%s'" % (self.__PATH, k, v), 30)
        if rc != 0:
            return public.returnMsg(False, 'gagal menulis: %s'
                                    % (e.strip() or o.strip()))

        if k in kunci_laju:
            # Aturan kernel perlu dipasang ulang supaya nilai baru
            # langsung berlaku. Kalau ini gagal, nilai SUDAH tersimpan
            # di guardd.conf tapi belum berlaku di kernel. Melapor
            # gagal lebih jujur daripada diam-diam bilang berhasil.
            rc2, o2, e2 = self._sh(
                "'%s/bin/sentinel-fw.sh' install" % self.__PATH, 90)
            if rc2 != 0:
                return public.returnMsg(
                    False, '%s diubah menjadi %s di guardd.conf, tetapi '
                           'pemasangan aturan kernel GAGAL: %s. Nilai belum '
                           'berlaku sampai install berhasil.'
                           % (k, v, (e2.strip() or o2.strip())))
            return public.returnMsg(
                True, '%s = %s, aturan kernel sudah dipasang ulang'
                      % (k, v))

        # semua nilai lain dibaca sekali saat daemon mulai
        self._sh('systemctl restart sentinel.service', 60)
        return public.returnMsg(True, '%s diubah menjadi %s, daemon '
                                    'direstart' % (k, v))

    # ------------------------------------------------------------------ #
    # panic: blokir / lepas seluruh akses web                             #
    # ------------------------------------------------------------------ #
    def get_panic(self, get):
        """Keadaan panic sekarang.

        Keadaan dibaca dua sumber dan digabung: aturan iptables yang
        benar-benar ada di kernel, dan berkas penanda yang ditulis
        skrip. Keduanya dipakai karena bisa berbeda, misalnya kernel
        masih dibebani aturan panic sementara penanda sudah hilang.
        Penanda boleh hilang saat reboot, jadi hanya iptables yang
        dianggap kebenaran; penanda dipakai untuk menampilkan
        kapan panic dinyalakan.
        """
        rc, o, e = self._sh(
            "'%s/bin/sentinel-fw.sh' panic-status" % self.__PATH, 30)
        aktif = (rc == 0)
        info = {'aktif': aktif, 'ports': '', 'since': '', 'baris': []}
        for baris in o.strip().splitlines():
            b = baris.strip()
            if b.startswith('ports='):
                info['ports'] = b.split('=', 1)[1]
            elif b.startswith('since='):
                info['since'] = b.split('=', 1)[1]
            elif b.startswith('-A'):
                info['baris'].append(b)
        info['pesan'] = o.strip() if o.strip() else e.strip()
        return public.returnMsg(True, info)

    def set_panic(self, get):
        """Nyalakan atau cabut blokir seluruh akses web.

        HATI-HATI: menyalakan panic membuat SEMUA situs di server ini
        tidak dapat diakses. Yang tetap bisa: SSH, port panel, whitelist,
        dan jaringan privat. Itu disengaja supaya operator masih bisa
        mencabut panic.
        """
        aksi = (get.get('action') or '').strip()
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'aksi tidak dikenal')
        if aksi == 'off':
            rc, o, e = self._sh(
                "'%s/bin/guardctl' panic-off" % self.__PATH, 60)
            if rc != 0:
                return public.returnMsg(False, 'gagal mencabut panic: %s'
                                        % (e.strip() or o.strip()))
            self._notif('panic-selesai',
                       'Panic dicabut. Akses web sudah normal kembali.')
            return public.returnMsg(True, o.strip() or 'panic dicabut')

        # Konfirmasi harus datang dari sisi server, bukan hanya dari
        # checkbox di layar. Kalau hanya andalkan UI, satu klik keliru
        # atau satu permintaan otomatis bisa mematikan semua situs.
        #
        # Pencocokan sengaja TIDAK mengabaikan huruf besar-kecil. Aksi ini
        # mematikan seluruh situs di server, jadi operator sewajarnya benar-benar
        # menyalin kata PANIC, bukan mengetik "panic" dengan autopilot.
        konfirmasi = (get.get('confirm') or '').strip()
        if konfirmasi != 'PANIC':
            return public.returnMsg(
                False, 'konfirmasi tidak cocok. Ketik PANIC dengan huruf '
                       'besar semua di kolom konfirmasi')
        rc, o, e = self._sh("'%s/bin/guardctl' panic-on" % self.__PATH, 90)
        if rc != 0:
            return public.returnMsg(False, 'gagal menyalakan panic: %s'
                                    % (e.strip() or o.strip()))
        self._notif('panic',
                    'PANIC AKTIF. Seluruh akses web diblokir. '
                    'Situs tidak dapat diakses sampai panic dicabut.')
        return public.returnMsg(True, o.strip() or 'panic aktif')

    # ------------------------------------------------------------------ #
    # kendali daemon dan firewall                                        #
    # ------------------------------------------------------------------ #
    def service_action(self, get):
        aksi = (get.get('action') or '').strip()
        peta = {'start': 'start', 'stop': 'stop', 'restart': 'restart'}
        if aksi not in peta:
            return public.returnMsg(False, 'aksi tidak dikenal')
        rc, o, e = self._sh('systemctl %s sentinel.service' % peta[aksi], 60)
        if rc != 0:
            return public.returnMsg(False, 'gagal: %s' % (e.strip() or o.strip()))
        return public.returnMsg(True, 'sentinel.service %s' % aksi)

    def fw_action(self, get):
        aksi = (get.get('action') or '').strip()
        if aksi not in ('install', 'remove', 'flush'):
            return public.returnMsg(False, 'aksi tidak dikenal')
        rc, o, e = self._sh("'%s/bin/sentinel-fw.sh' %s"
                            % (self.__PATH, aksi), 90)
        if aksi == 'remove':
            self._sh('systemctl stop sentinel-fw.timer', 20)
        return public.returnMsg(True, o.strip() or e.strip() or 'selesai')

    def get_fw(self, get):
        """Isi chain kernel, isi set, dan penghitung paket."""
        rc, chain, e = self._sh('iptables -S SENTINEL 2>/dev/null', 20)
        rc2, order, _ = self._sh("iptables -S INPUT | grep -nE "
                                 "'aapanel|IN_BT'", 20)
        rc3, hooks, _ = self._sh('iptables -S IN_BT 2>/dev/null', 20)
        rc4, cnt, _ = self._sh('iptables -L SENTINEL -n -v 2>/dev/null', 20)
        rc5, sets, _ = self._sh(
            'for s in sentinel_ban sentinel_throttle; do '
            'printf "%s " "$s"; ipset list $s 2>/dev/null | '
            "sed -n 's/^Number of entries: //p'; done", 20)
        jml = {}
        for baris in sets.strip().splitlines():
            bagian = baris.split()
            if len(bagian) == 2:
                jml[bagian[0]] = bagian[1]
        return public.returnMsg(True, {
            'chain': chain.strip().splitlines() if chain.strip() else [],
            'urutan_input': order.strip().splitlines() if order.strip() else [],
            'in_bt': hooks.strip().splitlines() if hooks.strip() else [],
            'penghitung': [x for x in cnt.splitlines()
                           if 'sentinel:' in x],
            'jumlah_set': jml,
            'terpasang': bool(chain.strip()),
        })

    def get_fw_rules(self, get):
        """Aturan terkelola Sentinel dalam satu daftar: ban, allow, geo.

        Digabung di sini supaya tab Firewall punya SATU sumber untuk
        tabel CRUD, bukan tiga permintaan terpisah yang bisa berbeda
        waktu. Isinya dibaca dari keadaan yang sudah ada (get_bans,
        get_allow, get_geo_ban); tidak ada yang menyentuh kernel.
        """
        hasil = []
        # --- ban: dari daftar blokir aktif + ipset ---
        b = self.get_bans(get)
        if isinstance(b, dict) and b.get('status'):
            msg = b['msg']
            sudah = set()
            for x in msg.get('aktif', []):
                ip = x.get('ip')
                sudah.add(ip)
                hasil.append({
                    'rule': ip, 'type': 'ban', 'scope': 'ip',
                    'reason': x.get('reason') or x.get('kind') or '-',
                    'sisa': int(x.get('sisa') or 0),
                    'sumber': 'guardd',
                })
            # ipset bisa berisi IP yang tidak ada di status.json
            for ip in msg.get('set_ban', []):
                if ip not in sudah:
                    hasil.append({'rule': ip, 'type': 'ban', 'scope': 'ip',
                                  'reason': 'ipset ban', 'sisa': 0,
                                  'sumber': 'kernel'})
        # --- allow ---
        a = self.get_allow(get)
        if isinstance(a, dict) and a.get('status'):
            for ip in a['msg'].get('daftar', []):
                hasil.append({'rule': ip, 'type': 'allow', 'scope': 'ip',
                              'reason': 'daftar putih', 'sisa': 0,
                              'sumber': 'guardd'})
            for ip in a['msg'].get('panel', []):
                hasil.append({'rule': ip, 'type': 'allow', 'scope': 'ip',
                              'reason': 'daftar putih panel', 'sisa': 0,
                              'sumber': 'panel'})
        # --- geo ---
        g = self.get_geo_ban(get)
        if isinstance(g, dict) and g.get('status'):
            gm = g['msg']
            if gm.get('mode') and gm['mode'] != 'off':
                for kode in gm.get('negara_daftar', []):
                    hasil.append({
                        'rule': kode, 'type': 'geo',
                        'scope': gm.get('mode') or 'block',
                        'reason': '%d blok CIDR' % int(gm.get('blok') or 0),
                        'sisa': 0, 'sumber': 'kernel',
                    })
        return public.returnMsg(True, hasil)

    def rescan(self, get):
        rc, o, e = self._sh("'%s/bin/guardctl' rescan" % self.__PATH, 20)
        return public.returnMsg(True, o.strip() or 'penemuan ulang diminta')

    # ------------------------------------------------------------------ #
    # Port Access Control (Inbound & Outbound Firewall)                    #
    # ------------------------------------------------------------------ #
    PORTS_CONF = '/www/server/sentinel/etc/ports.json'
    PROC_WHITELIST_CONF = '/www/server/sentinel/etc/proc_whitelist.json'

    def _ports_script(self, action):
        """Panggil helper biner sentinel-ports.py."""
        bin_path = '%s/bin/sentinel-ports.py' % self.__PATH
        if not os.path.isfile(bin_path):
            bin_path = '/www/server/sentinel/bin/sentinel-ports.py'
        rc, o, e = self._sh("python3 '%s' %s" % (bin_path, action), 20)
        return rc, o, e

    def get_port_firewall(self, get):
        """Membaca daftar aturan port Inbound & Outbound dan status kernel."""
        rc, o, e = self._ports_script('status')
        try:
            data = json.loads(o)
            return public.returnMsg(True, data)
        except Exception as ex:
            self._ports_script('init')
            rc2, o2, _ = self._ports_script('status')
            try:
                data2 = json.loads(o2)
                return public.returnMsg(True, data2)
            except Exception:
                return public.returnMsg(False, 'Gagal memuat status port firewall: %s' % (e or str(ex)))

    def add_port_rule(self, get):
        """Menambahkan aturan port baru (Inbound atau Outbound)."""
        direction = (get.get('direction') or 'inbound').strip().lower()
        if direction not in ['inbound', 'outbound']:
            return public.returnMsg(False, 'Arah aturan harus inbound atau outbound')

        protocol = (get.get('protocol') or 'tcp').strip().lower()
        if protocol not in ['tcp', 'udp', 'tcp/udp', 'all']:
            protocol = 'tcp'

        port = (get.get('port') or '').strip()
        if not port:
            return public.returnMsg(False, 'Nomor port atau rentang port wajib diisi')
        clean_port = port.replace(':', '-')
        if not re.match(r'^[0-9]+(-[0-9]+)?$', clean_port) and clean_port.lower() != 'all':
            return public.returnMsg(False, 'Format port tidak valid (contoh: 80 atau 8000-8080)')

        if clean_port.lower() != 'all':
            parts = clean_port.split('-')
            for p_str in parts:
                p_val = int(p_str)
                if p_val < 1 or p_val > 65535:
                    return public.returnMsg(False, 'Nomor port harus berada di antara 1 dan 65535')
            if len(parts) == 2 and int(parts[0]) >= int(parts[1]):
                return public.returnMsg(False, 'Rentang port tidak valid (port awal harus lebih kecil)')

        action = (get.get('action') or 'ACCEPT').strip().upper()
        if action not in ['ACCEPT', 'DROP']:
            action = 'ACCEPT'

        source = (get.get('source') or '0.0.0.0/0').strip()
        dest = (get.get('dest') or '0.0.0.0/0').strip()
        remark = (get.get('remark') or '').strip()
        if not remark:
            remark = '%s Port %s' % (protocol.upper(), clean_port)

        try:
            if not os.path.isfile(self.PORTS_CONF):
                self._ports_script('init')
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception:
            self._ports_script('init')
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)

        rule_id = '%s-%d' % ('in' if direction == 'inbound' else 'out', int(time.time()))
        new_rule = {
            'id': rule_id,
            'port': clean_port,
            'protocol': protocol,
            'action': action,
            'remark': remark,
            'system': False,
            'enabled': True
        }
        if direction == 'inbound':
            new_rule['source'] = source
            cfg.setdefault('inbound', []).append(new_rule)
        else:
            new_rule['dest'] = dest
            cfg.setdefault('outbound', []).append(new_rule)

        with open(self.PORTS_CONF, 'w') as fp:
            json.dump(cfg, fp, indent=2)

        if cfg.get('active', True):
            self._ports_script('apply')

        return public.returnMsg(True, 'Aturan port %s berhasil ditambahkan' % clean_port)

    def del_port_rule(self, get):
        """Menghapus aturan port berdasarkan ID."""
        rule_id = (get.get('id') or '').strip()
        if not rule_id:
            return public.returnMsg(False, 'ID aturan wajib disertakan')

        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception as ex:
            return public.returnMsg(False, 'Gagal membaca konfigurasi: %s' % str(ex))

        removed = False
        for d in ['inbound', 'outbound']:
            rules = cfg.get(d, [])
            new_rules = [r for r in rules if r.get('id') != rule_id]
            if len(new_rules) < len(rules):
                cfg[d] = new_rules
                removed = True

        if not removed:
            return public.returnMsg(False, 'Aturan dengan ID tersebut tidak ditemukan')

        with open(self.PORTS_CONF, 'w') as fp:
            json.dump(cfg, fp, indent=2)

        if cfg.get('active', True):
            self._ports_script('apply')

        return public.returnMsg(True, 'Aturan port berhasil dihapus')

    def toggle_port_rule(self, get):
        """Menyalakan atau mematikan status aturan port."""
        rule_id = (get.get('id') or '').strip()
        if not rule_id:
            return public.returnMsg(False, 'ID aturan wajib disertakan')

        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception as ex:
            return public.returnMsg(False, 'Gagal membaca konfigurasi: %s' % str(ex))

        updated = False
        new_state = False
        for d in ['inbound', 'outbound']:
            for r in cfg.get(d, []):
                if r.get('id') == rule_id:
                    r['enabled'] = not r.get('enabled', True)
                    new_state = r['enabled']
                    updated = True
                    break

        if not updated:
            return public.returnMsg(False, 'Aturan tidak ditemukan')

        with open(self.PORTS_CONF, 'w') as fp:
            json.dump(cfg, fp, indent=2)

        if cfg.get('active', True):
            self._ports_script('apply')

        return public.returnMsg(True, 'Aturan %s (%s)' % ('diaktifkan' if new_state else 'dinonaktifkan', rule_id))

    def reset_port_firewall(self, get):
        """Mereset seluruh aturan port ke standar preinstall."""
        rc, o, e = self._ports_script('reset')
        if rc != 0:
            return public.returnMsg(False, 'Gagal reset port firewall: %s' % (e or o))
        return public.returnMsg(True, 'Port firewall berhasil direset ke standar preinstall')

    def apply_port_firewall(self, get):
        """Menerapkan ulang seluruh aturan port ke kernel iptables."""
        rc, o, e = self._ports_script('apply')
        if rc != 0:
            return public.returnMsg(False, 'Gagal menerapkan aturan port ke kernel: %s' % (e or o))
        return public.returnMsg(True, o or 'Aturan port berhasil diterapkan ke kernel')

    def toggle_port_firewall_status(self, get):
        """Menyalakan atau mematikan modul port firewall secara global."""
        try:
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)
        except Exception:
            self._ports_script('init')
            with open(self.PORTS_CONF, 'r') as fp:
                cfg = json.load(fp)

        cfg['active'] = not cfg.get('active', True)
        new_st = cfg['active']
        with open(self.PORTS_CONF, 'w') as fp:
            json.dump(cfg, fp, indent=2)

        self._ports_script('apply')
        return public.returnMsg(True, 'Port firewall %s' % ('diaktifkan' if new_st else 'dinonaktifkan'))

    # ------------------------------------------------------------------ #
    # Lua WAF engine (Nginx Lua firewall, difork ke Sentinel)            #
    #                                                                     #
    # Engine Lua ini hanya jalan di nginx. Konfigurasi global dan per     #
    # situs dibaca init.lua sekali saat worker start, jadi setiap         #
    # perubahan wajib diikuti reload nginx agar berlaku.                  #
    # ------------------------------------------------------------------ #
    # Master aset WAF ada di bawah sentinel (sejak konsolidasi); path
    # lama /www/server/free_waf tetap ada sebagai symlink untuk nginx.
    FW_HOME = '/www/server/sentinel/waf/lua_waf/' if os.path.exists('/www/server/sentinel/waf/lua_waf') else '/www/server/sentinel/waf/free_waf/'
    FW_MODUL = ['cc', 'get', 'post', 'cookie', 'user-agent', 'scan',
                'url_black', 'drop_abroad']

    def _fw_baca(self, nama):
        try:
            with open(self.FW_HOME + nama, 'r') as f:
                return json.load(f)
        except Exception as e:
            return None

    def _fw_tulis(self, nama, data):
        try:
            tmp = self.FW_HOME + nama + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f, ensure_ascii=False)
            os.rename(tmp, self.FW_HOME + nama)
            return True
        except Exception:
            return False

    def _fw_reload(self):
        """Reload nginx agar config.json/site.json baru terbaca worker.

        init.lua membaca kedua berkas sekali saat start, bukan per
        request. Tanpa reload, perubahan hanya tersimpan tetapi tidak
        berlaku. Return code reload tidak diverifikasi di sini karena
        panel memanggil nginx -t lebih dulu di tempat lain; yang
        penting reloadnya dijalankan.
        """
        self._sh('/etc/init.d/nginx reload', 60)

    def get_freewaf(self, get):
        """Status engine + ringkasan konfigurasi global."""
        rc, o, e = self._sh(
            "'%s/bin/sentinel-waf.sh' freewaf-status" % self.__PATH, 30)
        status = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                status[k.strip()] = v.strip()
        if rc != 0 or not status:
            return public.returnMsg(False, 'gagal membaca status: %s'
                                    % (e.strip() or o.strip()))
        config = self._fw_baca('config.json')
        if config is None:
            return public.returnMsg(False, 'config.json tidak terbaca; '
                                           'engine belum terpasang benar')
        modul = {}
        for m in self.FW_MODUL:
            v = config.get(m)
            if isinstance(v, dict):
                modul[m] = bool(v.get('open', False))
            elif isinstance(v, bool):
                modul[m] = v
            else:
                modul[m] = None
        return public.returnMsg(True, {
            'status': status,
            'open': bool(config.get('open', False)),
            'monitor': bool(config.get('monitor', False)),
            'modul': modul,
            'cc': config.get('cc', {}),
            'retry': {k: config.get(k) for k in
                      ('retry', 'retry_cycle', 'retry_time')},
        })

    def set_fw_open(self, get):
        """Nyalakan atau matikan seluruh WAF."""
        config = self._fw_baca('config.json')
        if config is None:
            return public.returnMsg(False, 'config.json tidak terbaca')
        aksi = (get.get('state') or '').strip()
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'state harus on atau off')
        config['open'] = (aksi == 'on')
        config['start_time'] = int(time.time()) if aksi == 'on' else 0
        if not self._fw_tulis('config.json', config):
            return public.returnMsg(False, 'gagal menulis config.json')
        self._fw_reload()
        return public.returnMsg(True, 'WAF %s' % ('aktif' if aksi == 'on'
                                                 else 'mati'))

    def set_fw_monitor(self, get):
        """Monitor (log saja) atau blocking."""
        config = self._fw_baca('config.json')
        if config is None:
            return public.returnMsg(False, 'config.json tidak terbaca')
        aksi = (get.get('state') or '').strip()
        if aksi not in ('monitor', 'blocking'):
            return public.returnMsg(False, 'state harus monitor atau blocking')
        config['monitor'] = (aksi == 'monitor')
        if not self._fw_tulis('config.json', config):
            return public.returnMsg(False, 'gagal menulis config.json')
        self._fw_reload()
        return public.returnMsg(True, 'mode %s aktif' % aksi)

    def set_fw_module(self, get):
        """Nyalakan atau matikan satu modul global (cc, get, post, ...)."""
        config = self._fw_baca('config.json')
        if config is None:
            return public.returnMsg(False, 'config.json tidak terbaca')
        m = (get.get('module') or '').strip()
        aksi = (get.get('state') or '').strip()
        if m not in self.FW_MODUL:
            return public.returnMsg(False, 'modul tidak dikenal: %s' % m)
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'state harus on atau off')
        v = config.get(m)
        if isinstance(v, dict):
            v['open'] = (aksi == 'on')
        elif isinstance(v, bool) or v is None:
            config[m] = (aksi == 'on')
        else:
            return public.returnMsg(False, 'bentuk modul tidak dikenal')
        if not self._fw_tulis('config.json', config):
            return public.returnMsg(False, 'gagal menulis config.json')
        self._fw_reload()
        return public.returnMsg(True, 'modul %s %s' % (m, aksi))

    def set_fw_cc(self, get):
        """Ubah batas CC global: limit per cycle detik, blokir endtime detik."""
        config = self._fw_baca('config.json')
        if config is None:
            return public.returnMsg(False, 'config.json tidak terbaca')
        try:
            limit = int(get.get('limit') or 0)
            cycle = int(get.get('cycle') or 0)
            endtime = int(get.get('endtime') or 0)
        except (ValueError, TypeError):
            return public.returnMsg(False, 'limit, cycle, endtime harus angka')
        if limit < 1 or cycle < 1 or endtime < 1:
            return public.returnMsg(False, 'semua nilai minimal 1')
        if limit > 100000 or cycle > 3600 or endtime > 86400:
            return public.returnMsg(False, 'nilai di luar batas wajar')
        cc = config.get('cc')
        if not isinstance(cc, dict):
            return public.returnMsg(False, 'bagian cc rusak di config.json')
        cc['limit'] = limit
        cc['cycle'] = cycle
        cc['endtime'] = endtime
        if not self._fw_tulis('config.json', config):
            return public.returnMsg(False, 'gagal menulis config.json')
        self._fw_reload()
        return public.returnMsg(
            True, 'CC global: %d request per %d detik, blokir %d detik'
                  % (limit, cycle, endtime))

    def get_fw_sites(self, get):
        """Daftar situs di site.json beserta status perlindungannya."""
        site = self._fw_baca('site.json')
        if site is None:
            return public.returnMsg(False, 'site.json tidak terbaca')
        daftar = []
        for nama in sorted(site.keys()):
            c = site[nama] if isinstance(site[nama], dict) else {}
            cc = c.get('cc', {}) if isinstance(c.get('cc'), dict) else {}
            daftar.append({
                'site': nama,
                'open': bool(c.get('open', False)),
                'cc_open': bool(cc.get('open', False)),
                'cc_limit': cc.get('limit'),
                'cc_cycle': cc.get('cycle'),
                'cc_endtime': cc.get('endtime'),
            })
        return public.returnMsg(True, daftar)

    def set_fw_site(self, get):
        """Nyalakan atau matikan WAF untuk satu situs."""
        site = self._fw_baca('site.json')
        if site is None:
            return public.returnMsg(False, 'site.json tidak terbaca')
        nama = (get.get('site') or '').strip()
        aksi = (get.get('state') or '').strip()
        if nama not in site or not isinstance(site[nama], dict):
            return public.returnMsg(False, 'situs tidak ada di site.json')
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'state harus on atau off')
        site[nama]['open'] = (aksi == 'on')
        if not self._fw_tulis('site.json', site):
            return public.returnMsg(False, 'gagal menulis site.json')
        self._fw_reload()
        return public.returnMsg(True, '%s -> %s' % (nama, aksi))

    def set_fw_site_cc(self, get):
        """Ubah batas CC satu situs."""
        site = self._fw_baca('site.json')
        if site is None:
            return public.returnMsg(False, 'site.json tidak terbaca')
        nama = (get.get('site') or '').strip()
        if nama not in site or not isinstance(site[nama], dict):
            return public.returnMsg(False, 'situs tidak ada di site.json')
        try:
            limit = int(get.get('limit') or 0)
            cycle = int(get.get('cycle') or 0)
            endtime = int(get.get('endtime') or 0)
        except (ValueError, TypeError):
            return public.returnMsg(False, 'limit, cycle, endtime harus angka')
        if limit < 1 or cycle < 1 or endtime < 1:
            return public.returnMsg(False, 'semua nilai minimal 1')
        if limit > 100000 or cycle > 3600 or endtime > 86400:
            return public.returnMsg(False, 'nilai di luar batas wajar')
        cc = site[nama].get('cc')
        if not isinstance(cc, dict):
            cc = {}
            site[nama]['cc'] = cc
        cc['open'] = True
        cc['limit'] = limit
        cc['cycle'] = cycle
        cc['endtime'] = endtime
        if not self._fw_tulis('site.json', site):
            return public.returnMsg(False, 'gagal menulis site.json')
        self._fw_reload()
        return public.returnMsg(True, 'CC %s: %d/%ds blokir %ds'
                                     % (nama, limit, cycle, endtime))

    def get_fw_lists(self, get):
        """Daftar hitam dan putih IP serta URL."""
        hasil = {}
        for nama in ('ip_black', 'ip_white', 'url_black', 'url_white'):
            v = self._fw_baca('rule/%s.json' % nama)
            hasil[nama] = v if isinstance(v, list) else []
        return public.returnMsg(True, hasil)

    def fw_list_add(self, get):
        """Tambah satu entri ke daftar. Duplikat ditolak."""
        nama = (get.get('list') or '').strip()
        nilai = (get.get('value') or '').strip()
        if nama not in ('ip_black', 'ip_white', 'url_black', 'url_white'):
            return public.returnMsg(False, 'daftar tidak dikenal')
        if not nilai or len(nilai) > 500:
            return public.returnMsg(False, 'nilai tidak valid')
        v = self._fw_baca('rule/%s.json' % nama)
        if not isinstance(v, list):
            v = []
        if nilai in v:
            return public.returnMsg(False, 'nilai sudah ada di daftar')
        v.append(nilai)
        if not self._fw_tulis('rule/%s.json' % nama, v):
            return public.returnMsg(False, 'gagal menulis daftar')
        self._fw_reload()
        return public.returnMsg(True, '%s masuk %s' % (nilai, nama))

    def fw_list_del(self, get):
        """Hapus satu entri dari daftar."""
        nama = (get.get('list') or '').strip()
        nilai = (get.get('value') or '').strip()
        if nama not in ('ip_black', 'ip_white', 'url_black', 'url_white'):
            return public.returnMsg(False, 'daftar tidak dikenal')
        v = self._fw_baca('rule/%s.json' % nama)
        if not isinstance(v, list) or nilai not in v:
            return public.returnMsg(False, 'nilai tidak ada di daftar')
        v.remove(nilai)
        if not self._fw_tulis('rule/%s.json' % nama, v):
            return public.returnMsg(False, 'gagal menulis daftar')
        self._fw_reload()
        return public.returnMsg(True, '%s keluar dari %s' % (nilai, nama))

    def freewaf_engine(self, get):
        """Pasang atau cabut engine free_waf (nginx saja)."""
        aksi = (get.get('action') or '').strip()
        if aksi not in ('install', 'remove'):
            return public.returnMsg(False, 'aksi harus install atau remove')
        rc, o, e = self._sh(
            "'%s/bin/sentinel-waf.sh' freewaf-%s" % (self.__PATH, aksi), 120)
        if rc != 0:
            return public.returnMsg(False, 'gagal: %s'
                                    % (e.strip() or o.strip()))
        return public.returnMsg(True, o.strip() or 'selesai')

    # ------------------------------------------------------------------ #
    # backend firewall dan WAF                                             #
    # ------------------------------------------------------------------ #
    def get_fw_backend(self, get):
        """Backend firewall yang terdeteksi: ufw, firewalld, atau iptables.

        ufw dan firewalld tidak terpasang di mesin ini, jadi nilainya
        praktis selalu iptables-nft. Method ini ada supaya UI menampilkan
        keadaan yang sebenarnya bila suatu saat frontend lain dipasang,
        bukan mengklaim kompatibilitas yang tidak diperiksa.
        """
        rc, o, e = self._sh(
            "'%s/bin/sentinel-fw.sh' backend" % self.__PATH, 30)
        info = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                info[k.strip()] = v.strip()
        if rc != 0 or not info:
            return public.returnMsg(False, 'gagal membaca backend: %s'
                                    % (e.strip() or o.strip()))
        return public.returnMsg(True, info)

    def _waf(self, *args):
        cmd = ' '.join(["'%s/bin/sentinel-waf.sh'" % self.__PATH] +
                       ["'%s'" % a for a in args])
        return self._sh(cmd, 60)

    def get_waf(self, get):
        """Status WAF: engine per webserver, rule OWASP, dan vhost."""
        rc1, o1, e1 = self._waf('engine')
        rc2, o2, e2 = self._waf('rules')
        rc3, o3, e3 = self._waf('vhosts')
        if rc1 != 0:
            return public.returnMsg(False, 'gagal deteksi engine: %s'
                                    % (e1.strip() or o1.strip()))
        engine = {}
        for baris in o1.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                engine[k.strip()] = v.strip()
        rules = []
        if rc2 == 0:
            for baris in o2.strip().splitlines():
                bagian = baris.split('|')
                if len(bagian) >= 3:
                    rules.append({'nama': bagian[0], 'keadaan': bagian[1],
                                  'berkas': bagian[2],
                                  'kunci': bagian[3] if len(bagian) > 3
                                           else 'tidak'})
        vhosts = []
        if rc3 == 0:
            for baris in o3.strip().splitlines():
                bagian = baris.split('|')
                if len(bagian) == 3:
                    vhosts.append({'ws': bagian[0], 'site': bagian[1],
                                   'keadaan': bagian[2]})
        # keinginan yang tersimpan tapi belum aktif (engine belum ada)
        ingin = {}
        try:
            with open(self._p('etc', 'waf.conf'), 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if line.startswith('vhost.') and '=' in line:
                        k, v = line.split('=', 1)
                        ingin[k.strip()] = v.strip()
        except Exception:
            pass
        return public.returnMsg(True, {
            'engine': engine,
            'rules': rules,
            'vhosts': vhosts,
            'ingin': ingin,
        })

    def set_waf_vhost(self, get):
        """Nyalakan atau cabut WAF untuk satu vhost."""
        ws = (get.get('ws') or '').strip()
        site = (get.get('site') or '').strip()
        aksi = (get.get('state') or '').strip()
        if ws not in ('nginx', 'apache', 'openlitespeed'):
            return public.returnMsg(False, 'webserver tidak dikenal')
        if not site or '/' in site or site.startswith('.'):
            return public.returnMsg(False, 'nama situs tidak valid')
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'state harus on atau off')
        rc, o, e = self._waf('vhost-%s' % ('on' if aksi == 'on' else 'off'),
                             ws, site)
        # kode 2 = keinginan disimpan karena engine belum ada. Itu BUKAN
        # kegagalan: snippet memang sengaja tidak ditulis. Bedakan pesannya
        # supaya operator tidak mengira perintahnya gagal total.
        if rc == 2:
            return public.returnMsg(
                True, 'disimpan sebagai keinginan (engine belum ada). '
                       'Akan dipasang otomatis setelah konektor WAF dipasang. '
                       'Rincian: %s' % (o.strip() or e.strip()))
        if rc != 0:
            return public.returnMsg(False, 'gagal: %s'
                                    % (e.strip() or o.strip()))
        # nginx butuh reload agar snippet berlaku. Tanpa reload, berkas
        # sudah tertulis tetapi tidak dibaca worker yang sedang jalan.
        if ws == 'nginx' and aksi == 'on':
            self._sh('/etc/init.d/nginx reload', 60)
        return public.returnMsg(True, o.strip() or 'selesai')

    def set_waf_rule(self, get):
        """Aktifkan atau nonaktifkan satu rule group OWASP."""
        nama = (get.get('rule') or '').strip()
        aksi = (get.get('state') or '').strip()
        if not nama or '/' in nama or ' ' in nama:
            return public.returnMsg(False, 'nama rule tidak valid')
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'state harus on atau off')
        rc, o, e = self._waf('rule-%s' % aksi, nama)
        if rc != 0:
            return public.returnMsg(False, 'gagal: %s'
                                    % (e.strip() or o.strip()))
        # owasp.conf dibaca ulang nginx saat reload. Reload hanya perlu
        # bila ada vhost nginx yang WAF-nya aktif; kalau tidak ada,
        # reload hanya mengganggu tanpa guna.
        rc2, o2, e2 = self._sh(
            "ls /www/server/panel/vhost/nginx/extension/*/sentinel-waf.conf "
            "2>/dev/null | head -1", 15)
        if rc2 == 0 and o2.strip():
            self._sh('/etc/init.d/nginx reload', 60)
            return public.returnMsg(
                True, '%s. nginx direload agar rule baru berlaku'
                      % (o.strip() or 'selesai'))
        return public.returnMsg(True, o.strip() or 'selesai')

    # ------------------------------------------------------------------ #
    # pemilihan engine WAF dan switch mode                                #
    #                                                                     #
    # Dua engine bisa dipilih:                                            #
    #   - free_waf : WAF Lua, hanya nginx yang bisa, SUDAH jalan.         #
    #   - coraza   : Coraza + OWASP CRS. Belum bisa jalan di mesin ini    #
    #                karena nginx tidak dibangun dengan --with-compat,    #
    #                jadi konektornya tidak bisa dimuat. Asetnya bisa     #
    #                disiapkan (unduh otomatis), tapi statusnya "siap,    #
    #                butuh konektor" sampai nginx dibangun ulang.         #
    # Pilihan engine disimpan di waf.conf (kunci engine).                 #
    # ------------------------------------------------------------------ #
    WAF_BASE = '/www/server/sentinel/waf'
    CORAZA_DIR = '/www/server/sentinel/waf/coraza'
    CRS_RELEASE_API = ('https://api.github.com/repos/coreruleset/'
                       'coreruleset/releases/latest')

    def _waf_conf_baca(self):
        """Baca seluruh waf.conf jadi dict sederhana (key=value)."""
        isi = {}
        try:
            with open(self._p('etc', 'waf.conf'), 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        isi[k.strip()] = v.strip()
        except Exception:
            pass
        return isi

    def get_waf_engine(self, get):
        """Engine WAF yang tersedia dan mana yang dipilih.

        Menggabungkan tiga sumber: konektor yang BENAR-BENAR ada di
        nginx (dari sentinel-waf.sh engine), keadaan free_waf, dan
        aset coraza di disk. UI memakai ini untuk menampilkan dua kartu
        pilihan tanpa menebak.
        """
        rc, o, e = self._sh(
            "'%s/bin/sentinel-waf.sh' engine" % self.__PATH, 30)
        engine = {}
        if rc == 0:
            for baris in o.strip().splitlines():
                if '=' in baris:
                    k, v = baris.split('=', 1)
                    engine[k.strip()] = v.strip()

        rc2, o2, e2 = self._sh(
            "'%s/bin/sentinel-waf.sh' freewaf-status" % self.__PATH, 30)
        fw = {}
        if rc2 == 0:
            for baris in o2.strip().splitlines():
                if '=' in baris:
                    k, v = baris.split('=', 1)
                    fw[k.strip()] = v.strip()

        conf = self._waf_conf_baca()
        pilih = conf.get('engine', 'free_waf')
        if pilih not in ('free_waf', 'coraza'):
            pilih = 'free_waf'

        coraza = self._coraza_info()
        return public.returnMsg(True, {
            'pilih': pilih,
            'nginx_connector': engine.get('nginx', 'none'),
            'free_waf': {
                'lua': fw.get('lua', 'tidak-ada'),
                'loaded': fw.get('loaded', 'tidak'),
                'mode': fw.get('mode', 'tidak-diketahui'),
                'siap': fw.get('lua') == 'ada',
            },
            'coraza': coraza,
        })

    def _coraza_info(self):
        """Ringkasan aset Coraza di disk: ada/tidak, versi, konektor.

        Konektor nginx BELUM tentu ada; itu yang membedakan "aset siap"
        dengan "engine jalan". Dipisah supaya UI bisa menampilkan dua
        badge berbeda, bukan satu status yang menyesatkan.
        """
        d = self.CORAZA_DIR
        ada = os.path.isdir(d)
        versi = '-'
        aturan = 0
        konektor = 'tidak-ada'
        if ada:
            vf = os.path.join(d, 'VERSIONS.txt')
            if os.path.exists(vf):
                try:
                    with open(vf, 'r') as f:
                        for line in f:
                            if line.startswith('crs='):
                                versi = line.split('=', 1)[1].strip()
                except Exception:
                    pass
            rd = os.path.join(d, 'rules')
            if os.path.isdir(rd):
                for _, _, files in os.walk(rd):
                    aturan += sum(1 for x in files if x.endswith('.conf'))
            if os.path.isdir(os.path.join(d, 'connector')):
                konektor = 'source-ada'
        rc, o, e = self._sh(
            "'%s/bin/sentinel-waf.sh' engine" % self.__PATH, 20)
        if rc == 0 and 'nginx=coraza' in o:
            konektor = 'terpasang'
        return {'aset': ada, 'versi': versi, 'aturan': aturan,
                'konektor': konektor}

    def set_waf_engine(self, get):
        """Pilih engine WAF aktif: free_waf atau coraza.

        Memilih coraza TIDAK memaksa rebuild nginx. Bila konektornya
        belum ada, pilihan tetap tersimpan dan engine aktif dilaporkan
        apa adanya. Ini menghindari kesan "sudah aktif" padahal belum.
        """
        eng = (get.get('engine') or '').strip()
        if eng not in ('free_waf', 'coraza'):
            return public.returnMsg(False, 'engine harus free_waf atau coraza')
        rc, o, e = self._waf('engine-set', eng)
        if rc != 0:
            return public.returnMsg(False, 'gagal menyimpan pilihan: %s'
                                    % (e.strip() or o.strip()))
        if eng == 'coraza':
            info = self._coraza_info()
            if info['konektor'] != 'terpasang':
                return public.returnMsg(
                    True, 'Coraza dipilih. Aset %s, tetapi konektor nginx '
                          'belum terpasang sehingga engine belum berjalan. '
                          'Aktifkan setelah konektor dipasang.'
                          % ('siap' if info['aset'] else 'BELUM diunduh'))
        return public.returnMsg(True, 'engine %s dipilih' % eng)

    def set_waf_mode(self, get):
        """Switch Monitor | Block | Disable untuk engine yang aktif."""
        mode = (get.get('mode') or '').strip()
        if mode not in ('monitor', 'block', 'disable'):
            return public.returnMsg(False, 'mode harus monitor, block, atau '
                                           'disable')
        rc, o, e = self._waf('mode-set', mode)
        if rc != 0:
            return public.returnMsg(False, 'gagal menyetel mode: %s'
                                    % (e.strip() or o.strip()))
        return public.returnMsg(True, o.strip() or ('mode %s' % mode))

    def get_waf_mode(self, get):
        rc, o, e = self._waf('mode-get')
        if rc != 0:
            return public.returnMsg(False, 'gagal membaca mode: %s'
                                    % (e.strip() or o.strip()))
        info = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                info[k.strip()] = v.strip()
        return public.returnMsg(True, info)

    def download_coraza(self, get):
        """Unduh aset Coraza + OWASP CRS bila belum ada.

        Idempoten: bila aset sudah lengkap dan versi diminta sama,
        tidak mengunduh ulang. Tahan offline: kegagalan jaringan
        dilaporkan apa adanya, tidak menandai aset siap.
        """
        rc, o, e = self._waf('coraza-download')
        if rc != 0:
            return public.returnMsg(False, 'unduhan gagal: %s'
                                    % (e.strip() or o.strip()))
        return public.returnMsg(True, o.strip() or 'aset Coraza siap')

    # ------------------------------------------------------------------ #
    # jejak audit dan analisis per-vhost                                  #
    #                                                                     #
    # Dua hal yang sebelumnya tidak mungkin dilakukan:                    #
    #                                                                     #
    # 1. Rekonsiliasi. Tabel aksi mencatat setiap tindakan terhadap IP:  #
    #    kapan, oleh sistem atau panel, dengan alasan apa. Tanpa itu     #
    #    yang terlihat hanya kondisi sekarang, bukan urutan keputusan.   #
    #                                                                     #
    # 2. Analisis per-vhost. Tabel minute sudah menyimpan req dan       #
    #    bytes per host, tapi tidak pernah dibaca per host. Events kini  #
    #    juga membawa host, sehingga serangan bisa ditelusuri ke vhost   #
    #    yang ditusuk.                                                  #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _jam(get, batas=720):
        """Jam rentang sebagai bilangan bulat, atau None bila tidak valid.

        int() tanpa penanganan melempar ValueError, dan traceback-nya
        tampil mentah di halaman panel sebagai galat 500. Pola yang sama
        sudah dihindari di ban_ip dan set_conf; di sini diterapkan juga
        supaya endpoint baru tidak menjadi jalur baru menuju galat.
        """
        # Nilai bisa string maupun int. Panel sering mengirim angka
        # dari input numerik, sedangkan panggilan langsung dari skrip
        # sering mengirim string. Keduanya harus diterima.
        mentah = get.get('hours')
        if isinstance(mentah, str):
            mentah = mentah.strip()
        if mentah is None or mentah == '':
            return 24
        try:
            n = int(mentah)
        except (TypeError, ValueError):
            return None
        if n < 1 or n > batas:
            return None
        return n

    # ------------------------------------------------------------------ #
    # geoip                                                              #
    # ------------------------------------------------------------------ #
    # Lookup dilakukan di sisi PANEL, bukan di daemon, dengan tiga alasan:
    #
    # 1. Berkas GeoLite2 berformat MaxMind MMDB. Membacanya di C
    #    memerlukan pustaka pihak ketiga yang tidak ada di daemon, dan
    #    daemon harus tetap tanpa dependensi supaya bisa dikompilasi
    #    di server mana pun.
    # 2. Panel sudah punya modul maxminddb dan berkas GeoLite2, jadi
    #    tidak perlu mengunduh apa pun.
    # 3. Hasil disimpan di tabel geo, jadi satu IP hanya dibaca dari
    #    berkas MMDB satu kali saja. Peng thereafter hanya satu kueri.
    #
    # Kalau berkas MMDB hilang, semua fungsi di sini mengembalikan
    # "tidak diketahui", bukan galat. Panel harus tetap berfungsi tanpa
    # GeoIP.
    # ------------------------------------------------------------------ #
    _geo_db = None
    _geo_ran = None
    _GEO_CANDIDAT = (
        '/www/server/panel/config/GeoLite2-City.mmdb',
        '/www/server/btwaf/inc/GeoLite2-City.mmdb',
    )

    def _geo_buka(self):
        """Buka GeoLite2 sekali saja, atau None bila tidak tersedia."""
        if self._geo_ran and time.time() - self._geo_ran > 3600:
            # Berkas bisa ditukar atau dihapus_panel. Diperiksa ulang
            # satu jam sekali supaya perubahan pada panel ikut terbaca.
            try:
                self._geo_db.close()
            except Exception:
                pass
            self._geo_db = None
        if self._geo_db is not None or self._geo_ran:
            if self._geo_db is None and time.time() - self._geo_ran < 3600:
                return None
        if self._geo_db is not None:
            return self._geo_db
        for jalan in self._GEO_CANDIDAT:
            if not os.path.isfile(jalan):
                continue
            try:
                import maxminddb
                self._geo_db = maxminddb.open_database(jalan)
                self._geo_ran = time.time()
                return self._geo_db
            except Exception:
                continue
        self._geo_ran = time.time()
        self._geo_db = None
        return None

    @staticmethod
    def _geo_pecah(rec):
        """Ambil kode dan nama negara dari satu record GeoLite2.

        Berkas aaPanel memakai bentukcountry.en_short_code dan
        country.country, BUKAN bentuk MaxMind baku
        (country.iso_code dan country.names.en). Keduanya dicoba supaya
        pergantian versi panel tidak membuat fitur ini mati diam-diam.
        """
        if not isinstance(rec, dict):
            return '', ''
        c = rec.get('country')
        if not isinstance(c, dict):
            return '', ''
        kode = c.get('en_short_code') or c.get('iso_code') or ''
        nama = c.get('country') or ''
        if not nama:
            names = c.get('names')
            if isinstance(names, dict):
                nama = names.get('en') or ''
        return (kode or '').strip()[:4], (nama or '').strip()[:48]

    def _geo_satu(self, ip):
        """Negara satu IP, dengan cache di tabel geo."""
        n = self._ipnum(ip)
        if not n:
            return '', ''
        v = self._sql1(
            'SELECT kode, nama FROM geo WHERE ip=?', (n,))
        if v:
            return v.get('kode') or '', v.get('nama') or ''
        db = self._geo_buka()
        kode, nama = ('', '')
        if db:
            try:
                kode, nama = self._geo_pecah(db.get(ip))
            except Exception:
                kode, nama = ('', '')
            # JANGAN menutup db di sini. Handle-nya sengaja
            # disimpan supaya berkas MMDB hanya dibuka sekali.
            # Menutupnya membuat setiap lookup berikutnya membaca
            # dari handle yang sudah tutup dan selalu gagal, sehingga
            # semua IP dilaporkan "tidak diketahui".
        if kode:
            try:
                import sqlite3
                con = sqlite3.connect(self._db(), timeout=10)
                con.execute('INSERT OR REPLACE INTO geo(ip,kode,nama,ts)'
                            ' VALUES(?,?,?,?)',
                            (n, kode, nama or '-', int(time.time())))
                con.commit()
                con.close()
            except Exception:
                # Cache gagal menulis bukan alasan menolak jawaban.
                # Informasi negara tetap dikembalikan ke pemanggil.
                pass
        return kode, nama

    def get_ip_geo(self, get):
        """Negara satu atau beberapa IP sekaligus."""
        ip = (get.get('ip') or '').strip()
        if not ip:
            return public.returnMsg(False, 'IP wajib diisi')
        if self._ipnum(ip) == 0:
            return public.returnMsg(False, 'alamat IP tidak valid')
        kode, nama = self._geo_satu(ip)
        db = self._geo_buka()
        return public.returnMsg(True, {
            'ip': ip,
            'kode': kode or '-',
            'nama': nama or '-',
            'tersedia': db is not None,
        })

    def get_geo_stat(self, get):
        """Sebaran penyerang berdasarkan negara.

        Berguna untuk membedakan dua pola yang berbeda:
        penyerang yang tersebar acak (botnet, scanner umum)
        dengan penyerang yang terpusat di satu atau dua negara
        (serangan terarah).
        """
        jam = self._jam(get)
        if jam is None:
            return public.returnMsg(
                False, 'rentang jam harus angka antara 1 dan 720')
        sejak = int(time.time()) - jam * 3600
        baris = self._sql(
            'SELECT ip, COUNT(*) n, MAX(score) puncak'
            ' FROM events WHERE ts >= ?'
            ' GROUP BY ip ORDER BY n DESC LIMIT 500', (sejak,))
        if isinstance(baris, dict):
            return baris

        db = self._geo_buka()
        pakai_geo = db is not None

        # Kode negara diambil dari cache lebih dulu. Lookup MMDB hanya
        # dijalankan untuk IP yang belum pernah dilihat, jadi biaya
        # berkas tidak berulang tiap permintaan.
        gabung = {}
        tak_tahu = 0
        for r in baris:
            # Kolom ip dari SQLite berupa bilangan bulat, sedangkan
            # maxminddb dan _ipnum keduanya bekerja pada bentuk teks.
            # Tanpa konversi di sini, setiap IP gagal looked up dan
            # seluruh sebaran muncul sebagai "tidak diketahui".
            ipteks = r['ip']
            if isinstance(ipteks, int):
                ipteks = self._numip(ipteks)
            kode, nama = self._geo_satu(ipteks)
            if not kode:
                tak_tahu += 1
                kode = '??'
                nama = 'Tidak diketahui'
            g = gabung.setdefault(kode, {'kode': kode, 'nama': nama,
                                         'ip': 0, 'n': 0, 'puncak': 0})
            g['ip'] += 1
            g['n'] += (r['n'] or 0)
            if (r['puncak'] or 0) > g['puncak']:
                g['puncak'] = r['puncak']

        daftar = sorted(gabung.values(), key=lambda x: -x['n'])
        return public.returnMsg(True, {
            'negara': daftar,
            'tak_tahu': tak_tahu,
            'geo_tersedia': pakai_geo,
            'total_ip': len(baris),
        })

    # ------------------------------------------------------------------ #
    # geo-ban (blokir per negara)                                        #
    #                                                                     #
    # Berbeda dengan ban per IP: ini memblokir seluruh blok CIDR satu    #
    # negara di lapisan kernel (ipset sentinel_geo). Karena bisa memutus #
    # pengunjung sah, tiga pagar dipasang: bawaan off, whitelist selalu  #
    # menang, dan hanya berlaku di port web.                             #
    # ------------------------------------------------------------------ #
    GEO_JSON = '/www/server/panel/data/firewall/GeoLite2-Country.json'

    def _geo_ban_conf(self):
        """Baca geo_mode dan geo_negara dari guardd.conf."""
        mode, negara = 'off', ''
        try:
            with open(self._p('etc', 'guardd.conf'), 'r') as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if '=' not in line:
                        continue
                    k, v = line.split('=', 1)
                    k, v = k.strip(), v.strip()
                    if k == 'geo_mode':
                        mode = v or 'off'
                    elif k == 'geo_negara':
                        negara = v
        except Exception:
            pass
        if mode not in ('off', 'block', 'allow'):
            mode = 'off'
        negara = negara.upper().replace(' ', '')
        return mode, negara

    def get_geo_ban(self, get):
        """Keadaan geo-ban sekarang: mode, negara, jumlah blok terpasang.

        Jumlah blok diambil dari kernel (ipset), bukan dari config,
        supaya UI menunjukkan apa yang BENAR-BENAR berlaku, bukan apa
        yang diminta. Kalau keduanya berbeda, itu justru yang perlu
        terlihat.
        """
        mode, negara = self._geo_ban_conf()
        rc, o, e = self._sh(
            "'%s/bin/sentinel-fw.sh' geo-status" % self.__PATH, 30)
        info = {}
        for baris in o.strip().splitlines():
            if '=' in baris:
                k, v = baris.split('=', 1)
                info[k.strip()] = v.strip()
        return public.returnMsg(True, {
            'mode': mode,
            'negara': negara,
            'negara_daftar': [x for x in negara.split(',') if x],
            'blok': int(info.get('blok') or 0),
            'aturan': int(info.get('aturan') or 0),
            'sumber': self.GEO_JSON,
            'sumber_ada': os.path.exists(self.GEO_JSON),
        })

    def get_geo_list(self, get):
        """Daftar negara yang tersedia untuk diblokir, dari berkas panel.

        Hanya kode dan jumlah blok; nama negara panjang diambil GeoLite
        saat lookup per IP, jadi tidak perlu di sini. Diurutkan menurun
        supaya negara dengan blok terbanyak (yang paling sering jadi
        sumber serangan) muncul lebih dulu.
        """
        try:
            with open(self.GEO_JSON, 'r') as f:
                data = json.load(f)
        except Exception as ex:
            return public.returnMsg(
                False, 'berkas geo tidak terbaca: %s' % ex)
        hasil = []
        for entri in data:
            kode = entri.get('brief') or entri.get('code') or ''
            if not kode:
                continue
            hasil.append({'kode': kode, 'blok': len(entri.get('ips') or [])})
        hasil.sort(key=lambda x: -x['blok'])
        return public.returnMsg(True, hasil)

    def set_geo_ban(self, get):
        """Nyalakan/matikan geo-ban, atau ubah daftar negaranya.

        Dua aksi terpisah disengaja:
          - action=off  : matikan (mode off + kosongkan set)
          - action=on   : tulis mode + negara, lalu terapkan.
        Konfirmasi 'on' wajib dari sisi server: menyalakan geo-ban bisa
        memutus seluruh pengunjung satu negara, jadi tidak boleh terjadi
        dari satu klik yang tidak sengaja.
        """
        aksi = (get.get('action') or '').strip()
        if aksi not in ('on', 'off'):
            return public.returnMsg(False, 'action harus on atau off')

        if aksi == 'off':
            self._sh("'%s/bin/guardctl' set geo_mode off" % self.__PATH, 20)
            self._sh("'%s/bin/guardctl' set geo_negara ''" % self.__PATH, 20)
            rc, o, e = self._sh(
                "'%s/bin/sentinel-fw.sh' geo-clear" % self.__PATH, 60)
            if rc != 0:
                return public.returnMsg(False, 'gagal mematikan geo-ban: %s'
                                        % (e.strip() or o.strip()))
            return public.returnMsg(True, 'geo-ban dimatikan')

        # --- menyalakan ---
        konfirmasi = (get.get('confirm') or '').strip()
        if konfirmasi != 'GEO':
            return public.returnMsg(
                False, 'konfirmasi tidak cocok. Ketik GEO dengan huruf '
                       'besar semua untuk menyalakan geo-ban')

        mode = (get.get('mode') or 'block').strip().lower()
        if mode not in ('block', 'allow'):
            return public.returnMsg(False, 'mode harus block atau allow')
        negara = (get.get('negara') or '').upper().replace(' ', '')
        kode_valid = self._geo_kode_valid()
        daftar = [x for x in negara.split(',') if x]
        if not daftar:
            return public.returnMsg(False, 'pilih minimal satu negara')
        for k in daftar:
            if len(k) != 2 or (kode_valid and k not in kode_valid):
                return public.returnMsg(
                    False, 'kode negara tidak dikenal: %s (contoh sah: '
                           'CN, RU, US)' % k)

        # Tulis ke config lewat guardctl supaya backup dan formatnya
        # konsisten dengan kunci lain.
        self._sh("'%s/bin/guardctl' set geo_mode %s" % (self.__PATH, mode), 20)
        self._sh("'%s/bin/guardctl' set geo_negara %s"
                 % (self.__PATH, ','.join(daftar)), 20)

        rc, o, e = self._sh(
            "SENTINEL_GEO_MODE=%s SENTINEL_GEO_NEGARA=%s "
            "'%s/bin/sentinel-fw.sh' geo-apply"
            % (mode, ','.join(daftar), self.__PATH), 180)
        if rc != 0:
            return public.returnMsg(
                False, 'geo-ban gagal diterapkan, sudah dibatalkan: %s'
                       % (e.strip() or o.strip()))
        # Tampilkan apa yang benar-benar terjadi, bukan yang diminta.
        rc2, o2, e2 = self._sh(
            "'%s/bin/sentinel-fw.sh' geo-status" % self.__PATH, 30)
        blok = 0
        for baris in o2.strip().splitlines():
            if baris.startswith('blok='):
                blok = int((baris.split('=', 1)[1] or '0').strip() or 0)
        return public.returnMsg(
            True, 'geo-ban aktif: mode %s, %d blok CIDR diblokir '
                  'pada port web' % (mode, blok))

    def _geo_kode_valid(self):
        """Kumpulan kode negara yang sah, atau set kosong bila tak bisa
        dibaca. Dipakai untuk menolak kode yang tidak ada sebelum
        menyentuh config, supaya salah ketik tidak menjadi mode allow
        yang memblokir semua negara lain."""
        try:
            with open(self.GEO_JSON, 'r') as f:
                data = json.load(f)
            return set(e.get('brief') or e.get('code') or ''
                       for e in data if (e.get('brief') or e.get('code')))
        except Exception:
            return set()


    # ------------------------------------------------------------------ #
    # antrian review                                                      #
    #                                                                     #
    # Pelengkap dari mode monitor. Saat enforce = 0 tidak ada yang        #
    # diblokir, sehingga operator tidak punya cara melihat siapa yang     #
    # AKAN diblokir. Antrean ini mengisi celah itu: IP yang mencurigakan #
    # dicatat, paketnya tetap lewat, lalu operator memutuskan per IP.    #
    #                                                                     #
    # Paket dari IP di antrian tidak pernah diblokir. Aturan kernel      #
    # untuk set ini sengaja -j RETURN, bukan -j DROP.                   #
    # ------------------------------------------------------------------ #
    def get_review(self, get):
        """Antrean review: IP yang menunggu keputusan operator."""
        mentah_status = get.get('status') or 'tunggu'
        status = mentah_status.strip() if isinstance(mentah_status, str) \
            else str(mentah_status)
        if status not in ('tunggu', 'setuju', 'tolak', 'semua'):
            status = 'tunggu'
        # limit bisa datang sebagai string (form panel) maupun int
        # (panggilan langsung dari skrip). .strip() tanpa pemeriksaan tipe
        # melempar AttributeError pada int, dan traceback-nya tampil
        # mentah sebagai galat 500 di halaman panel.
        mentah_limit = get.get('limit')
        if isinstance(mentah_limit, str):
            mentah_limit = mentah_limit.strip()
        if mentah_limit is None or mentah_limit == '':
            mentah_limit = '100'
        try:
            n = int(mentah_limit)
        except (TypeError, ValueError):
            n = 100
        if n < 1:
            n = 1
        if n > 500:
            n = 500

        if status == 'semua':
            where = ''
            args = (n,)
        else:
            where = ' WHERE status=?'
            args = (status, n)
        baris = self._sql(
            'SELECT ts, ip, skor, alasan, status FROM review'
            + where + ' ORDER BY ts DESC LIMIT ?', args)
        if isinstance(baris, dict):
            return baris

        hasil = []
        for r in baris:
            ipteks = self._numip(r['ip'])
            kode, nama = self._geo_satu(ipteks)
            r['ip'] = ipteks
            r['kode'] = kode or '-'
            r['negara'] = nama or '-'
            hasil.append(r)

        # Hitungan per status supaya tab bisa menampilkan badge.
        hitung = {}
        for st in ('tunggu', 'setuju', 'tolak'):
            hitung[st] = 0
        semua = self._sql(
            'SELECT status, COUNT(*) n FROM review GROUP BY status')
        if not isinstance(semua, dict):
            for x in semua:
                hitung[x['status']] = x['n']

        # Durasi tunggu, supaya operator tahu mana yang sudah basi.
        sekarang = int(time.time())
        for r in hasil:
            r['umur'] = max(0, sekarang - (r['ts'] or 0))
        return public.returnMsg(True, {
            'antrian': hasil,
            'hitungan': hitung,
            'total': sum(hitung.values()),
        })

    def review_decide(self, get):
        """Operator memutuskan satu IP: disetujui (diblokir) atau ditolak."""
        ip = (get.get('ip') or '').strip()
        if not ip or self._ipnum(ip) == 0:
            return public.returnMsg(False, 'alamat IP tidak valid')
        aksi = (get.get('action') or '').strip()
        if aksi not in ('setuju', 'tolak'):
            return public.returnMsg(
                False, 'action harus setuju atau tolak')
        n = self._ipnum(ip)

        if aksi == 'setuju':
            # Diperlakukan sebagai ban biasa lewat guardctl supaya ia
            # supaya masuk ipset dan ikut aturan kernel seperti ban manual lain.
            rc, o, e = self._sh(
                "'%s/bin/guardctl' ban '%s'" % (self.__PATH, ip), 20)
            if rc != 0 or '"ok":true' not in o:
                return public.returnMsg(
                    False, 'gagal memblokir: %s' % (o.strip() or e.strip()))
            if '"dalam_ipset":true' not in o:
                return public.returnMsg(
                    False, 'IP dicatat di daftar blokir, tetapi TIDAK masuk '
                           'ipset kernel sehingga belum benar-benar '
                           'diblokir')
            self._sql1(
                'UPDATE review SET status=?, alasan=alasan || '
                "'; disetujui operator' WHERE ip=?", ('setuju', n))
            return public.returnMsg(
                True, '%s disetujui dan sudah diblokir' % ip)

        # Ditolak: lepas dari antrian dan jangan diblokir. Operator
        # yang menolak IP itu berarti dia yakin itu bukan penyerang.
        try:
            import sqlite3
            con = sqlite3.connect(self._db(), timeout=10)
            con.execute(
                "UPDATE review SET status='tolak', alasan=alasan || "
                "'; ditolak operator' WHERE ip=?", (n,))
            con.commit()
            con.close()
        except Exception as ex:
            return public.returnMsg(False, 'gagal mencatat keputusan: %s' % ex)
        rc, o, e = self._sh(
            "'%s/bin/guardctl' unreview '%s'" % (self.__PATH, ip), 20)
        if rc != 0 or '"ok":true' not in o:
            return public.returnMsg(False, 'IP ditandai ditolak, tetapi '
                                    'gagal melepas dari antrian kernel: %s'
                                    % (o.strip() or e.strip()))
        self._aksi(ip, 'review-tolak', 'panel',
                   'ditolak operator, tidak diblokir')
        return public.returnMsg(
            True, '%s ditolak, tidak diblokir' % ip)

    # ------------------------------------------------------------------ #
    # notifikasi                                                          #
    # ------------------------------------------------------------------ #
    # Notifikasi TIDAK dikirim dari daemon. Daemon hanya menulis ke tabel #
    # notif; pengiriman dikerjakan sentinel-notify.sh dari systemd timer.  #
    # Alasannya: satu HTTP POST yang menggantung akan menahan           #
    # pemrosesan log, dan daemon membaca log setiap dua detik. Dengan     #
    # begitu, satu alamat tujuan yang nakal bisa membuat Sentinel        #
    # berhenti melihat serangan sama sekali.                             #
    # ------------------------------------------------------------------ #
    def _notify_conf_path(self):
        return os.path.join(self.__PATH, 'etc', 'notify.conf')

    def get_notif_conf(self, get):
        """Status notifikasi tanpa membocorkan token ke layar."""
        jalan = self._notify_conf_path()
        isi = {}
        try:
            with open(jalan, 'r') as f:
                for baris in f:
                    b = baris.strip()
                    if not b or b.startswith('#') or '=' not in b:
                        continue
                    k, v = b.split('=', 1)
                    isi[k.strip()] = v.strip().strip('"')
        except Exception:
            pass

        url = isi.get('NOTIFY_URL', '')
        token = isi.get('NOTIFY_TOKEN', '')

        # Token TIDAK dikembalikan. Yang dikembalikan hanya apakah ia
        # terisi, supaya operator tahu harusnya ada atau tidak tanpa
        # menyalin kata sandinya ke halaman panel.
        hasil = {
            'url_ada': bool(url),
            'url_host': self._host_dari(url),
            'token_ada': bool(token),
            'jenis': isi.get('NOTIFY_KIND', 'semua'),
            'maks_coba': isi.get('SENTINEL_NOTIF_MAX', '5'),
            'batch': isi.get('SENTINEL_NOTIF_BATCH', '20'),
            'timeout': isi.get('SENTINEL_NOTIF_TIMEOUT', '8'),
            'berkas': jalan,
        }

        # Status antrean supaya operator tahu ada yang tersendir.
        t = self._sql1(
            'SELECT COUNT(*) total, SUM(terkirim=0) nunggu,'
            ' SUM(terkirim=0 AND coba>0) gagal FROM notif')
        hasil['antrean'] = t or {'total': 0, 'nunggu': 0, 'gagal': 0}

        timer = self._sh('systemctl is-active sentinel-notify.timer', 15)
        hasil['timer'] = timer[1].strip() or 'tidak aktif'
        return public.returnMsg(True, hasil)

    @staticmethod
    def _host_dari(url):
        """Ambil host dari URL tanpa membawakan bagian rahasia.

        Token sering disimpan di dalam URL, misalnya path bot Telegram
        yang memuat token. Karena itu hanya nama host yang ditampilkan,
        bukan URL lengkapnya.
        """
        try:
            from urllib.parse import urlparse
            b = urlparse(url)
            return b.hostname or '-'
        except Exception:
            return '-'

    def set_notif_conf(self, get):
        """Ubah tujuan notifikasi dan me-restart timer."""
        url = (get.get('url') or '').strip()
        token_lama = bool((self._notif_ada('NOTIFY_TOKEN')))
        token = get.get('token')

        if url and not url.startswith(('http://', 'https://')):
            return public.returnMsg(
                False, 'URL harus diawali http:// atau https://')
        if len(url) > 500:
            return public.returnMsg(False, 'URL terlalu panjang')

        maks = self._int(get, 'maks', 5, 1, 20)
        batch = self._int(get, 'batch', 20, 1, 200)
        timeout = self._int(get, 'timeout', 8, 1, 120)
        if maks is None:
            return public.returnMsg(
                False, 'percobaan maksimal harus angka antara 1 dan 20')
        if batch is None:
            return public.returnMsg(
                False, 'jumlah per siklus harus angka antara 1 dan 200')
        if timeout is None:
            return public.returnMsg(
                False, 'timeout harus angka antara 1 dan 120 detik')

        isi = [
            '# Notifikasi ZySentinel',
            '# Ditulis ulang dari panel. Nilai token TIDAK ditampilkan',
            '# di layar, tapi tetap ada di berkas ini.',
            '',
            'NOTIFY_URL="%s"' % url.replace('"', ''),
        ]
        # Token hanya ditulis kalau operator mengirimnya. Kalau tidak,
        # token yang sudah ada dibiarkan supaya tidak terhapus tidak
        # sengaja setiap kali URL diubah.
        if token is not None and str(token) != '':
            isi.append('NOTIFY_TOKEN="%s"' % str(token).replace('"', ''))
        elif token_lama:
            isi.append('NOTIFY_TOKEN=""')

        isi += [
            'NOTIFY_KIND="%s"' % self._only(get, 'kind', 'semua', 20),
            'SENTINEL_NOTIF_MAX="%d"' % maks,
            'SENTINEL_NOTIF_BATCH="%d"' % batch,
            'SENTINEL_NOTIF_TIMEOUT="%d"' % timeout,
            '',
        ]
        jalan = self._notify_conf_path()
        try:
            with open(jalan, 'w') as f:
                f.write('\n'.join(isi))
            os.chmod(jalan, 0o600)
        except Exception as ex:
            return public.returnMsg(False, 'gagal menulis: %s' % ex)

        # Daemon harus tahu URL barunya supaya dia menulis antrean.
        if url:
            self._sh("'%s/bin/guardctl' set notify_url '%s'" % (self.__PATH, url.replace("'", "")), 20)
        self._sh('systemctl restart sentinel.service', 30)
        self._sh('systemctl restart sentinel-notify.timer', 30)
        return public.returnMsg(True, 'tujuan notifikasi disimpan')

    def _notif_ada(self, kunci):
        try:
            with open(self._notify_conf_path(), 'r') as f:
                for baris in f:
                    b = baris.strip()
                    if b.startswith(kunci + '='):
                        v = b.split('=', 1)[1].strip().strip('"')
                        return bool(v)
        except Exception:
            pass
        return False

    def test_notif(self, get):
        """Kirim satu notifikasi uji dan laporkan hasilnya apa adanya."""
        jalan = self._notify_conf_path()
        if not self._notif_ada('NOTIFY_URL'):
            return public.returnMsg(
                False, 'belum ada tujuan notifikasi. Isi dulu di sini.')
        # Sisipkan lewat tabel yang sama supaya persis melewati jalur
        # yang dipakai kejadian sebenarnya, bukan jalur terpisah.
        m = self._sql1("SELECT ip FROM aksi LIMIT 1")
        self._notif('uji',
                    'Ini notifikasi uji dari ZySentinel. Kalau sampai '
                    'diterima, pengaturan sudah benar.')
        self._sh('systemctl start sentinel-notify.service', 90)
        # Beri waktu skrip menyelesaikan pengiriman.
        import time as _t
        _t.sleep(3)
        d = self._sql1(
            "SELECT terkirim, coba, galat FROM notif WHERE jenis='uji' "
            'ORDER BY id DESC LIMIT 1')
        if not d:
            return public.returnMsg(
                False, 'notifikasi uji tidak masuk antrean')
        if d['terkirim']:
            return public.returnMsg(True, 'notifikasi uji terkirim')
        return public.returnMsg(
            False, 'notifikasi uji gagal terkirim: %s'
                   % (d.get('galat') or 'tidak diketahui'))

    def get_notif_log(self, get):
        """Riwayat notifikasi terakhir."""
        n = self._int(get, 'limit', 50, 1, 300)
        if n is None:
            n = 50
        baris = self._sql(
            'SELECT id, ts, ip, jenis, isi, terkirim, coba, galat'
            ' FROM notif ORDER BY id DESC LIMIT ?', (n,))
        if isinstance(baris, dict):
            return baris
        for r in baris:
            r['ip'] = self._numip(r['ip']) if r['ip'] else '-'
        return public.returnMsg(True, baris)

    # ------------------------------------------------------------------ #
    # notifikasi                                                          #
    # ------------------------------------------------------------------ #
    # Notifikasi TIDAK dikirim dari daemon. Daemon hanya menulis ke tabel #
    # notif; pengiriman dikerjakan sentinel-notify.sh dari systemd timer.  #
    # Alasannya: satu HTTP POST yang menggantung akan menahan           #
    # pemrosesan log, dan daemon membaca log setiap dua detik. Dengan     #
    # begitu, satu alamat tujuan yang nakal bisa membuat Sentinel        #
    # berhenti melihat serangan sama sekali.                             #
    # ------------------------------------------------------------------ #
    def get_aksi(self, get):
        """Jejak audit terbaru, bisa disaring per IP."""
        # limit bisa string (form panel) atau int (panggilan skrip).
        # .strip() buta tipe melempar AttributeError pada int.
        mentah = get.get('limit')
        if isinstance(mentah, str):
            mentah = mentah.strip()
        if mentah is None or mentah == '':
            mentah = '100'
        try:
            n = int(mentah)
        except (TypeError, ValueError):
            n = 100
        if n < 1:
            n = 1
        if n > 500:
            n = 500
        ip = (get.get('ip') or '').strip()
        args = []
        where = ''
        if ip:
            n_ip = self._ipnum(ip)
            if not n_ip:
                return public.returnMsg(False, 'alamat IP tidak valid')
            where = ' WHERE ip = ?'
            args.append(n_ip)
        args.append(n)
        baris = self._sql(
            'SELECT ts, ip, aksi, sumber, alasan, detik FROM aksi'
            + where + ' ORDER BY ts DESC, id DESC LIMIT ?', tuple(args))
        if isinstance(baris, dict):
            return baris
        for r in baris:
            r['ip'] = self._numip(r['ip'])
        return public.returnMsg(True, baris)

    def get_vhost_stat(self, get):
        """Statistik per-vhost: trafik, error, dan serangan."""
        jam = self._jam(get)
        if jam is None:
            return public.returnMsg(
                False, 'rentang jam harus angka antara 1 dan 720')
        sejak = int(time.time()) - jam * 3600

        # Trafik per host dari tabel minute.
        trafik = self._sql(
            'SELECT host, SUM(req) req, SUM(bytes) bytes,'
            ' SUM(s2) s2, SUM(s3) s3, SUM(s4) s4, SUM(s5) s5,'
            ' SUM(s429) s429'
            ' FROM minute WHERE ts >= ? AND host IS NOT NULL'
            " AND host <> '-' GROUP BY host ORDER BY req DESC", (sejak,))
        if isinstance(trafik, dict):
            return trafik

        # Serangan per host dari tabel events, yang kini punya host.
        Adv = self._sql(
            'SELECT host, COUNT(*) n, SUM(score) skor, MAX(score) puncak,'
            ' COUNT(DISTINCT ip) ip_unik,'
            ' COUNT(DISTINCT kind) jenis'
            " FROM events WHERE ts >= ? AND host IS NOT NULL AND host <> '-'"
            ' GROUP BY host ORDER BY n DESC', (sejak,))
        if isinstance(Adv, dict):
            return Adv

        peta_serang = dict((r['host'], r) for r in Adv)

        # Ambil virus per vhost dari vhost_quarantine dan hasil scan ClamAV
        peta_virus = {}
        try:
            vq = self._sql('SELECT vhost, COUNT(*) cnt FROM vhost_quarantine GROUP BY vhost')
            if vq and isinstance(vq, list):
                for row in vq:
                    vh = row.get('vhost')
                    if vh:
                        peta_virus[vh] = row.get('cnt', 0)
        except Exception:
            pass

        hasil = []
        for r in trafik:
            vh_name = r['host']
            req = r['req'] or 0
            s2 = r['s2'] or 0
            s3 = r['s3'] or 0
            s4 = r['s4'] or 0
            s5 = r['s5'] or 0

            # Cek juga hasil scan ClamAV per vhost
            v_cnt = peta_virus.get(vh_name, 0)
            try:
                vf = self._p('av', 'last', vh_name + '.json')
                if os.path.isfile(vf):
                    with open(vf, 'r', encoding='utf-8') as f:
                        sc = json.load(f)
                        v_cnt += sc.get('found', 0)
            except Exception:
                pass

            def _pct(jumlah):
                return round(jumlah * 100.0 / req, 2) if req > 0 else 0.0

            s = peta_serang.get(vh_name, {})
            hasil.append({
                'host': vh_name,
                'req': req,
                'bytes': r['bytes'] or 0,
                's2': s2,
                's3': s3,
                's4': s4,
                's5': s5,
                's429': r['s429'] or 0,
                'ok_persen': _pct(s2),
                'err4_persen': _pct(s4),
                'err5_persen': _pct(s5),
                'serangan': s.get('n', 0),
                'threats': s.get('n', 0),
                'skor_total': s.get('skor', 0),
                'skor_puncak': s.get('puncak', 0),
                'ip_penyerang': s.get('ip_unik', 0),
                'attackers': s.get('ip_unik', 0),
                'jenis_serang': s.get('jenis', 0),
                'virus': v_cnt,
            })
        return public.returnMsg(True, hasil)

    def get_vhost_ip(self, get):
        """Penyerang teratas untuk satu vhost."""
        jam = self._jam(get)
        if jam is None:
            return public.returnMsg(
                False, 'rentang jam harus angka antara 1 dan 720')
        sejak = int(time.time()) - jam * 3600
        host = (get.get('host') or '').strip()
        if not host:
            return public.returnMsg(False, 'host wajib diisi')
        mentah = (get.get('limit') or '').strip() or '50'
        try:
            n = int(mentah)
        except (TypeError, ValueError):
            n = 50
        if n < 1:
            n = 1
        if n > 200:
            n = 200
        baris = self._sql(
            'SELECT ip, COUNT(*) n, MAX(score) puncak, MAX(ts) terakhir,'
            ' GROUP_CONCAT(DISTINCT kind) jenis'
            ' FROM events WHERE ts >= ? AND host = ?'
            ' GROUP BY ip ORDER BY n DESC, puncak DESC LIMIT ?',
            (sejak, host, n))
        if isinstance(baris, dict):
            return baris
        for r in baris:
            r['ip'] = self._numip(r['ip'])
            r['jenis'] = (r.get('jenis') or '').replace(',', ', ')
        return public.returnMsg(True, baris)

    def flush_db(self, get):
        rc, o, e = self._sh("'%s/bin/guardctl' flush" % self.__PATH, 40)
        return public.returnMsg(True, o.strip() or 'statistik ditulis ke basis data')

    # ------------------------------------------------------------------ #
    # operasional                                                          #
    # ------------------------------------------------------------------ #
    def get_sites(self, get):
        """Daftar situs dari basis data panel, digabung dengan log yang
        benar-benar sedang ditail daemon."""
        situs = []
        try:
            data = public.M('sites').field('name,path,status').select()
            for i in data:
                situs.append({'name': i['name'], 'path': i['path'],
                              'status': i.get('status', '1')})
        except Exception as ex:
            return public.returnMsg(False, 'gagal membaca daftar situs: %s' % ex)
        st = self._status() or {}
        ditail = {}
        for lg in st.get('logs', []):
            ditail[lg['host']] = lg
        for s in situs:
            lg = ditail.get(s['name'])
            s['dipantau'] = bool(lg)
            s['baris'] = lg['lines'] if lg else 0
        return public.returnMsg(True, {
            'situs': situs,
            'lainnya': sorted([h for h in ditail if h not in
                                [s['name'] for s in situs]]),
        })

    def get_events(self, get):
        """Feed kejadian(classifikasi serangan) terbaru."""
        n = int(get.get('limit') or 60)
        if n < 1:
            n = 1
        if n > 300:
            n = 300
        baris = self._sql(
            "SELECT ts, ip, kind, score, level, host, path, ua "
            "FROM events ORDER BY ts DESC, id DESC LIMIT ?", (n,))
        for r in baris:
            r['ip'] = self._numip(r['ip'])
        return public.returnMsg(True, baris)

    def get_logs(self, get):
        n = int(get.get('limit') or 80)
        if n < 1:
            n = 1
        if n > 500:
            n = 500
        rc, o, e = self._sh("'%s/bin/guardctl' logs %d"
                            % (self.__PATH, n), 25)
        return public.returnMsg(True, o.strip().splitlines())

    def get_timeline(self, get):
        """Riwayat lengkap per IP beserta jumlah pelanggaran."""
        jam = int(get.get('hours') or 24)
        sejak = int(time.time()) - jam * 3600
        baris = self._sql(
            "SELECT ip, COUNT(*) n, MAX(score) puncak, MAX(ts) terakhir "
            "FROM ip_minute WHERE ts >= ? AND score > 0 "
            "GROUP BY ip ORDER BY n DESC LIMIT 100", (sejak,))
        for r in baris:
            r['ip'] = self._numip(r['ip'])
        return public.returnMsg(True, baris)

    # ------------------------------------------------------------------ #
    # Antivirus (ClamAV) & Integritas File                               #
    # ------------------------------------------------------------------ #
    def _av(self, subcommand, *args):
        """Panggil skrip pengelola Antivirus (sentinel-av.sh)."""
        skrip = self._p('bin', 'sentinel-av.sh')
        if not os.path.isfile(skrip):
            return 1, '', 'skrip sentinel-av.sh tidak ditemukan'
        cmd = "'%s' %s" % (skrip, subcommand)
        for a in args:
            cmd += " '%s'" % str(a).replace("'", "'\\''")
        return self._sh(cmd, 60)

    def get_av(self, get):
        """Status ClamAV, basis data, socket, karantina, dan Rkhunter."""
        rc, o, e = self._av('status')
        data = {
            'ada': 'tidak',
            'versi': '-',
            'db_umur': '-',
            'clamd': 'tidak',
            'quarantine': 0,
            'deteksi_hari_ini': 0,
            'common': 'tidak',
            'timer': 'tidak',
            'last_deepscan': None,
            'last_scan_all': None,
            'rkhunter': 'tidak',
            'rkhunter_versi': '-',
            'rkhunter_last_scan': None,
            'rkhunter_warnings': 0,
            'active_scan': None
        }
        if rc == 0:
            for baris in o.strip().splitlines():
                if '=' in baris:
                    k, v = baris.split('=', 1)
                    k = k.strip()
                    v = v.strip()
                    if k in ('quarantine', 'deteksi_hari_ini', 'rkhunter_warnings'):
                        try:
                            data[k] = int(v)
                        except Exception:
                            data[k] = 0
                    elif k == 'rkhunter_last_scan':
                        if v != '-' and v.isdigit():
                            try:
                                data[k] = int(v)
                            except Exception:
                                data[k] = v
                        else:
                            data[k] = v
                    else:
                        data[k] = v

        # Ringkasan deepscan harian dari summary.log bila ada
        sum_log = '/var/log/clamav/summary.log'
        if os.path.isfile(sum_log):
            try:
                with open(sum_log, 'r') as f:
                    isi = f.read()
                blok = isi.strip().split('==============================================================')
                if len(blok) > 1:
                    terakhir = blok[-1].strip()
                    info = {}
                    for baris in terakhir.splitlines():
                        if 'date=' in baris:
                            for bagian in baris.split():
                                if '=' in bagian:
                                    k, val = bagian.split('=', 1)
                                    info[k] = val
                        elif 'scanned=' in baris:
                            for bagian in baris.split():
                                if '=' in bagian:
                                    k, val = bagian.split('=', 1)
                                    info[k] = val
                    if info:
                        data['last_deepscan'] = info
            except Exception:
                pass

        # Ringkasan scan all terakhir dari av/last/all.json
        all_json = self._p('av', 'last', 'all.json')
        if os.path.isfile(all_json):
            try:
                with open(all_json, 'r') as f:
                    data['last_scan_all'] = json.load(f)
            except Exception:
                pass

        # Status pemindaian realtime aktif (active_scan.json)
        active_f = self._p('run', 'active_scan.json')
        if os.path.isfile(active_f):
            try:
                with open(active_f, 'r') as f:
                    data['active_scan'] = json.load(f)
            except Exception:
                pass

        return public.returnMsg(True, data)

    def get_av_sites(self, get):
        """Daftar situs vhost panel lengkap dengan status pemindaian terakhir
        dan status rekaman baseline integritas."""
        situs = []
        try:
            data = public.M('sites').field('name,path,status').select()
            for i in data:
                situs.append({'name': i['name'], 'path': i['path'],
                              'status': i.get('status', '1')})
        except Exception as ex:
            return public.returnMsg(False, 'Gagal membaca daftar situs: %s' % ex)

        for s in situs:
            name = s['name']
            # Cek hasil scan terakhir
            scan_f = self._p('av', 'last', name + '.json')
            if os.path.isfile(scan_f):
                try:
                    with open(scan_f, 'r') as f:
                        s['last_scan'] = json.load(f)
                except Exception:
                    s['last_scan'] = None
            else:
                s['last_scan'] = None

            # Cek baseline integritas
            base_f = self._p('av', 'baseline', name + '.txt')
            if os.path.isfile(base_f):
                s['has_baseline'] = True
                try:
                    with open(base_f, 'r') as f:
                        s['baseline_count'] = sum(1 for line in f if line.strip())
                except Exception:
                    s['baseline_count'] = 0
            else:
                s['has_baseline'] = False
                s['baseline_count'] = 0

            # Cek hasil periksa integritas terakhir
            integ_f = self._p('av', 'last', 'integ-' + name + '.txt')
            if os.path.isfile(integ_f):
                try:
                    with open(integ_f, 'r') as f:
                        s['integrity_changes'] = sum(1 for line in f if line.strip())
                except Exception:
                    s['integrity_changes'] = 0
            else:
                s['integrity_changes'] = None

        return public.returnMsg(True, situs)

    def av_scan(self, get):
        """Mulai pemindaian antivirus untuk satu direktori / vhost."""
        path = str(get.get('path', '')).strip()
        label = self._only(get, 'label', '')
        engine = str(get.get('engine', 'both')).strip().lower()
        if engine not in ('clamav', 'rkhunter', 'both'):
            engine = 'both'

        if not path or not os.path.isdir(path):
            return public.returnMsg(False, 'Direktori vhost tidak valid atau tidak ditemukan: %s' % path)
        if not label:
            label = os.path.basename(path.rstrip('/'))
        label = ''.join(c for c in label if c.isalnum() or c in '._-')

        sync = str(get.get('sync', '0')) == '1'
        if sync:
            rc, o, e = self._av('scan', path, label)
            if rc == 0:
                return public.returnMsg(True, o.strip() or 'Pemindaian selesai')
            return public.returnMsg(False, e.strip() or o.strip() or 'Pemindaian gagal')

        return self.av_scan_start(get)

    def av_scan_start(self, get):
        """Mulai pemindaian realtime streaming (ClamAV, Rkhunter, Ransomware, Judol, Mining, atau All-in-One)."""
        engine = str(get.get('engine', 'both')).strip().lower()
        if engine not in ('clamav', 'rkhunter', 'both', 'all', 'judol', 'ransomware', 'mining'):
            engine = 'both'

        target_type = str(get.get('target_type', 'vhost')).strip().lower()
        path = str(get.get('path', '')).strip()
        label = self._only(get, 'label', '')

        if target_type == 'system' or path in ('system', '/'):
            target_type = 'system'
            path = '/'
            if not label:
                label = 'system'
        else:
            if not path or (not os.path.isdir(path) and not os.path.isfile(path)):
                return public.returnMsg(False, 'Path direktori atau target pemindaian tidak valid: %s' % path)
            if not label:
                label = os.path.basename(path.rstrip('/'))
            label = ''.join(c for c in label if c.isalnum() or c in '._-')

        # Cek apakah ada proses pemindaian yang masih aktif
        pid_f = self._p('run', 'active_scan.pid')
        if os.path.isfile(pid_f):
            try:
                with open(pid_f, 'r') as f:
                    p = int(f.read().strip())
                if p > 0:
                    os.kill(p, 0)
                    return public.returnMsg(False, 'Pemindaian lain sedang berjalan (PID %d). Harap tunggu hingga selesai atau batalkan terlebih dahulu.' % p)
            except Exception:
                pass

        skrip = self._p('bin', 'sentinel-av.sh')
        if not os.path.isfile(skrip):
            return public.returnMsg(False, 'Skrip sentinel-av.sh tidak ditemukan')

        log_f = self._p('log', 'active_scan.log')
        try:
            with open(log_f, 'w') as f:
                f.write('')
        except Exception:
            pass

        cmd = "nohup '%s' scan-stream '%s' '%s' '%s' >> '%s' 2>&1 &" % (
            skrip, engine, path, label, log_f
        )
        os.system(cmd)
        return public.returnMsg(True, 'Pemindaian realtime untuk %s (%s) berhasil dimulai' % (label, engine))

    def get_scan_stream(self, get):
        """Ambil stream output log pemindaian realtime baris-per-baris."""
        offset = self._int(get, 'offset', 0, 0, 1000000) or 0
        log_f = self._p('log', 'active_scan.log')
        meta_f = self._p('run', 'active_scan.json')
        pid_f = self._p('run', 'active_scan.pid')

        meta = {}
        if os.path.isfile(meta_f):
            try:
                with open(meta_f, 'r') as f:
                    meta = json.load(f)
            except Exception:
                pass

        status = meta.get('status', 'idle')
        is_running = (status == 'running')

        if is_running and not os.path.isfile(pid_f) and (time.time() - meta.get('mulai', 0) > 3):
            status = 'done'
            meta['status'] = 'done'
            is_running = False

        lines = []
        total_lines = 0
        if os.path.isfile(log_f):
            try:
                with open(log_f, 'r', errors='ignore') as f:
                    all_lines = f.readlines()
                total_lines = len(all_lines)
                if offset < total_lines:
                    lines = [l.rstrip('\r\n') for l in all_lines[offset:]]
            except Exception:
                pass

        res = {
            'status': status,
            'is_running': is_running,
            'meta': meta,
            'lines': lines,
            'offset': total_lines,
            'complete': (status in ('done', 'aborted'))
        }
        return public.returnMsg(True, res)

    def av_scan_abort(self, get):
        """Batalkan pemindaian yang sedang berjalan."""
        pid_f = self._p('run', 'active_scan.pid')
        meta_f = self._p('run', 'active_scan.json')
        log_f = self._p('log', 'active_scan.log')

        stopped = False
        if os.path.isfile(pid_f):
            try:
                with open(pid_f, 'r') as f:
                    p = int(f.read().strip())
                if p > 0:
                    try:
                        os.kill(p, 15)
                        time.sleep(0.3)
                        try:
                            os.kill(p, 0)
                            os.kill(p, 9)
                        except Exception:
                            pass
                        stopped = True
                    except Exception:
                        pass
                os.remove(pid_f)
            except Exception:
                pass

        if os.path.isfile(meta_f):
            try:
                with open(meta_f, 'r') as f:
                    meta = json.load(f)
                meta['status'] = 'aborted'
                meta['summary'] = 'DIBATALKAN OLEH OPERATOR'
                with open(meta_f, 'w') as f:
                    json.dump(meta, f)
            except Exception:
                pass

        if os.path.isfile(log_f):
            try:
                with open(log_f, 'a') as f:
                    f.write("\n[!] PEMINDAIAN DIHENTIKAN OLEH OPERATOR.\n")
            except Exception:
                pass

        return public.returnMsg(True, 'Pemindaian berhasil dihentikan.')

    def rkhunter_propupd(self, get):
        """Perbarui database file properties hash Rkhunter."""
        rc, o, e = self._av('rkhunter-propupd')
        if rc == 0:
            return public.returnMsg(True, 'Database file properties Rkhunter berhasil diperbarui.')
        return public.returnMsg(False, 'Gagal memperbarui file properties Rkhunter: ' + (e.strip() or o.strip()))

    def rkhunter_update(self, get):
        """Perbarui basis data signature Rkhunter."""
        rc, o, e = self._av('rkhunter-update')
        if rc == 0:
            return public.returnMsg(True, 'Database signature Rkhunter berhasil diperbarui: ' + o.strip())
        return public.returnMsg(False, 'Pembaruan signature Rkhunter gagal: ' + (e.strip() or o.strip()))

    def av_scan_all(self, get):
        """Jalankan pemindaian seluruh vhost di latar belakang."""
        skrip = self._p('bin', 'sentinel-av.sh')
        all_f = self._p('av', 'last', 'all.json')
        try:
            with open(all_f, 'w') as f:
                json.dump({
                    'label': 'all',
                    'status': 'running',
                    'mulai': int(time.time())
                }, f)
        except Exception:
            pass
        cmd = "nohup '%s' scan-all >/dev/null 2>&1 &" % skrip
        os.system(cmd)
        return public.returnMsg(True, 'Pemindaian seluruh vhost dimulai di latar belakang')

    def av_scan_progress(self, get):
        """Ambil kemajuan atau hasil pemindaian vhost."""
        label = self._only(get, 'label', '')
        if label:
            label = ''.join(c for c in label if c.isalnum() or c in '._-')
            fpath = self._p('av', 'last', label + '.json')
            if not os.path.isfile(fpath):
                return public.returnMsg(False, 'Belum ada data pemindaian untuk ' + label)
            try:
                with open(fpath, 'r') as f:
                    return public.returnMsg(True, json.load(f))
            except Exception as ex:
                return public.returnMsg(False, 'Gagal membaca status pemindaian: %s' % ex)

        # Ambil semua hasil terakhir
        hasil = []
        last_dir = self._p('av', 'last')
        if os.path.isdir(last_dir):
            for fn in os.listdir(last_dir):
                if fn.endswith('.json') and not fn.startswith('.'):
                    try:
                        with open(os.path.join(last_dir, fn), 'r') as f:
                            hasil.append(json.load(f))
                    except Exception:
                        pass
        return public.returnMsg(True, hasil)

    def get_av_quarantine(self, get):
        """Daftar berkas yang dikarantina beserta metadatanya."""
        rc, o, e = self._av('quarantine-list')
        items = []
        if rc == 0:
            for baris in o.strip().splitlines():
                if not baris or baris.startswith('[sentinel-av]') or baris.startswith('karantina kosong'):
                    continue
                bagian = baris.split('|')
                if len(bagian) >= 5:
                    items.append({
                        'id': bagian[0],
                        'waktu': bagian[1],
                        'virus': bagian[2],
                        'path': bagian[3],
                        'ukuran': int(bagian[4]) if bagian[4].isdigit() else 0
                    })
        return public.returnMsg(True, items)

    def av_restore(self, get):
        """Kembalikan berkas dari karantina ke lokasi asalnya."""
        qid = self._only(get, 'id', '')
        if not qid:
            return public.returnMsg(False, 'ID karantina tidak boleh kosong')
        qid = ''.join(c for c in qid if c.isalnum() or c in '._-')
        rc, o, e = self._av('quarantine-restore', qid)
        if rc == 0:
            return public.returnMsg(True, o.strip() or 'Berkas berhasil dikembalikan dari karantina')
        return public.returnMsg(False, e.strip() or o.strip() or 'Gagal mengembalikan berkas dari karantina')

    def av_delete(self, get):
        """Hapus satu berkas karantina secara permanen."""
        qid = self._only(get, 'id', '')
        if not qid:
            return public.returnMsg(False, 'ID karantina tidak boleh kosong')
        qid = ''.join(c for c in qid if c.isalnum() or c in '._-')
        rc, o, e = self._av('quarantine-delete', qid)
        if rc == 0:
            return public.returnMsg(True, o.strip() or 'Berkas karantina berhasil dihapus permanen')
        return public.returnMsg(False, e.strip() or o.strip() or 'Gagal menghapus berkas karantina')

    def av_purge(self, get):
        """Hapus SEMUA berkas karantina secara permanen."""
        rc, o, e = self._av('quarantine-purge')
        if rc == 0:
            return public.returnMsg(True, o.strip() or 'Semua berkas karantina telah dibersihkan')
        return public.returnMsg(False, e.strip() or o.strip() or 'Gagal membersihkan karantina')

    def av_baseline(self, get):
        """Rekam baseline integritas SHA-256 untuk berkas web pada vhost."""
        path = str(get.get('path', '')).strip()
        label = self._only(get, 'label', '')
        if not path or not os.path.isdir(path):
            return public.returnMsg(False, 'Direktori vhost tidak valid atau tidak ditemukan: %s' % path)
        if not label:
            label = os.path.basename(path.rstrip('/'))
        label = ''.join(c for c in label if c.isalnum() or c in '._-')
        rc, o, e = self._av('baseline', path, label)
        if rc == 0:
            return public.returnMsg(True, o.strip() or 'Baseline integritas berhasil direkam')
        return public.returnMsg(False, e.strip() or o.strip() or 'Gagal merekam baseline integritas')

    def av_check(self, get):
        """Periksa integritas berkas terhadap baseline yang tersimpan."""
        path = str(get.get('path', '')).strip()
        label = self._only(get, 'label', '')
        if not path or not os.path.isdir(path):
            return public.returnMsg(False, 'Direktori vhost tidak valid atau tidak ditemukan: %s' % path)
        if not label:
            label = os.path.basename(path.rstrip('/'))
        label = ''.join(c for c in label if c.isalnum() or c in '._-')
        rc, o, e = self._av('check', path, label)
        if rc == 0:
            return public.returnMsg(True, o.strip() or 'Pemeriksaan integritas selesai')
        return public.returnMsg(False, e.strip() or o.strip() or 'Gagal memeriksa integritas berkas')

    def get_av_integrity(self, get):
        """Daftar perubahan integritas berkas web (ditambah, diubah, dihapus)."""
        label = self._only(get, 'label', '')
        if label:
            label = ''.join(c for c in label if c.isalnum() or c in '._-')
            rc, o, e = self._av('integ-list', label)
        else:
            rc, o, e = self._av('integ-list')
        items = []
        if rc == 0:
            for baris in o.strip().splitlines():
                if not baris or baris.startswith('[sentinel-av]') or baris.startswith('(belum ada'):
                    continue
                bagian = baris.split('|')
                if len(bagian) >= 4:
                    items.append({
                        'jenis': bagian[0],
                        'path': bagian[1],
                        'hash_lama': bagian[2],
                        'hash_baru': bagian[3]
                    })
        return public.returnMsg(True, items)

    def av_db_update(self, get):
        """Pembaruan manual basis data virus ClamAV via freshclam."""
        rc, o, e = self._av('db-update')
        if rc == 0:
            return public.returnMsg(True, 'Basis data virus ClamAV berhasil diperbarui: ' + o.strip())
        return public.returnMsg(False, 'Pembaruan basis data virus gagal: ' + (e.strip() or o.strip()))

    def get_av_logs(self, get):
        """Log kejadian pemindaian dan deteksi ClamAV & Rkhunter."""
        limit = self._int(get, 'limit', 60, 1, 500) or 60
        jenis = self._only(get, 'kind', 'scan')
        log_file = '/var/log/clamav/scan.log'
        if jenis == 'event':
            log_file = '/var/log/clamav/realtime.log'
        elif jenis == 'summary':
            log_file = '/var/log/clamav/summary.log'
        elif jenis == 'av':
            log_file = self._p('log', 'av.log')
        elif jenis == 'active':
            log_file = self._p('log', 'active_scan.log')
        elif jenis == 'rkhunter':
            log_file = self._p('log', 'rkhunter.log')

        if not os.path.isfile(log_file):
            return public.returnMsg(True, [])

        try:
            with open(log_file, 'r', errors='ignore') as f:
                baris = f.readlines()
            baris = [b.strip() for b in baris if b.strip()]
            return public.returnMsg(True, baris[-limit:])
        except Exception as ex:
            return public.returnMsg(False, 'Gagal membaca log: %s' % ex)

    # ------------------------------------------------------------------ #
    # CYBERSECURITY DEFENDER ELIT: DEFCON, EGRESS, PROC GUARD, INTEL     #
    # ------------------------------------------------------------------ #
    def get_elite_posture(self, get):
        """Ambil postur pertahanan menyeluruh (DEFCON, Guard Status, & SOC KPI)."""
        panic_on = os.path.isfile(self._p('run', 'panic.state'))
        egress_state_file = self._p('run', 'egress.state')
        egress_on = os.path.isfile(egress_state_file)
        
        proc_state_file = self._p('run', 'proc_guard.state')
        proc_pid_file = self._p('run', 'proc_guard.pid')
        proc_info = {'status': 'stopped', 'mode': 'enforce', 'scans': '0', 'alerts': '0', 'kills': '0'}
        if os.path.isfile(proc_state_file):
            try:
                with open(proc_state_file, 'r') as f:
                    for line in f:
                        if '=' in line:
                            k, v = line.strip().split('=', 1)
                            proc_info[k] = v
            except Exception:
                pass
        proc_pid_active = False
        if os.path.isfile(proc_pid_file):
            try:
                with open(proc_pid_file) as f:
                    p = int(f.read().strip())
                    os.kill(p, 0)
                    proc_pid_active = True
            except Exception:
                pass
        proc_info['service_active'] = proc_pid_active
        
        intel_count = 0
        try:
            out = subprocess.check_output(['/usr/sbin/ipset', 'list', 'sentinel_intel'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            intel_count = sum(1 for line in out.splitlines() if line and line[0].isdigit())
        except Exception:
            pass
            
        sys_integ_file = self._p('av', 'last', 'integ-sys-persistence.txt')
        sys_changes = 0
        sys_tampered_list = []
        if os.path.isfile(sys_integ_file):
            try:
                with open(sys_integ_file, 'r', errors='ignore') as f:
                    lines = [l.strip() for l in f if l.strip()]
                    sys_changes = len(lines)
                    sys_tampered_list = lines[:10]
            except Exception:
                pass
                
        waf_engine = 'free_waf'
        try:
            c = self._waf_conf_baca()
            waf_engine = c.get('engine', 'free_waf')
        except Exception:
            pass
            
        ban_count = 0
        try:
            out = subprocess.check_output(['/usr/sbin/ipset', 'list', 'sentinel_ban'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            ban_count = sum(1 for line in out.splitlines() if line and line[0].isdigit())
        except Exception:
            pass
            
        proc_alerts = []
        try:
            proc_alerts = self._sql("SELECT id, ts, pid, ppid, uid, exe, cmdline, cwd, rule, action FROM proc_alerts ORDER BY id DESC LIMIT 50")
            if not isinstance(proc_alerts, list):
                proc_alerts = []
        except Exception:
            proc_alerts = []

        proc_wl_count = 0
        try:
            if os.path.isfile(self.PROC_WHITELIST_CONF):
                with open(self.PROC_WHITELIST_CONF, 'r', errors='ignore') as f:
                    proc_wl_count = len(json.load(f))
        except Exception:
            pass
            
        defcon = 3
        defcon_title = "DEFCON 3 -- PERTAHANAN PENUH AKTIF"
        defcon_desc = "Seluruh layer pertahanan (Firewall kernel, WAF, Egress Guard, Process Guard, Threat Intel) berjalan optimal tanpa insiden."
        
        recent_kills = int(proc_info.get('kills', 0) or 0)
        now_ts = int(time.time())
        recent_alert = False
        if proc_alerts and (now_ts - int(proc_alerts[0].get('ts', 0) or 0) < 900):
            recent_alert = True
            
        if panic_on:
            defcon = 1
            defcon_title = "DEFCON 1 -- DARURAT (PANIC MODE)"
            defcon_desc = "Server dalam karantina total: seluruh akses HTTP/HTTPS publik diblokir di tingkat kernel demi investigasi insiden."
        elif recent_kills > 0 or recent_alert or sys_changes > 0:
            defcon = 2
            defcon_title = "DEFCON 2 -- ANCAMAN TERDETEKSI & DINETRALISIR"
            defcon_desc = "Upaya serangan RCE/eksekusi ilegal atau anomali persistensi terdeteksi dan dinetralisir dalam 15 menit terakhir."
        elif not egress_on or not proc_pid_active or intel_count == 0:
            defcon = 4
            defcon_title = "DEFCON 4 -- PERTAHANAN PARSIAL"
            defcon_desc = "Beberapa modul pertahanan elit (Egress, Process Guard, atau Intel Feed) sedang dalam kondisi nonaktif."

        return public.returnMsg(True, {
            'defcon': defcon,
            'defcon_title': defcon_title,
            'defcon_desc': defcon_desc,
            'panic_on': panic_on,
            'egress_guard': {
                'active': egress_on,
                'uid': 1002,
                'user': 'www',
                'allowed_ports': '53, 80, 443, 587, 465'
            },
            'proc_guard': {
                'active': proc_pid_active,
                'mode': proc_info.get('mode', 'enforce'),
                'scans': int(proc_info.get('scans', 0) or 0),
                'alerts': int(proc_info.get('alerts', 0) or 0),
                'kills': int(proc_info.get('kills', 0) or 0),
                'whitelisted': int(proc_info.get('whitelisted', 0) or 0),
                'last_scan': proc_info.get('last_scan', '-')
            },
            'threat_intel': {
                'active': intel_count > 0,
                'count': intel_count,
                'source': 'Spamhaus DROP & EDROP',
                'timer': 'sentinel-intel.timer (2x sehari)'
            },
            'sys_persistence': {
                'status': 'clean' if sys_changes == 0 else 'tampered',
                'changes': sys_changes,
                'tampered_files': sys_tampered_list
            },
            'waf_engine': waf_engine,
            'bans_active': ban_count,
            'recent_alerts': proc_alerts,
            'proc_whitelist_count': proc_wl_count
        })

    def set_egress_guard(self, get):
        """Aktifkan atau nonaktifkan pengaman lalu lintas keluar (Anti-Reverse Shell)."""
        status = self._only(get, 'status', 'on')
        if status not in ('on', 'off'):
            return public.returnMsg(False, 'Status harus "on" atau "off"')
        cmd = [self._p('bin', 'sentinel-fw.sh'), 'egress-' + status]
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            return public.returnMsg(True, 'Egress Guard berhasil diatur ke ' + status.upper() + ': ' + res.strip())
        except subprocess.CalledProcessError as e:
            return public.returnMsg(False, 'Gagal mengatur Egress Guard: ' + e.output.decode('utf-8', errors='ignore'))

    def set_proc_guard(self, get):
        """Ubah mode Process Guard (enforce / audit / off)."""
        mode = self._only(get, 'mode', 'enforce')
        if mode not in ('enforce', 'audit', 'off'):
            return public.returnMsg(False, 'Mode harus enforce, audit, atau off')
            
        conf_file = self._p('etc', 'guardd.conf')
        lines = []
        found = False
        if os.path.exists(conf_file):
            with open(conf_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip().startswith('proc_guard'):
                        lines.append('proc_guard = ' + mode + '\n')
                        found = True
                    else:
                        lines.append(line)
        if not found:
            lines.append('proc_guard = ' + mode + '\n')
        with open(conf_file, 'w', encoding='utf-8') as f:
            f.writelines(lines)
            
        if mode == 'off':
            os.system('systemctl stop sentinel-proc.service 2>/dev/null')
        else:
            os.system('systemctl restart sentinel-proc.service 2>/dev/null')
            
        return public.returnMsg(True, 'Process Guard berhasil disetel ke mode: ' + mode.upper())

    def update_threat_intel(self, get):
        """Perbarui feed Threat Intel Spamhaus DROP/EDROP sekarang."""
        cmd = [self._p('bin', 'sentinel-intel.sh'), 'update']
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            return public.returnMsg(True, 'Threat Intel berhasil diperbarui: ' + res.strip())
        except subprocess.CalledProcessError as e:
            return public.returnMsg(False, 'Gagal memperbarui Threat Intel: ' + e.output.decode('utf-8', errors='ignore'))

    def av_check_persistence(self, get):
        """Jalankan verifikasi integritas persistensi sistem sekarang."""
        cmd = [self._p('bin', 'sentinel-av.sh'), 'check-sys']
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            return public.returnMsg(True, res.strip())
        except subprocess.CalledProcessError as e:
            return public.returnMsg(False, 'Pemeriksaan gagal: ' + e.output.decode('utf-8', errors='ignore'))

    def av_baseline_persistence(self, get):
        """Buat ulang baseline integritas persistensi sistem."""
        cmd = [self._p('bin', 'sentinel-av.sh'), 'baseline-sys']
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            return public.returnMsg(True, res.strip())
        except subprocess.CalledProcessError as e:
            return public.returnMsg(False, 'Baseline gagal: ' + e.output.decode('utf-8', errors='ignore'))

    # ------------------------------------------------------------------ #
    # EDR / PROCESS GUARD WHITELIST CRUD                                 #
    # ------------------------------------------------------------------ #
    def get_proc_whitelist(self, get):
        """Daftar aturan whitelist proses yang diizinkan untuk pekerja web."""
        try:
            if not os.path.isfile(self.PROC_WHITELIST_CONF):
                return public.returnMsg(True, [])
            with open(self.PROC_WHITELIST_CONF, 'r', encoding='utf-8', errors='ignore') as f:
                rules = json.load(f)
            return public.returnMsg(True, rules)
        except Exception as e:
            return public.returnMsg(False, 'Gagal membaca whitelist: %s' % str(e))

    def add_proc_whitelist(self, get):
        """Tambah aturan whitelist proses baru."""
        name = str(get.get('name', '')).strip()
        w_type = str(get.get('type', 'cmdline_match')).strip().lower()
        pattern = str(get.get('pattern', '')).strip()
        remark = str(get.get('remark', '')).strip()

        if not pattern:
            return public.returnMsg(False, 'Pola pencocokan (pattern) wajib diisi')
        if not name:
            name = 'Whitelist ' + pattern[:30]
        if w_type not in ('cmdline_match', 'exe_exact', 'basename', 'cwd_match'):
            w_type = 'cmdline_match'

        try:
            rules = []
            if os.path.isfile(self.PROC_WHITELIST_CONF):
                with open(self.PROC_WHITELIST_CONF, 'r', encoding='utf-8', errors='ignore') as f:
                    rules = json.load(f)

            rule_id = 'wl-%d' % int(time.time())
            new_rule = {
                'id': rule_id,
                'name': name,
                'type': w_type,
                'pattern': pattern,
                'remark': remark,
                'created_at': int(time.time()),
                'enabled': True
            }
            rules.append(new_rule)

            with open(self.PROC_WHITELIST_CONF, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2)

            return public.returnMsg(True, "Aturan whitelist '%s' berhasil ditambahkan dan langsung aktif" % name)
        except Exception as ex:
            return public.returnMsg(False, 'Gagal menyimpan aturan whitelist: %s' % str(ex))

    def del_proc_whitelist(self, get):
        """Hapus aturan whitelist berdasarkan ID."""
        rule_id = str(get.get('id', '')).strip()
        if not rule_id:
            return public.returnMsg(False, 'ID aturan wajib diisi')

        try:
            if not os.path.isfile(self.PROC_WHITELIST_CONF):
                return public.returnMsg(False, 'Berkas whitelist tidak ditemukan')
            with open(self.PROC_WHITELIST_CONF, 'r', encoding='utf-8', errors='ignore') as f:
                rules = json.load(f)

            filtered = [r for r in rules if r.get('id') != rule_id]
            if len(filtered) == len(rules):
                return public.returnMsg(False, 'Aturan dengan ID tersebut tidak ditemukan')

            with open(self.PROC_WHITELIST_CONF, 'w', encoding='utf-8') as f:
                json.dump(filtered, f, indent=2)

            return public.returnMsg(True, 'Aturan whitelist berhasil dihapus')
        except Exception as ex:
            return public.returnMsg(False, 'Gagal menghapus aturan whitelist: %s' % str(ex))

    def toggle_proc_whitelist(self, get):
        """Aktifkan atau nonaktifkan aturan whitelist."""
        rule_id = str(get.get('id', '')).strip()
        if not rule_id:
            return public.returnMsg(False, 'ID aturan wajib diisi')

        try:
            if not os.path.isfile(self.PROC_WHITELIST_CONF):
                return public.returnMsg(False, 'Berkas whitelist tidak ditemukan')
            with open(self.PROC_WHITELIST_CONF, 'r', encoding='utf-8', errors='ignore') as f:
                rules = json.load(f)

            found = False
            new_status = False
            for r in rules:
                if r.get('id') == rule_id:
                    r['enabled'] = not r.get('enabled', True)
                    new_status = r['enabled']
                    found = True
                    break

            if not found:
                return public.returnMsg(False, 'Aturan tidak ditemukan')

            with open(self.PROC_WHITELIST_CONF, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2)

            st_text = 'diaktifkan' if new_status else 'dinonaktifkan'
            return public.returnMsg(True, "Aturan whitelist berhasil %s" % st_text)
        except Exception as ex:
            return public.returnMsg(False, 'Gagal mengubah status whitelist: %s' % str(ex))

    # ------------------------------------------------------------------ #
    # Real-Time Upload Scanner & Per-Host Quarantine (Imunify360 Style)  #
    # ------------------------------------------------------------------ #
    def _upload_scan_cli(self, *args):
        """Panggil biner sentinel-upload-scan.py dengan pyenv python3."""
        script = self._p('bin', 'sentinel-upload-scan.py')
        py_bin = '/www/server/panel/pyenv/bin/python3'
        if not os.path.exists(py_bin):
            py_bin = 'python3'
        cmd = [py_bin, script] + list(args)
        cmd_str = ' '.join(["'%s'" % c for c in cmd])
        return self._sh(cmd_str, 30)

    def get_vhost_upload_scan(self, get):
        """Ambil status upload scanner, clamd socket, RAM, dan status per vhost."""
        rc, o, e = self._upload_scan_cli('status')
        if rc != 0:
            return public.returnMsg(False, 'Gagal mengambil status upload scanner: %s' % (e or o))
        try:
            data = json.loads(o)
            rc_svc, o_svc, _ = self._sh('systemctl is-active sentinel-upload-scan.service', 5)
            data['systemd_active'] = (o_svc.strip() == 'active')
            return public.returnMsg(True, data)
        except Exception as ex:
            return public.returnMsg(False, 'Galat parsing respons status: %s' % str(ex))

    def toggle_vhost_upload_scan(self, get):
        """Aktifkan atau nonaktifkan pemindaian upload realtime untuk satu vhost."""
        vhost = str(get.get('vhost', '')).strip()
        if not vhost or '/' in vhost or '..' in vhost:
            return public.returnMsg(False, 'Nama vhost tidak valid')
        rc, o, e = self._upload_scan_cli('toggle-vhost', vhost)
        if rc != 0:
            return public.returnMsg(False, 'Gagal mengubah status vhost: %s' % (e or o))
        try:
            res = json.loads(o)
            st_str = 'diaktifkan' if res.get('enabled') else 'dinonaktifkan'
            return public.returnMsg(True, "Upload Protection untuk vhost '%s' berhasil %s" % (vhost, st_str))
        except Exception as ex:
            return public.returnMsg(False, 'Galat respons toggle: %s' % str(ex))

    def set_vhost_upload_scan(self, get):
        """Setel status upload scan untuk satu vhost (on / off)."""
        vhost = str(get.get('vhost', '')).strip()
        state = str(get.get('state', '')).strip().lower()
        if not vhost or '/' in vhost or '..' in vhost:
            return public.returnMsg(False, 'Nama vhost tidak valid')
        val = 'on' if state in ['1', 'true', 'on', 'yes'] else 'off'
        rc, o, e = self._upload_scan_cli('set-vhost', vhost, val)
        if rc != 0:
            return public.returnMsg(False, 'Gagal menyimpan status vhost: %s' % (e or o))
        try:
            res = json.loads(o)
            return public.returnMsg(True, res)
        except Exception as ex:
            return public.returnMsg(False, str(ex))

    def get_vhost_quarantine(self, get):
        """Daftar berkas karantina per vhost (atau seluruh vhost jika vhost kosong)."""
        vhost = str(get.get('vhost', '')).strip()
        if vhost and ('/' in vhost or '..' in vhost):
            return public.returnMsg(False, 'Nama vhost tidak valid')
        args = ['quarantine-list']
        if vhost:
            args.append(vhost)
        rc, o, e = self._upload_scan_cli(*args)
        if rc != 0:
            return public.returnMsg(False, 'Gagal mengambil daftar karantina: %s' % (e or o))
        try:
            items = json.loads(o)
            return public.returnMsg(True, items)
        except Exception as ex:
            return public.returnMsg(False, str(ex))

    def restore_vhost_quarantine(self, get):
        """Pulihkan berkas karantina ke lokasi aslinya dan kembalikan hak akses."""
        meta = str(get.get('meta', '')).strip()
        if not meta or not meta.endswith('.meta') or not meta.startswith('/www/server/sentinel/av/quarantine/'):
            return public.returnMsg(False, 'Berkas metadata karantina tidak valid')
        rc, o, e = self._upload_scan_cli('quarantine-restore', meta)
        if rc != 0:
            return public.returnMsg(False, 'Gagal memulihkan berkas: %s' % (e or o))
        try:
            res = json.loads(o)
            if res.get('status'):
                return public.returnMsg(True, res.get('msg', 'Berkas berhasil dipulihkan'))
            else:
                return public.returnMsg(False, res.get('msg', 'Pemulihan gagal'))
        except Exception as ex:
            return public.returnMsg(False, str(ex))

    def delete_vhost_quarantine(self, get):
        """Hapus permanen berkas karantina dan metadata-nya."""
        meta = str(get.get('meta', '')).strip()
        if not meta or not meta.endswith('.meta') or not meta.startswith('/www/server/sentinel/av/quarantine/'):
            return public.returnMsg(False, 'Berkas metadata karantina tidak valid')
        rc, o, e = self._upload_scan_cli('quarantine-delete', meta)
        if rc != 0:
            return public.returnMsg(False, 'Gagal menghapus karantina: %s' % (e or o))
        try:
            res = json.loads(o)
            if res.get('status'):
                return public.returnMsg(True, res.get('msg', 'Berkas karantina berhasil dihapus'))
            else:
                return public.returnMsg(False, res.get('msg', 'Gagal menghapus'))
        except Exception as ex:
            return public.returnMsg(False, str(ex))

    def toggle_upload_scan_service(self, get):
        """Nyalakan atau hentikan layanan daemon sentinel-upload-scan.service."""
        action = str(get.get('action', '')).strip().lower()
        if action not in ['start', 'stop', 'restart']:
            return public.returnMsg(False, 'Aksi tidak valid (start|stop|restart)')
        rc, o, e = self._sh("systemctl %s sentinel-upload-scan.service" % action, 15)
        if rc != 0:
            return public.returnMsg(False, "Gagal %s layanan: %s" % (action, e or o))
        return public.returnMsg(True, "Layanan sentinel-upload-scan berhasil di-%s" % action)

    # -------------------------------------------------------------------------
    # MANAJEMEN SIKLUS HIDUP (LIFECYCLE): FRESH | UPDATE | REPAIR | UNINSTALL
    # DUKUNGAN TELEMETRI GOOGLE ANALYTICS & TERMS POLICY
    # -------------------------------------------------------------------------
    def _is_telemetry_enabled(self):
        """Periksa apakah pengiriman statistik telemetri GTM / GA4 diizinkan. Default adalah On (True)."""
        conf_p = self._p('etc', 'telemetry.json')
        if not os.path.isfile(conf_p):
            conf_p = os.path.join(os.path.dirname(__file__), 'telemetry.json')
        if os.path.isfile(conf_p):
            try:
                with open(conf_p, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                    return bool(cfg.get('enabled', True))
            except Exception:
                return True
        return True

    def get_telemetry_setting(self, get):
        """Ambil konfigurasi telemetri statistik Google Tag Manager."""
        return public.returnMsg(True, {
            'enabled': self._is_telemetry_enabled()
        })

    def set_telemetry_setting(self, get):
        """Ubah konfigurasi On/Off telemetri statistik Google Tag Manager."""
        val = str(get.get('enabled', '1')).strip().lower()
        enabled = val in ('1', 'true', 'on', 'yes')
        payload = {
            'enabled': enabled,
            'updated_at': int(time.time())
        }
        target_etc = self._p('etc', 'telemetry.json')
        try:
            os.makedirs(os.path.dirname(target_etc), exist_ok=True)
            with open(target_etc, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            return public.returnMsg(False, 'Gagal menyimpan konfigurasi telemetri: %s' % str(e))

        try:
            local_p = os.path.join(os.path.dirname(__file__), 'telemetry.json')
            with open(local_p, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

        status_text = 'Aktif (ON)' if enabled else 'Nonaktif (OFF)'
        return public.returnMsg(True, 'Pengaturan telemetri Google Tag Manager berhasil diubah: %s' % status_text)

    def _send_telemetry(self, event_name, extra_params=None):
        """Kirim statistik telemetri anonim (instalasi/error/pembaruan) ke Google Analytics.
        
        Sesuai kebijakan privasi lisensi: HANYA metrik umum sistem yang dikirim.
        TIDAK ADA kredensial, password, token, atau informasi pribadi/rahasia server.
        """
        if not self._is_telemetry_enabled():
            return
        try:
            cid = 'anon-sentinel'
            if os.path.exists('/etc/machine-id'):
                try:
                    with open('/etc/machine-id', 'r') as f:
                        cid = hashlib.md5(f.read().strip().encode('utf-8')).hexdigest()
                except Exception:
                    pass
            elif os.path.exists('/var/lib/dbus/machine-id'):
                try:
                    with open('/var/lib/dbus/machine-id', 'r') as f:
                        cid = hashlib.md5(f.read().strip().encode('utf-8')).hexdigest()
                except Exception:
                    pass

            v_info = '1.6.1'
            try:
                info_p = os.path.join(os.path.dirname(__file__), 'info.json')
                if os.path.exists(info_p):
                    with open(info_p, 'r', encoding='utf-8') as f:
                        v_info = json.load(f).get('versions', '1.6.1')
            except Exception:
                pass

            params = {
                'v': '2',
                'tid': 'G-8DBL8LPYQZ',
                'cid': cid,
                'en': event_name,
                'ep.plugin_version': v_info,
                'ep.os_name': platform.system(),
                'ep.os_release': platform.release()[:20],
                'ep.arch': platform.machine()
            }
            if extra_params and isinstance(extra_params, dict):
                for k, v in extra_params.items():
                    params['ep.' + str(k)] = str(v)[:100]

            url = 'https://www.google-analytics.com/g/collect?' + urllib.parse.urlencode(params)
            req = urllib.request.Request(url, headers={'User-Agent': 'ZySentinel-Telemetry/' + v_info})
            urllib.request.urlopen(req, timeout=3.0)
        except Exception:
            pass

    def _parse_version(self, v_str):
        """Parse semver string menjadi tuple integer (mis. 'v1.6.1' -> (1, 6, 1))."""
        if not v_str:
            return (0, 0, 0)
        v_clean = str(v_str).strip().lstrip('vV')
        parts = []
        for x in re.split(r'[-.+_]', v_clean):
            if x.isdigit():
                parts.append(int(x))
            else:
                break
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _normalize_version(self, v_str):
        """Pastikan format versi selalu berawalan 'v' (mis. 'v1.6.1')."""
        if not v_str or str(v_str).strip() in ('-', ''):
            return 'v1.6.1'
        s = str(v_str).strip()
        return s if s.lower().startswith('v') else ('v' + s)

    def get_lifecycle_status(self, get):
        """Ambil status detail siklus hidup, versi, dan diagnostik komponen."""
        v_info = 'v1.6.1'
        try:
            info_p = os.path.join(os.path.dirname(__file__), 'info.json')
            if os.path.exists(info_p):
                with open(info_p, 'r', encoding='utf-8') as f:
                    v_raw = json.load(f).get('versions', '1.6.1')
                    v_info = self._normalize_version(v_raw)
        except Exception:
            pass

        installed = os.path.exists(os.path.join(self.__PATH, 'bin', 'guardd'))
        lock_active = os.path.exists(os.path.join(self.__PATH, 'etc', 'uninstall.lock'))

        units = ['sentinel.service', 'sentinel-fw.service', 'sentinel-proc.service',
                 'sentinel-upload-scan.service', 'sentinel-intel.timer', 'sentinel-av.timer']
        services_status = {}
        for u in units:
            services_status[u] = (self._svc(u) == 'running')

        hostname = socket.gethostname() if hasattr(socket, 'gethostname') else 'unknown-host'

        return public.returnMsg(True, {
            'version': v_info,
            'is_installed': installed,
            'uninstall_locked': lock_active,
            'services': services_status,
            'hostname': hostname
        })

    def run_lifecycle_action(self, get):
        """Jalankan aksi siklus hidup: fresh, repair, update, uninstall."""
        action = str(get.get('action', '')).strip().lower()
        if action not in ['fresh', 'repair', 'update', 'uninstall']:
            return public.returnMsg(False, 'Aksi tidak valid (fresh|repair|update|uninstall)')

        plug_dir = os.path.dirname(__file__)
        install_script = os.path.join(plug_dir, 'install.sh')
        if not os.path.exists(install_script):
            return public.returnMsg(False, 'Skrip install.sh tidak ditemukan di direktori plugin')

        if action == 'uninstall':
            confirm = str(get.get('confirm', '')).strip()
            if confirm != 'UNINSTALL':
                return public.returnMsg(False, 'Konfirmasi pencabutan tidak sesuai. Harap ketik UNINSTALL.')
            rc, o, e = self._sh("bash %s cabut --clean" % install_script, 60)
            self._send_telemetry('uninstall_clean', {'status': 'success' if rc == 0 else 'failed'})
            if rc != 0:
                return public.returnMsg(False, 'Pencabutan gagal: %s' % (e or o))
            return public.returnMsg(True, 'ZySentinel berhasil dicabut bersih tanpa sisa.')

        elif action == 'fresh':
            rc, o, e = self._sh("bash %s fresh" % install_script, 90)
            self._send_telemetry('install_fresh', {'status': 'success' if rc == 0 else 'failed'})
            if rc != 0:
                return public.returnMsg(False, 'Fresh install gagal: %s' % (e or o))
            return public.returnMsg(True, 'Fresh install berhasil diselesaikan dengan konfigurasi bawaan bersih.')

        elif action == 'repair':
            rc, o, e = self._sh("bash %s repair" % install_script, 60)
            self._send_telemetry('install_repair', {'status': 'success' if rc == 0 else 'failed'})
            if rc != 0:
                return public.returnMsg(False, 'Self-heal / perbaikan mandiri gagal: %s' % (e or o))
            return public.returnMsg(True, 'Perbaikan mandiri (Self-Heal) selesai: seluruh komponen normal.')

        elif action == 'update':
            return self.perform_github_update(get)

    def check_github_update(self, get):
        """Periksa versi rilis terbaru di repository GitHub omysurya/zysentinel.
        
        Mendukung inspeksi melalui Releases API, Tags API, dan Branches API
        (untuk branch rilis seperti v1.6.1), dengan parsing semver akurat."""
        v_current = 'v1.6.1'
        try:
            info_p = os.path.join(os.path.dirname(__file__), 'info.json')
            if os.path.exists(info_p):
                with open(info_p, 'r', encoding='utf-8') as f:
                    v_raw = json.load(f).get('versions', '1.6.1')
                    v_current = self._normalize_version(v_raw)
        except Exception:
            pass

        url_release = 'https://api.github.com/repos/omysurya/zysentinel/releases/latest'
        url_tags = 'https://api.github.com/repos/omysurya/zysentinel/tags'
        url_branches = 'https://api.github.com/repos/omysurya/zysentinel/branches'
        headers = {
            'User-Agent': 'ZySentinel-Updater/' + v_current,
            'Accept': 'application/vnd.github.v3+json'
        }

        latest_version = v_current
        release_notes = 'Versi stabil ZySentinel sinkron dengan branch/tag GitHub resmi.'
        download_url = 'https://github.com/omysurya/zysentinel/archive/refs/heads/%s.zip' % v_current
        found_target = False

        # 1. Cek GitHub Releases
        try:
            req = urllib.request.Request(url_release, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                tag_name = data.get('tag_name', '').strip()
                if tag_name:
                    latest_version = self._normalize_version(tag_name)
                    release_notes = data.get('body', release_notes)
                    for asset in data.get('assets', []):
                        if asset.get('name', '').endswith('.zip'):
                            download_url = asset.get('browser_download_url', download_url)
                            break
                    else:
                        download_url = 'https://github.com/omysurya/zysentinel/archive/refs/tags/%s.zip' % latest_version
                    found_target = True
        except Exception:
            pass

        # 2. Cek GitHub Tags jika release belum dibuat
        if not found_target:
            try:
                req = urllib.request.Request(url_tags, headers=headers)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    tags_data = json.loads(resp.read().decode('utf-8'))
                    if tags_data and isinstance(tags_data, list):
                        best_tag = None
                        best_tuple = (-1, -1, -1)
                        for t in tags_data:
                            t_name = t.get('name', '').strip()
                            t_tuple = self._parse_version(t_name)
                            if t_tuple > best_tuple and t_tuple > (0, 0, 0):
                                best_tuple = t_tuple
                                best_tag = t_name
                        if best_tag:
                            latest_version = self._normalize_version(best_tag)
                            download_url = 'https://github.com/omysurya/zysentinel/archive/refs/tags/%s.zip' % latest_version
                            found_target = True
            except Exception:
                pass

        # 3. Cek GitHub Branches (sinkronisasi dengan branch rilis seperti v1.6.1)
        if not found_target:
            try:
                req = urllib.request.Request(url_branches, headers=headers)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    branches_data = json.loads(resp.read().decode('utf-8'))
                    if branches_data and isinstance(branches_data, list):
                        best_branch = None
                        best_tuple = (-1, -1, -1)
                        for b in branches_data:
                            b_name = b.get('name', '').strip()
                            b_tuple = self._parse_version(b_name)
                            if b_tuple > best_tuple and b_tuple > (0, 0, 0):
                                best_tuple = b_tuple
                                best_branch = b_name
                        if best_branch:
                            latest_version = self._normalize_version(best_branch)
                            download_url = 'https://github.com/omysurya/zysentinel/archive/refs/heads/%s.zip' % latest_version
                            found_target = True
            except Exception:
                pass

        # Normalisasi akhir versi
        latest_version = self._normalize_version(latest_version)
        has_update = self._parse_version(latest_version) > self._parse_version(v_current)

        return public.returnMsg(True, {
            'current_version': v_current,
            'latest_version': latest_version,
            'has_update': has_update,
            'release_notes': release_notes,
            'download_url': download_url
        })

    def perform_github_update(self, get):
        """Unduh paket rilis/patch dari GitHub dan jalankan update mandiri."""
        chk = self.check_github_update(get)
        data = chk.get('msg', {})
        download_url = data.get('download_url')
        latest_ver = self._normalize_version(data.get('latest_version', 'v1.6.1'))

        staging_zip = '/tmp/sentinel_update.zip'
        staging_dir = '/tmp/sentinel_update_staging'

        try:
            if download_url and download_url.startswith('http'):
                try:
                    headers = {'User-Agent': 'ZySentinel-Updater/1.6.1'}
                    req = urllib.request.Request(download_url, headers=headers)
                    with urllib.request.urlopen(req, timeout=30) as resp, open(staging_zip, 'wb') as out_f:
                        out_f.write(resp.read())
                except Exception:
                    pass

            if not os.path.exists(staging_zip) or os.path.getsize(staging_zip) < 1000:
                if os.path.exists('/www/backup/sentinel.zip'):
                    self._sh("cp -f /www/backup/sentinel.zip %s" % staging_zip, 5)

            if not os.path.exists(staging_zip):
                return public.returnMsg(False, 'Paket pembaruan tidak ditemukan untuk diunduh.')

            self._sh("rm -rf %s && mkdir -p %s" % (staging_dir, staging_dir), 5)
            self._sh("unzip -o -q %s -d %s" % (staging_zip, staging_dir), 15)

            src_plugin = staging_dir
            for root, dirs, files in os.walk(staging_dir):
                if 'install.sh' in files and 'sentinel_main.py' in files:
                    src_plugin = root
                    break

            plug_dir = os.path.dirname(__file__)
            self._sh("cp -af %s/* %s/" % (src_plugin, plug_dir), 15)

            rc, o, e = self._sh("bash %s/install.sh update" % plug_dir, 60)
            self._sh("rm -rf %s %s" % (staging_zip, staging_dir), 5)

            self._send_telemetry('install_update', {'status': 'success' if rc == 0 else 'failed', 'new_version': latest_ver})
            if rc != 0:
                return public.returnMsg(False, 'Pembaruan gagal dijalankan: %s' % (e or o))
            return public.returnMsg(True, 'Pembaruan ke versi %s berhasil diterapkan!' % latest_ver)
        except Exception as ex:
            self._send_telemetry('error_event', {'error': str(ex)[:50], 'context': 'update'})
            return public.returnMsg(False, 'Gagal mengunduh dan menerapkan update: %s' % str(ex))

    # -------------------------------------------------------------------------
    # FITUR FEEDBACK & BUGS REPORT (SUBJEK: Feedback | Bugsreport [Topic] [hostname])
    # SANITASI KREDENSIAL LENGKAP TANPA DATA SENSITIF
    # -------------------------------------------------------------------------
    def _sanitize_payload_for_feedback(self, text):
        """Hapus seluruh kata sandi, token, kunci privat, dan rahasia server."""
        if not text:
            return ""
        s = str(text)
        s = re.sub(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----', '[KUNCI_PRIVAT_DIHAPUS]', s)
        s = re.sub(r'(?i)(password|passwd|pass|pwd|secret|token|api_key|auth|bearer)\s*[:=]\s*[\'"]?[^\s,\'"]+', r'\1: [DIHAPUS_UNTUK_KEAMANAN]', s)
        s = re.sub(r'(mysql|postgres|redis)://[^:]+:[^@]+@', r'\1://***:***@', s)
        s = re.sub(r'\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b', '[BOT_TOKEN_DIHAPUS]', s)
        return s

    def _init_feedback_db(self):
        """Pastikan tabel feedback_reports tersedia di guardd.db."""
        try:
            con = sqlite3.connect(os.path.join(self.__PATH, 'data', 'guardd.db'), timeout=3.0)
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS feedback_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER,
                    type TEXT,
                    topic TEXT,
                    subject TEXT,
                    message TEXT,
                    email TEXT,
                    status TEXT
                )
            """)
            con.commit()
            con.close()
        except Exception:
            pass

    def send_feedback(self, get):
        """Kirim Feedback atau Bugs Report dengan subject standar tanpa kredensial."""
        report_type = str(get.get('type', 'Feedback')).strip()
        if report_type not in ['Feedback', 'Bugsreport', 'Bugs Report']:
            report_type = 'Feedback'
        if report_type == 'Bugs Report':
            report_type = 'Bugsreport'

        raw_topic = str(get.get('topic', '')).strip()
        if not raw_topic:
            return public.returnMsg(False, 'Topik laporan tidak boleh kosong')

        raw_message = str(get.get('message', '')).strip()
        if not raw_message:
            return public.returnMsg(False, 'Isi pesan tidak boleh kosong')

        user_email = str(get.get('email', '')).strip()
        include_log = bool(get.get('include_log', False))

        topic = self._sanitize_payload_for_feedback(raw_topic)[:80]
        message = self._sanitize_payload_for_feedback(raw_message)[:3000]

        hostname = socket.gethostname() if hasattr(socket, 'gethostname') else 'unknown-host'
        subject = "%s [%s] [%s]" % (report_type, topic, hostname)

        diagnostics = ""
        if include_log:
            try:
                log_file = os.path.join(self.__PATH, 'log', 'sentinel.log')
                if os.path.exists(log_file):
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()[-20:]
                        diagnostics = self._sanitize_payload_for_feedback("".join(lines))
            except Exception:
                pass

        full_body = message
        if diagnostics:
            full_body += "\n\n=== DIAGNOSTIK SENTINEL (DISANITASI) ===\n" + diagnostics

        self._init_feedback_db()
        now_ts = int(time.time())
        try:
            con = sqlite3.connect(os.path.join(self.__PATH, 'data', 'guardd.db'), timeout=3.0)
            cur = con.cursor()
            cur.execute("""
                INSERT INTO feedback_reports (ts, type, topic, subject, message, email, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (now_ts, report_type, topic, subject, full_body, user_email, 'SENT'))
            con.commit()
            con.close()
        except Exception:
            pass

        self._send_telemetry('feedback_submitted', {
            'report_type': report_type,
            'topic_len': len(topic),
            'has_email': bool(user_email)
        })

        try:
            payload_data = json.dumps({
                'type': report_type,
                'topic': topic,
                'hostname': hostname,
                'subject': subject,
                'message': full_body,
                'email': user_email,
                'version': '1.6.1'
            }).encode('utf-8')
            dev_url = 'https://api.zysens.com/api/v1/sentinel/feedback'
            req = urllib.request.Request(
                dev_url,
                data=payload_data,
                headers={'Content-Type': 'application/json', 'User-Agent': 'ZySentinel-Feedback/1.6.1'}
            )
            urllib.request.urlopen(req, timeout=4.0)
        except Exception:
            pass

        return public.returnMsg(True, {
            'subject': subject,
            'msg': 'Laporan berhasil dicatat dan dikirim dengan subjek: %s' % subject
        })

    def get_feedback_history(self, get):
        """Ambil riwayat feedback dan laporan bug yang pernah dikirim."""
        self._init_feedback_db()
        reports = []
        try:
            con = sqlite3.connect(os.path.join(self.__PATH, 'data', 'guardd.db'), timeout=3.0)
            cur = con.cursor()
            cur.execute("""
                SELECT id, ts, type, topic, subject, email, status
                FROM feedback_reports
                ORDER BY id DESC LIMIT 20
            """)
            for row in cur.fetchall():
                reports.append({
                    'id': row[0],
                    'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row[1])),
                    'type': row[2],
                    'topic': row[3],
                    'subject': row[4],
                    'email': row[5],
                    'status': row[6]
                })
            con.close()
        except Exception:
            pass
        return public.returnMsg(True, reports)

    def get_terms_and_policy(self, get):
        """Kembalikan teks syarat ketentuan lisensi dan kebijakan transparansi telemetri."""
        text = """SYARAT KETENTUAN LISENSI & KEBIJAKAN PRIVASI ZYSENTINEL

1. LISENSI PERANGKAT LUNAK (APACHE LICENSE 2.0)
ZySentinel adalah perangkat lunak keamanan sumber terbuka berlisensi Apache License, Version 2.0. Anda bebas menggunakan, memodifikasi, dan mendistribusikan perangkat lunak ini untuk keperluan komersial maupun pribadi tanpa biaya royalti.

2. PENGUMPULAN STATISTIK & TELEMETRI GOOGLE ANALYTICS
Untuk mengukur keandalan, performa, dan memprioritaskan perbaikan bug pada versi selanjutnya, ZySentinel mengumpulkan data analitik anonim saat instalasi, pembaruan, perbaikan mandiri (self-heal), serta galat sistem via Google Analytics.

3. JAMINAN PRIVASI DAN KEAMANAN KREDENSIAL:
- TIDAK ADA kata sandi, token otentikasi, atau kunci privat (SSL/SSH) yang dikumpulkan atau dikirim.
- TIDAK ADA data database (MySQL, PostgreSQL, Redis) yang dibaca atau dikirim.
- TIDAK ADA konten berkas vhost atau data pelanggan situs web yang dikumpulkan.
- Data yang dikirim murni berupa metrik versi perangkat lunak, sistem operasi (Linux distro), arsitektur mesin, dan status kode aksi instalasi.

4. PELAPORAN FEEDBACK & BUGS:
Laporan yang dikirim melalui formulir Feedback & Bugs Report secara otomatis disanitasi oleh sistem untuk menghapus segala bentuk kredensial sebelum diteruskan kepada pengembang dengan subjek: Feedback | Bugsreport [Topic] [hostname].
"""
        return public.returnMsg(True, text)