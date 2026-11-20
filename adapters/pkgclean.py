#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Cabut paket prasyarat yang DIPASANG installer ZySentinel (mis. clamav) saat uninstall, tanpa merusak server.

Installer mencatat paket yang benar-benar baru muncul (bukan yang sudah ada sebelumnya) di <BASE>/etc/dipasang-paket.list.
Saat uninstall, hanya paket di daftar itu yang dipertimbangkan, dengan pengaman berlapis:

  * Disimulasikan dulu (`apt-get -s remove`, `rpm -e --test`): bila pencabutan akan ikut menyeret paket di LUAR daftar
    (artinya sudah dipakai paket lain, misalnya panel), paket itu DILEWATI dan dilaporkan, tidak dipaksa.
  * Tanpa `autoremove`: paket lain yang yatim sebelumnya tidak disentuh.
  * Paket yang sudah tidak terpasang diabaikan; daftar ditulis ulang hanya berisi yang masih ada (idempoten).
  * Nama paket divalidasi ketat sebelum menyentuh apt/rpm (daftar berasal dari berkas, bukan dipercaya begitu saja).
  * Unit systemd milik paket yang dicabut dihentikan dan dinonaktifkan LEBIH DULU (soket/timer dulu, lalu service). Tanpa itu
    daemon dengan aktivasi soket (mis. clamd) tetap hidup sebagai proses yatim: binernya terhapus tetapi prosesnya jalan terus.

Pemakaian: pkgclean.py remove <berkas-daftar> [--dry-run] [--deferred-out <berkas>]     | pkgclean.py list <berkas-daftar>

Paket pemilik interpreter yang menjalankan pembersih ini (mis. python3 yang dipasang installer di CentOS 7) tidak bisa dicabut dari
dalam prosesnya sendiri. Dengan --deferred-out, rencana pencabutannya (sudah lolos simulasi yang sama) ditulis ke berkas dan
DIJALANKAN OLEH SHELL SETELAH Python keluar, sehingga tidak ada paket milik installer yang tertinggal.
Keluar 0 bila selesai (juga bila sebagian dilewati); 1 bila pengelola paket gagal tak terduga.
"""
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

RUN_DIR = os.environ.get('ZYS_RUN_DIR', '/run')
VAR_DIR = os.environ.get('ZYS_VAR_DIR', '/var')
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9+._-]{0,99}$')


def _run(cmd, timeout=900, env=None):
    e = dict(os.environ)
    e['DEBIAN_FRONTEND'] = 'noninteractive'
    e['LC_ALL'] = 'C'
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout, env=e)
        return p.returncode, p.stdout
    except Exception as ex:
        return 127, str(ex)


def family():
    if shutil.which('apt-get') and shutil.which('dpkg-query'):
        return 'deb'
    if shutil.which('rpm'):
        return 'rpm'
    return ''


def read_list(path):
    """Nama paket unik dan sah dari berkas daftar (baris tidak sah diabaikan, bukan dieksekusi)."""
    try:
        with open(path) as f:
            names = [ln.strip() for ln in f if ln.strip() and not ln.startswith('#')]
    except OSError:
        return []
    return sorted({n for n in names if _NAME.match(n)})


def _installed(pkg, fam):
    if fam == 'deb':
        rc, out = _run(['dpkg-query', '-W', '-f=${Status}', pkg], 60)
        return rc == 0 and 'install ok installed' in out
    return _run(['rpm', '-q', pkg], 60)[0] == 0


def _self_packages(fam):
    """Paket pemilik interpreter yang sedang menjalankan pembersih ini (mis. python3): mencabutnya di tengah jalan akan merusak
    prosesnya sendiri dan memutus Python yang dipakai installer."""
    exe = os.path.realpath(sys.executable or '')
    own = set()
    if exe and os.path.exists(exe):
        rc, out = _run(['dpkg-query', '-S', exe] if fam == 'deb' else ['rpm', '-qf', '--qf', '%{NAME}\n', exe], 60)
        if rc == 0:
            for ln in out.splitlines():
                nm = ln.split(':', 1)[0].strip() if fam == 'deb' else ln.strip()
                if _NAME.match(nm):
                    own.add(nm)
    return own


def _base(name):
    return name.split(':', 1)[0]


def _deb_removal_set(pkgs):
    """Himpunan paket yang AKAN dicabut bila `pkgs` dicabut (simulasi); None bila simulasi gagal."""
    rc, out = _run(['apt-get', '-s', '-y', 'remove', '--purge'] + list(pkgs), 300)
    if rc != 0:
        return None
    return {_base(m.group(1)) for m in re.finditer(r'^Remv\s+(\S+)', out, re.M)}


_UNIT_RE = re.compile(r'^(?:/usr)?/lib/systemd/system/([A-Za-z0-9@_.:-]+\.(?:service|socket|timer|path))$')
_UNIT_ORDER = {'socket': 0, 'timer': 0, 'path': 0, 'service': 1}


def _units_of(pkgs, fam):
    """Unit systemd yang dibawa paket-paket ini; soket/timer lebih dulu agar tidak mengaktifkan ulang service."""
    units = []
    for p in pkgs:
        rc, out = _run(['dpkg-query', '-L', p] if fam == 'deb' else ['rpm', '-ql', p], 60)
        if rc != 0:
            continue
        for ln in out.splitlines():
            m = _UNIT_RE.match(ln.strip())
            if m and m.group(1) not in units:
                units.append(m.group(1))
    return sorted(units, key=lambda u: _UNIT_ORDER[u.rsplit('.', 1)[1]])


def _stop_units(units):
    if not units or not shutil.which('systemctl'):
        return
    for u in units:
        _run(['systemctl', 'stop', u], 120)
        _run(['systemctl', 'disable', u], 60)


def _owned(path, fam):
    """Apakah ada paket terpasang yang memiliki path ini (dpkg -S / rpm -qf)?"""
    cmd = ['dpkg-query', '-S', path] if fam == 'deb' else ['rpm', '-qf', path]
    return _run(cmd, 60)[0] == 0


def _drop_state_dirs(pkgs, fam):
    """Data yang dibuat DAEMON paket sesudah dipasang (mis. /var/lib/clamav berisi berkas tanda tangan hasil unduhan freshclam)
    tidak ikut dihapus `purge`. Dibuang hanya bila: namanya sama dengan paket yang baru kita cabut (atau awalan yang dipakai
    >= 2 paket yang kita cabut, mis. 'clamav'), berupa direktori asli di /var/lib|/var/log|/var/cache, dan TIDAK dimiliki
    paket terpasang mana pun. Direktori kosong biasa tetap lewat rmdir."""
    names = set(pkgs)
    count = {}
    for p in pkgs:
        pre = p.split('-', 1)[0]
        count[pre] = count.get(pre, 0) + 1
    names |= {pre for pre, n in count.items() if n >= 2 and len(pre) >= 4}
    for sub in ('lib', 'log', 'cache'):
        for n in sorted(names):
            d = os.path.join(VAR_DIR, sub, n)
            if os.path.islink(d) or not os.path.isdir(d) or _owned(d, fam):
                continue
            shutil.rmtree(d, ignore_errors=True)


def _drop_runtime_dirs(pkgs):
    """Direktori runtime kosong yang ditinggalkan paket (mis. /run/clamav): hanya rmdir, tidak pernah menghapus isi."""
    names = set()
    for p in pkgs:
        names.add(p)
        names.add(p.split('-', 1)[0])
    for n in sorted(names):
        d = os.path.join(RUN_DIR, n)
        if os.path.isdir(d) and not os.path.islink(d):
            try:
                os.rmdir(d)
            except OSError:
                pass


def _after_units(units):
    if units and shutil.which('systemctl'):
        _run(['systemctl', 'daemon-reload'], 60)
        _run(['systemctl', 'reset-failed'] + list(units), 60)


_RPM_ARCH = r'(?:x86_64|noarch|i[3-6]86|aarch64|ppc64le|s390x|armv7hl)'
_RPM_ROW = re.compile(r'^\s+([A-Za-z0-9+._-]+)\s+' + _RPM_ARCH + r'\s+\S+')
_RPM_NAME_ONLY = re.compile(r'^\s+([A-Za-z0-9+._-]+)\s*$')
_RPM_ARCH_ROW = re.compile(r'^\s+' + _RPM_ARCH + r'\s+\S+')


def _rpm_tool():
    return shutil.which('dnf') or shutil.which('yum')


def _rpm_removal_set(pkgs):
    """Himpunan paket yang AKAN dicabut (simulasi `yum|dnf --assumeno remove`); None bila simulasi tidak bisa dibaca."""
    tool = _rpm_tool()
    if not tool:
        return None
    # yum menyimpan berkas transaksi di /tmp (yum_save_tx.*.yumtx) setiap simulasi dibatalkan: itu sampah buatan kita, buang
    # hanya yang BARU muncul selama simulasi ini (berkas yang sudah ada sebelumnya bukan milik kita).
    pola = os.path.join(tempfile.gettempdir(), 'yum_save_tx.*.yumtx')
    sebelum = set(glob.glob(pola))
    try:
        rc, out = _run([tool, '--assumeno', 'remove'] + list(pkgs), 600)
    finally:
        for f in set(glob.glob(pola)) - sebelum:
            try:
                os.remove(f)
            except OSError:
                pass
    names, in_remove, pending = set(), False, None
    for ln in out.splitlines():
        if ln.startswith('Removing'):
            in_remove, pending = True, None
            continue
        if ln.startswith(('Installing', 'Updating', 'Transaction Summary', 'Dependencies Resolved')) and in_remove:
            in_remove = False
        if not in_remove:
            continue
        m = _RPM_ROW.match(ln)
        if m:
            names.add(m.group(1))
            pending = None
            continue
        if pending and _RPM_ARCH_ROW.match(ln):          # yum memecah nama panjang ke baris sendiri
            names.add(pending)
            pending = None
            continue
        n = _RPM_NAME_ONLY.match(ln)
        pending = n.group(1) if n else None
    if not names:
        return None
    return names


def _write_list(path, pkgs):
    try:
        if not pkgs:
            os.remove(path)
            return
        with open(path, 'w') as f:
            f.write('# paket yang dipasang installer ZySentinel dan belum dicabut\n' + '\n'.join(pkgs) + '\n')
    except OSError:
        pass


def _plan(pkgs, removal_set):
    """Pilih himpunan terbesar dari `pkgs` yang pencabutannya TIDAK menyeret paket di luar daftar. Mengembalikan (keep, skipped)."""
    want = set(pkgs)
    keep = list(pkgs)
    skipped = {}
    # buang paket yang pencabutannya menyeret paket di luar daftar; ulangi sampai stabil (satu paket bisa bergantung pada lainnya)
    for _ in range(len(pkgs) + 1):
        bad = []
        for p in keep:
            sim = removal_set([p])
            if sim is None:
                bad.append((p, 'simulasi gagal'))
            elif sim - want:
                bad.append((p, 'dipakai paket lain: ' + ', '.join(sorted(sim - want))[:80]))
        if not bad:
            break
        for p, why in bad:
            skipped[p] = why
            keep.remove(p)
        want = set(keep)
    if keep:
        sim = removal_set(keep)
        if sim is None or sim - set(keep):
            for p in keep:
                skipped[p] = 'pencabutan serentak menyeret paket lain'
            keep = []
    return keep, skipped


def _remove_deb(pkgs, dry):
    keep, skipped = _plan(pkgs, _deb_removal_set)
    removed = []
    if keep and not dry:
        units = _units_of(keep, 'deb')
        _stop_units(units)
        rc, out = _run(['apt-get', '-y', '-q', 'remove', '--purge'] + keep, 1200)
        _after_units(units)
        if rc == 0:
            _drop_runtime_dirs(keep)
            _drop_state_dirs(keep, 'deb')
        if rc != 0:
            print('pkgclean: apt-get remove gagal: %s' % out.strip().splitlines()[-1:], file=sys.stderr)
            return removed, skipped, 1
        removed = keep
    elif keep:
        removed = keep
    return removed, skipped, 0


def _remove_rpm(pkgs, dry):
    tool = _rpm_tool()
    if not tool:
        return [], {p: 'yum/dnf tidak ada' for p in pkgs}, 0
    keep, skipped = _plan(pkgs, _rpm_removal_set)
    removed = []
    if keep and not dry:
        units = _units_of(keep, 'rpm')
        _stop_units(units)
        rc, out = _run([tool, '-y', 'remove'] + keep, 1800)
        _after_units(units)
        if rc != 0:
            print('pkgclean: %s remove gagal: %s' % (os.path.basename(tool), out.strip().splitlines()[-1:]), file=sys.stderr)
            return removed, skipped, 1
        _drop_runtime_dirs(keep)
        _drop_state_dirs(keep, 'rpm')
        removed = keep
    elif keep:
        removed = keep
    return removed, skipped, 0


def _deferred_plan(path, fam):
    """Sisa paket tercatat (pemilik interpreter dan paket yang bergantung padanya) yang aman dicabut SETELAH Python keluar."""
    rest = [p for p in read_list(path) if _installed(p, fam)]
    if not rest:
        return []
    keep, _ = _plan(rest, _deb_removal_set if fam == 'deb' else _rpm_removal_set)
    return keep


def cleanup(path, dry=False, deferred_out=None):
    fam = family()
    pkgs = read_list(path)
    if not pkgs:
        print('pkgclean: tidak ada paket tercatat untuk dicabut')
        try:
            os.remove(path)
        except OSError:
            pass
        return 0
    if not fam:
        print('pkgclean: pengelola paket tidak dikenali; paket dibiarkan: %s' % ' '.join(pkgs))
        return 0
    present = [p for p in pkgs if _installed(p, fam)]
    self_pk = _self_packages(fam)
    held = [p for p in present if p in self_pk or p.startswith(('libpython', 'python3-libs'))]
    present = [p for p in present if p not in held]
    if not present and not held:
        print('pkgclean: semua paket tercatat sudah tidak terpasang')
        if not dry:
            _write_list(path, [])
        return 0
    removed, skipped, rc = ((_remove_deb if fam == 'deb' else _remove_rpm)(present, dry)) if present else ([], {}, 0)
    if removed:
        print('pkgclean: %s %d paket prasyarat yang dipasang ZySentinel: %s' % ('akan dicabut' if dry else 'dicabut', len(removed), ' '.join(removed)))
    for p in held:
        skipped[p] = 'interpreter yang sedang menjalankan pembersih ini'
    later = []
    if held and deferred_out and not dry:
        later = _deferred_plan(path, fam) if not removed or rc == 0 else []
        # _deferred_plan membaca daftar; paket yang baru dicabut sudah tidak terpasang sehingga tidak ikut
        if later:
            try:
                with open(deferred_out, 'w') as f:
                    f.write('%s %s\n' % (fam, ' '.join(later)))
            except OSError:
                later = []
    for p in later:
        skipped.pop(p, None)
    for p, why in sorted(skipped.items()):
        print('pkgclean: DILEWATI %s (%s); dibiarkan terpasang agar server tidak rusak' % (p, why))
    if later:
        print('pkgclean: DITUNDA %d paket (pemilik interpreter beserta paket yang bergantung padanya) dan dicabut oleh installer setelah Python keluar: %s' % (len(later), ' '.join(later)))
    if not dry:
        _write_list(path, sorted(skipped))
    return rc


def main(argv):
    if len(argv) < 3 or argv[1] not in ('remove', 'list'):
        print('pakai: pkgclean.py {remove|list} <berkas-daftar> [--dry-run]', file=sys.stderr)
        return 2
    if argv[1] == 'list':
        print('\n'.join(read_list(argv[2])))
        return 0
    deferred = None
    if '--deferred-out' in argv:
        i = argv.index('--deferred-out')
        deferred = argv[i + 1] if i + 1 < len(argv) else None
    return cleanup(argv[2], dry='--dry-run' in argv, deferred_out=deferred)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
