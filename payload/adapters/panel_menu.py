#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Menu ZySentinel di panel hosting: tile/ikon di grup Security (CyberPanel).

ZySentinel di luar aaPanel memakai UI standalone (HTTPS, port 18491). Modul ini menaruh pintu masuknya ke menu
bawaan panel supaya admin tidak perlu mengingat alamat dan port:

  cyberpanel : tile "ZySentinel" di Administration > Security (hub.html) dan entri pencarian menu (index.html).
               Templat panel ditambal di antara penanda ZYSENTINEL:BEGIN/END, jadi aman diulang dan bisa dicabut bersih.
               Pembaruan CyberPanel menimpa templat; `check` (dipanggil pemulihan mandiri) memasang ulang bila hilang.

  cpanel     : ikon "ZySentinel" di WHM > Plugins (jalur resmi AppConfig: /var/cpanel/apps/zysentinel.conf + register_appconfig,
               dengan entryurl relatif terhadap cgi/ dan ikon PNG di whostmgr/docroot/addon_plugins). Tidak ada penambalan berkas inti WHM, jadi
               pembaruan cPanel tidak menghapusnya. Tombol membuka CGI pengarah ke UI standalone (https://<host>:18491/).
               Versi lama yang menambal themes/x/dynamicui.conf (grup Security Center) dibersihkan otomatis saat install.

  directadmin: plugin DirectAdmin standar (plugins/zysentinel: plugin.conf, hooks/admin_txt.html, admin/index.html, ikon SVG);
               Evolution menaruhnya di menu admin (Extra Features). Halaman plugin meneruskan ke UI standalone. Versi di Plugin
               Manager mengikuti info.json. `check` tidak melakukan apa pun di sini: update DA tidak menimpa plugin, dan Disable/Delete
               di Plugin Manager adalah keputusan admin yang tidak boleh dibatalkan pemulihan mandiri (install.sh yang memasang/menimpa).

Pemakaian: panel_menu.py {install|remove|status|check} [--panel cyberpanel|cpanel|directadmin]
Keluar 0 bila berhasil atau tidak ada yang perlu dilakukan; 1 bila gagal.
"""
import base64
import json
import os
import re
import subprocess
import sys

CYBERCP = os.environ.get('ZYS_CYBERCP_DIR', '/usr/local/CyberCP')
UI_PORT = int(os.environ.get('ZYS_UI_PORT', '18491'))
CPANEL = os.environ.get('ZYS_CPANEL_DIR', '/usr/local/cpanel')
CPANEL_VAR = os.environ.get('ZYS_CPANEL_VAR', '/var/cpanel')
TPL = os.path.join(CYBERCP, 'baseTemplate', 'templates', 'baseTemplate')
HUB = os.path.join(TPL, 'hub.html')
IDX = os.path.join(TPL, 'index.html')

# Tautan dibentuk di peramban dari nama host yang dipakai admin membuka panel, jadi benar untuk IP maupun domain.
_LOGO = ('<svg viewBox="0 0 64 64" width="22" height="22" aria-hidden="true"><defs><linearGradient id="zysg" x1="0" y1="0" x2="1" y2="1">'
         '<stop offset="0" stop-color="#0891b2"/><stop offset="1" stop-color="#059669"/></linearGradient></defs>'
         '<path d="M32 6 10 15v16c0 13 9 25 22 29 13-4 22-16 22-29V15z" fill="none" stroke="url(#zysg)" stroke-width="5" stroke-linejoin="round"/>'
         '<path d="M22 32l7 7 13-14" fill="none" stroke="url(#zysg)" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg>')

HUB_BLOCK = (
    "{# ZYSENTINEL:BEGIN #}"
    '<a class="cp-tile" data-zysentinel="1" href="https://localhost:%(port)d/" target="_blank" rel="noopener">'
    '<span class="cp-tile-ic">%(logo)s</span><span><div class="cp-tile-title">ZySentinel</div>'
    '<div class="cp-tile-sub">{%% trans "WAF, antivirus, firewall" %%}</div></span></a>'
    "<script>document.querySelectorAll('a[data-zysentinel]').forEach(function(a){a.href='https://'+location.hostname+':%(port)d/';});</script>"
    "{# ZYSENTINEL:END #}"
)
IDX_BLOCK = ("/*ZYSENTINEL:BEGIN*/{l:'ZySentinel', h:'https://'+location.hostname+':%(port)d/', i:'fa-shield-halved', "
             "g:'{%% trans \"Security\" %%}', t:'_blank'},/*ZYSENTINEL:END*/")

_HUB_RE = re.compile(r"[ \t]*\{# ZYSENTINEL:BEGIN #\}.*?\{# ZYSENTINEL:END #\}\n?", re.S)
_IDX_RE = re.compile(r"[ \t]*/\*ZYSENTINEL:BEGIN\*/.*?/\*ZYSENTINEL:END\*/\n?", re.S)


def _read(p):
    with open(p, encoding='utf-8') as f:
        return f.read()


def _write(p, s):
    """Tulis atomik dan pertahankan izin/pemilik berkas asli."""
    st = os.stat(p)
    tmp = p + '.zys-tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(s)
    os.chmod(tmp, st.st_mode & 0o7777)
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except OSError:
        pass
    os.replace(tmp, p)


def _backup(p):
    b = p + '.zys-orig'
    if not os.path.exists(b):
        with open(p, 'rb') as f, open(b, 'wb') as g:
            g.write(f.read())


def _patch_hub(s):
    """Sisipkan tile sebagai tile pertama grup Security; None bila struktur templat tidak dikenali."""
    s = _HUB_RE.sub('', s)
    m = re.search(r"\{% elif section == 'security' %\}.*?<div class=\"cp-tile-grid\">\n", s, re.S)
    if not m:
        return None
    return s[:m.end()] + '            ' + HUB_BLOCK % {'port': UI_PORT, 'logo': _LOGO} + '\n' + s[m.end():]


def _patch_idx(s):
    """Sisipkan entri pencarian menu tepat sebelum komentar "// Settings (admin)"."""
    s = _IDX_RE.sub('', s)
    m = re.search(r"^([ \t]*)// Settings \(admin\)", s, re.M)
    if not m:
        return None
    return s[:m.start()] + m.group(1) + IDX_BLOCK % {'port': UI_PORT} + '\n' + s[m.start():]


def cyberpanel_present():
    return os.path.isfile(HUB) and os.path.isfile(IDX)


def cyberpanel_status():
    try:
        return '{# ZYSENTINEL:BEGIN #}' in _read(HUB) and '/*ZYSENTINEL:BEGIN*/' in _read(IDX)
    except OSError:
        return False


def _restart_panel():
    """Templat Django di-cache proses panel; muat ulang agar menu muncul. Tanpa systemd, abaikan."""
    try:
        subprocess.run(['systemctl', 'restart', 'lscpd'], timeout=60, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def cyberpanel_install(restart=True):
    if not cyberpanel_present():
        print('panel_menu: templat CyberPanel tidak ditemukan di %s' % TPL, file=sys.stderr)
        return 1
    hub, idx = _read(HUB), _read(IDX)
    nh, ni = _patch_hub(hub), _patch_idx(idx)
    if nh is None or ni is None:
        print('panel_menu: struktur templat CyberPanel tidak dikenali (versi baru?); menu tidak dipasang', file=sys.stderr)
        return 1
    changed = False
    for p, old, new in ((HUB, hub, nh), (IDX, idx, ni)):
        if old != new:
            _backup(p)
            _write(p, new)
            changed = True
    if changed and restart:
        _restart_panel()
    print('panel_menu: menu ZySentinel %s di CyberPanel > Security' % ('dipasang' if changed else 'sudah ada'))
    return 0


def cyberpanel_remove(restart=True):
    if not cyberpanel_present():
        return 0
    changed = False
    for p, rx in ((HUB, _HUB_RE), (IDX, _IDX_RE)):
        s = _read(p)
        n = rx.sub('', s)
        if n != s:
            _write(p, n)
            changed = True
    for p in (HUB, IDX):                # cadangan hanya berguna selama blok kita terpasang
        try:
            os.remove(p + '.zys-orig')
        except OSError:
            pass
    if changed and restart:
        _restart_panel()
    print('panel_menu: menu ZySentinel %s dari CyberPanel' % ('dicabut' if changed else 'tidak ada'))
    return 0


# ----------------------------------------------------------------------------- cPanel/WHM
def _whm_paths():
    docroot = os.path.join(CPANEL, 'whostmgr', 'docroot')
    return {
        'dui': os.path.join(docroot, 'themes', 'x', 'dynamicui.conf'),
        'icon': os.path.join(docroot, 'addon_plugins', 'zysentinel.png'),
        'oldicon': os.path.join(docroot, 'themes', 'x', 'icons', 'zysentinel.svg'),
        'cgi': os.path.join(docroot, 'cgi', 'zysentinel', 'index.cgi'),
        'app': os.path.join(CPANEL_VAR, 'apps', 'zysentinel.conf'),
    }


_CGI = r"""#!/usr/local/cpanel/3rdparty/bin/perl
# Pintu masuk ZySentinel dari menu WHM: arahkan ke UI standalone di host yang sama (https://<host>:%(port)d/).
use strict; use warnings;
my $h = $ENV{HTTP_HOST} // "";
my $host = "localhost";                                  # nilai tak dikenal tidak pernah masuk ke header Location
if    ($h =~ /^(\[[0-9A-Fa-f:]+\])(?::\d+)?$/)   { $host = $1 }   # IPv6 [..] dengan/ tanpa port WHM
elsif ($h =~ /^([A-Za-z0-9.\-]+)(?::\d+)?$/)      { $host = $1 }   # nama host atau IPv4, port WHM dibuang
print "Status: 302 Found\r\nLocation: https://$host:%(port)d/\r\nCache-Control: no-store\r\n\r\n";
"""

# entryurl RELATIF TERHADAP cgi/: WHM membentuk tautan menu sebagai <token>/cgi/<entryurl> (templat plugins_list.tmpl),
# jadi 'cgi/zysentinel/...' menghasilkan /cgi/cgi/... dan HTTP 404. url harus selalu '/cgi/' + entryurl.
_APPCONF = ('name=zysentinel\nservice=whostmgr\nuser=root\nurl=/cgi/zysentinel/index.cgi\nacls=all\n'
            'displayname=ZySentinel\nentryurl=zysentinel/index.cgi\nicon=zysentinel.png\ntarget=_blank\n'
            'searchtext=ZySentinel security waf antivirus firewall\n')

# ikon plugin 48x48 (PNG, dibangkitkan dari logo ZySentinel)
_ICON_PNG_B64 = (
    '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')

# Ikon SVG (DirectAdmin memakai images/admin_icon.svg)
_ICON_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64"><defs>'
             '<linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0891b2"/><stop offset="1" stop-color="#059669"/></linearGradient></defs>'
             '<path d="M32 6 10 15v16c0 13 9 25 22 29 13-4 22-16 22-29V15z" fill="none" stroke="url(#g)" stroke-width="4" stroke-linejoin="round"/>'
             '<path d="M22 32l7 7 13-14" fill="none" stroke="url(#g)" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>\n')

# Item lama (versi sebelumnya menambal grup Security Center); dipertahankan hanya untuk membersihkannya.
_WHM_ITEM = """    {
        "acl": "ACL=all",
        "file": "zysentinel.svg",
        "group": "security_center",
        "imgtype": "icon",
        "itemdesc": "ZySentinel",
        "description": "WAF, antivirus, firewall",
        "itemorder": 20,
        "searchtext": "security center zysentinel waf antivirus firewall",
        "subtype": "img",
        "type": "image",
        "url": "/cgi/zysentinel/index.cgi",
        "key": "zysentinel"
    }"""
# objek item kita tidak bersarang, jadi pola ini cukup untuk mencabutnya beserta koma pemisahnya
_WHM_ITEM_RE = re.compile(r',[ \t]*\n[ \t]*\{[^{}]*"key"\s*:\s*"zysentinel"[^{}]*\}')


def cpanel_present():
    return os.path.isfile(_whm_paths()['dui']) and os.path.isfile(os.path.join(CPANEL, 'version'))


def _dui_del(s):
    return _WHM_ITEM_RE.sub('', s)


def cpanel_status():
    p = _whm_paths()
    try:
        return (os.path.isfile(p['cgi']) and os.path.isfile(p['icon']) and 'entryurl=' in _read(p['app'])
                and '"key": "zysentinel"' not in _read(p['dui']))
    except OSError:
        return False


def _put(path, text, mode):
    """Tulis berkas bila isinya berbeda; mengembalikan True bila berubah."""
    try:
        if _read(path) == text:
            os.chmod(path, mode)
            return False
    except OSError:
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.zys-tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def _put_bytes(path, data, mode):
    try:
        with open(path, 'rb') as f:
            if f.read() == data:
                os.chmod(path, mode)
                return False
    except OSError:
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.zys-tmp'
    with open(tmp, 'wb') as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def _restart_whm():
    try:
        subprocess.run(['/scripts/restartsrv_cpsrvd'], timeout=120, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _appconfig(cmd, path):
    exe = os.path.join(CPANEL, 'bin', cmd)
    if os.path.isfile(exe):
        subprocess.run([exe, path], timeout=120, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _drop_dui_cache():
    try:
        os.remove(os.path.join(CPANEL_VAR, 'dynamicaclitems.cache'))
    except OSError:
        pass


def cpanel_install(restart=True):
    if not cpanel_present():
        print('panel_menu: cPanel/WHM tidak ditemukan di %s' % CPANEL, file=sys.stderr)
        return 1
    p = _whm_paths()
    changed = _put(p['cgi'], _CGI % {'port': UI_PORT}, 0o755)
    changed |= _put_bytes(p['icon'], base64.b64decode(''.join(_ICON_PNG_B64)), 0o644)
    if _put(p['app'], _APPCONF, 0o644):
        changed = True
        _appconfig('register_appconfig', p['app'])
    # pembersihan versi lama yang menambal grup Security Center di berkas inti WHM
    try:
        dui = _read(p['dui'])
        if _dui_del(dui) != dui:
            _write(p['dui'], _dui_del(dui))
            changed = True
    except OSError:
        pass
    try:
        os.remove(p['oldicon'])
        changed = True
    except OSError:
        pass
    if changed and restart:
        _drop_dui_cache()
        _restart_whm()
    print('panel_menu: ikon ZySentinel %s di WHM > Plugins' % ('dipasang' if changed else 'sudah ada'))
    return 0


def cpanel_remove(restart=True):
    if not cpanel_present():
        return 0
    p = _whm_paths()
    changed = False
    try:
        dui = _read(p['dui'])
        if _dui_del(dui) != dui:
            _write(p['dui'], _dui_del(dui))
            changed = True
    except OSError:
        pass
    if os.path.exists(p['app']):
        _appconfig('unregister_appconfig', p['app'])
        changed = True
    for f in (p['cgi'], p['icon'], p['oldicon'], p['app']):
        try:
            os.remove(f)
            changed = True
        except OSError:
            pass
    try:
        os.remove(p['dui'] + '.zys-orig')       # cadangan dari versi lama yang menambal berkas inti
    except OSError:
        pass
    try:
        os.rmdir(os.path.dirname(p['cgi']))
    except OSError:
        pass
    if changed and restart:
        _drop_dui_cache()
        _restart_whm()
    print('panel_menu: ikon ZySentinel %s dari WHM' % ('dicabut' if changed else 'tidak ada'))
    return 0


# ----------------------------------------------------------------------------- DirectAdmin
# Plugin DirectAdmin standar (/usr/local/directadmin/plugins/<nama>): plugin.conf + hooks/admin_txt.html (tautan menu admin,
# Evolution menampilkannya di grup Extra Features) + images/admin_icon.svg + admin/index.html (halaman yang dijalankan DA).
DA = os.environ.get('ZYS_DA_DIR', '/usr/local/directadmin')

_VER_RE = re.compile(r'^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]{1,20})?$')


def plugin_version():
    """Versi ZySentinel terpasang: sumber tunggal info.json ("versions"), sama dengan yang dipakai plugin dan Plugin Manager.
    Urutan: ZYS_PLUGIN_INFO, info.json di samping adapters/, lalu salinan terpasang di <BASE>/ui. Tidak ketemu atau formatnya
    ganjil: '0.0' (tidak pernah menampilkan versi karangan)."""
    here = os.path.dirname(os.path.abspath(__file__))
    base = os.environ.get('ZYS_BASE', '/www/server/sentinel')
    cands = [os.environ.get('ZYS_PLUGIN_INFO', ''), os.path.join(here, '..', 'info.json'),
             os.path.join(base, 'ui', 'info.json'), os.path.join(here, '..', '..', 'info.json')]
    for c in cands:
        if not c:
            continue
        try:
            with open(c, encoding='utf-8') as f:
                v = str(json.load(f).get('versions', '')).strip()
        except (OSError, ValueError, AttributeError):
            continue
        if _VER_RE.match(v):
            return v
    return '0.0'


def _da_conf():
    return ('active=yes\nauthor=ZySens Labs\nid=zysentinel\ninstalled=yes\nname=ZySentinel\n'
            'update_url=\nversion=%s\nversion_url=\n' % plugin_version())

_DA_HOOK = '<a href="/CMD_PLUGINS_ADMIN/zysentinel" target="_blank">ZySentinel</a>\n'

# Halaman plugin: teruskan ke UI standalone di host yang sama. Nama host diambil di peramban (location.hostname),
# jadi benar untuk IP maupun domain dan tidak bergantung pada variabel lingkungan DA. Skema SELALU https: UI standalone hanya
# HTTPS, sedangkan panel (DirectAdmin tanpa sertifikat) bisa melayani http; location.protocol di sini membuat tautan salah.
_DA_PAGE = r"""#!/bin/sh
echo '<div style="padding:24px;font-family:sans-serif">'
echo '<h2>ZySentinel</h2>'
echo '<p><a id="zysentinel-go" href="#">Open ZySentinel (WAF, antivirus, firewall)</a></p>'
echo '</div>'
echo '<script>(function(){var u="https://"+location.hostname+":%(port)d/";var a=document.getElementById("zysentinel-go");if(a){a.href=u;}location.replace(u);})();</script>'
"""


def _da_paths():
    d = os.path.join(DA, 'plugins', 'zysentinel')
    return {'dir': d, 'conf': os.path.join(d, 'plugin.conf'), 'hook': os.path.join(d, 'hooks', 'admin_txt.html'),
            'page': os.path.join(d, 'admin', 'index.html'), 'icon': os.path.join(d, 'images', 'admin_icon.svg')}


def da_present():
    return os.path.isfile(os.path.join(DA, 'directadmin')) and os.path.isdir(os.path.join(DA, 'plugins'))


def da_status():
    p = _da_paths()
    try:
        return (_read(p['conf']) == _da_conf() and _read(p['hook']) == _DA_HOOK and _read(p['page']) == _DA_PAGE % {'port': UI_PORT}
                and os.access(p['page'], os.X_OK) and os.path.isfile(p['icon']))
    except OSError:
        return False


def _da_chown(path):
    """Pemilik mengikuti plugin bawaan DA (diradmin); tanpa pengguna itu (uji) dibiarkan."""
    try:
        import pwd
        u = pwd.getpwnam('diradmin')
        os.chown(path, u.pw_uid, u.pw_gid)
    except (ImportError, KeyError, OSError):
        pass


def da_install():
    if not da_present():
        print('panel_menu: DirectAdmin tidak ditemukan di %s' % DA, file=sys.stderr)
        return 1
    p = _da_paths()
    changed = False
    for key, text, mode in (('conf', _da_conf(), 0o644), ('hook', _DA_HOOK, 0o644), ('page', _DA_PAGE % {'port': UI_PORT}, 0o755),
                            ('icon', _ICON_SVG, 0o644)):
        changed |= _put(p[key], text, mode)
        _da_chown(p[key])
    for sub in ('', 'hooks', 'admin', 'images'):
        d = os.path.join(p['dir'], sub) if sub else p['dir']
        os.chmod(d, 0o755)
        _da_chown(d)
    print('panel_menu: ZySentinel %s di DirectAdmin (menu admin, Extra Features)' % ('dipasang' if changed else 'sudah ada'))
    return 0


def da_remove():
    if not da_present():
        return 0
    d = _da_paths()['dir']
    existed = os.path.isdir(d)
    if existed:
        # hanya berkas buatan kita; isi lain (jika admin menambah) tidak ikut terhapus
        for sub in ('plugin.conf', 'hooks/admin_txt.html', 'admin/index.html', 'images/admin_icon.svg'):
            try:
                os.remove(os.path.join(d, sub))
            except OSError:
                pass
        for sub in ('hooks', 'admin', 'images', ''):
            try:
                os.rmdir(os.path.join(d, sub) if sub else d)
            except OSError:
                pass
    print('panel_menu: ZySentinel %s dari DirectAdmin' % ('dicabut' if existed else 'tidak ada'))
    return 0


def detect():
    if os.path.isdir(CYBERCP):
        return 'cyberpanel'
    if os.path.isfile(os.path.join(CPANEL, 'version')):
        return 'cpanel'
    if os.path.isfile(os.path.join(DA, 'directadmin')):
        return 'directadmin'
    return ''


def main(argv):
    args = [a for a in argv[1:]]
    panel = ''
    if '--panel' in args:
        i = args.index('--panel')
        panel = args[i + 1] if i + 1 < len(args) else ''
        del args[i:i + 2]
    cmd = args[0] if args else 'status'
    panel = panel or detect()
    if panel not in ('cyberpanel', 'cpanel', 'directadmin'):
        if cmd == 'status':
            print('tidak ada integrasi menu untuk panel ini')
        return 0
    present, status, install, remove = {'cpanel': (cpanel_present, cpanel_status, cpanel_install, cpanel_remove),
                                        'directadmin': (da_present, da_status, da_install, da_remove)}.get(
        panel, (cyberpanel_present, cyberpanel_status, cyberpanel_install, cyberpanel_remove))
    if cmd == 'install':
        return install()
    if cmd == 'remove':
        return remove()
    if cmd == 'check':          # dipanggil pemulihan mandiri: pasang ulang bila pembaruan panel menimpa berkas menu
        if panel == 'directadmin':
            return 0            # update DirectAdmin tidak menyentuh folder plugin; Disable/Delete di Plugin Manager adalah keputusan admin
        return 0 if status() or not present() else install()
    if cmd == 'status':
        print('terpasang' if status() else 'belum terpasang')
        return 0
    print('pakai: panel_menu.py {install|remove|status|check} [--panel cyberpanel|cpanel|directadmin]', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
