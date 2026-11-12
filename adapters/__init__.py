# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""ZySentinel Universal Adapters Package.

Menyediakan abstraksi terpadu untuk:
- Control Panels: aaPanel, Standalone, cPanel/WHM, DirectAdmin, CyberPanel
- Web Servers: Nginx, Apache HTTPD, Caddy, OpenLiteSpeed, LiteSpeed Enterprise
- Package Managers: APT (Debian/Ubuntu), DNF/YUM (RHEL/AlmaLinux/RockyLinux), APK (Alpine)
"""
from typing import Optional

from .panel.base import BasePanelAdapter, PanelInfo, VHostInfo, PHPRuntimeInfo
from .panel.aapanel import AAPanelAdapter
from .panel.standalone import StandaloneAdapter
from .panel.cpanel import CPanelAdapter
from .panel.directadmin import DirectAdminAdapter
from .panel.cyberpanel import CyberPanelAdapter

from .webserver.base import BaseWebServerAdapter, WebServerInfo, WAFStatus
from .webserver.nginx import NginxAdapter
from .webserver.apache import ApacheAdapter
from .webserver.caddy import CaddyAdapter
from .webserver.openlitespeed import OpenLiteSpeedAdapter

from .pkg.base import BasePkgAdapter, PackageInfo
from .pkg.apt import AptAdapter
from .pkg.dnf import DnfAdapter
from .pkg.apk import ApkAdapter


def get_panel_adapter() -> BasePanelAdapter:
    """Mendeteksi dan mengembalikan adapter control panel aktif."""
    aa = AAPanelAdapter()
    if aa.detect():
        return aa
    cp = CPanelAdapter()
    if cp.detect():
        return cp
    da = DirectAdminAdapter()
    if da.detect():
        return da
    cb = CyberPanelAdapter()
    if cb.detect():
        return cb
    st = StandaloneAdapter()
    if st.detect():
        return st
    return StandaloneAdapter()


def get_webserver_adapter() -> BaseWebServerAdapter:
    """Mendeteksi dan mengembalikan adapter web server aktif."""
    ng = NginxAdapter()
    if ng.detect():
        return ng
    ap = ApacheAdapter()
    if ap.detect():
        return ap
    cd = CaddyAdapter()
    if cd.detect():
        return cd
    ols = OpenLiteSpeedAdapter()
    if ols.detect():
        return ols
    return NginxAdapter()


def get_pkg_adapter() -> Optional[BasePkgAdapter]:
    """Mendeteksi dan mengembalikan adapter package manager sistem."""
    apt = AptAdapter()
    if apt.detect():
        return apt
    dnf = DnfAdapter()
    if dnf.detect():
        return dnf
    apk = ApkAdapter()
    if apk.detect():
        return apk
    return None
