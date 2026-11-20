# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk control panel cPanel & WHM."""
import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from .base import BasePanelAdapter, PanelInfo, VHostInfo, PHPRuntimeInfo


class CPanelAdapter(BasePanelAdapter):
    """Implementasi adapter untuk cPanel/WHM."""

    def __init__(self, cpanel_dir: str = "/usr/local/cpanel"):
        self.cpanel_dir = cpanel_dir
        self.version_file = os.path.join(cpanel_dir, "version")
        self.userdata_domains = "/etc/userdatadomains"
        self.auth_log = "/usr/local/cpanel/logs/login_log"

    def detect(self) -> bool:
        """Mengembalikan True jika cPanel/WHM terpasang."""
        return os.path.isfile(self.version_file) or os.path.isdir("/var/cpanel")

    def get_panel_info(self) -> PanelInfo:
        """Metadata instalasi cPanel/WHM."""
        ver = ""
        if os.path.isfile(self.version_file):
            try:
                with open(self.version_file, "r") as f:
                    ver = f.read().strip()
            except Exception:
                pass

        return PanelInfo(
            name="cpanel",
            version=ver,
            port=2087,
            bind_ip="0.0.0.0",
            config_dir="/var/cpanel",
            is_installed=self.detect(),
        )

    def get_vhosts(self) -> List[VHostInfo]:
        """Membaca daftar virtual host dari /etc/userdatadomains cPanel."""
        vhosts = []
        if os.path.isfile(self.userdata_domains):
            try:
                with open(self.userdata_domains, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or ":" not in line:
                            continue
                        domain, rest = line.split(":", 1)
                        parts = rest.strip().split("==")
                        # user==owner==type==main_domain==docroot==ip_port==ssl_cert==ssl_key
                        if len(parts) >= 5:
                            docroot = parts[4]
                            has_ssl = len(parts) >= 7 and bool(parts[6].strip())
                            vhosts.append(
                                VHostInfo(
                                    domain=domain.strip(),
                                    docroot=docroot.strip(),
                                    ssl_enabled=has_ssl,
                                    is_active=True,
                                )
                            )
            except Exception:
                pass
        return vhosts

    def get_php_runtimes(self) -> List[PHPRuntimeInfo]:
        """Menemukan runtime EasyApache (ea-php) cPanel."""
        runtimes = []
        base_ea = "/opt/cpanel"
        if os.path.isdir(base_ea):
            try:
                for entry in sorted(os.listdir(base_ea)):
                    if entry.startswith("ea-php"):
                        bin_p = os.path.join(base_ea, entry, "root", "usr", "bin", "php")
                        if os.path.isfile(bin_p) and os.access(bin_p, os.X_OK):
                            m = re.search(r"ea-php(\d)(\d+)", entry)
                            v_str = f"{m.group(1)}.{m.group(2)}" if m else entry
                            runtimes.append(
                                PHPRuntimeInfo(
                                    version=v_str,
                                    binary_path=bin_p,
                                    ini_path=os.path.join(base_ea, entry, "root", "etc", "php.ini"),
                                )
                            )
            except Exception:
                pass
        return runtimes

    def get_auth_log_path(self) -> str:
        return self.auth_log if os.path.isfile(self.auth_log) else "/var/log/secure"

    def render_error(self, message: str, code: int = -1) -> Dict[str, Any]:
        return {
            "status": 0,
            "statusmsg": message,
            "error": message,
            "code": code,
        }

    def render_success(self, data: Optional[Dict[str, Any]] = None, message: str = "Success") -> Dict[str, Any]:
        res = {
            "status": 1,
            "statusmsg": message,
        }
        if data is not None:
            res["data"] = data
        return res
