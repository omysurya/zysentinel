# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk control panel CyberPanel."""
import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from .base import BasePanelAdapter, PanelInfo, VHostInfo, PHPRuntimeInfo


class CyberPanelAdapter(BasePanelAdapter):
    """Implementasi adapter untuk CyberPanel."""

    def __init__(self, cybercp_dir: str = "/usr/local/CyberCP"):
        self.cybercp_dir = cybercp_dir
        self.auth_log = "/home/cyberpanel/error-logs.txt"

    def detect(self) -> bool:
        """Mengembalikan True jika CyberPanel terpasang."""
        return os.path.isdir(self.cybercp_dir)

    def get_panel_info(self) -> PanelInfo:
        """Metadata CyberPanel."""
        ver = ""
        ver_file = os.path.join(self.cybercp_dir, "version.txt")
        if os.path.isfile(ver_file):
            try:
                with open(ver_file, "r") as f:
                    ver = f.read().strip()
            except Exception:
                pass

        return PanelInfo(
            name="cyberpanel",
            version=ver,
            port=8090,
            bind_ip="0.0.0.0",
            config_dir=self.cybercp_dir,
            is_installed=self.detect(),
        )

    def get_vhosts(self) -> List[VHostInfo]:
        """Membaca daftar virtual host dari direktori /home CyberPanel."""
        vhosts = []
        home_dir = "/home"
        if os.path.isdir(home_dir):
            try:
                for entry in sorted(os.listdir(home_dir)):
                    docroot = os.path.join(home_dir, entry, "public_html")
                    if os.path.isdir(docroot):
                        vhosts.append(
                            VHostInfo(
                                domain=entry,
                                docroot=docroot,
                                ssl_enabled=os.path.isdir(f"/etc/letsencrypt/live/{entry}"),
                                is_active=True,
                            )
                        )
            except Exception:
                pass
        return vhosts

    def get_php_runtimes(self) -> List[PHPRuntimeInfo]:
        """Menemukan runtime LiteSpeed PHP (lsphp) CyberPanel."""
        runtimes = []
        lsws_dir = "/usr/local/lsws"
        if os.path.isdir(lsws_dir):
            try:
                for entry in sorted(os.listdir(lsws_dir)):
                    if entry.startswith("lsphp"):
                        bin_p = os.path.join(lsws_dir, entry, "bin", "php")
                        if os.path.isfile(bin_p) and os.access(bin_p, os.X_OK):
                            m = re.search(r"lsphp(\d)(\d+)", entry)
                            v_str = f"{m.group(1)}.{m.group(2)}" if m else entry
                            runtimes.append(
                                PHPRuntimeInfo(
                                    version=v_str,
                                    binary_path=bin_p,
                                    ini_path=os.path.join(lsws_dir, entry, "etc", "php.ini"),
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
            "error_message": message,
            "code": code,
        }

    def render_success(self, data: Optional[Dict[str, Any]] = None, message: str = "Success") -> Dict[str, Any]:
        res = {
            "status": 1,
            "success": 1,
            "message": message,
        }
        if data is not None:
            res["data"] = data
        return res
