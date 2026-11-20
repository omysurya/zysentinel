# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk control panel DirectAdmin."""
import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from .base import BasePanelAdapter, PanelInfo, VHostInfo, PHPRuntimeInfo


class DirectAdminAdapter(BasePanelAdapter):
    """Implementasi adapter untuk DirectAdmin."""

    def __init__(self, da_dir: str = "/usr/local/directadmin"):
        self.da_dir = da_dir
        self.da_bin = os.path.join(da_dir, "directadmin")
        self.data_dir = os.path.join(da_dir, "data")
        self.auth_log = "/var/log/directadmin/login.log"

    def detect(self) -> bool:
        """Mengembalikan True jika DirectAdmin terpasang."""
        return os.path.isfile(self.da_bin) and os.access(self.da_bin, os.X_OK)

    def get_panel_info(self) -> PanelInfo:
        """Metadata DirectAdmin."""
        ver = ""
        if os.path.isfile(self.da_bin):
            try:
                p = subprocess.run([self.da_bin, "v"], capture_output=True, text=True, timeout=5)
                m = re.search(r"DirectAdmin v([0-9.]+)", p.stdout or p.stderr)
                if m:
                    ver = m.group(1)
            except Exception:
                pass

        return PanelInfo(
            name="directadmin",
            version=ver,
            port=2222,
            bind_ip="0.0.0.0",
            config_dir=self.data_dir,
            is_installed=self.detect(),
        )

    def get_vhosts(self) -> List[VHostInfo]:
        """Membaca daftar virtual host dari /etc/virtual/domainowners DirectAdmin."""
        vhosts = []
        domain_owners = "/etc/virtual/domainowners"
        if os.path.isfile(domain_owners):
            try:
                with open(domain_owners, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or ":" not in line:
                            continue
                        domain, user = line.split(":", 1)
                        domain = domain.strip()
                        user = user.strip()
                        docroot = f"/home/{user}/domains/{domain}/public_html"
                        vhosts.append(
                            VHostInfo(
                                domain=domain,
                                docroot=docroot,
                                ssl_enabled=os.path.isdir(f"/home/{user}/domains/{domain}/private_html"),
                                is_active=True,
                            )
                        )
            except Exception:
                pass
        return vhosts

    def get_php_runtimes(self) -> List[PHPRuntimeInfo]:
        """Menemukan runtime PHP CustomBuild DirectAdmin."""
        runtimes = []
        # CustomBuild runtimes
        for cand in ("/usr/local/php56/bin/php", "/usr/local/php74/bin/php", "/usr/local/php80/bin/php", "/usr/local/php81/bin/php", "/usr/local/php82/bin/php", "/usr/local/php83/bin/php"):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                m = re.search(r"php(\d)(\d+)", cand)
                v_str = f"{m.group(1)}.{m.group(2)}" if m else "php"
                runtimes.append(
                    PHPRuntimeInfo(
                        version=v_str,
                        binary_path=cand,
                        ini_path=os.path.join(os.path.dirname(os.path.dirname(cand)), "lib", "php.ini"),
                    )
                )
        return runtimes

    def get_auth_log_path(self) -> str:
        return self.auth_log if os.path.isfile(self.auth_log) else "/var/log/secure"

    def render_error(self, message: str, code: int = -1) -> Dict[str, Any]:
        return {
            "error": "1",
            "text": message,
            "details": message,
            "code": code,
        }

    def render_success(self, data: Optional[Dict[str, Any]] = None, message: str = "Success") -> Dict[str, Any]:
        res = {
            "error": "0",
            "text": message,
        }
        if data is not None:
            res["result"] = data
        return res
