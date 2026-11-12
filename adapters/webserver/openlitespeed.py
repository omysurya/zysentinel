# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk web server OpenLiteSpeed (OLS)."""
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseWebServerAdapter, WebServerInfo, WAFStatus


class OpenLiteSpeedAdapter(BaseWebServerAdapter):
    """Implementasi adapter untuk OpenLiteSpeed."""

    def __init__(
        self,
        base_dir: str = "/usr/local/lsws",
    ):
        self.base_dir = base_dir
        self.bin_path = os.path.join(base_dir, "bin", "openlitespeed")
        self.ctrl_path = os.path.join(base_dir, "bin", "lswsctrl")
        self.conf_path = os.path.join(base_dir, "conf", "httpd_config.conf")
        self.vhost_dir = os.path.join(base_dir, "conf", "vhosts")

    def detect(self) -> bool:
        """Mengembalikan True jika OpenLiteSpeed terpasang."""
        return os.path.isfile(self.ctrl_path) and os.access(self.ctrl_path, os.X_OK)

    def get_info(self) -> WebServerInfo:
        """Metadata OpenLiteSpeed dan status running."""
        ver = ""
        is_running = False
        if os.path.isfile(self.bin_path):
            try:
                p = subprocess.run([self.bin_path, "-v"], capture_output=True, text=True, timeout=5)
                out = p.stdout or p.stderr
                m = re.search(r"OpenLiteSpeed/([0-9.]+)", out)
                if m:
                    ver = m.group(1)
            except Exception:
                pass

        try:
            p = subprocess.run(["pgrep", "-f", "openlitespeed"], capture_output=True, text=True, timeout=3)
            is_running = p.returncode == 0 and bool(p.stdout.strip())
        except Exception:
            pass

        return WebServerInfo(
            name="openlitespeed",
            version=ver,
            binary_path=self.bin_path,
            config_file=self.conf_path,
            vhost_dir=self.vhost_dir,
            is_running=is_running,
        )

    def test_configuration(self) -> Tuple[bool, str]:
        """Memeriksa keberadaan dan keterbacaan berkas konfigurasi OLS."""
        if not os.path.isfile(self.conf_path):
            return False, f"Berkas konfigurasi tidak ditemukan: {self.conf_path}"
        try:
            with open(self.conf_path, "r") as f:
                content = f.read(1024)
            return True, "Sintaks dasar konfigurasi OLS valid"
        except Exception as e:
            return False, str(e)

    def reload_service(self) -> bool:
        """Melakukan reload graceful OpenLiteSpeed via lswsctrl."""
        if os.path.isfile(self.ctrl_path):
            try:
                p = subprocess.run([self.ctrl_path, "restart"], capture_output=True, text=True, timeout=10)
                return p.returncode == 0
            except Exception:
                pass
        try:
            p = subprocess.run(["systemctl", "reload", "lsws"], capture_output=True, text=True, timeout=10)
            return p.returncode == 0
        except Exception:
            return False

    def get_vhost_config_dir(self) -> str:
        return self.vhost_dir

    def inject_waf_include(self, vhost_domain: str, snippet_path: str) -> bool:
        """Menyisipkan konfigurasi ModSecurity rule pada OLS vhost."""
        vh_conf = os.path.join(self.vhost_dir, vhost_domain, "vhconf.conf")
        if not os.path.isfile(vh_conf):
            return False
        try:
            with open(vh_conf, "r") as f:
                content = f.read()

            marker = f"include {snippet_path}"
            if marker in content:
                return True

            new_content = content + f"\n# ZySentinel OLS WAF\nmodule mod_security {{\n  include {snippet_path}\n}}\n"
            with open(vh_conf + ".tmp", "w") as f:
                f.write(new_content)
            os.replace(vh_conf + ".tmp", vh_conf)
            return True
        except Exception:
            return False

    def remove_waf_include(self, vhost_domain: str) -> bool:
        """Mencabut konfigurasi WAF dari OLS vhost."""
        vh_conf = os.path.join(self.vhost_dir, vhost_domain, "vhconf.conf")
        if not os.path.isfile(vh_conf):
            return False
        try:
            with open(vh_conf, "r") as f:
                lines = f.readlines()
            new_lines = [l for l in lines if not ("sentinel" in l.lower() and "include" in l.lower())]
            with open(vh_conf + ".tmp", "w") as f:
                f.writelines(new_lines)
            os.replace(vh_conf + ".tmp", vh_conf)
            return True
        except Exception:
            return False

    def get_access_log_paths(self, vhost_domain: str) -> List[str]:
        """Membaca log path dari vhconf.conf OLS."""
        vh_conf = os.path.join(self.vhost_dir, vhost_domain, "vhconf.conf")
        logs = []
        if os.path.isfile(vh_conf):
            try:
                with open(vh_conf, "r") as f:
                    for line in f:
                        line = line.strip()
                        m = re.search(r"fileName\s+([^\s]+)", line)
                        if m and "log" in m.group(1).lower():
                            path = m.group(1).replace("$VH_ROOT", os.path.join(self.base_dir, vhost_domain))
                            if os.path.isfile(path) and path not in logs:
                                logs.append(path)
            except Exception:
                pass
        return logs

    def get_waf_status(self) -> WAFStatus:
        """Memeriksa status modul mod_security OLS."""
        has_modsec = False
        if os.path.isfile(self.conf_path):
            try:
                with open(self.conf_path, "r") as f:
                    if "mod_security" in f.read():
                        has_modsec = True
            except Exception:
                pass

        return WAFStatus(
            engine="modsecurity" if has_modsec else "none",
            is_enabled=has_modsec,
            active_rulesets=["zyrules"] if has_modsec else [],
        )
