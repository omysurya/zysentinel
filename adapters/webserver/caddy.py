# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk web server Caddy."""
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseWebServerAdapter, WebServerInfo, WAFStatus


class CaddyAdapter(BaseWebServerAdapter):
    """Implementasi adapter untuk Caddy Web Server."""

    def __init__(
        self,
        binary_path: Optional[str] = None,
        config_path: Optional[str] = None,
    ):
        self._custom_bin = binary_path
        self._custom_conf = config_path

    def _bin(self) -> str:
        if self._custom_bin and os.path.isfile(self._custom_bin):
            return self._custom_bin
        for cand in ("/usr/bin/caddy", "/usr/local/bin/caddy", "/bin/caddy"):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
        w = shutil.which("caddy")
        return w or "/usr/bin/caddy"

    def _conf(self) -> str:
        if self._custom_conf and os.path.isfile(self._custom_conf):
            return self._custom_conf
        for cand in ("/etc/caddy/Caddyfile", "/etc/caddy/caddy.json"):
            if os.path.isfile(cand):
                return cand
        return "/etc/caddy/Caddyfile"

    def detect(self) -> bool:
        """Mengembalikan True jika biner caddy tersedia."""
        b = self._bin()
        return os.path.isfile(b) and os.access(b, os.X_OK)

    def get_info(self) -> WebServerInfo:
        """Metadata biner Caddy dan status proses."""
        b = self._bin()
        ver = ""
        is_running = False
        if os.path.isfile(b):
            try:
                p = subprocess.run([b, "version"], capture_output=True, text=True, timeout=5)
                out = p.stdout.strip()
                m = re.search(r"v?([0-9.]+)", out)
                if m:
                    ver = m.group(1)
            except Exception:
                pass

        try:
            p = subprocess.run(["pgrep", "-x", "caddy"], capture_output=True, text=True, timeout=3)
            is_running = p.returncode == 0 and bool(p.stdout.strip())
        except Exception:
            pass

        return WebServerInfo(
            name="caddy",
            version=ver,
            binary_path=b,
            config_file=self._conf(),
            vhost_dir=os.path.dirname(self._conf()),
            is_running=is_running,
        )

    def test_configuration(self) -> Tuple[bool, str]:
        """Menjalankan caddy validate --config <conf>."""
        b = self._bin()
        c = self._conf()
        try:
            p = subprocess.run([b, "validate", "--config", c], capture_output=True, text=True, timeout=10)
            msg = (p.stderr or p.stdout or "").strip()
            return p.returncode == 0, msg
        except Exception as e:
            return False, str(e)

    def reload_service(self) -> bool:
        """Melakukan reload konfigurasi Caddy (caddy reload atau systemctl reload caddy)."""
        ok, _ = self.test_configuration()
        if not ok:
            return False

        b = self._bin()
        c = self._conf()
        try:
            p = subprocess.run([b, "reload", "--config", c], capture_output=True, text=True, timeout=10)
            if p.returncode == 0:
                return True
        except Exception:
            pass

        try:
            p = subprocess.run(["systemctl", "reload", "caddy"], capture_output=True, text=True, timeout=10)
            return p.returncode == 0
        except Exception:
            return False

    def get_vhost_config_dir(self) -> str:
        """Direktori Caddyfile snippets."""
        snip_dir = "/etc/caddy/conf.d"
        return snip_dir if os.path.isdir(snip_dir) else os.path.dirname(self._conf())

    def inject_waf_include(self, vhost_domain: str, snippet_path: str) -> bool:
        """Menyisipkan direktif import snippet ke Caddyfile."""
        conf = self._conf()
        if not os.path.isfile(conf):
            return False
        try:
            with open(conf, "r") as f:
                content = f.read()

            marker = f"import {snippet_path}"
            if marker in content:
                return True

            # Sisipkan ke dalam blok domain bersangkutan
            pattern = rf"({re.escape(vhost_domain)}\s*\{{)"
            if re.search(pattern, content):
                replacement = f"\\1\n    import {snippet_path}"
                new_content = re.sub(pattern, replacement, content, count=1)
            else:
                new_content = content + f"\nimport {snippet_path}\n"

            with open(conf + ".tmp", "w") as f:
                f.write(new_content)
            os.replace(conf + ".tmp", conf)
            return True
        except Exception:
            return False

    def remove_waf_include(self, vhost_domain: str) -> bool:
        """Mencabut snippet import WAF dari Caddyfile."""
        conf = self._conf()
        if not os.path.isfile(conf):
            return False
        try:
            with open(conf, "r") as f:
                lines = f.readlines()

            new_lines = [l for l in lines if not ("import" in l and "sentinel" in l.lower())]

            with open(conf + ".tmp", "w") as f:
                f.writelines(new_lines)
            os.replace(conf + ".tmp", conf)
            return True
        except Exception:
            return False

    def get_access_log_paths(self, vhost_domain: str) -> List[str]:
        """Membaca log path dari direktif log Caddyfile."""
        conf = self._conf()
        logs = []
        if os.path.isfile(conf):
            try:
                with open(conf, "r") as f:
                    for line in f:
                        line = line.strip()
                        m = re.search(r"output\s+file\s+([^\s]+)", line)
                        if m:
                            p = m.group(1).strip("\"'")
                            if os.path.isfile(p) and p not in logs:
                                logs.append(p)
            except Exception:
                pass
        return logs

    def get_waf_status(self) -> WAFStatus:
        """Memeriksa engine Coraza pada Caddy."""
        b = self._bin()
        has_coraza = False
        try:
            p = subprocess.run([b, "list-modules"], capture_output=True, text=True, timeout=5)
            if "coraza" in p.stdout.lower():
                has_coraza = True
        except Exception:
            pass

        return WAFStatus(
            engine="coraza" if has_coraza else "none",
            is_enabled=has_coraza,
            active_rulesets=["zyrules"] if has_coraza else [],
        )
