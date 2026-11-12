# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk web server Nginx."""
import os
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseWebServerAdapter, WebServerInfo, WAFStatus


class NginxAdapter(BaseWebServerAdapter):
    """Implementasi adapter untuk Nginx."""

    def __init__(
        self,
        binary_path: Optional[str] = None,
        config_path: Optional[str] = None,
        vhost_dir: Optional[str] = None,
    ):
        self._custom_bin = binary_path
        self._custom_conf = config_path
        self._custom_vhost = vhost_dir

    def _bin(self) -> str:
        if self._custom_bin and os.path.isfile(self._custom_bin):
            return self._custom_bin
        for cand in ("/www/server/nginx/sbin/nginx", "/usr/sbin/nginx", "/usr/local/sbin/nginx"):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
        w = shutil.which("nginx")
        return w or "/www/server/nginx/sbin/nginx"

    def _conf(self) -> str:
        if self._custom_conf and os.path.isfile(self._custom_conf):
            return self._custom_conf
        for cand in ("/www/server/nginx/conf/nginx.conf", "/etc/nginx/nginx.conf"):
            if os.path.isfile(cand):
                return cand
        return "/www/server/nginx/conf/nginx.conf"

    def detect(self) -> bool:
        """Mengembalikan True jika biner nginx tersedia dan dapat dieksekusi."""
        b = self._bin()
        return os.path.isfile(b) and os.access(b, os.X_OK)

    def get_info(self) -> WebServerInfo:
        """Metadata biner Nginx dan status running."""
        b = self._bin()
        ver = ""
        is_running = False
        if os.path.isfile(b):
            try:
                p = subprocess.run([b, "-v"], capture_output=True, text=True, timeout=5)
                out = p.stderr or p.stdout
                m = re.search(r"nginx/([0-9.]+)", out)
                if m:
                    ver = m.group(1)
            except Exception:
                pass

        try:
            pids = subprocess.run(["pgrep", "-f", "nginx"], capture_output=True, text=True, timeout=3)
            is_running = bool(pids.stdout.strip())
        except Exception:
            pass

        return WebServerInfo(
            name="nginx",
            version=ver,
            binary_path=b,
            config_file=self._conf(),
            vhost_dir=self.get_vhost_config_dir(),
            is_running=is_running,
        )

    def test_configuration(self) -> Tuple[bool, str]:
        """Uji sintaks via nginx -t."""
        b = self._bin()
        c = self._conf()
        if not os.path.isfile(b):
            return False, "Biner nginx tidak ditemukan"
        try:
            cmd = [b, "-t"]
            if os.path.isfile(c):
                cmd.extend(["-c", c])
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            out = (p.stderr + "\n" + p.stdout).strip()
            ok = p.returncode == 0 and "syntax is ok" in out and "test is successful" in out
            return ok, out
        except Exception as e:
            return False, str(e)

    def _worker_pids(self) -> List[str]:
        """Membaca daftar PID worker nginx yang sedang aktif."""
        try:
            p = subprocess.run(
                ["ps", "-o", "pid,cmd", "-C", "nginx"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            pids = []
            for line in p.stdout.splitlines():
                if "worker" in line:
                    parts = line.strip().split()
                    if parts:
                        pids.append(parts[0])
            return sorted(pids)
        except Exception:
            return []

    def reload_service(self) -> bool:
        """Reload dengan verifikasi pergantian PID worker (aturan /www/AGENTS.md)."""
        ok, out = self.test_configuration()
        if not ok:
            return False

        pids_before = self._worker_pids()

        # Eksekusi reload (coba init script lalu systemctl)
        reloaded = False
        for cmd in (["/etc/init.d/nginx", "reload"], ["systemctl", "reload", "nginx"]):
            if os.path.isfile(cmd[0]) or shutil.which(cmd[0]):
                try:
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if p.returncode == 0:
                        reloaded = True
                        break
                except Exception:
                    pass

        if not reloaded:
            b = self._bin()
            try:
                subprocess.run([b, "-s", "reload"], capture_output=True, timeout=10)
            except Exception:
                pass

        time.sleep(1.5)
        pids_after = self._worker_pids()

        # Jika proses worker sebelum reload ada, pastikan PID berubah
        if pids_before and pids_after and pids_before == pids_after:
            return False

        return True

    def get_vhost_config_dir(self) -> str:
        """Mendapatkan direktori berkas vhost Nginx."""
        if self._custom_vhost and os.path.isdir(self._custom_vhost):
            return self._custom_vhost
        for cand in (
            "/www/server/panel/vhost/nginx",
            "/etc/nginx/sites-enabled",
            "/etc/nginx/conf.d",
        ):
            if os.path.isdir(cand):
                return cand
        return "/www/server/panel/vhost/nginx"

    def inject_waf_include(self, vhost_domain: str, snippet_path: str) -> bool:
        """Menyisipkan direktif include WAF pada vhost."""
        vhost_dir = self.get_vhost_config_dir()
        conf_file = os.path.join(vhost_dir, f"{vhost_domain}.conf")
        if not os.path.isfile(conf_file):
            return False

        try:
            with open(conf_file, "r") as f:
                content = f.read()

            inc_stmt = f"include {snippet_path};"
            if inc_stmt in content:
                return True

            # Sisipkan sebelum penutup blok server
            if "server {" in content:
                idx = content.rfind("}")
                if idx != -1:
                    new_content = content[:idx] + f"\n    {inc_stmt}\n" + content[idx:]
                    with open(conf_file + ".tmp", "w") as f:
                        f.write(new_content)

                    # Validasi konfigurasi sebelum menerapkan permanen
                    os.replace(conf_file + ".tmp", conf_file)
                    ok, _ = self.test_configuration()
                    if not ok:
                        # Rollback bila tidak valid
                        with open(conf_file, "w") as f:
                            f.write(content)
                        return False
                    return True
        except Exception:
            pass
        return False

    def remove_waf_include(self, vhost_domain: str) -> bool:
        """Mencabut direktif include WAF dari vhost."""
        vhost_dir = self.get_vhost_config_dir()
        conf_file = os.path.join(vhost_dir, f"{vhost_domain}.conf")
        if not os.path.isfile(conf_file):
            return False

        try:
            with open(conf_file, "r") as f:
                lines = f.readlines()

            new_lines = [l for l in lines if "sentinel/waf" not in l and "free_waf" not in l]
            if len(new_lines) != len(lines):
                with open(conf_file + ".tmp", "w") as f:
                    f.writelines(new_lines)
                os.replace(conf_file + ".tmp", conf_file)
                return True
        except Exception:
            pass
        return False

    def get_access_log_paths(self, vhost_domain: str) -> List[str]:
        """Menemukan jalur access log vhost domain bersangkutan."""
        paths = []
        for cand in (
            f"/www/wwwlogs/{vhost_domain}.log",
            f"/var/log/nginx/{vhost_domain}.access.log",
            f"/var/log/nginx/{vhost_domain}_access.log",
        ):
            if os.path.isfile(cand):
                paths.append(cand)
        return paths

    def get_waf_status(self) -> WAFStatus:
        """Membaca konfigurasi WAF Nginx (Coraza / Lua)."""
        conf_path = self._conf()
        engine = "none"
        is_enabled = False
        if os.path.isfile(conf_path):
            try:
                with open(conf_path, "r", errors="ignore") as f:
                    txt = f.read()
                    if "ngx_http_coraza_module.so" in txt or "coraza_rules" in txt:
                        engine = "coraza"
                        is_enabled = True
                    elif "access_by_lua_file" in txt or "lua_package_path" in txt:
                        engine = "lua"
                        is_enabled = True
            except OSError:
                pass
        return WAFStatus(engine=engine, is_enabled=is_enabled)
