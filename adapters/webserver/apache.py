# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk web server Apache HTTPD."""
import os
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseWebServerAdapter, WebServerInfo, WAFStatus


class ApacheAdapter(BaseWebServerAdapter):
    """Implementasi adapter untuk Apache HTTPD."""

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
        for cand in (
            "/www/server/apache/bin/httpd",
            "/usr/sbin/apache2",
            "/usr/sbin/httpd",
            "/usr/local/apache2/bin/httpd",
        ):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
        w = shutil.which("apache2") or shutil.which("httpd")
        return w or "/usr/sbin/apache2"

    def _conf(self) -> str:
        if self._custom_conf and os.path.isfile(self._custom_conf):
            return self._custom_conf
        for cand in (
            "/www/server/apache/conf/httpd.conf",
            "/etc/apache2/apache2.conf",
            "/etc/httpd/conf/httpd.conf",
        ):
            if os.path.isfile(cand):
                return cand
        return "/etc/apache2/apache2.conf"

    def detect(self) -> bool:
        """Mengembalikan True jika biner apache2/httpd tersedia dan dapat dieksekusi."""
        b = self._bin()
        return os.path.isfile(b) and os.access(b, os.X_OK)

    def get_info(self) -> WebServerInfo:
        """Metadata biner Apache dan status running."""
        b = self._bin()
        ver = ""
        is_running = False
        if os.path.isfile(b):
            try:
                p = subprocess.run([b, "-v"], capture_output=True, text=True, timeout=5)
                out = p.stdout or p.stderr
                m = re.search(r"Apache/([0-9.]+)", out)
                if m:
                    ver = m.group(1)
            except Exception:
                pass

        # Cek apakah proses aktif
        try:
            p = subprocess.run(
                ["pgrep", "-f", "(httpd|apache2)"], capture_output=True, text=True, timeout=3
            )
            is_running = p.returncode == 0 and bool(p.stdout.strip())
        except Exception:
            pass

        return WebServerInfo(
            name="apache",
            version=ver,
            binary_path=b,
            config_file=self._conf(),
            vhost_dir=self.get_vhost_config_dir(),
            is_running=is_running,
        )

    def test_configuration(self) -> Tuple[bool, str]:
        """Menjalankan pengujian konfigurasi (apache2ctl configtest atau httpd -t)."""
        ctl = shutil.which("apache2ctl") or shutil.which("apachectl")
        cmd = [ctl, "configtest"] if ctl else [self._bin(), "-t"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            msg = (p.stderr or p.stdout or "").strip()
            return p.returncode == 0, msg
        except Exception as e:
            return False, str(e)

    def _get_worker_pids(self) -> set:
        """Mengambil PID worker Apache untuk verifikasi reload."""
        pids = set()
        try:
            p = subprocess.run(
                ["pgrep", "-f", "(httpd|apache2)"], capture_output=True, text=True, timeout=3
            )
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    line = line.strip()
                    if line.isdigit():
                        pids.add(int(line))
        except Exception:
            pass
        return pids

    def reload_service(self) -> bool:
        """Melakukan reload layanan Apache dengan verifikasi aman."""
        ok, msg = self.test_configuration()
        if not ok:
            return False

        b_pids = self._get_worker_pids()

        # Coba systemctl reload apache2 / httpd
        reloaded = False
        for svc in ("apache2", "httpd"):
            try:
                p = subprocess.run(
                    ["systemctl", "reload", svc], capture_output=True, text=True, timeout=10
                )
                if p.returncode == 0:
                    reloaded = True
                    break
            except Exception:
                pass

        if not reloaded:
            for init_script in ("/etc/init.d/apache2", "/etc/init.d/httpd", "/etc/init.d/apache"):
                if os.path.isfile(init_script):
                    try:
                        p = subprocess.run(
                            [init_script, "reload"], capture_output=True, text=True, timeout=10
                        )
                        if p.returncode == 0:
                            reloaded = True
                            break
                    except Exception:
                        pass

        if not reloaded:
            return False

        time.sleep(1.0)
        a_pids = self._get_worker_pids()
        # Jika service berjalan, worker PID harus ada
        return bool(a_pids)

    def get_vhost_config_dir(self) -> str:
        """Menemukan direktori konfigurasi virtual host Apache."""
        if self._custom_vhost and os.path.isdir(self._custom_vhost):
            return self._custom_vhost
        for cand in (
            "/www/server/panel/vhost/apache",
            "/etc/apache2/sites-enabled",
            "/etc/httpd/conf.d",
            "/etc/apache2/conf.d",
        ):
            if os.path.isdir(cand):
                return cand
        return "/etc/apache2/sites-enabled"

    def inject_waf_include(self, vhost_domain: str, snippet_path: str) -> bool:
        """Menyisipkan direktif IncludeOptional WAF ke konfigurasi vhost."""
        vhost_dir = self.get_vhost_config_dir()
        conf_target = None
        for cand_name in (f"{vhost_domain}.conf", f"{vhost_domain}"):
            p = os.path.join(vhost_dir, cand_name)
            if os.path.isfile(p):
                conf_target = p
                break

        if not conf_target:
            return False

        try:
            with open(conf_target, "r") as f:
                content = f.read()

            marker = f"IncludeOptional {snippet_path}"
            if marker in content:
                return True

            # Sisipkan sebelum penutup </VirtualHost>
            pattern = r"(</VirtualHost>)"
            if re.search(pattern, content, re.IGNORECASE):
                replacement = f"    # ZySentinel ModSecurity WAF\n    IncludeOptional {snippet_path}\n\\1"
                new_content = re.sub(pattern, replacement, content, count=1, flags=re.IGNORECASE)
            else:
                new_content = content + f"\nIncludeOptional {snippet_path}\n"

            with open(conf_target + ".tmp", "w") as f:
                f.write(new_content)
            os.replace(conf_target + ".tmp", conf_target)
            return True
        except Exception:
            return False

    def remove_waf_include(self, vhost_domain: str) -> bool:
        """Mencabut direktif IncludeOptional WAF dari konfigurasi vhost."""
        vhost_dir = self.get_vhost_config_dir()
        conf_target = None
        for cand_name in (f"{vhost_domain}.conf", f"{vhost_domain}"):
            p = os.path.join(vhost_dir, cand_name)
            if os.path.isfile(p):
                conf_target = p
                break

        if not conf_target:
            return False

        try:
            with open(conf_target, "r") as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                if "sentinel" in line.lower() and "includeoptional" in line.lower():
                    continue
                new_lines.append(line)

            with open(conf_target + ".tmp", "w") as f:
                f.writelines(new_lines)
            os.replace(conf_target + ".tmp", conf_target)
            return True
        except Exception:
            return False

    def get_access_log_paths(self, vhost_domain: str) -> List[str]:
        """Membaca direktif CustomLog dari konfigurasi vhost Apache."""
        vhost_dir = self.get_vhost_config_dir()
        logs = []
        conf_target = None
        for cand_name in (f"{vhost_domain}.conf", f"{vhost_domain}"):
            p = os.path.join(vhost_dir, cand_name)
            if os.path.isfile(p):
                conf_target = p
                break

        if conf_target:
            try:
                with open(conf_target, "r") as f:
                    for line in f:
                        line = line.strip()
                        m = re.match(r"CustomLog\s+([^\s]+)", line, re.IGNORECASE)
                        if m:
                            path = m.group(1).strip("\"'")
                            if os.path.isfile(path) and path not in logs:
                                logs.append(path)
            except Exception:
                pass

        return logs

    def get_waf_status(self) -> WAFStatus:
        """Memeriksa apakah modul mod_security aktif di Apache."""
        is_modsec = False
        try:
            ctl = shutil.which("apache2ctl") or shutil.which("apachectl")
            cmd = [ctl, "-M"] if ctl else [self._bin(), "-M"]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            out = p.stdout or p.stderr
            if "security2_module" in out or "mod_security" in out:
                is_modsec = True
        except Exception:
            pass

        return WAFStatus(
            engine="modsecurity" if is_modsec else "none",
            is_enabled=is_modsec,
            active_rulesets=["zyrules"] if is_modsec else [],
        )
