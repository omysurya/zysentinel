# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk aaPanel (BAOTA Panel)."""
import os
import re
import sqlite3
from typing import Any, Dict, List, Optional

from .base import BasePanelAdapter, PanelInfo, VHostInfo, PHPRuntimeInfo


class AAPanelAdapter(BasePanelAdapter):
    """Implementasi adapter khusus lingkungan aaPanel."""

    def __init__(self, panel_root: str = "/www/server/panel"):
        self.panel_root = panel_root.rstrip("/")
        self.data_dir = os.path.join(self.panel_root, "data")
        self.vhost_nginx = os.path.join(self.panel_root, "vhost", "nginx")
        self.vhost_apache = os.path.join(self.panel_root, "vhost", "apache")
        self.vhost_ols = os.path.join(self.panel_root, "vhost", "openlitespeed")
        self.php_base = "/www/server/php"

    def detect(self) -> bool:
        """Mengembalikan True bila lingkungan aaPanel terpasang."""
        return (
            os.path.isdir(os.path.join(self.panel_root, "class"))
            or os.path.isfile(os.path.join(self.data_dir, "port.pl"))
        )

    def get_panel_info(self) -> PanelInfo:
        """Membaca port, versi, dan konfigurasi aaPanel."""
        port = 7800
        port_file = os.path.join(self.data_dir, "port.pl")
        if os.path.isfile(port_file):
            try:
                with open(port_file, "r") as f:
                    raw = f.read().strip()
                    if raw.isdigit():
                        port = int(raw)
            except OSError:
                pass

        version = ""
        ver_file = os.path.join(self.panel_root, "class", "common.py")
        if os.path.isfile(ver_file):
            try:
                with open(ver_file, "r", errors="ignore") as f:
                    for line in f:
                        if "version" in line and "=" in line:
                            m = re.search(r"['\"]([0-9.]+)['\"]", line)
                            if m:
                                version = m.group(1)
                                break
            except OSError:
                pass

        return PanelInfo(
            name="aapanel",
            version=version,
            port=port,
            bind_ip="0.0.0.0",
            config_dir=self.data_dir,
            is_installed=self.detect(),
        )

    def get_vhosts(self) -> List[VHostInfo]:
        """Membaca daftar virtual host dari basis data default.db atau berkas vhost."""
        vhosts = []
        db_path = os.path.join(self.data_dir, "default.db")
        if os.path.isfile(db_path):
            try:
                con = sqlite3.connect(db_path, timeout=5)
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                for row in cur.execute("SELECT name, path, status, ps FROM sites"):
                    domain = row["name"]
                    path = row["path"]
                    # Deteksi sertifikat SSL aaPanel
                    ssl_cert = os.path.join(self.panel_root, "vhost", "cert", domain, "fullchain.pem")
                    ssl_key = os.path.join(self.panel_root, "vhost", "cert", domain, "privkey.pem")
                    ssl_ok = os.path.isfile(ssl_cert) and os.path.isfile(ssl_key)

                    vhosts.append(
                        VHostInfo(
                            domain=domain,
                            docroot=path,
                            webserver="nginx" if os.path.isdir(self.vhost_nginx) else "apache",
                            ssl_enabled=ssl_ok,
                            ssl_cert_path=ssl_cert if ssl_ok else "",
                            ssl_key_path=ssl_key if ssl_ok else "",
                            extra={"status": row["status"], "ps": row["ps"]},
                        )
                    )
                con.close()
                return vhosts
            except Exception:
                pass

        # Fallback pembacaan berkas konfigurasi .conf
        if os.path.isdir(self.vhost_nginx):
            try:
                for fname in sorted(os.listdir(self.vhost_nginx)):
                    if fname.endswith(".conf") and fname != "0.default.conf":
                        domain = fname[:-5]
                        vhosts.append(
                            VHostInfo(
                                domain=domain,
                                docroot=f"/www/wwwroot/{domain}",
                                webserver="nginx",
                            )
                        )
            except OSError:
                pass

        return vhosts

    def get_php_runtimes(self) -> List[PHPRuntimeInfo]:
        """Memindai seluruh versi PHP aaPanel di /www/server/php."""
        runtimes = []
        if os.path.isdir(self.php_base):
            try:
                for entry in sorted(os.listdir(self.php_base)):
                    if entry.isdigit() and len(entry) == 2:
                        # mis. 81 -> 8.1
                        ver_str = f"{entry[0]}.{entry[1]}"
                        bin_path = os.path.join(self.php_base, entry, "bin", "php")
                        ini_path = os.path.join(self.php_base, entry, "etc", "php.ini")
                        fpm_sock = f"/tmp/php-cgi-{entry}.sock"
                        if os.path.isfile(bin_path):
                            runtimes.append(
                                PHPRuntimeInfo(
                                    version=ver_str,
                                    binary_path=bin_path,
                                    fpm_service=f"php-fpm-{entry}",
                                    ini_path=ini_path if os.path.isfile(ini_path) else "",
                                    is_default=False,
                                )
                            )
            except OSError:
                pass
        return runtimes

    def get_auth_log_path(self) -> str:
        """Jalur berkas log login aaPanel."""
        log_path = os.path.join(self.panel_root, "logs", "login.log")
        if os.path.isfile(log_path):
            return log_path
        return os.path.join(self.panel_root, "logs", "request.log")

    def render_error(self, message: str) -> Dict[str, Any]:
        """Format respons galat khas aaPanel (public.returnMsg(False, msg))."""
        return {"status": False, "msg": str(message)}

    def render_success(self, data: Any = None, message: str = "") -> Dict[str, Any]:
        """Format respons sukses khas aaPanel (public.returnMsg(True, ...))."""
        if isinstance(data, dict) and not message:
            return {"status": True, **data}
        res: Dict[str, Any] = {"status": True, "msg": message}
        if data is not None:
            res["data"] = data
        return res
