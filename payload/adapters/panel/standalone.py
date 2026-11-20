# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk lingkungan Standalone (Linux murni tanpa control panel)."""
import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from .base import BasePanelAdapter, PanelInfo, VHostInfo, PHPRuntimeInfo


class StandaloneAdapter(BasePanelAdapter):
    """Implementasi adapter untuk server Linux tanpa control panel."""

    def __init__(self, config_dir: str = "/etc/sentinel"):
        self.config_dir = config_dir
        self.nginx_sites = "/etc/nginx/sites-enabled"
        self.nginx_conf_d = "/etc/nginx/conf.d"
        self.apache_sites = "/etc/apache2/sites-enabled"
        self.httpd_conf_d = "/etc/httpd/conf.d"

    def _get_version(self) -> str:
        """Membaca versi dari info.json."""
        for cand in (
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "info.json"),
            "/www/server/panel/plugin/sentinel/info.json",
        ):
            if os.path.isfile(cand):
                try:
                    with open(cand, "r") as f:
                        return json.load(f).get("versions", "")
                except Exception:
                    pass
        return ""

    def detect(self) -> bool:
        """Standalone bila deteksi lingkungan (adapters/env.py) tidak menemukan panel hosting. Cadangan: platform.json (ditulis
        installer), lalu penanda panel langsung."""
        try:
            from .. import env
            return env.profile()["panel"]["type"] in ("none",)
        except Exception:
            pass
        try:
            with open("/www/server/sentinel/etc/platform.json") as f:
                return json.load(f).get("panel") in ("none", "standalone")
        except (OSError, ValueError, AttributeError):
            pass
        return not (os.path.isdir("/www/server/panel/class") or os.path.isfile("/usr/local/cpanel/version")
                    or os.path.isfile("/usr/local/directadmin/directadmin") or os.path.isdir("/usr/local/CyberCP"))

    def get_panel_info(self) -> PanelInfo:
        """Metadata lingkungan Standalone."""
        return PanelInfo(
            name="standalone",
            version=self._get_version(),
            port=18491,
            bind_ip="127.0.0.1",
            config_dir=self.config_dir,
            is_installed=True,
        )

    # ------------------------------------------------------------------ #
    # penguraian konfigurasi vhost nyata (nginx / Apache)                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _strip_comments(text: str) -> str:
        return "\n".join(re.sub(r"(^|\s)#.*$", "", ln) for ln in text.splitlines())

    @staticmethod
    def _blocks(text: str, opener: re.Pattern) -> List[str]:
        """Isi blok `... { ... }` bersarang yang dibuka pola `opener` (pencocokan kurung kurawal)."""
        out = []
        for m in opener.finditer(text):
            depth, i = 1, m.end()
            while i < len(text) and depth:
                depth += (text[i] == "{") - (text[i] == "}")
                i += 1
            out.append(text[m.end():i - 1])
        return out

    @staticmethod
    def _read(path: str) -> str:
        try:
            with open(path, "r", errors="replace") as f:
                return f.read(2_000_000)
        except OSError:
            return ""

    @staticmethod
    def _files(d: str, ext_only: bool) -> List[str]:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            return []
        out = []
        for n in names:
            if n.startswith(".") or n.endswith((".bak", ".dpkg-old", ".dpkg-dist", "~")):
                continue
            if ext_only and not n.endswith(".conf"):
                continue
            p = os.path.join(d, n)
            if os.path.isfile(p):
                out.append(p)
        return out

    @staticmethod
    def _php_from(text: str) -> str:
        m = re.search(r"php-?(\d\.\d)", text)
        return m.group(1) if m else ""

    def _nginx_vhosts(self) -> List[VHostInfo]:
        res = []
        opener = re.compile(r"\bserver\s*\{")
        for d in (self.nginx_sites, self.nginx_conf_d):
            for path in self._files(d, ext_only=(d == self.nginx_conf_d)):
                text = self._strip_comments(self._read(path))
                for blk in self._blocks(text, opener):
                    names = []
                    for m in re.finditer(r"\bserver_name\s+([^;]+);", blk):
                        names += [n for n in m.group(1).split() if n not in ("_", "localhost") and not n.startswith("~") and "*" not in n]
                    if not names:
                        continue
                    root = re.search(r"(?:^|[;{])\s*root\s+([^;]+);", blk, re.M)
                    docroot = root.group(1).strip().strip("\"'") if root else ""
                    cert = re.search(r"\bssl_certificate\s+([^;]+);", blk)
                    key = re.search(r"\bssl_certificate_key\s+([^;]+);", blk)
                    ssl_on = bool(re.search(r"\blisten\s+[^;]*\bssl\b", blk)) or bool(cert)
                    res.append(VHostInfo(domain=names[0], docroot=docroot, webserver="nginx", php_version=self._php_from(blk),
                                         ssl_enabled=ssl_on, ssl_cert_path=cert.group(1).strip() if cert else "",
                                         ssl_key_path=key.group(1).strip() if key else "", extra={"aliases": names[1:], "config": path}))
        return res

    def _apache_vhosts(self) -> List[VHostInfo]:
        res = []
        for d in (self.apache_sites, self.httpd_conf_d):
            for path in self._files(d, ext_only=True):
                text = self._strip_comments(self._read(path))
                for m in re.finditer(r"<VirtualHost\b[^>]*>(.*?)</VirtualHost>", text, re.S | re.I):
                    blk = m.group(1)
                    sn = re.search(r"^\s*ServerName\s+(\S+)", blk, re.M | re.I)
                    if not sn or sn.group(1).lower() in ("localhost", "_default_"):
                        continue
                    dr = re.search(r"^\s*DocumentRoot\s+(\S+)", blk, re.M | re.I)
                    cert = re.search(r"^\s*SSLCertificateFile\s+(\S+)", blk, re.M | re.I)
                    key = re.search(r"^\s*SSLCertificateKeyFile\s+(\S+)", blk, re.M | re.I)
                    ssl_on = bool(re.search(r"^\s*SSLEngine\s+on", blk, re.M | re.I))
                    res.append(VHostInfo(domain=sn.group(1), docroot=dr.group(1).strip("\"'") if dr else "", webserver="apache",
                                         php_version=self._php_from(blk), ssl_enabled=ssl_on, ssl_cert_path=cert.group(1) if cert else "",
                                         ssl_key_path=key.group(1) if key else "", extra={"config": path}))
        return res

    def get_vhosts(self) -> List[VHostInfo]:
        """Virtual host dari konfigurasi web server yang benar-benar ada: docroot dibaca dari `root`/`DocumentRoot`
        (bukan ditebak), SSL dideteksi, duplikat dibuang (satu domain yang sama di nginx dan Apache tetap dua entri)."""
        seen, hasil = set(), []
        extra = []
        try:
            from .. import env
            for e in env.sites():
                extra.append(VHostInfo(domain=e["domain"], docroot=e["docroot"], webserver=e["webserver"] or "nginx", php_version=e.get("php", ""),
                                       ssl_enabled=e.get("ssl", False), extra={"aliases": e.get("aliases", []), "config": e.get("config", "")}))
        except Exception:
            pass
        for v in self._nginx_vhosts() + self._apache_vhosts() + extra:
            k = (v.domain.lower(), v.webserver)
            if k in seen:
                continue
            seen.add(k)
            hasil.append(v)
        return hasil

    def get_php_runtimes(self) -> List[PHPRuntimeInfo]:
        """Menemukan biner PHP sistem dan FPM."""
        runtimes = []
        php_bin = shutil.which("php")
        if php_bin:
            try:
                out = subprocess.check_output([php_bin, "-r", "echo PHP_VERSION;"], timeout=3).decode().strip()
                ver_short = ".".join(out.split(".")[:2]) if "." in out else out
                runtimes.append(
                    PHPRuntimeInfo(
                        version=ver_short,
                        binary_path=php_bin,
                        fpm_service=f"php{ver_short}-fpm",
                        is_default=True,
                    )
                )
            except Exception:
                pass
        return runtimes

    def get_auth_log_path(self) -> str:
        """Jalur log otentikasi Linux (/var/log/auth.log atau /var/log/secure)."""
        if os.path.isfile("/var/log/auth.log"):
            return "/var/log/auth.log"
        if os.path.isfile("/var/log/secure"):
            return "/var/log/secure"
        return "/var/log/messages"

    def render_error(self, message: str) -> Dict[str, Any]:
        """Format respons galat standar REST API."""
        return {"ok": False, "error": str(message)}

    def render_success(self, data: Any = None, message: str = "") -> Dict[str, Any]:
        """Format respons sukses standar REST API."""
        res: Dict[str, Any] = {"ok": True}
        if message:
            res["message"] = message
        if data is not None:
            res["data"] = data
        return res
