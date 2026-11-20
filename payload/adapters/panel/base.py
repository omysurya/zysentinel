# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Kontrak dasar dan struktur data untuk adapter control panel."""
import os
from typing import Any, Dict, List, Optional


class PanelInfo:
    """Informasi metadata control panel host."""

    def __init__(
        self,
        name: str,
        version: str = "",
        port: int = 0,
        bind_ip: str = "0.0.0.0",
        config_dir: str = "",
        is_installed: bool = False,
    ):
        self.name = name
        self.version = version
        self.port = int(port)
        self.bind_ip = bind_ip
        self.config_dir = config_dir
        self.is_installed = is_installed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "port": self.port,
            "bind_ip": self.bind_ip,
            "config_dir": self.config_dir,
            "is_installed": self.is_installed,
        }


class VHostInfo:
    """Informasi virtual host situs web pada panel."""

    def __init__(
        self,
        domain: str,
        docroot: str,
        webserver: str = "nginx",
        php_version: str = "",
        ssl_enabled: bool = False,
        ssl_cert_path: str = "",
        ssl_key_path: str = "",
        is_active: bool = True,
        extra: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ):
        self.domain = domain
        self.docroot = docroot
        self.webserver = webserver
        self.php_version = php_version
        self.ssl_enabled = bool(ssl_enabled)
        self.ssl_cert_path = ssl_cert_path
        self.ssl_key_path = ssl_key_path
        self.is_active = bool(is_active)
        self.extra = extra or {}
        if kwargs:
            self.extra.update(kwargs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "docroot": self.docroot,
            "webserver": self.webserver,
            "php_version": self.php_version,
            "ssl_enabled": self.ssl_enabled,
            "ssl_cert_path": self.ssl_cert_path,
            "ssl_key_path": self.ssl_key_path,
            "is_active": self.is_active,
            "extra": self.extra,
        }


class PHPRuntimeInfo:
    """Informasi runtime PHP yang terpasang di sistem."""

    def __init__(
        self,
        version: str,
        binary_path: str,
        fpm_service: str = "",
        ini_path: str = "",
        is_default: bool = False,
    ):
        self.version = version
        self.binary_path = binary_path
        self.fpm_service = fpm_service
        self.ini_path = ini_path
        self.is_default = is_default

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "binary_path": self.binary_path,
            "fpm_service": self.fpm_service,
            "ini_path": self.ini_path,
            "is_default": self.is_default,
        }


class BasePanelAdapter:
    """Kelas dasar abstrak untuk adapter panel hosting."""

    def detect(self) -> bool:
        """Mengembalikan True jika panel ini terpasang di host."""
        raise NotImplementedError

    def get_panel_info(self) -> PanelInfo:
        """Mengembalikan objek PanelInfo berisi metadata panel."""
        raise NotImplementedError

    def get_vhosts(self) -> List[VHostInfo]:
        """Mengembalikan daftar VHostInfo untuk seluruh virtual host yang terdaftar."""
        raise NotImplementedError

    def get_php_runtimes(self) -> List[PHPRuntimeInfo]:
        """Mengembalikan daftar PHPRuntimeInfo yang terpasang di sistem."""
        raise NotImplementedError

    def get_auth_log_path(self) -> str:
        """Mengembalikan jalur berkas log autentikasi admin panel."""
        raise NotImplementedError

    def render_error(self, message: str) -> Dict[str, Any]:
        """Mengembalikan payload format respons galat sesuai konvensi panel."""
        raise NotImplementedError

    def render_success(self, data: Any = None, message: str = "") -> Dict[str, Any]:
        """Mengembalikan payload format respons sukses sesuai konvensi panel."""
        raise NotImplementedError
