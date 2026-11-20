# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Kontrak dasar dan struktur data untuk adapter web server."""
from typing import Any, Dict, List, Optional, Tuple


class WebServerInfo:
    """Informasi metadata web server host."""

    def __init__(
        self,
        name: str,
        version: str = "",
        binary_path: str = "",
        config_file: str = "",
        vhost_dir: str = "",
        is_running: bool = False,
    ):
        self.name = name
        self.version = version
        self.binary_path = binary_path
        self.config_file = config_file
        self.vhost_dir = vhost_dir
        self.is_running = is_running

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "binary_path": self.binary_path,
            "config_file": self.config_file,
            "vhost_dir": self.vhost_dir,
            "is_running": self.is_running,
        }


class WAFStatus:
    """Status konfigurasi WAF pada web server."""

    def __init__(
        self,
        engine: str = "none",
        is_enabled: bool = False,
        active_rulesets: Optional[List[str]] = None,
        vhosts_protected: Optional[List[str]] = None,
    ):
        self.engine = engine
        self.is_enabled = is_enabled
        self.active_rulesets = active_rulesets or []
        self.vhosts_protected = vhosts_protected or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine,
            "is_enabled": self.is_enabled,
            "active_rulesets": self.active_rulesets,
            "vhosts_protected": self.vhosts_protected,
        }


class BaseWebServerAdapter:
    """Kelas dasar abstrak untuk adapter web server."""

    def detect(self) -> bool:
        """Mengembalikan True jika web server ini terpasang dan aktif."""
        raise NotImplementedError

    def get_info(self) -> WebServerInfo:
        """Mengembalikan objek WebServerInfo berisi metadata web server."""
        raise NotImplementedError

    def test_configuration(self) -> Tuple[bool, str]:
        """Menjalankan pengujian sintaks konfigurasi web server."""
        raise NotImplementedError

    def reload_service(self) -> bool:
        """Melakukan reload layanan web server dengan verifikasi pergantian proses worker."""
        raise NotImplementedError

    def get_vhost_config_dir(self) -> str:
        """Mengembalikan jalur direktori tempat berkas virtual host disimpan."""
        raise NotImplementedError

    def inject_waf_include(self, vhost_domain: str, snippet_path: str) -> bool:
        """Menyisipkan direktif WAF include ke dalam konfigurasi vhost."""
        raise NotImplementedError

    def remove_waf_include(self, vhost_domain: str) -> bool:
        """Mencabut direktif WAF include dari konfigurasi vhost."""
        raise NotImplementedError

    def get_access_log_paths(self, vhost_domain: str) -> List[str]:
        """Mengembalikan daftar jalur berkas log akses untuk vhost domain bersangkutan."""
        raise NotImplementedError

    def get_waf_status(self) -> WAFStatus:
        """Mengembalikan objek WAFStatus mengenai engine WAF aktif."""
        raise NotImplementedError
