# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Kontrak dasar dan struktur data untuk adapter manajer paket OS."""
from typing import Any, Dict, List, Optional


class PackageInfo:
    """Informasi paket perangkat lunak sistem operasi."""

    def __init__(
        self,
        name: str,
        version: str,
        architecture: str = "amd64",
        status: str = "installed",
    ):
        self.name = name
        self.version = version
        self.architecture = architecture
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "architecture": self.architecture,
            "status": self.status,
        }


class BasePkgAdapter:
    """Kelas dasar abstrak untuk adapter manajer paket host (APT, DNF, APK)."""

    def detect(self) -> bool:
        """Mengembalikan True jika manajer paket ini aktif pada sistem operasi host."""
        raise NotImplementedError

    def get_manager_name(self) -> str:
        """Mengembalikan nama manajer paket (mis. apt, dnf, apk)."""
        raise NotImplementedError

    def list_installed_packages(self) -> Dict[str, str]:
        """Mengembalikan kamus pemetaan nama_paket -> versi_paket untuk seluruh paket terpasang."""
        raise NotImplementedError

    def get_package_version(self, pkg_name: str) -> Optional[str]:
        """Mengembalikan string versi paket tertentu atau None jika tidak terpasang."""
        raise NotImplementedError

    def check_security_updates(self) -> List[str]:
        """Mengembalikan daftar nama paket yang memiliki pembaruan keamanan tertunda."""
        raise NotImplementedError
