# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter untuk manajer paket apk (Alpine Linux)."""
import shutil
import subprocess
from typing import Dict, List, Optional

from .base import BasePkgAdapter, PackageInfo


class ApkAdapter(BasePkgAdapter):
    """Implementasi adapter untuk apk (Alpine Linux)."""

    def detect(self) -> bool:
        """Mengembalikan True jika biner apk tersedia."""
        return shutil.which("apk") is not None

    def get_manager_name(self) -> str:
        return "apk"

    def list_installed_packages(self) -> List[PackageInfo]:
        """Membaca daftar paket terpasang via apk info -v."""
        packages = []
        if not self.detect():
            return packages
        try:
            p = subprocess.run(["apk", "info", "-v"], capture_output=True, text=True, timeout=10)
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    line = line.strip()
                    if line and "-" in line:
                        # Format: pkgname-1.2.3-r0
                        parts = line.rsplit("-", 2)
                        if len(parts) == 3:
                            pkg_name = parts[0]
                            pkg_ver = f"{parts[1]}-{parts[2]}"
                            packages.append(PackageInfo(name=pkg_name, version=pkg_ver, arch=""))
        except Exception:
            pass
        return packages

    def get_package_version(self, package_name: str) -> Optional[str]:
        """Membaca versi spesifik paket via apk info -e <package_name>."""
        if not self.detect():
            return None
        try:
            p = subprocess.run(["apk", "info", "-v", package_name], capture_output=True, text=True, timeout=5)
            if p.returncode == 0 and p.stdout.strip():
                line = p.stdout.strip().splitlines()[0]
                parts = line.rsplit("-", 2)
                if len(parts) == 3:
                    return f"{parts[1]}-{parts[2]}"
        except Exception:
            pass
        return None

    def check_security_updates(self) -> List[Dict[str, str]]:
        """Memeriksa paket yang dapat di-upgrade via apk version."""
        updates = []
        if not self.detect():
            return updates
        try:
            p = subprocess.run(["apk", "version", "-l", "<"], capture_output=True, text=True, timeout=15)
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("Installed"):
                        updates.append({"package": line, "type": "upgrade"})
        except Exception:
            pass
        return updates
