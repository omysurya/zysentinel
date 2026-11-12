# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter manajer paket APT (Debian, Ubuntu)."""
import shutil
import subprocess
from typing import Dict, List, Optional

from .base import BasePkgAdapter, PackageInfo


class AptAdapter(BasePkgAdapter):
    """Implementasi adapter manajer paket untuk APT/dpkg."""

    def detect(self) -> bool:
        """Mengembalikan True jika dpkg dan apt-get tersedia."""
        return bool(shutil.which("dpkg") and shutil.which("apt-get"))

    def get_manager_name(self) -> str:
        return "apt"

    def list_installed_packages(self) -> Dict[str, str]:
        """Membaca daftar paket terpasang via dpkg-query."""
        pkgs = {}
        if not shutil.which("dpkg-query"):
            return pkgs
        try:
            p = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package} ${Version} ${Architecture} ${db:Status-Status}\n"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in p.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[3] == "installed":
                    pkgs[parts[0]] = parts[1]
                elif len(parts) >= 2:
                    pkgs[parts[0]] = parts[1]
        except Exception:
            pass
        return pkgs

    def get_package_version(self, pkg_name: str) -> Optional[str]:
        """Membaca versi paket tertentu via dpkg-query."""
        if not shutil.which("dpkg-query"):
            return None
        try:
            p = subprocess.run(
                ["dpkg-query", "-W", "-f=${Version}\n", pkg_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if p.returncode == 0:
                return p.stdout.strip()
        except Exception:
            pass
        return None

    def check_security_updates(self) -> List[str]:
        """Memeriksa paket dengan security updates via apt-get -s upgrade."""
        updates = []
        if not shutil.which("apt-get"):
            return updates
        try:
            p = subprocess.run(
                ["apt-get", "-s", "upgrade"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            for line in p.stdout.splitlines():
                if line.startswith("Inst ") and "security" in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        updates.append(parts[1])
        except Exception:
            pass
        return updates
