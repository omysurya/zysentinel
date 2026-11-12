# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Adapter manajer paket DNF/YUM (RHEL, AlmaLinux, Rocky Linux, CentOS)."""
import shutil
import subprocess
from typing import Dict, List, Optional

from .base import BasePkgAdapter, PackageInfo


class DnfAdapter(BasePkgAdapter):
    """Implementasi adapter manajer paket untuk DNF/YUM/rpm."""

    def detect(self) -> bool:
        """Mengembalikan True jika rpm dan (dnf atau yum) tersedia."""
        return bool(shutil.which("rpm") and (shutil.which("dnf") or shutil.which("yum")))

    def get_manager_name(self) -> str:
        return "dnf" if shutil.which("dnf") else "yum"

    def list_installed_packages(self) -> Dict[str, str]:
        """Membaca daftar paket terpasang via rpm query."""
        pkgs = {}
        if not shutil.which("rpm"):
            return pkgs
        try:
            p = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in p.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    pkgs[parts[0]] = parts[1]
        except Exception:
            pass
        return pkgs

    def get_package_version(self, pkg_name: str) -> Optional[str]:
        """Membaca versi paket tertentu via rpm -q."""
        if not shutil.which("rpm"):
            return None
        try:
            p = subprocess.run(
                ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", pkg_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if p.returncode == 0 and not p.stdout.startswith("package "):
                return p.stdout.strip()
        except Exception:
            pass
        return None

    def check_security_updates(self) -> List[str]:
        """Memeriksa pembaruan keamanan via dnf updateinfo."""
        updates = []
        mgr = self.get_manager_name()
        if not shutil.which(mgr):
            return updates
        try:
            p = subprocess.run(
                [mgr, "updateinfo", "list", "security"],
                capture_output=True,
                text=True,
                timeout=25,
            )
            for line in p.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    # format: RHSA-xxxx or ALSA-xxxx Sec. pkg-ver.arch
                    updates.append(parts[2])
        except Exception:
            pass
        return updates
