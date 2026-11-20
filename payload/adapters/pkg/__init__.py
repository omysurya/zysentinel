# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Package manager adapters package."""
from .base import BasePkgAdapter, PackageInfo
from .apt import AptAdapter
from .dnf import DnfAdapter
from .apk import ApkAdapter

__all__ = ["BasePkgAdapter", "PackageInfo", "AptAdapter", "DnfAdapter", "ApkAdapter"]
