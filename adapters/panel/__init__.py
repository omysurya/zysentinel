# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Panel adapters package."""
from .base import BasePanelAdapter, PanelInfo, VHostInfo, PHPRuntimeInfo
from .aapanel import AAPanelAdapter
from .standalone import StandaloneAdapter
from .cpanel import CPanelAdapter
from .directadmin import DirectAdminAdapter
from .cyberpanel import CyberPanelAdapter

__all__ = [
    "BasePanelAdapter",
    "PanelInfo",
    "VHostInfo",
    "PHPRuntimeInfo",
    "AAPanelAdapter",
    "StandaloneAdapter",
    "CPanelAdapter",
    "DirectAdminAdapter",
    "CyberPanelAdapter",
]
