# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""Web server adapters package."""
from .base import BaseWebServerAdapter, WebServerInfo, WAFStatus
from .nginx import NginxAdapter
from .apache import ApacheAdapter
from .caddy import CaddyAdapter
from .openlitespeed import OpenLiteSpeedAdapter

__all__ = [
    "BaseWebServerAdapter",
    "WebServerInfo",
    "WAFStatus",
    "NginxAdapter",
    "ApacheAdapter",
    "CaddyAdapter",
    "OpenLiteSpeedAdapter",
]
