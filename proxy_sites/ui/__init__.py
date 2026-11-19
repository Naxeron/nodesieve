"""UI package exports."""

from proxy_sites.ui.cli import main, manage_subscriptions, settings_menu
from proxy_sites.ui.dashboard import VPNDashboard

__all__ = [
    "VPNDashboard",
    "main",
    "manage_subscriptions",
    "settings_menu",
]
