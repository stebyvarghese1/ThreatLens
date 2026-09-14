"""Views package for ThreatLens."""
from .dashboard_view import DashboardView
from .live_activity_view import LiveActivityView
from .processes_view import ProcessesView
from .security_view import SecurityView
from .network_view import NetworkView
from .applications_view import ApplicationsView
from .system_changes_view import SystemChangesView
from .assistant_view import AssistantView
from .reports_view import ReportsView
from .settings_view import SettingsView

__all__ = [
    "DashboardView",
    "LiveActivityView",
    "ProcessesView",
    "SecurityView",
    "NetworkView",
    "ApplicationsView",
    "SystemChangesView",
    "AssistantView",
    "ReportsView",
    "SettingsView",
]
