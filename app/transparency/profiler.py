"""Application Behavioral Profiler and Trust Scorer."""
import os
from typing import Any, Dict, List, Optional
from app.database.repository import Repository

WELL_KNOWN_TRUSTED_VENDORS = {
    "chrome.exe": 95,
    "code.exe": 92,
    "msedge.exe": 92,
    "explorer.exe": 98,
    "svchost.exe": 90,
    "notepad.exe": 95,
    "teams.exe": 88,
    "discord.exe": 85,
    "slack.exe": 88,
    "spotify.exe": 85,
}

class ApplicationProfiler:
    """Tracks application baseline activity habits and computes a 0-100% Trust Meter."""

    def __init__(self, repository: Repository):
        self.repository = repository

    def calculate_trust_score(self, app_name: str, exe_path: Optional[str], is_signed: int = 0, alert_count: int = 0) -> int:
        name_lower = app_name.lower()

        # Check known trusted software list
        if name_lower in WELL_KNOWN_TRUSTED_VENDORS:
            base_score = WELL_KNOWN_TRUSTED_VENDORS[name_lower]
        else:
            base_score = 65

        # Digital signature bonus
        if is_signed:
            base_score += 15

        # Path heuristics
        if exe_path:
            p_lower = exe_path.lower()
            if "downloads" in p_lower or "\\temp\\" in p_lower:
                base_score -= 30
            elif "program files" in p_lower or "system32" in p_lower:
                base_score += 10

        # Deductions for prior security alerts
        base_score -= (alert_count * 20)

        return max(5, min(100, base_score))

    def profile_process(self, proc_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate or retrieve the application activity profile."""
        name = proc_data.get("name", "unknown")
        exe = proc_data.get("exe") or proc_data.get("exe_path")
        is_signed = proc_data.get("is_signed", 0)

        score = self.calculate_trust_score(name, exe, is_signed)

        # Infer habitual behaviors
        habits = []
        if any(b in name.lower() for b in ["chrome", "edge", "firefox"]):
            habits = ["Frequent Web Communication", "Downloads Folder Access", "Temporary Cache Files"]
        elif "code" in name.lower() or "python" in name.lower():
            habits = ["Terminal Script Spawns", "Project Workspace File Modifications", "Local Sockets"]
        else:
            habits = ["Standard Desktop Execution", "Local User Profile Access"]

        self.repository.upsert_app_profile(
            app_name=name,
            exe_path=exe,
            trust_score=score,
            habitual_ports=[80, 443] if "chrome" in name.lower() else [],
            habitual_dirs=["Downloads"] if "chrome" in name.lower() else [],
            is_trusted=1 if score >= 85 else 0,
        )

        return {
            "name": name,
            "exe_path": exe,
            "trust_score": score,
            "habits": habits,
            "rating": "High Trust" if score >= 80 else ("Moderate" if score >= 50 else "Low / Untrusted"),
        }
