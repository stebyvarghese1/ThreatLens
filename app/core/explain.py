"""Explainability Engine for ThreatLens.

Converts technical system activity (PIDs, handles, syscalls) into clear,
human-readable narratives and contextual 'Why?' breakdowns.
"""
from typing import Any, Dict, Optional

class ExplainEngine:
    """Translates technical system events into clear human-understandable insights."""

    @staticmethod
    def generate_simple_summary(
        event_type: str,
        app_name: Optional[str],
        action: str,
        target: Optional[str],
    ) -> str:
        """Create a clean 1-sentence description for casual users."""
        app = app_name or "An application"
        target_display = target if target else ""

        if event_type == "PROCESS_STARTED":
            if "powershell" in app.lower() or "cmd" in app.lower():
                return f"{app} executed a command-line script."
            return f"{app} started running."

        elif event_type == "PROCESS_STOPPED":
            return f"{app} closed or was terminated."

        elif event_type == "FILE_CREATED":
            return f"{app} created file: {target_display}"

        elif event_type == "FILE_MODIFIED":
            return f"{app} modified file: {target_display}"

        elif event_type == "FILE_DELETED":
            return f"{app} deleted file: {target_display}"

        elif event_type == "STARTUP_CREATED":
            return f"{app} added itself to Windows Startup to run automatically on boot."

        elif event_type == "NETWORK_CONNECTED":
            return f"{app} connected to network host: {target_display}"

        elif event_type == "RANSOMWARE_SUSPECTED":
            return f"🚨 Rapid mass file modifications detected from {app}!"

        return f"{app} performed {action} on {target_display}".strip()

    @classmethod
    def generate_why_breakdown(cls, event: Dict[str, Any]) -> Dict[str, str]:
        """Generate structured answers for: What?, Who?, Where?, Why?, and Recommended Action."""
        event_type = event.get("event_type", "UNKNOWN")
        app = event.get("application") or event.get("process_name") or "Unknown Application"
        target = event.get("target") or "System resource"
        risk_score = event.get("risk_score", 0)

        what = cls.generate_simple_summary(event_type, app, event.get("action", ""), target)
        who = f"{app} (PID: {event.get('process_id', 'N/A')})"
        where = target

        # Contextual 'Why' reasoning
        if event_type == "STARTUP_CREATED":
            why = (
                "Startup entries allow programs to automatically launch whenever Windows boots up. "
                "While legitimate software uses this for background services, malware frequently uses "
                "this mechanism (Persistence) to ensure it stays active after reboots."
            )
            rec = "Verify whether you want this program running continuously at Windows startup."

        elif "powershell" in app.lower() or (event.get("process_name") and "powershell" in event["process_name"].lower()):
            why = (
                "PowerShell is a powerful Windows administrative tool capable of downloading scripts, "
                "modifying system settings, and executing code in memory. Attackers often leverage it "
                "for Living-off-the-Land (LotL) execution."
            )
            rec = "If you did not initiate a terminal script or software installation, investigate the parent process."

        elif event_type == "RANSOMWARE_SUSPECTED":
            why = (
                "An unusually high frequency of file writes or renames was observed in a short time window. "
                "This pattern is characteristic of ransomware encrypting documents or bulk asset modification."
            )
            rec = "Stop or isolate the application immediately and verify recent file integrity."

        elif "Downloads" in target:
            why = (
                "The Downloads directory frequently contains untrusted files retrieved from the web or email attachments. "
                "Executables running directly from Downloads represent an elevated threat risk."
            )
            rec = "Ensure this downloaded file originates from a trusted, verified publisher before allowing execution."

        else:
            if risk_score > 50:
                why = (
                    "This behavior matches indicators associated with suspicious system manipulation or anomalous "
                    "application execution patterns."
                )
                rec = "Review the technical details below and consider isolating or quarantining the file if unrecognized."
            else:
                why = "This is standard, expected behavior for active desktop and background applications."
                rec = "No action required. ThreatLens is monitoring normally."

        return {
            "what": what,
            "who": who,
            "where": where,
            "why": why,
            "recommendation": rec,
            "risk_assessment": f"Risk Score: {risk_score}/100 ({event.get('severity', 'Low')})",
        }
