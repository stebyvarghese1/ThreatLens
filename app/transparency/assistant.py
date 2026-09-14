"""'Ask ThreatLens' Offline Natural-Language Security Assistant."""
from datetime import datetime
from typing import Any, Dict, List
from app.database.repository import Repository

class AskThreatLensAssistant:
    """Answers user questions in plain English from locally collected security data."""

    def __init__(self, repository: Repository):
        self.repository = repository

    def ask(self, query: str) -> str:
        """Process user question and return an evidence-grounded response."""
        q = query.strip().lower()

        # 1. Intent: "What happened today?" / "Recent activity"
        if any(w in q for w in ["what happened", "today", "summary", "activity", "overview"]):
            stats = self.repository.get_event_stats()
            total = stats.get("Total", 0)
            high = stats.get("High", 0)
            crit = stats.get("Critical", 0)
            alerts = self.repository.get_unresolved_alerts()

            response = f"**ThreatLens Endpoint Summary:**\n\n"
            response += f"- **Total Events Monitored:** {total}\n"
            response += f"- **Active Threat Alerts:** {len(alerts)}\n"
            response += f"- **High/Critical Events:** {high + crit}\n\n"

            if alerts:
                response += "⚠️ **Attention Required:**\n"
                for a in alerts[:3]:
                    response += f"- *{a['title']}*: {a['description']}\n"
            else:
                response += "✓ No critical threats are active. Your system is operating smoothly."
            return response

        # 2. Intent: "What applications connected to the internet?"
        if any(w in q for w in ["internet", "network", "connected", "outbound", "wifi"]):
            net_events = self.repository.get_recent_network_events(limit=25)
            if not net_events:
                return "ThreatLens has not recorded any external network connections during this session."

            apps = {}
            for e in net_events:
                app = e.get("process_name") or "Unknown"
                remote = f"{e.get('remote_address')}:{e.get('remote_port')}"
                apps.setdefault(app, []).append(remote)

            response = "**Applications with recent network connections:**\n\n"
            for app, remotes in list(apps.items())[:6]:
                sample = ", ".join(remotes[:2])
                response += f"- **{app}**: connected to {len(remotes)} endpoints (e.g. `{sample}`)\n"
            return response

        # 3. Intent: "Why did you flag / why is this suspicious?"
        if any(w in q for w in ["why did you flag", "why is this suspicious", "flagged", "alert reason"]):
            alerts = self.repository.get_unresolved_alerts()
            if not alerts:
                return "There are currently no active flagged alerts or suspicious processes in ThreatLens."

            top = alerts[0]
            return (
                f"**Why was '{top['title']}' flagged?**\n\n"
                f"{top['description']}\n\n"
                f"- **Risk Level:** {top['risk_level']}\n"
                f"- **Detection Source:** {top['source']}\n"
                f"- **Recommendation:** {top.get('recommendation', 'Review technical details in Security Center.')}"
            )

        # 4. Intent: "What changed on my computer?" / "System changes"
        if any(w in q for w in ["what changed", "changes", "startup", "installed", "registry"]):
            changes = self.repository.get_recent_system_changes(limit=5)
            if not changes:
                return "No persistence or major system configuration changes have been recorded recently."

            response = "**Recent System & Persistence Changes:**\n\n"
            for c in changes:
                response += f"- **[{c['category']}]** {c['description']} (Target: `{c.get('target', 'N/A')}`)\n"
            return response

        # 5. Intent: "Why is my laptop slow?"
        if any(w in q for w in ["slow", "lag", "cpu", "memory", "performance", "freeze"]):
            procs = self.repository.get_active_processes()
            suspicious = [p for p in procs if p.get("risk_score", 0) >= 40]
            if suspicious:
                names = ", ".join([p["name"] for p in suspicious[:3]])
                return f"Your system may be experiencing load from elevated risk processes: **{names}**. Review them in the Processes tab."
            return f"ThreatLens is monitoring {len(procs)} active processes. None currently exhibit malicious resource strain or anomaly chains."

        # 6. Fallback: Search Database
        matches = self.repository.search_telemetry(query, limit=5)
        if matches:
            response = f"Found {len(matches)} recorded events related to '{query}':\n\n"
            for m in matches:
                time_str = str(m.get("timestamp", ""))[-8:]
                response += f"- `[{time_str}]` **{m.get('application')}**: {m.get('explanation')}\n"
            return response

        return (
            f"I couldn't find any specific telemetry matching '{query}'. "
            "You can ask me questions like:\n"
            "- *'What happened on my computer today?'*\n"
            "- *'What applications connected to the internet?'*\n"
            "- *'What changed on my computer?'*\n"
            "- *'Why is my laptop slow?'*"
        )
