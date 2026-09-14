"""Daily and Weekly Security Report Generator."""
from datetime import datetime
from typing import Any, Dict
from app.database.repository import Repository

class ReportGenerator:
    """Generates structured, exportable security reports."""

    def __init__(self, repository: Repository):
        self.repository = repository

    def generate_daily_report(self) -> str:
        """Generate formatted daily markdown security report."""
        stats = self.repository.get_event_stats()
        alerts = self.repository.get_unresolved_alerts()
        changes = self.repository.get_recent_system_changes(limit=10)
        net_events = self.repository.get_recent_network_events(limit=50)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = f"""# 🛡️ ThreatLens Daily Security Report
**Generated at:** {now_str}  
**Status:** {"⚠️ Attention Required" if alerts else "✓ Clean / Protected"}

---

## 1. Key Metrics
- **Active Threats:** {len(alerts)}
- **Total System Events Analyzed:** {stats.get('Total', 0)}
- **High/Critical Severity Events:** {stats.get('High', 0) + stats.get('Critical', 0)}
- **Outbound Network Connections:** {len(net_events)}
- **System / Startup Modifications:** {len(changes)}

---

## 2. Active Alerts & Incidents
"""
        if alerts:
            for a in alerts:
                report += f"- **[{a['risk_level']}] {a['title']}**: {a['description']}\n"
                if a.get("recommendation"):
                    report += f"  - *Recommended Action:* {a['recommendation']}\n"
        else:
            report += "No active alerts or critical anomalies recorded.\n"

        report += "\n---\n\n## 3. Significant System & Startup Changes\n"
        if changes:
            for c in changes:
                report += f"- `[{c['category']}]` {c['description']} (Target: {c.get('target', 'N/A')})\n"
        else:
            report += "No unauthorized startup entries or system configuration changes detected.\n"

        report += "\n---\n*Report generated locally by ThreatLens. Your data never leaves this computer.*"
        return report
