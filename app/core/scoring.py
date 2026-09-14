"""Security Score Calculator for ThreatLens.

Evaluates active endpoint signals, unresolved alerts, running process reputations,
and system changes to compute a transparent, explainable 0–100 health score.
"""
from typing import Any, Dict, List

class SecurityScoreCalculator:
    """Calculates dynamic security score with detailed rationale for every point deducted."""

    @staticmethod
    def calculate_score(
        active_alerts: List[Dict[str, Any]],
        suspicious_processes: List[Dict[str, Any]],
        recent_system_changes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compute the composite security score from active signals."""
        score = 100
        deductions: List[Dict[str, Any]] = []

        # 1. Deduct for unresolved alerts
        for alert in active_alerts:
            level = alert.get("risk_level", "Medium")
            if level == "Critical":
                penalty = 35
                reason = f"Active Critical Threat: {alert.get('title', 'Unknown threat')}"
            elif level == "High":
                penalty = 20
                reason = f"Unresolved High-Risk Alert: {alert.get('title', 'Suspicious activity')}"
            else:  # Medium
                penalty = 10
                reason = f"Security Notice: {alert.get('title', 'Unusual event')}"

            score -= penalty
            deductions.append({"reason": reason, "penalty": penalty})

        # 2. Deduct for running processes flagged with high risk
        for proc in suspicious_processes:
            proc_risk = proc.get("risk_score", 0)
            if proc_risk >= 60:
                penalty = 15
                name = proc.get("name", "process")
                score -= penalty
                deductions.append({
                    "reason": f"Elevated Risk Process Running: {name} (Risk {proc_risk}/100)",
                    "penalty": penalty,
                })

        # 3. Deduct for unreviewed startup/persistence changes in the last 24h
        for change in recent_system_changes:
            if change.get("category") == "STARTUP":
                penalty = 8
                score -= penalty
                deductions.append({
                    "reason": f"Recent Startup Item Added: {change.get('description', 'New program registered')}",
                    "penalty": penalty,
                })
                break  # Cap penalty to avoid runaway deduction

        # Bound score between 0 and 100
        score = max(0, min(100, score))

        if score >= 85:
            status_text = "Your computer looks safe"
            status_level = "Safe"
            status_color = "#10B981"  # Emerald Green
        elif score >= 60:
            status_text = "Attention Recommended"
            status_level = "Attention"
            status_color = "#F59E0B"  # Amber
        else:
            status_text = "Potential Security Threats Detected"
            status_level = "Threat"
            status_color = "#EF4444"  # Red

        return {
            "score": score,
            "status_text": status_text,
            "status_level": status_level,
            "status_color": status_color,
            "deductions": deductions,
        }
