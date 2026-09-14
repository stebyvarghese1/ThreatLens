"""Behavioral Event Correlation Engine."""
import time
from collections import defaultdict, deque
from typing import Any, Callable, Dict, List, Optional

class CorrelationEngine:
    """Correlates multiple sequential telemetry events into unified behavioral incident chains."""

    def __init__(self, incident_callback: Optional[Callable[[Dict[str, Any]], None]] = None, window_seconds: float = 60.0):
        self.incident_callback = incident_callback
        self.window_seconds = window_seconds
        # Buffer of events grouped by application/process name: name -> deque of (timestamp, event)
        self._history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._flagged_incidents: set = set()

    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Feed an event into correlation pipeline and return an Incident if chain matches."""
        app = (event.get("application") or event.get("process_name") or "unknown").lower()
        now = time.time()
        buf = self._history[app]

        # Prune old events outside sliding window
        while buf and (now - buf[0][0] > self.window_seconds):
            buf.popleft()

        buf.append((now, event))

        # Check for correlated patterns
        incident = self._evaluate_chain(app, buf)
        if incident:
            incident_key = f"{app}_{incident['title']}"
            if incident_key not in self._flagged_incidents:
                self._flagged_incidents.add(incident_key)
                if self.incident_callback:
                    self.incident_callback(incident)
                return incident

        return None

    def _evaluate_chain(self, app: str, events_buffer: deque) -> Optional[Dict[str, Any]]:
        events = [item[1] for item in events_buffer]
        event_types = {e.get("event_type", "") for e in events}
        actions = " ".join([e.get("action", "").lower() for e in events])

        # Pattern 1: Download / File Drop -> Process Spawn -> Persistence
        has_file = any("FILE" in t or "DOWNLOAD" in actions for t in event_types)
        has_process = any("PROCESS" in t for t in event_types)
        has_persistence = any("STARTUP" in t or "registry" in actions for t in event_types)
        has_network = any("NETWORK" in t or "connected" in actions for t in event_types)

        chain_score = 0
        stages: List[str] = []

        if has_file:
            chain_score += 15
            stages.append("File Drop/Download")
        if has_process:
            chain_score += 20
            stages.append("Process Execution")
        if has_persistence:
            chain_score += 35
            stages.append("Windows Persistence Attempt")
        if has_network:
            chain_score += 25
            stages.append("Outbound Network Communication")

        # Flag if 3 or more stages occurred in close succession with elevated score
        if len(stages) >= 3 and chain_score >= 65:
            explanation = (
                f"ThreatLens detected a correlated multi-stage attack chain from '{app}': "
                + " ➔ ".join(stages)
                + ". While individual steps might look harmless, this rapid sequence indicates suspicious endpoint manipulation."
            )
            return {
                "event_type": "CORRELATED_INCIDENT",
                "application": app,
                "title": f"Multi-Stage Behavior Chain ({' ➔ '.join(stages)})",
                "severity": "Critical" if chain_score >= 80 else "High",
                "risk_score": min(100, chain_score),
                "stages": stages,
                "explanation": explanation,
                "correlated_events_count": len(events),
            }

        return None
