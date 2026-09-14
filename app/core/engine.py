"""ThreatLens Core Coordination and Ingestion Engine."""
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from app.config import DB_FLUSH_INTERVAL
from app.core.explain import ExplainEngine
from app.core.monitors.file_monitor import FileMonitor
from app.core.monitors.network_monitor import NetworkMonitor
from app.core.monitors.persistence_monitor import PersistenceMonitor
from app.core.monitors.process_monitor import ProcessMonitor
from app.core.scoring import SecurityScoreCalculator
from app.database.connection import init_db
from app.database.repository import Repository
from app.detection.correlation import CorrelationEngine
from app.detection.ransomware import RansomwareDetector
from app.detection.scanner import SecurityScanner
from app.security.decisions import UserDecisionMemory
from app.security.quarantine import QuarantineVault
from app.transparency.assistant import AskThreatLensAssistant
from app.transparency.profiler import ApplicationProfiler
from app.transparency.reports import ReportGenerator

class CoreEngine:
    """Coordinates telemetry monitors, event dispatch, and database persistence."""

    def __init__(self, db_path=None):
        self.repository = Repository(db_path)
        self.explain_engine = ExplainEngine()
        self.score_calculator = SecurityScoreCalculator()

        # Security & Transparency subsystems
        self.scanner = SecurityScanner()
        self.quarantine = QuarantineVault(self.repository)
        self.decisions = UserDecisionMemory(self.repository)
        self.profiler = ApplicationProfiler(self.repository)
        self.assistant = AskThreatLensAssistant(self.repository)
        self.reports = ReportGenerator(self.repository)

        # Correlation & Ransomware detectors
        self.correlation = CorrelationEngine(incident_callback=self.on_telemetry_event)
        self.ransomware = RansomwareDetector(alert_callback=self.on_telemetry_event)

        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._event_queue: queue.Queue = queue.Queue()
        self._running = False
        self._db_writer_thread: Optional[threading.Thread] = None

        # Telemetry monitors
        self.process_monitor = ProcessMonitor(event_callback=self.on_telemetry_event)
        self.file_monitor = FileMonitor(event_callback=self.on_telemetry_event)
        self.network_monitor = NetworkMonitor(event_callback=self.on_telemetry_event)
        self.persistence_monitor = PersistenceMonitor(event_callback=self.on_telemetry_event)

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Subscribe a listener (e.g., GUI) to live telemetry events."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def start(self) -> None:
        """Start all monitors and background database writer."""
        init_db(self.repository.db_path)
        self._running = True

        # Start database ingestion queue worker
        self._db_writer_thread = threading.Thread(
            target=self._db_writer_loop, daemon=True, name="TL-DBWriter"
        )
        self._db_writer_thread.start()

        # Start all monitors
        self.process_monitor.start()
        self.file_monitor.start()
        self.network_monitor.start()
        self.persistence_monitor.start()

    def stop(self) -> None:
        """Clean shutdown of monitors and flush remaining events."""
        self._running = False
        self.process_monitor.stop()
        self.file_monitor.stop()
        self.network_monitor.stop()
        self.persistence_monitor.stop()

        if self._db_writer_thread and self._db_writer_thread.is_alive():
            self._db_writer_thread.join(timeout=2.0)


    def on_telemetry_event(self, raw_event: Dict[str, Any]) -> None:
        """Callback for receiving telemetry events from monitors."""
        app_name = raw_event.get("application") or raw_event.get("process_name") or ""

        # Check User Decision Memory (whitelist/allowlist suppression)
        if app_name and self.decisions.is_allowed(app_name):
            raw_event["risk_score"] = 0
            raw_event["severity"] = "Low"

        # 1. Enrich with natural language explanation if missing
        if not raw_event.get("explanation"):
            raw_event["explanation"] = self.explain_engine.generate_simple_summary(
                raw_event.get("event_type", ""),
                raw_event.get("application"),
                raw_event.get("action", ""),
                raw_event.get("target"),
            )

        # 2. Record specialized network telemetry
        if raw_event.get("event_type") == "NETWORK_CONNECTED":
            details = raw_event.get("technical_details", {})
            self.repository.record_network_event(
                process_id=raw_event.get("process_id"),
                process_name=raw_event.get("process_name"),
                protocol=details.get("protocol", "TCP"),
                local_address=details.get("local_address", ""),
                remote_address=details.get("remote_address", ""),
                remote_port=details.get("remote_port", 0),
                domain=details.get("domain"),
                status=details.get("status"),
                risk_level=raw_event.get("severity", "Low"),
                explanation=raw_event.get("explanation"),
            )

        # 3. Update application profiling
        if raw_event.get("event_type") == "PROCESS_STARTED":
            self.profiler.profile_process(raw_event)

        # 4. Feed into Behavioral Correlation Engine (detect multi-stage attack chains)
        if raw_event.get("event_type") != "CORRELATED_INCIDENT":
            self.correlation.process_event(raw_event)

        # 5. Check canary tripwire on file events
        if "FILE" in raw_event.get("event_type", ""):
            self.ransomware.check_canary_integrity()

        # 6. Queue for database batch persistence
        self._event_queue.put(raw_event)

        # 7. If High or Critical risk, generate an Alert immediately
        if raw_event.get("severity") in {"High", "Critical"}:
            breakdown = self.explain_engine.generate_why_breakdown(raw_event)
            self.repository.add_alert(
                title=f"Suspicious: {raw_event.get('action', 'Activity')}",
                description=raw_event.get("explanation", ""),
                risk_level=raw_event.get("severity", "High"),
                process_id=raw_event.get("process_id"),
                source=raw_event.get("event_type", "Telemetry"),
                recommendation=breakdown.get("recommendation"),
            )

        # 8. Notify live subscribers (GUI)
        for sub in list(self._subscribers):
            try:
                sub(raw_event)
            except Exception:
                pass


    def _db_writer_loop(self) -> None:
        """Collects events from queue and writes them in batches."""
        batch: List[Dict[str, Any]] = []
        last_flush = time.time()

        while self._running or not self._event_queue.empty():
            try:
                event = self._event_queue.get(timeout=0.2)
                batch.append(event)
            except queue.Empty:
                pass

            now = time.time()
            if (len(batch) >= 20) or (batch and now - last_flush >= DB_FLUSH_INTERVAL):
                try:
                    self.repository.add_events_batch(batch)
                except Exception:
                    pass
                batch.clear()
                last_flush = now

    def get_security_health(self) -> Dict[str, Any]:
        """Compute the current endpoint security score and health metrics."""
        active_alerts = self.repository.get_unresolved_alerts()
        suspicious_procs = [p for p in self.process_monitor.get_process_list() if p.get("risk_score", 0) >= 50]
        recent_changes = self.repository.get_recent_system_changes(limit=10)

        score_data = self.score_calculator.calculate_score(
            active_alerts=active_alerts,
            suspicious_processes=suspicious_procs,
            recent_system_changes=recent_changes,
        )

        stats = self.repository.get_event_stats()
        score_data["total_events"] = stats.get("Total", 0)
        score_data["active_threats"] = len(active_alerts)
        score_data["running_apps"] = len(self.process_monitor.get_process_list())

        return score_data
