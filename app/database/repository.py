"""Thread-safe Repository for ThreatLens database operations."""
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from app.database.connection import get_db_connection

from contextlib import contextmanager

class Repository:
    def __init__(self, db_path=None):
        self.db_path = db_path

    @contextmanager
    def _connection(self):
        conn = get_db_connection(self.db_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


    # -------------------------------------------------------------
    # Events Operations
    # -------------------------------------------------------------
    def add_event(
        self,
        event_type: str,
        action: str,
        process_id: Optional[int] = None,
        process_name: Optional[str] = None,
        application: Optional[str] = None,
        target: Optional[str] = None,
        risk_score: int = 0,
        severity: str = "Low",
        explanation: Optional[str] = None,
        technical_details: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Insert a single telemetry event."""
        tech_json = json.dumps(technical_details or {})
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO events (
                    event_type, process_id, process_name, application,
                    action, target, risk_score, severity,
                    explanation, technical_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_type,
                    process_id,
                    process_name,
                    application,
                    action,
                    target,
                    risk_score,
                    severity,
                    explanation,
                    tech_json,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def add_events_batch(self, events: List[Dict[str, Any]]) -> None:
        """Bulk insert events efficiently inside a single transaction."""
        if not events:
            return
        rows = [
            (
                e.get("event_type", "UNKNOWN"),
                e.get("process_id"),
                e.get("process_name"),
                e.get("application"),
                e.get("action", ""),
                e.get("target"),
                e.get("risk_score", 0),
                e.get("severity", "Low"),
                e.get("explanation"),
                json.dumps(e.get("technical_details", {})),
            )
            for e in events
        ]
        with self._connection() as conn:
            conn.executemany(
                """
                INSERT INTO events (
                    event_type, process_id, process_name, application,
                    action, target, risk_score, severity,
                    explanation, technical_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()

    def get_recent_events(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent events sorted by newest first."""
        query = "SELECT * FROM events"
        params: List[Any] = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        params.append(limit)

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_event_stats(self) -> Dict[str, int]:
        """Get count of events grouped by severity."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT severity, COUNT(*) as count FROM events GROUP BY severity")
            stats = {row["severity"]: row["count"] for row in cursor.fetchall()}
            cursor.execute("SELECT COUNT(*) as total FROM events")
            total = cursor.fetchone()["total"]
            stats["Total"] = total
            return stats

    # -------------------------------------------------------------
    # Processes Operations
    # -------------------------------------------------------------
    def upsert_process(
        self,
        pid: int,
        ppid: Optional[int],
        name: str,
        exe_path: Optional[str],
        cmdline: Optional[str],
        username: Optional[str],
        is_signed: int = 0,
        risk_score: int = 0,
    ) -> None:
        """Insert or update a running process."""
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO processes (
                    pid, ppid, name, exe_path, cmdline, username, is_signed, risk_score, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'RUNNING')
                ON CONFLICT(pid) DO UPDATE SET
                    ppid = excluded.ppid,
                    name = excluded.name,
                    exe_path = excluded.exe_path,
                    cmdline = excluded.cmdline,
                    username = excluded.username,
                    is_signed = excluded.is_signed,
                    risk_score = excluded.risk_score,
                    status = 'RUNNING'
                """,
                (pid, ppid, name, exe_path, cmdline, username, is_signed, risk_score),
            )
            conn.commit()

    def mark_process_terminated(self, pid: int) -> None:
        """Mark a process as terminated."""
        with self._connection() as conn:
            conn.execute("UPDATE processes SET status = 'TERMINATED' WHERE pid = ?", (pid,))
            conn.commit()

    def get_active_processes(self) -> List[Dict[str, Any]]:
        """Retrieve all currently running processes."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM processes WHERE status = 'RUNNING' ORDER BY risk_score DESC, name ASC"
            )
            return [dict(row) for row in cursor.fetchall()]

    # -------------------------------------------------------------
    # Alerts Operations
    # -------------------------------------------------------------
    def add_alert(
        self,
        title: str,
        description: str,
        risk_level: str,
        process_id: Optional[int] = None,
        source: str = "Engine",
        recommendation: Optional[str] = None,
    ) -> int:
        """Create a new security alert."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (title, description, risk_level, process_id, source, recommendation)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (title, description, risk_level, process_id, source, recommendation),
            )
            conn.commit()
            return cursor.lastrowid

    def get_unresolved_alerts(self) -> List[Dict[str, Any]]:
        """Retrieve active unresolved alerts."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM alerts WHERE is_resolved = 0 ORDER BY timestamp DESC"
            )
            return [dict(row) for row in cursor.fetchall()]

    def resolve_alert(self, alert_id: int) -> None:
        """Dismiss or resolve an alert."""
        with self._connection() as conn:
            conn.execute("UPDATE alerts SET is_resolved = 1 WHERE id = ?", (alert_id,))
            conn.commit()

    # -------------------------------------------------------------
    # System Changes Operations
    # -------------------------------------------------------------
    def record_system_change(
        self,
        category: str,
        description: str,
        process_id: Optional[int] = None,
        target: Optional[str] = None,
        details: Optional[str] = None,
    ) -> int:
        """Log a significant system configuration change (e.g. Startup, Service)."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO system_changes (category, description, process_id, target, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (category, description, process_id, target, details),
            )
            conn.commit()
            return cursor.lastrowid

    def get_recent_system_changes(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent system changes."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM system_changes ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    # -------------------------------------------------------------
    # Retention Maintenance
    # -------------------------------------------------------------
    def cleanup_old_events(self, days: int = 30) -> int:
        """Prune telemetry events older than specified days."""
        cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    # -------------------------------------------------------------
    # Network Operations
    # -------------------------------------------------------------
    def record_network_event(
        self,
        process_id: Optional[int],
        process_name: Optional[str],
        protocol: str,
        local_address: str,
        remote_address: str,
        remote_port: int,
        domain: Optional[str] = None,
        status: Optional[str] = None,
        risk_level: str = "Low",
        explanation: Optional[str] = None,
    ) -> int:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO network_events (
                    process_id, process_name, protocol, local_address,
                    remote_address, remote_port, domain, status, risk_level, explanation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    process_id,
                    process_name,
                    protocol,
                    local_address,
                    remote_address,
                    remote_port,
                    domain,
                    status,
                    risk_level,
                    explanation,
                ),
            )
            return cursor.lastrowid

    def get_recent_network_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM network_events ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    # -------------------------------------------------------------
    # Application Profiles & Baselines
    # -------------------------------------------------------------
    def upsert_app_profile(
        self,
        app_name: str,
        exe_path: Optional[str],
        trust_score: int,
        habitual_ports: Optional[List[int]] = None,
        habitual_dirs: Optional[List[str]] = None,
        is_trusted: int = 0,
    ) -> None:
        ports_json = json.dumps(habitual_ports or [])
        dirs_json = json.dumps(habitual_dirs or [])
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO app_profiles (
                    app_name, exe_path, trust_score, habitual_ports, habitual_dirs, is_trusted, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(app_name) DO UPDATE SET
                    exe_path = excluded.exe_path,
                    trust_score = excluded.trust_score,
                    habitual_ports = excluded.habitual_ports,
                    habitual_dirs = excluded.habitual_dirs,
                    is_trusted = excluded.is_trusted,
                    last_seen = CURRENT_TIMESTAMP
                """,
                (app_name, exe_path, trust_score, ports_json, dirs_json, is_trusted),
            )

    def get_app_profiles(self) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM app_profiles ORDER BY trust_score DESC, app_name ASC")
            return [dict(r) for r in cursor.fetchall()]

    # -------------------------------------------------------------
    # Quarantine Operations
    # -------------------------------------------------------------
    def add_quarantine_record(
        self,
        original_path: str,
        quarantine_path: str,
        reason: str,
        detection_source: str,
    ) -> int:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO quarantine (original_path, quarantine_path, reason, detection_source)
                VALUES (?, ?, ?, ?)
                """,
                (original_path, quarantine_path, reason, detection_source),
            )
            return cursor.lastrowid

    def get_quarantine_records(self) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine ORDER BY quarantined_at DESC")
            return [dict(r) for r in cursor.fetchall()]

    def update_quarantine_status(self, record_id: int, status: str) -> None:
        with self._connection() as conn:
            conn.execute("UPDATE quarantine SET status = ? WHERE id = ?", (status, record_id))

    # -------------------------------------------------------------
    # User Decision Memory
    # -------------------------------------------------------------
    def add_user_decision(self, target_identifier: str, decision: str, reason: Optional[str] = None) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO user_decisions (target_identifier, decision, reason)
                VALUES (?, ?, ?)
                ON CONFLICT(target_identifier) DO UPDATE SET
                    decision = excluded.decision,
                    reason = excluded.reason,
                    timestamp = CURRENT_TIMESTAMP
                """,
                (target_identifier, decision, reason),
            )

    def get_user_decision(self, target_identifier: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM user_decisions WHERE target_identifier = ?", (target_identifier,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # -------------------------------------------------------------
    # Search / Assistant Queries
    # -------------------------------------------------------------
    def search_telemetry(self, keyword: str, limit: int = 50) -> List[Dict[str, Any]]:
        param = f"%{keyword}%"
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM events
                WHERE application LIKE ? OR process_name LIKE ? OR action LIKE ? OR target LIKE ? OR explanation LIKE ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (param, param, param, param, param, limit),
            )
            return [dict(r) for r in cursor.fetchall()]

