"""File Activity and High-Risk Folder Monitor."""
import os
import re
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, List, Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
except ImportError:
    Observer = None
    FileSystemEventHandler = object
    FileSystemEvent = None

from app.config import FILE_DEBOUNCE_INTERVAL, IGNORED_PATTERNS, MONITORED_PATHS

class _WatcherHandler(FileSystemEventHandler):
    """Internal event handler for Watchdog file events."""

    def __init__(self, on_event_fn: Callable[[str, str, str], None]):
        super().__init__()
        self.on_event_fn = on_event_fn
        self._patterns = [re.compile(p, re.IGNORECASE) for p in IGNORED_PATTERNS]

    def _is_ignored(self, path: str) -> bool:
        return any(pat.search(path) for pat in self._patterns)

    def on_created(self, event: Any) -> None:
        if not event.is_directory and not self._is_ignored(event.src_path):
            self.on_event_fn("FILE_CREATED", event.src_path, "File Created")

    def on_modified(self, event: Any) -> None:
        if not event.is_directory and not self._is_ignored(event.src_path):
            self.on_event_fn("FILE_MODIFIED", event.src_path, "File Modified")

    def on_deleted(self, event: Any) -> None:
        if not event.is_directory and not self._is_ignored(event.src_path):
            self.on_event_fn("FILE_DELETED", event.src_path, "File Deleted")

    def on_moved(self, event: Any) -> None:
        if not event.is_directory and not self._is_ignored(event.dest_path):
            self.on_event_fn("FILE_RENAMED", event.dest_path, f"Renamed from {os.path.basename(event.src_path)}")

class FileMonitor:
    """Watches high-value user directories and detects suspicious file manipulation bursts."""

    def __init__(
        self,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        monitored_paths: Optional[List[str]] = None,
    ):
        self.event_callback = event_callback
        self.monitored_paths = monitored_paths or MONITORED_PATHS
        self._observer: Optional[Any] = None
        self._running = False
        self._lock = threading.Lock()
        self._recent_events: Dict[str, float] = {}  # For debouncing
        self._event_history: deque = deque(maxlen=200)  # For rapid-burst detection (Ransomware heuristic)

    def start(self) -> None:
        """Start directory watching."""
        if self._running or not Observer:
            return

        self._observer = Observer()
        handler = _WatcherHandler(self._handle_file_event)

        for folder in self.monitored_paths:
            if os.path.exists(folder):
                try:
                    self._observer.schedule(handler, folder, recursive=False)
                except Exception:
                    pass

        try:
            self._observer.start()
            self._running = True
        except Exception:
            self._running = False

    def stop(self) -> None:
        """Stop watching directories."""
        if self._running and self._observer:
            self._observer.stop()
            self._observer.join(timeout=2.0)
            self._running = False

    def _handle_file_event(self, event_type: str, file_path: str, action_desc: str) -> None:
        now = time.time()
        file_name = os.path.basename(file_path)

        # 1. Debounce rapid duplicate notifications for the same file
        with self._lock:
            last_time = self._recent_events.get(file_path, 0)
            if now - last_time < FILE_DEBOUNCE_INTERVAL:
                return
            self._recent_events[file_path] = now
            self._event_history.append((now, file_path))

            # 2. Ransomware Rapid Burst Heuristic:
            # Check if > 35 file actions happened in the last 4 seconds
            burst_window = 4.0
            recent_count = sum(1 for (t, _) in self._event_history if now - t <= burst_window)
            is_burst = recent_count >= 35

        # Assess risk
        risk = 5
        severity = "Low"
        ext = os.path.splitext(file_name)[1].lower()

        # Flag executable/script drops in Downloads or Startup
        if ext in {".exe", ".bat", ".ps1", ".vbs", ".cmd", ".scr", ".dll"}:
            risk = 35
            severity = "Medium"

        if "Startup" in file_path:
            event_type = "STARTUP_CREATED"
            risk = 60
            severity = "High"

        if is_burst:
            event_type = "RANSOMWARE_SUSPECTED"
            risk = 85
            severity = "Critical"

        if self.event_callback:
            event = {
                "event_type": event_type,
                "process_id": None,
                "process_name": "Explorer / System",
                "application": "File System",
                "action": action_desc,
                "target": file_path,
                "risk_score": risk,
                "severity": severity,
                "technical_details": {
                    "file_path": file_path,
                    "extension": ext,
                    "folder": os.path.dirname(file_path),
                },
            }
            self.event_callback(event)
