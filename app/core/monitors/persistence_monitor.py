"""Windows Persistence Mechanism Monitor (Registry Run Keys & Startup)."""
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    import winreg
except ImportError:
    winreg = None

REG_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") if winreg else None,
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce") if winreg else None,
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run") if winreg else None,
]
REG_RUN_KEYS = [k for k in REG_RUN_KEYS if k is not None]

class PersistenceMonitor:
    """Continuously observes Windows Registry Run keys and Startup folders for persistence creation."""

    def __init__(self, event_callback: Optional[Callable[[Dict[str, Any]], None]] = None, poll_interval: float = 5.0):
        self.event_callback = event_callback
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_entries: Dict[str, str] = {}
        self._lock = threading.RLock()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="TL-PersistenceMonitor")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _poll_loop(self) -> None:
        # First pass sets initial baseline without spamming events
        try:
            self._scan_persistence(emit_events=False)
        except Exception:
            pass

        while self._running:
            time.sleep(self.poll_interval)
            if not self._running:
                break
            try:
                self._scan_persistence(emit_events=True)
            except Exception:
                pass

    def _scan_persistence(self, emit_events: bool = True) -> None:
        current_entries: Dict[str, str] = {}

        # 1. Scan Registry Run Keys
        if winreg:
            for root_key, subkey in REG_RUN_KEYS:
                root_name = "HKCU" if root_key == winreg.HKEY_CURRENT_USER else "HKLM"
                try:
                    with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as key:
                        i = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(key, i)
                                full_id = f"{root_name}\\{subkey}\\{name}"
                                current_entries[full_id] = str(val)
                                i += 1
                            except OSError:
                                break
                except Exception:
                    pass

        # 2. Scan Startup Folder Shortcuts
        startup_dir = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(startup_dir):
            for item in os.listdir(startup_dir):
                full_id = f"StartupFolder\\{item}"
                current_entries[full_id] = os.path.join(startup_dir, item)

        with self._lock:
            if emit_events:
                new_entries = set(current_entries.keys()) - set(self._known_entries.keys())
                for entry_id in new_entries:
                    cmd_val = current_entries[entry_id]
                    if self.event_callback:
                        event = {
                            "event_type": "STARTUP_CREATED",
                            "process_id": None,
                            "process_name": "Windows Registry / Startup",
                            "application": entry_id.split("\\")[-1],
                            "action": "Persistence Registered",
                            "target": cmd_val,
                            "risk_score": 60,
                            "severity": "High",
                            "explanation": f"A new program '{entry_id}' was registered to start automatically on Windows boot.",
                            "technical_details": {
                                "location": entry_id,
                                "command": cmd_val,
                            },
                        }
                        self.event_callback(event)

            self._known_entries = current_entries

    def get_persistence_entries(self) -> List[Dict[str, str]]:
        with self._lock:
            return [{"location": k, "command": v} for k, v in self._known_entries.items()]
