"""Process Telemetry and Execution Hierarchy Monitor."""
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

try:
    import psutil
except ImportError:
    psutil = None

from app.config import PROCESS_POLL_INTERVAL

class ProcessMonitor:
    """Continuously monitors process lifecycle events, parent-child lineages, and suspicious executions."""

    def __init__(self, event_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.event_callback = event_callback
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_processes: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def start(self) -> None:
        """Start the asynchronous polling worker."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="TL-ProcessMonitor")
        self._thread.start()

    def stop(self) -> None:
        """Stop the monitor."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _monitor_loop(self) -> None:
        # Take initial snapshot silently in background thread without blocking main thread
        try:
            self._take_snapshot(emit_events=False)
        except Exception:
            pass

        while self._running:
            time.sleep(PROCESS_POLL_INTERVAL)
            if not self._running:
                break
            try:
                self._take_snapshot(emit_events=True)
            except Exception:
                pass


    def _assess_process_risk(self, name: str, exe: Optional[str], cmdline: Optional[str], ppid: Optional[int]) -> int:
        """Heuristic risk assessment of a new process."""
        score = 0
        name_lower = name.lower()
        cmdline_lower = (cmdline or "").lower()
        exe_lower = (exe or "").lower()

        # 1. Suspicious command line parameters
        if "powershell" in name_lower or "cmd" in name_lower:
            score += 15
            if "-enc" in cmdline_lower or "-encodedcommand" in cmdline_lower:
                score += 40
            if "bypass" in cmdline_lower:
                score += 20
            if "downloadstring" in cmdline_lower or "invoke-webrequest" in cmdline_lower:
                score += 35

        # 2. Executing out of untrusted directories (Downloads, Temp)
        if "downloads" in exe_lower or "\\temp\\" in exe_lower:
            score += 25

        # 3. Parent-child anomaly check
        with self._lock:
            parent = self._known_processes.get(ppid or 0)
        if parent:
            parent_name = parent.get("name", "").lower()
            # Office or PDF viewer spawning script interpreters
            office_apps = {"winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "acrobat.exe"}
            if parent_name in office_apps and name_lower in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
                score += 50

        return min(100, score)

    def _take_snapshot(self, emit_events: bool = True) -> None:
        """Capture current process table and detect additions/removals."""
        if not psutil:
            return

        current_snapshot: Dict[int, Dict[str, Any]] = {}

        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username"]):
            try:
                info = proc.info
                pid = info["pid"]
                if pid == 0:
                    continue  # System idle process
                cmdline_str = " ".join(info["cmdline"]) if info["cmdline"] else ""
                current_snapshot[pid] = {
                    "pid": pid,
                    "ppid": info["ppid"],
                    "name": info["name"] or "unknown",
                    "exe": info["exe"] or "",
                    "cmdline": cmdline_str,
                    "username": info["username"] or "",
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        with self._lock:
            old_pids = set(self._known_processes.keys())
            current_pids = set(current_snapshot.keys())

            new_pids = current_pids - old_pids
            dead_pids = old_pids - current_pids

            # Process newly created processes
            for pid in new_pids:
                p_data = current_snapshot[pid]
                risk = self._assess_process_risk(
                    p_data["name"], p_data["exe"], p_data["cmdline"], p_data["ppid"]
                )
                p_data["risk_score"] = risk
                self._known_processes[pid] = p_data

                if emit_events and self.event_callback:
                    severity = "Critical" if risk >= 75 else ("High" if risk >= 50 else ("Medium" if risk >= 25 else "Low"))
                    event = {
                        "event_type": "PROCESS_STARTED",
                        "process_id": pid,
                        "process_name": p_data["name"],
                        "application": p_data["name"],
                        "action": "Process Execution",
                        "target": p_data["exe"] or p_data["name"],
                        "risk_score": risk,
                        "severity": severity,
                        "technical_details": {
                            "pid": pid,
                            "ppid": p_data["ppid"],
                            "path": p_data["exe"],
                            "cmdline": p_data["cmdline"],
                            "user": p_data["username"],
                        },
                    }
                    self.event_callback(event)

            # Process terminated processes
            for pid in dead_pids:
                dead_proc = self._known_processes.pop(pid, None)
                if emit_events and self.event_callback and dead_proc:
                    event = {
                        "event_type": "PROCESS_STOPPED",
                        "process_id": pid,
                        "process_name": dead_proc["name"],
                        "application": dead_proc["name"],
                        "action": "Process Termination",
                        "target": dead_proc.get("exe", ""),
                        "risk_score": 0,
                        "severity": "Low",
                        "technical_details": {"pid": pid, "name": dead_proc["name"]},
                    }
                    self.event_callback(event)

    def get_process_list(self) -> List[Dict[str, Any]]:
        """Return list of current active processes sorted by risk."""
        with self._lock:
            return sorted(self._known_processes.values(), key=lambda x: x.get("risk_score", 0), reverse=True)

    def get_process_tree(self) -> List[Dict[str, Any]]:
        """Construct hierarchical parent-child process tree."""
        with self._lock:
            procs = list(self._known_processes.values())

        # Map by pid
        proc_dict = {p["pid"]: {**p, "children": []} for p in procs}
        roots: List[Dict[str, Any]] = []

        for p in proc_dict.values():
            ppid = p.get("ppid")
            if ppid and ppid in proc_dict and ppid != p["pid"]:
                proc_dict[ppid]["children"].append(p)
            else:
                roots.append(p)

        return roots
