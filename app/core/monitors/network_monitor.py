"""Active Network Connection Telemetry and Explainability Monitor."""
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

try:
    import psutil
except ImportError:
    psutil = None

PORT_DESCRIPTIONS = {
    80: "HTTP (Web Traffic - Unencrypted)",
    443: "HTTPS (Secure Web Traffic)",
    53: "DNS (Domain Name Resolution)",
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    25: "SMTP (Email Transmission)",
    587: "SMTP Submission (Encrypted Email)",
    993: "IMAPS (Encrypted Email Retrieval)",
    3389: "RDP (Remote Desktop Protocol)",
    8080: "HTTP Alternative Web Proxy",
    8443: "HTTPS Alternative Web Service",
}

SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 1337, 31337}

class NetworkMonitor:
    """Monitors active TCP/UDP socket connections and converts endpoints into human explanations."""

    def __init__(self, event_callback: Optional[Callable[[Dict[str, Any]], None]] = None, poll_interval: float = 3.0):
        self.event_callback = event_callback
        self.poll_interval = poll_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_connections: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def start(self) -> None:
        if self._running or not psutil:
            return
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="TL-NetMonitor")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _poll_loop(self) -> None:
        while self._running:
            try:
                self._inspect_sockets()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _inspect_sockets(self) -> None:
        if not psutil:
            return

        current_conns: Dict[str, Dict[str, Any]] = {}

        try:
            net_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return

        for c in net_conns:
            if not c.raddr:
                continue  # Skip listening sockets with no remote peer

            remote_ip, remote_port = c.raddr
            local_ip, local_port = c.laddr if c.laddr else ("", 0)

            # Ignore local loopback connections to avoid spam
            if remote_ip in {"127.0.0.1", "::1", "0.0.0.0"}:
                continue

            conn_key = f"{c.pid}_{c.type}_{remote_ip}_{remote_port}"
            proc_name = "System"
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:
                    pass

            proto_str = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            port_desc = PORT_DESCRIPTIONS.get(remote_port, f"Port {remote_port}")

            # Risk evaluation
            risk = 0
            risk_level = "Low"
            if remote_port in SUSPICIOUS_PORTS:
                risk = 60
                risk_level = "High"
            elif remote_port not in {80, 443, 53, 587, 993, 8080, 8443}:
                risk = 25
                risk_level = "Medium"

            explanation = f"{proc_name} connected to {remote_ip}:{remote_port} ({port_desc})."

            current_conns[conn_key] = {
                "process_id": c.pid,
                "process_name": proc_name,
                "protocol": proto_str,
                "local_address": f"{local_ip}:{local_port}",
                "remote_address": remote_ip,
                "remote_port": remote_port,
                "status": c.status,
                "risk_level": risk_level,
                "risk_score": risk,
                "explanation": explanation,
            }

        with self._lock:
            # Detect new connections
            new_keys = set(current_conns.keys()) - set(self._known_connections.keys())
            for k in new_keys:
                conn_data = current_conns[k]
                self._known_connections[k] = conn_data

                if self.event_callback:
                    event = {
                        "event_type": "NETWORK_CONNECTED",
                        "process_id": conn_data["process_id"],
                        "process_name": conn_data["process_name"],
                        "application": conn_data["process_name"],
                        "action": "Network Connection",
                        "target": f"{conn_data['remote_address']}:{conn_data['remote_port']}",
                        "risk_score": conn_data["risk_score"],
                        "severity": conn_data["risk_level"],
                        "explanation": conn_data["explanation"],
                        "technical_details": conn_data,
                    }
                    self.event_callback(event)

            self._known_connections = current_conns

    def get_active_connections(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._known_connections.values())
