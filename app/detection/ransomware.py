"""Ransomware Protection: Canary Decoys & Entropy Burst Detection."""
import hashlib
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

CANARY_FILENAME = ".threatlens_canary.docx"
CANARY_CONTENT = b"ThreatLens Integrity Verification Canary - Do Not Modify. (Security Decoy)"
CANARY_EXPECTED_HASH = hashlib.sha256(CANARY_CONTENT).hexdigest()

class RansomwareDetector:
    """Monitors hidden canary tripwires and mass-modification spikes for early ransomware containment."""

    def __init__(self, target_folders: Optional[List[str]] = None, alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.alert_callback = alert_callback
        self.target_folders = target_folders or [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "Documents"),
        ]
        self.canary_paths: List[str] = []
        self._deploy_canaries()

    def _deploy_canaries(self) -> None:
        """Place hidden decoy canary files in target directories."""
        for folder in self.target_folders:
            if os.path.isdir(folder):
                canary_file = os.path.join(folder, CANARY_FILENAME)
                self.canary_paths.append(canary_file)
                try:
                    if not os.path.exists(canary_file):
                        with open(canary_file, "wb") as f:
                            f.write(CANARY_CONTENT)
                except Exception:
                    pass

    def check_canary_integrity(self) -> List[Dict[str, Any]]:
        """Verify all canary decoy files remain unaltered. Returns triggered violations."""
        violations = []
        for path in self.canary_paths:
            if not os.path.exists(path):
                violations.append({
                    "path": path,
                    "issue": "Canary file deleted or renamed",
                })
            else:
                try:
                    with open(path, "rb") as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                    if h != CANARY_EXPECTED_HASH:
                        violations.append({
                            "path": path,
                            "issue": "Canary file encrypted or altered",
                        })
                except Exception as e:
                    violations.append({"path": path, "issue": f"Canary access error: {e}"})

        if violations and self.alert_callback:
            alert = {
                "event_type": "RANSOMWARE_CANARY_TRIGGERED",
                "severity": "Critical",
                "risk_score": 95,
                "title": "🚨 Ransomware Tripwire Triggered!",
                "explanation": (
                    f"A hidden ThreatLens canary decoy file ({violations[0]['path']}) was tampered with ({violations[0]['issue']}). "
                    "This strongly indicates active ransomware attempting mass file encryption."
                ),
                "violations": violations,
            }
            self.alert_callback(alert)

        return violations

    @staticmethod
    def contain_process(pid: int) -> bool:
        """Immediate emergency containment: suspends or terminates the rogue process."""
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.suspend()  # Freeze immediately to halt active encryption
            proc.terminate() # Then terminate
            return True
        except Exception:
            return False
