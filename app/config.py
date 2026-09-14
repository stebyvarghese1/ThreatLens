"""Configuration settings for ThreatLens."""
import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "threatlens.db"
QUARANTINE_DIR = DATA_DIR / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Monitored Folders (Standard user high-risk targets)
USER_HOME = Path.home()
MONITORED_PATHS = [
    str(USER_HOME / "Downloads"),
    str(USER_HOME / "Desktop"),
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
]
# Filter out paths that don't exist on this machine
MONITORED_PATHS = [p for p in MONITORED_PATHS if os.path.exists(p)]

# Ignore filters for file monitor (to prevent CPU overhead and spam)
IGNORED_PATTERNS = [
    r"\\\.venv\\",
    r"\\node_modules\\",
    r"\\\.git\\",
    r"\\AppData\\Local\\Temp\\",
    r"\.tmp$",
    r"~.*",
]

# Retention settings (in days)
DEFAULT_RETENTION_DAYS = 30

# Polling intervals (seconds)
PROCESS_POLL_INTERVAL = 1.5  # Lightweight psutil diff
FILE_DEBOUNCE_INTERVAL = 0.5  # Seconds to debounce rapid duplicate file events
DB_FLUSH_INTERVAL = 1.0       # Seconds between bulk DB writes

# Threat scoring weights
SCORE_WEIGHTS = {
    "unsigned_executable": 15,
    "runs_from_downloads": 10,
    "startup_persistence": 20,
    "powershell_execution": 15,
    "suspicious_network": 20,
    "rapid_file_burst": 25,
    "known_malicious_hash": 40,
}
