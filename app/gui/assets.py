"""Asset loader and icon management for ThreatLens."""
from pathlib import Path
from PySide6.QtGui import QIcon, QPixmap

def get_icon_path() -> Path:
    """Returns the absolute path to the official ThreatLens icon."""
    primary = Path(__file__).parent / "assets" / "threatlens_icon.png"
    if primary.exists():
        return primary
    fallback = Path(__file__).resolve().parent.parent.parent / "file_0000000056108211babc520e29fd4515.png"
    if fallback.exists():
        return fallback
    return primary

def get_app_icon() -> QIcon:
    """Returns a QIcon initialized with the ThreatLens application icon."""
    path = get_icon_path()
    if path.exists():
        return QIcon(str(path))
    return QIcon()
