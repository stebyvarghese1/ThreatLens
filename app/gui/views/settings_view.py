"""Settings and Configuration View."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from app.config import DEFAULT_RETENTION_DAYS, MONITORED_PATHS

class SettingsView(QWidget):
    """User preferences, retention policy, and monitored paths configuration."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # Header
        hdr = QVBoxLayout()
        title = QLabel("Settings & Preferences")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Configure data retention, monitoring targets, and privacy.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr.addWidget(title)
        hdr.addWidget(subtitle)
        layout.addLayout(hdr)

        # 1. Retention Card
        card_retention = QFrame()
        card_retention.setProperty("class", "Card")
        ret_layout = QVBoxLayout(card_retention)
        ret_layout.setSpacing(12)

        ret_hdr = QLabel("DATA RETENTION POLICY")
        ret_hdr.setProperty("class", "CardTitle")
        ret_layout.addWidget(ret_hdr)

        ret_desc = QLabel("Controls how long local telemetry and event logs are stored in your local SQLite database before automatic purging.")
        ret_desc.setStyleSheet("color: #94A3B8; font-size: 12px;")
        ret_desc.setWordWrap(True)
        ret_layout.addWidget(ret_desc)

        ret_row = QHBoxLayout()
        lbl_days = QLabel("Retain Events For:")
        self.combo_days = QComboBox()
        self.combo_days.addItems(["7 Days", "30 Days (Recommended)", "90 Days", "365 Days"])
        self.combo_days.setCurrentIndex(1)
        self.combo_days.setStyleSheet("background-color: #101623; border: 1px solid #1E293B; padding: 6px 12px; border-radius: 6px; color: #F1F5F9;")

        btn_cleanup = QPushButton("Purge Old Data Now")
        btn_cleanup.setProperty("class", "SecondaryBtn")
        btn_cleanup.clicked.connect(self._run_cleanup)

        ret_row.addWidget(lbl_days)
        ret_row.addWidget(self.combo_days)
        ret_row.addStretch()
        ret_row.addWidget(btn_cleanup)
        ret_layout.addLayout(ret_row)

        layout.addWidget(card_retention)

        # 2. Monitored Directories Card
        card_dirs = QFrame()
        card_dirs.setProperty("class", "Card")
        dirs_layout = QVBoxLayout(card_dirs)
        dirs_layout.setSpacing(10)

        dirs_hdr = QLabel("ACTIVELY MONITORED DIRECTORIES")
        dirs_hdr.setProperty("class", "CardTitle")
        dirs_layout.addWidget(dirs_hdr)

        self.list_dirs = QListWidget()
        self.list_dirs.setFixedHeight(120)
        self.list_dirs.setStyleSheet("background-color: #101623; border: 1px solid #1E293B; border-radius: 6px; padding: 6px; color: #E2E8F0;")
        for p in MONITORED_PATHS:
            self.list_dirs.addItem(p)
        dirs_layout.addWidget(self.list_dirs)

        layout.addWidget(card_dirs)

        # 3. Privacy Card
        card_privacy = QFrame()
        card_privacy.setProperty("class", "Card")
        priv_layout = QVBoxLayout(card_privacy)
        priv_layout.setSpacing(6)

        priv_hdr = QLabel("PRIVACY & LOCAL OPERATION")
        priv_hdr.setProperty("class", "CardTitle")
        priv_layout.addWidget(priv_hdr)

        priv_text = QLabel(
            "ThreatLens operates entirely on your local computer. Telemetry, process logs, "
            "and file event histories are stored exclusively in your local threatlens.db. "
            "No cloud telemetry or tracking data is transmitted without explicit user configuration."
        )
        priv_text.setStyleSheet("color: #94A3B8; font-size: 12px; line-height: 1.4;")
        priv_text.setWordWrap(True)
        priv_layout.addWidget(priv_text)

        layout.addWidget(card_privacy)
        layout.addStretch()

    def _run_cleanup(self) -> None:
        deleted = self.engine.repository.cleanup_old_events(days=DEFAULT_RETENTION_DAYS)
        QMessageBox.information(
            self,
            "Cleanup Complete",
            f"Successfully pruned {deleted} event records older than {DEFAULT_RETENTION_DAYS} days.",
        )
