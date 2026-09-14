"""Live Activity Timeline View."""
from typing import Any, Dict, List
from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from app.gui.widgets.event_card import EventCardWidget

class _EventBridge(QObject):
    """Bridge for cross-thread Qt signal dispatch from background engine to GUI."""
    new_event = Signal(dict)

class LiveActivityView(QWidget):
    """Real-time streaming timeline of endpoint events with search and filtering."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._is_paused = False
        self._events_cache: List[Dict[str, Any]] = []

        self._bridge = _EventBridge()
        self._bridge.new_event.connect(self._on_live_event)

        self._init_ui()
        self._load_initial_history()

        # Subscribe to engine
        self.engine.subscribe(self._on_engine_telemetry)

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        hdr_layout = QVBoxLayout()
        title = QLabel("Live Activity Stream")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Continuous human-readable timeline of what programs are doing on your system.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr_layout.addWidget(title)
        hdr_layout.addWidget(subtitle)
        layout.addLayout(hdr_layout)

        # Filter & Search Controls Row
        controls_row = QHBoxLayout()
        controls_row.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search application, file, or action...")
        self.search_input.textChanged.connect(self._apply_filters)
        controls_row.addWidget(self.search_input, stretch=1)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Events", "Threats & Warnings (High/Critical)", "Process Activity", "File Activity"])
        self.filter_combo.setStyleSheet("background-color: #101623; border: 1px solid #1E293B; padding: 6px 12px; border-radius: 6px; color: #F1F5F9;")
        self.filter_combo.currentIndexChanged.connect(self._apply_filters)
        controls_row.addWidget(self.filter_combo)

        self.btn_pause = QPushButton("Pause Stream")
        self.btn_pause.setProperty("class", "SecondaryBtn")
        self.btn_pause.clicked.connect(self._toggle_pause)
        controls_row.addWidget(self.btn_pause)

        layout.addLayout(controls_row)

        # Scrollable events area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        self.events_container = QWidget()
        self.events_layout = QVBoxLayout(self.events_container)
        self.events_layout.setContentsMargins(0, 0, 0, 0)
        self.events_layout.setSpacing(10)
        self.events_layout.addStretch()

        scroll.setWidget(self.events_container)
        layout.addWidget(scroll, stretch=1)

    def _load_initial_history(self) -> None:
        """Load recent events from the database on startup."""
        events = self.engine.repository.get_recent_events(limit=40)
        self._events_cache = events
        self._rebuild_list()

    def _on_engine_telemetry(self, event: Dict[str, Any]) -> None:
        """Background thread callback routed safely through Qt signals."""
        self._bridge.new_event.emit(event)

    def _on_live_event(self, event: Dict[str, Any]) -> None:
        """Qt Main Thread handler for incoming live event."""
        if self._is_paused:
            return

        self._events_cache.insert(0, event)
        if len(self._events_cache) > 150:
            self._events_cache.pop()

        if self._matches_filter(event):
            card = EventCardWidget(event)
            self.events_layout.insertWidget(0, card)

    def _toggle_pause(self) -> None:
        self._is_paused = not self._is_paused
        self.btn_pause.setText("Resume Stream" if self._is_paused else "Pause Stream")

    def _matches_filter(self, event: Dict[str, Any]) -> bool:
        search_txt = self.search_input.text().strip().lower()
        filter_type = self.filter_combo.currentText()

        # Text search matching
        if search_txt:
            app = (event.get("application") or "").lower()
            action = (event.get("action") or "").lower()
            target = (event.get("target") or "").lower()
            explanation = (event.get("explanation") or "").lower()
            if not any(search_txt in field for field in [app, action, target, explanation]):
                return False

        # Dropdown filtering
        if "Threats" in filter_type:
            if event.get("severity") not in {"High", "Critical"}:
                return False
        elif "Process" in filter_type:
            if "PROCESS" not in event.get("event_type", ""):
                return False
        elif "File" in filter_type:
            if "FILE" not in event.get("event_type", "") and "STARTUP" not in event.get("event_type", ""):
                return False

        return True

    def _apply_filters(self) -> None:
        self._rebuild_list()

    def _rebuild_list(self) -> None:
        """Clear and rebuild cards matching current search and filter criteria."""
        while self.events_layout.count() > 1:
            item = self.events_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        matching = [e for e in self._events_cache if self._matches_filter(e)]
        if not matching:
            lbl_empty = QLabel("No events match your current filter.")
            lbl_empty.setStyleSheet("color: #64748B; font-style: italic; padding: 20px;")
            self.events_layout.insertWidget(0, lbl_empty)
        else:
            for ev in matching:
                card = EventCardWidget(ev)
                self.events_layout.insertWidget(self.events_layout.count() - 1, card)
