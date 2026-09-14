"""Dashboard / Overview View."""
from typing import Any, Dict, List
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from app.gui.widgets.score_gauge import ScoreGaugeWidget

class DashboardView(QWidget):
    """Main overview dashboard with Security Score, quick stats, and protection shields."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._init_ui()

        # Polling timer for refreshing dashboard metrics
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(2500)  # Every 2.5 seconds
        self.refresh_data()

    def _init_ui(self) -> None:
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        container = QWidget()
        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(20)

        # Header Title with Refresh Button
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Overview & Health")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Real-time visibility, endpoint security posture, and active protection shields.")
        subtitle.setProperty("class", "ViewSubheader")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_row.addLayout(title_box)
        header_row.addStretch()

        btn_refresh = QPushButton("⟳ Refresh Status")
        btn_refresh.setProperty("class", "SecondaryBtn")
        btn_refresh.clicked.connect(self.refresh_data)
        header_row.addWidget(btn_refresh, alignment=Qt.AlignmentFlag.AlignTop)
        main_layout.addLayout(header_row)

        # Hero Row: Security Score Gauge
        self.score_gauge = ScoreGaugeWidget()
        main_layout.addWidget(self.score_gauge)

        # Quick Stats Grid
        stats_grid = QGridLayout()
        stats_grid.setSpacing(14)

        self.card_threats = self._create_stat_card("ACTIVE THREATS", "0", "#EF4444")
        self.card_apps = self._create_stat_card("RUNNING APPS", "0", "#38BDF8")
        self.card_events = self._create_stat_card("MONITORED EVENTS", "0", "#10B981")
        self.card_protection = self._create_stat_card("REAL-TIME SHIELD", "ACTIVE", "#34D399")

        stats_grid.addWidget(self.card_threats, 0, 0)
        stats_grid.addWidget(self.card_apps, 0, 1)
        stats_grid.addWidget(self.card_events, 0, 2)
        stats_grid.addWidget(self.card_protection, 0, 3)
        main_layout.addLayout(stats_grid)

        # Active Protection Shields Section
        lbl_shields = QLabel("ACTIVE PROTECTION SHIELDS")
        lbl_shields.setProperty("class", "CardTitle")
        main_layout.addWidget(lbl_shields)

        shields_grid = QGridLayout()
        shields_grid.setSpacing(14)

        s1 = self._create_shield_card(
            "🛡️ Process Behavioral Shield",
            "Monitors parent-child process chains and flags suspicious scripting utilities (PowerShell, CMD, WScript).",
            "ACTIVE"
        )
        s2 = self._create_shield_card(
            "📂 File System Integrity Guard",
            "Watches sensitive directories (Downloads, Desktop, Startup) for unauthorized binary drops and script creation.",
            "ACTIVE"
        )
        s3 = self._create_shield_card(
            "🌐 Network Socket Monitor",
            "Tracks active inbound and outbound connections and maps technical port numbers to understandable services.",
            "ACTIVE"
        )
        s4 = self._create_shield_card(
            "🔑 Persistence Sentinel",
            "Detects changes to Windows Registry Run keys, startup locations, and auto-start configurations in real time.",
            "ARMED"
        )
        s5 = self._create_shield_card(
            "🪤 Canary Ransomware Decoys",
            "Deploys hidden tripwire canary files in user document directories to catch and isolate encryption attempts.",
            "ARMED"
        )
        s6 = self._create_shield_card(
            "✨ AI Explainability Engine",
            "Translates low-level Windows telemetry into plain-English explanations with actionable security guidance.",
            "OPERATIONAL"
        )

        shields_grid.addWidget(s1, 0, 0)
        shields_grid.addWidget(s2, 0, 1)
        shields_grid.addWidget(s3, 0, 2)
        shields_grid.addWidget(s4, 1, 0)
        shields_grid.addWidget(s5, 1, 1)
        shields_grid.addWidget(s6, 1, 2)
        main_layout.addLayout(shields_grid)

        # Quick Navigation & Shortcuts Section
        lbl_shortcuts = QLabel("QUICK SECURITY ACTIONS")
        lbl_shortcuts.setProperty("class", "CardTitle")
        main_layout.addWidget(lbl_shortcuts)

        actions_grid = QGridLayout()
        actions_grid.setSpacing(14)

        a1 = self._create_action_card(
            "⚡ Live Activity Stream",
            "Inspect continuous telemetry feed with severity filters and plain-language 'Why?' breakdowns.",
            1
        )
        a2 = self._create_action_card(
            "🌳 Process Hierarchy Explorer",
            "View parent-child tree relationships and resource usage of running programs.",
            2
        )
        a3 = self._create_action_card(
            "🔒 Threat Scanner & Quarantine",
            "Perform manual hash/PE inspections and manage isolated threats in the encrypted vault.",
            6
        )
        a4 = self._create_action_card(
            "💬 Ask ThreatLens Assistant",
            "Ask questions like 'What happened today?' or get clarity on suspicious activity.",
            7
        )

        actions_grid.addWidget(a1, 0, 0)
        actions_grid.addWidget(a2, 0, 1)
        actions_grid.addWidget(a3, 0, 2)
        actions_grid.addWidget(a4, 0, 3)
        main_layout.addLayout(actions_grid)

        main_layout.addStretch()

        scroll.setWidget(container)
        outer_layout.addWidget(scroll)

    def _create_stat_card(self, title: str, initial_val: str, color: str) -> QFrame:
        card = QFrame()
        card.setProperty("class", "Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)

        lbl_title = QLabel(title)
        lbl_title.setProperty("class", "CardTitle")

        lbl_val = QLabel(initial_val)
        lbl_val.setProperty("class", "StatValue")
        lbl_val.setStyleSheet(f"color: {color};")
        lbl_val.setObjectName(f"val_{title.lower().replace(' ', '_')}")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        return card

    def _create_shield_card(self, title: str, description: str, status_text: str = "ACTIVE") -> QFrame:
        card = QFrame()
        card.setProperty("class", "Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        top_row = QHBoxLayout()
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #F1F5F9;")
        top_row.addWidget(lbl_title)
        top_row.addStretch()

        badge = QLabel(status_text)
        badge.setStyleSheet("background-color: #064E3B; color: #34D399; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px;")
        top_row.addWidget(badge)
        layout.addLayout(top_row)

        lbl_desc = QLabel(description)
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #94A3B8; font-size: 11px; line-height: 1.3;")
        layout.addWidget(lbl_desc)

        return card

    def _create_action_card(self, icon_title: str, subtitle: str, nav_index: int) -> QFrame:
        card = QFrame()
        card.setProperty("class", "Card")
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        lbl_title = QLabel(icon_title)
        lbl_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #38BDF8;")
        layout.addWidget(lbl_title)

        lbl_sub = QLabel(subtitle)
        lbl_sub.setWordWrap(True)
        lbl_sub.setStyleSheet("color: #94A3B8; font-size: 11px; line-height: 1.3;")
        layout.addWidget(lbl_sub)

        # Make card clickable to navigate
        card.mousePressEvent = lambda e: self._navigate_to(nav_index)
        return card

    def _navigate_to(self, view_index: int) -> None:
        main_win = self.window()
        if hasattr(main_win, "_switch_view"):
            main_win._switch_view(view_index)

    def refresh_data(self) -> None:
        """Fetch latest telemetry and refresh all dashboard indicators."""
        # 1. Update score & top stats
        health = self.engine.get_security_health()
        self.score_gauge.update_score(health)

        threats_lbl = self.card_threats.findChild(QLabel, "val_active_threats")
        if threats_lbl:
            threats_lbl.setText(str(health.get("active_threats", 0)))

        apps_lbl = self.card_apps.findChild(QLabel, "val_running_apps")
        if apps_lbl:
            apps_lbl.setText(str(health.get("running_apps", 0)))

        events_lbl = self.card_events.findChild(QLabel, "val_monitored_events")
        if events_lbl:
            events_lbl.setText(str(health.get("total_events", 0)))
