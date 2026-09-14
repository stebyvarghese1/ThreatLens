"""Interactive Event Card Widget with Dual-Layer View and 'Why?' Explanation Dialog."""
import json
from typing import Any, Dict
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from app.core.explain import ExplainEngine

class WhyDialog(QDialog):
    """Modal dialog displaying contextual 'Why?' reasoning and recommended actions."""

    def __init__(self, breakdown: Dict[str, str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("ThreatLens Security Explanation")
        self.setMinimumWidth(500)
        self.setStyleSheet("""
            QDialog {
                background-color: #0F172A;
                border: 1px solid #334155;
                border-radius: 12px;
            }
            QLabel {
                color: #E2E8F0;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Title
        title = QLabel("🔍 Why was this activity recorded?")
        title.setStyleSheet("font-size: 16px; font-weight: 700; color: #38BDF8;")
        layout.addWidget(title)

        # Content blocks
        sections = [
            ("WHAT HAPPENED?", breakdown.get("what", "")),
            ("WHO CAUSED IT?", breakdown.get("who", "")),
            ("WHERE?", breakdown.get("where", "")),
            ("WHY IS THIS RELEVANT?", breakdown.get("why", "")),
            ("RECOMMENDED ACTION", breakdown.get("recommendation", "")),
        ]

        for sec_title, sec_content in sections:
            lbl_title = QLabel(sec_title)
            lbl_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #94A3B8; letter-spacing: 0.5px;")
            layout.addWidget(lbl_title)

            lbl_desc = QLabel(sec_content)
            lbl_desc.setWordWrap(True)
            lbl_desc.setStyleSheet("font-size: 13px; color: #F8FAFC; background-color: #1E293B; padding: 10px 12px; border-radius: 6px;")
            layout.addWidget(lbl_desc)

        # Close button
        btn_close = QPushButton("Close")
        btn_close.setProperty("class", "PrimaryBtn")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)

class EventCardWidget(QFrame):
    """Visualizes an individual telemetry event with Simple vs Technical view toggle."""

    def __init__(self, event: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.event_data = event
        self.setProperty("class", "Card")
        self._init_ui()

    def _init_ui(self) -> None:
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(16, 12, 16, 12)
        self.main_layout.setSpacing(8)

        # Top row: Time + App Name + Severity Badge + 'Why?' button
        top_row = QHBoxLayout()

        time_str = str(self.event_data.get("timestamp", ""))[-8:] if self.event_data.get("timestamp") else "Just now"
        lbl_time = QLabel(time_str)
        lbl_time.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 600;")
        top_row.addWidget(lbl_time)

        app_name = self.event_data.get("application") or self.event_data.get("process_name") or "Application"
        lbl_app = QLabel(f"•  {app_name}")
        lbl_app.setStyleSheet("color: #38BDF8; font-weight: 700; font-size: 13px;")
        top_row.addWidget(lbl_app)

        top_row.addStretch()

        # Severity Badge
        severity = self.event_data.get("severity", "Low")
        lbl_badge = QLabel(severity.upper())
        if severity == "Critical":
            lbl_badge.setStyleSheet("background-color: #7F1D1D; color: #F87171; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px;")
        elif severity == "High":
            lbl_badge.setStyleSheet("background-color: #831843; color: #F472B6; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px;")
        elif severity == "Medium":
            lbl_badge.setStyleSheet("background-color: #78350F; color: #FBBF24; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px;")
        else:
            lbl_badge.setStyleSheet("background-color: #064E3B; color: #34D399; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px;")
        top_row.addWidget(lbl_badge)

        # Why? button
        btn_why = QPushButton("Why?")
        btn_why.setProperty("class", "WhyBtn")
        btn_why.clicked.connect(self._open_why_dialog)
        top_row.addWidget(btn_why)

        self.main_layout.addLayout(top_row)

        # Middle: Simple Human-Readable Description
        explanation = self.event_data.get("explanation")
        if not explanation:
            explanation = ExplainEngine.generate_simple_summary(
                self.event_data.get("event_type", ""),
                app_name,
                self.event_data.get("action", ""),
                self.event_data.get("target"),
            )

        lbl_summary = QLabel(explanation)
        lbl_summary.setWordWrap(True)
        lbl_summary.setStyleSheet("color: #F1F5F9; font-size: 13px; font-weight: 500;")
        self.main_layout.addWidget(lbl_summary)

        # Technical Details Container (Initially collapsed)
        self.tech_container = QWidget()
        tech_layout = QVBoxLayout(self.tech_container)
        tech_layout.setContentsMargins(8, 8, 8, 8)

        tech_text = QTextEdit()
        tech_text.setReadOnly(True)
        tech_text.setFixedHeight(80)
        tech_text.setStyleSheet("background-color: #090D16; border: 1px solid #1E293B; color: #94A3B8; font-family: Consolas, monospace; font-size: 11px; border-radius: 6px;")

        # Format technical data
        tech_data = {
            "PID": self.event_data.get("process_id"),
            "Event": self.event_data.get("event_type"),
            "Action": self.event_data.get("action"),
            "Target": self.event_data.get("target"),
            "RiskScore": f"{self.event_data.get('risk_score', 0)}/100",
            "Details": self.event_data.get("technical_details"),
        }
        tech_text.setText(json.dumps(tech_data, indent=2))
        tech_layout.addWidget(tech_text)

        self.tech_container.setVisible(False)
        self.main_layout.addWidget(self.tech_container)

        # Bottom row: Toggle Technical View
        bottom_row = QHBoxLayout()
        self.btn_toggle_tech = QPushButton("▾ Show technical details")
        self.btn_toggle_tech.setStyleSheet("color: #64748B; font-size: 11px; background: transparent; border: none; text-align: left;")
        self.btn_toggle_tech.clicked.connect(self._toggle_technical_details)
        bottom_row.addWidget(self.btn_toggle_tech)
        bottom_row.addStretch()

        self.main_layout.addLayout(bottom_row)

    def _toggle_technical_details(self) -> None:
        is_visible = self.tech_container.isVisible()
        self.tech_container.setVisible(not is_visible)
        self.btn_toggle_tech.setText("▴ Hide technical details" if not is_visible else "▾ Show technical details")

    def _open_why_dialog(self) -> None:
        breakdown = ExplainEngine.generate_why_breakdown(self.event_data)
        dlg = WhyDialog(breakdown, parent=self)
        dlg.exec()
