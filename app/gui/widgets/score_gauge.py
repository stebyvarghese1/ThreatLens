"""Security Score Display Widget."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

class ScoreGaugeWidget(QFrame):
    """Visualizes the 0-100 Endpoint Security Score with explainable drop factors."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ScoreGaugeWidget")
        self.setProperty("class", "HeroCard")
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        # Header row: Status badge + "Security Score" label
        header_row = QHBoxLayout()
        self.label_title = QLabel("ENDPOINT SECURITY SCORE")
        self.label_title.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 700; letter-spacing: 1px;")

        self.badge_status = QLabel("● Safe")
        self.badge_status.setProperty("class", "BadgeSafe")
        self.badge_status.setStyleSheet(
            "background-color: #064E3B; color: #34D399; font-weight: 600; font-size: 11px; padding: 4px 10px; border-radius: 6px;"
        )

        header_row.addWidget(self.label_title)
        header_row.addStretch()
        header_row.addWidget(self.badge_status)
        layout.addLayout(header_row)

        # Main Score Row: Giant 87 / 100
        score_row = QHBoxLayout()
        self.label_score = QLabel("100")
        self.label_score.setStyleSheet("color: #10B981; font-size: 48px; font-weight: 800;")
        
        self.label_max = QLabel("/ 100")
        self.label_max.setStyleSheet("color: #64748B; font-size: 20px; font-weight: 600; margin-bottom: 8px;")

        score_row.addWidget(self.label_score)
        score_row.addWidget(self.label_max, alignment=Qt.AlignmentFlag.AlignBottom)
        score_row.addStretch()
        layout.addLayout(score_row)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1E293B;
                border-radius: 4px;
                border: none;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10B981);
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Explainable Subtext / Reasons
        self.label_reason = QLabel("Your computer looks safe. No anomalous behavior detected.")
        self.label_reason.setStyleSheet("color: #CBD5E1; font-size: 13px; font-weight: 500;")
        self.label_reason.setWordWrap(True)
        layout.addWidget(self.label_reason)

    def update_score(self, score_data: dict) -> None:
        """Update widget with new score calculation data."""
        score = score_data.get("score", 100)
        status_text = score_data.get("status_text", "Your computer looks safe")
        status_level = score_data.get("status_level", "Safe")
        color = score_data.get("status_color", "#10B981")
        deductions = score_data.get("deductions", [])

        self.label_score.setText(str(score))
        self.label_score.setStyleSheet(f"color: {color}; font-size: 48px; font-weight: 800;")
        self.progress_bar.setValue(score)

        if status_level == "Safe":
            self.badge_status.setText("● Safe")
            self.badge_status.setStyleSheet("background-color: #064E3B; color: #34D399; font-weight: 600; padding: 4px 10px; border-radius: 6px;")
            self.progress_bar.setStyleSheet("""
                QProgressBar { background-color: #1E293B; border-radius: 4px; border: none; }
                QProgressBar::chunk { background: #10B981; border-radius: 4px; }
            """)
        elif status_level == "Attention":
            self.badge_status.setText("● Attention")
            self.badge_status.setStyleSheet("background-color: #78350F; color: #FBBF24; font-weight: 600; padding: 4px 10px; border-radius: 6px;")
            self.progress_bar.setStyleSheet("""
                QProgressBar { background-color: #1E293B; border-radius: 4px; border: none; }
                QProgressBar::chunk { background: #F59E0B; border-radius: 4px; }
            """)
        else:
            self.badge_status.setText("● Threat Active")
            self.badge_status.setStyleSheet("background-color: #7F1D1D; color: #F87171; font-weight: 600; padding: 4px 10px; border-radius: 6px;")
            self.progress_bar.setStyleSheet("""
                QProgressBar { background-color: #1E293B; border-radius: 4px; border: none; }
                QProgressBar::chunk { background: #EF4444; border-radius: 4px; }
            """)

        # Display primary deduction reason if any
        if deductions:
            top_reason = deductions[0].get("reason", "")
            penalty = deductions[0].get("penalty", 0)
            self.label_reason.setText(f"{status_text} • -{penalty} pts: {top_reason}")
        else:
            self.label_reason.setText(status_text)
