"""'Ask ThreatLens' Interactive Natural-Language Security Console View."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

class AssistantView(QWidget):
    """Interactive offline security assistant providing human-readable explanations of local telemetry."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        hdr = QVBoxLayout()
        title = QLabel("Ask ThreatLens")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Ask questions about what happened on your PC, network activity, or why an alert was flagged.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr.addWidget(title)
        hdr.addWidget(subtitle)
        layout.addLayout(hdr)

        # Suggestion chips row
        chips_row = QHBoxLayout()
        chips_row.setSpacing(8)

        suggestions = [
            "What happened on my computer today?",
            "What applications connected to the internet?",
            "Why is my laptop slow?",
            "What changed recently?",
        ]
        for s in suggestions:
            btn_chip = QPushButton(s)
            btn_chip.setStyleSheet("""
                QPushButton {
                    background-color: #161F30;
                    color: #38BDF8;
                    border: 1px solid #1E293B;
                    border-radius: 14px;
                    padding: 5px 12px;
                    font-size: 11px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background-color: #1E293B;
                    color: #7DD3FC;
                }
            """)
            btn_chip.clicked.connect(lambda _, txt=s: self._send_query(txt))
            chips_row.addWidget(btn_chip)

        chips_row.addStretch()
        layout.addLayout(chips_row)

        # Chat display
        self.chat_display = QTextBrowser()
        self.chat_display.setStyleSheet("""
            QTextBrowser {
                background-color: #101623;
                border: 1px solid #1E293B;
                border-radius: 10px;
                padding: 16px;
                color: #F1F5F9;
                font-size: 13px;
                line-height: 1.5;
            }
        """)
        self.chat_display.setOpenExternalLinks(False)
        layout.addWidget(self.chat_display, stretch=1)

        # Initial greeting
        self._append_message("ThreatLens Assistant", "Hello! I analyze your local computer telemetry to explain what's happening in plain English. Click one of the questions above or type your question below.")

        # Input row
        input_row = QHBoxLayout()
        input_row.setSpacing(10)

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Ask ThreatLens a question (e.g. 'What happened today?' or search an app name)...")
        self.input_field.returnPressed.connect(self._handle_input)
        input_row.addWidget(self.input_field, stretch=1)

        btn_ask = QPushButton("Ask Assistant")
        btn_ask.setProperty("class", "PrimaryBtn")
        btn_ask.clicked.connect(self._handle_input)
        input_row.addWidget(btn_ask)

        layout.addLayout(input_row)

    def _handle_input(self) -> None:
        txt = self.input_field.text().strip()
        if not txt:
            return
        self.input_field.clear()
        self._send_query(txt)

    def _send_query(self, query: str) -> None:
        self._append_message("You", query)
        answer = self.engine.assistant.ask(query)
        self._append_message("ThreatLens Assistant", answer)

    def _append_message(self, sender: str, markdown_text: str) -> None:
        color = "#38BDF8" if sender == "ThreatLens Assistant" else "#10B981"
        html_msg = f"<div style='margin-bottom: 14px;'><b style='color: {color}; font-size: 13px;'>{sender}</b><br><div style='margin-top: 4px; color: #E2E8F0;'>{markdown_text.replace(chr(10), '<br>')}</div></div>"
        self.chat_display.append(html_msg)
        self.chat_display.verticalScrollBar().setValue(self.chat_display.verticalScrollBar().maximum())
