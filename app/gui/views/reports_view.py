"""Security Reports View."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

class ReportsView(QWidget):
    """View and export daily/weekly endpoint transparency reports."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._init_ui()
        self.generate_report()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        hdr = QVBoxLayout()
        title = QLabel("Security & Transparency Reports")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Generate summaries of system health, active threats, and network interactions.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr.addWidget(title)
        hdr.addWidget(subtitle)
        layout.addLayout(hdr)

        ctrl_row = QHBoxLayout()
        btn_refresh = QPushButton("Regenerate Daily Report")
        btn_refresh.setProperty("class", "PrimaryBtn")
        btn_refresh.clicked.connect(self.generate_report)
        ctrl_row.addWidget(btn_refresh)

        btn_export = QPushButton("Export Report to Markdown")
        btn_export.setProperty("class", "SecondaryBtn")
        btn_export.clicked.connect(self.export_report)
        ctrl_row.addWidget(btn_export)

        ctrl_row.addStretch()
        layout.addLayout(ctrl_row)

        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setStyleSheet("""
            QTextEdit {
                background-color: #101623;
                border: 1px solid #1E293B;
                border-radius: 10px;
                padding: 18px;
                color: #F1F5F9;
                font-family: Consolas, 'Segoe UI', monospace;
                font-size: 13px;
                line-height: 1.6;
            }
        """)
        layout.addWidget(self.report_text)

    def generate_report(self) -> None:
        rep = self.engine.reports.generate_daily_report()
        self.report_text.setMarkdown(rep)

    def export_report(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Security Report", "ThreatLens_Report.md", "Markdown Files (*.md);;Text Files (*.txt)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.report_text.toPlainText())
                QMessageBox.information(self, "Exported", f"Security report successfully saved to:\n{path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Error", f"Failed to save report: {e}")
