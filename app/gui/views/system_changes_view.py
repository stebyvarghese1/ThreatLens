"""System and Persistence Changes Timeline View."""
from typing import Any, Dict, List
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

class SystemChangesView(QWidget):
    """Timeline of Windows persistence mechanisms, startup additions, and registry changes."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._init_ui()
        self.refresh_changes()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        hdr = QVBoxLayout()
        title = QLabel("System Changes & Persistence Timeline")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Tracks startup additions, registry run modifications, and system configuration updates.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr.addWidget(title)
        hdr.addWidget(subtitle)
        layout.addLayout(hdr)

        ctrl_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search system changes...")
        self.search_input.textChanged.connect(self._filter_table)
        ctrl_row.addWidget(self.search_input, stretch=1)

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setProperty("class", "SecondaryBtn")
        btn_refresh.clicked.connect(self.refresh_changes)
        ctrl_row.addWidget(btn_refresh)
        layout.addLayout(ctrl_row)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Category", "Description", "Target / Command"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

    def refresh_changes(self) -> None:
        changes = self.engine.repository.get_recent_system_changes(limit=50)

        # Also pull active persistence entries if DB is fresh
        entries = self.engine.persistence_monitor.get_persistence_entries()

        total_rows = len(changes) + len(entries)
        self.table.setRowCount(total_rows)

        row = 0
        for c in changes:
            self.table.setItem(row, 0, QTableWidgetItem(str(c.get("timestamp", ""))[-8:]))
            self.table.setItem(row, 1, QTableWidgetItem(c.get("category", "SYSTEM")))
            self.table.setItem(row, 2, QTableWidgetItem(c.get("description", "")))
            self.table.setItem(row, 3, QTableWidgetItem(c.get("target") or ""))
            row += 1

        for e in entries:
            self.table.setItem(row, 0, QTableWidgetItem("Active"))
            self.table.setItem(row, 1, QTableWidgetItem("STARTUP_PERSISTENCE"))
            self.table.setItem(row, 2, QTableWidgetItem(f"Registered Auto-Start: {e['location'].split(chr(92))[-1]}"))
            self.table.setItem(row, 3, QTableWidgetItem(e.get("command", "")))
            row += 1

        self._filter_table()

    def _filter_table(self) -> None:
        q = self.search_input.text().strip().lower()
        for r in range(self.table.rowCount()):
            text = " ".join([self.table.item(r, c).text().lower() for c in range(self.table.columnCount()) if self.table.item(r, c)])
            self.table.setRowHidden(r, bool(q and q not in text))
