"""Application Profiles and Behavioral Trust Meter View."""
import json
from typing import Any, Dict, List
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

class ApplicationsView(QWidget):
    """Visualizes application baseline profiles, trust scores, and observed behavioral habits."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._init_ui()
        self.refresh_profiles()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        hdr = QVBoxLayout()
        title = QLabel("Application Behavior Profiles & Trust")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Learned baseline behaviors, trust meters, and habit deviations.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr.addWidget(title)
        hdr.addWidget(subtitle)
        layout.addLayout(hdr)

        ctrl_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter applications by name or path...")
        self.search_input.textChanged.connect(self._filter_table)
        ctrl_row.addWidget(self.search_input, stretch=1)

        btn_trust = QPushButton("Mark as Trusted (Allow)")
        btn_trust.setProperty("class", "PrimaryBtn")
        btn_trust.clicked.connect(self._mark_trusted)
        ctrl_row.addWidget(btn_trust)

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setProperty("class", "SecondaryBtn")
        btn_refresh.clicked.connect(self.refresh_profiles)
        ctrl_row.addWidget(btn_refresh)

        layout.addLayout(ctrl_row)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Application", "Trust Score", "Rating", "Observed Habits", "Executable Path"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

    def refresh_profiles(self) -> None:
        profiles = self.engine.repository.get_app_profiles()

        # If empty initially, populate from active processes
        if not profiles:
            procs = self.engine.process_monitor.get_process_list()
            for p in procs[:25]:
                self.engine.profiler.profile_process(p)
            profiles = self.engine.repository.get_app_profiles()

        self.table.setRowCount(len(profiles))
        for row, p in enumerate(profiles):
            item_name = QTableWidgetItem(p.get("app_name", ""))
            score = p.get("trust_score", 70)
            item_score = QTableWidgetItem(f"{score}%")

            rating = "High Trust" if score >= 80 else ("Moderate" if score >= 50 else "Low / Untrusted")
            item_rating = QTableWidgetItem(rating)
            if score >= 80:
                item_score.setForeground(Qt.GlobalColor.green)
                item_rating.setForeground(Qt.GlobalColor.green)
            elif score >= 50:
                item_score.setForeground(Qt.GlobalColor.yellow)
                item_rating.setForeground(Qt.GlobalColor.yellow)
            else:
                item_score.setForeground(Qt.GlobalColor.red)
                item_rating.setForeground(Qt.GlobalColor.red)

            ports = json.loads(p.get("habitual_ports", "[]"))
            dirs = json.loads(p.get("habitual_dirs", "[]"))
            habits_desc = []
            if ports:
                habits_desc.append(f"Ports: {', '.join(map(str, ports))}")
            if dirs:
                habits_desc.append(f"Dirs: {', '.join(dirs)}")
            if not habits_desc:
                habits_desc.append("Standard local desktop execution")

            item_habits = QTableWidgetItem(" • ".join(habits_desc))
            item_path = QTableWidgetItem(p.get("exe_path") or "System Path")

            self.table.setItem(row, 0, item_name)
            self.table.setItem(row, 1, item_score)
            self.table.setItem(row, 2, item_rating)
            self.table.setItem(row, 3, item_habits)
            self.table.setItem(row, 4, item_path)

        self._filter_table()

    def _filter_table(self) -> None:
        q = self.search_input.text().strip().lower()
        for r in range(self.table.rowCount()):
            text = " ".join([self.table.item(r, c).text().lower() for c in range(self.table.columnCount()) if self.table.item(r, c)])
            self.table.setRowHidden(r, bool(q and q not in text))

    def _mark_trusted(self) -> None:
        curr_row = self.table.currentRow()
        if curr_row < 0:
            QMessageBox.information(self, "Select Application", "Please select an application to trust.")
            return

        app_name = self.table.item(curr_row, 0).text()
        self.engine.decisions.allow(app_name, reason="Whitelisted by user in Applications View")
        QMessageBox.information(
            self, "Application Trusted", f"'{app_name}' has been added to your trusted whitelist. Alerts from this app will be suppressed."
        )
        self.refresh_profiles()
