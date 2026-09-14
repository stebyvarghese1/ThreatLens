"""Network Telemetry and Connection Explainability View."""
from typing import Any, Dict, List
from PySide6.QtCore import Qt, QTimer
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

class NetworkView(QWidget):
    """Visualizes live network socket connections and explains endpoints."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._init_ui()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_connections)
        self.timer.start(3000)
        self.refresh_connections()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        hdr = QVBoxLayout()
        title = QLabel("Network Activity & Connections")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Real-time outbound socket mapping and human-readable endpoint explanations.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr.addWidget(title)
        hdr.addWidget(subtitle)
        layout.addLayout(hdr)

        ctrl_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by application, IP, port, or protocol...")
        self.search_input.textChanged.connect(self._filter_table)
        ctrl_row.addWidget(self.search_input, stretch=1)

        btn_refresh = QPushButton("Refresh Now")
        btn_refresh.setProperty("class", "SecondaryBtn")
        btn_refresh.clicked.connect(self.refresh_connections)
        ctrl_row.addWidget(btn_refresh)
        layout.addLayout(ctrl_row)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Application", "Remote Endpoint", "Protocol", "Status", "Risk", "What is this connection?"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

    def refresh_connections(self) -> None:
        conns = self.engine.network_monitor.get_active_connections()
        self.table.setRowCount(len(conns))

        for row, c in enumerate(conns):
            item_app = QTableWidgetItem(c.get("process_name", "System"))
            item_end = QTableWidgetItem(f"{c.get('remote_address')}:{c.get('remote_port')}")
            item_proto = QTableWidgetItem(c.get("protocol", "TCP"))
            item_status = QTableWidgetItem(c.get("status", "ESTABLISHED"))

            risk = c.get("risk_level", "Low")
            item_risk = QTableWidgetItem(risk)
            if risk == "High":
                item_risk.setForeground(Qt.GlobalColor.red)
            elif risk == "Medium":
                item_risk.setForeground(Qt.GlobalColor.yellow)
            else:
                item_risk.setForeground(Qt.GlobalColor.green)

            item_exp = QTableWidgetItem(c.get("explanation", ""))

            self.table.setItem(row, 0, item_app)
            self.table.setItem(row, 1, item_end)
            self.table.setItem(row, 2, item_proto)
            self.table.setItem(row, 3, item_status)
            self.table.setItem(row, 4, item_risk)
            self.table.setItem(row, 5, item_exp)

        self._filter_table()

    def _filter_table(self) -> None:
        q = self.search_input.text().strip().lower()
        for r in range(self.table.rowCount()):
            row_text = " ".join([
                self.table.item(r, c).text().lower() for c in range(self.table.columnCount()) if self.table.item(r, c)
            ])
            self.table.setRowHidden(r, bool(q and q not in row_text))
