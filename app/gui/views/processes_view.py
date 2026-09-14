"""Processes View with Process Tree and Risk Inspection."""
from typing import Any, Dict, List
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

class ProcessesView(QWidget):
    """Visualizes active processes, parent-child hierarchies, and risk ratings."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._init_ui()

        # Polling timer to refresh active processes
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_processes)
        self.timer.start(3000)
        self.refresh_processes()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        hdr = QVBoxLayout()
        title = QLabel("Process Tree & Hierarchy")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("Inspect active applications, child process spawns, and risk ratings.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr.addWidget(title)
        hdr.addWidget(subtitle)
        layout.addLayout(hdr)

        # Controls Row
        ctrl_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter processes by name, PID, or path...")
        self.search_input.textChanged.connect(self._filter_tree)
        ctrl_row.addWidget(self.search_input, stretch=1)

        btn_refresh = QPushButton("Refresh Now")
        btn_refresh.setProperty("class", "SecondaryBtn")
        btn_refresh.clicked.connect(self.refresh_processes)
        ctrl_row.addWidget(btn_refresh)

        self.btn_terminate = QPushButton("End Process")
        self.btn_terminate.setStyleSheet("background-color: #7F1D1D; color: #F87171; border: 1px solid #991B1B; padding: 8px 16px; border-radius: 6px; font-weight: 600;")
        self.btn_terminate.clicked.connect(self._terminate_selected_process)
        ctrl_row.addWidget(self.btn_terminate)

        layout.addLayout(ctrl_row)

        # Process Tree Widget
        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["Process Name", "PID", "Parent PID", "Risk Score", "Executable Path"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.tree)

    def refresh_processes(self) -> None:
        """Fetch and populate process tree."""
        roots = self.engine.process_monitor.get_process_tree()
        self.tree.clear()

        for root in roots:
            self._add_tree_node(None, root)

        self._filter_tree()

    def _add_tree_node(self, parent_item: QTreeWidgetItem, proc: Dict[str, Any]) -> None:
        item = QTreeWidgetItem()
        item.setText(0, proc.get("name", "Unknown"))
        item.setText(1, str(proc.get("pid", "")))
        item.setText(2, str(proc.get("ppid", "")))

        risk = proc.get("risk_score", 0)
        item.setText(3, f"{risk} / 100")
        if risk >= 60:
            item.setForeground(3, Qt.GlobalColor.red)
        elif risk >= 30:
            item.setForeground(3, Qt.GlobalColor.yellow)
        else:
            item.setForeground(3, Qt.GlobalColor.green)

        item.setText(4, proc.get("exe") or "")
        item.setData(0, Qt.ItemDataRole.UserRole, proc.get("pid"))

        if parent_item is None:
            self.tree.addTopLevelItem(item)
        else:
            parent_item.addChild(item)

        for child in proc.get("children", []):
            self._add_tree_node(item, child)

    def _filter_tree(self) -> None:
        query = self.search_input.text().strip().lower()
        if not query:
            self._set_item_visibility(self.tree.invisibleRootItem(), True)
            return

        def match_and_show(item: QTreeWidgetItem) -> bool:
            name = item.text(0).lower()
            pid = item.text(1).lower()
            path = item.text(4).lower()
            self_matches = query in name or query in pid or query in path

            child_matches = False
            for i in range(item.childCount()):
                if match_and_show(item.child(i)):
                    child_matches = True

            visible = self_matches or child_matches
            item.setHidden(not visible)
            if visible and child_matches:
                item.setExpanded(True)
            return visible

        for i in range(self.tree.topLevelItemCount()):
            match_and_show(self.tree.topLevelItem(i))

    def _set_item_visibility(self, item: QTreeWidgetItem, visible: bool) -> None:
        for i in range(item.childCount()):
            child = item.child(i)
            child.setHidden(not visible)
            self._set_item_visibility(child, visible)

    def _terminate_selected_process(self) -> None:
        curr = self.tree.currentItem()
        if not curr:
            QMessageBox.information(self, "Select Process", "Please select a process from the tree first.")
            return

        pid = curr.data(0, Qt.ItemDataRole.UserRole)
        name = curr.text(0)

        reply = QMessageBox.question(
            self,
            "Confirm Process Termination",
            f"Are you sure you want to terminate {name} (PID: {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                import psutil
                p = psutil.Process(pid)
                p.terminate()
                QMessageBox.information(self, "Success", f"Process {name} (PID: {pid}) has been terminated.")
                self.refresh_processes()
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to terminate process: {e}")
