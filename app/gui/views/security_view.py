"""Security Center and Scanner View."""
import os
from typing import Any, Dict, List
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from app.config import MONITORED_PATHS
from app.detection.scanner import SecurityScanner

class _ScanWorker(QThread):
    progress = Signal(int, str)
    finished = Signal(list)

    def __init__(self, target_folders: List[str]):
        super().__init__()
        self.target_folders = target_folders

    def run(self):
        found_threats = []
        files_to_scan = []

        for folder in self.target_folders:
            if os.path.exists(folder):
                for root, _, files in os.walk(folder):
                    for f in files:
                        files_to_scan.append(os.path.join(root, f))
                        if len(files_to_scan) >= 500:
                            break

        total = len(files_to_scan)
        for i, file_path in enumerate(files_to_scan):
            pct = int(((i + 1) / max(1, total)) * 100)
            self.progress.emit(pct, f"Scanning: {os.path.basename(file_path)}")

            res = SecurityScanner.scan_file(file_path)
            if res.get("is_threat"):
                found_threats.append({
                    "file": file_path,
                    "risk": f"{res.get('risk_score')}/100",
                    "threat": res.get("threat_name"),
                    "indicators": res.get("indicators", []),
                })

        self.finished.emit(found_threats)


class SecurityView(QWidget):
    """Protection status, on-demand scanning, and quarantine controls."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._scan_worker = None
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # Header
        hdr = QVBoxLayout()
        title = QLabel("Security Center")
        title.setProperty("class", "ViewHeader")
        subtitle = QLabel("System shield modules, on-demand scanning, and quarantine.")
        subtitle.setProperty("class", "ViewSubheader")
        hdr.addWidget(title)
        hdr.addWidget(subtitle)
        layout.addLayout(hdr)

        # Protection Shields Grid
        shields_grid = QGridLayout()
        shields_grid.setSpacing(12)

        shields_grid.addWidget(self._create_shield_card("Real-Time Behavioral Shield", "Continuous anomaly detection", True), 0, 0)
        shields_grid.addWidget(self._create_shield_card("File & Downloads Guard", "Active folder inspection", True), 0, 1)
        shields_grid.addWidget(self._create_shield_card("Ransomware Containment", "Rapid mass-file heuristic", True), 1, 0)
        shields_grid.addWidget(self._create_shield_card("Persistence Watcher", "Registry & Startup tracking", True), 1, 1)

        layout.addLayout(shields_grid)

        # Scanner Card
        scan_card = QFrame()
        scan_card.setProperty("class", "Card")
        scan_layout = QVBoxLayout(scan_card)
        scan_layout.setContentsMargins(18, 16, 18, 16)
        scan_layout.setSpacing(12)

        scan_hdr = QHBoxLayout()
        lbl_scan_title = QLabel("MALWARE & ANOMALY SCANNER")
        lbl_scan_title.setProperty("class", "CardTitle")
        scan_hdr.addWidget(lbl_scan_title)
        scan_hdr.addStretch()

        self.btn_quick_scan = QPushButton("Run Quick Scan")
        self.btn_quick_scan.setProperty("class", "PrimaryBtn")
        self.btn_quick_scan.clicked.connect(self._start_quick_scan)
        scan_hdr.addWidget(self.btn_quick_scan)

        self.btn_custom_scan = QPushButton("Custom Folder Scan")
        self.btn_custom_scan.setProperty("class", "SecondaryBtn")
        self.btn_custom_scan.clicked.connect(self._start_custom_scan)
        scan_hdr.addWidget(self.btn_custom_scan)

        scan_layout.addLayout(scan_hdr)

        self.scan_progress = QProgressBar()
        self.scan_progress.setFixedHeight(8)
        self.scan_progress.setValue(0)
        self.scan_progress.setTextVisible(False)
        self.scan_progress.setVisible(False)
        scan_layout.addWidget(self.scan_progress)

        self.lbl_scan_status = QLabel("System idle. Run a scan to inspect key download and desktop paths.")
        self.lbl_scan_status.setStyleSheet("color: #94A3B8; font-size: 12px;")
        scan_layout.addWidget(self.lbl_scan_status)

        layout.addWidget(scan_card)

        # Quarantine Section
        quar_hdr_row = QHBoxLayout()
        quar_hdr = QLabel("QUARANTINED ITEMS")
        quar_hdr.setProperty("class", "CardTitle")
        quar_hdr_row.addWidget(quar_hdr)
        quar_hdr_row.addStretch()

        btn_restore = QPushButton("Restore Selected")
        btn_restore.setProperty("class", "SecondaryBtn")
        btn_restore.clicked.connect(self._restore_quarantine)
        quar_hdr_row.addWidget(btn_restore)

        btn_del = QPushButton("Delete Permanently")
        btn_del.setStyleSheet("background-color: #7F1D1D; color: #F87171; border: 1px solid #991B1B; padding: 6px 14px; border-radius: 6px; font-weight: 600;")
        btn_del.clicked.connect(self._delete_quarantine)
        quar_hdr_row.addWidget(btn_del)

        layout.addLayout(quar_hdr_row)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(["File Name", "Original Path", "Reason", "Quarantined At"])

        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.quarantine_table, stretch=1)
        self.refresh_quarantine()


    def _create_shield_card(self, name: str, desc: str, active: bool) -> QFrame:
        card = QFrame()
        card.setProperty("class", "Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)

        row = QHBoxLayout()
        lbl_name = QLabel(name)
        lbl_name.setStyleSheet("font-weight: 700; color: #F8FAFC; font-size: 13px;")

        badge = QLabel("● Active" if active else "● Disabled")
        badge.setStyleSheet("color: #34D399; font-weight: 600; font-size: 11px;" if active else "color: #EF4444; font-weight: 600; font-size: 11px;")

        row.addWidget(lbl_name)
        row.addStretch()
        row.addWidget(badge)
        layout.addLayout(row)

        lbl_desc = QLabel(desc)
        lbl_desc.setStyleSheet("color: #64748B; font-size: 11px;")
        layout.addWidget(lbl_desc)
        return card

    def _start_quick_scan(self) -> None:
        self._run_scan(MONITORED_PATHS)

    def _start_custom_scan(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self._run_scan([folder])

    def _run_scan(self, paths: List[str]) -> None:
        self.btn_quick_scan.setEnabled(False)
        self.btn_custom_scan.setEnabled(False)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.lbl_scan_status.setText("Initializing security scan...")

        self._scan_worker = _ScanWorker(paths)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.start()

    def _on_scan_progress(self, pct: int, status: str) -> None:
        self.scan_progress.setValue(pct)
        self.lbl_scan_status.setText(status)

    def _on_scan_finished(self, threats: List[Dict[str, Any]]) -> None:
        self.scan_progress.setVisible(False)
        self.btn_quick_scan.setEnabled(True)
        self.btn_custom_scan.setEnabled(True)

        if threats:
            self.lbl_scan_status.setText(f"Scan complete. ⚠️ {len(threats)} potentially suspicious files detected!")
            reply = QMessageBox.question(
                self,
                "Threats Detected",
                f"ThreatLens detected {len(threats)} suspicious items. Would you like to isolate and quarantine them now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                for t in threats:
                    self.engine.quarantine.quarantine_file(
                        t["file"], reason=f"Detected during scan: {t['threat']}", detection_source="Scanner"
                    )
                self.refresh_quarantine()
                QMessageBox.information(self, "Quarantined", "Offending files have been encrypted and moved to the Quarantine Vault.")
        else:
            self.lbl_scan_status.setText("Scan complete. ✓ No malicious or suspicious items detected.")

    def refresh_quarantine(self) -> None:
        items = [i for i in self.engine.quarantine.list_quarantined_items() if i.get("status") == "QUARANTINED"]
        self.quarantine_table.setRowCount(len(items))
        for row, item in enumerate(items):
            orig = item.get("original_path", "")
            fname = os.path.basename(orig)
            item_name = QTableWidgetItem(fname)
            item_name.setData(Qt.ItemDataRole.UserRole, item.get("id"))

            self.quarantine_table.setItem(row, 0, item_name)
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(orig))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(item.get("reason", "Malicious")))
            self.quarantine_table.setItem(row, 3, QTableWidgetItem(str(item.get("quarantined_at", ""))[-8:]))

    def _restore_quarantine(self) -> None:
        row = self.quarantine_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select Item", "Please select a quarantined item to restore.")
            return

        q_id = self.quarantine_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if self.engine.quarantine.restore_file(q_id):
            QMessageBox.information(self, "Restored", "File has been restored to its original location.")
            self.refresh_quarantine()
        else:
            QMessageBox.warning(self, "Error", "Failed to restore file from quarantine vault.")

    def _delete_quarantine(self) -> None:
        row = self.quarantine_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select Item", "Please select a quarantined item to permanently delete.")
            return

        q_id = self.quarantine_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            "Are you sure you want to permanently delete this file? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.engine.quarantine.delete_permanently(q_id)
            self.refresh_quarantine()

