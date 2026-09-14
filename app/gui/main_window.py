"""Main Desktop Application Window for ThreatLens."""
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from app.gui.assets import get_app_icon, get_icon_path
from app.gui.views.dashboard_view import DashboardView
from app.gui.views.live_activity_view import LiveActivityView
from app.gui.views.processes_view import ProcessesView
from app.gui.views.network_view import NetworkView
from app.gui.views.applications_view import ApplicationsView
from app.gui.views.system_changes_view import SystemChangesView
from app.gui.views.security_view import SecurityView
from app.gui.views.assistant_view import AssistantView
from app.gui.views.reports_view import ReportsView
from app.gui.views.settings_view import SettingsView

class MainWindow(QMainWindow):
    """Main window with sidebar navigation and stacked workspace views."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.setWindowTitle("ThreatLens — Endpoint Visibility & Security")
        self.resize(1260, 820)
        self.setMinimumSize(1020, 680)

        app_icon = get_app_icon()
        if not app_icon.isNull():
            self.setWindowIcon(app_icon)

        self._init_ui()

    def _init_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        root_layout = QHBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Left Sidebar Navigation
        sidebar = QWidget()
        sidebar.setObjectName("SidebarWidget")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 16)
        sidebar_layout.setSpacing(2)

        # Brand header with official logo icon
        brand_container = QWidget()
        brand_layout = QHBoxLayout(brand_container)
        brand_layout.setContentsMargins(16, 20, 16, 4)
        brand_layout.setSpacing(10)

        icon_path = get_icon_path()
        if icon_path.exists():
            lbl_logo = QLabel()
            pix = QPixmap(str(icon_path)).scaled(
                34, 34, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            )
            lbl_logo.setPixmap(pix)
            brand_layout.addWidget(lbl_logo)

        lbl_brand = QLabel("ThreatLens")
        lbl_brand.setObjectName("SidebarTitle")
        lbl_brand.setStyleSheet("padding: 0px; font-size: 18px; font-weight: 700; color: #38BDF8;")
        brand_layout.addWidget(lbl_brand)
        brand_layout.addStretch()

        sidebar_layout.addWidget(brand_container)

        lbl_tagline = QLabel("Visibility • Control • Shield")
        lbl_tagline.setObjectName("SidebarSubtitle")
        sidebar_layout.addWidget(lbl_tagline)

        # Nav Buttons
        self.btn_group = QButtonGroup(self)
        self.btn_group.setExclusive(True)

        nav_items = [
            ("📊  Overview", 0),
            ("⚡  Live Activity", 1),
            ("🌲  Processes", 2),
            ("🌐  Network", 3),
            ("📦  Applications", 4),
            ("⏱️  System Changes", 5),
            ("🛡️  Security Center", 6),
            ("🤖  Ask ThreatLens", 7),
            ("📑  Reports", 8),
            ("⚙️  Settings", 9),
        ]

        self.nav_buttons = []
        for text, index in nav_items:
            btn = QPushButton(text)
            btn.setProperty("class", "NavBtn")
            btn.setCheckable(True)
            if index == 0:
                btn.setChecked(True)
            btn.clicked.connect(lambda _, idx=index: self._switch_view(idx))
            self.btn_group.addButton(btn, index)
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        # Bottom version badge
        lbl_ver = QLabel("ThreatLens v0.1.0\nProtected by Local Engine")
        lbl_ver.setStyleSheet("color: #475569; font-size: 10px; padding: 12px 16px; line-height: 1.4;")
        sidebar_layout.addWidget(lbl_ver)

        root_layout.addWidget(sidebar)

        # 2. Right Content Area (QStackedWidget)
        self.stack = QStackedWidget()
        self.stack.setObjectName("ContentArea")

        self.view_dashboard = DashboardView(self.engine)
        self.view_live = LiveActivityView(self.engine)
        self.view_processes = ProcessesView(self.engine)
        self.view_network = NetworkView(self.engine)
        self.view_applications = ApplicationsView(self.engine)
        self.view_system_changes = SystemChangesView(self.engine)
        self.view_security = SecurityView(self.engine)
        self.view_assistant = AssistantView(self.engine)
        self.view_reports = ReportsView(self.engine)
        self.view_settings = SettingsView(self.engine)

        self.stack.addWidget(self.view_dashboard)
        self.stack.addWidget(self.view_live)
        self.stack.addWidget(self.view_processes)
        self.stack.addWidget(self.view_network)
        self.stack.addWidget(self.view_applications)
        self.stack.addWidget(self.view_system_changes)
        self.stack.addWidget(self.view_security)
        self.stack.addWidget(self.view_assistant)
        self.stack.addWidget(self.view_reports)
        self.stack.addWidget(self.view_settings)

        root_layout.addWidget(self.stack, stretch=1)


    def _switch_view(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
