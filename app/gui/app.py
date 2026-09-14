"""Application lifecycle and tray setup."""
import sys
from typing import Tuple
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon
from app.gui.assets import get_app_icon
from app.gui.main_window import MainWindow
from app.gui.theme import THEME_QSS

def create_application(engine) -> Tuple[QApplication, MainWindow]:
    """Initialize QApplication, apply dark theme, setup system tray, and launch main window."""
    # Register Windows AppUserModelID so Windows Taskbar displays the ThreatLens icon
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("threatlens.security.endpoint.1.0")
    except Exception:
        pass

    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    app.setApplicationName("ThreatLens")
    app.setStyleSheet(THEME_QSS)

    app_icon = get_app_icon()
    if not app_icon.isNull():
        app.setWindowIcon(app_icon)

    window = MainWindow(engine)
    if not app_icon.isNull():
        window.setWindowIcon(app_icon)

    # Windows System Tray Integration
    if QSystemTrayIcon.isSystemTrayAvailable():
        tray = QSystemTrayIcon(window)
        tray.setIcon(app_icon if not app_icon.isNull() else window.windowIcon())
        tray.setToolTip("ThreatLens — Protected")

        tray_menu = QMenu()
        act_open = QAction("Open ThreatLens", tray_menu)
        act_open.triggered.connect(window.showNormal)
        tray_menu.addAction(act_open)

        act_scan = QAction("Run Quick Scan", tray_menu)
        act_scan.triggered.connect(lambda: (window.showNormal(), window._switch_view(6), window.view_security._start_quick_scan()))
        tray_menu.addAction(act_scan)

        tray_menu.addSeparator()

        act_quit = QAction("Exit ThreatLens", tray_menu)
        act_quit.triggered.connect(app.quit)
        tray_menu.addAction(act_quit)

        tray.setContextMenu(tray_menu)
        tray.activated.connect(lambda reason: window.showNormal() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        tray.show()
        window._tray = tray

    return app, window

