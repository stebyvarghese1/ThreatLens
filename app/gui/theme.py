"""Cybersecurity Dark Theme (QSS) for ThreatLens."""

THEME_QSS = """
/* Global Window Styling */
QMainWindow, QWidget {
    background-color: #0A0D14;
    color: #F0F6FC;
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}

/* Sidebar Navigation */
#SidebarWidget {
    background-color: #10141D;
    border-right: 1px solid #1E2638;
    min-width: 220px;
    max-width: 220px;
}

#SidebarTitle {
    color: #38BDF8;
    font-size: 18px;
    font-weight: 700;
    padding: 20px 16px 4px 16px;
    letter-spacing: 0.5px;
}

#SidebarSubtitle {
    color: #64748B;
    font-size: 11px;
    padding: 0px 16px 20px 16px;
}

/* Navigation Buttons */
QPushButton.NavBtn {
    text-align: left;
    padding: 12px 18px;
    margin: 3px 10px;
    border-radius: 8px;
    background-color: transparent;
    color: #94A3B8;
    font-size: 13px;
    font-weight: 500;
    border: none;
}

QPushButton.NavBtn:hover {
    background-color: #1A2234;
    color: #F1F5F9;
}

QPushButton.NavBtn:checked, QPushButton.NavBtn.active {
    background-color: #0369A1;
    color: #FFFFFF;
    font-weight: 600;
}

/* Content Area */
#ContentArea {
    background-color: #0A0D14;
    padding: 24px;
}

/* Cards & Containers */
QFrame.Card {
    background-color: #121826;
    border: 1px solid #1E293B;
    border-radius: 12px;
    padding: 18px;
}

QFrame.HeroCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #111827, stop:1 #1E293B);
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 22px;
}

/* Section Headings */
QLabel.ViewHeader {
    font-size: 22px;
    font-weight: 700;
    color: #F8FAFC;
    margin-bottom: 4px;
}

QLabel.ViewSubheader {
    font-size: 13px;
    color: #64748B;
    margin-bottom: 16px;
}

QLabel.CardTitle {
    font-size: 14px;
    font-weight: 600;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

QLabel.StatValue {
    font-size: 28px;
    font-weight: 700;
    color: #F8FAFC;
    margin-top: 4px;
}

/* Buttons */
QPushButton.PrimaryBtn {
    background-color: #0284C7;
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-weight: 600;
    font-size: 13px;
}

QPushButton.PrimaryBtn:hover {
    background-color: #0369A1;
}

QPushButton.SecondaryBtn {
    background-color: #1E293B;
    color: #E2E8F0;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: 500;
}

QPushButton.SecondaryBtn:hover {
    background-color: #334155;
}

QPushButton.WhyBtn {
    background-color: #1E1B4B;
    color: #A5B4FC;
    border: 1px solid #3730A3;
    border-radius: 6px;
    padding: 5px 12px;
    font-weight: 600;
    font-size: 11px;
}

QPushButton.WhyBtn:hover {
    background-color: #312E81;
    color: #C7D2FE;
}

/* Badges */
QLabel.BadgeSafe {
    background-color: #064E3B;
    color: #34D399;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeWarning {
    background-color: #78350F;
    color: #FBBF24;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeDanger {
    background-color: #7F1D1D;
    color: #F87171;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
}

/* Tables and Trees */
QTableWidget, QTreeWidget {
    background-color: #101623;
    border: 1px solid #1E293B;
    border-radius: 10px;
    gridline-color: #1E293B;
    outline: none;
    color: #E2E8F0;
    font-size: 12px;
}

QHeaderView::section {
    background-color: #0E131F;
    color: #94A3B8;
    padding: 10px 14px;
    border: none;
    border-bottom: 1px solid #1E293B;
    font-weight: 600;
    font-size: 12px;
}

QTableWidget::item, QTreeWidget::item {
    padding: 8px 12px;
    border-bottom: 1px solid #161F30;
}

QTableWidget::item:selected, QTreeWidget::item:selected {
    background-color: #1E293B;
    color: #38BDF8;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: #0A0D14;
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background-color: #1E293B;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #334155;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Inputs & Search */
QLineEdit {
    background-color: #101623;
    border: 1px solid #1E293B;
    border-radius: 8px;
    padding: 8px 14px;
    color: #F1F5F9;
    font-size: 13px;
}

QLineEdit:focus {
    border: 1px solid #0284C7;
}

/* Dialogs */
QDialog {
    background-color: #0E131F;
}
"""
