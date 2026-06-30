import sys

from PyQt6.QtCore import (
    Qt,
    QTimer
)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFontDatabase

# IMPORTANT
QApplication.setAttribute(
    Qt.ApplicationAttribute.AA_ShareOpenGLContexts
)

from ui.splash import SplashScreen
from ui.login import LoginWindow


app = QApplication(sys.argv)

app.setStyle("Fusion")

# =========================
# STYLESHEET
# =========================

app.setStyleSheet("""

/* =========================
   GLOBAL
   ========================= */

QWidget {
    background-color: #0F172A;
    color: #F8FAFC;
    font-family: "Segoe UI";
    font-size: 12px;
}

/* =========================
   LABELS
   ========================= */

QLabel {
    color: #F8FAFC;
    background: transparent;
}

/* =========================
   BUTTONS
   ========================= */

QPushButton {
    background-color: #2563EB;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 8px 14px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #3B82F6;
}

QPushButton:pressed {
    background-color: #1D4ED8;
}

/* =========================
   LISTS
   ========================= */

QListWidget {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 10px;
    outline: none;
}

QListWidget::item {
    padding: 10px;
    border-radius: 6px;
    margin: 2px;
}

QListWidget::item:hover {
    background-color: #334155;
}

QListWidget::item:selected {
    background-color: #2563EB;
    color: white;
}

/* =========================
   TABLES
   ========================= */

QTableWidget {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 10px;
    color: white;
    gridline-color: #334155;
    selection-background-color: #2563EB;
    outline: none;
}

QTableWidget::item {
    padding: 8px;
}

QHeaderView::section {
    background-color: #111827;
    color: white;
    border: none;
    padding: 10px;
    font-weight: bold;
}

/* =========================
   TEXT INPUT
   ========================= */

QLineEdit {
    background-color: #111827;
    color: white;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px;
}

QLineEdit:focus {
    border: 1px solid #3B82F6;
}


/* =========================
   SPLITTER
   ========================= */

QSplitter::handle {
    background-color: #0F172A;
    width: 2px;
}

/* =========================
   SCROLLBARS
   ========================= */

QScrollBar:vertical {
    background: transparent;
    width: 10px;
}

QScrollBar::handle:vertical {
    background: #475569;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #64748B;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: transparent;
    height: 10px;
}

QScrollBar::handle:horizontal {
    background: #475569;
    border-radius: 5px;
}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* =========================
   Findings
   ========================= */

QListWidget#findings {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 10px;
    outline: none;
}

QListWidget#findings::item {
    padding: 8px;
}

QListWidget#findings::item:selected {
    background-color: #2563EB;
}
""")

# =========================
# WINDOWS
# =========================

splash = SplashScreen()

login_window = LoginWindow()

# =========================
# STARTUP FLOW
# =========================

def show_dashboard():

    splash.close()

    from ui.dashboardv2 import Dashboard
    from capture.sniffer import PacketSniffer

    dashboard = Dashboard()

    sniffer = PacketSniffer()

    sniffer.packet_received.connect(
        dashboard.add_packet
    )

    import threading

    threading.Thread(
        target=sniffer.start,
        daemon=True
    ).start()

    dashboard.sniffer = sniffer

    dashboard.show()

    app.dashboard = dashboard

QTimer.singleShot(
    5000,
    show_dashboard
)

# SHOW SPLASH
splash.show()


sys.exit(app.exec())