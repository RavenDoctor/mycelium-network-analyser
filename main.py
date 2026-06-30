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

QFontDatabase.addApplicationFont(
    "assets/fonts/Orbitron-VariableFont_wght.ttf"
)

QFontDatabase.addApplicationFont(
    "assets/fonts/ShareTechMono-Regular.ttf"
)

app.setStyle("Fusion")

# =========================
# STYLESHEET
# =========================

app.setStyleSheet("""

QWidget {
    background-color: #0f172a;
    color: #F9FAFB;
    font-family: "Segoe UI";
    font-size: 12px;
}

QLabel {
    color: #F9FAFB;
}

QTableWidget {
    background-color: #1F2937;
    border: 1px solid #374151;
    gridline-color: #374151;
    color: white;
    selection-background-color: #3B82F6;
}

QHeaderView::section {
    background-color: #374151;
    color: white;
    padding: 8px;
    border: none;
    font-weight: 600;
}

QListWidget {
    background-color: #1F2937;
    border: 1px solid #374151;
    border-radius: 8px;
}

QListWidget::item {
    padding: 10px;
    border-bottom: 1px solid #111827;
}

QListWidget::item:selected {
    background-color: #3B82F6;
}

QPushButton {
    background-color: #2563EB;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 8px;
}

QPushButton:hover {
    background-color: #1D4ED8;
}

QLineEdit {
    background-color: #0b1118;
    border: 1px solid #1f2a35;
    padding: 8px;
    color: white;
}

QSplitter::handle {
    background-color: #05080c;
    border: none;
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