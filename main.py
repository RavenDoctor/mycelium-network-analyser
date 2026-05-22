import sys

from PyQt6.QtCore import (
    Qt,
    QTimer
)

from PyQt6.QtWidgets import QApplication

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

QWidget {
    background-color: #05080c;
    color: #d8dee9;
    font-family: Consolas;
    font-size: 12px;
}

QLabel {
    color: #4dd0e1;
}

QTableWidget {
    background-color: #0b1118;
    border: none;
    gridline-color: #16202a;
    color: white;
    selection-background-color: #123040;
}

QHeaderView::section {
    background-color: #111827;
    color: #4dd0e1;
    padding: 6px;
    border: none;
    font-weight: bold;
}

QListWidget {
    background-color: #0b1118;
    border: none;
    color: white;
}

QListWidget::item {
    padding: 10px;
    border-bottom: 1px solid #111827;
}

QListWidget::item:selected {
    background-color: #123040;
}

QPushButton {
    background-color: #111827;
    border: 1px solid #1f2a35;
    padding: 8px;
    color: #4dd0e1;
}

QPushButton:hover {
    background-color: #123040;
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

def show_login():

    splash.close()

    login_window.show()

# SHOW SPLASH
splash.show()

# WAIT 5s THEN LOGIN
QTimer.singleShot(
    5000,
    show_login
)

sys.exit(app.exec())