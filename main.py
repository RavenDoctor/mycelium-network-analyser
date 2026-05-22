import sys

import threading

import qdarkstyle

from PyQt6.QtWidgets import QApplication

from ui.dashboard import Dashboard

from capture.sniffer import PacketSniffer


app = QApplication(sys.argv)

app.setStyleSheet(
    qdarkstyle.load_stylesheet_pyqt6()
)

app.setStyleSheet(app.styleSheet() + """

QMainWindow {
    background-color: #0a0f14;
}

QLabel {
    font-family: 'Orbitron';
    font-size: 14px;
    color: #00ffee;
    font-weight: bold;
}

QTableWidget {
    background-color: #0d1117;
    color: #00ffee;
    font-weight: bold;
    gridline-color: #1f2937;
    font-family: 'Share Tech Mono';
    font-size: 12px;
    border: 1px solid #00ffee;
}

QHeaderView::section {
    background-color: #111827;
    color: #00ffee;
    font-weight: bold;
    padding: 6px;
    border: 1px solid #00ffee;
    font-family: 'Orbitron';
    font-size: 12px;
}

QListWidget {
    background-color: #0d1117;
    font-weight: bold;
    color: #00ffee;
    font-family: 'Share Tech Mono';
    border: 1px solid #00ffee;
}

""")

window = Dashboard()

window.show()

sniffer = PacketSniffer()

# Connect Qt signal safely
sniffer.packet_received.connect(
    window.add_packet
)

# Start sniffer thread
thread = threading.Thread(
    target=sniffer.start
)

thread.daemon = True

thread.start()

sys.exit(app.exec())