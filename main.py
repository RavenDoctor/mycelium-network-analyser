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