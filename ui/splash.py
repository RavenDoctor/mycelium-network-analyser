from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel
)

from PyQt6.QtCore import (
    Qt,
    QTimer
)

from PyQt6.QtGui import QFont


class SplashScreen(QWidget):

    def __init__(self):

        super().__init__()

        self.setWindowTitle("Mycelium")

        self.resize(900, 500)

        self.setStyleSheet("""

            background-color: #05080c;
            color: #4dd0e1;

        """)

        layout = QVBoxLayout()

        layout.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.title = QLabel("MYCELIUM")

        self.title.setFont(
            QFont("Orbitron", 36)
        )

        self.title.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.status = QLabel(
            "Initializing..."
        )

        self.status.setFont(
            QFont("Consolas", 12)
        )

        self.status.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        layout.addWidget(
            self.title
        )

        layout.addSpacing(30)

        layout.addWidget(
            self.status
        )

        self.setLayout(layout)

        # Boot messages
        self.messages = [

            "Loading telemetry engine...",
            "Initializing packet capture...",
            "Loading threat intelligence...",
            "Starting behavioural analysis...",
            "Connecting visualisation systems...",
            "Launching operator console..."
        ]

        self.index = 0

        self.timer = QTimer()

        self.timer.timeout.connect(
            self.next_message
        )

        self.timer.start(800)

    def next_message(self):

        if self.index < len(self.messages):

            self.status.setText(
                self.messages[self.index]
            )

            self.index += 1

        else:

            self.timer.stop()

            self.close()