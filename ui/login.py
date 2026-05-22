from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton
)

from PyQt6.QtCore import (
    Qt,
    QPropertyAnimation
)

from PyQt6.QtGui import QFont



class LoginWindow(QWidget):

    def __init__(self):

        super().__init__()

        self.setWindowTitle("Mycelium Login")

        self.resize(500, 400)

        self.setStyleSheet("""

            background-color: #05080c;
            color: #4dd0e1;

            QLabel {
                color: #4dd0e1;
            }

            QLineEdit {

                background-color: #0d1117;
                border: 1px solid #4dd0e1;
                padding: 10px;
                color: white;
                font-size: 14px;
            }

            QPushButton {

                background-color: #4dd0e1;
                color: #05080c;
                padding: 10px;
                font-weight: bold;
            }

            QPushButton:hover {

                background-color: #7ce7f5;
            }

        """)

        layout = QVBoxLayout()

        layout.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        title = QLabel("MYCELIUM")

        title.setFont(
            QFont("Orbitron", 28)
        )

        title.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        subtitle = QLabel(
            "Operator Authentication"
        )

        subtitle.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )

        self.username = QLineEdit()

        self.username.setPlaceholderText(
            "Username"
        )

        self.password = QLineEdit()

        self.password.setPlaceholderText(
            "Password"
        )

        self.password.setEchoMode(
            QLineEdit.EchoMode.Password
        )

        login_button = QPushButton(
            "ACCESS SYSTEM"
        )

        login_button.clicked.connect(
            self.login
        )

        layout.addWidget(title)

        layout.addSpacing(10)

        layout.addWidget(subtitle)

        layout.addSpacing(30)

        layout.addWidget(self.username)

        layout.addWidget(self.password)

        layout.addSpacing(20)

        layout.addWidget(login_button)

        self.setLayout(layout)

        # Fade animation
        self.fade = QPropertyAnimation(
            self,
            b"windowOpacity"
        )

        self.fade.setDuration(1500)

        self.fade.setStartValue(0)

        self.fade.setEndValue(1)

        self.fade.start()

    def login(self):

        from ui.dashboard import Dashboard

        username = self.username.text()

        password = self.password.text()

        if (
            username == "operator"
            and password == "mycelium"
        ):

            self.dashboard = Dashboard()

            from capture.sniffer import PacketSniffer

            self.sniffer = PacketSniffer()

            self.sniffer.packet_received.connect(
                self.dashboard.add_packet
        )
        
        import threading

        threading.Thread(
                target=self.sniffer.start,
                daemon=True
        ).start()

        self.dashboard.show()

        self.close()