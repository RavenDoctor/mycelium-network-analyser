from PyQt6.QtWidgets import (
    QMainWindow,
    QWidget,
    QLabel,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QHBoxLayout,
    QHeaderView,
    QStackedWidget,
    QSplitter,
    QFrame,
)

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal

from ui.map_widget import MapWidget

from threatintel.geoip import lookup_ip

from network.lan_scanner import scan_network
from network.port_scanner import scan_ports

import pyqtgraph as pg

from collections import deque

import time

import socket

from detection.beacon_data import beaconing_results


def get_local_subnet():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:

        s.connect(("8.8.8.8", 80))

        ip = s.getsockname()[0]

    finally:

        s.close()

    parts = ip.split(".")

    return f"{parts[0]}." f"{parts[1]}." f"{parts[2]}.0/24"


class DeviceAnalysisWorker(QThread):

    finished = pyqtSignal(dict, list)

    def __init__(self, device):

        super().__init__()

        self.device = device

    def run(self):

        results = scan_ports(self.device["ip"])

        self.finished.emit(self.device, results)


class LanScanWorker(QThread):

    finished = pyqtSignal(list)

    def run(self):

        try:

            subnet = get_local_subnet()

            print(f"Starting LAN scan: {subnet}")

            devices = scan_network(subnet)

            print("Finished LAN scan")
            print(devices)

            self.finished.emit(devices)

        except Exception as e:

            print("LAN SCAN ERROR:")
            print(e)


class Dashboard(QMainWindow):

    def __init__(self):

        super().__init__()

        self.setWindowTitle("Mycelium Security Centre")

        self.resize(1600, 900)

        self.packet_count = 0
        self.packet_rate = 0

        self.alert_count = 0
        self.device_count = 0
        self.security_events = []

        self.network_health = 100

        self.graph_data = deque(maxlen=30)

        self.last_seen_paths = {}

        self.geo_cache = {}

        self.devices = []

        self.setup_ui()

        self.setup_timer()

    def create_stat_card(self, title, value):

        card = QFrame()

        card.setStyleSheet("""
            QFrame {
                background-color: #1f2937;
                border-radius: 16px;
                border: 1px solid #374151;
                padding: 8px;
            }
        """)

        layout = QVBoxLayout()

        title_label = QLabel(title)

        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label.setStyleSheet("""
            color: #bbbbbb;
            font-size: 12px;
        """)

        value_label = QLabel(str(value))

        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        value_label.setStyleSheet("""
            color: white;
            font-size: 24px;
            font-weight: 700;
        """)

        layout.addWidget(title_label)

        layout.addWidget(value_label)

        card.setLayout(layout)

        return card, value_label

    def setup_ui(self):

        self.sidebar = QListWidget()

        self.sidebar.addItems(
            ["Overview", "Devices", "Security Centre", "Network Activity"]
        )

        self.sidebar.setFixedWidth(220)

        self.sidebar.currentRowChanged.connect(self.change_page)

        self.pages = QStackedWidget()

        self.build_overview_page()
        self.build_devices_page()
        self.build_security_page()

        content = QHBoxLayout()

        content.addWidget(self.sidebar)

        content.addWidget(self.pages)

        container = QWidget()

        container.setLayout(content)

        self.setCentralWidget(container)

    def build_overview_page(self):

        page = QWidget()

        layout = QVBoxLayout()

        # Cards

        self.health_card, self.health_value = self.create_stat_card(
            "Network Health", "100"
        )

        self.devices_card, self.devices_value = self.create_stat_card("Devices", "0")

        self.alerts_card, self.alerts_value = self.create_stat_card(
            "Items To Review", "0"
        )

        self.status_card, self.status_value = self.create_stat_card(
            "Protection", "Healthy"
        )

        cards = QHBoxLayout()

        cards.addWidget(self.health_card)

        cards.addWidget(self.devices_card)

        cards.addWidget(self.alerts_card)

        cards.addWidget(self.status_card)

        layout.addLayout(cards)

        findings_title = QLabel("Security Findings")

        findings_title.setStyleSheet("""
            font-size:18px;
            font-weight:bold;
            color:white;
        """)

        layout.addWidget(findings_title)

        self.findings_list = QListWidget()

        self.findings_list.addItem("No security findings detected.")

        self.findings_list.setMaximumHeight(180)

        layout.addWidget(self.findings_list)

        self.graph_widget = pg.PlotWidget()

        self.graph_widget.setBackground("#1c1c1c")

        self.graph_widget.setTitle("Network Activity")

        self.graph_widget.showGrid(x=True, y=True)

        self.graph_line = self.graph_widget.plot(pen="#4CAF50")

        layout.addWidget(self.graph_widget)

        map_title = QLabel("Global Connections")

        map_title.setStyleSheet("""
            font-size:18px;
            font-weight:bold;
            color:white;
        """)

        layout.addWidget(map_title)

        self.map_widget = MapWidget()

        self.map_widget.setMinimumHeight(300)

        layout.addWidget(self.map_widget)

        page.setLayout(layout)

        self.pages.addWidget(page)

    def change_page(self, index):

        self.pages.setCurrentIndex(index)

    def setup_timer(self):

        self.timer = QTimer()

        self.timer.timeout.connect(self.update_graph)

        self.timer.start(1000)

    def update_graph(self):

        self.graph_data.append(self.packet_rate)

        self.graph_line.setData(list(self.graph_data))

        self.packet_rate = 0

    def add_packet(
        self, timestamp, src, dst, sport, dport, proto, process, alerts, severity
    ):

        self.packet_count += 1
        self.packet_rate += 1

        if severity in ["HIGH", "MEDIUM"]:

            if (
                self.findings_list.count() == 1
                and "No security findings" in self.findings_list.item(0).text()
            ):
                self.findings_list.clear()

            self.alert_count += 1

            self.alerts_value.setText(str(self.alert_count))

            self.update_health_score()

            if "beacon" in alerts.lower():

                finding = "Repeated external communication detected"

            elif "port" in alerts.lower():

                finding = "Connection to an uncommon network service"

            elif "process" in alerts.lower():

                finding = "Potentially risky application activity"

            else:

                finding = alerts

            event = {
                "timestamp": timestamp,
                "severity": severity,
                "message": finding,
                "source": src,
                "destination": dst,
                "process": process,
                "raw_alert": alerts,
            }

            self.security_events.append(event)

            print(self.security_events)

            self.update_security_page()

            self.findings_list.insertItem(0, f"{severity} • {finding}")

            if self.findings_list.count() > 20:

                self.findings_list.takeItem(20)

    def update_health_score(self):

        score = max(0, 100 - (self.alert_count * 5))

        self.health_value.setText(f"{score}%")

        if score >= 80:

            colour = "#4CAF50"

        elif score >= 60:

            colour = "#FFC107"

        else:

            colour = "#F44336"

        self.health_value.setStyleSheet(f"""
            color: {colour};
            font-size: 24px;
            font-weight: bold;
            """)

    def build_devices_page(self):

        page = QWidget()

        layout = QHBoxLayout()

        # Device list

        self.device_list = QListWidget()

        self.device_list.clicked.connect(self.show_device_details)

        # Details panel

        details = QVBoxLayout()

        self.device_title = QLabel("Select a device")

        self.device_title.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: white;
        """)

        self.device_info = QLabel("Run a network scan to discover devices.")

        self.device_risk = QLabel("Risk Level: Unknown")

        self.device_risk.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: white;
        """)

        self.device_info.setWordWrap(True)

        self.scan_button = QPushButton("Scan Network")

        self.scan_button.clicked.connect(self.run_lan_scan)

        details.addWidget(self.device_title)

        details.addWidget(self.device_risk)
        details.addWidget(self.device_info)

        self.recommendations = QLabel()

        details.addWidget(self.recommendations)

        details.addWidget(self.scan_button)

        details.addStretch()

        layout.addWidget(self.device_list, 2)

        details_widget = QWidget()

        details_widget.setLayout(details)

        layout.addWidget(details_widget, 3)

        page.setLayout(layout)

        self.pages.addWidget(page)

        self.recommendations.setWordWrap(True)

        self.recommendations.setStyleSheet("""
            color: #bbbbbb;
            font-size: 13px;
        """)

    def run_lan_scan(self):

        self.scan_button.setEnabled(False)

        self.scan_button.setText("Scanning...")

        self.worker = LanScanWorker()

        self.worker.finished.connect(self.populate_lan_table)

        self.worker.start()

    def populate_lan_table(self, devices):

        print("populate_lan_table called")
        print(f"Found {len(devices)} devices")
        print(devices)

        self.devices = devices

        self.device_list.clear()

        self.device_count = len(devices)

        self.devices_value.setText(str(self.device_count))

        for device in devices:

            name = device["hostname"] if device["hostname"] else device["ip"]

            item_text = f"{name}\n" f"{device['device_type']}\n" f"Online"

            self.device_list.addItem(item_text)

        self.scan_button.setEnabled(True)

        self.scan_button.setText("Scan Network")

    def show_device_details(self):

        row = self.device_list.currentRow()

        if row < 0:
            return

        device = self.devices[row]

        ip = device["ip"]

        self.device_title.setText(device["hostname"] or ip)

        self.device_info.setText("Analysing device...")

        self.device_info.setText("Analysing device...")

        self.device_risk.setText("Risk Level: Analysing...")

        self.analysis_worker = DeviceAnalysisWorker(device)

        self.analysis_worker.finished.connect(self.populate_device_analysis)

        self.analysis_worker.start()

    def populate_device_analysis(self, device, results):

        high = 0
        medium = 0

        findings = []
        recommendations = []
        services = []

        for result in results:

            service = result["service"].lower()
            port = result["port"]

            services.append(f"• {service.upper()} ({port})")

            if service == "rdp":

                high += 1

                findings.append("Remote Desktop access enabled")

                recommendations.append("Disable Remote Desktop if not required.")

            elif service == "telnet":

                high += 1

                findings.append("Insecure remote administration service detected")

                recommendations.append("Disable Telnet and use SSH instead.")

            elif service == "ftp":

                medium += 1

                findings.append("Legacy file transfer service available")

                recommendations.append("Consider replacing FTP with SFTP.")

            elif service == "ssh":

                medium += 1

                findings.append("Remote administration service available")

                recommendations.append("Use strong passwords and key authentication.")

            elif service == "smb":

                findings.append("File sharing service available")

                recommendations.append("Disable file sharing if not required.")

        if len(results) > 10:

            medium += 1

            findings.append("Large number of network services detected")

            recommendations.append("Review whether all exposed services are required.")

        if high > 0:

            overall_risk = "HIGH"
            colour = "#F44336"

        elif medium > 0:

            overall_risk = "MEDIUM"
            colour = "#FFC107"

        else:

            overall_risk = "LOW"
            colour = "#4CAF50"

        self.device_risk.setText(f"Risk Level: {overall_risk}")

        self.device_risk.setStyleSheet(f"""
            color: {colour};
            font-size: 18px;
            font-weight: bold;
            """)

        info = f"""
    Type:
    {device['device_type']}

    Manufacturer:
    {device['vendor']}

    IP Address:
    {device['ip']}
    """

        if findings:

            info += "\n\nIssues Found:\n"

            for finding in findings:

                info += f"• {finding}\n"

        else:

            info += "\n\nNo significant issues detected."

        if services:

            info += "\n\nOpen Services:\n"

            info += "\n".join(services)

        self.device_info.setText(info)

        if recommendations:

            text = "Recommendations\n\n"

            for item in recommendations:

                text += f"• {item}\n"

        else:

            text = "Recommendations\n\n" "No action required."

        self.recommendations.setText(text)

    def build_security_page(self):

        page = QWidget()

        main_layout = QVBoxLayout()

        title = QLabel("Security Centre")

        title.setStyleSheet("""
            font-size: 22px;
            font-weight: bold;
            color: white;
        """)

        main_layout.addWidget(title)

        content_layout = QHBoxLayout()

        self.security_list = QListWidget()

        self.security_list.currentRowChanged.connect(self.show_security_details)

        self.security_list.addItem("No security findings detected.")

        details_layout = QVBoxLayout()

        self.security_title = QLabel("Select a finding")

        self.security_title.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: white;
        """)

        self.security_details = QLabel("Details will appear here.")

        self.security_details.setWordWrap(True)

        details_layout.addWidget(self.security_title)

        details_layout.addWidget(self.security_details)

        details_layout.addStretch()

        details_widget = QWidget()

        details_widget.setLayout(details_layout)

        content_layout.addWidget(self.security_list, 2)

        content_layout.addWidget(details_widget, 3)

        main_layout.addLayout(content_layout)

        page.setLayout(main_layout)

        self.pages.addWidget(page)

    def update_security_page(self):

        self.security_list.clear()

        if not self.security_events:

            self.security_list.addItem("No security findings detected.")

            return

        for event in reversed(self.security_events):

            severity = event["severity"]

            message = event["message"]

            if severity == "HIGH":

                icon = "🔴"

            elif severity == "MEDIUM":

                icon = "🟡"

            else:

                icon = "🔵"

            self.security_list.addItem(
                f"{icon} [{event['timestamp']}] "
                f"{message}\n"
                f"Process: {event['process']}\n"
                f"Destination: {event['destination']}"
            )
        if self.security_list.count() > 0:

            self.security_list.setCurrentRow(0)

    def show_security_details(self, row):

        if row < 0:
            return

        if not self.security_events:
            return

        event = self.security_events[len(self.security_events) - 1 - row]

        self.security_title.setText(event["message"])

        explanation = "Review whether this activity " "is expected."

        if "communication" in event["message"].lower():

            explanation = (
                "Repeated communication with "
                "the same destination can "
                "sometimes indicate automated "
                "network activity."
            )

        elif "application" in event["message"].lower():

            explanation = (
                "An application generated " "activity that may require " "review."
            )

        elif "service" in event["message"].lower():

            explanation = "Traffic was detected to an " "uncommon network service."

        self.security_details.setText(f"""
    Severity:
    {event['severity']}

    Time:
    {event['timestamp']}

    Application:
    {event['process']}

    Destination:
    {event['destination']}

    Why This Matters:
    {explanation}

    Recommended Action:
    Review whether this behaviour is expected.
    """)
