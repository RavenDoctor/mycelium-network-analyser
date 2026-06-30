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
    QScrollArea,
    QFileDialog,
    QMessageBox
)

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal

from ui.map_widget import MapWidget

from threatintel.geoip import lookup_ip
from threatintel.ip_resolver import resolve_hostname



from network.lan_scanner import scan_network
from network.port_scanner import scan_ports

import pyqtgraph as pg

from collections import deque
import psutil
import os
import time
from datetime import datetime
import socket

from detection.beacon_data import beaconing_results
from utils.report_generator import generate_report

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

        from collections import Counter
        self.start_time = time.time()
        self.process = psutil.Process(os.getpid())
        
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

        self.application_stats = Counter()

        self.protocol_stats = Counter()

        self.destination_stats = Counter()
        
        self.security_tips = [

            "Review repeated outbound connections to unfamiliar destinations.",
            "Run a LAN scan regularly to identify unknown devices.",
            "Investigate HIGH severity findings as soon as possible.",
            "Repeated beaconing can indicate automated communication.",
            "Monitor unexpected applications generating network traffic.",
            "Regularly review unusual destination countries.",
            "Keep Windows and applications fully updated.",
            "Use strong, unique passwords for every account.",
            "Enable multi-factor authentication where available.",
            "Investigate traffic to uncommon network services."
        ]

        self.current_tip = 0

        self.live_activity = []
        print("1")                      #Printing statements for debugging crash on startup
        self.setup_ui()
        print ("2")
        self.setup_timer()
        print ("3")
        

        
        self.external_hosts = set()
        self.active_paths = 0       
        self.map_countries = set()
        self.country_counter = Counter()
     
        

        self.recent_map_connections = {} 

        from threatintel.geoip import lookup_my_location

        location = lookup_my_location()

        if location:

            self.origin_lat = location["lat"]
            self.origin_lon = location["lon"]

        else:

            self.origin_lat = 51.5074
            self.origin_lon = -0.1278
    def create_stat_card(self, title, value):

        card = QFrame()

        card.setStyleSheet("""
        QFrame {
            background-color: #1E293B;
            border: 1px solid #334155;
            border-radius: 16px;
        }
        """)

        card.setMinimumHeight(120)

        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)

        title_label = QLabel(title)

        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label.setStyleSheet("""
        color:#94A3B8;
        font-size:13px;
        font-weight:600;
        """)

        value_label = QLabel(str(value))

        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        value_label.setStyleSheet("""
        color:white;
        font-size:34px;
        font-weight:700;
        """)

        layout.addStretch()

        layout.addWidget(title_label)

        layout.addWidget(value_label)

        layout.addStretch()

        card.setLayout(layout)

        return card, value_label

    def setup_ui(self):

        self.sidebar = QListWidget()

        self.sidebar.addItems([
            "Overview",
            "Network Activity",
            "Threat Map",
            "Devices",
            "Security Centre"
        ])

        self.sidebar.setFixedWidth(220)

        self.sidebar.currentRowChanged.connect(self.change_page)

        self.pages = QStackedWidget()

        self.build_overview_page()          # 0
        self.build_network_activity_page()  # 1
        self.build_threat_map_page()        # 2
        self.build_devices_page()           # 3
        self.build_security_page()          # 4

        content = QHBoxLayout()

        content.addWidget(self.sidebar)

        content.addWidget(self.pages)

        container = QWidget()

        container.setLayout(content)

        self.setCentralWidget(container)

    def build_overview_page(self):

    # =====================================
    # Header
    # =====================================
        page = QWidget()
        layout = QVBoxLayout()
        
        header = QHBoxLayout()

        title = QLabel("Overview")

        title.setStyleSheet("""
            font-size:22px;
            font-weight:700;
            color:white;
        """)

        header.addWidget(title)

        header.addStretch()

        export_button = QPushButton("Export Report")

        export_button.setCursor(Qt.CursorShape.PointingHandCursor)

        export_button.setFixedHeight(38)

        export_button.clicked.connect(
            self.export_report
        )

        export_button.setStyleSheet("""
        QPushButton {

            background-color:#2563EB;
            color:white;
            border:none;
            border-radius:8px;
            padding:8px 18px;
            font-size:13px;
            font-weight:600;

        }

        QPushButton:hover {

            background-color:#1D4ED8;

        }

        QPushButton:pressed {

            background-color:#1E40AF;

        }
        """)

        header.addWidget(export_button)

        layout.addLayout(header)

        # =====================================
        # Statistic Cards
        # =====================================

        self.health_card, self.health_value = self.create_stat_card(
            "Network Health",
            "100"
        )

        self.devices_card, self.devices_value = self.create_stat_card(
            "Devices",
            "0"
        )

        self.alerts_card, self.alerts_value = self.create_stat_card(
            "Items To Review",
            "0"
        )

        self.status_card, self.status_value = self.create_stat_card(
            "Protection",
            "Healthy"
        )

        cards = QHBoxLayout()

        cards.addWidget(self.health_card)
        cards.addWidget(self.devices_card)
        cards.addWidget(self.alerts_card)
        cards.addWidget(self.status_card)

        layout.addLayout(cards)

        # =====================================
        # Recent Findings
        # =====================================

        findings_title = QLabel("Recent Security Findings")

        findings_title.setStyleSheet("""
            font-size:18px;
            font-weight:600;
            color:white;
        """)

        layout.addWidget(findings_title)

        self.findings_scroll = QScrollArea()

        self.findings_scroll.setWidgetResizable(True)
        self.findings_scroll.setFixedHeight(180)
        self.findings_scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.findings_container = QWidget()

        self.findings_layout = QVBoxLayout()
        
        self.empty_findings = QFrame()

        self.empty_findings.setStyleSheet("""
        QFrame {
            background-color:#1E293B;
            border:1px solid #334155;
            border-radius:12px;
        }
        """)

        empty_layout = QVBoxLayout(self.empty_findings)

        empty_layout.setContentsMargins(20,20,20,20)

        title = QLabel("🟢 Monitoring Network")

        title.setStyleSheet("""
        font-size:16px;
        font-weight:bold;
        color:#22C55E;
        """)

        message = QLabel(
            "No suspicious activity has been detected.\n\n"
            "Mycelium is actively monitoring live network traffic "
            "and analysing connections in real time."
        )

        message.setWordWrap(True)

        message.setStyleSheet("""
        color:#CBD5E1;
        font-size:13px;
        """)

        empty_layout.addWidget(title)
        empty_layout.addWidget(message)

        self.findings_layout.addWidget(self.empty_findings)
        self.findings_layout.setSpacing(10)

        self.findings_layout.setContentsMargins(
            0,
            0,
            0,
            0
        )

        self.findings_container.setLayout(
            self.findings_layout
        )

        self.findings_scroll.setWidget(
            self.findings_container
        )

        layout.addWidget(
            self.findings_scroll
        )

        # =====================================
        # System Status
        # =====================================

        status_title = QLabel("System Status")

        status_title.setStyleSheet("""
            font-size:18px;
            font-weight:600;
            color:white;
        """)

        layout.addWidget(status_title)

        status_card = QFrame()

        status_card.setStyleSheet("""
            QFrame {
                background-color:#1E293B;
                border:1px solid #334155;
                border-radius:12px;
            }
        """)

        status_layout = QVBoxLayout(status_card)

        status_layout.setContentsMargins(
            18,
            18,
            18,
            18
        )

        self.system_status = QLabel()

        self.system_status.setStyleSheet("""
            color:#E2E8F0;
            font-size:13px;
            line-height:1.4;
        """)

        status_layout.addWidget(
            self.system_status
        )

        layout.addWidget(status_card)
        
        

        # Initialise status

        self.update_system_status()

        layout.addStretch()

        page.setLayout(layout)

        self.pages.addWidget(page) 

    def update_system_status(self):

        cpu = psutil.cpu_percent(interval=None)

        memory = self.process.memory_info().rss / (1024 * 1024)

        elapsed = int(time.time() - self.start_time)

        hours = elapsed // 3600

        minutes = (elapsed % 3600) // 60

        seconds = elapsed % 60

        uptime = f"{hours:02}:{minutes:02}:{seconds:02}"

        geo_status = (
            "Online"
            if self.geo_cache
            else "Waiting..."
        )

        self.system_status.setText(
            f"""
    🟢 Packet Capture      Active
    🟢 Threat Engine       Active
    🟢 GeoIP               {geo_status}

    ⚡ CPU Usage           {cpu:.1f}%

    💾 Memory Usage        {memory:.1f} MB

    📦 Packets Captured    {self.packet_count:,}

    📈 Packet Rate         {self.packet_rate}/s

    💻 Devices             {self.device_count}

    🛡 Threats             {self.alert_count}

    ⏱ Uptime              {uptime}

    🕒 Last Update         {datetime.now().strftime("%H:%M:%S")}
    """
        )
    def create_finding_card(
        self,
        severity,
        message,
        timestamp,
        process
    ):

        if severity == "HIGH":

            colour = "#EF4444"
            icon = "🔴"

        elif severity == "MEDIUM":

            colour = "#F59E0B"
            icon = "🟡"

        else:

            colour = "#22C55E"
            icon = "🟢"

        card = QFrame()

        card.setStyleSheet(f"""
            QFrame {{
                background-color: #1F2937;
                border-left: 5px solid {colour};
                border-radius: 10px;
            }}
        """)

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            16,
            12,
            16,
            12
        )

        layout.setSpacing(4)

        content = QLabel(f"""
        <div style="line-height:1.5;">

            <span style="color:{colour};
                        font-size:16px;
                        font-weight:700;">
                {icon} {severity}
            </span>

            <br><br>

            <span style="color:white;
                        font-size:14px;">
                {message}
            </span>

            <br><br>

            <span style="color:#94A3B8;
                        font-size:11px;">
                 {timestamp}
                &nbsp;&nbsp;&nbsp;&nbsp;
                 {process}
            </span>

        </div>
        """)

        content.setWordWrap(True)

        content.setTextFormat(
            Qt.TextFormat.RichText
        )

        content.setStyleSheet("""
            QLabel {
                background: transparent;
                border: none;
            }
        """)

        layout.addWidget(content)

        return card
    def change_page(self, index):

        self.pages.setCurrentIndex(index)

    def setup_timer(self):

        self.timer = QTimer()

        self.timer.timeout.connect(
            self.refresh_dashboard
        )

        self.timer.start(1000)
    def refresh_dashboard(self):
        self.update_security_summary()
        self.update_graph()
        self.update_network_activity()
        self.update_system_status()

    def update_graph(self):

        self.graph_data.append(self.packet_rate)

        self.graph_line.setData(list(self.graph_data))
        self.update_system_status()
        self.packet_rate = 0

    def add_packet(
        self,
        timestamp,
        src,
        dst,
        sport,
        dport,
        proto,
        process,
        alerts,
        severity
    ):

        # =========================
        # Packet Counters
        # =========================

        self.packet_count += 1
        self.packet_rate += 1
        self.update_system_status()

        # =========================
        # Network Activity
        # (Update for EVERY packet)
        # =========================

        self.application_stats[process] += 1

        self.protocol_stats[proto] += 1

        self.destination_stats[dst] += 1
        
        self.live_activity.insert(
            0,
            f"{timestamp} {process} → {dst} ({proto})"
        )
                # Keep only latest 100 entries
        self.live_activity = self.live_activity[:100]


        # =========================
        # Security Detection
        # (Only HIGH/MEDIUM)
        # =========================

        if severity in ["HIGH", "MEDIUM"]:

            self.alert_count += 1
            self.alerts_value.setText(
                str(self.alert_count)
            )
            self.update_system_status()
            self.update_health_score()

            if "beacon" in alerts.lower():

                finding = (
                    "Repeated external communication detected"
                )

            elif "port" in alerts.lower():

                finding = (
                    "Connection to an uncommon network service"
                )

            elif "process" in alerts.lower():

                finding = (
                    "Potentially risky application activity"
                )

            else:

                finding = alerts

            event = {

                "timestamp": timestamp,

                "severity": severity,

                "message": finding,

                "source": src,

                "destination": dst,

                "process": process,

                "raw_alert": alerts

            }

            self.security_events.append(
                event
            )

            self.update_security_page()

            if severity == "HIGH":
                icon = "🔴"
            elif severity == "MEDIUM":
                icon = "🟡"
            else:
                icon = "🔵"

            text = (
                f"{icon}  {finding}\n"
                f"{timestamp}    {process}"
            )
            if self.empty_findings.isVisible():

                
                self.empty_findings.hide()
            card = self.create_finding_card(
                severity,
                finding,
                timestamp,
                process
            )

            self.findings_layout.insertWidget(
                0,
                card
            )

            while self.findings_layout.count() > 10:

                item = self.findings_layout.takeAt(10)

                if item.widget():

                    item.widget().deleteLater()
            while self.findings_layout.count() > 10:

                item = self.findings_layout.takeAt(10)

                if item.widget():

                    item.widget().deleteLater()
            print("HIGH/MEDIUM DETECTED")
            print("Destination:", dst)

        print("DST:", dst)

        if dst in self.geo_cache:

            geo = self.geo_cache[dst]

        else:

            geo = lookup_ip(dst)

            self.geo_cache[dst] = geo
        
        print("GEO:", geo)

        if geo:

            now = time.time()

            key = (process, dst)

            # Remove entries older than 30 seconds
            self.recent_map_connections = {
                k: t
                for k, t in self.recent_map_connections.items()
                if now - t < 30
            }
            self.update_map_statistics()

            # Only draw NEW paths
            if key not in self.recent_map_connections:

                self.recent_map_connections[key] = now

                self.map_countries.add(geo["country"])

                self.external_hosts.add(dst)
                
                self.country_counter[
                    geo["country"]
                ] += 1

                self.update_map_statistics()


            popup = f"""
            <div style="
            font-family:Segoe UI;
            font-size:12px;
            line-height:1.25;
            ">

            <div style="
            font-size:13px;
            font-weight:600;
            margin-bottom:4px;
            ">
            {process}
            </div>

            <div>{dst}</div>

            <div>{geo['country']}</div>

            <div style="
            margin-top:6px;
            color:{
            '#EF4444' if severity=='HIGH'
            else '#F59E0B' if severity=='MEDIUM'
            else '#22C55E'
            };
            font-weight:600;
            ">
            {severity}
            </div>

            </div>
            """

            self.map_widget.add_attack_path(
                self.origin_lat,
                self.origin_lon,
                geo["lat"],
                geo["lon"],
                popup,
                severity
            )

                                   
    def update_network_activity(self):

        self.application_table.setRowCount(0)

        self.protocol_list.clear()

        self.destination_list.clear()

        self.activity_list.clear()

        total_packets = sum(
            self.application_stats.values()
        )

        for app, count in self.application_stats.most_common(10):

            row = self.application_table.rowCount()

            self.application_table.insertRow(row)

            percentage = (
                count / total_packets * 100
                if total_packets else 0
            )

            bar = "█" * max(
                1,
                int(percentage / 5)
            )

            self.application_table.setItem(
                row,
                0,
                QTableWidgetItem(app)
            )

            self.application_table.setItem(
                row,
                1,
                QTableWidgetItem(bar)
            )

            self.application_table.setItem(
                row,
                2,
                QTableWidgetItem(
                    f"{percentage:.1f}%"
                )
            )

        for proto, count in self.protocol_stats.most_common(10):

            self.protocol_list.addItem(
                f"{proto} ({count})"
            )

        for dst, count in self.destination_stats.most_common(10):

            self.destination_list.addItem(
                f"{dst} ({count})"
            )
        for item in self.live_activity:

            self.activity_list.addItem(item)
            
        self.activity_list.scrollToTop()

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
        
        self.devices_value.setText(
            str(self.device_count)
        )

        self.update_system_status()

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

    def build_network_activity_page(self):

        page = QWidget()

        main_layout = QVBoxLayout()

        # =====================================
        # Live Graph
        # =====================================

        graph_title = QLabel("Live Network Activity")

        graph_title.setStyleSheet("""
            font-size:18px;
            font-weight:600;
            color:white;
        """)

        main_layout.addWidget(graph_title)

        self.graph_widget = pg.PlotWidget()

        self.graph_widget.setBackground("#1E293B")

        self.graph_widget.showGrid(x=True, y=True)

        self.graph_widget.setMaximumHeight(260)

        self.graph_line = self.graph_widget.plot(
            pen="#22C55E"
        )

        main_layout.addWidget(self.graph_widget)

        # =====================================
        # Main Content
        # =====================================

        content_layout = QHBoxLayout()

        # -------------------------------------
        # Left Column
        # -------------------------------------

        left = QVBoxLayout()

        left.addWidget(QLabel("Top Applications"))

        self.application_table = QTableWidget()

        self.application_table.setColumnCount(3)

        self.application_table.setHorizontalHeaderLabels([
            "Application",
            "Usage",
            "%"
        ])

        self.application_table.horizontalHeader().setStretchLastSection(False)

        self.application_table.horizontalHeader().setSectionResizeMode(
            0,
            QHeaderView.ResizeMode.Stretch
        )

        self.application_table.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeMode.Stretch
        )

        self.application_table.horizontalHeader().setSectionResizeMode(
            2,
            QHeaderView.ResizeMode.ResizeToContents
        )

        self.application_table.verticalHeader().hide()

        self.application_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        left.addWidget(self.application_table)

        left.addWidget(QLabel("Protocol Usage"))

        self.protocol_list = QListWidget()

        left.addWidget(self.protocol_list)

        # -------------------------------------
        # Right Column
        # -------------------------------------

        right = QVBoxLayout()

        right.addWidget(QLabel("Top Destinations"))

        self.destination_list = QListWidget()

        right.addWidget(self.destination_list)

        right.addWidget(QLabel("Live Activity"))

        self.activity_list = QListWidget()

        right.addWidget(self.activity_list)

        # =====================================
        # Assemble Layout
        # =====================================

        content_layout.addLayout(left, 1)

        content_layout.addLayout(right, 2)

        main_layout.addLayout(content_layout)

        page.setLayout(main_layout)

        self.pages.addWidget(page)

    def build_security_page(self):

        page = QWidget()

        main_layout = QVBoxLayout()

        # =====================================
        # Title
        # =====================================

        title = QLabel("Security Centre")

        title.setStyleSheet("""
            font-size:22px;
            font-weight:bold;
            color:white;
        """)

        main_layout.addWidget(title)

        # =====================================
        # Empty State
        # =====================================

        self.empty_security = QFrame()

        self.empty_security.setStyleSheet("""
            QFrame{
                background:#1E293B;
                border:1px solid #334155;
                border-radius:12px;
            }
        """)

        empty_layout = QVBoxLayout(self.empty_security)

        posture = QLabel("🟢 Security Posture: Secure")

        posture.setStyleSheet("""
            font-size:20px;
            font-weight:bold;
            color:#22C55E;
        """)

        empty_layout.addWidget(posture)

        summary = QLabel(
            "No active security findings have been detected.\n\n"
            "Mycelium is actively monitoring your network traffic."
        )

        summary.setWordWrap(True)

        summary.setStyleSheet("""
            color:#CBD5E1;
            font-size:13px;
        """)

        empty_layout.addWidget(summary)

        empty_layout.addSpacing(15)

        modules = QLabel(
            "Detection Modules\n\n"
            "🟢 Beacon Detection\n"
            "🟢 Port Monitoring\n"
            "🟢 Process Analysis\n"
            "🟢 GeoIP Intelligence"
        )

        modules.setStyleSheet("""
            font-size:13px;
            color:white;
        """)

        empty_layout.addWidget(modules)

        empty_layout.addSpacing(15)

        self.security_summary = QLabel()

        self.security_summary.setStyleSheet("""
            font-size:13px;
            color:#E2E8F0;
        """)

        empty_layout.addWidget(self.security_summary)

        empty_layout.addSpacing(15)

        self.tip_label = QLabel()
        self.tip_label.setWordWrap(True)

        self.tip_label.setStyleSheet("""
        color:#94A3B8;
        font-size:12px;
        """)

        empty_layout.addWidget(self.tip_label)

        empty_layout.addStretch()

        main_layout.addWidget(self.empty_security)

        # =====================================
        # Threat View
        # =====================================

        self.threat_widget = QWidget()

        content_layout = QHBoxLayout()

        self.security_list = QListWidget()

        self.security_list.currentRowChanged.connect(
            self.show_security_details
        )

        details_layout = QVBoxLayout()

        self.security_title = QLabel("Select a finding")

        self.security_title.setStyleSheet("""
            font-size:20px;
            font-weight:bold;
            color:white;
        """)

        self.security_details = QLabel(
            "Details will appear here."
        )

        self.security_details.setWordWrap(True)

        details_layout.addWidget(self.security_title)

        details_layout.addWidget(self.security_details)

        details_layout.addStretch()

        details_widget = QWidget()

        details_widget.setLayout(details_layout)

        content_layout.addWidget(
            self.security_list,
            2
        )

        content_layout.addWidget(
            details_widget,
            3
        )

        self.threat_widget.setLayout(content_layout)

        self.threat_widget.hide()

        main_layout.addWidget(self.threat_widget)

        page.setLayout(main_layout)
        self.update_security_tip()  
        self.pages.addWidget(page)
        
    def update_security_tip(self):

        self.tip_label.setText(
            f"""
    Security Tip

    💡 {self.security_tips[self.current_tip]}
    """
        )

        self.current_tip += 1

        if self.current_tip >= len(self.security_tips):

            self.current_tip = 0  
            
    def update_security_page(self):

        self.security_list.clear()

        if not self.security_events:

            self.empty_security.show()

            self.threat_widget.hide()

            self.update_security_summary()

            return

        self.empty_security.hide()

        self.threat_widget.show()

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

    def update_security_summary(self):

        elapsed = int(time.time() - self.start_time)

        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60

        self.security_summary.setText(
            f"""
    Packets Analysed      {self.packet_count:,}

    Threats Detected      {self.alert_count}

    Monitoring Time       {hours:02}:{minutes:02}:{seconds:02}
    """
        )
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

    def build_threat_map_page(self):

        page = QWidget()

        layout = QVBoxLayout()

        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # ============================================
        # Title
        # ============================================

        title = QLabel("Global Threat Map")

        title.setStyleSheet("""
            font-size:22px;
            font-weight:700;
            color:white;
        """)

        subtitle = QLabel(
            "Real-time visualisation of external network communications and detected security events."
        )

        subtitle.setStyleSheet("""
            color:#94A3B8;
            font-size:13px;
        """)

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # ============================================
        # Statistics
        # ============================================

        cards = QHBoxLayout()

        self.countries_card, self.countries_value = self.create_stat_card(
            "Countries Reached",
            "0"
        )

        self.hosts_card, self.hosts_value = self.create_stat_card(
            "External Hosts",
            "0"
        )

        self.connections_card, self.connections_value = self.create_stat_card(
            "Top Country",
            "-"
        )

        self.threats_card, self.threats_value = self.create_stat_card(
            "Threat Events",
            "0"
        )

        cards.addWidget(self.countries_card)
        cards.addWidget(self.hosts_card)
        cards.addWidget(self.connections_card)
        cards.addWidget(self.threats_card)

        layout.addLayout(cards)

        # ============================================
        # Map
        # ============================================

        self.map_widget = MapWidget()

        self.map_widget.setMinimumHeight(600)

        layout.addWidget(self.map_widget)

        page.setLayout(layout)

        self.pages.addWidget(page)
        

    def update_map_statistics(self):

        self.countries_value.setText(
            str(len(self.map_countries))
        )

        self.hosts_value.setText(
            str(len(self.external_hosts))
        )

        if self.country_counter:

            top_country = self.country_counter.most_common(1)[0][0]

        else:

            top_country = "-"

        self.connections_value.setText(
            top_country
        )

        self.threats_value.setText(
            str(self.alert_count)
        )
        
    def export_report(self):

        filename, _ = QFileDialog.getSaveFileName(

            self,

            "Export Security Report",

            "Mycelium_Report.pdf",

            "PDF Files (*.pdf)"

        )

        if filename:

            generate_report(

                filename,

                self

            )

            QMessageBox.information(

                self,

                "Report Exported",

                "Security report saved successfully."

            )