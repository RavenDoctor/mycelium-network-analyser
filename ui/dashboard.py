from PyQt6.QtWidgets import (
    QMainWindow,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QLabel,
    QHBoxLayout,
    QHeaderView,
    QSplitter,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QStackedWidget,
)

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal

from ui.map_widget import MapWidget

from threatintel.geoip import lookup_ip

from network.lan_scanner import scan_network

from network.port_scanner import scan_ports

import pyqtgraph as pg

import time

from collections import deque

from detection.beacon_data import beaconing_results

class LanScanWorker(QThread):

    finished = pyqtSignal(list)

    def run(self):

        devices = scan_network(
            "192.168.0.0/24"
        )

        self.finished.emit(devices)

class Dashboard(QMainWindow):

    def __init__(self):

        super().__init__()

        # =========================
        # STATE
        # =========================

        self.packet_count = 0

        self.packet_rate = 0

        self.graph_data = deque(maxlen=30)

        self.last_seen_paths = {}

        self.geo_cache = {}

        # =========================
        # WINDOW
        # =========================

        self.setWindowTitle("Mycelium")

        self.resize(1600, 900)

        # =========================
        # SIDEBAR
        # =========================

        self.sidebar = QListWidget()

        self.sidebar.addItems([
            "Dashboard",
            "Packet Analysis",
            "LAN Recon",
            "Beacon Analysis"
        ])

        self.sidebar.setFixedWidth(220)

        self.sidebar.currentRowChanged.connect(
            self.change_page
        )

        # =========================
        # STACKED PAGES
        # =========================

        self.pages = QStackedWidget()

        # =========================
        # PACKET TABLE
        # =========================

        self.table = QTableWidget()

        self.table.setColumnCount(9)

        self.table.setHorizontalHeaderLabels([
            "Time",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Protocol",
            "Process",
            "Alerts",
            "Severity"
        ])

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        # =========================
        # GRAPH
        # =========================

        self.graph_widget = pg.PlotWidget()

        self.graph_widget.getPlotItem().layout.setContentsMargins(
            20,
            10,
            10,
            20
        )

        self.graph_widget.setMinimumHeight(220)
        self.graph_widget.setMaximumHeight(260)

        self.graph_widget.setTitle(
            '<span style="color:#4dd0e1;'
            'font-size:16pt;'
            'font-family:Orbitron;">'
            'Packets Per Second'
            '</span>'
        )

        self.graph_widget.showGrid(
            x=True,
            y=True
        )

        self.graph_widget.getAxis(
            "left"
        ).setTextPen("#4dd0e1")

        self.graph_widget.getAxis(
            "left"
        ).setWidth(60)

        self.graph_widget.getAxis(
            "bottom"
        ).setTextPen("#4dd0e1")

        self.graph_widget.setYRange(0, 100)

        self.graph_line = self.graph_widget.plot(
            pen='#4dd0e1'
        )

        # =========================
        # MAP
        # =========================

        self.map_widget = MapWidget()

        # =========================
        # THREAT FEED
        # =========================

        self.threat_feed = QListWidget()

        self.threat_feed.setFixedWidth(180)

        # =========================
        # LAN TABLE
        # =========================

        self.lan_table = QTableWidget()

        self.lan_table.setColumnCount(5)

        self.lan_table.setHorizontalHeaderLabels([
            "IP",
            "MAC",
            "Vendor",
            "Hostname",
            "Device Type"
        ])

        self.lan_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.lan_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        # =========================
        # BEACON TABLE
        # =========================

        self.beacon_table = QTableWidget()

        self.beacon_table.setColumnCount(4)

        self.beacon_table.setHorizontalHeaderLabels([
        "Destination IP",
        "Hits",
        "Avg Interval",
        "Severity"
        ])

        self.beacon_table.horizontalHeader().setSectionResizeMode(
        QHeaderView.ResizeMode.Stretch
        )

        self.beacon_table.setEditTriggers(
        QTableWidget.EditTrigger.NoEditTriggers
        )

        # =========================
        # BEACON PAGE
        # =========================

        beacon_page = QWidget()

        beacon_layout = QVBoxLayout()

        beacon_layout.addWidget(
            self.beacon_table
        )

        beacon_page.setLayout(
            beacon_layout
        )

        # =========================
        # PORT SCANNER TABLE
        # =========================

        self.port_table = QTableWidget()

        self.port_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )   

        self.port_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.port_table.setColumnCount(4)

        self.port_table.setHorizontalHeaderLabels([
            "Port",
            "Service",
            "Status",
            "Risk"
        ])

        self.port_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.port_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.target_input = QLabel(
        "Select device from LAN Recon"
        )

        # =========================
        # TOP BAR
        # =========================

        self.health_card = QLabel("Network Health\n85/100")
        self.device_card = QLabel("Devices\n0")
        self.alert_card = QLabel("Alerts\n0")
        card_style = """
        QLabel {
            background-color: #2b2b2b;
            border-radius: 10px;
            padding: 20px;
            font-size: 18px;
        }
        """

        self.health_card.setStyleSheet(card_style)
        self.device_card.setStyleSheet(card_style)
        self.alert_card.setStyleSheet(card_style)
        self.scan_button = QPushButton(
            "Scan LAN"
        )

        self.scan_button.clicked.connect(
        self.run_lan_scan
        )


        top_bar = QHBoxLayout()

        top_bar.addWidget(
            self.packet_label
        )

        top_bar.addWidget(
            self.alert_label
        )

        top_bar.addWidget(
            self.status_label
        )

        top_bar.addWidget(
        self.scan_button
        )

        top_bar.addStretch()

        # =========================
        # DASHBOARD SPLITTERS
        # =========================

        left_splitter = QSplitter(
            Qt.Orientation.Vertical
        )

        left_splitter.addWidget(
            self.graph_widget
        )

        left_splitter.addWidget(
            self.map_widget
        )

        left_splitter.setStretchFactor(0, 1)

        left_splitter.setStretchFactor(1, 6)

        top_splitter = QSplitter(
            Qt.Orientation.Horizontal
        )

        top_splitter.addWidget(
            left_splitter
        )

        top_splitter.addWidget(
            self.threat_feed
        )

        top_splitter.setStretchFactor(0, 8)

        top_splitter.setStretchFactor(1, 1)

        # =========================
        # DASHBOARD PAGE
        # =========================

        dashboard_page = QWidget()

        dashboard_layout = QVBoxLayout()

        dashboard_layout.addWidget(
            top_splitter
        )

        dashboard_page.setLayout(
            dashboard_layout
        )

        # =========================
        # PACKET PAGE
        # =========================

        packet_page = QWidget()

        packet_layout = QVBoxLayout()

        packet_layout.addWidget(
            self.table
        )

        packet_page.setLayout(
            packet_layout
        )

        # =========================
        # LAN PAGE
        # =========================

        lan_page = QWidget()

        lan_layout = QHBoxLayout()

        lan_splitter = QSplitter(
            Qt.Orientation.Horizontal
        )

        # LEFT SIDE
        left_widget = QWidget()

        left_layout = QVBoxLayout()

        left_layout.addWidget(
            self.lan_table
        )

        left_widget.setLayout(
            left_layout
        )

        # RIGHT SIDE
        right_widget = QWidget()

        right_layout = QVBoxLayout()

        self.selected_device_label = QLabel(
            "No device selected"
        )

        right_layout.addWidget(
            self.selected_device_label
        )

        right_layout.addWidget(
            self.port_table
        )

        right_widget.setLayout(
            right_layout
        )

        # ADD TO SPLITTER
        lan_splitter.addWidget(
            left_widget
        )

        lan_splitter.addWidget(
            right_widget
        )

        lan_splitter.setStretchFactor(0, 2)

        lan_splitter.setStretchFactor(1, 1)

        lan_layout.addWidget(
            lan_splitter
        )

        lan_page.setLayout(
            lan_layout
        )

        # =========================
        # ADD PAGES
        # =========================

        self.pages.addWidget(
            dashboard_page
        )

        self.pages.addWidget(
            packet_page
        )

        self.pages.addWidget(
            lan_page
        )

        self.pages.addWidget(
            beacon_page
        )

        # =========================
        # MAIN LAYOUT
        # =========================

        content_layout = QHBoxLayout()

        content_layout.addWidget(
            self.sidebar
        )

        content_layout.addWidget(
            self.pages
        )

        layout = QVBoxLayout()

        layout.addLayout(
            top_bar
        )

        layout.addLayout(
            content_layout
        )

        container = QWidget()

        container.setLayout(
            layout
        )

        self.setCentralWidget(
            container
        )

        # =========================
        # TIMERS
        # =========================

        self.timer = QTimer()

        self.timer.timeout.connect(
            self.update_graph
        )

        self.timer.start(1000)

    # =========================
    # PAGE SWITCHING
    # =========================

    def change_page(self, index):

        self.pages.setCurrentIndex(index)

    # =========================
    # GRAPH UPDATES
    # =========================

    def update_graph(self):

        self.graph_data.append(
            self.packet_rate
        )

        self.graph_line.setData(
            list(self.graph_data)
        )

        self.packet_rate = 0

        self.update_beacon_table()

    # =========================
    # PACKET PROCESSING
    # =========================

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

        MAX_ROWS = 300

        row = self.table.rowCount()

        self.table.insertRow(row)

        values = [
            timestamp,
            src,
            dst,
            sport,
            dport,
            proto,
            process,
            alerts,
            severity
        ]

        for col, value in enumerate(values):

            self.table.setItem(
                row,
                col,
                QTableWidgetItem(str(value))
            )

        # =========================
        # PROTOCOL COLORS
        # =========================

        if proto == "TCP":

            self.table.item(
                row,
                5
            ).setForeground(
                Qt.GlobalColor.cyan
            )

        elif proto == "UDP":

            self.table.item(
                row,
                5
            ).setForeground(
                Qt.GlobalColor.yellow
            )

        # =========================
        # SEVERITY COLORS
        # =========================

        if severity == "HIGH":

            self.table.item(
                row,
                8
            ).setForeground(
                Qt.GlobalColor.red
            )

        elif severity == "MEDIUM":

            self.table.item(
                row,
                8
            ).setForeground(
                Qt.GlobalColor.yellow
            )

        elif severity == "LOW":

            self.table.item(
                row,
                8
            ).setForeground(
                Qt.GlobalColor.green
            )

        # =========================
        # THREAT FEED
        # =========================

        if severity in ["HIGH", "MEDIUM"]:

            current = int(
                self.alert_label.text().split(": ")[1]
            )

            self.alert_label.setText(
                f"Threats: {current + 1}"
            )

            message = (
                f"[{severity}] "
                f"{process} → {alerts}"
            )

            item = QListWidgetItem(message)

            if severity == "HIGH":

                item.setForeground(
                    Qt.GlobalColor.red
                )

            elif severity == "MEDIUM":

                item.setForeground(
                    Qt.GlobalColor.yellow
                )

            self.threat_feed.insertItem(
                0,
                item
            )

            if self.threat_feed.count() > 100:

                self.threat_feed.takeItem(100)

        # =========================
        # ROW LIMIT
        # =========================

        if self.table.rowCount() > MAX_ROWS:

            self.table.removeRow(0)

        # =========================
        # PACKET STATS
        # =========================

        self.packet_count += 1

        self.packet_rate += 1

        self.packet_label.setText(
            f"Packets: {self.packet_count}"
        )

        # =========================
        # MAP VISUALISATION
        # =========================

        if (
            dst.startswith("192.168.")
            or dst.startswith("10.")
            or dst.startswith("172.")
            or dst.startswith("127.")
        ):
            return

        current_time = time.time()

        cooldown = 5

        last_seen = self.last_seen_paths.get(
            dst,
            0
        )

        if current_time - last_seen > cooldown:

            self.last_seen_paths[dst] = current_time

            if dst in self.geo_cache:

                geo = self.geo_cache[dst]

            else:

                geo = lookup_ip(dst)

                if geo:

                    self.geo_cache[dst] = geo

            if geo and self.map_widget.map_ready:

                popup = f"""
                <b>IP:</b> {dst}<br>
                <b>Country:</b> {geo["country"]}<br>
                <b>Process:</b> {process}<br>
                <b>Severity:</b> {severity}<br>
                <b>Alert:</b> {alerts}
                """

                js = f"""
                addAttackPath(
                    {geo['lat']},
                    {geo['lon']},
                    `{popup}`,
                    '{severity}'
                );
                """

                self.map_widget.page().runJavaScript(js)

    # =========================
    # LAN SCANNING
    # =========================

    def run_lan_scan(self):

        self.status_label.setText(
            "Status: Scanning LAN..."
        )

        self.scan_button.setEnabled(False)

        self.worker = LanScanWorker()

        self.worker.finished.connect(
            self.populate_lan_table
        )

        self.lan_table.cellDoubleClicked.connect(
            self.scan_selected_device
        )

        self.worker.start()

    def populate_lan_table(self, devices):

        self.lan_table.setRowCount(0)

        for device in devices:

            row = self.lan_table.rowCount()

            self.lan_table.insertRow(row)

            self.lan_table.setItem(
                row,
                0,
                QTableWidgetItem(device["ip"])
            )

            self.lan_table.setItem(
                row,
                1,
                QTableWidgetItem(device["mac"])
            )

            self.lan_table.setItem(
                row,
                2,
                QTableWidgetItem(device["vendor"])
            )

            self.lan_table.setItem(
                row,
                3,
                QTableWidgetItem(
                    device["hostname"]
                )
            )

            self.lan_table.setItem(
                row,
                4,
                QTableWidgetItem(
                    device["device_type"]
                )
            )

        self.status_label.setText(
            "Status: Monitoring"
        )

        self.scan_button.setEnabled(True)

    def update_beacon_table(self):

        self.beacon_table.setRowCount(0)

        for ip, data in beaconing_results.items():

            row = self.beacon_table.rowCount()

            self.beacon_table.insertRow(row)

            self.beacon_table.setItem(
                row,
                0,
                QTableWidgetItem(ip)
            )

            self.beacon_table.setItem(
                row,
                1,
                QTableWidgetItem(
                    str(data["hits"])
                )
            )

            self.beacon_table.setItem(
                row,
                2,
                QTableWidgetItem(
                    f'{data["avg_interval"]}s'
                )
            )

            severity_item = QTableWidgetItem(
                "HIGH"
            )

            severity_item.setForeground(
                Qt.GlobalColor.red
            )

            self.beacon_table.setItem(
                row,
                3,
                severity_item
            )

    def scan_selected_device(
        self,
        row,
        column
    ):

            ip_item = self.lan_table.item(
            row,
            0
        )

            if not ip_item:
                return

            ip = ip_item.text()

            self.selected_device_label.setText(
                f"Scanning: {ip}"
            )

            self.port_table.setRowCount(0)

            results = scan_ports(ip)

            for result in results:

                row_position = self.port_table.rowCount()

                self.port_table.insertRow(
                    row_position
                )

                self.port_table.setItem(
                    row_position,
                    0,
                    QTableWidgetItem(
                        str(result["port"])
                    )
                )

                self.port_table.setItem(
                    row_position,
                    1,
                    QTableWidgetItem(
                        result["service"]
                    )
                )

                self.port_table.setItem(
                    row_position,
                    2,
                    QTableWidgetItem(
                        "OPEN"
                    )
                )

                risk_item = QTableWidgetItem(
                    result["risk"]
                )

                if result["risk"] == "HIGH":

                    risk_item.setForeground(
                        Qt.GlobalColor.red
                    )

                elif result["risk"] == "MEDIUM":

                    risk_item.setForeground(
                        Qt.GlobalColor.yellow
                    )

                else:

                    risk_item.setForeground(
                        Qt.GlobalColor.green
                    )

                self.port_table.setItem(
                    row_position,
                    3,
                    risk_item
                )

            self.selected_device_label.setText(
                f"Device Analysis: {ip}"
            )