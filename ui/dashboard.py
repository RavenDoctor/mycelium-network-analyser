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
    QTabWidget
)

from PyQt6.QtCore import Qt, QTimer

from ui.map_widget import MapWidget

from threatintel.geoip import lookup_ip

import pyqtgraph as pg

import time

from collections import deque

from network.lan_scanner import scan_network


class Dashboard(QMainWindow):

    def __init__(self):

        super().__init__()

        self.packet_count = 0

        self.packet_rate = 0

        self.graph_data = deque(maxlen=60)

        # Map state
        self.last_seen_paths = {}

        self.geo_cache = {}

        self.setWindowTitle("Mycelium")

        self.resize(1600, 900)

        # =========================
        # TABLE
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

        header = self.table.horizontalHeader()

        header.setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )

        self.table.setAlternatingRowColors(True)

        # =========================
        # GRAPH
        # =========================

        self.graph_widget = pg.PlotWidget()

        self.graph_widget.setTitle(
            '<span style="color:#00ffee;'
            'font-size:16pt;'
            'font-family:Orbitron;">'
            'Packets Per Second'
            '</span>'
        )

        self.graph_widget.showGrid(
            x=True,
            y=True
        )

        axis_style = {
        "color": "#00ffee",
        "font-size": "10pt",
        "font-family": "Share Tech Mono"
        }

        self.graph_widget.getAxis(
        "left"
        ).setTextPen("#00ffee")

        self.graph_widget.getAxis(
        "bottom"
        ).setTextPen("#00ffee")

        self.graph_widget.setYRange(0, 100)

        self.graph_line = self.graph_widget.plot(
            pen='c'
        )

        # =========================
        # MAP
        # =========================

        self.map_widget = MapWidget()

        # =========================
        # THREAT FEED
        # =========================

        self.threat_feed = QListWidget()

        self.threat_feed.setMinimumWidth(350)

# =========================
# LAN DEVICES
# =========================

        self.lan_table = QTableWidget()

        self.lan_table.setColumnCount(3)

        self.lan_table.setHorizontalHeaderLabels([
        "IP",
        "MAC",
        "Vendor"
        ])

        self.lan_table.horizontalHeader().setSectionResizeMode(
        QHeaderView.ResizeMode.Stretch
        )

        self.lan_table.setMaximumHeight(220)   

# =========================
# TAB SYSTEM
# =========================

        self.tabs = QTabWidget()

        self.tabs.addTab(
            self.table,
            "Packets"
        )

        self.tabs.addTab(
            self.lan_table,
            "LAN Devices"
        )    

        # =========================
        # STATS BAR
        # =========================

        self.packet_label = QLabel(
            "Packets: 0"
        )

        self.alert_label = QLabel(
            "Threats: 0"
        )

        self.status_label = QLabel(
            "Status: Monitoring"
        )
        from PyQt6.QtWidgets import QPushButton

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
        # SPLITTERS
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

        left_splitter.setSizes([300, 400])

        top_splitter = QSplitter(
            Qt.Orientation.Horizontal
        )

        top_splitter.addWidget(
            left_splitter
        )

        top_splitter.addWidget(
            self.threat_feed
        )

        top_splitter.setSizes([1200, 300])

        main_splitter = QSplitter(
            Qt.Orientation.Vertical
        )

        main_splitter.addWidget(
            top_splitter
        )

        main_splitter.addWidget(
            self.tabs
        )

        main_splitter.setSizes([350, 550])
        # =========================
        # MAIN LAYOUT
        # =========================

        layout = QVBoxLayout()

        layout.addLayout(
            top_bar
        )

        layout.addWidget(
            main_splitter
        )

        container = QWidget()

        container.setLayout(
            layout
        )

        self.setCentralWidget(
            container
        )

        # =========================
        # GRAPH TIMER
        # =========================

        self.timer = QTimer()

        self.timer.timeout.connect(
            self.update_graph
        )

        self.timer.start(1000)

    def update_graph(self):

        self.graph_data.append(
            self.packet_rate
        )

        self.graph_line.setData(
            list(self.graph_data)
        )

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

        MAX_ROWS = 1000

        row = self.table.rowCount()

        self.table.insertRow(row)

        # =========================
        # TABLE DATA
        # =========================

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
                row, 5
            ).setForeground(
                Qt.GlobalColor.cyan
            )

        elif proto == "UDP":

            self.table.item(
                row, 5
            ).setForeground(
                Qt.GlobalColor.yellow
            )

        # =========================
        # SEVERITY COLORS
        # =========================

        if severity == "HIGH":

            self.table.item(
                row, 8
            ).setForeground(
                Qt.GlobalColor.red
            )

        elif severity == "MEDIUM":

            self.table.item(
                row, 8
            ).setForeground(
                Qt.GlobalColor.yellow
            )

        elif severity == "LOW":

            self.table.item(
                row, 8
            ).setForeground(
                Qt.GlobalColor.green
            )

        # =========================
        # THREAT COUNTER
        # =========================

        if severity in ["HIGH", "MEDIUM"]:

            current = int(
                self.alert_label.text().split(": ")[1]
            )

            self.alert_label.setText(
                f"Threats: {current + 1}"
            )

        # =========================
        # THREAT FEED
        # =========================

        if severity in ["HIGH", "MEDIUM"]:

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

            # Feed size limit
            if self.threat_feed.count() > 100:

                self.threat_feed.takeItem(100)

        # =========================
        # ROW LIMIT
        # =========================

        if self.table.rowCount() > MAX_ROWS:

            self.table.removeRow(0)

        # =========================
        # AUTO SCROLL
        # =========================

        self.table.scrollToBottom()

        # =========================
        # PACKET COUNTERS
        # =========================

        self.packet_count += 1

        self.packet_rate += 1

        self.packet_label.setText(
            f"Packets: {self.packet_count}"
        )

        # =========================
        # MAP GEOLOCATION
        # =========================

        # Skip local/private IPs
        if (
            dst.startswith("192.168.")
            or dst.startswith("10.")
            or dst.startswith("172.")
            or dst.startswith("127.")
        ):
            return

        # =========================
        # PATH RATE LIMITING
        # =========================

        current_time = time.time()

        cooldown = 3

        last_seen = self.last_seen_paths.get(
            dst,
            0
        )

        # Redraw every X seconds
        if current_time - last_seen > cooldown:

            self.last_seen_paths[dst] = current_time

            # Use cache
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
            
    def run_lan_scan(self):

        self.lan_table.setRowCount(0)

        devices = scan_network(
            "192.168.1.0/24"
        )

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