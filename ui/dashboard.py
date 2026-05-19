from PyQt6.QtWidgets import (
    QMainWindow,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QLabel,
    QHBoxLayout,
    QHeaderView,
    QSplitter
)

from PyQt6.QtCore import Qt, QTimer

from ui.map_widget import MapWidget

from threatintel.geoip import lookup_ip

import pyqtgraph as pg

from collections import deque


class Dashboard(QMainWindow):

    def __init__(self):

        super().__init__()

        self.packet_count = 0

        self.packet_rate = 0

        self.graph_data = deque(maxlen=60)

        # Map caching
        self.seen_ips = set()

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
            "Packets Per Second"
        )

        self.graph_widget.showGrid(
            x=True,
            y=True
        )

        self.graph_widget.setYRange(0, 100)

        self.graph_line = self.graph_widget.plot(
            pen='c'
        )

        # =========================
        # MAP
        # =========================

        self.map_widget = MapWidget()

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

        top_bar.addStretch()

        # =========================
        # SPLITTERS
        # =========================

        top_splitter = QSplitter(
            Qt.Orientation.Horizontal
        )

        top_splitter.addWidget(
            self.graph_widget
        )

        top_splitter.addWidget(
            self.map_widget
        )

        top_splitter.setSizes([700, 700])

        main_splitter = QSplitter(
            Qt.Orientation.Vertical
        )

        main_splitter.addWidget(
            top_splitter
        )

        main_splitter.addWidget(
            self.table
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
        time,
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
            time,
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

        # Only process NEW IPs
        if dst not in self.seen_ips:

            self.seen_ips.add(dst)

            # Use cache
            if dst in self.geo_cache:

                geo = self.geo_cache[dst]

            else:

                geo = lookup_ip(dst)

                if geo:

                    self.geo_cache[dst] = geo

            if geo and self.map_widget.map_ready:

                js = f"""
                addMarker(
                    {geo['lat']},
                    {geo['lon']},
                    '{dst} ({geo["country"]})'
                );
                """

                self.map_widget.page().runJavaScript(js)