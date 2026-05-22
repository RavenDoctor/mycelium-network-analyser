from scapy.all import sniff

from datetime import datetime

from PyQt6.QtCore import QObject, pyqtSignal

from utils.process_lookup import get_process_by_port

from detection.heuristics import analyse_packet


class PacketSniffer(QObject):

    packet_received = pyqtSignal(
        str,  # time
        str,  # src
        str,  # dst
        str,  # sport
        str,  # dport
        str,  # proto
        str,  # process
        str,  # alerts
        str   # severity
    )

    def __init__(self):

        super().__init__()

    def process_packet(self, packet):

        try:

            if packet.haslayer("IP"):

                src = packet["IP"].src

                dst = packet["IP"].dst

                proto = packet["IP"].proto

                # Protocol names
                if proto == 6:
                    proto_name = "TCP"

                elif proto == 17:
                    proto_name = "UDP"

                else:
                    proto_name = str(proto)

                # Default ports
                sport = "?"

                dport = "?"

                # TCP
                if packet.haslayer("TCP"):

                    sport = str(packet["TCP"].sport)

                    dport = str(packet["TCP"].dport)

                # UDP
                elif packet.haslayer("UDP"):

                    sport = str(packet["UDP"].sport)

                    dport = str(packet["UDP"].dport)

                # Process lookup
                if sport != "?":

                    process_name = get_process_by_port(
                        int(sport)
                    )

                else:
                    process_name = "Unknown"

                # Detection engine
                alerts, severity = analyse_packet(
                    process_name,
                    dport,
                    dst
                )

                timestamp = datetime.now().strftime(
                    "%H:%M:%S"
                )

                # Emit safely to GUI
                self.packet_received.emit(
                    timestamp,
                    src,
                    dst,
                    sport,
                    dport,
                    proto_name,
                    process_name,
                    ", ".join(alerts),
                    severity
                )

        except Exception as e:

            print(e)

    def start(self):

        sniff(
            prn=self.process_packet,
            store=False
        )