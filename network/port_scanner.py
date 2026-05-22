import socket


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-ALT"
}


def scan_ports(ip):

    results = []

    for port in COMMON_PORTS:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.5)

        result = sock.connect_ex(
            (ip, port)
        )

        if result == 0:

            service = COMMON_PORTS.get(
                port,
                "Unknown"
            )

            risk = "LOW"

            if port in [445, 3389, 23]:
                risk = "HIGH"

            elif port in [21, 139]:
                risk = "MEDIUM"

            results.append({

                "port": port,
                "service": service,
                "risk": risk
            })

        sock.close()

    return results