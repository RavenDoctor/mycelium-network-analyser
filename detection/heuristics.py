from detection.beaconing import detect_beaconing

SUSPICIOUS_PORTS = [
    4444,
    5555,
    1337,
    6666,
    31337
]

SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe"
]


def analyse_packet(
    process,
    dport,
    dst_ip
):

    alerts = []

    severity = "LOW"

    # Suspicious ports
    if str(dport).isdigit():

        if int(dport) in SUSPICIOUS_PORTS:

            alerts.append(
                f"Suspicious destination port: {dport}"
            )

            severity = "HIGH"

    # Suspicious processes
    if process.lower() in SUSPICIOUS_PROCESSES:

        alerts.append(
            f"Suspicious process: {process}"
        )

        severity = "MEDIUM"

# Beacon detection
    if detect_beaconing(dst_ip, process):

        alerts.append(
            "Possible beaconing detected"
        )

        severity = "HIGH"

    return alerts, severity