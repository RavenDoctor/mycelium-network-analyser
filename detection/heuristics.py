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
    dport
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

    return alerts, severity