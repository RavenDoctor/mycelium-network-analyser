from collections import defaultdict
from detection.beacon_data import beaconing_results
import time



# Stores timestamps per IP
connections = defaultdict(list)

from collections import defaultdict

import time


connections = defaultdict(list)


def detect_beaconing(
    dst_ip,
    process
):

    # Ignore browsers
    ignored = [
        "chrome.exe",
        "msedge.exe",
        "opera.exe",
        "firefox.exe",
        "steam.exe"
    ]

    if process.lower() in ignored:
        return False

    now = time.time()

    connections[dst_ip].append(now)

    timestamps = connections[dst_ip]

    # Need more samples
    if len(timestamps) < 8:
        return False

    # Keep latest 15
    if len(timestamps) > 15:

        timestamps.pop(0)

    intervals = []

    for i in range(1, len(timestamps)):

        interval = (
            timestamps[i]
            - timestamps[i - 1]
        )

        intervals.append(interval)

    avg = sum(intervals) / len(intervals)

    # Ignore rapid noisy traffic
    if avg < 5:
        return False

    # Much stricter consistency
    consistent = all(

        abs(i - avg) < 1

        for i in intervals
    )

    if consistent:

        beaconing_results[dst_ip] = {

        "hits": len(timestamps),

        "avg_interval": round(avg, 2)
    }

    return consistent