from scapy.all import (
    ARP,
    Ether,
    srp,
    IP,
    ICMP,
    sr1
)

from mac_vendor_lookup import MacLookup

import socket


def guess_device_type(
    hostname,
    vendor,
    ttl=None
):

    host = hostname.lower()

    vendor = vendor.lower()

    # Apple
    if (
        "apple" in vendor
        or "iphone" in host
        or "ipad" in host
        or "macbook" in host
    ):
        return "Apple Device"

    # Android
    if (
        "android" in host
        or "galaxy" in host
        or "samsung" in vendor
    ):
        return "Android Device"

    # Routers
    if (
        "tp-link" in vendor
        or "router" in host
        or ttl == 255
    ):
        return "Router"

    # Raspberry Pi
    if (
        "raspberry" in vendor
        or "raspberrypi" in host
    ):
        return "Raspberry Pi"

    # Smart TVs
    if (
        "lg" in vendor
        or "webos" in host
        or "tv" in host
    ):
        return "Smart TV"

    # Windows
    if (
        host.startswith("desktop-")
        or host.startswith("laptop-")
        or ttl == 128
    ):
        return "Windows Device"

    # Linux/macOS
    if ttl == 64:
        return "Linux/macOS"

    return "Unknown"


def scan_network(ip_range):

    devices = []

    arp = ARP(
        pdst=ip_range
    )

    ether = Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    packet = ether / arp

    result = srp(
        packet,
        timeout=2,
        verbose=0,
        iface="Realtek RTL8822CE 802.11ac PCIe Adapter"
    )[0]

    for sent, received in result:

        ip = received.psrc

        mac = received.hwsrc

        # =========================
        # VENDOR LOOKUP
        # =========================

        try:

            vendor = MacLookup().lookup(mac)

        except:

            vendor = "Unknown"

        # =========================
        # HOSTNAME LOOKUP
        # =========================

        try:

            hostname = socket.gethostbyaddr(ip)[0]

        except:

            hostname = "Unknown"

        # =========================
        # TTL FINGERPRINTING
        # =========================

        ttl = None

        try:

            reply = sr1(
                IP(dst=ip) / ICMP(),
                timeout=1,
                verbose=0
            )

            if reply:

                ttl = reply.ttl

        except:

            pass

        # =========================
        # DEVICE GUESSING
        # =========================

        device_type = guess_device_type(
            hostname,
            vendor,
            ttl
        )

        devices.append({

            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "device_type": device_type
        })

    return devices