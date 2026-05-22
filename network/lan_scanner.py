from scapy.all import ARP, Ether, srp

from mac_vendor_lookup import MacLookup


def scan_network(ip_range):

    devices = []

    arp = ARP(pdst=ip_range)

    ether = Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    packet = ether / arp

    result = srp(
        packet,
        timeout=2,
        verbose=0
    )[0]

    for sent, received in result:

        ip = received.psrc

        mac = received.hwsrc

        try:

            vendor = MacLookup().lookup(mac)

        except:

            vendor = "Unknown"

        devices.append({

            "ip": ip,
            "mac": mac,
            "vendor": vendor
        })

    return devices