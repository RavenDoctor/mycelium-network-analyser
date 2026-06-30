import socket


CACHE = {}


def resolve_hostname(ip):

    if ip in CACHE:

        return CACHE[ip]

    try:

        host = socket.gethostbyaddr(ip)[0]

    except:

        host = ip

    CACHE[ip] = host

    return host