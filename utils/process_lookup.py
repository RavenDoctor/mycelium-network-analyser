import psutil
import time

# -----------------------------
# Connection Cache
# -----------------------------

_connection_cache = {}

_last_refresh = 0

CACHE_REFRESH = 2  # seconds


def refresh_connections():

    global _connection_cache
    global _last_refresh

    now = time.time()

    if now - _last_refresh < CACHE_REFRESH:
        return

    _connection_cache.clear()

    try:

        for conn in psutil.net_connections(kind="inet"):

            if not conn.laddr:
                continue

            if not conn.pid:
                continue

            try:

                process = psutil.Process(conn.pid)

                _connection_cache[conn.laddr.port] = process.name()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

    except Exception as e:

        print(f"Process lookup error: {e}")

    _last_refresh = now


def get_process_by_port(port):

    refresh_connections()

    return _connection_cache.get(
        port,
        "Unknown"
    )