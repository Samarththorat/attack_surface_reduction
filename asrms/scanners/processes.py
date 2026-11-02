import socket

import psutil


def listening_processes():
    processes = {}
    for connection in psutil.net_connections(kind="inet"):
        socket_type = int(connection.type)
        if socket_type == socket.SOCK_DGRAM:
            protocol = "UDP"
        elif socket_type == socket.SOCK_STREAM:
            protocol = "TCP"
        else:
            continue
        if not connection.laddr or (
            protocol == "TCP" and connection.status != psutil.CONN_LISTEN
        ):
            continue
        port = getattr(connection.laddr, "port", None)
        address = getattr(connection.laddr, "ip", None)
        if (port is None or address is None) and isinstance(connection.laddr, tuple):
            address, port = connection.laddr[:2]
        if not port:
            continue
        address = str(address or "")
        local_address = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
        item = processes.setdefault(
            (protocol, port, local_address),
            {
                "protocol": protocol,
                "port": port,
                "local_address": local_address,
                "processes": [],
            },
        )
        if connection.pid is None:
            continue
        try:
            process = psutil.Process(connection.pid)
            details = {
                "pid": process.pid,
                "name": process.name(),
                "exe": process.exe(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            details = {"pid": connection.pid, "name": "Unavailable", "exe": "Unavailable"}
        if details not in item["processes"]:
            item["processes"].append(details)
    return list(processes.values())
