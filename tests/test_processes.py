import socket
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import psutil

from asrms.scanners.processes import listening_processes


class ProcessInventoryTests(unittest.TestCase):
    @patch("asrms.scanners.processes.psutil.net_connections")
    def test_maps_tcp_listener_and_tolerates_missing_pid(self, connections):
        connections.return_value = [
            SimpleNamespace(
                status="LISTEN",
                laddr=SimpleNamespace(port=8090),
                type=socket.SOCK_STREAM,
                pid=None,
            ),
            SimpleNamespace(status="ESTABLISHED", laddr=SimpleNamespace(port=443), type=socket.SOCK_STREAM, pid=4),
        ]
        result = listening_processes()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["protocol"], "TCP")
        self.assertEqual(result[0]["port"], 8090)
        self.assertEqual(result[0]["processes"], [])

    @patch("asrms.scanners.processes.psutil.net_connections")
    def test_includes_udp_bound_sockets_without_listen_status(self, connections):
        connections.return_value = [
            SimpleNamespace(
                status="NONE",
                laddr=SimpleNamespace(port=5353),
                type=socket.SOCK_DGRAM,
                pid=None,
            )
        ]
        result = listening_processes()
        self.assertEqual(result[0]["protocol"], "UDP")
        self.assertEqual(result[0]["port"], 5353)

    @patch("asrms.scanners.processes.psutil.Process")
    @patch("asrms.scanners.processes.psutil.net_connections")
    def test_maps_listener_to_process_details(self, connections, process_class):
        connections.return_value = [
            SimpleNamespace(
                status="LISTEN",
                laddr=SimpleNamespace(port=8090),
                type=socket.SOCK_STREAM,
                pid=42,
            )
        ]
        process_class.return_value.pid = 42
        process_class.return_value.name.return_value = "web"
        process_class.return_value.exe.return_value = r"C:\web.exe"
        self.assertEqual(
            listening_processes()[0]["processes"],
            [{"pid": 42, "name": "web", "exe": r"C:\web.exe"}],
        )

    @patch("asrms.scanners.processes.psutil.net_connections")
    def test_maps_tcp_and_udp_protocols_and_tuple_addresses(self, connections):
        connections.return_value = [
            SimpleNamespace(
                status="LISTEN",
                laddr=("127.0.0.1", 445),
                type=socket.SOCK_STREAM,
                pid=None,
            ),
            SimpleNamespace(
                status="NONE",
                laddr=("127.0.0.1", 5000),
                type=socket.SOCK_DGRAM,
                pid=None,
            ),
        ]
        result = listening_processes()
        self.assertEqual(
            [(item["protocol"], item["port"], item["local_address"]) for item in result],
            [("TCP", 445, "127.0.0.1:445"), ("UDP", 5000, "127.0.0.1:5000")],
        )

    @patch("asrms.scanners.processes.psutil.net_connections", side_effect=psutil.AccessDenied("denied"))
    def test_propagates_socket_inventory_permission_errors(self, _connections):
        with self.assertRaises(psutil.AccessDenied):
            listening_processes()


if __name__ == "__main__":
    unittest.main()
