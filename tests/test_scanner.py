import unittest
from unittest.mock import patch

from asrms.scanners.nmap import ScanError, _parse_xml, scan_local_ports


class NmapTests(unittest.TestCase):
    def test_parses_nmap_port_states_and_service(self):
        xml = """<?xml version="1.0"?><nmaprun><host><ports>
        <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
        <service name="http" product="Example"/></port>
        <port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/></port>
        </ports></host></nmaprun>"""
        tcp = _parse_xml(xml, "tcp")
        udp_xml = """<?xml version="1.0"?><nmaprun><host><ports>
        <port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/></port>
        </ports></host></nmaprun>"""
        udp = _parse_xml(udp_xml, "udp")
        self.assertEqual(tcp[0]["state"], "open")
        self.assertEqual(tcp[0]["service"], "http")
        self.assertEqual(tcp[0]["identification"]["source"], "port-database")
        self.assertFalse(tcp[0]["identification"]["confirmed_service_probe"])
        self.assertEqual(udp[0]["state"], "open|filtered")

    def test_service_version_probe_captures_version_confidence_and_probe_source(self):
        xml = """<nmaprun><host><ports>
        <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="ExampleServer" version="4.2"
        extrainfo="TLS" method="probed" conf="10"/></port>
        </ports></host></nmaprun>"""
        result = _parse_xml(xml, "tcp")[0]
        self.assertEqual(result["product"], "ExampleServer")
        self.assertEqual(result["version"], "4.2")
        self.assertEqual(result["extra_info"], "TLS")
        self.assertEqual(result["identification"]["source"], "version-probe")
        self.assertEqual(result["identification"]["confidence"], 10)
        self.assertTrue(result["identification"]["confirmed_service_probe"])

    def test_service_detection_is_optional_and_uses_version_probe_flags(self):
        xml = (
            '<nmaprun><scaninfo protocol="tcp" services="443"/>'
            '<scaninfo protocol="udp" services="443"/><host><ports/></host></nmaprun>'
        )
        with patch("asrms.scanners.nmap._nmap_executable", return_value="nmap"), patch(
            "asrms.scanners.nmap.subprocess.run"
        ) as run:
            run.return_value.stdout = xml
            run.return_value.stderr = ""
            run.return_value.returncode = 0
            scan_local_ports([443], service_detection=True, version_timeout=70)
        for call in run.call_args_list:
            command = call.args[0]
            self.assertIn("-sV", command)
            self.assertIn("--version-light", command)
            self.assertIn("--version-timeout", command)
            self.assertIn("70s", command)

    def test_rejects_non_local_or_invalid_scan_input(self):
        for ports in ([], [0], [65536], [True], [80, 80], list(range(1, 102))):
            with self.subTest(ports=ports[:3]):
                with self.assertRaises(ValueError):
                    scan_local_ports(ports, nmap_path="nmap")

    @patch("asrms.scanners.nmap.subprocess.run")
    @patch("asrms.scanners.nmap._nmap_executable", return_value="nmap")
    def test_runs_tcp_and_udp_only_against_loopback(self, _executable, run):
        run.return_value.stdout = (
            '<nmaprun><scaninfo protocol="tcp" services="80"/>'
            '<scaninfo protocol="udp" services="80"/><host><ports/></host></nmaprun>'
        )
        run.return_value.stderr = ""
        run.return_value.returncode = 0
        result = scan_local_ports([80])
        self.assertEqual(result, {"tcp": [], "udp": []})
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            args = call.args[0]
            self.assertEqual(args[-1], "127.0.0.1")
            self.assertIn("-oX", args)
            self.assertFalse(call.kwargs["shell"])

    def test_rejects_nmap_results_that_do_not_confirm_complete_protocol_scope(self):
        incomplete = '<nmaprun><host><ports/></host></nmaprun>'
        with self.assertRaises(ScanError):
            _parse_xml(incomplete, "tcp", [80])

    @patch("asrms.scanners.nmap.subprocess.run")
    @patch("asrms.scanners.nmap._nmap_executable", return_value="nmap")
    def test_fails_closed_on_nmap_error(self, _executable, run):
        run.return_value.stdout = ""
        run.return_value.stderr = "probe error"
        run.return_value.returncode = 1
        with self.assertRaises(ScanError):
            scan_local_ports([80])


if __name__ == "__main__":
    unittest.main()
