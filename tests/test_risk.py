import unittest

from asrms.security.risk import analyze_risk


class RiskTests(unittest.TestCase):
    def test_open_port_is_a_finding_not_automatically_a_vulnerability(self):
        risk = analyze_risk(
            [{"protocol": "TCP", "port": 8090, "state": "open", "service": "http"}],
            [],
            [],
        )
        self.assertEqual(risk["score"], 97)
        self.assertEqual(risk["findings"][0]["severity"], "Low")
        self.assertEqual(risk["exposed_ports"], 1)
        self.assertEqual(risk["findings"][0]["service_state"], "not_mapped")

    def test_verified_matching_firewall_rule_reduces_exposure_not_service_state(self):
        risk = analyze_risk(
            [{"protocol": "TCP", "port": 3389, "state": "open", "service": "ms-wbt-server"}],
            [],
            [{
                "protocol": "TCP", "port": 3389, "enabled": True,
                "direction": "Inbound", "action": "Block",
            }],
        )
        self.assertEqual(risk["score"], 100)
        self.assertEqual(risk["findings"][0]["severity"], "High")
        self.assertTrue(risk["findings"][0]["firewall_restricted"])
        self.assertEqual(risk["findings"][0]["service_state"], "not_mapped")
        self.assertEqual(risk["exposed_ports"], 0)

    def test_disabled_or_removed_rule_does_not_reduce_exposure(self):
        entries = [
            {"protocol": "TCP", "port": 23, "state": "open"},
        ]
        for rule in (
            {"protocol": "TCP", "port": 23, "enabled": False, "direction": "Inbound", "action": "Block"},
            {"protocol": "TCP", "port": 23, "enabled": True, "direction": "Outbound", "action": "Block"},
            {"protocol": "TCP", "port": 23, "enabled": True, "direction": "Inbound", "action": "Allow"},
            {"protocol": "UDP", "port": 23, "enabled": True, "direction": "Inbound", "action": "Block"},
        ):
            with self.subTest(rule=rule):
                result = analyze_risk(entries, [], [rule])
                self.assertEqual(result["score"], 75)
                self.assertFalse(result["findings"][0]["firewall_restricted"])


if __name__ == "__main__":
    unittest.main()
