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
                "profiles": "Any", "local_addresses": "Any", "remote_addresses": "Any",
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
            {"protocol": "TCP", "port": 23, "enabled": True, "direction": "Inbound", "action": "Block"},
            {"protocol": "TCP", "port": 23, "enabled": True, "direction": "Inbound", "action": "Block",
             "profiles": "Public", "local_addresses": "Any", "remote_addresses": "Any"},
        ):
            with self.subTest(rule=rule):
                result = analyze_risk(entries, [], [rule])
                self.assertEqual(result["score"], 75)
                self.assertFalse(result["findings"][0]["firewall_restricted"])

    def test_unverified_url_heuristics_are_visible_but_not_double_counted_in_host_score(self):
        result = analyze_risk(
            [], [], [],
            url_scans=[{
                "id": 7,
                "created_at": "2026-11-04T00:00:00+00:00",
                "submitted_url": "http://127.0.0.1/",
                "normalized_url": "http://127.0.0.1/",
                "risk_score": 10,
                "risk_level": "Low",
                "analysis": {
                    "destination_type": "LOOPBACK",
                    "findings": [{"code": "NO_HTTPS"}],
                    "threat_intelligence": {"status": "UNVERIFIED"},
                },
            }],
        )
        self.assertEqual(result["score"], 100)
        observation = result["url_security_observations"]["scans"][0]
        self.assertEqual(observation["destination_type"], "LOOPBACK")
        self.assertEqual(observation["reputation_status"], "UNVERIFIED")
        self.assertFalse(result["url_security_observations"]["deducted_from_host_score"])


if __name__ == "__main__":
    unittest.main()
