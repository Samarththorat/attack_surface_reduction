import unittest
from unittest.mock import patch

from asrms.firewall import manager


class FirewallRuleVerificationTests(unittest.TestCase):
    def setUp(self):
        self.valid = {
            "name": "ASRMS-test",
            "enabled": True,
            "direction": "Inbound",
            "action": "Block",
            "protocol": "TCP",
            "port": "8090",
        }

    def test_requires_exact_enabled_inbound_block_protocol_and_port(self):
        self.assertTrue(manager.matches_rule(self.valid, "TCP", 8090))
        invalid_rules = (
            {**self.valid, "enabled": False},
            {**self.valid, "direction": "Outbound"},
            {**self.valid, "action": "Allow"},
            {**self.valid, "protocol": "UDP"},
            {**self.valid, "port": "8091"},
            {**self.valid, "port": "Any"},
        )
        for rule in invalid_rules:
            with self.subTest(rule=rule):
                self.assertFalse(manager.matches_rule(rule, "TCP", 8090))

    def test_numeric_protocol_and_single_element_port_array_are_supported(self):
        self.assertTrue(manager.matches_rule(
            {**self.valid, "protocol": "6", "port": [8090]}, "TCP", 8090
        ))

    def test_rule_coverage_handles_protocol_any_and_port_ranges(self):
        self.assertTrue(manager.rule_covers_port(
            {**self.valid, "port": "8000-9000"}, "TCP", 8090
        ))
        self.assertTrue(manager.rule_covers_port(
            {**self.valid, "protocol": "256", "port": "Any"}, "UDP", 8090
        ))
        self.assertFalse(manager.rule_covers_port(
            {**self.valid, "enabled": False}, "TCP", 8090
        ))

    @patch("asrms.firewall.manager.list_inbound_block_rules")
    def test_creation_refuses_existing_rule_that_covers_requested_port(self, list_rules):
        list_rules.return_value = [
            {**self.valid, "name": "Manual rule", "port": "8000-9000"}
        ]
        with self.assertRaises(manager.FirewallRuleAlreadyExists):
            manager.create_block_rule("TCP", 8090)

    @patch("asrms.firewall.manager.subprocess.run")
    def test_powershell_timeout_is_reported_as_firewall_error(self, run):
        import subprocess

        run.side_effect = subprocess.TimeoutExpired("powershell.exe", 20)
        with patch("asrms.firewall.manager.sys.platform", "win32"):
            with self.assertRaises(manager.FirewallError):
                manager._powershell("Get-NetFirewallRule", {})

    @patch("asrms.firewall.manager._rule_exists_by_identity", side_effect=[True, False])
    @patch("asrms.firewall.manager._powershell", return_value="")
    def test_rollback_uses_exact_recorded_identity_and_name(self, _powershell, _exists):
        self.assertTrue(manager.remove_rule("ASRMS-test", "recorded-guid"))
        _powershell.assert_called_once()
        script = _powershell.call_args.args[0]
        self.assertIn("Get-NetFirewallRule -PolicyStore PersistentStore", script)
        self.assertIn("$_.InstanceID -eq $env:ASRMS_INSTANCE_ID", script)
        self.assertIn("$_.DisplayName -eq $env:ASRMS_RULE_NAME", script)
        self.assertIn("$matches | Remove-NetFirewallRule", script)
        self.assertEqual(
            _powershell.call_args.args[1],
            {"ASRMS_INSTANCE_ID": "recorded-guid", "ASRMS_RULE_NAME": "ASRMS-test"},
        )


if __name__ == "__main__":
    unittest.main()
