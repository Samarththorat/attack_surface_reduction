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
            "profiles": "Any",
            "local_addresses": "Any",
            "remote_addresses": "Any",
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
            {**self.valid, "remote_addresses": "LocalSubnet"},
            {**self.valid, "profiles": "Public"},
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
        self.assertFalse(manager.rule_covers_port(
            {**self.valid, "remote_addresses": "LocalSubnet"}, "TCP", 8090
        ))
        self.assertFalse(manager.rule_covers_port(
            {**self.valid, "profiles": "Public"}, "TCP", 8090
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


class FirewallProfileStateTests(unittest.TestCase):
    def test_gpo_boolean_values_are_mapped_explicitly(self):
        cases = (
            (True, "True"),
            (False, "False"),
            ("True", "True"),
            ("False", "False"),
            ("NotConfigured", "NotConfigured"),
            (" notconfigured ", "NotConfigured"),
        )
        for requested, expected in cases:
            with self.subTest(requested=requested):
                self.assertEqual(manager._gpo_boolean_value(requested), expected)

    def test_gpo_boolean_mapping_rejects_non_allowlisted_values(self):
        for requested in (1, 0, None, "yes", "False; Get-NetFirewallProfile"):
            with self.subTest(requested=requested):
                with self.assertRaises(ValueError):
                    manager._gpo_boolean_value(requested)

    def test_profile_command_uses_typed_gpo_boolean_and_allowlisted_environment(self):
        expected_states = {
            True: "True",
            False: "False",
            "NotConfigured": "NotConfigured",
        }
        for profile in ("Domain", "Private", "Public"):
            for requested, expected_state in expected_states.items():
                with self.subTest(profile=profile, requested=requested), \
                     patch("asrms.firewall.manager._powershell", return_value="") as powershell, \
                     patch("asrms.firewall.manager.get_firewall_profiles", return_value={"profiles": []}):
                    result = manager.set_firewall_profile(profile, requested)
                self.assertEqual(result, {"profiles": []})
                args, kwargs = powershell.call_args
                self.assertIn("Import-Module NetSecurity -ErrorAction Stop", args[0])
                self.assertIn("System.Enum]::Parse", args[0])
                self.assertIn("GeneratedTypes.NetSecurity.GpoBoolean", args[0])
                self.assertNotIn("Convert]::ToBoolean", args[0])
                self.assertIn("-Profile $env:ASRMS_PROFILE", args[0])
                self.assertIn("-Enabled $enabled", args[0])
                self.assertEqual(
                    args[1],
                    {"ASRMS_PROFILE": profile, "ASRMS_ENABLED": expected_state},
                )
                self.assertEqual(kwargs["timeout"], 20)

    def test_profile_command_failure_is_not_swallowed(self):
        with patch(
            "asrms.firewall.manager._powershell",
            side_effect=manager.FirewallError("GpoBoolean command failed"),
        ), patch("asrms.firewall.manager.get_firewall_profiles") as readback:
            with self.assertRaisesRegex(manager.FirewallError, "GpoBoolean command failed"):
                manager.set_firewall_profile("Public", False)
        readback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
