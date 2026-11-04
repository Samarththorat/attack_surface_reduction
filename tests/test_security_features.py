import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import psutil

from asrms import create_app, database
from asrms.firewall import manager
from asrms.monitoring import ports
from asrms.routes.api import _exposed
from asrms.security.risk import analyze_risk
from asrms.security.url_scanner import URLValidationError, analyze_url


def profiles(enabled):
    return {
        "collection_status": "verified",
        "verified_at": "2026-11-04T00:00:00+00:00",
        "profiles": [
            {
                "name": name,
                "enabled": is_enabled,
                "default_inbound_action": "Block",
                "default_outbound_action": "Allow",
            }
            for name, is_enabled in zip(("Domain", "Private", "Public"), enabled)
        ],
        "error": None,
    }


class FirewallRiskTests(unittest.TestCase):
    def test_profile_disable_counts_and_score_deductions(self):
        expected = {
            (True, True, True): (100, "Healthy", 0),
            (False, True, True): (85, "Warning", 15),
            (False, False, True): (70, "High Risk", 30),
            (False, False, False): (55, "Critical", 45),
        }
        for enabled, (score, health, penalty) in expected.items():
            with self.subTest(enabled=enabled):
                result = analyze_risk([], [], [], firewall_profiles=profiles(enabled))
                self.assertEqual(result["score"], score)
                self.assertEqual(result["firewall_health"]["status"], health)
                self.assertEqual(result["score_deductions"][-1]["points"], penalty)

    def test_disabled_profile_does_not_treat_block_rule_as_effective_or_double_count(self):
        result = analyze_risk(
            [{"protocol": "TCP", "port": 3389, "state": "open"}],
            [],
            [{
                "protocol": "TCP",
                "port": "3389",
                "enabled": True,
                "direction": "Inbound",
                "action": "Block",
            }],
            firewall_profiles=profiles((False, False, False)),
        )
        self.assertFalse(result["findings"][0]["firewall_restricted"])
        self.assertEqual(result["score"], 55)
        self.assertEqual(sum(item["points"] or 0 for item in result["score_deductions"]), 45)

    def test_comparison_exposure_only_counts_network_ports(self):
        scan = {
            "risk": {
                "findings": [
                    {"protocol": "FIREWALL", "port": "", "firewall_restricted": False},
                    {"protocol": "TCP", "port": 443, "firewall_restricted": False},
                ]
            }
        }
        self.assertEqual(_exposed(scan), ["TCP/443"])

    def test_unknown_profile_collection_makes_assessment_incomplete(self):
        result = analyze_risk(
            [], [], [],
            firewall_profiles={
                "collection_status": "error",
                "profiles": [],
                "error": "Access denied",
            },
        )
        self.assertIsNone(result["score"])
        self.assertFalse(result["assessment_complete"])
        self.assertEqual(result["firewall_health"]["status"], "Unknown")
        self.assertIn("firewall_profile_collection", {item.get("source") for item in result["findings"]})

    def test_powershell_profile_data_is_normalized_and_requires_all_profiles(self):
        output = (
            '[{"Name":"Domain","Enabled":1,"DefaultInboundAction":4,'
            '"DefaultOutboundAction":2},'
            '{"Name":"Private","Enabled":0,"DefaultInboundAction":0,'
            '"DefaultOutboundAction":2},'
            '{"Name":"Public","Enabled":1,"DefaultInboundAction":4,'
            '"DefaultOutboundAction":2}]'
        )
        with patch.object(manager, "_powershell", return_value=output):
            result = manager.get_firewall_profiles()
        self.assertEqual(len(result["profiles"]), 3)
        self.assertFalse(result["profiles"][1]["enabled"])
        self.assertEqual(result["profiles"][1]["default_inbound_action"], "NotConfigured")
        with patch.object(manager, "_powershell", return_value='{"Name":"Domain","Enabled":true}'):
            with self.assertRaises(manager.FirewallError):
                manager.get_firewall_profiles()

    def test_profile_setter_uses_allowlisted_environment_parameters_and_requeries(self):
        response = json.dumps([
            {
                "Name": name,
                "Enabled": name == "Public",
                "DefaultInboundAction": 4,
                "DefaultOutboundAction": 2,
            }
            for name in ("Domain", "Private", "Public")
        ])
        with patch.object(manager, "_powershell", side_effect=["", response]) as powershell:
            result = manager.set_firewall_profile("public", True)
        self.assertTrue(result["profiles"][2]["enabled"])
        self.assertEqual(powershell.call_args_list[0].args[1], {
            "ASRMS_PROFILE": "Public",
            "ASRMS_ENABLED": "True",
        })
        self.assertIn("$env:ASRMS_PROFILE", powershell.call_args_list[0].args[0])

    def test_profile_setter_rejects_unallowlisted_profile_and_non_boolean_state(self):
        with self.assertRaises(ValueError):
            manager.set_firewall_profile("All", True)
        with self.assertRaises(ValueError):
            manager.set_firewall_profile("Public", 1)


class URLScannerTests(unittest.TestCase):
    def test_normalizes_and_reports_unverified_reputation(self):
        result = analyze_url("HTTPS://ExAmPlE.com/path")
        self.assertEqual(result["normalized_url"], "https://example.com/path")
        self.assertEqual(result["domain"], "example.com")
        self.assertTrue(result["https"])
        self.assertEqual(result["threat_intelligence"]["status"], "UNVERIFIED")
        self.assertFalse(result["network_requests_made"])

    def test_rejects_invalid_scheme_and_url(self):
        for value in ("", "ftp://example.com", "https:///missing-host"):
            with self.subTest(value=value), self.assertRaises(URLValidationError):
                analyze_url(value)

    def test_detects_shortener_and_brand_subdomain(self):
        shortened = analyze_url("https://bit.ly/AbCd")
        self.assertIn("URL_SHORTENER", {item["code"] for item in shortened["findings"]})
        impersonation = analyze_url("https://paypal.example.net/login")
        self.assertIn(
            "BRAND_IMPERSONATION_PATTERN",
            {item["code"] for item in impersonation["findings"]},
        )
        self.assertGreaterEqual(impersonation["risk_score"], 26)

    def test_url_risk_components_separate_structure_and_transport(self):
        result = analyze_url("http://paypal.verify.example.net/setup.exe")
        self.assertEqual(result["risk_components"]["transport"], 10)
        self.assertEqual(
            result["risk_components"]["structural"],
            sum(
                finding["points"]
                for finding in result["findings"]
                if finding["code"] != "NO_HTTPS"
            ),
        )
        self.assertEqual(result["risk_components"]["overall"], result["risk_score"])
        self.assertEqual(result["risk_components"]["destination"], 0)

    def test_classifies_loopback_without_calling_it_malicious_or_fetching(self):
        result = analyze_url("http://127.0.0.1/admin")
        self.assertEqual(result["destination_type"], "LOOPBACK")
        self.assertIn("Local address detected", result["destination_message"])
        self.assertEqual(result["risk_components"]["destination"], 0)
        self.assertEqual(result["risk_level"], "Low")
        self.assertFalse(result["network_requests_made"])
        self.assertEqual(result["redirect_chain"]["status"], "NOT_CHECKED")

    def test_classifies_all_destination_categories_without_network_requests(self):
        examples = {
            "http://example.test/": "RESERVED_IP",
            "http://localhost:5000/": "LOOPBACK",
            "http://127.0.0.1/": "LOOPBACK",
            "http://10.1.2.3/": "PRIVATE_IP",
            "http://169.254.1.2/": "LINK_LOCAL",
            "http://240.0.0.1/": "RESERVED_IP",
            "https://8.8.8.8/": "PUBLIC_IP",
            "http://127.1/": "RESERVED_IP",
            "https://example.com/": "PUBLIC_DOMAIN",
        }
        for value, expected in examples.items():
            with self.subTest(value=value):
                result = analyze_url(value)
                self.assertEqual(result["destination_type"], expected)
                self.assertFalse(result["network_requests_made"])
                self.assertEqual(result["threat_intelligence"]["status"], "UNVERIFIED")
                self.assertEqual(result["risk_components"]["threat_reputation"]["score"], None)

    def test_short_urls_and_downloads_are_not_claimed_safe(self):
        result = analyze_url("https://files.example.com/setup.exe")
        self.assertIn("DIRECT_DOWNLOAD", {item["code"] for item in result["findings"]})
        self.assertIn("UNVERIFIED", result["threat_intelligence"]["status"])


class PortMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": str(Path(self.temp.name) / "monitor.sqlite3"),
                "SECRET_KEY": "monitor-test",
                "PORT_MONITOR_PERSISTENT_SECONDS": 1,
            }
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_new_and_closed_socket_events_are_deduplicated(self):
        listener = {
            "protocol": "TCP",
            "port": 8181,
            "local_address": "0.0.0.0:8181",
            "processes": [{"pid": 42, "name": "server", "exe": "C:\\server.exe"}],
        }
        with self.app.app_context(), \
             patch.object(ports, "listening_processes", return_value=[listener]), \
             patch.object(ports.manager, "list_inbound_block_rules", return_value=[]), \
             patch.object(ports, "_service_by_pid", return_value={}), \
             patch.object(ports.psutil, "Process", side_effect=psutil.NoSuchProcess(42)):
            ports.collect_once()
            ports.collect_once()
            self.assertEqual(
                sum(item["event_type"] == "NEW_TCP_LISTENER" for item in database.list_port_activity()),
                1,
            )
            with patch.object(ports, "listening_processes", return_value=[]):
                ports.collect_once()
            self.assertEqual(
                sum(item["event_type"] == "TCP_LISTENER_CLOSED" for item in database.list_port_activity()),
                1,
            )

    def test_detects_process_change_and_persistent_listener(self):
        listener = {
            "protocol": "TCP",
            "port": 8182,
            "local_address": "0.0.0.0:8182",
            "processes": [{"pid": 42, "name": "server", "exe": "C:\\server.exe"}],
        }
        with self.app.app_context(), \
             patch.object(ports.manager, "list_inbound_block_rules", return_value=[]), \
             patch.object(ports, "_service_by_pid", return_value={}), \
             patch.object(ports.psutil, "Process", side_effect=psutil.NoSuchProcess(42)):
            with patch.object(ports, "listening_processes", return_value=[listener]):
                ports.collect_once()
            with patch.object(ports, "listening_processes", return_value=[
                {
                    **listener,
                    "processes": [{"pid": 43, "name": "replacement", "exe": "C:\\replacement.exe"}],
                }
            ]):
                ports.collect_once()
            types = {item["event_type"] for item in database.list_port_activity()}
            self.assertIn("TCP_PROCESS_CHANGED", types)
            self.assertIn("NEW_TCP_LISTENER", types)
            snapshot = database.get_port_monitor_snapshot()
            self.assertTrue(snapshot["listeners"][0]["risk_indicators"])

    def test_detects_pid_reuse_when_process_name_and_path_are_unchanged(self):
        listener = {
            "protocol": "TCP",
            "port": 8187,
            "local_address": "127.0.0.1:8187",
            "processes": [{"pid": 42, "name": "server", "exe": r"C:\server.exe"}],
        }
        process = Mock()
        process.create_time.side_effect = [1000, 2000]
        with self.app.app_context(), \
             patch.object(ports, "listening_processes", return_value=[listener]), \
             patch.object(ports.manager, "list_inbound_block_rules", return_value=[]), \
             patch.object(ports, "_service_by_pid", return_value={}), \
             patch.object(ports.psutil, "Process", return_value=process):
            ports.collect_once()
            ports.collect_once()
            events = database.list_port_activity()
        self.assertIn("TCP_PROCESS_CHANGED", {item["event_type"] for item in events})

    def test_persistent_listener_event_after_configured_duration(self):
        listener = {
            "protocol": "TCP",
            "port": 8183,
            "local_address": "127.0.0.1:8183",
            "processes": [{"pid": 42, "name": "server", "exe": "C:\\server.exe"}],
        }
        now = datetime.now(timezone.utc)
        old_record = {
            "socket_id": "TCP|127.0.0.1:8183|8183",
            "protocol": "TCP",
            "local_address": "127.0.0.1:8183",
            "port": 8183,
            "pid": 42,
            "process_name": "server",
            "executable": "C:\\server.exe",
            "process_start_time": None,
            "first_detected_at": (now - timedelta(seconds=5)).isoformat(timespec="seconds"),
            "last_detected_at": (now - timedelta(seconds=5)).isoformat(timespec="seconds"),
            "state": "LISTENING",
            "persistent": False,
            "firewall_restriction": "No verified matching block rule",
            "windows_service": "Not identified",
            "risk_indicators": [],
        }
        with self.app.app_context(), \
             patch.object(ports, "listening_processes", return_value=[listener]), \
             patch.object(ports.manager, "list_inbound_block_rules", return_value=[]), \
             patch.object(ports, "_service_by_pid", return_value={}), \
             patch.object(ports.psutil, "Process", side_effect=psutil.NoSuchProcess(42)):
            database.save_port_monitor_snapshot([old_record])
            ports.collect_once()
            self.assertIn(
                "PERSISTENT_TCP_LISTENER",
                {item["event_type"] for item in database.list_port_activity()},
            )

    def test_process_collection_failure_is_explicit(self):
        with self.app.app_context(), \
             patch.object(ports, "listening_processes", side_effect=psutil.AccessDenied()), \
             patch.object(ports.manager, "list_inbound_block_rules", return_value=[]):
            snapshot = ports.collect_once()
            self.assertEqual(snapshot["status"], "error")
            self.assertIn("Could not collect", snapshot["error"])
            self.assertEqual(
                database.list_port_activity(1)[0]["event_type"],
                "INVENTORY_COLLECTION_FAILED",
            )

    def test_missing_process_details_are_reported_with_reason(self):
        listener = {
            "protocol": "TCP",
            "port": 8186,
            "local_address": "0.0.0.0:8186",
            "processes": [],
        }
        with self.app.app_context(), \
             patch.object(ports, "listening_processes", return_value=[listener]), \
             patch.object(ports.manager, "list_inbound_block_rules", return_value=[]), \
             patch.object(ports, "_service_by_pid", return_value={}):
            ports.collect_once()
            event = next(
                item for item in database.list_port_activity()
                if item["event_type"] == "PROCESS_UNAVAILABLE"
            )
        self.assertEqual(event["details"]["severity"], "MEDIUM")
        self.assertIn("Psutil did not provide", event["details"]["reason"])
        self.assertTrue(event["details"]["recommendation"])

    def test_known_windows_service_is_not_marked_safe_or_suspicious_by_name(self):
        listener = {
            "protocol": "TCP",
            "local_address": "0.0.0.0:53",
            "process_name": "svchost.exe",
            "executable": r"C:\Windows\System32\svchost.exe",
            "windows_service": "Dnscache",
            "identity_status": "WINDOWS_SERVICE_ASSOCIATED_SIGNATURE_UNVERIFIED",
        }
        severity, reason, recommendation = ports._classify_listener_event(
            "NEW_TCP_LISTENER", listener
        )
        self.assertEqual(severity, "info")
        self.assertIn("signature was not verified", reason)
        self.assertNotIn("SAFE", listener["identity_status"])
        self.assertTrue(recommendation)

    def test_worker_starts_only_once_for_database(self):
        self.app.config["TESTING"] = False
        path = str(self.app.config["DATABASE"])
        with patch.object(ports.threading.Thread, "start") as start, \
             patch.object(ports.threading.Thread, "is_alive", return_value=True):
            ports.start_worker(self.app)
            ports.start_worker(self.app)
            self.assertEqual(start.call_count, 1)
        ports.shutdown_worker(path)

    def test_udp_lifecycle_and_persistence_have_udp_specific_events(self):
        udp = {
            "protocol": "UDP",
            "port": 8184,
            "local_address": "0.0.0.0:8184",
            "processes": [{"pid": 42, "name": "server", "exe": "C:\\server.exe"}],
        }
        self.app.config["UDP_PERSISTENT_SECONDS"] = 1
        with self.app.app_context(), \
             patch.object(ports, "listening_processes", return_value=[udp]), \
             patch.object(ports.manager, "list_inbound_block_rules", return_value=[]), \
             patch.object(ports, "_service_by_pid", return_value={}), \
             patch.object(ports.psutil, "Process", side_effect=psutil.NoSuchProcess(42)):
            ports.collect_once()
            old = database.get_port_monitor_snapshot()["listeners"][0]
            old["first_detected_at"] = (
                datetime.now(timezone.utc) - timedelta(seconds=5)
            ).isoformat(timespec="seconds")
            database.save_port_monitor_snapshot([old])
            ports.collect_once()
            with patch.object(ports, "listening_processes", return_value=[]):
                ports.collect_once()
            types = {event["event_type"] for event in database.list_port_activity()}
            self.assertTrue({
                "NEW_UDP_SOCKET", "PERSISTENT_UDP_SOCKET", "UDP_SOCKET_REMOVED"
            }.issubset(types))

    def test_socket_event_reason_and_notification_cooldown(self):
        listener = {
            "socket_id": "TCP|0.0.0.0:8185|8185",
            "protocol": "TCP",
            "port": 8185,
            "local_address": "0.0.0.0:8185",
            "pid": 42,
            "process_name": "unknown.exe",
            "executable": "C:\\temp\\unknown.exe",
            "first_detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        with self.app.app_context():
            ports._record_event(
                "NEW_TCP_LISTENER",
                listener,
                "new listener",
                "medium",
                "Wildcard-bound process identity is not verified.",
                "Verify the executable and inbound policy.",
                cooldown_seconds=300,
            )
            notifications = database.list_security_notifications()
            self.assertEqual(len(notifications), 1)
            self.assertEqual(notifications[0]["details"]["reason"], "Wildcard-bound process identity is not verified.")
            self.assertEqual(notifications[0]["details"]["recommendation"], "Verify the executable and inbound policy.")
            self.assertFalse(database.record_security_notification(
                "medium",
                "NEW_TCP_LISTENER",
                "duplicate",
                {"socket_id": listener["socket_id"]},
                "different-event-key",
                cooldown_seconds=300,
                group_key=listener["socket_id"],
            ))
            notification_id = notifications[0]["id"]
            self.assertTrue(database.dismiss_security_notification(notification_id))
            self.assertTrue(database.list_security_notifications()[0]["dismissed"])


class NewEndpointTests(unittest.TestCase):
    def make_client(self, database_path):
        app = create_app(
            {
                "TESTING": True,
                "DATABASE": str(database_path),
                "SECRET_KEY": "profile-test",
                "PORT_MONITOR_ENABLED": False,
            }
        )
        client = app.test_client()
        import re

        page = client.get("/firewall").get_data(as_text=True)
        token = re.search(
            r'<meta name="asrms-csrf" content="([^"]+)"', page
        ).group(1)
        return app, client, {"X-ASRMS-CSRF": token}

    def test_enable_each_profile_requires_confirmation_and_verifies_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            app, client, headers = self.make_client(Path(temporary) / "profiles.sqlite3")
            for name in ("Domain", "Private", "Public"):
                enabled = tuple(profile == name for profile in ("Domain", "Private", "Public"))
                with self.subTest(profile=name), \
                     patch("asrms.routes.api.manager.is_admin", return_value=True), \
                     patch("asrms.routes.api._get_firewall_profile_state", side_effect=[
                         profiles((False, False, False)),
                         profiles(enabled),
                     ]), \
                     patch("asrms.routes.api.manager.set_firewall_profile") as setter, \
                     patch("asrms.routes.api._latest_scope", return_value={
                         "target": "127.0.0.1",
                         "protocols": ["TCP", "UDP"],
                         "ports": [80],
                         "service_detection": False,
                         "scope_label": "Loopback only",
                     }), \
                     patch("asrms.routes.api._scan_and_save", return_value={
                         "id": 8, "status": "verified"
                     }):
                    response = client.post(
                        f"/api/firewall/profiles/{name}",
                        json={"enabled": True, "confirmed": True},
                        headers=headers,
                    )
                self.assertEqual(response.status_code, 200, response.json)
                self.assertTrue(response.json["verified"])
                self.assertTrue(response.json["profile"]["enabled"])
                setter.assert_called_once_with(name, True)

    def test_disable_profile_after_confirmation_and_verification(self):
        for profile in ("Domain", "Private", "Public"):
            with tempfile.TemporaryDirectory() as temporary:
                _, client, headers = self.make_client(
                    Path(temporary) / f"disable-{profile.lower()}.sqlite3"
                )
                final_state = tuple(
                    name != profile for name in ("Domain", "Private", "Public")
                )
                with self.subTest(profile=profile), \
                     patch("asrms.routes.api.manager.is_admin", return_value=True), \
                     patch("asrms.routes.api._get_firewall_profile_state", side_effect=[
                         profiles((True, True, True)),
                         profiles(final_state),
                     ]), \
                     patch("asrms.routes.api.manager.set_firewall_profile") as setter, \
                     patch("asrms.routes.api._latest_scope", return_value={
                         "target": "127.0.0.1",
                         "protocols": ["TCP", "UDP"],
                         "ports": [80],
                         "service_detection": False,
                         "scope_label": "Loopback only",
                     }), \
                     patch("asrms.routes.api._scan_and_save", return_value={
                         "id": 9, "status": "verified"
                     }):
                    response = client.post(
                        f"/api/firewall/profiles/{profile}",
                        json={"enabled": False, "confirmed": True},
                        headers=headers,
                    )
                self.assertEqual(response.status_code, 200, response.json)
                self.assertFalse(response.json["profile"]["enabled"])
                setter.assert_called_once_with(profile, False)

    def test_firewall_profile_api_denies_missing_admin_and_unconfirmed_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, client, headers = self.make_client(Path(temporary) / "denied.sqlite3")
            with patch("asrms.routes.api.manager.is_admin", return_value=False):
                denied = client.post(
                    "/api/firewall/profiles/Domain",
                    json={"enabled": True, "confirmed": True},
                    headers=headers,
                )
                unconfirmed = client.post(
                    "/api/firewall/profiles/Domain",
                    json={"enabled": True},
                    headers=headers,
                )
            self.assertEqual(denied.status_code, 403)
            self.assertIn("Administrator", denied.json["error"])
            self.assertEqual(unconfirmed.status_code, 428)

    def test_firewall_profile_api_never_disables_all_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, client, headers = self.make_client(Path(temporary) / "last-profile.sqlite3")
            with patch("asrms.routes.api.manager.is_admin", return_value=True), \
                 patch("asrms.routes.api._get_firewall_profile_state", return_value=profiles((False, False, True))), \
                 patch("asrms.routes.api.manager.set_firewall_profile") as setter:
                response = client.post(
                    "/api/firewall/profiles/Public",
                    json={"enabled": False, "confirmed": True},
                    headers=headers,
                )
            self.assertEqual(response.status_code, 409)
            setter.assert_not_called()

    def test_firewall_profile_api_reports_powershell_and_verification_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, client, headers = self.make_client(Path(temporary) / "failure.sqlite3")
            with patch("asrms.routes.api.manager.is_admin", return_value=True), \
                 patch("asrms.routes.api._get_firewall_profile_state", return_value=profiles((True, True, True))), \
                 patch("asrms.routes.api.manager.set_firewall_profile", side_effect=manager.FirewallError("Group Policy denied the request")):
                command_failure = client.post(
                    "/api/firewall/profiles/Domain",
                    json={"enabled": False, "confirmed": True},
                    headers=headers,
                )
            self.assertEqual(command_failure.status_code, 503)
            self.assertIn("policy", command_failure.json["error"].lower())

            with patch("asrms.routes.api.manager.is_admin", return_value=True), \
                 patch("asrms.routes.api._get_firewall_profile_state", side_effect=[
                     profiles((True, True, True)),
                     profiles((True, True, True)),
                 ]), \
                 patch("asrms.routes.api.manager.set_firewall_profile"), \
                 patch("asrms.routes.api._scan_and_save") as scan:
                verification_failure = client.post(
                    "/api/firewall/profiles/Domain",
                    json={"enabled": False, "confirmed": True},
                    headers=headers,
                )
            self.assertEqual(verification_failure.status_code, 503)
            self.assertNotIn("verified", verification_failure.json)
            self.assertIn("not confirmed", verification_failure.json["error"])
            scan.assert_not_called()

    def test_notification_dismissal_preserves_the_notification_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            app, client, headers = self.make_client(Path(temporary) / "dismiss.sqlite3")
            with app.app_context():
                database.record_security_notification(
                    "critical", "FIREWALL", "Critical", {}, "critical-notification"
                )
                database.record_security_notification(
                    "medium", "TEST", "Keep audit record", {}, "test-notification"
                )
                notification_id = next(
                    item["id"] for item in database.list_security_notifications()
                    if item["severity"] == "medium"
                )
            filtered = client.get("/api/security-notifications?severity=medium")
            self.assertEqual(len(filtered.json), 1)
            self.assertEqual(filtered.json[0]["severity"], "medium")
            response = client.post(
                f"/api/security-notifications/{notification_id}/dismiss",
                json={"confirmed": True},
                headers=headers,
            )
            self.assertEqual(response.status_code, 200)
            active = client.get("/api/security-notifications").json
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0]["severity"], "critical")
            retained = client.get("/api/security-notifications?include_dismissed=true").json
            self.assertEqual(len(retained), 2)
            self.assertTrue(next(item for item in retained if item["severity"] == "medium")["dismissed"])

    def test_invalid_url_api_classifies_validation_failure_without_fetching(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, client, headers = self.make_client(Path(temporary) / "invalid-url.sqlite3")
            response = client.post(
                "/api/url-scans",
                json={"url": "file:///C:/Windows/win.ini"},
                headers=headers,
            )
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json["destination_type"], "INVALID_URL")
            self.assertEqual(client.get("/api/url-scans").json, [])

    def test_url_scan_endpoint_persists_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = create_app(
                {
                    "TESTING": True,
                    "DATABASE": str(Path(temporary) / "url.sqlite3"),
                    "SECRET_KEY": "url-test",
                }
            )
            client = app.test_client()
            response = client.get("/")
            import re

            token = re.search(
                r'<meta name="asrms-csrf" content="([^"]+)"',
                response.get_data(as_text=True),
            ).group(1)
            result = client.post(
                "/api/url-scans",
                json={"url": "https://bit.ly/example"},
                headers={"X-ASRMS-CSRF": token},
            )
            self.assertEqual(result.status_code, 201)
            self.assertEqual(result.json["risk_level"], "Medium")
            self.assertEqual(client.get("/api/url-scans").json[0]["id"], result.json["id"])
            with patch("asrms.routes.api.manager.list_inbound_block_rules", return_value=[]), \
                 patch("asrms.routes.api.manager.get_firewall_profiles", return_value=profiles((True, True, True))):
                excel = client.get("/api/reports/excel")
                pdf = client.get("/api/reports/pdf")
            self.assertEqual(excel.status_code, 200)
            self.assertEqual(pdf.status_code, 200)
            from io import BytesIO
            from openpyxl import load_workbook

            workbook = load_workbook(BytesIO(excel.data), read_only=True)
            self.assertIn("URL Assessments", workbook.sheetnames)
            self.assertIn("URL Findings", workbook.sheetnames)
            self.assertIn("Firewall Profiles", workbook.sheetnames)
            self.assertIn("Live Listeners", workbook.sheetnames)
            self.assertIn("TCP Listeners", workbook.sheetnames)
            self.assertIn("UDP Sockets", workbook.sheetnames)
            self.assertIn("Port Activity", workbook.sheetnames)
            self.assertIn("Security Notifications", workbook.sheetnames)
            workbook.close()


if __name__ == "__main__":
    unittest.main()
