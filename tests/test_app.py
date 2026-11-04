import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psutil

from asrms import create_app
from asrms import database
from asrms.firewall import manager
from asrms.scanners.nmap import ScanError


GOOD_SCAN = {
    "tcp": [
        {
            "protocol": "TCP", "port": 8090, "state": "open", "reason": "syn-ack",
            "service": "http", "product": "", "version": "", "extra_info": "",
            "identification": {"source": "port-database", "confidence": 3},
        },
        {
            "protocol": "TCP", "port": 80, "state": "closed", "reason": "reset",
            "service": "http", "product": "", "version": "", "extra_info": "",
            "identification": {"source": "port-database", "confidence": 3},
        },
    ],
    "udp": [
        {
            "protocol": "UDP", "port": 53, "state": "open|filtered", "reason": "no-response",
            "service": "domain", "product": "", "version": "", "extra_info": "",
            "identification": {"source": "port-database", "confidence": 3},
        }
    ],
}
PROCESSES = [
    {
        "protocol": "TCP", "port": 8090, "local_address": "127.0.0.1:8090",
        "processes": [{"pid": 42, "name": "web", "exe": r"C:\web.exe"}],
    }
]
APP_RULE = {
    "name": "ASRMS-test-rule",
    "instance_id": "test-instance-8090",
    "enabled": True,
    "direction": "Inbound",
    "action": "Block",
    "protocol": "TCP",
    "port": "8090",
    "profiles": "Any",
    "local_addresses": "Any",
    "remote_addresses": "Any",
}


def scan_scope(ports, service_detection=False):
    return {
        "target": "127.0.0.1",
        "protocols": ["TCP", "UDP"],
        "ports": sorted(ports),
        "service_detection": service_detection,
        "network_access_test": "not_performed",
        "scope_label": "Loopback only (this computer)",
    }


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        db_path = str(Path(self.temp.name) / "test.sqlite3")
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": db_path,
                "SECRET_KEY": "test",
                "NMAP_TIMEOUT": 45,
                "NMAP_VERSION_TIMEOUT": 90,
            }
        )
        self.client = self.app.test_client()
        response = self.client.get("/")
        self.csrf = re.search(
            r'<meta name="asrms-csrf" content="([^"]+)"', response.get_data(as_text=True)
        ).group(1)
        self.firewall_snapshot = patch(
            "asrms.routes.api.manager.list_inbound_block_rules", return_value=[]
        )
        self.firewall_snapshot.start()
        self.firewall_profiles = patch(
            "asrms.routes.api.manager.get_firewall_profiles",
            return_value={
                "collection_status": "verified",
                "verified_at": "2026-11-04T00:00:00+00:00",
                "profiles": [
                    {
                        "name": name,
                        "enabled": True,
                        "default_inbound_action": "Block",
                        "default_outbound_action": "Allow",
                    }
                    for name in ("Domain", "Private", "Public")
                ],
                "error": None,
            },
        )
        self.firewall_profiles.start()

    def tearDown(self):
        self.firewall_snapshot.stop()
        self.firewall_profiles.stop()
        self.temp.cleanup()

    def post(self, path, **kwargs):
        headers = dict(kwargs.pop("headers", {}))
        headers["X-ASRMS-CSRF"] = self.csrf
        return self.client.post(path, headers=headers, **kwargs)

    def delete(self, path, **kwargs):
        headers = dict(kwargs.pop("headers", {}))
        headers["X-ASRMS-CSRF"] = self.csrf
        return self.client.delete(path, headers=headers, **kwargs)

    def save_assessment(
        self, ports=(80, 443, 8090), service_detection=False, risk=None, processes=None
    ):
        result = {
            **GOOD_SCAN,
            "processes": PROCESSES if processes is None else processes,
            "risk": risk or {
                "score": 97,
                "open_ports": 1,
                "exposed_ports": 1,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 1,
                "findings": [
                    {
                        "protocol": "TCP", "port": 8090, "service": "http", "severity": "Low",
                        "firewall_restricted": False, "service_state": "listening",
                        "listeners": [], "recommendation": "Review service exposure.",
                    }
                ],
            },
            "firewall_rules": [],
            "verification": {"firewall_configuration": "observed"},
        }
        with self.app.app_context():
            return database.save_scan(
                result,
                scope=scan_scope(list(ports), service_detection),
                complete=True,
            )

    def test_legacy_scan_is_not_reported_as_verified(self):
        with self.app.app_context():
            database.save_scan({"tcp": [], "udp": [], "processes": [], "risk": {}})
        state = self.client.get("/api/state").json
        self.assertEqual(state["assessment_status"], "legacy_scope_unknown")
        self.assertEqual(state["latest_scan"]["status"], "legacy_scope_unknown")
        self.assertFalse(state["comparison"]["compatible"])
        report = self.client.get("/api/reports/excel")
        self.assertEqual(report.status_code, 200)
        import pandas as pd
        from io import BytesIO

        assessment = pd.read_excel(BytesIO(report.data), sheet_name="Assessment")
        self.assertEqual(
            assessment.loc[assessment["field"] == "Assessment status", "value"].iloc[0],
            "legacy_scope_unknown",
        )

    @patch("asrms.routes.api.listening_processes", return_value=PROCESSES)
    @patch("asrms.routes.api.scan_local_ports", return_value=GOOD_SCAN)
    def test_scan_persists_results_and_dashboard_pages_load(self, scan, _processes):
        response = self.post("/api/scans", json={"ports": [8090, 80]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk"]["score"], 97)
        self.assertEqual(response.json["scope"]["ports"], [80, 8090])
        self.assertTrue(response.json["complete"])
        state = self.client.get("/api/state").json
        self.assertEqual(state["latest_scan"]["tcp"][0]["port"], 8090)
        self.assertEqual(state["latest_scan"]["status"], "verified")
        self.assertIn("comparison", state)
        self.assertIn("administrator", state)
        self.assertEqual(state["latest_assessment_id"], response.json["id"])
        self.assertEqual(len(state["history"]), 1)
        scan.assert_called_once()
        self.assertEqual(scan.call_args.args[0], [80, 8090])
        for path in ("/", "/scanner", "/processes", "/risks", "/firewall", "/monitoring", "/comparison", "/history", "/reports"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_process_api_and_risk_share_the_same_assessment_inventory(self):
        self.save_assessment()
        state = self.client.get("/api/state").json
        process_response = self.client.get("/api/processes")
        self.assertEqual(process_response.status_code, 200)
        inventory = process_response.json
        self.assertEqual(inventory, state["process_inventory"])
        self.assertEqual(inventory["status"], "verified")
        self.assertEqual(inventory["scan_id"], state["latest_assessment_id"])
        finding = next(
            item for item in state["latest_scan"]["risk"]["findings"]
            if item["protocol"] == "TCP" and item["port"] == 8090
        )
        self.assertEqual(
            finding["listeners"],
            [
                {
                    "local_address": PROCESSES[0]["local_address"],
                    "processes": PROCESSES[0]["processes"],
                }
            ],
        )

    def test_process_inventory_distinguishes_empty_from_collection_error(self):
        empty_id = self.save_assessment(ports=(80,), risk={
            "score": 100, "open_ports": 0, "exposed_ports": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "findings": [],
        }, processes=[])
        empty = self.client.get("/api/processes").json
        self.assertEqual(empty["status"], "empty")
        self.assertEqual(empty["listeners"], [])
        self.assertEqual(empty["scan_id"], empty_id)

        with patch(
            "asrms.routes.api.listening_processes",
            side_effect=psutil.AccessDenied("socket inventory denied"),
        ), patch("asrms.routes.api.scan_local_ports", return_value=GOOD_SCAN):
            failed = self.post("/api/scans", json={"ports": [8090]})
        self.assertEqual(failed.status_code, 503)
        inventory = self.client.get("/api/processes").json
        self.assertEqual(inventory["status"], "stale")
        self.assertIn("socket inventory denied", inventory["error"])

    @patch("asrms.routes.api.listening_processes", return_value=PROCESSES)
    @patch("asrms.routes.api.scan_local_ports", return_value=GOOD_SCAN)
    def test_failed_rescan_preserves_results_and_marks_them_stale(self, _scan, _processes):
        self.post("/api/scans", json={"ports": [8090]})
        with patch("asrms.routes.api.scan_local_ports", side_effect=ScanError("nmap unavailable")):
            response = self.post("/api/scans", json={"ports": [8090]})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["status"], "stale")
        state = self.client.get("/api/state").json
        self.assertEqual(state["latest_scan"]["tcp"][0]["port"], 8090)
        self.assertEqual(state["latest_scan"]["status"], "stale")
        self.assertEqual(len(state["history"]), 1)

    def test_mutating_api_rejects_missing_csrf_token(self):
        response = self.client.post("/api/scans", json={"ports": [8090]})
        self.assertEqual(response.status_code, 403)

    def test_scan_validates_ports_before_invoking_nmap(self):
        response = self.post("/api/scans", json={"ports": [8090, "80"]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("ports", response.json["error"])

    @patch("asrms.firewall.manager.is_admin", return_value=False)
    def test_firewall_requires_confirmation_and_administrator(self, _admin):
        missing_confirmation = self.post(
            "/api/firewall/rules", json={"protocol": "TCP", "port": 8090}
        )
        self.assertEqual(missing_confirmation.status_code, 428)
        not_admin = self.post(
            "/api/firewall/rules",
            json={"protocol": "TCP", "port": 8090, "confirmed": True},
        )
        self.assertEqual(not_admin.status_code, 403)

    @patch("asrms.routes.api.listening_processes", return_value=PROCESSES)
    @patch("asrms.routes.api.scan_local_ports", return_value=GOOD_SCAN)
    @patch("asrms.firewall.manager.is_admin", return_value=True)
    @patch("asrms.firewall.manager.create_block_rule", return_value={
        "rule_name": APP_RULE["name"], "instance_id": APP_RULE["instance_id"], "verified": True
    })
    def test_post_remediation_uses_full_prior_scope_and_refreshes_state(
        self, _create, _admin, scan, _processes
    ):
        self.save_assessment(ports=(80, 443, 8090), service_detection=True)
        calls = 0

        def firewall_snapshot(instance_id=None):
            nonlocal calls
            calls += 1
            return [] if calls == 1 else [APP_RULE]

        with patch(
            "asrms.routes.api.manager.list_inbound_block_rules",
            side_effect=firewall_snapshot,
        ):
            response = self.post(
                "/api/firewall/rules",
                json={"protocol": "TCP", "port": 8090, "confirmed": True},
            )
            state = self.client.get("/api/state").json
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json["verified"])
        self.assertEqual(scan.call_args.args[0], [80, 443, 8090])
        self.assertTrue(scan.call_args.kwargs["service_detection"])
        self.assertEqual(response.json["scan"]["scope"]["ports"], [80, 443, 8090])
        self.assertEqual(state["latest_assessment_id"], response.json["scan"]["id"])
        self.assertEqual(state["history"][0]["id"], response.json["scan"]["id"])
        self.assertEqual(state["process_inventory"]["listeners"], response.json["scan"]["processes"])
        self.assertTrue(state["firewall_rules"][0]["verified"])
        self.assertEqual(
            state["latest_scan"]["risk"]["findings"][0]["listeners"][0]["processes"],
            PROCESSES[0]["processes"],
        )

    @patch("asrms.routes.api.listening_processes", return_value=PROCESSES)
    @patch("asrms.routes.api.scan_local_ports", return_value=GOOD_SCAN)
    @patch("asrms.firewall.manager.is_admin", return_value=True)
    @patch("asrms.firewall.manager.remove_rule", return_value=True)
    def test_post_rollback_uses_full_prior_scope(self, _remove, _admin, scan, _processes):
        self.save_assessment(ports=(80, 443, 8090))
        with self.app.app_context():
            database.insert_firewall_rule(
                APP_RULE["name"], APP_RULE["instance_id"], "TCP", 8090, True
            )
            rule_id = database.list_firewall_rules(active_only=True)[0]["id"]
        response = self.delete(
            f"/api/firewall/rules/{rule_id}", json={"confirmed": True}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(scan.call_args.args[0], [80, 443, 8090])
        self.assertEqual(response.json["scan"]["source"], "post-rollback")

    def _save_verified_rule_and_scan(self):
        self.save_assessment()
        with self.app.app_context():
            database.insert_firewall_rule(
                APP_RULE["name"], APP_RULE["instance_id"], "TCP", 8090, True
            )

    def test_external_disable_reconciles_database_and_risk(self):
        self._save_verified_rule_and_scan()
        disabled = {**APP_RULE, "enabled": False}
        with patch(
            "asrms.routes.api.manager.list_inbound_block_rules",
            return_value=[disabled],
        ):
            state = self.client.get("/api/state").json
        self.assertFalse(state["firewall_rules"][0]["verified"])
        self.assertFalse(state["firewall_rules"][0]["enabled"])
        self.assertEqual(state["latest_scan"]["risk"]["exposed_ports"], 1)
        with self.app.app_context():
            stored = database.list_firewall_rules(active_only=True)[0]
            self.assertEqual(stored["verified"], 0)

    def test_manually_deleted_rule_is_marked_unverified_and_exposure_returns(self):
        self._save_verified_rule_and_scan()
        with patch("asrms.routes.api.manager.list_inbound_block_rules", return_value=[]):
            state = self.client.get("/api/state").json
        self.assertEqual(len(state["firewall_rules"]), 1)
        self.assertFalse(state["firewall_rules"][0]["verified"])
        self.assertEqual(state["latest_scan"]["risk"]["exposed_ports"], 1)

    def test_wrong_protocol_or_port_does_not_verify_or_reduce_risk(self):
        self._save_verified_rule_and_scan()
        mismatched = {**APP_RULE, "protocol": "UDP", "port": "8091"}
        with patch(
            "asrms.routes.api.manager.list_inbound_block_rules",
            return_value=[mismatched],
        ):
            state = self.client.get("/api/state").json
        self.assertFalse(state["firewall_rules"][0]["verified"])
        self.assertEqual(state["latest_scan"]["risk"]["exposed_ports"], 1)
        self.assertFalse(state["latest_scan"]["risk"]["findings"][0]["firewall_restricted"])

    @patch("asrms.firewall.manager.is_admin", return_value=True)
    @patch("asrms.firewall.manager.create_block_rule", return_value={
        "rule_name": APP_RULE["name"], "instance_id": APP_RULE["instance_id"], "verified": True
    })
    def test_duplicate_live_firewall_restriction_is_rejected(self, _create, _admin):
        self._save_verified_rule_and_scan()
        with patch(
            "asrms.routes.api.manager.list_inbound_block_rules",
            return_value=[APP_RULE],
        ):
            response = self.post(
                "/api/firewall/rules",
                json={"protocol": "TCP", "port": 8090, "confirmed": True},
            )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json["existing_rule"]["ownership"], "application-owned")
        _create.assert_not_called()

    @patch("asrms.firewall.manager.is_admin", return_value=True)
    @patch("asrms.firewall.manager.create_block_rule")
    def test_external_firewall_rule_is_reported_without_claiming_ownership(self, create, _admin):
        self.save_assessment()
        external = {**APP_RULE, "name": "Manual SMB restriction", "instance_id": "external-id"}
        with patch(
            "asrms.routes.api.manager.list_inbound_block_rules",
            return_value=[external],
        ):
            response = self.post(
                "/api/firewall/rules",
                json={"protocol": "TCP", "port": 8090, "confirmed": True},
            )
            state = self.client.get("/api/state").json
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json["existing_rule"]["ownership"], "external")
        self.assertFalse(response.json["created"])
        self.assertIn("ASRMS did not create or change it", response.json["error"])
        self.assertFalse(state["firewall_rules"][0]["rollback_allowed"])
        create.assert_not_called()

    @patch("asrms.firewall.manager.is_admin", return_value=True)
    @patch("asrms.firewall.manager.create_block_rule")
    def test_disabled_application_rule_is_not_duplicated(self, create, _admin):
        self._save_verified_rule_and_scan()
        disabled = {**APP_RULE, "enabled": False}
        with patch(
            "asrms.routes.api.manager.list_inbound_block_rules",
            return_value=[disabled],
        ):
            response = self.post(
                "/api/firewall/rules",
                json={"protocol": "TCP", "port": 8090, "confirmed": True},
            )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json["existing_rule"]["ownership"], "application-owned")
        self.assertFalse(response.json["existing_rule"]["verified"])
        create.assert_not_called()

    def test_baseline_reset_is_explicit_and_updates_comparison(self):
        first = self.save_assessment(ports=(80, 443))
        current_risk = {
            "score": 100,
            "open_ports": 0,
            "exposed_ports": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "findings": [],
        }
        second = self.save_assessment(ports=(80, 443), risk=current_risk)
        before = self.client.get("/api/comparison").json
        self.assertTrue(before["compatible"])
        self.assertEqual(before["baseline_id"], first)
        changed = self.post("/api/comparison/baseline", json={"scan_id": second})
        self.assertEqual(changed.status_code, 200)
        after = self.client.get("/api/comparison").json
        self.assertEqual(after["baseline_id"], second)
        self.assertEqual(after["score_improvement"], 0)

    def test_incompatible_scan_scopes_disable_comparison_metrics(self):
        self.save_assessment(ports=(80, 443))
        self.save_assessment(ports=(80, 443, 8090))
        response = self.client.get("/api/comparison")
        self.assertFalse(response.json["compatible"])
        self.assertEqual(
            response.json["incompatibility_reason"],
            "Port scopes differ: baseline 80, 443, current 80, 443, 8090.",
        )
        self.assertIsNone(response.json["attack_surface_reduction_percent"])
        self.assertEqual(response.json["restricted_ports"], [])

    @patch("asrms.routes.api.listening_processes", return_value=PROCESSES)
    @patch("asrms.routes.api.scan_local_ports", return_value=GOOD_SCAN)
    def test_selected_baseline_scope_can_be_rescanned_exactly(self, scan, _processes):
        baseline_id = self.save_assessment(ports=(80, 443), service_detection=True)
        self.save_assessment(ports=(80, 443, 8090), service_detection=False)
        response = self.post(
            "/api/comparison/scan-baseline",
            json={"scan_id": baseline_id},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["scan"]["scope"], scan_scope((80, 443), True))
        self.assertEqual(response.json["latest_assessment_id"], response.json["scan"]["id"])
        scan.assert_called_once()
        self.assertEqual(scan.call_args.args[0], [80, 443])
        self.assertTrue(scan.call_args.kwargs["service_detection"])
        state = self.client.get("/api/state").json
        self.assertEqual(state["latest_assessment_id"], response.json["scan"]["id"])
        self.assertTrue(state["comparison"]["compatible"])

    def test_stale_excel_and_pdf_reports_disclose_stale_assessment(self):
        scan_id = self.save_assessment(ports=(80, 8090))
        with self.app.app_context():
            database.set_latest_scan_error("Nmap timed out")
            database.mark_latest_scan_stale("Nmap timed out", scan_id=scan_id)
        excel = self.client.get("/api/reports/excel")
        pdf = self.client.get("/api/reports/pdf")
        self.assertEqual(excel.status_code, 200)
        import pandas as pd
        from io import BytesIO

        assessment = pd.read_excel(BytesIO(excel.data), sheet_name="Assessment")
        self.assertIn("stale", assessment.loc[assessment["field"] == "Assessment status", "value"].iloc[0])
        self.assertEqual(pdf.status_code, 200)
        self.assertIn(b"stale", pdf.data.lower())

    def test_pdf_report_has_valid_download_response(self):
        response = self.client.get("/api/reports/pdf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertIn(
            'attachment; filename=asrms-security-report.pdf',
            response.headers["Content-Disposition"],
        )
        self.assertGreater(len(response.data), 0)
        self.assertTrue(response.data.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", response.data[-2048:])

    @patch("asrms.routes.reports.pdf_report", side_effect=OSError("PDF renderer failed"))
    def test_pdf_generation_failure_returns_error_instead_of_download(self, _pdf_report):
        response = self.client.get("/api/reports/pdf")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json["error"],
            "Report generation failed: PDF renderer failed",
        )

    @patch("asrms.routes.api.listening_processes", return_value=PROCESSES)
    @patch("asrms.routes.api.scan_local_ports", side_effect=ScanError("Nmap timed out"))
    @patch("asrms.firewall.manager.is_admin", return_value=True)
    @patch("asrms.firewall.manager.create_block_rule", return_value={
        "rule_name": APP_RULE["name"], "instance_id": APP_RULE["instance_id"], "verified": True
    })
    def test_firewall_change_is_not_success_when_complete_post_scan_fails(
        self, _create, _admin, _scan, _processes
    ):
        response = self.post(
            "/api/firewall/rules",
            json={"protocol": "TCP", "port": 8090, "confirmed": True},
        )
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json.get("verified", False))
        self.assertEqual(self.client.get("/api/state").json["latest_scan"], None)


if __name__ == "__main__":
    unittest.main()
