import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

from asrms import create_app


class IdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, _tag, attrs):
        self.ids.extend(value for name, value in attrs if name == "id")


class FrontendContractTests(unittest.TestCase):
    def test_comparison_page_has_unique_controls_and_scope_rescan(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": "test",
                    "DATABASE": str(Path(directory) / "test.sqlite3"),
                }
            )
            response = app.test_client().get("/comparison")
        self.assertEqual(response.status_code, 200)
        parser = IdCollector()
        parser.feed(response.get_data(as_text=True))
        duplicates = {item for item in parser.ids if parser.ids.count(item) > 1}
        self.assertEqual(duplicates, set())
        self.assertIn("scanBaselineScope", parser.ids)
        self.assertIn("baselineSelect", parser.ids)

    def test_firewall_actions_emit_one_final_status_not_competing_toasts(self):
        script_path = Path(__file__).resolve().parents[1] / "static" / "js" / "app.js"
        script = script_path.read_text(encoding="utf-8")
        start = script.index("async function confirmRestriction")
        end = script.index("const baselineScanButton", start)
        firewall_actions = script[start:end]
        self.assertNotIn("toast(", firewall_actions)
        self.assertIn("Restriction verified for", firewall_actions)
        self.assertIn("setStatus(error.message, \"error\")", firewall_actions)

    def test_report_downloads_validate_blob_and_prevent_duplicate_requests(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "static" / "js" / "app.js").read_text(encoding="utf-8")
        template = (root / "templates" / "section.html").read_text(encoding="utf-8")
        self.assertIn("await response.blob()", script)
        self.assertIn("URL.createObjectURL(blob)", script)
        self.assertIn("Content-Disposition", script)
        self.assertIn("reportDownloads.has(downloadKey)", script)
        self.assertIn('data-report-download="pdf"', template)
        self.assertIn('data-report-download="excel"', template)

    def test_scanner_process_labels_deduplicate_same_pid_across_local_addresses(self):
        script_path = Path(__file__).resolve().parents[1] / "static" / "js" / "app.js"
        script = script_path.read_text(encoding="utf-8")
        self.assertIn("[...new Set(processNames)]", script)


if __name__ == "__main__":
    unittest.main()
