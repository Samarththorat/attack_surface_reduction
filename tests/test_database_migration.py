import sqlite3
import tempfile
import unittest
from pathlib import Path

from asrms import create_app


class DatabaseMigrationTests(unittest.TestCase):
    def test_migration_backs_up_and_preserves_legacy_scan_and_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy.sqlite3"
            db = sqlite3.connect(path)
            db.executescript(
                """
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tcp_json TEXT NOT NULL,
                    udp_json TEXT NOT NULL,
                    processes_json TEXT NOT NULL,
                    risk_json TEXT NOT NULL,
                    error TEXT
                );
                CREATE TABLE firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL UNIQUE,
                    protocol TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    verified INTEGER NOT NULL,
                    removed_at TEXT
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    category TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO scans VALUES
                    (1, '2026-01-01T00:00:00+00:00', 'verified', 'manual', '[]', '[]', '[]', '{}', NULL);
                INSERT INTO settings VALUES ('baseline_scan_id', '1');
                """
            )
            db.commit()
            db.close()
            app = create_app(
                {
                    "TESTING": True,
                    "DATABASE": str(path),
                    "SECRET_KEY": "migration-test",
                }
            )
            backups = list(Path(temporary).glob("legacy.backup-*.sqlite3"))
            self.assertEqual(len(backups), 1)
            migrated = sqlite3.connect(path)
            self.assertEqual(migrated.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
            self.assertEqual(
                migrated.execute("SELECT value FROM settings WHERE key='baseline_scan_id'").fetchone()[0],
                "1",
            )
            columns = {row[1] for row in migrated.execute("PRAGMA table_info(scans)")}
            self.assertTrue({"scan_scope_json", "complete", "firewall_json", "verification_json"} <= columns)
            tables = {
                row[0]
                for row in migrated.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertTrue(
                {
                    "url_scans",
                    "url_security_findings",
                    "port_monitor_snapshots",
                    "port_activity_events",
                    "firewall_profile_snapshots",
                    "security_notifications",
                }
                <= tables
            )
            firewall_columns = {row[1] for row in migrated.execute("PRAGMA table_info(firewall_rules)")}
            self.assertIn("instance_id", firewall_columns)
            migrated.close()
            backup = sqlite3.connect(backups[0])
            self.assertEqual(backup.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(backup.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
            backup.close()
            self.assertIsNotNone(app)


if __name__ == "__main__":
    unittest.main()
