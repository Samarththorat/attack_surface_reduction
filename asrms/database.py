import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    source TEXT NOT NULL,
    tcp_json TEXT NOT NULL,
    udp_json TEXT NOT NULL,
    processes_json TEXT NOT NULL,
    risk_json TEXT NOT NULL,
    error TEXT,
    scan_scope_json TEXT NOT NULL DEFAULT '{}',
    complete INTEGER NOT NULL DEFAULT 0,
    firewall_json TEXT NOT NULL DEFAULT '[]',
    verification_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL UNIQUE,
    instance_id TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    verified INTEGER NOT NULL,
    removed_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    category TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    if "db" not in g:
        path = _database_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(path, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 15000")
    return g.db


def _database_path():
    path = Path(current_app.config["DATABASE"])
    if not path.is_absolute():
        path = Path(current_app.root_path).parent / path
    return path


def _backup_database(path):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup_path = path.with_name(f"{path.stem}.backup-{timestamp}{path.suffix}")
    source = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=15)
    target = sqlite3.connect(backup_path)
    try:
        source.backup(target)
        integrity = target.execute("PRAGMA quick_check").fetchone()[0]
        if integrity != "ok":
            raise sqlite3.DatabaseError(f"Database backup integrity check failed: {integrity}")
    except Exception:
        target.close()
        source.close()
        backup_path.unlink(missing_ok=True)
        raise
    finally:
        if target:
            target.close()
        if source:
            source.close()


def _migrate_schema(db):
    path = _database_path()
    tables = {
        row["name"]
        for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    }
    migration_needed = False
    if "scans" in tables:
        columns = {row["name"] for row in db.execute("PRAGMA table_info(scans)").fetchall()}
        expected = {
            "scan_scope_json",
            "complete",
            "firewall_json",
            "verification_json",
        }
        migration_needed = bool(expected - columns)
    if "firewall_rules" in tables:
        firewall_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(firewall_rules)").fetchall()
        }
        migration_needed = migration_needed or "instance_id" not in firewall_columns
    if migration_needed and path.is_file() and path.stat().st_size:
        _backup_database(path)
    db.executescript(SCHEMA)
    columns = {row["name"] for row in db.execute("PRAGMA table_info(scans)").fetchall()}
    additions = {
        "scan_scope_json": "TEXT NOT NULL DEFAULT '{}'",
        "complete": "INTEGER NOT NULL DEFAULT 0",
        "firewall_json": "TEXT NOT NULL DEFAULT '[]'",
        "verification_json": "TEXT NOT NULL DEFAULT '{}'",
    }
    for column, definition in additions.items():
        if column not in columns:
            db.execute(f"ALTER TABLE scans ADD COLUMN {column} {definition}")
    firewall_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(firewall_rules)").fetchall()
    }
    if "instance_id" not in firewall_columns:
        db.execute("ALTER TABLE firewall_rules ADD COLUMN instance_id TEXT NOT NULL DEFAULT ''")
    db.commit()


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    _migrate_schema(get_db())


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()


def record_event(category, message, details=None):
    db = get_db()
    db.execute(
        "INSERT INTO events (created_at, category, message, details_json) VALUES (?, ?, ?, ?)",
        (utc_now(), category, message, json.dumps(details or {}, separators=(",", ":"))),
    )
    db.commit()


def get_latest_scan():
    row = get_db().execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return scan_from_row(row) if row else None


def scan_from_row(row):
    scan = dict(row)
    for column in ("tcp_json", "udp_json", "processes_json", "risk_json"):
        scan[column.removesuffix("_json")] = json.loads(scan.pop(column))
    scan["scope"] = json.loads(scan.pop("scan_scope_json", "{}"))
    scan["firewall_rules"] = json.loads(scan.pop("firewall_json", "[]"))
    scan["verification"] = json.loads(scan.pop("verification_json", "{}"))
    scan["complete"] = bool(scan.get("complete", False))
    return scan


def get_latest_complete_scan():
    row = get_db().execute(
        "SELECT * FROM scans WHERE complete = 1 ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return scan_from_row(row) if row else None


def get_scan(scan_id):
    row = get_db().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return scan_from_row(row) if row else None


def save_scan(result, source="manual", status="verified", error=None, scope=None, complete=False):
    db = get_db()
    db.execute(
        """INSERT INTO scans
           (created_at, status, source, tcp_json, udp_json, processes_json, risk_json, error,
            scan_scope_json, complete, firewall_json, verification_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            utc_now(),
            status,
            source,
            json.dumps(result.get("tcp", []), separators=(",", ":")),
            json.dumps(result.get("udp", []), separators=(",", ":")),
            json.dumps(result.get("processes", []), separators=(",", ":")),
            json.dumps(result.get("risk", {}), separators=(",", ":")),
            error,
            json.dumps(scope or {}, separators=(",", ":")),
            int(complete),
            json.dumps(result.get("firewall_rules", []), separators=(",", ":")),
            json.dumps(result.get("verification", {}), separators=(",", ":")),
        ),
    )
    scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    if complete:
        db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('baseline_scan_id', ?)",
            (str(scan_id),),
        )
    db.execute(
        """INSERT INTO settings (key, value) VALUES ('latest_scan_status', ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
        (status,),
    )
    db.execute(
        """INSERT INTO settings (key, value) VALUES ('latest_scan_error', '')
           ON CONFLICT(key) DO UPDATE SET value = excluded.value"""
    )
    db.commit()
    return scan_id


def mark_latest_scan_stale(error=None, scan_id=None):
    db = get_db()
    if scan_id is not None:
        db.execute(
            "UPDATE scans SET status = 'stale', error = ? WHERE id = ?",
            ((error or "Assessment verification failed.")[:500], scan_id),
        )
        db.commit()
    set_setting("latest_scan_status", "stale")
    if error:
        set_latest_scan_error(error)


def set_latest_scan_error(error):
    set_setting("latest_scan_error", error[:500])


def update_scan_security_state(scan_id, risk, firewall_rules):
    db = get_db()
    db.execute(
        "UPDATE scans SET risk_json = ?, firewall_json = ? WHERE id = ?",
        (
            json.dumps(risk, separators=(",", ":")),
            json.dumps(firewall_rules, separators=(",", ":")),
            scan_id,
        ),
    )
    db.commit()


def update_firewall_rule_status(rule_name, enabled, verified):
    db = get_db()
    db.execute(
        "UPDATE firewall_rules SET enabled = ?, verified = ? WHERE rule_name = ? AND removed_at IS NULL",
        (int(enabled), int(verified), rule_name),
    )
    db.commit()


def set_baseline_scan_id(scan_id):
    set_setting("baseline_scan_id", str(scan_id))


def list_scans(limit=50):
    rows = get_db().execute(
        """SELECT id, created_at, status, source, error, risk_json, scan_scope_json, complete
           FROM scans ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [
        {
            "id": row["id"],
            "created_at": row["created_at"],
            "status": row["status"],
            "source": row["source"],
            "error": row["error"],
            "risk": json.loads(row["risk_json"]),
            "scope": json.loads(row["scan_scope_json"]),
            "complete": bool(row["complete"]),
        }
        for row in rows
    ]


def list_events(limit=100):
    rows = get_db().execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [
        {
            "id": row["id"],
            "created_at": row["created_at"],
            "category": row["category"],
            "message": row["message"],
            "details": json.loads(row["details_json"]),
        }
        for row in rows
    ]


def list_firewall_rules(active_only=False):
    query = "SELECT * FROM firewall_rules"
    if active_only:
        query += " WHERE removed_at IS NULL"
    return [dict(row) for row in get_db().execute(query + " ORDER BY id DESC").fetchall()]


def insert_firewall_rule(rule_name, instance_id, protocol, port, verified):
    db = get_db()
    db.execute(
        """INSERT INTO firewall_rules
           (rule_name, instance_id, protocol, port, created_at, enabled, verified)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (rule_name, instance_id, protocol, port, utc_now(), int(verified), int(verified)),
    )
    db.commit()


def mark_firewall_rule_removed(rule_name):
    db = get_db()
    db.execute(
        "UPDATE firewall_rules SET enabled = 0, removed_at = ? WHERE rule_name = ?",
        (utc_now(), rule_name),
    )
    db.commit()


def get_setting(key):
    row = get_db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(key, value):
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    db.commit()
