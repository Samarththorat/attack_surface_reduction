import atexit
import hashlib
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone

import psutil

from asrms import database
from asrms.firewall import manager
from asrms.scanners.processes import listening_processes


_WORKERS = {}
_WORKERS_LOCK = threading.Lock()
LOGGER = logging.getLogger(__name__)
KNOWN_WINDOWS_PROCESS_NAMES = {
    "svchost.exe",
    "system",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
}


def _utc_now():
    return datetime.now(timezone.utc)


def _stamp(value):
    return value.isoformat(timespec="seconds")


def _service_by_pid():
    if not hasattr(psutil, "win_service_iter"):
        return {}
    services = {}
    try:
        for service in psutil.win_service_iter():
            try:
                details = service.as_dict()
            except (psutil.Error, OSError):
                continue
            if details.get("pid"):
                services[details["pid"]] = details.get("name", "Unknown")
    except (psutil.Error, OSError):
        LOGGER.warning("Windows service inventory is unavailable", exc_info=True)
        return None
    return services


def _firewall_rule_status(rules, protocol, port):
    if rules is None:
        return "Unknown"
    return (
        "Verified all-address, all-profile matching block rule"
        if any(manager.rule_covers_port(rule, protocol, port) for rule in rules)
        else "No verified effective matching block rule"
    )


def _listener_records(listeners, rules, services, prior, now, persistent_seconds):
    previous = {item["socket_id"]: item for item in prior}
    current = []
    for listener in listeners:
        processes = listener.get("processes") or [None]
        for process in processes:
            pid = process.get("pid") if process else None
            process_name = process.get("name", "Unavailable") if process else "Unavailable"
            executable = process.get("exe", "Unavailable") if process else "Unavailable"
            try:
                started_at = _stamp(datetime.fromtimestamp(psutil.Process(pid).create_time(), timezone.utc)) if pid else None
            except (psutil.Error, OSError, ValueError):
                started_at = None
            protocol = listener["protocol"].upper()
            port = int(listener["port"])
            local_address = str(listener.get("local_address", ""))
            socket_id = f"{protocol}|{local_address}|{port}"
            old = previous.get(socket_id)
            identity = (pid, process_name, executable, started_at)
            prior_identity = old_identity(old) if old else None
            first_seen = old.get("first_detected_at") if old else _stamp(now)
            try:
                duration = (now - datetime.fromisoformat(first_seen)).total_seconds()
            except (TypeError, ValueError):
                duration = 0
            risk_indicators = []
            if address_is_wildcard(local_address):
                risk_indicators.append("Wildcard-bound address may accept connections on multiple interfaces.")
            if process_name == "Unavailable":
                risk_indicators.append("Process identity is unavailable.")
            if services is None:
                risk_indicators.append("Windows service attribution is unavailable.")
            restriction = _firewall_rule_status(rules, protocol, port)
            if restriction == "No verified matching block rule":
                risk_indicators.append("No verified matching inbound block rule was observed.")
            identity_status = "UNKNOWN"
            windows_root = os.environ.get("SystemRoot", r"C:\Windows").rstrip("\\").lower()
            normalized_exe = executable.replace("/", "\\").lower()
            known_process = process_name.lower() in KNOWN_WINDOWS_PROCESS_NAMES
            verified_system_path = normalized_exe.startswith(windows_root + "\\")
            service_name = services.get(pid, "Not identified") if services is not None and pid else "Unavailable"
            if known_process and verified_system_path and service_name not in {"Not identified", "Unavailable"}:
                identity_status = "WINDOWS_SERVICE_ASSOCIATED_SIGNATURE_UNVERIFIED"
            current.append(
                {
                    "socket_id": socket_id,
                    "protocol": protocol,
                    "local_address": local_address,
                    "port": port,
                    "pid": pid,
                    "process_name": process_name,
                    "executable": executable,
                    "process_start_time": started_at,
                    "first_detected_at": first_seen,
                    "last_detected_at": _stamp(now),
                    "state": "LISTENING" if protocol == "TCP" else "BOUND",
                    "persistent": duration >= (
                        persistent_seconds["tcp"] if protocol == "TCP" else persistent_seconds["udp"]
                    ),
                    "firewall_restriction": restriction,
                    "windows_service": "Unavailable" if services is None or not pid else services.get(pid, "Not identified"),
                    "risk_indicators": risk_indicators,
                    "identity_status": identity_status,
                    "persistence_seconds": int(duration),
                    "_previous_identity": prior_identity,
                    "_identity": identity,
                }
            )
    return current


def address_is_wildcard(local_address):
    address = local_address.rsplit("]:", 1)[0].lstrip("[") if local_address.startswith("[") else local_address.rsplit(":", 1)[0]
    return address in {"0.0.0.0", "::", "*"}


def _event_key(event_type, listener, discriminator=""):
    value = "|".join(
        (
            event_type,
            listener.get("socket_id", ""),
            str(listener.get("first_detected_at", "")),
            discriminator,
        )
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _record_event(
    event_type,
    listener,
    message,
    severity="info",
    reason="Routine socket state change.",
    recommendation="Review the detailed monitoring history if this activity is unexpected.",
    discriminator="",
    cooldown_seconds=0,
):
    key = _event_key(event_type, listener, discriminator)
    details = {key: value for key, value in listener.items() if not key.startswith("_")}
    details.update(
        severity=severity.upper(),
        reason=reason,
        recommendation=recommendation,
        detected_at=_stamp(_utc_now()),
    )
    if database.record_port_activity(event_type, key, details):
        database.record_event(event_type.lower(), message, details)
        if severity != "info":
            database.record_security_notification(
                severity,
                event_type,
                message,
                details,
                key,
                cooldown_seconds=cooldown_seconds,
                group_key=listener.get("socket_id"),
            )


def _classify_listener_event(event_type, listener, persistence_seconds=0):
    protocol = listener["protocol"]
    wildcard = address_is_wildcard(listener["local_address"])
    process_name = listener.get("process_name", "Unavailable")
    if event_type in {"TCP_PROCESS_CHANGED", "UDP_PROCESS_CHANGED"}:
        return (
            "medium",
            f"The process identity associated with this {protocol} socket changed; the new identity is not independently trusted.",
            "Verify the current PID, executable path, process start time, and expected service association.",
        )
    known_service = (
        process_name.lower() in KNOWN_WINDOWS_PROCESS_NAMES
        and listener.get("windows_service") not in {"Unavailable", "Not identified"}
        and listener.get("identity_status") == "WINDOWS_SERVICE_ASSOCIATED_SIGNATURE_UNVERIFIED"
    )
    if protocol == "UDP":
        if event_type == "PERSISTENT_UDP_SOCKET":
            return (
                "info",
                f"UDP socket persisted for {int(persistence_seconds)} seconds; no TCP listener state is implied.",
                "Review UDP ownership only if the binding is unexpected.",
            )
        return "info", "UDP-bound socket observation; UDP has no TCP LISTENING state.", "Review its owning process if this binding is unexpected."
    if known_service:
        return (
            "info",
            "Process name and Windows service association match a Windows component, but its digital signature was not verified.",
            "No action based on the process name alone; verify signature and service ownership if needed.",
        )
    if event_type == "PERSISTENT_TCP_LISTENER":
        return (
            "medium",
            f"Unknown or unverified process remains bound for {int(persistence_seconds)} seconds"
            + (" on a wildcard address." if wildcard else "."),
            "Investigate the process, executable path, listening address, and effective firewall policy.",
        )
    if event_type == "NEW_TCP_LISTENER" and wildcard:
        return (
            "medium",
            "A new TCP listener is bound to a wildcard address; external reachability was not tested.",
            "Verify process ownership, executable provenance, and inbound firewall policy.",
        )
    return (
        "info",
        "TCP listener state changed without a verified suspicious process indicator.",
        "Investigate only if the process or port is unexpected.",
    )


def _compare_and_record(
    previous,
    current,
    now,
    tcp_persistent_seconds,
    udp_persistent_seconds,
    alert_cooldown_seconds,
):
    previous_by_id = {item["socket_id"]: item for item in previous}
    current_by_id = {item["socket_id"]: item for item in current}
    for socket_id, listener in current_by_id.items():
        old = previous_by_id.get(socket_id)
        protocol = listener["protocol"]
        event_names = (
            ("NEW_TCP_LISTENER", "PERSISTENT_TCP_LISTENER", "TCP_LISTENER_CLOSED", "TCP_PROCESS_CHANGED")
            if protocol == "TCP"
            else ("NEW_UDP_SOCKET", "PERSISTENT_UDP_SOCKET", "UDP_SOCKET_REMOVED", "UDP_PROCESS_CHANGED")
        )
        new_type, persistent_type, _, process_change_type = event_names
        label = f"{protocol}/{listener['port']} at {listener['local_address']}"
        if old is None:
            event_type = new_type
            severity, reason, recommendation = _classify_listener_event(event_type, listener)
            message = f"{event_type.replace('_', ' ').title()}: {label}."
            _record_event(
                event_type,
                listener,
                message,
                severity,
                reason,
                recommendation,
                cooldown_seconds=alert_cooldown_seconds,
            )
        elif listener["_identity"] != old_identity(old):
            severity, reason, recommendation = _classify_listener_event(process_change_type, listener)
            _record_event(
                process_change_type,
                listener,
                f"{process_change_type.replace('_', ' ').title()} for {label}.",
                severity,
                reason,
                recommendation,
                discriminator=f"{listener.get('pid')}|{listener.get('process_start_time')}",
                cooldown_seconds=alert_cooldown_seconds,
            )
        if listener["process_name"] == "Unavailable":
            _record_event(
                "PROCESS_UNAVAILABLE",
                listener,
                f"Process details are unavailable for {label}.",
                "medium" if protocol == "TCP" and address_is_wildcard(listener["local_address"]) else "info",
                "Psutil did not provide process details for this socket.",
                "Recollect with sufficient permissions and check the owning PID locally.",
                cooldown_seconds=alert_cooldown_seconds,
            )
        try:
            first_seen = datetime.fromisoformat(listener["first_detected_at"])
            duration = (now - first_seen).total_seconds()
        except (TypeError, ValueError):
            duration = 0
        threshold = tcp_persistent_seconds if protocol == "TCP" else udp_persistent_seconds
        if duration >= threshold:
            event_type = persistent_type
            severity, reason, recommendation = _classify_listener_event(
                event_type, listener, duration
            )
            _record_event(
                event_type,
                listener,
                f"{event_type.replace('_', ' ').title()} for {int(duration)} seconds: {label}.",
                severity,
                reason,
                recommendation,
                cooldown_seconds=alert_cooldown_seconds,
            )
    for socket_id, listener in previous_by_id.items():
        if socket_id not in current_by_id:
            closed_type = "TCP_LISTENER_CLOSED" if listener["protocol"] == "TCP" else "UDP_SOCKET_REMOVED"
            _record_event(
                closed_type,
                listener,
                f"{closed_type.replace('_', ' ').title()}: {listener['protocol']}/{listener['port']} at {listener['local_address']}.",
                "info",
                "Previously observed socket is no longer present in the successful snapshot.",
                "No action is required unless the socket unexpectedly stopped.",
            )


def old_identity(listener):
    return (
        listener.get("pid"),
        listener.get("process_name"),
        listener.get("executable"),
        listener.get("process_start_time"),
    )


def collect_once():
    now = _utc_now()
    existing = database.get_port_monitor_snapshot()
    previous = existing["listeners"] if existing else []
    try:
        listeners = listening_processes()
    except (psutil.Error, OSError) as exc:
        error = f"Could not collect process/socket inventory: {exc}"
        if not existing or existing.get("status") != "error":
            cooldown_seconds = 300
            try:
                from flask import current_app

                cooldown_seconds = max(
                    0, int(current_app.config.get("ALERT_COOLDOWN_SECONDS", 300))
                )
            except RuntimeError:
                pass
            failed_listener = {
                "socket_id": "inventory",
                "first_detected_at": _stamp(now),
            }
            _record_event(
                "INVENTORY_COLLECTION_FAILED",
                failed_listener,
                error,
                "medium",
                "The local socket inventory could not be collected; prior observations are retained but are not current.",
                "Check process permissions and the monitoring service, then wait for a successful snapshot.",
                discriminator="inventory",
                cooldown_seconds=cooldown_seconds,
            )
        database.save_port_monitor_snapshot(previous, status="error", error=error[:500])
        return database.get_port_monitor_snapshot()

    try:
        firewall_rules = manager.list_inbound_block_rules()
    except manager.FirewallError:
        firewall_rules = None
        LOGGER.warning("Live firewall restrictions unavailable for port monitor snapshot", exc_info=True)
    services = _service_by_pid()
    persistent_seconds = {"tcp": 30, "udp": 60}
    cooldown_seconds = 300
    try:
        from flask import current_app

        persistent_seconds = {
            "tcp": int(current_app.config.get("PORT_MONITOR_PERSISTENT_SECONDS", 30)),
            "udp": int(current_app.config.get("UDP_PERSISTENT_SECONDS", 60)),
        }
        cooldown_seconds = int(current_app.config.get("ALERT_COOLDOWN_SECONDS", 300))
    except RuntimeError:
        pass
    persistent_seconds = {key: max(1, value) for key, value in persistent_seconds.items()}
    cooldown_seconds = max(0, cooldown_seconds)
    current = _listener_records(
        listeners, firewall_rules, services, previous, now, persistent_seconds
    )
    _compare_and_record(
        previous,
        current,
        now,
        persistent_seconds["tcp"],
        persistent_seconds["udp"],
        cooldown_seconds,
    )
    for listener in current:
        listener.pop("_previous_identity", None)
        listener.pop("_identity", None)
    database.save_port_monitor_snapshot(current)
    return database.get_port_monitor_snapshot()


def port_monitor_payload(snapshot=None):
    snapshot = snapshot or database.get_port_monitor_snapshot()
    events = database.list_port_activity(100)
    listeners = snapshot["listeners"] if snapshot else []
    current_listeners = listeners if snapshot and snapshot["status"] == "verified" else []
    tcp = [item for item in current_listeners if item["protocol"] == "TCP"]
    udp = [item for item in current_listeners if item["protocol"] == "UDP"]
    event_counts = {}
    for event in events:
        event_counts[event["event_type"]] = event_counts.get(event["event_type"], 0) + 1
    return {
        "status": snapshot["status"] if snapshot else "unavailable",
        "error": snapshot["error"] if snapshot else None,
        "last_updated": snapshot["observed_at"] if snapshot else None,
        "listeners": listeners,
        "tcp_listeners": tcp,
        "udp_sockets": udp,
        "events": events,
        "summary": {
            "tcp_listeners": len(tcp) if snapshot and snapshot["status"] == "verified" else None,
            "udp_sockets": len(udp) if snapshot and snapshot["status"] == "verified" else None,
            "new_tcp_listeners": event_counts.get("NEW_TCP_LISTENER", 0),
            "new_udp_sockets": event_counts.get("NEW_UDP_SOCKET", 0),
            "persistent_tcp_listeners": sum(bool(item.get("persistent")) for item in tcp),
            "persistent_udp_sockets": sum(bool(item.get("persistent")) for item in udp),
            "recently_closed_tcp_listeners": event_counts.get("TCP_LISTENER_CLOSED", 0),
            "recently_removed_udp_sockets": event_counts.get("UDP_SOCKET_REMOVED", 0),
            "tcp_process_changes": event_counts.get("TCP_PROCESS_CHANGED", 0),
            "udp_process_changes": event_counts.get("UDP_PROCESS_CHANGED", 0),
        },
    }


def _worker(app, stop_event):
    interval = max(3, min(60, int(app.config.get("PORT_MONITOR_INTERVAL_SECONDS", 5))))
    while not stop_event.is_set():
        try:
            with app.app_context():
                collect_once()
        except (psutil.Error, OSError, sqlite3.Error, ValueError, manager.FirewallError):
            LOGGER.exception("Continuous port monitoring iteration failed")
        stop_event.wait(interval)


def start_worker(app):
    if app.testing or not app.config.get("PORT_MONITOR_ENABLED", True):
        return
    path = str(app.config["DATABASE"])
    with _WORKERS_LOCK:
        if path in _WORKERS and _WORKERS[path][0].is_alive():
            return
        stop_event = threading.Event()
        thread = threading.Thread(
            target=_worker,
            args=(app, stop_event),
            name="asrms-port-monitor",
            daemon=True,
        )
        _WORKERS[path] = (thread, stop_event)
        thread.start()
    atexit.register(shutdown_worker, path)


def shutdown_worker(path):
    with _WORKERS_LOCK:
        worker = _WORKERS.pop(path, None)
    if not worker:
        return
    thread, stop_event = worker
    stop_event.set()
    if thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=3)
