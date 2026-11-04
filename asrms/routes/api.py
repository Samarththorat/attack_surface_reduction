import sqlite3
import threading
from datetime import datetime, timezone

import psutil
from flask import Blueprint, current_app, jsonify, request

from asrms import database
from asrms.firewall import manager
from asrms.monitoring.ports import port_monitor_payload
from asrms.scanners.nmap import ScanError, scan_local_ports
from asrms.scanners.processes import listening_processes
from asrms.security.risk import analyze_risk, firewall_profile_health
from asrms.security.url_scanner import URLValidationError, analyze_url

api = Blueprint("api", __name__)
_FIREWALL_PROFILE_LOCK = threading.Lock()
DEFAULT_PORTS = [21, 22, 23, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5000, 5432, 5900, 8080, 8443]


def _error(message, status=400):
    return jsonify({"error": message}), status


def _make_scope(ports, service_detection=False):
    return {
        "target": "127.0.0.1",
        "protocols": ["TCP", "UDP"],
        "ports": sorted(ports),
        "service_detection": service_detection,
        "network_access_test": "not_performed",
        "scope_label": "Loopback only (this computer)",
    }


def _valid_scope(scope):
    if not isinstance(scope, dict):
        return False
    ports = scope.get("ports")
    protocols = scope.get("protocols")
    return (
        scope.get("target") == "127.0.0.1"
        and isinstance(protocols, list)
        and all(isinstance(protocol, str) for protocol in protocols)
        and sorted(protocols) == ["TCP", "UDP"]
        and isinstance(ports, list)
        and bool(ports)
        and all(type(port) is int and 1 <= port <= 65535 for port in ports)
        and ports == sorted(set(ports))
    )


def _scopes_compatible(left, right):
    return (
        _valid_scope(left)
        and _valid_scope(right)
        and left["target"] == right["target"]
        and sorted(left["protocols"]) == sorted(right["protocols"])
        and left["ports"] == right["ports"]
    )


def _comparison_incompatibility_reason(baseline, latest):
    if not baseline:
        return "Select a complete verified baseline before comparing assessments."
    if not latest:
        return "No complete current assessment is available; run an assessment."
    if not baseline.get("complete") or not _valid_scope(baseline.get("scope")):
        return "The selected baseline has no complete verified scan scope."
    if not latest.get("complete") or not _valid_scope(latest.get("scope")):
        return "The current assessment has no complete verified scan scope."
    if baseline.get("status") != "verified":
        return f"Baseline scan #{baseline['id']} is {baseline.get('status')}, not verified."
    if latest.get("status") != "verified" or _current_assessment_status() != "verified":
        return f"Current assessment scan #{latest['id']} is stale or unverified; run a complete assessment."
    left = baseline["scope"]
    right = latest["scope"]
    if left["target"] != right["target"]:
        return f"Targets differ: baseline {left['target']}, current {right['target']}."
    if left["protocols"] != right["protocols"]:
        return (
            f"Protocol scopes differ: baseline {', '.join(left['protocols'])}, "
            f"current {', '.join(right['protocols'])}."
        )
    if left["ports"] != right["ports"]:
        return (
            f"Port scopes differ: baseline {', '.join(map(str, left['ports']))}, "
            f"current {', '.join(map(str, right['ports']))}."
        )
    return "Assessments are not comparable because their verified scope metadata differs."


def _normalize_protocol(protocol):
    protocol = str(protocol or "").upper()
    if protocol == "6":
        return "TCP"
    if protocol == "17":
        return "UDP"
    return protocol


def _actual_firewall_state():
    observed = manager.list_inbound_block_rules()
    records = database.list_firewall_rules(active_only=True)
    remaining = list(observed)
    application_rules = []
    verification_changed = False

    for record in records:
        identity = record.get("instance_id", "")
        matches = [
            item
            for item in remaining
            if identity and item.get("instance_id") == identity
        ]
        if not identity:
            matches = [
                item for item in remaining
                if item.get("name") == record["rule_name"]
            ]
        exact_name = len(matches) == 1 and matches[0].get("name") == record["rule_name"]
        actual = matches[0] if len(matches) == 1 else None
        exact_rule = bool(
            actual
            and exact_name
            and manager.matches_rule(actual, record["protocol"], record["port"])
        )
        current_enabled = bool(actual and actual.get("enabled") is True)
        current_verified = bool(exact_rule and identity)
        if (
            bool(record["enabled"]) != current_enabled
            or bool(record["verified"]) != current_verified
        ):
            verification_changed = True
            database.update_firewall_rule_status(
                record["rule_name"], current_enabled, current_verified
            )
            database.record_event(
                "firewall_verification",
                f"Live firewall verification changed for {record['rule_name']}.",
                {
                    "rule_name": record["rule_name"],
                    "verified": current_verified,
                    "enabled": current_enabled,
                    "identity_found": bool(actual),
                },
            )
        if actual:
            remaining.remove(actual)
        application_rules.append(
            {
                **record,
                "enabled": current_enabled,
                "verified": current_verified,
                "recorded": True,
                "rollback_allowed": bool(identity),
                "observed_rule": actual,
            }
        )

    for actual in observed:
        if actual not in remaining:
            continue
        remaining.remove(actual)
        application_rules.append(
            {
                "id": None,
                "rule_name": actual.get("name", ""),
                "instance_id": actual.get("instance_id", ""),
                "protocol": _normalize_protocol(actual.get("protocol")),
                "port": actual.get("port"),
                "enabled": bool(actual.get("enabled")),
                "verified": bool(manager.matches_rule(
                    actual,
                    _normalize_protocol(actual.get("protocol")),
                    int(actual["port"]),
                )) if str(actual.get("port", "")).isdigit()
                and _normalize_protocol(actual.get("protocol")) in {"TCP", "UDP"} else False,
                "recorded": False,
                "rollback_allowed": False,
                "observed_rule": actual,
            }
        )

    return observed, application_rules, verification_changed


def _current_assessment_status():
    status = database.get_setting("latest_scan_status")
    if status == "stale":
        return "stale"
    if database.get_latest_complete_scan():
        return status or "verified"
    if database.get_latest_scan():
        if status == "incomplete":
            return "incomplete"
        return "legacy_scope_unknown"
    return "unavailable"


def _process_inventory_payload(scan):
    if not scan:
        failed_error = (
            database.get_setting("latest_scan_error")
            if _current_assessment_status() == "stale"
            else None
        )
        return {
            "status": "error" if failed_error else "unavailable",
            "error": failed_error or "Run a complete assessment to collect listener data.",
            "scan_id": None,
            "listeners": [],
        }
    listeners = scan.get("processes") or []
    if _current_assessment_status() == "stale" or scan.get("status") == "stale":
        status = "stale"
        error = database.get_setting("latest_scan_error") or "Listener inventory may be out of date."
    elif not scan.get("complete") and scan.get("status") != "incomplete":
        status = "legacy_scope_unknown"
        error = "This legacy listener inventory has no verified scan scope."
    elif not scan.get("complete"):
        status = "incomplete"
        error = "Firewall profile verification failed; run a complete assessment."
    else:
        status = "verified" if listeners else "empty"
        error = None
    return {
        "status": status,
        "error": error,
        "scan_id": scan["id"],
        "listeners": listeners,
    }


def _sync_security_state():
    actual_rules, application_rules, verification_changed = _actual_firewall_state()
    profile_state = _get_firewall_profile_state()
    latest = database.get_latest_complete_scan()
    if latest:
        prior_profiles = latest.get("verification", {}).get("firewall_profiles")
        previous_profile_state = {
            item.get("name"): item.get("enabled")
            for item in (prior_profiles or {}).get("profiles", [])
        }
        current_profile_state = {
            item.get("name"): item.get("enabled")
            for item in profile_state.get("profiles", [])
        }
        profiles_changed = bool(
            profile_state.get("collection_status") == "verified"
            and previous_profile_state
            and previous_profile_state != current_profile_state
        )
        prior_snapshot = sorted(
            repr(item.get("observed_rule"))
            for item in latest.get("firewall_rules", [])
            if item.get("observed_rule")
        )
        current_snapshot = sorted(
            repr(item.get("observed_rule"))
            for item in application_rules
            if item.get("observed_rule")
        )
        if verification_changed or prior_snapshot != current_snapshot or profiles_changed:
            error = (
                "Windows Firewall profiles or rules changed since the latest complete scan; "
                "fresh scanning is required."
            )
            database.mark_latest_scan_stale(error)
            database.record_event(
                "firewall_state_change",
                error,
                {"scan_id": latest["id"]},
            )
        verification = latest.get("verification", {})
        verification["firewall_profiles"] = profile_state
        risk = analyze_risk(
            latest["tcp"],
            latest["udp"],
            actual_rules,
            latest.get("processes", []),
            profile_state,
            database.list_url_scans(20),
        )
        if profile_state.get("collection_status") != "verified":
            error = profile_state.get("error") or "Live firewall profile status is unavailable."
            database.mark_latest_scan_stale(error)
        database.update_scan_security_state(latest["id"], risk, application_rules, verification)
        latest["risk"] = risk
        latest["firewall_rules"] = application_rules
        latest["firewall_profiles"] = profile_state
        latest["verification"] = verification
    return actual_rules, application_rules, latest, profile_state


def _get_firewall_profile_state(force_store=False):
    try:
        state = manager.get_firewall_profiles()
        state["verified_at"] = database.utc_now()
    except (manager.FirewallError, OSError) as exc:
        state = {
            "collection_status": "error",
            "verified_at": None,
            "profiles": [],
            "error": str(exc),
        }
    state["health"] = firewall_profile_health(state)
    previous = database.get_latest_firewall_profile_snapshot()
    should_store = force_store or not previous
    if previous:
        should_store = should_store or (
            previous["collection_status"] != state["collection_status"]
            or previous["profiles"] != state["profiles"]
            or previous["error"] != state["error"]
        )
        try:
            last_saved = datetime.fromisoformat(previous["verified_at"])
            should_store = should_store or (
                datetime.now(timezone.utc) - last_saved
            ).total_seconds() >= 60
        except (TypeError, ValueError):
            should_store = True
    if should_store:
        database.save_firewall_profile_snapshot(
            state["profiles"], state["collection_status"], state["error"]
        )
    return state


def _latest_scope():
    scan = database.get_latest_complete_scan()
    if scan and _valid_scope(scan.get("scope")):
        return scan["scope"]
    return _make_scope(DEFAULT_PORTS)


def _scan_and_save(source, scope):
    if not _valid_scope(scope):
        raise ValueError("A complete loopback TCP/UDP scan scope is required.")
    state = scan_local_ports(
        scope["ports"],
        nmap_path=current_app.config.get("NMAP_PATH"),
        timeout=current_app.config["NMAP_TIMEOUT"],
        service_detection=scope.get("service_detection", False),
        version_timeout=current_app.config["NMAP_VERSION_TIMEOUT"],
    )
    processes = listening_processes()
    actual_rules, application_rules, _ = _actual_firewall_state()
    profile_state = _get_firewall_profile_state()
    risk = analyze_risk(
        state["tcp"],
        state["udp"],
        actual_rules,
        processes,
        profile_state,
        database.list_url_scans(20),
    )
    verification = {
        "nmap_tcp": "verified",
        "nmap_udp": "verified",
        "listener_inventory": "verified",
        "firewall_configuration": "observed",
        "firewall_profiles": profile_state,
        "remote_accessibility": "not_tested",
        "loopback_only": True,
    }
    result = {
        **state,
        "processes": processes,
        "risk": risk,
        "firewall_rules": application_rules,
        "verification": verification,
    }
    scan_id = database.save_scan(
        result,
        source=source,
        status="verified" if profile_state["collection_status"] == "verified" else "incomplete",
        scope=scope,
        complete=profile_state["collection_status"] == "verified",
    )
    database.record_event(
        "scan",
        (
            f"Completed full-scope loopback TCP and UDP assessment ({len(scope['ports'])} ports)."
            if profile_state["collection_status"] == "verified"
            else "Port scan completed, but firewall profile verification failed; assessment is incomplete."
        ),
        {"scan_id": scan_id, "scope": scope, "verification": verification},
    )
    return {
        "id": scan_id,
        "created_at": database.utc_now(),
        "status": "verified" if profile_state["collection_status"] == "verified" else "incomplete",
        "source": source,
        **result,
        "scope": scope,
        "complete": profile_state["collection_status"] == "verified",
    }


def _mark_failed_assessment(error, scan_id=None):
    previous_status = _current_assessment_status()
    previous_error = database.get_setting("latest_scan_error") or ""
    database.mark_latest_scan_stale(error, scan_id=scan_id)
    if previous_status != "stale" or previous_error != str(error)[:500]:
        database.record_event(
            "assessment_error",
            f"Assessment is stale: {error}",
            {"scan_id": scan_id, "error": str(error)[:500]},
        )


def _current_scan_payload():
    latest = database.get_latest_scan()
    if latest and latest.get("status") != "incomplete":
        latest = database.get_latest_complete_scan() or latest
    if not latest:
        return None
    if _current_assessment_status() == "stale":
        latest["status"] = "stale"
        latest["error"] = database.get_setting("latest_scan_error") or latest.get("error")
    elif not latest.get("complete"):
        latest["status"] = "legacy_scope_unknown"
    return latest


def _scan_history():
    history = database.list_scans(100)
    if history and _current_assessment_status() == "stale":
        history[0]["status"] = "stale"
        history[0]["error"] = database.get_setting("latest_scan_error")
    return history


def _validate_scan_request(data):
    if not isinstance(data, dict):
        raise ValueError("The scan request must be a JSON object.")
    ports = data.get("ports", DEFAULT_PORTS)
    if (
        not isinstance(ports, list)
        or not ports
        or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
        or len(ports) > current_app.config["MAX_SCAN_PORTS"]
        or len(set(ports)) != len(ports)
    ):
        raise ValueError("ports must be a non-empty list of at most 100 unique port numbers (1-65535).")
    service_detection = data.get("service_detection", False)
    if type(service_detection) is not bool:
        raise ValueError("service_detection must be a boolean.")
    return _make_scope(ports, service_detection)


def _comparison_payload(latest):
    baseline_id = database.get_setting("baseline_scan_id")
    baseline = database.get_scan(int(baseline_id)) if baseline_id and baseline_id.isdigit() else None
    compatible = bool(
        baseline
        and latest
        and baseline["complete"]
        and latest["complete"]
        and baseline["status"] == "verified"
        and latest["status"] == "verified"
        and _current_assessment_status() == "verified"
        and _scopes_compatible(baseline.get("scope"), latest.get("scope"))
    )
    incompatibility_reason = (
        None if compatible else _comparison_incompatibility_reason(baseline, latest)
    )
    initial_exposed = _exposed(baseline) if baseline else []
    current_exposed = _exposed(latest) if latest else []
    restricted = []
    no_longer_open = []
    if compatible:
        baseline_set = set(initial_exposed)
        current_findings = {
            f"{item['protocol']}/{item['port']}": item
            for item in latest["risk"].get("findings", [])
        }
        restricted = sorted(
            key for key in baseline_set
            if current_findings.get(key, {}).get("firewall_restricted")
        )
        no_longer_open = sorted(baseline_set - set(current_exposed) - set(restricted))
    before_score = baseline["risk"]["score"] if compatible else None
    after_score = latest["risk"]["score"] if compatible else None
    reduction = None
    if compatible:
        reduction = (
            round(100 * (len(initial_exposed) - len(current_exposed)) / len(initial_exposed), 1)
            if initial_exposed
            else 0
        )
    return {
        "compatible": compatible,
        "incompatibility_reason": (
            incompatibility_reason
        ),
        "baseline": baseline,
        "baseline_id": baseline["id"] if baseline else None,
        "baseline_timestamp": baseline["created_at"] if baseline else None,
        "latest": latest,
        "scope": latest.get("scope") if latest else None,
        "baseline_scope": baseline.get("scope") if baseline else None,
        "can_assess_baseline_scope": bool(
            baseline
            and baseline.get("complete")
            and baseline.get("status") == "verified"
            and _valid_scope(baseline.get("scope"))
        ),
        "initially_exposed": initial_exposed,
        "currently_exposed": current_exposed,
        "restricted_ports": restricted if compatible else [],
        "no_longer_observed_open": no_longer_open if compatible else [],
        "service_state_note": "A firewall restriction does not stop a listener; absence from the current scan does not prove a service was stopped.",
        "restricted_since_baseline": restricted if compatible else [],
        "remaining_high_risk": [
            finding
            for finding in (latest or {}).get("risk", {}).get("findings", [])
            if finding["severity"] in {"Critical", "High"} and not finding["firewall_restricted"]
        ],
        "score_improvement": (
            after_score - before_score
            if before_score is not None and after_score is not None
            else None
        ),
        "attack_surface_reduction_percent": reduction,
    }


@api.get("/state")
def state():
    try:
        _, application_rules, latest, firewall_profiles = _sync_security_state()
        current_scan = _current_scan_payload()
        try:
            monitoring = _monitor_snapshot()
            monitoring_error = None
        except (psutil.Error, OSError) as exc:
            monitoring = {}
            monitoring_error = str(exc)
        return jsonify(
            {
                "latest_scan": current_scan,
                "latest_assessment_id": current_scan["id"] if current_scan else None,
                "history": _scan_history(),
                "events": database.list_events(20),
                "firewall_rules": application_rules,
                "process_inventory": _process_inventory_payload(current_scan),
                "comparison": _comparison_payload(latest),
                "monitoring": monitoring,
                "monitoring_error": monitoring_error,
                "port_monitoring": port_monitor_payload(),
                "firewall_profiles": firewall_profiles,
                "url_scans": database.list_url_scans(20),
                "security_notifications": database.list_security_notifications(50),
                "assessment_status": _current_assessment_status(),
                "assessment_error": database.get_setting("latest_scan_error") or "",
                "scope": latest.get("scope") if latest else None,
                "administrator": manager.is_admin(),
                "network_verification": {
                    "local_listener_detection": "Psutil local socket inventory",
                    "firewall_configuration": "Live Windows Firewall configuration only",
                    "remote_accessibility": "Not tested",
                    "scan_target": "127.0.0.1 (loopback only)",
                },
            }
        )
    except (manager.FirewallError, sqlite3.Error, ValueError, OSError) as exc:
        try:
            _mark_failed_assessment(str(exc))
        except sqlite3.Error:
            current_app.logger.exception("Could not persist stale assessment state")
        try:
            latest = _current_scan_payload()
        except (sqlite3.Error, ValueError):
            latest = None
        if latest:
            latest["status"] = "stale"
        return jsonify(
            {
                "error": str(exc),
                "latest_scan": latest,
                "assessment_status": "stale",
                "assessment_error": str(exc),
            }
        ), 503


@api.post("/url-scans")
def scan_url():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("The URL scan request must be a JSON object.")
    try:
        analysis = analyze_url(data.get("url"))
    except URLValidationError as exc:
        return jsonify({"error": str(exc), "destination_type": "INVALID_URL"}), 422
    try:
        scan_id, created_at = database.save_url_scan(data["url"].strip(), analysis)
        database.record_event(
            "url_scan",
            f"URL analysis #{scan_id} completed with {analysis['risk_level']} risk.",
            {
                "scan_id": scan_id,
                "domain": analysis["domain"],
                "risk_score": analysis["risk_score"],
                "risk_level": analysis["risk_level"],
            },
        )
        if analysis["risk_level"] in {"High", "Critical"}:
            database.record_security_notification(
                "medium",
                "URL_HEURISTIC_FINDING",
                f"URL heuristics found indicators in {analysis['domain']}; reputation remains unverified.",
                {
                    "scan_id": scan_id,
                    "domain": analysis["domain"],
                    "destination_type": analysis["destination_type"],
                    "reason": "; ".join(
                        finding["message"] for finding in analysis["findings"]
                    ),
                    "recommendation": analysis["recommended_action"],
                    "reputation_status": analysis["threat_intelligence"]["status"],
                },
                f"url-scan:{scan_id}",
            )
    except sqlite3.Error as exc:
        current_app.logger.exception("Could not save URL analysis")
        return _error(f"Could not save URL analysis: {exc}", 503)
    return jsonify({"id": scan_id, "created_at": created_at, **analysis}), 201


@api.get("/url-scans")
def url_scan_history():
    try:
        return jsonify(database.list_url_scans(100))
    except (sqlite3.Error, ValueError) as exc:
        return _error(f"Could not read URL analysis history: {exc}", 503)


@api.get("/port-monitoring")
def port_monitoring():
    try:
        return jsonify(port_monitor_payload())
    except (sqlite3.Error, ValueError) as exc:
        return _error(f"Could not read port monitoring state: {exc}", 503)


@api.get("/port-monitoring/events")
def port_monitoring_events():
    try:
        return jsonify(database.list_port_activity(200))
    except (sqlite3.Error, ValueError) as exc:
        return _error(f"Could not read port activity history: {exc}", 503)


@api.get("/security-notifications")
def security_notifications():
    severity = request.args.get("severity", "").lower()
    allowed = {"", "critical", "high", "medium", "info"}
    if severity not in allowed:
        return _error("severity must be critical, high, medium, or info.")
    include_dismissed = request.args.get("include_dismissed") == "true"
    try:
        items = database.list_security_notifications(200)
        if severity:
            items = [item for item in items if item["severity"].lower() == severity]
        if not include_dismissed:
            items = [item for item in items if not item["dismissed"]]
        return jsonify(items)
    except (sqlite3.Error, ValueError) as exc:
        return _error(f"Could not read security notifications: {exc}", 503)


@api.post("/security-notifications/<int:notification_id>/dismiss")
def dismiss_notification(notification_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("confirmed") is not True:
        return _error("Explicit confirmation is required to dismiss this notification.", 428)
    try:
        if not database.dismiss_security_notification(notification_id):
            return _error("Security notification was not found.", 404)
        database.record_event(
            "notification_dismissed",
            f"Dismissed security notification #{notification_id}; audit history was retained.",
            {"notification_id": notification_id},
        )
        return jsonify({"dismissed": True, "notification_id": notification_id})
    except sqlite3.Error as exc:
        return _error(f"Could not dismiss security notification: {exc}", 503)


@api.post("/scans")
def start_scan():
    try:
        scope = _validate_scan_request(request.get_json(silent=True))
    except ValueError as exc:
        return _error(str(exc))
    try:
        result = _scan_and_save("manual", scope)
    except (ScanError, manager.FirewallError, OSError, ValueError, psutil.Error, sqlite3.Error) as exc:
        try:
            _mark_failed_assessment(str(exc))
        except sqlite3.Error:
            current_app.logger.exception("Could not persist failed assessment status")
        latest = _current_scan_payload()
        return jsonify(
            {
                "error": str(exc),
                "latest_verified_scan": latest,
                "status": "stale",
                "stage": "scan_or_verification",
            }
        ), 503
    return jsonify(result)


@api.post("/comparison/scan-baseline")
def scan_baseline_scope():
    data = request.get_json(silent=True)
    scan_id = data.get("scan_id") if isinstance(data, dict) else None
    if type(scan_id) is not int or scan_id < 1:
        return _error("scan_id must identify a complete verified baseline.", 422)
    try:
        baseline = database.get_scan(scan_id)
        if (
            not baseline
            or not baseline.get("complete")
            or baseline.get("status") != "verified"
            or not _valid_scope(baseline.get("scope"))
        ):
            return _error("The selected baseline has no complete verified scan scope.", 422)
        result = _scan_and_save("comparison-baseline", baseline["scope"])
    except (ScanError, manager.FirewallError, OSError, ValueError, psutil.Error, sqlite3.Error) as exc:
        try:
            _mark_failed_assessment(str(exc))
        except sqlite3.Error:
            current_app.logger.exception("Could not persist baseline-scope scan failure")
        return jsonify(
            {
                "error": f"Baseline-scope assessment failed; prior results are stale: {exc}",
                "status": "stale",
                "baseline_id": scan_id,
                "latest_verified_scan": _current_scan_payload(),
            }
        ), 503
    return jsonify(
        {
            "baseline_id": scan_id,
            "latest_assessment_id": result["id"],
            "scan": result,
        }
    )


@api.get("/scans")
def scan_history():
    try:
        return jsonify(_scan_history())
    except (sqlite3.Error, ValueError) as exc:
        return _error(f"Could not read scan history: {exc}", 503)


@api.get("/processes")
def processes():
    try:
        return jsonify(_process_inventory_payload(_current_scan_payload()))
    except (sqlite3.Error, ValueError) as exc:
        return _error(f"Could not read the synchronized listener inventory: {exc}", 503)


def _application_owned_rule(rule):
    instance_id = rule.get("instance_id")
    if not instance_id:
        return None
    return next(
        (
            record
            for record in database.list_firewall_rules(active_only=True)
            if record.get("instance_id") == instance_id
            and record.get("rule_name") == rule.get("name")
        ),
        None,
    )


def _duplicate_rule_response(rule, protocol, port):
    record = _application_owned_rule(rule)
    ownership = "application-owned" if record else "external"
    verified = manager.matches_rule(rule, protocol, port)
    message = (
        f"An {ownership} Windows Firewall rule already covers {protocol}/{port}; "
        f"ASRMS did not create or change it."
    )
    if record and not verified:
        message = (
            f"An application-owned rule exists for {protocol}/{port}, but its current "
            "configuration is disabled or mismatched; ASRMS did not create a duplicate."
        )
    return jsonify(
        {
            "error": message,
            "existing_rule": {
                "name": rule.get("name"),
                "instance_id": rule.get("instance_id"),
                "protocol": rule.get("protocol"),
                "port": rule.get("port"),
                "enabled": rule.get("enabled") is True,
                "direction": rule.get("direction"),
                "action": rule.get("action"),
                "ownership": ownership,
                "verified": verified,
            },
            "created": False,
        }
    ), 409


@api.get("/firewall/rules")
def firewall_rules():
    try:
        actual, records, _, _ = _sync_security_state()
        return jsonify(
            {
                "rules": records,
                "actual_inbound_block_rules": actual,
                "administrator": manager.is_admin(),
                "remote_accessibility_tested": False,
            }
        )
    except (manager.FirewallError, sqlite3.Error, ValueError) as exc:
        return _error(f"Could not verify the live firewall configuration: {exc}", 503)


@api.post("/firewall/profiles/<profile_name>")
def change_firewall_profile(profile_name):
    profile = str(profile_name or "").title()
    if profile not in {"Domain", "Private", "Public"}:
        return _error("Profile must be Domain, Private, or Public.")
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or type(data.get("enabled")) is not bool:
        return _error("The request must include a boolean enabled value.")
    if data.get("confirmed") is not True:
        return _error("Explicit confirmation is required before changing a firewall profile.", 428)
    if not manager.is_admin():
        return _error("Administrator privileges are required for firewall changes.", 403)

    with _FIREWALL_PROFILE_LOCK:
        try:
            before = _get_firewall_profile_state()
            if before.get("collection_status") != "verified":
                raise manager.FirewallError(
                    before.get("error") or "Current firewall profile state could not be verified."
                )
            current = next(
                item for item in before["profiles"] if item.get("name") == profile
            )
            enabled = data["enabled"]
            if not enabled and not any(
                item.get("enabled") is True
                for item in before["profiles"]
                if item.get("name") != profile
            ):
                return _error(
                    "This change would disable all Windows Firewall profiles; it is not allowed.",
                    409,
                )
            changed = current["enabled"] is not enabled
            if changed:
                manager.set_firewall_profile(profile, enabled)
            verified = _get_firewall_profile_state(force_store=True)
            observed = next(
                (
                    item for item in verified.get("profiles", [])
                    if item.get("name") == profile
                ),
                None,
            )
            if verified.get("collection_status") != "verified" or not observed or observed.get("enabled") is not enabled:
                raise manager.FirewallError(
                    "The requested profile state was not confirmed by a fresh Windows Firewall query. "
                    "A policy restriction may have prevented the change."
                )
        except (manager.FirewallError, OSError, sqlite3.Error) as exc:
            database.record_event(
                "firewall_profile_change_failed",
                f"Could not verify the requested {profile} Firewall profile change.",
                {"profile": profile, "requested_enabled": data["enabled"], "error": str(exc)},
            )
            message = str(exc)
            if "policy" in message.lower() or "group" in message.lower():
                message += " Windows or organizational policy may control this setting."
            return _error(message, 503)

        message = (
            f"Windows Firewall {profile} profile is verified "
            f"{'enabled' if enabled else 'disabled'}."
        )
        database.record_event(
            "firewall_profile_change",
            message,
            {
                "profile": profile,
                "enabled": enabled,
                "changed": changed,
                "verified_at": verified["verified_at"],
                "administrator": True,
            },
        )
        assessment = None
        assessment_error = None
        try:
            assessment = _scan_and_save("firewall-profile-change", _latest_scope())
        except (ScanError, manager.FirewallError, OSError, ValueError, psutil.Error, sqlite3.Error) as exc:
            assessment_error = str(exc)
            try:
                _mark_failed_assessment(assessment_error)
            except sqlite3.Error:
                current_app.logger.exception("Could not persist failed post-firewall assessment")
        return jsonify(
            {
                "verified": True,
                "changed": changed,
                "profile": observed,
                "firewall_profiles": verified,
                "assessment": assessment,
                "assessment_status": (
                    assessment.get("status", "incomplete") if assessment else "stale"
                ),
                "assessment_error": (
                    assessment_error
                    or (
                        None
                        if assessment and assessment.get("status") == "verified"
                        else "Post-change assessment is incomplete because live firewall profile verification failed."
                    )
                ),
            }
        )


@api.post("/firewall/rules")
def create_firewall_rule():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("The firewall request must be a JSON object.")
    protocol = data.get("protocol")
    port = data.get("port")
    if protocol not in {"TCP", "UDP"} or type(port) is not int or not 1 <= port <= 65535:
        return _error("protocol must be TCP or UDP and port must be an integer from 1 to 65535.")
    if data.get("confirmed") is not True:
        return _error("Explicit confirmation is required before creating a firewall rule.", 428)
    if not manager.is_admin():
        return _error("Administrator privileges are required for firewall changes.", 403)
    try:
        actual_rules, _, _, _ = _sync_security_state()
        existing = next(
            (rule for rule in actual_rules if manager.rule_covers_port(rule, protocol, port)),
            None,
        )
        if existing:
            return _duplicate_rule_response(existing, protocol, port)
        tracked = next(
            (
                record for record in database.list_firewall_rules(active_only=True)
                if record["protocol"] == protocol and record["port"] == port
                and record.get("instance_id")
                and any(
                    rule.get("instance_id") == record["instance_id"]
                    and rule.get("name") == record["rule_name"]
                    for rule in actual_rules
                )
            ),
            None,
        )
        if tracked:
            actual = next(
                rule for rule in actual_rules
                if rule.get("instance_id") == tracked["instance_id"]
                and rule.get("name") == tracked["rule_name"]
            )
            return _duplicate_rule_response(actual, protocol, port)
        scope = _latest_scope()
        created = manager.create_block_rule(protocol, port)
        try:
            database.insert_firewall_rule(
                created["rule_name"],
                created["instance_id"],
                protocol,
                port,
                created["verified"],
            )
            database.record_event(
                "firewall",
                f"Created inbound {protocol} block rule for port {port}; live rule verified.",
                created,
            )
        except sqlite3.Error:
            manager.remove_rule(created["rule_name"], created["instance_id"])
            raise
        result = _scan_and_save("post-remediation", scope)
        saved = next(
            (rule for rule in result["firewall_rules"] if rule.get("instance_id") == created["instance_id"]),
            None,
        )
        if not saved or not saved["verified"]:
            error = "The created firewall rule did not remain verifiable during the complete post-change assessment."
            database.mark_latest_scan_stale(error, scan_id=result["id"])
            raise manager.FirewallError(error)
    except manager.FirewallRuleAlreadyExists as exc:
        return _duplicate_rule_response(exc.rule, protocol, port)
    except (manager.FirewallError, ScanError, OSError, ValueError, sqlite3.Error, psutil.Error) as exc:
        try:
            _mark_failed_assessment(str(exc))
        except sqlite3.Error:
            current_app.logger.exception("Could not persist firewall failure status")
        return _error(
            f"Firewall change was not reported as fully verified; complete assessment failed: {exc}",
            503,
        )
    return jsonify({"rule": created, "scan": result, "verified": True}), 201


@api.delete("/firewall/rules/<int:rule_id>")
def remove_firewall_rule(rule_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("confirmed") is not True:
        return _error("Explicit confirmation is required before removing a firewall rule.", 428)
    if not manager.is_admin():
        return _error("Administrator privileges are required for firewall changes.", 403)
    try:
        record = next(
            (
                item for item in database.list_firewall_rules(active_only=True)
                if item["id"] == rule_id
            ),
            None,
        )
        if record is None or not record.get("instance_id"):
            return _error("No identifiable active application-created firewall rule was found.", 404)
        scope = _latest_scope()
        if not manager.remove_rule(record["rule_name"], record["instance_id"]):
            raise manager.FirewallError("Firewall rule removal could not be verified.")
        database.mark_firewall_rule_removed(record["rule_name"])
        database.record_event(
            "firewall",
            f"Removed application-created firewall rule for port {record['port']}.",
            {"rule_name": record["rule_name"], "instance_id": record["instance_id"]},
        )
        result = _scan_and_save("post-rollback", scope)
        if any(
            item.get("instance_id") == record["instance_id"]
            for item in result["firewall_rules"]
        ):
            error = "The firewall rule remained present after rollback."
            database.mark_latest_scan_stale(error, scan_id=result["id"])
            raise manager.FirewallError(error)
    except (manager.FirewallError, ScanError, OSError, ValueError, sqlite3.Error, psutil.Error) as exc:
        try:
            _mark_failed_assessment(str(exc))
        except sqlite3.Error:
            current_app.logger.exception("Could not persist rollback failure status")
        return _error(f"Rollback was not reported as fully verified: {exc}", 503)
    return jsonify({"removed": True, "scan": result})


@api.get("/comparison")
def comparison():
    try:
        _, _, latest, _ = _sync_security_state()
        return jsonify(_comparison_payload(latest))
    except (manager.FirewallError, sqlite3.Error, ValueError) as exc:
        return _error(f"Comparison is unavailable because live verification failed: {exc}", 503)


@api.post("/comparison/baseline")
def select_baseline():
    data = request.get_json(silent=True)
    scan_id = data.get("scan_id") if isinstance(data, dict) else None
    if type(scan_id) is not int or scan_id < 1:
        return _error("scan_id must identify a complete verified assessment.")
    try:
        selected = database.get_scan(scan_id)
        if not selected or not selected["complete"] or selected["status"] != "verified":
            return _error("Baseline must be selected from a complete verified scan.", 422)
        if not _valid_scope(selected.get("scope")):
            return _error("This legacy assessment has no verified scan scope.", 422)
        database.set_baseline_scan_id(scan_id)
        database.record_event(
            "baseline",
            f"Comparison baseline explicitly changed to scan #{scan_id}.",
            {"scan_id": scan_id, "scope": selected["scope"]},
        )
    except sqlite3.Error as exc:
        return _error(f"Could not save the selected baseline: {exc}", 503)
    return jsonify(
        {
            "baseline_id": selected["id"],
            "baseline_timestamp": selected["created_at"],
            "scope": selected["scope"],
        }
    )


@api.get("/monitoring")
def monitoring():
    try:
        return jsonify(_monitor_snapshot())
    except (psutil.Error, OSError) as exc:
        return _error(f"Could not collect system monitoring data: {exc}", 503)


@api.get("/events")
def events():
    try:
        return jsonify(database.list_events(200))
    except (sqlite3.Error, ValueError) as exc:
        return _error(f"Could not read security events: {exc}", 503)


def _monitor_snapshot():
    memory = psutil.virtual_memory()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": memory.percent,
        "memory_used_mb": round(memory.used / 1024 / 1024),
        "process_count": len(psutil.pids()),
    }


def _exposed(scan):
    if not scan:
        return []
    return sorted(
        f"{item['protocol']}/{item['port']}"
        for item in scan.get("risk", {}).get("findings", [])
        if item.get("protocol") != "FIREWALL" and not item.get("firewall_restricted")
    )
