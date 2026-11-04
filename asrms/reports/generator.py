import json
import textwrap
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure

from asrms import database
from asrms.monitoring.ports import port_monitor_payload
from asrms.routes.api import _current_assessment_status, _scopes_compatible, _sync_security_state


PORT_COLUMNS = [
    "protocol", "port", "state", "reason", "service", "product", "version",
    "extra_info", "identification",
]
PROCESS_COLUMNS = ["protocol", "local_address", "port", "pid", "name", "executable"]
FIREWALL_COLUMNS = [
    "rule_name", "instance_id", "protocol", "port", "enabled", "direction",
    "action", "profiles", "recorded", "verified", "rollback_allowed",
]
FINDING_COLUMNS = [
    "protocol", "port", "service", "severity", "firewall_restricted",
    "service_state", "listeners", "recommendation", "source", "profiles",
]
EVENT_COLUMNS = ["id", "created_at", "category", "message", "details"]
URL_SCAN_COLUMNS = [
    "id", "created_at", "submitted_url", "normalized_url", "domain", "destination_type",
    "risk_score", "risk_level", "risk_components", "reputation_status", "redirect_status",
]
URL_FINDING_COLUMNS = [
    "scan_id", "domain", "risk_score", "risk_level", "code", "severity",
    "points", "message",
]
FIREWALL_PROFILE_COLUMNS = [
    "name", "enabled", "default_inbound_action", "default_outbound_action",
    "collection_status", "verified_at",
]
NOTIFICATION_COLUMNS = ["id", "created_at", "severity", "category", "message", "details", "dismissed"]
PORT_ACTIVITY_COLUMNS = ["id", "created_at", "event_type", "details"]
PORT_LISTENER_COLUMNS = [
    "protocol", "local_address", "port", "pid", "process_name", "executable",
    "process_start_time", "first_detected_at", "last_detected_at", "state",
    "firewall_restriction", "windows_service", "risk_indicators",
]
PDF_RECENT_EVENT_LIMIT = 25


def _report_data():
    actual_rules, application_rules, latest, firewall_profiles = _sync_security_state()
    assessment_status = _current_assessment_status()
    stale = assessment_status == "stale" or (
        latest is not None and latest.get("status") == "stale"
    )
    baseline_id = database.get_setting("baseline_scan_id")
    baseline = database.get_scan(int(baseline_id)) if baseline_id and baseline_id.isdigit() else None
    compatible = bool(
        latest
        and baseline
        and latest["complete"]
        and baseline["complete"]
        and _scopes_compatible(latest.get("scope"), baseline.get("scope"))
        and baseline["status"] == "verified"
        and not stale
    )
    events = database.list_events(500)
    url_scans = database.list_url_scans(500)
    port_monitoring = port_monitor_payload()
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "scan": latest,
        "scan_status": (
            "stale" if stale
            else "verified" if latest and assessment_status == "verified"
            else assessment_status
        ),
        "stale_error": database.get_setting("latest_scan_error") or "",
        "scope": latest.get("scope") if latest else {},
        "actual_firewall_rules": actual_rules,
        "firewall_rules": application_rules,
        "events": events,
        "firewall_profiles": firewall_profiles,
        "url_scans": url_scans,
        "port_monitoring": port_monitoring,
        "port_activity": database.list_port_activity(500),
        "security_notifications": database.list_security_notifications(500),
        "baseline": baseline,
        "baseline_compatible": compatible,
        "generated_at": generated_at,
    }


def _rows_for_scan(scan):
    if not scan:
        return []
    rows = []
    for item in scan["tcp"] + scan["udp"]:
        row = {key: item.get(key, "") for key in PORT_COLUMNS if key != "identification"}
        row["identification"] = json.dumps(item.get("identification", {}), separators=(",", ":"))
        rows.append(row)
    return rows


def _process_rows(scan):
    rows = []
    for listener in (scan or {}).get("processes", []):
        processes = listener.get("processes", [])
        if not processes:
            rows.append(
                {
                    "protocol": listener.get("protocol", ""),
                    "local_address": listener.get("local_address", ""),
                    "port": listener.get("port", ""),
                    "pid": "",
                    "name": "Unavailable",
                    "executable": "Unavailable",
                }
            )
        for process in processes:
            rows.append(
                {
                    "protocol": listener.get("protocol", ""),
                    "local_address": listener.get("local_address", ""),
                    "port": listener.get("port", ""),
                    "pid": process.get("pid", ""),
                    "name": process.get("name", "Unavailable"),
                    "executable": process.get("exe", "Unavailable"),
                }
            )
    return rows


def _firewall_rows(data):
    rows = []
    for rule in data["actual_firewall_rules"]:
        row = {
            "rule_name": rule.get("name", ""),
            "instance_id": rule.get("instance_id", ""),
            "protocol": rule.get("protocol", ""),
            "port": json.dumps(rule.get("port", "")) if isinstance(rule.get("port"), list) else rule.get("port", ""),
            "enabled": rule.get("enabled", False),
            "direction": rule.get("direction", ""),
            "action": rule.get("action", ""),
            "profiles": rule.get("profiles", ""),
            "recorded": False,
            "verified": False,
            "rollback_allowed": False,
        }
        saved = next(
            (item for item in data["firewall_rules"] if item.get("instance_id") == row["instance_id"]),
            None,
        )
        if saved:
            row.update(
                recorded=True,
                verified=saved.get("verified", False),
                rollback_allowed=saved.get("rollback_allowed", False),
            )
        rows.append(row)
    for saved in data["firewall_rules"]:
        if saved.get("recorded") and not any(
            row["instance_id"] == saved.get("instance_id") for row in rows
        ):
            rows.append(
                {
                    "rule_name": saved.get("rule_name", ""),
                    "instance_id": saved.get("instance_id", ""),
                    "protocol": saved.get("protocol", ""),
                    "port": saved.get("port", ""),
                    "enabled": False,
                    "direction": "",
                    "action": "",
                    "profiles": "",
                    "recorded": True,
                    "verified": False,
                    "rollback_allowed": saved.get("rollback_allowed", False),
                }
            )
    return rows


def _summary_rows(data):
    scan = data["scan"]
    baseline = data["baseline"]
    risk = (scan or {}).get("risk", {})
    firewall_health = risk.get("firewall_health") or (
        (data.get("firewall_profiles") or {}).get("health", {})
    )
    latest_url = (data.get("url_scans") or [None])[0]
    port_summary = data.get("port_monitoring", {}).get("summary", {})
    return [
        {"field": "Report generated (UTC)", "value": data["generated_at"]},
        {"field": "Latest complete scan ID", "value": scan["id"] if scan else "Unavailable"},
        {"field": "Scan timestamp", "value": scan["created_at"] if scan else "Unavailable"},
        {"field": "Assessment status", "value": data["scan_status"]},
        {"field": "Assessment error", "value": data["stale_error"]},
        {"field": "Complete assessment", "value": bool(scan and scan["complete"])},
        {"field": "Scan scope", "value": json.dumps(data["scope"], separators=(",", ":"))},
        {"field": "Remote accessibility tested", "value": "No"},
        {"field": "Security score", "value": risk.get("score", "Unavailable")},
        {"field": "Score deductions", "value": json.dumps(risk.get("score_deductions", []), separators=(",", ":"))},
        {"field": "Exposed open ports", "value": risk.get("exposed_ports", "Unavailable")},
        {"field": "Firewall health", "value": firewall_health.get("status", "Unknown")},
        {"field": "Firewall profiles enabled", "value": firewall_health.get("enabled_count", "Unknown")},
        {"field": "Firewall profiles disabled", "value": firewall_health.get("disabled_count", "Unknown")},
        {"field": "Firewall profile verification time", "value": (data.get("firewall_profiles") or {}).get("verified_at", "Unavailable")},
        {"field": "Firewall profile collection status", "value": (data.get("firewall_profiles") or {}).get("collection_status", "Unavailable")},
        {"field": "Active TCP listeners", "value": port_summary.get("tcp_listeners", "Unavailable")},
        {"field": "Relevant UDP sockets", "value": port_summary.get("udp_sockets", "Unavailable")},
        {"field": "Port monitoring status", "value": data.get("port_monitoring", {}).get("status", "Unavailable")},
        {"field": "Latest URL risk", "value": f"{latest_url['risk_level']} ({latest_url['risk_score']}/100)" if latest_url else "Unavailable"},
        {"field": "Latest URL reputation", "value": latest_url["analysis"]["threat_intelligence"]["status"] if latest_url else "Unavailable"},
        {"field": "Baseline scan ID", "value": baseline["id"] if baseline else "Unavailable"},
        {"field": "Baseline timestamp", "value": baseline["created_at"] if baseline else "Unavailable"},
        {"field": "Baseline scope compatible", "value": data["baseline_compatible"]},
    ]


def _write_sheet(writer, records, columns, sheet_name):
    frame = pd.DataFrame(records, columns=columns)
    for column in frame.columns:
        frame[column] = frame[column].map(
            lambda value: (
                "'" + value
                if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r"))
                else value
            )
        )
    frame.to_excel(writer, sheet_name=sheet_name, index=False)
    worksheet = writer.sheets[sheet_name]
    worksheet.freeze_panes = "A2"
    if len(frame.columns):
        worksheet.auto_filter.ref = worksheet.dimensions
    for index, column in enumerate(frame.columns, start=1):
        values = [str(column)] + [str(value) for value in frame[column].head(100)]
        worksheet.column_dimensions[worksheet.cell(row=1, column=index).column_letter].width = min(
            55, max(12, max(len(value) for value in values) + 2)
        )


def excel_report():
    data = _report_data()
    scan = data["scan"]
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        _write_sheet(writer, _summary_rows(data), ["field", "value"], "Assessment")
        _write_sheet(writer, _rows_for_scan(scan), PORT_COLUMNS, "Port Observations")
        _write_sheet(writer, _process_rows(scan), PROCESS_COLUMNS, "Processes")
        _write_sheet(writer, _firewall_rows(data), FIREWALL_COLUMNS, "Firewall Status")
        _write_sheet(
            writer,
            [
                {
                    **item,
                    "collection_status": data["firewall_profiles"].get("collection_status"),
                    "verified_at": data["firewall_profiles"].get("verified_at"),
                }
                for item in data["firewall_profiles"].get("profiles", [])
            ] if data["firewall_profiles"] else [],
            FIREWALL_PROFILE_COLUMNS,
            "Firewall Profiles",
        )
        url_rows = [
            {
                key: item.get(key, "")
                for key in ("id", "created_at", "submitted_url", "normalized_url", "domain", "risk_score", "risk_level")
            }
            | {
                "destination_type": item.get("analysis", {}).get("destination_type", "UNKNOWN"),
                "risk_components": json.dumps(
                    item.get("analysis", {}).get("risk_components", {}),
                    separators=(",", ":"),
                ),
                "reputation_status": item.get("analysis", {}).get("threat_intelligence", {}).get("status", "UNVERIFIED"),
                "redirect_status": item.get("analysis", {}).get("redirect_chain", {}).get("status", "NOT_CHECKED"),
            }
            for item in data["url_scans"]
        ]
        _write_sheet(writer, url_rows, URL_SCAN_COLUMNS, "URL Assessments")
        url_finding_rows = [
            {
                "scan_id": item["id"],
                "domain": item["domain"],
                "risk_score": item["risk_score"],
                "risk_level": item["risk_level"],
                **finding,
            }
            for item in data["url_scans"]
            for finding in item["analysis"].get("findings", [])
        ]
        _write_sheet(writer, url_finding_rows, URL_FINDING_COLUMNS, "URL Findings")
        listeners = (
            data["port_monitoring"].get("listeners", [])
            if data["port_monitoring"].get("status") == "verified"
            else []
        )
        listener_rows = [
            {
                **{
                    key: item.get(key, "")
                    for key in PORT_LISTENER_COLUMNS
                    if key != "risk_indicators"
                },
                "risk_indicators": "; ".join(item.get("risk_indicators", [])),
            }
            for item in listeners
        ]
        _write_sheet(writer, listener_rows, PORT_LISTENER_COLUMNS, "Live Listeners")
        for protocol, sheet_name in (("TCP", "TCP Listeners"), ("UDP", "UDP Sockets")):
            _write_sheet(
                writer,
                [row for row in listener_rows if row["protocol"] == protocol],
                PORT_LISTENER_COLUMNS,
                sheet_name,
            )
        port_activity_rows = [
            {**event, "details": json.dumps(event.get("details", {}), separators=(",", ":"))}
            for event in data["port_activity"]
        ]
        _write_sheet(writer, port_activity_rows, PORT_ACTIVITY_COLUMNS, "Port Activity")
        notification_rows = [
            {
                **item,
                "details": json.dumps(item.get("details", {}), separators=(",", ":")),
            }
            for item in data["security_notifications"]
        ]
        _write_sheet(writer, notification_rows, NOTIFICATION_COLUMNS, "Security Notifications")
        findings = (scan or {}).get("risk", {}).get("findings", [])
        finding_rows = [
            {
                **item,
                "listeners": json.dumps(item.get("listeners", []), separators=(",", ":")),
            }
            for item in findings
        ]
        _write_sheet(writer, finding_rows, FINDING_COLUMNS, "Risk Findings")
        events = [
            {**event, "details": json.dumps(event.get("details", {}), separators=(",", ":"))}
            for event in data["events"]
        ]
        _write_sheet(writer, events, EVENT_COLUMNS, "Audit Events")
        baseline = data["baseline"]
        comparison_rows = [
            {"field": "Baseline scan ID", "value": baseline["id"] if baseline else "Unavailable"},
            {"field": "Baseline timestamp", "value": baseline["created_at"] if baseline else "Unavailable"},
            {"field": "Baseline scope compatible", "value": data["baseline_compatible"]},
        ]
        if data["baseline_compatible"]:
            base_exposed = {
                f"{item['protocol']}/{item['port']}"
                for item in baseline["risk"].get("findings", [])
                if not item.get("firewall_restricted")
            }
            current_findings = {
                f"{item['protocol']}/{item['port']}": item
                for item in scan["risk"].get("findings", [])
            }
            current_exposed = {
                key for key, item in current_findings.items()
                if not item.get("firewall_restricted")
            }
            restricted = sorted(
                key for key in base_exposed
                if current_findings.get(key, {}).get("firewall_restricted")
            )
            no_longer_open = sorted(base_exposed - current_exposed - set(restricted))
            comparison_rows.extend(
                [
                    {"field": "Baseline exposed ports", "value": ", ".join(sorted(base_exposed))},
                    {"field": "Current exposed ports", "value": ", ".join(sorted(current_exposed))},
                    {"field": "Restricted by verified firewall rule", "value": ", ".join(restricted)},
                    {"field": "No longer observed open", "value": ", ".join(no_longer_open)},
                    {
                        "field": "Baseline attack-surface reduction (%)",
                        "value": round(
                            100 * (len(base_exposed) - len(current_exposed)) / max(1, len(base_exposed)),
                            1,
                        ),
                    },
                ]
            )
        _write_sheet(writer, comparison_rows, ["field", "value"], "Before and After")
    output.seek(0)
    return output


def _pdf_table(pdf, title, rows, columns, generated_at, stale_notice=None):
    if not rows:
        rows = [{columns[0]: "No records available"}]
    page_size = 24
    for offset in range(0, len(rows), page_size):
        chunk = rows[offset:offset + page_size]
        figure = Figure(figsize=(11.69, 8.27))
        axis = figure.subplots()
        axis.axis("off")
        heading = title if offset == 0 else f"{title} (continued)"
        figure.suptitle(heading, x=0.07, y=0.96, ha="left", fontsize=16, fontweight="bold")
        figure.text(0.07, 0.91, f"Generated {generated_at} UTC", fontsize=8, color="#526174")
        if stale_notice:
            figure.text(0.07, 0.875, stale_notice, fontsize=9, color="#a43636")
        cell_values = []
        for row in chunk:
            cell_values.append([
                "\n".join(textwrap.wrap(str(row.get(column, "")), 42))[:180]
                for column in columns
            ])
        table = axis.table(
            cellText=cell_values,
            colLabels=columns,
            loc="upper center",
            cellLoc="left",
            colLoc="left",
            bbox=[0.02, 0.04, 0.96, 0.78 if stale_notice else 0.82],
        )
        table.auto_set_font_size(False)
        table.set_fontsize(7)
        table.scale(1, 1.35)
        for (row_index, _), cell in table.get_celld().items():
            if row_index == 0:
                cell.set_facecolor("#14243a")
                cell.get_text().set_color("#ffffff")
                cell.get_text().set_weight("bold")
            elif row_index % 2:
                cell.set_facecolor("#edf2f7")
        pdf.savefig(figure)


def pdf_report():
    data = _report_data()
    scan = data["scan"]
    stale_notice = (
        f"WARNING: assessment status is {data['scan_status']}. {data['stale_error']}".strip()
        if data["scan_status"] != "verified"
        else None
    )
    output = BytesIO()
    with PdfPages(output) as pdf:
        metadata = pdf.infodict()
        metadata["Title"] = "ASRMS Security Assessment"
        metadata["Creator"] = "Attack Surface Reduction Management System"
        metadata["Subject"] = (
            f"Assessment status: {data['scan_status']}; generated {data['generated_at']}. "
            f"{data['stale_error']}"
        )
        summary = _summary_rows(data)
        _pdf_table(pdf, "ASRMS Security Assessment", summary, ["field", "value"], data["generated_at"], stale_notice)
        _pdf_table(
            pdf,
            "TCP and UDP Port Observations",
            _rows_for_scan(scan),
            ["protocol", "port", "state", "service", "product", "version", "extra_info"],
            data["generated_at"],
            stale_notice,
        )
        _pdf_table(
            pdf,
            "Process and Listener Inventory",
            _process_rows(scan),
            PROCESS_COLUMNS,
            data["generated_at"],
            stale_notice,
        )
        _pdf_table(
            pdf,
            "Current Firewall Configuration",
            _firewall_rows(data),
            FIREWALL_COLUMNS,
            data["generated_at"],
            stale_notice,
        )
        _pdf_table(
            pdf,
            "Windows Firewall Profiles",
            [
                {
                    **item,
                    "collection_status": data["firewall_profiles"].get("collection_status"),
                    "verified_at": data["firewall_profiles"].get("verified_at"),
                }
                for item in data["firewall_profiles"].get("profiles", [])
            ] if data["firewall_profiles"] else [],
            FIREWALL_PROFILE_COLUMNS,
            data["generated_at"],
            stale_notice,
        )
        url_rows = [
            {
                "created_at": item["created_at"],
                "domain": item["domain"],
                "destination": item["analysis"].get("destination_type", "UNKNOWN"),
                "risk_components": json.dumps(
                    item["analysis"].get("risk_components", {}),
                    separators=(",", ":"),
                ),
                "risk_score": item["risk_score"],
                "risk_level": item["risk_level"],
                "reputation_status": item["analysis"]["threat_intelligence"]["status"],
                "redirect_status": item["analysis"]["redirect_chain"]["status"],
                "findings": "; ".join(
                    finding["message"] for finding in item["analysis"]["findings"]
                ),
            }
            for item in data["url_scans"]
        ]
        _pdf_table(
            pdf,
            "URL Security Assessments",
            url_rows,
            ["created_at", "domain", "destination", "risk_score", "risk_level", "risk_components", "reputation_status", "redirect_status", "findings"],
            data["generated_at"],
            stale_notice,
        )
        url_finding_rows = [
            {
                "scan_id": item["id"],
                "domain": item["domain"],
                "risk": f"{item['risk_level']} ({item['risk_score']}/100)",
                "code": finding["code"],
                "severity": finding["severity"],
                "points": finding["points"],
                "finding": finding["message"],
            }
            for item in data["url_scans"]
            for finding in item["analysis"].get("findings", [])
        ]
        _pdf_table(
            pdf,
            "URL Security Findings",
            url_finding_rows,
            ["scan_id", "domain", "risk", "code", "severity", "points", "finding"],
            data["generated_at"],
            stale_notice,
        )
        listeners = (
            data["port_monitoring"].get("listeners", [])
            if data["port_monitoring"].get("status") == "verified"
            else []
        )
        _pdf_table(
            pdf,
            "Current TCP Listeners",
            [item for item in listeners if item.get("protocol") == "TCP"],
            PORT_LISTENER_COLUMNS,
            data["generated_at"],
            stale_notice,
        )
        _pdf_table(
            pdf,
            "Current UDP-Bound Sockets",
            [item for item in listeners if item.get("protocol") == "UDP"],
            PORT_LISTENER_COLUMNS,
            data["generated_at"],
            stale_notice,
        )
        _pdf_table(
            pdf,
            f"Current Listeners ({data['port_monitoring'].get('status', 'unavailable')})",
            listeners,
            PORT_LISTENER_COLUMNS,
            data["generated_at"],
            stale_notice,
        )
        _pdf_table(
            pdf,
            f"Recent Continuous Port Activity (up to {PDF_RECENT_EVENT_LIMIT})",
            [
                {**event, "details": json.dumps(event.get("details", {}), separators=(",", ":"))}
                for event in data["port_activity"][:PDF_RECENT_EVENT_LIMIT]
            ],
            PORT_ACTIVITY_COLUMNS,
            data["generated_at"],
            stale_notice,
        )
        _pdf_table(
            pdf,
            f"Recent Security Notifications (up to {PDF_RECENT_EVENT_LIMIT})",
            [
                {
                    **item,
                    "details": json.dumps(item.get("details", {}), separators=(",", ":")),
                }
                for item in data["security_notifications"][:PDF_RECENT_EVENT_LIMIT]
            ],
            NOTIFICATION_COLUMNS,
            data["generated_at"],
            stale_notice,
        )
        _pdf_table(
            pdf,
            "Risk Findings",
            (scan or {}).get("risk", {}).get("findings", []),
            ["protocol", "port", "service", "severity", "firewall_restricted", "service_state", "recommendation"],
            data["generated_at"],
            stale_notice,
        )
        baseline = data["baseline"]
        comparison = [
            {"field": "Baseline ID", "value": baseline["id"] if baseline else "Unavailable"},
            {"field": "Baseline timestamp", "value": baseline["created_at"] if baseline else "Unavailable"},
            {"field": "Scope compatible", "value": data["baseline_compatible"]},
            {
                "field": "Comparison",
                "value": (
                    "Matched assessments" if data["baseline_compatible"]
                    else "Not calculated: complete scan scopes are incompatible or unavailable"
                ),
            },
        ]
        _pdf_table(pdf, "Before and After Comparison", comparison, ["field", "value"], data["generated_at"], stale_notice)
        _pdf_table(
            pdf,
            f"Recent Audit Events (up to {PDF_RECENT_EVENT_LIMIT})",
            [
                {**event, "details": json.dumps(event.get("details", {}), separators=(",", ":"))}
                for event in data["events"][:PDF_RECENT_EVENT_LIMIT]
            ],
            ["id", "created_at", "category", "message", "details"],
            data["generated_at"],
            stale_notice,
        )
    output.seek(0)
    return output
