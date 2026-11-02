import json
import textwrap
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure

from asrms import database
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
    "service_state", "listeners", "recommendation",
]
EVENT_COLUMNS = ["id", "created_at", "category", "message", "details"]


def _report_data():
    actual_rules, application_rules, latest = _sync_security_state()
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
        {"field": "Exposed open ports", "value": risk.get("exposed_ports", "Unavailable")},
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
        pdf.savefig(figure, bbox_inches="tight")


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
            "Audit Events",
            [
                {**event, "details": json.dumps(event.get("details", {}), separators=(",", ":"))}
                for event in data["events"]
            ],
            ["id", "created_at", "category", "message", "details"],
            data["generated_at"],
            stale_notice,
        )
    output.seek(0)
    return output
