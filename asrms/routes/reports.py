import sqlite3

from flask import Blueprint, send_file
from asrms.firewall.manager import FirewallError

from asrms.reports.generator import excel_report, pdf_report

reports = Blueprint("reports", __name__)


@reports.get("/excel")
def excel():
    try:
        return send_file(
            excel_report(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name="asrms-security-report.xlsx",
        )
    except (FirewallError, sqlite3.Error, ValueError, OSError) as exc:
        return {"error": f"Report could not verify current firewall/database state: {exc}"}, 503


@reports.get("/pdf")
def pdf():
    try:
        return send_file(
            pdf_report(),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="asrms-security-report.pdf",
        )
    except (FirewallError, sqlite3.Error, ValueError, OSError) as exc:
        return {"error": f"Report could not verify current firewall/database state: {exc}"}, 503