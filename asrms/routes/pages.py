from flask import Blueprint, render_template

pages = Blueprint("pages", __name__)


@pages.get("/")
def dashboard():
    return render_template("dashboard.html", active_page="dashboard", title="Overview")


@pages.get("/<page>")
def section(page):
    titles = {
        "scanner": "Network Scanner",
        "processes": "Processes & Services",
        "risks": "Risk Analysis",
        "firewall": "Firewall Manager",
        "monitoring": "System Monitoring",
        "url-scanner": "URL Security Scanner",
        "port-monitoring": "Continuous Port Monitoring",
        "comparison": "Before & After",
        "history": "Scan History",
        "reports": "Reports & Audit",
    }
    if page not in titles:
        return render_template("404.html"), 404
    return render_template("section.html", active_page=page, title=titles[page])
