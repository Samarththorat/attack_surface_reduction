# Attack Surface Reduction Management System (ASRMS)

A standalone, local-first Windows security dashboard built with Flask. It
combines bounded Nmap port observations, Psutil listener/process inventory,
transparent exposure prioritization, confirmed Windows Firewall rules, and
SQLite-backed scan history and audit events.

The application binds to loopback and rejects non-loopback client and Host
requests. State-changing JSON APIs require a session CSRF token rendered into
the local UI. Keep this application on the local machine; do not expose it
through a public reverse proxy.

## Windows setup and startup

Open PowerShell in this folder. Use the existing `venv`:

```powershell
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

If PowerShell activation is restricted, use the venv interpreter directly:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe app.py
```

Open <http://127.0.0.1:5000/>. Stop the server with Ctrl+C. Nmap must be
installed and available on `PATH`; alternatively, set `NMAP_PATH` in the
process environment to its executable. ASRMS checks the usual Windows Nmap
installation path as well.

For service/version probes, check **Enable Nmap service/version detection
(-sV)** before scanning. Version probing takes longer. Nmap port-database
service names are labeled as hints; the application records probe method and
Nmap confidence separately and does not guarantee identification.

Run as a standard user for read-only scans and dashboard use. Run PowerShell
as Administrator only when you choose to add or remove a Windows Firewall
rule. Every firewall operation asks for confirmation, verifies the exact
application-created inbound block rule, and runs a new TCP and UDP scan.
ASRMS never disables services. Rules created by the app are named with the
`ASRMS-` prefix and can be rolled back from Firewall Manager.

## Scope and safety

Port scans are deliberately restricted to `127.0.0.1` (this computer). The UI
offers a bounded list of individual ports; the API rejects invalid, duplicate,
or oversized lists. TCP uses Nmap connect scans; UDP results can include
`open|filtered`, which means a response was inconclusive and must not be read
as confirmed open. A failed scan retains the last verified assessment and
marks it stale. Each complete assessment records its exact scope, protocols,
and service-detection setting. Firewall changes and rollbacks reuse the
previous complete scope, not just the changed port.

Loopback scanning, Psutil local listener inspection, Windows Firewall
configuration observation, and remote reachability are separate checks.
ASRMS does not run remote accessibility tests; reports explicitly say so.

Listening processes are read through Psutil. Executable path or PID details
may be unavailable without elevated permissions. Firewall restrictions do not
stop a listening service; both observations are displayed separately.
The Processes page, `/api/processes`, and risk findings share the listener
snapshot from the same assessment. An empty successful inventory is reported
separately from stale, unavailable, or failed collection; failed Psutil
collection marks the previous assessment stale instead of showing an empty list.

## Modules

```text
app.py                    Flask entry point
asrms/
  database.py             SQLite schema, history, events, and baseline
  routes/                 Dashboard and centralized JSON/report APIs
  scanners/               Local Nmap probes and Psutil socket inventory
  firewall/               Confirmed, verified Windows firewall operations
  security/               Transparent severity-weighted risk analysis
  reports/                Excel and PDF generation
templates/                Responsive Bootstrap dashboard pages
static/css/               Dark-theme dashboard styles
static/js/                Polling, table rendering, and confirmation UX
tests/                    Automated unittest suite
reports/                  Sample report
instance/                 Created automatically; SQLite database lives here
```

## Dashboard modules

- **Overview:** weighted 0–100 exposure score, statistics, and chart.
- **Network scanner:** TCP/UDP port states and Nmap service observations.
- **Processes & services:** listening socket mapping to PID, process, and path.
- **Risk analysis:** Critical, High, Medium, and Low findings with recommendations.
- **Firewall manager:** create/verify/rollback application-owned restrictions.
- **System monitoring:** CPU, memory, process count, and recent audit events.
- **Before & after:** first successful scan baseline, current exposure, and score delta.
- **Scan history / reports:** stored history, audit events, Excel workbook, and PDF.

All pages poll the centralized `/api/state` endpoint for synchronized data.
The first successful scan establishes the comparison baseline. Later scans
update the current assessment without overwriting that baseline.
Before-and-after comparisons require identical target, protocol, and port
scope. The page shows the exact scope mismatch and can run a new assessment
using the selected verified baseline's recorded scope.

## Risk score

The score begins at 100 and subtracts a transparent penalty for each open,
unrestricted finding: Critical 25, High 15, Medium 8, and Low 3 points, capped
at 100 total penalty. Known higher-risk service ports receive higher severity;
an unknown open service is Low and is not labeled a vulnerability. A matching,
enabled, verified inbound block rule removes the port from exposed findings.
Creating a rule does not independently award points, and the score does not
claim that the underlying service stopped.

This prioritization heuristic is not a vulnerability scanner or guarantee of
security. Confirm service ownership and operational requirements before
restricting access.

## Database and reports

SQLite is initialized automatically at `instance/asrms.sqlite3`. It stores
verified scan results, historical assessments, the first-scan baseline,
application-created firewall rule metadata, and security events. Reports are
generated from locally stored data:

- Excel: port observations, risk findings, and recent audit events.
- PDF: concise latest-assessment summary.
- Sample: [`reports/sample-security-report.md`](reports/sample-security-report.md) (illustrative, not live system data).

Schema upgrades are additive. Before altering an existing database, ASRMS
creates a timestamped SQLite backup in `instance/` and verifies its integrity.
Old assessments without recorded scope are preserved but cannot be treated as
complete or compared to new scans. The initial baseline is never silently
replaced; choose an explicitly verified complete scan on the Before & After
page to reset it. Comparisons are calculated only for matching loopback
target, protocols, and ports.

The Windows Firewall API observes current inbound block rules and verifies
stored application-rule identity, name, enabled state, direction, action,
protocol, and local port. A disabled, deleted, or mismatched rule is marked
unverified; risk scoring uses the live Windows configuration rather than
SQLite verification flags alone. A configured rule is not evidence that
remote traffic was tested or blocked.
Before creating a restriction, ASRMS checks live inbound block rules for an
existing exact or broader matching restriction. Conflicts report whether the
rule has an ASRMS-owned database identity or is external; external rules are
never eligible for rollback.

## Tests

Run from the project root using the existing virtual environment:

```powershell
.\venv\Scripts\python.exe -m unittest discover -v
```

Tests use temporary SQLite databases and mock Nmap/firewall changes; they do
not modify Windows Firewall or scan external systems.
