# ASRMS Runtime Validation and Acceptance Report

**Disposition: Conditionally ready for a local demonstration.** Automated tests and the bounded local browser checks passed. This is not a production security certification or an independent penetration test.

## Acceptance summary

| Area | Result | Evidence and limits |
|---|---|---|
| URL analysis | Pass, local-only | A loopback URL was classified without resolving, fetching, or submitting it to a third party. Reputation remains `UNVERIFIED`; redirect and domain-age checks are not performed. |
| TCP/UDP scanning | Pass, bounded | Nmap completed a seven-port scan against `127.0.0.1` from the browser. The scan does not establish remote reachability. TCP 445 and 5000 were observed open on loopback; their reachability from other interfaces was not tested. |
| Port monitoring | Pass for tested behavior | The suite covers socket lifecycle, process changes, persistence, and collection failures. Final review also added coverage for PID reuse when the PID, process name, and executable path remain the same. |
| Firewall status and safety | Partial | Live Domain, Private, and Public profiles were read-only checked and reported enabled. No firewall profile or rule was changed. A live firewall mutation/rollback was not authorized or tested; automated tests do not replace that check. |
| Risk scoring | Pass for tested behavior | Automated coverage verifies the scoring paths, firewall-profile handling, and separation of URL observations from the host exposure score. Scores are prioritization aids, not security guarantees. |
| Reports | Pass | PDF and Excel downloads were verified in the browser. The PDF response was validated as a non-empty PDF. PDF activity sections are limited to the latest 25 records each; Excel retains broader history. |
| Browser routes and UI | Pass for tested routes | All 11 dashboard routes returned HTTP 200 in the isolated local run, with no browser page errors. Process labels were checked for duplicate PID presentation. |
| Documentation | Pass | The README now documents purpose, architecture, data relationships, limitations, report behavior, and a demonstration checklist. |
| Independent audit | Not completed | No separate third-party or independent security audit was performed. |
| Requested screenshots | Not delivered | Browser interactions were checked, but screenshot files were not captured as submission assets. |

## Verification run

- `.\venv\Scripts\python.exe -m unittest discover -v` — **86 tests passed**.
- Focused regression tests for PID reuse, Nmap service-detection timeout, report responses, and frontend contracts — **8 tests passed**.
- `node --check static\js\app.js` — passed.
- `git diff --check` — passed.
- Browser verification used an isolated SQLite database and loopback-only scan scope; the default application database was not used for the live run.

## Final review fixes

- Process identity comparison now includes process start time, so PID reuse by an identically named executable is detected as a process change.
- Nmap service/version detection now uses the configured `version_timeout` argument rather than a hard-coded five-second value.
- Regression tests were added for both behaviors.

## Safety and remaining work

- Do not infer external exposure from the loopback scan. If exposure validation is required, authorize and perform a separately scoped test from an appropriate network vantage point.
- Review why TCP 445 is listening and confirm the intended SMB/firewall policy; no firewall configuration was altered during this validation.
- External threat-intelligence lookups, redirect following, and domain-age checks are intentionally not performed. The URL scanner reports these as unverified/not checked.
- Complete the requested screenshot package and independent audit before presenting this as a full security sign-off.
- The temporary validation server was stopped after testing. No firewall settings were changed.
