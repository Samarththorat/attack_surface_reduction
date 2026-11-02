# Sample Local Security Assessment

**Example only — not a scan of your computer.** Create a real report from the
Reports page after running a local scan.

| Metric | Example |
|---|---:|
| Scope | This computer (`127.0.0.1`) |
| TCP ports checked | 22, 80, 443, 445, 3389 |
| UDP ports checked | 22, 80, 443, 445, 3389 |
| Example open service | TCP/8090 — application service |
| Example severity | Low (unknown service; review whether it is needed) |
| Example recommendation | Identify its owner before changing access; if inbound access is unnecessary, create a confirmed firewall restriction and verify it with a fresh scan. |

An open port is an observation, not proof of a vulnerability. A firewall rule
can restrict inbound traffic while the service continues listening. ASRMS
reports those states separately and never stops Windows services.
