from asrms.firewall.manager import rule_covers_port


RISKY_PORTS = {
    21: ("FTP", "High"),
    23: ("Telnet", "Critical"),
    445: ("SMB", "High"),
    1433: ("Microsoft SQL Server", "High"),
    2375: ("Docker API", "Critical"),
    3306: ("MySQL", "High"),
    3389: ("Remote Desktop", "High"),
    5432: ("PostgreSQL", "High"),
    5900: ("VNC", "High"),
}
SEVERITY_WEIGHT = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}


def analyze_risk(tcp, udp, firewall_rules, processes=None):
    listeners = processes or []
    findings = []
    for entry in tcp + udp:
        if entry.get("state") != "open":
            continue
        protocol = entry["protocol"].upper()
        port = int(entry["port"])
        label, severity = RISKY_PORTS.get(port, (entry.get("service", "Unknown service"), "Low"))
        blocked = any(rule_covers_port(rule, protocol, port) for rule in firewall_rules)
        matching_listeners = [
            {
                "local_address": listener.get("local_address", ""),
                "processes": listener.get("processes", []),
            }
            for listener in listeners
            if listener.get("protocol", "").upper() == protocol
            and int(listener.get("port", 0)) == port
        ]
        findings.append(
            {
                "protocol": protocol,
                "port": port,
                "service": label,
                "severity": severity,
                "firewall_restricted": blocked,
                "service_state": "listening" if matching_listeners else "not_mapped",
                "listeners": matching_listeners,
                "recommendation": (
                    "Confirm the service is required; retain the verified inbound firewall restriction."
                    if blocked
                    else "Confirm this service is needed; restrict inbound access if it is unnecessary."
                ),
            }
        )
    exposed = [item for item in findings if not item["firewall_restricted"]]
    penalty = min(100, sum(SEVERITY_WEIGHT[item["severity"]] for item in exposed))
    return {
        "score": max(0, 100 - penalty),
        "open_ports": len(findings),
        "exposed_ports": len(exposed),
        "critical": sum(item["severity"] == "Critical" and not item["firewall_restricted"] for item in findings),
        "high": sum(item["severity"] == "High" and not item["firewall_restricted"] for item in findings),
        "medium": sum(item["severity"] == "Medium" and not item["firewall_restricted"] for item in findings),
        "low": sum(item["severity"] == "Low" and not item["firewall_restricted"] for item in findings),
        "findings": findings,
        "method": "100 minus severity-weighted unverified-exposure penalties; firewall rules alone do not add points.",
    }
