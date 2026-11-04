import os

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


FIREWALL_PENALTIES = {1: 15, 2: 30, 3: 45}


def _firewall_penalty(disabled_count):
    setting = os.environ.get(f"ASRMS_FIREWALL_PENALTY_{disabled_count}_PROFILE")
    if setting is None:
        return FIREWALL_PENALTIES[disabled_count]
    try:
        penalty = int(setting)
    except ValueError as exc:
        raise ValueError(
            f"ASRMS_FIREWALL_PENALTY_{disabled_count}_PROFILE must be an integer."
        ) from exc
    if not 0 <= penalty <= 100:
        raise ValueError(
            f"ASRMS_FIREWALL_PENALTY_{disabled_count}_PROFILE must be between 0 and 100."
        )
    return penalty


def firewall_profile_health(firewall_profiles):
    if not isinstance(firewall_profiles, dict) or firewall_profiles.get("collection_status") != "verified":
        state = firewall_profiles if isinstance(firewall_profiles, dict) else {}
        return {
            "status": "Unknown",
            "enabled_count": None,
            "disabled_count": None,
            "profiles": state.get("profiles", []),
            "verified_at": state.get("verified_at"),
            "error": state.get("error") or "Live firewall profile status is unavailable.",
        }
    profiles = firewall_profiles.get("profiles")
    if not isinstance(profiles, list):
        profiles = []
    keyed = {
        str(item.get("name", "")).lower(): item
        for item in profiles
        if isinstance(item, dict)
    }
    if set(keyed) != {"domain", "private", "public"} or any(
        type(item.get("enabled")) is not bool for item in keyed.values()
    ):
        return {
            "status": "Unknown",
            "enabled_count": None,
            "disabled_count": None,
            "profiles": profiles,
            "verified_at": firewall_profiles.get("verified_at"),
            "error": "A complete Domain, Private, and Public profile inventory is required.",
        }
    enabled_count = sum(item["enabled"] for item in keyed.values())
    disabled_count = 3 - enabled_count
    status = {
        0: "Critical",
        1: "High Risk",
        2: "Warning",
        3: "Healthy",
    }[enabled_count]
    return {
        "status": status,
        "enabled_count": enabled_count,
        "disabled_count": disabled_count,
        "profiles": sorted(profiles, key=lambda item: item["name"]),
        "verified_at": firewall_profiles.get("verified_at"),
        "error": None,
    }


def analyze_risk(
    tcp,
    udp,
    firewall_rules,
    processes=None,
    firewall_profiles=None,
    url_scans=None,
):
    listeners = processes or []
    firewall_health = firewall_profile_health(firewall_profiles)
    profile_status_assessed = firewall_profiles is not None
    trust_firewall_rules = (
        not profile_status_assessed or firewall_health["status"] == "Healthy"
    )
    findings = []
    for entry in tcp + udp:
        if entry.get("state") != "open":
            continue
        protocol = entry["protocol"].upper()
        port = int(entry["port"])
        label, severity = RISKY_PORTS.get(port, (entry.get("service", "Unknown service"), "Low"))
        blocked = trust_firewall_rules and any(
            rule_covers_port(rule, protocol, port) for rule in firewall_rules
        )
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
    port_penalty = min(
        100,
        sum(
            SEVERITY_WEIGHT[item["severity"]]
            for item in findings
            if not item["firewall_restricted"]
        ),
    )
    score_deductions = []
    assessment_complete = True
    if profile_status_assessed:
        if firewall_health["status"] == "Unknown":
            assessment_complete = False
            score = None
            score_deductions.extend(
                [
                    {
                        "source": "exposed_ports",
                        "points": port_penalty,
                        "description": "Severity-weighted penalty for observed open ports without a verified matching inbound block rule.",
                    },
                    {
                        "source": "firewall_profiles",
                        "points": None,
                        "description": "Firewall profile penalty is unknown because live profile collection failed.",
                    },
                ]
            )
            findings.append(
                {
                    "protocol": "FIREWALL",
                    "port": "",
                    "service": "Windows Firewall profiles",
                    "severity": "High",
                    "firewall_restricted": False,
                    "service_state": "unknown",
                    "listeners": [],
                    "recommendation": firewall_health["error"]
                    or "Verify the live Windows Firewall profile state.",
                    "source": "firewall_profile_collection",
                }
            )
        else:
            disabled_count = firewall_health["disabled_count"]
            configured_firewall_penalty = (
                _firewall_penalty(disabled_count) if disabled_count else 0
            )
            total_penalty = max(port_penalty, configured_firewall_penalty)
            applied_port_penalty = min(port_penalty, total_penalty)
            applied_firewall_penalty = total_penalty - applied_port_penalty
            if disabled_count:
                severity = {1: "Medium", 2: "High", 3: "Critical"}[disabled_count]
                names = [
                    item["name"]
                    for item in firewall_health["profiles"]
                    if not item["enabled"]
                ]
                findings.append(
                    {
                        "protocol": "FIREWALL",
                        "port": "",
                        "service": "Disabled firewall profiles",
                        "severity": severity,
                        "firewall_restricted": False,
                        "service_state": "disabled",
                        "listeners": [],
                        "recommendation": (
                            "Review and explicitly enable the disabled Windows Firewall profiles "
                            "if appropriate for this system."
                        ),
                        "source": "firewall_profile_health",
                        "profiles": names,
                    }
                )
            score_deductions.append(
                {
                    "source": "exposed_ports",
                    "points": applied_port_penalty,
                    "description": "Severity-weighted penalty for observed open ports without an effective verified inbound block rule.",
                }
            )
            score_deductions.append(
                {
                    "source": "firewall_profiles",
                    "points": applied_firewall_penalty,
                    "configured_points": configured_firewall_penalty,
                    "description": (
                        f"Configured penalty for {disabled_count} disabled Windows Firewall profile(s); "
                        "overlapping points are not counted twice."
                    ),
                }
            )
            score = max(0, 100 - min(100, total_penalty))
    else:
        score_deductions.append(
            {
                "source": "exposed_ports",
                "points": port_penalty,
                "description": "Severity-weighted penalty for observed open ports without a verified matching inbound block rule.",
            }
        )
        score = max(0, 100 - port_penalty)
    exposed = [
        item
        for item in findings
        if item.get("protocol") != "FIREWALL" and not item["firewall_restricted"]
    ]
    port_findings = [item for item in findings if item.get("protocol") != "FIREWALL"]
    url_observations = [
        {
            "scan_id": item.get("id"),
            "created_at": item.get("created_at"),
            "submitted_url": item.get("submitted_url"),
            "normalized_url": item.get("normalized_url"),
            "destination_type": item.get("analysis", {}).get("destination_type", "UNKNOWN"),
            "risk_score": item.get("risk_score"),
            "risk_level": item.get("risk_level"),
            "findings": [
                finding.get("code")
                for finding in item.get("analysis", {}).get("findings", [])
            ],
            "reputation_status": item.get("analysis", {})
            .get("threat_intelligence", {})
            .get("status", "UNVERIFIED"),
        }
        for item in (url_scans or [])
    ]
    return {
        "score": score,
        "assessment_complete": assessment_complete,
        "score_deductions": score_deductions,
        "firewall_health": firewall_health,
        "open_ports": len(port_findings),
        "exposed_ports": len(exposed),
        "critical": sum(item["severity"] == "Critical" and not item["firewall_restricted"] for item in findings),
        "high": sum(item["severity"] == "High" and not item["firewall_restricted"] for item in findings),
        "medium": sum(item["severity"] == "Medium" and not item["firewall_restricted"] for item in findings),
        "low": sum(item["severity"] == "Low" and not item["firewall_restricted"] for item in findings),
        "findings": findings,
        "url_security_observations": {
            "status": "UNVERIFIED" if url_observations else "NO_RECENT_SCANS",
            "deducted_from_host_score": False,
            "reason": (
                "Submitted URL heuristics and unknown reputation are separate from host exposure; "
                "they do not establish that a URL is malicious or that this host is compromised."
            ),
            "scans": url_observations,
        },
        "method": (
            "100 minus the greater of severity-weighted exposed-port penalties or the configurable "
            "disabled-profile penalty (15/30/45 by default), avoiding duplicate scoring of the same "
            "unprotected exposure; unknown live profile status makes the score unavailable. "
            "This prioritization model is not a security guarantee."
        ),
    }
