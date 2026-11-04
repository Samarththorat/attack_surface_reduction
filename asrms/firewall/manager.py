import json
import os
import subprocess
import sys
import threading
import uuid


RULE_PREFIX = "ASRMS-"
_RULE_CREATION_LOCK = threading.Lock()


class FirewallError(RuntimeError):
    pass


class FirewallRuleAlreadyExists(FirewallError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__(
            f"An enabled inbound block rule already covers "
            f"{rule.get('protocol', 'unknown')}/{rule.get('port', 'unknown')}."
        )


def is_admin():
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _powershell(script, environment, timeout=20):
    if sys.platform != "win32":
        raise FirewallError("Windows Defender Firewall management is available only on Windows.")
    env = os.environ.copy()
    env.update(environment)
    script = "$ErrorActionPreference = 'Stop'; " + script
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewallError(f"Windows Firewall command failed: {exc}") from exc
    if result.returncode:
        message = (result.stderr or result.stdout or "unknown Windows Firewall error").strip()
        raise FirewallError(message[:400])
    return result.stdout.strip()


def list_inbound_block_rules(instance_id=None):
    script = (
        "$rules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | "
        "Where-Object { $_.DisplayName -like 'ASRMS-*' -or "
        "($_.Direction -eq 'Inbound' -and $_.Action -eq 'Block') -or "
        "($_.InstanceID -eq $env:ASRMS_INSTANCE_ID -and $env:ASRMS_INSTANCE_ID) }; "
        "$result = foreach ($rule in $rules) { "
        "$filter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop; "
        "$address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop; "
        "[pscustomobject]@{name=$rule.DisplayName; enabled=($rule.Enabled -eq 'True'); "
        "instance_id=[string]$rule.InstanceID; "
        "direction=[string]$rule.Direction; action=[string]$rule.Action; "
        "protocol=[string]$filter.Protocol; port=$filter.LocalPort; "
        "profiles=[string]$rule.Profile; "
        "local_addresses=[string](@($address.LocalAddress) -join ','); "
        "remote_addresses=[string](@($address.RemoteAddress) -join ',')} }; "
        "$result | ConvertTo-Json -Compress -Depth 3"
    )
    environment = {"ASRMS_INSTANCE_ID": instance_id} if instance_id else {}
    output = _powershell(script, environment)
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise FirewallError("Could not parse Windows Firewall rule inventory.") from exc
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def get_firewall_profiles():
    script = (
        "Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | "
        "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | "
        "ConvertTo-Json -Compress"
    )
    output = _powershell(script, {}, timeout=15)
    if not output:
        raise FirewallError("Windows Firewall returned no profile status.")
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise FirewallError("Could not parse Windows Firewall profile status.") from exc
    records = data if isinstance(data, list) else [data]
    profiles = []
    firewall_actions = {0: "NotConfigured", 2: "Allow", 4: "Block"}
    for record in records:
        if not isinstance(record, dict):
            raise FirewallError("Windows Firewall returned an invalid profile record.")
        name = str(record.get("Name", "")).lower()
        if name not in {"domain", "private", "public"}:
            continue
        enabled = record.get("Enabled")
        if isinstance(enabled, str):
            lowered = enabled.lower()
            if lowered in {"true", "1"}:
                enabled = True
            elif lowered in {"false", "0"}:
                enabled = False
        elif type(enabled) is int and enabled in {0, 1}:
            enabled = bool(enabled)
        if not isinstance(enabled, bool):
            raise FirewallError(f"Windows Firewall did not report enabled status for {name}.")
        inbound = record.get("DefaultInboundAction", "Unknown")
        outbound = record.get("DefaultOutboundAction", "Unknown")
        if type(inbound) is int:
            inbound = firewall_actions.get(inbound, "Unknown")
        if type(outbound) is int:
            outbound = firewall_actions.get(outbound, "Unknown")
        profiles.append(
            {
                "name": name.title(),
                "enabled": enabled,
                "default_inbound_action": str(inbound),
                "default_outbound_action": str(outbound),
            }
        )
    if {item["name"].lower() for item in profiles} != {"domain", "private", "public"}:
        raise FirewallError("Windows Firewall did not return all three profile statuses.")
    return {
        "collection_status": "verified",
        "verified_at": None,
        "profiles": sorted(profiles, key=lambda item: item["name"]),
        "error": None,
    }


def _gpo_boolean_value(value):
    if type(value) is bool:
        return "True" if value else "False"
    if isinstance(value, str):
        values = {
            "true": "True",
            "false": "False",
            "notconfigured": "NotConfigured",
        }
        normalized = value.strip().lower()
        if normalized in values:
            return values[normalized]
    raise ValueError("Firewall profile state must be True, False, or NotConfigured.")


def set_firewall_profile(profile_name, enabled):
    profile = str(profile_name or "").title()
    if profile not in {"Domain", "Private", "Public"}:
        raise ValueError("Profile must be Domain, Private, or Public.")
    gpo_boolean = _gpo_boolean_value(enabled)
    script = (
        "Import-Module NetSecurity -ErrorAction Stop; "
        "$enabled = [System.Enum]::Parse("
        "[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean], "
        "$env:ASRMS_ENABLED, $true); "
        "Set-NetFirewallProfile -Profile $env:ASRMS_PROFILE -Enabled $enabled "
        "-ErrorAction Stop"
    )
    _powershell(
        script,
        {"ASRMS_PROFILE": profile, "ASRMS_ENABLED": gpo_boolean},
        timeout=20,
    )
    return get_firewall_profiles()


def list_managed_rules():
    return [
        rule
        for rule in list_inbound_block_rules()
        if str(rule.get("name", "")).startswith(RULE_PREFIX)
    ]


def _rule_exists_by_identity(instance_id):
    script = (
        "$rule = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | "
        "Where-Object { $_.InstanceID -eq $env:ASRMS_INSTANCE_ID }; "
        "$rule | Select-Object -First 1 | "
        "ForEach-Object { [pscustomobject]@{instance_id=[string]$_.InstanceID} } | "
        "ConvertTo-Json -Compress"
    )
    output = _powershell(script, {"ASRMS_INSTANCE_ID": instance_id})
    if not output or output == "null":
        return False
    try:
        data = json.loads(output)
    except json.JSONDecodeError as exc:
        raise FirewallError("Could not verify firewall rule identity.") from exc
    return isinstance(data, dict) and data.get("instance_id") == instance_id


def create_block_rule(protocol, port):
    with _RULE_CREATION_LOCK:
        return _create_block_rule(protocol, port)


def _create_block_rule(protocol, port):
    if protocol not in {"TCP", "UDP"} or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Protocol must be TCP or UDP and port must be between 1 and 65535.")
    existing = next(
        (rule for rule in list_inbound_block_rules() if rule_covers_port(rule, protocol, port)),
        None,
    )
    if existing:
        raise FirewallRuleAlreadyExists(existing)
    name = f"{RULE_PREFIX}{uuid.uuid4().hex}"
    script = (
        "$rule = New-NetFirewallRule -DisplayName $env:ASRMS_RULE_NAME "
        "-Direction Inbound -Action Block -Enabled True -Profile Any "
        "-Protocol $env:ASRMS_PROTOCOL -LocalPort $env:ASRMS_PORT "
        "-ErrorAction Stop; "
        "[pscustomobject]@{instance_id=[string]$rule.InstanceID} | ConvertTo-Json -Compress"
    )
    output = _powershell(
        script,
        {"ASRMS_RULE_NAME": name, "ASRMS_PROTOCOL": protocol, "ASRMS_PORT": str(port)},
    )
    try:
        instance_id = json.loads(output).get("instance_id", "")
    except (json.JSONDecodeError, AttributeError) as exc:
        raise FirewallError("Windows Firewall did not return the new rule identity.") from exc
    rules = [
        rule for rule in list_inbound_block_rules(instance_id)
        if rule.get("name") == name and rule.get("instance_id") == instance_id
    ]
    verified = len(rules) == 1 and matches_rule(rules[0], protocol, port)
    if not verified:
        if instance_id:
            remove_rule(name, instance_id)
        raise FirewallError("Firewall rule creation could not be verified; no successful status was recorded.")
    return {"rule_name": name, "instance_id": instance_id, "verified": True}


def matches_rule(rule, protocol, port):
    observed_protocol = _normalize_protocol(rule.get("protocol"))
    observed_ports = rule.get("port", "")
    if isinstance(observed_ports, list):
        port_matches = len(observed_ports) == 1 and str(observed_ports[0]) == str(port)
    else:
        port_matches = str(observed_ports) == str(port)
    return (
        rule.get("enabled") is True
        and str(rule.get("direction", "")).lower() == "inbound"
        and str(rule.get("action", "")).lower() == "block"
        and observed_protocol == protocol
        and port_matches
        and _all_profiles(rule.get("profiles"))
        and _unrestricted_addresses(rule.get("local_addresses"))
        and _unrestricted_addresses(rule.get("remote_addresses"))
    )


def _tokens(value):
    if isinstance(value, list):
        return [str(item).strip().lower() for item in value]
    return [item.strip().lower() for item in str(value or "").split(",")]


def _all_profiles(value):
    tokens = set(_tokens(value))
    return "any" in tokens or {"domain", "private", "public"}.issubset(tokens)


def _unrestricted_addresses(value):
    tokens = set(_tokens(value))
    return bool(tokens) and tokens.issubset(
        {"any", "*", "0.0.0.0/0", "::/0"}
    )


def rule_covers_port(rule, protocol, port):
    observed_protocol = _normalize_protocol(rule.get("protocol"))
    if observed_protocol in {"256", "ANY"}:
        observed_protocol = "ANY"
    if (
        rule.get("enabled") is not True
        or str(rule.get("direction", "")).lower() != "inbound"
        or str(rule.get("action", "")).lower() != "block"
        or observed_protocol not in {protocol, "ANY"}
        or not _all_profiles(rule.get("profiles"))
        or not _unrestricted_addresses(rule.get("local_addresses"))
        or not _unrestricted_addresses(rule.get("remote_addresses"))
    ):
        return False
    values = rule.get("port", "")
    tokens = values if isinstance(values, list) else str(values).split(",")
    for token in tokens:
        token = str(token).strip()
        if token.lower() == "any" or token == str(port):
            return True
        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) == 2 and all(part.isdigit() for part in parts):
                start, end = map(int, parts)
                if 1 <= start <= end <= 65535 and start <= port <= end:
                    return True
    return False


def _normalize_protocol(protocol):
    protocol = str(protocol or "").upper()
    if protocol == "6":
        return "TCP"
    if protocol == "17":
        return "UDP"
    return protocol


def verify_rule(rule_name, protocol, port, instance_id=None):
    if not rule_name.startswith(RULE_PREFIX):
        raise ValueError("Only application-created firewall rules can be verified.")
    matching = [
        rule for rule in list_inbound_block_rules(instance_id)
        if rule.get("name") == rule_name
        and (not instance_id or rule.get("instance_id") == instance_id)
    ]
    return len(matching) == 1 and matches_rule(matching[0], protocol, port)


def remove_rule(rule_name, instance_id):
    if not rule_name.startswith(RULE_PREFIX) or len(rule_name) > 80:
        raise ValueError("Only application-created firewall rules can be removed.")
    if not instance_id or len(instance_id) > 100:
        raise ValueError("The recorded application rule identity is required for rollback.")
    if not _rule_exists_by_identity(instance_id):
        return True
    _powershell(
        "$matches = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | "
        "Where-Object { $_.InstanceID -eq $env:ASRMS_INSTANCE_ID -and "
        "$_.DisplayName -eq $env:ASRMS_RULE_NAME }); "
        "if ($matches.Count -ne 1) { throw 'Expected exactly one identified ASRMS firewall rule.' }; "
        "$matches | Remove-NetFirewallRule -ErrorAction Stop",
        {
            "ASRMS_INSTANCE_ID": instance_id,
            "ASRMS_RULE_NAME": rule_name,
        },
    )
    return not _rule_exists_by_identity(instance_id)
