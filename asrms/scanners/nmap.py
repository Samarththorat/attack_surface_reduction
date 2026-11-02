import os
import shutil
import subprocess
import xml.etree.ElementTree as ET


class ScanError(RuntimeError):
    pass


def _nmap_executable(configured_path=None):
    configured_path = configured_path or os.environ.get("NMAP_PATH")
    if configured_path:
        return configured_path
    executable = shutil.which("nmap")
    if executable:
        return executable
    windows_default = r"C:\Program Files (x86)\Nmap\nmap.exe"
    if os.path.isfile(windows_default):
        return windows_default
    raise ScanError("Nmap was not found. Install Nmap or set NMAP_PATH.")


def _parse_xml(xml_text, protocol, requested_ports=None):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError("Nmap returned invalid XML output.") from exc
    if root.tag != "nmaprun":
        raise ScanError("Nmap returned an unexpected XML document.")
    if root.find(".//host/ports") is None:
        raise ScanError(f"Nmap {protocol.upper()} scan returned no port results.")
    if requested_ports is not None:
        scaninfo = root.find(f".//scaninfo[@protocol='{protocol.lower()}']")
        if scaninfo is None:
            raise ScanError(f"Nmap did not confirm the requested {protocol.upper()} scan.")
        scanned_ports = set()
        for token in scaninfo.attrib.get("services", "").split(","):
            token = token.strip()
            if token.isdigit():
                scanned_ports.add(int(token))
            elif "-" in token:
                start_end = token.split("-", 1)
                if len(start_end) == 2 and all(value.isdigit() for value in start_end):
                    start, end = map(int, start_end)
                    if 1 <= start <= end <= 65535:
                        scanned_ports.update(range(start, end + 1))
        if not set(requested_ports).issubset(scanned_ports):
            raise ScanError(
                f"Nmap {protocol.upper()} results did not confirm the complete requested port scope."
            )
    results = []
    for port_node in root.findall(".//port"):
        state = port_node.find("state")
        service_node = port_node.find("service")
        if state is None:
            continue
        method = service_node.attrib.get("method", "table") if service_node is not None else "none"
        try:
            confidence = int(service_node.attrib.get("conf", "0")) if service_node is not None else 0
        except ValueError:
            confidence = 0
        results.append(
            {
                "protocol": port_node.attrib.get("protocol", protocol).upper(),
                "port": int(port_node.attrib["portid"]),
                "state": state.attrib.get("state", "unknown"),
                "reason": state.attrib.get("reason", ""),
                "service": service_node.attrib.get("name", "unknown") if service_node is not None else "unknown",
                "product": service_node.attrib.get("product", "") if service_node is not None else "",
                "version": service_node.attrib.get("version", "") if service_node is not None else "",
                "extra_info": service_node.attrib.get("extrainfo", "") if service_node is not None else "",
                "identification": {
                    "source": (
                        "version-probe" if method == "probed"
                        else "port-database" if method == "table"
                        else "none"
                    ),
                    "method": method,
                    "confidence": confidence,
                    "confidence_label": (
                        "high" if confidence >= 8
                        else "medium" if confidence >= 4
                        else "low" if confidence > 0
                        else "unknown"
                    ),
                    "confirmed_service_probe": method == "probed",
                    "is_port_database_hint": method == "table",
                },
            }
        )
    return results


def scan_local_ports(ports, nmap_path=None, timeout=45, service_detection=False, version_timeout=90):
    if not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("Provide one or more valid TCP/UDP ports.")
    if len(ports) > 100 or len(set(ports)) != len(ports):
        raise ValueError("Select at most 100 unique ports.")
    executable = _nmap_executable(nmap_path)
    port_list = ",".join(str(port) for port in sorted(ports))
    output = {}
    effective_timeout = max(timeout, version_timeout) if service_detection else timeout
    for protocol, flag in (("tcp", "-sT"), ("udp", "-sU")):
        command = [
            executable,
            "-Pn",
            "-n",
            flag,
            "--reason",
            "--max-retries",
            "1",
            "--host-timeout",
            f"{int(effective_timeout)}s",
            "-p",
            port_list,
        ]
        if service_detection:
            command.extend(["-sV", "--version-light", "--version-timeout", "5s"])
        command.extend([
            "-oX",
            "-",
            "127.0.0.1",
        ])
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=effective_timeout + 5,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"Nmap {protocol.upper()} scan exceeded its time limit.") from exc
        except OSError as exc:
            raise ScanError(f"Unable to run Nmap: {exc}") from exc
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "unknown Nmap error").strip()
            raise ScanError(f"Nmap {protocol.upper()} scan failed: {message[:400]}")
        output[protocol] = _parse_xml(completed.stdout, protocol, ports)
    return output
