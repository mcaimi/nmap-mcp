"""MCP tool implementations for nmap scanning."""

from __future__ import annotations

import json
import os
import platform
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer

from nmap_mcp.command_builder import build_command
from nmap_mcp.executor import execute_nmap
from nmap_mcp.models import PROFILES, ProfileName, ScanProfile, ScanRequest
from nmap_mcp.target_validator import is_private_target, validate_target


def register(mcp: MCPServer) -> None:
    """Register all tools with the MCP server."""

    @mcp.tool(
        description=(
            "Execute an nmap scan against a target using a predefined scan profile. "
            "Returns structured JSON with discovered hosts, ports, services, and OS information. "
            "Available profiles: quick_discovery, standard_scan, comprehensive_scan, "
            "aggressive_recon, stealth_l1-l4, firewall_analysis, sctp_scan, "
            "protocol_discovery, udp_scan, vulnerability_scan, web_application_scan, "
            "infrastructure_discovery, custom_scan."
        ),
    )
    async def nmap_scan(
        target: str,
        profile: str,
        custom_flags: list[str] | None = None,
        zombie_host: str | None = None,
        timeout: int = 600,
    ) -> str:
        """Run an nmap scan with the specified profile against the target.

        Args:
            target: IP address, CIDR range, or hostname to scan.
            profile: Scan profile name (e.g. 'standard_scan', 'quick_discovery').
            custom_flags: Additional nmap flags (validated against allowlist). Required for custom_scan.
            zombie_host: Zombie host:port for idle scan (stealth_l4 only).
            timeout: Scan timeout in seconds (default 600, max 3600).
        """
        try:
            profile_enum = ProfileName(profile)
        except ValueError:
            valid = [p.value for p in ProfileName]
            return json.dumps({"error": f"Unknown profile '{profile}'. Valid: {valid}"})

        try:
            req = ScanRequest(
                target=target,
                profile=profile_enum,
                custom_flags=custom_flags,
                zombie_host=zombie_host,
                timeout=timeout,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})

        valid, msg = validate_target(req.target)
        if not valid:
            return json.dumps({"error": msg})

        if not is_private_target(req.target):
            return json.dumps({
                "warning": (
                    f"Target {req.target} is not a private/localhost address. "
                    "Please confirm you have written authorization to scan this target. "
                    "Re-run with the same parameters after confirming authorization."
                ),
                "authorization_required": True,
                "target": req.target,
            })

        scan_profile = PROFILES[req.profile]
        is_root = os.getuid() == 0

        try:
            cmd = build_command(
                target=req.target,
                profile=scan_profile,
                is_root=is_root,
                custom_flags=req.custom_flags,
                zombie_host=req.zombie_host,
            )
        except (RuntimeError, ValueError) as e:
            return json.dumps({"error": str(e)})

        result = await execute_nmap(cmd, timeout=req.timeout)

        if result.timed_out:
            return json.dumps({
                "error": "Scan timed out",
                "timeout_seconds": req.timeout,
                "stderr": result.stderr,
                "command": " ".join(result.command),
            })

        if result.return_code != 0 and not result.stdout:
            return json.dumps({
                "error": "Scan failed",
                "return_code": result.return_code,
                "stderr": result.stderr,
                "command": " ".join(result.command),
            })

        if scan_profile.discovery_only:
            return json.dumps({
                "raw_output": result.stdout,
                "stderr": result.stderr,
                "return_code": result.return_code,
                "duration_seconds": result.duration_seconds,
                "command": " ".join(result.command),
            })

        try:
            parsed = _parse_root(ET.fromstring(result.stdout))
            parsed["command"] = " ".join(result.command)
            parsed["duration_seconds"] = result.duration_seconds
            if result.stderr:
                parsed["stderr"] = result.stderr
            return json.dumps(parsed, indent=2)
        except ET.ParseError:
            return json.dumps({
                "error": "Failed to parse nmap XML output",
                "raw_output": result.stdout[:2000],
                "stderr": result.stderr,
                "command": " ".join(result.command),
            })

    @mcp.tool(
        description=(
            "Parse nmap XML output into structured JSON. Accepts either a file path "
            "to an nmap XML file or raw XML content."
        ),
    )
    async def parse_nmap_xml(
        xml_source: str,
        source_type: Literal["file", "raw_xml"] = "file",
    ) -> str:
        """Parse nmap XML output into structured JSON.

        Args:
            xml_source: File path to nmap XML output, or raw XML string.
            source_type: 'file' for file path, 'raw_xml' for raw XML content.
        """
        try:
            if source_type == "raw_xml":
                root = ET.fromstring(xml_source)
            else:
                path = Path(xml_source).resolve()
                if not path.exists():
                    return json.dumps({"error": f"File not found: {xml_source}"})
                tree = ET.parse(str(path))
                root = tree.getroot()
            return json.dumps(_parse_root(root), indent=2)
        except ET.ParseError as e:
            return json.dumps({"error": f"Failed to parse XML: {e}"})

    @mcp.tool(
        description="Verify nmap installation, version, and privilege level.",
        annotations={"readOnlyHint": True},
    )
    async def check_prerequisites() -> str:
        """Check if nmap is installed and report system privilege level."""
        import asyncio

        result: dict[str, object] = {
            "nmap_installed": False,
            "nmap_path": None,
            "nmap_version": None,
            "is_root": os.getuid() == 0,
            "uid": os.getuid(),
            "platform": platform.system(),
        }

        nmap_path = shutil.which("nmap")
        if not nmap_path:
            install_map = {
                "Darwin": "brew install nmap",
                "Linux": "sudo apt-get install nmap  # or: sudo dnf install nmap",
            }
            result["install_instructions"] = install_map.get(
                platform.system(), "Install nmap from https://nmap.org"
            )
            return json.dumps(result, indent=2)

        result["nmap_installed"] = True
        result["nmap_path"] = nmap_path

        try:
            proc = await asyncio.create_subprocess_exec(
                nmap_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            version_output = stdout.decode("utf-8", errors="replace")
            for line in version_output.splitlines():
                if "Nmap version" in line or "nmap version" in line.lower():
                    result["nmap_version"] = line.strip()
                    break
            else:
                result["nmap_version"] = version_output.splitlines()[0].strip() if version_output else None
        except OSError:
            result["nmap_version"] = "Unable to determine version"

        return json.dumps(result, indent=2)

    @mcp.tool(
        description="List all available nmap scan profiles with descriptions and privilege requirements.",
        annotations={"readOnlyHint": True},
    )
    async def list_scan_profiles() -> str:
        """Return all available scan profiles."""
        profiles = []
        for p in PROFILES.values():
            profiles.append({
                "name": p.name.value,
                "display_name": p.display_name,
                "description": p.description,
                "requires_root": p.requires_root,
                "has_unprivileged_fallback": p.unprivileged_flags is not None,
            })
        return json.dumps(profiles, indent=2)


# ---------------------------------------------------------------------------
# XML parser (adapted from port-scanner/scripts/parse_nmap_xml.py)
# ---------------------------------------------------------------------------

def _parse_root(root: ET.Element) -> dict:
    """Parse nmap XML from an ElementTree root element."""
    result = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start_time": root.get("startstr", ""),
        "start_timestamp": root.get("start", ""),
        "version": root.get("version", ""),
        "hosts": [],
        "tasks": [],
        "summary": {},
    }

    for task in root.findall("taskbegin"):
        task_entry = {
            "task": task.get("task", ""),
            "time": task.get("time", ""),
            "extrainfo": task.get("extrainfo", ""),
        }
        end = root.find(f"taskend[@task='{task.get('task', '')}']")
        if end is not None:
            task_entry["end_time"] = end.get("time", "")
            task_entry["extrainfo_end"] = end.get("extrainfo", "")
        result["tasks"].append(task_entry)

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        hosts_elem = runstats.find("hosts")
        if finished is not None:
            result["summary"]["end_time"] = finished.get("timestr", "")
            result["summary"]["elapsed"] = finished.get("elapsed", "")
            result["summary"]["exit_status"] = finished.get("exit", "")
        if hosts_elem is not None:
            result["summary"]["hosts_up"] = int(hosts_elem.get("up", 0))
            result["summary"]["hosts_down"] = int(hosts_elem.get("down", 0))
            result["summary"]["hosts_total"] = int(hosts_elem.get("total", 0))

    for host_elem in root.findall("host"):
        result["hosts"].append(_parse_host(host_elem))

    return result


def _parse_host(host_elem: ET.Element) -> dict:
    host: dict = {
        "status": "",
        "addresses": [],
        "hostnames": [],
        "ports": [],
        "os": [],
        "scripts": [],
        "traceroute": [],
        "uptime": None,
        "distance": None,
        "tcp_sequence": None,
        "ip_id_sequence": None,
        "tcp_ts_sequence": None,
    }

    status = host_elem.find("status")
    if status is not None:
        host["status"] = status.get("state", "")
        host["status_reason"] = status.get("reason", "")

    for addr in host_elem.findall("address"):
        host["addresses"].append({
            "addr": addr.get("addr", ""),
            "type": addr.get("addrtype", ""),
            "vendor": addr.get("vendor", ""),
        })

    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            host["hostnames"].append({
                "name": hn.get("name", ""),
                "type": hn.get("type", ""),
            })

    ports = host_elem.find("ports")
    if ports is not None:
        for port in ports.findall("port"):
            host["ports"].append(_parse_port(port))
        for extraports in ports.findall("extraports"):
            host.setdefault("extraports", []).append({
                "state": extraports.get("state", ""),
                "count": int(extraports.get("count", 0)),
            })

    os_elem = host_elem.find("os")
    if os_elem is not None:
        for match in os_elem.findall("osmatch"):
            os_entry: dict = {
                "name": match.get("name", ""),
                "accuracy": match.get("accuracy", ""),
                "classes": [],
            }
            for osclass in match.findall("osclass"):
                cls: dict = {
                    "type": osclass.get("type", ""),
                    "vendor": osclass.get("vendor", ""),
                    "osfamily": osclass.get("osfamily", ""),
                    "osgen": osclass.get("osgen", ""),
                    "accuracy": osclass.get("accuracy", ""),
                    "cpe": [],
                }
                for cpe in osclass.findall("cpe"):
                    if cpe.text:
                        cls["cpe"].append(cpe.text)
                os_entry["classes"].append(cls)
            host["os"].append(os_entry)

    for script in host_elem.findall(".//hostscript/script"):
        host["scripts"].append(_parse_script(script))

    trace = host_elem.find("trace")
    if trace is not None:
        host["traceroute_proto"] = trace.get("proto", "")
        host["traceroute_port"] = trace.get("port", "")
        for hop in trace.findall("hop"):
            host["traceroute"].append({
                "ttl": hop.get("ttl", ""),
                "rtt": hop.get("rtt", ""),
                "ipaddr": hop.get("ipaddr", ""),
                "host": hop.get("host", ""),
            })

    uptime = host_elem.find("uptime")
    if uptime is not None:
        host["uptime"] = {
            "seconds": uptime.get("seconds", ""),
            "lastboot": uptime.get("lastboot", ""),
        }

    distance = host_elem.find("distance")
    if distance is not None:
        host["distance"] = int(distance.get("value", 0))

    tcpseq = host_elem.find("tcpsequence")
    if tcpseq is not None:
        host["tcp_sequence"] = {
            "index": tcpseq.get("index", ""),
            "difficulty": tcpseq.get("difficulty", ""),
            "values": tcpseq.get("values", ""),
        }

    ipidseq = host_elem.find("ipidsequence")
    if ipidseq is not None:
        host["ip_id_sequence"] = {
            "class": ipidseq.get("class", ""),
            "values": ipidseq.get("values", ""),
        }

    tcptsseq = host_elem.find("tcptssequence")
    if tcptsseq is not None:
        host["tcp_ts_sequence"] = {
            "class": tcptsseq.get("class", ""),
            "values": tcptsseq.get("values", ""),
        }

    return host


def _parse_port(port_elem: ET.Element) -> dict:
    port: dict = {
        "protocol": port_elem.get("protocol", ""),
        "portid": port_elem.get("portid", ""),
        "state": "",
        "reason": "",
        "reason_ttl": "",
        "service": "",
        "product": "",
        "version": "",
        "extrainfo": "",
        "tunnel": "",
        "cpe": [],
        "scripts": [],
    }

    state = port_elem.find("state")
    if state is not None:
        port["state"] = state.get("state", "")
        port["reason"] = state.get("reason", "")
        port["reason_ttl"] = state.get("reason_ttl", "")

    service = port_elem.find("service")
    if service is not None:
        port["service"] = service.get("name", "")
        port["product"] = service.get("product", "")
        port["version"] = service.get("version", "")
        port["extrainfo"] = service.get("extrainfo", "")
        port["tunnel"] = service.get("tunnel", "")
        port["method"] = service.get("method", "")
        port["conf"] = service.get("conf", "")
        for cpe in service.findall("cpe"):
            if cpe.text:
                port["cpe"].append(cpe.text)

    for script in port_elem.findall("script"):
        port["scripts"].append(_parse_script(script))

    return port


def _parse_script(script_elem: ET.Element) -> dict:
    entry: dict = {
        "id": script_elem.get("id", ""),
        "output": script_elem.get("output", ""),
    }
    tables = script_elem.findall("table")
    if tables:
        entry["tables"] = [_parse_script_table(t) for t in tables]
    elems = script_elem.findall("elem")
    if elems:
        entry["elements"] = {}
        for elem in elems:
            key = elem.get("key", "")
            if key and elem.text:
                entry["elements"][key] = elem.text
    return entry


def _parse_script_table(table_elem: ET.Element) -> dict:
    result: dict = {"key": table_elem.get("key", "")}
    elems = {}
    for elem in table_elem.findall("elem"):
        key = elem.get("key", "")
        if key and elem.text:
            elems[key] = elem.text
    if elems:
        result["elements"] = elems
    subtables = table_elem.findall("table")
    if subtables:
        result["tables"] = [_parse_script_table(t) for t in subtables]
    return result
