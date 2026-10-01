"""MCP resource handlers for nmap reference documentation."""

from __future__ import annotations

from importlib.resources import files

from mcp.server import MCPServer


def _read_reference(filename: str) -> str:
    ref = files("nmap_mcp.data.references").joinpath(filename)
    return ref.read_text(encoding="utf-8")


def register(mcp: MCPServer) -> None:
    """Register all resources with the MCP server."""

    @mcp.resource(
        "nmap://reference/flags",
        description="Complete nmap flag reference organized by category: host discovery, scan techniques, port specification, service/version detection, OS detection, NSE scripting, timing, evasion, and output options.",
        mime_type="text/markdown",
    )
    def nmap_flags_reference() -> str:
        return _read_reference("NMAP_REFERENCE.md")

    @mcp.resource(
        "nmap://reference/methodologies",
        description="Advanced scanning strategies: multi-phase scanning, scan correlation (FIN+ACK), performance optimization, scan resumption, and runtime interaction.",
        mime_type="text/markdown",
    )
    def nmap_methodologies() -> str:
        return _read_reference("METHODOLOGIES.md")

    @mcp.resource(
        "nmap://reference/scan-profiles",
        description="Detailed nmap commands and notes for each scan profile: Quick Discovery, Standard, Comprehensive, Aggressive, Stealth L1-L4, Firewall Analysis, SCTP, Protocol Discovery, UDP, Vulnerability, Web Application, Infrastructure Discovery, and Custom.",
        mime_type="text/markdown",
    )
    def nmap_scan_profiles() -> str:
        return _read_reference("SCAN_PROFILES.md")

    @mcp.resource(
        "nmap://reference/output-format",
        description="Port scan report template with risk rating criteria (Critical/High/Medium/Low/Info), key patterns to flag, and structured markdown format for scan results.",
        mime_type="text/markdown",
    )
    def nmap_output_format() -> str:
        return _read_reference("OUTPUT_FORMAT.md")
