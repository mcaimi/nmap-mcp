"""MCP prompt templates for report generation."""

from __future__ import annotations

from importlib.resources import files

from mcp.server import MCPServer


def _read_reference(filename: str) -> str:
    ref = files("nmap_mcp.data.references").joinpath(filename)
    return ref.read_text(encoding="utf-8")


def register(mcp: MCPServer) -> None:
    """Register all prompts with the MCP server."""

    @mcp.prompt(
        description=(
            "Generate a structured markdown report from nmap scan results. "
            "Applies risk ratings (Critical/High/Medium/Low/Info) and flags "
            "key security patterns like exposed databases, unencrypted protocols, "
            "and EOL software."
        ),
    )
    def generate_scan_report(scan_results_json: str) -> str:
        """Generate a scan report from JSON results.

        Args:
            scan_results_json: JSON string of parsed nmap scan results.
        """
        output_format = _read_reference("OUTPUT_FORMAT.md")
        return (
            "Analyze the following nmap scan results and generate a structured "
            "markdown report following this template:\n\n"
            f"{output_format}\n\n"
            "## Scan Results (JSON):\n\n"
            f"```json\n{scan_results_json}\n```\n\n"
            "Apply the risk rating criteria from the template. Flag all key "
            "patterns listed in the template. Each recommendation must be "
            "actionable — say what to do, not just what is wrong."
        )
