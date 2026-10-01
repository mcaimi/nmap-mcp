# nmap-mcp

An MCP (Model Context Protocol) server that exposes nmap network scanning capabilities as tools, resources, and prompts. Built with the MCP SDK v2, FastAPI, and UV.

Part of a security-oriented toolset for authorized penetration testing and network reconnaissance.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      FastAPI App                        │
│                                                         │
│  GET /health ──── nmap availability + privilege check   │
│                                                         │
│  /mcp ─────────── MCP Streamable HTTP Transport         │
│    │                                                    │
│    ├── Tools                                            │
│    │   ├── nmap_scan          (run scans)               │
│    │   ├── parse_nmap_xml     (parse XML results)       │
│    │   ├── check_prerequisites (verify nmap install)    │
│    │   └── list_scan_profiles  (list 16 profiles)       │
│    │                                                    │
│    ├── Resources                                        │
│    │   ├── nmap://reference/flags                       │
│    │   ├── nmap://reference/methodologies               │
│    │   ├── nmap://reference/scan-profiles               │
│    │   └── nmap://reference/output-format               │
│    │                                                    │
│    └── Prompts                                          │
│        └── generate_scan_report                         │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                    Core Modules                         │
│                                                         │
│  command_builder.py ── allowlisted flag construction     │
│  target_validator.py ── injection prevention + authz    │
│  executor.py ────────── async subprocess with timeout   │
│  models.py ──────────── scan profiles + request models  │
└─────────────────────────────────────────────────────────┘
```

## Requirements

- Python 3.12+
- [nmap](https://nmap.org) installed and in PATH
- [UV](https://docs.astral.sh/uv/) for project management

## Setup

```bash
# Clone and install
cd nmap-mcp
uv sync

# Install dev dependencies (pytest, ruff, httpx)
uv sync --extra dev
```

## Running the Server

```bash
# Start on default port 8000
uv run nmap-mcp

# Or with custom host/port via uvicorn
uv run uvicorn nmap_mcp.server:app --host 127.0.0.1 --port 9000

# With hot reload during development
uv run uvicorn nmap_mcp.server:app --host 127.0.0.1 --port 8000 --reload
```

### Health Check

```bash
curl http://127.0.0.1:8000/health
```

```json
{
  "status": "ok",
  "nmap_available": true,
  "nmap_path": "/usr/bin/nmap",
  "privileged": false
}
```

## MCP Tools

### `nmap_scan`

Run an nmap scan using a predefined profile.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | string | yes | IP, CIDR, or hostname |
| `profile` | string | yes | Scan profile name (see below) |
| `custom_flags` | list[string] | no | Additional nmap flags (validated against allowlist) |
| `zombie_host` | string | no | Zombie host:port for idle scan (`stealth_l4` only) |
| `timeout` | int | no | Timeout in seconds (default 600, max 3600) |

**Available profiles:**

| Profile | Privileges | Use case |
|---|---|---|
| `quick_discovery` | No | Find live hosts on a network |
| `standard_scan` | Preferred | Default port + service scan |
| `comprehensive_scan` | Yes | Full port range, OS, scripts, traceroute |
| `aggressive_recon` | Yes | Maximum info gathering (`-A`) |
| `stealth_l1` | Yes | Basic IDS evasion (slow timing, fragmentation) |
| `stealth_l2` | Yes | Firewall bypass (NULL scan) |
| `stealth_l3` | Yes | Deep evasion (decoys, MAC spoofing, source port) |
| `stealth_l4` | Yes | Idle scan via zombie host |
| `firewall_analysis` | Yes | Map firewall rules (ACK scan) |
| `sctp_scan` | Yes | Telecom/SIGTRAN infrastructure |
| `protocol_discovery` | Yes | IP protocol enumeration |
| `udp_scan` | Yes | UDP services (DNS, SNMP, NTP) |
| `vulnerability_scan` | Yes | NSE vuln + safe scripts |
| `web_application_scan` | No | HTTP/HTTPS enumeration |
| `infrastructure_discovery` | No | Broadcast/SNMP discovery |
| `custom_scan` | Depends | User-specified flags (requires `custom_flags`) |

### `parse_nmap_xml`

Parse nmap XML output into structured JSON.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `xml_source` | string | yes | File path or raw XML content |
| `source_type` | string | no | `"file"` (default) or `"raw_xml"` |

### `check_prerequisites`

Verify nmap installation, version, and privilege level. No parameters.

### `list_scan_profiles`

List all available scan profiles with descriptions. No parameters.

## MCP Resources

Read-only reference documentation accessible via MCP resource URIs:

| URI | Content |
|---|---|
| `nmap://reference/flags` | Complete nmap flag reference by category |
| `nmap://reference/methodologies` | Multi-phase scanning, scan correlation, tuning |
| `nmap://reference/scan-profiles` | Detailed commands for each scan profile |
| `nmap://reference/output-format` | Report template with risk rating criteria |

## MCP Prompts

### `generate_scan_report`

Generate a structured markdown report from scan results with risk ratings and remediation guidance.

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `scan_results_json` | string | JSON output from `nmap_scan` or `parse_nmap_xml` |

## Connecting an MCP Client

### Claude Desktop / Claude Code

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "nmap": {
      "url": "http://127.0.0.1:8000/mcp"
    }
  }
}
```

### Programmatic Client

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("http://127.0.0.1:8000/mcp") as (r, w, _):
    async with ClientSession(r, w) as session:
        await session.initialize()

        # List available tools
        tools = await session.list_tools()

        # Run a scan
        result = await session.call_tool("nmap_scan", {
            "target": "192.168.1.0/24",
            "profile": "quick_discovery",
        })
```

## Security

This server is designed for **authorized security testing only**.

### Command Injection Prevention

- Nmap commands are built as `list[str]` and executed via `asyncio.create_subprocess_exec` — `shell=True` is never used
- Custom flags are validated against an allowlist of known-safe nmap flags
- Value flags (e.g. `-p`, `--script`) are regex-validated
- Dangerous flags (`-iR`, `-b`, output redirection) are explicitly denied
- Targets are validated to reject shell metacharacters (`;|&$` etc.)

### Target Authorization

- Private/localhost targets (RFC 1918, `127.0.0.0/8`, `::1`) are auto-authorized
- Public targets return an authorization warning — the MCP client must confirm
- Well-known public infrastructure IPs are denied
- Overly large CIDR ranges (>/16 IPv4, >/48 IPv6) are rejected

### Scan Execution

- Configurable timeout (default 10 minutes, max 1 hour)
- Process is killed on timeout
- Non-root execution falls back to unprivileged scan techniques where available (e.g. `-sT` instead of `-sS`)

## Testing

```bash
# Run all tests
uv run pytest tests/ -v

# Run specific test modules
uv run pytest tests/test_command_builder.py -v
uv run pytest tests/test_target_validator.py -v
uv run pytest tests/test_parser.py -v
```

## License

GPL v3
