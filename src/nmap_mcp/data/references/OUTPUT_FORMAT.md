# Port Scanner Report Format

Use this template for scan result reports. Adjust sections based on what was actually
scanned (omit OS detection section if `-O` was not used, etc.).

---

## Template

```markdown
# Port Scan Report

| Field | Value |
|---|---|
| **Target** | `<target specification>` |
| **Profile** | <profile name or "Custom"> |
| **Date** | <YYYY-MM-DD HH:MM:SS TZ> |
| **Nmap Version** | <version> |
| **Scan Duration** | <duration> |
| **Command** | `<full nmap command>` |

---

## Host Discovery

| # | Host | Status | Hostname | MAC Address | Vendor |
|---|---|---|---|---|---|
| 1 | 192.168.1.1 | Up | router.local | AA:BB:CC:DD:EE:FF | Cisco |
| 2 | 192.168.1.10 | Up | webserver.local | — | — |

**Summary**: X hosts up, Y hosts down out of Z scanned.

---

## Port Findings

### Host: <IP> (<hostname>)

| Port | State | Service | Version | CPE | Reason | Risk |
|---|---|---|---|---|---|---|
| 22/tcp | open | ssh | OpenSSH 8.9p1 | cpe:/a:openbsd:openssh:8.9p1 | syn-ack | Info |
| 80/tcp | open | http | nginx 1.18.0 | cpe:/a:igor_sysoev:nginx:1.18.0 | syn-ack | Medium |
| 443/tcp | open | https | nginx 1.18.0 | cpe:/a:igor_sysoev:nginx:1.18.0 | syn-ack | Info |
| 3306/tcp | open | mysql | MySQL 8.0.32 | cpe:/a:oracle:mysql:8.0.32 | syn-ack | High |
| 23/tcp | open | telnet | Linux telnetd | — | syn-ack | Critical |

#### Ambiguous Port States

| Port | State | Analysis |
|---|---|---|
| 53/udp | open\|filtered | No response received; DNS may be filtered or accepting silently |
| 161/udp | open\|filtered | SNMP — try `-sV` for confirmation |

<Repeat per host>

---

## OS Detection

| Host | OS Guess | Confidence | Device Type | Vendor | OS Family |
|---|---|---|---|---|---|
| 192.168.1.1 | Cisco IOS 15.x | 95% | Router | Cisco | IOS |
| 192.168.1.10 | Ubuntu 22.04 (Linux 5.15) | 92% | General Purpose | Linux | Linux |

---

## Script Results

### Host: <IP>

#### <script-name>

<script output or finding summary>

**CVE References**: CVE-XXXX-XXXXX (if applicable)

<Repeat per script finding>

---

## Firewall Analysis

| Port Range | State | Firewall Behavior |
|---|---|---|
| 1-79 | filtered | Silently dropped (stateful firewall) |
| 80, 443 | unfiltered | Allowed through firewall |
| 81-442 | filtered | Silently dropped |
| 444-65535 | filtered | ICMP admin-prohibited (explicit deny rule) |

**Assessment**: Stateful firewall with explicit allow rules for HTTP/HTTPS only.
Non-allowed ports return ICMP admin-prohibited, indicating an explicit deny policy
rather than silent drop.

---

## Network Topology

### Traceroute to 192.168.1.10

| Hop | RTT | Host | IP |
|---|---|---|---|
| 1 | 1.2 ms | gateway.local | 10.0.0.1 |
| 2 | 4.5 ms | isp-router.example.com | 203.0.113.1 |
| 3 | 8.1 ms | — | 192.168.1.10 |

**Distance**: 3 hops

---

## Scan Coverage

| Dimension | Coverage |
|---|---|
| **Ports scanned** | TCP 1-65535, UDP top 100 |
| **Protocols** | TCP, UDP |
| **Scan types** | SYN (TCP), UDP |
| **Scripts** | vuln, safe categories |
| **OS detection** | Enabled (2 hosts met open+closed requirement) |
| **Hosts skipped** | 1 host timed out after 30m |
| **Incomplete** | Full UDP range not scanned (rate-limited) |

---

## Risk Summary

| Rating | Count | Details |
|---|---|---|
| Critical | 1 | Telnet (23/tcp) on 192.168.1.10 |
| High | 1 | MySQL (3306/tcp) exposed on 192.168.1.10 |
| Medium | 1 | HTTP without redirect to HTTPS on 192.168.1.10 |
| Low | 0 | — |
| Info | 2 | SSH, HTTPS properly configured |

---

## Recommendations

1. **[Critical] Disable Telnet on 192.168.1.10**: Replace with SSH. Telnet transmits
   credentials in cleartext.
2. **[High] Restrict MySQL access on 192.168.1.10**: Bind to localhost or use firewall
   rules to limit access to application servers only.
3. **[Medium] Enable HTTP to HTTPS redirect on 192.168.1.10**: Configure nginx to
   redirect all HTTP traffic to HTTPS.
```

---

## Report Sections

Include the following sections, adjusted based on what was actually scanned (omit OS
detection section if `-O` was not used, etc.):

1. **Scan Summary**: Target, profile, timestamp, nmap version, scan duration
2. **Host Discovery**: Hosts up/down, hostnames, MAC addresses
3. **Port Findings**: Per-host table of open ports, services, versions, CPE identifiers
4. **Ambiguous States**: Ports in `open|filtered` or `closed|filtered` states with analysis
5. **OS Detection**: Identified operating systems with confidence, device type, vendor
6. **Firewall Analysis**: Filtered vs unfiltered ports, stateful/stateless determination
7. **Network Topology**: Traceroute results, hop counts, network path analysis
8. **Script Results**: Any script findings with CVE references
9. **Scan Coverage**: What was scanned (ports, protocols, phases) and what was not
10. **Risk Assessment**: Severity ratings for findings
11. **Recommendations**: Actionable remediation steps

---

## Key Patterns to Flag

- Unencrypted protocols where encrypted alternatives exist (HTTP vs HTTPS, Telnet vs SSH, FTP vs SFTP)
- Database ports exposed to non-private networks (3306, 5432, 27017, 6379)
- Administrative interfaces exposed (management consoles, debug ports)
- End-of-life software versions with known CVEs
- Default or commonly-exploited services (SMB, RDP with weak config)
- Services running on non-standard ports (possible evasion attempt or misconfiguration)
- SCTP services on telecom infrastructure (SS7/SIGTRAN exposure)
- Supported IP protocols beyond TCP/UDP/ICMP on endpoints (unexpected GRE, ESP, etc.)
- Weak TCP sequence prediction (enables IP spoofing attacks)
- Missing or misconfigured firewall rules (ports unfiltered that should be filtered)

---

## Risk Rating Criteria

Apply these ratings consistently across all reports.

### Critical

- Known exploitable vulnerability with public exploit
- Default or no credentials on administrative service
- Unauthenticated remote code execution
- Unencrypted remote access protocols (telnet, rlogin, rsh)

### High

- Dangerous service directly exposed (database, message queue, cache)
- Known CVE on detected service version
- Administrative interface exposed without access controls
- Weak or deprecated encryption (SSLv3, TLS 1.0)

### Medium

- Unnecessary service exposed to network
- Outdated software version (no known exploit but unsupported)
- Missing security headers or redirects
- Non-standard port usage suggesting shadow IT

### Low

- Minor information disclosure (server version banners)
- Services with adequate security but room for hardening
- Missing best practices that don't directly enable attack

### Info

- Expected services properly configured
- Observations with no security implication
- Network topology notes

---

## Notes on Report Generation

- Always include the exact nmap command used for reproducibility
- Include scan duration so the user can plan future scans
- When a service version matches a known CVE, reference it explicitly
- Group recommendations by severity, most critical first
- Each recommendation should be actionable: say what to do, not just what's wrong
- If the scan was partial (timeouts, unreachable hosts), note what was missed
- Include CPE identifiers when available for automated vulnerability cross-referencing
- Report ambiguous port states (`open|filtered`, `closed|filtered`) with analysis of
  what caused the ambiguity and suggestions for resolving it (e.g., use `-sV` for UDP)
- Include firewall analysis section when ACK/Window scan data is available, or when
  filtered port patterns suggest specific firewall configurations
- Include network topology section when traceroute data is available
- Include scan coverage section documenting what was and wasn't scanned, including ports,
  protocols, scan types, and any hosts or ranges that timed out or were skipped
- Flag TCP sequence predictability findings as a spoofing risk in the risk summary
- Note IP ID sequence class when incremental (zombie candidate for idle scans)
