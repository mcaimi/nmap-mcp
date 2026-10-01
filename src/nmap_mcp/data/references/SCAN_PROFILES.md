# Scan Profiles Reference

Detailed nmap commands, flags, and notes for each scan profile. The agent should load
this file and read only the profile section matching the user's request.

## Quick Discovery

**Purpose**: Fast host discovery with minimal port checking.
**When to use**: "What's on this network?", "Find live hosts", "Quick scan".

```bash
nmap -sn -PE -PS80,443 -PA80,443 -PP -PU40125 --reason <target>
```

Use combined TCP SYN (`-PS`) and TCP ACK (`-PA`) probes together to maximize bypass
chances against both stateful and stateless firewalls. Add `-PU` for UDP probe diversity.

**Notes**:
- ARP scanning is automatic on local LAN segments and is fastest/most reliable. Proxy ARP
  can cause false positives; use `--disable-arp-ping` if this is suspected.
- Add `--traceroute` for network topology mapping when needed.
- On the Internet, `-PE` alone is unreliable — many hosts block ICMP echo. The combined
  probe approach compensates for this.
- For IPv6 targets, add `-6`. ICMP neighbor discovery replaces ARP on IPv6.

## Standard Scan

**Purpose**: Default balanced scan of common ports with service detection.
**When to use**: "Scan this host", "What ports are open?", no specific profile requested.

Privileged (root):
```bash
sudo nmap -sS -sV --version-intensity 5 -T4 --reason --open -oX - <target>
```

Unprivileged (non-root):
```bash
nmap -sT -sV --version-intensity 5 -T4 --reason --open -oX - <target>
```

Note: `-sT` (connect scan) performs a full TCP handshake (2x packets for open ports vs SYN
scan) and the connection is logged by target services in syslog. `-sT` is also required
for IPv6 scanning and when using `--proxies`.

## Comprehensive Scan

**Purpose**: Deep scan with OS detection, scripts, full port range, and traceroute.
**When to use**: "Full scan", "Deep scan", "Comprehensive assessment", "Thorough scan".

```bash
sudo nmap -sS -sU -sV -O --osscan-limit --osscan-guess -sC -p- -T4 \
  --traceroute --reason --open --host-timeout 30m --script-timeout 5m -oX - <target>
```

**Notes**:
- OS detection requires at least one open AND one closed TCP port for accurate
  fingerprinting. `--osscan-limit` skips hosts that don't meet this requirement,
  saving time. `--osscan-guess` provides best-effort matches with confidence percentages.
- `--host-timeout 30m` prevents slow hosts from consuming the majority of scan time.
- `--script-timeout 5m` prevents individual script hangs.
- Full port range UDP (`-sU -p-`) takes 18+ hours on Linux due to ICMP rate limiting.
  Consider a phased approach (see [methodologies](METHODOLOGIES.md#multi-phase-scanning-methodology)).

## Aggressive Recon

**Purpose**: Maximum information gathering on a single host or small group.
**When to use**: "Tell me everything", "Full recon", "Aggressive scan".

```bash
sudo nmap -A -T4 --reason --open -oX - <target>
```

The `-A` flag enables OS detection (`-O`), version detection (`-sV`), default script scan
(`-sC`), and traceroute (`--traceroute`) in one flag. Equivalent to running all of those
individually but more convenient for single-target deep dives.

## Stealth Scan

Stealth scanning is not a single profile but a graduated methodology. Choose the
appropriate level based on the threat model and IDS/IPS sophistication.

### Level 1 — Low Profile (Basic IDS Evasion)

```bash
sudo nmap -sS -T2 -f --data-length 24 --randomize-hosts --reason --open -oX - <target>
```

Slower timing, fragmented packets, random payload padding. Effective against simple
threshold-based IDS.

### Level 2 — Firewall Bypass (Non-Stateful Firewalls)

```bash
sudo nmap -sN -T2 --data-length 24 --randomize-hosts --reason -oX - <target>
```

NULL scan (`-sN`) sends packets with no TCP flags set. Exploits RFC 793: compliant stacks
drop the packet if the port is open, send RST if closed. Bypasses non-stateful firewalls
that only filter SYN packets (e.g., iptables `--syn` rules).

Alternatives: `-sF` (FIN only) or `-sX` (FIN+PSH+URG / Xmas tree).

**Critical limitation**: NULL/FIN/Xmas scans do NOT work against Windows, Cisco IOS,
IBM OS/400, or BSDI — these systems send RST for all ports regardless of state. Check
the target OS first. Results are always `open|filtered` (cannot distinguish).

### Level 3 — Deep Evasion (IDS-Aware)

```bash
sudo nmap -sS -T1 -f -D RND:5,ME -g 53 --scan-delay 5s \
  --data-length 32 --randomize-hosts --spoof-mac 0 --reason --open -oX - <target>
```

- `-T1` (Sneaky): 15-second inter-probe delay defeats threshold-based IDS.
- `-D RND:5,ME`: Five random decoys with your real IP positioned among them. Decoy
  hosts must be alive to avoid SYN-flooding the target. Position `ME` sixth or later
  to hide from detectors like Scanlogd.
- `-g 53`: Spoof source port as DNS (53). Exploits misconfigured firewalls that
  allow all traffic from port 53 (also try 20 for FTP, 88 for Kerberos).
- `--spoof-mac 0`: Random MAC address (only works on same subnet).
- `--scan-delay 5s`: Explicit inter-probe delay to evade rate-based detection.

### Level 4 — Maximum Stealth (Idle Scan)

```bash
sudo nmap -sI <zombie_host>:<probe_port> -Pn --reason -oX - <target>
```

Truly blind scan — no packets are sent from your real IP address. All probing is
performed through a "zombie" host by exploiting predictable IP ID sequences.

**Requirements**:
- Find a suitable zombie: `nmap --script ipidseq -p <port> <candidate_zombie>`
  Look for "Incremental" IP ID sequence class.
- Zombie must be idle (minimal traffic) to maintain predictable IP IDs.
- Must use `-Pn` to skip host discovery (which would expose your real IP).
- Performance: ~15x slower than direct SYN scan.

**Bonus**: Idle scan also reveals IP-based trust relationships — if the target firewall
allows traffic from the zombie's IP but not yours, idle scan will find those ports.

## Firewall Analysis

**Purpose**: Map firewall rules and determine filtering policies before deeper scanning.
**When to use**: "Map the firewall", "What's filtered?", "Firewall rules", pre-scan recon.

```bash
sudo nmap -sA -T4 --reason -oX - <target>
```

ACK scan never finds open ports directly. Instead it classifies ports as `filtered`
(no response or ICMP unreachable) or `unfiltered` (RST received). This reveals which
ports the firewall is actively blocking.

**Advanced — Combine with Window scan for deeper analysis**:

```bash
sudo nmap -sW -T4 --reason -oX - <target>
```

Window scan is identical to ACK scan but examines the TCP window size in RST responses.
Some systems use different window sizes for open vs closed ports, allowing single-scan
differentiation.

**Multi-Scan Correlation** (see [methodologies](METHODOLOGIES.md#multi-scan-correlation)):
1. FIN scan → ports show `open|filtered`
2. ACK scan → ports show `filtered` vs `unfiltered`
3. Correlate: `open|filtered` (FIN) + `unfiltered` (ACK) = **open**

## SCTP Scan

**Purpose**: Scan SCTP ports used in telecom/SS7/SIGTRAN infrastructure.
**When to use**: "Scan SCTP", "Check SIGTRAN", "Telecom infrastructure scan".

```bash
sudo nmap -sY -T4 --reason --open -oX - <target>
```

SCTP INIT scan (`-sY`) is the SCTP equivalent of a TCP SYN scan — half-open, does not
complete the four-way handshake. For more stealth, use COOKIE ECHO scan (`-sZ`), which
cannot distinguish `open` from `filtered` but is less likely to be logged.

## Protocol Discovery

**Purpose**: Determine which IP protocols (not ports) a host supports.
**When to use**: "What protocols does this host support?", "Protocol scan", device profiling.

```bash
sudo nmap -sO --reason -oX - <target>
```

Reveals supported IP protocols (TCP, UDP, ICMP, IGMP, GRE, ESP, etc.). Useful for:
- **Device profiling**: End hosts typically support TCP/UDP/ICMP. Routers add GRE/EGP.
  VPN gateways add ESP/AH (IPsec).
- **Attack surface mapping**: Every supported protocol is a potential vector.
- **Network equipment identification**: Before deeper port scanning.

## UDP Scan

**Purpose**: Scan UDP ports (DNS, SNMP, DHCP, NTP, etc.).
**When to use**: "Scan UDP", "Check UDP services".

```bash
sudo nmap -sU --top-ports 100 -sV --version-intensity 0 -T4 \
  --reason --open -oX - <target>
```

**Performance notes** (UDP scanning is inherently slow):
- Linux kernels rate-limit ICMP port-unreachable to 1/second. A full 65,536-port UDP
  scan takes **18+ hours** per host.
- `--version-intensity 0` drastically reduces scan time (from ~1 hour to ~13 seconds in
  nmap documentation examples) while still sending protocol-specific payloads for common
  services.
- Nmap automatically sends protocol-appropriate payloads for well-known UDP services
  (DNS, SNMP, DHCP, TFTP, NTP) rather than empty packets.

**For full UDP coverage, use a phased approach**:
1. Fast scan: `-sU -F -sV --version-intensity 0` (top 100 ports)
2. Background sweep: `-sU -p- --defeat-icmp-ratelimit --host-timeout 15m`

**Combine with TCP** for comprehensive coverage:
```bash
sudo nmap -sU -sS --top-ports 100 -sV --version-intensity 2 -T4 \
  --reason --open -oX - <target>
```

**Distinguishing open vs filtered** (UDP's hardest problem):
- Add `-sV` — version detection sends service-specific probes that elicit responses.
- Compare traceroute hop counts: fewer hops to `open|filtered` vs `closed` ports
  may indicate the port is actually open (packet reached host but no ICMP response).

## Vulnerability Scan

**Purpose**: Script-based vulnerability assessment on discovered services.
**When to use**: "Check for vulnerabilities", "Vuln scan", "Security assessment".

```bash
sudo nmap -sS -sV -O --script=vuln,safe -T4 --reason --open -oX - <target>
```

**NSE Script Categories**:

| Category | Risk | Description |
|---|---|---|
| `default` / `-sC` | Safe | Useful scripts run by default |
| `safe` | Safe | Unlikely to crash targets |
| `vuln` | Safe | Check for known vulnerabilities |
| `auth` | Low | Authentication-related checks |
| `discovery` | Low | Network/service discovery |
| `broadcast` | Low | LAN broadcast-based discovery |
| `intrusive` | Medium | May crash targets or be detected |
| `brute` | High | Brute-force credential attacks |
| `exploit` | **Dangerous** | Actively exploit vulnerabilities |
| `dos` | **Dangerous** | Denial of service tests |

**Script selection with boolean expressions**:
```bash
--script="(default or safe or vuln) and not http-*"
--script="http-* and not (dos or exploit)"
```

**Authenticated checks** — pass credentials via `--script-args`:
```bash
--script-args 'user=admin,pass=secret'
--script-args-file creds.txt
```

**Warning**: NSE scripts are NOT sandboxed. The `exploit` and `dos` categories can damage
targets. Only use with explicit authorization and understanding of impact.

## Web Application Scan

**Purpose**: HTTP/HTTPS-focused service enumeration and vulnerability checks.
**When to use**: "Scan web services", "Check web apps", "Web security scan".

```bash
nmap -sV -p 80,443,8080,8443 --script="http-* and safe" -T4 \
  --reason --open -oX - <target>
```

**Useful HTTP scripts** (add individually as needed):
- `http-title`: Page titles for quick identification
- `http-headers`: Response headers analysis
- `http-methods`: Allowed HTTP methods (PUT, DELETE, etc.)
- `http-enum`: Common directory/file enumeration
- `http-sql-injection`: Basic SQL injection checks
- `http-csrf`: CSRF vulnerability detection
- `http-robots.txt`: Parse robots.txt for hidden paths

Use the `+` prefix to force a script to run even when the service is not auto-detected:
```bash
--script="+http-title"
```

## Infrastructure Discovery

**Purpose**: Broad network and service discovery using broadcast and SNMP.
**When to use**: "Map the infrastructure", "What devices are on this network?", "Network inventory".

```bash
nmap -sn --script=broadcast,discovery -e <interface> --reason <target>
```

Discovers services via LAN broadcast protocols (mDNS, UPnP, DHCP, NetBIOS, etc.).
Combine with SNMP enumeration for managed devices:

```bash
nmap -sU -p 161 --script=snmp-info,snmp-interfaces,snmp-sysdescr \
  --script-args snmpcommunity=public -T4 --reason --open -oX - <target>
```

## Custom Scan

When the user specifies individual flags or scan types, build the command from the
[nmap reference](NMAP_REFERENCE.md). Always include `--reason --open -oX -`
for parseable output unless the user explicitly requests otherwise.

**Custom TCP flags** (`--scanflags`): Combine arbitrary flags for evasion:
```bash
sudo nmap --scanflags SYNFIN -T4 --reason -oX - <target>
```
SYN/FIN combinations bypass firewalls that only block pure SYN packets. Over half of
OS fingerprints respond to SYN/FIN/URG/PSH combinations. Custom flag scans also evade
IDS that only pattern-match known nmap scan types.
