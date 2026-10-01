# Nmap Complete Flag Reference

Comprehensive reference for all nmap options organized by category.
Source: nmap.org documentation.

## Host Discovery

### Discovery Controls

| Flag | Name | Description |
|---|---|---|
| `-sL` | List Scan | Lists hosts without sending packets; performs reverse DNS |
| `-sn` | No Port Scan | Ping scan only, no port scanning |
| `-Pn` | No Ping | Skip host discovery, scan every target |

### TCP Probes

| Flag | Name | Default Port | Description |
|---|---|---|---|
| `-PS<ports>` | TCP SYN Ping | 80 | Sends SYN; RST or SYN/ACK = host up |
| `-PA<ports>` | TCP ACK Ping | 80 | Sends ACK; RST = host up. Bypasses stateless firewalls |

### UDP/SCTP Probes

| Flag | Name | Default Port | Description |
|---|---|---|---|
| `-PU<ports>` | UDP Ping | 40125 | ICMP port unreachable = host up. Bypasses TCP-only filters |
| `-PY<ports>` | SCTP INIT Ping | 80 | Sends SCTP INIT chunk |

### ICMP Probes

| Flag | Name | Description |
|---|---|---|
| `-PE` | Echo Request | ICMP type 8; standard ping |
| `-PP` | Timestamp | ICMP code 13; bypasses echo-only blocking |
| `-PM` | Address Mask | ICMP code 17 |

### Other Discovery

| Flag | Name | Description |
|---|---|---|
| `-PO<protocols>` | IP Protocol Ping | Default: ICMP(1), IGMP(2), IP-in-IP(4) |
| `-PR` | ARP Scan | Raw ARP; default for LAN hosts, fastest and most accurate |
| `--disable-arp-ping` | Disable ARP | Force IP-based discovery even on LAN |
| `--discovery-ignore-rst` | Ignore RST | Ignore spoofed RST packets during discovery |
| `--traceroute` | Traceroute | Post-scan traceroute using reverse TTL |

### DNS Resolution

| Flag | Description |
|---|---|
| `-n` | Never do DNS resolution |
| `-R` | Always resolve (default: only for online hosts) |
| `--resolve-all` | Resolve all IPs for multi-address hosts |
| `--system-dns` | Use OS DNS resolver instead of nmap's |
| `--dns-servers <srv1,srv2,...>` | Custom DNS servers |

### Default Privileged Discovery: `-PE -PS443 -PA80 -PP`
### Default Unprivileged Discovery: `-PS80,443`

---

## Port Scanning Techniques

### TCP Scans

| Flag | Name | Root | Description |
|---|---|---|---|
| `-sS` | SYN Scan | Yes | Half-open; fast, stealthy. Default when privileged |
| `-sT` | Connect Scan | No | Full TCP connect(). Default when unprivileged |
| `-sN` | NULL Scan | Yes | No flags set. Exploits RFC 793 loophole |
| `-sF` | FIN Scan | Yes | FIN flag only. Same RFC 793 loophole |
| `-sX` | Xmas Scan | Yes | FIN+PSH+URG flags. Same loophole |
| `-sA` | ACK Scan | Yes | Maps firewall rules; never finds open ports directly |
| `-sW` | Window Scan | Yes | Like ACK but checks TCP window in RST |
| `-sM` | Maimon Scan | Yes | FIN/ACK probe; some BSD systems drop if open |
| `--scanflags <flags>` | Custom Scan | Yes | Arbitrary TCP flags (URG,ACK,PSH,RST,SYN,FIN or numeric) |

### UDP Scan

| Flag | Name | Root | Description |
|---|---|---|---|
| `-sU` | UDP Scan | Yes | Slow due to ICMP rate limiting. Combinable with TCP scans |

### SCTP Scans

| Flag | Name | Root | Description |
|---|---|---|---|
| `-sY` | SCTP INIT | Yes | Half-open SCTP; like SYN scan for SCTP |
| `-sZ` | SCTP COOKIE ECHO | Yes | More stealthy; can't distinguish open vs filtered |

### Special Scans

| Flag | Name | Root | Description |
|---|---|---|---|
| `-sI <zombie>[:port]` | Idle Scan | Yes | Truly blind scan via zombie host |
| `-sO` | IP Protocol Scan | Yes | Determines supported IP protocols (not ports) |
| `-b <FTP host>` | FTP Bounce | No | Scans via FTP proxy connection |

### Port States

| State | Meaning |
|---|---|
| `open` | Application actively listening |
| `closed` | Accessible but no listener |
| `filtered` | Packet filtering prevents probes |
| `unfiltered` | Accessible but open/closed unknown (ACK scan) |
| `open\|filtered` | Cannot determine if open or filtered |
| `closed\|filtered` | Cannot determine if closed or filtered (idle scan) |

---

## Port Specification

| Flag | Description |
|---|---|
| `-p <ranges>` | Scan specific ports: `-p22`, `-p1-65535`, `-p-` (all), `-p U:53,T:80` |
| `--exclude-ports <ranges>` | Exclude ports from all scan types |
| `-F` | Fast: 100 most common ports (vs default 1000) |
| `--top-ports <n>` | Scan n highest-frequency ports |
| `--port-ratio <ratio>` | Scan ports above frequency ratio (0.0-1.0) |
| `-r` | Sequential port order (default is randomized) |

---

## Service and Version Detection

| Flag | Description |
|---|---|
| `-sV` | Enable version detection |
| `--allports` | Don't skip any ports |
| `--version-intensity <0-9>` | Probe intensity (default 7) |
| `--version-light` | Alias for `--version-intensity 2` |
| `--version-all` | Alias for `--version-intensity 9` |
| `--version-trace` | Debug version scanning |

---

## OS Detection

| Flag | Description |
|---|---|
| `-O` | Enable OS detection (requires root) |
| `--osscan-limit` | Only attempt on hosts with open+closed TCP ports |
| `--osscan-guess` | Guess aggressively with confidence percentages |
| `--fuzzy` | Alias for `--osscan-guess` |
| `--max-os-tries <n>` | Max OS detection attempts (default ~5) |

---

## Scripting Engine (NSE)

| Flag | Description |
|---|---|
| `-sC` | Default script scan (equivalent to `--script=default`) |
| `--script <spec>` | Run scripts by name, category, directory, or boolean expression |
| `--script-args <args>` | Pass key=value arguments to scripts |
| `--script-args-file <file>` | Load script arguments from file |
| `--script-help <spec>` | Show help for matching scripts |
| `--script-trace` | Show all script communication |
| `--script-updatedb` | Update script database |

### Useful Script Categories

| Category | Description |
|---|---|
| `default` (`-sC`) | Safe, useful scripts run by default |
| `safe` | Scripts unlikely to crash targets |
| `vuln` | Check for known vulnerabilities |
| `exploit` | Actively exploit vulnerabilities |
| `auth` | Authentication-related checks |
| `brute` | Brute-force credential attacks |
| `discovery` | Network/service discovery |
| `intrusive` | May crash targets or be detected |

---

## Timing and Performance

### Templates

| Flag | Name | Description |
|---|---|---|
| `-T0` | Paranoid | Serial, 5 min between probes. IDS evasion |
| `-T1` | Sneaky | 15 sec between probes. IDS evasion |
| `-T2` | Polite | 0.4 sec between probes. Reduced bandwidth |
| `-T3` | Normal | Default. Parallel scanning |
| `-T4` | Aggressive | Fast network assumed |
| `-T5` | Insane | Very fast. May miss results |

### Fine-Grained Controls

| Flag | Description |
|---|---|
| `--min-hostgroup <n>` / `--max-hostgroup <n>` | Parallel host group size |
| `--min-parallelism <n>` / `--max-parallelism <n>` | Outstanding probes per group |
| `--min-rtt-timeout <t>` / `--max-rtt-timeout <t>` | Probe round-trip timeout |
| `--initial-rtt-timeout <t>` | Initial probe timeout |
| `--max-retries <n>` | Max retransmissions per port (default 10) |
| `--host-timeout <t>` | Give up on host after time (e.g. `30m`) |
| `--script-timeout <t>` | Max script execution time |
| `--scan-delay <t>` / `--max-scan-delay <t>` | Wait between probes |
| `--min-rate <n>` / `--max-rate <n>` | Packets per second floor/ceiling |
| `--defeat-rst-ratelimit` | Ignore RST rate limits (less accurate) |
| `--defeat-icmp-ratelimit` | Ignore ICMP rate limits for UDP scans |

---

## Firewall/IDS Evasion

| Flag | Description |
|---|---|
| `-f` | Fragment packets (8-byte fragments; use `-f -f` for 16) |
| `--mtu <val>` | Custom MTU (must be multiple of 8) |
| `-D <decoy1,decoy2,...>` | Decoy scan; `ME` = your position, `RND` = random |
| `-S <IP>` | Spoof source IP (requires `-e` and `-Pn`) |
| `-e <iface>` | Specify network interface |
| `--source-port <port>` / `-g <port>` | Spoof source port |
| `--data <hex>` | Append custom binary payload |
| `--data-string <str>` | Append custom string payload |
| `--data-length <n>` | Append n random bytes |
| `--ip-options <opts>` | Set IP options (R=record-route, T=timestamp, L/S=source routing) |
| `--ttl <val>` | Set IPv4 TTL |
| `--randomize-hosts` | Shuffle target order |
| `--spoof-mac <mac>` | Spoof MAC (0=random, hex=specific, name=vendor OUI) |
| `--proxies <urls>` | Relay through HTTP/SOCKS4 proxies |
| `--badsum` | Invalid checksum to detect firewalls/IDS |

---

## Output Options

| Flag | Description |
|---|---|
| `-oN <file>` | Normal text output |
| `-oX <file>` | XML output (use `-oX -` for stdout) |
| `-oG <file>` | Grepable output |
| `-oA <base>` | All formats (.nmap, .xml, .gnmap) |
| `-v` / `-vv` | Increase verbosity |
| `-d` / `-d<0-9>` | Debug level |
| `--reason` | Show reason for port state determination |
| `--open` | Show only open/open\|filtered/unfiltered ports |
| `--packet-trace` | Trace all packets sent/received |
| `--iflist` | Print interfaces and routes |
| `--append-output` | Append to existing output files |
| `--resume <file>` | Resume aborted scan |
| `--stats-every <t>` | Print periodic status (e.g. `30s`) |

---

## Scan Algorithm Tuning

### How Nmap Times Probes

Nmap uses a TCP-style smoothed RTT estimator with exponential backoff. It measures
round-trip times from probe/response pairs and adjusts timeouts dynamically. The
congestion control window drops to 1 on packet loss and recovers via slow-start.

Nmap sends timing probes to known-open ports every 1.25 seconds on filtered-heavy
hosts to maintain an accurate RTT estimate even when most probes get no response.

### Recommended Tuning by Scenario

| Scenario | Flags |
|---|---|
| Reliable LAN | `--min-rtt-timeout 50ms --max-rtt-timeout 200ms --max-retries 3 --min-rate 300` |
| Across WAN | `--initial-rtt-timeout 500ms --max-rtt-timeout 2s --max-retries 5` |
| Lossy network | `-T3 --max-retries 8 --max-rate 100` |
| Speed over accuracy | `--min-rate 100 --max-retries 0` (stateless-scanner emulation) |
| Large subnet (/24+) | `--min-hostgroup 256 --host-timeout 30m` |
| UDP full range | `--defeat-icmp-ratelimit --scan-delay 1s --host-timeout 15m` |
| IDS evasion | `-T1 --scan-delay 15s --max-parallelism 1` |

### Key Interactions

- Higher `--min-rate` can paradoxically increase total scan time by triggering
  congestion-related retransmissions.
- `--defeat-icmp-ratelimit` marks rate-limited ports as `open` rather than `open|filtered`.
  Faster but less accurate.
- The scan delay auto-detection starts at 5ms and doubles on each drop until 1s cap.
  Use `--scan-delay` to override if you know the target's rate limit.

---

## CPE (Common Platform Enumeration)

Both OS detection and version detection produce CPE identifiers in the XML output:
- OS: `cpe:/o:linux:linux_kernel:2.6`
- Service: `cpe:/a:apache:http_server:2.4.41`

CPE identifiers enable automated correlation with vulnerability databases (NVD, CVE).
They appear in `<osclass>` and `<service>` XML elements as `cpe` attributes.

---

## Scan Resumption

| Flag | Description |
|---|---|
| `--resume <file>` | Resume aborted scan from `-oN` or `-oG` output file |

Only works with normal (`-oN`) or grepable (`-oG`) output. Does NOT work with XML-only.
For critical scans, always use `-oA <basename>` to enable resumption.

---

## Miscellaneous

| Flag | Description |
|---|---|
| `-6` | Enable IPv6 scanning |
| `-A` | Aggressive: enables `-O -sV -sC --traceroute` |
| `--privileged` | Assume sufficient privileges |
| `--unprivileged` | Assume no raw socket privileges |
| `--noninteractive` | Disable runtime keyboard input (for scripted execution) |
| `--unique` | Deduplicate overlapping target specifications |
| `--resolve-all` | Scan all addresses a hostname resolves to |
| `-iR <count>` | Generate random targets for Internet-wide surveys |
| `-V` | Print nmap version |
| `-h` | Print help |
