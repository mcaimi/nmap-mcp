# Operational Methodologies

Advanced scanning strategies for complex assessments. Load this reference when the user
requests multi-phase scanning, scan correlation, performance tuning, or scan resumption.

## Multi-Phase Scanning Methodology

For large networks or thorough assessments, use a phased approach rather than a single
monolithic scan:

**Phase 1 — Firewall Mapping** (optional, for hardened targets):
```bash
sudo nmap -sA -T4 --reason -oX - <target_network>
```
Understand filtering rules before investing time in deep scans.

**Phase 2 — Host Discovery**:
```bash
nmap -sn -PE -PS80,443 -PA80,443 -PP -PU40125 --reason <target_network>
```
Identify live hosts. Save the list for subsequent phases.

**Phase 3 — Quick Port Survey**:
```bash
sudo nmap -sS --top-ports 1000 -T4 --reason --open -oX - -iL live_hosts.txt
```
Fast scan of common ports on discovered hosts.

**Phase 4 — Deep Scan on Interesting Hosts**:
```bash
sudo nmap -sS -sU -p- -sV -T4 --host-timeout 30m --reason --open -oX - <interesting_hosts>
```
Full port range with service detection on hosts that showed interesting results.

**Phase 5 — OS Fingerprinting and Scripts**:
```bash
sudo nmap -O --osscan-limit --osscan-guess -sC --script=vuln,safe \
  --reason --open -oX - <interesting_hosts>
```
Targeted fingerprinting and vulnerability checks on priority targets.

## Multi-Scan Correlation

Some port states cannot be determined by a single scan technique. Combine results
from different scans to reach definitive conclusions:

**Pattern: FIN + ACK correlation**
1. Run FIN scan: `sudo nmap -sF -T4 --reason -oX - <target>`
   - Open ports → `open|filtered` (no response)
   - Closed ports → `closed` (RST received)
2. Run ACK scan: `sudo nmap -sA -T4 --reason -oX - <target>`
   - Unfiltered ports → `unfiltered` (RST received regardless of open/closed)
   - Filtered ports → `filtered` (no response or ICMP unreachable)
3. Correlate results:
   - `open|filtered` (FIN) + `unfiltered` (ACK) = **open**
   - `open|filtered` (FIN) + `filtered` (ACK) = **filtered**
   - `closed` (FIN) + `unfiltered` (ACK) = **closed**

This technique is essential when stateful firewalls block SYN scans but allow other
TCP flag combinations through.

## Performance Optimization

**Version detection is the largest time sink.** Omitting `-sV` or reducing
`--version-intensity` is far more effective than adjusting timing templates.

**RTT-based tuning** for known network conditions:
- Ping the target first and note the maximum RTT.
- Set `--initial-rtt-timeout` to 2x the observed RTT.
- Set `--max-rtt-timeout` to 3-4x the observed RTT. Never below 100ms.

**Host group sizing** for network scans:
- For /24 networks: `--min-hostgroup 256` processes the entire subnet at once.
- For few-port scans: `--min-hostgroup 2048` or higher improves throughput.

**Retry tuning**:
- Reliable networks: `--max-retries 3` (default is 10).
- Informal surveys: `--max-retries 0` (fastest but may miss filtered ports).

**Slow host management**:
- `--host-timeout 30m` abandons hosts that take too long. The slowest few percent
  of hosts often consume the majority of total scan time.

**Rate control**:
- `--min-rate 100` guarantees minimum packet rate.
- `--max-rate 300` caps rate to avoid triggering IDS or overwhelming targets.
- Caution: higher rate can cause *longer* scans due to congestion-triggered retransmissions.

**UDP-specific optimization**:
- `--defeat-icmp-ratelimit`: Marks rate-limited ports as `open` instead of
  `open|filtered`. Faster but less accurate.
- `--scan-delay 1s`: Match the host's ICMP rate limit explicitly.
- `--min-hostgroup 100`: Amortize rate limiting across multiple hosts in parallel.

**DNS optimization**:
- `-n`: Skip reverse DNS resolution — significant speed improvement.
- `--dns-servers <srv>`: Use custom DNS for authoritative/faster resolution.
- Scan for port 53 on private networks first to find usable local DNS servers.

## Scan Resumption

Long-running scans can be resumed if interrupted. This requires file-based output
(not stdout):

```bash
sudo nmap -sS -p- -oN scan_progress.nmap -oX scan_results.xml <target>
# If interrupted (Ctrl+C or timeout):
sudo nmap --resume scan_progress.nmap
```

`--resume` only works with normal output (`-oN`) or grepable output (`-oG`), not XML.
For critical long-running scans, always use `-oA <basename>` to save all formats and
enable resumption.

## Runtime Interaction

During a running scan, nmap accepts keyboard input:
- `v` / `V`: Increase/decrease verbosity
- `d` / `D`: Increase/decrease debug level
- `p` / `P`: Turn on/off packet tracing
- Any other key: Print status line

For automated/scripted execution, use `--noninteractive` to disable these controls
and prevent accidental input from affecting the scan.
