"""Scan profile definitions and request models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from pydantic import BaseModel, model_validator


class ProfileName(str, Enum):
    QUICK_DISCOVERY = "quick_discovery"
    STANDARD_SCAN = "standard_scan"
    COMPREHENSIVE_SCAN = "comprehensive_scan"
    AGGRESSIVE_RECON = "aggressive_recon"
    STEALTH_L1 = "stealth_l1"
    STEALTH_L2 = "stealth_l2"
    STEALTH_L3 = "stealth_l3"
    STEALTH_L4 = "stealth_l4"
    FIREWALL_ANALYSIS = "firewall_analysis"
    SCTP_SCAN = "sctp_scan"
    PROTOCOL_DISCOVERY = "protocol_discovery"
    UDP_SCAN = "udp_scan"
    VULNERABILITY_SCAN = "vulnerability_scan"
    WEB_APPLICATION_SCAN = "web_application_scan"
    INFRASTRUCTURE_DISCOVERY = "infrastructure_discovery"
    CUSTOM_SCAN = "custom_scan"


@dataclass(frozen=True)
class ScanProfile:
    name: ProfileName
    display_name: str
    description: str
    requires_root: bool
    base_flags: list[str]
    unprivileged_flags: list[str] | None = None
    discovery_only: bool = False
    always_append: list[str] = field(default_factory=lambda: ["--reason"])


PROFILES: dict[ProfileName, ScanProfile] = {
    ProfileName.QUICK_DISCOVERY: ScanProfile(
        name=ProfileName.QUICK_DISCOVERY,
        display_name="Quick Discovery",
        description="Fast host discovery with minimal port checking.",
        requires_root=False,
        base_flags=["-sn", "-PE", "-PS80,443", "-PA80,443", "-PP", "-PU40125"],
        discovery_only=True,
    ),
    ProfileName.STANDARD_SCAN: ScanProfile(
        name=ProfileName.STANDARD_SCAN,
        display_name="Standard Scan",
        description="Default balanced scan of common ports with service detection.",
        requires_root=True,
        base_flags=["-sS", "-sV", "--version-intensity", "5", "-T4", "--open"],
        unprivileged_flags=["-sT", "-sV", "--version-intensity", "5", "-T4", "--open"],
    ),
    ProfileName.COMPREHENSIVE_SCAN: ScanProfile(
        name=ProfileName.COMPREHENSIVE_SCAN,
        display_name="Comprehensive Scan",
        description="Deep scan with OS detection, scripts, full port range, and traceroute.",
        requires_root=True,
        base_flags=[
            "-sS", "-sU", "-sV", "-O", "--osscan-limit", "--osscan-guess",
            "-sC", "-p-", "-T4", "--traceroute", "--open",
            "--host-timeout", "30m", "--script-timeout", "5m",
        ],
    ),
    ProfileName.AGGRESSIVE_RECON: ScanProfile(
        name=ProfileName.AGGRESSIVE_RECON,
        display_name="Aggressive Recon",
        description="Maximum information gathering with OS detection, version detection, scripts, and traceroute.",
        requires_root=True,
        base_flags=["-A", "-T4", "--open"],
    ),
    ProfileName.STEALTH_L1: ScanProfile(
        name=ProfileName.STEALTH_L1,
        display_name="Stealth L1 — Low Profile",
        description="Basic IDS evasion with slower timing, fragmented packets, and random payload padding.",
        requires_root=True,
        base_flags=["-sS", "-T2", "-f", "--data-length", "24", "--randomize-hosts", "--open"],
    ),
    ProfileName.STEALTH_L2: ScanProfile(
        name=ProfileName.STEALTH_L2,
        display_name="Stealth L2 — Firewall Bypass",
        description="NULL scan to bypass non-stateful firewalls that only filter SYN packets.",
        requires_root=True,
        base_flags=["-sN", "-T2", "--data-length", "24", "--randomize-hosts"],
    ),
    ProfileName.STEALTH_L3: ScanProfile(
        name=ProfileName.STEALTH_L3,
        display_name="Stealth L3 — Deep Evasion",
        description="IDS-aware evasion with decoys, spoofed source port, MAC randomization, and slow timing.",
        requires_root=True,
        base_flags=[
            "-sS", "-T1", "-f", "-D", "RND:5,ME", "-g", "53",
            "--scan-delay", "5s", "--data-length", "32",
            "--randomize-hosts", "--spoof-mac", "0", "--open",
        ],
    ),
    ProfileName.STEALTH_L4: ScanProfile(
        name=ProfileName.STEALTH_L4,
        display_name="Stealth L4 — Idle Scan",
        description="Truly blind scan via zombie host. No packets sent from your real IP.",
        requires_root=True,
        base_flags=["-Pn"],
    ),
    ProfileName.FIREWALL_ANALYSIS: ScanProfile(
        name=ProfileName.FIREWALL_ANALYSIS,
        display_name="Firewall Analysis",
        description="Map firewall rules using ACK scan to determine filtering policies.",
        requires_root=True,
        base_flags=["-sA", "-T4"],
    ),
    ProfileName.SCTP_SCAN: ScanProfile(
        name=ProfileName.SCTP_SCAN,
        display_name="SCTP Scan",
        description="Scan SCTP ports used in telecom/SS7/SIGTRAN infrastructure.",
        requires_root=True,
        base_flags=["-sY", "-T4", "--open"],
    ),
    ProfileName.PROTOCOL_DISCOVERY: ScanProfile(
        name=ProfileName.PROTOCOL_DISCOVERY,
        display_name="Protocol Discovery",
        description="Determine which IP protocols a host supports (TCP, UDP, ICMP, GRE, ESP, etc.).",
        requires_root=True,
        base_flags=["-sO"],
    ),
    ProfileName.UDP_SCAN: ScanProfile(
        name=ProfileName.UDP_SCAN,
        display_name="UDP Scan",
        description="Scan UDP ports (DNS, SNMP, DHCP, NTP, etc.).",
        requires_root=True,
        base_flags=[
            "-sU", "--top-ports", "100", "-sV", "--version-intensity", "0",
            "-T4", "--open",
        ],
    ),
    ProfileName.VULNERABILITY_SCAN: ScanProfile(
        name=ProfileName.VULNERABILITY_SCAN,
        display_name="Vulnerability Scan",
        description="Script-based vulnerability assessment with OS and service detection.",
        requires_root=True,
        base_flags=["-sS", "-sV", "-O", "--script=vuln,safe", "-T4", "--open"],
    ),
    ProfileName.WEB_APPLICATION_SCAN: ScanProfile(
        name=ProfileName.WEB_APPLICATION_SCAN,
        display_name="Web Application Scan",
        description="HTTP/HTTPS-focused service enumeration and vulnerability checks.",
        requires_root=False,
        base_flags=[
            "-sV", "-p", "80,443,8080,8443",
            "--script=http-* and safe", "-T4", "--open",
        ],
    ),
    ProfileName.INFRASTRUCTURE_DISCOVERY: ScanProfile(
        name=ProfileName.INFRASTRUCTURE_DISCOVERY,
        display_name="Infrastructure Discovery",
        description="Broad network and service discovery using broadcast and SNMP.",
        requires_root=False,
        base_flags=["-sn", "--script=broadcast,discovery"],
        discovery_only=True,
    ),
    ProfileName.CUSTOM_SCAN: ScanProfile(
        name=ProfileName.CUSTOM_SCAN,
        display_name="Custom Scan",
        description="User specifies individual nmap flags. Requires custom_flags parameter.",
        requires_root=False,
        base_flags=[],
    ),
}


class ScanRequest(BaseModel):
    target: str
    profile: ProfileName
    custom_flags: list[str] | None = None
    zombie_host: str | None = None
    timeout: int = 600

    @model_validator(mode="after")
    def validate_profile_requirements(self) -> ScanRequest:
        if self.profile == ProfileName.STEALTH_L4 and not self.zombie_host:
            raise ValueError("zombie_host is required for Stealth L4 (Idle Scan) profile")
        if self.profile == ProfileName.CUSTOM_SCAN and not self.custom_flags:
            raise ValueError("custom_flags is required for Custom Scan profile")
        return self
