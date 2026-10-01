"""Target validation and authorization checking."""

from __future__ import annotations

import ipaddress
import re

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

_TARGET_PATTERNS = [
    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"),
    re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$"),
    re.compile(r"^[0-9a-fA-F:]+$"),
    re.compile(r"^[0-9a-fA-F:]+/\d{1,3}$"),
    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$"),
]

_SHELL_METACHARACTERS = set(";|&$`(){}[]!#'\"\\")

_DENIED_TARGETS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}


def validate_target(target: str) -> tuple[bool, str]:
    """Validate a scan target. Returns (is_valid, message)."""
    target = target.strip()

    if not target:
        return False, "Target cannot be empty"

    if any(c in _SHELL_METACHARACTERS for c in target):
        return False, "Target contains invalid characters"

    if target in _DENIED_TARGETS:
        return False, f"Scanning {target} is not allowed (public infrastructure)"

    if not any(p.match(target) for p in _TARGET_PATTERNS):
        return False, f"Invalid target format: {target}"

    try:
        ipaddress.ip_address(target)
    except ValueError:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.version == 4 and net.prefixlen < 16:
                return False, f"Network {target} is too large (/{net.prefixlen}). Maximum /16."
            if net.version == 6 and net.prefixlen < 48:
                return False, f"Network {target} is too large (/{net.prefixlen}). Maximum /48."
        except ValueError:
            pass

    return True, "Target is valid"


def is_private_target(target: str) -> bool:
    """Check if target is in private/localhost ranges (auto-authorized)."""
    if target in ("localhost", "localhost.localdomain"):
        return True
    try:
        addr = ipaddress.ip_address(target)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return any(net.subnet_of(priv) for priv in _PRIVATE_RANGES)
        except (ValueError, TypeError):
            return False
