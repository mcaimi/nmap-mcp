"""Safe nmap command construction with allowlisted flags."""

from __future__ import annotations

import re
import shutil

from nmap_mcp.models import ProfileName, ScanProfile

ALLOWED_FLAGS: set[str] = {
    "-sS", "-sT", "-sU", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM",
    "-sY", "-sZ", "-sO", "-sV", "-sC", "-O", "-A",
    "-Pn", "-PE", "-PP", "-PM", "-PR",
    "-n", "-R", "-6", "-F", "-r",
    "--open", "--reason", "--traceroute", "--osscan-limit", "--osscan-guess",
    "--version-light", "--version-all", "--allports",
    "--randomize-hosts", "--noninteractive", "--unique",
    "--defeat-rst-ratelimit", "--defeat-icmp-ratelimit",
    "--disable-arp-ping",
    "-f", "-sn",
}

VALUE_FLAGS: dict[str, re.Pattern[str]] = {
    "-p": re.compile(r"^[TUStus:,0-9\-]+$"),
    "--top-ports": re.compile(r"^\d+$"),
    "-T": re.compile(r"^[0-5]$"),
    "--version-intensity": re.compile(r"^[0-9]$"),
    "--min-rate": re.compile(r"^\d+$"),
    "--max-rate": re.compile(r"^\d+$"),
    "--max-retries": re.compile(r"^\d+$"),
    "--host-timeout": re.compile(r"^\d+[smh]?$"),
    "--script-timeout": re.compile(r"^\d+[smh]?$"),
    "--scan-delay": re.compile(r"^\d+[smh]?$"),
    "--max-scan-delay": re.compile(r"^\d+[smh]?$"),
    "--data-length": re.compile(r"^\d+$"),
    "--stats-every": re.compile(r"^\d+[smh]?$"),
    "-g": re.compile(r"^\d+$"),
    "--source-port": re.compile(r"^\d+$"),
    "-e": re.compile(r"^[a-zA-Z0-9_\-\.]+$"),
    "--script": re.compile(r"^[a-zA-Z0-9_,\-\*\+\(\) ]+$"),
    "--script-args": re.compile(r"^[a-zA-Z0-9_,=\.\-]+$"),
    "--min-hostgroup": re.compile(r"^\d+$"),
    "--max-hostgroup": re.compile(r"^\d+$"),
    "--min-parallelism": re.compile(r"^\d+$"),
    "--max-parallelism": re.compile(r"^\d+$"),
    "--ttl": re.compile(r"^\d+$"),
    "--mtu": re.compile(r"^\d+$"),
}

DENIED_FLAGS: set[str] = {
    "-iR", "--script-updatedb", "-b",
    "-oN", "-oG", "-oA",
}


def build_command(
    target: str,
    profile: ScanProfile,
    is_root: bool,
    custom_flags: list[str] | None = None,
    zombie_host: str | None = None,
) -> list[str]:
    """Build a safe nmap command as a list of strings.

    Never produces a shell-interpolated string. The returned list is
    passed directly to asyncio.create_subprocess_exec().
    """
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError("nmap not found in PATH")

    cmd: list[str] = []

    if profile.requires_root and not is_root:
        sudo_path = shutil.which("sudo")
        if sudo_path and profile.unprivileged_flags is None:
            cmd.append(sudo_path)
        elif profile.unprivileged_flags is not None:
            pass
        else:
            raise RuntimeError("Root privileges required for this scan profile but sudo is not available")

    cmd.append(nmap_path)

    if profile.requires_root and not is_root and profile.unprivileged_flags is not None:
        cmd.extend(profile.unprivileged_flags)
    else:
        cmd.extend(profile.base_flags)

    if profile.name == ProfileName.STEALTH_L4 and zombie_host:
        cmd.extend(["-sI", zombie_host])

    cmd.extend(profile.always_append)

    if custom_flags:
        cmd.extend(_validate_custom_flags(custom_flags))

    if not profile.discovery_only:
        cmd.extend(["-oX", "-"])

    cmd.append(target)

    return cmd


def _validate_custom_flags(flags: list[str]) -> list[str]:
    """Validate custom flags against the allowlist."""
    validated: list[str] = []
    i = 0
    while i < len(flags):
        flag = flags[i]

        if flag in DENIED_FLAGS:
            raise ValueError(f"Flag '{flag}' is not allowed")

        if flag in ALLOWED_FLAGS:
            validated.append(flag)
            i += 1
            continue

        matched = False
        # Check exact matches first (longer keys before shorter to avoid
        # --script matching --script-args via prefix)
        for vflag, pattern in sorted(VALUE_FLAGS.items(), key=lambda kv: -len(kv[0])):
            if flag == vflag:
                if i + 1 >= len(flags):
                    raise ValueError(f"Flag '{flag}' requires a value")
                value = flags[i + 1]
                if not pattern.match(value):
                    raise ValueError(f"Invalid value for '{flag}': '{value}'")
                validated.extend([flag, value])
                i += 2
                matched = True
                break
        if not matched:
            for vflag, pattern in sorted(VALUE_FLAGS.items(), key=lambda kv: -len(kv[0])):
                if flag.startswith(vflag) and len(flag) > len(vflag):
                    value_part = flag[len(vflag):]
                    if pattern.match(value_part):
                        validated.append(flag)
                        i += 1
                        matched = True
                        break

        if not matched:
            raise ValueError(f"Unknown or disallowed flag: '{flag}'")

    return validated
