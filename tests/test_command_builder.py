"""Tests for safe nmap command construction."""

from __future__ import annotations

import pytest

from nmap_mcp.command_builder import _validate_custom_flags, build_command
from nmap_mcp.models import PROFILES, ProfileName


class TestBuildCommand:
    def test_standard_scan_privileged(self):
        profile = PROFILES[ProfileName.STANDARD_SCAN]
        cmd = build_command("192.168.1.1", profile, is_root=True)
        assert cmd[-1] == "192.168.1.1"
        assert "-sS" in cmd
        assert "-sV" in cmd
        assert "--reason" in cmd
        assert "-oX" in cmd
        assert "-" in cmd

    def test_standard_scan_unprivileged_falls_back(self):
        profile = PROFILES[ProfileName.STANDARD_SCAN]
        cmd = build_command("192.168.1.1", profile, is_root=False)
        assert "-sT" in cmd
        assert "-sS" not in cmd

    def test_discovery_profile_no_xml_output(self):
        profile = PROFILES[ProfileName.QUICK_DISCOVERY]
        cmd = build_command("192.168.1.1", profile, is_root=False)
        assert "-oX" not in cmd

    def test_idle_scan_includes_zombie(self):
        profile = PROFILES[ProfileName.STEALTH_L4]
        cmd = build_command(
            "192.168.1.1", profile, is_root=True, zombie_host="10.0.0.50:80"
        )
        assert "-sI" in cmd
        assert "10.0.0.50:80" in cmd

    def test_custom_flags_appended(self):
        profile = PROFILES[ProfileName.STANDARD_SCAN]
        cmd = build_command(
            "192.168.1.1", profile, is_root=True, custom_flags=["-n", "-F"]
        )
        assert "-n" in cmd
        assert "-F" in cmd

    def test_command_is_list_not_string(self):
        profile = PROFILES[ProfileName.STANDARD_SCAN]
        cmd = build_command("192.168.1.1", profile, is_root=True)
        assert isinstance(cmd, list)
        assert all(isinstance(c, str) for c in cmd)

    def test_reason_always_present(self):
        for name, profile in PROFILES.items():
            if name == ProfileName.CUSTOM_SCAN:
                continue
            cmd = build_command("192.168.1.1", profile, is_root=True)
            assert "--reason" in cmd, f"--reason missing for {name}"

    def test_all_profiles_produce_valid_commands(self):
        for name, profile in PROFILES.items():
            if name == ProfileName.CUSTOM_SCAN:
                cmd = build_command(
                    "192.168.1.1", profile, is_root=True, custom_flags=["-sT"]
                )
            elif name == ProfileName.STEALTH_L4:
                cmd = build_command(
                    "192.168.1.1", profile, is_root=True, zombie_host="10.0.0.1:80"
                )
            else:
                cmd = build_command("192.168.1.1", profile, is_root=True)
            assert cmd[-1] == "192.168.1.1"
            assert len(cmd) >= 2


class TestValidateCustomFlags:
    def test_allowed_flag(self):
        result = _validate_custom_flags(["-n", "-F"])
        assert result == ["-n", "-F"]

    def test_value_flag_separate(self):
        result = _validate_custom_flags(["-p", "22,80,443"])
        assert result == ["-p", "22,80,443"]

    def test_value_flag_joined(self):
        result = _validate_custom_flags(["-T4"])
        assert result == ["-T4"]

    def test_denied_flag_raises(self):
        with pytest.raises(ValueError, match="not allowed"):
            _validate_custom_flags(["-iR"])

    def test_output_flag_denied(self):
        with pytest.raises(ValueError, match="not allowed"):
            _validate_custom_flags(["-oN"])

    def test_unknown_flag_raises(self):
        with pytest.raises(ValueError, match="Unknown"):
            _validate_custom_flags(["--some-unknown-flag"])

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError, match="Invalid value"):
            _validate_custom_flags(["-p", "$(whoami)"])

    def test_value_flag_missing_value(self):
        with pytest.raises(ValueError, match="requires a value"):
            _validate_custom_flags(["-p"])

    def test_injection_in_script_args(self):
        with pytest.raises(ValueError, match="Invalid value"):
            _validate_custom_flags(["--script-args", "user=admin;rm -rf /"])
