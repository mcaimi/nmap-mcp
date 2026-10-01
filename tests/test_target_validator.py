"""Tests for target validation."""

from nmap_mcp.target_validator import is_private_target, validate_target


class TestValidateTarget:
    def test_valid_ipv4(self):
        valid, _ = validate_target("192.168.1.1")
        assert valid

    def test_valid_cidr(self):
        valid, _ = validate_target("192.168.1.0/24")
        assert valid

    def test_valid_hostname(self):
        valid, _ = validate_target("webserver.local")
        assert valid

    def test_valid_ipv6(self):
        valid, _ = validate_target("::1")
        assert valid

    def test_empty_target(self):
        valid, msg = validate_target("")
        assert not valid
        assert "empty" in msg.lower()

    def test_shell_injection_semicolon(self):
        valid, msg = validate_target("192.168.1.1; rm -rf /")
        assert not valid
        assert "invalid characters" in msg.lower()

    def test_shell_injection_pipe(self):
        valid, msg = validate_target("192.168.1.1 | cat /etc/passwd")
        assert not valid
        assert "invalid characters" in msg.lower()

    def test_shell_injection_backtick(self):
        valid, msg = validate_target("`whoami`")
        assert not valid

    def test_shell_injection_dollar(self):
        valid, msg = validate_target("$(whoami)")
        assert not valid

    def test_denied_target(self):
        valid, msg = validate_target("8.8.8.8")
        assert not valid
        assert "not allowed" in msg.lower()

    def test_cidr_too_large_ipv4(self):
        valid, msg = validate_target("10.0.0.0/8")
        assert not valid
        assert "too large" in msg.lower()

    def test_cidr_acceptable_ipv4(self):
        valid, _ = validate_target("10.0.0.0/16")
        assert valid

    def test_ipv4_range(self):
        valid, _ = validate_target("192.168.1.1-50")
        assert valid

    def test_invalid_format(self):
        valid, msg = validate_target("not a valid target at all")
        assert not valid
        assert "invalid target format" in msg.lower()


class TestIsPrivateTarget:
    def test_localhost(self):
        assert is_private_target("127.0.0.1")

    def test_localhost_name(self):
        assert is_private_target("localhost")

    def test_rfc1918_10(self):
        assert is_private_target("10.0.0.1")

    def test_rfc1918_172(self):
        assert is_private_target("172.16.0.1")

    def test_rfc1918_192(self):
        assert is_private_target("192.168.1.1")

    def test_ipv6_loopback(self):
        assert is_private_target("::1")

    def test_public_ip(self):
        assert not is_private_target("93.184.216.34")

    def test_hostname_not_private(self):
        assert not is_private_target("example.com")
