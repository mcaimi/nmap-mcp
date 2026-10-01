"""Tests for nmap XML parser."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from nmap_mcp.tools import _parse_root


class TestParseRoot:
    def test_parses_scanner_info(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        data = _parse_root(root)
        assert data["scanner"] == "nmap"
        assert data["version"] == "7.94"
        assert "192.168.1.10" in data["args"]

    def test_parses_hosts(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        data = _parse_root(root)
        assert len(data["hosts"]) == 1
        host = data["hosts"][0]
        assert host["status"] == "up"
        assert host["status_reason"] == "arp-response"

    def test_parses_addresses(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        addrs = {a["type"]: a["addr"] for a in host["addresses"]}
        assert addrs["ipv4"] == "192.168.1.10"
        assert addrs["mac"] == "AA:BB:CC:DD:EE:FF"

    def test_parses_hostnames(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        assert host["hostnames"][0]["name"] == "webserver.local"

    def test_parses_ports(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        assert len(host["ports"]) == 3
        ports_by_id = {p["portid"]: p for p in host["ports"]}
        assert ports_by_id["22"]["service"] == "ssh"
        assert ports_by_id["22"]["product"] == "OpenSSH"
        assert ports_by_id["80"]["service"] == "http"
        assert ports_by_id["3306"]["service"] == "mysql"

    def test_parses_cpe(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        ports_by_id = {p["portid"]: p for p in host["ports"]}
        assert "cpe:/a:openbsd:openssh:8.9p1" in ports_by_id["22"]["cpe"]

    def test_parses_scripts(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        ports_by_id = {p["portid"]: p for p in host["ports"]}
        scripts = ports_by_id["80"]["scripts"]
        assert len(scripts) == 1
        assert scripts[0]["id"] == "http-title"
        assert scripts[0]["output"] == "Welcome Page"

    def test_parses_os(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        assert len(host["os"]) == 1
        assert host["os"][0]["name"] == "Linux 5.15"
        assert host["os"][0]["accuracy"] == "95"

    def test_parses_summary(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        data = _parse_root(root)
        assert data["summary"]["hosts_up"] == 1
        assert data["summary"]["hosts_total"] == 1
        assert data["summary"]["elapsed"] == "10.00"
        assert data["summary"]["exit_status"] == "success"

    def test_parses_tcp_sequence(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        assert host["tcp_sequence"]["difficulty"] == "Good luck!"

    def test_parses_distance(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        assert host["distance"] == 1

    def test_parses_tasks(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        data = _parse_root(root)
        assert len(data["tasks"]) == 2
        assert data["tasks"][0]["task"] == "SYN Stealth Scan"

    def test_from_string(self, sample_xml_string: str):
        root = ET.fromstring(sample_xml_string)
        data = _parse_root(root)
        assert len(data["hosts"]) == 1

    def test_extraports(self, sample_xml_path: Path):
        root = ET.parse(str(sample_xml_path)).getroot()
        host = _parse_root(root)["hosts"][0]
        assert host["extraports"][0]["state"] == "closed"
        assert host["extraports"][0]["count"] == 997
