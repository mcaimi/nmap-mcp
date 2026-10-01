"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_xml_path() -> Path:
    return FIXTURES_DIR / "sample_scan.xml"


@pytest.fixture
def sample_xml_string(sample_xml_path: Path) -> str:
    return sample_xml_path.read_text()
