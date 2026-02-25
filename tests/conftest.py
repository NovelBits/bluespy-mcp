"""Shared test fixtures — mock BlueSPY module for unit testing without hardware."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, PropertyMock
from typing import Any

import pytest


@dataclass
class MockPacket:
    """Simulates a BlueSPY event_id with query support."""
    summary: str = ""
    timestamp: int = 0
    rssi: int = -60
    channel: int = 37

    def query(self, name: str) -> Any:
        return getattr(self, name, "")

    def query_str(self, name: str) -> str:
        return str(getattr(self, name, ""))

    def query_int(self, name: str) -> int:
        return int(getattr(self, name, 0))

    def query_bool(self, name: str) -> bool:
        return bool(getattr(self, name, False))

    def parent(self):
        return None

    def children(self):
        return []


@dataclass
class MockDevice:
    """Simulates a BlueSPY device."""
    _address: str = "AA:BB:CC:DD:EE:FF"
    _name: str = "Test Device"

    def query(self, name: str) -> Any:
        if name == "address":
            return self._address
        if name == "name":
            return self._name
        return ""

    def query_str(self, name: str) -> str:
        return str(self.query(name))

    def get_connections(self):
        return []

    def get_audio_streams(self):
        return []


@dataclass
class MockConnection:
    """Simulates a BlueSPY connection."""
    _summary: str = "LE Connection"
    _interval: int = 30
    _latency: int = 0
    _timeout: int = 500

    @property
    def summary(self):
        return self._summary

    def query(self, name: str) -> Any:
        mapping = {
            "summary": self._summary,
            "interval": self._interval,
            "latency": self._latency,
            "timeout": self._timeout,
        }
        return mapping.get(name, "")

    def query_str(self, name: str) -> str:
        return str(self.query(name))

    def get_audio_streams(self):
        return []


class MockPackets:
    """Simulates bluespy.packets list-like object."""

    def __init__(self, packets: list[MockPacket]):
        self._packets = packets

    def __len__(self):
        return len(self._packets)

    def __getitem__(self, index):
        return self._packets[index]

    def __iter__(self):
        return iter(self._packets)


@pytest.fixture
def mock_bluespy():
    """Create a mock BlueSPY module with sample data."""
    module = MagicMock()

    sample_packets = [
        MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", timestamp=1000000, rssi=-55, channel=37),
        MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", timestamp=1100000, rssi=-58, channel=38),
        MockPacket(summary="SCAN_REQ to AA:BB:CC:DD:EE:FF", timestamp=1200000, rssi=-60, channel=37),
        MockPacket(summary="SCAN_RSP from AA:BB:CC:DD:EE:FF", timestamp=1300000, rssi=-56, channel=37),
        MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", timestamp=2000000, rssi=-52, channel=39),
        MockPacket(summary="LE-U L2CAP Data", timestamp=3000000, rssi=-50, channel=5),
        MockPacket(summary="ATT Read Request", timestamp=3100000, rssi=-51, channel=5),
        MockPacket(summary="ATT Read Response", timestamp=3200000, rssi=-49, channel=5),
        MockPacket(summary="SMP Pairing Request", timestamp=4000000, rssi=-53, channel=5),
        MockPacket(summary="LL_TERMINATE_IND Reason: Remote User Terminated", timestamp=5000000, rssi=-55, channel=5),
    ]
    module.packets = MockPackets(sample_packets)
    module.devices = [MockDevice()]
    module.connections = [MockConnection()]

    return module
