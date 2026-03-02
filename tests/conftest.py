"""Shared test fixtures — mock blueSPY module for unit testing without hardware."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock, PropertyMock
from typing import Any

import pytest


@dataclass
class MockPacket:
    """Simulates a blueSPY event_id with query support.

    Real API uses query("time") not query("timestamp").
    Direct attribute access (pkt.summary) goes through __getattr__ → query().
    """
    summary: str = ""
    time: int = 0
    rssi: int = -60
    channel: int = 37
    payload: bytes | None = None

    def query(self, name: str) -> Any:
        if hasattr(self, name) and name != "query":
            return getattr(self, name)
        raise AttributeError()

    def query_str(self, name: str) -> str:
        return str(self.query(name))

    def query_int(self, name: str) -> int:
        return int(self.query(name))

    def query_bool(self, name: str) -> bool:
        return bool(self.query(name))

    def parent(self):
        return None

    def children(self):
        return []


@dataclass
class MockDevice:
    """Simulates a blueSPY device.

    Real API: query("address") and query("name") raise AttributeError.
    Address is parsed from query("summary") which returns "AA:BB:CC:DD:EE:FF, Static".
    """
    _address: str = "AA:BB:CC:DD:EE:FF"
    _name: str = "Test Device"

    def query(self, name: str) -> Any:
        if name == "summary":
            return f"{self._address}, Static"
        raise AttributeError()

    def query_str(self, name: str) -> str:
        return str(self.query(name))

    def get_connections(self):
        return []

    def get_audio_streams(self):
        return []


@dataclass
class MockConnection:
    """Simulates a blueSPY connection.

    Real API: query("interval"), query("latency"), query("timeout") all raise AttributeError.
    Only query("summary") works.
    """
    _summary: str = "0xABCD1234 21:40:50.5-21:40:55.4: Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66, 0/0/141 Adv/Ctrl/Data packets"

    def query(self, name: str) -> Any:
        if name == "summary":
            return self._summary
        raise AttributeError()

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
    """Create a mock blueSPY module with sample data."""
    module = MagicMock()

    sample_packets = [
        MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000000, rssi=-55, channel=37),
        MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1100000, rssi=-58, channel=38),
        MockPacket(summary="SCAN_REQ to AA:BB:CC:DD:EE:FF", time=1200000, rssi=-60, channel=37),
        MockPacket(summary="SCAN_RSP from AA:BB:CC:DD:EE:FF", time=1300000, rssi=-56, channel=37),
        MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000000, rssi=-52, channel=39),
        MockPacket(summary="LE-U L2CAP Data", time=3000000, rssi=-50, channel=5),
        MockPacket(summary="ATT Read Request", time=3100000, rssi=-51, channel=5),
        MockPacket(summary="ATT Read Response", time=3200000, rssi=-49, channel=5),
        MockPacket(summary="SMP Pairing Request", time=4000000, rssi=-53, channel=5),
        MockPacket(summary="LL_TERMINATE_IND Reason: Remote User Terminated", time=5000000, rssi=-55, channel=5),
    ]
    module.packets = MockPackets(sample_packets)
    module.devices = [MockDevice()]
    module.connections = [MockConnection()]

    return module
