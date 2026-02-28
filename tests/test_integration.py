"""Integration tests using real BlueSPY library and capture files.

Run with: pytest -m hardware -v
Requires: BLUESPY_LIBRARY_PATH pointing to libblueSPY dylib/so/dll

These tests are skipped by default (no -m hardware flag).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CAPTURE_5SEC = FIXTURES_DIR / "5_sec_capture.pcapng"
CAPTURE_SMART_HOME = FIXTURES_DIR / "smart_home_capture_10min.pcapng"

# Skip entire module if dylib not available
pytestmark = pytest.mark.hardware

_bluespy_available = False
try:
    from bluespy_mcp.loader import reset_cache, discover_bluespy

    reset_cache()
    _mod = discover_bluespy()
    if _mod is not None:
        _bluespy_available = True
    reset_cache()
except Exception:
    pass

if not _bluespy_available:
    pytestmark = [pytest.mark.hardware, pytest.mark.skip(reason="BlueSPY library not available")]


@pytest.fixture(autouse=True)
def _reset_loader_cache():
    """Reset loader cache before each test so each test gets a fresh load."""
    from bluespy_mcp.loader import reset_cache

    reset_cache()
    yield
    reset_cache()


class TestRealCaptureLoading:
    """Test loading real .pcapng files with the actual BlueSPY library."""

    def test_load_5sec_capture(self):
        from bluespy_mcp.capture import CaptureManager

        mgr = CaptureManager()
        result = mgr.load(str(CAPTURE_5SEC))

        assert mgr.is_loaded
        assert result["packet_count"] > 0
        assert result["file_size_bytes"] > 0
        assert "5_sec_capture.pcapng" in result["file_path"]
        mgr.close()

    def test_load_smart_home_capture(self):
        from bluespy_mcp.capture import CaptureManager

        mgr = CaptureManager()
        result = mgr.load(str(CAPTURE_SMART_HOME))

        assert mgr.is_loaded
        # This capture may have 0 packets but should still load
        assert result["file_size_bytes"] > 0
        mgr.close()

    def test_close_and_reload(self):
        from bluespy_mcp.capture import CaptureManager

        mgr = CaptureManager()
        mgr.load(str(CAPTURE_5SEC))
        count1 = mgr.packet_count
        mgr.close()
        assert not mgr.is_loaded

        mgr.load(str(CAPTURE_5SEC))
        assert mgr.packet_count == count1
        mgr.close()


class TestRealMetadata:
    """Test metadata extraction from real captures."""

    def test_metadata_has_expected_fields(self):
        from bluespy_mcp.capture import CaptureManager

        with CaptureManager() as mgr:
            mgr.load(str(CAPTURE_5SEC))
            meta = mgr.get_metadata()

        assert meta["packet_count"] > 0
        assert meta["device_count"] > 0
        assert "file_path" in meta
        assert "file_size_bytes" in meta
        assert "devices" in meta
        assert "connections" in meta

    def test_duration_extracted(self):
        from bluespy_mcp.capture import CaptureManager

        with CaptureManager() as mgr:
            mgr.load(str(CAPTURE_5SEC))
            meta = mgr.get_metadata()

        # 5-sec capture should have duration data
        if meta["packet_count"] > 1:
            assert "duration_ns" in meta
            assert meta["duration_ns"] > 0
            assert "duration_seconds" in meta

    def test_devices_have_addresses(self):
        from bluespy_mcp.capture import CaptureManager

        with CaptureManager() as mgr:
            mgr.load(str(CAPTURE_5SEC))
            devices = mgr.get_devices()

        assert len(devices) > 0
        # At least some devices should have addresses parsed from summary
        addresses = [d.address for d in devices if d.address]
        assert len(addresses) > 0
        # Addresses should be MAC format
        for addr in addresses[:5]:
            assert ":" in addr, f"Expected MAC address format, got: {addr}"


class TestRealAnalyzer:
    """Test analyzer functions against real capture data."""

    def test_summarize_real_capture(self):
        from bluespy_mcp.capture import CaptureManager
        from bluespy_mcp.analyzer import summarize_capture

        with CaptureManager() as mgr:
            mgr.load(str(CAPTURE_5SEC))
            summary = summarize_capture(mgr)

        assert summary["packet_count"] > 0
        assert "packet_type_counts" in summary
        # Should have at least some recognized packet types
        known_types = {"ADV_IND", "ADV_NONCONN_IND", "SCAN_REQ", "SCAN_RSP",
                       "CONNECT_IND", "ATT", "SMP", "LE_DATA", "CRC_ERROR",
                       "LL_CONTROL", "DATA", "OTHER"}
        found_types = set(summary["packet_type_counts"].keys())
        assert len(found_types & known_types) > 0, f"No known types found in: {found_types}"

    def test_find_packets_by_type(self):
        from bluespy_mcp.capture import CaptureManager
        from bluespy_mcp.analyzer import find_packets

        with CaptureManager() as mgr:
            mgr.load(str(CAPTURE_5SEC))
            # ADV_IND is the most common advertising packet
            adv_packets = find_packets(mgr, packet_type="ADV_IND", max_results=10)

        # A 5-sec capture should have some advertising packets
        assert len(adv_packets) > 0
        for pkt in adv_packets:
            assert "summary" in pkt
            assert "index" in pkt

    def test_find_packets_with_rssi(self):
        from bluespy_mcp.capture import CaptureManager
        from bluespy_mcp.analyzer import find_packets

        with CaptureManager() as mgr:
            mgr.load(str(CAPTURE_5SEC))
            packets = find_packets(mgr, max_results=5)

        # Packets should have rssi from real captures
        packets_with_rssi = [p for p in packets if "rssi" in p]
        assert len(packets_with_rssi) > 0
        for p in packets_with_rssi:
            assert -120 <= p["rssi"] <= 0, f"RSSI out of range: {p['rssi']}"

    def test_find_errors(self):
        from bluespy_mcp.capture import CaptureManager
        from bluespy_mcp.analyzer import find_errors

        with CaptureManager() as mgr:
            mgr.load(str(CAPTURE_5SEC))
            errors = find_errors(mgr)

        # CRC errors are common in real captures
        # Just verify the function runs without crashing
        assert isinstance(errors, list)
        for err in errors[:5]:
            assert "summary" in err
            assert "index" in err


class TestRealServer:
    """Test MCP server tool functions against real captures."""

    def test_load_and_summarize(self):
        import json
        from bluespy_mcp.server import load_capture, capture_summary, close_capture

        result = json.loads(load_capture(str(CAPTURE_5SEC)))
        assert result["success"] is True
        assert result["packet_count"] > 0

        summary = json.loads(capture_summary())
        assert "packet_type_counts" in summary

        close_capture()

    def test_list_devices_and_connections(self):
        import json
        from bluespy_mcp.server import load_capture, list_devices, list_connections, close_capture

        load_capture(str(CAPTURE_5SEC))

        devices = json.loads(list_devices())
        assert devices["count"] > 0
        assert len(devices["devices"]) > 0

        connections = json.loads(list_connections())
        assert isinstance(connections["connections"], list)

        close_capture()

    def test_search_packets(self):
        import json
        from bluespy_mcp.server import load_capture, search_packets, close_capture

        load_capture(str(CAPTURE_5SEC))

        result = json.loads(search_packets(packet_type="ADV_IND", max_results=5))
        assert "packets" in result

        close_capture()

    def test_list_captures_finds_fixtures(self):
        import json
        from bluespy_mcp.server import list_captures

        result = json.loads(list_captures(str(FIXTURES_DIR)))
        assert result["count"] >= 2  # We have at least 2 fixture files


class TestHardwareIntegration:
    """Integration tests requiring BlueSPY hardware.

    Run with: pytest tests/ -v -m hardware
    """

    def test_discover_finds_device(self):
        from bluespy_mcp.hardware import HardwareManager
        mgr = HardwareManager()
        result = mgr.discover()
        assert len(result["serials"]) > 0

    def test_connect_and_disconnect(self):
        from bluespy_mcp.hardware import HardwareManager, HardwareState
        mgr = HardwareManager()
        try:
            mgr.connect()
            assert mgr.state == HardwareState.CONNECTED
        finally:
            mgr.disconnect()
            assert mgr.state == HardwareState.IDLE

    def test_capture_5_seconds(self, tmp_path):
        from bluespy_mcp.hardware import HardwareManager, HardwareState
        mgr = HardwareManager()
        try:
            mgr.connect()
            result = mgr.start_capture(
                filename=str(tmp_path / "test.pcapng"),
                duration_seconds=5,
                LE=True,
            )
            assert result["timed"] is True
            assert result["packet_count"] >= 0
        finally:
            mgr.disconnect()

    def test_manual_start_stop(self, tmp_path):
        from bluespy_mcp.hardware import HardwareManager, HardwareState
        import time
        mgr = HardwareManager()
        try:
            mgr.connect()
            mgr.start_capture(
                filename=str(tmp_path / "manual.pcapng"),
                LE=True,
            )
            assert mgr.state == HardwareState.CAPTURING
            time.sleep(3)
            result = mgr.stop_capture()
            assert mgr.state == HardwareState.CONNECTED
            assert result["packet_count"] >= 0
            assert result["file_path"].endswith(".pcapng")
        finally:
            mgr.disconnect()
