"""Tests for hardware MCP tools in the server."""

import json
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture
def mock_hardware_mgr():
    """Create a mock HardwareManager for server tests."""
    mgr = MagicMock()
    mgr.state = MagicMock()
    mgr.state.value = "idle"
    mgr.is_hardware_active = False
    mgr.get_status.return_value = {
        "state": "idle", "serial": None,
        "capturing": False, "capture_file": None,
    }
    return mgr


class TestConnectHardware:
    def test_connect_success(self, mock_hardware_mgr):
        mock_hardware_mgr.connect.return_value = {
            "serial": -1, "connected_serials": [0x00010100]
        }
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import connect_hardware
            result = json.loads(connect_hardware())
        assert result["success"] is True

    def test_connect_rejects_when_file_loaded(self, mock_hardware_mgr):
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            with patch("bluespy_mcp.server._capture") as mock_cap:
                mock_cap.is_loaded = True
                from bluespy_mcp.server import connect_hardware
                result = json.loads(connect_hardware())
        assert "error" in result


class TestStartCapture:
    def test_start_success(self, mock_hardware_mgr):
        mock_hardware_mgr.start_capture.return_value = {
            "file_path": "/tmp/test.pcapng", "capturing": True
        }
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import start_capture
            result = json.loads(start_capture())
        assert result["success"] is True


class TestStopCapture:
    def test_stop_success(self, mock_hardware_mgr):
        mock_hardware_mgr.stop_capture.return_value = {
            "file_path": "/tmp/test.pcapng",
            "packet_count": 150,
            "duration_seconds": 5.2,
        }
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import stop_capture
            result = json.loads(stop_capture())
        assert result["success"] is True
        assert result["packet_count"] == 150


class TestDisconnectHardware:
    def test_disconnect_success(self, mock_hardware_mgr):
        mock_hardware_mgr.disconnect.return_value = {"disconnected": True}
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import disconnect_hardware
            result = json.loads(disconnect_hardware())
        assert result["success"] is True

    def test_disconnect_not_connected(self, mock_hardware_mgr):
        mock_hardware_mgr.disconnect.side_effect = RuntimeError("Not connected")
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import disconnect_hardware
            result = json.loads(disconnect_hardware())
        assert result["success"] is False


class TestHardwareStatus:
    def test_returns_status(self, mock_hardware_mgr):
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import hardware_status
            result = json.loads(hardware_status())
        assert result["state"] == "idle"


class TestAnalysisToolGuards:
    """Test that analysis tools work in CAPTURING state but reject CONNECTED."""

    def test_capture_summary_rejects_when_idle(self, mock_hardware_mgr):
        """Analysis tools reject when no data is available."""
        from bluespy_mcp.hardware import HardwareState
        mock_hardware_mgr.state = HardwareState.IDLE
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import capture_summary
            result = json.loads(capture_summary())
        assert "error" in result

    def test_capture_summary_rejects_when_connected_not_capturing(self, mock_hardware_mgr):
        """Analysis tools should reject CONNECTED state (no data yet)."""
        from bluespy_mcp.hardware import HardwareState
        mock_hardware_mgr.state = HardwareState.CONNECTED
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import capture_summary
            result = json.loads(capture_summary())
        assert "error" in result

    def test_list_devices_works_in_capturing_state(self, mock_hardware_mgr):
        """Analysis tools should work during live capture (CAPTURING state)."""
        from bluespy_mcp.hardware import HardwareState
        mock_hardware_mgr.state = HardwareState.CAPTURING
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            # This verifies the guard passes — the actual analysis
            # may still error on mock data, but the guard check passes
            from bluespy_mcp.server import _data_available
            assert _data_available() is True

    def test_analysis_works_with_file_loaded(self, mock_hardware_mgr):
        """Analysis tools should work when a file is loaded (existing behavior)."""
        from bluespy_mcp.hardware import HardwareState
        mock_hardware_mgr.state = HardwareState.IDLE
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = True
            from bluespy_mcp.server import _data_available
            assert _data_available() is True


class TestResources:
    def test_hardware_resource(self, mock_hardware_mgr):
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import hardware_resource
            result = json.loads(hardware_resource())
        assert result["state"] == "idle"

    def test_capture_resource_no_data(self, mock_hardware_mgr):
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            with patch("bluespy_mcp.server._capture") as mock_cap:
                mock_cap.is_loaded = False
                from bluespy_mcp.server import capture_resource
                result = json.loads(capture_resource())
        assert result["mode"] == "idle"

    def test_capture_resource_live_mode(self, mock_hardware_mgr):
        from bluespy_mcp.hardware import HardwareState
        mock_hardware_mgr.state = HardwareState.CAPTURING
        mock_hardware_mgr.get_status.return_value = {
            "state": "capturing", "serial": 0x00010100,
            "capturing": True, "capture_file": "/tmp/live.pcapng",
        }
        mock_hardware_mgr.get_packet_count.return_value = 42
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import capture_resource
            result = json.loads(capture_resource())
        assert result["mode"] == "live"
        assert result["packet_count"] == 42

    def test_capture_resource_file_mode(self, mock_hardware_mgr):
        from bluespy_mcp.hardware import HardwareState
        mock_hardware_mgr.state = HardwareState.IDLE
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = True
            mock_cap.get_metadata.return_value = {
                "file_path": "/tmp/saved.pcapng", "packet_count": 300
            }
            from bluespy_mcp.server import capture_resource
            result = json.loads(capture_resource())
        assert result["mode"] == "file"

    def test_hardware_resource_when_capturing(self, mock_hardware_mgr):
        mock_hardware_mgr.get_status.return_value = {
            "state": "capturing", "serial": 0x00010100,
            "capturing": True, "capture_file": "/tmp/live.pcapng",
            "capture_elapsed_seconds": 12.5,
        }
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import hardware_resource
            result = json.loads(hardware_resource())
        assert result["capturing"] is True
        assert result["capture_elapsed_seconds"] == 12.5


class TestPromptTemplates:
    """Test prompt templates render with correct arguments."""

    def test_analyze_capture_includes_file_path(self):
        from bluespy_mcp.server import analyze_capture
        result = analyze_capture(file_path="/tmp/test.pcapng")
        assert "/tmp/test.pcapng" in result
        assert "load_capture" in result
        assert "capture_summary" in result

    def test_quick_capture_includes_duration(self):
        from bluespy_mcp.server import quick_capture
        result = quick_capture(duration_seconds="30")
        assert "30" in result
        assert "connect_hardware" in result
        assert "start_capture" in result

    def test_quick_capture_default_duration(self):
        from bluespy_mcp.server import quick_capture
        result = quick_capture()
        assert "10" in result

    def test_debug_connection_includes_file_path(self):
        from bluespy_mcp.server import debug_connection
        result = debug_connection(file_path="/tmp/debug.pcapng")
        assert "/tmp/debug.pcapng" in result
        assert "list_connections" in result
        assert "inspect_connection" in result
        assert "find_capture_errors" in result


class TestLiveAnalysisRouting:
    """Test that analysis tools route through hardware worker during live capture."""

    @pytest.fixture
    def capturing_hw(self):
        """HardwareManager mock in CAPTURING state."""
        from bluespy_mcp.hardware import HardwareState
        mgr = MagicMock()
        mgr.state = HardwareState.CAPTURING
        return mgr

    @pytest.fixture
    def idle_hw(self):
        """HardwareManager mock in IDLE state."""
        from bluespy_mcp.hardware import HardwareState
        mgr = MagicMock()
        mgr.state = HardwareState.IDLE
        return mgr

    def test_capture_summary_routes_to_hardware(self, capturing_hw):
        capturing_hw.get_summary.return_value = {
            "packet_count": 42, "duration": 5.0, "devices": 3,
        }
        with patch("bluespy_mcp.server._hardware", capturing_hw), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import capture_summary
            result = json.loads(capture_summary())
        capturing_hw.get_summary.assert_called_once()
        assert result["packet_count"] == 42

    def test_search_packets_routes_to_hardware(self, capturing_hw):
        capturing_hw.get_packets.return_value = {
            "count": 2, "packets": [{"id": 1}, {"id": 2}],
        }
        with patch("bluespy_mcp.server._hardware", capturing_hw), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import search_packets
            result = json.loads(search_packets(channel=37))
        capturing_hw.get_packets.assert_called_once_with(
            summary_contains=None, packet_type=None, channel=37, max_results=100,
        )
        assert result["count"] == 2

    def test_list_devices_routes_to_hardware(self, capturing_hw):
        capturing_hw.get_devices.return_value = {
            "count": 1, "devices": [{"address": "AA:BB:CC:DD:EE:FF"}],
        }
        with patch("bluespy_mcp.server._hardware", capturing_hw), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import list_devices
            result = json.loads(list_devices())
        capturing_hw.get_devices.assert_called_once()
        assert result["count"] == 1

    def test_list_connections_routes_to_hardware(self, capturing_hw):
        capturing_hw.get_connections.return_value = {
            "count": 1, "connections": [{"handle": 0x0040}],
        }
        with patch("bluespy_mcp.server._hardware", capturing_hw), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import list_connections
            result = json.loads(list_connections())
        capturing_hw.get_connections.assert_called_once()
        assert result["count"] == 1

    def test_find_errors_routes_to_hardware(self, capturing_hw):
        capturing_hw.get_errors.return_value = {
            "count": 0, "errors": [],
        }
        with patch("bluespy_mcp.server._hardware", capturing_hw), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import find_capture_errors
            result = json.loads(find_capture_errors())
        capturing_hw.get_errors.assert_called_once_with(max_results=100)
        assert result["count"] == 0

    def test_file_analysis_still_works(self, idle_hw):
        """When hw is IDLE and a file is loaded, use existing capture path."""
        with patch("bluespy_mcp.server._hardware", idle_hw), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = True
            mock_cap.get_devices.return_value = {
                "count": 1,
                "devices": [{"address": "11:22:33:44:55:66"}],
            }
            from bluespy_mcp.server import list_devices
            result = json.loads(list_devices())
        mock_cap.get_devices.assert_called_once()
        idle_hw.get_devices.assert_not_called()
        assert result["count"] == 1

    def test_inspect_connection_routes_to_hardware(self, capturing_hw):
        capturing_hw.inspect_connection_live.return_value = {
            "index": 0, "summary": "Connection 0xABCD",
            "packet_type_counts": {"ATT": 5, "LE_DATA": 10},
        }
        with patch("bluespy_mcp.server._hardware", capturing_hw), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import inspect_connection
            result = json.loads(inspect_connection(connection_index=1))
        capturing_hw.inspect_connection_live.assert_called_once_with(1)
        assert result["packet_type_counts"]["ATT"] == 5

    def test_inspect_advertising_routes_to_hardware(self, capturing_hw):
        capturing_hw.inspect_advertising_live.return_value = {
            "address": "AA:BB:CC:DD:EE:FF", "advertisement_count": 42,
            "channels_used": [37, 38, 39],
        }
        with patch("bluespy_mcp.server._hardware", capturing_hw), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            from bluespy_mcp.server import inspect_advertising
            result = json.loads(inspect_advertising(device_index=2))
        capturing_hw.inspect_advertising_live.assert_called_once_with(2)
        assert result["advertisement_count"] == 42
        assert result["address"] == "AA:BB:CC:DD:EE:FF"


class TestLiveAnalysisEndToEnd:
    """End-to-end test simulating the full live capture + analysis flow."""

    def test_full_live_analysis_flow(self):
        from bluespy_mcp.hardware import HardwareState
        from bluespy_mcp.server import (
            connect_hardware,
            start_capture,
            capture_summary,
            search_packets,
            stop_capture,
        )

        mgr = MagicMock()

        # Phase 1: Connect hardware (IDLE → CONNECTED)
        mgr.state = HardwareState.IDLE
        mgr.connect.return_value = {
            "serial": -1, "connected_serials": [0x00010100],
        }
        with patch("bluespy_mcp.server._hardware", mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            result = json.loads(connect_hardware())
        assert result["success"] is True
        mgr.connect.assert_called_once()

        # Phase 2: Start capture (CONNECTED → CAPTURING)
        mgr.state = HardwareState.CONNECTED
        mgr.start_capture.return_value = {
            "file_path": "/tmp/live-test.pcapng", "capturing": True,
        }
        with patch("bluespy_mcp.server._hardware", mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            result = json.loads(start_capture())
        assert result["success"] is True
        assert result["capturing"] is True
        mgr.start_capture.assert_called_once()

        # Phase 3: Query capture summary (CAPTURING state)
        mgr.state = HardwareState.CAPTURING
        mgr.get_summary.return_value = {
            "packet_count": 1500,
            "duration": 12.3,
            "devices": 5,
            "type_counts": {
                "ADV_IND": 800,
                "CONNECT_IND": 50,
                "DATA": 650,
            },
        }
        with patch("bluespy_mcp.server._hardware", mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            result = json.loads(capture_summary())
        assert result["packet_count"] == 1500
        assert result["type_counts"]["ADV_IND"] == 800
        mgr.get_summary.assert_called_once()

        # Phase 4: Search packets by channel (CAPTURING state)
        mgr.get_packets.return_value = {
            "count": 3,
            "packets": [
                {"id": 10, "channel": 37, "type": "ADV_IND"},
                {"id": 25, "channel": 37, "type": "ADV_IND"},
                {"id": 42, "channel": 37, "type": "SCAN_REQ"},
            ],
        }
        with patch("bluespy_mcp.server._hardware", mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            result = json.loads(search_packets(channel=37))
        assert result["count"] == 3
        assert all(p["channel"] == 37 for p in result["packets"])
        mgr.get_packets.assert_called_once_with(
            summary_contains=None, packet_type=None, channel=37, max_results=100,
        )

        # Phase 5: Stop capture
        mgr.stop_capture.return_value = {
            "file_path": "/tmp/live-test.pcapng",
            "packet_count": 1500,
            "duration_seconds": 12.3,
        }
        with patch("bluespy_mcp.server._hardware", mgr), \
             patch("bluespy_mcp.server._capture") as mock_cap:
            mock_cap.is_loaded = False
            result = json.loads(stop_capture())
        assert result["success"] is True
        assert result["packet_count"] == 1500
        mgr.stop_capture.assert_called_once()
