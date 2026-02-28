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


class TestDiscoverHardware:
    def test_returns_serials(self, mock_hardware_mgr):
        mock_hardware_mgr.discover.return_value = {"serials": [0x00010100]}
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import discover_hardware
            result = json.loads(discover_hardware())
        assert result["serials"] == [0x00010100]

    def test_handles_error(self, mock_hardware_mgr):
        from bluespy_mcp.hardware import HardwareError
        mock_hardware_mgr.discover.side_effect = HardwareError("No devices")
        with patch("bluespy_mcp.server._hardware", mock_hardware_mgr):
            from bluespy_mcp.server import discover_hardware
            result = json.loads(discover_hardware())
        assert "error" in result


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
