"""Tests for the MCP server tools."""

import json
from unittest.mock import patch, MagicMock

import pytest

from bluespy_mcp.server import mcp


@pytest.fixture
def loaded_capture(tmp_path):
    """Set up a loaded capture via the server's internal state."""
    pcapng = tmp_path / "test.pcapng"
    pcapng.write_bytes(b"\x00" * 100)

    from bluespy_mcp.server import _capture

    # Mock the worker subprocess layer
    with patch.object(_capture, "_spawn_worker"), \
         patch.object(_capture, "_send_command") as mock_send, \
         patch.object(_capture, "_kill_worker"):
        mock_send.return_value = {"ok": True, "data": {"packet_count": 10}}

        from bluespy_mcp.server import load_capture
        result = load_capture(str(pcapng))
        data = json.loads(result)
        assert data["success"] is True

        yield mock_send

        from bluespy_mcp.server import close_capture
        close_capture()


class TestLoadCapture:
    def test_load_nonexistent(self):
        from bluespy_mcp.server import load_capture
        result = json.loads(load_capture("/nonexistent/file.pcapng"))
        assert result["success"] is False
        assert "not found" in result["error"].lower() or "error" in result

    def test_load_wrong_extension(self, tmp_path):
        bad = tmp_path / "test.txt"
        bad.write_text("nope")
        from bluespy_mcp.server import load_capture
        result = json.loads(load_capture(str(bad)))
        assert result["success"] is False


class TestCaptureSummary:
    def test_requires_loaded(self):
        from bluespy_mcp.server import capture_summary, _capture
        _capture.close()  # ensure unloaded
        result = json.loads(capture_summary())
        assert "error" in result

    def test_returns_summary(self, loaded_capture):
        mock_send = loaded_capture
        mock_send.return_value = {"ok": True, "data": {"packet_count": 10, "packet_type_counts": {}}}
        from bluespy_mcp.server import capture_summary
        result = json.loads(capture_summary())
        assert "packet_count" in result


class TestSearchPackets:
    def test_requires_loaded(self):
        from bluespy_mcp.server import search_packets, _capture
        _capture.close()
        result = json.loads(search_packets())
        assert "error" in result

    def test_returns_packets(self, loaded_capture):
        mock_send = loaded_capture
        mock_send.return_value = {"ok": True, "data": {"packets": [], "count": 0}}
        from bluespy_mcp.server import search_packets
        result = json.loads(search_packets(summary_contains="ATT"))
        assert "count" in result


class TestListDevices:
    def test_requires_loaded(self):
        from bluespy_mcp.server import list_devices, _capture
        _capture.close()
        result = json.loads(list_devices())
        assert "error" in result

    def test_returns_devices(self, loaded_capture):
        mock_send = loaded_capture
        mock_send.return_value = {"ok": True, "data": {"devices": [], "count": 0}}
        from bluespy_mcp.server import list_devices
        result = json.loads(list_devices())
        assert "count" in result


class TestListConnections:
    def test_requires_loaded(self):
        from bluespy_mcp.server import list_connections, _capture
        _capture.close()
        result = json.loads(list_connections())
        assert "error" in result

    def test_returns_connections(self, loaded_capture):
        mock_send = loaded_capture
        mock_send.return_value = {"ok": True, "data": {"connections": [], "count": 0}}
        from bluespy_mcp.server import list_connections
        result = json.loads(list_connections())
        assert "count" in result


class TestListCaptures:
    def test_lists_pcapng_files(self, tmp_path):
        (tmp_path / "a.pcapng").write_bytes(b"\x00")
        (tmp_path / "b.pcapng").write_bytes(b"\x00")
        (tmp_path / "c.txt").write_text("nope")

        from bluespy_mcp.server import list_captures
        result = json.loads(list_captures(str(tmp_path)))
        assert result["count"] == 2

    def test_nonexistent_directory(self):
        from bluespy_mcp.server import list_captures
        result = json.loads(list_captures("/nonexistent/dir"))
        assert "error" in result
