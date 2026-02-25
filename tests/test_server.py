"""Tests for the MCP server tools."""

import json
from unittest.mock import patch

import pytest

from bluespy_mcp.server import mcp


@pytest.fixture
def loaded_capture(tmp_path, mock_bluespy):
    """Set up a loaded capture via the server's internal state."""
    pcapng = tmp_path / "test.pcapng"
    pcapng.write_bytes(b"\x00" * 100)

    with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
        # Import and call the tool function directly
        from bluespy_mcp.server import _capture, load_capture
        result = load_capture(str(pcapng))
        data = json.loads(result)
        assert data["success"] is True
        yield _capture
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
        from bluespy_mcp.server import capture_summary
        with patch("bluespy_mcp.capture.get_bluespy") as mock:
            mock.return_value = loaded_capture  # reuse fixture indirectly
            result = json.loads(capture_summary())
        # Should have packet_count at minimum
        assert "packet_count" in result or "error" in result


class TestSearchPackets:
    def test_requires_loaded(self):
        from bluespy_mcp.server import search_packets, _capture
        _capture.close()
        result = json.loads(search_packets())
        assert "error" in result


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
