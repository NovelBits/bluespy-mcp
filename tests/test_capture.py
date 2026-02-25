"""Tests for CaptureManager."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from bluespy_mcp.capture import CaptureManager


class TestCaptureManagerInit:
    def test_starts_not_loaded(self):
        mgr = CaptureManager()
        assert not mgr.is_loaded
        assert mgr.file_path is None


class TestLoad:
    def test_rejects_nonexistent_file(self):
        mgr = CaptureManager()
        with pytest.raises(FileNotFoundError, match="not found"):
            mgr.load("/nonexistent/file.pcapng")

    def test_rejects_non_pcapng(self, tmp_path):
        bad_file = tmp_path / "test.txt"
        bad_file.write_text("not a capture")
        mgr = CaptureManager()
        with pytest.raises(ValueError, match=".pcapng"):
            mgr.load(str(bad_file))

    def test_rejects_when_no_bluespy(self, tmp_path):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", side_effect=ImportError("no dylib")):
            with pytest.raises(ImportError, match="no dylib"):
                mgr.load(str(pcapng))

    def test_loads_valid_file(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)

        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            result = mgr.load(str(pcapng))

        assert mgr.is_loaded
        assert result["packet_count"] == 10
        assert "file_path" in result

    def test_auto_closes_previous_file(self, tmp_path, mock_bluespy):
        file1 = tmp_path / "first.pcapng"
        file2 = tmp_path / "second.pcapng"
        file1.write_bytes(b"\x00" * 100)
        file2.write_bytes(b"\x00" * 100)

        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(file1))
            mgr.load(str(file2))

        assert "second.pcapng" in str(mgr.file_path)
        assert mock_bluespy.close_file.call_count == 1  # closed first file


class TestClose:
    def test_close_when_not_loaded(self):
        mgr = CaptureManager()
        mgr.close()  # Should not raise
        assert not mgr.is_loaded

    def test_close_resets_state(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)

        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(pcapng))
            mgr.close()

        assert not mgr.is_loaded
        assert mgr.file_path is None


class TestMetadata:
    def test_get_metadata(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)

        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(pcapng))
            meta = mgr.get_metadata()

        assert meta["packet_count"] == 10
        assert meta["device_count"] == 1
        assert meta["connection_count"] == 1
        assert "duration_ns" in meta

    def test_metadata_requires_loaded(self):
        mgr = CaptureManager()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.get_metadata()


class TestContextManager:
    def test_context_manager_closes(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)

        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            with CaptureManager() as mgr:
                mgr.load(str(pcapng))
                assert mgr.is_loaded
            assert not mgr.is_loaded
