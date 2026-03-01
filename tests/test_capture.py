"""Tests for CaptureManager (worker-subprocess based)."""

from pathlib import Path
from unittest.mock import patch, MagicMock, call

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

    def test_loads_valid_file(self, tmp_path):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)

        mgr = CaptureManager()
        with patch.object(mgr, "_spawn_worker") as mock_spawn, \
             patch.object(mgr, "_send_command") as mock_send, \
             patch.object(mgr, "_kill_worker"):
            mock_send.return_value = {"ok": True, "data": {"packet_count": 10}}
            result = mgr.load(str(pcapng))

        assert mgr.is_loaded
        assert result["packet_count"] == 10
        assert "file_path" in result
        mock_spawn.assert_called_once()
        mock_send.assert_called_once()
        cmd = mock_send.call_args[0][0]
        assert cmd["cmd"] == "load_file"

    def test_auto_closes_previous_file(self, tmp_path):
        file1 = tmp_path / "first.pcapng"
        file2 = tmp_path / "second.pcapng"
        file1.write_bytes(b"\x00" * 100)
        file2.write_bytes(b"\x00" * 100)

        mgr = CaptureManager()
        with patch.object(mgr, "_spawn_worker"), \
             patch.object(mgr, "_send_command") as mock_send, \
             patch.object(mgr, "_kill_worker"):
            mock_send.return_value = {"ok": True, "data": {"packet_count": 10}}
            mgr.load(str(file1))

            # close() will send close_file + shutdown commands
            mock_send.reset_mock()
            mock_send.return_value = {"ok": True, "data": {"packet_count": 5}}
            mgr.load(str(file2))

        assert "second.pcapng" in str(mgr.file_path)

    def test_worker_load_failure_kills_worker(self, tmp_path):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)

        mgr = CaptureManager()
        with patch.object(mgr, "_spawn_worker"), \
             patch.object(mgr, "_send_command") as mock_send, \
             patch.object(mgr, "_kill_worker") as mock_kill:
            mock_send.return_value = {"ok": False, "error": "corrupt file"}
            with pytest.raises(RuntimeError, match="corrupt file"):
                mgr.load(str(pcapng))
            mock_kill.assert_called()
        assert not mgr.is_loaded


class TestClose:
    def test_close_when_not_loaded(self):
        mgr = CaptureManager()
        mgr.close()  # Should not raise
        assert not mgr.is_loaded

    def test_close_resets_state(self, tmp_path):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)

        mgr = CaptureManager()
        with patch.object(mgr, "_spawn_worker"), \
             patch.object(mgr, "_send_command") as mock_send, \
             patch.object(mgr, "_kill_worker"):
            mock_send.return_value = {"ok": True, "data": {"packet_count": 10}}
            mgr.load(str(pcapng))
            mgr.close()

        assert not mgr.is_loaded
        assert mgr.file_path is None


class TestMetadata:
    def _make_loaded_mgr(self, tmp_path):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch.object(mgr, "_spawn_worker"), \
             patch.object(mgr, "_send_command") as mock_send, \
             patch.object(mgr, "_kill_worker"):
            mock_send.return_value = {"ok": True, "data": {"packet_count": 10}}
            mgr.load(str(pcapng))
        return mgr

    def test_get_metadata(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        meta_data = {
            "packet_count": 10,
            "device_count": 1,
            "connection_count": 1,
            "duration_ns": 4000000,
        }
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": True, "data": meta_data}
            meta = mgr.get_metadata()

        assert meta["packet_count"] == 10
        assert meta["device_count"] == 1
        assert meta["connection_count"] == 1
        assert "duration_ns" in meta
        # file_path and file_size_bytes added by get_metadata
        assert "file_path" in meta

    def test_metadata_requires_loaded(self):
        mgr = CaptureManager()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.get_metadata()


class TestAnalysisMethods:
    """Test that analysis methods delegate to worker correctly."""

    def _make_loaded_mgr(self, tmp_path):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch.object(mgr, "_spawn_worker"), \
             patch.object(mgr, "_send_command") as mock_send, \
             patch.object(mgr, "_kill_worker"):
            mock_send.return_value = {"ok": True, "data": {"packet_count": 10}}
            mgr.load(str(pcapng))
        return mgr

    def test_get_summary(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": True, "data": {"packet_count": 10}}
            result = mgr.get_summary()
        assert result["packet_count"] == 10
        cmd = mock_send.call_args[0][0]
        assert cmd["cmd"] == "get_summary"

    def test_search_packets(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": True, "data": {"packets": [], "count": 0}}
            result = mgr.search_packets(summary_contains="ATT", channel=5)
        cmd = mock_send.call_args[0][0]
        assert cmd["cmd"] == "get_packets"
        assert cmd["summary_contains"] == "ATT"
        assert cmd["channel"] == 5

    def test_get_devices(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": True, "data": {"devices": [], "count": 0}}
            result = mgr.get_devices()
        assert result["count"] == 0

    def test_get_connections(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": True, "data": {"connections": [], "count": 0}}
            result = mgr.get_connections()
        assert result["count"] == 0

    def test_get_errors(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": True, "data": {"errors": [], "count": 0}}
            result = mgr.get_errors(max_results=50)
        cmd = mock_send.call_args[0][0]
        assert cmd["max_results"] == 50

    def test_inspect_connection(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": True, "data": {"summary": "test"}}
            result = mgr.inspect_connection(connection_index=2)
        cmd = mock_send.call_args[0][0]
        assert cmd["cmd"] == "inspect_connection"
        assert cmd["connection_index"] == 2

    def test_inspect_advertising(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": True, "data": {"address": "AA:BB"}}
            result = mgr.inspect_advertising(device_index=1)
        cmd = mock_send.call_args[0][0]
        assert cmd["cmd"] == "inspect_advertising"
        assert cmd["device_index"] == 1

    def test_worker_error_raises(self, tmp_path):
        mgr = self._make_loaded_mgr(tmp_path)
        with patch.object(mgr, "_send_command") as mock_send:
            mock_send.return_value = {"ok": False, "error": "analysis failed"}
            with pytest.raises(RuntimeError, match="analysis failed"):
                mgr.get_summary()

    def test_all_methods_require_loaded(self):
        mgr = CaptureManager()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.get_summary()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.search_packets()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.get_devices()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.get_connections()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.get_errors()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.inspect_connection()
        with pytest.raises(RuntimeError, match="No capture"):
            mgr.inspect_advertising()


class TestContextManager:
    def test_context_manager_closes(self, tmp_path):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)

        with CaptureManager() as mgr:
            with patch.object(mgr, "_spawn_worker"), \
                 patch.object(mgr, "_send_command") as mock_send, \
                 patch.object(mgr, "_kill_worker"):
                mock_send.return_value = {"ok": True, "data": {"packet_count": 10}}
                mgr.load(str(pcapng))
                assert mgr.is_loaded
        assert not mgr.is_loaded
