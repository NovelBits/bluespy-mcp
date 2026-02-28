"""Tests for the hardware worker subprocess."""

import multiprocessing as mp
from unittest.mock import MagicMock, patch

import pytest


def _make_mock_bluespy():
    """Create a mock bluespy module for worker tests."""
    mock = MagicMock()
    mock.connected_morephs.return_value = [0x00010100]
    mock.connect.return_value = None
    mock.disconnect.return_value = None
    mock.reboot_moreph.return_value = None
    mock.capture.return_value = None
    mock.stop_capture.return_value = None
    mock.packets = MagicMock()
    mock.packets.__len__ = MagicMock(return_value=0)
    return mock


class TestWorkerCommands:
    """Test individual command handlers in the worker."""

    def test_connect_calls_reboot_then_connect(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        result = handle_command(mock, {"cmd": "connect", "serial": -1})
        assert result["ok"] is True
        mock.reboot_moreph.assert_called_once_with(-1)
        mock.connect.assert_called_once_with(-1)

    def test_connect_error_returns_failure(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.connect.side_effect = Exception("Device not found")
        result = handle_command(mock, {"cmd": "connect", "serial": -1})
        assert result["ok"] is False
        assert "Device not found" in result["error"]

    def test_start_capture_with_defaults(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        result = handle_command(mock, {
            "cmd": "start_capture",
            "filename": "/tmp/test.pcapng",
            "LE": True, "CL": False, "QHS": False,
            "wifi": False, "CS": False,
        })
        assert result["ok"] is True
        mock.capture.assert_called_once()
        call_kwargs = mock.capture.call_args
        assert call_kwargs[0][0] == "/tmp/test.pcapng"

    def test_start_capture_timed(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.packets.__len__ = MagicMock(return_value=42)
        with patch("bluespy_mcp.worker.time.sleep") as mock_sleep:
            result = handle_command(mock, {
                "cmd": "start_capture",
                "filename": "/tmp/test.pcapng",
                "duration_seconds": 0.1,
                "LE": True, "CL": False, "QHS": False,
                "wifi": False, "CS": False,
            })
        assert result["ok"] is True
        mock_sleep.assert_called_once_with(0.1)
        mock.stop_capture.assert_called_once()
        assert result["data"]["packet_count"] == 42

    def test_stop_capture(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.packets.__len__ = MagicMock(return_value=150)
        result = handle_command(mock, {"cmd": "stop_capture"})
        assert result["ok"] is True
        mock.stop_capture.assert_called_once()
        assert result["data"]["packet_count"] == 150

    def test_disconnect(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        result = handle_command(mock, {"cmd": "disconnect"})
        assert result["ok"] is True
        mock.disconnect.assert_called_once()

    def test_unknown_command(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        result = handle_command(mock, {"cmd": "explode"})
        assert result["ok"] is False
        assert "unknown" in result["error"].lower()

    def test_query_packet_count(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.packets.__len__ = MagicMock(return_value=99)
        result = handle_command(mock, {"cmd": "packet_count"})
        assert result["ok"] is True
        assert result["data"]["packet_count"] == 99


class TestWorkerBluespyErrors:
    """Test that BluespyError (ctypes layer) is handled, not just generic Exception."""

    def test_connect_bluespy_error(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        error = type("BluespyError", (Exception,), {})("HCI timeout")
        mock.connect.side_effect = error
        result = handle_command(mock, {"cmd": "connect", "serial": -1})
        assert result["ok"] is False
        assert "HCI timeout" in result["error"]

    def test_capture_bluespy_error(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        error = type("BluespyError", (Exception,), {})("Capture init failed")
        mock.capture.side_effect = error
        result = handle_command(mock, {
            "cmd": "start_capture",
            "filename": "/tmp/test.pcapng",
            "LE": True, "CL": False, "QHS": False,
            "wifi": False, "CS": False,
        })
        assert result["ok"] is False
        assert "Capture init failed" in result["error"]

    def test_disconnect_bluespy_error(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        error = type("BluespyError", (Exception,), {})("USB disconnect")
        mock.disconnect.side_effect = error
        result = handle_command(mock, {"cmd": "disconnect"})
        assert result["ok"] is False
        assert "USB disconnect" in result["error"]

    def test_reboot_failure_doesnt_prevent_connect(self):
        """Reboot can fail on first-ever connection. connect() should still be attempted."""
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.reboot_moreph.side_effect = Exception("Device not found for reboot")
        result = handle_command(mock, {"cmd": "connect", "serial": -1})
        assert result["ok"] is True
        mock.connect.assert_called_once_with(-1)

    def test_stop_capture_error_during_timed(self):
        """If stop_capture fails during timed capture, error is propagated."""
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.stop_capture.side_effect = Exception("Flush failed")
        with patch("bluespy_mcp.worker.time.sleep"):
            result = handle_command(mock, {
                "cmd": "start_capture",
                "filename": "/tmp/test.pcapng",
                "duration_seconds": 1.0,
                "LE": True, "CL": False, "QHS": False,
                "wifi": False, "CS": False,
            })
        assert result["ok"] is False
        assert "Flush failed" in result["error"]


class TestWorkerLoop:
    """Test the worker_loop main entry point."""

    def test_worker_loop_signals_ready(self):
        """Worker sends ready signal after loading bluespy."""
        from bluespy_mcp.worker import worker_loop

        cmd_q = mp.Queue()
        result_q = mp.Queue()
        cmd_q.put({"cmd": "shutdown"})

        with patch("bluespy_mcp.loader.get_bluespy") as mock_get:
            mock_get.return_value = _make_mock_bluespy()
            import threading
            t = threading.Thread(target=worker_loop, args=(cmd_q, result_q))
            t.start()
            t.join(timeout=5)

        ready = result_q.get(timeout=1)
        assert ready["ok"] is True
        assert ready["data"]["status"] == "ready"

    def test_worker_loop_import_failure(self):
        """If bluespy can't be loaded, worker signals failure and exits."""
        from bluespy_mcp.worker import worker_loop

        cmd_q = mp.Queue()
        result_q = mp.Queue()

        with patch("bluespy_mcp.loader.get_bluespy") as mock_get:
            mock_get.side_effect = ImportError("bluespy not found")
            import threading
            t = threading.Thread(target=worker_loop, args=(cmd_q, result_q))
            t.start()
            t.join(timeout=5)

        result = result_q.get(timeout=1)
        assert result["ok"] is False
        assert "bluespy" in result["error"].lower()

    def test_worker_loop_processes_commands(self):
        """Worker processes commands until shutdown."""
        from bluespy_mcp.worker import worker_loop

        cmd_q = mp.Queue()
        result_q = mp.Queue()
        cmd_q.put({"cmd": "connect", "serial": -1})
        cmd_q.put({"cmd": "shutdown"})

        with patch("bluespy_mcp.loader.get_bluespy") as mock_get:
            mock_bluespy = _make_mock_bluespy()
            mock_get.return_value = mock_bluespy
            import threading
            t = threading.Thread(target=worker_loop, args=(cmd_q, result_q))
            t.start()
            t.join(timeout=5)

        ready = result_q.get(timeout=1)
        assert ready["ok"] is True  # ready signal
        connect_result = result_q.get(timeout=1)
        assert connect_result["ok"] is True  # connect result
        shutdown_result = result_q.get(timeout=1)
        assert shutdown_result["data"]["status"] == "shutdown"
