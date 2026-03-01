"""Tests for the hardware worker subprocess."""

import multiprocessing as mp
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import MockPacket, MockPackets, MockDevice, MockConnection


def _make_mock_bluespy():
    """Create a mock bluespy module for worker tests."""
    mock = MagicMock()
    mock.connected_morephs.return_value = [0x00010100]
    mock.connect.return_value = None
    mock.disconnect.return_value = None
    mock.reboot_moreph.return_value = None
    mock.capture.return_value = None
    mock.stop_capture.return_value = None
    mock.load_file.return_value = None
    mock.close_file.return_value = None
    mock.packets = MagicMock()
    mock.packets.__len__ = MagicMock(return_value=0)
    mock.devices = []
    mock.connections = []
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
        with patch("bluespy_mcp.worker.time.sleep"):
            result = handle_command(mock, {"cmd": "connect", "serial": -1})
        assert result["ok"] is False
        assert "Device not found" in result["error"]

    def test_connect_retries_on_transient_failure(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        # Fail twice, succeed on third attempt
        mock.connect.side_effect = [
            Exception("bluespy_init failed"),
            Exception("bluespy_init failed"),
            None,
        ]
        with patch("bluespy_mcp.worker.time.sleep") as mock_sleep:
            result = handle_command(mock, {"cmd": "connect", "serial": -1})
        assert result["ok"] is True
        assert mock.connect.call_count == 3
        assert mock_sleep.call_count >= 2  # slept between retries

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


class TestFileManagementCommands:
    """Test file management command handlers in the worker."""

    def test_load_file(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.packets.__len__ = MagicMock(return_value=42)
        result = handle_command(mock, {"cmd": "load_file", "path": "/tmp/test.pcapng"})
        assert result["ok"] is True
        assert result["data"]["packet_count"] == 42
        mock.load_file.assert_called_once_with("/tmp/test.pcapng")

    def test_load_file_error(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.load_file.side_effect = Exception("corrupt file")
        result = handle_command(mock, {"cmd": "load_file", "path": "/tmp/bad.pcapng"})
        assert result["ok"] is False
        assert "corrupt file" in result["error"]

    def test_close_file(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        result = handle_command(mock, {"cmd": "close_file"})
        assert result["ok"] is True
        mock.close_file.assert_called_once()

    def test_get_metadata(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        packets = [
            MockPacket(summary="ADV_IND", time=1000000, rssi=-55, channel=37),
            MockPacket(summary="CONNECT_IND", time=5000000, rssi=-52, channel=39),
        ]
        mock.packets = MockPackets(packets)
        mock.devices = [MockDevice()]
        mock.connections = [MockConnection()]

        result = handle_command(mock, {"cmd": "get_metadata"})
        assert result["ok"] is True
        data = result["data"]
        assert data["packet_count"] == 2
        assert data["device_count"] == 1
        assert data["connection_count"] == 1
        assert data["duration_ns"] == 4000000
        assert data["first_timestamp_ns"] == 1000000
        assert data["last_timestamp_ns"] == 5000000

    def test_get_metadata_empty_packets(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        mock.packets = MockPackets([])
        result = handle_command(mock, {"cmd": "get_metadata"})
        assert result["ok"] is True
        assert result["data"]["packet_count"] == 0
        assert "duration_ns" not in result["data"]


class TestWorkerBluespyErrors:
    """Test that BluespyError (ctypes layer) is handled, not just generic Exception."""

    def test_connect_bluespy_error(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_bluespy()
        error = type("BluespyError", (Exception,), {})("HCI timeout")
        mock.connect.side_effect = error
        with patch("bluespy_mcp.worker.time.sleep"):
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

    def test_worker_loop_hardware_signals_ready(self):
        """Hardware-mode worker sends ready signal after loading bluespy."""
        from bluespy_mcp.worker import worker_loop

        cmd_q = mp.Queue()
        result_q = mp.Queue()
        cmd_q.put({"cmd": "shutdown"})

        with patch("bluespy_mcp.loader.get_bluespy") as mock_get:
            mock_get.return_value = _make_mock_bluespy()
            import threading
            t = threading.Thread(target=worker_loop, args=(cmd_q, result_q, "hardware"))
            t.start()
            t.join(timeout=5)

        ready = result_q.get(timeout=1)
        assert ready["ok"] is True
        assert ready["data"]["status"] == "ready"

    def test_worker_loop_file_signals_ready(self):
        """File-mode worker sends ready signal without USB health check."""
        from bluespy_mcp.worker import worker_loop

        cmd_q = mp.Queue()
        result_q = mp.Queue()
        cmd_q.put({"cmd": "shutdown"})

        with patch("bluespy_mcp.loader.get_bluespy") as mock_get:
            mock_bs = _make_mock_bluespy()
            mock_get.return_value = mock_bs
            import threading
            t = threading.Thread(target=worker_loop, args=(cmd_q, result_q, "file"))
            t.start()
            t.join(timeout=5)

        ready = result_q.get(timeout=1)
        assert ready["ok"] is True
        # File mode should NOT call connected_morephs()
        mock_bs.connected_morephs.assert_not_called()

    def test_worker_loop_import_failure(self):
        """If bluespy can't be loaded, worker signals failure and exits."""
        from bluespy_mcp.worker import worker_loop

        cmd_q = mp.Queue()
        result_q = mp.Queue()

        with patch("bluespy_mcp.loader.get_bluespy") as mock_get:
            mock_get.side_effect = ImportError("bluespy not found")
            import threading
            t = threading.Thread(target=worker_loop, args=(cmd_q, result_q, "hardware"))
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
            t = threading.Thread(target=worker_loop, args=(cmd_q, result_q, "hardware"))
            t.start()
            t.join(timeout=5)

        ready = result_q.get(timeout=1)
        assert ready["ok"] is True  # ready signal
        connect_result = result_q.get(timeout=1)
        assert connect_result["ok"] is True  # connect result
        shutdown_result = result_q.get(timeout=1)
        assert shutdown_result["data"]["status"] == "shutdown"

    def test_worker_loop_file_mode_no_disconnect_on_shutdown(self):
        """File-mode worker does not call disconnect on shutdown."""
        from bluespy_mcp.worker import worker_loop

        cmd_q = mp.Queue()
        result_q = mp.Queue()
        cmd_q.put({"cmd": "shutdown"})

        with patch("bluespy_mcp.loader.get_bluespy") as mock_get:
            mock_bs = _make_mock_bluespy()
            mock_get.return_value = mock_bs
            import threading
            t = threading.Thread(target=worker_loop, args=(cmd_q, result_q, "file"))
            t.start()
            t.join(timeout=5)

        result_q.get(timeout=1)  # ready
        shutdown = result_q.get(timeout=1)
        assert shutdown["data"]["status"] == "shutdown"
        mock_bs.disconnect.assert_not_called()


def _make_mock_with_packets():
    """Create a mock bluespy with sample packets, devices, and connections."""
    mock = MagicMock()
    packets = [
        MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000000, rssi=-55, channel=37),
        MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1100000, rssi=-58, channel=38),
        MockPacket(summary="SCAN_REQ to AA:BB:CC:DD:EE:FF", time=1200000, rssi=-60, channel=37),
        MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000000, rssi=-52, channel=39),
        MockPacket(summary="ATT Read Request", time=3000000, rssi=-50, channel=5),
        MockPacket(summary="LL_TERMINATE_IND Reason: Remote User Terminated", time=5000000, rssi=-55, channel=5),
    ]
    mock.packets = MockPackets(packets)
    mock.devices = [MockDevice(), MockDevice(_address="11:22:33:44:55:66", _name="Other")]
    mock.connections = [MockConnection()]
    return mock


class TestLiveAnalysisCommands:
    """Test live analysis command handlers in the worker."""

    def test_get_summary_returns_counts(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_summary"})
        assert result["ok"] is True
        data = result["data"]
        assert data["packet_count"] == 6
        assert "ADV_IND" in data["packet_type_counts"]
        assert data["packet_type_counts"]["ADV_IND"] == 2
        assert len(data["devices"]) == 2
        assert len(data["connections"]) == 1

    def test_get_summary_with_limit(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_summary", "limit": 3})
        assert result["ok"] is True
        data = result["data"]
        assert data["packet_count"] == 6  # total count still full
        # Only first 3 packets classified (2 ADV_IND + 1 SCAN_REQ)
        assert sum(data["packet_type_counts"].values()) == 3
        assert "note" in data

    def test_get_packets_no_filter(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_packets"})
        assert result["ok"] is True
        assert result["data"]["count"] == 6

    def test_get_packets_channel_filter(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_packets", "channel": 37})
        assert result["ok"] is True
        # channel 37: ADV_IND #1, SCAN_REQ
        assert result["data"]["count"] == 2
        for pkt in result["data"]["packets"]:
            assert pkt["channel"] == 37

    def test_get_packets_type_filter(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_packets", "packet_type": "ADV_IND"})
        assert result["ok"] is True
        assert result["data"]["count"] == 2

    def test_get_packets_with_start(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_packets", "start": 4})
        assert result["ok"] is True
        # Packets at index 4 and 5
        assert result["data"]["count"] == 2
        assert result["data"]["packets"][0]["index"] == 4

    def test_get_devices(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_devices"})
        assert result["ok"] is True
        assert result["data"]["count"] == 2
        addresses = [d["address"] for d in result["data"]["devices"]]
        assert "AA:BB:CC:DD:EE:FF" in addresses
        assert "11:22:33:44:55:66" in addresses

    def test_get_connections(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_connections"})
        assert result["ok"] is True
        assert result["data"]["count"] == 1
        assert result["data"]["connections"][0]["summary"] != ""

    def test_get_errors(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "get_errors"})
        assert result["ok"] is True
        # LL_TERMINATE_IND matches TERMINATE keyword
        assert result["data"]["count"] == 1
        assert "TERMINATE" in result["data"]["errors"][0]["summary"]

    def test_inspect_connection(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "inspect_connection", "connection_index": 0})
        assert result["ok"] is True
        data = result["data"]
        assert "summary" in data
        assert "packet_type_counts" in data
        # ADV packets should be excluded from connection counts
        assert "ADV_IND" not in data["packet_type_counts"]

    def test_inspect_connection_no_connections(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        mock.connections = []
        result = handle_command(mock, {"cmd": "inspect_connection"})
        assert result["ok"] is True
        assert "error" in result["data"]

    def test_inspect_advertising(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        result = handle_command(mock, {"cmd": "inspect_advertising", "device_index": 0})
        assert result["ok"] is True
        data = result["data"]
        assert data["address"] == "AA:BB:CC:DD:EE:FF"
        assert data["advertisement_count"] > 0
        assert "channels_used" in data

    def test_inspect_advertising_no_devices(self):
        from bluespy_mcp.worker import handle_command

        mock = _make_mock_with_packets()
        mock.devices = []
        result = handle_command(mock, {"cmd": "inspect_advertising"})
        assert result["ok"] is True
        assert "error" in result["data"]
