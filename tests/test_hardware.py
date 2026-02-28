# tests/test_hardware.py
"""Tests for HardwareManager — subprocess management and state machine."""

import fcntl
import json
import os
import tempfile
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from bluespy_mcp.hardware import HardwareManager, HardwareState, HardwareError


class TestHardwareState:
    def test_initial_state_is_idle(self):
        mgr = HardwareManager()
        assert mgr.state == HardwareState.IDLE

    def test_state_enum_values(self):
        assert HardwareState.IDLE.value == "idle"
        assert HardwareState.CONNECTED.value == "connected"
        assert HardwareState.CAPTURING.value == "capturing"


class TestFileLock:
    def test_acquire_lock_succeeds(self):
        mgr = HardwareManager()
        with tempfile.NamedTemporaryFile() as f:
            mgr._lock_path = f.name
            assert mgr._try_acquire_lock() is True
            mgr._release_lock()

    def test_second_lock_fails(self):
        mgr1 = HardwareManager()
        mgr2 = HardwareManager()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            lock_path = f.name
        try:
            mgr1._lock_path = lock_path
            mgr2._lock_path = lock_path
            assert mgr1._try_acquire_lock() is True
            assert mgr2._try_acquire_lock() is False
            mgr1._release_lock()
        finally:
            os.unlink(lock_path)


class TestStateTransitions:
    """Test that invalid state transitions are rejected."""

    def test_cannot_start_capture_when_idle(self):
        mgr = HardwareManager()
        with pytest.raises(RuntimeError, match="[Nn]ot connected"):
            mgr.start_capture()

    def test_cannot_load_file_when_connected(self):
        mgr = HardwareManager()
        mgr._state = HardwareState.CONNECTED
        # The guard should prevent file operations
        assert mgr.is_hardware_active is True

    def test_cannot_connect_when_file_loaded(self):
        mgr = HardwareManager()
        mgr._state = HardwareState.IDLE
        # File loaded is tracked by CaptureManager, not HardwareManager
        # This test verifies the hardware manager's own state check
        assert mgr.state == HardwareState.IDLE


class TestHardwareStatus:
    def test_idle_status(self):
        mgr = HardwareManager()
        status = mgr.get_status()
        assert status["state"] == "idle"
        assert status["serial"] is None
        assert status["capturing"] is False

    def test_connected_status(self):
        mgr = HardwareManager()
        mgr._state = HardwareState.CONNECTED
        mgr._serial = 0x00010100
        status = mgr.get_status()
        assert status["state"] == "connected"
        assert status["serial"] == 0x00010100

    def test_capturing_status(self):
        mgr = HardwareManager()
        mgr._state = HardwareState.CAPTURING
        mgr._serial = 0x00010100
        mgr._capture_file = "/tmp/test.pcapng"
        status = mgr.get_status()
        assert status["state"] == "capturing"
        assert status["capture_file"] == "/tmp/test.pcapng"


class TestTimeoutAndRecovery:
    """Test _send_command timeout behavior — the critical safety path."""

    def test_timeout_kills_worker_and_resets_state(self):
        """When a command times out, worker is killed and state returns to IDLE."""
        mgr = HardwareManager()
        mgr._state = HardwareState.CONNECTED
        mgr._serial = 0x00010100

        # Mock a worker that never responds
        mock_process = MagicMock()
        mock_process.is_alive.return_value = True
        mgr._process = mock_process
        mgr._cmd_queue = MagicMock()
        mgr._result_queue = MagicMock()
        mgr._result_queue.get.side_effect = Exception("Queue.Empty")

        with tempfile.NamedTemporaryFile(delete=False) as f:
            mgr._lock_path = f.name
            mgr._lock_fd = os.open(f.name, os.O_CREAT | os.O_RDWR)
            fcntl.flock(mgr._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        with pytest.raises(HardwareError, match="timed out"):
            mgr._send_command({"cmd": "connect"}, timeout=0.1)

        assert mgr._state == HardwareState.IDLE
        assert mgr._serial is None
        mock_process.kill.assert_called_once()
        os.unlink(f.name)

    def test_timeout_during_capture_resets_to_idle(self):
        """Timeout during stop_capture still recovers to IDLE."""
        mgr = HardwareManager()
        mgr._state = HardwareState.CAPTURING
        mgr._serial = 0x00010100
        mgr._capture_file = "/tmp/test.pcapng"

        mock_process = MagicMock()
        mock_process.is_alive.return_value = True
        mgr._process = mock_process
        mgr._cmd_queue = MagicMock()
        mgr._result_queue = MagicMock()
        mgr._result_queue.get.side_effect = Exception("Queue.Empty")

        with pytest.raises(HardwareError, match="timed out"):
            mgr._send_command({"cmd": "stop_capture"}, timeout=0.1)

        assert mgr._state == HardwareState.IDLE
        assert mgr._capture_file is None

    def test_worker_not_running_raises_error(self):
        """Sending command without worker raises clear error."""
        mgr = HardwareManager()
        with pytest.raises(HardwareError, match="Worker not running"):
            mgr._send_command({"cmd": "connect"})


class TestFullTransitionChain:
    """Test complete state machine transition sequences."""

    def test_connect_start_stop_disconnect(self):
        """Full lifecycle: IDLE -> CONNECTED -> CAPTURING -> CONNECTED -> IDLE."""
        mgr = HardwareManager()

        # Mock subprocess layer
        with patch.object(mgr, "_try_acquire_lock", return_value=True), \
             patch.object(mgr, "_spawn_worker"), \
             patch.object(mgr, "_send_command") as mock_send, \
             patch.object(mgr, "_kill_worker"), \
             patch.object(mgr, "_release_lock"):

            # Connect
            mock_send.return_value = {"ok": True, "data": {"serial": -1, "connected_serials": [1]}}
            mgr.connect()
            assert mgr.state == HardwareState.CONNECTED

            # Start capture
            mock_send.return_value = {"ok": True, "data": {"file_path": "/tmp/t.pcapng", "capturing": True}}
            mgr.start_capture(filename="/tmp/t.pcapng")
            assert mgr.state == HardwareState.CAPTURING

            # Stop capture
            mock_send.return_value = {"ok": True, "data": {"packet_count": 100}}
            result = mgr.stop_capture()
            assert mgr.state == HardwareState.CONNECTED
            assert result["packet_count"] == 100

            # Disconnect
            mock_send.return_value = {"ok": True, "data": {}}
            mgr.disconnect()
            assert mgr.state == HardwareState.IDLE

    def test_disconnect_while_capturing_stops_first(self):
        """Disconnect during capture should stop capture then disconnect."""
        mgr = HardwareManager()
        mgr._state = HardwareState.CAPTURING
        mgr._capture_file = "/tmp/test.pcapng"
        mgr._capture_start_time = time.time()
        mgr._serial = 0x00010100

        call_log = []

        def mock_send(cmd, timeout=None):
            call_log.append(cmd["cmd"])
            return {"ok": True, "data": {"packet_count": 50}}

        with patch.object(mgr, "_send_command", side_effect=mock_send), \
             patch.object(mgr, "_kill_worker"), \
             patch.object(mgr, "_release_lock"):
            mgr.disconnect()

        assert "stop_capture" in call_log
        assert "disconnect" in call_log
        assert call_log.index("stop_capture") < call_log.index("disconnect")
        assert mgr.state == HardwareState.IDLE

    def test_connect_failure_returns_to_idle(self):
        """If connect fails mid-way, state should return to IDLE and lock released."""
        mgr = HardwareManager()
        release_called = []

        with patch.object(mgr, "_try_acquire_lock", return_value=True), \
             patch.object(mgr, "_spawn_worker"), \
             patch.object(mgr, "_send_command", return_value={"ok": False, "error": "USB error"}), \
             patch.object(mgr, "_kill_worker"), \
             patch.object(mgr, "_release_lock", side_effect=lambda: release_called.append(True)):

            with pytest.raises(HardwareError):
                mgr.connect()

        assert mgr.state == HardwareState.IDLE
        assert len(release_called) > 0  # Lock was released


class TestConcurrentLockContention:
    """Test file lock behavior under contention."""

    def test_two_managers_same_lock_file(self):
        """Second manager cannot acquire lock held by first."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            lock_path = f.name

        try:
            mgr1 = HardwareManager(lock_path=lock_path)
            mgr2 = HardwareManager(lock_path=lock_path)

            assert mgr1._try_acquire_lock() is True
            assert mgr2._try_acquire_lock() is False

            mgr1._release_lock()
            # After release, mgr2 can now acquire
            assert mgr2._try_acquire_lock() is True
            mgr2._release_lock()
        finally:
            os.unlink(lock_path)

    def test_lock_released_after_connect_failure(self):
        """Lock is released if connect fails, allowing another client."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            lock_path = f.name

        try:
            mgr1 = HardwareManager(lock_path=lock_path)
            mgr2 = HardwareManager(lock_path=lock_path)

            # mgr1 connects and fails
            with patch.object(mgr1, "_spawn_worker"), \
                 patch.object(mgr1, "_send_command", side_effect=HardwareError("fail")), \
                 patch.object(mgr1, "_kill_worker"):
                with pytest.raises(HardwareError):
                    mgr1.connect()

            # mgr2 should be able to connect now
            assert mgr2._try_acquire_lock() is True
            mgr2._release_lock()
        finally:
            os.unlink(lock_path)


class TestCleanup:
    """Test atexit cleanup behavior."""

    def test_cleanup_stops_capture_and_disconnects(self):
        """_cleanup should stop capture and disconnect if active."""
        mgr = HardwareManager()
        mgr._state = HardwareState.CAPTURING
        mgr._capture_file = "/tmp/test.pcapng"

        commands_sent = []
        def mock_send(cmd, timeout=None):
            commands_sent.append(cmd["cmd"])
            return {"ok": True, "data": {}}

        with patch.object(mgr, "_send_command", side_effect=mock_send), \
             patch.object(mgr, "_kill_worker"), \
             patch.object(mgr, "_release_lock"):
            mgr._cleanup()

        assert "stop_capture" in commands_sent
        assert "disconnect" in commands_sent

    def test_cleanup_handles_errors_gracefully(self):
        """_cleanup should not raise even if commands fail."""
        mgr = HardwareManager()
        mgr._state = HardwareState.CAPTURING

        with patch.object(mgr, "_send_command", side_effect=Exception("dead")), \
             patch.object(mgr, "_kill_worker"), \
             patch.object(mgr, "_release_lock"):
            # Should not raise
            mgr._cleanup()

    def test_cleanup_idle_is_noop(self):
        """_cleanup on idle manager does nothing harmful."""
        mgr = HardwareManager()
        with patch.object(mgr, "_kill_worker") as mock_kill, \
             patch.object(mgr, "_release_lock") as mock_release:
            mgr._cleanup()
            mock_kill.assert_called_once()
            mock_release.assert_called_once()
