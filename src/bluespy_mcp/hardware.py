# src/bluespy_mcp/hardware.py
"""Hardware management with subprocess isolation and file locking.

All bluespy hardware calls run in a child subprocess to prevent ctypes
hangs from freezing the MCP server. A file lock ensures only one MCP
client uses the hardware at a time.

Architecture overview:

    MCP Server (main process)
        │
        ├── HardwareManager (state machine: IDLE ↔ CONNECTED ↔ CAPTURING)
        │       │
        │       ├── File lock (~/.bluespy-mcp.lock) for single-client access
        │       ├── Worker subprocess (daemon) via multiprocessing.Process
        │       │       └── bluespy module (ctypes FFI to libblueSPY)
        │       └── Command/result queues for IPC
        │
        └── CaptureManager (file analysis, no hardware)

Each hardware session follows this lifecycle:

    1. connect()  → acquire lock → spawn worker → reboot device → connect
    2. capture()  → start/stop capture via worker commands
    3. disconnect() → disconnect → shutdown worker (reboot to release USB)

The worker subprocess is killed and respawned for each connect() call.
Retry logic (3 attempts, 2s delay) handles USB recovery timing between
worker process exits. See worker.py docstring for USB lifecycle details.
"""

from __future__ import annotations

import atexit
import enum
import fcntl
import logging
import multiprocessing as mp
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_LOCK_PATH = os.path.expanduser("~/.bluespy-mcp.lock")
_DEFAULT_CAPTURES_DIR = Path(os.environ.get("BLE_CAPTURES_DIR", "captures"))

# Timeouts per operation (seconds)
_TIMEOUTS = {
    "connect": 45,
    "disconnect": 5,
    "start_capture": 10,
    "stop_capture": 10,
    "packet_count": 5,
    "get_summary": 15,
    "get_packets": 10,
    "get_devices": 5,
    "get_connections": 5,
    "get_errors": 10,
    "inspect_connection": 15,
    "inspect_advertising": 15,
    "inspect_all_devices": 30,
    "inspect_all_connections": 30,
}


class HardwareState(enum.Enum):
    IDLE = "idle"
    CONNECTED = "connected"
    CAPTURING = "capturing"


class HardwareError(RuntimeError):
    """Raised when a hardware operation fails."""


class HardwareManager:
    """Manages blueSPY hardware via a worker subprocess.

    State machine:
        IDLE <-> CONNECTED <-> CAPTURING

    File lock ensures single-client access. Subprocess isolation
    prevents ctypes hangs from blocking the MCP server.
    """

    def __init__(self, lock_path: str = _DEFAULT_LOCK_PATH):
        self._state = HardwareState.IDLE
        self._serial: int | None = None
        self._capture_file: str | None = None
        self._capture_start_time: float | None = None
        self._lock_path = lock_path
        self._lock_fd: int | None = None
        self._process: mp.Process | None = None
        self._cmd_queue: mp.Queue | None = None
        self._result_queue: mp.Queue | None = None
        atexit.register(self._cleanup)

    @property
    def state(self) -> HardwareState:
        return self._state

    @property
    def is_hardware_active(self) -> bool:
        return self._state in (HardwareState.CONNECTED, HardwareState.CAPTURING)

    def _try_acquire_lock(self, force: bool = False) -> bool:
        """Try to acquire the file lock. Returns True on success.

        If force=True, removes the existing lock file first. Use this
        when a previous session crashed without releasing the lock.
        """
        if force and os.path.exists(self._lock_path):
            try:
                os.remove(self._lock_path)
                logger.info(f"Force-removed stale lock file: {self._lock_path}")
            except OSError:
                pass
        try:
            self._lock_fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR)
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (OSError, IOError):
            if self._lock_fd is not None:
                os.close(self._lock_fd)
                self._lock_fd = None
            return False

    def _release_lock(self) -> None:
        """Release the file lock."""
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            except (OSError, IOError):
                pass
            self._lock_fd = None

    def _spawn_worker(self, retries: int = 3, retry_delay: float = 2.0) -> None:
        """Spawn the hardware worker subprocess.

        Retries on failure because the USB device may need recovery time
        after a previous subprocess exits.
        """
        from bluespy_mcp.worker import worker_loop

        last_error = None
        for attempt in range(retries):
            self._cmd_queue = mp.Queue()
            self._result_queue = mp.Queue()
            self._process = mp.Process(
                target=worker_loop,
                args=(self._cmd_queue, self._result_queue),
                daemon=True,
            )
            self._process.start()

            try:
                result = self._result_queue.get(timeout=30)
                if result.get("ok"):
                    return  # Worker ready
                last_error = result.get("error", "unknown error")
            except Exception as e:
                last_error = str(e)

            # Worker failed — clean up and retry after delay
            self._kill_worker()
            if attempt < retries - 1:
                logger.info(
                    f"Worker failed to start (attempt {attempt + 1}/{retries}): "
                    f"{last_error}. Retrying in {retry_delay}s..."
                )
                time.sleep(retry_delay)

        raise HardwareError(
            f"Worker failed to start after {retries} attempts: {last_error}. "
            "If the blueSPY desktop app is open, close it first. "
            "Otherwise, try unplugging and replugging the USB cable."
        )

    def _kill_worker(self) -> None:
        """Kill the worker subprocess.

        Waits up to 5 seconds for clean exit (worker calls reboot_moreph
        to release USB, then os._exit). Falls back to SIGKILL if the
        worker hangs.
        """
        if self._process and self._process.is_alive():
            self._process.join(timeout=5)
            if self._process.is_alive():
                self._process.kill()
                self._process.join(timeout=2)
        self._process = None
        self._cmd_queue = None
        self._result_queue = None

    def _send_command(self, cmd: dict, timeout: float | None = None) -> dict:
        """Send a command to the worker and wait for a response.

        Raises HardwareError on timeout or worker death.
        """
        if self._cmd_queue is None or self._result_queue is None:
            raise HardwareError("Worker not running")

        if timeout is None:
            timeout = _TIMEOUTS.get(cmd["cmd"], 10)

        self._cmd_queue.put(cmd)
        try:
            result = self._result_queue.get(timeout=timeout)
            return result
        except Exception:
            # Timeout — kill the hung worker
            logger.error(f"Hardware command '{cmd['cmd']}' timed out after {timeout}s")
            self._kill_worker()
            self._state = HardwareState.IDLE
            self._serial = None
            self._capture_file = None
            self._release_lock()
            raise HardwareError(
                f"Hardware operation '{cmd['cmd']}' timed out after {timeout}s. "
                "If the device LED is green, close the blueSPY desktop app "
                "or unplug/replug the USB cable."
            )

    def connect(self, serial: int = -1, force: bool = False) -> dict:
        """Connect to hardware: acquire lock -> spawn worker -> reboot -> connect.

        Args:
            serial: Moreph serial number. Use -1 for first available device.
            force: If True, remove stale lock file from a crashed session
                   before connecting. Does not help if the blueSPY desktop
                   app is actively using the device.
        """
        if self._state != HardwareState.IDLE:
            raise HardwareError(
                f"Cannot connect: current state is {self._state.value}. "
                "Disconnect first or close the loaded file."
            )

        if not self._try_acquire_lock(force=force):
            raise HardwareError(
                "Hardware is in use by another MCP session. "
                "Try connect_hardware(force=True) to override a stale lock "
                "from a crashed session."
            )

        # Retry the full spawn+connect sequence. The USB device may need
        # recovery time after a previous worker process exited (e.g., after
        # a discover_hardware() call). The health check in _spawn_worker
        # can pass while heavier operations like reboot/connect still fail.
        last_error = None
        retries = 3
        retry_delay = 2.0
        for attempt in range(retries):
            try:
                self._spawn_worker()
                result = self._send_command({"cmd": "connect", "serial": serial})
                if result["ok"]:
                    self._state = HardwareState.CONNECTED
                    self._serial = serial
                    return result["data"]
                last_error = result["error"]
            except HardwareError as e:
                last_error = str(e)

            # Connect failed — kill worker and retry after delay
            self._kill_worker()
            if attempt < retries - 1:
                logger.info(
                    f"Connect attempt {attempt + 1}/{retries} failed: "
                    f"{last_error}. Retrying in {retry_delay}s..."
                )
                time.sleep(retry_delay)

        self._release_lock()
        self._state = HardwareState.IDLE
        raise HardwareError(
            f"Failed to connect after {retries} attempts: {last_error}. "
            "If the device LED is green, close the blueSPY desktop app "
            "or unplug/replug the USB cable."
        )

    def start_capture(
        self,
        filename: str | None = None,
        duration_seconds: float | None = None,
        LE: bool = True,
        CL: bool = False,
        QHS: bool = False,
        wifi: bool = False,
        CS: bool = False,
    ) -> dict:
        """Start a live capture."""
        if self._state != HardwareState.CONNECTED:
            raise RuntimeError(
                f"Not connected to hardware (state: {self._state.value}). "
                "Call connect_hardware() first."
            )

        if filename is None:
            ts = datetime.now().strftime("%Y-%m-%d-%H%M%S")
            filename = str(_DEFAULT_CAPTURES_DIR / f"capture-{ts}.pcapng")
            # Ensure directory exists
            Path(filename).parent.mkdir(parents=True, exist_ok=True)

        timeout = _TIMEOUTS["start_capture"]
        if duration_seconds is not None:
            timeout = _TIMEOUTS["start_capture"] + duration_seconds + _TIMEOUTS["stop_capture"]

        cmd = {
            "cmd": "start_capture",
            "filename": filename,
            "duration_seconds": duration_seconds,
            "LE": LE, "CL": CL, "QHS": QHS, "wifi": wifi, "CS": CS,
        }
        result = self._send_command(cmd, timeout=timeout)
        if not result["ok"]:
            raise HardwareError(result["error"])

        if duration_seconds is not None:
            # Timed capture completed — stay in CONNECTED
            self._capture_file = None
            return result["data"]
        else:
            # Ongoing capture
            self._state = HardwareState.CAPTURING
            self._capture_file = filename
            self._capture_start_time = time.time()
            return result["data"]

    def stop_capture(self) -> dict:
        """Stop an active capture."""
        if self._state != HardwareState.CAPTURING:
            raise RuntimeError("No capture in progress.")

        result = self._send_command({"cmd": "stop_capture"})
        if not result["ok"]:
            raise HardwareError(result["error"])

        duration = None
        if self._capture_start_time:
            duration = round(time.time() - self._capture_start_time, 1)

        data = result["data"]
        data["file_path"] = self._capture_file
        data["duration_seconds"] = duration

        self._state = HardwareState.CONNECTED
        self._capture_file = None
        self._capture_start_time = None
        return data

    def disconnect(self) -> dict:
        """Disconnect from hardware."""
        if self._state == HardwareState.CAPTURING:
            self.stop_capture()

        if self._state != HardwareState.CONNECTED:
            raise RuntimeError("Not connected to hardware.")

        try:
            result = self._send_command({"cmd": "disconnect"})
            self._send_command({"cmd": "shutdown"}, timeout=5)
        except HardwareError:
            pass  # Best-effort disconnect
        finally:
            self._kill_worker()
            self._release_lock()
            self._state = HardwareState.IDLE
            self._serial = None

        return {"disconnected": True}

    def get_packet_count(self) -> int:
        """Get current packet count from the worker (for live status)."""
        if self._state != HardwareState.CAPTURING:
            return 0
        try:
            result = self._send_command({"cmd": "packet_count"})
            if result["ok"]:
                return result["data"]["packet_count"]
        except HardwareError:
            pass
        return 0

    def get_summary(self, limit: int | None = None) -> dict:
        """Get a summary of the live capture from the worker."""
        if self._state != HardwareState.CAPTURING:
            return {}
        try:
            result = self._send_command({"cmd": "get_summary", "limit": limit})
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return {}

    def get_packets(
        self,
        *,
        summary_contains: str | None = None,
        packet_type: str | None = None,
        channel: int | None = None,
        max_results: int = 100,
        start: int = 0,
    ) -> dict:
        """Query captured packets with optional filters."""
        empty = {"packets": [], "has_more": False, "returned": 0}
        if self._state != HardwareState.CAPTURING:
            return empty
        try:
            cmd: dict[str, Any] = {
                "cmd": "get_packets",
                "max_results": max_results,
                "start": start,
            }
            if summary_contains is not None:
                cmd["summary_contains"] = summary_contains
            if packet_type is not None:
                cmd["packet_type"] = packet_type
            if channel is not None:
                cmd["channel"] = channel
            result = self._send_command(cmd)
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return empty

    def get_devices(self) -> dict:
        """Get list of discovered devices from the live capture."""
        if self._state != HardwareState.CAPTURING:
            return {"devices": [], "count": 0}
        try:
            result = self._send_command({"cmd": "get_devices"})
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return {"devices": [], "count": 0}

    def get_connections(self) -> dict:
        """Get list of active connections from the live capture."""
        if self._state != HardwareState.CAPTURING:
            return {"connections": [], "count": 0}
        try:
            result = self._send_command({"cmd": "get_connections"})
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return {"connections": [], "count": 0}

    def get_errors(self, max_results: int = 100, start: int = 0) -> dict:
        """Get capture errors from the live capture."""
        if self._state != HardwareState.CAPTURING:
            return {"errors": [], "count": 0}
        try:
            result = self._send_command(
                {"cmd": "get_errors", "max_results": max_results, "start": start}
            )
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return {"errors": [], "count": 0}

    def inspect_connection_live(self, connection_index: int = 0) -> dict:
        """Inspect a connection during live capture."""
        if self._state != HardwareState.CAPTURING:
            return {}
        try:
            result = self._send_command(
                {"cmd": "inspect_connection", "connection_index": connection_index}
            )
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return {}

    def inspect_advertising_live(self, device_index: int = 0) -> dict:
        """Inspect advertising data for a device during live capture."""
        if self._state != HardwareState.CAPTURING:
            return {}
        try:
            result = self._send_command(
                {"cmd": "inspect_advertising", "device_index": device_index}
            )
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return {}

    def inspect_all_devices(self) -> dict:
        """Inspect advertising data for all devices in a single pass."""
        if self._state != HardwareState.CAPTURING:
            return {"devices": [], "total_devices": 0}
        try:
            result = self._send_command({"cmd": "inspect_all_devices"})
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return {"devices": [], "total_devices": 0}

    def inspect_all_connections(self) -> dict:
        """Inspect all connections in a single pass."""
        if self._state != HardwareState.CAPTURING:
            return {"connections": [], "total_connections": 0}
        try:
            result = self._send_command({"cmd": "inspect_all_connections"})
            if result["ok"]:
                return result["data"]
        except HardwareError:
            pass
        return {"connections": [], "total_connections": 0}

    def get_status(self) -> dict:
        """Get current hardware status (local state, no subprocess call)."""
        status: dict[str, Any] = {
            "state": self._state.value,
            "serial": self._serial,
            "capturing": self._state == HardwareState.CAPTURING,
            "capture_file": self._capture_file,
        }
        if self._capture_start_time and self._state == HardwareState.CAPTURING:
            status["capture_elapsed_seconds"] = round(
                time.time() - self._capture_start_time, 1
            )
        return status

    def _cleanup(self) -> None:
        """Cleanup on process exit."""
        try:
            if self._state == HardwareState.CAPTURING:
                self._send_command({"cmd": "stop_capture"}, timeout=5)
            if self._state in (HardwareState.CONNECTED, HardwareState.CAPTURING):
                self._send_command({"cmd": "disconnect"}, timeout=5)
                self._send_command({"cmd": "shutdown"}, timeout=5)
        except Exception:
            pass
        self._kill_worker()
        self._release_lock()
