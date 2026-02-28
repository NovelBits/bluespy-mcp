# src/bluespy_mcp/hardware.py
"""Hardware management with subprocess isolation and file locking.

All bluespy hardware calls run in a child subprocess to prevent ctypes
hangs from freezing the MCP server. A file lock ensures only one MCP
client uses the hardware at a time.
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
    "discover": 5,
    "connect": 15,
    "disconnect": 5,
    "start_capture": 10,
    "stop_capture": 10,
    "packet_count": 5,
}


class HardwareState(enum.Enum):
    IDLE = "idle"
    CONNECTED = "connected"
    CAPTURING = "capturing"


class HardwareError(RuntimeError):
    """Raised when a hardware operation fails."""


class HardwareManager:
    """Manages BlueSPY hardware via a worker subprocess.

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

    def _try_acquire_lock(self) -> bool:
        """Try to acquire the file lock. Returns True on success."""
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

        raise HardwareError(f"Worker failed to start after {retries} attempts: {last_error}")

    def _kill_worker(self) -> None:
        """Kill the worker subprocess.

        Tries to let the worker exit cleanly first (os._exit skips atexit),
        falling back to SIGKILL if it doesn't exit within 2 seconds.
        """
        if self._process and self._process.is_alive():
            # Give worker time to exit cleanly via os._exit
            self._process.join(timeout=2)
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
                "The device may need a USB unplug/replug."
            )

    def discover(self) -> dict:
        """Discover connected Moreph hardware. Does not require connection."""
        self._spawn_worker()
        try:
            result = self._send_command({"cmd": "discover"})
            if not result["ok"]:
                raise HardwareError(result["error"])
            return result["data"]
        finally:
            self._send_command({"cmd": "shutdown"}, timeout=5)
            self._kill_worker()

    def connect(self, serial: int = -1) -> dict:
        """Connect to hardware: acquire lock -> spawn worker -> reboot -> connect."""
        if self._state != HardwareState.IDLE:
            raise HardwareError(
                f"Cannot connect: current state is {self._state.value}. "
                "Disconnect first or close the loaded file."
            )

        if not self._try_acquire_lock():
            raise HardwareError(
                "Hardware is in use by another session. "
                "Only one MCP client can use the hardware at a time."
            )

        try:
            self._spawn_worker()
            result = self._send_command({"cmd": "connect", "serial": serial})
            if not result["ok"]:
                raise HardwareError(result["error"])
            self._state = HardwareState.CONNECTED
            self._serial = serial
            return result["data"]
        except Exception:
            self._kill_worker()
            self._release_lock()
            self._state = HardwareState.IDLE
            raise

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
