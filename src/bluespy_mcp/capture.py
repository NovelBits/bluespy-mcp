"""Capture file loading and management via a worker subprocess.

All bluespy calls are routed through a subprocess to prevent the native
Qt-based library from loading in the main MCP server process. Loading
the library in the main process causes SIGSEGV when AnyIO worker threads
make concurrent ctypes calls that race with the library's internal Qt
event loop and TaskRunner threads.

Architecture:

    MCP Server (main process)
        └── CaptureManager
                └── Worker subprocess (mode="file")
                        └── bluespy module (ctypes FFI)

The worker subprocess is spawned on load() and killed on close().
Analysis commands (summary, search, devices, connections, errors,
inspect) are forwarded to the worker via IPC queues.
"""

from __future__ import annotations

import logging
import multiprocessing as mp
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Per-operation timeouts (seconds)
_TIMEOUTS = {
    "load_file": 30,
    "close_file": 5,
    "get_metadata": 10,
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


class CaptureManager:
    """Manages loading and querying of .pcapng capture files.

    All bluespy calls are isolated in a subprocess to prevent SIGSEGV
    from concurrent ctypes access in the main process. The subprocess
    is spawned on load() and killed on close().
    """

    def __init__(self) -> None:
        self._file_path: Path | None = None
        self._is_loaded: bool = False
        self._process: mp.Process | None = None
        self._cmd_queue: mp.Queue | None = None
        self._result_queue: mp.Queue | None = None

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def file_path(self) -> Path | None:
        return self._file_path

    def _spawn_worker(self) -> None:
        """Spawn a file-mode worker subprocess."""
        from bluespy_mcp.worker import worker_loop

        self._cmd_queue = mp.Queue()
        self._result_queue = mp.Queue()
        self._process = mp.Process(
            target=worker_loop,
            args=(self._cmd_queue, self._result_queue, "file"),
            daemon=True,
        )
        self._process.start()

        try:
            result = self._result_queue.get(timeout=30)
            if not result.get("ok"):
                error = result.get("error", "unknown error")
                self._kill_worker()
                raise RuntimeError(f"File worker failed to start: {error}")
        except Exception:
            self._kill_worker()
            raise

    def _kill_worker(self) -> None:
        """Kill the worker subprocess."""
        if self._process and self._process.is_alive():
            self._process.join(timeout=5)
            if self._process.is_alive():
                self._process.kill()
                self._process.join(timeout=2)
        self._process = None
        self._cmd_queue = None
        self._result_queue = None

    def _send_command(self, cmd: dict, timeout: float | None = None) -> dict:
        """Send a command to the worker and wait for a response."""
        if self._cmd_queue is None or self._result_queue is None:
            raise RuntimeError("Worker not running")

        if timeout is None:
            timeout = _TIMEOUTS.get(cmd["cmd"], 10)

        self._cmd_queue.put(cmd)
        try:
            result = self._result_queue.get(timeout=timeout)
            return result
        except Exception:
            logger.error(f"File worker command '{cmd['cmd']}' timed out after {timeout}s")
            self._kill_worker()
            self._is_loaded = False
            self._file_path = None
            raise RuntimeError(
                f"File analysis operation '{cmd['cmd']}' timed out after {timeout}s"
            )

    def load(self, file_path: str | Path) -> dict:
        """Load a .pcapng capture file.

        Spawns a worker subprocess and loads the file in isolation.
        Returns dict with basic capture info (packet_count, file_path, file_size_bytes).
        """
        path = Path(file_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Capture file not found: {path}")
        if path.suffix.lower() != ".pcapng":
            raise ValueError(f"Only .pcapng files are supported, got: {path.suffix}")

        if self._is_loaded:
            self.close()

        self._spawn_worker()

        result = self._send_command({"cmd": "load_file", "path": str(path)})
        if not result["ok"]:
            self._kill_worker()
            raise RuntimeError(result["error"])

        self._file_path = path
        self._is_loaded = True
        pkt_count = result["data"]["packet_count"]

        logger.info(f"Loaded capture: {path} ({pkt_count} packets)")

        return {
            "file_path": str(path),
            "file_size_bytes": path.stat().st_size,
            "packet_count": pkt_count,
        }

    def close(self) -> None:
        """Close the currently loaded capture file and kill the worker."""
        if not self._is_loaded:
            return
        try:
            if self._cmd_queue is not None:
                self._send_command({"cmd": "close_file"}, timeout=5)
                self._send_command({"cmd": "shutdown"}, timeout=5)
        except Exception:
            pass
        self._kill_worker()
        self._file_path = None
        self._is_loaded = False

    def _require_loaded(self) -> None:
        if not self._is_loaded:
            raise RuntimeError("No capture file loaded. Call load() first.")

    def get_metadata(self) -> dict:
        """Extract capture metadata via the worker subprocess."""
        self._require_loaded()
        result = self._send_command({"cmd": "get_metadata"})
        if not result["ok"]:
            raise RuntimeError(result["error"])
        data = result["data"]
        data["file_path"] = str(self._file_path)
        data["file_size_bytes"] = self._file_path.stat().st_size if self._file_path else 0
        return data

    def get_summary(self, limit: int | None = None) -> dict:
        """Get capture summary via the worker subprocess."""
        self._require_loaded()
        result = self._send_command({"cmd": "get_summary", "limit": limit})
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def search_packets(
        self,
        *,
        summary_contains: str | None = None,
        packet_type: str | None = None,
        channel: int | None = None,
        max_results: int = 100,
        start: int = 0,
    ) -> dict:
        """Search packets via the worker subprocess."""
        self._require_loaded()
        cmd: dict[str, Any] = {"cmd": "get_packets", "max_results": max_results, "start": start}
        if summary_contains is not None:
            cmd["summary_contains"] = summary_contains
        if packet_type is not None:
            cmd["packet_type"] = packet_type
        if channel is not None:
            cmd["channel"] = channel
        result = self._send_command(cmd)
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def get_devices(self) -> dict:
        """Get devices via the worker subprocess."""
        self._require_loaded()
        result = self._send_command({"cmd": "get_devices"})
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def get_connections(self) -> dict:
        """Get connections via the worker subprocess."""
        self._require_loaded()
        result = self._send_command({"cmd": "get_connections"})
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def get_errors(self, max_results: int = 100) -> dict:
        """Get error packets via the worker subprocess."""
        self._require_loaded()
        result = self._send_command(
            {"cmd": "get_errors", "max_results": max_results}
        )
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def inspect_connection(self, connection_index: int = 0) -> dict:
        """Inspect a connection via the worker subprocess."""
        self._require_loaded()
        result = self._send_command(
            {"cmd": "inspect_connection", "connection_index": connection_index}
        )
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def inspect_advertising(self, device_index: int = 0) -> dict:
        """Inspect advertising data via the worker subprocess."""
        self._require_loaded()
        result = self._send_command(
            {"cmd": "inspect_advertising", "device_index": device_index}
        )
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def inspect_all_devices(self) -> dict:
        """Inspect advertising data for all devices in a single pass."""
        self._require_loaded()
        result = self._send_command({"cmd": "inspect_all_devices"})
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def inspect_all_connections(self) -> dict:
        """Inspect all connections in a single pass."""
        self._require_loaded()
        result = self._send_command({"cmd": "inspect_all_connections"})
        if not result["ok"]:
            raise RuntimeError(result["error"])
        return result["data"]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        if self._is_loaded:
            return f"CaptureManager(file={self._file_path})"
        return "CaptureManager(not loaded)"
