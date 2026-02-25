"""Capture file loading and management using the BlueSPY API.

Wraps bluespy.load_file() with state management, metadata extraction,
and clean Python interfaces for packet/device/connection access.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from bluespy_mcp.loader import get_bluespy

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Summary of a Bluetooth device found in a capture."""
    index: int
    address: str = ""
    name: str = ""
    connection_count: int = 0

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "address": self.address,
            "name": self.name,
            "connection_count": self.connection_count,
        }


@dataclass
class ConnectionInfo:
    """Summary of a Bluetooth connection found in a capture."""
    index: int
    summary: str = ""
    interval: Any = None
    latency: Any = None
    timeout: Any = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {"index": self.index, "summary": self.summary}
        if self.interval is not None:
            result["interval"] = self.interval
        if self.latency is not None:
            result["latency"] = self.latency
        if self.timeout is not None:
            result["timeout"] = self.timeout
        return result


def _extract_address(dev) -> str:
    """Extract device address, trying multiple BlueSPY query approaches."""
    for method in ["query_str", "query"]:
        try:
            addr = getattr(dev, method)("address")
            if isinstance(addr, bytes) and len(addr) >= 6:
                return ":".join(f"{b:02X}" for b in addr[:6])
            if isinstance(addr, str) and addr:
                return addr
        except (AttributeError, Exception):
            continue

    # Try extracting from summary
    try:
        summary = dev.query_str("summary")
        match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", summary)
        if match:
            return match.group(1)
    except (AttributeError, Exception):
        pass

    return ""


def _extract_name(dev) -> str:
    """Extract device name from BlueSPY device object."""
    for method in ["query_str", "query"]:
        try:
            name = getattr(dev, method)("name")
            if isinstance(name, bytes):
                return name.decode("utf-8", errors="replace")
            if isinstance(name, str) and name:
                return name
        except (AttributeError, Exception):
            continue
    return ""


class CaptureManager:
    """Manages loading and querying of .pcapng capture files via the BlueSPY API.

    BlueSPY supports only one loaded file at a time (global state).
    This class wraps that global state with file tracking and metadata.
    """

    def __init__(self) -> None:
        self._file_path: Path | None = None
        self._is_loaded: bool = False

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def file_path(self) -> Path | None:
        return self._file_path

    def load(self, file_path: str | Path) -> dict:
        """Load a .pcapng capture file.

        Returns dict with basic capture info (packet_count, file_path, file_size_bytes).
        """
        path = Path(file_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Capture file not found: {path}")
        if path.suffix.lower() != ".pcapng":
            raise ValueError(f"Only .pcapng files are supported, got: {path.suffix}")

        if self._is_loaded:
            self.close()

        bluespy = get_bluespy()
        bluespy.load_file(str(path))
        self._file_path = path
        self._is_loaded = True

        logger.info(f"Loaded capture: {path} ({self.packet_count} packets)")

        return {
            "file_path": str(path),
            "file_size_bytes": path.stat().st_size,
            "packet_count": self.packet_count,
        }

    def close(self) -> None:
        """Close the currently loaded capture file."""
        if not self._is_loaded:
            return
        try:
            bluespy = get_bluespy()
            bluespy.close_file()
        except ImportError:
            pass
        self._file_path = None
        self._is_loaded = False

    def _require_loaded(self) -> None:
        if not self._is_loaded:
            raise RuntimeError("No capture file loaded. Call load() first.")

    @property
    def packet_count(self) -> int:
        """Number of packets in the loaded capture."""
        self._require_loaded()
        bluespy = get_bluespy()
        return len(bluespy.packets)

    def get_packet(self, index: int) -> Any:
        """Get a raw BlueSPY event_id by packet index."""
        self._require_loaded()
        bluespy = get_bluespy()
        return bluespy.packets[index]

    def iter_packets(self, start: int = 0, limit: int | None = None) -> Iterator[tuple[int, Any]]:
        """Iterate over packets, yielding (index, event_id) tuples."""
        self._require_loaded()
        bluespy = get_bluespy()
        total = len(bluespy.packets)
        end = total if limit is None else min(start + limit, total)
        for i in range(start, end):
            yield i, bluespy.packets[i]

    def get_devices(self) -> list[DeviceInfo]:
        """Get all devices found in the capture."""
        self._require_loaded()
        bluespy = get_bluespy()
        devices = []
        for idx, dev in enumerate(bluespy.devices):
            info = DeviceInfo(index=idx)
            info.address = _extract_address(dev)
            info.name = _extract_name(dev)
            try:
                info.connection_count = len(list(dev.get_connections()))
            except (AttributeError, Exception):
                pass
            devices.append(info)
        return devices

    def get_connections(self) -> list[ConnectionInfo]:
        """Get all connections found in the capture."""
        self._require_loaded()
        bluespy = get_bluespy()
        connections = []
        for idx, conn in enumerate(bluespy.connections):
            info = ConnectionInfo(index=idx)
            try:
                info.summary = conn.query_str("summary")
            except (AttributeError, Exception):
                try:
                    info.summary = str(conn.summary)
                except (AttributeError, Exception):
                    pass
            for field_name in ["interval", "latency", "timeout"]:
                try:
                    setattr(info, field_name, conn.query(field_name))
                except (AttributeError, Exception):
                    pass
            connections.append(info)
        return connections

    def get_metadata(self) -> dict:
        """Extract capture metadata: duration, packet count, device/connection info."""
        self._require_loaded()
        bluespy = get_bluespy()

        total = len(bluespy.packets)
        result: dict[str, Any] = {
            "file_path": str(self._file_path),
            "file_size_bytes": self._file_path.stat().st_size if self._file_path else 0,
            "packet_count": total,
        }

        if total > 0:
            try:
                first_ts = int(bluespy.packets[0].time)
                last_ts = int(bluespy.packets[total - 1].time)
                result["first_timestamp_ns"] = first_ts
                result["last_timestamp_ns"] = last_ts
                result["duration_ns"] = last_ts - first_ts
                result["duration_seconds"] = round((last_ts - first_ts) / 1e9, 3)
            except (AttributeError, TypeError, ValueError, OverflowError):
                pass

        devices = self.get_devices()
        connections = self.get_connections()
        result["device_count"] = len(devices)
        result["connection_count"] = len(connections)
        result["devices"] = [d.to_dict() for d in devices]
        result["connections"] = [c.to_dict() for c in connections]

        return result

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        if self._is_loaded:
            return f"CaptureManager(file={self._file_path}, packets={self.packet_count})"
        return "CaptureManager(not loaded)"
