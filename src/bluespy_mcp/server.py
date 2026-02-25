"""FastMCP server exposing BlueSPY capture analysis tools.

Run with:
    bluespy-mcp
    python -m bluespy_mcp
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from bluespy_mcp.analyzer import (
    analyze_advertising,
    analyze_connection,
    classify_packet,
    find_errors,
    find_packets,
    summarize_capture,
)
from bluespy_mcp.capture import CaptureManager

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "BlueSPY Sniffer",
    instructions=(
        "Bluetooth LE protocol capture analysis tools powered by the BlueSPY sniffer. "
        "Load a .pcapng capture file, then analyze packets, devices, connections, "
        "advertising data, and errors. Requires the BlueSPY application to be installed."
    ),
)

_capture = CaptureManager()
_captures_dir = Path(os.environ.get("BLE_CAPTURES_DIR", "captures"))


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _error(message: str) -> str:
    return _json({"error": message})


def _not_loaded() -> str:
    return _error("No capture file loaded. Use load_capture() first.")


# --- MCP Resource ---


@mcp.resource("capture://status")
def capture_status() -> str:
    """Current capture file status and metadata."""
    if not _capture.is_loaded:
        return _json({"status": "no_file_loaded"})
    try:
        meta = _capture.get_metadata()
        meta["status"] = "loaded"
        return _json(meta)
    except Exception as e:
        return _json({"status": "error", "error": str(e)})


# --- File Management Tools ---


@mcp.tool
def load_capture(file_path: str) -> str:
    """Load a .pcapng capture file for analysis.

    Args:
        file_path: Path to the .pcapng capture file. Can be absolute
                   or relative to the captures directory.
    """
    path = Path(file_path)
    if not path.is_absolute() and not path.exists():
        alt = _captures_dir / path
        if alt.exists():
            path = alt

    try:
        result = _capture.load(path)
        return _json({"success": True, **result})
    except (FileNotFoundError, ValueError, ImportError) as e:
        return _json({"success": False, "error": str(e)})


@mcp.tool
def close_capture() -> str:
    """Close the currently loaded capture file."""
    if not _capture.is_loaded:
        return _json({"message": "No capture file is currently loaded."})
    file_path = str(_capture.file_path)
    _capture.close()
    return _json({"message": f"Closed {file_path}"})


@mcp.tool
def list_captures(directory: str | None = None) -> str:
    """List available .pcapng capture files in a directory.

    Args:
        directory: Directory to search. Defaults to the captures directory.
    """
    search_dir = Path(directory) if directory else _captures_dir
    if not search_dir.exists():
        return _error(f"Directory not found: {search_dir}")

    files = sorted(search_dir.glob("**/*.pcapng"))
    return _json({
        "directory": str(search_dir),
        "count": len(files),
        "files": [
            {"path": str(f), "name": f.name, "size_bytes": f.stat().st_size}
            for f in files
        ],
    })


# --- Discovery Tools ---


@mcp.tool
def capture_summary() -> str:
    """Get a high-level summary of the loaded capture.

    Returns packet counts by type, device list, connection list,
    capture duration, and other metadata.
    """
    if not _capture.is_loaded:
        return _not_loaded()
    try:
        return _json(summarize_capture(_capture))
    except Exception as e:
        return _error(str(e))


@mcp.tool
def list_devices() -> str:
    """List all Bluetooth devices found in the loaded capture."""
    if not _capture.is_loaded:
        return _not_loaded()
    try:
        devices = _capture.get_devices()
        return _json({
            "count": len(devices),
            "devices": [d.to_dict() for d in devices],
        })
    except Exception as e:
        return _error(str(e))


@mcp.tool
def list_connections() -> str:
    """List all Bluetooth connections found in the loaded capture."""
    if not _capture.is_loaded:
        return _not_loaded()
    try:
        connections = _capture.get_connections()
        return _json({
            "count": len(connections),
            "connections": [c.to_dict() for c in connections],
        })
    except Exception as e:
        return _error(str(e))


# --- Analysis Tools ---


@mcp.tool
def search_packets(
    summary_contains: str | None = None,
    packet_type: str | None = None,
    channel: int | None = None,
    max_results: int = 100,
) -> str:
    """Search for packets matching criteria in the loaded capture.

    Args:
        summary_contains: Find packets whose summary contains this text (case-insensitive).
        packet_type: Filter by classified type (e.g., "ADV_IND", "CONNECT_IND", "ATT", "SMP").
        channel: Filter by Bluetooth channel number.
        max_results: Maximum results to return (default 100).
    """
    if not _capture.is_loaded:
        return _not_loaded()
    try:
        results = find_packets(
            _capture,
            summary_contains=summary_contains,
            packet_type=packet_type,
            channel=channel,
            max_results=max_results,
        )
        return _json({"count": len(results), "packets": results})
    except Exception as e:
        return _error(str(e))


@mcp.tool
def inspect_connection(connection_index: int = 0) -> str:
    """Deep-dive analysis of a specific Bluetooth connection.

    Args:
        connection_index: Which connection to analyze (0-based index from list_connections).
    """
    if not _capture.is_loaded:
        return _not_loaded()
    try:
        return _json(analyze_connection(_capture, connection_index))
    except Exception as e:
        return _error(str(e))


@mcp.tool
def inspect_advertising(device_index: int = 0) -> str:
    """Analyze advertising data for a specific device.

    Args:
        device_index: Which device to analyze (0-based index from list_devices).
    """
    if not _capture.is_loaded:
        return _not_loaded()
    try:
        return _json(analyze_advertising(_capture, device_index))
    except Exception as e:
        return _error(str(e))


@mcp.tool
def find_capture_errors(max_results: int = 100) -> str:
    """Find all error, failure, and disconnect packets in the loaded capture.

    Args:
        max_results: Maximum number of errors to return (default 100).
    """
    if not _capture.is_loaded:
        return _not_loaded()
    try:
        errors = find_errors(_capture, max_results=max_results)
        return _json({"count": len(errors), "errors": errors})
    except Exception as e:
        return _error(str(e))


# --- Entry point ---


def main():
    """Run the BlueSPY MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
