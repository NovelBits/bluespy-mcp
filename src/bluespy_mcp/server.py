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
from bluespy_mcp.hardware import HardwareManager, HardwareError, HardwareState

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
_hardware = HardwareManager()


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _error(message: str) -> str:
    return _json({"error": message})


def _not_loaded() -> str:
    return _error("No capture file loaded. Use load_capture() first.")


def _not_ready() -> str:
    return _error(
        "No data available. Load a capture file with load_capture() "
        "or start a live capture with start_capture()."
    )


def _data_available() -> bool:
    """Check if packet data is available (file loaded or live capture)."""
    return _capture.is_loaded or _hardware.state == HardwareState.CAPTURING


# --- MCP Resources ---


@mcp.resource("bluespy://hardware")
def hardware_resource() -> str:
    """Current hardware connection status."""
    return _json(_hardware.get_status())


@mcp.resource("bluespy://capture")
def capture_resource() -> str:
    """Current capture state — file or live."""
    hw_state = _hardware.state

    if hw_state == HardwareState.CAPTURING:
        status = _hardware.get_status()
        status["mode"] = "live"
        try:
            status["packet_count"] = _hardware.get_packet_count()
        except Exception:
            pass
        return _json(status)

    if _capture.is_loaded:
        try:
            meta = _capture.get_metadata()
            meta["mode"] = "file"
            return _json(meta)
        except Exception as e:
            return _json({"mode": "error", "error": str(e)})

    return _json({"mode": "idle"})


# --- Prompt Templates ---


@mcp.prompt()
def analyze_capture(file_path: str) -> str:
    """Full analysis workflow for a capture file."""
    return (
        f"Please analyze the Bluetooth LE capture file at: {file_path}\n\n"
        "Follow these steps:\n"
        "1. Load the capture file with load_capture()\n"
        "2. Get a capture_summary() to understand what's in the file\n"
        "3. Check find_capture_errors() for any protocol errors or disconnects\n"
        "4. Use list_devices() and inspect_advertising() for the most active device\n"
        "5. Use list_connections() and inspect_connection() for each connection\n"
        "6. Summarize your findings: devices seen, connection quality, any issues found"
    )


@mcp.prompt()
def quick_capture(duration_seconds: str = "10") -> str:
    """End-to-end live capture workflow."""
    return (
        f"Please capture Bluetooth LE traffic for {duration_seconds} seconds.\n\n"
        "Follow these steps:\n"
        "1. Use connect_hardware() to connect to the BlueSPY sniffer\n"
        f"2. Use start_capture(duration_seconds={duration_seconds}) to capture\n"
        "3. Report what was captured: file path, packet count, duration\n"
        "4. Ask if I'd like to analyze the capture or disconnect"
    )


@mcp.prompt()
def debug_connection(file_path: str) -> str:
    """Connection debugging workflow."""
    return (
        f"Please debug the Bluetooth LE connections in: {file_path}\n\n"
        "Follow these steps:\n"
        "1. Load the capture file with load_capture()\n"
        "2. Use list_connections() to find all connections\n"
        "3. Use inspect_connection() for each connection found\n"
        "4. Use find_capture_errors() to identify errors and disconnects\n"
        "5. Search for specific error types with search_packets()\n"
        "6. Report: connection parameters, packet distribution, errors found, "
        "likely root cause of any issues"
    )


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


# --- Hardware Tools ---


@mcp.tool
def connect_hardware(serial: int = -1, force: bool = False) -> str:
    """Connect to BlueSPY Moreph hardware for live capture.

    Reboots the device first to ensure clean state, then connects.
    Only one MCP client can use the hardware at a time.

    Args:
        serial: Moreph serial number (hex integer). Use -1 for first available device.
        force: Override a stale lock from a crashed session. Use this when
               connect fails with "Hardware is in use by another session" but
               no other session is actually running.
    """
    if _capture.is_loaded:
        return _error(
            "A capture file is currently loaded. Close it with close_capture() "
            "before connecting to hardware."
        )
    try:
        data = _hardware.connect(serial, force=force)
        return _json({"success": True, **data})
    except HardwareError as e:
        return _json({"success": False, "error": str(e)})


@mcp.tool
def disconnect_hardware() -> str:
    """Disconnect from BlueSPY hardware.

    If a capture is in progress, it will be stopped first.
    """
    try:
        data = _hardware.disconnect()
        return _json({"success": True, **data})
    except (HardwareError, RuntimeError) as e:
        return _json({"success": False, "error": str(e)})


@mcp.tool
def start_capture(
    filename: str | None = None,
    duration_seconds: float | None = None,
    LE: bool = True,
    CL: bool = False,
    QHS: bool = False,
    wifi: bool = False,
    CS: bool = False,
) -> str:
    """Start a live Bluetooth capture.

    Args:
        filename: Path to save the .pcapng file. Auto-generated if not provided.
        duration_seconds: Capture duration in seconds. If set, capture runs for
                         this duration then stops automatically. If None, capture
                         runs until stop_capture() is called.
        LE: Enable Bluetooth LE capture (default True).
        CL: Enable Bluetooth Classic capture.
        QHS: Enable Qualcomm High Speed capture.
        wifi: Enable WiFi capture.
        CS: Enable Channel Sounding capture.
    """
    try:
        data = _hardware.start_capture(
            filename=filename, duration_seconds=duration_seconds,
            LE=LE, CL=CL, QHS=QHS, wifi=wifi, CS=CS,
        )
        return _json({"success": True, **data})
    except (HardwareError, RuntimeError) as e:
        return _json({"success": False, "error": str(e)})


@mcp.tool
def stop_capture() -> str:
    """Stop the active live capture.

    Returns the file path, packet count, and duration of the capture.
    The file is NOT automatically loaded for analysis — use load_capture()
    to analyze it, or disconnect and save it for later.
    """
    try:
        data = _hardware.stop_capture()
        return _json({"success": True, **data})
    except (HardwareError, RuntimeError) as e:
        return _json({"success": False, "error": str(e)})


@mcp.tool
def hardware_status() -> str:
    """Get current hardware connection and capture status."""
    return _json(_hardware.get_status())


# --- Discovery Tools ---


@mcp.tool
def capture_summary() -> str:
    """Get a high-level summary of the loaded capture.

    Returns packet counts by type, device list, connection list,
    capture duration, and other metadata.
    """
    if not _data_available():
        return _not_ready()
    try:
        return _json(summarize_capture(_capture))
    except Exception as e:
        return _error(str(e))


@mcp.tool
def list_devices() -> str:
    """List all Bluetooth devices found in the loaded capture."""
    if not _data_available():
        return _not_ready()
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
    if not _data_available():
        return _not_ready()
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
    if not _data_available():
        return _not_ready()
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
    if not _data_available():
        return _not_ready()
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
    if not _data_available():
        return _not_ready()
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
    if not _data_available():
        return _not_ready()
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
