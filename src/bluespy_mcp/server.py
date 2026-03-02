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

from bluespy_mcp.capture import CaptureManager
from bluespy_mcp.hardware import HardwareManager, HardwareError, HardwareState

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "blueSPY MCP Server",
    instructions=(
        "Bluetooth LE protocol capture analysis tools powered by the BlueSPY sniffer. "
        "Requires the BlueSPY application to be installed.\n\n"
        "## Two Modes\n"
        "1. **File analysis** — load a .pcapng file with load_capture(), then analyze it.\n"
        "2. **Live hardware capture** — connect_hardware() → start_capture() → "
        "analyze in real-time → stop_capture() → disconnect_hardware().\n\n"
        "## Tool Sequence Rules\n"
        "- **Always start with** load_capture() (file mode) or connect_hardware() "
        "(live mode). All analysis tools require data to be available.\n"
        "- **Close before switching**: close_capture() before connect_hardware(), "
        "and vice versa. Only one data source at a time.\n"
        "- **Discovery first, then drill down**: capture_summary() and list_devices() / "
        "list_connections() give you indices. Use those indices with inspect_advertising() "
        "and inspect_connection() for deep analysis.\n"
        "- **Errors last**: find_capture_errors() after you understand the devices and "
        "connections, so error context makes sense.\n\n"
        "## Live Capture: Timed vs Open-Ended\n"
        "- **Timed**: start_capture(duration_seconds=N) blocks until done. "
        "No analysis is possible during the capture — use this only when the user "
        "wants a quick grab-and-analyze-later flow.\n"
        "- **Open-ended** (preferred for live analysis): start_capture() with NO "
        "duration_seconds. The capture runs in the background and ALL analysis "
        "tools work in real-time on the growing data. Call stop_capture() when done.\n"
        "- When the user asks to analyze traffic as it appears, watch devices live, "
        "or do real-time analysis, ALWAYS use open-ended capture.\n\n"
        "## Recommended Workflow\n"
        "1. Load or capture data\n"
        "2. capture_summary() — understand scope (packet count, duration, device count)\n"
        "3. list_devices() + list_connections() — identify what's present\n"
        "4. inspect_advertising(device_index) / inspect_connection(connection_index) — "
        "deep-dive on items of interest\n"
        "5. search_packets() — filter by type, channel, or text for specific investigation\n"
        "6. find_capture_errors() — protocol errors, disconnects, failures\n"
        "7. Summarize findings for the user"
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


@mcp.prompt()
def investigate_device(file_path: str, device_address: str) -> str:
    """Investigate a specific device's behavior in a capture file."""
    return (
        f"Please investigate the Bluetooth LE device {device_address} "
        f"in capture file: {file_path}\n\n"
        "Follow these steps:\n"
        f"1. Load the capture file with load_capture(file_path=\"{file_path}\")\n"
        "2. Use list_devices() to find the target device and note its index\n"
        f"3. Use inspect_advertising(device_index=<index>) for device {device_address}\n"
        f"4. Use search_packets(summary_contains=\"{device_address}\") to find all "
        "packets involving this device\n"
        "5. Report:\n"
        "   - Advertising behavior (type, interval, channels)\n"
        "   - RSSI readings and signal quality\n"
        "   - Packet types and counts involving this device\n"
        "   - Any connections this device participates in\n"
        "   - Anomalies or unusual behavior"
    )


@mcp.prompt()
def capture_and_analyze(duration_seconds: str = "30") -> str:
    """Live capture with real-time analysis, then stop and summarize."""
    return (
        f"Please capture Bluetooth LE traffic for about {duration_seconds} seconds "
        "while analyzing it in real-time.\n\n"
        "IMPORTANT: Do NOT pass duration_seconds to start_capture(). Start an "
        "open-ended capture so analysis tools work during the capture.\n\n"
        "Follow these steps:\n"
        "1. Use connect_hardware() to connect to the BlueSPY sniffer\n"
        "2. Use start_capture() — no duration_seconds, so it runs in the background\n"
        "3. While the capture is running, analyze the live data:\n"
        "   a. capture_summary() — see how many packets are arriving\n"
        "   b. list_devices() — discover devices as they appear\n"
        "   c. inspect_advertising() for interesting devices\n"
        "   d. list_connections() — watch for new connections\n"
        "   e. Repeat a few times to see the data grow\n"
        f"4. After ~{duration_seconds} seconds, use stop_capture()\n"
        "5. Run find_capture_errors() for protocol issues\n"
        "6. Use disconnect_hardware() to release the sniffer\n"
        "7. Summarize: devices found, connections, advertising behavior, errors"
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

    IMPORTANT: If you need to analyze data during the capture (list_devices,
    capture_summary, inspect_advertising, etc.), do NOT set duration_seconds.
    When duration_seconds is set, the capture blocks and no analysis tools
    can run until it finishes.

    Args:
        filename: Path to save the .pcapng file. Auto-generated if not provided.
        duration_seconds: Capture duration in seconds. If set, capture BLOCKS
                         for this duration (no live analysis possible). If None
                         (recommended), capture runs in the background — all
                         analysis tools work on live data — until stop_capture().
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
        if _hardware.state == HardwareState.CAPTURING:
            return _json(_hardware.get_summary())
        return _json(_capture.get_summary())
    except Exception as e:
        return _error(str(e))


@mcp.tool
def list_devices() -> str:
    """List all Bluetooth devices found in the loaded capture."""
    if not _data_available():
        return _not_ready()
    try:
        if _hardware.state == HardwareState.CAPTURING:
            return _json(_hardware.get_devices())
        return _json(_capture.get_devices())
    except Exception as e:
        return _error(str(e))


@mcp.tool
def list_connections() -> str:
    """List all Bluetooth connections found in the loaded capture."""
    if not _data_available():
        return _not_ready()
    try:
        if _hardware.state == HardwareState.CAPTURING:
            return _json(_hardware.get_connections())
        return _json(_capture.get_connections())
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
        if _hardware.state == HardwareState.CAPTURING:
            return _json(_hardware.get_packets(
                summary_contains=summary_contains,
                packet_type=packet_type,
                channel=channel,
                max_results=max_results,
            ))
        return _json(_capture.search_packets(
            summary_contains=summary_contains,
            packet_type=packet_type,
            channel=channel,
            max_results=max_results,
        ))
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
        if _hardware.state == HardwareState.CAPTURING:
            return _json(_hardware.inspect_connection_live(connection_index))
        return _json(_capture.inspect_connection(connection_index))
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
        if _hardware.state == HardwareState.CAPTURING:
            return _json(_hardware.inspect_advertising_live(device_index))
        return _json(_capture.inspect_advertising(device_index))
    except Exception as e:
        return _error(str(e))


@mcp.tool
def inspect_all_devices() -> str:
    """Analyze advertising data for ALL devices in a single pass.

    Much faster than calling inspect_advertising() for each device.
    Returns advertising stats (packet count, RSSI, channels, sample)
    for every discovered device. Use this when you need to analyze
    multiple devices — then use inspect_advertising(device_index)
    only for deep dives on specific devices of interest.
    """
    if not _data_available():
        return _not_ready()
    try:
        if _hardware.state == HardwareState.CAPTURING:
            return _json(_hardware.inspect_all_devices())
        return _json(_capture.inspect_all_devices())
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
        if _hardware.state == HardwareState.CAPTURING:
            return _json(_hardware.get_errors(max_results=max_results))
        return _json(_capture.get_errors(max_results=max_results))
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
