"""Hardware worker subprocess for BlueSPY MCP.

Runs in a child process so that ctypes calls to libblueSPY cannot hang
the MCP server. Receives commands via multiprocessing.Queue and sends
results back.

This module imports bluespy lazily — it's only loaded when a command
is first received, keeping the import cost in the subprocess.

USB Lifecycle and Cleanup
-------------------------
The Moreph hardware has firmware-level USB session state that persists
independently of the Python library's internal state. Three cleanup
mechanisms exist, each operating at a different level:

1. bluespy.disconnect() — Library-level cleanup. Tells the bluespy
   library the connection is done, but the firmware still holds the USB
   session. The device LED stays green.

2. bluespy_deinit() — Library teardown. Cleans up the native library's
   internal state (threads, memory). Does NOT release the firmware-level
   USB session after a connect/disconnect cycle. Only effective for
   sessions that never connected (e.g., discover-only).

3. reboot_moreph() — Firmware-level reset. Reboots the device firmware,
   fully releasing the USB session. The device LED turns blue. This is
   the ONLY reliable way to release hardware after a connection.

The worker uses reboot_moreph() at both ends of a hardware session:
- At connect time: clears stale firmware state from previous sessions
- At shutdown: releases the USB session (only if a connection was opened)

atexit and os._exit
-------------------
The vendored bluespy.py registers bluespy_deinit as an atexit handler.
We must prevent this from running in the subprocess because:

- multiprocessing.Process calls os._exit() after the target function
  returns, so atexit handlers never run in normal subprocess exit anyway.
- If SIGTERM arrives (parent exit kills daemon children), Python raises
  SystemExit → atexit → bluespy_deinit → SIGSEGV in the native library.
- We install a SIGTERM handler that calls os._exit(0) to prevent this.
- For normal shutdown, we call os._exit(0) explicitly after cleanup.

See docs/hardware-lifecycle.md for the full debugging history.
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import queue
import signal
import time
from typing import Any

from bluespy_mcp.analysis_core import (
    summarize_packets,
    filter_packets,
    find_error_packets,
    extract_device_info,
    extract_connection_info,
    analyze_connection_live,
    analyze_advertising_live,
)
from bluespy_mcp.packet_cache import (
    PacketCache,
    CachedPackets,
    build_cache,
    extend_cache,
)

logger = logging.getLogger(__name__)

_REBOOT_WAIT_SECONDS = 5.0
_CONNECT_RETRIES = 3
_CONNECT_RETRY_DELAYS = [2.0, 3.0, 5.0]


def _ensure_cache(bluespy: Any, cache: PacketCache | None) -> PacketCache:
    """Build or extend the packet cache as needed.

    If no cache exists, builds one from scratch. If packets have been
    added since the last cache build (live capture), extends in place.
    """
    if cache is None:
        return build_cache(bluespy.packets)
    current = len(bluespy.packets)
    cached = len(cache.summaries)
    if current > cached:
        extend_cache(cache, bluespy.packets, cached)
    return cache


def handle_command(
    bluespy: Any, cmd: dict, cache: PacketCache | None = None
) -> tuple[dict, PacketCache | None]:
    """Execute a single command against the bluespy module.

    Args:
        bluespy: The loaded bluespy module.
        cmd: Command dict with "cmd" key and optional parameters.
        cache: Current packet cache (None if not yet built).

    Returns:
        Tuple of (result_dict, updated_cache).
        result_dict: {"ok": True, "data": {...}} or {"ok": False, "error": "..."}.
        updated_cache: The cache after this command (may be new, extended, or cleared).
    """
    action = cmd.get("cmd")

    try:
        # --- File management commands ---

        if action == "load_file":
            path = cmd["path"]
            bluespy.load_file(path)
            packet_count = len(bluespy.packets)
            cache = build_cache(bluespy.packets)
            return {"ok": True, "data": {"packet_count": packet_count}}, cache

        elif action == "close_file":
            bluespy.close_file()
            return {"ok": True, "data": {}}, None

        elif action == "get_metadata":
            cache = _ensure_cache(bluespy, cache)
            packets_view = CachedPackets(cache)
            total = len(packets_view)
            result: dict[str, Any] = {"packet_count": total}
            if total > 0:
                try:
                    first_ts = cache.times[0]
                    last_ts = cache.times[-1]
                    result["first_timestamp_ns"] = first_ts
                    result["last_timestamp_ns"] = last_ts
                    result["duration_ns"] = last_ts - first_ts
                    result["duration_seconds"] = round((last_ts - first_ts) / 1e9, 3)
                except (IndexError, TypeError, ValueError, OverflowError):
                    pass
            result["devices"] = extract_device_info(bluespy.devices)
            result["connections"] = extract_connection_info(bluespy.connections)
            result["device_count"] = len(result["devices"])
            result["connection_count"] = len(result["connections"])
            return {"ok": True, "data": result}, cache

        # --- Hardware commands ---

        elif action == "connect":
            serial = cmd.get("serial", -1)
            # Try connecting without reboot first (fast path for fresh devices).
            # Only reboot if the direct connect fails, since reboot + USB
            # re-enumeration adds ~6 seconds.
            try:
                bluespy.connect(serial)
                serials = bluespy.connected_morephs()
                return {"ok": True, "data": {"serial": serial, "connected_serials": serials}}, cache
            except Exception as e:
                logger.info(f"Direct connect failed ({e}), rebooting device...")
            # Reboot to clear stale hardware state, then retry
            try:
                bluespy.reboot_moreph(serial)
                time.sleep(_REBOOT_WAIT_SECONDS)
            except Exception as e:
                logger.warning(f"Reboot failed (may be first connection): {e}")
            # Retry connect after reboot — avoids the expensive
            # worker-kill-and-respawn cycle for transient USB timing issues.
            last_err = None
            for attempt in range(_CONNECT_RETRIES):
                try:
                    bluespy.connect(serial)
                    serials = bluespy.connected_morephs()
                    return {"ok": True, "data": {"serial": serial, "connected_serials": serials}}, cache
                except Exception as e:
                    last_err = e
                    delay = _CONNECT_RETRY_DELAYS[min(attempt, len(_CONNECT_RETRY_DELAYS) - 1)]
                    logger.warning(
                        f"connect() attempt {attempt + 1}/{_CONNECT_RETRIES} failed: {e}. "
                        f"Retrying in {delay}s..."
                    )
                    time.sleep(delay)
            raise last_err

        elif action == "start_capture":
            filename = cmd["filename"]
            duration = cmd.get("duration_seconds")
            bluespy.capture(
                filename,
                LE=cmd.get("LE", True),
                CL=cmd.get("CL", False),
                QHS=cmd.get("QHS", False),
                wifi=cmd.get("wifi", False),
                CS=cmd.get("CS", False),
            )
            if duration is not None:
                time.sleep(duration)
                bluespy.stop_capture()
                packet_count = len(bluespy.packets)
                cache = build_cache(bluespy.packets)
                return {"ok": True, "data": {
                    "file_path": filename,
                    "packet_count": packet_count,
                    "duration_seconds": duration,
                    "timed": True,
                }}, cache
            return {"ok": True, "data": {"file_path": filename, "capturing": True}}, cache

        elif action == "stop_capture":
            bluespy.stop_capture()
            packet_count = len(bluespy.packets)
            cache = build_cache(bluespy.packets)
            return {"ok": True, "data": {"packet_count": packet_count}}, cache

        elif action == "disconnect":
            bluespy.disconnect()
            return {"ok": True, "data": {}}, cache

        elif action == "packet_count":
            count = len(bluespy.packets)
            return {"ok": True, "data": {"packet_count": count}}, cache

        elif action == "get_summary":
            cache = _ensure_cache(bluespy, cache)
            packets_view = CachedPackets(cache)
            summary = summarize_packets(packets_view, limit=cmd.get("limit"))
            summary["devices"] = extract_device_info(bluespy.devices)
            summary["connections"] = extract_connection_info(bluespy.connections)
            return {"ok": True, "data": summary}, cache

        elif action == "get_packets":
            cache = _ensure_cache(bluespy, cache)
            packets_view = CachedPackets(cache)
            results = filter_packets(
                packets_view,
                summary_contains=cmd.get("summary_contains"),
                packet_type=cmd.get("packet_type"),
                channel=cmd.get("channel"),
                max_results=cmd.get("max_results", 100),
                start=cmd.get("start", 0),
            )
            return {"ok": True, "data": {"packets": results, "count": len(results)}}, cache

        elif action == "get_devices":
            devices = extract_device_info(bluespy.devices)
            return {"ok": True, "data": {"devices": devices, "count": len(devices)}}, cache

        elif action == "get_connections":
            connections = extract_connection_info(bluespy.connections)
            return {"ok": True, "data": {"connections": connections, "count": len(connections)}}, cache

        elif action == "get_errors":
            cache = _ensure_cache(bluespy, cache)
            packets_view = CachedPackets(cache)
            errors = find_error_packets(
                packets_view,
                max_results=cmd.get("max_results", 100),
                start=cmd.get("start", 0),
            )
            return {"ok": True, "data": {"errors": errors, "count": len(errors)}}, cache

        elif action == "inspect_connection":
            cache = _ensure_cache(bluespy, cache)
            packets_view = CachedPackets(cache)
            result = analyze_connection_live(
                bluespy.connections,
                packets_view,
                connection_index=cmd.get("connection_index", 0),
            )
            return {"ok": True, "data": result}, cache

        elif action == "inspect_advertising":
            cache = _ensure_cache(bluespy, cache)
            packets_view = CachedPackets(cache)
            result = analyze_advertising_live(
                bluespy.devices,
                packets_view,
                device_index=cmd.get("device_index", 0),
            )
            return {"ok": True, "data": result}, cache

        else:
            return {"ok": False, "error": f"Unknown command: {action}"}, cache

    except Exception as e:
        return {"ok": False, "error": str(e)}, cache


def worker_loop(cmd_queue, result_queue, mode="hardware"):
    """Main loop for the worker subprocess.

    Imports bluespy on first command, then processes commands until
    a "shutdown" command or the queue is empty and parent is gone.

    Args:
        cmd_queue: Queue to receive commands from the parent.
        result_queue: Queue to send results back to the parent.
        mode: "hardware" for live capture (validates USB health),
              "file" for file-only analysis (skips USB checks).
    """
    from bluespy_mcp.loader import get_bluespy

    # If we're in a subprocess, intercept SIGTERM so that when the parent
    # exits (killing daemon children), we skip atexit handlers. Without
    # this, SIGTERM → SystemExit → atexit → bluespy_deinit → SIGSEGV.
    if multiprocessing.current_process().name != "MainProcess":
        signal.signal(signal.SIGTERM, lambda *_: os._exit(0))

    try:
        bluespy = get_bluespy()
        if mode == "hardware":
            # Verify bluespy is functional — bluespy_init can fail silently,
            # leaving the module loaded but hardware operations broken.
            bluespy.connected_morephs()
    except Exception as e:
        result_queue.put({"ok": False, "error": f"Failed to load BlueSPY: {e}"})
        if multiprocessing.current_process().name != "MainProcess":
            os._exit(1)
        return

    # Signal ready
    result_queue.put({"ok": True, "data": {"status": "ready"}})

    # Track whether we opened a hardware connection so we know
    # whether USB release is needed on exit (hardware mode only).
    was_connected = False
    cache: PacketCache | None = None

    while True:
        try:
            cmd = cmd_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        except (EOFError, BrokenPipeError):
            logger.info("Parent process disconnected, shutting down worker")
            break

        if cmd.get("cmd") == "shutdown":
            if mode == "hardware":
                try:
                    bluespy.disconnect()
                except Exception:
                    pass
            result_queue.put({"ok": True, "data": {"status": "shutdown"}})
            break

        result, cache = handle_command(bluespy, cmd, cache)
        if mode == "hardware" and cmd.get("cmd") == "connect" and result.get("ok"):
            was_connected = True
        result_queue.put(result)

    # After a hardware session, reboot the device to fully release
    # the USB handle (turns LED blue). bluespy_deinit alone doesn't
    # release USB after a connect/disconnect cycle, and
    # multiprocessing.Process calls os._exit internally so atexit
    # handlers never run in subprocesses anyway.
    if mode == "hardware" and was_connected:
        try:
            bluespy.reboot_moreph(-1)
        except Exception:
            pass

    # os._exit skips atexit handlers (bluespy_deinit → SIGSEGV on
    # SIGTERM). The reboot above handles USB release; the OS cleans
    # up file descriptors and memory on process exit.
    if multiprocessing.current_process().name != "MainProcess":
        time.sleep(0.1)  # Let result queue flush
        os._exit(0)
