"""Hardware worker subprocess for BlueSPY MCP.

Runs in a child process so that ctypes calls to libblueSPY cannot hang
the MCP server. Receives commands via multiprocessing.Queue and sends
results back.

This module imports bluespy lazily — it's only loaded when a command
is first received, keeping the import cost in the subprocess.
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import queue
import signal
import time
from typing import Any

logger = logging.getLogger(__name__)

_REBOOT_WAIT_SECONDS = 3.0


def handle_command(bluespy: Any, cmd: dict) -> dict:
    """Execute a single hardware command against the bluespy module.

    Args:
        bluespy: The loaded bluespy module.
        cmd: Command dict with "cmd" key and optional parameters.

    Returns:
        {"ok": True, "data": {...}} on success.
        {"ok": False, "error": "message"} on failure.
    """
    action = cmd.get("cmd")

    try:
        if action == "discover":
            serials = bluespy.connected_morephs()
            return {"ok": True, "data": {"serials": serials}}

        elif action == "connect":
            serial = cmd.get("serial", -1)
            # Always reboot first to clear stale hardware state
            try:
                bluespy.reboot_moreph(serial)
                time.sleep(_REBOOT_WAIT_SECONDS)
            except Exception as e:
                logger.warning(f"Reboot failed (may be first connection): {e}")
            bluespy.connect(serial)
            serials = bluespy.connected_morephs()
            return {"ok": True, "data": {"serial": serial, "connected_serials": serials}}

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
                return {"ok": True, "data": {
                    "file_path": filename,
                    "packet_count": packet_count,
                    "duration_seconds": duration,
                    "timed": True,
                }}
            return {"ok": True, "data": {"file_path": filename, "capturing": True}}

        elif action == "stop_capture":
            bluespy.stop_capture()
            packet_count = len(bluespy.packets)
            return {"ok": True, "data": {"packet_count": packet_count}}

        elif action == "disconnect":
            bluespy.disconnect()
            return {"ok": True, "data": {}}

        elif action == "packet_count":
            count = len(bluespy.packets)
            return {"ok": True, "data": {"packet_count": count}}

        else:
            return {"ok": False, "error": f"Unknown command: {action}"}

    except Exception as e:
        return {"ok": False, "error": str(e)}


def worker_loop(cmd_queue, result_queue):
    """Main loop for the hardware worker subprocess.

    Imports bluespy on first command, then processes commands until
    a "shutdown" command or the queue is empty and parent is gone.
    """
    from bluespy_mcp.loader import get_bluespy

    # If we're in a subprocess, intercept SIGTERM so that when the parent
    # exits (killing daemon children), we skip atexit handlers. Without
    # this, SIGTERM → SystemExit → atexit → bluespy_deinit → SIGSEGV.
    if multiprocessing.current_process().name != "MainProcess":
        signal.signal(signal.SIGTERM, lambda *_: os._exit(0))

    try:
        bluespy = get_bluespy()
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

    # Track whether we opened a hardware connection. Only sessions that
    # connect need bluespy_deinit on exit — discover-only sessions can
    # skip it to avoid an unnecessary USB recovery delay.
    was_connected = False

    while True:
        try:
            cmd = cmd_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        except (EOFError, BrokenPipeError):
            logger.info("Parent process disconnected, shutting down worker")
            break

        if cmd.get("cmd") == "shutdown":
            try:
                bluespy.disconnect()
            except Exception:
                pass
            result_queue.put({"ok": True, "data": {"status": "shutdown"}})
            break

        result = handle_command(bluespy, cmd)
        if cmd.get("cmd") == "connect" and result.get("ok"):
            was_connected = True
        result_queue.put(result)

    # Explicit deinit releases the USB handle (turns LED blue).
    # We call it here instead of relying on atexit because os._exit
    # below skips atexit handlers (atexit path can SIGSEGV on SIGTERM).
    # Only needed after a real connection — discover-only sessions don't
    # hold a deep USB handle, and deinit would cause an unnecessary
    # recovery delay (~2s) that could break the next connection attempt.
    if was_connected:
        try:
            bluespy._libbluespy.bluespy_deinit()
        except Exception:
            pass

    if multiprocessing.current_process().name != "MainProcess":
        time.sleep(0.1)  # Let result queue flush
        os._exit(0)
