"""Hardware worker subprocess for BlueSPY MCP.

Runs in a child process so that ctypes calls to libblueSPY cannot hang
the MCP server. Receives commands via multiprocessing.Queue and sends
results back.

This module imports bluespy lazily — it's only loaded when a command
is first received, keeping the import cost in the subprocess.
"""

from __future__ import annotations

import logging
import queue
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

    try:
        bluespy = get_bluespy()
    except ImportError as e:
        # Signal that we can't start
        result_queue.put({"ok": False, "error": f"Failed to load BlueSPY: {e}"})
        return

    # Signal ready
    result_queue.put({"ok": True, "data": {"status": "ready"}})

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
        result_queue.put(result)
