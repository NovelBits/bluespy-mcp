# BlueSPY Hardware Lifecycle

This document explains how the MCP server manages the Moreph hardware,
why the cleanup sequence works the way it does, and the debugging history
that led to the current design.

## Architecture

```
MCP Server (main process)
    │
    HardwareManager
    ├── File lock (~/.bluespy-mcp.lock)
    ├── State machine: IDLE ↔ CONNECTED ↔ CAPTURING
    └── Worker subprocess (daemon, multiprocessing.Process)
            └── bluespy module (ctypes FFI → libblueSPY.dylib)
```

All native library calls run in a worker subprocess. The MCP server
never imports bluespy directly. This prevents ctypes hangs from
freezing the server's stdio transport.

## The Three Levels of Cleanup

The Moreph hardware has cleanup at three distinct levels. Understanding
these is critical — they are NOT interchangeable.

### Level 1: `bluespy.disconnect()` — Library-level

Tells the Python library the connection is done. Unregisters atexit
handlers for `stop_capture` and `disconnect`. Calls `bluespy_disconnect()`
in the native library.

**Does NOT release the firmware-level USB session.** The device LED
stays green.

### Level 2: `bluespy_deinit()` — Native library teardown

Cleans up the native library's internal state (threads, memory, file
handles). Registered as an `atexit` handler by the vendored `bluespy.py`.

**Behavior depends on session type:**
- After a discover-only session (no `connect()` was called): releases
  the USB handle. LED turns blue.
- After a connect/disconnect cycle: does NOT release the firmware-level
  USB session. LED stays green.

This asymmetry is why `bluespy_deinit()` alone is insufficient for
connected sessions.

### Level 3: `reboot_moreph()` — Firmware-level reset

Reboots the Moreph device firmware. Fully releases the USB session
regardless of prior state. **LED turns blue.**

This is the ONLY reliable way to release hardware after a connection.
It introduces a ~2-3 second USB recovery window during which the device
is unavailable for new connections.

## Hardware Session Lifecycle

Every hardware session follows this pattern — reboot bookends the
connection:

```
connect_hardware()
│
├── 1. Acquire file lock (~/.bluespy-mcp.lock)
├── 2. Spawn worker subprocess
│       └── bluespy_init() runs at import time
│       └── Health check: connected_morephs()
├── 3. reboot_moreph()     ← ENTRY REBOOT: clear stale firmware state
├── 4. sleep(3s)           ← USB recovery window
├── 5. bluespy.connect()
│
│   ... capture operations ...
│
disconnect_hardware()
│
├── 6. bluespy.disconnect()  ← library-level cleanup
├── 7. shutdown worker
│       └── reboot_moreph()  ← EXIT REBOOT: release USB (LED → blue)
│       └── os._exit(0)      ← skip atexit (prevents SIGSEGV)
├── 8. Wait for worker to exit (join, 5s timeout)
└── 9. Release file lock
```

## Why os._exit(0)?

The vendored `bluespy.py` registers `bluespy_deinit` as an atexit
handler at import time:

```python
_libbluespy.bluespy_init()
atexit.register(_libbluespy.bluespy_deinit)
```

We must prevent this atexit handler from running in the worker
subprocess for two reasons:

1. **SIGTERM path (crash prevention):** When the parent process exits,
   daemon subprocesses receive SIGTERM. Python converts SIGTERM to
   SystemExit, which triggers atexit handlers. Running bluespy_deinit
   during SIGTERM teardown causes a SIGSEGV in
   `bluespy_private_close_all_filter_files`.

2. **multiprocessing internals:** `multiprocessing.Process` calls
   `os._exit()` after the target function returns anyway, so atexit
   handlers never run in normal subprocess exit. We can't rely on
   atexit even if we wanted to.

The worker installs a SIGTERM handler that calls `os._exit(0)` to
prevent the crash path. For normal shutdown, it calls `os._exit(0)`
explicitly after cleanup.

## Retry Logic

Two layers of retry handle USB recovery timing:

### Worker spawn retry (3 attempts, 2s delay)

`_spawn_worker()` retries when `bluespy_init()` fails silently. The
health check (`connected_morephs()`) detects this. Handles the case
where the USB device hasn't recovered from a previous worker exit.

### Connect retry (3 attempts, 2s delay)

`connect()` retries the full spawn+connect sequence. Handles the case
where `bluespy_init()` succeeds (health check passes) but heavier
operations like `reboot_moreph()` and `bluespy_connect()` fail because
USB recovery is incomplete.

## Why discover_hardware() Was Removed

The original `discover_hardware()` tool called `connected_morephs()` to
list available devices. However, `connected_morephs()` only returns
devices with an active `bluespy.connect()` session — it does NOT
enumerate USB-connected devices. This meant discover always returned an
empty list unless something else had already connected.

Since `connect_hardware(serial=-1)` handles first-available device
selection internally (via `bluespy.connect(-1)`), and there's no
way to enumerate devices without connecting, discover was removed
entirely in v1.1.

The worker tracks whether a connection was opened with a `was_connected`
flag, set to `True` only when a connect command succeeds. This
determines whether a firmware reboot is needed at shutdown.

## File Lock

`~/.bluespy-mcp.lock` uses `fcntl.flock()` to ensure only one MCP
client controls the hardware at a time. The lock is acquired at
`connect()` and released at `disconnect()`.

If a previous session crashed without releasing the lock,
`connect_hardware(force=True)` removes the stale lock file before
acquiring. This only helps with stale *lock files* — if the device
itself is held by another process (BlueSPY desktop app), only closing
that process or rebooting the device will release it.

## LED States

| LED Color | Meaning |
|-----------|---------|
| Blue | Device available, no active session |
| Green | Device held by an active session |

## Debugging History

The current design was reached through iterative debugging. Here's
what was tried and why each approach failed:

### Attempt 1: `atexit.unregister(bluespy_deinit)`

Tried to unregister the atexit handler in the worker. Failed because
ctypes function wrappers create new Python objects on each attribute
access, so `atexit.unregister()` can't match the registered function
by identity.

### Attempt 2: `os._exit(0)` only

Skipped all atexit handlers via `os._exit(0)`. Worked for preventing
SIGSEGV but left the USB session unreleased (LED stays green). Also
killed the pytest process when worker_loop was tested in threads
instead of subprocesses — fixed by guarding with
`multiprocessing.current_process().name != "MainProcess"`.

### Attempt 3: Explicit `bluespy_deinit()` + `os._exit(0)`

Called `bluespy_deinit()` before `os._exit(0)`. Deinit ran
successfully but introduced a USB recovery delay (0s=works, 1s=fails,
2s=works pattern). Removed because it made back-to-back operations
unreliable.

### Attempt 4: `_spawn_worker()` retry

Added retry logic (3 attempts, 2s delay) to worker spawning. But the
worker started "successfully" — `bluespy_init()` passed, health check
passed — while the actual connect command still failed. The retry was
at the wrong level.

### Attempt 5: Health check + spawn retry

Added `connected_morephs()` health check after loading bluespy. This
detected silent `bluespy_init()` failures and triggered spawn retry.
Solved the init-level recovery but didn't help when init succeeded
and connect failed.

### Attempt 6: Connect retry

Added retry logic to `connect()` wrapping the full spawn+connect
sequence. This handled the case where spawn succeeds but connect fails.
Tests passed, but the LED stayed green after the session ended.

### Attempt 7: Conditional `bluespy_deinit()` (was_connected flag)

Only called `bluespy_deinit()` when the worker had actually connected.
Discover-only sessions skipped it. Tests passed, but LED still green
after connected sessions. Proved that `bluespy_deinit()` doesn't
release USB after a connect/disconnect cycle.

### Attempt 8: Natural atexit (return instead of os._exit)

Let the worker return normally from `worker_loop()` so Python's atexit
would run `bluespy_deinit`. Discovered that `multiprocessing.Process`
calls `os._exit()` internally after the target returns — atexit
handlers never run in subprocesses regardless.

### Attempt 9: `reboot_moreph()` at shutdown (current solution)

Called `reboot_moreph(-1)` at worker shutdown when `was_connected` is
True. This is the same mechanism used at connect time to clear stale
state. Firmware-level reset fully releases the USB session. LED turns
blue. All tests pass.

**Key insight:** The Moreph firmware holds USB sessions independently
of the Python library's state. Only a firmware reboot releases them.
`disconnect()` and `bluespy_deinit()` operate at the library level
and don't touch firmware session state.
