# BlueSPY MCP Server

MCP server for the [BlueSPY](https://rfcreations.com) Bluetooth LE protocol analyzer. Gives AI assistants direct access to .pcapng capture analysis — turn packet captures into conversations instead of writing scripts or scrolling through Wireshark.

Works with Claude Desktop, Claude Code, and Cursor.

## What It Does

Instead of writing Python scripts or manually filtering packets, just ask:

> "Load this capture and tell me what's going on."

The AI loads your capture file, classifies 54,000+ packets, identifies 219 devices, maps 25 connections, and gives you a structured breakdown — in seconds.

### Example: Analyzing a Restaurant Bluetooth LE Environment

```
You: Load the First Watch capture and summarize it.

Claude: Loaded First Watch Carmel.pcapng — 54,195 packets over 32 seconds.

  219 devices detected, 25 active connections.

  Packet breakdown:
  → 11,671 ADV_IND (connectable advertisements)
  → 4,738 ADV_NONCONN_IND (beacons)
  → 6,554 LE_DATA (active data transfer)
  → 5,642 SCAN_REQ / 5,014 SCAN_RSP
  → 113 CRC errors from RF congestion
  → 33 new connections initiated

You: Show me the advertising for the first device.

Claude: Device BC:57:29:01:00:42 — 34 advertisements found.
  Channels: 37, 38, 39
  RSSI: min -82, max -48, avg -65.2

You: Find all the errors.

Claude: 113 errors found — all CRC failures on advertising channels,
  consistent with a congested RF environment (219 devices in range).
```

No scripts. No manual filtering. Just a conversation.

## Prerequisites

- **Python 3.10+**
- **BlueSPY application** installed from [rfcreations.com](https://rfcreations.com) (provides the native `libblueSPY` library)

## Installation

```bash
pip install bluespy-mcp
```

Or install from source:

```bash
git clone https://github.com/novelbits/bluespy-mcp.git
cd bluespy-mcp
pip install .
```

## Configuration

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bluespy": {
      "command": "bluespy-mcp",
      "env": {
        "BLUESPY_LIBRARY_PATH": "/Applications/blueSPY.app/Contents/Frameworks/libblueSPY.dylib"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add bluespy -- bluespy-mcp
```

Or add to your `.mcp.json`:

```json
{
  "bluespy": {
    "command": "bluespy-mcp",
    "env": {
      "BLUESPY_LIBRARY_PATH": "/Applications/blueSPY.app/Contents/Frameworks/libblueSPY.dylib"
    }
  }
}
```

### Cursor

Add to your MCP server configuration:

```json
{
  "bluespy": {
    "command": "bluespy-mcp",
    "env": {
      "BLUESPY_LIBRARY_PATH": "/Applications/blueSPY.app/Contents/Frameworks/libblueSPY.dylib"
    }
  }
}
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `BLUESPY_LIBRARY_PATH` | Path to `libblueSPY.dylib` / `.so` / `.dll` | Yes |
| `BLUESPY_API_PATH` | Path to directory containing `bluespy.py` (auto-discovered if not set) | No |
| `BLE_CAPTURES_DIR` | Default directory for capture files (default: `captures/`) | No |

### Platform-Specific Library Paths

| Platform | Path |
|----------|------|
| macOS | `/Applications/blueSPY.app/Contents/Frameworks/libblueSPY.dylib` |
| Windows | `C:\Program Files\blueSPY\libblueSPY.dll` |
| Linux | `/usr/local/lib/libblueSPY.so` |

## Tools

### File Management

| Tool | Description |
|------|-------------|
| `load_capture(file_path)` | Load a .pcapng capture file for analysis |
| `close_capture()` | Close the currently loaded file |
| `list_captures(directory?)` | List .pcapng files in a directory |

### Discovery

| Tool | Description |
|------|-------------|
| `capture_summary()` | Packet counts by type, duration, device/connection counts |
| `list_devices()` | All Bluetooth devices with addresses and names |
| `list_connections()` | All connections with parameters |

### Analysis

| Tool | Description |
|------|-------------|
| `search_packets(summary_contains?, packet_type?, channel?, max_results?)` | Filter packets by criteria |
| `inspect_connection(connection_index)` | Deep-dive connection analysis with packet breakdown |
| `inspect_advertising(device_index)` | Per-device advertising analysis with RSSI and channel stats |
| `find_capture_errors(max_results?)` | Error, failure, disconnect, and timeout packets |

### Resources

| Resource | Description |
|----------|-------------|
| `capture://status` | Current loaded file metadata (JSON) |

## Troubleshooting

### "BlueSPY library not found"

Ensure `BLUESPY_LIBRARY_PATH` points to the correct native library for your platform. The BlueSPY application must be installed from [rfcreations.com](https://rfcreations.com).

### "No capture file loaded"

Use `load_capture()` with a path to your .pcapng file before calling analysis tools.

### Claude Desktop crashes on startup

If you're using FastMCP v3.0.2+, ensure the server runs with `show_banner=False` (this is the default in bluespy-mcp). The FastMCP banner corrupts the MCP stdio protocol.

### Module not found errors

Ensure you're using Python 3.10+ and have installed the package:

```bash
python --version  # Should be 3.10+
pip install bluespy-mcp
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Links

- [BlueSPY by RFcreations](https://rfcreations.com)
- [MCP Protocol](https://modelcontextprotocol.io)
- [Issues](https://github.com/novelbits/bluespy-mcp/issues)
